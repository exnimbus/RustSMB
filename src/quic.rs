//! SMB over QUIC transport support.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use quinn::crypto::rustls::QuicServerConfig;
use quinn::{Endpoint, IdleTimeout, TransportConfig, VarInt};
use thiserror::Error;
use tracing::{Instrument, error, info, info_span, warn};

use crate::conn::connection_loop_with_io;
use crate::server::SmbServer;

/// TLS ALPN token for SMB over QUIC.
pub const SMB_QUIC_ALPN: &[u8] = b"smb";

pub const DEFAULT_QUIC_MAX_IDLE_TIMEOUT: Duration = Duration::from_secs(3 * 60);
pub const DEFAULT_QUIC_KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(15);
pub const DEFAULT_QUIC_STREAM_RECEIVE_WINDOW: u64 = 64 << 20;
pub const DEFAULT_QUIC_CONNECTION_RECEIVE_WINDOW: u64 = 256 << 20;

/// QUIC transport settings for SMB over QUIC.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SmbQuicConfig {
    pub max_idle_timeout: Duration,
    pub keep_alive_interval: Duration,
    pub stream_receive_window: u64,
    pub connection_receive_window: u64,
}

impl Default for SmbQuicConfig {
    fn default() -> Self {
        Self {
            max_idle_timeout: DEFAULT_QUIC_MAX_IDLE_TIMEOUT,
            keep_alive_interval: DEFAULT_QUIC_KEEP_ALIVE_INTERVAL,
            stream_receive_window: DEFAULT_QUIC_STREAM_RECEIVE_WINDOW,
            connection_receive_window: DEFAULT_QUIC_CONNECTION_RECEIVE_WINDOW,
        }
    }
}

#[derive(Debug, Error)]
pub enum SmbQuicConfigError {
    #[error("QUIC stream receive window must be positive")]
    ZeroStreamReceiveWindow,
    #[error("QUIC connection receive window must be positive")]
    ZeroConnectionReceiveWindow,
    #[error("QUIC {field} is outside the protocol varint range")]
    VarIntBounds { field: &'static str },
    #[error("invalid QUIC TLS server config: no initial cipher suite")]
    NoInitialCipherSuite(#[from] quinn::crypto::rustls::NoInitialCipherSuite),
    #[error("invalid QUIC TLS server config: {0}")]
    Tls(#[from] quinn::rustls::Error),
}

/// Build a Quinn server config suitable for SMB over QUIC.
pub fn smb_quic_server_config(
    mut tls_config: quinn::rustls::ServerConfig,
    config: SmbQuicConfig,
) -> Result<quinn::ServerConfig, SmbQuicConfigError> {
    if config.stream_receive_window == 0 {
        return Err(SmbQuicConfigError::ZeroStreamReceiveWindow);
    }
    if config.connection_receive_window == 0 {
        return Err(SmbQuicConfigError::ZeroConnectionReceiveWindow);
    }

    tls_config.alpn_protocols = smb_quic_next_protos(&tls_config.alpn_protocols);
    let crypto = QuicServerConfig::try_from(tls_config)?;
    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    server_config.transport_config(Arc::new(smb_quic_transport_config(config)?));
    Ok(server_config)
}

/// Bind an SMB-over-QUIC endpoint.
pub fn smb_quic_endpoint(
    addr: SocketAddr,
    tls_config: quinn::rustls::ServerConfig,
    config: SmbQuicConfig,
) -> Result<Endpoint, SmbQuicEndpointError> {
    let server_config = smb_quic_server_config(tls_config, config)?;
    Ok(Endpoint::server(server_config, addr)?)
}

#[derive(Debug, Error)]
pub enum SmbQuicEndpointError {
    #[error(transparent)]
    Config(#[from] SmbQuicConfigError),
    #[error(transparent)]
    Io(#[from] io::Error),
}

impl SmbServer {
    /// Serve SMB over an already-bound Quinn endpoint.
    ///
    /// Each QUIC connection accepts one bidirectional SMB stream and then runs
    /// the same dispatcher used by direct TCP, with the connection marked as a
    /// secure transport for SMB 3.1.1 transport-security negotiation.
    pub async fn serve_quic(self, endpoint: Endpoint) -> io::Result<()> {
        let state = self.state();
        let local = endpoint.local_addr().ok();
        let span = info_span!("smb_quic_server", listen = ?local);
        async move {
            info!("QUIC server starting");
            loop {
                if state.shutting_down.load(Ordering::Acquire) {
                    endpoint.close(0u32.into(), b"shutdown");
                    break;
                }
                tokio::select! {
                    biased;
                    _ = state.shutdown.notified() => {
                        info!("shutdown requested; stopping QUIC accept loop");
                        endpoint.close(0u32.into(), b"shutdown");
                        break;
                    }
                    incoming = endpoint.accept() => {
                        let Some(incoming) = incoming else {
                            break;
                        };
                        if state.shutting_down.load(Ordering::Acquire) {
                            incoming.refuse();
                            endpoint.close(0u32.into(), b"shutdown");
                            break;
                        }
                        let server_state = state.clone();
                        let remote = incoming.remote_address();
                        let span = info_span!("quic_conn", peer = %remote);
                        tokio::spawn(async move {
                            match incoming.await {
                                Ok(conn) => handle_quic_connection(conn, server_state).await,
                                Err(e) => warn!(error = %e, "QUIC handshake failed"),
                            }
                        }.instrument(span));
                    }
                }
            }
            info!("QUIC server stopped");
            Ok::<(), io::Error>(())
        }
        .instrument(span)
        .await
    }
}

async fn handle_quic_connection(conn: quinn::Connection, server: Arc<crate::server::ServerState>) {
    let remote = conn.remote_address();
    let result = match conn.accept_bi().await {
        Ok((send, recv)) => connection_loop_with_io(recv, send, server, true).await,
        Err(e) => {
            warn!(%remote, error = %e, "SMB over QUIC stream accept failed");
            Err(io::Error::other(e))
        }
    };
    if let Err(e) = result {
        error!(%remote, error = %e, "QUIC SMB connection loop exited with error");
    }
    conn.close(0u32.into(), b"");
}

fn smb_quic_transport_config(config: SmbQuicConfig) -> Result<TransportConfig, SmbQuicConfigError> {
    if config.stream_receive_window == 0 {
        return Err(SmbQuicConfigError::ZeroStreamReceiveWindow);
    }
    if config.connection_receive_window == 0 {
        return Err(SmbQuicConfigError::ZeroConnectionReceiveWindow);
    }
    let mut transport = TransportConfig::default();
    transport.max_concurrent_bidi_streams(VarInt::from_u32(1));
    transport.max_concurrent_uni_streams(VarInt::from_u32(0));
    transport.max_idle_timeout(Some(
        IdleTimeout::try_from(config.max_idle_timeout).map_err(|_| {
            SmbQuicConfigError::VarIntBounds {
                field: "max_idle_timeout",
            }
        })?,
    ));
    transport.keep_alive_interval(Some(config.keep_alive_interval));
    transport.stream_receive_window(VarInt::try_from(config.stream_receive_window).map_err(
        |_| SmbQuicConfigError::VarIntBounds {
            field: "stream_receive_window",
        },
    )?);
    transport.receive_window(
        VarInt::try_from(config.connection_receive_window).map_err(|_| {
            SmbQuicConfigError::VarIntBounds {
                field: "connection_receive_window",
            }
        })?,
    );
    Ok(transport)
}

fn smb_quic_next_protos(existing: &[Vec<u8>]) -> Vec<Vec<u8>> {
    let mut out = vec![SMB_QUIC_ALPN.to_vec()];
    out.extend(
        existing
            .iter()
            .filter(|proto| proto.as_slice() != SMB_QUIC_ALPN)
            .cloned(),
    );
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn smb_quic_transport_config_applies_smb_defaults() {
        let transport =
            smb_quic_transport_config(SmbQuicConfig::default()).expect("transport config");
        let debug = format!("{transport:?}");

        assert!(debug.contains("max_concurrent_bidi_streams: 1"));
        assert!(debug.contains("max_concurrent_uni_streams: 0"));
        assert!(debug.contains("max_idle_timeout: Some(180000)"));
        assert!(debug.contains("keep_alive_interval: Some(15s)"));
        assert!(debug.contains(&format!(
            "stream_receive_window: {}",
            DEFAULT_QUIC_STREAM_RECEIVE_WINDOW
        )));
        assert!(debug.contains(&format!(
            "receive_window: {}",
            DEFAULT_QUIC_CONNECTION_RECEIVE_WINDOW
        )));
    }

    #[test]
    fn smb_quic_transport_config_preserves_explicit_timeouts_and_windows() {
        let config = SmbQuicConfig {
            max_idle_timeout: Duration::from_secs(4),
            keep_alive_interval: Duration::from_secs(1),
            stream_receive_window: 1024,
            connection_receive_window: 2048,
        };
        let transport = smb_quic_transport_config(config).expect("transport config");
        let debug = format!("{transport:?}");

        assert!(debug.contains("max_concurrent_bidi_streams: 1"));
        assert!(debug.contains("max_concurrent_uni_streams: 0"));
        assert!(debug.contains("max_idle_timeout: Some(4000)"));
        assert!(debug.contains("keep_alive_interval: Some(1s)"));
        assert!(debug.contains("stream_receive_window: 1024"));
        assert!(debug.contains("receive_window: 2048"));
    }

    #[test]
    fn smb_quic_config_rejects_zero_receive_windows() {
        let config = SmbQuicConfig {
            stream_receive_window: 0,
            ..SmbQuicConfig::default()
        };
        assert!(matches!(
            smb_quic_transport_config(config),
            Err(SmbQuicConfigError::ZeroStreamReceiveWindow)
        ));

        let config = SmbQuicConfig {
            connection_receive_window: 0,
            ..SmbQuicConfig::default()
        };
        assert!(matches!(
            smb_quic_transport_config(config),
            Err(SmbQuicConfigError::ZeroConnectionReceiveWindow)
        ));
    }

    #[test]
    fn smb_quic_alpn_is_first_and_deduplicated() {
        assert_eq!(
            smb_quic_next_protos(&[b"h3".to_vec(), SMB_QUIC_ALPN.to_vec()]),
            vec![SMB_QUIC_ALPN.to_vec(), b"h3".to_vec()]
        );
    }
}
