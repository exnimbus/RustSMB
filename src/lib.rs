//! SMB2/3 file-sharing server with pluggable storage backends.
//!
//! See `docs/superpowers/specs/2026-04-27-rust-smb-server-design.md` for the
//! v1 design. The public API is small on purpose:
//!
//! ```no_run
//! use smb_server::{SmbServer, Share, Access, ShareBackend};
//! # async fn run<B: ShareBackend>(backend: B) -> Result<(), Box<dyn std::error::Error>> {
//! SmbServer::builder()
//!     .listen("0.0.0.0:4445".parse()?)
//!     .user("alice", "password")
//!     .share(Share::new("home", backend).user("alice", Access::ReadWrite))
//!     .build()?
//!     .serve()
//!     .await?;
//! # Ok(()) }
//! ```

#![allow(clippy::too_many_arguments, clippy::type_complexity)]

mod backend;
mod builder;
pub(crate) mod conn;
mod dispatch;
mod error;
#[cfg(feature = "localfs")]
mod fs;
mod handlers;
pub(crate) mod info_class;
pub mod ntstatus;
mod path;
mod proto;
#[cfg(feature = "quic")]
mod quic;
mod server;
mod utils;

pub use backend::{
    BackendCapabilities, DirEntry, FileInfo, FileTimes, Handle, OpenIntent, OpenOptions,
    ShareBackend,
};
pub use builder::{Access, Share, SmbServerBuilder};
pub use error::{SmbError, SmbResult};
#[cfg(feature = "localfs")]
pub use fs::LocalFsBackend;
pub use path::SmbPath;
pub use proto::auth::ntlm::Identity;
#[cfg(feature = "quic")]
pub use quic::{
    DEFAULT_QUIC_CONNECTION_RECEIVE_WINDOW, DEFAULT_QUIC_KEEP_ALIVE_INTERVAL,
    DEFAULT_QUIC_MAX_IDLE_TIMEOUT, DEFAULT_QUIC_STREAM_RECEIVE_WINDOW, SMB_QUIC_ALPN,
    SmbQuicConfig, SmbQuicConfigError, SmbQuicEndpointError, smb_quic_endpoint,
    smb_quic_server_config,
};
pub use server::{ConfigHandle, ShareMode, ShutdownHandle, SmbServer};

pub mod wire {
    pub mod crypto {
        pub use crate::proto::crypto::{
            SigningAlgo, sign, signing_key_30, signing_key_311, verify,
        };
    }
    pub use crate::proto::header;
    pub use crate::proto::messages;
}

#[cfg(test)]
mod tests {
    mod dynamic_config;
    mod memfs;
}
