//! Per-connection frame reader: pulls bytes off the socket, frames them,
//! hands each frame to the dispatcher.

use std::io;
use std::sync::Arc;

use crate::proto::framing::{FRAME_HEADER_LEN, decode_frame_header};
use crate::proto::header::SMB2_HEADER_LEN;
use tokio::io::{AsyncRead, AsyncReadExt};
use tracing::{debug, error};

use crate::conn::state::Connection;
use crate::server::ServerState;

/// Read one frame's payload (without the 4-byte length prefix).
///
/// Returns `Ok(None)` on a clean EOF, `Ok(Some(bytes))` on a complete frame,
/// `Err` on partial/garbled data.
pub async fn read_one_frame<R>(reader: &mut R) -> io::Result<Option<Vec<u8>>>
where
    R: AsyncRead + Unpin,
{
    let mut hdr = [0u8; FRAME_HEADER_LEN];
    match reader.read_exact(&mut hdr).await {
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let len = match decode_frame_header(&hdr) {
        Ok(n) => n,
        Err(e) => {
            return Err(io::Error::new(io::ErrorKind::InvalidData, e.to_string()));
        }
    };
    let mut payload = vec![0u8; len as usize];
    reader.read_exact(&mut payload).await?;
    Ok(Some(payload))
}

/// Continuously read frames and route responses to the writer.
///
/// Standalone READ/WRITE requests that do not depend on compound context are
/// dispatched in worker tasks so the transport can keep draining a pipelined
/// credit window. Other requests run behind the connection dispatch gate to
/// keep state transitions ordered with those workers.
pub async fn reader_task(
    mut reader: impl AsyncRead + Unpin,
    server: Arc<ServerState>,
    conn: Arc<Connection>,
    tx: tokio::sync::mpsc::Sender<crate::conn::writer::FramePayload>,
) -> io::Result<()> {
    let mut workers = tokio::task::JoinSet::new();
    loop {
        while let Some(joined) = workers.try_join_next() {
            if let Err(e) = joined {
                debug!(error = %e, "independent dispatch worker failed");
            }
        }
        let frame = match read_one_frame(&mut reader).await {
            Ok(Some(b)) => b,
            Ok(None) => {
                debug!("client closed connection");
                wait_for_workers(&mut workers).await;
                return Ok(());
            }
            Err(e) => {
                error!(error = %e, "frame read error");
                wait_for_workers(&mut workers).await;
                return Err(e);
            }
        };
        if invalid_short_payload(&frame) {
            let e = io::Error::new(
                io::ErrorKind::InvalidData,
                "SMB transport payload too short for a recognized protocol header",
            );
            error!(error = %e, "frame read error");
            wait_for_workers(&mut workers).await;
            return Err(e);
        }
        // Check shutdown after every frame.
        if server
            .shutting_down
            .load(std::sync::atomic::Ordering::Acquire)
        {
            debug!("server shutting down; dropping connection");
            wait_for_workers(&mut workers).await;
            return Ok(());
        }
        if crate::dispatch::can_dispatch_independent_frame(&server, &conn, &frame).await {
            let server = Arc::clone(&server);
            let conn = Arc::clone(&conn);
            let tx = tx.clone();
            workers.spawn(async move {
                let _guard = conn.dispatch_gate.read().await;
                let response = crate::dispatch::dispatch_frame(&server, &conn, &frame).await;
                if let Some(bytes) = response
                    && tx.send(bytes).await.is_err()
                {
                    debug!("writer channel closed; independent worker exiting");
                }
            });
            continue;
        }

        let _guard = conn.dispatch_gate.write().await;
        let response = crate::dispatch::dispatch_frame(&server, &conn, &frame).await;
        if let Some(bytes) = response
            && tx.send(bytes).await.is_err()
        {
            debug!("writer channel closed; reader exiting");
            wait_for_workers(&mut workers).await;
            return Ok(());
        }
        if conn.disconnect_requested() {
            wait_for_workers(&mut workers).await;
            return Err(io::Error::new(
                io::ErrorKind::ConnectionReset,
                "SMB dispatch requested disconnect",
            ));
        }
    }
}

fn invalid_short_payload(frame: &[u8]) -> bool {
    if frame.len() >= SMB2_HEADER_LEN {
        return false;
    }
    if crate::proto::crypto::is_compression_transform(frame)
        || crate::proto::crypto::encryption::is_encryption_transform(frame)
    {
        return false;
    }
    frame.len() < 35 || frame[0..4] != [0xFF, b'S', b'M', b'B'] || frame[4] != 0x72
}

async fn wait_for_workers(workers: &mut tokio::task::JoinSet<()>) {
    while let Some(joined) = workers.join_next().await {
        if let Err(e) = joined {
            debug!(error = %e, "independent dispatch worker failed");
        }
    }
}
