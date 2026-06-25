//! Per-connection writer task: serializes responses, applies signing, and
//! frames the bytes onto the wire.

use crate::proto::framing::encode_frame;
use tokio::io::{AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;
use tracing::{debug, error};

/// One packet of bytes to send. Already includes the final SMB2 header +
/// body, *with signing already applied if required*.
pub type FramePayload = Vec<u8>;

const RAW_FRAMES_PREFIX: &[u8] = b"\0GoSMB-raw-frames\0";

/// Writer-task channel size: large enough that a slow remote rarely backs up
/// the dispatcher.
pub const WRITER_CHANNEL: usize = 64;

pub(crate) fn raw_frame_payload(frames: Vec<Vec<u8>>) -> FramePayload {
    let mut out = Vec::from(RAW_FRAMES_PREFIX);
    for frame in frames {
        encode_frame(&frame, &mut out);
    }
    out
}

pub async fn writer_task(
    mut writer: impl AsyncWrite + Unpin,
    mut rx: mpsc::Receiver<FramePayload>,
) {
    while let Some(payload) = rx.recv().await {
        if let Some(raw) = payload.strip_prefix(RAW_FRAMES_PREFIX) {
            if let Err(e) = writer.write_all(raw).await {
                error!(error = %e, "writer task: socket write failed");
                return;
            }
            debug!(len = raw.len(), "wrote raw frame batch");
            continue;
        }
        let mut out = Vec::with_capacity(payload.len() + 4);
        encode_frame(&payload, &mut out);
        if let Err(e) = writer.write_all(&out).await {
            error!(error = %e, "writer task: socket write failed");
            return;
        }
        debug!(len = out.len(), "wrote frame");
    }
    // Channel closed — flush and bail.
    if let Err(e) = writer.shutdown().await {
        debug!(error = %e, "writer shutdown error (best-effort)");
    }
}
