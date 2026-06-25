//! Per-connection task layout.

pub mod reader;
pub mod state;
pub mod writer;

use std::io;
use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tracing::{debug, info};

use crate::server::ServerState;
use state::Connection;

/// Runs the reader and writer tasks for a single accepted connection until
/// either side hangs up. Returns once both halves are done.
pub async fn connection_loop(stream: TcpStream, server: Arc<ServerState>) -> io::Result<()> {
    let mut stream = stream;
    accept_netbios_session_request(&mut stream).await?;
    let (read_half, write_half) = tokio::io::split(stream);
    connection_loop_with_io(read_half, write_half, server, false).await
}

async fn accept_netbios_session_request(stream: &mut TcpStream) -> io::Result<()> {
    let mut hdr = [0u8; 4];
    let peeked = stream.peek(&mut hdr).await?;
    if peeked == 0 || hdr[0] != 0x81 {
        return Ok(());
    }

    stream.read_exact(&mut hdr).await?;
    let len = ((hdr[1] as usize) << 16) | ((hdr[2] as usize) << 8) | hdr[3] as usize;
    let mut payload = vec![0u8; len];
    stream.read_exact(&mut payload).await?;
    stream.write_all(&[0x82, 0x00, 0x00, 0x00]).await?;
    stream.flush().await
}

/// Runs SMB over an already-accepted bidirectional transport.
pub async fn connection_loop_with_io<R, W>(
    read_half: R,
    write_half: W,
    server: Arc<ServerState>,
    secure_transport: bool,
) -> io::Result<()>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let conn = Arc::new(Connection::new_with_transport_security(
        server.config.server_guid,
        server.config.max_read_size,
        server.config.max_write_size,
        server.config.max_credits,
        secure_transport,
    ));
    let conn_id = server.active_connections.register(&conn).await;
    let (tx, rx) = mpsc::channel::<writer::FramePayload>(writer::WRITER_CHANNEL);
    conn.set_async_sender(tx.clone()).await;

    let writer_handle = tokio::spawn(writer::writer_task(write_half, rx));

    info!("connection accepted");
    let reader_result = reader::reader_task(read_half, server.clone(), conn.clone(), tx).await;
    debug!(?reader_result, "reader exited");
    conn.clear_async_sender().await;
    server
        .cleanup_cache_break_creates_for_connection(&conn)
        .await;
    server
        .cleanup_cache_break_writes_for_connection(&conn)
        .await;
    server.cleanup_cache_break_tasks_for_connection(&conn);
    server.detach_durable_opens_for_connection(&conn).await;
    server.cleanup_opens_for_connection(&conn).await;
    // Wait for writer to drain.
    let _ = writer_handle.await;
    server.active_connections.unregister(conn_id).await;
    info!("connection closed");
    reader_result
}
