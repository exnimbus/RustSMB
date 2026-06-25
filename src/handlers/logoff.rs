//! LOGOFF handler.

use std::sync::Arc;

use crate::proto::header::Smb2Header;
use crate::proto::messages::LogoffResponse;

use crate::conn::state::Connection;
use crate::dispatch::HandlerResponse;
use crate::handlers::shared::lookup_session;
use crate::ntstatus;
use crate::server::ServerState;

pub async fn handle(
    server: &Arc<ServerState>,
    conn: &Arc<Connection>,
    hdr: &Smb2Header,
    _body: &[u8],
) -> HandlerResponse {
    if hdr.session_id == 0 {
        return HandlerResponse::err(ntstatus::STATUS_USER_SESSION_DELETED);
    }
    let session = match lookup_session(conn, hdr.session_id).await {
        Ok(session) => session,
        Err(status) => return HandlerResponse::err(status),
    };
    server
        .cleanup_change_notifies_for_session(conn, hdr.session_id, ntstatus::STATUS_NOTIFY_CLEANUP)
        .await;
    server
        .cleanup_pipe_reads_for_session(conn, hdr.session_id, ntstatus::STATUS_NOTIFY_CLEANUP)
        .await;
    server
        .cleanup_byte_range_lock_waits_for_session(
            conn,
            hdr.session_id,
            ntstatus::STATUS_NOTIFY_CLEANUP,
        )
        .await;
    server
        .cleanup_cache_break_creates_for_session(
            conn,
            hdr.session_id,
            ntstatus::STATUS_NOTIFY_CLEANUP,
        )
        .await;
    server
        .cleanup_cache_break_writes_for_session(
            conn,
            hdr.session_id,
            ntstatus::STATUS_NOTIFY_CLEANUP,
        )
        .await;
    server
        .cleanup_cache_break_tasks_for_session(
            conn,
            hdr.session_id,
            ntstatus::STATUS_NOTIFY_CLEANUP,
        )
        .await;
    server.detach_durable_opens_for_session(&session).await;
    let trees = {
        let session = session.read().await;
        session
            .trees
            .read()
            .await
            .values()
            .cloned()
            .collect::<Vec<_>>()
    };
    for tree in trees {
        server.cleanup_opens_for_tree(conn, &tree).await;
    }
    conn.close_session(hdr.session_id).await;
    let mut buf = Vec::new();
    LogoffResponse::default()
        .write_to(&mut buf)
        .expect("encode");
    HandlerResponse::ok(buf)
}
