//! TREE_DISCONNECT handler.

use std::sync::Arc;

use crate::proto::header::Smb2Header;
use crate::proto::messages::TreeDisconnectResponse;

use crate::conn::state::Connection;
use crate::dispatch::HandlerResponse;
use crate::handlers::shared::lookup_session_tree;
use crate::ntstatus;
use crate::server::ServerState;

pub async fn handle(
    server: &Arc<ServerState>,
    conn: &Arc<Connection>,
    hdr: &Smb2Header,
    _body: &[u8],
) -> HandlerResponse {
    let tid = match hdr.tree_id() {
        Some(t) => t,
        None => return HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER),
    };

    let tree_arc = match lookup_session_tree(conn, hdr).await {
        Ok(tree) => tree,
        Err(status) => return HandlerResponse::err(status),
    };
    server
        .cleanup_change_notifies_for_tree(
            conn,
            hdr.session_id,
            tid,
            ntstatus::STATUS_NOTIFY_CLEANUP,
        )
        .await;
    server
        .cleanup_pipe_reads_for_tree(conn, hdr.session_id, tid, ntstatus::STATUS_NOTIFY_CLEANUP)
        .await;
    server
        .cleanup_byte_range_lock_waits_for_tree(
            conn,
            hdr.session_id,
            tid,
            ntstatus::STATUS_NOTIFY_CLEANUP,
        )
        .await;
    server
        .cleanup_cache_break_creates_for_tree(
            conn,
            hdr.session_id,
            tid,
            ntstatus::STATUS_NOTIFY_CLEANUP,
        )
        .await;
    server
        .cleanup_cache_break_writes_for_tree(
            conn,
            hdr.session_id,
            tid,
            ntstatus::STATUS_NOTIFY_CLEANUP,
        )
        .await;
    server
        .cleanup_cache_break_tasks_for_tree(
            conn,
            hdr.session_id,
            tid,
            ntstatus::STATUS_NOTIFY_CLEANUP,
        )
        .await;
    server.cleanup_tree_disconnect_opens(conn, &tree_arc).await;
    if !conn.close_tree(hdr.session_id, tid).await {
        return HandlerResponse::err(ntstatus::STATUS_NETWORK_NAME_DELETED);
    }
    let mut buf = Vec::new();
    TreeDisconnectResponse::default()
        .write_to(&mut buf)
        .expect("encode");
    HandlerResponse::ok(buf)
}
