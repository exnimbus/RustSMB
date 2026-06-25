//! CHANGE_NOTIFY handler.
//!
//! Full change-notify support needs async pending responses and a server-wide
//! notification queue. This handler implements the synchronous validation
//! surface first so invalid requests get GoSMB-compatible statuses instead of a
//! blanket `STATUS_NOT_SUPPORTED`.

use std::sync::Arc;

use crate::proto::header::Smb2Header;
use crate::proto::messages::ChangeNotifyRequest;

use crate::conn::state::Connection;
use crate::dispatch::HandlerResponse;
use crate::handlers::shared::{lookup_open, lookup_session_tree};
use crate::ntstatus;
use crate::server::{ServerState, encode_change_notify_response_body, encode_file_notify_events};

const FILE_LIST_DIRECTORY: u32 = 0x0000_0001;

pub async fn handle(
    server: &Arc<ServerState>,
    conn: &Arc<Connection>,
    hdr: &Smb2Header,
    body: &[u8],
) -> HandlerResponse {
    let req = match ChangeNotifyRequest::parse(body) {
        Ok(req) => req,
        Err(_) => return HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER),
    };
    if req.structure_size != 32 {
        return HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER);
    }
    if req.flags & !ChangeNotifyRequest::FLAG_WATCH_TREE != 0 {
        return HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER);
    }
    let max_transact = *conn.max_read_size.read().await;
    if req.output_buffer_length > max_transact {
        return HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER);
    }

    let tree_arc = match lookup_session_tree(conn, hdr).await {
        Ok(tree) => tree,
        Err(status) => return HandlerResponse::err(status),
    };
    let (share_name, backend) = {
        let tree = tree_arc.read().await;
        (tree.share.name.clone(), Arc::clone(&tree.share.backend))
    };
    let open_arc = match lookup_open(&tree_arc, req.file_id).await {
        Some(open) => open,
        None => return HandlerResponse::err(ntstatus::STATUS_FILE_CLOSED),
    };
    let watch_path;
    let notify_first;
    let notify_force_enum_dir;
    let completion_filter;
    let buffered_events;
    let recursive = req.flags & ChangeNotifyRequest::FLAG_WATCH_TREE != 0;
    {
        let mut open = open_arc.write().await;
        if !open.is_directory {
            return HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER);
        }
        if open.desired_access & FILE_LIST_DIRECTORY == 0 {
            return HandlerResponse::err(ntstatus::STATUS_ACCESS_DENIED);
        }
        notify_first = !open.notify_started;
        open.notify_started = true;
        notify_force_enum_dir = open.notify_enum_dir;
        open.notify_recursive = recursive;
        if notify_first {
            open.notify_completion_filter = req.completion_filter;
        }
        completion_filter = open.notify_completion_filter;
        watch_path = open.last_path.clone();
        if recursive {
            buffered_events = std::mem::take(&mut open.notify_buffer);
        } else {
            let mut remaining = Vec::new();
            let mut selected = Vec::new();
            for event in open.notify_buffer.drain(..) {
                if event.name.contains('\\') {
                    remaining.push(event);
                } else {
                    selected.push(event);
                }
            }
            open.notify_buffer = remaining;
            buffered_events = selected;
        }
        open.notify_buffer_suppressed = false;
    }
    if !buffered_events.is_empty() {
        let output = encode_file_notify_events(&buffered_events);
        if !notify_force_enum_dir
            && req.output_buffer_length > 0
            && output.len() <= req.output_buffer_length as usize
        {
            return HandlerResponse::ok(encode_change_notify_response_body(&output));
        }
        if notify_first && !notify_force_enum_dir {
            open_arc.write().await.notify_enum_dir = true;
        }
        let mut response = HandlerResponse::ok(encode_change_notify_response_body(&[]));
        response.status = ntstatus::STATUS_NOTIFY_ENUM_DIR;
        return response;
    }

    let Some(tx) = conn.async_sender().await else {
        return HandlerResponse::err(ntstatus::STATUS_NOT_SUPPORTED);
    };
    if !server.reserve_change_notify_async_slot(conn) {
        return HandlerResponse::err(ntstatus::STATUS_INSUFFICIENT_RESOURCES);
    }
    let async_id = conn.alloc_async_id();
    let backend_watch = match backend.watch(&watch_path, recursive).await {
        Ok(watch) => watch,
        Err(err) => {
            conn.release_pending_async();
            return HandlerResponse::err(err.to_nt_status());
        }
    };
    let (watch_cancel, watch_cancel_rx) = if backend_watch.is_some() {
        let (tx, rx) = tokio::sync::oneshot::channel();
        (Some(tx), Some(rx))
    } else {
        (None, None)
    };

    server.register_change_notify(
        async_id,
        conn,
        &open_arc,
        tx,
        *hdr,
        req.file_id,
        &share_name,
        watch_path,
        recursive,
        req.output_buffer_length,
        completion_filter,
        notify_first,
        notify_force_enum_dir,
        watch_cancel,
    );
    if let (Some(watch), Some(cancel)) = (backend_watch, watch_cancel_rx) {
        tokio::spawn(Arc::clone(server).forward_backend_change_notify_watch(
            Arc::clone(conn),
            async_id,
            watch,
            cancel,
        ));
    }
    HandlerResponse::pending_async(async_id, encode_change_notify_response_body(&[]))
}
