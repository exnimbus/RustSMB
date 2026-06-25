//! CLOSE handler.

use std::sync::Arc;

use crate::error::SmbError;
use crate::proto::header::Smb2Header;
use crate::proto::messages::{CloseRequest, CloseResponse, FileId};
use tracing::debug;

use crate::conn::state::{Connection, Open, TreeConnect};
use crate::dispatch::HandlerResponse;
use crate::handlers::shared::lookup_session_tree;
use crate::ntstatus;
use crate::server::ServerState;

const FLAG_POSTQUERY_ATTRIB: u16 = 0x0001;
const LEASE_READ_CACHING: u32 = 0x0000_0001;

pub async fn handle(
    server: &Arc<ServerState>,
    conn: &Arc<Connection>,
    hdr: &Smb2Header,
    body: &[u8],
) -> HandlerResponse {
    let req = match CloseRequest::parse(body) {
        Ok(r) => r,
        Err(_) => return HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER),
    };
    let tree_arc = match lookup_session_tree(conn, hdr).await {
        Ok(t) => t,
        Err(s) => return HandlerResponse::err(s),
    };
    let pending_open = {
        let tree = tree_arc.read().await;
        let opens = tree.opens.read().await;
        opens.get(&req.file_id).cloned()
    };
    if let Some(open_arc) = pending_open {
        let (delete_on_close, path, stream_name, lease_key) = {
            let open = open_arc.read().await;
            (
                open.delete_on_close,
                open.last_path.clone(),
                open.stream_name.clone(),
                open.lease_key,
            )
        };
        if delete_on_close {
            let share_name = {
                let tree = tree_arc.read().await;
                tree.share.name.clone()
            };
            let wait_lease_keys = server
                .break_conflicting_leases_for_open(
                    &share_name,
                    &path,
                    stream_name.as_deref(),
                    lease_key,
                    LEASE_READ_CACHING,
                )
                .await;
            if !wait_lease_keys.is_empty() {
                let Some(tx) = conn.async_sender().await else {
                    return HandlerResponse::err(ntstatus::STATUS_NOT_SUPPORTED);
                };
                if !server.reserve_cache_break_task_async_slot(conn) {
                    return HandlerResponse::err(ntstatus::STATUS_INSUFFICIENT_RESOURCES);
                }
                let async_id = conn.alloc_async_id();
                let resume_server = Arc::clone(server);
                let resume_conn = Arc::clone(conn);
                let resume_tree_arc = Arc::clone(&tree_arc);
                let resume_req = req.clone();
                server.register_cache_break_task(
                    async_id,
                    conn,
                    tx,
                    *hdr,
                    wait_lease_keys,
                    Vec::new(),
                    Box::new(move || {
                        Box::pin(async move {
                            complete_close_after_cache_break(
                                &resume_server,
                                &resume_conn,
                                &resume_tree_arc,
                                resume_req,
                            )
                            .await
                        })
                    }),
                );
                return HandlerResponse::pending_async(
                    async_id,
                    HandlerResponse::err(ntstatus::STATUS_PENDING).body,
                );
            }
        }
    }
    complete_close_after_cache_break(server, conn, &tree_arc, req).await
}

async fn complete_close_after_cache_break(
    server: &Arc<ServerState>,
    conn: &Arc<Connection>,
    tree_arc: &Arc<tokio::sync::RwLock<TreeConnect>>,
    req: CloseRequest,
) -> HandlerResponse {
    let removed = {
        let tree = tree_arc.write().await;
        let mut opens = tree.opens.write().await;
        opens
            .remove(&req.file_id)
            .map(|open| (open, Arc::clone(tree_arc)))
    };
    let (open_arc, owning_tree_arc) = match removed {
        Some(open) => open,
        None => match remove_open_from_session(conn, req.file_id).await {
            Some(open) => open,
            None => match server.open_by_file_id(req.file_id).await {
                Some(open) => (open, Arc::clone(tree_arc)),
                None => return HandlerResponse::err(ntstatus::STATUS_FILE_CLOSED),
            },
        },
    };
    complete_removed_close(server, conn, &owning_tree_arc, req, open_arc).await
}

async fn remove_open_from_session(
    conn: &Arc<Connection>,
    file_id: FileId,
) -> Option<(
    Arc<tokio::sync::RwLock<Open>>,
    Arc<tokio::sync::RwLock<TreeConnect>>,
)> {
    let sessions = conn.sessions.read().await;
    let session_arcs = sessions.values().cloned().collect::<Vec<_>>();
    drop(sessions);

    for session_arc in session_arcs {
        let session = session_arc.read().await;
        let trees = session.trees.read().await;
        let tree_arcs = trees.values().cloned().collect::<Vec<_>>();
        drop(trees);
        drop(session);

        for tree_arc in tree_arcs {
            let removed = {
                let tree = tree_arc.write().await;
                let mut opens = tree.opens.write().await;
                opens.remove(&file_id)
            };
            if let Some(open) = removed {
                return Some((open, tree_arc));
            }
        }
    }
    None
}

async fn complete_removed_close(
    server: &Arc<ServerState>,
    conn: &Arc<Connection>,
    tree_arc: &Arc<tokio::sync::RwLock<TreeConnect>>,
    req: CloseRequest,
    open_arc: Arc<tokio::sync::RwLock<Open>>,
) -> HandlerResponse {
    server
        .cleanup_change_notifies_for_file(conn, req.file_id, ntstatus::STATUS_NOTIFY_CLEANUP)
        .await;
    server
        .cleanup_pipe_reads_for_file(conn, req.file_id, ntstatus::STATUS_NOTIFY_CLEANUP)
        .await;
    server
        .cleanup_byte_range_lock_waits_for_file(conn, req.file_id, ntstatus::STATUS_NOTIFY_CLEANUP)
        .await;

    // Pull state out, close the handle, then optionally unlink.
    let mut open = open_arc.write().await;
    let handle = open.handle.take();
    let path = open.last_path.clone();
    let stream_name = open.stream_name.clone();
    let file_id = open.file_id;
    let lease_key = open.lease_key;
    let is_directory = open.is_directory;
    let delete_on_close = open.delete_on_close;
    let delete_on_close_unlinks_name = open.delete_on_close_unlinks_name;
    let want_attrs = req.flags & FLAG_POSTQUERY_ATTRIB != 0;
    open.oplock_breaking = false;
    open.oplock_break_to = 0;
    open.desired_access = 0;
    open.share_access = 0x0000_0007;
    open.delete_on_close = false;
    open.delete_on_close_unlinks_name = false;
    drop(open);
    server.remove_durable_open(file_id);

    let (backend, share_name) = {
        let tree = tree_arc.read().await;
        (tree.share.backend.clone(), tree.share.name.clone())
    };

    // Stat before closing if needed.
    let info_before_close = if want_attrs {
        if let Some(h) = handle.as_ref() {
            h.stat()
                .await
                .ok()
                .map(|info| server.effective_file_info(&share_name, &path, info))
        } else {
            None
        }
    } else {
        None
    };
    if let Some(h) = handle {
        let _ = h.close().await;
    }
    server.unregister_open(&open_arc);
    server.remove_byte_range_locks(&share_name, &path, stream_name.as_deref(), file_id);
    server
        .try_complete_byte_range_lock_waits(&share_name, &path, stream_name.as_deref())
        .await;
    server
        .complete_cache_break_waits_for_oplock_file_id(file_id)
        .await;
    if lease_key != [0; 16] {
        let wake_server = Arc::clone(server);
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(1)).await;
            wake_server
                .complete_cache_break_waits_for_lease_key(lease_key)
                .await;
        });
    }
    let mut final_pending_delete = false;
    if delete_on_close {
        server
            .drop_level_ii_oplocks_without_notification(&share_name, &path, stream_name.as_deref())
            .await;
        if let Some(stream_name) = stream_name {
            if let Err(e) = server.delete_stream(&share_name, &path, &stream_name) {
                debug!(error = %e, stream_name, "delete-on-close stream delete failed");
            }
        } else if server.has_other_open(&share_name, &path, &open_arc).await {
            if is_directory {
                if let Err(e) = backend.unlink(&path).await {
                    debug!(error = %e, "delete-on-close directory unlink with other opens failed");
                    server.mark_delete_pending(&share_name, &path);
                    server
                        .cleanup_change_notifies_for_deleted_path(
                            &share_name,
                            &path,
                            ntstatus::STATUS_DELETE_PENDING,
                        )
                        .await;
                } else {
                    server.mark_name_deleted(&share_name, &path);
                    server.mark_delete_pending(&share_name, &path);
                    server.mark_posix_deleted_opens(&share_name, &path).await;
                    server
                        .cleanup_change_notifies_for_deleted_path(
                            &share_name,
                            &path,
                            ntstatus::STATUS_DELETE_PENDING,
                        )
                        .await;
                    server.delete_security_descriptor(&share_name, &path);
                    server.delete_extended_attributes(&share_name, &path);
                    server.delete_allocation_size(&share_name, &path);
                    server.delete_file_attributes(&share_name, &path);
                    server.delete_file_times(&share_name, &path);
                    server.delete_posix_metadata(&share_name, &path);
                    server
                        .notify_removed(&share_name, &path, is_directory)
                        .await;
                }
            } else if !delete_on_close_unlinks_name {
                server.mark_delete_pending(&share_name, &path);
                server
                    .cleanup_change_notifies_for_deleted_path(
                        &share_name,
                        &path,
                        ntstatus::STATUS_DELETE_PENDING,
                    )
                    .await;
            } else if let Err(e) = backend.unlink(&path).await {
                debug!(error = %e, "delete-on-close unlink with other opens failed");
            } else {
                server.mark_name_deleted(&share_name, &path);
                server.mark_delete_pending(&share_name, &path);
                server.mark_posix_deleted_opens(&share_name, &path).await;
                server
                    .cleanup_change_notifies_for_deleted_path(
                        &share_name,
                        &path,
                        ntstatus::STATUS_DELETE_PENDING,
                    )
                    .await;
                server.delete_security_descriptor(&share_name, &path);
                server.delete_extended_attributes(&share_name, &path);
                server.delete_allocation_size(&share_name, &path);
                server.delete_file_attributes(&share_name, &path);
                server.delete_file_times(&share_name, &path);
                server.delete_posix_metadata(&share_name, &path);
                server
                    .notify_removed(&share_name, &path, is_directory)
                    .await;
            }
        } else if let Err(e) = backend.unlink(&path).await {
            debug!(error = %e, "delete-on-close unlink failed");
        } else {
            server.mark_name_deleted(&share_name, &path);
            server
                .cleanup_change_notifies_for_deleted_path(
                    &share_name,
                    &path,
                    ntstatus::STATUS_DELETE_PENDING,
                )
                .await;
            server.delete_security_descriptor(&share_name, &path);
            server.delete_extended_attributes(&share_name, &path);
            server.delete_allocation_size(&share_name, &path);
            server.delete_file_attributes(&share_name, &path);
            server.delete_file_times(&share_name, &path);
            server.delete_streams(&share_name, &path);
            server.delete_posix_metadata(&share_name, &path);
            server
                .notify_removed(&share_name, &path, is_directory)
                .await;
        }
    } else if server
        .take_delete_pending_if_last(&share_name, &path, &open_arc)
        .await
    {
        final_pending_delete = true;
    }
    if final_pending_delete {
        if let Err(e) = backend.unlink(&path).await {
            if matches!(e, SmbError::NotFound | SmbError::PathNotFound) {
                server
                    .cleanup_change_notifies_for_deleted_path(
                        &share_name,
                        &path,
                        ntstatus::STATUS_DELETE_PENDING,
                    )
                    .await;
                server.delete_security_descriptor(&share_name, &path);
                server.delete_extended_attributes(&share_name, &path);
                server.delete_allocation_size(&share_name, &path);
                server.delete_file_attributes(&share_name, &path);
                server.delete_file_times(&share_name, &path);
                server.delete_streams(&share_name, &path);
                server.delete_posix_metadata(&share_name, &path);
                server.clear_delete_pending(&share_name, &path);
                server
                    .notify_removed(&share_name, &path, is_directory)
                    .await;
            } else {
                debug!(error = %e, "final pending-delete unlink failed");
            }
        } else {
            server.mark_name_deleted(&share_name, &path);
            server
                .cleanup_change_notifies_for_deleted_path(
                    &share_name,
                    &path,
                    ntstatus::STATUS_DELETE_PENDING,
                )
                .await;
            server.delete_security_descriptor(&share_name, &path);
            server.delete_extended_attributes(&share_name, &path);
            server.delete_allocation_size(&share_name, &path);
            server.delete_file_attributes(&share_name, &path);
            server.delete_file_times(&share_name, &path);
            server.delete_streams(&share_name, &path);
            server.delete_posix_metadata(&share_name, &path);
            server.clear_delete_pending(&share_name, &path);
            server
                .notify_removed(&share_name, &path, is_directory)
                .await;
        }
    }

    let resp = CloseResponse {
        structure_size: 60,
        flags: req.flags & FLAG_POSTQUERY_ATTRIB,
        reserved: 0,
        creation_time: info_before_close
            .as_ref()
            .map(|i| i.creation_time)
            .unwrap_or(0),
        last_access_time: info_before_close
            .as_ref()
            .map(|i| i.last_access_time)
            .unwrap_or(0),
        last_write_time: info_before_close
            .as_ref()
            .map(|i| i.last_write_time)
            .unwrap_or(0),
        change_time: info_before_close
            .as_ref()
            .map(|i| i.change_time)
            .unwrap_or(0),
        allocation_size: info_before_close
            .as_ref()
            .map(|i| i.allocation_size)
            .unwrap_or(0),
        end_of_file: info_before_close
            .as_ref()
            .map(|i| i.end_of_file)
            .unwrap_or(0),
        file_attributes: info_before_close
            .as_ref()
            .map(|i| i.attributes())
            .unwrap_or(0),
    };
    let mut buf = Vec::new();
    resp.write_to(&mut buf).expect("encode");
    HandlerResponse::ok(buf)
}
