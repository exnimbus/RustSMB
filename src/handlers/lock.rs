//! LOCK handler.

use std::sync::Arc;

use crate::proto::header::Smb2Header;
use crate::proto::messages::{LockElement, LockRequest, LockResponse};

use crate::conn::state::Connection;
use crate::dispatch::HandlerResponse;
use crate::handlers::shared::{lookup_open, lookup_session_tree};
use crate::ntstatus;
use crate::server::ByteRangeLockRequest;
use crate::server::ServerState;

pub async fn handle(
    server: &Arc<ServerState>,
    conn: &Arc<Connection>,
    hdr: &Smb2Header,
    body: &[u8],
) -> HandlerResponse {
    let req = match LockRequest::parse(body) {
        Ok(r) if r.structure_size == 48 && r.lock_count != 0 => r,
        _ => return HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER),
    };
    let tree_arc = match lookup_session_tree(conn, hdr).await {
        Ok(t) => t,
        Err(s) => return HandlerResponse::err(s),
    };
    let open_arc = match lookup_open(&tree_arc, req.file_id).await {
        Some(o) => o,
        None => return HandlerResponse::err(ntstatus::STATUS_FILE_CLOSED),
    };
    let dialect = *conn.dialect.read().await;
    let (share_name, path, stream_name, locking_lease_key) = {
        let tree = tree_arc.read().await;
        let open = open_arc.read().await;
        if open.handle.is_none() {
            return HandlerResponse::err(ntstatus::STATUS_FILE_CLOSED);
        }
        (
            tree.share.name.clone(),
            open.last_path.clone(),
            open.stream_name.clone(),
            open.lease_key,
        )
    };
    {
        let mut open = open_arc.write().await;
        if open.replayed_lock_sequence(dialect, req.lock_sequence) {
            return lock_success_response();
        }
    }

    let result = apply_lock_request(server, &share_name, &path, stream_name.as_deref(), &req);
    if result.status == ntstatus::STATUS_LOCK_NOT_GRANTED && lock_request_can_wait(&req) {
        let Some(tx) = conn.async_sender().await else {
            return HandlerResponse::err(ntstatus::STATUS_NOT_SUPPORTED);
        };
        if !server.reserve_byte_range_lock_wait_async_slot(conn) {
            return HandlerResponse::err(ntstatus::STATUS_INSUFFICIENT_RESOURCES);
        }
        let async_id = conn.alloc_async_id();
        let locks = byte_range_lock_requests(&req);
        server.register_byte_range_lock_wait(
            async_id,
            conn,
            tx,
            *hdr,
            &share_name,
            path,
            stream_name,
            req.file_id,
            &open_arc,
            dialect,
            req.lock_sequence,
            locks,
        );
        return HandlerResponse::pending_async(
            async_id,
            HandlerResponse::err(ntstatus::STATUS_PENDING).body,
        );
    }
    if result.released_locks {
        server
            .try_complete_byte_range_lock_waits(&share_name, &path, stream_name.as_deref())
            .await;
    }
    if result.status != ntstatus::STATUS_SUCCESS {
        return HandlerResponse::err(result.status);
    }
    {
        let mut open = open_arc.write().await;
        open.record_lock_sequence(dialect, req.lock_sequence);
    }
    if !result.released_locks && lock_request_has_exclusive_lock(&req) {
        server
            .break_conflicting_leases_for_open(
                &share_name,
                &path,
                stream_name.as_deref(),
                locking_lease_key,
                0,
            )
            .await;
        server
            .break_own_level_ii_oplock_if_other_handles(
                &share_name,
                &path,
                stream_name.as_deref(),
                req.file_id,
            )
            .await;
    }

    lock_success_response()
}

fn lock_success_response() -> HandlerResponse {
    let mut buf = Vec::new();
    LockResponse::default().write_to(&mut buf).expect("encode");
    HandlerResponse::ok(buf)
}

struct LockApplyResult {
    status: u32,
    released_locks: bool,
}

fn apply_lock_request(
    server: &ServerState,
    share_name: &str,
    path: &crate::path::SmbPath,
    stream_name: Option<&str>,
    req: &LockRequest,
) -> LockApplyResult {
    let first_is_unlock = req.locks[0].flags & LockElement::FLAG_UNLOCK != 0;
    if first_is_unlock {
        let mut released_locks = false;
        for lock in &req.locks {
            if !valid_unlock_flags(lock.flags) {
                return LockApplyResult {
                    status: ntstatus::STATUS_INVALID_PARAMETER,
                    released_locks,
                };
            }
            if !valid_lock_range(lock.offset, lock.length) {
                return LockApplyResult {
                    status: ntstatus::STATUS_INVALID_LOCK_RANGE,
                    released_locks,
                };
            }
            let status = server.unlock_byte_ranges(
                share_name,
                path,
                stream_name,
                req.file_id,
                &[(lock.offset, lock.length)],
            );
            if status != ntstatus::STATUS_SUCCESS {
                return LockApplyResult {
                    status,
                    released_locks,
                };
            }
            released_locks = true;
        }
        return LockApplyResult {
            status: ntstatus::STATUS_SUCCESS,
            released_locks,
        };
    }

    for lock in &req.locks {
        if !valid_lock_request_flags(lock.flags) {
            return LockApplyResult {
                status: ntstatus::STATUS_INVALID_PARAMETER,
                released_locks: false,
            };
        }
        if !valid_lock_range(lock.offset, lock.length) {
            return LockApplyResult {
                status: ntstatus::STATUS_INVALID_LOCK_RANGE,
                released_locks: false,
            };
        }
        if req.locks.len() > 1 && lock.flags & LockElement::FLAG_FAIL_IMMEDIATELY == 0 {
            return LockApplyResult {
                status: ntstatus::STATUS_INVALID_PARAMETER,
                released_locks: false,
            };
        }
    }

    let locks = byte_range_lock_requests(req);
    LockApplyResult {
        status: server.apply_byte_range_locks(share_name, path, stream_name, &locks),
        released_locks: false,
    }
}

fn byte_range_lock_requests(req: &LockRequest) -> Vec<ByteRangeLockRequest> {
    req.locks
        .iter()
        .map(|lock| ByteRangeLockRequest {
            fid: req.file_id,
            offset: lock.offset,
            length: lock.length,
            exclusive: lock.flags & LockElement::FLAG_EXCLUSIVE_LOCK != 0,
        })
        .collect()
}

fn lock_request_can_wait(req: &LockRequest) -> bool {
    req.locks.len() == 1
        && req.locks[0].flags & LockElement::FLAG_UNLOCK == 0
        && req.locks[0].flags & LockElement::FLAG_FAIL_IMMEDIATELY == 0
}

fn lock_request_has_exclusive_lock(req: &LockRequest) -> bool {
    req.locks.iter().any(|lock| {
        lock.flags & LockElement::FLAG_UNLOCK == 0
            && lock.flags & LockElement::FLAG_EXCLUSIVE_LOCK != 0
    })
}

fn valid_lock_request_flags(flags: u32) -> bool {
    flags == LockElement::FLAG_SHARED_LOCK
        || flags == LockElement::FLAG_EXCLUSIVE_LOCK
        || flags == (LockElement::FLAG_SHARED_LOCK | LockElement::FLAG_FAIL_IMMEDIATELY)
        || flags == (LockElement::FLAG_EXCLUSIVE_LOCK | LockElement::FLAG_FAIL_IMMEDIATELY)
}

fn valid_unlock_flags(flags: u32) -> bool {
    flags == LockElement::FLAG_UNLOCK
}

fn valid_lock_range(offset: u64, length: u64) -> bool {
    if length == 0 {
        return true;
    }
    offset.checked_add(length - 1).is_some()
}
