//! WRITE handler.

use std::sync::Arc;

use crate::proto::header::Smb2Header;
use crate::proto::messages::{WriteRequest, WriteResponse};

use crate::builder::Access;
use crate::conn::state::Connection;
use crate::dispatch::HandlerResponse;
use crate::handlers::shared::{lookup_open, lookup_session_tree};
use crate::ntstatus;
use crate::server::ServerState;

const FILE_WRITE_DATA: u32 = 0x0000_0002;
const FILE_APPEND_DATA: u32 = 0x0000_0004;
const MAX_SMB_FILE_SIZE: u64 = 0x0fff_ffff_0000;
const LEASE_NONE: u32 = 0x0000_0000;

pub async fn handle(
    server: &Arc<ServerState>,
    conn: &Arc<Connection>,
    hdr: &Smb2Header,
    body: &[u8],
) -> HandlerResponse {
    let req = match WriteRequest::parse(body) {
        Ok(r) => r,
        Err(_) => return HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER),
    };
    if req.channel != 0 || req.write_channel_info_offset != 0 || req.write_channel_info_length != 0
    {
        return HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER);
    }
    if !valid_write_offset(req.offset, req.length) {
        return HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER);
    }
    let max_write = *conn.max_write_size.read().await;
    if req.length > max_write {
        return HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER);
    }
    let tree_arc = match lookup_session_tree(conn, hdr).await {
        Ok(t) => t,
        Err(s) => return HandlerResponse::err(s),
    };
    let granted = {
        let tree = tree_arc.read().await;
        tree.granted_access
    };
    if !matches!(granted, Access::ReadWrite) {
        return HandlerResponse::err(ntstatus::STATUS_ACCESS_DENIED);
    }
    let open_arc = match lookup_open(&tree_arc, req.file_id).await {
        Some(o) => o,
        None => return HandlerResponse::err(ntstatus::STATUS_FILE_CLOSED),
    };
    {
        let open = open_arc.read().await;
        if open.desired_access & (FILE_WRITE_DATA | FILE_APPEND_DATA) == 0 {
            return HandlerResponse::err(ntstatus::STATUS_ACCESS_DENIED);
        }
        if open.is_directory {
            return HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER);
        }
    }
    if req.length == 0 || req.data.is_empty() {
        open_arc.write().await.current_offset = req.offset;
        let mut buf = Vec::new();
        WriteResponse::new(0).write_to(&mut buf).expect("encode");
        return HandlerResponse::ok(buf);
    }
    if write_hits_smb_file_size_limit(req.offset, req.length) {
        return HandlerResponse::err(ntstatus::STATUS_DISK_FULL);
    }
    let status = {
        let tree = tree_arc.read().await;
        let open = open_arc.read().await;
        server.check_write_lock(
            &tree.share.name,
            &open.last_path,
            open.stream_name.as_deref(),
            req.file_id,
            req.offset,
            req.length as u64,
        )
    };
    if status != ntstatus::STATUS_SUCCESS {
        return HandlerResponse::err(status);
    }
    let (share_name, path, stream_name, is_directory, lease_key) = {
        let tree = tree_arc.read().await;
        let open = open_arc.read().await;
        (
            tree.share.name.clone(),
            open.last_path.clone(),
            open.stream_name.clone(),
            open.is_directory,
            open.lease_key,
        )
    };
    let wait_lease_keys = server
        .break_conflicting_leases_for_open_waiting_for_ack(
            &share_name,
            &path,
            stream_name.as_deref(),
            lease_key,
            LEASE_NONE,
        )
        .await;
    if !wait_lease_keys.is_empty() {
        let Some(tx) = conn.async_sender().await else {
            return HandlerResponse::err(ntstatus::STATUS_NOT_SUPPORTED);
        };
        if !server.reserve_cache_break_write_async_slot(conn) {
            return HandlerResponse::err(ntstatus::STATUS_INSUFFICIENT_RESOURCES);
        }
        let async_id = conn.alloc_async_id();
        server.register_cache_break_write(
            async_id,
            conn,
            &open_arc,
            tx,
            *hdr,
            wait_lease_keys,
            &share_name,
            path,
            stream_name,
            req.file_id,
            req.offset,
            req.data,
            is_directory,
        );
        return HandlerResponse::pending_async(
            async_id,
            HandlerResponse::err(ntstatus::STATUS_PENDING).body,
        );
    }
    let mutation_gate = {
        let open = open_arc.read().await;
        open.mutation_gate.clone()
    };
    let _mutation_guard = mutation_gate.lock().await;
    let result = {
        let open = open_arc.read().await;
        match open.handle.as_ref() {
            Some(h) => h.write_owned(req.offset, req.data).await,
            None => return HandlerResponse::err(ntstatus::STATUS_FILE_CLOSED),
        }
    };
    let count = match result {
        Ok(n) => n,
        Err(e) => return HandlerResponse::err(e.to_nt_status()),
    };
    open_arc.write().await.current_offset = req.offset + u64::from(count);
    if count != 0 {
        if stream_name.is_none() {
            server.update_file_times_after_write(&share_name, &path, req.file_id);
        }
        server
            .break_level_ii_oplocks_for_mutation(&share_name, &path, stream_name.as_deref())
            .await;
        server
            .notify_data_modified(&share_name, &path, is_directory)
            .await;
    }
    let mut buf = Vec::new();
    WriteResponse::new(count)
        .write_to(&mut buf)
        .expect("encode");
    HandlerResponse::ok(buf)
}

fn valid_write_offset(offset: u64, length: u32) -> bool {
    const MAX_INT64_OFFSET: u64 = (1u64 << 63) - 1;
    if offset > MAX_INT64_OFFSET {
        return false;
    }
    if length == 0 {
        return true;
    }
    if offset > MAX_SMB_FILE_SIZE {
        return false;
    }
    if offset == MAX_INT64_OFFSET || offset >= MAX_SMB_FILE_SIZE {
        return false;
    }
    offset
        .checked_add(u64::from(length))
        .is_some_and(|end| end <= MAX_SMB_FILE_SIZE)
}

fn write_hits_smb_file_size_limit(offset: u64, length: u32) -> bool {
    offset
        .checked_add(u64::from(length))
        .is_some_and(|end| end == MAX_SMB_FILE_SIZE)
}
