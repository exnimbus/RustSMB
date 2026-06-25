//! READ handler.

use std::sync::Arc;

use crate::proto::header::Smb2Header;
use crate::proto::messages::{ReadRequest, ReadResponse};

use crate::conn::state::Connection;
use crate::dispatch::HandlerResponse;
use crate::handlers::shared::{lookup_open, lookup_session_tree};
use crate::ntstatus;
use crate::server::ServerState;

const FILE_READ_DATA: u32 = 0x0000_0001;
const FILE_EXECUTE: u32 = 0x0000_0020;

pub async fn handle(
    server: &Arc<ServerState>,
    conn: &Arc<Connection>,
    hdr: &Smb2Header,
    body: &[u8],
) -> HandlerResponse {
    let req = match ReadRequest::parse(body) {
        Ok(r) => r,
        Err(_) => return HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER),
    };
    if req.channel != 0 || req.read_channel_info_offset != 0 || req.read_channel_info_length != 0 {
        return HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER);
    }
    let max_read = *conn.max_read_size.read().await;
    if req.length > max_read {
        return HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER);
    }
    let tree_arc = match lookup_session_tree(conn, hdr).await {
        Ok(t) => t,
        Err(s) => return HandlerResponse::err(s),
    };
    let open_arc = match lookup_open(&tree_arc, req.file_id).await {
        Some(o) => o,
        None => return HandlerResponse::err(ntstatus::STATUS_FILE_CLOSED),
    };
    let is_ipc = {
        let tree = tree_arc.read().await;
        tree.share.is_ipc
    };
    {
        let open = open_arc.read().await;
        if open.desired_access & (FILE_READ_DATA | FILE_EXECUTE) == 0 {
            return HandlerResponse::err(ntstatus::STATUS_ACCESS_DENIED);
        }
        if is_ipc {
            return begin_pending_pipe_read(server, conn, hdr, req.file_id).await;
        }
        if open.is_directory {
            return HandlerResponse::err(ntstatus::STATUS_INVALID_DEVICE_REQUEST);
        }
    }
    if !valid_read_offset(req.offset, req.length) {
        return HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER);
    }
    let status = {
        let tree = tree_arc.read().await;
        let open = open_arc.read().await;
        server.check_read_lock(
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

    let result = {
        let open = open_arc.read().await;
        match open.handle.as_ref() {
            Some(h) => h.read(req.offset, req.length).await,
            None => return HandlerResponse::err(ntstatus::STATUS_FILE_CLOSED),
        }
    };
    let bytes = match result {
        Ok(b) => b,
        Err(e) => return HandlerResponse::err(e.to_nt_status()),
    };
    if bytes.len() < req.minimum_count as usize {
        return HandlerResponse::err(ntstatus::STATUS_END_OF_FILE);
    }
    if bytes.is_empty() && req.length > 0 {
        return HandlerResponse::err(ntstatus::STATUS_END_OF_FILE);
    }
    if req.length > 0 {
        open_arc.write().await.current_offset = req.offset + bytes.len() as u64;
    }
    let resp = ReadResponse {
        structure_size: 17,
        data_offset: ReadResponse::STANDARD_DATA_OFFSET,
        reserved: 0,
        data_length: bytes.len() as u32,
        data_remaining: 0,
        flags: 0,
        data: bytes.to_vec(),
    };
    let mut buf = Vec::new();
    resp.write_to(&mut buf).expect("encode");
    HandlerResponse::ok(buf)
}

async fn begin_pending_pipe_read(
    server: &Arc<ServerState>,
    conn: &Arc<Connection>,
    hdr: &Smb2Header,
    file_id: crate::proto::messages::FileId,
) -> HandlerResponse {
    let Some(tx) = conn.async_sender().await else {
        return HandlerResponse::err(ntstatus::STATUS_NOT_SUPPORTED);
    };
    if !server.reserve_pipe_read_async_slot(conn) {
        return HandlerResponse::err(ntstatus::STATUS_INSUFFICIENT_RESOURCES);
    }
    let async_id = conn.alloc_async_id();
    server.register_pipe_read(async_id, conn, tx, *hdr, file_id);
    HandlerResponse::pending_async(
        async_id,
        HandlerResponse::err(ntstatus::STATUS_PENDING).body,
    )
}

fn valid_read_offset(offset: u64, length: u32) -> bool {
    const MAX_INT64_OFFSET: u64 = (1u64 << 63) - 1;
    if offset > MAX_INT64_OFFSET {
        return false;
    }
    length == 0 || offset < MAX_INT64_OFFSET
}
