//! OPLOCK_BREAK handler — acknowledge oplock and lease breaks.

use std::sync::Arc;

use crate::proto::header::Smb2Header;
use crate::proto::messages::{
    LeaseBreakAck, LeaseBreakResponse, OplockBreakAck, OplockBreakNotification, OplockLevel,
};

use crate::conn::state::Connection;
use crate::dispatch::HandlerResponse;
use crate::ntstatus;
use crate::server::ServerState;

const LEASE_READ_CACHING: u32 = 0x0000_0001;
const LEASE_HANDLE_CACHING: u32 = 0x0000_0002;
const LEASE_WRITE_CACHING: u32 = 0x0000_0004;

pub async fn handle(
    server: &Arc<ServerState>,
    conn: &Arc<Connection>,
    _hdr: &Smb2Header,
    body: &[u8],
) -> HandlerResponse {
    if body.len() < 2 {
        return HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER);
    }
    match u16::from_le_bytes(body[0..2].try_into().unwrap()) {
        24 => acknowledge_oplock_break(server, conn, body).await,
        36 => acknowledge_lease_break(server, body).await,
        _ => HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER),
    }
}

async fn acknowledge_oplock_break(
    server: &Arc<ServerState>,
    conn: &Arc<Connection>,
    body: &[u8],
) -> HandlerResponse {
    let Ok(ack) = OplockBreakAck::parse(body) else {
        return HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER);
    };
    if !valid_oplock_ack_level(ack.oplock_level) {
        return HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER);
    }
    let status = server
        .acknowledge_oplock_break(conn, ack.file_id, ack.oplock_level)
        .await;
    if status != ntstatus::STATUS_SUCCESS {
        return HandlerResponse::err(status);
    }
    let response = OplockBreakNotification {
        structure_size: 24,
        oplock_level: ack.oplock_level,
        reserved: 0,
        reserved2: 0,
        file_id: ack.file_id,
    };
    let mut buf = Vec::new();
    response
        .write_to(&mut buf)
        .expect("encode oplock break response");
    HandlerResponse::ok(buf)
}

async fn acknowledge_lease_break(server: &Arc<ServerState>, body: &[u8]) -> HandlerResponse {
    let Ok(ack) = LeaseBreakAck::parse(body) else {
        return HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER);
    };
    if !valid_lease_state(ack.lease_state) {
        return HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER);
    }
    let status = server
        .acknowledge_lease_break(ack.lease_key, ack.lease_state)
        .await;
    if status != ntstatus::STATUS_SUCCESS {
        return HandlerResponse::err(status);
    }
    let response = LeaseBreakResponse {
        structure_size: 36,
        reserved: 0,
        flags: 0,
        lease_key: ack.lease_key,
        lease_state: ack.lease_state,
        lease_duration: 0,
    };
    let mut buf = Vec::new();
    response
        .write_to(&mut buf)
        .expect("encode lease break response");
    HandlerResponse::ok(buf)
}

fn valid_oplock_ack_level(level: u8) -> bool {
    matches!(
        level,
        level if level == OplockLevel::None as u8
            || level == OplockLevel::Ii as u8
            || level == OplockLevel::Exclusive as u8
    )
}

fn valid_lease_state(state: u32) -> bool {
    state & !(LEASE_READ_CACHING | LEASE_HANDLE_CACHING | LEASE_WRITE_CACHING) == 0
}
