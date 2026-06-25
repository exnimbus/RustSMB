#![allow(clippy::too_many_arguments)]

mod common;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use common::{
    STATUS_SUCCESS, anonymous_session_setup, anonymous_session_setup_with_previous, build_header,
    negotiate, parse_response_header, read_frame, tree_connect, utf16le, write_frame,
};
use smb_server::wire::header::{
    Command, HeaderTail, SMB2_FLAGS_ASYNC_COMMAND, SMB2_FLAGS_REPLAY_OPERATION, Smb2Header,
};
use smb_server::wire::messages::{
    CancelRequest, CloseRequest, CloseResponse, CreateContext, CreateRequest, CreateResponse,
    Fsctl, InfoType, IoctlRequest, IoctlResponse, LeaseBreakAck, LeaseBreakNotification,
    LeaseBreakResponse, LockElement, LockRequest, LockResponse, LogoffRequest, LogoffResponse,
    NegotiateContext, NegotiateRequest, NegotiateResponse, OplockBreakAck,
    PreauthIntegrityCapabilities, QueryInfoRequest, QueryInfoResponse, ReadRequest, ReadResponse,
    SetInfoRequest, SetInfoResponse, TreeDisconnectRequest, TreeDisconnectResponse, WriteRequest,
    WriteResponse,
};
use smb_server::{LocalFsBackend, Share, SmbServer};
use tempfile::tempdir;
use tokio::net::TcpStream;

const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_UNSUCCESSFUL: u32 = 0xC000_0001;
const STATUS_FILE_LOCK_CONFLICT: u32 = 0xC000_0054;
const STATUS_LOCK_NOT_GRANTED: u32 = 0xC000_0055;
const STATUS_OBJECT_NAME_NOT_FOUND: u32 = 0xC000_0034;
const STATUS_RANGE_NOT_LOCKED: u32 = 0xC000_007E;
const STATUS_PENDING: u32 = 0x0000_0103;
const STATUS_NOTIFY_CLEANUP: u32 = 0x0000_010B;
const STATUS_ACCESS_DENIED: u32 = 0xC000_0022;
const STATUS_CANCELLED: u32 = 0xC000_0120;
const STATUS_INVALID_LOCK_RANGE: u32 = 0xC000_01A1;
const STATUS_DUPLICATE_OBJECTID: u32 = 0xC000_022A;
const STATUS_FILE_CLOSED: u32 = 0xC000_0128;
const STATUS_FILE_NOT_AVAILABLE: u32 = 0xC000_0467;
const STATUS_INVALID_OPLOCK_PROTOCOL: u32 = 0xC000_00E3;
const STATUS_REQUEST_NOT_ACCEPTED: u32 = 0xC000_00D0;
const STATUS_SHARING_VIOLATION: u32 = 0xC000_0043;
const STATUS_DELETE_PENDING: u32 = 0xC000_0056;
const STATUS_USER_SESSION_DELETED: u32 = 0xC000_0203;

#[tokio::test]
async fn byte_range_locks_block_conflicting_io_and_release_on_close() {
    let td = tempdir().expect("tempdir");
    std::fs::write(td.path().join("hello.txt"), b"hello world").expect("seed file");
    let backend = LocalFsBackend::new(td.path()).expect("open root");
    let server = SmbServer::builder()
        .listen("127.0.0.1:0".parse().unwrap())
        .share(Share::new("share", backend).public())
        .netbios_name("TESTSERVER")
        .build()
        .expect("build");

    server.bind().await.expect("bind");
    let addr = server.local_addr().await.expect("addr");
    let handle = tokio::spawn(async move { server.serve().await });
    tokio::task::yield_now().await;

    let mut s = TcpStream::connect(addr).await.expect("connect");
    let _ = negotiate(&mut s).await;
    let session_id = anonymous_session_setup(&mut s).await;
    let tree_id = tree_connect(&mut s, "\\\\127.0.0.1\\share", session_id, 3).await;

    let owner = create_rw(&mut s, session_id, tree_id, 4).await;
    let other = create_rw(&mut s, session_id, tree_id, 5).await;

    lock(
        &mut s,
        session_id,
        tree_id,
        6,
        owner,
        2,
        4,
        LockElement::FLAG_EXCLUSIVE_LOCK,
        STATUS_SUCCESS,
    )
    .await;
    read(
        &mut s,
        session_id,
        tree_id,
        7,
        other,
        2,
        3,
        STATUS_FILE_LOCK_CONFLICT,
    )
    .await;
    write(
        &mut s,
        session_id,
        tree_id,
        8,
        other,
        3,
        b"x",
        STATUS_FILE_LOCK_CONFLICT,
    )
    .await;
    lock(
        &mut s,
        session_id,
        tree_id,
        9,
        other,
        3,
        1,
        LockElement::FLAG_SHARED_LOCK | LockElement::FLAG_FAIL_IMMEDIATELY,
        STATUS_LOCK_NOT_GRANTED,
    )
    .await;
    read(&mut s, session_id, tree_id, 10, other, 6, 2, STATUS_SUCCESS).await;

    lock(
        &mut s,
        session_id,
        tree_id,
        11,
        owner,
        2,
        4,
        LockElement::FLAG_UNLOCK,
        STATUS_SUCCESS,
    )
    .await;
    write(
        &mut s,
        session_id,
        tree_id,
        12,
        other,
        3,
        b"x",
        STATUS_SUCCESS,
    )
    .await;

    lock(
        &mut s,
        session_id,
        tree_id,
        13,
        owner,
        2,
        4,
        LockElement::FLAG_UNLOCK,
        STATUS_RANGE_NOT_LOCKED,
    )
    .await;
    lock(
        &mut s,
        session_id,
        tree_id,
        14,
        owner,
        u64::MAX,
        u64::MAX,
        LockElement::FLAG_EXCLUSIVE_LOCK | LockElement::FLAG_FAIL_IMMEDIATELY,
        STATUS_INVALID_LOCK_RANGE,
    )
    .await;
    lock(
        &mut s,
        session_id,
        tree_id,
        15,
        owner,
        0,
        1,
        LockElement::FLAG_SHARED_LOCK | LockElement::FLAG_EXCLUSIVE_LOCK,
        STATUS_INVALID_PARAMETER,
    )
    .await;

    lock(
        &mut s,
        session_id,
        tree_id,
        16,
        owner,
        2,
        4,
        LockElement::FLAG_EXCLUSIVE_LOCK,
        STATUS_SUCCESS,
    )
    .await;
    close(&mut s, session_id, tree_id, 17, owner).await;
    write(
        &mut s,
        session_id,
        tree_id,
        18,
        other,
        3,
        b"y",
        STATUS_SUCCESS,
    )
    .await;
    close(&mut s, session_id, tree_id, 19, other).await;

    drop(s);
    handle.abort();
}

#[tokio::test]
async fn shared_byte_range_lock_allows_shared_lock_and_read_but_blocks_writes() {
    let (handle, mut s, session_id, tree_id) = setup_lock_server().await;
    let owner = create_rw(&mut s, session_id, tree_id, 4).await;
    let other = create_rw(&mut s, session_id, tree_id, 5).await;

    lock(
        &mut s,
        session_id,
        tree_id,
        6,
        owner,
        2,
        4,
        LockElement::FLAG_SHARED_LOCK,
        STATUS_SUCCESS,
    )
    .await;
    lock(
        &mut s,
        session_id,
        tree_id,
        7,
        other,
        3,
        1,
        LockElement::FLAG_SHARED_LOCK,
        STATUS_SUCCESS,
    )
    .await;
    read(&mut s, session_id, tree_id, 8, other, 2, 3, STATUS_SUCCESS).await;
    write(
        &mut s,
        session_id,
        tree_id,
        9,
        other,
        3,
        b"x",
        STATUS_FILE_LOCK_CONFLICT,
    )
    .await;
    write(
        &mut s,
        session_id,
        tree_id,
        10,
        owner,
        3,
        b"x",
        STATUS_FILE_LOCK_CONFLICT,
    )
    .await;
    lock(
        &mut s,
        session_id,
        tree_id,
        11,
        other,
        3,
        1,
        LockElement::FLAG_EXCLUSIVE_LOCK | LockElement::FLAG_FAIL_IMMEDIATELY,
        STATUS_LOCK_NOT_GRANTED,
    )
    .await;

    close(&mut s, session_id, tree_id, 12, owner).await;
    close(&mut s, session_id, tree_id, 13, other).await;
    drop(s);
    handle.abort();
}

#[tokio::test]
async fn byte_range_lock_breaks_own_level_ii_oplock_when_other_handle_open() {
    let (handle, mut s, session_id, tree_id) = setup_lock_server_smb311().await;

    let first = create_oplock_open(&mut s, session_id, tree_id, 4, 0x09, 0x001f_01ff).await;
    assert_eq!(first.oplock_level, 0x09);

    send_create_oplock_open(&mut s, session_id, tree_id, 5, 0, 0x001f_01ff).await;
    let frames = [read_frame(&mut s).await, read_frame(&mut s).await];
    let mut pending_async_id = None;
    let mut notification = None;
    for frame in frames {
        let (rh, rb) = parse_response_header(&frame);
        match rh.command {
            Command::Create => {
                assert_eq!(rh.channel_sequence_status, STATUS_PENDING);
                pending_async_id = Some(rh.async_id().expect("pending create async id"));
            }
            Command::OplockBreak => {
                assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
                notification = Some(OplockBreakAck::parse(rb).expect("parse oplock break"));
            }
            other => panic!("unexpected response command {other:?}"),
        }
    }

    let pending_async_id = pending_async_id.expect("missing pending create");
    let notification = notification.expect("missing batch-to-level-II oplock break");
    assert_eq!(notification.oplock_level, 0x01);
    assert_eq!(notification.file_id, first.file_id);

    let ack = OplockBreakAck {
        structure_size: 24,
        oplock_level: 0x01,
        reserved: 0,
        reserved2: 0,
        file_id: first.file_id,
    };
    let mut body = Vec::new();
    ack.write_to(&mut body).expect("write oplock break ack");
    let hdr = build_header(Command::OplockBreak, 6, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;

    let frames = [read_frame(&mut s).await, read_frame(&mut s).await];
    let mut ack_seen = false;
    let mut second = None;
    for frame in frames {
        let (rh, rb) = parse_response_header(&frame);
        match rh.command {
            Command::OplockBreak => {
                assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
                let ack = OplockBreakAck::parse(rb).expect("parse oplock break ack response");
                assert_eq!(ack.oplock_level, 0x01);
                assert_eq!(ack.file_id, first.file_id);
                ack_seen = true;
            }
            Command::Create => {
                assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
                assert_eq!(rh.async_id(), Some(pending_async_id));
                second = Some(CreateResponse::parse(rb).expect("parse final create"));
            }
            other => panic!("unexpected post-ack response command {other:?}"),
        }
    }
    assert!(ack_seen, "missing oplock break ack response");
    let second = second.expect("missing final create response");
    assert_eq!(second.oplock_level, 0);

    let req = LockRequest {
        structure_size: 48,
        lock_count: 1,
        lock_sequence: 0,
        file_id: first.file_id,
        locks: vec![LockElement {
            offset: 0,
            length: 4,
            flags: LockElement::FLAG_EXCLUSIVE_LOCK | LockElement::FLAG_FAIL_IMMEDIATELY,
            reserved: 0,
        }],
    };
    let mut body = Vec::new();
    req.write_to(&mut body).expect("write lock");
    let hdr = build_header(Command::Lock, 7, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;

    let frames = [read_frame(&mut s).await, read_frame(&mut s).await];
    let mut lock_seen = false;
    let mut break_seen = false;
    for frame in frames {
        let (rh, rb) = parse_response_header(&frame);
        match rh.command {
            Command::Lock => {
                assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
                let _ = LockResponse::parse(rb).expect("parse lock response");
                lock_seen = true;
            }
            Command::OplockBreak => {
                assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
                let notification = OplockBreakAck::parse(rb).expect("parse level-II break");
                assert_eq!(notification.oplock_level, 0);
                assert_eq!(notification.file_id, first.file_id);
                break_seen = true;
            }
            other => panic!("unexpected lock response command {other:?}"),
        }
    }
    assert!(lock_seen, "missing lock response");
    assert!(break_seen, "missing level-II-to-none oplock break");

    let ack = OplockBreakAck {
        structure_size: 24,
        oplock_level: 0,
        reserved: 0,
        reserved2: 0,
        file_id: first.file_id,
    };
    let mut body = Vec::new();
    ack.write_to(&mut body)
        .expect("write no-ack oplock break ack");
    let hdr = build_header(Command::OplockBreak, 8, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, _rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::OplockBreak);
    assert_eq!(rh.channel_sequence_status, STATUS_INVALID_OPLOCK_PROTOCOL);

    close(&mut s, session_id, tree_id, 9, second.file_id).await;
    close(&mut s, session_id, tree_id, 10, first.file_id).await;
    drop(s);
    handle.abort();
}

#[tokio::test]
async fn stacked_same_handle_locks_require_multiple_unlocks() {
    let (handle, mut s, session_id, tree_id) = setup_lock_server().await;
    let file_id = create_rw(&mut s, session_id, tree_id, 4).await;

    lock(
        &mut s,
        session_id,
        tree_id,
        5,
        file_id,
        2,
        4,
        LockElement::FLAG_EXCLUSIVE_LOCK | LockElement::FLAG_FAIL_IMMEDIATELY,
        STATUS_SUCCESS,
    )
    .await;
    lock(
        &mut s,
        session_id,
        tree_id,
        6,
        file_id,
        2,
        4,
        LockElement::FLAG_SHARED_LOCK,
        STATUS_SUCCESS,
    )
    .await;
    lock(
        &mut s,
        session_id,
        tree_id,
        7,
        file_id,
        2,
        4,
        LockElement::FLAG_SHARED_LOCK,
        STATUS_SUCCESS,
    )
    .await;

    for message_id in 8..=10 {
        lock(
            &mut s,
            session_id,
            tree_id,
            message_id,
            file_id,
            2,
            4,
            LockElement::FLAG_UNLOCK,
            STATUS_SUCCESS,
        )
        .await;
    }
    lock(
        &mut s,
        session_id,
        tree_id,
        11,
        file_id,
        2,
        4,
        LockElement::FLAG_UNLOCK,
        STATUS_RANGE_NOT_LOCKED,
    )
    .await;

    close(&mut s, session_id, tree_id, 12, file_id).await;
    drop(s);
    handle.abort();
}

#[tokio::test]
async fn unlock_requires_exact_owned_range() {
    let (handle, mut s, session_id, tree_id) = setup_lock_server().await;
    let file_id = create_rw(&mut s, session_id, tree_id, 4).await;

    lock(
        &mut s,
        session_id,
        tree_id,
        5,
        file_id,
        2,
        4,
        LockElement::FLAG_EXCLUSIVE_LOCK,
        STATUS_SUCCESS,
    )
    .await;
    lock(
        &mut s,
        session_id,
        tree_id,
        6,
        file_id,
        2,
        2,
        LockElement::FLAG_UNLOCK,
        STATUS_RANGE_NOT_LOCKED,
    )
    .await;
    lock(
        &mut s,
        session_id,
        tree_id,
        7,
        file_id,
        2,
        4,
        LockElement::FLAG_UNLOCK,
        STATUS_SUCCESS,
    )
    .await;
    lock(
        &mut s,
        session_id,
        tree_id,
        8,
        file_id,
        2,
        4,
        LockElement::FLAG_UNLOCK,
        STATUS_RANGE_NOT_LOCKED,
    )
    .await;

    close(&mut s, session_id, tree_id, 9, file_id).await;
    drop(s);
    handle.abort();
}

#[tokio::test]
async fn unlock_rejects_fail_immediately_flag_without_releasing_lock() {
    let (handle, mut s, session_id, tree_id) = setup_lock_server().await;
    let owner = create_rw(&mut s, session_id, tree_id, 4).await;
    let other = create_rw(&mut s, session_id, tree_id, 5).await;

    lock(
        &mut s,
        session_id,
        tree_id,
        6,
        owner,
        2,
        4,
        LockElement::FLAG_EXCLUSIVE_LOCK,
        STATUS_SUCCESS,
    )
    .await;
    write(
        &mut s,
        session_id,
        tree_id,
        7,
        other,
        3,
        b"x",
        STATUS_FILE_LOCK_CONFLICT,
    )
    .await;
    lock(
        &mut s,
        session_id,
        tree_id,
        8,
        owner,
        2,
        4,
        LockElement::FLAG_UNLOCK | LockElement::FLAG_FAIL_IMMEDIATELY,
        STATUS_INVALID_PARAMETER,
    )
    .await;
    write(
        &mut s,
        session_id,
        tree_id,
        9,
        other,
        3,
        b"x",
        STATUS_FILE_LOCK_CONFLICT,
    )
    .await;
    lock(
        &mut s,
        session_id,
        tree_id,
        10,
        owner,
        2,
        4,
        LockElement::FLAG_UNLOCK,
        STATUS_SUCCESS,
    )
    .await;
    write(
        &mut s,
        session_id,
        tree_id,
        11,
        other,
        3,
        b"x",
        STATUS_SUCCESS,
    )
    .await;

    close(&mut s, session_id, tree_id, 12, owner).await;
    close(&mut s, session_id, tree_id, 13, other).await;
    drop(s);
    handle.abort();
}

#[tokio::test]
async fn lock_rejects_unknown_file_id() {
    let (handle, mut s, session_id, tree_id) = setup_lock_server().await;
    let missing = smb_server::wire::messages::FileId::new(1, 404);

    lock(
        &mut s,
        session_id,
        tree_id,
        4,
        missing,
        0,
        10,
        LockElement::FLAG_EXCLUSIVE_LOCK,
        STATUS_FILE_CLOSED,
    )
    .await;

    drop(s);
    handle.abort();
}

#[tokio::test]
async fn invalid_lock_ranges_match_gosmb_boundaries() {
    let (handle, mut s, session_id, tree_id) = setup_lock_server().await;
    let file_id = create_rw(&mut s, session_id, tree_id, 4).await;
    let other_id = create_rw(&mut s, session_id, tree_id, 5).await;

    lock(
        &mut s,
        session_id,
        tree_id,
        6,
        file_id,
        u64::MAX,
        u64::MAX,
        LockElement::FLAG_EXCLUSIVE_LOCK | LockElement::FLAG_FAIL_IMMEDIATELY,
        STATUS_INVALID_LOCK_RANGE,
    )
    .await;
    lock(
        &mut s,
        session_id,
        tree_id,
        7,
        file_id,
        u64::MAX,
        1,
        LockElement::FLAG_EXCLUSIVE_LOCK | LockElement::FLAG_FAIL_IMMEDIATELY,
        STATUS_SUCCESS,
    )
    .await;
    lock(
        &mut s,
        session_id,
        tree_id,
        8,
        other_id,
        u64::MAX,
        1,
        LockElement::FLAG_EXCLUSIVE_LOCK | LockElement::FLAG_FAIL_IMMEDIATELY,
        STATUS_LOCK_NOT_GRANTED,
    )
    .await;
    lock(
        &mut s,
        session_id,
        tree_id,
        9,
        file_id,
        u64::MAX,
        1,
        LockElement::FLAG_UNLOCK,
        STATUS_SUCCESS,
    )
    .await;
    lock(
        &mut s,
        session_id,
        tree_id,
        10,
        file_id,
        u64::MAX,
        2,
        LockElement::FLAG_EXCLUSIVE_LOCK | LockElement::FLAG_FAIL_IMMEDIATELY,
        STATUS_INVALID_LOCK_RANGE,
    )
    .await;

    close(&mut s, session_id, tree_id, 11, other_id).await;
    close(&mut s, session_id, tree_id, 12, file_id).await;
    drop(s);
    handle.abort();
}

#[tokio::test]
async fn zero_length_locks_can_stack_and_only_conflict_when_range_crosses_point() {
    let (handle, mut s, session_id, tree_id) = setup_lock_server().await;
    let owner = create_rw(&mut s, session_id, tree_id, 4).await;
    let other = create_rw(&mut s, session_id, tree_id, 5).await;

    lock(
        &mut s,
        session_id,
        tree_id,
        6,
        owner,
        10,
        0,
        LockElement::FLAG_EXCLUSIVE_LOCK | LockElement::FLAG_FAIL_IMMEDIATELY,
        STATUS_SUCCESS,
    )
    .await;
    lock(
        &mut s,
        session_id,
        tree_id,
        7,
        owner,
        10,
        0,
        LockElement::FLAG_SHARED_LOCK | LockElement::FLAG_FAIL_IMMEDIATELY,
        STATUS_SUCCESS,
    )
    .await;
    lock(
        &mut s,
        session_id,
        tree_id,
        8,
        other,
        10,
        1,
        LockElement::FLAG_EXCLUSIVE_LOCK | LockElement::FLAG_FAIL_IMMEDIATELY,
        STATUS_SUCCESS,
    )
    .await;
    lock(
        &mut s,
        session_id,
        tree_id,
        9,
        other,
        10,
        1,
        LockElement::FLAG_UNLOCK,
        STATUS_SUCCESS,
    )
    .await;
    lock(
        &mut s,
        session_id,
        tree_id,
        10,
        other,
        5,
        10,
        LockElement::FLAG_EXCLUSIVE_LOCK | LockElement::FLAG_FAIL_IMMEDIATELY,
        STATUS_LOCK_NOT_GRANTED,
    )
    .await;
    lock(
        &mut s,
        session_id,
        tree_id,
        11,
        other,
        5,
        10,
        LockElement::FLAG_SHARED_LOCK | LockElement::FLAG_FAIL_IMMEDIATELY,
        STATUS_LOCK_NOT_GRANTED,
    )
    .await;
    lock(
        &mut s,
        session_id,
        tree_id,
        12,
        other,
        10,
        0,
        LockElement::FLAG_EXCLUSIVE_LOCK | LockElement::FLAG_FAIL_IMMEDIATELY,
        STATUS_SUCCESS,
    )
    .await;
    lock(
        &mut s,
        session_id,
        tree_id,
        13,
        other,
        10,
        0,
        LockElement::FLAG_UNLOCK,
        STATUS_SUCCESS,
    )
    .await;
    lock(
        &mut s,
        session_id,
        tree_id,
        14,
        owner,
        10,
        0,
        LockElement::FLAG_UNLOCK,
        STATUS_SUCCESS,
    )
    .await;
    lock(
        &mut s,
        session_id,
        tree_id,
        15,
        owner,
        10,
        0,
        LockElement::FLAG_UNLOCK,
        STATUS_SUCCESS,
    )
    .await;
    lock(
        &mut s,
        session_id,
        tree_id,
        16,
        owner,
        10,
        0,
        LockElement::FLAG_UNLOCK,
        STATUS_RANGE_NOT_LOCKED,
    )
    .await;

    close(&mut s, session_id, tree_id, 17, owner).await;
    close(&mut s, session_id, tree_id, 18, other).await;
    drop(s);
    handle.abort();
}

#[tokio::test]
async fn exclusive_lock_on_same_handle_conflicts_but_shared_can_stack() {
    let (handle, mut s, session_id, tree_id) = setup_lock_server().await;
    let file_id = create_rw(&mut s, session_id, tree_id, 4).await;

    lock(
        &mut s,
        session_id,
        tree_id,
        5,
        file_id,
        0,
        1,
        LockElement::FLAG_EXCLUSIVE_LOCK | LockElement::FLAG_FAIL_IMMEDIATELY,
        STATUS_SUCCESS,
    )
    .await;
    lock(
        &mut s,
        session_id,
        tree_id,
        6,
        file_id,
        0,
        1,
        LockElement::FLAG_EXCLUSIVE_LOCK | LockElement::FLAG_FAIL_IMMEDIATELY,
        STATUS_LOCK_NOT_GRANTED,
    )
    .await;
    lock(
        &mut s,
        session_id,
        tree_id,
        7,
        file_id,
        0,
        1,
        LockElement::FLAG_SHARED_LOCK,
        STATUS_SUCCESS,
    )
    .await;
    lock(
        &mut s,
        session_id,
        tree_id,
        8,
        file_id,
        10,
        1,
        LockElement::FLAG_SHARED_LOCK | LockElement::FLAG_FAIL_IMMEDIATELY,
        STATUS_SUCCESS,
    )
    .await;
    lock(
        &mut s,
        session_id,
        tree_id,
        9,
        file_id,
        10,
        1,
        LockElement::FLAG_EXCLUSIVE_LOCK | LockElement::FLAG_FAIL_IMMEDIATELY,
        STATUS_LOCK_NOT_GRANTED,
    )
    .await;

    close(&mut s, session_id, tree_id, 10, file_id).await;
    drop(s);
    handle.abort();
}

#[tokio::test]
async fn invalid_lock_flags_and_multi_lock_fail_immediately_rules() {
    let (handle, mut s, session_id, tree_id) = setup_lock_server().await;
    let file_id = create_rw(&mut s, session_id, tree_id, 4).await;

    lock(
        &mut s,
        session_id,
        tree_id,
        5,
        file_id,
        0,
        1,
        LockElement::FLAG_SHARED_LOCK | LockElement::FLAG_EXCLUSIVE_LOCK,
        STATUS_INVALID_PARAMETER,
    )
    .await;
    lock_elements(
        &mut s,
        session_id,
        tree_id,
        6,
        file_id,
        &[
            (0, 1, LockElement::FLAG_SHARED_LOCK),
            (2, 1, LockElement::FLAG_SHARED_LOCK),
        ],
        STATUS_INVALID_PARAMETER,
    )
    .await;
    lock_elements(
        &mut s,
        session_id,
        tree_id,
        7,
        file_id,
        &[
            (
                0,
                1,
                LockElement::FLAG_SHARED_LOCK | LockElement::FLAG_FAIL_IMMEDIATELY,
            ),
            (
                2,
                1,
                LockElement::FLAG_SHARED_LOCK | LockElement::FLAG_FAIL_IMMEDIATELY,
            ),
        ],
        STATUS_SUCCESS,
    )
    .await;

    close(&mut s, session_id, tree_id, 8, file_id).await;
    drop(s);
    handle.abort();
}

#[tokio::test]
async fn mixed_unlock_request_keeps_prior_unlocks_before_invalid_element() {
    let (handle, mut s, session_id, tree_id) = setup_lock_server().await;
    let owner = create_rw(&mut s, session_id, tree_id, 4).await;
    let other = create_rw(&mut s, session_id, tree_id, 5).await;

    lock(
        &mut s,
        session_id,
        tree_id,
        6,
        owner,
        0,
        2,
        LockElement::FLAG_EXCLUSIVE_LOCK,
        STATUS_SUCCESS,
    )
    .await;
    lock(
        &mut s,
        session_id,
        tree_id,
        7,
        owner,
        4,
        2,
        LockElement::FLAG_EXCLUSIVE_LOCK,
        STATUS_SUCCESS,
    )
    .await;
    lock_elements(
        &mut s,
        session_id,
        tree_id,
        8,
        owner,
        &[
            (0, 2, LockElement::FLAG_UNLOCK),
            (4, 2, LockElement::FLAG_EXCLUSIVE_LOCK),
        ],
        STATUS_INVALID_PARAMETER,
    )
    .await;
    write(
        &mut s,
        session_id,
        tree_id,
        9,
        other,
        0,
        b"x",
        STATUS_SUCCESS,
    )
    .await;
    write(
        &mut s,
        session_id,
        tree_id,
        10,
        other,
        4,
        b"x",
        STATUS_FILE_LOCK_CONFLICT,
    )
    .await;

    close(&mut s, session_id, tree_id, 11, owner).await;
    close(&mut s, session_id, tree_id, 12, other).await;
    drop(s);
    handle.abort();
}

#[tokio::test]
async fn invalid_mixed_lock_request_does_not_apply_earlier_locks() {
    let (handle, mut s, session_id, tree_id) = setup_lock_server().await;
    let owner = create_rw(&mut s, session_id, tree_id, 4).await;
    let other = create_rw(&mut s, session_id, tree_id, 5).await;

    lock_elements(
        &mut s,
        session_id,
        tree_id,
        6,
        owner,
        &[
            (
                0,
                2,
                LockElement::FLAG_EXCLUSIVE_LOCK | LockElement::FLAG_FAIL_IMMEDIATELY,
            ),
            (
                4,
                2,
                LockElement::FLAG_UNLOCK | LockElement::FLAG_FAIL_IMMEDIATELY,
            ),
        ],
        STATUS_INVALID_PARAMETER,
    )
    .await;
    write(
        &mut s,
        session_id,
        tree_id,
        7,
        other,
        0,
        b"x",
        STATUS_SUCCESS,
    )
    .await;
    write(
        &mut s,
        session_id,
        tree_id,
        8,
        other,
        4,
        b"x",
        STATUS_SUCCESS,
    )
    .await;

    close(&mut s, session_id, tree_id, 9, owner).await;
    close(&mut s, session_id, tree_id, 10, other).await;
    drop(s);
    handle.abort();
}

#[tokio::test]
async fn blocking_lock_waits_and_completes_after_unlock() {
    let (handle, mut s, session_id, tree_id) = setup_lock_server().await;
    let owner = create_rw(&mut s, session_id, tree_id, 4).await;
    let other = create_rw(&mut s, session_id, tree_id, 5).await;

    lock(
        &mut s,
        session_id,
        tree_id,
        6,
        owner,
        2,
        4,
        LockElement::FLAG_EXCLUSIVE_LOCK,
        STATUS_SUCCESS,
    )
    .await;
    let pending = send_lock(
        &mut s,
        session_id,
        tree_id,
        7,
        other,
        2,
        4,
        LockElement::FLAG_EXCLUSIVE_LOCK,
    )
    .await;
    assert_eq!(pending.channel_sequence_status, STATUS_PENDING);
    assert!(pending.is_async());
    let async_id = pending.async_id().expect("async id");

    write_lock(
        &mut s,
        session_id,
        tree_id,
        8,
        owner,
        2,
        4,
        LockElement::FLAG_UNLOCK,
    )
    .await;
    let mut saw_unlock = false;
    let mut saw_final = false;
    for _ in 0..2 {
        let resp = read_frame(&mut s).await;
        let (rh, rb) = parse_response_header(&resp);
        assert_eq!(rh.command, Command::Lock);
        assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
        if rh.is_async() {
            assert_eq!(rh.async_id(), Some(async_id));
            assert_eq!(rh.credit_request_response, 0);
            let _ = LockResponse::parse(rb).expect("parse final lock");
            saw_final = true;
        } else {
            let _ = LockResponse::parse(rb).expect("parse unlock");
            saw_unlock = true;
        }
    }
    assert!(saw_unlock, "missing unlock response");
    assert!(saw_final, "missing final lock response");

    close(&mut s, session_id, tree_id, 9, owner).await;
    close(&mut s, session_id, tree_id, 10, other).await;
    drop(s);
    handle.abort();
}

#[tokio::test]
async fn pending_lock_cancel_completes_cancelled() {
    let (handle, mut s, session_id, tree_id) = setup_lock_server().await;
    let owner = create_rw(&mut s, session_id, tree_id, 4).await;
    let other = create_rw(&mut s, session_id, tree_id, 5).await;

    lock(
        &mut s,
        session_id,
        tree_id,
        6,
        owner,
        2,
        4,
        LockElement::FLAG_EXCLUSIVE_LOCK,
        STATUS_SUCCESS,
    )
    .await;
    let pending = send_lock(
        &mut s,
        session_id,
        tree_id,
        7,
        other,
        2,
        4,
        LockElement::FLAG_EXCLUSIVE_LOCK,
    )
    .await;
    let async_id = pending.async_id().expect("async id");

    send_async_cancel(&mut s, 8, session_id, async_id).await;
    let final_resp = read_frame(&mut s).await;
    let (rh, _rb) = parse_response_header(&final_resp);
    assert_eq!(rh.command, Command::Lock);
    assert_eq!(rh.channel_sequence_status, STATUS_CANCELLED);
    assert_eq!(rh.async_id(), Some(async_id));
    assert_eq!(rh.credit_request_response, 0);

    close(&mut s, session_id, tree_id, 9, owner).await;
    close(&mut s, session_id, tree_id, 10, other).await;
    drop(s);
    handle.abort();
}

#[tokio::test]
async fn pending_lock_close_completes_range_not_locked() {
    let (handle, mut s, session_id, tree_id) = setup_lock_server().await;
    let owner = create_rw(&mut s, session_id, tree_id, 4).await;
    let other = create_rw(&mut s, session_id, tree_id, 5).await;

    lock(
        &mut s,
        session_id,
        tree_id,
        6,
        owner,
        2,
        4,
        LockElement::FLAG_EXCLUSIVE_LOCK,
        STATUS_SUCCESS,
    )
    .await;
    let pending = send_lock(
        &mut s,
        session_id,
        tree_id,
        7,
        other,
        2,
        4,
        LockElement::FLAG_EXCLUSIVE_LOCK,
    )
    .await;
    let async_id = pending.async_id().expect("async id");

    write_close(&mut s, session_id, tree_id, 8, other).await;
    let mut saw_close = false;
    let mut saw_final = false;
    for _ in 0..2 {
        let resp = read_frame(&mut s).await;
        let (rh, rb) = parse_response_header(&resp);
        match rh.command {
            Command::Close => {
                assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
                let _ = CloseResponse::parse(rb).expect("parse close");
                saw_close = true;
            }
            Command::Lock => {
                assert_eq!(rh.channel_sequence_status, STATUS_RANGE_NOT_LOCKED);
                assert_eq!(rh.async_id(), Some(async_id));
                assert_eq!(rh.credit_request_response, 0);
                saw_final = true;
            }
            other => panic!("unexpected response {other:?}"),
        }
    }
    assert!(saw_close, "missing close response");
    assert!(saw_final, "missing final lock response");

    close(&mut s, session_id, tree_id, 9, owner).await;
    drop(s);
    handle.abort();
}

#[tokio::test]
async fn resiliency_ioctl_enables_lock_sequence_duplicate_lock_replay() {
    let (handle, mut s, session_id, tree_id) = setup_lock_server().await;
    let owner = create_rw(&mut s, session_id, tree_id, 4).await;
    let other = create_rw(&mut s, session_id, tree_id, 5).await;

    lock_with_sequence(
        &mut s,
        session_id,
        tree_id,
        6,
        owner,
        1,
        3,
        2,
        4,
        LockElement::FLAG_EXCLUSIVE_LOCK | LockElement::FLAG_FAIL_IMMEDIATELY,
        STATUS_SUCCESS,
    )
    .await;
    lock_with_sequence(
        &mut s,
        session_id,
        tree_id,
        7,
        owner,
        1,
        3,
        2,
        4,
        LockElement::FLAG_EXCLUSIVE_LOCK | LockElement::FLAG_FAIL_IMMEDIATELY,
        STATUS_LOCK_NOT_GRANTED,
    )
    .await;
    lock(
        &mut s,
        session_id,
        tree_id,
        8,
        owner,
        2,
        4,
        LockElement::FLAG_UNLOCK,
        STATUS_SUCCESS,
    )
    .await;

    request_resiliency(&mut s, session_id, tree_id, 9, owner, 1_000).await;
    lock_with_sequence(
        &mut s,
        session_id,
        tree_id,
        10,
        owner,
        1,
        3,
        2,
        4,
        LockElement::FLAG_EXCLUSIVE_LOCK | LockElement::FLAG_FAIL_IMMEDIATELY,
        STATUS_SUCCESS,
    )
    .await;
    lock_with_sequence(
        &mut s,
        session_id,
        tree_id,
        11,
        owner,
        1,
        3,
        2,
        4,
        LockElement::FLAG_EXCLUSIVE_LOCK | LockElement::FLAG_FAIL_IMMEDIATELY,
        STATUS_SUCCESS,
    )
    .await;
    lock(
        &mut s,
        session_id,
        tree_id,
        12,
        owner,
        2,
        4,
        LockElement::FLAG_UNLOCK,
        STATUS_SUCCESS,
    )
    .await;
    write(
        &mut s,
        session_id,
        tree_id,
        13,
        other,
        3,
        b"x",
        STATUS_SUCCESS,
    )
    .await;
    lock(
        &mut s,
        session_id,
        tree_id,
        14,
        owner,
        2,
        4,
        LockElement::FLAG_UNLOCK,
        STATUS_RANGE_NOT_LOCKED,
    )
    .await;

    close(&mut s, session_id, tree_id, 15, owner).await;
    close(&mut s, session_id, tree_id, 16, other).await;
    drop(s);
    handle.abort();
}

#[tokio::test]
async fn resilient_lock_sequence_duplicate_unlock_is_idempotent() {
    let (handle, mut s, session_id, tree_id) = setup_lock_server().await;
    let owner = create_rw(&mut s, session_id, tree_id, 4).await;
    let other = create_rw(&mut s, session_id, tree_id, 5).await;

    request_resiliency(&mut s, session_id, tree_id, 6, owner, 1_000).await;
    lock(
        &mut s,
        session_id,
        tree_id,
        7,
        owner,
        2,
        4,
        LockElement::FLAG_EXCLUSIVE_LOCK,
        STATUS_SUCCESS,
    )
    .await;
    write(
        &mut s,
        session_id,
        tree_id,
        8,
        other,
        3,
        b"x",
        STATUS_FILE_LOCK_CONFLICT,
    )
    .await;
    lock_with_sequence(
        &mut s,
        session_id,
        tree_id,
        9,
        owner,
        4,
        8,
        2,
        4,
        LockElement::FLAG_UNLOCK,
        STATUS_SUCCESS,
    )
    .await;
    lock_with_sequence(
        &mut s,
        session_id,
        tree_id,
        10,
        owner,
        4,
        8,
        2,
        4,
        LockElement::FLAG_UNLOCK,
        STATUS_SUCCESS,
    )
    .await;
    write(
        &mut s,
        session_id,
        tree_id,
        11,
        other,
        3,
        b"x",
        STATUS_SUCCESS,
    )
    .await;
    lock(
        &mut s,
        session_id,
        tree_id,
        12,
        owner,
        2,
        4,
        LockElement::FLAG_UNLOCK,
        STATUS_RANGE_NOT_LOCKED,
    )
    .await;

    close(&mut s, session_id, tree_id, 13, owner).await;
    close(&mut s, session_id, tree_id, 14, other).await;
    drop(s);
    handle.abort();
}

#[tokio::test]
async fn durable_v1_batch_create_enables_lock_sequence_replay() {
    let (handle, mut s, session_id, tree_id) = setup_lock_server().await;
    let owner = create_durable_batch(&mut s, session_id, tree_id, 4).await;
    let other = create_rw(&mut s, session_id, tree_id, 5).await;

    lock_with_sequence(
        &mut s,
        session_id,
        tree_id,
        6,
        owner,
        9,
        3,
        2,
        4,
        LockElement::FLAG_EXCLUSIVE_LOCK | LockElement::FLAG_FAIL_IMMEDIATELY,
        STATUS_SUCCESS,
    )
    .await;
    lock_with_sequence(
        &mut s,
        session_id,
        tree_id,
        7,
        owner,
        9,
        3,
        2,
        4,
        LockElement::FLAG_EXCLUSIVE_LOCK | LockElement::FLAG_FAIL_IMMEDIATELY,
        STATUS_SUCCESS,
    )
    .await;
    lock(
        &mut s,
        session_id,
        tree_id,
        8,
        owner,
        2,
        4,
        LockElement::FLAG_UNLOCK,
        STATUS_SUCCESS,
    )
    .await;
    write(
        &mut s,
        session_id,
        tree_id,
        9,
        other,
        3,
        b"x",
        STATUS_SUCCESS,
    )
    .await;
    lock(
        &mut s,
        session_id,
        tree_id,
        10,
        owner,
        2,
        4,
        LockElement::FLAG_UNLOCK,
        STATUS_RANGE_NOT_LOCKED,
    )
    .await;

    close(&mut s, session_id, tree_id, 11, owner).await;
    close(&mut s, session_id, tree_id, 12, other).await;
    drop(s);
    handle.abort();
}

#[tokio::test]
async fn durable_v1_reconnect_fails_after_tree_disconnect() {
    let (handle, mut s, session_id, tree_id) = setup_lock_server().await;
    let file_id = create_durable_batch(&mut s, session_id, tree_id, 4).await;

    tree_disconnect(&mut s, session_id, tree_id, 5).await;
    let tree_id = tree_connect(&mut s, "\\\\127.0.0.1\\share", session_id, 6).await;
    let status = create_durable_reconnect_status(&mut s, session_id, tree_id, 7, file_id).await;
    assert_eq!(status, STATUS_OBJECT_NAME_NOT_FOUND);

    drop(s);
    handle.abort();
}

#[tokio::test]
async fn durable_v1_reconnect_with_bogus_fields_fails_after_tree_disconnect() {
    let (handle, mut s, session_id, tree_id) = setup_lock_server().await;
    let file_id = create_durable_batch(&mut s, session_id, tree_id, 4).await;

    tree_disconnect(&mut s, session_id, tree_id, 5).await;
    let tree_id = tree_connect(&mut s, "\\\\127.0.0.1\\share", session_id, 6).await;
    let status = create_durable_reconnect_status(&mut s, session_id, tree_id, 7, file_id).await;
    assert_eq!(status, STATUS_OBJECT_NAME_NOT_FOUND);

    drop(s);
    handle.abort();
}

#[tokio::test]
async fn durable_v2_batch_create_grants_durable_handle() {
    let (handle, mut s, session_id, tree_id) = setup_lock_server_smb311().await;
    let file_id = create_durable_v2_batch(&mut s, session_id, tree_id, 4).await;

    read(
        &mut s,
        session_id,
        tree_id,
        5,
        file_id,
        0,
        5,
        STATUS_SUCCESS,
    )
    .await;
    close(&mut s, session_id, tree_id, 6, file_id).await;

    drop(s);
    handle.abort();
}

#[tokio::test]
async fn durable_v2_batch_reconnect_fails_after_tree_disconnect() {
    let (handle, mut s, session_id, tree_id) = setup_lock_server_smb311().await;
    let file_id = create_durable_v2_batch(&mut s, session_id, tree_id, 4).await;

    tree_disconnect(&mut s, session_id, tree_id, 5).await;
    let tree_id = tree_connect(&mut s, "\\\\127.0.0.1\\share", session_id, 6).await;
    let status =
        create_durable_v2_batch_reconnect_status(&mut s, session_id, tree_id, 7, file_id).await;
    assert_eq!(status, STATUS_OBJECT_NAME_NOT_FOUND);

    drop(s);
    handle.abort();
}

#[tokio::test]
async fn durable_v2_batch_can_reconnect_with_v1_context_after_tcp_disconnect() {
    let (handle, addr, mut s, session_id, tree_id) = setup_lock_server_with_addr_smb311().await;
    let file_id = create_durable_v2_batch(&mut s, session_id, tree_id, 4).await;
    drop(s);
    tokio::time::sleep(Duration::from_millis(25)).await;

    let mut s = TcpStream::connect(addr).await.expect("reconnect tcp");
    let _ = negotiate_smb311(&mut s).await;
    let session_id = anonymous_session_setup(&mut s).await;
    let tree_id = tree_connect(&mut s, "\\\\127.0.0.1\\share", session_id, 3).await;
    let status = create_durable_reconnect_status(&mut s, session_id, tree_id, 4, file_id).await;
    assert_eq!(status, STATUS_SUCCESS);
    read(
        &mut s,
        session_id,
        tree_id,
        5,
        file_id,
        0,
        5,
        STATUS_SUCCESS,
    )
    .await;
    close(&mut s, session_id, tree_id, 6, file_id).await;

    drop(s);
    handle.abort();
}

#[tokio::test]
async fn durable_v1_reconnect_after_tcp_disconnect() {
    let (handle, addr, mut s, session_id, tree_id) = setup_lock_server_with_addr().await;
    let file_id = create_durable_batch(&mut s, session_id, tree_id, 4).await;
    drop(s);
    tokio::time::sleep(Duration::from_millis(25)).await;

    let mut s = TcpStream::connect(addr).await.expect("reconnect tcp");
    let _ = negotiate(&mut s).await;
    let session_id = anonymous_session_setup(&mut s).await;
    let tree_id = tree_connect(&mut s, "\\\\127.0.0.1\\share", session_id, 3).await;
    let reconnected = create_durable_reconnect(&mut s, session_id, tree_id, 4, file_id).await;
    assert_eq!(reconnected, file_id);
    read(
        &mut s,
        session_id,
        tree_id,
        5,
        file_id,
        0,
        5,
        STATUS_SUCCESS,
    )
    .await;
    close(&mut s, session_id, tree_id, 6, file_id).await;

    drop(s);
    handle.abort();
}

#[tokio::test]
async fn durable_v1_lease_reconnect_after_tcp_disconnect_requires_lease_context() {
    let (handle, addr, mut s, session_id, tree_id) = setup_lock_server_with_addr_smb311().await;
    let file_id = create_durable_v1_lease(&mut s, session_id, tree_id, 4)
        .await
        .file_id;
    drop(s);
    tokio::time::sleep(Duration::from_millis(25)).await;

    let mut s = TcpStream::connect(addr).await.expect("reconnect tcp");
    let _ = negotiate_smb311(&mut s).await;
    let session_id = anonymous_session_setup(&mut s).await;
    let tree_id = tree_connect(&mut s, "\\\\127.0.0.1\\share", session_id, 3).await;

    let status = create_durable_reconnect_status(&mut s, session_id, tree_id, 4, file_id).await;
    assert_eq!(status, STATUS_OBJECT_NAME_NOT_FOUND);

    let status = create_durable_v1_lease_reconnect_name_with_key_status(
        &mut s,
        session_id,
        tree_id,
        5,
        file_id,
        "hello.txt",
        b"other-key-123456",
    )
    .await;
    assert_eq!(status, STATUS_OBJECT_NAME_NOT_FOUND);

    let status = create_durable_v1_lease_reconnect_name_status(
        &mut s,
        session_id,
        tree_id,
        6,
        file_id,
        "__non_existing_fname__",
    )
    .await;
    assert_eq!(status, STATUS_INVALID_PARAMETER);

    let status = create_durable_v1_lease_reconnect_name_status(
        &mut s,
        session_id,
        tree_id,
        7,
        file_id,
        "hello.txt",
    )
    .await;
    assert_eq!(status, STATUS_SUCCESS);
    close(&mut s, session_id, tree_id, 8, file_id).await;

    drop(s);
    handle.abort();
}

#[tokio::test]
async fn durable_v1_reconnect_after_timeout_fails_and_scavenges() {
    let (handle, addr, mut s, session_id, tree_id) =
        setup_lock_server_with_addr_and_timeout(Duration::from_millis(10)).await;
    let file_id = create_durable_batch(&mut s, session_id, tree_id, 4).await;
    drop(s);
    tokio::time::sleep(Duration::from_millis(40)).await;

    let mut s = TcpStream::connect(addr).await.expect("reconnect tcp");
    let _ = negotiate(&mut s).await;
    let session_id = anonymous_session_setup(&mut s).await;
    let tree_id = tree_connect(&mut s, "\\\\127.0.0.1\\share", session_id, 3).await;
    let status = create_durable_reconnect_status(&mut s, session_id, tree_id, 4, file_id).await;
    assert_eq!(status, STATUS_OBJECT_NAME_NOT_FOUND);

    drop(s);
    handle.abort();
}

#[tokio::test]
async fn fresh_open_invalidates_detached_durable_v1_reconnect() {
    let (handle, mut s, session_id, tree_id) = setup_lock_server().await;
    let file_id = create_durable_batch(&mut s, session_id, tree_id, 4).await;

    tree_disconnect(&mut s, session_id, tree_id, 5).await;
    let tree_id = tree_connect(&mut s, "\\\\127.0.0.1\\share", session_id, 6).await;
    let fresh = create_durable_batch(&mut s, session_id, tree_id, 7).await;
    close(&mut s, session_id, tree_id, 8, fresh).await;

    let status = create_durable_reconnect_status(&mut s, session_id, tree_id, 9, file_id).await;
    assert_eq!(status, STATUS_OBJECT_NAME_NOT_FOUND);

    drop(s);
    handle.abort();
}

#[tokio::test]
async fn durable_v1_granted_with_handle_caching_lease() {
    let (handle, mut s, session_id, tree_id) = setup_lock_server().await;
    let create = create_durable_v1_lease(&mut s, session_id, tree_id, 4).await;

    assert_eq!(create.oplock_level, 0xff);
    close(&mut s, session_id, tree_id, 5, create.file_id).await;

    drop(s);
    handle.abort();
}

#[tokio::test]
async fn durable_v1_no_write_lease_with_lock_does_not_detach() {
    let (handle, mut s, session_id, tree_id) = setup_lock_server().await;
    let file_id = create_durable_v1_lease(&mut s, session_id, tree_id, 4)
        .await
        .file_id;
    lock(
        &mut s,
        session_id,
        tree_id,
        5,
        file_id,
        0,
        1,
        LockElement::FLAG_EXCLUSIVE_LOCK,
        STATUS_SUCCESS,
    )
    .await;

    tree_disconnect(&mut s, session_id, tree_id, 6).await;
    let tree_id = tree_connect(&mut s, "\\\\127.0.0.1\\share", session_id, 7).await;
    let status = create_durable_reconnect_status(&mut s, session_id, tree_id, 8, file_id).await;
    assert_eq!(status, STATUS_OBJECT_NAME_NOT_FOUND);

    let fresh = create_rw(&mut s, session_id, tree_id, 9).await;
    lock(
        &mut s,
        session_id,
        tree_id,
        10,
        fresh,
        0,
        1,
        LockElement::FLAG_EXCLUSIVE_LOCK,
        STATUS_SUCCESS,
    )
    .await;
    close(&mut s, session_id, tree_id, 11, fresh).await;

    drop(s);
    handle.abort();
}

#[tokio::test]
async fn durable_v1_lease_reconnect_requires_original_name() {
    let (handle, addr, mut s, session_id, tree_id) = setup_lock_server_with_addr().await;
    let file_id = create_durable_v1_lease(&mut s, session_id, tree_id, 4)
        .await
        .file_id;
    drop(s);
    tokio::time::sleep(Duration::from_millis(25)).await;

    let mut s = TcpStream::connect(addr).await.expect("reconnect tcp");
    let _ = negotiate(&mut s).await;
    let session_id = anonymous_session_setup(&mut s).await;
    let tree_id = tree_connect(&mut s, "\\\\127.0.0.1\\share", session_id, 3).await;
    let status = create_durable_v1_lease_reconnect_name_status(
        &mut s,
        session_id,
        tree_id,
        4,
        file_id,
        "__non_existing_fname__",
    )
    .await;
    assert_eq!(status, STATUS_INVALID_PARAMETER);

    let status = create_durable_v1_lease_reconnect_name_status(
        &mut s,
        session_id,
        tree_id,
        5,
        file_id,
        "hello.txt",
    )
    .await;
    assert_eq!(status, STATUS_SUCCESS);
    close(&mut s, session_id, tree_id, 6, file_id).await;

    drop(s);
    handle.abort();
}

#[tokio::test]
async fn durable_v1_lease_reconnect_rejects_different_client_guid() {
    let (handle, addr, mut s, session_id, tree_id) = setup_lock_server_with_addr_smb311().await;
    let file_id = create_durable_v1_lease(&mut s, session_id, tree_id, 4)
        .await
        .file_id;

    tree_disconnect(&mut s, session_id, tree_id, 5).await;
    drop(s);

    let mut s = TcpStream::connect(addr)
        .await
        .expect("connect wrong client");
    let _ = negotiate_smb311_with_client_guid(&mut s, [0x55; 16]).await;
    let session_id = anonymous_session_setup(&mut s).await;
    let tree_id = tree_connect(&mut s, "\\\\127.0.0.1\\share", session_id, 3).await;
    let status = create_durable_v1_lease_reconnect_name_status(
        &mut s,
        session_id,
        tree_id,
        4,
        file_id,
        "hello.txt",
    )
    .await;
    assert_eq!(status, STATUS_OBJECT_NAME_NOT_FOUND);

    drop(s);
    handle.abort();
}

#[tokio::test]
async fn durable_v1_lease_reconnect_succeeds_after_wrong_client_takeover_attempt() {
    let (handle, addr, mut original, original_session_id, tree_id) =
        setup_lock_server_with_addr_smb311().await;
    let file_id = create_durable_v1_lease(&mut original, original_session_id, tree_id, 4)
        .await
        .file_id;

    let mut wrong_client = TcpStream::connect(addr)
        .await
        .expect("connect wrong client");
    let _ = negotiate_smb311_with_client_guid(&mut wrong_client, [0x55; 16]).await;
    let wrong_session_id =
        anonymous_session_setup_with_previous(&mut wrong_client, original_session_id).await;
    let wrong_tree_id = tree_connect(
        &mut wrong_client,
        "\\\\127.0.0.1\\share",
        wrong_session_id,
        3,
    )
    .await;
    let status = create_durable_reconnect_name_status(
        &mut wrong_client,
        wrong_session_id,
        wrong_tree_id,
        4,
        file_id,
        "hello.txt",
    )
    .await;
    assert_eq!(status, STATUS_OBJECT_NAME_NOT_FOUND);

    let mut correct_client = TcpStream::connect(addr)
        .await
        .expect("connect original client guid");
    let _ = negotiate_smb311_with_client_guid(&mut correct_client, [0x31; 16]).await;
    let correct_session_id =
        anonymous_session_setup_with_previous(&mut correct_client, original_session_id).await;
    let correct_tree_id = tree_connect(
        &mut correct_client,
        "\\\\127.0.0.1\\share",
        correct_session_id,
        3,
    )
    .await;
    let status = create_durable_v1_lease_reconnect_name_status(
        &mut correct_client,
        correct_session_id,
        correct_tree_id,
        4,
        file_id,
        "hello.txt",
    )
    .await;
    assert_eq!(status, STATUS_SUCCESS);
    close(
        &mut correct_client,
        correct_session_id,
        correct_tree_id,
        5,
        file_id,
    )
    .await;

    drop(original);
    drop(wrong_client);
    drop(correct_client);
    handle.abort();
}

#[tokio::test]
async fn durable_v2_reconnect_can_reattach_v1_lease_handle() {
    let (handle, addr, mut s, session_id, tree_id) = setup_lock_server_with_addr_smb311().await;
    let file_id = create_durable_v1_lease(&mut s, session_id, tree_id, 4)
        .await
        .file_id;
    drop(s);
    tokio::time::sleep(Duration::from_millis(25)).await;

    let mut s = TcpStream::connect(addr).await.expect("reconnect tcp");
    let _ = negotiate_smb311(&mut s).await;
    let session_id = anonymous_session_setup(&mut s).await;
    let tree_id = tree_connect(&mut s, "\\\\127.0.0.1\\share", session_id, 3).await;
    let status = create_durable_v2_reconnect_status(&mut s, session_id, tree_id, 4, file_id).await;
    assert_eq!(status, STATUS_SUCCESS);
    read(
        &mut s,
        session_id,
        tree_id,
        5,
        file_id,
        0,
        5,
        STATUS_SUCCESS,
    )
    .await;
    close(&mut s, session_id, tree_id, 6, file_id).await;

    drop(s);
    handle.abort();
}

#[tokio::test]
async fn durable_v2_reconnect_rejects_smb300_v1_lease_handle() {
    let (handle, addr, mut s, session_id, tree_id) = setup_lock_server_with_addr_smb300().await;
    let file_id = create_durable_v1_lease(&mut s, session_id, tree_id, 4)
        .await
        .file_id;
    drop(s);
    tokio::time::sleep(Duration::from_millis(25)).await;

    let mut s = TcpStream::connect(addr).await.expect("reconnect tcp");
    let _ = negotiate_smb300(&mut s).await;
    let session_id = anonymous_session_setup(&mut s).await;
    let tree_id = tree_connect(&mut s, "\\\\127.0.0.1\\share", session_id, 3).await;

    let name = utf16le("hello.txt");
    let req = CreateRequest {
        structure_size: 57,
        security_flags: 0,
        requested_oplock_level: 0xff,
        impersonation_level: 2,
        smb_create_flags: 0,
        reserved: 0,
        desired_access: 0x0012_0089,
        file_attributes: 0,
        share_access: 0x0000_0007,
        create_disposition: 1,
        create_options: 0,
        name_offset: 0x78,
        name_length: name.len() as u16,
        create_contexts_offset: 0,
        create_contexts_length: 0,
        name,
        create_contexts: vec![],
    };
    let body = create_request_with_contexts(
        req,
        &[
            CreateContext {
                name: CreateContext::NAME_DH2C.to_vec(),
                data: durable_v2_reconnect_with_guid(file_id, b"wrongcreateguid!", 0),
            },
            CreateContext {
                name: CreateContext::NAME_RQLS.to_vec(),
                data: lease_v2_request(0),
            },
        ],
    );
    let hdr = build_header(Command::Create, 4, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, _rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Create);
    assert_eq!(rh.channel_sequence_status, STATUS_OBJECT_NAME_NOT_FOUND);

    drop(s);
    handle.abort();
}

#[tokio::test]
async fn durable_v1_delete_on_close_reconnects_then_deletes_on_close() {
    let (handle, root, addr, mut s, session_id, tree_id) =
        setup_lock_server_with_path_and_addr().await;
    let file_id = create_durable_delete_on_close_batch(&mut s, session_id, tree_id, 4).await;
    write(
        &mut s,
        session_id,
        tree_id,
        5,
        file_id,
        0,
        b"x",
        STATUS_SUCCESS,
    )
    .await;

    drop(s);
    tokio::time::sleep(Duration::from_millis(25)).await;
    assert!(
        root.join("hello.txt").exists(),
        "detached durable delete-on-close handle removed the file before close"
    );

    let mut s = TcpStream::connect(addr).await.expect("reconnect tcp");
    let _ = negotiate(&mut s).await;
    let session_id = anonymous_session_setup(&mut s).await;
    let tree_id = tree_connect(&mut s, "\\\\127.0.0.1\\share", session_id, 7).await;
    let reconnected = create_durable_reconnect(&mut s, session_id, tree_id, 8, file_id).await;
    assert_eq!(reconnected, file_id);
    close(&mut s, session_id, tree_id, 9, file_id).await;
    assert!(
        !root.join("hello.txt").exists(),
        "reconnected durable delete-on-close handle did not delete on close"
    );

    drop(s);
    handle.abort();
}

#[tokio::test]
async fn regular_open_scavenges_detached_delete_on_close_durable() {
    let (handle, root, mut s, session_id, tree_id) = setup_lock_server_with_path().await;
    let durable_id = create_durable_delete_on_close_batch(&mut s, session_id, tree_id, 4).await;
    write(
        &mut s,
        session_id,
        tree_id,
        5,
        durable_id,
        0,
        b"x",
        STATUS_SUCCESS,
    )
    .await;

    tree_disconnect(&mut s, session_id, tree_id, 6).await;
    assert!(
        root.join("hello.txt").exists(),
        "detached durable delete-on-close handle removed the file before scavenging"
    );

    let tree_id = tree_connect(&mut s, "\\\\127.0.0.1\\share", session_id, 7).await;
    let fresh = create_regular_delete_on_close_batch(&mut s, session_id, tree_id, 8).await;
    assert_eq!(fresh.create_action, 0x0000_0002);

    let status = create_durable_reconnect_status(&mut s, session_id, tree_id, 9, durable_id).await;
    assert_eq!(status, STATUS_OBJECT_NAME_NOT_FOUND);

    close(&mut s, session_id, tree_id, 10, fresh.file_id).await;
    assert!(
        !root.join("hello.txt").exists(),
        "fresh delete-on-close handle did not delete recreated file"
    );

    drop(s);
    handle.abort();
}

#[tokio::test]
async fn previous_session_setup_detaches_durable_v1_open_for_reconnect() {
    let (handle, mut s, old_session_id, tree_id) = setup_lock_server().await;
    let file_id = create_durable_batch(&mut s, old_session_id, tree_id, 4).await;

    let new_session_id = anonymous_session_setup_with_previous(&mut s, old_session_id).await;
    assert_ne!(new_session_id, old_session_id);
    let tree_id = tree_connect(&mut s, "\\\\127.0.0.1\\share", new_session_id, 5).await;
    let reconnected = create_durable_reconnect(&mut s, new_session_id, tree_id, 6, file_id).await;

    assert_eq!(reconnected, file_id);
    read(
        &mut s,
        new_session_id,
        tree_id,
        7,
        file_id,
        0,
        5,
        STATUS_SUCCESS,
    )
    .await;
    close(&mut s, new_session_id, tree_id, 8, file_id).await;

    drop(s);
    handle.abort();
}

#[tokio::test]
async fn previous_session_setup_on_new_connection_detaches_durable_v1_open_for_reconnect() {
    let (handle, addr, mut old, old_session_id, tree_id) = setup_lock_server_with_addr().await;
    let file_id = create_durable_batch(&mut old, old_session_id, tree_id, 4).await;

    let mut new_conn = TcpStream::connect(addr).await.expect("connect takeover");
    let _ = negotiate(&mut new_conn).await;
    let new_session_id = anonymous_session_setup_with_previous(&mut new_conn, old_session_id).await;
    let new_tree_id = tree_connect(&mut new_conn, "\\\\127.0.0.1\\share", new_session_id, 3).await;

    let stale_status =
        create_durable_reconnect_status(&mut old, old_session_id, tree_id, 5, file_id).await;
    assert_eq!(stale_status, STATUS_USER_SESSION_DELETED);

    let reconnected =
        create_durable_reconnect(&mut new_conn, new_session_id, new_tree_id, 4, file_id).await;

    assert_eq!(reconnected, file_id);
    read(
        &mut new_conn,
        new_session_id,
        new_tree_id,
        5,
        file_id,
        0,
        5,
        STATUS_SUCCESS,
    )
    .await;
    close(&mut new_conn, new_session_id, new_tree_id, 6, file_id).await;

    drop(old);
    drop(new_conn);
    handle.abort();
}

#[tokio::test]
async fn previous_session_setup_closes_regular_batch_open_for_fresh_reopen() {
    let (handle, addr, mut old, old_session_id, tree_id) = setup_lock_server_with_addr().await;
    let name = "session_reconnect_local.dat";
    send_create_named_open(
        &mut old,
        old_session_id,
        tree_id,
        4,
        name,
        0x001f_01ff,
        0,
        3,
        0,
        0x09,
    )
    .await;
    let resp = read_frame_with_timeout(&mut old).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Create);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let first = CreateResponse::parse(rb).expect("parse first create");
    assert_eq!(first.create_action, 0x0000_0002);
    assert_eq!(first.oplock_level, 0x09);

    let mut new_conn = TcpStream::connect(addr)
        .await
        .expect("connect previous-session takeover");
    let _ = negotiate(&mut new_conn).await;
    let new_session_id = anonymous_session_setup_with_previous(&mut new_conn, old_session_id).await;
    let new_tree_id = tree_connect(&mut new_conn, "\\\\127.0.0.1\\share", new_session_id, 3).await;

    let stale_status =
        query_basic_info_status(&mut old, old_session_id, tree_id, 5, first.file_id).await;
    assert_eq!(stale_status, STATUS_USER_SESSION_DELETED);

    send_create_named_open(
        &mut new_conn,
        new_session_id,
        new_tree_id,
        4,
        name,
        0x001f_01ff,
        0,
        3,
        0,
        0x09,
    )
    .await;
    let resp = read_frame_with_timeout(&mut new_conn).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Create);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let reopened = CreateResponse::parse(rb).expect("parse reopened create");
    assert_eq!(reopened.create_action, 0x0000_0001);
    close(
        &mut new_conn,
        new_session_id,
        new_tree_id,
        5,
        reopened.file_id,
    )
    .await;

    drop(old);
    drop(new_conn);
    handle.abort();
}

#[tokio::test]
async fn durable_v1_batch_reconnect_allows_different_client_guid() {
    let (handle, addr, mut old, old_session_id, tree_id) =
        setup_lock_server_with_addr_smb311().await;
    let file_id = create_durable_batch(&mut old, old_session_id, tree_id, 4).await;

    let mut new_conn = TcpStream::connect(addr)
        .await
        .expect("connect takeover with different client guid");
    let _ = negotiate_smb311_with_client_guid(&mut new_conn, [0x55; 16]).await;
    let new_session_id = anonymous_session_setup_with_previous(&mut new_conn, old_session_id).await;
    let new_tree_id = tree_connect(&mut new_conn, "\\\\127.0.0.1\\share", new_session_id, 3).await;
    let reconnected =
        create_durable_reconnect(&mut new_conn, new_session_id, new_tree_id, 4, file_id).await;

    assert_eq!(reconnected, file_id);
    read(
        &mut new_conn,
        new_session_id,
        new_tree_id,
        5,
        file_id,
        0,
        5,
        STATUS_SUCCESS,
    )
    .await;
    close(&mut new_conn, new_session_id, new_tree_id, 6, file_id).await;

    drop(old);
    drop(new_conn);
    handle.abort();
}

#[tokio::test]
async fn durable_v2_lease_reconnect_fails_after_tree_disconnect() {
    let (handle, mut s, session_id, tree_id) = setup_lock_server_smb311().await;
    let file_id = create_durable_v2_lease(&mut s, session_id, tree_id, 4).await;

    tree_disconnect(&mut s, session_id, tree_id, 5).await;
    let tree_id = tree_connect(&mut s, "\\\\127.0.0.1\\share", session_id, 6).await;
    let status = create_durable_v2_reconnect_status(&mut s, session_id, tree_id, 7, file_id).await;
    assert_eq!(status, STATUS_OBJECT_NAME_NOT_FOUND);

    drop(s);
    handle.abort();
}

#[tokio::test]
async fn previous_session_setup_detaches_durable_v2_open_for_reconnect() {
    let (handle, mut s, old_session_id, tree_id) = setup_lock_server_smb311().await;
    let file_id = create_durable_v2_lease(&mut s, old_session_id, tree_id, 4).await;

    let new_session_id = anonymous_session_setup_with_previous(&mut s, old_session_id).await;
    assert_ne!(new_session_id, old_session_id);
    let tree_id = tree_connect(&mut s, "\\\\127.0.0.1\\share", new_session_id, 5).await;
    let reconnected =
        create_durable_v2_reconnect(&mut s, new_session_id, tree_id, 6, file_id).await;

    assert_eq!(reconnected, file_id);
    read(
        &mut s,
        new_session_id,
        tree_id,
        7,
        file_id,
        0,
        5,
        STATUS_SUCCESS,
    )
    .await;
    close(&mut s, new_session_id, tree_id, 8, file_id).await;

    drop(s);
    handle.abort();
}

#[tokio::test]
async fn previous_session_setup_on_new_connection_detaches_durable_v2_open_for_reconnect() {
    let (handle, addr, mut old, old_session_id, tree_id) =
        setup_lock_server_with_addr_smb311().await;
    let file_id = create_durable_v2_lease(&mut old, old_session_id, tree_id, 4).await;

    let mut new_conn = TcpStream::connect(addr).await.expect("connect takeover");
    let _ = negotiate_smb311(&mut new_conn).await;
    let new_session_id = anonymous_session_setup_with_previous(&mut new_conn, old_session_id).await;
    let new_tree_id = tree_connect(&mut new_conn, "\\\\127.0.0.1\\share", new_session_id, 3).await;

    let stale_status =
        create_durable_v2_reconnect_status(&mut old, old_session_id, tree_id, 5, file_id).await;
    assert_eq!(stale_status, STATUS_USER_SESSION_DELETED);

    let reconnected =
        create_durable_v2_reconnect(&mut new_conn, new_session_id, new_tree_id, 4, file_id).await;

    assert_eq!(reconnected, file_id);
    read(
        &mut new_conn,
        new_session_id,
        new_tree_id,
        5,
        file_id,
        0,
        5,
        STATUS_SUCCESS,
    )
    .await;
    close(&mut new_conn, new_session_id, new_tree_id, 6, file_id).await;

    drop(old);
    drop(new_conn);
    handle.abort();
}

#[tokio::test]
async fn durable_v2_batch_reconnect_allows_different_client_guid() {
    let (handle, addr, mut old, old_session_id, tree_id) =
        setup_lock_server_with_addr_smb311().await;
    let file_id = create_durable_v2_batch(&mut old, old_session_id, tree_id, 4).await;

    let mut new_conn = TcpStream::connect(addr)
        .await
        .expect("connect takeover with different client guid");
    let _ = negotiate_smb311_with_client_guid(&mut new_conn, [0x55; 16]).await;
    let new_session_id = anonymous_session_setup_with_previous(&mut new_conn, old_session_id).await;
    let new_tree_id = tree_connect(&mut new_conn, "\\\\127.0.0.1\\share", new_session_id, 3).await;

    let stale_status =
        create_durable_v2_batch_reconnect_status(&mut old, old_session_id, tree_id, 5, file_id)
            .await;
    assert_eq!(stale_status, STATUS_USER_SESSION_DELETED);

    let reconnected =
        create_durable_v2_batch_reconnect(&mut new_conn, new_session_id, new_tree_id, 4, file_id)
            .await;
    assert_eq!(reconnected, file_id);
    read(
        &mut new_conn,
        new_session_id,
        new_tree_id,
        5,
        file_id,
        0,
        5,
        STATUS_SUCCESS,
    )
    .await;
    close(&mut new_conn, new_session_id, new_tree_id, 6, file_id).await;

    drop(old);
    drop(new_conn);
    handle.abort();
}

#[tokio::test]
async fn durable_v2_lease_reconnect_after_tcp_disconnect() {
    let (handle, addr, mut s, session_id, tree_id) = setup_lock_server_with_addr_smb311().await;
    let file_id = create_durable_v2_lease(&mut s, session_id, tree_id, 4).await;
    drop(s);
    tokio::time::sleep(Duration::from_millis(25)).await;

    let mut s = TcpStream::connect(addr).await.expect("reconnect tcp");
    let _ = negotiate_smb311(&mut s).await;
    let session_id = anonymous_session_setup(&mut s).await;
    let tree_id = tree_connect(&mut s, "\\\\127.0.0.1\\share", session_id, 3).await;
    let reconnected = create_durable_v2_reconnect(&mut s, session_id, tree_id, 4, file_id).await;
    assert_eq!(reconnected, file_id);
    let data = read_data(&mut s, session_id, tree_id, 5, file_id, 0, 11).await;
    assert_eq!(data, b"hello world");
    close(&mut s, session_id, tree_id, 6, file_id).await;

    drop(s);
    handle.abort();
}

#[tokio::test]
async fn durable_v2_lease_reconnect_rejects_wrong_name_without_attaching() {
    let (handle, addr, mut s, session_id, tree_id) = setup_lock_server_with_addr_smb311().await;
    let file_id = create_durable_v2_lease(&mut s, session_id, tree_id, 4).await;
    drop(s);
    tokio::time::sleep(Duration::from_millis(25)).await;

    let mut s = TcpStream::connect(addr).await.expect("reconnect tcp");
    let _ = negotiate_smb311(&mut s).await;
    let session_id = anonymous_session_setup(&mut s).await;
    let tree_id = tree_connect(&mut s, "\\\\127.0.0.1\\share", session_id, 3).await;

    let status = create_durable_v2_reconnect_name_status(
        &mut s,
        session_id,
        tree_id,
        4,
        file_id,
        "__non_existing_fname__",
    )
    .await;
    assert_eq!(status, STATUS_INVALID_PARAMETER);

    let reconnected = create_durable_v2_reconnect(&mut s, session_id, tree_id, 5, file_id).await;
    assert_eq!(reconnected, file_id);
    close(&mut s, session_id, tree_id, 6, file_id).await;

    drop(s);
    handle.abort();
}

#[tokio::test]
async fn durable_v2_reconnect_after_timeout_fails_and_scavenges() {
    let (handle, mut s, session_id, tree_id) =
        setup_lock_server_smb311_with_durable_timeout(Duration::from_millis(10)).await;
    let file_id = create_durable_v2_lease_with_timeout(&mut s, session_id, tree_id, 4, 10).await;

    tree_disconnect(&mut s, session_id, tree_id, 5).await;
    tokio::time::sleep(Duration::from_millis(30)).await;
    let tree_id = tree_connect(&mut s, "\\\\127.0.0.1\\share", session_id, 6).await;
    let status = create_durable_v2_reconnect_status(&mut s, session_id, tree_id, 7, file_id).await;
    assert_eq!(status, STATUS_OBJECT_NAME_NOT_FOUND);

    let fresh = create_rw(&mut s, session_id, tree_id, 8).await;
    close(&mut s, session_id, tree_id, 9, fresh).await;

    drop(s);
    handle.abort();
}

#[tokio::test]
async fn durable_v2_close_removes_durable_state_and_share_conflict() {
    let (handle, mut s, session_id, tree_id) = setup_lock_server_smb311().await;
    let file_id = create_durable_v2_lease(&mut s, session_id, tree_id, 4).await;

    close(&mut s, session_id, tree_id, 5, file_id).await;
    let status = create_durable_v2_reconnect_status(&mut s, session_id, tree_id, 6, file_id).await;
    assert_eq!(status, STATUS_OBJECT_NAME_NOT_FOUND);

    let fresh = create_rw(&mut s, session_id, tree_id, 7).await;
    close(&mut s, session_id, tree_id, 8, fresh).await;

    drop(s);
    handle.abort();
}

#[tokio::test]
async fn durable_v2_does_not_survive_handle_lease_break_ack_to_none() {
    let (handle, mut s, session_id, tree_id) = setup_lock_server_smb311().await;
    let lease_key = b"lease-key-123456";
    let file_id = create_durable_v2_lease(&mut s, session_id, tree_id, 4).await;
    let writer = create_oplock_open(&mut s, session_id, tree_id, 5, 0, 0x4000_0000).await;

    send_write(&mut s, session_id, tree_id, 6, writer.file_id, 0, b"x").await;

    let frames = [read_frame(&mut s).await, read_frame(&mut s).await];
    let mut pending_async_id = None;
    let mut write_seen = false;
    let mut break_seen = false;
    for frame in frames {
        let (rh, rb) = parse_response_header(&frame);
        match rh.command {
            Command::Write => {
                if rh.channel_sequence_status == STATUS_PENDING {
                    pending_async_id = rh.async_id();
                } else {
                    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
                    let wr = WriteResponse::parse(rb).expect("parse write response");
                    assert_eq!(wr.count, 1);
                    write_seen = true;
                }
            }
            Command::OplockBreak => {
                assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
                let notification =
                    LeaseBreakNotification::parse(rb).expect("parse lease break notification");
                assert_eq!(&notification.lease_key, lease_key);
                assert_eq!(notification.current_lease_state, 0x0000_0001 | 0x0000_0002);
                assert_eq!(notification.new_lease_state, 0);
                assert_eq!(notification.flags, 0x0000_0001);
                break_seen = true;
            }
            other => panic!("unexpected write side response command {other:?}"),
        }
    }
    assert!(break_seen, "missing lease break notification");

    let ack = LeaseBreakAck {
        structure_size: 36,
        reserved: 0,
        flags: 0,
        lease_key: *lease_key,
        lease_state: 0,
        lease_duration: 0,
    };
    let mut ack_body = Vec::new();
    ack.write_to(&mut ack_body).expect("write lease break ack");
    let ack_hdr = build_header(Command::OplockBreak, 7, session_id, tree_id);
    write_frame(&mut s, &ack_hdr, &ack_body).await;

    if let Some(async_id) = pending_async_id {
        let frames = [read_frame(&mut s).await, read_frame(&mut s).await];
        let mut ack_seen = false;
        let mut final_write_seen = false;
        for frame in frames {
            let (rh, rb) = parse_response_header(&frame);
            match rh.command {
                Command::OplockBreak => {
                    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
                    ack_seen = true;
                }
                Command::Write => {
                    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
                    assert_eq!(rh.async_id(), Some(async_id));
                    let wr = WriteResponse::parse(rb).expect("parse final write response");
                    assert_eq!(wr.count, 1);
                    final_write_seen = true;
                }
                other => panic!("unexpected post-ack response command {other:?}"),
            }
        }
        assert!(ack_seen, "missing lease break ack response");
        assert!(final_write_seen, "missing final write response");
    } else {
        let ack_frame = read_frame(&mut s).await;
        let (rh, _) = parse_response_header(&ack_frame);
        assert_eq!(rh.command, Command::OplockBreak);
        assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
        assert!(write_seen, "missing immediate write response");
    }

    close(&mut s, session_id, tree_id, 8, writer.file_id).await;
    tree_disconnect(&mut s, session_id, tree_id, 9).await;
    let tree_id = tree_connect(&mut s, "\\\\127.0.0.1\\share", session_id, 10).await;
    let status = create_durable_v2_reconnect_status(&mut s, session_id, tree_id, 11, file_id).await;
    assert_eq!(status, STATUS_OBJECT_NAME_NOT_FOUND);

    drop(s);
    handle.abort();
}

#[tokio::test]
async fn durable_v2_persistent_request_is_granted_non_persistent() {
    const SMB2_DHANDLE_FLAG_PERSISTENT: u32 = 0x0000_0002;

    let (handle, mut s, session_id, tree_id) = setup_lock_server_smb311().await;
    let name = utf16le("hello.txt");
    let req = CreateRequest {
        structure_size: 57,
        security_flags: 0,
        requested_oplock_level: 0xff,
        impersonation_level: 2,
        smb_create_flags: 0,
        reserved: 0,
        desired_access: 0x0012_0089,
        file_attributes: 0,
        share_access: 0x0000_0007,
        create_disposition: 1,
        create_options: 0,
        name_offset: 0x78,
        name_length: name.len() as u16,
        create_contexts_offset: 0,
        create_contexts_length: 0,
        name,
        create_contexts: vec![],
    };
    let body = create_request_with_contexts(
        req,
        &[
            CreateContext {
                name: CreateContext::NAME_DH2Q.to_vec(),
                data: durable_v2_request(SMB2_DHANDLE_FLAG_PERSISTENT),
            },
            CreateContext {
                name: CreateContext::NAME_RQLS.to_vec(),
                data: lease_v2_request(0x0000_0001 | 0x0000_0002),
            },
        ],
    );
    let hdr = build_header(Command::Create, 4, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Create);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let create = CreateResponse::parse(rb).expect("parse persistent durable create");
    let contexts = CreateContext::parse_chain(&create.create_contexts).expect("parse contexts");
    let durable = contexts
        .iter()
        .find(|ctx| ctx.name == CreateContext::NAME_DH2Q.as_slice())
        .expect("missing durable v2 response context");
    assert_eq!(durable.data.len(), 8);
    assert_eq!(
        u32::from_le_bytes(durable.data[4..8].try_into().unwrap()),
        0
    );
    close(&mut s, session_id, tree_id, 5, create.file_id).await;

    drop(s);
    handle.abort();
}

#[tokio::test]
async fn fresh_open_invalidates_detached_durable_v2_reconnect() {
    let (handle, mut s, session_id, tree_id) = setup_lock_server_smb311().await;
    let file_id = create_durable_v2_lease(&mut s, session_id, tree_id, 4).await;

    tree_disconnect(&mut s, session_id, tree_id, 5).await;
    let tree_id = tree_connect(&mut s, "\\\\127.0.0.1\\share", session_id, 6).await;
    let fresh = create_rw(&mut s, session_id, tree_id, 7).await;
    close(&mut s, session_id, tree_id, 8, fresh).await;

    let status = create_durable_v2_reconnect_status(&mut s, session_id, tree_id, 9, file_id).await;
    assert_eq!(status, STATUS_OBJECT_NAME_NOT_FOUND);

    drop(s);
    handle.abort();
}

#[tokio::test]
async fn stat_open_preserves_detached_durable_v2_lease_reconnect() {
    let (handle, addr, mut s, session_id, tree_id) = setup_lock_server_with_addr_smb311().await;
    let file_id = create_durable_v2_lease(&mut s, session_id, tree_id, 4).await;
    drop(s);
    tokio::time::sleep(Duration::from_millis(25)).await;

    let mut stat_conn = TcpStream::connect(addr).await.expect("connect stat tcp");
    let _ = negotiate_smb311(&mut stat_conn).await;
    let stat_session_id = anonymous_session_setup(&mut stat_conn).await;
    let stat_tree_id =
        tree_connect(&mut stat_conn, "\\\\127.0.0.1\\share", stat_session_id, 3).await;
    let stat = create_oplock_open(
        &mut stat_conn,
        stat_session_id,
        stat_tree_id,
        4,
        0,
        0x0000_0080,
    )
    .await;

    let mut reconnect_conn = TcpStream::connect(addr)
        .await
        .expect("connect reconnect tcp");
    let _ = negotiate_smb311(&mut reconnect_conn).await;
    let reconnect_session_id = anonymous_session_setup(&mut reconnect_conn).await;
    let reconnect_tree_id = tree_connect(
        &mut reconnect_conn,
        "\\\\127.0.0.1\\share",
        reconnect_session_id,
        3,
    )
    .await;
    let reconnected = create_durable_v2_reconnect(
        &mut reconnect_conn,
        reconnect_session_id,
        reconnect_tree_id,
        4,
        file_id,
    )
    .await;
    assert_eq!(reconnected, file_id);

    close(
        &mut reconnect_conn,
        reconnect_session_id,
        reconnect_tree_id,
        5,
        file_id,
    )
    .await;
    close(
        &mut stat_conn,
        stat_session_id,
        stat_tree_id,
        5,
        stat.file_id,
    )
    .await;
    drop(reconnect_conn);
    drop(stat_conn);
    handle.abort();
}

#[tokio::test]
async fn compatible_rh_open_preserves_detached_durable_v2_lease_reconnect() {
    let (handle, addr, mut s, session_id, tree_id) = setup_lock_server_with_addr_smb311().await;
    let file_id = create_durable_v2_lease(&mut s, session_id, tree_id, 4).await;
    drop(s);
    tokio::time::sleep(Duration::from_millis(25)).await;

    let mut lease_conn = TcpStream::connect(addr).await.expect("connect lease tcp");
    let _ = negotiate_smb311(&mut lease_conn).await;
    let lease_session_id = anonymous_session_setup(&mut lease_conn).await;
    let lease_tree_id =
        tree_connect(&mut lease_conn, "\\\\127.0.0.1\\share", lease_session_id, 3).await;
    let (status, compatible) = create_durable_v2_lease_with_key_result(
        &mut lease_conn,
        lease_session_id,
        lease_tree_id,
        4,
        b"other-key-123456",
        b"other-guid-12345",
        false,
    )
    .await;
    assert_eq!(status, STATUS_SUCCESS);
    let compatible = compatible.expect("compatible RH create response");

    let mut reconnect_conn = TcpStream::connect(addr)
        .await
        .expect("connect reconnect tcp");
    let _ = negotiate_smb311(&mut reconnect_conn).await;
    let reconnect_session_id = anonymous_session_setup(&mut reconnect_conn).await;
    let reconnect_tree_id = tree_connect(
        &mut reconnect_conn,
        "\\\\127.0.0.1\\share",
        reconnect_session_id,
        3,
    )
    .await;
    let reconnected = create_durable_v2_reconnect(
        &mut reconnect_conn,
        reconnect_session_id,
        reconnect_tree_id,
        4,
        file_id,
    )
    .await;
    assert_eq!(reconnected, file_id);

    close(
        &mut reconnect_conn,
        reconnect_session_id,
        reconnect_tree_id,
        5,
        file_id,
    )
    .await;
    close(
        &mut lease_conn,
        lease_session_id,
        lease_tree_id,
        5,
        compatible.file_id,
    )
    .await;
    drop(reconnect_conn);
    drop(lease_conn);
    handle.abort();
}

#[tokio::test]
async fn rwh_open_purges_detached_durable_v2_lease_reconnect() {
    const LEASE_READ: u32 = 0x0000_0001;
    const LEASE_HANDLE: u32 = 0x0000_0002;
    const LEASE_WRITE: u32 = 0x0000_0004;

    let (handle, addr, mut s, session_id, tree_id) = setup_lock_server_with_addr_smb311().await;
    let (status, first) = create_durable_v2_lease_with_key_state_result(
        &mut s,
        session_id,
        tree_id,
        4,
        b"lease-key-123456",
        b"0123456789abcdef",
        LEASE_READ | LEASE_HANDLE | LEASE_WRITE,
        false,
    )
    .await;
    assert_eq!(status, STATUS_SUCCESS);
    let first = first.expect("first RWH create response");
    assert_eq!(
        lease_grant_from_create(&first).state,
        LEASE_READ | LEASE_HANDLE | LEASE_WRITE
    );
    let first_file_id = first.file_id;
    drop(s);
    tokio::time::sleep(Duration::from_millis(25)).await;

    let mut lease_conn = TcpStream::connect(addr).await.expect("connect lease tcp");
    let _ = negotiate_smb311(&mut lease_conn).await;
    let lease_session_id = anonymous_session_setup(&mut lease_conn).await;
    let lease_tree_id =
        tree_connect(&mut lease_conn, "\\\\127.0.0.1\\share", lease_session_id, 3).await;
    let (status, second) = create_durable_v2_lease_with_key_state_result(
        &mut lease_conn,
        lease_session_id,
        lease_tree_id,
        4,
        b"other-key-123456",
        b"other-guid-12345",
        LEASE_READ | LEASE_HANDLE | LEASE_WRITE,
        false,
    )
    .await;
    assert_eq!(status, STATUS_SUCCESS);
    let second = second.expect("second RWH create response");
    assert_eq!(
        lease_grant_from_create(&second).state,
        LEASE_READ | LEASE_HANDLE | LEASE_WRITE
    );

    let mut reconnect_conn = TcpStream::connect(addr)
        .await
        .expect("connect reconnect tcp");
    let _ = negotiate_smb311(&mut reconnect_conn).await;
    let reconnect_session_id = anonymous_session_setup(&mut reconnect_conn).await;
    let reconnect_tree_id = tree_connect(
        &mut reconnect_conn,
        "\\\\127.0.0.1\\share",
        reconnect_session_id,
        3,
    )
    .await;
    let status = create_durable_v2_reconnect_status(
        &mut reconnect_conn,
        reconnect_session_id,
        reconnect_tree_id,
        4,
        first_file_id,
    )
    .await;
    assert_eq!(status, STATUS_OBJECT_NAME_NOT_FOUND);

    close(
        &mut lease_conn,
        lease_session_id,
        lease_tree_id,
        5,
        second.file_id,
    )
    .await;
    drop(reconnect_conn);
    drop(lease_conn);
    handle.abort();
}

#[tokio::test]
async fn fresh_open_after_detached_durable_v2_share_conflict_invalidates_reconnect() {
    let (handle, mut s, session_id, tree_id) = setup_lock_server_smb311().await;
    let file_id = create_durable_v2_lease_with_access_and_share(
        &mut s,
        session_id,
        tree_id,
        4,
        0x0012_0089,
        0,
    )
    .await;

    tree_disconnect(&mut s, session_id, tree_id, 5).await;
    let tree_id = tree_connect(&mut s, "\\\\127.0.0.1\\share", session_id, 6).await;
    let fresh = create_rw(&mut s, session_id, tree_id, 7).await;
    close(&mut s, session_id, tree_id, 8, fresh).await;

    let status = create_durable_v2_reconnect_status(&mut s, session_id, tree_id, 9, file_id).await;
    assert_eq!(status, STATUS_OBJECT_NAME_NOT_FOUND);

    drop(s);
    handle.abort();
}

#[tokio::test]
async fn durable_v2_app_instance_create_closes_existing_durable_open() {
    let (handle, mut s, session_id, tree_id) = setup_lock_server_smb311().await;
    let app_instance_id = *b"app-instance-001";
    let first = create_durable_v2_lease_with_app_instance(
        &mut s,
        session_id,
        tree_id,
        4,
        0x0012_0089,
        0,
        app_instance_id,
    )
    .await;

    let second = create_durable_v2_lease_with_app_instance(
        &mut s,
        session_id,
        tree_id,
        5,
        0x0012_0089,
        0x0000_0007,
        app_instance_id,
    )
    .await;

    assert_ne!(second, first);
    read(
        &mut s,
        session_id,
        tree_id,
        6,
        first,
        0,
        1,
        STATUS_FILE_CLOSED,
    )
    .await;
    close(&mut s, session_id, tree_id, 7, second).await;

    drop(s);
    handle.abort();
}

#[tokio::test]
async fn durable_v2_app_instance_version_is_accepted_for_takeover() {
    let (handle, mut s, session_id, tree_id) = setup_lock_server_smb311().await;
    let app_instance_id = *b"app-instance-002";
    let first = create_durable_v2_lease_with_app_instance_version(
        &mut s,
        session_id,
        tree_id,
        4,
        0x0012_0089,
        0,
        app_instance_id,
        1,
    )
    .await;

    let second = create_durable_v2_lease_with_app_instance_version(
        &mut s,
        session_id,
        tree_id,
        5,
        0x0012_0089,
        0x0000_0007,
        app_instance_id,
        2,
    )
    .await;

    assert_ne!(second, first);
    read(
        &mut s,
        session_id,
        tree_id,
        6,
        first,
        0,
        1,
        STATUS_FILE_CLOSED,
    )
    .await;
    close(&mut s, session_id, tree_id, 7, second).await;

    drop(s);
    handle.abort();
}

#[tokio::test]
async fn durable_reconnect_fails_without_opening_fresh_handle() {
    let (handle, mut s, session_id, tree_id) = setup_lock_server_smb311().await;
    let missing_file_id = smb_server::wire::messages::FileId::new(0x99, 0x77);

    let status = create_durable_reconnect_name_status(
        &mut s,
        session_id,
        tree_id,
        4,
        missing_file_id,
        "hello.txt",
    )
    .await;
    assert_eq!(status, STATUS_OBJECT_NAME_NOT_FOUND);
    let status =
        create_durable_v2_reconnect_status(&mut s, session_id, tree_id, 5, missing_file_id).await;
    assert_eq!(status, STATUS_OBJECT_NAME_NOT_FOUND);

    let fresh = create_rw(&mut s, session_id, tree_id, 6).await;
    close(&mut s, session_id, tree_id, 7, fresh).await;

    drop(s);
    handle.abort();
}

#[tokio::test]
async fn durable_v2_reconnect_rejects_wrong_create_guid_without_attaching() {
    let (handle, addr, mut s, session_id, tree_id) = setup_lock_server_with_addr_smb311().await;
    let file_id = create_durable_v2_lease(&mut s, session_id, tree_id, 4).await;
    drop(s);
    tokio::time::sleep(Duration::from_millis(25)).await;

    let mut s = TcpStream::connect(addr).await.expect("reconnect tcp");
    let _ = negotiate_smb311(&mut s).await;
    let session_id = anonymous_session_setup(&mut s).await;
    let tree_id = tree_connect(&mut s, "\\\\127.0.0.1\\share", session_id, 3).await;
    let status = create_durable_v2_reconnect_status_with_guid(
        &mut s,
        session_id,
        tree_id,
        4,
        file_id,
        b"wrongcreateguid!",
    )
    .await;
    assert_eq!(status, STATUS_OBJECT_NAME_NOT_FOUND);

    let reconnected = create_durable_v2_reconnect(&mut s, session_id, tree_id, 5, file_id).await;
    assert_eq!(reconnected, file_id);
    close(&mut s, session_id, tree_id, 6, file_id).await;

    drop(s);
    handle.abort();
}

#[tokio::test]
async fn durable_v2_reconnect_rejects_different_client_guid() {
    let (handle, addr, mut s, session_id, tree_id) = setup_lock_server_with_addr_smb311().await;
    let file_id = create_durable_v2_lease(&mut s, session_id, tree_id, 4).await;
    tree_disconnect(&mut s, session_id, tree_id, 5).await;
    drop(s);

    let mut s = TcpStream::connect(addr)
        .await
        .expect("connect wrong client");
    let _ = negotiate_smb311_with_client_guid(&mut s, [0x44; 16]).await;
    let session_id = anonymous_session_setup(&mut s).await;
    let tree_id = tree_connect(&mut s, "\\\\127.0.0.1\\share", session_id, 3).await;
    let status = create_durable_v2_reconnect_status(&mut s, session_id, tree_id, 4, file_id).await;
    assert_eq!(status, STATUS_OBJECT_NAME_NOT_FOUND);

    drop(s);
    handle.abort();
}

#[tokio::test]
async fn durable_v2_reconnect_rejects_wrong_volatile_file_id_without_attaching() {
    let (handle, addr, mut s, session_id, tree_id) = setup_lock_server_with_addr_smb311().await;
    let file_id = create_durable_v2_lease(&mut s, session_id, tree_id, 4).await;
    drop(s);
    tokio::time::sleep(Duration::from_millis(25)).await;

    let mut s = TcpStream::connect(addr).await.expect("reconnect tcp");
    let _ = negotiate_smb311(&mut s).await;
    let session_id = anonymous_session_setup(&mut s).await;
    let tree_id = tree_connect(&mut s, "\\\\127.0.0.1\\share", session_id, 3).await;
    let wrong_file_id = smb_server::wire::messages::FileId::new(
        file_id.persistent,
        file_id.volatile.wrapping_add(1),
    );
    let status =
        create_durable_v2_reconnect_status(&mut s, session_id, tree_id, 4, wrong_file_id).await;
    assert_eq!(status, STATUS_OBJECT_NAME_NOT_FOUND);

    let reconnected = create_durable_v2_reconnect(&mut s, session_id, tree_id, 5, file_id).await;
    assert_eq!(reconnected, file_id);
    close(&mut s, session_id, tree_id, 6, file_id).await;

    drop(s);
    handle.abort();
}

#[tokio::test]
async fn durable_v2_reconnect_ignores_create_access_and_share() {
    let (handle, addr, mut s, session_id, tree_id) = setup_lock_server_with_addr_smb311().await;
    let file_id = create_durable_v2_lease(&mut s, session_id, tree_id, 4).await;
    drop(s);
    tokio::time::sleep(Duration::from_millis(25)).await;

    let mut s = TcpStream::connect(addr).await.expect("reconnect tcp");
    let _ = negotiate_smb311(&mut s).await;
    let session_id = anonymous_session_setup(&mut s).await;
    let tree_id = tree_connect(&mut s, "\\\\127.0.0.1\\share", session_id, 3).await;
    let reconnected = create_durable_v2_reconnect_with_access_and_share(
        &mut s, session_id, tree_id, 4, file_id, 0, 0,
    )
    .await;
    assert_eq!(reconnected, file_id);
    close(&mut s, session_id, tree_id, 5, file_id).await;

    drop(s);
    handle.abort();
}

#[tokio::test]
async fn durable_v2_create_replay_returns_existing_open_without_truncating() {
    let (handle, mut s, session_id, tree_id) = setup_lock_server_smb311().await;
    let (file_id, original_action) =
        create_durable_v2_lease_overwrite(&mut s, session_id, tree_id, 4, false).await;
    assert_eq!(original_action, 0x0000_0003);

    write(
        &mut s,
        session_id,
        tree_id,
        5,
        file_id,
        0,
        b"after",
        STATUS_SUCCESS,
    )
    .await;

    let (replayed_file_id, replayed_action) =
        create_durable_v2_lease_overwrite(&mut s, session_id, tree_id, 6, true).await;
    assert_eq!(replayed_file_id, file_id);
    assert_eq!(replayed_action, original_action);
    let data = read_data(&mut s, session_id, tree_id, 7, file_id, 0, 5).await;
    assert_eq!(data, b"after");
    close(&mut s, session_id, tree_id, 8, file_id).await;

    drop(s);
    handle.abort();
}

#[tokio::test]
async fn durable_v2_create_duplicate_guid_without_replay_fails_without_truncating() {
    let (handle, mut s, session_id, tree_id) = setup_lock_server_smb311().await;
    let (file_id, _original_action) =
        create_durable_v2_lease_overwrite(&mut s, session_id, tree_id, 4, false).await;
    write(
        &mut s,
        session_id,
        tree_id,
        5,
        file_id,
        0,
        b"kept",
        STATUS_SUCCESS,
    )
    .await;

    let (status, create) = create_durable_v2_lease_overwrite_result(
        &mut s,
        session_id,
        tree_id,
        6,
        false,
        b"lease-key-123456",
    )
    .await;
    assert_eq!(status, STATUS_DUPLICATE_OBJECTID);
    assert!(create.is_none());
    let data = read_data(&mut s, session_id, tree_id, 7, file_id, 0, 4).await;
    assert_eq!(data, b"kept");
    close(&mut s, session_id, tree_id, 8, file_id).await;

    drop(s);
    handle.abort();
}

#[tokio::test]
async fn durable_v2_create_replay_rejects_wrong_lease_key_without_truncating() {
    let (handle, mut s, session_id, tree_id) = setup_lock_server_smb311().await;
    let (file_id, _original_action) =
        create_durable_v2_lease_overwrite(&mut s, session_id, tree_id, 4, false).await;
    write(
        &mut s,
        session_id,
        tree_id,
        5,
        file_id,
        0,
        b"after",
        STATUS_SUCCESS,
    )
    .await;

    let (status, create) = create_durable_v2_lease_overwrite_result(
        &mut s,
        session_id,
        tree_id,
        6,
        true,
        b"wrong-lease-key!",
    )
    .await;
    assert_eq!(status, STATUS_ACCESS_DENIED);
    assert!(create.is_none());
    let data = read_data(&mut s, session_id, tree_id, 7, file_id, 0, 5).await;
    assert_eq!(data, b"after");
    close(&mut s, session_id, tree_id, 8, file_id).await;

    drop(s);
    handle.abort();
}

#[tokio::test]
async fn durable_v2_create_replay_rejects_different_session() {
    let (handle, addr, mut s, session_id, tree_id) = setup_lock_server_with_addr_smb311().await;
    let (file_id, _original_action) =
        create_durable_v2_lease_overwrite(&mut s, session_id, tree_id, 4, false).await;
    write(
        &mut s,
        session_id,
        tree_id,
        5,
        file_id,
        0,
        b"still",
        STATUS_SUCCESS,
    )
    .await;

    let mut other = TcpStream::connect(addr)
        .await
        .expect("connect second client");
    let _ = negotiate_smb311(&mut other).await;
    let other_session_id = anonymous_session_setup(&mut other).await;
    let other_tree_id = tree_connect(&mut other, "\\\\127.0.0.1\\share", other_session_id, 3).await;
    let (status, create) = create_durable_v2_lease_overwrite_result(
        &mut other,
        other_session_id,
        other_tree_id,
        4,
        true,
        b"lease-key-123456",
    )
    .await;
    assert_eq!(status, STATUS_DUPLICATE_OBJECTID);
    assert!(create.is_none());
    read(
        &mut s,
        session_id,
        tree_id,
        6,
        file_id,
        0,
        5,
        STATUS_SUCCESS,
    )
    .await;
    close(&mut s, session_id, tree_id, 7, file_id).await;

    drop(other);
    drop(s);
    handle.abort();
}

#[tokio::test]
async fn durable_v2_create_replay_while_original_create_pending_returns_file_not_available() {
    let (handle, mut s, session_id, tree_id) = setup_lock_server_smb311().await;
    let first_key = b"lease-key-123456";
    let replay_key = b"replay-leasekey!";

    let (leased, _) = create_lease_open_with_lease_data(
        &mut s,
        session_id,
        tree_id,
        4,
        0x0012_0089,
        lease_v2_request_with_key(0x0000_0001 | 0x0000_0002 | 0x0000_0004, first_key),
    )
    .await;

    send_create_durable_v2_lease_with_key(&mut s, session_id, tree_id, 5, replay_key, false).await;

    let frames = [read_frame(&mut s).await, read_frame(&mut s).await];
    let mut pending_async_id = None;
    let mut notification = None;
    for frame in frames {
        let (rh, rb) = parse_response_header(&frame);
        match rh.command {
            Command::Create => {
                assert_eq!(rh.channel_sequence_status, STATUS_PENDING);
                pending_async_id = Some(rh.async_id().expect("pending durable create async id"));
            }
            Command::OplockBreak => {
                notification = Some(
                    LeaseBreakNotification::parse(rb).expect("parse lease break notification"),
                );
            }
            other => panic!("unexpected response command {other:?}"),
        }
    }
    let pending_async_id = pending_async_id.expect("missing pending durable create");
    let notification = notification.expect("missing lease break notification");
    assert_eq!(&notification.lease_key, first_key);
    assert_eq!(notification.new_lease_state, 0x0000_0001 | 0x0000_0002);

    let status =
        create_durable_v2_lease_with_key_status(&mut s, session_id, tree_id, 6, replay_key, true)
            .await;
    assert_eq!(status, STATUS_FILE_NOT_AVAILABLE);

    let ack = LeaseBreakAck {
        structure_size: 36,
        reserved: 0,
        flags: 0,
        lease_key: *first_key,
        lease_state: notification.new_lease_state,
        lease_duration: 0,
    };
    let mut ack_body = Vec::new();
    ack.write_to(&mut ack_body).expect("write lease break ack");
    let ack_hdr = build_header(Command::OplockBreak, 7, session_id, tree_id);
    write_frame(&mut s, &ack_hdr, &ack_body).await;

    let frames = [read_frame(&mut s).await, read_frame(&mut s).await];
    let mut ack_seen = false;
    let mut pending_create = None;
    for frame in frames {
        let (rh, rb) = parse_response_header(&frame);
        match rh.command {
            Command::OplockBreak => {
                assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
                ack_seen = true;
            }
            Command::Create => {
                assert_eq!(rh.async_id(), Some(pending_async_id));
                assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
                pending_create =
                    Some(CreateResponse::parse(rb).expect("parse final pending create"));
            }
            other => panic!("unexpected post-ack command {other:?}"),
        }
    }
    assert!(ack_seen, "missing lease break ack response");
    let pending_create = pending_create.expect("missing final pending create");

    close(&mut s, session_id, tree_id, 8, leased.file_id).await;
    close(&mut s, session_id, tree_id, 9, pending_create.file_id).await;
    let (replay_status, replayed) = create_durable_v2_lease_with_key_result(
        &mut s,
        session_id,
        tree_id,
        10,
        replay_key,
        b"0123456789abcdef",
        true,
    )
    .await;
    assert_eq!(replay_status, STATUS_SUCCESS);
    let replayed = replayed.expect("parse completed create replay");
    assert_eq!(replayed.file_id, pending_create.file_id);
    assert_eq!(replayed.create_action, pending_create.create_action);

    drop(s);
    handle.abort();
}

#[tokio::test]
async fn durable_v2_metadata_only_create_is_not_create_replay_eligible() {
    let (handle, mut s, session_id, tree_id) = setup_lock_server_smb311().await;
    let first = create_durable_v2_metadata_only(&mut s, session_id, tree_id, 4, false).await;
    let second = create_durable_v2_metadata_only(&mut s, session_id, tree_id, 5, false).await;
    let replay = create_durable_v2_metadata_only(&mut s, session_id, tree_id, 6, true).await;

    assert_ne!(second.file_id, first.file_id);
    assert_ne!(replay.file_id, first.file_id);
    close(&mut s, session_id, tree_id, 7, first.file_id).await;
    close(&mut s, session_id, tree_id, 8, second.file_id).await;
    close(&mut s, session_id, tree_id, 9, replay.file_id).await;

    drop(s);
    handle.abort();
}

#[tokio::test]
async fn durable_v2_replay_after_replayed_handle_use_falls_through_to_new_create() {
    let (handle, mut s, session_id, tree_id) = setup_lock_server_smb311().await;
    let create_guid = b"replay6-guid-123";

    let first =
        create_durable_v2_batch_with_guid(&mut s, session_id, tree_id, 4, create_guid, false).await;
    let replayed =
        create_durable_v2_batch_with_guid(&mut s, session_id, tree_id, 5, create_guid, true).await;
    assert_eq!(replayed.file_id, first.file_id);

    let _ = query_standard_delete_pending(&mut s, session_id, tree_id, 6, first.file_id).await;

    let second_replay =
        create_durable_v2_batch_with_guid(&mut s, session_id, tree_id, 7, create_guid, true).await;
    assert_ne!(second_replay.file_id, first.file_id);

    close(&mut s, session_id, tree_id, 8, second_replay.file_id).await;
    close(&mut s, session_id, tree_id, 9, first.file_id).await;
    drop(s);
    handle.abort();
}

#[tokio::test]
async fn detached_durable_v2_lease_replay_preserves_created_action() {
    let (handle, addr, mut s, session_id, tree_id) = setup_lock_server_with_addr_smb311().await;
    let create_guid = b"twice-durable-01";
    let lease_key = b"twice-lease-key!";
    let name = "twice-durable.dat";

    let first = create_durable_v2_lease_name_with_guid(
        &mut s,
        session_id,
        tree_id,
        4,
        name,
        lease_key,
        create_guid,
        false,
    )
    .await;
    assert_eq!(first.create_action, 0x0000_0002);
    drop(s);
    tokio::time::sleep(Duration::from_millis(25)).await;

    let mut s = TcpStream::connect(addr).await.expect("reconnect tcp");
    let _ = negotiate_smb311(&mut s).await;
    let session_id = anonymous_session_setup(&mut s).await;
    let tree_id = tree_connect(&mut s, "\\\\127.0.0.1\\share", session_id, 3).await;

    let replay = create_durable_v2_lease_name_with_guid(
        &mut s,
        session_id,
        tree_id,
        4,
        name,
        lease_key,
        create_guid,
        true,
    )
    .await;
    assert_eq!(replay.file_id, first.file_id);
    assert_eq!(replay.create_action, 0x0000_0002);

    close(&mut s, session_id, tree_id, 5, replay.file_id).await;
    drop(s);
    handle.abort();
}

#[tokio::test]
async fn durable_write_rejects_stale_channel_sequence_number() {
    let (handle, mut s, session_id, tree_id) = setup_lock_server_smb311().await;
    let file_id = create_durable_v2_lease_with_access_and_share(
        &mut s,
        session_id,
        tree_id,
        4,
        0x0012_0089 | 0x0012_0116,
        0x0000_0007,
    )
    .await;

    write_with_channel_sequence(
        &mut s,
        session_id,
        tree_id,
        5,
        file_id,
        0,
        b"zero",
        0,
        STATUS_SUCCESS,
    )
    .await;
    write_with_channel_sequence(
        &mut s,
        session_id,
        tree_id,
        6,
        file_id,
        0,
        b"stale",
        0x8000,
        STATUS_FILE_NOT_AVAILABLE,
    )
    .await;
    write_with_channel_sequence(
        &mut s,
        session_id,
        tree_id,
        7,
        file_id,
        0,
        b"high",
        0x7fff,
        STATUS_SUCCESS,
    )
    .await;
    write_with_channel_sequence(
        &mut s,
        session_id,
        tree_id,
        8,
        file_id,
        0,
        b"old",
        0x7ffe,
        STATUS_FILE_NOT_AVAILABLE,
    )
    .await;
    write_with_channel_sequence(
        &mut s,
        session_id,
        tree_id,
        9,
        file_id,
        0,
        b"wrap",
        0x8000,
        STATUS_SUCCESS,
    )
    .await;

    close(&mut s, session_id, tree_id, 10, file_id).await;
    drop(s);
    handle.abort();
}

#[tokio::test]
async fn create_lease_request_grants_read_write_lease() {
    let (handle, mut s, session_id, tree_id) = setup_lock_server_smb311().await;
    let (create, lease_state) = create_lease_open(
        &mut s,
        session_id,
        tree_id,
        4,
        0x0012_0089 | 0x0012_0116,
        0x0000_0001 | 0x0000_0004,
    )
    .await;

    assert_eq!(create.oplock_level, 0xff);
    assert_eq!(lease_state, 0x0000_0001 | 0x0000_0004);
    close(&mut s, session_id, tree_id, 5, create.file_id).await;

    drop(s);
    handle.abort();
}

#[tokio::test]
async fn create_lease_request_grants_metadata_only_read_handle_write_lease() {
    let (handle, mut s, session_id, tree_id) = setup_lock_server_smb311().await;
    let (create, lease_state) = create_lease_open(
        &mut s,
        session_id,
        tree_id,
        4,
        0x0000_0080,
        0x0000_0001 | 0x0000_0002 | 0x0000_0004,
    )
    .await;

    assert_eq!(create.oplock_level, 0xff);
    assert_eq!(lease_state, 0x0000_0001 | 0x0000_0002 | 0x0000_0004);
    close(&mut s, session_id, tree_id, 5, create.file_id).await;

    drop(s);
    handle.abort();
}

#[tokio::test]
async fn existing_stat_open_does_not_block_read_handle_write_lease() {
    let (handle, mut s, session_id, tree_id) = setup_lock_server_smb311().await;

    let stat = create_oplock_open(&mut s, session_id, tree_id, 4, 0, 0x0000_0080).await;
    let (leased, lease_state) = create_lease_open(
        &mut s,
        session_id,
        tree_id,
        5,
        0x0000_0002,
        0x0000_0001 | 0x0000_0002 | 0x0000_0004,
    )
    .await;

    assert_eq!(leased.oplock_level, 0xff);
    assert_eq!(lease_state, 0x0000_0001 | 0x0000_0002 | 0x0000_0004);
    close(&mut s, session_id, tree_id, 6, leased.file_id).await;
    close(&mut s, session_id, tree_id, 7, stat.file_id).await;

    drop(s);
    handle.abort();
}

#[tokio::test]
async fn durable_v2_lease_grants_handle_caching_after_nonstat_metadata_open() {
    let (handle, mut s, session_id, tree_id) = setup_lock_server_smb311().await;

    let metadata = create_oplock_open(&mut s, session_id, tree_id, 4, 0, 0x0012_0180).await;
    let leased = create_durable_v2_lease(&mut s, session_id, tree_id, 5).await;

    close(&mut s, session_id, tree_id, 6, leased).await;
    close(&mut s, session_id, tree_id, 7, metadata.file_id).await;

    drop(s);
    handle.abort();
}

#[tokio::test]
async fn create_lease_request_rejects_same_key_on_different_file() {
    let (handle, root, mut s, session_id, tree_id) = setup_lock_server_with_path_smb311().await;
    std::fs::write(root.join("first.txt"), b"first").expect("seed first");
    std::fs::write(root.join("second.txt"), b"second").expect("seed second");
    let lease_key = b"lease-key-123456";

    let (first, grant) = create_lease_open_name_with_lease_data(
        &mut s,
        session_id,
        tree_id,
        4,
        "first.txt",
        0x0012_0089 | 0x0012_0116,
        lease_v2_request_with_key(0x0000_0001 | 0x0000_0002 | 0x0000_0004, lease_key),
    )
    .await;
    assert_eq!(grant.state, 0x0000_0001 | 0x0000_0002 | 0x0000_0004);

    send_create_lease_open_name_with_lease_data(
        &mut s,
        session_id,
        tree_id,
        5,
        "second.txt",
        0x0012_0089 | 0x0012_0116,
        lease_v2_request_with_key(0x0000_0001 | 0x0000_0002 | 0x0000_0004, lease_key),
    )
    .await;
    let resp = read_frame(&mut s).await;
    let (rh, _rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Create);
    assert_eq!(rh.channel_sequence_status, STATUS_INVALID_PARAMETER);

    close(&mut s, session_id, tree_id, 6, first.file_id).await;
    drop(s);
    handle.abort();
}

#[tokio::test]
async fn same_key_lease_survives_base_file_rename() {
    let (handle, root, mut s, session_id, tree_id) = setup_lock_server_with_path_smb311().await;
    let lease_key = b"lease-key-123456";

    let (first, first_grant) = create_lease_open_name_with_lease_data(
        &mut s,
        session_id,
        tree_id,
        4,
        "hello.txt",
        0x001f_01ff,
        lease_v2_request_with_key_and_epoch(
            0x0000_0001 | 0x0000_0002 | 0x0000_0004,
            lease_key,
            0x4711,
        ),
    )
    .await;
    assert_eq!(first_grant.state, 0x0000_0001 | 0x0000_0002 | 0x0000_0004);
    assert_eq!(first_grant.epoch, 0x4712);

    let rename = file_rename_information("renamed.txt", true);
    let req = SetInfoRequest {
        structure_size: 33,
        info_type: InfoType::File as u8,
        file_information_class: 0x0A,
        buffer_length: rename.len() as u32,
        buffer_offset: 64 + 32,
        reserved: 0,
        additional_information: 0,
        file_id: first.file_id,
        buffer: rename,
    };
    let mut body = Vec::new();
    req.write_to(&mut body).expect("write set-info rename");
    let hdr = build_header(Command::SetInfo, 5, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, _rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::SetInfo);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    assert_no_frame(&mut s).await;
    assert!(!root.join("hello.txt").exists());
    assert!(root.join("renamed.txt").exists());

    let (second, second_grant) = create_lease_open_name_with_lease_data(
        &mut s,
        session_id,
        tree_id,
        6,
        "renamed.txt",
        0x001f_01ff,
        lease_v2_request_with_key_and_epoch(0, lease_key, first_grant.epoch),
    )
    .await;
    assert_eq!(second_grant.state, 0x0000_0001 | 0x0000_0002 | 0x0000_0004);
    assert_eq!(second_grant.epoch, first_grant.epoch);

    close(&mut s, session_id, tree_id, 7, second.file_id).await;
    close(&mut s, session_id, tree_id, 8, first.file_id).await;
    drop(s);
    handle.abort();
}

#[tokio::test]
async fn overwrite_rename_breaks_target_lease_then_denies_while_target_open() {
    let (handle, root, mut s, session_id, tree_id) = setup_lock_server_with_path_smb311().await;
    std::fs::write(root.join("source.txt"), b"source").expect("seed source");
    std::fs::write(root.join("target.txt"), b"target").expect("seed target");
    let source_key = b"source-key-12345";
    let target_key = b"target-key-12345";

    let (source, source_grant) = create_lease_open_name_with_lease_data(
        &mut s,
        session_id,
        tree_id,
        4,
        "source.txt",
        0x001f_01ff,
        lease_v2_request_with_key_and_epoch(
            0x0000_0001 | 0x0000_0002 | 0x0000_0004,
            source_key,
            0x4711,
        ),
    )
    .await;
    let (target, target_grant) = create_lease_open_name_with_lease_data(
        &mut s,
        session_id,
        tree_id,
        5,
        "target.txt",
        0x001f_01ff,
        lease_v2_request_with_key_and_epoch(
            0x0000_0001 | 0x0000_0002 | 0x0000_0004,
            target_key,
            0x4711,
        ),
    )
    .await;
    assert_eq!(source_grant.state, 0x0000_0001 | 0x0000_0002 | 0x0000_0004);
    assert_eq!(target_grant.state, 0x0000_0001 | 0x0000_0002 | 0x0000_0004);

    let rename = file_rename_information("target.txt", true);
    let req = SetInfoRequest {
        structure_size: 33,
        info_type: InfoType::File as u8,
        file_information_class: 0x0A,
        buffer_length: rename.len() as u32,
        buffer_offset: 64 + 32,
        reserved: 0,
        additional_information: 0,
        file_id: source.file_id,
        buffer: rename,
    };
    let mut body = Vec::new();
    req.write_to(&mut body).expect("write set-info rename");
    let hdr = build_header(Command::SetInfo, 6, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;

    let first_frame = read_frame_with_timeout(&mut s).await;
    let second_frame = read_frame_with_timeout(&mut s).await;
    let frames = [first_frame, second_frame];
    let mut pending_async_id = None;
    let mut notification = None;
    for frame in frames {
        let (rh, rb) = parse_response_header(&frame);
        match rh.command {
            Command::SetInfo => {
                assert_eq!(rh.channel_sequence_status, STATUS_PENDING);
                pending_async_id = Some(rh.async_id().expect("pending rename async id"));
            }
            Command::OplockBreak => {
                assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
                notification =
                    Some(LeaseBreakNotification::parse(rb).expect("parse target lease break"));
            }
            other => panic!("unexpected response command {other:?}"),
        }
    }

    let notification = notification.expect("missing target lease break");
    assert_eq!(&notification.lease_key, target_key);
    assert_eq!(
        notification.current_lease_state,
        0x0000_0001 | 0x0000_0002 | 0x0000_0004
    );
    assert_eq!(notification.new_lease_state, 0x0000_0001 | 0x0000_0004);

    let ack = LeaseBreakAck {
        structure_size: 36,
        reserved: 0,
        flags: 0,
        lease_key: *target_key,
        lease_state: 0x0000_0001 | 0x0000_0004,
        lease_duration: 0,
    };
    let mut ack_body = Vec::new();
    ack.write_to(&mut ack_body)
        .expect("write target lease break ack");
    let ack_hdr = build_header(Command::OplockBreak, 7, session_id, tree_id);
    write_frame(&mut s, &ack_hdr, &ack_body).await;

    let first_frame = read_frame_with_timeout(&mut s).await;
    let second_frame = read_frame_with_timeout(&mut s).await;
    let frames = [first_frame, second_frame];
    let mut ack_seen = false;
    let mut denied_seen = false;
    for frame in frames {
        let (rh, _rb) = parse_response_header(&frame);
        match rh.command {
            Command::OplockBreak => {
                assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
                ack_seen = true;
            }
            Command::SetInfo => {
                assert_eq!(rh.async_id(), pending_async_id);
                assert_eq!(rh.channel_sequence_status, STATUS_ACCESS_DENIED);
                denied_seen = true;
            }
            other => panic!("unexpected post-ack response command {other:?}"),
        }
    }
    assert!(ack_seen, "missing lease break ack response");
    assert!(denied_seen, "missing final access denied rename response");
    assert_eq!(
        std::fs::read(root.join("target.txt")).expect("read target"),
        b"target"
    );
    assert_eq!(
        std::fs::read(root.join("source.txt")).expect("read source"),
        b"source"
    );

    close(&mut s, session_id, tree_id, 8, target.file_id).await;
    close(&mut s, session_id, tree_id, 9, source.file_id).await;
    drop(s);
    handle.abort();
}

#[tokio::test]
async fn stat_and_read_control_opens_without_lease_context_do_not_break_existing_lease() {
    let (handle, mut s, session_id, tree_id) = setup_lock_server_smb311().await;

    let (leased, lease_state) = create_lease_open(
        &mut s,
        session_id,
        tree_id,
        4,
        0x0012_0089 | 0x0012_0116,
        0x0000_0001 | 0x0000_0002 | 0x0000_0004,
    )
    .await;
    assert_eq!(lease_state, 0x0000_0001 | 0x0000_0002 | 0x0000_0004);

    let stat = create_oplock_open(&mut s, session_id, tree_id, 5, 0, 0x0010_0080).await;
    assert_no_frame(&mut s).await;

    let read_control = create_oplock_open(&mut s, session_id, tree_id, 6, 0, 0x0002_0000).await;
    assert_no_frame(&mut s).await;

    close(&mut s, session_id, tree_id, 7, leased.file_id).await;
    close(&mut s, session_id, tree_id, 8, stat.file_id).await;
    close(&mut s, session_id, tree_id, 9, read_control.file_id).await;
    drop(s);
    handle.abort();
}

#[tokio::test]
async fn data_open_without_lease_context_breaks_existing_write_lease() {
    let (handle, mut s, session_id, tree_id) = setup_lock_server_smb311().await;
    let lease_key = b"lease-key-123456";

    let (leased, grant) = create_lease_open_with_lease_data(
        &mut s,
        session_id,
        tree_id,
        4,
        0x0012_0089 | 0x0012_0116,
        lease_v2_request_with_key(0x0000_0001 | 0x0000_0002 | 0x0000_0004, lease_key),
    )
    .await;
    assert_eq!(grant.state, 0x0000_0001 | 0x0000_0002 | 0x0000_0004);

    send_create_oplock_open(&mut s, session_id, tree_id, 5, 0, 0x0000_0001).await;

    let frames = [read_frame(&mut s).await, read_frame(&mut s).await];
    let mut pending_async_id = None;
    let mut notification = None;
    for frame in frames {
        let (rh, rb) = parse_response_header(&frame);
        match rh.command {
            Command::Create => {
                assert_eq!(rh.channel_sequence_status, STATUS_PENDING);
                pending_async_id = Some(rh.async_id().expect("pending create async id"));
            }
            Command::OplockBreak => {
                assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
                notification = Some(
                    LeaseBreakNotification::parse(rb).expect("parse lease break notification"),
                );
            }
            other => panic!("unexpected response command {other:?}"),
        }
    }
    let pending_async_id = pending_async_id.expect("missing pending create");
    let notification = notification.expect("missing lease break notification");
    assert_eq!(&notification.lease_key, lease_key);
    assert_eq!(
        notification.current_lease_state,
        0x0000_0001 | 0x0000_0002 | 0x0000_0004
    );
    assert_eq!(notification.new_lease_state, 0x0000_0001 | 0x0000_0002);

    let ack = LeaseBreakAck {
        structure_size: 36,
        reserved: 0,
        flags: 0,
        lease_key: *lease_key,
        lease_state: 0x0000_0001 | 0x0000_0002,
        lease_duration: 0,
    };
    let mut ack_body = Vec::new();
    ack.write_to(&mut ack_body).expect("write lease break ack");
    let ack_hdr = build_header(Command::OplockBreak, 6, session_id, tree_id);
    write_frame(&mut s, &ack_hdr, &ack_body).await;

    let frames = [read_frame(&mut s).await, read_frame(&mut s).await];
    let mut ack_seen = false;
    let mut data_open = None;
    for frame in frames {
        let (rh, rb) = parse_response_header(&frame);
        match rh.command {
            Command::OplockBreak => {
                assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
                ack_seen = true;
            }
            Command::Create => {
                assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
                assert_eq!(rh.async_id(), Some(pending_async_id));
                data_open = Some(CreateResponse::parse(rb).expect("parse final create"));
            }
            other => panic!("unexpected post-ack command {other:?}"),
        }
    }
    assert!(ack_seen, "missing lease break ack response");
    let data_open = data_open.expect("missing final data-open create");

    close(&mut s, session_id, tree_id, 7, leased.file_id).await;
    close(&mut s, session_id, tree_id, 8, data_open.file_id).await;
    drop(s);
    handle.abort();
}

#[tokio::test]
async fn wrong_lease_break_ack_does_not_resume_pending_create() {
    let (handle, mut s, session_id, tree_id) = setup_lock_server_smb311().await;
    let lease_key = b"lease-key-123456";
    let other_key = b"fedcba9876543210";

    let (leased, grant) = create_lease_open_with_lease_data(
        &mut s,
        session_id,
        tree_id,
        4,
        0x0012_0089 | 0x0012_0116,
        lease_v2_request_with_key(0x0000_0001 | 0x0000_0004, lease_key),
    )
    .await;
    assert_eq!(grant.state, 0x0000_0001 | 0x0000_0004);

    send_create_lease_open_with_lease_data(
        &mut s,
        session_id,
        tree_id,
        5,
        0x0012_0089,
        lease_v2_request_with_key(0x0000_0001, other_key),
    )
    .await;

    let frames = [
        read_frame_with_timeout(&mut s).await,
        read_frame_with_timeout(&mut s).await,
    ];
    let mut pending_async_id = None;
    let mut notification = None;
    for frame in frames {
        let (rh, rb) = parse_response_header(&frame);
        match rh.command {
            Command::Create => {
                assert_eq!(rh.channel_sequence_status, STATUS_PENDING);
                pending_async_id = Some(rh.async_id().expect("pending create async id"));
            }
            Command::OplockBreak => {
                assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
                notification = Some(
                    LeaseBreakNotification::parse(rb).expect("parse lease break notification"),
                );
            }
            other => panic!("unexpected response command {other:?}"),
        }
    }
    let pending_async_id = pending_async_id.expect("missing pending create");
    let notification = notification.expect("missing lease break notification");
    assert_eq!(&notification.lease_key, lease_key);
    assert_eq!(notification.current_lease_state, 0x0000_0001 | 0x0000_0004);
    assert_eq!(notification.new_lease_state, 0x0000_0001);

    let (status, _) =
        send_lease_break_ack(&mut s, session_id, tree_id, 6, lease_key, 0x0000_0002).await;
    assert_eq!(status, STATUS_REQUEST_NOT_ACCEPTED);
    assert_no_frame(&mut s).await;

    send_async_cancel(&mut s, 7, session_id, pending_async_id).await;
    let cleanup = read_frame_with_timeout(&mut s).await;
    let (rh, _) = parse_response_header(&cleanup);
    assert_eq!(rh.command, Command::Create);
    assert_eq!(rh.async_id(), Some(pending_async_id));
    assert_eq!(rh.channel_sequence_status, STATUS_CANCELLED);

    close(&mut s, session_id, tree_id, 8, leased.file_id).await;
    drop(s);
    handle.abort();
}

#[tokio::test]
async fn overwrite_create_breaks_lease_to_none_and_rejects_wrong_ack_state() {
    const LEASE_READ: u32 = 0x0000_0001;
    const LEASE_HANDLE: u32 = 0x0000_0002;
    const LEASE_WRITE: u32 = 0x0000_0004;
    const LEASE_BREAK_IN_PROGRESS: u32 = 0x0000_0002;
    const FILE_ALL_ACCESS: u32 = 0x001f_01ff;

    let (handle, mut s, session_id, tree_id) = setup_lock_server_smb311().await;
    let lease_key = b"lease-key-123456";

    let (leased, grant) = create_lease_open_with_lease_data(
        &mut s,
        session_id,
        tree_id,
        4,
        FILE_ALL_ACCESS,
        lease_v1_request_with_key(LEASE_READ | LEASE_HANDLE | LEASE_WRITE, lease_key),
    )
    .await;
    assert_eq!(grant.state, LEASE_READ | LEASE_HANDLE | LEASE_WRITE);

    send_overwrite_create(&mut s, session_id, tree_id, 5, FILE_ALL_ACCESS).await;
    let frames = [
        read_frame_with_timeout(&mut s).await,
        read_frame_with_timeout(&mut s).await,
    ];
    let mut pending_async_id = None;
    let mut notification = None;
    for frame in frames {
        let (rh, rb) = parse_response_header(&frame);
        match rh.command {
            Command::Create => {
                assert_eq!(rh.channel_sequence_status, STATUS_PENDING);
                pending_async_id = Some(rh.async_id().expect("pending overwrite async id"));
            }
            Command::OplockBreak => {
                assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
                notification = Some(
                    LeaseBreakNotification::parse(rb).expect("parse lease break notification"),
                );
            }
            other => panic!("unexpected response command {other:?}"),
        }
    }
    let pending_async_id = pending_async_id.expect("missing pending overwrite create");
    let notification = notification.expect("missing overwrite lease break notification");
    assert_eq!(&notification.lease_key, lease_key);
    assert_eq!(
        notification.current_lease_state,
        LEASE_READ | LEASE_HANDLE | LEASE_WRITE
    );
    assert_eq!(notification.new_lease_state, 0);

    let (same_key, same_key_grant) = create_lease_open_with_lease_data(
        &mut s,
        session_id,
        tree_id,
        6,
        FILE_ALL_ACCESS,
        lease_v1_request_with_key(LEASE_READ | LEASE_HANDLE | LEASE_WRITE, lease_key),
    )
    .await;
    assert_eq!(
        same_key_grant.state,
        LEASE_READ | LEASE_HANDLE | LEASE_WRITE
    );
    assert_eq!(same_key_grant.flags, LEASE_BREAK_IN_PROGRESS);
    close(&mut s, session_id, tree_id, 7, same_key.file_id).await;
    assert_no_frame(&mut s).await;

    let (status, _) = send_lease_break_ack(
        &mut s,
        session_id,
        tree_id,
        8,
        lease_key,
        LEASE_READ | LEASE_HANDLE,
    )
    .await;
    assert_eq!(status, STATUS_REQUEST_NOT_ACCEPTED);
    assert_no_frame(&mut s).await;

    send_lease_break_ack_without_waiting(&mut s, session_id, tree_id, 9, lease_key, 0).await;
    let frames = [
        read_frame_with_timeout(&mut s).await,
        read_frame_with_timeout(&mut s).await,
    ];
    let mut saw_ack = false;
    let mut overwritten = None;
    for frame in frames {
        let (rh, rb) = parse_response_header(&frame);
        match rh.command {
            Command::OplockBreak => {
                assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
                let ack = LeaseBreakAck::parse(rb).expect("parse lease break ack response");
                assert_eq!(ack.lease_state, 0);
                saw_ack = true;
            }
            Command::Create => {
                assert_eq!(rh.async_id(), Some(pending_async_id));
                assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
                overwritten =
                    Some(CreateResponse::parse(rb).expect("parse final overwrite create"));
            }
            other => panic!("unexpected post-ack command {other:?}"),
        }
    }
    assert!(saw_ack, "missing lease break ack response");
    let overwritten = overwritten.expect("missing final overwrite create");

    let duplicate = send_lease_break_ack(&mut s, session_id, tree_id, 10, lease_key, 0).await;
    assert_eq!(duplicate.0, STATUS_UNSUCCESSFUL);

    close(&mut s, session_id, tree_id, 11, leased.file_id).await;
    close(&mut s, session_id, tree_id, 12, overwritten.file_id).await;
    drop(s);
    handle.abort();
}

#[tokio::test]
async fn overwrite_create_does_not_wait_for_handle_only_lease_break_to_none() {
    const LEASE_READ: u32 = 0x0000_0001;
    const LEASE_HANDLE: u32 = 0x0000_0002;
    const LEASE_BREAK_IN_PROGRESS: u32 = 0x0000_0002;
    const FILE_ALL_ACCESS: u32 = 0x001f_01ff;

    let (handle, mut s, session_id, tree_id) = setup_lock_server_smb311().await;
    let lease_key = b"lease-key-123456";

    let (leased, grant) = create_lease_open_with_lease_data(
        &mut s,
        session_id,
        tree_id,
        4,
        FILE_ALL_ACCESS,
        lease_v1_request_with_key(LEASE_READ | LEASE_HANDLE, lease_key),
    )
    .await;
    assert_eq!(grant.state, LEASE_READ | LEASE_HANDLE);

    send_overwrite_create(&mut s, session_id, tree_id, 5, FILE_ALL_ACCESS).await;
    let frames = [
        read_frame_with_timeout(&mut s).await,
        read_frame_with_timeout(&mut s).await,
    ];
    let mut notification = None;
    let mut overwritten = None;
    for frame in frames {
        let (rh, rb) = parse_response_header(&frame);
        match rh.command {
            Command::Create => {
                assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
                overwritten = Some(CreateResponse::parse(rb).expect("parse overwrite create"));
            }
            Command::OplockBreak => {
                assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
                notification = Some(
                    LeaseBreakNotification::parse(rb).expect("parse lease break notification"),
                );
            }
            other => panic!("unexpected response command {other:?}"),
        }
    }
    let notification = notification.expect("missing handle-only lease break");
    assert_eq!(&notification.lease_key, lease_key);
    assert_eq!(notification.current_lease_state, LEASE_READ | LEASE_HANDLE);
    assert_eq!(notification.new_lease_state, 0);
    let overwritten = overwritten.expect("missing synchronous overwrite create");
    close(&mut s, session_id, tree_id, 6, overwritten.file_id).await;
    assert_no_frame(&mut s).await;

    send_overwrite_create(&mut s, session_id, tree_id, 7, FILE_ALL_ACCESS).await;
    let frame = read_frame_with_timeout(&mut s).await;
    let (rh, rb) = parse_response_header(&frame);
    assert_eq!(rh.command, Command::Create);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let overwritten_again = CreateResponse::parse(rb).expect("parse second overwrite create");
    close(&mut s, session_id, tree_id, 8, overwritten_again.file_id).await;
    assert_no_frame(&mut s).await;

    let (same_key, same_key_grant) = create_lease_open_with_lease_data(
        &mut s,
        session_id,
        tree_id,
        9,
        FILE_ALL_ACCESS,
        lease_v1_request_with_key(0, lease_key),
    )
    .await;
    assert_eq!(same_key_grant.state, LEASE_READ | LEASE_HANDLE);
    assert_eq!(same_key_grant.flags, LEASE_BREAK_IN_PROGRESS);
    close(&mut s, session_id, tree_id, 10, same_key.file_id).await;
    assert_no_frame(&mut s).await;

    let (status, ack_body) =
        send_lease_break_ack(&mut s, session_id, tree_id, 11, lease_key, 0).await;
    assert_eq!(status, STATUS_SUCCESS);
    let ack = LeaseBreakAck::parse(&ack_body).expect("parse lease break ack response");
    assert_eq!(ack.lease_state, 0);
    assert_no_frame(&mut s).await;

    close(&mut s, session_id, tree_id, 12, leased.file_id).await;
    drop(s);
    handle.abort();
}

#[tokio::test]
async fn deferred_lease_break_ack_remains_valid_after_second_pending_create() {
    const LEASE_READ: u32 = 0x0000_0001;
    const LEASE_HANDLE: u32 = 0x0000_0002;
    const LEASE_WRITE: u32 = 0x0000_0004;
    const LEASE_BREAK_IN_PROGRESS: u32 = 0x0000_0002;
    const FILE_ALL_ACCESS: u32 = 0x001f_01ff;

    let (handle, mut s, session_id, tree_id) = setup_lock_server_smb311().await;
    let lease_key = b"lease-key-123456";
    let lease_epoch = 0x11;

    let (leased, grant) = create_lease_open_with_lease_data(
        &mut s,
        session_id,
        tree_id,
        4,
        FILE_ALL_ACCESS,
        lease_v2_request_with_key_and_epoch(
            LEASE_READ | LEASE_HANDLE | LEASE_WRITE,
            lease_key,
            lease_epoch,
        ),
    )
    .await;
    assert_eq!(grant.state, LEASE_READ | LEASE_HANDLE | LEASE_WRITE);
    assert_eq!(grant.epoch, lease_epoch + 1);

    send_create_oplock_open(&mut s, session_id, tree_id, 5, 0, FILE_ALL_ACCESS).await;
    let frames = [
        read_frame_with_timeout(&mut s).await,
        read_frame_with_timeout(&mut s).await,
    ];
    let mut notification = None;
    for frame in frames {
        let (rh, rb) = parse_response_header(&frame);
        match rh.command {
            Command::Create => assert_eq!(rh.channel_sequence_status, STATUS_PENDING),
            Command::OplockBreak => {
                notification =
                    Some(LeaseBreakNotification::parse(rb).expect("parse first lease break"));
            }
            other => panic!("unexpected response command {other:?}"),
        }
    }
    let notification = notification.expect("missing first lease break");
    assert_eq!(
        notification.current_lease_state,
        LEASE_READ | LEASE_HANDLE | LEASE_WRITE
    );
    assert_eq!(notification.new_lease_state, LEASE_READ | LEASE_HANDLE);
    let break_epoch = notification.new_epoch;
    assert_eq!(break_epoch, grant.epoch + 1);

    let (same_key, same_key_grant) = create_lease_open_with_lease_data(
        &mut s,
        session_id,
        tree_id,
        6,
        FILE_ALL_ACCESS,
        lease_v2_request_with_key_and_epoch(
            LEASE_READ | LEASE_HANDLE | LEASE_WRITE,
            lease_key,
            break_epoch,
        ),
    )
    .await;
    assert_eq!(
        same_key_grant.state,
        LEASE_READ | LEASE_HANDLE | LEASE_WRITE
    );
    assert_eq!(same_key_grant.flags, LEASE_BREAK_IN_PROGRESS);
    assert_eq!(same_key_grant.epoch, break_epoch);
    close(&mut s, session_id, tree_id, 7, same_key.file_id).await;

    send_overwrite_create(&mut s, session_id, tree_id, 8, FILE_ALL_ACCESS).await;
    let second_pending_frame = read_frame_with_timeout(&mut s).await;
    let (rh, _) = parse_response_header(&second_pending_frame);
    assert_eq!(rh.command, Command::Create);
    assert_eq!(rh.channel_sequence_status, STATUS_PENDING);

    let (same_key, same_key_grant) = create_lease_open_with_lease_data(
        &mut s,
        session_id,
        tree_id,
        9,
        FILE_ALL_ACCESS,
        lease_v2_request_with_key_and_epoch(
            LEASE_READ | LEASE_HANDLE | LEASE_WRITE,
            lease_key,
            break_epoch,
        ),
    )
    .await;
    assert_eq!(
        same_key_grant.state,
        LEASE_READ | LEASE_HANDLE | LEASE_WRITE
    );
    assert_eq!(same_key_grant.flags, LEASE_BREAK_IN_PROGRESS);
    assert_eq!(same_key_grant.epoch, break_epoch);
    close(&mut s, session_id, tree_id, 10, same_key.file_id).await;

    send_lease_break_ack_without_waiting(
        &mut s,
        session_id,
        tree_id,
        11,
        lease_key,
        LEASE_READ | LEASE_HANDLE,
    )
    .await;
    let frames = [
        read_frame_with_timeout(&mut s).await,
        read_frame_with_timeout(&mut s).await,
    ];
    let mut saw_ack = false;
    let mut saw_next_break = false;
    for frame in frames {
        let (rh, rb) = parse_response_header(&frame);
        assert_eq!(rh.command, Command::OplockBreak);
        assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
        match rb.first().copied() {
            Some(36) => {
                let ack = LeaseBreakAck::parse(rb).expect("parse lease break ack response");
                assert_eq!(ack.lease_state, LEASE_READ | LEASE_HANDLE);
                saw_ack = true;
            }
            Some(44) => {
                let notification =
                    LeaseBreakNotification::parse(rb).expect("parse staged lease break");
                assert_eq!(notification.current_lease_state, LEASE_READ | LEASE_HANDLE);
                assert_eq!(notification.new_lease_state, LEASE_READ);
                assert_eq!(notification.new_epoch, break_epoch);
                saw_next_break = true;
            }
            other => panic!("unexpected oplock break body structure {other:?}"),
        }
    }
    assert!(saw_ack, "missing lease break ack response");
    assert!(saw_next_break, "missing staged lease break");

    let (same_key, same_key_grant) = create_lease_open_with_lease_data(
        &mut s,
        session_id,
        tree_id,
        12,
        FILE_ALL_ACCESS,
        lease_v2_request_with_key_and_epoch(
            LEASE_READ | LEASE_HANDLE | LEASE_WRITE,
            lease_key,
            break_epoch,
        ),
    )
    .await;
    assert_eq!(same_key_grant.state, LEASE_READ | LEASE_HANDLE);
    assert_eq!(same_key_grant.flags, LEASE_BREAK_IN_PROGRESS);
    assert_eq!(same_key_grant.epoch, break_epoch);
    close(&mut s, session_id, tree_id, 13, same_key.file_id).await;

    close(&mut s, session_id, tree_id, 14, leased.file_id).await;
    drop(s);
    handle.abort();
}

#[tokio::test]
async fn write_capable_open_preserves_existing_read_lease() {
    let (handle, mut s, session_id, tree_id) = setup_lock_server_smb311().await;

    let (leased, lease_state) = create_lease_open(
        &mut s,
        session_id,
        tree_id,
        4,
        0x0012_0089 | 0x0012_0116,
        0x0000_0001,
    )
    .await;
    assert_eq!(lease_state, 0x0000_0001);

    let writer = create_oplock_open(&mut s, session_id, tree_id, 5, 0, 0x4000_0000).await;
    assert_no_frame(&mut s).await;

    close(&mut s, session_id, tree_id, 6, leased.file_id).await;
    close(&mut s, session_id, tree_id, 7, writer.file_id).await;
    drop(s);
    handle.abort();
}

#[tokio::test]
async fn write_breaks_existing_read_lease_to_none() {
    let (handle, mut s, session_id, tree_id) = setup_lock_server_smb311().await;
    let lease_key = b"lease-key-123456";

    let (leased, lease_state) = create_lease_open_with_lease_data(
        &mut s,
        session_id,
        tree_id,
        4,
        0x0012_0089 | 0x0012_0116,
        lease_v2_request_with_key(0x0000_0001, lease_key),
    )
    .await;
    assert_eq!(lease_state.state, 0x0000_0001);
    let writer = create_oplock_open(&mut s, session_id, tree_id, 5, 0, 0x4000_0000).await;

    let req = WriteRequest {
        structure_size: 49,
        data_offset: WriteRequest::STANDARD_DATA_OFFSET,
        length: 1,
        offset: 0,
        file_id: writer.file_id,
        channel: 0,
        remaining_bytes: 0,
        write_channel_info_offset: 0,
        write_channel_info_length: 0,
        flags: 0,
        data: b"x".to_vec(),
    };
    let mut body = Vec::new();
    req.write_to(&mut body).expect("write write request");
    let hdr = build_header(Command::Write, 6, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;

    let frames = [read_frame(&mut s).await, read_frame(&mut s).await];
    let mut write_seen = false;
    let mut break_seen = false;
    for frame in frames {
        let (rh, rb) = parse_response_header(&frame);
        match rh.command {
            Command::Write => {
                assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
                let wr = WriteResponse::parse(rb).expect("parse write response");
                assert_eq!(wr.count, 1);
                write_seen = true;
            }
            Command::OplockBreak => {
                assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
                let notification =
                    LeaseBreakNotification::parse(rb).expect("parse lease break notification");
                assert_eq!(&notification.lease_key, lease_key);
                assert_eq!(notification.current_lease_state, 0x0000_0001);
                assert_eq!(notification.new_lease_state, 0);
                break_seen = true;
            }
            other => panic!("unexpected response command {other:?}"),
        }
    }
    assert!(write_seen, "missing write response");
    assert!(break_seen, "missing lease break notification");

    close(&mut s, session_id, tree_id, 7, leased.file_id).await;
    close(&mut s, session_id, tree_id, 8, writer.file_id).await;
    drop(s);
    handle.abort();
}

#[tokio::test]
async fn lease_break_sent_once_per_lease_key_for_multiple_read_lease_opens() {
    let (handle, mut s, session_id, tree_id) = setup_lock_server_smb311().await;
    let lease_key = b"lease-key-123456";

    let (first, first_grant) = create_lease_open_with_lease_data(
        &mut s,
        session_id,
        tree_id,
        4,
        0x0012_0089 | 0x0012_0116,
        lease_v2_request_with_key(0x0000_0001, lease_key),
    )
    .await;
    let (second, second_grant) = create_lease_open_with_lease_data(
        &mut s,
        session_id,
        tree_id,
        5,
        0x0012_0089 | 0x0012_0116,
        lease_v2_request_with_key(0x0000_0001, lease_key),
    )
    .await;
    assert_eq!(first_grant.state, 0x0000_0001);
    assert_eq!(second_grant.state, 0x0000_0001);

    let writer = create_oplock_open(&mut s, session_id, tree_id, 6, 0, 0x4000_0000).await;
    write_success_and_expect_lease_break(
        &mut s,
        session_id,
        tree_id,
        7,
        writer.file_id,
        0,
        b"x",
        lease_key,
        0x0000_0001,
        0,
    )
    .await;
    assert_no_frame(&mut s).await;

    close(&mut s, session_id, tree_id, 8, first.file_id).await;
    close(&mut s, session_id, tree_id, 9, second.file_id).await;
    close(&mut s, session_id, tree_id, 10, writer.file_id).await;
    drop(s);
    handle.abort();
}

#[tokio::test]
async fn smb210_read_lease_break_uses_zero_epoch() {
    let (handle, mut s, session_id, tree_id) = setup_lock_server().await;
    let lease_key = b"lease-key-123456";

    let (leased, lease_grant) = create_lease_open_with_lease_data(
        &mut s,
        session_id,
        tree_id,
        4,
        0x0012_0089 | 0x0012_0116,
        lease_v1_request_with_key(0x0000_0001, lease_key),
    )
    .await;
    assert_eq!(lease_grant.response_len, 32);
    assert_eq!(lease_grant.state, 0x0000_0001);

    let writer = create_oplock_open(&mut s, session_id, tree_id, 5, 0, 0x4000_0000).await;
    let req = WriteRequest {
        structure_size: 49,
        data_offset: WriteRequest::STANDARD_DATA_OFFSET,
        length: 1,
        offset: 0,
        file_id: writer.file_id,
        channel: 0,
        remaining_bytes: 0,
        write_channel_info_offset: 0,
        write_channel_info_length: 0,
        flags: 0,
        data: b"x".to_vec(),
    };
    let mut body = Vec::new();
    req.write_to(&mut body).expect("write write request");
    let hdr = build_header(Command::Write, 6, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;

    let frames = [read_frame(&mut s).await, read_frame(&mut s).await];
    let mut saw_write = false;
    let mut saw_break = false;
    for frame in frames {
        let (rh, rb) = parse_response_header(&frame);
        match rh.command {
            Command::Write => {
                assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
                let wr = WriteResponse::parse(rb).expect("parse write response");
                assert_eq!(wr.count, 1);
                saw_write = true;
            }
            Command::OplockBreak => {
                assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
                let notification =
                    LeaseBreakNotification::parse(rb).expect("parse lease break notification");
                assert_eq!(notification.new_epoch, 0);
                assert_eq!(notification.flags, 0);
                assert_eq!(&notification.lease_key, lease_key);
                assert_eq!(notification.current_lease_state, 0x0000_0001);
                assert_eq!(notification.new_lease_state, 0);
                saw_break = true;
            }
            other => panic!("unexpected response command {other:?}"),
        }
    }
    assert!(saw_write, "missing write response");
    assert!(saw_break, "missing lease break notification");

    close(&mut s, session_id, tree_id, 7, leased.file_id).await;
    close(&mut s, session_id, tree_id, 8, writer.file_id).await;
    drop(s);
    handle.abort();
}

#[tokio::test]
async fn create_ignores_durable_v2_request_when_unsupported_but_returns_mxac() {
    let (handle, mut s, session_id, tree_id) = setup_lock_server().await;

    let name = utf16le("hello.txt");
    let req = CreateRequest {
        structure_size: 57,
        security_flags: 0,
        requested_oplock_level: 0,
        impersonation_level: 2,
        smb_create_flags: 0,
        reserved: 0,
        desired_access: 0x001f_01ff,
        file_attributes: 0,
        share_access: 0x0000_0007,
        create_disposition: 1,
        create_options: 0,
        name_offset: 0x78,
        name_length: name.len() as u16,
        create_contexts_offset: 0,
        create_contexts_length: 0,
        name,
        create_contexts: vec![],
    };
    let body = create_request_with_contexts(
        req,
        &[
            CreateContext {
                name: CreateContext::NAME_DH2Q.to_vec(),
                data: durable_v2_request(0),
            },
            CreateContext {
                name: CreateContext::NAME_MXAC.to_vec(),
                data: Vec::new(),
            },
        ],
    );
    let hdr = build_header(Command::Create, 4, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Create);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let create = CreateResponse::parse(rb).expect("parse create");
    let contexts = CreateContext::parse_chain(&create.create_contexts).expect("parse contexts");
    assert!(
        contexts
            .iter()
            .all(|ctx| ctx.name != CreateContext::NAME_DH2Q.as_slice()),
        "unexpected durable v2 response context: {contexts:?}"
    );
    assert!(
        contexts
            .iter()
            .any(|ctx| ctx.name == CreateContext::NAME_MXAC.as_slice()),
        "missing maximal access response context: {contexts:?}"
    );

    close(&mut s, session_id, tree_id, 5, create.file_id).await;
    drop(s);
    handle.abort();
}

#[tokio::test]
async fn set_info_eof_breaks_existing_read_lease_to_none() {
    let (handle, mut s, session_id, tree_id) = setup_lock_server_smb311().await;
    let lease_key = b"lease-key-123456";

    let (leased, lease_state) = create_lease_open_with_lease_data(
        &mut s,
        session_id,
        tree_id,
        4,
        0x0012_0089 | 0x0012_0116,
        lease_v2_request_with_key(0x0000_0001, lease_key),
    )
    .await;
    assert_eq!(lease_state.state, 0x0000_0001);
    let writer = create_oplock_open(&mut s, session_id, tree_id, 5, 0, 0x4000_0000).await;

    let mut eof = Vec::new();
    eof.extend_from_slice(&3u64.to_le_bytes());
    let req = SetInfoRequest {
        structure_size: 33,
        info_type: InfoType::File as u8,
        file_information_class: 0x14,
        buffer_length: eof.len() as u32,
        buffer_offset: 64 + 32,
        reserved: 0,
        additional_information: 0,
        file_id: writer.file_id,
        buffer: eof,
    };
    let mut body = Vec::new();
    req.write_to(&mut body).expect("write set-info eof");
    let hdr = build_header(Command::SetInfo, 6, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;

    let frames = [read_frame(&mut s).await, read_frame(&mut s).await];
    let mut set_info_seen = false;
    let mut break_seen = false;
    for frame in frames {
        let (rh, rb) = parse_response_header(&frame);
        match rh.command {
            Command::SetInfo => {
                assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
                set_info_seen = true;
            }
            Command::OplockBreak => {
                assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
                let notification =
                    LeaseBreakNotification::parse(rb).expect("parse lease break notification");
                assert_eq!(&notification.lease_key, lease_key);
                assert_eq!(notification.current_lease_state, 0x0000_0001);
                assert_eq!(notification.new_lease_state, 0);
                break_seen = true;
            }
            other => panic!("unexpected response command {other:?}"),
        }
    }
    assert!(set_info_seen, "missing set-info response");
    assert!(break_seen, "missing lease break notification");

    close(&mut s, session_id, tree_id, 7, leased.file_id).await;
    close(&mut s, session_id, tree_id, 8, writer.file_id).await;
    drop(s);
    handle.abort();
}

#[tokio::test]
async fn write_breaks_own_level_ii_oplock_to_none_without_ack() {
    let (handle, mut s, session_id, tree_id) = setup_lock_server_smb311().await;

    let level_ii = create_oplock_open(&mut s, session_id, tree_id, 4, 0x01, 0x001f_01ff).await;
    assert_eq!(level_ii.oplock_level, 0x01);

    let req = WriteRequest {
        structure_size: 49,
        data_offset: WriteRequest::STANDARD_DATA_OFFSET,
        length: 1,
        offset: 0,
        file_id: level_ii.file_id,
        channel: 0,
        remaining_bytes: 0,
        write_channel_info_offset: 0,
        write_channel_info_length: 0,
        flags: 0,
        data: b"x".to_vec(),
    };
    let mut body = Vec::new();
    req.write_to(&mut body).expect("write write request");
    let hdr = build_header(Command::Write, 5, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;

    let frames = [read_frame(&mut s).await, read_frame(&mut s).await];
    let mut write_seen = false;
    let mut break_seen = false;
    for frame in frames {
        let (rh, rb) = parse_response_header(&frame);
        match rh.command {
            Command::Write => {
                assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
                let wr = WriteResponse::parse(rb).expect("parse write response");
                assert_eq!(wr.count, 1);
                write_seen = true;
            }
            Command::OplockBreak => {
                assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
                let notification = OplockBreakAck::parse(rb).expect("parse oplock break");
                assert_eq!(notification.oplock_level, 0);
                assert_eq!(notification.file_id, level_ii.file_id);
                break_seen = true;
            }
            other => panic!("unexpected response command {other:?}"),
        }
    }
    assert!(write_seen, "missing write response");
    assert!(break_seen, "missing LevelII-to-None oplock break");

    let ack = OplockBreakAck {
        structure_size: 24,
        oplock_level: 0,
        reserved: 0,
        reserved2: 0,
        file_id: level_ii.file_id,
    };
    let mut ack_body = Vec::new();
    ack.write_to(&mut ack_body).expect("write oplock break ack");
    let ack_hdr = build_header(Command::OplockBreak, 6, session_id, tree_id);
    write_frame(&mut s, &ack_hdr, &ack_body).await;
    let resp = read_frame(&mut s).await;
    let (rh, _rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::OplockBreak);
    assert_eq!(rh.channel_sequence_status, STATUS_INVALID_OPLOCK_PROTOCOL);

    close(&mut s, session_id, tree_id, 7, level_ii.file_id).await;
    drop(s);
    handle.abort();
}

#[tokio::test]
async fn write_breaks_level_ii_oplocks_across_connections() {
    let (handle, addr, mut s1, session1, tree1) = setup_lock_server_with_addr_smb311().await;
    let mut s2 = TcpStream::connect(addr).await.expect("connect second");
    let _ = negotiate_smb311(&mut s2).await;
    let session2 = anonymous_session_setup(&mut s2).await;
    let tree2 = tree_connect(&mut s2, "\\\\127.0.0.1\\share", session2, 3).await;

    let first = create_oplock_open(&mut s1, session1, tree1, 4, 0x01, 0x001f_01ff).await;
    assert_eq!(first.oplock_level, 0x01);
    let second = create_oplock_open(&mut s2, session2, tree2, 4, 0x01, 0x001f_01ff).await;
    assert_eq!(second.oplock_level, 0x01);
    assert_ne!(
        first.file_id, second.file_id,
        "disk file ids are allocated globally, not per connection"
    );

    send_write(&mut s2, session2, tree2, 5, second.file_id, 0, b"x").await;

    let first_break = read_frame_with_timeout(&mut s1).await;
    let (rh, rb) = parse_response_header(&first_break);
    assert_eq!(rh.command, Command::OplockBreak);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let notification = OplockBreakAck::parse(rb).expect("parse first oplock break");
    assert_eq!(notification.oplock_level, 0);
    assert_eq!(notification.file_id, first.file_id);

    let frames = [
        read_frame_with_timeout(&mut s2).await,
        read_frame_with_timeout(&mut s2).await,
    ];
    let mut saw_write = false;
    let mut saw_second_break = false;
    for frame in frames {
        let (rh, rb) = parse_response_header(&frame);
        match rh.command {
            Command::Write => {
                assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
                let wr = WriteResponse::parse(rb).expect("parse write");
                assert_eq!(wr.count, 1);
                saw_write = true;
            }
            Command::OplockBreak => {
                assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
                let notification = OplockBreakAck::parse(rb).expect("parse second oplock break");
                assert_eq!(notification.oplock_level, 0);
                assert_eq!(notification.file_id, second.file_id);
                saw_second_break = true;
            }
            other => panic!("unexpected write-side response command {other:?}"),
        }
    }
    assert!(saw_write, "missing write response");
    assert!(saw_second_break, "missing second connection oplock break");

    close(&mut s1, session1, tree1, 6, first.file_id).await;
    close(&mut s2, session2, tree2, 6, second.file_id).await;
    drop(s1);
    drop(s2);
    handle.abort();
}

#[tokio::test]
async fn batch_oplock_ack_uses_connection_scoped_file_id() {
    let (handle, addr, mut s1, session1, tree1) = setup_lock_server_with_addr_smb311().await;
    let mut s2 = TcpStream::connect(addr).await.expect("connect second");
    let _ = negotiate_smb311(&mut s2).await;
    let session2 = anonymous_session_setup(&mut s2).await;
    let tree2 = tree_connect(&mut s2, "\\\\127.0.0.1\\share", session2, 3).await;

    let first = create_oplock_open(&mut s1, session1, tree1, 4, 0x09, 0x001f_01ff).await;
    assert_eq!(first.oplock_level, 0x09);

    send_create_oplock_open(&mut s2, session2, tree2, 4, 0x09, 0x001f_01ff).await;
    let frames = [
        read_frame_with_timeout(&mut s1).await,
        read_frame_with_timeout(&mut s2).await,
    ];
    let mut notification = None;
    let mut pending_async_id = None;
    for frame in frames {
        let (rh, rb) = parse_response_header(&frame);
        match rh.command {
            Command::OplockBreak => {
                assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
                notification = Some(OplockBreakAck::parse(rb).expect("parse oplock break"));
            }
            Command::Create => {
                assert_eq!(rh.channel_sequence_status, STATUS_PENDING);
                pending_async_id = Some(rh.async_id().expect("pending create async id"));
            }
            other => panic!("unexpected pre-ack response command {other:?}"),
        }
    }

    let notification = notification.expect("missing Batch-to-LevelII break");
    assert_eq!(notification.oplock_level, 0x01);
    assert_eq!(notification.file_id, first.file_id);

    let ack = OplockBreakAck {
        structure_size: 24,
        oplock_level: 0x01,
        reserved: 0,
        reserved2: 0,
        file_id: first.file_id,
    };
    let mut body = Vec::new();
    ack.write_to(&mut body).expect("write oplock break ack");
    let hdr = build_header(Command::OplockBreak, 5, session1, tree1);
    write_frame(&mut s1, &hdr, &body).await;

    let frames = [
        read_frame_with_timeout(&mut s1).await,
        read_frame_with_timeout(&mut s2).await,
    ];
    let mut saw_ack = false;
    let mut second = None;
    for frame in frames {
        let (rh, rb) = parse_response_header(&frame);
        match rh.command {
            Command::OplockBreak => {
                assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
                let ack = OplockBreakAck::parse(rb).expect("parse oplock break ack response");
                assert_eq!(ack.oplock_level, 0x01);
                assert_eq!(ack.file_id, first.file_id);
                saw_ack = true;
            }
            Command::Create => {
                assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
                assert_eq!(rh.async_id(), pending_async_id);
                second = Some(CreateResponse::parse(rb).expect("parse final create"));
            }
            other => panic!("unexpected post-ack response command {other:?}"),
        }
    }

    assert!(saw_ack, "missing oplock ACK response");
    let second = second.expect("missing final create response");
    assert_eq!(second.oplock_level, 0x01);

    let delete_open = create_named_open(
        &mut s2,
        session2,
        tree2,
        6,
        "hello.txt",
        0x0001_0000,
        0x0000_0007,
        1,
        0x0000_1040,
        0,
    )
    .await;
    close(&mut s2, session2, tree2, 7, delete_open.file_id).await;
    assert_no_frame(&mut s1).await;
    assert_no_frame(&mut s2).await;

    close(&mut s1, session1, tree1, 8, first.file_id).await;
    close(&mut s1, session1, tree1, 9, second.file_id).await;
    drop(s1);
    drop(s2);
    handle.abort();
}

#[tokio::test]
async fn exclusive_oplock_break_to_level_ii_resumes_cross_connection_create() {
    let (handle, addr, mut s1, session1, tree1) = setup_lock_server_with_addr_smb311().await;
    let mut s2 = TcpStream::connect(addr).await.expect("connect second");
    let _ = negotiate_smb311(&mut s2).await;
    let session2 = anonymous_session_setup(&mut s2).await;
    let tree2 = tree_connect(&mut s2, "\\\\127.0.0.1\\share", session2, 3).await;

    let first = create_oplock_open(&mut s1, session1, tree1, 4, 0x08, 0x001f_01ff).await;
    assert_eq!(first.oplock_level, 0x08);

    send_create_oplock_open(&mut s2, session2, tree2, 4, 0x08, 0x001f_01ff).await;
    let frames = [
        read_frame_with_timeout(&mut s1).await,
        read_frame_with_timeout(&mut s2).await,
    ];
    let mut notification = None;
    let mut pending_async_id = None;
    for frame in frames {
        let (rh, rb) = parse_response_header(&frame);
        match rh.command {
            Command::OplockBreak => {
                assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
                notification = Some(OplockBreakAck::parse(rb).expect("parse oplock break"));
            }
            Command::Create => {
                assert_eq!(rh.channel_sequence_status, STATUS_PENDING);
                pending_async_id = Some(rh.async_id().expect("pending create async id"));
            }
            other => panic!("unexpected pre-ack response command {other:?}"),
        }
    }

    let notification = notification.expect("missing Exclusive-to-LevelII break");
    assert_eq!(notification.oplock_level, 0x01);
    assert_eq!(notification.file_id, first.file_id);

    let ack = OplockBreakAck {
        structure_size: 24,
        oplock_level: 0x01,
        reserved: 0,
        reserved2: 0,
        file_id: first.file_id,
    };
    let mut body = Vec::new();
    ack.write_to(&mut body).expect("write oplock break ack");
    let hdr = build_header(Command::OplockBreak, 5, session1, tree1);
    write_frame(&mut s1, &hdr, &body).await;

    let frames = [
        read_frame_with_timeout(&mut s1).await,
        read_frame_with_timeout(&mut s2).await,
    ];
    let mut saw_ack = false;
    let mut second = None;
    for frame in frames {
        let (rh, rb) = parse_response_header(&frame);
        match rh.command {
            Command::OplockBreak => {
                assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
                let ack = OplockBreakAck::parse(rb).expect("parse oplock break ack response");
                assert_eq!(ack.oplock_level, 0x01);
                assert_eq!(ack.file_id, first.file_id);
                saw_ack = true;
            }
            Command::Create => {
                assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
                assert_eq!(rh.async_id(), pending_async_id);
                second = Some(CreateResponse::parse(rb).expect("parse final create"));
            }
            other => panic!("unexpected post-ack response command {other:?}"),
        }
    }

    assert!(saw_ack, "missing oplock ACK response");
    let second = second.expect("missing final create response");
    assert_eq!(second.oplock_level, 0x01);

    close(&mut s1, session1, tree1, 6, first.file_id).await;
    close(&mut s2, session2, tree2, 6, second.file_id).await;
    drop(s1);
    drop(s2);
    handle.abort();
}

#[tokio::test]
async fn named_stream_and_base_file_can_hold_independent_batch_oplocks() {
    let (handle, mut s, session_id, tree_id) = setup_lock_server_smb311().await;
    let desired_access = 0x0012_0089;
    let share_all = 0x0000_0007;

    let base = create_named_open(
        &mut s,
        session_id,
        tree_id,
        4,
        "hello.txt",
        desired_access,
        share_all,
        3,
        0,
        0x09,
    )
    .await;
    assert_eq!(base.oplock_level, 0x09);

    let stream = create_named_open(
        &mut s,
        session_id,
        tree_id,
        5,
        "hello.txt:Stream One:$DATA",
        desired_access,
        share_all,
        3,
        0,
        0x09,
    )
    .await;
    assert_eq!(stream.oplock_level, 0x09);

    send_create_named_open(
        &mut s,
        session_id,
        tree_id,
        6,
        "hello.txt",
        desired_access,
        share_all,
        3,
        0,
        0x09,
    )
    .await;

    let frames = [
        read_frame_with_timeout(&mut s).await,
        read_frame_with_timeout(&mut s).await,
    ];
    let mut pending_async_id = None;
    let mut notification = None;
    for frame in frames {
        let (rh, rb) = parse_response_header(&frame);
        match rh.command {
            Command::Create => {
                assert_eq!(rh.channel_sequence_status, STATUS_PENDING);
                pending_async_id = Some(rh.async_id().expect("pending create async id"));
            }
            Command::OplockBreak => {
                assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
                notification = Some(OplockBreakAck::parse(rb).expect("parse oplock break"));
            }
            other => panic!("unexpected pre-ack response command {other:?}"),
        }
    }

    let notification = notification.expect("missing base-file Batch break");
    assert_eq!(notification.oplock_level, 0x01);
    assert_eq!(notification.file_id, base.file_id);

    let ack = OplockBreakAck {
        structure_size: 24,
        oplock_level: 0x01,
        reserved: 0,
        reserved2: 0,
        file_id: base.file_id,
    };
    let mut body = Vec::new();
    ack.write_to(&mut body).expect("write oplock break ack");
    let hdr = build_header(Command::OplockBreak, 7, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;

    let frames = [
        read_frame_with_timeout(&mut s).await,
        read_frame_with_timeout(&mut s).await,
    ];
    let mut saw_ack = false;
    let mut second_base = None;
    for frame in frames {
        let (rh, rb) = parse_response_header(&frame);
        match rh.command {
            Command::OplockBreak => {
                assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
                let ack = OplockBreakAck::parse(rb).expect("parse oplock break response");
                assert_eq!(ack.oplock_level, 0x01);
                assert_eq!(ack.file_id, base.file_id);
                saw_ack = true;
            }
            Command::Create => {
                assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
                assert_eq!(rh.async_id(), pending_async_id);
                second_base = Some(CreateResponse::parse(rb).expect("parse final create"));
            }
            other => panic!("unexpected post-ack response command {other:?}"),
        }
    }

    assert!(saw_ack, "missing oplock ACK response");
    let second_base = second_base.expect("missing second base create response");
    assert_eq!(second_base.oplock_level, 0x01);

    close(&mut s, session_id, tree_id, 8, base.file_id).await;
    close(&mut s, session_id, tree_id, 9, stream.file_id).await;
    close(&mut s, session_id, tree_id, 10, second_base.file_id).await;
    drop(s);
    handle.abort();
}

#[tokio::test]
async fn same_named_stream_open_breaks_existing_stream_oplock_to_level_ii() {
    let (handle, addr, mut s1, session1, tree1) = setup_lock_server_with_addr_smb311().await;
    let mut s2 = TcpStream::connect(addr).await.expect("connect second");
    let _ = negotiate_smb311(&mut s2).await;
    let session2 = anonymous_session_setup(&mut s2).await;
    let tree2 = tree_connect(&mut s2, "\\\\127.0.0.1\\share", session2, 3).await;

    let desired_access = 0x0012_0089;
    let share_rw = 0x0000_0003;
    let stream = create_named_open(
        &mut s1,
        session1,
        tree1,
        4,
        "hello.txt:Stream One:$DATA",
        desired_access,
        share_rw,
        3,
        0,
        0x08,
    )
    .await;
    assert_eq!(stream.oplock_level, 0x08);

    let base = create_named_open(
        &mut s2,
        session2,
        tree2,
        4,
        "hello.txt",
        desired_access,
        share_rw,
        1,
        0,
        0x09,
    )
    .await;
    assert_eq!(base.oplock_level, 0x09);
    close(&mut s2, session2, tree2, 5, base.file_id).await;

    let no_break = tokio::time::timeout(Duration::from_millis(25), read_frame(&mut s1)).await;
    assert!(
        no_break.is_err(),
        "base-file open should not break named-stream oplock"
    );

    send_create_named_open(
        &mut s2,
        session2,
        tree2,
        6,
        "hello.txt:Stream One:$DATA",
        desired_access,
        share_rw,
        1,
        0,
        0x08,
    )
    .await;

    let frames = [
        read_frame_with_timeout(&mut s1).await,
        read_frame_with_timeout(&mut s2).await,
    ];
    let mut notification = None;
    let mut pending_async_id = None;
    for frame in frames {
        let (rh, rb) = parse_response_header(&frame);
        match rh.command {
            Command::OplockBreak => {
                assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
                notification = Some(OplockBreakAck::parse(rb).expect("parse oplock break"));
            }
            Command::Create => {
                assert_eq!(rh.channel_sequence_status, STATUS_PENDING);
                pending_async_id = Some(rh.async_id().expect("pending create async id"));
            }
            other => panic!("unexpected pre-ack response command {other:?}"),
        }
    }

    let notification = notification.expect("missing same-stream oplock break");
    assert_eq!(notification.oplock_level, 0x01);
    assert_eq!(notification.file_id, stream.file_id);

    let ack = OplockBreakAck {
        structure_size: 24,
        oplock_level: 0x01,
        reserved: 0,
        reserved2: 0,
        file_id: stream.file_id,
    };
    let mut body = Vec::new();
    ack.write_to(&mut body).expect("write oplock break ack");
    let hdr = build_header(Command::OplockBreak, 5, session1, tree1);
    write_frame(&mut s1, &hdr, &body).await;

    let frames = [
        read_frame_with_timeout(&mut s1).await,
        read_frame_with_timeout(&mut s2).await,
    ];
    let mut saw_ack = false;
    let mut second_stream = None;
    for frame in frames {
        let (rh, rb) = parse_response_header(&frame);
        match rh.command {
            Command::OplockBreak => {
                assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
                let ack = OplockBreakAck::parse(rb).expect("parse oplock break response");
                assert_eq!(ack.oplock_level, 0x01);
                assert_eq!(ack.file_id, stream.file_id);
                saw_ack = true;
            }
            Command::Create => {
                assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
                assert_eq!(rh.async_id(), pending_async_id);
                second_stream = Some(CreateResponse::parse(rb).expect("parse final create"));
            }
            other => panic!("unexpected post-ack response command {other:?}"),
        }
    }

    assert!(saw_ack, "missing oplock ACK response");
    let second_stream = second_stream.expect("missing second stream create response");
    assert_eq!(second_stream.oplock_level, 0x01);

    close(&mut s1, session1, tree1, 6, stream.file_id).await;
    close(&mut s2, session2, tree2, 7, second_stream.file_id).await;
    drop(s1);
    drop(s2);
    handle.abort();
}

#[tokio::test]
async fn delete_on_close_drops_level_ii_oplocks_without_notification() {
    let (handle, mut s, session_id, tree_id) = setup_lock_server_smb311().await;

    let first = create_oplock_open(&mut s, session_id, tree_id, 4, 0x01, 0x001f_01ff).await;
    let second = create_oplock_open(&mut s, session_id, tree_id, 5, 0x01, 0x001f_01ff).await;
    assert_eq!(first.oplock_level, 0x01);
    assert_eq!(second.oplock_level, 0x01);

    let name = utf16le("hello.txt");
    let delete_req = CreateRequest {
        structure_size: 57,
        security_flags: 0,
        requested_oplock_level: 0,
        impersonation_level: 2,
        smb_create_flags: 0,
        reserved: 0,
        desired_access: 0x0001_0000,
        file_attributes: 0,
        share_access: 0x0000_0007,
        create_disposition: 1,
        create_options: 0x0000_1040,
        name_offset: 0x78,
        name_length: name.len() as u16,
        create_contexts_offset: 0,
        create_contexts_length: 0,
        name,
        create_contexts: vec![],
    };
    let mut body = Vec::new();
    delete_req
        .write_to(&mut body)
        .expect("write delete-on-close create");
    let hdr = build_header(Command::Create, 6, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Create);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let delete_open = CreateResponse::parse(rb).expect("parse delete create");

    close(&mut s, session_id, tree_id, 7, delete_open.file_id).await;
    assert_no_frame(&mut s).await;

    let req = WriteRequest {
        structure_size: 49,
        data_offset: WriteRequest::STANDARD_DATA_OFFSET,
        length: 1,
        offset: 0,
        file_id: first.file_id,
        channel: 0,
        remaining_bytes: 0,
        write_channel_info_offset: 0,
        write_channel_info_length: 0,
        flags: 0,
        data: b"z".to_vec(),
    };
    let mut body = Vec::new();
    req.write_to(&mut body).expect("write write request");
    let hdr = build_header(Command::Write, 8, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Write);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let wr = WriteResponse::parse(rb).expect("parse write response");
    assert_eq!(wr.count, 1);
    assert_no_frame(&mut s).await;

    close(&mut s, session_id, tree_id, 9, first.file_id).await;
    close(&mut s, session_id, tree_id, 10, second.file_id).await;
    drop(s);
    handle.abort();
}

#[tokio::test]
async fn same_key_upgrade_survives_upgrading_handle_close_and_later_breaks() {
    const LEASE_READ: u32 = 0x0000_0001;
    const LEASE_HANDLE: u32 = 0x0000_0002;
    const LEASE_WRITE: u32 = 0x0000_0004;
    const FILE_READ_WRITE: u32 = 0x0012_0089 | 0x0012_0116;

    let (handle, addr, mut s1, session1, tree1) = setup_lock_server_with_addr_smb311().await;
    let mut s2 = TcpStream::connect(addr).await.expect("connect second");
    let _ = negotiate_smb311(&mut s2).await;
    let session2 = anonymous_session_setup(&mut s2).await;
    let tree2 = tree_connect(&mut s2, "\\\\127.0.0.1\\share", session2, 3).await;

    let first_key = b"lease-key-123456";
    let second_key = b"other-key-123456";

    let (first, first_grant) = create_lease_open_with_lease_data(
        &mut s1,
        session1,
        tree1,
        4,
        FILE_READ_WRITE,
        lease_v1_request_with_key(LEASE_READ, first_key),
    )
    .await;
    assert_eq!(first_grant.state, LEASE_READ);

    let (upgrader, upgraded_grant) = create_lease_open_with_lease_data(
        &mut s2,
        session2,
        tree2,
        4,
        FILE_READ_WRITE,
        lease_v1_request_with_key(LEASE_READ | LEASE_HANDLE | LEASE_WRITE, first_key),
    )
    .await;
    assert_eq!(
        upgraded_grant.state,
        LEASE_READ | LEASE_HANDLE | LEASE_WRITE
    );
    close(&mut s2, session2, tree2, 5, upgrader.file_id).await;

    send_create_lease_open_with_lease_data(
        &mut s2,
        session2,
        tree2,
        6,
        FILE_READ_WRITE,
        lease_v1_request_with_key(LEASE_READ, second_key),
    )
    .await;

    let pending = read_frame_with_timeout(&mut s2).await;
    let (pending_hdr, _) = parse_response_header(&pending);
    assert_eq!(pending_hdr.command, Command::Create);
    assert_eq!(pending_hdr.channel_sequence_status, STATUS_PENDING);

    let frame = read_frame_with_timeout(&mut s1).await;
    let (rh, rb) = parse_response_header(&frame);
    assert_eq!(rh.command, Command::OplockBreak);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let notification = LeaseBreakNotification::parse(rb).expect("parse lease break notification");
    assert_eq!(&notification.lease_key, first_key);
    assert_eq!(
        notification.current_lease_state,
        LEASE_READ | LEASE_HANDLE | LEASE_WRITE
    );
    assert_eq!(notification.new_lease_state, LEASE_READ | LEASE_HANDLE);
    assert_eq!(notification.flags, 0x0000_0001);

    let (status, ack_body) = send_lease_break_ack(
        &mut s1,
        session1,
        tree1,
        5,
        first_key,
        LEASE_READ | LEASE_HANDLE,
    )
    .await;
    assert_eq!(status, STATUS_SUCCESS);
    let ack = LeaseBreakAck::parse(&ack_body).expect("parse lease break ack response");
    assert_eq!(ack.lease_state, LEASE_READ | LEASE_HANDLE);

    let final_create = read_frame_with_timeout(&mut s2).await;
    let (rh, rb) = parse_response_header(&final_create);
    assert_eq!(rh.command, Command::Create);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let second = CreateResponse::parse(rb).expect("parse final create");
    let second_grant = lease_grant_from_create(&second);
    assert_eq!(second_grant.state, LEASE_READ);

    close(&mut s1, session1, tree1, 6, first.file_id).await;
    close(&mut s2, session2, tree2, 7, second.file_id).await;
    drop(s1);
    drop(s2);
    handle.abort();
}

#[tokio::test]
async fn create_lease_request_same_key_only_upgrades_for_strict_superset() {
    let (handle, mut s, session_id, tree_id) = setup_lock_server_smb311().await;
    let lease_key = b"lease-key-123456";

    let (first, first_state) = create_lease_open_with_key(
        &mut s,
        session_id,
        tree_id,
        4,
        0x0012_0089 | 0x0012_0116,
        0x0000_0001 | 0x0000_0002,
        lease_key,
    )
    .await;
    let (second, second_state) = create_lease_open_with_key(
        &mut s,
        session_id,
        tree_id,
        5,
        0x0012_0089 | 0x0012_0116,
        0x0000_0001 | 0x0000_0004,
        lease_key,
    )
    .await;
    let (third, third_state) = create_lease_open_with_key(
        &mut s,
        session_id,
        tree_id,
        6,
        0x0012_0089 | 0x0012_0116,
        0x0000_0001 | 0x0000_0002 | 0x0000_0004,
        lease_key,
    )
    .await;

    assert_eq!(first_state, 0x0000_0001 | 0x0000_0002);
    assert_eq!(second_state, 0x0000_0001 | 0x0000_0002);
    assert_eq!(third_state, 0x0000_0001 | 0x0000_0002 | 0x0000_0004);
    close(&mut s, session_id, tree_id, 7, first.file_id).await;
    close(&mut s, session_id, tree_id, 8, second.file_id).await;
    close(&mut s, session_id, tree_id, 9, third.file_id).await;

    drop(s);
    handle.abort();
}

#[tokio::test]
async fn create_lease_request_same_key_keeps_existing_v2_version_and_epoch() {
    let (handle, mut s, session_id, tree_id) = setup_lock_server_smb311().await;
    let lease_key = b"lease-key-123456";

    let (first, first_grant) = create_lease_open_with_lease_data(
        &mut s,
        session_id,
        tree_id,
        4,
        0x0012_0089 | 0x0012_0116,
        lease_v2_request_with_key_and_epoch(0x0000_0001, lease_key, 0x4711),
    )
    .await;
    let (second, second_grant) = create_lease_open_with_lease_data(
        &mut s,
        session_id,
        tree_id,
        5,
        0x0012_0089 | 0x0012_0116,
        lease_v1_request_with_key(0x0000_0001 | 0x0000_0002, lease_key),
    )
    .await;

    assert_eq!(first_grant.response_len, 52);
    assert_eq!(first_grant.epoch, 0x4712);
    assert_eq!(second_grant.response_len, 52);
    assert_eq!(second_grant.state, 0x0000_0001 | 0x0000_0002);
    assert_eq!(second_grant.epoch, 0x4713);
    close(&mut s, session_id, tree_id, 6, first.file_id).await;

    let (third, third_grant) = create_lease_open_with_lease_data(
        &mut s,
        session_id,
        tree_id,
        7,
        0x0012_0089 | 0x0012_0116,
        lease_v2_request_with_key_and_epoch(
            0x0000_0001 | 0x0000_0002 | 0x0000_0004,
            lease_key,
            0x0011,
        ),
    )
    .await;

    assert_eq!(third_grant.response_len, 52);
    assert_eq!(third_grant.state, 0x0000_0001 | 0x0000_0002 | 0x0000_0004);
    assert_eq!(third_grant.epoch, 0x4714);
    close(&mut s, session_id, tree_id, 8, second.file_id).await;
    close(&mut s, session_id, tree_id, 9, third.file_id).await;

    drop(s);
    handle.abort();
}

#[tokio::test]
async fn create_lease_v2_ignores_parent_key_without_parent_flag() {
    let (handle, mut s, session_id, tree_id) = setup_lock_server_smb311().await;
    let lease_key = b"lease-key-123456";

    let (open, grant) = create_lease_open_with_lease_data(
        &mut s,
        session_id,
        tree_id,
        4,
        0x0012_0089 | 0x0012_0116,
        lease_v2_request_with_key_and_epoch(0x0000_0001 | 0x0000_0002, lease_key, 0x4711),
    )
    .await;

    assert_eq!(grant.response_len, 52);
    assert_eq!(grant.flags, 0);
    assert_eq!(grant.parent_key, [0; 16]);
    close(&mut s, session_id, tree_id, 5, open.file_id).await;
    drop(s);
    handle.abort();
}

#[tokio::test]
async fn create_lease_request_same_key_v2_zero_state_does_not_advance_epoch() {
    let (handle, mut s, session_id, tree_id) = setup_lock_server_smb311().await;
    let lease_key = b"lease-key-123456";

    let (first, first_grant) = create_lease_open_with_lease_data(
        &mut s,
        session_id,
        tree_id,
        4,
        0x0012_0089 | 0x0012_0116,
        lease_v2_request_with_key_and_epoch(
            0x0000_0001 | 0x0000_0002 | 0x0000_0004,
            lease_key,
            0x4711,
        ),
    )
    .await;
    let (second, second_grant) = create_lease_open_with_lease_data(
        &mut s,
        session_id,
        tree_id,
        5,
        0x0012_0089 | 0x0012_0116,
        lease_v2_request_with_key_and_epoch(0, lease_key, 0x4712),
    )
    .await;

    assert_eq!(first_grant.epoch, 0x4712);
    assert_eq!(second_grant.response_len, 52);
    assert_eq!(second_grant.state, 0x0000_0001 | 0x0000_0002 | 0x0000_0004);
    assert_eq!(second_grant.epoch, 0x4712);
    close(&mut s, session_id, tree_id, 6, first.file_id).await;
    close(&mut s, session_id, tree_id, 7, second.file_id).await;

    drop(s);
    handle.abort();
}

#[tokio::test]
async fn create_lease_request_same_key_keeps_existing_v1_version() {
    let (handle, mut s, session_id, tree_id) = setup_lock_server_smb311().await;
    let lease_key = b"lease-key-123456";

    let (first, first_grant) = create_lease_open_with_lease_data(
        &mut s,
        session_id,
        tree_id,
        4,
        0x0012_0089 | 0x0012_0116,
        lease_v1_request_with_key(0x0000_0001, lease_key),
    )
    .await;
    let (second, second_grant) = create_lease_open_with_lease_data(
        &mut s,
        session_id,
        tree_id,
        5,
        0x0012_0089 | 0x0012_0116,
        lease_v2_request_with_key_and_epoch(0x0000_0001 | 0x0000_0004, lease_key, 0x4711),
    )
    .await;

    assert_eq!(first_grant.response_len, 32);
    assert_eq!(second_grant.response_len, 32);
    assert_eq!(second_grant.state, 0x0000_0001 | 0x0000_0004);
    close(&mut s, session_id, tree_id, 6, first.file_id).await;

    let (third, third_grant) = create_lease_open_with_lease_data(
        &mut s,
        session_id,
        tree_id,
        7,
        0x0012_0089 | 0x0012_0116,
        lease_v1_request_with_key(0x0000_0001 | 0x0000_0002 | 0x0000_0004, lease_key),
    )
    .await;

    assert_eq!(third_grant.response_len, 32);
    assert_eq!(third_grant.state, 0x0000_0001 | 0x0000_0002 | 0x0000_0004);
    close(&mut s, session_id, tree_id, 8, second.file_id).await;
    close(&mut s, session_id, tree_id, 9, third.file_id).await;

    drop(s);
    handle.abort();
}

#[tokio::test]
async fn create_lease_request_contended_same_key_upgrade_requires_compatible_request() {
    let cases = [
        (0x0000_0001 | 0x0000_0002, 0x0000_0001 | 0x0000_0002),
        (0x0000_0001 | 0x0000_0002 | 0x0000_0004, 0x0000_0001),
    ];

    for (upgrade, expected) in cases {
        let (handle, mut s, session_id, tree_id) = setup_lock_server_smb311().await;
        let lease_key = b"lease-key-123456";
        let other_key = b"fedcba9876543210";

        let (first, first_state) = create_lease_open_with_key(
            &mut s,
            session_id,
            tree_id,
            4,
            0x0012_0089 | 0x0012_0116,
            0x0000_0001,
            lease_key,
        )
        .await;
        let (other, other_state) = create_lease_open_with_key(
            &mut s,
            session_id,
            tree_id,
            5,
            0x0012_0089 | 0x0012_0116,
            0x0000_0001,
            other_key,
        )
        .await;
        let (third, third_state) = create_lease_open_with_key(
            &mut s,
            session_id,
            tree_id,
            6,
            0x0012_0089 | 0x0012_0116,
            upgrade,
            lease_key,
        )
        .await;

        assert_eq!(first_state, 0x0000_0001);
        assert_eq!(other_state, 0x0000_0001);
        assert_eq!(third_state, expected);
        close(&mut s, session_id, tree_id, 7, first.file_id).await;
        close(&mut s, session_id, tree_id, 8, other.file_id).await;
        close(&mut s, session_id, tree_id, 9, third.file_id).await;

        drop(s);
        handle.abort();
    }
}

#[tokio::test]
async fn same_lease_key_create_reports_break_in_progress() {
    const LEASE_READ: u32 = 0x0000_0001;
    const LEASE_WRITE: u32 = 0x0000_0004;
    const LEASE_BREAK_IN_PROGRESS: u32 = 0x0000_0002;

    let (handle, mut s, session_id, tree_id) = setup_lock_server_smb311().await;
    let first_key = b"lease-key-123456";
    let other_key = b"fedcba9876543210";

    let (first, first_grant) = create_lease_open_with_lease_data(
        &mut s,
        session_id,
        tree_id,
        4,
        0x0012_0089 | 0x0012_0116,
        lease_v1_request_with_key(LEASE_READ | LEASE_WRITE, first_key),
    )
    .await;
    assert_eq!(first_grant.response_len, 32);
    assert_eq!(first_grant.state, LEASE_READ | LEASE_WRITE);

    send_create_lease_open_with_lease_data(
        &mut s,
        session_id,
        tree_id,
        5,
        0x0012_0089,
        lease_v1_request_with_key(LEASE_READ, other_key),
    )
    .await;

    let frames = [read_frame(&mut s).await, read_frame(&mut s).await];
    let mut pending_async_id = None;
    let mut saw_notification = false;
    for frame in frames {
        let (rh, rb) = parse_response_header(&frame);
        match rh.command {
            Command::Create => {
                assert_eq!(rh.channel_sequence_status, STATUS_PENDING);
                assert_eq!(rh.message_id, 5);
                pending_async_id = Some(rh.async_id().expect("pending response async id"));
            }
            Command::OplockBreak => {
                assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
                let notification =
                    LeaseBreakNotification::parse(rb).expect("parse lease break notification");
                assert_eq!(notification.flags, 0x0000_0001);
                assert_eq!(&notification.lease_key, first_key);
                assert_eq!(notification.current_lease_state, LEASE_READ | LEASE_WRITE);
                assert_eq!(notification.new_lease_state, LEASE_READ);
                saw_notification = true;
            }
            other => panic!("unexpected response command {other:?}"),
        }
    }
    assert!(saw_notification, "missing lease break notification");

    let (same_key, same_key_grant) = create_lease_open_with_lease_data(
        &mut s,
        session_id,
        tree_id,
        6,
        0x0012_0089,
        lease_v1_request_with_key(LEASE_READ, first_key),
    )
    .await;
    assert_eq!(same_key_grant.response_len, 32);
    assert_eq!(same_key_grant.state, LEASE_READ | LEASE_WRITE);
    assert_eq!(same_key_grant.flags, LEASE_BREAK_IN_PROGRESS);

    let ack = LeaseBreakAck {
        structure_size: 36,
        reserved: 0,
        flags: 0,
        lease_key: *first_key,
        lease_state: LEASE_READ,
        lease_duration: 0,
    };
    let mut ack_body = Vec::new();
    ack.write_to(&mut ack_body).expect("write lease break ack");
    let ack_hdr = build_header(Command::OplockBreak, 7, session_id, tree_id);
    write_frame(&mut s, &ack_hdr, &ack_body).await;

    let frames = [read_frame(&mut s).await, read_frame(&mut s).await];
    let mut saw_ack = false;
    let mut saw_final_create = false;
    for frame in frames {
        let (rh, rb) = parse_response_header(&frame);
        match rh.command {
            Command::OplockBreak => {
                assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
                let ack_response = LeaseBreakAck::parse(rb).expect("parse lease break response");
                assert_eq!(ack_response.lease_state, LEASE_READ);
                saw_ack = true;
            }
            Command::Create => {
                assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
                assert_eq!(rh.async_id(), pending_async_id);
                saw_final_create = true;
            }
            other => panic!("unexpected response command {other:?}"),
        }
    }
    assert!(saw_ack, "missing lease break ack response");
    assert!(saw_final_create, "missing pending create completion");

    close(&mut s, session_id, tree_id, 8, first.file_id).await;
    close(&mut s, session_id, tree_id, 9, same_key.file_id).await;

    drop(s);
    handle.abort();
}

#[tokio::test]
async fn same_lease_key_create_rearms_existing_broken_lease() {
    const LEASE_READ: u32 = 0x0000_0001;
    const LEASE_NONE: u32 = 0x0000_0000;

    let (handle, mut s, session_id, tree_id) = setup_lock_server_smb311().await;
    let first_key = b"lease-key-123456";
    let other_key = b"fedcba9876543210";

    let (writer, writer_grant) = create_lease_open_with_lease_data(
        &mut s,
        session_id,
        tree_id,
        4,
        0x0012_0089 | 0x0012_0116,
        lease_v1_request_with_key(LEASE_READ, first_key),
    )
    .await;
    assert_eq!(writer_grant.state, LEASE_READ);

    let (rearmed, rearmed_grant) = create_lease_open_with_lease_data(
        &mut s,
        session_id,
        tree_id,
        5,
        0x0012_0089 | 0x0012_0116,
        lease_v1_request_with_key(LEASE_READ, other_key),
    )
    .await;
    assert_eq!(rearmed_grant.state, LEASE_READ);

    write_success_and_expect_lease_break(
        &mut s,
        session_id,
        tree_id,
        6,
        writer.file_id,
        0,
        b"a",
        other_key,
        LEASE_READ,
        LEASE_NONE,
    )
    .await;

    let (temp, temp_grant) = create_lease_open_with_lease_data(
        &mut s,
        session_id,
        tree_id,
        7,
        0x0012_0089 | 0x0012_0116,
        lease_v1_request_with_key(LEASE_READ, other_key),
    )
    .await;
    assert_eq!(temp_grant.state, LEASE_READ);
    close(&mut s, session_id, tree_id, 8, temp.file_id).await;

    write_success_and_expect_lease_break(
        &mut s,
        session_id,
        tree_id,
        9,
        writer.file_id,
        1,
        b"b",
        other_key,
        LEASE_READ,
        LEASE_NONE,
    )
    .await;

    close(&mut s, session_id, tree_id, 10, writer.file_id).await;
    close(&mut s, session_id, tree_id, 11, rearmed.file_id).await;

    drop(s);
    handle.abort();
}

#[tokio::test]
async fn create_lease_request_downgrades_write_caching_for_other_key_conflict() {
    let (handle, mut s, session_id, tree_id) = setup_lock_server_smb311().await;
    let first_key = b"lease-key-123456";
    let other_key = b"fedcba9876543210";

    let (first, first_state) = create_lease_open_with_key(
        &mut s,
        session_id,
        tree_id,
        4,
        0x0012_0089 | 0x0012_0116,
        0x0000_0001,
        first_key,
    )
    .await;
    let (second, second_state) = create_lease_open_with_key(
        &mut s,
        session_id,
        tree_id,
        5,
        0x0012_0089 | 0x0012_0116,
        0x0000_0001 | 0x0000_0004,
        other_key,
    )
    .await;

    assert_eq!(first_state, 0x0000_0001);
    assert_eq!(second_state, 0x0000_0001);
    close(&mut s, session_id, tree_id, 6, first.file_id).await;
    close(&mut s, session_id, tree_id, 7, second.file_id).await;

    drop(s);
    handle.abort();
}

#[tokio::test]
async fn conflicting_create_waits_for_lease_break_ack_for_write_lease() {
    let (handle, mut s, session_id, tree_id) = setup_lock_server_smb311().await;
    let first_key = b"lease-key-123456";
    let other_key = b"fedcba9876543210";

    let (first, first_grant) = create_lease_open_with_lease_data(
        &mut s,
        session_id,
        tree_id,
        4,
        0x0012_0089 | 0x0012_0116,
        lease_v2_request_with_key(0x0000_0001 | 0x0000_0004, first_key),
    )
    .await;
    assert_eq!(first_grant.state, 0x0000_0001 | 0x0000_0004);

    send_create_lease_open_with_lease_data(
        &mut s,
        session_id,
        tree_id,
        5,
        0x0012_0089 | 0x0012_0116,
        lease_v2_request_with_key(0x0000_0001, other_key),
    )
    .await;

    let frames = [read_frame(&mut s).await, read_frame(&mut s).await];
    let mut pending_async_id = None;
    let mut notification = None;
    for frame in frames {
        let (rh, rb) = parse_response_header(&frame);
        match rh.command {
            Command::Create => {
                assert_eq!(rh.channel_sequence_status, STATUS_PENDING);
                assert_eq!(rh.message_id, 5);
                assert!(
                    !rb.is_empty(),
                    "pending response should include an error body"
                );
                pending_async_id = Some(rh.async_id().expect("pending response async id"));
            }
            Command::OplockBreak => {
                assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
                assert_eq!(rh.message_id, u64::MAX);
                notification = Some(
                    LeaseBreakNotification::parse(rb).expect("parse lease break notification"),
                );
            }
            other => panic!("unexpected response command {other:?}"),
        }
    }

    let notification = notification.expect("missing lease break notification");
    assert_eq!(notification.structure_size, 44);
    assert_eq!(notification.new_epoch, first_grant.epoch + 1);
    assert_eq!(notification.flags, 0x0000_0001);
    assert_eq!(&notification.lease_key, first_key);
    assert_eq!(notification.current_lease_state, 0x0000_0001 | 0x0000_0004);
    assert_eq!(notification.new_lease_state, 0x0000_0001);

    let ack = LeaseBreakAck {
        structure_size: 36,
        reserved: 0,
        flags: 0,
        lease_key: *first_key,
        lease_state: 0x0000_0001,
        lease_duration: 0,
    };
    let mut ack_body = Vec::new();
    ack.write_to(&mut ack_body).expect("write lease break ack");
    let ack_hdr = build_header(Command::OplockBreak, 6, session_id, tree_id);
    write_frame(&mut s, &ack_hdr, &ack_body).await;

    let frames = [read_frame(&mut s).await, read_frame(&mut s).await];
    let mut ack_seen = false;
    let mut second = None;
    for frame in frames {
        let (rh, rb) = parse_response_header(&frame);
        match rh.command {
            Command::OplockBreak => {
                assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
                ack_seen = true;
            }
            Command::Create => {
                assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
                assert_eq!(
                    rh.async_id(),
                    pending_async_id,
                    "final async response must use pending async id"
                );
                let create = CreateResponse::parse(rb).expect("parse final second create");
                let contexts =
                    CreateContext::parse_chain(&create.create_contexts).expect("parse contexts");
                let lease = contexts
                    .iter()
                    .find(|ctx| ctx.name == CreateContext::NAME_RQLS.as_slice())
                    .expect("missing second lease response");
                assert_eq!(
                    u32::from_le_bytes(lease.data[16..20].try_into().unwrap()),
                    1
                );
                second = Some(create);
            }
            other => panic!("unexpected post-ack response command {other:?}"),
        }
    }
    assert!(ack_seen, "missing lease break ack response");

    close(&mut s, session_id, tree_id, 7, first.file_id).await;
    close(
        &mut s,
        session_id,
        tree_id,
        8,
        second.expect("missing second create response").file_id,
    )
    .await;

    drop(s);
    handle.abort();
}

#[tokio::test]
async fn sharing_violation_create_breaks_handle_caching_lease() {
    let (handle, mut s, session_id, tree_id) = setup_lock_server_smb311().await;
    let first_key = b"0123456789abcdef";
    let second_key = b"fedcba9876543210";
    const LEASE_READ: u32 = 0x0000_0001;
    const LEASE_HANDLE: u32 = 0x0000_0002;
    const LEASE_WRITE: u32 = 0x0000_0004;

    let (first, first_grant) = create_lease_open_with_lease_data(
        &mut s,
        session_id,
        tree_id,
        4,
        0x0012_0089 | 0x0012_0116,
        lease_v2_request_with_key(LEASE_READ | LEASE_HANDLE | LEASE_WRITE, first_key),
    )
    .await;
    assert_eq!(first_grant.state, LEASE_READ | LEASE_HANDLE | LEASE_WRITE);

    send_create_lease_open_with_lease_data_and_share(
        &mut s,
        session_id,
        tree_id,
        5,
        0x0012_0089 | 0x0012_0116,
        0x0000_0001,
        lease_v2_request_with_key(LEASE_READ | LEASE_HANDLE | LEASE_WRITE, second_key),
    )
    .await;

    let frames = [read_frame(&mut s).await, read_frame(&mut s).await];
    let mut pending_async_id = None;
    let mut notification = None;
    for frame in frames {
        let (rh, rb) = parse_response_header(&frame);
        match rh.command {
            Command::Create => {
                assert_eq!(rh.channel_sequence_status, STATUS_PENDING);
                assert_eq!(rh.message_id, 5);
                pending_async_id = Some(rh.async_id().expect("pending create async id"));
            }
            Command::OplockBreak => {
                assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
                assert_eq!(rh.message_id, u64::MAX);
                notification = Some(
                    LeaseBreakNotification::parse(rb).expect("parse lease break notification"),
                );
            }
            other => panic!("unexpected response command {other:?}"),
        }
    }

    let pending_async_id = pending_async_id.expect("missing pending create");
    let notification = notification.expect("missing lease break notification");
    assert_eq!(notification.structure_size, 44);
    assert_eq!(notification.new_epoch, first_grant.epoch + 1);
    assert_eq!(notification.flags, 0x0000_0001);
    assert_eq!(&notification.lease_key, first_key);
    assert_eq!(
        notification.current_lease_state,
        LEASE_READ | LEASE_HANDLE | LEASE_WRITE
    );
    assert_eq!(notification.new_lease_state, LEASE_READ | LEASE_WRITE);

    let ack = LeaseBreakAck {
        structure_size: 36,
        reserved: 0,
        flags: 0,
        lease_key: *first_key,
        lease_state: LEASE_READ | LEASE_WRITE,
        lease_duration: 0,
    };
    let mut ack_body = Vec::new();
    ack.write_to(&mut ack_body).expect("write lease break ack");
    let ack_hdr = build_header(Command::OplockBreak, 6, session_id, tree_id);
    write_frame(&mut s, &ack_hdr, &ack_body).await;

    let frames = [read_frame(&mut s).await, read_frame(&mut s).await];
    let mut ack_seen = false;
    let mut final_seen = false;
    for frame in frames {
        let (rh, rb) = parse_response_header(&frame);
        match rh.command {
            Command::OplockBreak => {
                assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
                let ack_resp = LeaseBreakResponse::parse(rb).expect("parse lease break response");
                assert_eq!(ack_resp.lease_state, LEASE_READ | LEASE_WRITE);
                ack_seen = true;
            }
            Command::Create => {
                assert_eq!(rh.async_id(), Some(pending_async_id));
                assert_eq!(rh.channel_sequence_status, STATUS_SHARING_VIOLATION);
                final_seen = true;
            }
            other => panic!("unexpected post-ack response command {other:?}"),
        }
    }
    assert!(ack_seen, "missing lease break ack response");
    assert!(final_seen, "missing final sharing violation response");

    send_create_lease_open_with_lease_data_and_share(
        &mut s,
        session_id,
        tree_id,
        7,
        0x0012_0089 | 0x0012_0116,
        0x0000_0007,
        lease_v2_request_with_key(LEASE_READ | LEASE_HANDLE | LEASE_WRITE, second_key),
    )
    .await;

    let frames = [read_frame(&mut s).await, read_frame(&mut s).await];
    let mut pending_async_id = None;
    let mut notification = None;
    for frame in frames {
        let (rh, rb) = parse_response_header(&frame);
        match rh.command {
            Command::Create => {
                assert_eq!(rh.channel_sequence_status, STATUS_PENDING);
                assert_eq!(rh.message_id, 7);
                pending_async_id = Some(rh.async_id().expect("pending create async id"));
            }
            Command::OplockBreak => {
                assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
                assert_eq!(rh.message_id, u64::MAX);
                notification = Some(
                    LeaseBreakNotification::parse(rb).expect("parse lease break notification"),
                );
            }
            other => panic!("unexpected second response command {other:?}"),
        }
    }

    let pending_async_id = pending_async_id.expect("missing second pending create");
    let notification = notification.expect("missing second lease break notification");
    assert_eq!(&notification.lease_key, first_key);
    assert_eq!(notification.current_lease_state, LEASE_READ | LEASE_WRITE);
    assert_eq!(notification.new_lease_state, LEASE_READ);

    let ack = LeaseBreakAck {
        structure_size: 36,
        reserved: 0,
        flags: 0,
        lease_key: *first_key,
        lease_state: LEASE_READ,
        lease_duration: 0,
    };
    let mut ack_body = Vec::new();
    ack.write_to(&mut ack_body).expect("write lease break ack");
    let ack_hdr = build_header(Command::OplockBreak, 8, session_id, tree_id);
    write_frame(&mut s, &ack_hdr, &ack_body).await;

    let frames = [read_frame(&mut s).await, read_frame(&mut s).await];
    let mut ack_seen = false;
    let mut second = None;
    for frame in frames {
        let (rh, rb) = parse_response_header(&frame);
        match rh.command {
            Command::OplockBreak => {
                assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
                let ack_resp = LeaseBreakResponse::parse(rb).expect("parse lease break response");
                assert_eq!(ack_resp.lease_state, LEASE_READ);
                ack_seen = true;
            }
            Command::Create => {
                assert_eq!(rh.async_id(), Some(pending_async_id));
                assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
                second = Some(CreateResponse::parse(rb).expect("parse second create"));
            }
            other => panic!("unexpected second post-ack response command {other:?}"),
        }
    }
    assert!(ack_seen, "missing second lease break ack response");
    let second = second.expect("missing final second create response");
    let second_grant = lease_grant_from_create(&second);
    assert_eq!(second_grant.state, LEASE_READ | LEASE_HANDLE);

    close(&mut s, session_id, tree_id, 9, second.file_id).await;
    close(&mut s, session_id, tree_id, 10, first.file_id).await;
    drop(s);
    handle.abort();
}

#[tokio::test]
async fn unacked_two_handle_lease_break_create_resumes_after_both_handles_close() {
    let (handle, addr, mut s1, session1, tree1) = setup_lock_server_with_addr_smb311().await;
    let mut s2 = TcpStream::connect(addr).await.expect("connect second");
    let _ = negotiate_smb311(&mut s2).await;
    let session2 = anonymous_session_setup(&mut s2).await;
    let tree2 = tree_connect(&mut s2, "\\\\127.0.0.1\\share", session2, 3).await;

    const FILE_READ: u32 = 0x0012_0089;
    const LEASE_READ: u32 = 0x0000_0001;
    const LEASE_HANDLE: u32 = 0x0000_0002;
    let first_key = b"\x01\xfelease-key-1234";
    let second_key = b"\x02\xfdlease-key-1234";
    let third_key = b"\x03\xfclease-key-1234";

    let (first, first_grant) = create_lease_open_with_lease_data_and_share(
        &mut s1,
        session1,
        tree1,
        4,
        FILE_READ,
        0x0000_0001,
        lease_v2_request_with_key(LEASE_READ | LEASE_HANDLE, first_key),
    )
    .await;
    assert_eq!(first_grant.state, LEASE_READ | LEASE_HANDLE);

    let (second, second_grant) = create_lease_open_with_lease_data_and_share(
        &mut s1,
        session1,
        tree1,
        5,
        FILE_READ,
        0x0000_0001,
        lease_v2_request_with_key(LEASE_READ | LEASE_HANDLE, second_key),
    )
    .await;
    assert_eq!(second_grant.state, LEASE_READ | LEASE_HANDLE);

    send_create_lease_open_with_lease_data_and_share(
        &mut s2,
        session2,
        tree2,
        4,
        FILE_READ,
        0,
        lease_v2_request_with_key(LEASE_READ | LEASE_HANDLE, third_key),
    )
    .await;

    let pending = read_frame_with_timeout(&mut s2).await;
    let (pending_hdr, _) = parse_response_header(&pending);
    assert_eq!(pending_hdr.command, Command::Create);
    assert_eq!(pending_hdr.channel_sequence_status, STATUS_PENDING);
    let pending_async_id = pending_hdr.async_id();

    let frames = [
        read_frame_with_timeout(&mut s1).await,
        read_frame_with_timeout(&mut s1).await,
    ];
    let mut broken_keys = Vec::new();
    for frame in frames {
        let (rh, rb) = parse_response_header(&frame);
        assert_eq!(rh.command, Command::OplockBreak);
        assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
        let notification = LeaseBreakNotification::parse(rb).expect("parse lease break");
        assert_eq!(notification.flags, 0x0000_0001);
        assert_eq!(notification.current_lease_state, LEASE_READ | LEASE_HANDLE);
        assert_eq!(notification.new_lease_state, LEASE_READ);
        let expected_epoch = if &notification.lease_key == first_key {
            first_grant.epoch + 1
        } else if &notification.lease_key == second_key {
            second_grant.epoch + 1
        } else {
            panic!("unexpected lease key {:?}", notification.lease_key);
        };
        assert_eq!(notification.new_epoch, expected_epoch);
        broken_keys.push(notification.lease_key);
    }
    assert_eq!(broken_keys.len(), 2);
    assert_eq!(broken_keys[0], broken_keys[1]);

    let (first_close, second_close) = if &broken_keys[0] == first_key {
        (first.file_id, second.file_id)
    } else if &broken_keys[0] == second_key {
        (second.file_id, first.file_id)
    } else {
        panic!("unexpected duplicated lease key {:?}", broken_keys[0]);
    };

    close(&mut s1, session1, tree1, 6, first_close).await;
    assert_no_frame(&mut s2).await;
    assert_no_frame(&mut s1).await;

    close(&mut s1, session1, tree1, 7, second_close).await;
    let final_create = read_frame_with_timeout(&mut s2).await;
    let (rh, rb) = parse_response_header(&final_create);
    assert_eq!(rh.command, Command::Create);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    assert_eq!(rh.async_id(), pending_async_id);
    let third = CreateResponse::parse(rb).expect("parse resumed create");

    close(&mut s2, session2, tree2, 5, third.file_id).await;
    drop(s1);
    drop(s2);
    handle.abort();
}

#[tokio::test]
async fn read_open_breaks_read_write_lease_to_read_caching() {
    let (handle, mut s, session_id, tree_id) = setup_lock_server_smb311().await;
    let first_key = b"lease-key-123456";
    let reader_key = b"fedcba9876543210";

    let (_first, first_grant) = create_lease_open_with_lease_data(
        &mut s,
        session_id,
        tree_id,
        4,
        0x0012_0089 | 0x0012_0116,
        lease_v2_request_with_key(0x0000_0001 | 0x0000_0004, first_key),
    )
    .await;
    assert_eq!(first_grant.state, 0x0000_0001 | 0x0000_0004);

    send_create_lease_open_with_lease_data(
        &mut s,
        session_id,
        tree_id,
        5,
        0x0012_0089,
        lease_v2_request_with_key(0x0000_0001, reader_key),
    )
    .await;

    let frames = [read_frame(&mut s).await, read_frame(&mut s).await];
    let mut pending_async_id = None;
    let mut notification = None;
    for frame in frames {
        let (rh, rb) = parse_response_header(&frame);
        match rh.command {
            Command::Create => {
                assert_eq!(rh.channel_sequence_status, STATUS_PENDING);
                assert_eq!(rh.message_id, 5);
                pending_async_id = Some(rh.async_id().expect("pending create async id"));
            }
            Command::OplockBreak => {
                assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
                assert_eq!(rh.message_id, u64::MAX);
                notification = Some(
                    LeaseBreakNotification::parse(rb).expect("parse lease break notification"),
                );
            }
            other => panic!("unexpected response command {other:?}"),
        }
    }

    let notification = notification.expect("missing lease break notification");
    assert_eq!(notification.structure_size, 44);
    assert_eq!(notification.flags, 0x0000_0001);
    assert_eq!(&notification.lease_key, first_key);
    assert_eq!(notification.current_lease_state, 0x0000_0001 | 0x0000_0004);
    assert_eq!(notification.new_lease_state, 0x0000_0001);

    let ack = LeaseBreakAck {
        structure_size: 36,
        reserved: 0,
        flags: 0,
        lease_key: *first_key,
        lease_state: 0x0000_0001,
        lease_duration: 0,
    };
    let mut ack_body = Vec::new();
    ack.write_to(&mut ack_body).expect("write lease break ack");
    let ack_hdr = build_header(Command::OplockBreak, 6, session_id, tree_id);
    write_frame(&mut s, &ack_hdr, &ack_body).await;

    let frames = [read_frame(&mut s).await, read_frame(&mut s).await];
    let mut ack_seen = false;
    let mut create = None;
    for frame in frames {
        let (rh, rb) = parse_response_header(&frame);
        match rh.command {
            Command::OplockBreak => {
                assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
                let ack_resp = LeaseBreakResponse::parse(rb).expect("parse lease break response");
                assert_eq!(ack_resp.lease_state, 0x0000_0001);
                ack_seen = true;
            }
            Command::Create => {
                assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
                assert_eq!(rh.async_id(), pending_async_id);
                let create_resp = CreateResponse::parse(rb).expect("parse final reader create");
                let contexts = CreateContext::parse_chain(&create_resp.create_contexts)
                    .expect("parse contexts");
                let lease = contexts
                    .iter()
                    .find(|ctx| ctx.name == CreateContext::NAME_RQLS.as_slice())
                    .expect("missing reader lease response");
                assert_eq!(
                    u32::from_le_bytes(lease.data[16..20].try_into().unwrap()),
                    1
                );
                create = Some(create_resp);
            }
            other => panic!("unexpected post-ack response command {other:?}"),
        }
    }
    assert!(ack_seen, "missing lease break ack response");
    let create = create.expect("missing final reader create response");

    close(&mut s, session_id, tree_id, 7, create.file_id).await;

    drop(s);
    handle.abort();
}

#[tokio::test]
async fn cache_break_timeout_forces_lease_downgrade_and_resumes_create() {
    let (handle, _addr, mut s, session_id, tree_id) =
        setup_lock_server_with_addr_smb311_and_cache_break_timeout(Duration::from_millis(20)).await;
    let first_key = b"lease-key-123456";
    let second_key = b"fedcba9876543210";
    let third_key = b"timeout-thirdkey";

    let (first, first_grant) = create_lease_open_with_lease_data(
        &mut s,
        session_id,
        tree_id,
        4,
        0x0012_0089 | 0x0012_0116,
        lease_v2_request_with_key(0x0000_0001 | 0x0000_0004, first_key),
    )
    .await;
    assert_eq!(first_grant.state, 0x0000_0001 | 0x0000_0004);

    send_create_lease_open_with_lease_data(
        &mut s,
        session_id,
        tree_id,
        5,
        0x0012_0089 | 0x0012_0116,
        lease_v2_request_with_key(0x0000_0001, second_key),
    )
    .await;

    let frames = [read_frame(&mut s).await, read_frame(&mut s).await];
    let mut pending_async_id = None;
    let mut notification = None;
    for frame in frames {
        let (rh, rb) = parse_response_header(&frame);
        match rh.command {
            Command::Create => {
                assert_eq!(rh.channel_sequence_status, STATUS_PENDING);
                assert_eq!(rh.message_id, 5);
                pending_async_id = Some(rh.async_id().expect("pending create async id"));
            }
            Command::OplockBreak => {
                assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
                notification = Some(
                    LeaseBreakNotification::parse(rb).expect("parse lease break notification"),
                );
            }
            other => panic!("unexpected response command {other:?}"),
        }
    }
    let pending_async_id = pending_async_id.expect("missing pending create");
    let notification = notification.expect("missing lease break notification");
    assert_eq!(&notification.lease_key, first_key);
    assert_eq!(notification.current_lease_state, 0x0000_0001 | 0x0000_0004);
    assert_eq!(notification.new_lease_state, 0x0000_0001);

    let final_frame = tokio::time::timeout(Duration::from_secs(2), read_frame(&mut s))
        .await
        .expect("timed out waiting for cache-break timeout final response");
    let (rh, rb) = parse_response_header(&final_frame);
    assert_eq!(rh.command, Command::Create);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    assert_eq!(rh.async_id(), Some(pending_async_id));
    let second = CreateResponse::parse(rb).expect("parse timeout-resumed create");

    let (same_key, same_key_grant) = create_lease_open_with_lease_data(
        &mut s,
        session_id,
        tree_id,
        6,
        0x0012_0089 | 0x0012_0116,
        lease_v2_request_with_key(0, first_key),
    )
    .await;
    assert_eq!(same_key_grant.state, 0);
    close(&mut s, session_id, tree_id, 7, same_key.file_id).await;

    send_create_lease_open_with_lease_data(
        &mut s,
        session_id,
        tree_id,
        8,
        0x0012_0089 | 0x0012_0116,
        lease_v2_request_with_key(0x0000_0001, third_key),
    )
    .await;
    let third_frame = read_frame_with_timeout(&mut s).await;
    let (rh, rb) = parse_response_header(&third_frame);
    assert_eq!(rh.command, Command::Create);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    assert_eq!(rh.message_id, 8);
    let third = CreateResponse::parse(rb).expect("parse post-timeout create");
    let no_break = tokio::time::timeout(Duration::from_millis(50), read_frame(&mut s)).await;
    assert!(
        no_break.is_err(),
        "post-timeout read lease create triggered another lease break"
    );

    close(&mut s, session_id, tree_id, 9, first.file_id).await;
    close(&mut s, session_id, tree_id, 10, second.file_id).await;
    close(&mut s, session_id, tree_id, 11, third.file_id).await;
    drop(s);
    handle.abort();
}

#[tokio::test]
async fn set_info_rename_waits_for_lease_break_ack_before_renaming() {
    let (handle, root, mut s, session_id, tree_id) = setup_lock_server_with_path_smb311().await;
    let first_key = b"lease-key-123456";
    let second_key = b"fedcba9876543210";

    let (first, first_grant) = create_lease_open_name_with_lease_data(
        &mut s,
        session_id,
        tree_id,
        4,
        "hello.txt",
        0x001f_01ff,
        lease_v2_request_with_key(0x0000_0001 | 0x0000_0002, first_key),
    )
    .await;
    let (_second, second_grant) = create_lease_open_name_with_lease_data(
        &mut s,
        session_id,
        tree_id,
        5,
        "hello.txt",
        0x0012_0089 | 0x0012_0116,
        lease_v2_request_with_key(0x0000_0001 | 0x0000_0002, second_key),
    )
    .await;
    assert_eq!(first_grant.state, 0x0000_0001 | 0x0000_0002);
    assert_eq!(second_grant.state, 0x0000_0001 | 0x0000_0002);

    let rename = file_rename_information("renamed.txt", false);
    let req = SetInfoRequest {
        structure_size: 33,
        info_type: InfoType::File as u8,
        file_information_class: 0x0A,
        buffer_length: rename.len() as u32,
        buffer_offset: 64 + 32,
        reserved: 0,
        additional_information: 0,
        file_id: first.file_id,
        buffer: rename,
    };
    let mut body = Vec::new();
    req.write_to(&mut body).expect("write set-info rename");
    let hdr = build_header(Command::SetInfo, 6, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;

    let first_frame = read_frame_with_timeout(&mut s).await;
    let (first_rh, _) = parse_response_header(&first_frame);
    match first_rh.command {
        Command::SetInfo => assert_eq!(first_rh.channel_sequence_status, STATUS_PENDING),
        Command::OplockBreak => assert_eq!(first_rh.channel_sequence_status, STATUS_SUCCESS),
        other => panic!("unexpected first response command {other:?}"),
    }
    let second_frame = tokio::time::timeout(Duration::from_secs(2), read_frame(&mut s))
        .await
        .unwrap_or_else(|_| {
            panic!(
                "missing second response after first {:?} status {:#010x}",
                first_rh.command, first_rh.channel_sequence_status
            )
        });
    let frames = [first_frame, second_frame];
    let mut pending_async_id = None;
    let mut notification = None;
    for frame in frames {
        let (rh, rb) = parse_response_header(&frame);
        match rh.command {
            Command::SetInfo => {
                assert_eq!(rh.channel_sequence_status, STATUS_PENDING);
                assert_eq!(rh.message_id, 6);
                pending_async_id = Some(rh.async_id().expect("pending set-info async id"));
            }
            Command::OplockBreak => {
                assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
                notification = Some(
                    LeaseBreakNotification::parse(rb).expect("parse lease break notification"),
                );
            }
            other => panic!("unexpected response command {other:?}"),
        }
    }

    let notification = notification.expect("missing lease break notification");
    assert_eq!(&notification.lease_key, second_key);
    assert_eq!(notification.current_lease_state, 0x0000_0001 | 0x0000_0002);
    assert_eq!(notification.new_lease_state, 0x0000_0001);
    assert!(root.join("hello.txt").exists());
    assert!(!root.join("renamed.txt").exists());

    let ack = LeaseBreakAck {
        structure_size: 36,
        reserved: 0,
        flags: 0,
        lease_key: *second_key,
        lease_state: 0x0000_0001,
        lease_duration: 0,
    };
    let mut ack_body = Vec::new();
    ack.write_to(&mut ack_body).expect("write lease break ack");
    let ack_hdr = build_header(Command::OplockBreak, 7, session_id, tree_id);
    write_frame(&mut s, &ack_hdr, &ack_body).await;

    let first_frame = read_frame_with_timeout(&mut s).await;
    let (first_rh, _) = parse_response_header(&first_frame);
    match first_rh.command {
        Command::OplockBreak | Command::SetInfo => {
            assert_eq!(first_rh.channel_sequence_status, STATUS_SUCCESS)
        }
        other => panic!("unexpected first post-ack response command {other:?}"),
    }
    let second_frame = tokio::time::timeout(Duration::from_secs(2), read_frame(&mut s))
        .await
        .unwrap_or_else(|_| {
            panic!(
                "missing second post-ack response after first {:?}",
                first_rh.command
            )
        });
    let frames = [first_frame, second_frame];
    let mut ack_seen = false;
    let mut set_info_seen = false;
    for frame in frames {
        let (rh, _rb) = parse_response_header(&frame);
        match rh.command {
            Command::OplockBreak => {
                assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
                ack_seen = true;
            }
            Command::SetInfo => {
                assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
                assert_eq!(rh.async_id(), pending_async_id);
                set_info_seen = true;
            }
            other => panic!("unexpected post-ack response command {other:?}"),
        }
    }
    assert!(ack_seen, "missing lease break ack response");
    assert!(set_info_seen, "missing final set-info response");
    assert!(!root.join("hello.txt").exists());
    assert_eq!(
        std::fs::read(root.join("renamed.txt")).unwrap(),
        b"hello world"
    );

    drop(s);
    handle.abort();
}

#[tokio::test]
async fn directory_rename_breaks_child_handle_leases_and_waits_for_closes() {
    let (handle, root, addr, mut rename_conn, rename_session, rename_tree) =
        setup_lock_server_with_path_and_addr_smb311().await;
    let mut child_conn = TcpStream::connect(addr).await.expect("connect child");
    let _ = negotiate_smb311_with_client_guid(&mut child_conn, [0x32; 16]).await;
    let child_session = anonymous_session_setup(&mut child_conn).await;
    let child_tree = tree_connect(&mut child_conn, "\\\\127.0.0.1\\share", child_session, 3).await;

    std::fs::create_dir(root.join("leased-dir")).expect("seed leased-dir");
    std::fs::write(root.join("leased-dir/file1.txt"), b"one").expect("seed file1");
    std::fs::write(root.join("leased-dir/file2.txt"), b"two").expect("seed file2");

    let first_key = b"dir-child-key-01";
    let second_key = b"dir-child-key-02";
    let dir = create_directory_open(
        &mut rename_conn,
        rename_session,
        rename_tree,
        4,
        "leased-dir",
    )
    .await;
    let (first, first_grant) = create_lease_open_name_with_lease_data(
        &mut child_conn,
        child_session,
        child_tree,
        5,
        "leased-dir\\file1.txt",
        0x0012_0089 | 0x0012_0116,
        lease_v2_request_with_key(0x0000_0001 | 0x0000_0002, first_key),
    )
    .await;
    let (second, second_grant) = create_lease_open_name_with_lease_data(
        &mut child_conn,
        child_session,
        child_tree,
        6,
        "leased-dir\\file2.txt",
        0x0012_0089 | 0x0012_0116,
        lease_v2_request_with_key(0x0000_0001 | 0x0000_0002, second_key),
    )
    .await;
    assert_eq!(first_grant.state, 0x0000_0001 | 0x0000_0002);
    assert_eq!(second_grant.state, 0x0000_0001 | 0x0000_0002);

    let rename = file_rename_information("leased-dir-renamed", false);
    let req = SetInfoRequest {
        structure_size: 33,
        info_type: InfoType::File as u8,
        file_information_class: 0x0A,
        buffer_length: rename.len() as u32,
        buffer_offset: 64 + 32,
        reserved: 0,
        additional_information: 0,
        file_id: dir.file_id,
        buffer: rename,
    };
    let mut body = Vec::new();
    req.write_to(&mut body).expect("write directory rename");
    let hdr = build_header(Command::SetInfo, 7, rename_session, rename_tree);
    write_frame(&mut rename_conn, &hdr, &body).await;

    let frames = [
        read_frame_with_timeout(&mut child_conn).await,
        read_frame_with_timeout(&mut child_conn).await,
    ];
    let mut broke_first = false;
    let mut broke_second = false;
    for frame in frames {
        let (rh, rb) = parse_response_header(&frame);
        match rh.command {
            Command::OplockBreak => {
                assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
                let notification = LeaseBreakNotification::parse(rb).expect("parse lease break");
                assert_eq!(notification.current_lease_state, 0x0000_0001 | 0x0000_0002);
                assert_eq!(notification.new_lease_state, 0x0000_0001);
                if notification.lease_key == *first_key {
                    broke_first = true;
                } else if notification.lease_key == *second_key {
                    broke_second = true;
                } else {
                    panic!("unexpected lease key {:?}", notification.lease_key);
                }
            }
            other => panic!("unexpected directory rename response {other:?}"),
        }
    }
    assert!(broke_first, "missing first child lease break");
    assert!(broke_second, "missing second child lease break");
    assert!(root.join("leased-dir").exists());
    assert!(!root.join("leased-dir-renamed").exists());

    close(&mut child_conn, child_session, child_tree, 8, first.file_id).await;

    close(
        &mut child_conn,
        child_session,
        child_tree,
        9,
        second.file_id,
    )
    .await;

    let final_frame = read_frame_with_timeout(&mut rename_conn).await;
    let (rh, _rb) = parse_response_header(&final_frame);
    assert_eq!(rh.command, Command::SetInfo);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    assert_eq!(rh.message_id, 7);
    assert!(!root.join("leased-dir").exists());
    assert_eq!(
        std::fs::read(root.join("leased-dir-renamed/file1.txt")).unwrap(),
        b"one"
    );
    assert_eq!(
        std::fs::read(root.join("leased-dir-renamed/file2.txt")).unwrap(),
        b"two"
    );

    close(
        &mut rename_conn,
        rename_session,
        rename_tree,
        10,
        dir.file_id,
    )
    .await;
    drop(rename_conn);
    drop(child_conn);
    handle.abort();
}

#[tokio::test]
async fn set_info_eof_waits_for_lease_break_ack_before_truncating() {
    let (handle, root, mut s, session_id, tree_id) = setup_lock_server_with_path_smb311().await;
    let first_key = b"lease-key-123456";
    let second_key = b"fedcba9876543210";

    let (writer, writer_grant) = create_lease_open_name_with_lease_data(
        &mut s,
        session_id,
        tree_id,
        4,
        "hello.txt",
        0x001f_01ff,
        lease_v2_request_with_key(0x0000_0001, first_key),
    )
    .await;
    let (_reader, reader_grant) = create_lease_open_name_with_lease_data(
        &mut s,
        session_id,
        tree_id,
        5,
        "hello.txt",
        0x0012_0089 | 0x0012_0116,
        lease_v2_request_with_key(0x0000_0001 | 0x0000_0002, second_key),
    )
    .await;
    assert_eq!(writer_grant.state, 0x0000_0001);
    assert_eq!(reader_grant.state, 0x0000_0001 | 0x0000_0002);

    let mut eof = Vec::new();
    eof.extend_from_slice(&3u64.to_le_bytes());
    let req = SetInfoRequest {
        structure_size: 33,
        info_type: InfoType::File as u8,
        file_information_class: 0x14,
        buffer_length: eof.len() as u32,
        buffer_offset: 64 + 32,
        reserved: 0,
        additional_information: 0,
        file_id: writer.file_id,
        buffer: eof,
    };
    let mut body = Vec::new();
    req.write_to(&mut body).expect("write set-info eof");
    let hdr = build_header(Command::SetInfo, 6, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;

    let first_frame = read_frame_with_timeout(&mut s).await;
    let (first_rh, _) = parse_response_header(&first_frame);
    match first_rh.command {
        Command::SetInfo => assert_eq!(first_rh.channel_sequence_status, STATUS_PENDING),
        Command::OplockBreak => assert_eq!(first_rh.channel_sequence_status, STATUS_SUCCESS),
        other => panic!("unexpected first response command {other:?}"),
    }
    let second_frame = tokio::time::timeout(Duration::from_secs(2), read_frame(&mut s))
        .await
        .unwrap_or_else(|_| {
            panic!(
                "missing second response after first {:?} status {:#010x}",
                first_rh.command, first_rh.channel_sequence_status
            )
        });
    let frames = [first_frame, second_frame];
    let mut pending_async_id = None;
    let mut notification = None;
    for frame in frames {
        let (rh, rb) = parse_response_header(&frame);
        match rh.command {
            Command::SetInfo => {
                assert_eq!(rh.channel_sequence_status, STATUS_PENDING);
                assert_eq!(rh.message_id, 6);
                pending_async_id = Some(rh.async_id().expect("pending set-info async id"));
            }
            Command::OplockBreak => {
                assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
                notification = Some(
                    LeaseBreakNotification::parse(rb).expect("parse lease break notification"),
                );
            }
            other => panic!("unexpected response command {other:?}"),
        }
    }

    let notification = notification.expect("missing lease break notification");
    assert_eq!(&notification.lease_key, second_key);
    assert_eq!(notification.current_lease_state, 0x0000_0001 | 0x0000_0002);
    assert_eq!(notification.new_lease_state, 0x0000_0000);
    assert_eq!(std::fs::metadata(root.join("hello.txt")).unwrap().len(), 11);

    let ack = LeaseBreakAck {
        structure_size: 36,
        reserved: 0,
        flags: 0,
        lease_key: *second_key,
        lease_state: 0x0000_0000,
        lease_duration: 0,
    };
    let mut ack_body = Vec::new();
    ack.write_to(&mut ack_body).expect("write lease break ack");
    let ack_hdr = build_header(Command::OplockBreak, 7, session_id, tree_id);
    write_frame(&mut s, &ack_hdr, &ack_body).await;

    let first_frame = read_frame_with_timeout(&mut s).await;
    let (first_rh, _) = parse_response_header(&first_frame);
    match first_rh.command {
        Command::OplockBreak | Command::SetInfo => {
            assert_eq!(first_rh.channel_sequence_status, STATUS_SUCCESS)
        }
        other => panic!("unexpected first post-ack response command {other:?}"),
    }
    let second_frame = tokio::time::timeout(Duration::from_secs(2), read_frame(&mut s))
        .await
        .unwrap_or_else(|_| {
            panic!(
                "missing second post-ack response after first {:?}",
                first_rh.command
            )
        });
    let frames = [first_frame, second_frame];
    let mut ack_seen = false;
    let mut set_info_seen = false;
    for frame in frames {
        let (rh, _rb) = parse_response_header(&frame);
        match rh.command {
            Command::OplockBreak => {
                assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
                ack_seen = true;
            }
            Command::SetInfo => {
                assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
                assert_eq!(rh.async_id(), pending_async_id);
                set_info_seen = true;
            }
            other => panic!("unexpected post-ack response command {other:?}"),
        }
    }
    assert!(ack_seen, "missing lease break ack response");
    assert!(set_info_seen, "missing final set-info response");
    assert_eq!(std::fs::metadata(root.join("hello.txt")).unwrap().len(), 3);

    drop(s);
    handle.abort();
}

#[tokio::test]
async fn set_info_allocation_waits_for_lease_break_ack_before_truncating() {
    let (handle, root, mut s, session_id, tree_id) = setup_lock_server_with_path_smb311().await;
    let first_key = b"lease-key-123456";
    let second_key = b"fedcba9876543210";

    let (writer, writer_grant) = create_lease_open_name_with_lease_data(
        &mut s,
        session_id,
        tree_id,
        4,
        "hello.txt",
        0x001f_01ff,
        lease_v2_request_with_key(0x0000_0001, first_key),
    )
    .await;
    let (_reader, reader_grant) = create_lease_open_name_with_lease_data(
        &mut s,
        session_id,
        tree_id,
        5,
        "hello.txt",
        0x0012_0089 | 0x0012_0116,
        lease_v2_request_with_key(0x0000_0001 | 0x0000_0002, second_key),
    )
    .await;
    assert_eq!(writer_grant.state, 0x0000_0001);
    assert_eq!(reader_grant.state, 0x0000_0001 | 0x0000_0002);

    let mut allocation = Vec::new();
    allocation.extend_from_slice(&3u64.to_le_bytes());
    let req = SetInfoRequest {
        structure_size: 33,
        info_type: InfoType::File as u8,
        file_information_class: 0x13,
        buffer_length: allocation.len() as u32,
        buffer_offset: 64 + 32,
        reserved: 0,
        additional_information: 0,
        file_id: writer.file_id,
        buffer: allocation,
    };
    let mut body = Vec::new();
    req.write_to(&mut body).expect("write set-info allocation");
    let hdr = build_header(Command::SetInfo, 6, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;

    let first_frame = read_frame_with_timeout(&mut s).await;
    let (first_rh, _) = parse_response_header(&first_frame);
    match first_rh.command {
        Command::SetInfo => assert_eq!(first_rh.channel_sequence_status, STATUS_PENDING),
        Command::OplockBreak => assert_eq!(first_rh.channel_sequence_status, STATUS_SUCCESS),
        other => panic!("unexpected first response command {other:?}"),
    }
    let second_frame = tokio::time::timeout(Duration::from_secs(2), read_frame(&mut s))
        .await
        .unwrap_or_else(|_| {
            panic!(
                "missing second response after first {:?} status {:#010x}",
                first_rh.command, first_rh.channel_sequence_status
            )
        });
    let frames = [first_frame, second_frame];
    let mut pending_async_id = None;
    let mut notification = None;
    for frame in frames {
        let (rh, rb) = parse_response_header(&frame);
        match rh.command {
            Command::SetInfo => {
                assert_eq!(rh.channel_sequence_status, STATUS_PENDING);
                assert_eq!(rh.message_id, 6);
                pending_async_id = Some(rh.async_id().expect("pending set-info async id"));
            }
            Command::OplockBreak => {
                assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
                notification = Some(
                    LeaseBreakNotification::parse(rb).expect("parse lease break notification"),
                );
            }
            other => panic!("unexpected response command {other:?}"),
        }
    }

    let notification = notification.expect("missing lease break notification");
    assert_eq!(&notification.lease_key, second_key);
    assert_eq!(notification.current_lease_state, 0x0000_0001 | 0x0000_0002);
    assert_eq!(notification.new_lease_state, 0x0000_0000);
    assert_eq!(std::fs::metadata(root.join("hello.txt")).unwrap().len(), 11);

    let ack = LeaseBreakAck {
        structure_size: 36,
        reserved: 0,
        flags: 0,
        lease_key: *second_key,
        lease_state: 0x0000_0000,
        lease_duration: 0,
    };
    let mut ack_body = Vec::new();
    ack.write_to(&mut ack_body).expect("write lease break ack");
    let ack_hdr = build_header(Command::OplockBreak, 7, session_id, tree_id);
    write_frame(&mut s, &ack_hdr, &ack_body).await;

    let first_frame = read_frame_with_timeout(&mut s).await;
    let (first_rh, _) = parse_response_header(&first_frame);
    match first_rh.command {
        Command::OplockBreak | Command::SetInfo => {
            assert_eq!(first_rh.channel_sequence_status, STATUS_SUCCESS)
        }
        other => panic!("unexpected first post-ack response command {other:?}"),
    }
    let second_frame = tokio::time::timeout(Duration::from_secs(2), read_frame(&mut s))
        .await
        .unwrap_or_else(|_| {
            panic!(
                "missing second post-ack response after first {:?}",
                first_rh.command
            )
        });
    let frames = [first_frame, second_frame];
    let mut ack_seen = false;
    let mut set_info_seen = false;
    for frame in frames {
        let (rh, _rb) = parse_response_header(&frame);
        match rh.command {
            Command::OplockBreak => {
                assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
                ack_seen = true;
            }
            Command::SetInfo => {
                assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
                assert_eq!(rh.async_id(), pending_async_id);
                set_info_seen = true;
            }
            other => panic!("unexpected post-ack response command {other:?}"),
        }
    }
    assert!(ack_seen, "missing lease break ack response");
    assert!(set_info_seen, "missing final set-info response");
    assert_eq!(std::fs::metadata(root.join("hello.txt")).unwrap().len(), 3);

    drop(s);
    handle.abort();
}

#[tokio::test]
async fn set_info_delete_waits_for_lease_break_ack_before_delete_pending() {
    let (handle, _root, mut s, session_id, tree_id) = setup_lock_server_with_path_smb311().await;
    let first_key = b"lease-key-123456";
    let second_key = b"fedcba9876543210";

    let (delete_open, delete_grant) = create_lease_open_name_with_lease_data(
        &mut s,
        session_id,
        tree_id,
        4,
        "hello.txt",
        0x001f_01ff,
        lease_v2_request_with_key(0x0000_0001, first_key),
    )
    .await;
    let (_reader, reader_grant) = create_lease_open_name_with_lease_data(
        &mut s,
        session_id,
        tree_id,
        5,
        "hello.txt",
        0x0012_0089 | 0x0012_0116,
        lease_v2_request_with_key(0x0000_0001 | 0x0000_0002, second_key),
    )
    .await;
    assert_eq!(delete_grant.state, 0x0000_0001);
    assert_eq!(reader_grant.state, 0x0000_0001 | 0x0000_0002);

    let req = SetInfoRequest {
        structure_size: 33,
        info_type: InfoType::File as u8,
        file_information_class: 0x0D,
        buffer_length: 1,
        buffer_offset: 64 + 32,
        reserved: 0,
        additional_information: 0,
        file_id: delete_open.file_id,
        buffer: vec![1],
    };
    let mut body = Vec::new();
    req.write_to(&mut body).expect("write set-info disposition");
    let hdr = build_header(Command::SetInfo, 6, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;

    let first_frame = read_frame_with_timeout(&mut s).await;
    let (first_rh, _) = parse_response_header(&first_frame);
    match first_rh.command {
        Command::SetInfo => assert_eq!(first_rh.channel_sequence_status, STATUS_PENDING),
        Command::OplockBreak => assert_eq!(first_rh.channel_sequence_status, STATUS_SUCCESS),
        other => panic!("unexpected first response command {other:?}"),
    }
    let second_frame = tokio::time::timeout(Duration::from_secs(2), read_frame(&mut s))
        .await
        .unwrap_or_else(|_| {
            panic!(
                "missing second response after first {:?} status {:#010x}",
                first_rh.command, first_rh.channel_sequence_status
            )
        });
    let frames = [first_frame, second_frame];
    let mut pending_async_id = None;
    let mut notification = None;
    for frame in frames {
        let (rh, rb) = parse_response_header(&frame);
        match rh.command {
            Command::SetInfo => {
                assert_eq!(rh.channel_sequence_status, STATUS_PENDING);
                assert_eq!(rh.message_id, 6);
                pending_async_id = Some(rh.async_id().expect("pending set-info async id"));
            }
            Command::OplockBreak => {
                assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
                notification = Some(
                    LeaseBreakNotification::parse(rb).expect("parse lease break notification"),
                );
            }
            other => panic!("unexpected response command {other:?}"),
        }
    }

    let notification = notification.expect("missing lease break notification");
    assert_eq!(&notification.lease_key, second_key);
    assert_eq!(notification.current_lease_state, 0x0000_0001 | 0x0000_0002);
    assert_eq!(notification.new_lease_state, 0x0000_0001);
    assert!(
        !query_standard_delete_pending(&mut s, session_id, tree_id, 7, delete_open.file_id).await
    );

    let ack = LeaseBreakAck {
        structure_size: 36,
        reserved: 0,
        flags: 0,
        lease_key: *second_key,
        lease_state: 0x0000_0001,
        lease_duration: 0,
    };
    let mut ack_body = Vec::new();
    ack.write_to(&mut ack_body).expect("write lease break ack");
    let ack_hdr = build_header(Command::OplockBreak, 8, session_id, tree_id);
    write_frame(&mut s, &ack_hdr, &ack_body).await;

    let first_frame = read_frame_with_timeout(&mut s).await;
    let (first_rh, _) = parse_response_header(&first_frame);
    match first_rh.command {
        Command::OplockBreak | Command::SetInfo => {
            assert_eq!(first_rh.channel_sequence_status, STATUS_SUCCESS)
        }
        other => panic!("unexpected first post-ack response command {other:?}"),
    }
    let second_frame = tokio::time::timeout(Duration::from_secs(2), read_frame(&mut s))
        .await
        .unwrap_or_else(|_| {
            panic!(
                "missing second post-ack response after first {:?}",
                first_rh.command
            )
        });
    let frames = [first_frame, second_frame];
    let mut ack_seen = false;
    let mut set_info_seen = false;
    for frame in frames {
        let (rh, _rb) = parse_response_header(&frame);
        match rh.command {
            Command::OplockBreak => {
                assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
                ack_seen = true;
            }
            Command::SetInfo => {
                assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
                assert_eq!(rh.async_id(), pending_async_id);
                set_info_seen = true;
            }
            other => panic!("unexpected post-ack response command {other:?}"),
        }
    }
    assert!(ack_seen, "missing lease break ack response");
    assert!(set_info_seen, "missing final set-info response");
    assert!(
        query_standard_delete_pending(&mut s, session_id, tree_id, 9, delete_open.file_id).await
    );

    drop(s);
    handle.abort();
}

#[tokio::test]
async fn cancelled_cache_break_create_does_not_resume_after_lease_ack() {
    let (handle, mut s, session_id, tree_id) = setup_lock_server_smb311().await;
    let first_key = b"lease-key-123456";
    let other_key = b"fedcba9876543210";

    let (first, _) = create_lease_open_with_lease_data(
        &mut s,
        session_id,
        tree_id,
        4,
        0x0012_0089 | 0x0012_0116,
        lease_v2_request_with_key(0x0000_0001 | 0x0000_0004, first_key),
    )
    .await;

    send_create_lease_open_with_lease_data(
        &mut s,
        session_id,
        tree_id,
        5,
        0x0012_0089 | 0x0012_0116,
        lease_v2_request_with_key(0x0000_0001, other_key),
    )
    .await;

    let frames = [read_frame(&mut s).await, read_frame(&mut s).await];
    let mut async_id = None;
    let mut saw_notification = false;
    for frame in frames {
        let (rh, _rb) = parse_response_header(&frame);
        match rh.command {
            Command::Create => {
                assert_eq!(rh.channel_sequence_status, STATUS_PENDING);
                async_id = rh.async_id();
            }
            Command::OplockBreak => {
                assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
                saw_notification = true;
            }
            other => panic!("unexpected response command {other:?}"),
        }
    }
    let async_id = async_id.expect("pending create async id");
    assert!(saw_notification, "missing lease break notification");

    send_async_cancel(&mut s, 6, session_id, async_id).await;
    let cancel_final = read_frame(&mut s).await;
    let (rh, _rb) = parse_response_header(&cancel_final);
    assert_eq!(rh.command, Command::Create);
    assert_eq!(rh.channel_sequence_status, STATUS_CANCELLED);
    assert_eq!(rh.async_id(), Some(async_id));
    assert_eq!(rh.credit_request_response, 0);

    let ack = send_lease_break_ack(&mut s, session_id, tree_id, 7, first_key, 0x0000_0001).await;
    assert_eq!(ack.0, STATUS_SUCCESS);
    let no_final = tokio::time::timeout(Duration::from_millis(25), read_frame(&mut s)).await;
    assert!(
        no_final.is_err(),
        "cancelled pending create resumed after lease ACK"
    );

    close(&mut s, session_id, tree_id, 8, first.file_id).await;
    drop(s);
    handle.abort();
}

#[tokio::test]
async fn tree_disconnect_cleans_up_pending_cache_break_create() {
    let (handle, mut s, session_id, tree_id) = setup_lock_server_smb311().await;
    let first_key = b"lease-key-123456";
    let other_key = b"fedcba9876543210";

    let (_first, _) = create_lease_open_with_lease_data(
        &mut s,
        session_id,
        tree_id,
        4,
        0x0012_0089 | 0x0012_0116,
        lease_v2_request_with_key(0x0000_0001 | 0x0000_0004, first_key),
    )
    .await;

    send_create_lease_open_with_lease_data(
        &mut s,
        session_id,
        tree_id,
        5,
        0x0012_0089 | 0x0012_0116,
        lease_v2_request_with_key(0x0000_0001, other_key),
    )
    .await;

    let frames = [read_frame(&mut s).await, read_frame(&mut s).await];
    let mut async_id = None;
    let mut saw_notification = false;
    for frame in frames {
        let (rh, _rb) = parse_response_header(&frame);
        match rh.command {
            Command::Create => {
                assert_eq!(rh.channel_sequence_status, STATUS_PENDING);
                async_id = rh.async_id();
            }
            Command::OplockBreak => {
                assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
                saw_notification = true;
            }
            other => panic!("unexpected response command {other:?}"),
        }
    }
    let async_id = async_id.expect("pending create async id");
    assert!(saw_notification, "missing lease break notification");

    let mut body = Vec::new();
    TreeDisconnectRequest::default()
        .write_to(&mut body)
        .expect("write tree disconnect");
    let hdr = build_header(Command::TreeDisconnect, 6, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;

    let frames = [read_frame(&mut s).await, read_frame(&mut s).await];
    let mut saw_cleanup = false;
    let mut saw_tree_disconnect = false;
    for frame in frames {
        let (rh, rb) = parse_response_header(&frame);
        match rh.command {
            Command::Create => {
                assert_eq!(rh.channel_sequence_status, STATUS_NOTIFY_CLEANUP);
                assert_eq!(rh.async_id(), Some(async_id));
                saw_cleanup = true;
            }
            Command::TreeDisconnect => {
                assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
                let _ = TreeDisconnectResponse::parse(rb).expect("parse tree disconnect");
                saw_tree_disconnect = true;
            }
            other => panic!("unexpected cleanup response command {other:?}"),
        }
    }
    assert!(saw_cleanup, "missing pending create cleanup response");
    assert!(saw_tree_disconnect, "missing tree disconnect response");

    drop(s);
    handle.abort();
}

#[tokio::test]
async fn lease_break_ack_rejects_unknown_and_non_breaking_keys() {
    let (handle, mut s, session_id, tree_id) = setup_lock_server_smb311().await;
    let lease_key = b"lease-key-123456";

    let (create, state) = create_lease_open_with_key(
        &mut s,
        session_id,
        tree_id,
        4,
        0x0012_0089 | 0x0012_0116,
        0x0000_0001 | 0x0000_0002,
        lease_key,
    )
    .await;
    assert_eq!(state, 0x0000_0001 | 0x0000_0002);

    let unknown =
        send_lease_break_ack(&mut s, session_id, tree_id, 5, b"unknown-leasekey", 0).await;
    assert_eq!(unknown.0, STATUS_OBJECT_NAME_NOT_FOUND);

    let known = send_lease_break_ack(&mut s, session_id, tree_id, 6, lease_key, 0x0000_0001).await;
    assert_eq!(known.0, STATUS_UNSUCCESSFUL);

    close(&mut s, session_id, tree_id, 7, create.file_id).await;
    drop(s);
    handle.abort();
}

#[tokio::test]
async fn logoff_cleans_up_pending_cache_break_create() {
    let (handle, mut s, session_id, tree_id) = setup_lock_server_smb311().await;
    let first_key = b"lease-key-123456";
    let other_key = b"fedcba9876543210";

    let (_first, _) = create_lease_open_with_lease_data(
        &mut s,
        session_id,
        tree_id,
        4,
        0x0012_0089 | 0x0012_0116,
        lease_v2_request_with_key(0x0000_0001 | 0x0000_0004, first_key),
    )
    .await;

    send_create_lease_open_with_lease_data(
        &mut s,
        session_id,
        tree_id,
        5,
        0x0012_0089 | 0x0012_0116,
        lease_v2_request_with_key(0x0000_0001, other_key),
    )
    .await;

    let frames = [read_frame(&mut s).await, read_frame(&mut s).await];
    let mut async_id = None;
    let mut saw_notification = false;
    for frame in frames {
        let (rh, _rb) = parse_response_header(&frame);
        match rh.command {
            Command::Create => {
                assert_eq!(rh.channel_sequence_status, STATUS_PENDING);
                async_id = rh.async_id();
            }
            Command::OplockBreak => {
                assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
                saw_notification = true;
            }
            other => panic!("unexpected response command {other:?}"),
        }
    }
    let async_id = async_id.expect("pending create async id");
    assert!(saw_notification, "missing lease break notification");

    let mut body = Vec::new();
    LogoffRequest::default()
        .write_to(&mut body)
        .expect("write logoff");
    let hdr = build_header(Command::Logoff, 6, session_id, 0);
    write_frame(&mut s, &hdr, &body).await;

    let frames = [read_frame(&mut s).await, read_frame(&mut s).await];
    let mut saw_logoff = false;
    let mut saw_cleanup = false;
    for frame in frames {
        let (rh, rb) = parse_response_header(&frame);
        match rh.command {
            Command::Logoff => {
                assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
                let _ = LogoffResponse::parse(rb).expect("parse logoff response");
                saw_logoff = true;
            }
            Command::Create => {
                assert_eq!(rh.channel_sequence_status, STATUS_NOTIFY_CLEANUP);
                assert_eq!(rh.async_id(), Some(async_id));
                assert_eq!(rh.credit_request_response, 0);
                saw_cleanup = true;
            }
            other => panic!("unexpected post-logoff response command {other:?}"),
        }
    }
    assert!(saw_logoff, "missing logoff response");
    assert!(saw_cleanup, "missing pending create cleanup response");

    let no_final = tokio::time::timeout(Duration::from_millis(25), read_frame(&mut s)).await;
    assert!(
        no_final.is_err(),
        "pending cache-break create produced an extra response after logoff"
    );

    drop(s);
    handle.abort();
}

#[tokio::test]
async fn logoff_cleans_up_pending_cache_break_set_info_task() {
    let (handle, root, mut s, session_id, tree_id) = setup_lock_server_with_path_smb311().await;
    let first_key = b"lease-key-123456";
    let second_key = b"fedcba9876543210";

    let (first, _) = create_lease_open_name_with_lease_data(
        &mut s,
        session_id,
        tree_id,
        4,
        "hello.txt",
        0x001f_01ff,
        lease_v2_request_with_key(0x0000_0001 | 0x0000_0002, first_key),
    )
    .await;
    let (_second, _) = create_lease_open_name_with_lease_data(
        &mut s,
        session_id,
        tree_id,
        5,
        "hello.txt",
        0x0012_0089 | 0x0012_0116,
        lease_v2_request_with_key(0x0000_0001 | 0x0000_0002, second_key),
    )
    .await;

    let rename = file_rename_information("renamed.txt", false);
    let req = SetInfoRequest {
        structure_size: 33,
        info_type: InfoType::File as u8,
        file_information_class: 0x0A,
        buffer_length: rename.len() as u32,
        buffer_offset: 64 + 32,
        reserved: 0,
        additional_information: 0,
        file_id: first.file_id,
        buffer: rename,
    };
    let mut body = Vec::new();
    req.write_to(&mut body).expect("write set-info rename");
    let hdr = build_header(Command::SetInfo, 6, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;

    let frames = [read_frame(&mut s).await, read_frame(&mut s).await];
    let mut async_id = None;
    let mut saw_notification = false;
    for frame in frames {
        let (rh, _rb) = parse_response_header(&frame);
        match rh.command {
            Command::SetInfo => {
                assert_eq!(rh.channel_sequence_status, STATUS_PENDING);
                async_id = rh.async_id();
            }
            Command::OplockBreak => {
                assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
                saw_notification = true;
            }
            other => panic!("unexpected response command {other:?}"),
        }
    }
    let async_id = async_id.expect("pending set-info async id");
    assert!(saw_notification, "missing lease break notification");
    assert!(root.join("hello.txt").exists());
    assert!(!root.join("renamed.txt").exists());

    let mut body = Vec::new();
    LogoffRequest::default()
        .write_to(&mut body)
        .expect("write logoff");
    let hdr = build_header(Command::Logoff, 7, session_id, 0);
    write_frame(&mut s, &hdr, &body).await;

    let frames = [read_frame(&mut s).await, read_frame(&mut s).await];
    let mut saw_logoff = false;
    let mut saw_cleanup = false;
    for frame in frames {
        let (rh, rb) = parse_response_header(&frame);
        match rh.command {
            Command::Logoff => {
                assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
                let _ = LogoffResponse::parse(rb).expect("parse logoff response");
                saw_logoff = true;
            }
            Command::SetInfo => {
                assert_eq!(rh.channel_sequence_status, STATUS_NOTIFY_CLEANUP);
                assert_eq!(rh.async_id(), Some(async_id));
                assert_eq!(rh.credit_request_response, 0);
                saw_cleanup = true;
            }
            other => panic!("unexpected post-logoff response command {other:?}"),
        }
    }
    assert!(saw_logoff, "missing logoff response");
    assert!(saw_cleanup, "missing pending set-info cleanup response");
    assert!(root.join("hello.txt").exists());
    assert!(!root.join("renamed.txt").exists());

    let no_final = tokio::time::timeout(Duration::from_millis(25), read_frame(&mut s)).await;
    assert!(
        no_final.is_err(),
        "pending cache-break set-info produced an extra response after logoff"
    );

    drop(s);
    handle.abort();
}

#[tokio::test]
async fn logoff_cleans_up_pending_cache_break_write() {
    let (handle, root, mut s, session_id, tree_id) = setup_lock_server_with_path_smb311().await;
    let first_key = b"lease-key-123456";
    let second_key = b"fedcba9876543210";

    let (writer, _) = create_lease_open_name_with_lease_data(
        &mut s,
        session_id,
        tree_id,
        4,
        "hello.txt",
        0x001f_01ff,
        lease_v2_request_with_key(0x0000_0001, first_key),
    )
    .await;
    let (_reader, _) = create_lease_open_name_with_lease_data(
        &mut s,
        session_id,
        tree_id,
        5,
        "hello.txt",
        0x0012_0089 | 0x0012_0116,
        lease_v2_request_with_key(0x0000_0001 | 0x0000_0002, second_key),
    )
    .await;

    let req = WriteRequest {
        structure_size: 49,
        data_offset: WriteRequest::STANDARD_DATA_OFFSET,
        length: 3,
        offset: 0,
        file_id: writer.file_id,
        channel: 0,
        remaining_bytes: 0,
        write_channel_info_offset: 0,
        write_channel_info_length: 0,
        flags: 0,
        data: b"bye".to_vec(),
    };
    let mut body = Vec::new();
    req.write_to(&mut body).expect("write write");
    let hdr = build_header(Command::Write, 6, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;

    let frames = [read_frame(&mut s).await, read_frame(&mut s).await];
    let mut async_id = None;
    let mut saw_notification = false;
    for frame in frames {
        let (rh, _rb) = parse_response_header(&frame);
        match rh.command {
            Command::Write => {
                assert_eq!(rh.channel_sequence_status, STATUS_PENDING);
                async_id = rh.async_id();
            }
            Command::OplockBreak => {
                assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
                saw_notification = true;
            }
            other => panic!("unexpected response command {other:?}"),
        }
    }
    let async_id = async_id.expect("pending write async id");
    assert!(saw_notification, "missing lease break notification");
    assert_eq!(
        std::fs::read(root.join("hello.txt")).unwrap(),
        b"hello world"
    );

    let mut body = Vec::new();
    LogoffRequest::default()
        .write_to(&mut body)
        .expect("write logoff");
    let hdr = build_header(Command::Logoff, 7, session_id, 0);
    write_frame(&mut s, &hdr, &body).await;

    let frames = [read_frame(&mut s).await, read_frame(&mut s).await];
    let mut saw_logoff = false;
    let mut saw_cleanup = false;
    for frame in frames {
        let (rh, rb) = parse_response_header(&frame);
        match rh.command {
            Command::Logoff => {
                assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
                let _ = LogoffResponse::parse(rb).expect("parse logoff response");
                saw_logoff = true;
            }
            Command::Write => {
                assert_eq!(rh.channel_sequence_status, STATUS_NOTIFY_CLEANUP);
                assert_eq!(rh.async_id(), Some(async_id));
                assert_eq!(rh.credit_request_response, 0);
                saw_cleanup = true;
            }
            other => panic!("unexpected post-logoff response command {other:?}"),
        }
    }
    assert!(saw_logoff, "missing logoff response");
    assert!(saw_cleanup, "missing pending write cleanup response");
    assert_eq!(
        std::fs::read(root.join("hello.txt")).unwrap(),
        b"hello world"
    );

    let no_final = tokio::time::timeout(Duration::from_millis(25), read_frame(&mut s)).await;
    assert!(
        no_final.is_err(),
        "pending cache-break write produced an extra response after logoff"
    );

    drop(s);
    handle.abort();
}

#[tokio::test]
async fn lease_break_ack_rejects_invalid_state_bits() {
    let (handle, mut s, session_id, tree_id) = setup_lock_server_smb311().await;
    let lease_key = b"lease-key-123456";

    let (create, _) = create_lease_open_with_key(
        &mut s,
        session_id,
        tree_id,
        4,
        0x0012_0089 | 0x0012_0116,
        0x0000_0001,
        lease_key,
    )
    .await;

    let invalid =
        send_lease_break_ack(&mut s, session_id, tree_id, 5, lease_key, 0x8000_0000).await;
    assert_eq!(invalid.0, STATUS_INVALID_PARAMETER);

    close(&mut s, session_id, tree_id, 6, create.file_id).await;
    drop(s);
    handle.abort();
}

#[tokio::test]
async fn oplock_break_ack_rejects_non_breaking_file_id() {
    let (handle, mut s, session_id, tree_id) = setup_lock_server_smb311().await;
    let file_id = create_rw(&mut s, session_id, tree_id, 4).await;

    let req = OplockBreakAck {
        structure_size: 24,
        oplock_level: 0x01,
        reserved: 0,
        reserved2: 0,
        file_id,
    };
    let mut body = Vec::new();
    req.write_to(&mut body).expect("write oplock break ack");
    let hdr = build_header(Command::OplockBreak, 5, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, _rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::OplockBreak);
    assert_eq!(rh.channel_sequence_status, STATUS_OBJECT_NAME_NOT_FOUND);

    close(&mut s, session_id, tree_id, 6, file_id).await;
    drop(s);
    handle.abort();
}

#[tokio::test]
async fn create_grants_exclusive_oplock() {
    let (handle, mut s, session_id, tree_id) = setup_lock_server_smb311().await;

    let create = create_oplock_open(&mut s, session_id, tree_id, 4, 0x08, 0x001f_01ff).await;
    assert_eq!(create.oplock_level, 0x08);

    close(&mut s, session_id, tree_id, 5, create.file_id).await;
    drop(s);
    handle.abort();
}

#[tokio::test]
async fn read_open_breaks_exclusive_oplock_to_level_ii() {
    let (handle, mut s, session_id, tree_id) = setup_lock_server_smb311().await;

    let first = create_oplock_open(&mut s, session_id, tree_id, 4, 0x08, 0x001f_01ff).await;
    assert_eq!(first.oplock_level, 0x08);

    send_create_oplock_open(&mut s, session_id, tree_id, 5, 0, 0x0012_0089).await;

    let frames = [read_frame(&mut s).await, read_frame(&mut s).await];
    let mut pending_async_id = None;
    let mut notification = None;
    for frame in frames {
        let (rh, rb) = parse_response_header(&frame);
        match rh.command {
            Command::Create => {
                assert_eq!(rh.channel_sequence_status, STATUS_PENDING);
                assert_eq!(rh.message_id, 5);
                pending_async_id = Some(rh.async_id().expect("pending create async id"));
            }
            Command::OplockBreak => {
                assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
                notification = Some(OplockBreakAck::parse(rb).expect("parse oplock break"));
            }
            other => panic!("unexpected response command {other:?}"),
        }
    }

    let pending_async_id = pending_async_id.expect("missing pending create");
    let notification = notification.expect("missing oplock break notification");
    assert_eq!(notification.oplock_level, 0x01);
    assert_eq!(notification.file_id, first.file_id);

    let ack = OplockBreakAck {
        structure_size: 24,
        oplock_level: 0x01,
        reserved: 0,
        reserved2: 0,
        file_id: first.file_id,
    };
    let mut body = Vec::new();
    ack.write_to(&mut body).expect("write oplock break ack");
    let hdr = build_header(Command::OplockBreak, 6, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;

    let frames = [read_frame(&mut s).await, read_frame(&mut s).await];
    let mut ack_seen = false;
    let mut second = None;
    for frame in frames {
        let (rh, rb) = parse_response_header(&frame);
        match rh.command {
            Command::OplockBreak => {
                assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
                let ack = OplockBreakAck::parse(rb).expect("parse oplock break ack response");
                assert_eq!(ack.oplock_level, 0x01);
                assert_eq!(ack.file_id, first.file_id);
                ack_seen = true;
            }
            Command::Create => {
                assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
                assert_eq!(rh.async_id(), Some(pending_async_id));
                second = Some(CreateResponse::parse(rb).expect("parse final create"));
            }
            other => panic!("unexpected post-ack response command {other:?}"),
        }
    }
    assert!(ack_seen, "missing oplock break ack response");
    let second = second.expect("missing final create response");
    assert_eq!(second.oplock_level, 0);

    close(&mut s, session_id, tree_id, 7, second.file_id).await;
    close(&mut s, session_id, tree_id, 8, first.file_id).await;
    drop(s);
    handle.abort();
}

#[tokio::test]
async fn lease_open_breaks_exclusive_oplock_to_level_ii_and_grants_read_lease() {
    const LEASE_READ: u32 = 0x0000_0001;
    const LEASE_HANDLE: u32 = 0x0000_0002;
    const LEASE_WRITE: u32 = 0x0000_0004;

    let (handle, mut s, session_id, tree_id) = setup_lock_server_smb311().await;

    let first = create_oplock_open(&mut s, session_id, tree_id, 4, 0x08, 0x001f_01ff).await;
    assert_eq!(first.oplock_level, 0x08);

    send_create_lease_open_with_lease_data(
        &mut s,
        session_id,
        tree_id,
        5,
        0x001f_01ff,
        lease_v1_request_with_key(LEASE_READ | LEASE_HANDLE | LEASE_WRITE, b"lease-key-123456"),
    )
    .await;

    let frames = [read_frame(&mut s).await, read_frame(&mut s).await];
    let mut pending_async_id = None;
    let mut notification = None;
    for frame in frames {
        let (rh, rb) = parse_response_header(&frame);
        match rh.command {
            Command::Create => {
                assert_eq!(rh.channel_sequence_status, STATUS_PENDING);
                pending_async_id = Some(rh.async_id().expect("pending create async id"));
            }
            Command::OplockBreak => {
                assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
                notification = Some(OplockBreakAck::parse(rb).expect("parse oplock break"));
            }
            other => panic!("unexpected response command {other:?}"),
        }
    }
    let pending_async_id = pending_async_id.expect("missing pending create");
    let notification = notification.expect("missing oplock break notification");
    assert_eq!(notification.oplock_level, 0x01);
    assert_eq!(notification.file_id, first.file_id);

    let ack = OplockBreakAck {
        structure_size: 24,
        oplock_level: 0x01,
        reserved: 0,
        reserved2: 0,
        file_id: first.file_id,
    };
    let mut body = Vec::new();
    ack.write_to(&mut body).expect("write oplock break ack");
    let hdr = build_header(Command::OplockBreak, 6, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;

    let frames = [read_frame(&mut s).await, read_frame(&mut s).await];
    let mut ack_seen = false;
    let mut second = None;
    for frame in frames {
        let (rh, rb) = parse_response_header(&frame);
        match rh.command {
            Command::OplockBreak => {
                assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
                ack_seen = true;
            }
            Command::Create => {
                assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
                assert_eq!(rh.async_id(), Some(pending_async_id));
                second = Some(CreateResponse::parse(rb).expect("parse final create"));
            }
            other => panic!("unexpected post-ack response command {other:?}"),
        }
    }
    assert!(ack_seen, "missing oplock break ack response");
    let second = second.expect("missing final create response");
    assert_eq!(lease_grant_from_create(&second).state, LEASE_READ);

    close(&mut s, session_id, tree_id, 7, second.file_id).await;
    close(&mut s, session_id, tree_id, 8, first.file_id).await;
    drop(s);
    handle.abort();
}

#[tokio::test]
async fn read_control_create_waits_for_batch_oplock_break_ack() {
    let (handle, mut s, session_id, tree_id) = setup_lock_server_smb311().await;

    let first = create_oplock_open(&mut s, session_id, tree_id, 4, 0x09, 0x001f_01ff).await;
    assert_eq!(first.oplock_level, 0x09);

    send_create_oplock_open(&mut s, session_id, tree_id, 5, 0, 0x0002_0000).await;

    let frames = [read_frame(&mut s).await, read_frame(&mut s).await];
    let mut pending_async_id = None;
    let mut notification = None;
    for frame in frames {
        let (rh, rb) = parse_response_header(&frame);
        match rh.command {
            Command::Create => {
                assert_eq!(rh.channel_sequence_status, STATUS_PENDING);
                pending_async_id = Some(rh.async_id().expect("pending create async id"));
            }
            Command::OplockBreak => {
                assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
                notification = Some(OplockBreakAck::parse(rb).expect("parse oplock break"));
            }
            other => panic!("unexpected response command {other:?}"),
        }
    }
    let pending_async_id = pending_async_id.expect("missing pending create");
    let notification = notification.expect("missing oplock break notification");
    assert_eq!(notification.oplock_level, 0x01);
    assert_eq!(notification.file_id, first.file_id);

    let ack = OplockBreakAck {
        structure_size: 24,
        oplock_level: 0x01,
        reserved: 0,
        reserved2: 0,
        file_id: first.file_id,
    };
    let mut body = Vec::new();
    ack.write_to(&mut body).expect("write oplock break ack");
    let hdr = build_header(Command::OplockBreak, 6, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;

    let frames = [read_frame(&mut s).await, read_frame(&mut s).await];
    let mut ack_seen = false;
    let mut second = None;
    for frame in frames {
        let (rh, rb) = parse_response_header(&frame);
        match rh.command {
            Command::OplockBreak => {
                assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
                let ack = OplockBreakAck::parse(rb).expect("parse oplock break ack response");
                assert_eq!(ack.oplock_level, 0x01);
                assert_eq!(ack.file_id, first.file_id);
                ack_seen = true;
            }
            Command::Create => {
                assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
                assert_eq!(rh.async_id(), Some(pending_async_id));
                second = Some(CreateResponse::parse(rb).expect("parse final create"));
            }
            other => panic!("unexpected post-ack response command {other:?}"),
        }
    }
    assert!(ack_seen, "missing oplock break ack response");
    let second = second.expect("missing final create response");
    assert_eq!(second.oplock_level, 0);

    let req = LockRequest {
        structure_size: 48,
        lock_count: 1,
        lock_sequence: 0,
        file_id: first.file_id,
        locks: vec![LockElement {
            offset: 0,
            length: 4,
            flags: LockElement::FLAG_EXCLUSIVE_LOCK | LockElement::FLAG_FAIL_IMMEDIATELY,
            reserved: 0,
        }],
    };
    let mut body = Vec::new();
    req.write_to(&mut body).expect("write lock");
    let hdr = build_header(Command::Lock, 7, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;

    let frames = [read_frame(&mut s).await, read_frame(&mut s).await];
    let mut saw_lock = false;
    let mut saw_level_none_break = false;
    for frame in frames {
        let (rh, rb) = parse_response_header(&frame);
        match rh.command {
            Command::Lock => {
                assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
                let _ = LockResponse::parse(rb).expect("parse lock response");
                saw_lock = true;
            }
            Command::OplockBreak => {
                assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
                let notification = OplockBreakAck::parse(rb).expect("parse oplock break");
                assert_eq!(notification.oplock_level, 0);
                assert_eq!(notification.file_id, first.file_id);
                saw_level_none_break = true;
            }
            other => panic!("unexpected post-lock response command {other:?}"),
        }
    }
    assert!(saw_lock, "missing lock response");
    assert!(saw_level_none_break, "missing LevelII-to-None oplock break");

    close(&mut s, session_id, tree_id, 8, first.file_id).await;
    close(&mut s, session_id, tree_id, 9, second.file_id).await;
    drop(s);
    handle.abort();
}

#[tokio::test]
async fn set_info_eof_breaks_batch_downgraded_level_ii_oplock_to_none() {
    let (handle, addr, mut s1, session1, tree1) = setup_lock_server_with_addr_smb311().await;
    let mut s2 = TcpStream::connect(addr).await.expect("connect second");
    let _ = negotiate_smb311_with_client_guid(&mut s2, [0x42; 16]).await;
    let session2 = anonymous_session_setup(&mut s2).await;
    let tree2 = tree_connect(&mut s2, "\\\\127.0.0.1\\share", session2, 3).await;

    let first = create_oplock_open(&mut s1, session1, tree1, 4, 0x09, 0x001f_01ff).await;
    assert_eq!(first.oplock_level, 0x09);

    send_create_oplock_open(&mut s2, session2, tree2, 5, 0, 0x001f_01ff).await;
    let pending = read_frame_with_timeout(&mut s2).await;
    let (pending_hdr, _) = parse_response_header(&pending);
    assert_eq!(pending_hdr.command, Command::Create);
    assert_eq!(pending_hdr.channel_sequence_status, STATUS_PENDING);
    let pending_async_id = pending_hdr.async_id().expect("pending create async id");

    let break_frame = read_frame_with_timeout(&mut s1).await;
    let (break_hdr, break_body) = parse_response_header(&break_frame);
    assert_eq!(break_hdr.command, Command::OplockBreak);
    assert_eq!(break_hdr.channel_sequence_status, STATUS_SUCCESS);
    let notification = OplockBreakAck::parse(break_body).expect("parse batch break");
    assert_eq!(notification.oplock_level, 0x01);
    assert_eq!(notification.file_id, first.file_id);

    let ack = OplockBreakAck {
        structure_size: 24,
        oplock_level: 0x01,
        reserved: 0,
        reserved2: 0,
        file_id: first.file_id,
    };
    let mut ack_body = Vec::new();
    ack.write_to(&mut ack_body).expect("write oplock ack");
    let ack_hdr = build_header(Command::OplockBreak, 6, session1, tree1);
    write_frame(&mut s1, &ack_hdr, &ack_body).await;

    let ack_response = read_frame_with_timeout(&mut s1).await;
    let (ack_rh, ack_rb) = parse_response_header(&ack_response);
    assert_eq!(ack_rh.command, Command::OplockBreak);
    assert_eq!(ack_rh.channel_sequence_status, STATUS_SUCCESS);
    let ack = OplockBreakAck::parse(ack_rb).expect("parse oplock ack response");
    assert_eq!(ack.oplock_level, 0x01);

    let final_create = read_frame_with_timeout(&mut s2).await;
    let (final_rh, final_rb) = parse_response_header(&final_create);
    assert_eq!(final_rh.command, Command::Create);
    assert_eq!(final_rh.channel_sequence_status, STATUS_SUCCESS);
    assert_eq!(final_rh.async_id(), Some(pending_async_id));
    let second = CreateResponse::parse(final_rb).expect("parse final create");

    let mut eof = Vec::new();
    eof.extend_from_slice(&100u64.to_le_bytes());
    let req = SetInfoRequest {
        structure_size: 33,
        info_type: InfoType::File as u8,
        file_information_class: 0x14,
        buffer_length: eof.len() as u32,
        buffer_offset: 64 + 32,
        reserved: 0,
        additional_information: 0,
        file_id: second.file_id,
        buffer: eof,
    };
    let mut body = Vec::new();
    req.write_to(&mut body).expect("write eof set-info");
    let hdr = build_header(Command::SetInfo, 7, session2, tree2);
    write_frame(&mut s2, &hdr, &body).await;

    let level_none_break = read_frame_with_timeout(&mut s1).await;
    let (break_hdr, break_body) = parse_response_header(&level_none_break);
    assert_eq!(break_hdr.command, Command::OplockBreak);
    assert_eq!(break_hdr.channel_sequence_status, STATUS_SUCCESS);
    let notification = OplockBreakAck::parse(break_body).expect("parse level-II break");
    assert_eq!(notification.oplock_level, 0);
    assert_eq!(notification.file_id, first.file_id);

    let set_info = read_frame_with_timeout(&mut s2).await;
    let (set_info_hdr, set_info_body) = parse_response_header(&set_info);
    assert_eq!(set_info_hdr.command, Command::SetInfo);
    assert_eq!(set_info_hdr.channel_sequence_status, STATUS_SUCCESS);
    let _ = SetInfoResponse::parse(set_info_body).expect("parse set-info response");

    close(&mut s2, session2, tree2, 8, second.file_id).await;
    close(&mut s1, session1, tree1, 9, first.file_id).await;
    drop(s2);
    drop(s1);
    handle.abort();
}

#[tokio::test]
async fn resumed_batch_open_rename_respects_parent_delete_access() {
    let (handle, root, mut s, session_id, tree_id) = setup_lock_server_with_path_smb311().await;
    std::fs::write(root.join("docs/source.txt"), b"source").expect("seed source");

    let parent = create_named_open(
        &mut s,
        session_id,
        tree_id,
        4,
        "docs",
        0x001f_01ff,
        0x0000_0007,
        1,
        0x0000_0001,
        0,
    )
    .await;

    let first = create_named_open(
        &mut s,
        session_id,
        tree_id,
        5,
        "docs/source.txt",
        0x001f_01ff,
        0x0000_0007,
        1,
        0x0000_0040,
        0x09,
    )
    .await;
    assert_eq!(first.oplock_level, 0x09);

    send_create_named_open(
        &mut s,
        session_id,
        tree_id,
        6,
        "docs/source.txt",
        0x001f_01ff,
        0x0000_0007,
        1,
        0x0000_0040,
        0x09,
    )
    .await;

    let frames = [read_frame(&mut s).await, read_frame(&mut s).await];
    let mut pending_async_id = None;
    let mut notification = None;
    for frame in frames {
        let (rh, rb) = parse_response_header(&frame);
        match rh.command {
            Command::Create => {
                assert_eq!(rh.channel_sequence_status, STATUS_PENDING);
                pending_async_id = Some(rh.async_id().expect("pending create async id"));
            }
            Command::OplockBreak => {
                assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
                notification = Some(OplockBreakAck::parse(rb).expect("parse oplock break"));
            }
            other => panic!("unexpected response command {other:?}"),
        }
    }
    let pending_async_id = pending_async_id.expect("missing pending create");
    let notification = notification.expect("missing oplock break notification");
    assert_eq!(notification.oplock_level, 0x01);
    assert_eq!(notification.file_id, first.file_id);

    let ack = OplockBreakAck {
        structure_size: 24,
        oplock_level: 0x01,
        reserved: 0,
        reserved2: 0,
        file_id: first.file_id,
    };
    let mut body = Vec::new();
    ack.write_to(&mut body).expect("write oplock break ack");
    let hdr = build_header(Command::OplockBreak, 7, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;

    let frames = [read_frame(&mut s).await, read_frame(&mut s).await];
    let mut ack_seen = false;
    let mut second = None;
    for frame in frames {
        let (rh, rb) = parse_response_header(&frame);
        match rh.command {
            Command::OplockBreak => {
                assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
                let ack = OplockBreakAck::parse(rb).expect("parse oplock break ack response");
                assert_eq!(ack.oplock_level, 0x01);
                assert_eq!(ack.file_id, first.file_id);
                ack_seen = true;
            }
            Command::Create => {
                assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
                assert_eq!(rh.async_id(), Some(pending_async_id));
                second = Some(CreateResponse::parse(rb).expect("parse final create"));
            }
            other => panic!("unexpected post-ack response command {other:?}"),
        }
    }
    assert!(ack_seen, "missing oplock break ack response");
    let second = second.expect("missing final create response");

    let rename = file_rename_information("docs/renamed.txt", false);
    let req = SetInfoRequest {
        structure_size: 33,
        info_type: InfoType::File as u8,
        file_information_class: 0x0A,
        buffer_length: rename.len() as u32,
        buffer_offset: 64 + 32,
        reserved: 0,
        additional_information: 0,
        file_id: second.file_id,
        buffer: rename,
    };
    let mut body = Vec::new();
    req.write_to(&mut body)
        .expect("write set-info rename after batch open");
    let hdr = build_header(Command::SetInfo, 8, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, _) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::SetInfo);
    assert_eq!(rh.channel_sequence_status, STATUS_SHARING_VIOLATION);
    assert!(root.join("docs/source.txt").exists());
    assert!(!root.join("docs/renamed.txt").exists());

    close(&mut s, session_id, tree_id, 9, second.file_id).await;
    close(&mut s, session_id, tree_id, 10, first.file_id).await;
    close(&mut s, session_id, tree_id, 11, parent.file_id).await;
    drop(s);
    handle.abort();
}

#[tokio::test]
async fn smbtorture_force_unacked_timeout_root_ioctl_succeeds() {
    let (handle, mut s, _session_id, _tree_id) = setup_lock_server_smb311().await;

    force_unacked_timeout(&mut s, 4).await;

    drop(s);
    handle.abort();
}

#[tokio::test]
async fn batch_oplock_create_resumes_after_normal_timeout_without_ack() {
    let (handle, _addr, mut s, session_id, tree_id) =
        setup_lock_server_with_addr_smb311_and_cache_break_timeout(Duration::from_millis(20)).await;

    let first = create_oplock_open(&mut s, session_id, tree_id, 4, 0x09, 0x001f_01ff).await;
    assert_eq!(first.oplock_level, 0x09);

    send_create_oplock_open(&mut s, session_id, tree_id, 5, 0x09, 0x001f_01ff).await;

    let frames = [
        read_frame_with_timeout(&mut s).await,
        read_frame_with_timeout(&mut s).await,
    ];
    let mut pending_async_id = None;
    let mut notification = None;
    for frame in frames {
        let (rh, rb) = parse_response_header(&frame);
        match rh.command {
            Command::Create => {
                assert_eq!(rh.channel_sequence_status, STATUS_PENDING);
                pending_async_id = Some(rh.async_id().expect("pending create async id"));
            }
            Command::OplockBreak => {
                assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
                notification = Some(OplockBreakAck::parse(rb).expect("parse oplock break"));
            }
            other => panic!("unexpected response command {other:?}"),
        }
    }
    let pending_async_id = pending_async_id.expect("missing pending create");
    let notification = notification.expect("missing oplock break notification");
    assert_eq!(notification.oplock_level, 0x01);
    assert_eq!(notification.file_id, first.file_id);

    let final_frame = read_frame_with_timeout(&mut s).await;
    let (final_hdr, final_body) = parse_response_header(&final_frame);
    assert_eq!(final_hdr.command, Command::Create);
    assert_eq!(final_hdr.channel_sequence_status, STATUS_SUCCESS);
    assert_eq!(final_hdr.async_id(), Some(pending_async_id));
    let second = CreateResponse::parse(final_body).expect("parse timeout final create");
    assert_eq!(second.oplock_level, 0x01);

    close(&mut s, session_id, tree_id, 6, second.file_id).await;
    close(&mut s, session_id, tree_id, 7, first.file_id).await;
    drop(s);
    handle.abort();
}

#[tokio::test]
async fn smbtorture_force_unacked_timeout_cleans_batch_handle_and_resumes_create() {
    let (handle, addr, mut s1, session1, tree1) =
        setup_lock_server_with_addr_smb311_and_cache_break_timeout(Duration::from_secs(3600)).await;
    let mut s2 = TcpStream::connect(addr).await.expect("connect second");
    let _ = negotiate_smb311(&mut s2).await;
    let session2 = anonymous_session_setup(&mut s2).await;
    let tree2 = tree_connect(&mut s2, "\\\\127.0.0.1\\share", session2, 3).await;

    let first = create_oplock_open(&mut s1, session1, tree1, 4, 0x09, 0x001f_01ff).await;
    assert_eq!(first.oplock_level, 0x09);
    force_unacked_timeout(&mut s1, 5).await;

    send_create_oplock_open(&mut s2, session2, tree2, 6, 0x09, 0x001f_01ff).await;

    let pending_frame = read_frame_with_timeout(&mut s2).await;
    let (pending_hdr, _) = parse_response_header(&pending_frame);
    assert_eq!(pending_hdr.command, Command::Create);
    assert_eq!(pending_hdr.channel_sequence_status, STATUS_PENDING);
    let pending_async_id = pending_hdr.async_id().expect("pending create async id");

    let notification_frame = read_frame_with_timeout(&mut s1).await;
    let (notify_hdr, notify_body) = parse_response_header(&notification_frame);
    assert_eq!(notify_hdr.command, Command::OplockBreak);
    assert_eq!(notify_hdr.channel_sequence_status, STATUS_SUCCESS);
    let notification = OplockBreakAck::parse(notify_body).expect("parse oplock break");
    assert_eq!(notification.oplock_level, 0x01);
    assert_eq!(notification.file_id, first.file_id);

    let final_frame = read_frame_with_timeout(&mut s2).await;
    let (final_hdr, final_body) = parse_response_header(&final_frame);
    assert_eq!(final_hdr.command, Command::Create);
    assert_eq!(final_hdr.channel_sequence_status, STATUS_SUCCESS);
    assert_eq!(final_hdr.async_id(), Some(pending_async_id));
    let second = CreateResponse::parse(final_body).expect("parse forced final create");
    assert_eq!(second.oplock_level, 0x09);

    close_status(
        &mut s1,
        session1,
        tree1,
        7,
        first.file_id,
        STATUS_FILE_CLOSED,
    )
    .await;
    close(&mut s2, session2, tree2, 8, second.file_id).await;

    drop(s2);
    drop(s1);
    handle.abort();
}

#[tokio::test]
async fn share_conflict_breaks_batch_oplock_to_level_ii_before_final_status() {
    let (handle, mut s, session_id, tree_id) = setup_lock_server_smb311().await;

    let name = utf16le("hello.txt");
    let first_req = CreateRequest {
        structure_size: 57,
        security_flags: 0,
        requested_oplock_level: 0x09,
        impersonation_level: 2,
        smb_create_flags: 0,
        reserved: 0,
        desired_access: 0x001f_01ff,
        file_attributes: 0,
        share_access: 0,
        create_disposition: 1,
        create_options: 0,
        name_offset: 0x78,
        name_length: name.len() as u16,
        create_contexts_offset: 0,
        create_contexts_length: 0,
        name,
        create_contexts: vec![],
    };
    let mut body = Vec::new();
    first_req.write_to(&mut body).expect("write batch create");
    let hdr = build_header(Command::Create, 4, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Create);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let first = CreateResponse::parse(rb).expect("parse batch create");
    assert_eq!(first.oplock_level, 0x09);

    let name = utf16le("hello.txt");
    let delete_req = CreateRequest {
        structure_size: 57,
        security_flags: 0,
        requested_oplock_level: 0,
        impersonation_level: 2,
        smb_create_flags: 0,
        reserved: 0,
        desired_access: 0x0001_0000,
        file_attributes: 0,
        share_access: 0x0000_0007,
        create_disposition: 1,
        create_options: 0x0000_1040,
        name_offset: 0x78,
        name_length: name.len() as u16,
        create_contexts_offset: 0,
        create_contexts_length: 0,
        name,
        create_contexts: vec![],
    };
    let mut body = Vec::new();
    delete_req
        .write_to(&mut body)
        .expect("write conflicting delete create");
    let hdr = build_header(Command::Create, 5, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;

    let frames = [read_frame(&mut s).await, read_frame(&mut s).await];
    let mut pending_async_id = None;
    let mut notification = None;
    for frame in frames {
        let (rh, rb) = parse_response_header(&frame);
        match rh.command {
            Command::Create => {
                assert_eq!(rh.channel_sequence_status, STATUS_PENDING);
                pending_async_id = Some(rh.async_id().expect("pending create async id"));
            }
            Command::OplockBreak => {
                assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
                notification = Some(OplockBreakAck::parse(rb).expect("parse oplock break"));
            }
            other => panic!("unexpected response command {other:?}"),
        }
    }
    let pending_async_id = pending_async_id.expect("missing pending create");
    let notification = notification.expect("missing oplock break notification");
    assert_eq!(notification.oplock_level, 0x01);
    assert_eq!(notification.file_id, first.file_id);

    let ack = OplockBreakAck {
        structure_size: 24,
        oplock_level: 0x01,
        reserved: 0,
        reserved2: 0,
        file_id: first.file_id,
    };
    let mut body = Vec::new();
    ack.write_to(&mut body).expect("write oplock break ack");
    let hdr = build_header(Command::OplockBreak, 6, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;

    let frames = [read_frame(&mut s).await, read_frame(&mut s).await];
    let mut saw_ack = false;
    let mut saw_final = false;
    for frame in frames {
        let (rh, rb) = parse_response_header(&frame);
        match rh.command {
            Command::OplockBreak => {
                assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
                let ack = OplockBreakAck::parse(rb).expect("parse oplock break response");
                assert_eq!(ack.oplock_level, 0x01);
                assert_eq!(ack.file_id, first.file_id);
                saw_ack = true;
            }
            Command::Create => {
                assert_eq!(rh.async_id(), Some(pending_async_id));
                assert_eq!(rh.channel_sequence_status, STATUS_SHARING_VIOLATION);
                saw_final = true;
            }
            other => panic!("unexpected post-ack response command {other:?}"),
        }
    }
    assert!(saw_ack, "missing oplock break ack response");
    assert!(saw_final, "missing final create response");

    let name = utf16le("hello.txt");
    let retry_req = CreateRequest {
        structure_size: 57,
        security_flags: 0,
        requested_oplock_level: 0,
        impersonation_level: 2,
        smb_create_flags: 0,
        reserved: 0,
        desired_access: 0x0001_0000,
        file_attributes: 0,
        share_access: 0x0000_0007,
        create_disposition: 1,
        create_options: 0x0000_1040,
        name_offset: 0x78,
        name_length: name.len() as u16,
        create_contexts_offset: 0,
        create_contexts_length: 0,
        name,
        create_contexts: vec![],
    };
    let mut body = Vec::new();
    retry_req
        .write_to(&mut body)
        .expect("write retry conflicting create");
    let hdr = build_header(Command::Create, 7, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, _) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Create);
    assert_eq!(rh.channel_sequence_status, STATUS_SHARING_VIOLATION);
    assert_no_frame(&mut s).await;

    close(&mut s, session_id, tree_id, 8, first.file_id).await;
    drop(s);
    handle.abort();
}

#[tokio::test]
async fn share_conflict_pending_create_succeeds_when_batch_oplock_handle_closes() {
    let (handle, mut s, session_id, tree_id) = setup_lock_server_smb311().await;

    let name = utf16le("hello.txt");
    let first_req = CreateRequest {
        structure_size: 57,
        security_flags: 0,
        requested_oplock_level: 0x09,
        impersonation_level: 2,
        smb_create_flags: 0,
        reserved: 0,
        desired_access: 0x001f_01ff,
        file_attributes: 0,
        share_access: 0,
        create_disposition: 1,
        create_options: 0,
        name_offset: 0x78,
        name_length: name.len() as u16,
        create_contexts_offset: 0,
        create_contexts_length: 0,
        name,
        create_contexts: vec![],
    };
    let mut body = Vec::new();
    first_req
        .write_to(&mut body)
        .expect("write first batch create");
    let hdr = build_header(Command::Create, 4, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Create);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let first = CreateResponse::parse(rb).expect("parse first batch create");
    assert_eq!(first.oplock_level, 0x09);

    let name = utf16le("hello.txt");
    let second_req = CreateRequest {
        structure_size: 57,
        security_flags: 0,
        requested_oplock_level: 0x09,
        impersonation_level: 2,
        smb_create_flags: 0,
        reserved: 0,
        desired_access: 0x001f_01ff,
        file_attributes: 0,
        share_access: 0,
        create_disposition: 1,
        create_options: 0,
        name_offset: 0x78,
        name_length: name.len() as u16,
        create_contexts_offset: 0,
        create_contexts_length: 0,
        name,
        create_contexts: vec![],
    };
    let mut body = Vec::new();
    second_req
        .write_to(&mut body)
        .expect("write second batch create");
    let hdr = build_header(Command::Create, 5, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;

    let frames = [read_frame(&mut s).await, read_frame(&mut s).await];
    let mut pending_async_id = None;
    let mut notification = None;
    for frame in frames {
        let (rh, rb) = parse_response_header(&frame);
        match rh.command {
            Command::Create => {
                assert_eq!(rh.channel_sequence_status, STATUS_PENDING);
                pending_async_id = Some(rh.async_id().expect("pending create async id"));
            }
            Command::OplockBreak => {
                assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
                notification = Some(OplockBreakAck::parse(rb).expect("parse oplock break"));
            }
            other => panic!("unexpected response command {other:?}"),
        }
    }
    let pending_async_id = pending_async_id.expect("missing pending create");
    let notification = notification.expect("missing oplock break notification");
    assert_eq!(notification.oplock_level, 0x01);
    assert_eq!(notification.file_id, first.file_id);

    let close_req = CloseRequest {
        structure_size: 24,
        flags: 0,
        reserved: 0,
        file_id: first.file_id,
    };
    let mut body = Vec::new();
    close_req.write_to(&mut body).expect("write close");
    let hdr = build_header(Command::Close, 6, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;

    let frames = [read_frame(&mut s).await, read_frame(&mut s).await];
    let mut saw_close = false;
    let mut second = None;
    for frame in frames {
        let (rh, rb) = parse_response_header(&frame);
        match rh.command {
            Command::Close => {
                assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
                let _ = CloseResponse::parse(rb).expect("parse close");
                saw_close = true;
            }
            Command::Create => {
                assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
                assert_eq!(rh.async_id(), Some(pending_async_id));
                let create = CreateResponse::parse(rb).expect("parse resumed create");
                assert_eq!(create.oplock_level, 0x09);
                second = Some(create);
            }
            other => panic!("unexpected post-close response command {other:?}"),
        }
    }
    assert!(saw_close, "missing close response");
    let second = second.expect("missing final create response");

    close(&mut s, session_id, tree_id, 7, second.file_id).await;
    drop(s);
    handle.abort();
}

#[tokio::test]
async fn share_conflict_delete_on_close_succeeds_when_batch_oplock_handle_closes() {
    let (handle, root, mut s, session_id, tree_id) = setup_lock_server_with_path_smb311().await;

    let name = utf16le("hello.txt");
    let first_req = CreateRequest {
        structure_size: 57,
        security_flags: 0,
        requested_oplock_level: 0x09,
        impersonation_level: 2,
        smb_create_flags: 0,
        reserved: 0,
        desired_access: 0x001f_01ff,
        file_attributes: 0,
        share_access: 0,
        create_disposition: 1,
        create_options: 0,
        name_offset: 0x78,
        name_length: name.len() as u16,
        create_contexts_offset: 0,
        create_contexts_length: 0,
        name,
        create_contexts: vec![],
    };
    let mut body = Vec::new();
    first_req
        .write_to(&mut body)
        .expect("write first batch create");
    let hdr = build_header(Command::Create, 4, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Create);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let first = CreateResponse::parse(rb).expect("parse first batch create");
    assert_eq!(first.oplock_level, 0x09);

    let name = utf16le("hello.txt");
    let delete_req = CreateRequest {
        structure_size: 57,
        security_flags: 0,
        requested_oplock_level: 0,
        impersonation_level: 2,
        smb_create_flags: 0,
        reserved: 0,
        desired_access: 0x0001_0000,
        file_attributes: 0,
        share_access: 0x0000_0007,
        create_disposition: 1,
        create_options: 0x0000_1040,
        name_offset: 0x78,
        name_length: name.len() as u16,
        create_contexts_offset: 0,
        create_contexts_length: 0,
        name,
        create_contexts: vec![],
    };
    let mut body = Vec::new();
    delete_req
        .write_to(&mut body)
        .expect("write pending delete-on-close create");
    let hdr = build_header(Command::Create, 5, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;

    let frames = [read_frame(&mut s).await, read_frame(&mut s).await];
    let mut pending_async_id = None;
    let mut notification = None;
    for frame in frames {
        let (rh, rb) = parse_response_header(&frame);
        match rh.command {
            Command::Create => {
                assert_eq!(rh.channel_sequence_status, STATUS_PENDING);
                pending_async_id = Some(rh.async_id().expect("pending create async id"));
            }
            Command::OplockBreak => {
                assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
                notification = Some(OplockBreakAck::parse(rb).expect("parse oplock break"));
            }
            other => panic!("unexpected response command {other:?}"),
        }
    }
    let pending_async_id = pending_async_id.expect("missing pending create");
    let notification = notification.expect("missing oplock break notification");
    assert_eq!(notification.oplock_level, 0x01);
    assert_eq!(notification.file_id, first.file_id);

    let close_req = CloseRequest {
        structure_size: 24,
        flags: 0,
        reserved: 0,
        file_id: first.file_id,
    };
    let mut body = Vec::new();
    close_req.write_to(&mut body).expect("write close");
    let hdr = build_header(Command::Close, 6, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;

    let frames = [read_frame(&mut s).await, read_frame(&mut s).await];
    let mut saw_close = false;
    let mut delete_file_id = None;
    for frame in frames {
        let (rh, rb) = parse_response_header(&frame);
        match rh.command {
            Command::Close => {
                assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
                let _ = CloseResponse::parse(rb).expect("parse close");
                saw_close = true;
            }
            Command::Create => {
                assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
                assert_eq!(rh.async_id(), Some(pending_async_id));
                let create = CreateResponse::parse(rb).expect("parse resumed create");
                delete_file_id = Some(create.file_id);
            }
            other => panic!("unexpected post-close response command {other:?}"),
        }
    }
    assert!(saw_close, "missing close response");
    let delete_file_id = delete_file_id.expect("missing final delete-on-close create response");

    close(&mut s, session_id, tree_id, 7, delete_file_id).await;
    assert!(
        std::fs::metadata(root.join("hello.txt")).is_err(),
        "delete-on-close file still exists after closing resumed create"
    );

    drop(s);
    handle.abort();
}

#[tokio::test]
async fn open_while_delete_on_close_handle_exists_returns_delete_pending_without_break() {
    let (handle, mut s, session_id, tree_id) = setup_lock_server_smb311().await;

    let first = create_oplock_open(&mut s, session_id, tree_id, 4, 0x09, 0x001f_01ff).await;
    assert_eq!(first.oplock_level, 0x09);

    let req = SetInfoRequest {
        structure_size: 33,
        info_type: InfoType::File as u8,
        file_information_class: 0x0D,
        buffer_length: 1,
        buffer_offset: 64 + 32,
        reserved: 0,
        additional_information: 0,
        file_id: first.file_id,
        buffer: vec![1],
    };
    let mut body = Vec::new();
    req.write_to(&mut body).expect("write set-info disposition");
    let hdr = build_header(Command::SetInfo, 5, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, _) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::SetInfo);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);

    let name = utf16le("hello.txt");
    let req = CreateRequest {
        structure_size: 57,
        security_flags: 0,
        requested_oplock_level: 0x09,
        impersonation_level: 2,
        smb_create_flags: 0,
        reserved: 0,
        desired_access: 0x0000_0001,
        file_attributes: 0,
        share_access: 0x0000_0007,
        create_disposition: 1,
        create_options: 0x0000_0040,
        name_offset: 0x78,
        name_length: name.len() as u16,
        create_contexts_offset: 0,
        create_contexts_length: 0,
        name,
        create_contexts: vec![],
    };
    let mut body = Vec::new();
    req.write_to(&mut body)
        .expect("write create against delete-pending file");
    let hdr = build_header(Command::Create, 6, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, _) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Create);
    assert_eq!(rh.channel_sequence_status, STATUS_DELETE_PENDING);
    assert_no_frame(&mut s).await;

    close(&mut s, session_id, tree_id, 7, first.file_id).await;
    drop(s);
    handle.abort();
}

#[tokio::test]
async fn attribute_only_open_if_after_exclusive_or_batch_gets_no_oplock_without_break() {
    for requested_oplock_level in [0x08, 0x09] {
        let (handle, mut s, session_id, tree_id) = setup_lock_server_smb311().await;

        let name = utf16le("hello.txt");
        let first_req = CreateRequest {
            structure_size: 57,
            security_flags: 0,
            requested_oplock_level,
            impersonation_level: 2,
            smb_create_flags: 0,
            reserved: 0,
            desired_access: 0x001f_01ff,
            file_attributes: 0,
            share_access: 0,
            create_disposition: 1,
            create_options: 0,
            name_offset: 0x78,
            name_length: name.len() as u16,
            create_contexts_offset: 0,
            create_contexts_length: 0,
            name,
            create_contexts: vec![],
        };
        let mut body = Vec::new();
        first_req
            .write_to(&mut body)
            .expect("write first oplock create");
        let hdr = build_header(Command::Create, 4, session_id, tree_id);
        write_frame(&mut s, &hdr, &body).await;
        let resp = read_frame(&mut s).await;
        let (rh, rb) = parse_response_header(&resp);
        assert_eq!(rh.command, Command::Create);
        assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
        let first = CreateResponse::parse(rb).expect("parse first oplock create");
        assert_eq!(first.oplock_level, requested_oplock_level);

        let name = utf16le("hello.txt");
        let attr_req = CreateRequest {
            structure_size: 57,
            security_flags: 0,
            requested_oplock_level,
            impersonation_level: 2,
            smb_create_flags: 0,
            reserved: 0,
            desired_access: 0x0010_0180,
            file_attributes: 0,
            share_access: 0,
            create_disposition: 3,
            create_options: 0x0000_0040,
            name_offset: 0x78,
            name_length: name.len() as u16,
            create_contexts_offset: 0,
            create_contexts_length: 0,
            name,
            create_contexts: vec![],
        };
        let mut body = Vec::new();
        attr_req
            .write_to(&mut body)
            .expect("write attribute-only open-if");
        let hdr = build_header(Command::Create, 5, session_id, tree_id);
        write_frame(&mut s, &hdr, &body).await;
        let resp = read_frame(&mut s).await;
        let (rh, rb) = parse_response_header(&resp);
        assert_eq!(rh.command, Command::Create);
        assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
        let attr = CreateResponse::parse(rb).expect("parse attribute-only create");
        assert_eq!(attr.oplock_level, 0);
        assert_no_frame(&mut s).await;

        close(&mut s, session_id, tree_id, 6, attr.file_id).await;
        close(&mut s, session_id, tree_id, 7, first.file_id).await;
        drop(s);
        handle.abort();
    }
}

#[tokio::test]
async fn attribute_only_overwrite_after_batch_break_gets_level_ii() {
    for create_disposition in [0, 4, 5] {
        let (handle, mut s, session_id, tree_id) = setup_lock_server_smb311().await;

        let first = create_oplock_open(&mut s, session_id, tree_id, 4, 0x09, 0x001f_01ff).await;
        assert_eq!(first.oplock_level, 0x09);

        let name = utf16le("hello.txt");
        let attr_req = CreateRequest {
            structure_size: 57,
            security_flags: 0,
            requested_oplock_level: 0x09,
            impersonation_level: 2,
            smb_create_flags: 0,
            reserved: 0,
            desired_access: 0x0010_0180,
            file_attributes: 0,
            share_access: 0x0000_0007,
            create_disposition,
            create_options: 0x0000_0040,
            name_offset: 0x78,
            name_length: name.len() as u16,
            create_contexts_offset: 0,
            create_contexts_length: 0,
            name,
            create_contexts: vec![],
        };
        let mut body = Vec::new();
        attr_req
            .write_to(&mut body)
            .expect("write attribute-only overwrite");
        let hdr = build_header(Command::Create, 5, session_id, tree_id);
        write_frame(&mut s, &hdr, &body).await;

        let frames = [read_frame(&mut s).await, read_frame(&mut s).await];
        let mut pending_async_id = None;
        let mut notification = None;
        for frame in frames {
            let (rh, rb) = parse_response_header(&frame);
            match rh.command {
                Command::Create => {
                    assert_eq!(rh.channel_sequence_status, STATUS_PENDING);
                    pending_async_id = Some(rh.async_id().expect("pending create async id"));
                }
                Command::OplockBreak => {
                    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
                    notification = Some(OplockBreakAck::parse(rb).expect("parse oplock break"));
                }
                other => panic!("unexpected response command {other:?}"),
            }
        }
        let pending_async_id = pending_async_id.expect("missing pending create");
        let notification = notification.expect("missing oplock break notification");
        assert_eq!(notification.oplock_level, 0);
        assert_eq!(notification.file_id, first.file_id);

        let ack = OplockBreakAck {
            structure_size: 24,
            oplock_level: 0,
            reserved: 0,
            reserved2: 0,
            file_id: first.file_id,
        };
        let mut body = Vec::new();
        ack.write_to(&mut body).expect("write oplock break ack");
        let hdr = build_header(Command::OplockBreak, 6, session_id, tree_id);
        write_frame(&mut s, &hdr, &body).await;

        let frames = [read_frame(&mut s).await, read_frame(&mut s).await];
        let mut saw_ack = false;
        let mut attr = None;
        for frame in frames {
            let (rh, rb) = parse_response_header(&frame);
            match rh.command {
                Command::OplockBreak => {
                    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
                    saw_ack = true;
                }
                Command::Create => {
                    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
                    assert_eq!(rh.async_id(), Some(pending_async_id));
                    attr = Some(CreateResponse::parse(rb).expect("parse resumed create"));
                }
                other => panic!("unexpected post-ack response command {other:?}"),
            }
        }
        assert!(saw_ack, "missing oplock ack response");
        let attr = attr.expect("missing final create response");
        assert_eq!(attr.oplock_level, 0x01);

        close(&mut s, session_id, tree_id, 7, first.file_id).await;
        close(&mut s, session_id, tree_id, 8, attr.file_id).await;
        drop(s);
        handle.abort();
    }
}

#[tokio::test]
async fn level_ii_oplock_granted_with_broad_access_alongside_read_lease() {
    let (handle, mut s, session_id, tree_id) = setup_lock_server_smb311().await;

    let (leased, lease_grant) = create_lease_open_with_lease_data(
        &mut s,
        session_id,
        tree_id,
        4,
        0x001f_01ff,
        lease_v1_request_with_key(0x0000_0001, b"lease-key-123456"),
    )
    .await;
    assert_eq!(lease_grant.response_len, 32);
    assert_eq!(lease_grant.state, 0x0000_0001);

    let level_ii = create_oplock_open(&mut s, session_id, tree_id, 5, 0x01, 0x001f_01ff).await;
    assert_eq!(level_ii.oplock_level, 0x01);
    assert_no_frame(&mut s).await;

    close(&mut s, session_id, tree_id, 6, level_ii.file_id).await;
    close(&mut s, session_id, tree_id, 7, leased.file_id).await;
    drop(s);
    handle.abort();
}

#[tokio::test]
async fn level_ii_oplock_denied_alongside_handle_caching_lease() {
    const LEASE_READ: u32 = 0x0000_0001;
    const LEASE_HANDLE: u32 = 0x0000_0002;

    let (handle, mut s, session_id, tree_id) = setup_lock_server_smb311().await;

    let (leased, lease_grant) = create_lease_open_with_lease_data(
        &mut s,
        session_id,
        tree_id,
        4,
        0x001f_01ff,
        lease_v1_request_with_key(LEASE_READ | LEASE_HANDLE, b"lease-key-123456"),
    )
    .await;
    assert_eq!(lease_grant.response_len, 32);
    assert_eq!(lease_grant.state, LEASE_READ | LEASE_HANDLE);

    for (idx, requested_oplock) in [0x01, 0x08, 0x09].into_iter().enumerate() {
        let opened = create_oplock_open(
            &mut s,
            session_id,
            tree_id,
            5 + (idx as u64 * 2),
            requested_oplock,
            0x001f_01ff,
        )
        .await;
        assert_eq!(opened.oplock_level, 0);
        assert_no_frame(&mut s).await;
        close(
            &mut s,
            session_id,
            tree_id,
            6 + (idx as u64 * 2),
            opened.file_id,
        )
        .await;
    }

    close(&mut s, session_id, tree_id, 12, leased.file_id).await;
    drop(s);
    handle.abort();
}

#[tokio::test]
async fn different_lease_keys_can_both_get_read_handle_caching() {
    const LEASE_READ: u32 = 0x0000_0001;
    const LEASE_HANDLE: u32 = 0x0000_0002;

    let (handle, mut s, session_id, tree_id) = setup_lock_server_smb311().await;

    let (first, first_grant) = create_lease_open_with_lease_data(
        &mut s,
        session_id,
        tree_id,
        4,
        0x001f_01ff,
        lease_v1_request_with_key(LEASE_READ | LEASE_HANDLE, b"lease-key-123456"),
    )
    .await;
    assert_eq!(first_grant.state, LEASE_READ | LEASE_HANDLE);

    let (second, second_grant) = create_lease_open_with_lease_data(
        &mut s,
        session_id,
        tree_id,
        5,
        0x001f_01ff,
        lease_v1_request_with_key(LEASE_READ | LEASE_HANDLE, b"other-key-123456"),
    )
    .await;
    assert_eq!(second_grant.state, LEASE_READ | LEASE_HANDLE);
    assert_no_frame(&mut s).await;

    close(&mut s, session_id, tree_id, 6, second.file_id).await;
    close(&mut s, session_id, tree_id, 7, first.file_id).await;
    drop(s);
    handle.abort();
}

#[tokio::test]
async fn create_lease_request_returns_none_for_lease_without_read_caching() {
    let (handle, mut s, session_id, tree_id) = setup_lock_server_smb311().await;
    let (create, lease_state) = create_lease_open(
        &mut s,
        session_id,
        tree_id,
        4,
        0x0012_0089 | 0x0012_0116,
        0x0000_0002 | 0x0000_0004,
    )
    .await;

    assert_eq!(create.oplock_level, 0xff);
    assert_eq!(lease_state, 0);
    close(&mut s, session_id, tree_id, 5, create.file_id).await;

    drop(s);
    handle.abort();
}

#[tokio::test]
async fn lease_v2_none_due_to_byte_range_lock_preserves_requested_epoch() {
    let (handle, mut s, session_id, tree_id) = setup_lock_server_smb311().await;
    let owner = create_rw(&mut s, session_id, tree_id, 4).await;
    write(
        &mut s,
        session_id,
        tree_id,
        5,
        owner,
        0,
        b"x",
        STATUS_SUCCESS,
    )
    .await;
    lock(
        &mut s,
        session_id,
        tree_id,
        6,
        owner,
        0,
        1,
        LockElement::FLAG_EXCLUSIVE_LOCK | LockElement::FLAG_FAIL_IMMEDIATELY,
        STATUS_SUCCESS,
    )
    .await;

    let name = utf16le("hello.txt");
    let req = CreateRequest {
        structure_size: 57,
        security_flags: 0,
        requested_oplock_level: 0xff,
        impersonation_level: 2,
        smb_create_flags: 0,
        reserved: 0,
        desired_access: 0x001f_01ff,
        file_attributes: 0,
        share_access: 0x0000_0007,
        create_disposition: 3,
        create_options: 0,
        name_offset: 0x78,
        name_length: name.len() as u16,
        create_contexts_offset: 0,
        create_contexts_length: 0,
        name,
        create_contexts: vec![],
    };
    let body = create_request_with_contexts(
        req,
        &[
            CreateContext {
                name: CreateContext::NAME_RQLS.to_vec(),
                data: lease_v2_request_with_key_and_epoch(0x0000_0001, b"epoch-lock-key!!", 100),
            },
            CreateContext {
                name: CreateContext::NAME_DH2Q.to_vec(),
                data: durable_v2_request(0),
            },
        ],
    );
    let hdr = build_header(Command::Create, 7, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Create);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let create = CreateResponse::parse(rb).expect("parse lease none create");
    let grant = lease_grant_from_create(&create);
    assert_eq!(create.oplock_level, 0xff);
    assert_eq!(grant.state, 0);
    assert_eq!(grant.epoch, 100);

    close(&mut s, session_id, tree_id, 8, create.file_id).await;
    close(&mut s, session_id, tree_id, 9, owner).await;
    drop(s);
    handle.abort();
}

#[tokio::test]
async fn create_lease_request_grants_read_lease_for_write_only_access() {
    const GENERIC_WRITE: u32 = 0x4000_0000;

    let (handle, mut s, session_id, tree_id) = setup_lock_server_smb311().await;
    let (create, lease_state) =
        create_lease_open(&mut s, session_id, tree_id, 4, GENERIC_WRITE, 0x0000_0001).await;

    assert_eq!(create.oplock_level, 0xff);
    assert_eq!(lease_state, 0x0000_0001);
    close(&mut s, session_id, tree_id, 5, create.file_id).await;

    drop(s);
    handle.abort();
}

#[tokio::test]
async fn create_lease_request_is_not_granted_for_directory() {
    let (handle, mut s, session_id, tree_id) = setup_lock_server_smb311().await;
    let create = create_lease_directory_open(&mut s, session_id, tree_id, 4).await;

    assert_eq!(create.oplock_level, 0);
    close(&mut s, session_id, tree_id, 5, create.file_id).await;

    drop(s);
    handle.abort();
}

async fn setup_lock_server() -> (tokio::task::JoinHandle<()>, TcpStream, u64, u32) {
    let (handle, _addr, stream, session_id, tree_id) = setup_lock_server_with_addr().await;
    (handle, stream, session_id, tree_id)
}

async fn setup_lock_server_smb311() -> (tokio::task::JoinHandle<()>, TcpStream, u64, u32) {
    let (handle, _addr, stream, session_id, tree_id) = setup_lock_server_with_addr_smb311().await;
    (handle, stream, session_id, tree_id)
}

async fn setup_lock_server_smb311_with_durable_timeout(
    durable_handle_timeout: Duration,
) -> (tokio::task::JoinHandle<()>, TcpStream, u64, u32) {
    let (handle, _addr, stream, session_id, tree_id) =
        setup_lock_server_with_addr_smb311_and_durable_timeout(durable_handle_timeout).await;
    (handle, stream, session_id, tree_id)
}

async fn setup_lock_server_with_addr()
-> (tokio::task::JoinHandle<()>, SocketAddr, TcpStream, u64, u32) {
    setup_lock_server_with_addr_and_timeout(Duration::from_secs(300)).await
}

async fn setup_lock_server_with_addr_smb300()
-> (tokio::task::JoinHandle<()>, SocketAddr, TcpStream, u64, u32) {
    let td = tempdir().expect("tempdir");
    std::fs::write(td.path().join("hello.txt"), b"hello world").expect("seed file");
    let backend = LocalFsBackend::new(td.path()).expect("open root");
    let server = SmbServer::builder()
        .listen("127.0.0.1:0".parse().unwrap())
        .share(Share::new("share", backend).public())
        .netbios_name("TESTSERVER")
        .durable_handle_timeout(Duration::from_secs(300))
        .build()
        .expect("build");

    server.bind().await.expect("bind");
    let addr = server.local_addr().await.expect("addr");
    let handle = tokio::spawn(async move {
        let _ = server.serve().await;
        drop(td);
    });
    tokio::task::yield_now().await;

    let mut s = TcpStream::connect(addr).await.expect("connect");
    let _ = negotiate_smb300(&mut s).await;
    let session_id = anonymous_session_setup(&mut s).await;
    let tree_id = tree_connect(&mut s, "\\\\127.0.0.1\\share", session_id, 3).await;
    (handle, addr, s, session_id, tree_id)
}

async fn setup_lock_server_with_path() -> (tokio::task::JoinHandle<()>, PathBuf, TcpStream, u64, u32)
{
    let (handle, root, _addr, s, session_id, tree_id) =
        setup_lock_server_with_path_and_addr().await;
    (handle, root, s, session_id, tree_id)
}

async fn setup_lock_server_with_path_and_addr() -> (
    tokio::task::JoinHandle<()>,
    PathBuf,
    SocketAddr,
    TcpStream,
    u64,
    u32,
) {
    let td = tempdir().expect("tempdir");
    let root = td.path().to_path_buf();
    std::fs::write(td.path().join("hello.txt"), b"hello world").expect("seed file");
    let backend = LocalFsBackend::new(td.path()).expect("open root");
    let server = SmbServer::builder()
        .listen("127.0.0.1:0".parse().unwrap())
        .share(Share::new("share", backend).public())
        .netbios_name("TESTSERVER")
        .durable_handle_timeout(Duration::from_secs(300))
        .build()
        .expect("build");

    server.bind().await.expect("bind");
    let addr = server.local_addr().await.expect("addr");
    let handle = tokio::spawn(async move {
        let _ = server.serve().await;
        drop(td);
    });
    tokio::task::yield_now().await;

    let mut s = TcpStream::connect(addr).await.expect("connect");
    let _ = negotiate(&mut s).await;
    let session_id = anonymous_session_setup(&mut s).await;
    let tree_id = tree_connect(&mut s, "\\\\127.0.0.1\\share", session_id, 3).await;
    (handle, root, addr, s, session_id, tree_id)
}

async fn setup_lock_server_with_addr_smb311()
-> (tokio::task::JoinHandle<()>, SocketAddr, TcpStream, u64, u32) {
    setup_lock_server_with_addr_smb311_and_cache_break_timeout(Duration::from_secs(35)).await
}

async fn setup_lock_server_with_addr_smb311_and_cache_break_timeout(
    cache_break_timeout: Duration,
) -> (tokio::task::JoinHandle<()>, SocketAddr, TcpStream, u64, u32) {
    let td = tempdir().expect("tempdir");
    std::fs::write(td.path().join("hello.txt"), b"hello world").expect("seed file");
    std::fs::create_dir(td.path().join("docs")).expect("mkdir docs");
    let backend = LocalFsBackend::new(td.path()).expect("open root");
    let server = SmbServer::builder()
        .listen("127.0.0.1:0".parse().unwrap())
        .share(Share::new("share", backend).public())
        .netbios_name("TESTSERVER")
        .cache_break_timeout(cache_break_timeout)
        .build()
        .expect("build");

    server.bind().await.expect("bind");
    let addr = server.local_addr().await.expect("addr");
    let handle = tokio::spawn(async move {
        let _ = server.serve().await;
        drop(td);
    });
    tokio::task::yield_now().await;

    let mut s = TcpStream::connect(addr).await.expect("connect");
    let _ = negotiate_smb311(&mut s).await;
    let session_id = anonymous_session_setup(&mut s).await;
    let tree_id = tree_connect(&mut s, "\\\\127.0.0.1\\share", session_id, 3).await;
    (handle, addr, s, session_id, tree_id)
}

async fn setup_lock_server_with_addr_smb311_and_durable_timeout(
    durable_handle_timeout: Duration,
) -> (tokio::task::JoinHandle<()>, SocketAddr, TcpStream, u64, u32) {
    let td = tempdir().expect("tempdir");
    std::fs::write(td.path().join("hello.txt"), b"hello world").expect("seed file");
    std::fs::create_dir(td.path().join("docs")).expect("mkdir docs");
    let backend = LocalFsBackend::new(td.path()).expect("open root");
    let server = SmbServer::builder()
        .listen("127.0.0.1:0".parse().unwrap())
        .share(Share::new("share", backend).public())
        .netbios_name("TESTSERVER")
        .durable_handle_timeout(durable_handle_timeout)
        .build()
        .expect("build");

    server.bind().await.expect("bind");
    let addr = server.local_addr().await.expect("addr");
    let handle = tokio::spawn(async move {
        let _ = server.serve().await;
        drop(td);
    });
    tokio::task::yield_now().await;

    let mut s = TcpStream::connect(addr).await.expect("connect");
    let _ = negotiate_smb311(&mut s).await;
    let session_id = anonymous_session_setup(&mut s).await;
    let tree_id = tree_connect(&mut s, "\\\\127.0.0.1\\share", session_id, 3).await;
    (handle, addr, s, session_id, tree_id)
}

async fn setup_lock_server_with_path_smb311()
-> (tokio::task::JoinHandle<()>, PathBuf, TcpStream, u64, u32) {
    let (handle, root, _addr, stream, session_id, tree_id) =
        setup_lock_server_with_path_and_addr_smb311().await;
    (handle, root, stream, session_id, tree_id)
}

async fn setup_lock_server_with_path_and_addr_smb311() -> (
    tokio::task::JoinHandle<()>,
    PathBuf,
    SocketAddr,
    TcpStream,
    u64,
    u32,
) {
    let td = tempdir().expect("tempdir");
    let root = td.path().to_path_buf();
    std::fs::write(td.path().join("hello.txt"), b"hello world").expect("seed file");
    std::fs::create_dir(td.path().join("docs")).expect("mkdir docs");
    let backend = LocalFsBackend::new(td.path()).expect("open root");
    let server = SmbServer::builder()
        .listen("127.0.0.1:0".parse().unwrap())
        .share(Share::new("share", backend).public())
        .netbios_name("TESTSERVER")
        .build()
        .expect("build");

    server.bind().await.expect("bind");
    let addr = server.local_addr().await.expect("addr");
    let handle = tokio::spawn(async move {
        let _ = server.serve().await;
        drop(td);
    });
    tokio::task::yield_now().await;

    let mut s = TcpStream::connect(addr).await.expect("connect");
    let _ = negotiate_smb311(&mut s).await;
    let session_id = anonymous_session_setup(&mut s).await;
    let tree_id = tree_connect(&mut s, "\\\\127.0.0.1\\share", session_id, 3).await;
    (handle, root, addr, s, session_id, tree_id)
}

async fn read_frame_with_timeout(s: &mut TcpStream) -> Vec<u8> {
    tokio::time::timeout(Duration::from_secs(2), read_frame(s))
        .await
        .expect("timed out waiting for SMB response frame")
}

async fn assert_no_frame(s: &mut TcpStream) {
    let result = tokio::time::timeout(Duration::from_millis(50), read_frame(s)).await;
    assert!(result.is_err(), "unexpected SMB frame received");
}

async fn query_standard_delete_pending(
    s: &mut TcpStream,
    session_id: u64,
    tree_id: u32,
    message_id: u64,
    file_id: smb_server::wire::messages::FileId,
) -> bool {
    let req = QueryInfoRequest {
        structure_size: 41,
        info_type: InfoType::File as u8,
        file_information_class: 0x05,
        output_buffer_length: 24,
        input_buffer_offset: 0,
        reserved: 0,
        input_buffer_length: 0,
        additional_information: 0,
        flags: 0,
        file_id,
        input_buffer: vec![],
    };
    let mut body = Vec::new();
    req.write_to(&mut body).expect("write query info");
    let hdr = build_header(Command::QueryInfo, message_id, session_id, tree_id);
    write_frame(s, &hdr, &body).await;
    let resp = read_frame_with_timeout(s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::QueryInfo);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let query = QueryInfoResponse::parse(rb).expect("parse query info response");
    assert!(query.buffer.len() >= 21);
    query.buffer[20] != 0
}

async fn query_basic_info_status(
    s: &mut TcpStream,
    session_id: u64,
    tree_id: u32,
    message_id: u64,
    file_id: smb_server::wire::messages::FileId,
) -> u32 {
    let req = QueryInfoRequest {
        structure_size: 41,
        info_type: InfoType::File as u8,
        file_information_class: 0x04,
        output_buffer_length: 40,
        input_buffer_offset: 0,
        reserved: 0,
        input_buffer_length: 0,
        additional_information: 0,
        flags: 0,
        file_id,
        input_buffer: vec![],
    };
    let mut body = Vec::new();
    req.write_to(&mut body).expect("write query info");
    let hdr = build_header(Command::QueryInfo, message_id, session_id, tree_id);
    write_frame(s, &hdr, &body).await;
    let resp = read_frame_with_timeout(s).await;
    let (rh, _) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::QueryInfo);
    rh.channel_sequence_status
}

async fn setup_lock_server_with_addr_and_timeout(
    durable_handle_timeout: Duration,
) -> (tokio::task::JoinHandle<()>, SocketAddr, TcpStream, u64, u32) {
    let td = tempdir().expect("tempdir");
    std::fs::write(td.path().join("hello.txt"), b"hello world").expect("seed file");
    let backend = LocalFsBackend::new(td.path()).expect("open root");
    let server = SmbServer::builder()
        .listen("127.0.0.1:0".parse().unwrap())
        .share(Share::new("share", backend).public())
        .netbios_name("TESTSERVER")
        .durable_handle_timeout(durable_handle_timeout)
        .build()
        .expect("build");

    server.bind().await.expect("bind");
    let addr = server.local_addr().await.expect("addr");
    let handle = tokio::spawn(async move {
        let _ = server.serve().await;
        drop(td);
    });
    tokio::task::yield_now().await;

    let mut s = TcpStream::connect(addr).await.expect("connect");
    let _ = negotiate(&mut s).await;
    let session_id = anonymous_session_setup(&mut s).await;
    let tree_id = tree_connect(&mut s, "\\\\127.0.0.1\\share", session_id, 3).await;
    (handle, addr, s, session_id, tree_id)
}

async fn negotiate_smb300(s: &mut TcpStream) -> NegotiateResponse {
    let neg_req = NegotiateRequest {
        structure_size: 36,
        dialect_count: 1,
        security_mode: 0x0001,
        reserved: 0,
        capabilities: 0,
        client_guid: [0x30; 16],
        negotiate_context_offset_or_client_start_time: 0,
        dialects: vec![0x0300],
    };
    let mut body = Vec::new();
    neg_req.write_to(&mut body).expect("write negotiate");
    let hdr = build_header(Command::Negotiate, 0, 0, 0);
    write_frame(s, &hdr, &body).await;

    let resp = read_frame(s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Negotiate);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let neg_resp = NegotiateResponse::parse(rb).expect("parse neg resp");
    assert_eq!(neg_resp.dialect_revision, 0x0300);
    neg_resp
}

async fn negotiate_smb311(s: &mut TcpStream) -> NegotiateResponse {
    negotiate_smb311_with_client_guid(s, [0x31; 16]).await
}

async fn negotiate_smb311_with_client_guid(
    s: &mut TcpStream,
    client_guid: [u8; 16],
) -> NegotiateResponse {
    let preauth = PreauthIntegrityCapabilities {
        hash_algorithm_count: 1,
        salt_length: 0,
        hash_algorithms: vec![PreauthIntegrityCapabilities::HASH_SHA512],
        salt: vec![],
    };
    let mut preauth_data = std::io::Cursor::new(Vec::new());
    binrw::BinWrite::write(&preauth, &mut preauth_data).expect("write preauth");
    let contexts = [NegotiateContext {
        context_type: NegotiateContext::TYPE_PREAUTH_INTEGRITY,
        data_length: preauth_data.get_ref().len() as u16,
        reserved: 0,
        data: preauth_data.into_inner(),
    }];
    let mut contexts_bytes = Vec::new();
    NegotiateContext::encode_list(&contexts, &mut contexts_bytes).expect("encode contexts");
    let contexts_offset = 104u32;
    let neg_req = NegotiateRequest {
        structure_size: 36,
        dialect_count: 1,
        security_mode: 0x0001,
        reserved: 0,
        capabilities: 0,
        client_guid,
        negotiate_context_offset_or_client_start_time: u64::from(contexts_offset) | (1u64 << 32),
        dialects: vec![0x0311],
    };
    let mut body = Vec::new();
    neg_req.write_to(&mut body).expect("write negotiate");
    body.resize(contexts_offset as usize - 64, 0);
    body.extend_from_slice(&contexts_bytes);
    let hdr = build_header(Command::Negotiate, 0, 0, 0);
    write_frame(s, &hdr, &body).await;

    let resp = read_frame(s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Negotiate);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let neg_resp = NegotiateResponse::parse(rb).expect("parse neg resp");
    assert_eq!(neg_resp.dialect_revision, 0x0311);
    neg_resp
}

async fn create_rw(
    s: &mut TcpStream,
    session_id: u64,
    tree_id: u32,
    message_id: u64,
) -> smb_server::wire::messages::FileId {
    let name = utf16le("hello.txt");
    let req = CreateRequest {
        structure_size: 57,
        security_flags: 0,
        requested_oplock_level: 0,
        impersonation_level: 2,
        smb_create_flags: 0,
        reserved: 0,
        desired_access: 0x0012_0089 | 0x0012_0116,
        file_attributes: 0,
        share_access: 0x0000_0007,
        create_disposition: 1,
        create_options: 0,
        name_offset: 0x78,
        name_length: name.len() as u16,
        create_contexts_offset: 0,
        create_contexts_length: 0,
        name,
        create_contexts: vec![],
    };
    let mut body = Vec::new();
    req.write_to(&mut body).expect("write create");
    let hdr = build_header(Command::Create, message_id, session_id, tree_id);
    write_frame(s, &hdr, &body).await;
    let resp = read_frame(s).await;
    let (rh, rb) = parse_response_header(&resp);
    if rh.command == Command::Create {
        assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
        return CreateResponse::parse(rb).expect("parse create").file_id;
    }
    assert_eq!(rh.command, Command::OplockBreak);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let notification = OplockBreakAck::parse(rb).expect("parse oplock break notification");
    let pending_frame = read_frame(s).await;
    let (pending_hdr, _) = parse_response_header(&pending_frame);
    assert_eq!(pending_hdr.command, Command::Create);
    assert_eq!(pending_hdr.channel_sequence_status, STATUS_PENDING);
    let pending_async_id = pending_hdr.async_id().expect("pending create async id");

    let ack = OplockBreakAck {
        structure_size: 24,
        oplock_level: notification.oplock_level,
        reserved: 0,
        reserved2: 0,
        file_id: notification.file_id,
    };
    let mut ack_body = Vec::new();
    ack.write_to(&mut ack_body).expect("write oplock break ack");
    let ack_hdr = build_header(Command::OplockBreak, message_id + 1000, session_id, tree_id);
    write_frame(s, &ack_hdr, &ack_body).await;

    let frames = [read_frame(s).await, read_frame(s).await];
    let mut final_create = None;
    for frame in frames {
        let (rh, rb) = parse_response_header(&frame);
        match rh.command {
            Command::OplockBreak => assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS),
            Command::Create => {
                assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
                assert_eq!(rh.async_id(), Some(pending_async_id));
                final_create = Some(CreateResponse::parse(rb).expect("parse final create"));
            }
            other => panic!("unexpected post-oplock-break response command {other:?}"),
        }
    }
    final_create.expect("missing final create response").file_id
}

async fn create_oplock_open(
    s: &mut TcpStream,
    session_id: u64,
    tree_id: u32,
    message_id: u64,
    requested_oplock_level: u8,
    desired_access: u32,
) -> CreateResponse {
    send_create_oplock_open(
        s,
        session_id,
        tree_id,
        message_id,
        requested_oplock_level,
        desired_access,
    )
    .await;
    let resp = read_frame(s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Create);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    CreateResponse::parse(rb).expect("parse oplock create")
}

async fn create_named_open(
    s: &mut TcpStream,
    session_id: u64,
    tree_id: u32,
    message_id: u64,
    name: &str,
    desired_access: u32,
    share_access: u32,
    create_disposition: u32,
    create_options: u32,
    requested_oplock_level: u8,
) -> CreateResponse {
    send_create_named_open(
        s,
        session_id,
        tree_id,
        message_id,
        name,
        desired_access,
        share_access,
        create_disposition,
        create_options,
        requested_oplock_level,
    )
    .await;
    let resp = read_frame(s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Create);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    CreateResponse::parse(rb).expect("parse named create")
}

async fn send_create_named_open(
    s: &mut TcpStream,
    session_id: u64,
    tree_id: u32,
    message_id: u64,
    name: &str,
    desired_access: u32,
    share_access: u32,
    create_disposition: u32,
    create_options: u32,
    requested_oplock_level: u8,
) {
    let name = utf16le(name);
    let req = CreateRequest {
        structure_size: 57,
        security_flags: 0,
        requested_oplock_level,
        impersonation_level: 2,
        smb_create_flags: 0,
        reserved: 0,
        desired_access,
        file_attributes: 0,
        share_access,
        create_disposition,
        create_options,
        name_offset: 0x78,
        name_length: name.len() as u16,
        create_contexts_offset: 0,
        create_contexts_length: 0,
        name,
        create_contexts: vec![],
    };
    let mut body = Vec::new();
    req.write_to(&mut body).expect("write named create");
    let hdr = build_header(Command::Create, message_id, session_id, tree_id);
    write_frame(s, &hdr, &body).await;
}

async fn send_create_oplock_open(
    s: &mut TcpStream,
    session_id: u64,
    tree_id: u32,
    message_id: u64,
    requested_oplock_level: u8,
    desired_access: u32,
) {
    let name = utf16le("hello.txt");
    let req = CreateRequest {
        structure_size: 57,
        security_flags: 0,
        requested_oplock_level,
        impersonation_level: 2,
        smb_create_flags: 0,
        reserved: 0,
        desired_access,
        file_attributes: 0,
        share_access: 0x0000_0007,
        create_disposition: 1,
        create_options: 0,
        name_offset: 0x78,
        name_length: name.len() as u16,
        create_contexts_offset: 0,
        create_contexts_length: 0,
        name,
        create_contexts: vec![],
    };
    let mut body = Vec::new();
    req.write_to(&mut body).expect("write create");
    let hdr = build_header(Command::Create, message_id, session_id, tree_id);
    write_frame(s, &hdr, &body).await;
}

async fn create_durable_batch(
    s: &mut TcpStream,
    session_id: u64,
    tree_id: u32,
    message_id: u64,
) -> smb_server::wire::messages::FileId {
    let name = utf16le("hello.txt");
    let req = CreateRequest {
        structure_size: 57,
        security_flags: 0,
        requested_oplock_level: 0x09,
        impersonation_level: 2,
        smb_create_flags: 0,
        reserved: 0,
        desired_access: 0x0012_0089 | 0x0012_0116,
        file_attributes: 0,
        share_access: 0x0000_0007,
        create_disposition: 1,
        create_options: 0,
        name_offset: 0x78,
        name_length: name.len() as u16,
        create_contexts_offset: 0,
        create_contexts_length: 0,
        name,
        create_contexts: vec![],
    };
    let body = create_request_with_contexts(
        req,
        &[CreateContext {
            name: CreateContext::NAME_DHNQ.to_vec(),
            data: vec![0; 16],
        }],
    );
    let hdr = build_header(Command::Create, message_id, session_id, tree_id);
    write_frame(s, &hdr, &body).await;
    let resp =
        read_create_response_after_optional_oplock_break(s, session_id, tree_id, message_id).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Create);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let create = CreateResponse::parse(rb).expect("parse durable create");
    assert_eq!(create.oplock_level, 0x09);
    let contexts = CreateContext::parse_chain(&create.create_contexts).expect("parse contexts");
    let durable = contexts
        .iter()
        .find(|ctx| ctx.name == CreateContext::NAME_DHNQ.as_slice())
        .expect("missing durable response context");
    assert_eq!(durable.data.len(), 8);
    assert_eq!(
        u32::from_le_bytes(durable.data[0..4].try_into().unwrap()),
        0
    );
    assert_eq!(
        u32::from_le_bytes(durable.data[4..8].try_into().unwrap()),
        0
    );
    create.file_id
}

async fn create_durable_v2_batch(
    s: &mut TcpStream,
    session_id: u64,
    tree_id: u32,
    message_id: u64,
) -> smb_server::wire::messages::FileId {
    let name = utf16le("hello.txt");
    let req = CreateRequest {
        structure_size: 57,
        security_flags: 0,
        requested_oplock_level: 0x09,
        impersonation_level: 2,
        smb_create_flags: 0,
        reserved: 0,
        desired_access: 0x0012_0089,
        file_attributes: 0,
        share_access: 0x0000_0007,
        create_disposition: 1,
        create_options: 0,
        name_offset: 0x78,
        name_length: name.len() as u16,
        create_contexts_offset: 0,
        create_contexts_length: 0,
        name,
        create_contexts: vec![],
    };
    let body = create_request_with_contexts(
        req,
        &[CreateContext {
            name: CreateContext::NAME_DH2Q.to_vec(),
            data: durable_v2_request(0),
        }],
    );
    let hdr = build_header(Command::Create, message_id, session_id, tree_id);
    write_frame(s, &hdr, &body).await;
    let resp =
        read_create_response_after_optional_oplock_break(s, session_id, tree_id, message_id).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Create);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let create = CreateResponse::parse(rb).expect("parse durable v2 batch create");
    assert_eq!(create.oplock_level, 0x09);
    let contexts = CreateContext::parse_chain(&create.create_contexts).expect("parse contexts");
    let durable = contexts
        .iter()
        .find(|ctx| ctx.name == CreateContext::NAME_DH2Q.as_slice())
        .expect("missing durable v2 response context");
    assert_eq!(durable.data.len(), 8);
    assert_eq!(
        u32::from_le_bytes(durable.data[4..8].try_into().unwrap()),
        0
    );
    create.file_id
}

async fn create_durable_v2_batch_with_guid(
    s: &mut TcpStream,
    session_id: u64,
    tree_id: u32,
    message_id: u64,
    create_guid: &[u8; 16],
    replay: bool,
) -> CreateResponse {
    let name = utf16le("hello.txt");
    let req = CreateRequest {
        structure_size: 57,
        security_flags: 0,
        requested_oplock_level: 0x09,
        impersonation_level: 2,
        smb_create_flags: 0,
        reserved: 0,
        desired_access: 0x0012_0089,
        file_attributes: 0,
        share_access: 0x0000_0007,
        create_disposition: 1,
        create_options: 0,
        name_offset: 0x78,
        name_length: name.len() as u16,
        create_contexts_offset: 0,
        create_contexts_length: 0,
        name,
        create_contexts: vec![],
    };
    let body = create_request_with_contexts(
        req,
        &[CreateContext {
            name: CreateContext::NAME_DH2Q.to_vec(),
            data: durable_v2_request_with_guid(0, create_guid),
        }],
    );
    let mut hdr = build_header(Command::Create, message_id, session_id, tree_id);
    if replay {
        hdr.flags |= SMB2_FLAGS_REPLAY_OPERATION;
    }
    write_frame(s, &hdr, &body).await;
    let resp =
        read_create_response_after_optional_oplock_break(s, session_id, tree_id, message_id).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Create);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    CreateResponse::parse(rb).expect("parse durable v2 batch create")
}

async fn read_create_response_after_optional_oplock_break(
    s: &mut TcpStream,
    session_id: u64,
    tree_id: u32,
    message_id: u64,
) -> Vec<u8> {
    let resp = read_frame(s).await;
    let (rh, rb) = parse_response_header(&resp);
    if rh.command == Command::Create {
        return resp;
    }

    assert_eq!(rh.command, Command::OplockBreak);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let notification = OplockBreakAck::parse(rb).expect("parse oplock break notification");
    let pending = read_frame(s).await;
    let (pending_hdr, _) = parse_response_header(&pending);
    assert_eq!(pending_hdr.command, Command::Create);
    assert_eq!(pending_hdr.channel_sequence_status, STATUS_PENDING);
    let pending_async_id = pending_hdr.async_id().expect("pending create async id");

    let ack = OplockBreakAck {
        structure_size: 24,
        oplock_level: notification.oplock_level,
        reserved: 0,
        reserved2: 0,
        file_id: notification.file_id,
    };
    let mut ack_body = Vec::new();
    ack.write_to(&mut ack_body).expect("write oplock break ack");
    let ack_hdr = build_header(Command::OplockBreak, message_id + 1000, session_id, tree_id);
    write_frame(s, &ack_hdr, &ack_body).await;

    let frames = [read_frame(s).await, read_frame(s).await];
    let mut final_create = None;
    for frame in frames {
        let (rh, _) = parse_response_header(&frame);
        match rh.command {
            Command::OplockBreak => assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS),
            Command::Create => {
                assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
                assert_eq!(rh.async_id(), Some(pending_async_id));
                final_create = Some(frame);
            }
            other => panic!("unexpected post-oplock-break response command {other:?}"),
        }
    }
    final_create.expect("missing final create response")
}

async fn create_durable_delete_on_close_batch(
    s: &mut TcpStream,
    session_id: u64,
    tree_id: u32,
    message_id: u64,
) -> smb_server::wire::messages::FileId {
    let name = utf16le("hello.txt");
    let req = CreateRequest {
        structure_size: 57,
        security_flags: 0,
        requested_oplock_level: 0x09,
        impersonation_level: 2,
        smb_create_flags: 0,
        reserved: 0,
        desired_access: 0x0012_0089 | 0x0012_0116 | 0x0001_0000,
        file_attributes: 0,
        share_access: 0x0000_0007,
        create_disposition: 3,
        create_options: 0x0000_0040 | 0x0000_1000,
        name_offset: 0x78,
        name_length: name.len() as u16,
        create_contexts_offset: 0,
        create_contexts_length: 0,
        name,
        create_contexts: vec![],
    };
    let body = create_request_with_contexts(
        req,
        &[CreateContext {
            name: CreateContext::NAME_DHNQ.to_vec(),
            data: vec![0; 16],
        }],
    );
    let hdr = build_header(Command::Create, message_id, session_id, tree_id);
    write_frame(s, &hdr, &body).await;
    let resp = read_frame(s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Create);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let create = CreateResponse::parse(rb).expect("parse durable delete-on-close create");
    assert_eq!(create.oplock_level, 0x09);
    let contexts = CreateContext::parse_chain(&create.create_contexts).expect("parse contexts");
    let durable = contexts
        .iter()
        .find(|ctx| ctx.name == CreateContext::NAME_DHNQ.as_slice())
        .expect("missing durable response context");
    assert_eq!(durable.data.len(), 8);
    create.file_id
}

async fn create_regular_delete_on_close_batch(
    s: &mut TcpStream,
    session_id: u64,
    tree_id: u32,
    message_id: u64,
) -> CreateResponse {
    let name = utf16le("hello.txt");
    let req = CreateRequest {
        structure_size: 57,
        security_flags: 0,
        requested_oplock_level: 0x09,
        impersonation_level: 2,
        smb_create_flags: 0,
        reserved: 0,
        desired_access: 0x0012_0089 | 0x0001_0000,
        file_attributes: 0,
        share_access: 0,
        create_disposition: 3,
        create_options: 0x0000_0040 | 0x0000_1000,
        name_offset: 0x78,
        name_length: name.len() as u16,
        create_contexts_offset: 0,
        create_contexts_length: 0,
        name,
        create_contexts: vec![],
    };
    let mut body = Vec::new();
    req.write_to(&mut body)
        .expect("write regular delete-on-close create");
    let hdr = build_header(Command::Create, message_id, session_id, tree_id);
    write_frame(s, &hdr, &body).await;
    let resp =
        read_create_response_after_optional_oplock_break(s, session_id, tree_id, message_id).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Create);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let create = CreateResponse::parse(rb).expect("parse regular delete-on-close create");
    assert_eq!(create.oplock_level, 0x09);
    create
}

async fn create_durable_v1_lease(
    s: &mut TcpStream,
    session_id: u64,
    tree_id: u32,
    message_id: u64,
) -> CreateResponse {
    let name = utf16le("hello.txt");
    let req = CreateRequest {
        structure_size: 57,
        security_flags: 0,
        requested_oplock_level: 0xff,
        impersonation_level: 2,
        smb_create_flags: 0,
        reserved: 0,
        desired_access: 0x0012_0089,
        file_attributes: 0,
        share_access: 0x0000_0007,
        create_disposition: 1,
        create_options: 0,
        name_offset: 0x78,
        name_length: name.len() as u16,
        create_contexts_offset: 0,
        create_contexts_length: 0,
        name,
        create_contexts: vec![],
    };
    let body = create_request_with_contexts(
        req,
        &[
            CreateContext {
                name: CreateContext::NAME_DHNQ.to_vec(),
                data: vec![0; 16],
            },
            CreateContext {
                name: CreateContext::NAME_RQLS.to_vec(),
                data: lease_v1_request_with_key(0x0000_0001 | 0x0000_0002, b"lease-key-123456"),
            },
        ],
    );
    let hdr = build_header(Command::Create, message_id, session_id, tree_id);
    write_frame(s, &hdr, &body).await;
    let resp = read_frame(s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Create);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let create = CreateResponse::parse(rb).expect("parse durable v1 lease create");
    let contexts = CreateContext::parse_chain(&create.create_contexts).expect("parse contexts");
    let durable = contexts
        .iter()
        .find(|ctx| ctx.name == CreateContext::NAME_DHNQ.as_slice())
        .expect("missing durable response context");
    assert_eq!(durable.data.len(), 8);
    let lease = contexts
        .iter()
        .find(|ctx| ctx.name == CreateContext::NAME_RQLS.as_slice())
        .expect("missing lease response context");
    assert_eq!(lease.data.len(), 32);
    assert_eq!(
        u32::from_le_bytes(lease.data[16..20].try_into().unwrap()),
        0x0000_0001 | 0x0000_0002
    );
    create
}

async fn create_durable_reconnect(
    s: &mut TcpStream,
    session_id: u64,
    tree_id: u32,
    message_id: u64,
    file_id: smb_server::wire::messages::FileId,
) -> smb_server::wire::messages::FileId {
    let name = utf16le("ignored-missing-name.txt");
    let req = CreateRequest {
        structure_size: 57,
        security_flags: 0,
        requested_oplock_level: 0,
        impersonation_level: 2,
        smb_create_flags: 0,
        reserved: 0,
        desired_access: 0x0012_0089,
        file_attributes: 0,
        share_access: 0x0000_0007,
        create_disposition: 1,
        create_options: 0,
        name_offset: 0x78,
        name_length: name.len() as u16,
        create_contexts_offset: 0,
        create_contexts_length: 0,
        name,
        create_contexts: vec![],
    };
    let body = create_request_with_contexts(
        req,
        &[CreateContext {
            name: CreateContext::NAME_DHNC.to_vec(),
            data: encode_file_id(file_id),
        }],
    );
    let hdr = build_header(Command::Create, message_id, session_id, tree_id);
    write_frame(s, &hdr, &body).await;
    let resp = read_frame(s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Create);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let create = CreateResponse::parse(rb).expect("parse durable reconnect");
    assert_eq!(create.oplock_level, 0x09);
    let contexts = CreateContext::parse_chain(&create.create_contexts).expect("parse contexts");
    let durable = contexts
        .iter()
        .find(|ctx| ctx.name == CreateContext::NAME_DHNC.as_slice())
        .expect("missing durable reconnect response context");
    assert_eq!(durable.data, vec![0; 8]);
    create.file_id
}

async fn create_durable_reconnect_status(
    s: &mut TcpStream,
    session_id: u64,
    tree_id: u32,
    message_id: u64,
    file_id: smb_server::wire::messages::FileId,
) -> u32 {
    create_durable_reconnect_name_status(
        s,
        session_id,
        tree_id,
        message_id,
        file_id,
        "ignored-missing-name.txt",
    )
    .await
}

async fn create_durable_reconnect_name_status(
    s: &mut TcpStream,
    session_id: u64,
    tree_id: u32,
    message_id: u64,
    file_id: smb_server::wire::messages::FileId,
    file_name: &str,
) -> u32 {
    let name = utf16le(file_name);
    let req = CreateRequest {
        structure_size: 57,
        security_flags: 0,
        requested_oplock_level: 0,
        impersonation_level: 2,
        smb_create_flags: 0,
        reserved: 0,
        desired_access: 0x0012_0089,
        file_attributes: 0,
        share_access: 0x0000_0007,
        create_disposition: 1,
        create_options: 0,
        name_offset: 0x78,
        name_length: name.len() as u16,
        create_contexts_offset: 0,
        create_contexts_length: 0,
        name,
        create_contexts: vec![],
    };
    let body = create_request_with_contexts(
        req,
        &[CreateContext {
            name: CreateContext::NAME_DHNC.to_vec(),
            data: encode_file_id(file_id),
        }],
    );
    let hdr = build_header(Command::Create, message_id, session_id, tree_id);
    write_frame(s, &hdr, &body).await;
    let resp = read_frame(s).await;
    let (rh, _rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Create);
    rh.channel_sequence_status
}

async fn create_durable_v1_lease_reconnect_name_status(
    s: &mut TcpStream,
    session_id: u64,
    tree_id: u32,
    message_id: u64,
    file_id: smb_server::wire::messages::FileId,
    file_name: &str,
) -> u32 {
    create_durable_v1_lease_reconnect_name_with_key_status(
        s,
        session_id,
        tree_id,
        message_id,
        file_id,
        file_name,
        b"lease-key-123456",
    )
    .await
}

async fn create_durable_v1_lease_reconnect_name_with_key_status(
    s: &mut TcpStream,
    session_id: u64,
    tree_id: u32,
    message_id: u64,
    file_id: smb_server::wire::messages::FileId,
    file_name: &str,
    lease_key: &[u8; 16],
) -> u32 {
    let name = utf16le(file_name);
    let req = CreateRequest {
        structure_size: 57,
        security_flags: 0,
        requested_oplock_level: 0xff,
        impersonation_level: 2,
        smb_create_flags: 0,
        reserved: 0,
        desired_access: 0x0012_0089,
        file_attributes: 0,
        share_access: 0x0000_0007,
        create_disposition: 1,
        create_options: 0,
        name_offset: 0x78,
        name_length: name.len() as u16,
        create_contexts_offset: 0,
        create_contexts_length: 0,
        name,
        create_contexts: vec![],
    };
    let body = create_request_with_contexts(
        req,
        &[
            CreateContext {
                name: CreateContext::NAME_DHNC.to_vec(),
                data: encode_file_id(file_id),
            },
            CreateContext {
                name: CreateContext::NAME_RQLS.to_vec(),
                data: lease_v1_request_with_key(0x0000_0001 | 0x0000_0002, lease_key),
            },
        ],
    );
    let hdr = build_header(Command::Create, message_id, session_id, tree_id);
    write_frame(s, &hdr, &body).await;
    let resp = read_frame(s).await;
    let (rh, _rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Create);
    rh.channel_sequence_status
}

async fn create_durable_v2_lease(
    s: &mut TcpStream,
    session_id: u64,
    tree_id: u32,
    message_id: u64,
) -> smb_server::wire::messages::FileId {
    create_durable_v2_lease_with_timeout(s, session_id, tree_id, message_id, 300_000).await
}

async fn create_durable_v2_lease_with_timeout(
    s: &mut TcpStream,
    session_id: u64,
    tree_id: u32,
    message_id: u64,
    expected_timeout_ms: u32,
) -> smb_server::wire::messages::FileId {
    create_durable_v2_lease_with_options(
        s,
        session_id,
        tree_id,
        message_id,
        expected_timeout_ms,
        0x0012_0089,
        0x0000_0007,
    )
    .await
}

async fn create_durable_v2_lease_with_access_and_share(
    s: &mut TcpStream,
    session_id: u64,
    tree_id: u32,
    message_id: u64,
    desired_access: u32,
    share_access: u32,
) -> smb_server::wire::messages::FileId {
    create_durable_v2_lease_with_options(
        s,
        session_id,
        tree_id,
        message_id,
        300_000,
        desired_access,
        share_access,
    )
    .await
}

async fn create_durable_v2_lease_with_app_instance(
    s: &mut TcpStream,
    session_id: u64,
    tree_id: u32,
    message_id: u64,
    desired_access: u32,
    share_access: u32,
    app_instance_id: [u8; 16],
) -> smb_server::wire::messages::FileId {
    let name = utf16le("hello.txt");
    let req = CreateRequest {
        structure_size: 57,
        security_flags: 0,
        requested_oplock_level: 0xff,
        impersonation_level: 2,
        smb_create_flags: 0,
        reserved: 0,
        desired_access,
        file_attributes: 0,
        share_access,
        create_disposition: 1,
        create_options: 0,
        name_offset: 0x78,
        name_length: name.len() as u16,
        create_contexts_offset: 0,
        create_contexts_length: 0,
        name,
        create_contexts: vec![],
    };
    let body = create_request_with_contexts(
        req,
        &[
            CreateContext {
                name: CreateContext::NAME_DH2Q.to_vec(),
                data: durable_v2_request(0),
            },
            CreateContext {
                name: CreateContext::NAME_APP_INSTANCE_ID.to_vec(),
                data: app_instance_id_context(app_instance_id),
            },
            CreateContext {
                name: CreateContext::NAME_RQLS.to_vec(),
                data: lease_v2_request(0x0000_0001 | 0x0000_0002),
            },
        ],
    );
    let hdr = build_header(Command::Create, message_id, session_id, tree_id);
    write_frame(s, &hdr, &body).await;
    let resp = read_frame(s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Create);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let create = CreateResponse::parse(rb).expect("parse durable v2 app-instance create");
    create.file_id
}

async fn create_durable_v2_lease_with_app_instance_version(
    s: &mut TcpStream,
    session_id: u64,
    tree_id: u32,
    message_id: u64,
    desired_access: u32,
    share_access: u32,
    app_instance_id: [u8; 16],
    app_instance_version: u64,
) -> smb_server::wire::messages::FileId {
    let name = utf16le("hello.txt");
    let req = CreateRequest {
        structure_size: 57,
        security_flags: 0,
        requested_oplock_level: 0xff,
        impersonation_level: 2,
        smb_create_flags: 0,
        reserved: 0,
        desired_access,
        file_attributes: 0,
        share_access,
        create_disposition: 1,
        create_options: 0,
        name_offset: 0x78,
        name_length: name.len() as u16,
        create_contexts_offset: 0,
        create_contexts_length: 0,
        name,
        create_contexts: vec![],
    };
    let body = create_request_with_contexts(
        req,
        &[
            CreateContext {
                name: CreateContext::NAME_DH2Q.to_vec(),
                data: durable_v2_request(0),
            },
            CreateContext {
                name: CreateContext::NAME_APP_INSTANCE_ID.to_vec(),
                data: app_instance_id_context(app_instance_id),
            },
            CreateContext {
                name: CreateContext::NAME_APP_INSTANCE_VERSION.to_vec(),
                data: app_instance_version_context(app_instance_version),
            },
            CreateContext {
                name: CreateContext::NAME_RQLS.to_vec(),
                data: lease_v2_request(0x0000_0001 | 0x0000_0002),
            },
        ],
    );
    let hdr = build_header(Command::Create, message_id, session_id, tree_id);
    write_frame(s, &hdr, &body).await;
    let resp = read_frame(s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Create);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let create = CreateResponse::parse(rb).expect("parse durable v2 app-instance-version create");
    create.file_id
}

async fn send_create_durable_v2_lease_with_key(
    s: &mut TcpStream,
    session_id: u64,
    tree_id: u32,
    message_id: u64,
    lease_key: &[u8; 16],
    replay: bool,
) {
    send_create_durable_v2_lease_with_key_and_guid(
        s,
        session_id,
        tree_id,
        message_id,
        lease_key,
        b"0123456789abcdef",
        replay,
    )
    .await
}

async fn send_create_durable_v2_lease_with_key_and_guid(
    s: &mut TcpStream,
    session_id: u64,
    tree_id: u32,
    message_id: u64,
    lease_key: &[u8; 16],
    create_guid: &[u8; 16],
    replay: bool,
) {
    send_create_durable_v2_lease_with_key_guid_state(
        s,
        session_id,
        tree_id,
        message_id,
        lease_key,
        create_guid,
        0x0000_0001 | 0x0000_0002,
        replay,
    )
    .await
}

async fn send_create_durable_v2_lease_with_key_guid_state(
    s: &mut TcpStream,
    session_id: u64,
    tree_id: u32,
    message_id: u64,
    lease_key: &[u8; 16],
    create_guid: &[u8; 16],
    lease_state: u32,
    replay: bool,
) {
    let name = utf16le("hello.txt");
    let req = CreateRequest {
        structure_size: 57,
        security_flags: 0,
        requested_oplock_level: 0xff,
        impersonation_level: 2,
        smb_create_flags: 0,
        reserved: 0,
        desired_access: 0x0012_0089,
        file_attributes: 0,
        share_access: 0x0000_0007,
        create_disposition: 1,
        create_options: 0,
        name_offset: 0x78,
        name_length: name.len() as u16,
        create_contexts_offset: 0,
        create_contexts_length: 0,
        name,
        create_contexts: vec![],
    };
    let body = create_request_with_contexts(
        req,
        &[
            CreateContext {
                name: CreateContext::NAME_DH2Q.to_vec(),
                data: durable_v2_request_with_guid(0, create_guid),
            },
            CreateContext {
                name: CreateContext::NAME_RQLS.to_vec(),
                data: lease_v2_request_with_key(lease_state, lease_key),
            },
        ],
    );
    let mut hdr = build_header(Command::Create, message_id, session_id, tree_id);
    if replay {
        hdr.flags |= SMB2_FLAGS_REPLAY_OPERATION;
    }
    write_frame(s, &hdr, &body).await;
}

async fn create_durable_v2_lease_with_key_status(
    s: &mut TcpStream,
    session_id: u64,
    tree_id: u32,
    message_id: u64,
    lease_key: &[u8; 16],
    replay: bool,
) -> u32 {
    send_create_durable_v2_lease_with_key(s, session_id, tree_id, message_id, lease_key, replay)
        .await;
    let resp = read_frame(s).await;
    let (rh, _) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Create);
    rh.channel_sequence_status
}

async fn create_durable_v2_lease_with_key_result(
    s: &mut TcpStream,
    session_id: u64,
    tree_id: u32,
    message_id: u64,
    lease_key: &[u8; 16],
    create_guid: &[u8; 16],
    replay: bool,
) -> (u32, Option<CreateResponse>) {
    send_create_durable_v2_lease_with_key_and_guid(
        s,
        session_id,
        tree_id,
        message_id,
        lease_key,
        create_guid,
        replay,
    )
    .await;
    let resp = read_frame(s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Create);
    let create = (rh.channel_sequence_status == STATUS_SUCCESS)
        .then(|| CreateResponse::parse(rb).expect("parse durable v2 lease result"));
    (rh.channel_sequence_status, create)
}

async fn create_durable_v2_lease_name_with_guid(
    s: &mut TcpStream,
    session_id: u64,
    tree_id: u32,
    message_id: u64,
    name: &str,
    lease_key: &[u8; 16],
    create_guid: &[u8; 16],
    replay: bool,
) -> CreateResponse {
    let name = utf16le(name);
    let req = CreateRequest {
        structure_size: 57,
        security_flags: 0,
        requested_oplock_level: 0xff,
        impersonation_level: 2,
        smb_create_flags: 0,
        reserved: 0,
        desired_access: 0x0012_0089 | 0x0012_0116,
        file_attributes: 0,
        share_access: 0x0000_0007,
        create_disposition: 3,
        create_options: 0,
        name_offset: 0x78,
        name_length: name.len() as u16,
        create_contexts_offset: 0,
        create_contexts_length: 0,
        name,
        create_contexts: vec![],
    };
    let body = create_request_with_contexts(
        req,
        &[
            CreateContext {
                name: CreateContext::NAME_DH2Q.to_vec(),
                data: durable_v2_request_with_guid(0, create_guid),
            },
            CreateContext {
                name: CreateContext::NAME_RQLS.to_vec(),
                data: lease_v2_request_with_key(0x0000_0001 | 0x0000_0002 | 0x0000_0004, lease_key),
            },
        ],
    );
    let mut hdr = build_header(Command::Create, message_id, session_id, tree_id);
    if replay {
        hdr.flags |= SMB2_FLAGS_REPLAY_OPERATION;
    }
    write_frame(s, &hdr, &body).await;
    let resp = read_frame(s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Create);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    CreateResponse::parse(rb).expect("parse durable v2 lease create")
}

async fn create_durable_v2_lease_with_key_state_result(
    s: &mut TcpStream,
    session_id: u64,
    tree_id: u32,
    message_id: u64,
    lease_key: &[u8; 16],
    create_guid: &[u8; 16],
    lease_state: u32,
    replay: bool,
) -> (u32, Option<CreateResponse>) {
    send_create_durable_v2_lease_with_key_guid_state(
        s,
        session_id,
        tree_id,
        message_id,
        lease_key,
        create_guid,
        lease_state,
        replay,
    )
    .await;
    let resp = read_frame(s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Create);
    let create = (rh.channel_sequence_status == STATUS_SUCCESS)
        .then(|| CreateResponse::parse(rb).expect("parse durable v2 lease result"));
    (rh.channel_sequence_status, create)
}

async fn create_durable_v2_lease_with_options(
    s: &mut TcpStream,
    session_id: u64,
    tree_id: u32,
    message_id: u64,
    expected_timeout_ms: u32,
    desired_access: u32,
    share_access: u32,
) -> smb_server::wire::messages::FileId {
    let name = utf16le("hello.txt");
    let req = CreateRequest {
        structure_size: 57,
        security_flags: 0,
        requested_oplock_level: 0xff,
        impersonation_level: 2,
        smb_create_flags: 0,
        reserved: 0,
        desired_access,
        file_attributes: 0,
        share_access,
        create_disposition: 1,
        create_options: 0,
        name_offset: 0x78,
        name_length: name.len() as u16,
        create_contexts_offset: 0,
        create_contexts_length: 0,
        name,
        create_contexts: vec![],
    };
    let body = create_request_with_contexts(
        req,
        &[
            CreateContext {
                name: CreateContext::NAME_DH2Q.to_vec(),
                data: durable_v2_request(0),
            },
            CreateContext {
                name: CreateContext::NAME_RQLS.to_vec(),
                data: lease_v2_request(0x0000_0001 | 0x0000_0002),
            },
        ],
    );
    let hdr = build_header(Command::Create, message_id, session_id, tree_id);
    write_frame(s, &hdr, &body).await;
    let resp = read_frame(s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Create);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let create = CreateResponse::parse(rb).expect("parse durable v2 create");
    assert_eq!(create.oplock_level, 0xff);
    let contexts = CreateContext::parse_chain(&create.create_contexts).expect("parse contexts");
    let lease = contexts
        .iter()
        .find(|ctx| ctx.name == CreateContext::NAME_RQLS.as_slice())
        .expect("missing lease response context");
    assert_eq!(lease.data.len(), 52);
    assert_eq!(
        u32::from_le_bytes(lease.data[16..20].try_into().unwrap()),
        0x0000_0001 | 0x0000_0002
    );
    let durable = contexts
        .iter()
        .find(|ctx| ctx.name == CreateContext::NAME_DH2Q.as_slice())
        .expect("missing durable v2 response context");
    assert_eq!(durable.data.len(), 8);
    assert_eq!(
        u32::from_le_bytes(durable.data[0..4].try_into().unwrap()),
        expected_timeout_ms
    );
    assert_eq!(
        u32::from_le_bytes(durable.data[4..8].try_into().unwrap()),
        0
    );
    create.file_id
}

async fn create_durable_v2_reconnect(
    s: &mut TcpStream,
    session_id: u64,
    tree_id: u32,
    message_id: u64,
    file_id: smb_server::wire::messages::FileId,
) -> smb_server::wire::messages::FileId {
    create_durable_v2_reconnect_with_access_and_share(
        s,
        session_id,
        tree_id,
        message_id,
        file_id,
        0x0012_0089,
        0x0000_0007,
    )
    .await
}

async fn create_durable_v2_reconnect_with_access_and_share(
    s: &mut TcpStream,
    session_id: u64,
    tree_id: u32,
    message_id: u64,
    file_id: smb_server::wire::messages::FileId,
    desired_access: u32,
    share_access: u32,
) -> smb_server::wire::messages::FileId {
    let name = utf16le("hello.txt");
    let req = CreateRequest {
        structure_size: 57,
        security_flags: 0,
        requested_oplock_level: 0xff,
        impersonation_level: 2,
        smb_create_flags: 0,
        reserved: 0,
        desired_access,
        file_attributes: 0,
        share_access,
        create_disposition: 1,
        create_options: 0,
        name_offset: 0x78,
        name_length: name.len() as u16,
        create_contexts_offset: 0,
        create_contexts_length: 0,
        name,
        create_contexts: vec![],
    };
    let body = create_request_with_contexts(
        req,
        &[
            CreateContext {
                name: CreateContext::NAME_DH2C.to_vec(),
                data: durable_v2_reconnect(file_id, 0),
            },
            CreateContext {
                name: CreateContext::NAME_RQLS.to_vec(),
                data: lease_v2_request(0x0000_0001 | 0x0000_0002),
            },
        ],
    );
    let hdr = build_header(Command::Create, message_id, session_id, tree_id);
    write_frame(s, &hdr, &body).await;
    let resp = read_frame(s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Create);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let create = CreateResponse::parse(rb).expect("parse durable v2 reconnect");
    assert_eq!(create.oplock_level, 0xff);
    let contexts = CreateContext::parse_chain(&create.create_contexts).expect("parse contexts");
    assert!(
        contexts
            .iter()
            .any(|ctx| ctx.name == CreateContext::NAME_RQLS.as_slice())
    );
    let durable = contexts
        .iter()
        .find(|ctx| ctx.name == CreateContext::NAME_DH2C.as_slice())
        .expect("missing durable v2 reconnect response context");
    assert_eq!(durable.data.len(), 8);
    assert_eq!(
        u32::from_le_bytes(durable.data[4..8].try_into().unwrap()),
        0
    );
    create.file_id
}

async fn create_durable_v2_batch_reconnect(
    s: &mut TcpStream,
    session_id: u64,
    tree_id: u32,
    message_id: u64,
    file_id: smb_server::wire::messages::FileId,
) -> smb_server::wire::messages::FileId {
    let name = utf16le("hello.txt");
    let req = CreateRequest {
        structure_size: 57,
        security_flags: 0,
        requested_oplock_level: 0x09,
        impersonation_level: 2,
        smb_create_flags: 0,
        reserved: 0,
        desired_access: 0x0012_0089,
        file_attributes: 0,
        share_access: 0x0000_0007,
        create_disposition: 1,
        create_options: 0,
        name_offset: 0x78,
        name_length: name.len() as u16,
        create_contexts_offset: 0,
        create_contexts_length: 0,
        name,
        create_contexts: vec![],
    };
    let body = create_request_with_contexts(
        req,
        &[CreateContext {
            name: CreateContext::NAME_DH2C.to_vec(),
            data: durable_v2_reconnect(file_id, 0),
        }],
    );
    let hdr = build_header(Command::Create, message_id, session_id, tree_id);
    write_frame(s, &hdr, &body).await;
    let resp = read_frame(s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Create);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let create = CreateResponse::parse(rb).expect("parse durable v2 batch reconnect");
    assert_eq!(create.oplock_level, 0x09);
    let contexts = CreateContext::parse_chain(&create.create_contexts).expect("parse contexts");
    let durable = contexts
        .iter()
        .find(|ctx| ctx.name == CreateContext::NAME_DH2C.as_slice())
        .expect("missing durable v2 reconnect response context");
    assert_eq!(durable.data.len(), 8);
    assert_eq!(
        u32::from_le_bytes(durable.data[4..8].try_into().unwrap()),
        0
    );
    create.file_id
}

async fn create_durable_v2_batch_reconnect_status(
    s: &mut TcpStream,
    session_id: u64,
    tree_id: u32,
    message_id: u64,
    file_id: smb_server::wire::messages::FileId,
) -> u32 {
    let name = utf16le("hello.txt");
    let req = CreateRequest {
        structure_size: 57,
        security_flags: 0,
        requested_oplock_level: 0x09,
        impersonation_level: 2,
        smb_create_flags: 0,
        reserved: 0,
        desired_access: 0x0012_0089,
        file_attributes: 0,
        share_access: 0x0000_0007,
        create_disposition: 1,
        create_options: 0,
        name_offset: 0x78,
        name_length: name.len() as u16,
        create_contexts_offset: 0,
        create_contexts_length: 0,
        name,
        create_contexts: vec![],
    };
    let body = create_request_with_contexts(
        req,
        &[CreateContext {
            name: CreateContext::NAME_DH2C.to_vec(),
            data: durable_v2_reconnect(file_id, 0),
        }],
    );
    let hdr = build_header(Command::Create, message_id, session_id, tree_id);
    write_frame(s, &hdr, &body).await;
    let resp = read_frame(s).await;
    let (rh, _) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Create);
    rh.channel_sequence_status
}

async fn create_durable_v2_reconnect_status(
    s: &mut TcpStream,
    session_id: u64,
    tree_id: u32,
    message_id: u64,
    file_id: smb_server::wire::messages::FileId,
) -> u32 {
    create_durable_v2_reconnect_name_status_with_guid(
        s,
        session_id,
        tree_id,
        message_id,
        file_id,
        "hello.txt",
        b"0123456789abcdef",
    )
    .await
}

async fn create_durable_v2_reconnect_name_status(
    s: &mut TcpStream,
    session_id: u64,
    tree_id: u32,
    message_id: u64,
    file_id: smb_server::wire::messages::FileId,
    name: &str,
) -> u32 {
    create_durable_v2_reconnect_name_status_with_guid(
        s,
        session_id,
        tree_id,
        message_id,
        file_id,
        name,
        b"0123456789abcdef",
    )
    .await
}

async fn create_durable_v2_reconnect_status_with_guid(
    s: &mut TcpStream,
    session_id: u64,
    tree_id: u32,
    message_id: u64,
    file_id: smb_server::wire::messages::FileId,
    create_guid: &[u8; 16],
) -> u32 {
    create_durable_v2_reconnect_name_status_with_guid(
        s,
        session_id,
        tree_id,
        message_id,
        file_id,
        "hello.txt",
        create_guid,
    )
    .await
}

async fn create_durable_v2_reconnect_name_status_with_guid(
    s: &mut TcpStream,
    session_id: u64,
    tree_id: u32,
    message_id: u64,
    file_id: smb_server::wire::messages::FileId,
    name: &str,
    create_guid: &[u8; 16],
) -> u32 {
    let name = utf16le(name);
    let req = CreateRequest {
        structure_size: 57,
        security_flags: 0,
        requested_oplock_level: 0xff,
        impersonation_level: 2,
        smb_create_flags: 0,
        reserved: 0,
        desired_access: 0x0012_0089,
        file_attributes: 0,
        share_access: 0x0000_0007,
        create_disposition: 1,
        create_options: 0,
        name_offset: 0x78,
        name_length: name.len() as u16,
        create_contexts_offset: 0,
        create_contexts_length: 0,
        name,
        create_contexts: vec![],
    };
    let body = create_request_with_contexts(
        req,
        &[
            CreateContext {
                name: CreateContext::NAME_DH2C.to_vec(),
                data: durable_v2_reconnect_with_guid(file_id, create_guid, 0),
            },
            CreateContext {
                name: CreateContext::NAME_RQLS.to_vec(),
                data: lease_v2_request(0x0000_0001 | 0x0000_0002),
            },
        ],
    );
    let hdr = build_header(Command::Create, message_id, session_id, tree_id);
    write_frame(s, &hdr, &body).await;
    let resp = read_frame(s).await;
    let (rh, _) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Create);
    rh.channel_sequence_status
}

async fn create_durable_v2_lease_overwrite(
    s: &mut TcpStream,
    session_id: u64,
    tree_id: u32,
    message_id: u64,
    replay: bool,
) -> (smb_server::wire::messages::FileId, u32) {
    let (status, create) = create_durable_v2_lease_overwrite_result(
        s,
        session_id,
        tree_id,
        message_id,
        replay,
        b"lease-key-123456",
    )
    .await;
    assert_eq!(status, STATUS_SUCCESS);
    create.expect("durable v2 overwrite create response")
}

async fn create_durable_v2_lease_overwrite_result(
    s: &mut TcpStream,
    session_id: u64,
    tree_id: u32,
    message_id: u64,
    replay: bool,
    lease_key: &[u8; 16],
) -> (u32, Option<(smb_server::wire::messages::FileId, u32)>) {
    let name = utf16le("hello.txt");
    let req = CreateRequest {
        structure_size: 57,
        security_flags: 0,
        requested_oplock_level: 0xff,
        impersonation_level: 2,
        smb_create_flags: 0,
        reserved: 0,
        desired_access: 0x0012_0089 | 0x0012_0116,
        file_attributes: 0,
        share_access: 0x0000_0007,
        create_disposition: 5,
        create_options: 0,
        name_offset: 0x78,
        name_length: name.len() as u16,
        create_contexts_offset: 0,
        create_contexts_length: 0,
        name,
        create_contexts: vec![],
    };
    let body = create_request_with_contexts(
        req,
        &[
            CreateContext {
                name: CreateContext::NAME_DH2Q.to_vec(),
                data: durable_v2_request(0),
            },
            CreateContext {
                name: CreateContext::NAME_RQLS.to_vec(),
                data: lease_v2_request_with_key(0x0000_0001 | 0x0000_0002, lease_key),
            },
        ],
    );
    let mut hdr = build_header(Command::Create, message_id, session_id, tree_id);
    if replay {
        hdr.flags |= SMB2_FLAGS_REPLAY_OPERATION;
    }
    write_frame(s, &hdr, &body).await;
    let resp = read_frame(s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Create);
    if rh.channel_sequence_status != STATUS_SUCCESS {
        return (rh.channel_sequence_status, None);
    }
    let create = CreateResponse::parse(rb).expect("parse durable v2 replay create");
    (
        rh.channel_sequence_status,
        Some((create.file_id, create.create_action)),
    )
}

async fn create_durable_v2_metadata_only(
    s: &mut TcpStream,
    session_id: u64,
    tree_id: u32,
    message_id: u64,
    replay: bool,
) -> CreateResponse {
    let name = utf16le("hello.txt");
    let req = CreateRequest {
        structure_size: 57,
        security_flags: 0,
        requested_oplock_level: 0xff,
        impersonation_level: 2,
        smb_create_flags: 0,
        reserved: 0,
        desired_access: 0x0000_0080,
        file_attributes: 0,
        share_access: 0x0000_0007,
        create_disposition: 1,
        create_options: 0,
        name_offset: 0x78,
        name_length: name.len() as u16,
        create_contexts_offset: 0,
        create_contexts_length: 0,
        name,
        create_contexts: vec![],
    };
    let body = create_request_with_contexts(
        req,
        &[
            CreateContext {
                name: CreateContext::NAME_DH2Q.to_vec(),
                data: durable_v2_request(0),
            },
            CreateContext {
                name: CreateContext::NAME_RQLS.to_vec(),
                data: lease_v2_request(0x0000_0001 | 0x0000_0002),
            },
        ],
    );
    let mut hdr = build_header(Command::Create, message_id, session_id, tree_id);
    if replay {
        hdr.flags |= SMB2_FLAGS_REPLAY_OPERATION;
    }
    write_frame(s, &hdr, &body).await;
    let resp = read_frame(s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Create);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let create = CreateResponse::parse(rb).expect("parse durable v2 metadata create");
    let contexts = CreateContext::parse_chain(&create.create_contexts).expect("parse contexts");
    assert!(
        contexts
            .iter()
            .any(|ctx| ctx.name == CreateContext::NAME_DH2Q.as_slice())
    );
    create
}

async fn create_lease_open(
    s: &mut TcpStream,
    session_id: u64,
    tree_id: u32,
    message_id: u64,
    desired_access: u32,
    lease_state: u32,
) -> (CreateResponse, u32) {
    let (create, lease) = create_lease_open_with_key(
        s,
        session_id,
        tree_id,
        message_id,
        desired_access,
        lease_state,
        b"lease-key-123456",
    )
    .await;
    (create, lease)
}

async fn create_lease_open_with_key(
    s: &mut TcpStream,
    session_id: u64,
    tree_id: u32,
    message_id: u64,
    desired_access: u32,
    lease_state: u32,
    lease_key: &[u8; 16],
) -> (CreateResponse, u32) {
    let (create, grant) = create_lease_open_with_lease_data(
        s,
        session_id,
        tree_id,
        message_id,
        desired_access,
        lease_v2_request_with_key(lease_state, lease_key),
    )
    .await;
    assert_eq!(grant.response_len, 52);
    (create, grant.state)
}

#[derive(Debug, Clone, Copy)]
struct LeaseGrant {
    response_len: usize,
    state: u32,
    flags: u32,
    epoch: u16,
    parent_key: [u8; 16],
}

async fn create_lease_open_with_lease_data(
    s: &mut TcpStream,
    session_id: u64,
    tree_id: u32,
    message_id: u64,
    desired_access: u32,
    lease_data: Vec<u8>,
) -> (CreateResponse, LeaseGrant) {
    create_lease_open_name_with_lease_data(
        s,
        session_id,
        tree_id,
        message_id,
        "hello.txt",
        desired_access,
        lease_data,
    )
    .await
}

async fn create_lease_open_with_lease_data_and_share(
    s: &mut TcpStream,
    session_id: u64,
    tree_id: u32,
    message_id: u64,
    desired_access: u32,
    share_access: u32,
    lease_data: Vec<u8>,
) -> (CreateResponse, LeaseGrant) {
    send_create_lease_open_with_lease_data_and_share(
        s,
        session_id,
        tree_id,
        message_id,
        desired_access,
        share_access,
        lease_data,
    )
    .await;
    let resp = read_frame(s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Create);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let create = CreateResponse::parse(rb).expect("parse lease create");
    let grant = lease_grant_from_create(&create);
    (create, grant)
}

async fn create_lease_open_name_with_lease_data(
    s: &mut TcpStream,
    session_id: u64,
    tree_id: u32,
    message_id: u64,
    name: &str,
    desired_access: u32,
    lease_data: Vec<u8>,
) -> (CreateResponse, LeaseGrant) {
    send_create_lease_open_name_with_lease_data(
        s,
        session_id,
        tree_id,
        message_id,
        name,
        desired_access,
        lease_data,
    )
    .await;
    let resp = read_frame(s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Create);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let create = CreateResponse::parse(rb).expect("parse lease create");
    let grant = lease_grant_from_create(&create);
    (create, grant)
}

fn lease_grant_from_create(create: &CreateResponse) -> LeaseGrant {
    let contexts = CreateContext::parse_chain(&create.create_contexts).expect("parse contexts");
    let lease = contexts
        .iter()
        .find(|ctx| ctx.name == CreateContext::NAME_RQLS.as_slice())
        .expect("missing lease response context");
    LeaseGrant {
        response_len: lease.data.len(),
        state: u32::from_le_bytes(lease.data[16..20].try_into().unwrap()),
        flags: u32::from_le_bytes(lease.data[20..24].try_into().unwrap()),
        epoch: if lease.data.len() >= 50 {
            u16::from_le_bytes(lease.data[48..50].try_into().unwrap())
        } else {
            0
        },
        parent_key: if lease.data.len() >= 48 {
            lease.data[32..48].try_into().unwrap()
        } else {
            [0; 16]
        },
    }
}

async fn send_create_lease_open_with_lease_data(
    s: &mut TcpStream,
    session_id: u64,
    tree_id: u32,
    message_id: u64,
    desired_access: u32,
    lease_data: Vec<u8>,
) {
    send_create_lease_open_name_with_lease_data(
        s,
        session_id,
        tree_id,
        message_id,
        "hello.txt",
        desired_access,
        lease_data,
    )
    .await;
}

async fn send_create_lease_open_name_with_lease_data(
    s: &mut TcpStream,
    session_id: u64,
    tree_id: u32,
    message_id: u64,
    name: &str,
    desired_access: u32,
    lease_data: Vec<u8>,
) {
    send_create_lease_open_name_with_lease_data_and_share(
        s,
        session_id,
        tree_id,
        message_id,
        name,
        desired_access,
        0x0000_0007,
        lease_data,
    )
    .await;
}

async fn send_create_lease_open_with_lease_data_and_share(
    s: &mut TcpStream,
    session_id: u64,
    tree_id: u32,
    message_id: u64,
    desired_access: u32,
    share_access: u32,
    lease_data: Vec<u8>,
) {
    send_create_lease_open_name_with_lease_data_and_share(
        s,
        session_id,
        tree_id,
        message_id,
        "hello.txt",
        desired_access,
        share_access,
        lease_data,
    )
    .await;
}

async fn send_create_lease_open_name_with_lease_data_and_share(
    s: &mut TcpStream,
    session_id: u64,
    tree_id: u32,
    message_id: u64,
    name: &str,
    desired_access: u32,
    share_access: u32,
    lease_data: Vec<u8>,
) {
    let name = utf16le(name);
    let req = CreateRequest {
        structure_size: 57,
        security_flags: 0,
        requested_oplock_level: 0xff,
        impersonation_level: 2,
        smb_create_flags: 0,
        reserved: 0,
        desired_access,
        file_attributes: 0,
        share_access,
        create_disposition: 1,
        create_options: 0,
        name_offset: 0x78,
        name_length: name.len() as u16,
        create_contexts_offset: 0,
        create_contexts_length: 0,
        name,
        create_contexts: vec![],
    };
    let body = create_request_with_contexts(
        req,
        &[CreateContext {
            name: CreateContext::NAME_RQLS.to_vec(),
            data: lease_data,
        }],
    );
    let hdr = build_header(Command::Create, message_id, session_id, tree_id);
    write_frame(s, &hdr, &body).await;
}

async fn send_overwrite_create(
    s: &mut TcpStream,
    session_id: u64,
    tree_id: u32,
    message_id: u64,
    desired_access: u32,
) {
    let name = utf16le("hello.txt");
    let req = CreateRequest {
        structure_size: 57,
        security_flags: 0,
        requested_oplock_level: 0,
        impersonation_level: 2,
        smb_create_flags: 0,
        reserved: 0,
        desired_access,
        file_attributes: 0,
        share_access: 0x0000_0007,
        create_disposition: 4,
        create_options: 0,
        name_offset: 0x78,
        name_length: name.len() as u16,
        create_contexts_offset: 0,
        create_contexts_length: 0,
        name,
        create_contexts: vec![],
    };
    let mut body = Vec::new();
    req.write_to(&mut body).expect("write overwrite create");
    let hdr = build_header(Command::Create, message_id, session_id, tree_id);
    write_frame(s, &hdr, &body).await;
}

async fn send_lease_break_ack(
    s: &mut TcpStream,
    session_id: u64,
    tree_id: u32,
    message_id: u64,
    lease_key: &[u8; 16],
    lease_state: u32,
) -> (u32, Vec<u8>) {
    let req = LeaseBreakAck {
        structure_size: 36,
        reserved: 0,
        flags: 0,
        lease_key: *lease_key,
        lease_state,
        lease_duration: 0,
    };
    let mut body = Vec::new();
    req.write_to(&mut body).expect("write lease break ack");
    let hdr = build_header(Command::OplockBreak, message_id, session_id, tree_id);
    write_frame(s, &hdr, &body).await;
    let resp = read_frame(s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::OplockBreak);
    (rh.channel_sequence_status, rb.to_vec())
}

async fn send_lease_break_ack_without_waiting(
    s: &mut TcpStream,
    session_id: u64,
    tree_id: u32,
    message_id: u64,
    lease_key: &[u8; 16],
    lease_state: u32,
) {
    let req = LeaseBreakAck {
        structure_size: 36,
        reserved: 0,
        flags: 0,
        lease_key: *lease_key,
        lease_state,
        lease_duration: 0,
    };
    let mut body = Vec::new();
    req.write_to(&mut body).expect("write lease break ack");
    let hdr = build_header(Command::OplockBreak, message_id, session_id, tree_id);
    write_frame(s, &hdr, &body).await;
}

async fn create_directory_open(
    s: &mut TcpStream,
    session_id: u64,
    tree_id: u32,
    message_id: u64,
    name: &str,
) -> CreateResponse {
    let name = utf16le(name);
    let req = CreateRequest {
        structure_size: 57,
        security_flags: 0,
        requested_oplock_level: 0,
        impersonation_level: 2,
        smb_create_flags: 0,
        reserved: 0,
        desired_access: 0x001f_01ff,
        file_attributes: 0x0000_0010,
        share_access: 0x0000_0007,
        create_disposition: 1,
        create_options: 0x0000_0001,
        name_offset: 0x78,
        name_length: name.len() as u16,
        create_contexts_offset: 0,
        create_contexts_length: 0,
        name,
        create_contexts: vec![],
    };
    let mut body = Vec::new();
    req.write_to(&mut body).expect("write directory create");
    let hdr = build_header(Command::Create, message_id, session_id, tree_id);
    write_frame(s, &hdr, &body).await;
    let resp = read_frame(s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Create);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    CreateResponse::parse(rb).expect("parse directory create")
}

async fn create_lease_directory_open(
    s: &mut TcpStream,
    session_id: u64,
    tree_id: u32,
    message_id: u64,
) -> CreateResponse {
    let name = utf16le("docs");
    let req = CreateRequest {
        structure_size: 57,
        security_flags: 0,
        requested_oplock_level: 0xff,
        impersonation_level: 2,
        smb_create_flags: 0,
        reserved: 0,
        desired_access: 0x0012_0089,
        file_attributes: 0,
        share_access: 0x0000_0007,
        create_disposition: 1,
        create_options: 0x0000_0001,
        name_offset: 0x78,
        name_length: name.len() as u16,
        create_contexts_offset: 0,
        create_contexts_length: 0,
        name,
        create_contexts: vec![],
    };
    let body = create_request_with_contexts(
        req,
        &[CreateContext {
            name: CreateContext::NAME_RQLS.to_vec(),
            data: lease_v2_request(0x0000_0001),
        }],
    );
    let hdr = build_header(Command::Create, message_id, session_id, tree_id);
    write_frame(s, &hdr, &body).await;
    let resp = read_frame(s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Create);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let create = CreateResponse::parse(rb).expect("parse directory lease create");
    let contexts = CreateContext::parse_chain(&create.create_contexts).expect("parse contexts");
    assert!(
        contexts
            .iter()
            .all(|ctx| ctx.name != CreateContext::NAME_RQLS.as_slice())
    );
    create
}

fn encode_file_id(file_id: smb_server::wire::messages::FileId) -> Vec<u8> {
    let mut out = Vec::with_capacity(16);
    out.extend_from_slice(&file_id.persistent.to_le_bytes());
    out.extend_from_slice(&file_id.volatile.to_le_bytes());
    out
}

fn durable_v2_request(flags: u32) -> Vec<u8> {
    durable_v2_request_with_guid(flags, b"0123456789abcdef")
}

fn durable_v2_request_with_guid(flags: u32, create_guid: &[u8; 16]) -> Vec<u8> {
    let mut out = vec![0; 32];
    out[4..8].copy_from_slice(&flags.to_le_bytes());
    out[16..32].copy_from_slice(create_guid);
    out
}

fn durable_v2_reconnect(file_id: smb_server::wire::messages::FileId, flags: u32) -> Vec<u8> {
    durable_v2_reconnect_with_guid(file_id, b"0123456789abcdef", flags)
}

fn durable_v2_reconnect_with_guid(
    file_id: smb_server::wire::messages::FileId,
    create_guid: &[u8; 16],
    flags: u32,
) -> Vec<u8> {
    let mut out = vec![0; 36];
    out[0..16].copy_from_slice(&encode_file_id(file_id));
    out[16..32].copy_from_slice(create_guid);
    out[32..36].copy_from_slice(&flags.to_le_bytes());
    out
}

fn app_instance_id_context(app_instance_id: [u8; 16]) -> Vec<u8> {
    let mut out = vec![0; 20];
    out[0..2].copy_from_slice(&20u16.to_le_bytes());
    out[4..20].copy_from_slice(&app_instance_id);
    out
}

fn app_instance_version_context(version: u64) -> Vec<u8> {
    let mut out = vec![0; 24];
    out[0..2].copy_from_slice(&24u16.to_le_bytes());
    out[8..16].copy_from_slice(&version.to_le_bytes());
    out
}

fn lease_v2_request(state: u32) -> Vec<u8> {
    lease_v2_request_with_key(state, b"lease-key-123456")
}

fn lease_v1_request_with_key(state: u32, key: &[u8; 16]) -> Vec<u8> {
    let mut out = vec![0; 32];
    out[0..16].copy_from_slice(key);
    out[16..20].copy_from_slice(&state.to_le_bytes());
    out
}

fn lease_v2_request_with_key(state: u32, key: &[u8; 16]) -> Vec<u8> {
    lease_v2_request_with_key_and_epoch(state, key, 7)
}

fn lease_v2_request_with_key_and_epoch(state: u32, key: &[u8; 16], epoch: u16) -> Vec<u8> {
    let mut out = vec![0; 52];
    out[0..16].copy_from_slice(key);
    out[16..20].copy_from_slice(&state.to_le_bytes());
    out[32..48].copy_from_slice(b"parent-key-12345");
    out[48..50].copy_from_slice(&epoch.to_le_bytes());
    out
}

fn file_rename_information(name: &str, replace_if_exists: bool) -> Vec<u8> {
    let name = utf16le(name);
    let mut out = Vec::with_capacity(20 + name.len());
    out.push(u8::from(replace_if_exists));
    out.extend_from_slice(&[0; 7]);
    out.extend_from_slice(&0u64.to_le_bytes());
    out.extend_from_slice(&(name.len() as u32).to_le_bytes());
    out.extend_from_slice(&name);
    out
}

fn create_request_with_contexts(mut req: CreateRequest, contexts_in: &[CreateContext]) -> Vec<u8> {
    req.create_contexts_offset = 0;
    req.create_contexts_length = 0;
    req.create_contexts.clear();
    let mut body = Vec::new();
    req.write_to(&mut body).expect("write create without ctx");
    let context_offset = (body.len() + 7) & !7;
    let mut contexts = Vec::new();
    CreateContext::encode_chain(contexts_in, &mut contexts).expect("encode create context");
    req.create_contexts_offset = 64 + context_offset as u32;
    req.create_contexts_length = contexts.len() as u32;
    body.clear();
    req.write_to(&mut body).expect("write create with ctx");
    body.resize(context_offset, 0);
    body.extend_from_slice(&contexts);
    body
}

async fn tree_disconnect(s: &mut TcpStream, session_id: u64, tree_id: u32, message_id: u64) {
    let mut body = Vec::new();
    TreeDisconnectRequest::default()
        .write_to(&mut body)
        .expect("write tree disconnect");
    let hdr = build_header(Command::TreeDisconnect, message_id, session_id, tree_id);
    write_frame(s, &hdr, &body).await;
    let resp = read_frame(s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::TreeDisconnect);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let _ = TreeDisconnectResponse::parse(rb).expect("parse tree disconnect");
}

#[allow(clippy::too_many_arguments)]
async fn lock(
    s: &mut TcpStream,
    session_id: u64,
    tree_id: u32,
    message_id: u64,
    file_id: smb_server::wire::messages::FileId,
    offset: u64,
    length: u64,
    flags: u32,
    expected_status: u32,
) {
    let req = LockRequest {
        structure_size: 48,
        lock_count: 1,
        lock_sequence: 0,
        file_id,
        locks: vec![LockElement {
            offset,
            length,
            flags,
            reserved: 0,
        }],
    };
    let mut body = Vec::new();
    req.write_to(&mut body).expect("write lock");
    let hdr = build_header(Command::Lock, message_id, session_id, tree_id);
    write_frame(s, &hdr, &body).await;
    read_lock_response_allowing_oplock_break(s, file_id, expected_status).await;
}

async fn lock_elements(
    s: &mut TcpStream,
    session_id: u64,
    tree_id: u32,
    message_id: u64,
    file_id: smb_server::wire::messages::FileId,
    elements: &[(u64, u64, u32)],
    expected_status: u32,
) {
    let req = LockRequest {
        structure_size: 48,
        lock_count: elements.len() as u16,
        lock_sequence: 0,
        file_id,
        locks: elements
            .iter()
            .map(|(offset, length, flags)| LockElement {
                offset: *offset,
                length: *length,
                flags: *flags,
                reserved: 0,
            })
            .collect(),
    };
    let mut body = Vec::new();
    req.write_to(&mut body).expect("write lock elements");
    let hdr = build_header(Command::Lock, message_id, session_id, tree_id);
    write_frame(s, &hdr, &body).await;
    read_lock_response_allowing_oplock_break(s, file_id, expected_status).await;
}

#[allow(clippy::too_many_arguments)]
async fn lock_with_sequence(
    s: &mut TcpStream,
    session_id: u64,
    tree_id: u32,
    message_id: u64,
    file_id: smb_server::wire::messages::FileId,
    sequence_number: u8,
    sequence_index: u32,
    offset: u64,
    length: u64,
    flags: u32,
    expected_status: u32,
) {
    let req = LockRequest {
        structure_size: 48,
        lock_count: 1,
        lock_sequence: u32::from(sequence_number & 0x0f) | (sequence_index << 4),
        file_id,
        locks: vec![LockElement {
            offset,
            length,
            flags,
            reserved: 0,
        }],
    };
    let mut body = Vec::new();
    req.write_to(&mut body).expect("write lock");
    let hdr = build_header(Command::Lock, message_id, session_id, tree_id);
    write_frame(s, &hdr, &body).await;
    read_lock_response_allowing_oplock_break(s, file_id, expected_status).await;
}

async fn read_lock_response_allowing_oplock_break(
    s: &mut TcpStream,
    file_id: smb_server::wire::messages::FileId,
    expected_status: u32,
) {
    let mut resp = read_frame(s).await;
    let (mut rh, mut rb) = parse_response_header(&resp);
    if rh.command == Command::OplockBreak {
        assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
        let notification = OplockBreakAck::parse(rb).expect("parse oplock break");
        assert_eq!(notification.oplock_level, 0);
        assert_eq!(notification.file_id, file_id);
        resp = read_frame(s).await;
        (rh, rb) = parse_response_header(&resp);
    }
    assert_eq!(rh.command, Command::Lock);
    assert_eq!(rh.channel_sequence_status, expected_status);
    if expected_status == STATUS_SUCCESS {
        let _ = LockResponse::parse(rb).expect("parse lock");
    }
}

async fn request_resiliency(
    s: &mut TcpStream,
    session_id: u64,
    tree_id: u32,
    message_id: u64,
    file_id: smb_server::wire::messages::FileId,
    timeout_ms: u32,
) {
    let mut input = Vec::with_capacity(8);
    input.extend_from_slice(&timeout_ms.to_le_bytes());
    input.extend_from_slice(&0u32.to_le_bytes());
    let req = IoctlRequest {
        structure_size: 57,
        reserved: 0,
        ctl_code: Fsctl::LMR_REQUEST_RESILIENCY,
        file_id,
        input_offset: 0x78,
        input_count: input.len() as u32,
        max_input_response: 0,
        output_offset: 0,
        output_count: 0,
        max_output_response: 0,
        flags: IoctlRequest::FLAG_IS_FSCTL,
        reserved2: 0,
        input,
    };
    let mut body = Vec::new();
    req.write_to(&mut body).expect("write ioctl");
    let hdr = build_header(Command::Ioctl, message_id, session_id, tree_id);
    write_frame(s, &hdr, &body).await;
    let resp = read_frame(s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Ioctl);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let ioctl = IoctlResponse::parse(rb).expect("parse ioctl");
    assert_eq!(ioctl.ctl_code, Fsctl::LMR_REQUEST_RESILIENCY);
    assert!(ioctl.output.is_empty());
}

async fn force_unacked_timeout(s: &mut TcpStream, message_id: u64) {
    let req = IoctlRequest {
        structure_size: 57,
        reserved: 0,
        ctl_code: Fsctl::SMBTORTURE_FORCE_UNACKED_TIMEOUT,
        file_id: smb_server::wire::messages::FileId::any(),
        input_offset: 0,
        input_count: 0,
        max_input_response: 0,
        output_offset: 0,
        output_count: 0,
        max_output_response: 0,
        flags: IoctlRequest::FLAG_IS_FSCTL,
        reserved2: 0,
        input: Vec::new(),
    };
    let mut body = Vec::new();
    req.write_to(&mut body).expect("write force-unacked ioctl");
    let hdr = build_header(Command::Ioctl, message_id, 0, 0);
    write_frame(s, &hdr, &body).await;
    let resp = read_frame(s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Ioctl);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let ioctl = IoctlResponse::parse(rb).expect("parse force-unacked ioctl");
    assert_eq!(ioctl.ctl_code, Fsctl::SMBTORTURE_FORCE_UNACKED_TIMEOUT);
    assert!(ioctl.output.is_empty());
}

#[allow(clippy::too_many_arguments)]
async fn send_lock(
    s: &mut TcpStream,
    session_id: u64,
    tree_id: u32,
    message_id: u64,
    file_id: smb_server::wire::messages::FileId,
    offset: u64,
    length: u64,
    flags: u32,
) -> Smb2Header {
    let req = LockRequest {
        structure_size: 48,
        lock_count: 1,
        lock_sequence: 0,
        file_id,
        locks: vec![LockElement {
            offset,
            length,
            flags,
            reserved: 0,
        }],
    };
    let mut body = Vec::new();
    req.write_to(&mut body).expect("write lock");
    let hdr = build_header(Command::Lock, message_id, session_id, tree_id);
    write_frame(s, &hdr, &body).await;
    let resp = read_frame(s).await;
    let (rh, _rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Lock);
    rh
}

#[allow(clippy::too_many_arguments)]
async fn write_lock(
    s: &mut TcpStream,
    session_id: u64,
    tree_id: u32,
    message_id: u64,
    file_id: smb_server::wire::messages::FileId,
    offset: u64,
    length: u64,
    flags: u32,
) {
    let req = LockRequest {
        structure_size: 48,
        lock_count: 1,
        lock_sequence: 0,
        file_id,
        locks: vec![LockElement {
            offset,
            length,
            flags,
            reserved: 0,
        }],
    };
    let mut body = Vec::new();
    req.write_to(&mut body).expect("write lock");
    let hdr = build_header(Command::Lock, message_id, session_id, tree_id);
    write_frame(s, &hdr, &body).await;
}

async fn send_async_cancel(s: &mut TcpStream, message_id: u64, session_id: u64, async_id: u64) {
    let mut body = Vec::new();
    CancelRequest::default()
        .write_to(&mut body)
        .expect("write cancel");
    let mut hdr = build_header(Command::Cancel, message_id, session_id, 0);
    hdr.flags |= SMB2_FLAGS_ASYNC_COMMAND;
    hdr.tail = HeaderTail::async_(async_id);
    write_frame(s, &hdr, &body).await;
}

async fn read(
    s: &mut TcpStream,
    session_id: u64,
    tree_id: u32,
    message_id: u64,
    file_id: smb_server::wire::messages::FileId,
    offset: u64,
    length: u32,
    expected_status: u32,
) {
    let req = ReadRequest {
        structure_size: 49,
        padding: ReadResponse::STANDARD_DATA_OFFSET,
        flags: 0,
        length,
        offset,
        file_id,
        minimum_count: 0,
        channel: 0,
        remaining_bytes: 0,
        read_channel_info_offset: 0,
        read_channel_info_length: 0,
        buffer: vec![0],
    };
    let mut body = Vec::new();
    req.write_to(&mut body).expect("write read");
    let hdr = build_header(Command::Read, message_id, session_id, tree_id);
    write_frame(s, &hdr, &body).await;
    let resp = read_frame(s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Read);
    assert_eq!(rh.channel_sequence_status, expected_status);
    if expected_status == STATUS_SUCCESS {
        let _ = ReadResponse::parse(rb).expect("parse read");
    }
}

async fn read_data(
    s: &mut TcpStream,
    session_id: u64,
    tree_id: u32,
    message_id: u64,
    file_id: smb_server::wire::messages::FileId,
    offset: u64,
    length: u32,
) -> Vec<u8> {
    let req = ReadRequest {
        structure_size: 49,
        padding: ReadResponse::STANDARD_DATA_OFFSET,
        flags: 0,
        length,
        offset,
        file_id,
        minimum_count: 0,
        channel: 0,
        remaining_bytes: 0,
        read_channel_info_offset: 0,
        read_channel_info_length: 0,
        buffer: vec![0],
    };
    let mut body = Vec::new();
    req.write_to(&mut body).expect("write read");
    let hdr = build_header(Command::Read, message_id, session_id, tree_id);
    write_frame(s, &hdr, &body).await;
    let resp = read_frame(s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Read);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    ReadResponse::parse(rb).expect("parse read").data
}

#[allow(clippy::too_many_arguments)]
async fn write(
    s: &mut TcpStream,
    session_id: u64,
    tree_id: u32,
    message_id: u64,
    file_id: smb_server::wire::messages::FileId,
    offset: u64,
    data: &[u8],
    expected_status: u32,
) {
    send_write(s, session_id, tree_id, message_id, file_id, offset, data).await;
    let resp = read_frame(s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Write);
    assert_eq!(rh.channel_sequence_status, expected_status);
    if expected_status == STATUS_SUCCESS {
        let wr = WriteResponse::parse(rb).expect("parse write");
        assert_eq!(wr.count, data.len() as u32);
    }
}

#[allow(clippy::too_many_arguments)]
async fn write_with_channel_sequence(
    s: &mut TcpStream,
    session_id: u64,
    tree_id: u32,
    message_id: u64,
    file_id: smb_server::wire::messages::FileId,
    offset: u64,
    data: &[u8],
    channel_sequence: u16,
    expected_status: u32,
) {
    let req = WriteRequest {
        structure_size: 49,
        data_offset: WriteRequest::STANDARD_DATA_OFFSET,
        length: data.len() as u32,
        offset,
        file_id,
        channel: 0,
        remaining_bytes: 0,
        write_channel_info_offset: 0,
        write_channel_info_length: 0,
        flags: 0,
        data: data.to_vec(),
    };
    let mut body = Vec::new();
    req.write_to(&mut body).expect("write write");
    let mut hdr = build_header(Command::Write, message_id, session_id, tree_id);
    hdr.channel_sequence_status = u32::from(channel_sequence);
    write_frame(s, &hdr, &body).await;

    let resp = read_frame(s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Write);
    assert_eq!(rh.channel_sequence_status, expected_status);
    if expected_status == STATUS_SUCCESS {
        let wr = WriteResponse::parse(rb).expect("parse write");
        assert_eq!(wr.count, data.len() as u32);
    }
}

async fn send_write(
    s: &mut TcpStream,
    session_id: u64,
    tree_id: u32,
    message_id: u64,
    file_id: smb_server::wire::messages::FileId,
    offset: u64,
    data: &[u8],
) {
    let req = WriteRequest {
        structure_size: 49,
        data_offset: WriteRequest::STANDARD_DATA_OFFSET,
        length: data.len() as u32,
        offset,
        file_id,
        channel: 0,
        remaining_bytes: 0,
        write_channel_info_offset: 0,
        write_channel_info_length: 0,
        flags: 0,
        data: data.to_vec(),
    };
    let mut body = Vec::new();
    req.write_to(&mut body).expect("write write");
    let hdr = build_header(Command::Write, message_id, session_id, tree_id);
    write_frame(s, &hdr, &body).await;
}

#[allow(clippy::too_many_arguments)]
async fn write_success_and_expect_lease_break(
    s: &mut TcpStream,
    session_id: u64,
    tree_id: u32,
    message_id: u64,
    file_id: smb_server::wire::messages::FileId,
    offset: u64,
    data: &[u8],
    lease_key: &[u8; 16],
    current_lease_state: u32,
    new_lease_state: u32,
) {
    let req = WriteRequest {
        structure_size: 49,
        data_offset: WriteRequest::STANDARD_DATA_OFFSET,
        length: data.len() as u32,
        offset,
        file_id,
        channel: 0,
        remaining_bytes: 0,
        write_channel_info_offset: 0,
        write_channel_info_length: 0,
        flags: 0,
        data: data.to_vec(),
    };
    let mut body = Vec::new();
    req.write_to(&mut body).expect("write write");
    let hdr = build_header(Command::Write, message_id, session_id, tree_id);
    write_frame(s, &hdr, &body).await;

    let frames = [read_frame(s).await, read_frame(s).await];
    let mut saw_write = false;
    let mut saw_break = false;
    for frame in frames {
        let (rh, rb) = parse_response_header(&frame);
        match rh.command {
            Command::Write => {
                assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
                let wr = WriteResponse::parse(rb).expect("parse write");
                assert_eq!(wr.count, data.len() as u32);
                saw_write = true;
            }
            Command::OplockBreak => {
                assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
                let notification =
                    LeaseBreakNotification::parse(rb).expect("parse lease break notification");
                assert_eq!(notification.flags, 0);
                assert_eq!(&notification.lease_key, lease_key);
                assert_eq!(notification.current_lease_state, current_lease_state);
                assert_eq!(notification.new_lease_state, new_lease_state);
                saw_break = true;
            }
            other => panic!("unexpected write side response command {other:?}"),
        }
    }
    assert!(saw_write, "missing write response");
    assert!(saw_break, "missing lease break notification");
}

async fn close(
    s: &mut TcpStream,
    session_id: u64,
    tree_id: u32,
    message_id: u64,
    file_id: smb_server::wire::messages::FileId,
) {
    let req = CloseRequest {
        structure_size: 24,
        flags: 0,
        reserved: 0,
        file_id,
    };
    let mut body = Vec::new();
    req.write_to(&mut body).expect("write close");
    let hdr = build_header(Command::Close, message_id, session_id, tree_id);
    write_frame(s, &hdr, &body).await;
    let resp = read_frame(s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Close);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let _ = CloseResponse::parse(rb).expect("parse close");
}

async fn close_status(
    s: &mut TcpStream,
    session_id: u64,
    tree_id: u32,
    message_id: u64,
    file_id: smb_server::wire::messages::FileId,
    expected_status: u32,
) {
    let req = CloseRequest {
        structure_size: 24,
        flags: 0,
        reserved: 0,
        file_id,
    };
    let mut body = Vec::new();
    req.write_to(&mut body).expect("write close");
    let hdr = build_header(Command::Close, message_id, session_id, tree_id);
    write_frame(s, &hdr, &body).await;
    let resp = read_frame(s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Close);
    assert_eq!(rh.channel_sequence_status, expected_status);
    if expected_status == STATUS_SUCCESS {
        let _ = CloseResponse::parse(rb).expect("parse close");
    }
}

async fn write_close(
    s: &mut TcpStream,
    session_id: u64,
    tree_id: u32,
    message_id: u64,
    file_id: smb_server::wire::messages::FileId,
) {
    let req = CloseRequest {
        structure_size: 24,
        flags: 0,
        reserved: 0,
        file_id,
    };
    let mut body = Vec::new();
    req.write_to(&mut body).expect("write close");
    let hdr = build_header(Command::Close, message_id, session_id, tree_id);
    write_frame(s, &hdr, &body).await;
}
