mod common;

use std::path::PathBuf;
use std::time::Duration;

use common::{
    STATUS_SUCCESS, anonymous_session_setup, build_header, encode_frame, negotiate,
    parse_response_header, read_frame, tree_connect, utf16le,
};
use smb_server::wire::header::{Command, SMB2_FLAGS_RELATED_OPERATIONS, Smb2Header};
use smb_server::wire::messages::{
    CloseRequest, CreateContext, CreateRequest, CreateResponse, FileId, FileInfoClass,
    FlushRequest, FlushResponse, Fsctl, InfoType, IoctlRequest, LeaseBreakAck,
    LeaseBreakNotification, NegotiateContext, NegotiateRequest, NegotiateResponse,
    PreauthIntegrityCapabilities, QueryDirectoryRequest, QueryDirectoryResponse, QueryInfoRequest,
    QueryInfoResponse, ReadRequest, ReadResponse, SetInfoRequest, TreeDisconnectRequest,
    TreeDisconnectResponse, WriteRequest, WriteResponse,
};
use smb_server::{LocalFsBackend, Share, SmbServer};
use tempfile::{TempDir, tempdir};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_OBJECT_NAME_NOT_FOUND: u32 = 0xC000_0034;
const STATUS_FILE_CLOSED: u32 = 0xC000_0128;
const STATUS_ACCESS_DENIED: u32 = 0xC000_0022;
const STATUS_USER_SESSION_DELETED: u32 = 0xC000_0203;
const STATUS_PENDING: u32 = 0x0000_0103;
const STATUS_NO_MORE_FILES: u32 = 0x8000_0006;

#[tokio::test]
async fn compound_related_propagates_failed_create_status() {
    let (mut s, session_id, tree_id, handle, _td) = setup().await;
    let placeholder = FileId::any();

    let mut compound = Vec::new();
    append_compound_part(
        &mut compound,
        &mut build_header(Command::Create, 4, session_id, tree_id),
        &create_body("missing.txt", 1),
        true,
    );
    let mut close_hdr = build_header(Command::Close, 5, u64::MAX, u32::MAX);
    close_hdr.flags |= SMB2_FLAGS_RELATED_OPERATIONS;
    append_compound_part(
        &mut compound,
        &mut close_hdr,
        &close_body(placeholder),
        true,
    );
    let mut second_close_hdr = build_header(Command::Close, 6, u64::MAX, u32::MAX);
    second_close_hdr.flags |= SMB2_FLAGS_RELATED_OPERATIONS;
    append_compound_part(
        &mut compound,
        &mut second_close_hdr,
        &close_body(placeholder),
        false,
    );

    let statuses = send_compound_statuses(&mut s, &compound).await;
    assert_eq!(
        statuses,
        vec![
            (Command::Create, STATUS_OBJECT_NAME_NOT_FOUND),
            (Command::Close, STATUS_OBJECT_NAME_NOT_FOUND),
            (Command::Close, STATUS_OBJECT_NAME_NOT_FOUND),
        ]
    );

    drop(s);
    handle.abort();
}

#[tokio::test]
async fn compound_related_file_id_does_not_survive_unrelated_gap() {
    let (mut s, session_id, tree_id, handle, _td) = setup().await;
    let placeholder = FileId::any();

    let mut compound = Vec::new();
    append_compound_part(
        &mut compound,
        &mut build_header(Command::Create, 4, session_id, tree_id),
        &create_body("related-gap.txt", 3),
        true,
    );
    append_compound_part(
        &mut compound,
        &mut build_header(Command::Close, 5, session_id, tree_id),
        &close_body(placeholder),
        true,
    );
    let mut related_close_hdr = build_header(Command::Close, 6, u64::MAX, u32::MAX);
    related_close_hdr.flags |= SMB2_FLAGS_RELATED_OPERATIONS;
    append_compound_part(
        &mut compound,
        &mut related_close_hdr,
        &close_body(placeholder),
        false,
    );

    let statuses = send_compound_statuses(&mut s, &compound).await;
    assert_eq!(
        statuses,
        vec![
            (Command::Create, STATUS_SUCCESS),
            (Command::Close, STATUS_FILE_CLOSED),
            (Command::Close, STATUS_FILE_CLOSED),
        ]
    );

    drop(s);
    handle.abort();
}

#[tokio::test]
async fn compound_unknown_related_command_is_invalid_parameter() {
    let (mut s, session_id, tree_id, handle, td) = setup().await;
    std::fs::write(td.path().join("unknown-related.txt"), b"x").expect("seed file");
    let file_id = create_open(&mut s, session_id, tree_id, 4, "unknown-related.txt").await;

    let mut compound = Vec::new();
    append_compound_part(
        &mut compound,
        &mut build_header(Command::Read, 5, session_id, tree_id),
        &read_body(file_id, 1, 0),
        true,
    );
    let mut unknown_hdr = build_header(Command::Unknown(0x00ff), 6, u64::MAX, u32::MAX);
    unknown_hdr.flags |= SMB2_FLAGS_RELATED_OPERATIONS;
    append_compound_part(&mut compound, &mut unknown_hdr, &[4, 0, 0, 0], false);

    let statuses = send_compound_statuses(&mut s, &compound).await;
    assert_eq!(
        statuses,
        vec![
            (Command::Read, STATUS_SUCCESS),
            (Command::Unknown(0x00ff), STATUS_INVALID_PARAMETER),
        ]
    );

    drop(s);
    handle.abort();
}

#[tokio::test]
async fn compound_first_related_request_is_invalid() {
    let (mut s, session_id, tree_id, handle, _td) = setup().await;
    let placeholder = FileId::any();

    let mut compound = Vec::new();
    let mut create_hdr = build_header(Command::Create, 4, session_id, tree_id);
    create_hdr.flags |= SMB2_FLAGS_RELATED_OPERATIONS;
    append_compound_part(
        &mut compound,
        &mut create_hdr,
        &create_body("first-related.txt", 3),
        true,
    );
    let mut related_close_hdr = build_header(Command::Close, 5, u64::MAX, u32::MAX);
    related_close_hdr.flags |= SMB2_FLAGS_RELATED_OPERATIONS;
    append_compound_part(
        &mut compound,
        &mut related_close_hdr,
        &close_body(placeholder),
        true,
    );
    append_compound_part(
        &mut compound,
        &mut build_header(Command::Close, 6, session_id, tree_id),
        &close_body(placeholder),
        false,
    );

    let statuses = send_compound_statuses(&mut s, &compound).await;
    assert_eq!(
        statuses,
        vec![
            (Command::Create, STATUS_INVALID_PARAMETER),
            (Command::Close, STATUS_INVALID_PARAMETER),
            (Command::Close, STATUS_FILE_CLOSED),
        ]
    );

    drop(s);
    handle.abort();
}

#[tokio::test]
async fn compound_related_after_invalid_unrelated_context_is_invalid_parameter() {
    let (mut s, session_id, tree_id, handle, _td) = setup().await;
    let placeholder = FileId::any();

    let mut compound = Vec::new();
    append_compound_part(
        &mut compound,
        &mut build_header(Command::Create, 4, session_id, tree_id),
        &create_body("compound-invalid2.txt", 3),
        true,
    );

    let mut related_close_hdr = build_header(Command::Close, 5, u64::MAX, u32::MAX);
    related_close_hdr.flags |= SMB2_FLAGS_RELATED_OPERATIONS;
    append_compound_part(
        &mut compound,
        &mut related_close_hdr,
        &close_body(placeholder),
        true,
    );

    append_compound_part(
        &mut compound,
        &mut build_header(Command::Close, 6, u64::MAX, u32::MAX),
        &close_body(placeholder),
        true,
    );
    append_compound_part(
        &mut compound,
        &mut build_header(Command::Close, 7, u64::MAX, u32::MAX),
        &close_body(placeholder),
        true,
    );

    let mut final_related_close_hdr = build_header(Command::Close, 8, u64::MAX, u32::MAX);
    final_related_close_hdr.flags |= SMB2_FLAGS_RELATED_OPERATIONS;
    append_compound_part(
        &mut compound,
        &mut final_related_close_hdr,
        &close_body(placeholder),
        false,
    );

    let statuses = send_compound_statuses(&mut s, &compound).await;
    assert_eq!(
        statuses,
        vec![
            (Command::Create, STATUS_SUCCESS),
            (Command::Close, STATUS_SUCCESS),
            (Command::Close, STATUS_USER_SESSION_DELETED),
            (Command::Close, STATUS_USER_SESSION_DELETED),
            (Command::Close, STATUS_INVALID_PARAMETER),
        ]
    );

    drop(s);
    handle.abort();
}

#[tokio::test]
async fn compound_create_read_close_uses_related_file_id() {
    let (mut s, session_id, tree_id, handle, td) = setup().await;
    let data = b"hello from compound\n";
    std::fs::write(td.path().join("hello.txt"), data).expect("seed file");
    let placeholder = FileId::any();

    let mut compound = Vec::new();
    append_compound_part(
        &mut compound,
        &mut build_header(Command::Create, 4, session_id, tree_id),
        &create_body("hello.txt", 1),
        true,
    );
    let mut read_hdr = build_header(Command::Read, 5, u64::MAX, u32::MAX);
    read_hdr.flags |= SMB2_FLAGS_RELATED_OPERATIONS;
    append_compound_part(
        &mut compound,
        &mut read_hdr,
        &read_body(placeholder, data.len() as u32, 0),
        true,
    );
    let mut close_hdr = build_header(Command::Close, 6, u64::MAX, u32::MAX);
    close_hdr.flags |= SMB2_FLAGS_RELATED_OPERATIONS;
    append_compound_part(
        &mut compound,
        &mut close_hdr,
        &close_body(placeholder),
        false,
    );

    let resp = send_compound_response(&mut s, &compound).await;
    let messages = split_response_parts(&resp);
    assert_eq!(messages.len(), 3);
    assert_success_commands(&messages, &[Command::Create, Command::Read, Command::Close]);
    assert_eq!(
        ReadResponse::parse(messages[1].body)
            .expect("parse read")
            .data
            .as_slice(),
        data
    );
    assert_related_ids(messages[1].header, session_id, tree_id);
    assert_related_ids(messages[2].header, session_id, tree_id);

    drop(s);
    handle.abort();
}

#[tokio::test]
async fn compound_create_query_info_close_uses_related_file_id() {
    let (mut s, session_id, tree_id, handle, td) = setup().await;
    std::fs::write(td.path().join("hello.txt"), vec![b'x'; 23]).expect("seed file");
    let placeholder = FileId::any();

    let mut compound = Vec::new();
    append_compound_part(
        &mut compound,
        &mut build_header(Command::Create, 4, session_id, tree_id),
        &create_body("hello.txt", 1),
        true,
    );
    let mut query_hdr = build_header(Command::QueryInfo, 5, u64::MAX, u32::MAX);
    query_hdr.flags |= SMB2_FLAGS_RELATED_OPERATIONS;
    append_compound_part(
        &mut compound,
        &mut query_hdr,
        &query_info_body(placeholder, 0x05, 4096),
        true,
    );
    let mut close_hdr = build_header(Command::Close, 6, u64::MAX, u32::MAX);
    close_hdr.flags |= SMB2_FLAGS_RELATED_OPERATIONS;
    append_compound_part(
        &mut compound,
        &mut close_hdr,
        &close_body(placeholder),
        false,
    );

    let resp = send_compound_response(&mut s, &compound).await;
    let messages = split_response_parts(&resp);
    assert_eq!(messages.len(), 3);
    assert_success_commands(
        &messages,
        &[Command::Create, Command::QueryInfo, Command::Close],
    );
    let query = QueryInfoResponse::parse(messages[1].body).expect("parse query info");
    assert!(query.buffer.len() >= 16);
    assert_eq!(
        u64::from_le_bytes(query.buffer[8..16].try_into().unwrap()),
        23
    );
    assert_related_ids(messages[1].header, session_id, tree_id);
    assert_related_ids(messages[2].header, session_id, tree_id);

    drop(s);
    handle.abort();
}

#[tokio::test]
async fn compound_related_multiple_close_after_create() {
    let (mut s, session_id, tree_id, handle, td) = setup().await;
    std::fs::write(td.path().join("hello.txt"), b"hello").expect("seed file");
    let placeholder = FileId::any();

    let mut compound = Vec::new();
    append_compound_part(
        &mut compound,
        &mut build_header(Command::Create, 4, session_id, tree_id),
        &create_body("hello.txt", 1),
        true,
    );
    for (message_id, has_next) in [(5, true), (6, true), (7, false)] {
        let mut close_hdr = build_header(Command::Close, message_id, u64::MAX, u32::MAX);
        close_hdr.flags |= SMB2_FLAGS_RELATED_OPERATIONS;
        append_compound_part(
            &mut compound,
            &mut close_hdr,
            &close_body(placeholder),
            has_next,
        );
    }

    let statuses = send_compound_statuses(&mut s, &compound).await;
    assert_eq!(
        statuses,
        vec![
            (Command::Create, STATUS_SUCCESS),
            (Command::Close, STATUS_SUCCESS),
            (Command::Close, STATUS_FILE_CLOSED),
            (Command::Close, STATUS_FILE_CLOSED),
        ]
    );

    drop(s);
    handle.abort();
}

#[tokio::test]
async fn compound_query_directory_related_uses_prior_request_file_id_and_cursor() {
    let (mut s, session_id, tree_id, handle, td) = setup().await;
    let dir = td.path().join("find-dir");
    std::fs::create_dir(&dir).expect("create dir");
    std::fs::write(dir.join("file0"), b"0").expect("seed file0");
    std::fs::write(dir.join("file1"), b"1").expect("seed file1");
    let file_id = create_directory_open(&mut s, session_id, tree_id, 4, "find-dir").await;
    let placeholder = FileId::any();

    let mut compound = Vec::new();
    append_compound_part(
        &mut compound,
        &mut build_header(Command::QueryDirectory, 5, session_id, tree_id),
        &query_directory_body(file_id, 0x1000),
        true,
    );
    let mut query_hdr = build_header(Command::QueryDirectory, 6, u64::MAX, u32::MAX);
    query_hdr.flags |= SMB2_FLAGS_RELATED_OPERATIONS;
    append_compound_part(
        &mut compound,
        &mut query_hdr,
        &query_directory_body(placeholder, 0x1000),
        false,
    );

    let resp = send_compound_response(&mut s, &compound).await;
    let messages = split_response_parts(&resp);
    assert_eq!(messages.len(), 2);
    assert_eq!(messages[0].header.command, Command::QueryDirectory);
    assert_eq!(messages[0].header.channel_sequence_status, STATUS_SUCCESS);
    let listing = QueryDirectoryResponse::parse(messages[0].body).expect("parse qdir");
    assert!(!listing.buffer.is_empty());
    assert_eq!(messages[1].header.command, Command::QueryDirectory);
    assert_eq!(
        messages[1].header.channel_sequence_status,
        STATUS_NO_MORE_FILES
    );
    assert_related_ids(messages[1].header, session_id, tree_id);

    drop(s);
    handle.abort();
}

#[tokio::test]
async fn compound_query_directory_unrelated_reuses_share_cursor() {
    let (mut s, session_id, tree_id, handle, td) = setup().await;
    let dir = td.path().join("find-dir");
    std::fs::create_dir(&dir).expect("create dir");
    std::fs::write(dir.join("file0"), b"0").expect("seed file0");
    std::fs::write(dir.join("file1"), b"1").expect("seed file1");
    let file_id = create_directory_open(&mut s, session_id, tree_id, 4, "find-dir").await;

    let mut compound = Vec::new();
    append_compound_part(
        &mut compound,
        &mut build_header(Command::QueryDirectory, 5, session_id, tree_id),
        &query_directory_body(file_id, 0x1000),
        true,
    );
    append_compound_part(
        &mut compound,
        &mut build_header(Command::QueryDirectory, 6, session_id, tree_id),
        &query_directory_body(file_id, 0x1000),
        false,
    );

    let resp = send_compound_response(&mut s, &compound).await;
    let messages = split_response_parts(&resp);
    assert_eq!(messages.len(), 2);
    assert_eq!(messages[0].header.command, Command::QueryDirectory);
    assert_eq!(messages[0].header.channel_sequence_status, STATUS_SUCCESS);
    let listing = QueryDirectoryResponse::parse(messages[0].body).expect("parse qdir");
    let names = file_both_directory_names(&listing.buffer);
    assert!(names.starts_with(&[".".to_string(), "..".to_string()]));
    assert_eq!(messages[1].header.command, Command::QueryDirectory);
    assert_eq!(
        messages[1].header.channel_sequence_status,
        STATUS_NO_MORE_FILES
    );

    drop(s);
    handle.abort();
}

#[tokio::test]
async fn compound_query_directory_close_keeps_find_response_and_closes_handle() {
    let (mut s, session_id, tree_id, handle, td) = setup().await;
    let dir = td.path().join("find-dir");
    std::fs::create_dir(&dir).expect("create dir");
    std::fs::write(dir.join("file0"), b"0").expect("seed file0");
    std::fs::write(dir.join("file1"), b"1").expect("seed file1");
    let file_id = create_directory_open(&mut s, session_id, tree_id, 4, "find-dir").await;

    let mut compound = Vec::new();
    append_compound_part(
        &mut compound,
        &mut build_header(Command::QueryDirectory, 5, session_id, tree_id),
        &query_directory_body(file_id, 0x100),
        true,
    );
    append_compound_part(
        &mut compound,
        &mut build_header(Command::Close, 6, session_id, tree_id),
        &close_body(file_id),
        false,
    );

    let resp = send_compound_response(&mut s, &compound).await;
    let messages = split_response_parts(&resp);
    assert_success_commands(&messages, &[Command::QueryDirectory, Command::Close]);
    let listing = QueryDirectoryResponse::parse(messages[0].body).expect("parse qdir");
    let names = file_both_directory_names(&listing.buffer);
    assert!(names.starts_with(&[".".to_string(), "..".to_string()]));
    assert_eq!(
        send_query_directory_status(&mut s, session_id, tree_id, 7, file_id).await,
        STATUS_FILE_CLOSED
    );

    drop(s);
    handle.abort();
}

#[tokio::test]
async fn compound_related_flush_close_uses_prior_request_file_id() {
    let (mut s, session_id, tree_id, handle, td) = setup().await;
    std::fs::write(td.path().join("flush-close.txt"), b"data").expect("seed file");
    let file_id = create_open(&mut s, session_id, tree_id, 4, "flush-close.txt").await;
    let placeholder = FileId::any();

    let mut compound = Vec::new();
    append_compound_part(
        &mut compound,
        &mut build_header(Command::Flush, 5, session_id, tree_id),
        &flush_body(file_id),
        true,
    );
    let mut close_hdr = build_header(Command::Close, 6, u64::MAX, u32::MAX);
    close_hdr.flags |= SMB2_FLAGS_RELATED_OPERATIONS;
    append_compound_part(
        &mut compound,
        &mut close_hdr,
        &close_body(placeholder),
        false,
    );

    let resp = send_compound_response(&mut s, &compound).await;
    let messages = split_response_parts(&resp);
    assert_eq!(messages.len(), 2);
    assert_success_commands(&messages, &[Command::Flush, Command::Close]);
    let _ = FlushResponse::parse(messages[0].body).expect("parse flush response");
    assert_related_ids(messages[1].header, session_id, tree_id);

    drop(s);
    handle.abort();
}

#[tokio::test]
async fn compound_related_ioctl_close_with_invalid_file_id_returns_file_closed() {
    let (mut s, session_id, tree_id, handle, _td) = setup().await;
    let placeholder = FileId::any();

    let mut compound = Vec::new();
    append_compound_part(
        &mut compound,
        &mut build_header(Command::Ioctl, 5, session_id, tree_id),
        &ioctl_body(placeholder, Fsctl::CREATE_OR_GET_OBJECT_ID, 0),
        true,
    );
    let mut close_hdr = build_header(Command::Close, 6, u64::MAX, u32::MAX);
    close_hdr.flags |= SMB2_FLAGS_RELATED_OPERATIONS;
    append_compound_part(
        &mut compound,
        &mut close_hdr,
        &close_body(placeholder),
        false,
    );

    let statuses = send_compound_statuses(&mut s, &compound).await;
    assert_eq!(
        statuses,
        [
            (Command::Ioctl, STATUS_FILE_CLOSED),
            (Command::Close, STATUS_FILE_CLOSED)
        ]
    );

    drop(s);
    handle.abort();
}

#[tokio::test]
async fn compound_related_flush_flush_uses_prior_request_file_id() {
    let (mut s, session_id, tree_id, handle, td) = setup().await;
    std::fs::write(td.path().join("flush-flush.txt"), b"data").expect("seed file");
    let file_id = create_open(&mut s, session_id, tree_id, 4, "flush-flush.txt").await;
    let placeholder = FileId::any();

    let mut compound = Vec::new();
    append_compound_part(
        &mut compound,
        &mut build_header(Command::Flush, 5, session_id, tree_id),
        &flush_body(file_id),
        true,
    );
    let mut flush_hdr = build_header(Command::Flush, 6, u64::MAX, u32::MAX);
    flush_hdr.flags |= SMB2_FLAGS_RELATED_OPERATIONS;
    append_compound_part(
        &mut compound,
        &mut flush_hdr,
        &flush_body(placeholder),
        false,
    );

    let resp = send_compound_response(&mut s, &compound).await;
    let messages = split_response_parts(&resp);
    assert_eq!(messages.len(), 2);
    assert_success_commands(&messages, &[Command::Flush, Command::Flush]);
    assert_related_ids(messages[1].header, session_id, tree_id);

    drop(s);
    handle.abort();
}

#[tokio::test]
async fn compound_related_write_write_uses_prior_request_file_id() {
    let (mut s, session_id, tree_id, handle, td) = setup().await;
    std::fs::write(td.path().join("write-write.txt"), vec![0; 128]).expect("seed file");
    let file_id = create_open(&mut s, session_id, tree_id, 4, "write-write.txt").await;
    let placeholder = FileId::any();

    let mut compound = Vec::new();
    append_compound_part(
        &mut compound,
        &mut build_header(Command::Write, 5, session_id, tree_id),
        &write_body(file_id, 0, &[b'a'; 64]),
        true,
    );
    let mut write_hdr = build_header(Command::Write, 6, u64::MAX, u32::MAX);
    write_hdr.flags |= SMB2_FLAGS_RELATED_OPERATIONS;
    append_compound_part(
        &mut compound,
        &mut write_hdr,
        &write_body(placeholder, 64, &[b'b'; 64]),
        false,
    );

    let resp = send_compound_response(&mut s, &compound).await;
    let messages = split_response_parts(&resp);
    assert_eq!(messages.len(), 2);
    assert_success_commands(&messages, &[Command::Write, Command::Write]);
    assert_eq!(
        WriteResponse::parse(messages[0].body)
            .expect("parse write")
            .count,
        64
    );
    assert_eq!(
        WriteResponse::parse(messages[1].body)
            .expect("parse write")
            .count,
        64
    );
    assert_related_ids(messages[1].header, session_id, tree_id);
    assert_eq!(
        std::fs::read(td.path().join("write-write.txt")).expect("read data"),
        [vec![b'a'; 64], vec![b'b'; 64]].concat()
    );

    drop(s);
    handle.abort();
}

#[tokio::test]
async fn compound_related_read_read_uses_prior_request_file_id() {
    let (mut s, session_id, tree_id, handle, td) = setup().await;
    let data = [vec![b'a'; 64], vec![b'b'; 64]].concat();
    std::fs::write(td.path().join("read-read.txt"), &data).expect("seed file");
    let file_id = create_open(&mut s, session_id, tree_id, 4, "read-read.txt").await;
    let placeholder = FileId::any();

    let mut compound = Vec::new();
    append_compound_part(
        &mut compound,
        &mut build_header(Command::Read, 5, session_id, tree_id),
        &read_body(file_id, 64, 0),
        true,
    );
    let mut read_hdr = build_header(Command::Read, 6, u64::MAX, u32::MAX);
    read_hdr.flags |= SMB2_FLAGS_RELATED_OPERATIONS;
    append_compound_part(
        &mut compound,
        &mut read_hdr,
        &read_body(placeholder, 64, 64),
        false,
    );

    let resp = send_compound_response(&mut s, &compound).await;
    let messages = split_response_parts(&resp);
    assert_eq!(messages.len(), 2);
    assert_success_commands(&messages, &[Command::Read, Command::Read]);
    assert_eq!(
        ReadResponse::parse(messages[0].body)
            .expect("parse read")
            .data
            .as_slice(),
        &data[..64]
    );
    assert_eq!(
        ReadResponse::parse(messages[1].body)
            .expect("parse read")
            .data
            .as_slice(),
        &data[64..]
    );
    assert_related_ids(messages[1].header, session_id, tree_id);

    drop(s);
    handle.abort();
}

#[tokio::test]
async fn compound_related_read_write_read_uses_read_only_create_handle() {
    let (mut s, session_id, tree_id, handle, td) = setup().await;
    let fname = "compound-related6.dat";
    let seed_file_id =
        create_open_if_access(&mut s, session_id, tree_id, 4, fname, 0x001f_01ff).await;
    common::write_frame(
        &mut s,
        &build_header(Command::Write, 5, session_id, tree_id),
        &write_body(seed_file_id, 0, &[0; 64]),
    )
    .await;
    let seed_write = read_frame_with_timeout(&mut s).await;
    let (seed_write_hdr, seed_write_body) = parse_response_header(&seed_write);
    assert_eq!(seed_write_hdr.command, Command::Write);
    assert_eq!(seed_write_hdr.channel_sequence_status, STATUS_SUCCESS);
    assert_eq!(
        WriteResponse::parse(seed_write_body)
            .expect("parse seed write")
            .count,
        64
    );

    let placeholder = FileId::any();
    let mut compound = Vec::new();
    append_compound_part(
        &mut compound,
        &mut build_header(Command::Create, 6, session_id, tree_id),
        &create_body_access(fname, 3, 0x0000_0001),
        true,
    );
    let mut first_read_hdr = build_header(Command::Read, 7, u64::MAX, u32::MAX);
    first_read_hdr.flags |= SMB2_FLAGS_RELATED_OPERATIONS;
    append_compound_part(
        &mut compound,
        &mut first_read_hdr,
        &read_body(placeholder, 1, 0),
        true,
    );
    let mut write_hdr = build_header(Command::Write, 8, u64::MAX, u32::MAX);
    write_hdr.flags |= SMB2_FLAGS_RELATED_OPERATIONS;
    append_compound_part(
        &mut compound,
        &mut write_hdr,
        &write_body(placeholder, 0, &[1; 64]),
        true,
    );
    let mut second_read_hdr = build_header(Command::Read, 9, u64::MAX, u32::MAX);
    second_read_hdr.flags |= SMB2_FLAGS_RELATED_OPERATIONS;
    append_compound_part(
        &mut compound,
        &mut second_read_hdr,
        &read_body(placeholder, 1, 0),
        true,
    );
    let mut close_hdr = build_header(Command::Close, 10, u64::MAX, u32::MAX);
    close_hdr.flags |= SMB2_FLAGS_RELATED_OPERATIONS;
    append_compound_part(
        &mut compound,
        &mut close_hdr,
        &close_body(placeholder),
        false,
    );

    let statuses = send_compound_statuses(&mut s, &compound).await;
    assert_eq!(
        statuses,
        vec![
            (Command::Create, STATUS_SUCCESS),
            (Command::Read, STATUS_SUCCESS),
            (Command::Write, STATUS_ACCESS_DENIED),
            (Command::Read, STATUS_SUCCESS),
            (Command::Close, STATUS_SUCCESS),
        ]
    );
    assert_eq!(
        std::fs::read(td.path().join(fname))
            .expect("read data")
            .len(),
        64
    );

    drop(s);
    handle.abort();
}

#[tokio::test]
async fn tree_disconnect_finalizes_pending_delete_after_other_handle_closes() {
    let (mut s, session_id, tree_id, handle, td) = setup().await;
    let fname = "tree-disconnect-pending-delete.dat";
    let surviving = create_open_if_access(&mut s, session_id, tree_id, 4, fname, 0x001f_01ff).await;
    let delete_handle =
        create_open_if_access(&mut s, session_id, tree_id, 5, fname, 0x0001_0000).await;

    common::write_frame(
        &mut s,
        &build_header(Command::SetInfo, 6, session_id, tree_id),
        &file_disposition_body(delete_handle, true),
    )
    .await;
    let set_resp = read_frame_with_timeout(&mut s).await;
    let (set_hdr, set_body) = parse_response_header(&set_resp);
    assert_eq!(set_hdr.command, Command::SetInfo);
    assert_eq!(set_hdr.channel_sequence_status, STATUS_SUCCESS);
    let _ = smb_server::wire::messages::SetInfoResponse::parse(set_body)
        .expect("parse set-info response");

    common::write_frame(
        &mut s,
        &build_header(Command::Close, 7, session_id, tree_id),
        &close_body(delete_handle),
    )
    .await;
    let close_resp = read_frame_with_timeout(&mut s).await;
    let (close_hdr, close_body) = parse_response_header(&close_resp);
    assert_eq!(close_hdr.command, Command::Close);
    assert_eq!(close_hdr.channel_sequence_status, STATUS_SUCCESS);
    let _ = smb_server::wire::messages::CloseResponse::parse(close_body).expect("parse close");
    assert!(td.path().join(fname).exists(), "pending delete should wait");

    let mut disconnect_body = Vec::new();
    TreeDisconnectRequest::default()
        .write_to(&mut disconnect_body)
        .expect("write tree disconnect");
    common::write_frame(
        &mut s,
        &build_header(Command::TreeDisconnect, 8, session_id, tree_id),
        &disconnect_body,
    )
    .await;
    let disconnect_resp = read_frame_with_timeout(&mut s).await;
    let (disconnect_hdr, disconnect_body) = parse_response_header(&disconnect_resp);
    assert_eq!(disconnect_hdr.command, Command::TreeDisconnect);
    assert_eq!(disconnect_hdr.channel_sequence_status, STATUS_SUCCESS);
    let _ = TreeDisconnectResponse::parse(disconnect_body).expect("parse tree disconnect");
    assert!(
        !td.path().join(fname).exists(),
        "tree disconnect should finalize pending delete"
    );

    let _ = surviving;
    drop(s);
    handle.abort();
}

#[tokio::test]
async fn async_compound_related_rename_last_uses_related_file_id() {
    let (mut s, session_id, tree_id, handle, root, _td) = setup_smb311_with_path().await;
    let first_key = b"0123456789abcdef";

    let _first = create_lease_open(
        &mut s,
        session_id,
        tree_id,
        4,
        "compound_rename_last_src",
        0x0012_0089 | 0x0012_0116,
        lease_v2_request_with_key(0x0000_0001 | 0x0000_0002, first_key),
    )
    .await;

    let placeholder = FileId::any();
    let mut compound = Vec::new();
    append_compound_part(
        &mut compound,
        &mut build_header(Command::Create, 5, session_id, tree_id),
        &create_body_access("compound_rename_last_src", 1, 0x001f_01ff),
        true,
    );
    let mut set_info_hdr = build_header(Command::SetInfo, 6, u64::MAX, u32::MAX);
    set_info_hdr.flags |= SMB2_FLAGS_RELATED_OPERATIONS;
    append_compound_part(
        &mut compound,
        &mut set_info_hdr,
        &rename_body(placeholder, "compound_rename_last_dst", false),
        false,
    );

    let mut framed = Vec::new();
    encode_frame(&compound, &mut framed);
    s.write_all(&framed).await.expect("write compound");

    let notification_frame = read_frame_with_timeout(&mut s).await;
    let (rh, rb) = parse_response_header(&notification_frame);
    assert_eq!(rh.command, Command::OplockBreak);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let notification = LeaseBreakNotification::parse(rb).expect("parse lease break notification");
    assert_eq!(&notification.lease_key, first_key);
    assert_eq!(notification.current_lease_state, 0x0000_0001 | 0x0000_0002);
    assert_eq!(notification.new_lease_state, 0x0000_0001);

    let no_immediate = tokio::time::timeout(Duration::from_millis(50), read_frame(&mut s)).await;
    assert!(
        no_immediate.is_err(),
        "compound response arrived before lease break ACK"
    );

    send_lease_break_ack(&mut s, session_id, tree_id, 7, first_key, 0x0000_0001).await;
    let frames = [
        read_frame_with_timeout(&mut s).await,
        read_frame_with_timeout(&mut s).await,
    ];
    let mut saw_ack = false;
    let mut compound_response = None;
    for frame in frames {
        let (rh, _) = parse_response_header(&frame);
        match rh.command {
            Command::OplockBreak => {
                assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
                saw_ack = true;
            }
            Command::Create => compound_response = Some(frame),
            other => panic!("unexpected post-ack response command {other:?}"),
        }
    }
    assert!(saw_ack, "missing lease break ACK response");
    let compound_response = compound_response.expect("missing deferred compound response");
    let messages = split_response_headers(&compound_response);
    assert_eq!(messages.len(), 2);
    assert_eq!(messages[0].command, Command::Create);
    assert_eq!(messages[0].channel_sequence_status, STATUS_SUCCESS);
    assert_ne!(messages[0].next_command, 0);
    assert_eq!(messages[1].command, Command::SetInfo);
    assert_eq!(messages[1].channel_sequence_status, STATUS_SUCCESS);
    assert_eq!(messages[1].session_id, session_id);
    assert!(root.join("compound_rename_last_dst").exists());

    drop(s);
    handle.abort();
}

#[tokio::test]
async fn async_compound_create_query_info_close_final_includes_tail() {
    let (mut s, session_id, tree_id, handle, _root, _td) = setup_smb311_with_path().await;
    let first_key = b"0123456789abcdef";

    let _first = create_lease_open(
        &mut s,
        session_id,
        tree_id,
        4,
        "compound_async_getinfo",
        0x0012_0089 | 0x0012_0116,
        lease_v2_request_with_key(0x0000_0001 | 0x0000_0002 | 0x0000_0004, first_key),
    )
    .await;

    let placeholder = FileId::any();
    let query_placeholder = FileId::new(u64::MAX, 0);
    let mut compound = Vec::new();
    append_compound_part(
        &mut compound,
        &mut build_header(Command::Create, 5, session_id, tree_id),
        &create_body_access("compound_async_getinfo", 1, 0x001f_01ff),
        true,
    );
    let mut query_hdr = build_header(Command::QueryInfo, 6, u64::MAX, u32::MAX);
    query_hdr.flags |= SMB2_FLAGS_RELATED_OPERATIONS;
    append_compound_part(
        &mut compound,
        &mut query_hdr,
        &query_info_body(query_placeholder, 0x04, 4096),
        true,
    );
    let mut close_hdr = build_header(Command::Close, 7, u64::MAX, u32::MAX);
    close_hdr.flags |= SMB2_FLAGS_RELATED_OPERATIONS;
    append_compound_part(
        &mut compound,
        &mut close_hdr,
        &close_body(placeholder),
        false,
    );

    let mut framed = Vec::new();
    encode_frame(&compound, &mut framed);
    s.write_all(&framed).await.expect("write compound");

    let frames = [
        read_frame_with_timeout(&mut s).await,
        read_frame_with_timeout(&mut s).await,
    ];
    let mut pending_async_id = None;
    let mut saw_notification = false;
    for frame in frames {
        let (rh, rb) = parse_response_header(&frame);
        match rh.command {
            Command::Create => {
                assert_eq!(rh.channel_sequence_status, STATUS_PENDING);
                pending_async_id = rh.async_id();
            }
            Command::OplockBreak => {
                assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
                let notification =
                    LeaseBreakNotification::parse(rb).expect("parse lease break notification");
                assert_eq!(&notification.lease_key, first_key);
                assert_eq!(
                    notification.current_lease_state,
                    0x0000_0001 | 0x0000_0002 | 0x0000_0004
                );
                assert_eq!(notification.new_lease_state, 0x0000_0001 | 0x0000_0002);
                saw_notification = true;
            }
            other => panic!("unexpected response command {other:?}"),
        }
    }
    let pending_async_id = pending_async_id.expect("missing pending async id");
    assert!(saw_notification, "missing lease break notification");

    send_lease_break_ack(
        &mut s,
        session_id,
        tree_id,
        8,
        first_key,
        0x0000_0001 | 0x0000_0002,
    )
    .await;
    let frames = [
        read_frame_with_timeout(&mut s).await,
        read_frame_with_timeout(&mut s).await,
    ];
    let mut saw_ack = false;
    let mut compound_response = None;
    for frame in frames {
        let (rh, _) = parse_response_header(&frame);
        match rh.command {
            Command::OplockBreak => {
                assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
                saw_ack = true;
            }
            Command::Create => compound_response = Some(frame),
            other => panic!("unexpected post-ack response command {other:?}"),
        }
    }
    assert!(saw_ack, "missing lease break ACK response");
    let compound_response = compound_response.expect("missing deferred compound final");
    let messages = split_response_headers(&compound_response);
    assert_eq!(messages.len(), 3);
    assert_eq!(messages[0].command, Command::Create);
    assert_eq!(messages[0].channel_sequence_status, STATUS_SUCCESS);
    assert_eq!(messages[0].async_id(), Some(pending_async_id));
    assert_ne!(messages[0].next_command, 0);
    assert_eq!(messages[1].command, Command::QueryInfo);
    assert_eq!(messages[1].channel_sequence_status, STATUS_SUCCESS);
    assert_eq!(messages[1].session_id, session_id);
    assert_eq!(messages[1].tree_id(), Some(tree_id));
    assert_ne!(messages[1].next_command, 0);
    assert_eq!(messages[2].command, Command::Close);
    assert_eq!(messages[2].channel_sequence_status, STATUS_SUCCESS);
    assert_eq!(messages[2].session_id, session_id);
    assert_eq!(messages[2].tree_id(), Some(tree_id));

    drop(s);
    handle.abort();
}

async fn setup() -> (TcpStream, u64, u32, tokio::task::JoinHandle<()>, TempDir) {
    let td = tempdir().expect("tempdir");
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
    });
    tokio::task::yield_now().await;

    let mut s = TcpStream::connect(addr).await.expect("connect");
    let _ = negotiate(&mut s).await;
    let session_id = anonymous_session_setup(&mut s).await;
    let tree_id = tree_connect(&mut s, "\\\\127.0.0.1\\share", session_id, 3).await;
    (s, session_id, tree_id, handle, td)
}

async fn setup_smb311_with_path() -> (
    TcpStream,
    u64,
    u32,
    tokio::task::JoinHandle<()>,
    PathBuf,
    TempDir,
) {
    let td = tempdir().expect("tempdir");
    let root = td.path().to_path_buf();
    std::fs::write(root.join("compound_rename_last_src"), b"data").expect("seed rename file");
    std::fs::write(root.join("compound_async_getinfo"), b"data").expect("seed query file");
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
    });
    tokio::task::yield_now().await;

    let mut s = TcpStream::connect(addr).await.expect("connect");
    let _ = negotiate_smb311(&mut s).await;
    let session_id = anonymous_session_setup(&mut s).await;
    let tree_id = tree_connect(&mut s, "\\\\127.0.0.1\\share", session_id, 3).await;
    (s, session_id, tree_id, handle, root, td)
}

async fn negotiate_smb311(s: &mut TcpStream) -> NegotiateResponse {
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
        client_guid: [0x31; 16],
        negotiate_context_offset_or_client_start_time: u64::from(contexts_offset) | (1u64 << 32),
        dialects: vec![0x0311],
    };
    let mut body = Vec::new();
    neg_req.write_to(&mut body).expect("write negotiate");
    body.resize(contexts_offset as usize - 64, 0);
    body.extend_from_slice(&contexts_bytes);
    let hdr = build_header(Command::Negotiate, 0, 0, 0);
    common::write_frame(s, &hdr, &body).await;

    let resp = read_frame(s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Negotiate);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let neg_resp = NegotiateResponse::parse(rb).expect("parse neg resp");
    assert_eq!(neg_resp.dialect_revision, 0x0311);
    neg_resp
}

async fn read_frame_with_timeout(s: &mut TcpStream) -> Vec<u8> {
    tokio::time::timeout(Duration::from_secs(2), read_frame(s))
        .await
        .expect("timed out waiting for SMB response frame")
}

async fn create_lease_open(
    s: &mut TcpStream,
    session_id: u64,
    tree_id: u32,
    message_id: u64,
    name: &str,
    desired_access: u32,
    lease_data: Vec<u8>,
) -> CreateResponse {
    let body = create_body_access_with_contexts(
        name,
        1,
        desired_access,
        &[CreateContext {
            name: CreateContext::NAME_RQLS.to_vec(),
            data: lease_data,
        }],
    );
    let hdr = build_header(Command::Create, message_id, session_id, tree_id);
    common::write_frame(s, &hdr, &body).await;
    let resp = read_frame_with_timeout(s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Create);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    CreateResponse::parse(rb).expect("parse lease create")
}

async fn create_open(
    s: &mut TcpStream,
    session_id: u64,
    tree_id: u32,
    message_id: u64,
    name: &str,
) -> FileId {
    let body = create_body(name, 1);
    let hdr = build_header(Command::Create, message_id, session_id, tree_id);
    common::write_frame(s, &hdr, &body).await;
    let resp = read_frame_with_timeout(s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Create);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    CreateResponse::parse(rb).expect("parse create").file_id
}

async fn create_open_if_access(
    s: &mut TcpStream,
    session_id: u64,
    tree_id: u32,
    message_id: u64,
    name: &str,
    desired_access: u32,
) -> FileId {
    let body = create_body_access(name, 3, desired_access);
    let hdr = build_header(Command::Create, message_id, session_id, tree_id);
    common::write_frame(s, &hdr, &body).await;
    let resp = read_frame_with_timeout(s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Create);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    CreateResponse::parse(rb).expect("parse create").file_id
}

async fn create_directory_open(
    s: &mut TcpStream,
    session_id: u64,
    tree_id: u32,
    message_id: u64,
    name: &str,
) -> FileId {
    let body = create_body_custom(name, 1, 0x001f_01ff, 0x0000_0001);
    let hdr = build_header(Command::Create, message_id, session_id, tree_id);
    common::write_frame(s, &hdr, &body).await;
    let resp = read_frame_with_timeout(s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Create);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    CreateResponse::parse(rb)
        .expect("parse directory create")
        .file_id
}

async fn send_query_directory_status(
    s: &mut TcpStream,
    session_id: u64,
    tree_id: u32,
    message_id: u64,
    file_id: FileId,
) -> u32 {
    let body = query_directory_body(file_id, 0x100);
    let hdr = build_header(Command::QueryDirectory, message_id, session_id, tree_id);
    common::write_frame(s, &hdr, &body).await;
    let resp = read_frame_with_timeout(s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::QueryDirectory);
    if rh.channel_sequence_status == STATUS_SUCCESS {
        let _ = QueryDirectoryResponse::parse(rb).expect("parse qdir");
    }
    rh.channel_sequence_status
}

async fn send_lease_break_ack(
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
    common::write_frame(s, &hdr, &body).await;
}

fn create_body(name: &str, create_disposition: u32) -> Vec<u8> {
    create_body_access(name, create_disposition, 0x0012_0089 | 0x0012_0116)
}

fn create_body_access(name: &str, create_disposition: u32, desired_access: u32) -> Vec<u8> {
    create_body_access_with_contexts(name, create_disposition, desired_access, &[])
}

fn create_body_access_with_contexts(
    name: &str,
    create_disposition: u32,
    desired_access: u32,
    contexts: &[CreateContext],
) -> Vec<u8> {
    create_body_custom_with_contexts(name, create_disposition, desired_access, 0, contexts)
}

fn create_body_custom(
    name: &str,
    create_disposition: u32,
    desired_access: u32,
    create_options: u32,
) -> Vec<u8> {
    create_body_custom_with_contexts(
        name,
        create_disposition,
        desired_access,
        create_options,
        &[],
    )
}

fn create_body_custom_with_contexts(
    name: &str,
    create_disposition: u32,
    desired_access: u32,
    create_options: u32,
    contexts: &[CreateContext],
) -> Vec<u8> {
    let name = utf16le(name);
    let req = CreateRequest {
        structure_size: 57,
        security_flags: 0,
        requested_oplock_level: if contexts.is_empty() { 0 } else { 0xff },
        impersonation_level: 2,
        smb_create_flags: 0,
        reserved: 0,
        desired_access,
        file_attributes: 0,
        share_access: 0x0000_0007,
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
    if contexts.is_empty() {
        req.write_to(&mut body).expect("write create");
    } else {
        body = create_request_with_contexts(req, contexts);
    }
    body
}

fn create_request_with_contexts(req: CreateRequest, contexts: &[CreateContext]) -> Vec<u8> {
    let mut context_bytes = Vec::new();
    CreateContext::encode_chain(contexts, &mut context_bytes).expect("encode create contexts");
    let mut req = req;
    req.create_contexts_offset = 64 + 56 + req.name.len() as u32;
    req.create_contexts_offset = align_8(req.create_contexts_offset as usize) as u32;
    req.create_contexts_length = context_bytes.len() as u32;
    let mut body = Vec::new();
    req.write_to(&mut body).expect("write create");
    body.resize(req.create_contexts_offset as usize - 64, 0);
    body.extend_from_slice(&context_bytes);
    body
}

fn rename_body(file_id: FileId, target: &str, replace: bool) -> Vec<u8> {
    let name = utf16le(target);
    let mut rename = vec![0; 20 + name.len()];
    rename[0] = u8::from(replace);
    rename[16..20].copy_from_slice(&(name.len() as u32).to_le_bytes());
    rename[20..].copy_from_slice(&name);
    let req = SetInfoRequest {
        structure_size: 33,
        info_type: InfoType::File as u8,
        file_information_class: 0x0A,
        buffer_length: rename.len() as u32,
        buffer_offset: 64 + 32,
        reserved: 0,
        additional_information: 0,
        file_id,
        buffer: rename,
    };
    let mut body = Vec::new();
    req.write_to(&mut body).expect("write set-info rename");
    body
}

fn query_info_body(
    file_id: FileId,
    file_information_class: u8,
    output_buffer_length: u32,
) -> Vec<u8> {
    let req = QueryInfoRequest {
        structure_size: 41,
        info_type: InfoType::File as u8,
        file_information_class,
        output_buffer_length,
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
    body
}

fn lease_v2_request_with_key(state: u32, key: &[u8; 16]) -> Vec<u8> {
    let mut data = vec![0; 52];
    data[0..16].copy_from_slice(key);
    data[16..20].copy_from_slice(&state.to_le_bytes());
    data[48..50].copy_from_slice(&7u16.to_le_bytes());
    data
}

fn close_body(file_id: FileId) -> Vec<u8> {
    let req = CloseRequest {
        structure_size: 24,
        flags: 0,
        reserved: 0,
        file_id,
    };
    let mut body = Vec::new();
    req.write_to(&mut body).expect("write close");
    body
}

fn flush_body(file_id: FileId) -> Vec<u8> {
    let req = FlushRequest::new(file_id.persistent, file_id.volatile);
    let mut body = Vec::new();
    req.write_to(&mut body).expect("write flush");
    body
}

fn ioctl_body(file_id: FileId, ctl_code: u32, max_output_response: u32) -> Vec<u8> {
    let req = IoctlRequest {
        structure_size: 57,
        reserved: 0,
        ctl_code,
        file_id,
        input_offset: 64 + 56,
        input_count: 0,
        max_input_response: 0,
        output_offset: 0,
        output_count: 0,
        max_output_response,
        flags: IoctlRequest::FLAG_IS_FSCTL,
        reserved2: 0,
        input: Vec::new(),
    };
    let mut body = Vec::new();
    req.write_to(&mut body).expect("write ioctl");
    body
}

fn file_disposition_body(file_id: FileId, delete: bool) -> Vec<u8> {
    let req = SetInfoRequest {
        structure_size: 33,
        info_type: InfoType::File as u8,
        file_information_class: 0x0D,
        buffer_length: 1,
        buffer_offset: 64 + 32,
        reserved: 0,
        additional_information: 0,
        file_id,
        buffer: vec![u8::from(delete)],
    };
    let mut body = Vec::new();
    req.write_to(&mut body).expect("write disposition");
    body
}

fn read_body(file_id: FileId, length: u32, offset: u64) -> Vec<u8> {
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
    body
}

fn write_body(file_id: FileId, offset: u64, data: &[u8]) -> Vec<u8> {
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
    body
}

fn query_directory_body(file_id: FileId, output_buffer_length: u32) -> Vec<u8> {
    let pattern = utf16le("*");
    let req = QueryDirectoryRequest {
        structure_size: 33,
        file_information_class: FileInfoClass::FileBothDirectoryInformation as u8,
        flags: 0,
        file_index: 0,
        file_id,
        file_name_offset: 0x60,
        file_name_length: pattern.len() as u16,
        output_buffer_length,
        file_name: pattern,
    };
    let mut body = Vec::new();
    req.write_to(&mut body).expect("write query directory");
    body
}

fn file_both_directory_names(mut buf: &[u8]) -> Vec<String> {
    let mut names = Vec::new();
    loop {
        assert!(
            buf.len() >= 94,
            "short FileBothDirectoryInformation record: {}",
            buf.len()
        );
        let next = u32::from_le_bytes(buf[0..4].try_into().unwrap()) as usize;
        let name_len = u32::from_le_bytes(buf[60..64].try_into().unwrap()) as usize;
        assert!(buf.len() >= 94 + name_len, "short file name");
        let units: Vec<u16> = buf[94..94 + name_len]
            .chunks_exact(2)
            .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
            .collect();
        names.push(String::from_utf16(&units).expect("utf16 name"));
        if next == 0 {
            break;
        }
        assert!(buf.len() >= next, "invalid next entry offset");
        buf = &buf[next..];
    }
    names
}

async fn send_compound_response(s: &mut TcpStream, compound: &[u8]) -> Vec<u8> {
    let mut framed = Vec::new();
    encode_frame(compound, &mut framed);
    s.write_all(&framed).await.expect("write compound");
    read_frame(s).await
}

async fn send_compound_statuses(s: &mut TcpStream, compound: &[u8]) -> Vec<(Command, u32)> {
    let resp = send_compound_response(s, compound).await;
    let mut offset = 0;
    let mut out = Vec::new();
    loop {
        let (hdr, body) = parse_response_header(&resp[offset..]);
        if hdr.command == Command::Create && hdr.channel_sequence_status == STATUS_SUCCESS {
            let _ = CreateResponse::parse(body).expect("parse create");
        }
        out.push((hdr.command, hdr.channel_sequence_status));
        if hdr.next_command == 0 {
            break;
        }
        offset += hdr.next_command as usize;
    }
    out
}

#[derive(Debug, Clone, Copy)]
struct ResponsePart<'a> {
    header: Smb2Header,
    body: &'a [u8],
}

fn split_response_parts(resp: &[u8]) -> Vec<ResponsePart<'_>> {
    let mut offset = 0;
    let mut out = Vec::new();
    loop {
        let (header, body) = parse_response_header(&resp[offset..]);
        out.push(ResponsePart { header, body });
        if header.next_command == 0 {
            break;
        }
        offset += header.next_command as usize;
    }
    out
}

fn assert_success_commands(messages: &[ResponsePart<'_>], commands: &[Command]) {
    assert_eq!(messages.len(), commands.len());
    for (index, (message, command)) in messages.iter().zip(commands).enumerate() {
        assert_eq!(
            message.header.command, *command,
            "response[{index}] command"
        );
        assert_eq!(
            message.header.channel_sequence_status, STATUS_SUCCESS,
            "response[{index}] status"
        );
        if index + 1 == commands.len() {
            assert_eq!(message.header.next_command, 0);
        } else {
            assert_ne!(message.header.next_command, 0);
        }
    }
}

fn assert_related_ids(header: Smb2Header, session_id: u64, tree_id: u32) {
    assert_eq!(header.session_id, session_id);
    assert_eq!(header.tree_id(), Some(tree_id));
}

fn split_response_headers(resp: &[u8]) -> Vec<Smb2Header> {
    let mut offset = 0;
    let mut out = Vec::new();
    loop {
        let (hdr, _) = parse_response_header(&resp[offset..]);
        out.push(hdr);
        if hdr.next_command == 0 {
            break;
        }
        offset += hdr.next_command as usize;
    }
    out
}

fn append_compound_part(
    compound: &mut Vec<u8>,
    header: &mut Smb2Header,
    body: &[u8],
    has_next: bool,
) {
    let message_len = 64 + body.len();
    header.next_command = if has_next {
        align_8(message_len) as u32
    } else {
        0
    };
    header.write(compound).expect("compound header");
    compound.extend_from_slice(body);
    if has_next {
        compound.resize(compound.len() + align_8(message_len) - message_len, 0);
    }
}

const fn align_8(n: usize) -> usize {
    (n + 7) & !7
}
