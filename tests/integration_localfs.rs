#![allow(clippy::too_many_arguments)]

//! Cross-stack integration test: drive a real `SmbServer` backed by
//! `LocalFsBackend` over a TCP loopback through the full
//! NEGOTIATE → SESSION_SETUP (anonymous) → TREE_CONNECT → CREATE → READ →
//! CLOSE → TREE_DISCONNECT → LOGOFF flow.
//!
//! Hand-crafts the request bytes since the workspace does not depend on an SMB
//! client crate.

mod common;

use async_trait::async_trait;
use bytes::Bytes;
use common::encode_frame;
use common::{
    STATUS_SUCCESS, anonymous_session_setup, build_header, negotiate, negotiate_smb311,
    parse_response_header, read_frame, tree_connect, tree_connect_status, utf16le, write_frame,
};
use smb_server::wire::header::{
    Command, HeaderTail, SMB2_FLAGS_ASYNC_COMMAND, SMB2_FLAGS_RELATED_OPERATIONS, Smb2Header,
};
use smb_server::wire::messages::{
    CancelRequest, ChangeNotifyRequest, ChangeNotifyResponse, CloseRequest, CloseResponse,
    CreateContext, CreateRequest, CreateResponse, EchoRequest, EchoResponse, FileId, FileInfoClass,
    FlushRequest, FlushResponse, InfoType, LogoffRequest, LogoffResponse, QueryDirectoryRequest,
    QueryDirectoryResponse, QueryInfoRequest, QueryInfoResponse, ReadRequest, ReadResponse,
    SetInfoRequest, TreeDisconnectRequest, TreeDisconnectResponse,
};
use smb_server::{
    BackendCapabilities, DirEntry, FileInfo, FileTimes, Handle, LocalFsBackend, OpenOptions,
    ShareBackend, SmbError, SmbPath, SmbResult,
};
use smb_server::{Share, SmbServer};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use tempfile::tempdir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Barrier;
use tokio::time::{Duration, sleep};

const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_END_OF_FILE: u32 = 0xC000_0011;
const STATUS_PENDING: u32 = 0x0000_0103;
const STATUS_NOTIFY_CLEANUP: u32 = 0x0000_010B;
const STATUS_NOTIFY_ENUM_DIR: u32 = 0x0000_010C;
const STATUS_BUFFER_OVERFLOW: u32 = 0x8000_0005;
const STATUS_NO_MORE_FILES: u32 = 0x8000_0006;
const STATUS_INVALID_INFO_CLASS: u32 = 0xC000_0003;
const STATUS_INFO_LENGTH_MISMATCH: u32 = 0xC000_0004;
const STATUS_OBJECT_NAME_INVALID: u32 = 0xC000_0033;
const STATUS_OBJECT_NAME_NOT_FOUND: u32 = 0xC000_0034;
const STATUS_OBJECT_NAME_COLLISION: u32 = 0xC000_0035;
const STATUS_OBJECT_PATH_NOT_FOUND: u32 = 0xC000_003A;
const STATUS_ACCESS_DENIED: u32 = 0xC000_0022;
const STATUS_BUFFER_TOO_SMALL: u32 = 0xC000_0023;
const STATUS_NO_SUCH_FILE: u32 = 0xC000_000F;
const STATUS_SHARING_VIOLATION: u32 = 0xC000_0043;
const STATUS_DELETE_PENDING: u32 = 0xC000_0056;
const STATUS_FILE_IS_A_DIRECTORY: u32 = 0xC000_00BA;
const STATUS_NOT_A_DIRECTORY: u32 = 0xC000_0103;
const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;
const STATUS_NOT_SUPPORTED: u32 = 0xC000_00BB;
const STATUS_BAD_IMPERSONATION_LEVEL: u32 = 0xC000_00A5;
const STATUS_CANCELLED: u32 = 0xC000_0120;
const STATUS_FILE_CLOSED: u32 = 0xC000_0128;
const STATUS_USER_SESSION_DELETED: u32 = 0xC000_0203;
const STATUS_NETWORK_NAME_DELETED: u32 = 0xC000_00C9;
const FILE_ATTRIBUTE_READONLY: u32 = 0x0000_0001;
const FILE_ATTRIBUTE_HIDDEN: u32 = 0x0000_0002;
const FILE_ATTRIBUTE_SYSTEM: u32 = 0x0000_0004;
const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x0000_0010;
const FILE_ATTRIBUTE_ARCHIVE: u32 = 0x0000_0020;
const FILE_ATTRIBUTE_NORMAL: u32 = 0x0000_0080;
const FILE_ATTRIBUTE_TEMPORARY: u32 = 0x0000_0100;
const FILE_ATTRIBUTE_ENCRYPTED: u32 = 0x0000_4000;

fn create_request_with_context(name: &str, req: CreateRequest, ctx: CreateContext) -> Vec<u8> {
    create_request_with_contexts(name, req, &[ctx])
}

fn create_request_with_contexts(
    name: &str,
    mut req: CreateRequest,
    contexts_in: &[CreateContext],
) -> Vec<u8> {
    req.name = utf16le(name);
    req.name_offset = 64 + 56;
    req.name_length = req.name.len() as u16;
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
    req.write_to(&mut body)
        .expect("write create with ctx header");
    body.resize(context_offset, 0);
    body.extend_from_slice(&contexts);
    body
}

fn create_request(
    name: &str,
    desired_access: u32,
    file_attributes: u32,
    create_disposition: u32,
    create_options: u32,
) -> CreateRequest {
    let name = utf16le(name);
    CreateRequest {
        structure_size: 57,
        security_flags: 0,
        requested_oplock_level: 0,
        impersonation_level: 2,
        smb_create_flags: 0,
        reserved: 0,
        desired_access,
        file_attributes,
        share_access: 0x0000_0007,
        create_disposition,
        create_options,
        name_offset: 0x78,
        name_length: name.len() as u16,
        create_contexts_offset: 0,
        create_contexts_length: 0,
        name,
        create_contexts: vec![],
    }
}

async fn send_create_request(
    s: &mut TcpStream,
    message_id: u64,
    session_id: u64,
    tree_id: u32,
    req: CreateRequest,
) -> (Smb2Header, Option<CreateResponse>) {
    let mut body = Vec::new();
    req.write_to(&mut body).expect("write create");
    let hdr = build_header(Command::Create, message_id, session_id, tree_id);
    write_frame(s, &hdr, &body).await;
    let resp = read_frame(s).await;
    let (rh, rb) = parse_response_header(&resp);
    let create = if rh.channel_sequence_status == STATUS_SUCCESS {
        Some(CreateResponse::parse(rb).expect("parse create resp"))
    } else {
        None
    };
    (rh, create)
}

async fn send_close_request(
    s: &mut TcpStream,
    message_id: u64,
    session_id: u64,
    tree_id: u32,
    file_id: FileId,
) -> u32 {
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
    if rh.channel_sequence_status == STATUS_SUCCESS {
        let _ = CloseResponse::parse(rb).expect("parse close resp");
    }
    rh.channel_sequence_status
}

async fn send_flush_status(
    s: &mut TcpStream,
    message_id: u64,
    session_id: u64,
    tree_id: u32,
    file_id: FileId,
) -> u32 {
    let req = FlushRequest::new(file_id.persistent, file_id.volatile);
    let mut body = Vec::new();
    req.write_to(&mut body).expect("write flush");
    let hdr = build_header(Command::Flush, message_id, session_id, tree_id);
    write_frame(s, &hdr, &body).await;
    let resp = read_frame(s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Flush);
    if rh.channel_sequence_status == STATUS_SUCCESS {
        let _ = FlushResponse::parse(rb).expect("parse flush resp");
    }
    rh.channel_sequence_status
}

async fn send_echo_status(s: &mut TcpStream, message_id: u64, session_id: u64) -> u32 {
    let mut body = Vec::new();
    EchoRequest::default()
        .write_to(&mut body)
        .expect("write echo");
    let hdr = build_header(Command::Echo, message_id, session_id, 0);
    write_frame(s, &hdr, &body).await;
    let resp = read_frame(s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Echo);
    if rh.channel_sequence_status == STATUS_SUCCESS {
        let _ = EchoResponse::parse(rb).expect("parse echo resp");
    }
    rh.channel_sequence_status
}

async fn set_file_disposition_status(
    s: &mut TcpStream,
    message_id: u64,
    session_id: u64,
    tree_id: u32,
    file_id: FileId,
    delete_on_close: bool,
) -> u32 {
    let req = SetInfoRequest {
        structure_size: 33,
        info_type: InfoType::File as u8,
        file_information_class: 0x0D,
        buffer_length: 1,
        buffer_offset: 64 + 32,
        reserved: 0,
        additional_information: 0,
        file_id,
        buffer: vec![u8::from(delete_on_close)],
    };
    let mut body = Vec::new();
    req.write_to(&mut body).expect("write disposition");
    let hdr = build_header(Command::SetInfo, message_id, session_id, tree_id);
    write_frame(s, &hdr, &body).await;
    let resp = read_frame(s).await;
    let (rh, _rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::SetInfo);
    rh.channel_sequence_status
}

async fn set_file_rename_status(
    s: &mut TcpStream,
    message_id: u64,
    session_id: u64,
    tree_id: u32,
    file_id: FileId,
    name: &str,
    replace_if_exists: bool,
) -> u32 {
    let buffer = file_rename_information(name, replace_if_exists);
    let req = SetInfoRequest {
        structure_size: 33,
        info_type: InfoType::File as u8,
        file_information_class: 0x0A,
        buffer_length: buffer.len() as u32,
        buffer_offset: 64 + 32,
        reserved: 0,
        additional_information: 0,
        file_id,
        buffer,
    };
    let mut body = Vec::new();
    req.write_to(&mut body).expect("write rename");
    let hdr = build_header(Command::SetInfo, message_id, session_id, tree_id);
    write_frame(s, &hdr, &body).await;
    let resp = read_frame(s).await;
    let (rh, _rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::SetInfo);
    rh.channel_sequence_status
}

async fn query_basic_attributes(
    s: &mut TcpStream,
    message_id: u64,
    session_id: u64,
    tree_id: u32,
    file_id: FileId,
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
    req.write_to(&mut body).expect("write query basic");
    let hdr = build_header(Command::QueryInfo, message_id, session_id, tree_id);
    write_frame(s, &hdr, &body).await;
    let resp = read_frame(s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::QueryInfo);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let query = QueryInfoResponse::parse(rb).expect("parse query basic resp");
    u32::from_le_bytes(query.buffer[32..36].try_into().unwrap())
}

async fn query_security_descriptor(
    s: &mut TcpStream,
    message_id: u64,
    session_id: u64,
    tree_id: u32,
    file_id: FileId,
) -> Vec<u8> {
    let (status, buffer) =
        query_security_descriptor_with_flags(s, message_id, session_id, tree_id, file_id, 0).await;
    assert_eq!(status, STATUS_SUCCESS);
    buffer
}

async fn query_security_descriptor_with_flags(
    s: &mut TcpStream,
    message_id: u64,
    session_id: u64,
    tree_id: u32,
    file_id: FileId,
    additional_information: u32,
) -> (u32, Vec<u8>) {
    let req = QueryInfoRequest {
        structure_size: 41,
        info_type: InfoType::Security as u8,
        file_information_class: 0,
        output_buffer_length: 4096,
        input_buffer_offset: 0,
        reserved: 0,
        input_buffer_length: 0,
        additional_information,
        flags: 0,
        file_id,
        input_buffer: vec![],
    };
    let mut body = Vec::new();
    req.write_to(&mut body).expect("write security query");
    let hdr = build_header(Command::QueryInfo, message_id, session_id, tree_id);
    write_frame(s, &hdr, &body).await;
    let resp = read_frame(s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::QueryInfo);
    let buffer = if rh.channel_sequence_status == STATUS_SUCCESS {
        QueryInfoResponse::parse(rb)
            .expect("parse security query resp")
            .buffer
    } else {
        Vec::new()
    };
    (rh.channel_sequence_status, buffer)
}

async fn query_security_descriptor_status(
    s: &mut TcpStream,
    message_id: u64,
    session_id: u64,
    tree_id: u32,
    file_id: FileId,
    output_buffer_length: u32,
) -> u32 {
    let req = QueryInfoRequest {
        structure_size: 41,
        info_type: InfoType::Security as u8,
        file_information_class: 0,
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
    req.write_to(&mut body)
        .expect("write security status query");
    let hdr = build_header(Command::QueryInfo, message_id, session_id, tree_id);
    write_frame(s, &hdr, &body).await;
    let resp = read_frame(s).await;
    let (rh, _rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::QueryInfo);
    rh.channel_sequence_status
}

async fn query_file_stream_information(
    s: &mut TcpStream,
    message_id: u64,
    session_id: u64,
    tree_id: u32,
    file_id: FileId,
) -> Vec<(String, u64)> {
    let req = QueryInfoRequest {
        structure_size: 41,
        info_type: InfoType::File as u8,
        file_information_class: 0x16,
        output_buffer_length: 4096,
        input_buffer_offset: 0,
        reserved: 0,
        input_buffer_length: 0,
        additional_information: 0,
        flags: 0,
        file_id,
        input_buffer: vec![],
    };
    let mut body = Vec::new();
    req.write_to(&mut body).expect("write stream query");
    let hdr = build_header(Command::QueryInfo, message_id, session_id, tree_id);
    write_frame(s, &hdr, &body).await;
    let resp = read_frame(s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::QueryInfo);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let query = QueryInfoResponse::parse(rb).expect("parse stream query resp");
    decode_stream_information(&query.buffer)
}

async fn query_file_all_information(
    s: &mut TcpStream,
    message_id: u64,
    session_id: u64,
    tree_id: u32,
    file_id: FileId,
) -> Vec<u8> {
    let req = QueryInfoRequest {
        structure_size: 41,
        info_type: InfoType::File as u8,
        file_information_class: 0x12,
        output_buffer_length: 4096,
        input_buffer_offset: 0,
        reserved: 0,
        input_buffer_length: 0,
        additional_information: 0,
        flags: 0,
        file_id,
        input_buffer: vec![],
    };
    let mut body = Vec::new();
    req.write_to(&mut body).expect("write all-info query");
    let hdr = build_header(Command::QueryInfo, message_id, session_id, tree_id);
    write_frame(s, &hdr, &body).await;
    let resp = read_frame(s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::QueryInfo);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    QueryInfoResponse::parse(rb)
        .expect("parse all-info query resp")
        .buffer
}

async fn query_file_information_class(
    s: &mut TcpStream,
    message_id: u64,
    session_id: u64,
    tree_id: u32,
    file_id: FileId,
    file_information_class: u8,
    output_buffer_length: u32,
) -> (u32, Vec<u8>) {
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
    req.write_to(&mut body).expect("write file-info query");
    let hdr = build_header(Command::QueryInfo, message_id, session_id, tree_id);
    write_frame(s, &hdr, &body).await;
    let resp = read_frame(s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::QueryInfo);
    let buffer = if rh.channel_sequence_status == STATUS_SUCCESS
        || rh.channel_sequence_status == STATUS_BUFFER_OVERFLOW
    {
        QueryInfoResponse::parse(rb)
            .expect("parse file-info query resp")
            .buffer
    } else {
        Vec::new()
    };
    (rh.channel_sequence_status, buffer)
}

async fn query_filesystem_information_class(
    s: &mut TcpStream,
    message_id: u64,
    session_id: u64,
    tree_id: u32,
    file_id: FileId,
    file_information_class: u8,
    output_buffer_length: u32,
) -> (u32, Vec<u8>) {
    let req = QueryInfoRequest {
        structure_size: 41,
        info_type: InfoType::FileSystem as u8,
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
    req.write_to(&mut body)
        .expect("write filesystem-info query");
    let hdr = build_header(Command::QueryInfo, message_id, session_id, tree_id);
    write_frame(s, &hdr, &body).await;
    let resp = read_frame(s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::QueryInfo);
    let buffer = if rh.channel_sequence_status == STATUS_SUCCESS
        || rh.channel_sequence_status == STATUS_BUFFER_OVERFLOW
    {
        QueryInfoResponse::parse(rb)
            .expect("parse filesystem-info query resp")
            .buffer
    } else {
        Vec::new()
    };
    (rh.channel_sequence_status, buffer)
}

async fn query_file_name_information(
    s: &mut TcpStream,
    message_id: u64,
    session_id: u64,
    tree_id: u32,
    file_id: FileId,
) -> String {
    let req = QueryInfoRequest {
        structure_size: 41,
        info_type: InfoType::File as u8,
        file_information_class: 0x09,
        output_buffer_length: 4096,
        input_buffer_offset: 0,
        reserved: 0,
        input_buffer_length: 0,
        additional_information: 0,
        flags: 0,
        file_id,
        input_buffer: vec![],
    };
    let mut body = Vec::new();
    req.write_to(&mut body).expect("write name query");
    let hdr = build_header(Command::QueryInfo, message_id, session_id, tree_id);
    write_frame(s, &hdr, &body).await;
    let resp = read_frame(s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::QueryInfo);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let query = QueryInfoResponse::parse(rb).expect("parse name query resp");
    decode_file_name_information(&query.buffer)
}

async fn query_file_normalized_name_information(
    s: &mut TcpStream,
    message_id: u64,
    session_id: u64,
    tree_id: u32,
    file_id: FileId,
) -> String {
    let (status, name) =
        query_file_normalized_name_information_status(s, message_id, session_id, tree_id, file_id)
            .await;
    assert_eq!(status, STATUS_SUCCESS);
    name.expect("normalized name")
}

async fn query_file_normalized_name_information_status(
    s: &mut TcpStream,
    message_id: u64,
    session_id: u64,
    tree_id: u32,
    file_id: FileId,
) -> (u32, Option<String>) {
    let req = QueryInfoRequest {
        structure_size: 41,
        info_type: InfoType::File as u8,
        file_information_class: 0x30,
        output_buffer_length: 4096,
        input_buffer_offset: 0,
        reserved: 0,
        input_buffer_length: 0,
        additional_information: 0,
        flags: 0,
        file_id,
        input_buffer: vec![],
    };
    let mut body = Vec::new();
    req.write_to(&mut body)
        .expect("write normalized-name query");
    let hdr = build_header(Command::QueryInfo, message_id, session_id, tree_id);
    write_frame(s, &hdr, &body).await;
    let resp = read_frame(s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::QueryInfo);
    if rh.channel_sequence_status != STATUS_SUCCESS {
        return (rh.channel_sequence_status, None);
    }
    let query = QueryInfoResponse::parse(rb).expect("parse normalized-name query resp");
    (
        rh.channel_sequence_status,
        Some(decode_file_name_information(&query.buffer)),
    )
}

async fn query_directory_file_id_both_names(
    s: &mut TcpStream,
    message_id: u64,
    session_id: u64,
    tree_id: u32,
    file_id: FileId,
    flags: u8,
    file_index: u32,
    output_buffer_length: u32,
    pattern: &str,
) -> (u32, Vec<String>) {
    let pattern = utf16le(pattern);
    let req = QueryDirectoryRequest {
        structure_size: 33,
        file_information_class: FileInfoClass::FileIdBothDirectoryInformation as u8,
        flags,
        file_index,
        file_id,
        file_name_offset: 64 + 32,
        file_name_length: pattern.len() as u16,
        output_buffer_length,
        file_name: pattern,
    };
    let mut body = Vec::new();
    req.write_to(&mut body).expect("write query directory");
    let hdr = build_header(Command::QueryDirectory, message_id, session_id, tree_id);
    write_frame(s, &hdr, &body).await;
    let resp = read_frame(s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::QueryDirectory);
    if rh.channel_sequence_status != STATUS_SUCCESS {
        return (rh.channel_sequence_status, Vec::new());
    }
    let qd_resp = QueryDirectoryResponse::parse(rb).expect("parse query directory resp");
    (
        rh.channel_sequence_status,
        decode_file_id_both_names(&qd_resp.buffer),
    )
}

async fn query_directory_file_id_both_entries(
    s: &mut TcpStream,
    message_id: u64,
    session_id: u64,
    tree_id: u32,
    file_id: FileId,
    flags: u8,
    output_buffer_length: u32,
    pattern: &str,
) -> (u32, Vec<(String, u32)>) {
    let pattern = utf16le(pattern);
    let req = QueryDirectoryRequest {
        structure_size: 33,
        file_information_class: FileInfoClass::FileIdBothDirectoryInformation as u8,
        flags,
        file_index: 0,
        file_id,
        file_name_offset: 64 + 32,
        file_name_length: pattern.len() as u16,
        output_buffer_length,
        file_name: pattern,
    };
    let mut body = Vec::new();
    req.write_to(&mut body).expect("write query directory");
    let hdr = build_header(Command::QueryDirectory, message_id, session_id, tree_id);
    write_frame(s, &hdr, &body).await;
    let resp = read_frame(s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::QueryDirectory);
    if rh.channel_sequence_status != STATUS_SUCCESS {
        return (rh.channel_sequence_status, Vec::new());
    }
    let qd_resp = QueryDirectoryResponse::parse(rb).expect("parse query directory resp");
    (
        rh.channel_sequence_status,
        decode_file_id_both_entries(&qd_resp.buffer),
    )
}

async fn query_directory_status_for_class(
    s: &mut TcpStream,
    message_id: u64,
    session_id: u64,
    tree_id: u32,
    file_id: FileId,
    file_information_class: u8,
) -> u32 {
    let pattern = utf16le("*");
    let req = QueryDirectoryRequest {
        structure_size: 33,
        file_information_class,
        flags: QueryDirectoryRequest::FLAG_RESTART_SCANS,
        file_index: 0,
        file_id,
        file_name_offset: 64 + 32,
        file_name_length: pattern.len() as u16,
        output_buffer_length: 256,
        file_name: pattern,
    };
    let mut body = Vec::new();
    req.write_to(&mut body).expect("write query directory");
    let hdr = build_header(Command::QueryDirectory, message_id, session_id, tree_id);
    write_frame(s, &hdr, &body).await;
    let resp = read_frame(s).await;
    let (rh, _rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::QueryDirectory);
    rh.channel_sequence_status
}

async fn query_directory_names_for_class(
    s: &mut TcpStream,
    message_id: u64,
    session_id: u64,
    tree_id: u32,
    file_id: FileId,
    file_information_class: u8,
    pattern: &str,
) -> (u32, Vec<String>) {
    query_directory_names_for_class_with_controls(
        s,
        message_id,
        session_id,
        tree_id,
        file_id,
        file_information_class,
        QueryDirectoryRequest::FLAG_RESTART_SCANS,
        0,
        1024,
        pattern,
    )
    .await
}

async fn query_directory_names_for_class_with_controls(
    s: &mut TcpStream,
    message_id: u64,
    session_id: u64,
    tree_id: u32,
    file_id: FileId,
    file_information_class: u8,
    flags: u8,
    file_index: u32,
    output_buffer_length: u32,
    pattern: &str,
) -> (u32, Vec<String>) {
    let (status, buffer) = query_directory_buffer_for_class_with_controls(
        s,
        message_id,
        session_id,
        tree_id,
        file_id,
        file_information_class,
        flags,
        file_index,
        output_buffer_length,
        pattern,
    )
    .await;
    if status != STATUS_SUCCESS {
        return (status, Vec::new());
    }
    (
        status,
        decode_query_directory_names_for_class(&buffer, file_information_class),
    )
}

async fn query_directory_buffer_for_class(
    s: &mut TcpStream,
    message_id: u64,
    session_id: u64,
    tree_id: u32,
    file_id: FileId,
    file_information_class: u8,
    pattern: &str,
) -> (u32, Vec<u8>) {
    query_directory_buffer_for_class_with_controls(
        s,
        message_id,
        session_id,
        tree_id,
        file_id,
        file_information_class,
        QueryDirectoryRequest::FLAG_RESTART_SCANS,
        0,
        1024,
        pattern,
    )
    .await
}

async fn query_directory_buffer_for_class_with_controls(
    s: &mut TcpStream,
    message_id: u64,
    session_id: u64,
    tree_id: u32,
    file_id: FileId,
    file_information_class: u8,
    flags: u8,
    file_index: u32,
    output_buffer_length: u32,
    pattern: &str,
) -> (u32, Vec<u8>) {
    let pattern = utf16le(pattern);
    let req = QueryDirectoryRequest {
        structure_size: 33,
        file_information_class,
        flags,
        file_index,
        file_id,
        file_name_offset: 64 + 32,
        file_name_length: pattern.len() as u16,
        output_buffer_length,
        file_name: pattern,
    };
    let mut body = Vec::new();
    req.write_to(&mut body).expect("write query directory");
    let hdr = build_header(Command::QueryDirectory, message_id, session_id, tree_id);
    write_frame(s, &hdr, &body).await;
    let resp = read_frame(s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::QueryDirectory);
    if rh.channel_sequence_status != STATUS_SUCCESS {
        return (rh.channel_sequence_status, Vec::new());
    }
    let qd_resp = QueryDirectoryResponse::parse(rb).expect("parse query directory resp");
    (rh.channel_sequence_status, qd_resp.buffer)
}

async fn start_localfs_session(
    root: &std::path::Path,
) -> (
    tokio::task::JoinHandle<std::io::Result<()>>,
    TcpStream,
    u64,
    u32,
) {
    let backend = LocalFsBackend::new(root).expect("open root");
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
    (handle, s, session_id, tree_id)
}

async fn start_localfs_session_smb311(
    root: &std::path::Path,
) -> (
    tokio::task::JoinHandle<std::io::Result<()>>,
    TcpStream,
    u64,
    u32,
) {
    let backend = LocalFsBackend::new(root).expect("open root");
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
    let _ = negotiate_smb311(&mut s).await;
    let session_id = anonymous_session_setup(&mut s).await;
    let tree_id = tree_connect(&mut s, "\\\\127.0.0.1\\share", session_id, 3).await;
    (handle, s, session_id, tree_id)
}

async fn start_delayed_session(
    backend: DelayedBackend,
) -> (
    tokio::task::JoinHandle<std::io::Result<()>>,
    TcpStream,
    u64,
    u32,
) {
    start_backend_session(backend).await
}

async fn start_backend_session<B: ShareBackend>(
    backend: B,
) -> (
    tokio::task::JoinHandle<std::io::Result<()>>,
    TcpStream,
    u64,
    u32,
) {
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
    (handle, s, session_id, tree_id)
}

#[derive(Clone)]
struct DelayedBackend {
    inner: Arc<DelayedInner>,
    metrics: Arc<IoMetrics>,
    read_delay: Duration,
    write_delay: Duration,
}

struct DelayedInner {
    files: Mutex<std::collections::HashMap<String, Vec<u8>>>,
}

impl DelayedBackend {
    fn new(read_delay: Duration, write_delay: Duration) -> Self {
        Self {
            inner: Arc::new(DelayedInner {
                files: Mutex::new(std::collections::HashMap::new()),
            }),
            metrics: Arc::new(IoMetrics::default()),
            read_delay,
            write_delay,
        }
    }

    fn with_file(self, name: &str, data: impl Into<Vec<u8>>) -> Self {
        self.inner
            .files
            .lock()
            .unwrap()
            .insert(name.to_string(), data.into());
        self
    }
}

#[derive(Clone)]
struct DynamicListingBackend {
    entries: Arc<Mutex<Vec<String>>>,
}

impl DynamicListingBackend {
    fn new(entries: &[&str]) -> Self {
        Self {
            entries: Arc::new(Mutex::new(
                entries.iter().map(|entry| (*entry).to_string()).collect(),
            )),
        }
    }

    fn add_file(&self, name: &str) {
        self.entries.lock().unwrap().push(name.to_string());
    }
}

#[async_trait]
impl ShareBackend for DynamicListingBackend {
    async fn open(&self, path: &SmbPath, _opts: OpenOptions) -> SmbResult<Box<dyn Handle>> {
        if !path.is_root() {
            return Err(SmbError::NotFound);
        }
        Ok(Box::new(DynamicListingHandle {
            entries: self.entries.clone(),
        }))
    }

    async fn unlink(&self, _path: &SmbPath) -> SmbResult<()> {
        Err(SmbError::NotSupported)
    }

    async fn rename(&self, _from: &SmbPath, _to: &SmbPath) -> SmbResult<()> {
        Err(SmbError::NotSupported)
    }

    fn capabilities(&self) -> BackendCapabilities {
        BackendCapabilities::default()
    }
}

struct DynamicListingHandle {
    entries: Arc<Mutex<Vec<String>>>,
}

#[async_trait]
impl Handle for DynamicListingHandle {
    async fn read(&self, _offset: u64, _len: u32) -> SmbResult<Bytes> {
        Err(SmbError::NotSupported)
    }

    async fn write(&self, _offset: u64, _data: &[u8]) -> SmbResult<u32> {
        Err(SmbError::NotSupported)
    }

    async fn flush(&self) -> SmbResult<()> {
        Ok(())
    }

    async fn stat(&self) -> SmbResult<FileInfo> {
        Ok(file_info(".", true, 0, 1))
    }

    async fn set_times(&self, _times: FileTimes) -> SmbResult<()> {
        Ok(())
    }

    async fn truncate(&self, _len: u64) -> SmbResult<()> {
        Err(SmbError::NotSupported)
    }

    async fn list_dir(&self, _pattern: Option<&str>) -> SmbResult<Vec<DirEntry>> {
        Ok(self
            .entries
            .lock()
            .unwrap()
            .iter()
            .enumerate()
            .map(|(idx, name)| DirEntry {
                info: file_info(name, false, 1, 10 + idx as u64),
            })
            .collect())
    }

    async fn close(self: Box<Self>) -> SmbResult<()> {
        Ok(())
    }
}

fn file_info(name: &str, is_directory: bool, end_of_file: u64, file_index: u64) -> FileInfo {
    FileInfo {
        name: name.to_string(),
        end_of_file,
        allocation_size: if end_of_file == 0 { 0 } else { 4096 },
        creation_time: 0,
        last_access_time: 0,
        last_write_time: 0,
        change_time: 0,
        is_directory,
        file_index,
        file_attributes: if is_directory {
            FILE_ATTRIBUTE_DIRECTORY
        } else {
            FILE_ATTRIBUTE_ARCHIVE
        },
    }
}

#[async_trait]
impl ShareBackend for DelayedBackend {
    async fn open(&self, path: &SmbPath, _opts: OpenOptions) -> SmbResult<Box<dyn Handle>> {
        let key = path.display_backslash();
        if !self.inner.files.lock().unwrap().contains_key(&key) {
            return Err(SmbError::NotFound);
        }
        Ok(Box::new(DelayedHandle {
            key,
            inner: self.inner.clone(),
            metrics: self.metrics.clone(),
            read_delay: self.read_delay,
            write_delay: self.write_delay,
        }))
    }

    async fn unlink(&self, _path: &SmbPath) -> SmbResult<()> {
        Err(SmbError::NotSupported)
    }

    async fn rename(&self, _from: &SmbPath, _to: &SmbPath) -> SmbResult<()> {
        Err(SmbError::NotSupported)
    }

    fn capabilities(&self) -> BackendCapabilities {
        BackendCapabilities::default()
    }
}

#[derive(Default)]
struct IoMetrics {
    active_reads: AtomicUsize,
    max_reads: AtomicUsize,
    active_writes: AtomicUsize,
    max_writes: AtomicUsize,
    flushes: AtomicUsize,
    active_writes_by_key: Mutex<std::collections::HashMap<String, usize>>,
    max_writes_by_key: Mutex<std::collections::HashMap<String, usize>>,
}

impl IoMetrics {
    fn max_writes_for(&self, key: &str) -> usize {
        self.max_writes_by_key
            .lock()
            .unwrap()
            .get(key)
            .copied()
            .unwrap_or(0)
    }
}

struct DelayedHandle {
    key: String,
    inner: Arc<DelayedInner>,
    metrics: Arc<IoMetrics>,
    read_delay: Duration,
    write_delay: Duration,
}

#[async_trait]
impl Handle for DelayedHandle {
    async fn read(&self, offset: u64, len: u32) -> SmbResult<Bytes> {
        let active = self.metrics.active_reads.fetch_add(1, Ordering::SeqCst) + 1;
        update_max(&self.metrics.max_reads, active);
        sleep(self.read_delay).await;
        let result = {
            let files = self.inner.files.lock().unwrap();
            let data = files.get(&self.key).ok_or(SmbError::NotFound)?;
            let start = offset as usize;
            if start >= data.len() {
                Bytes::new()
            } else {
                let end = (start + len as usize).min(data.len());
                Bytes::copy_from_slice(&data[start..end])
            }
        };
        self.metrics.active_reads.fetch_sub(1, Ordering::SeqCst);
        Ok(result)
    }

    async fn write(&self, offset: u64, data: &[u8]) -> SmbResult<u32> {
        let active = self.metrics.active_writes.fetch_add(1, Ordering::SeqCst) + 1;
        update_max(&self.metrics.max_writes, active);
        {
            let mut active_by_key = self.metrics.active_writes_by_key.lock().unwrap();
            let active_for_key = active_by_key.entry(self.key.clone()).or_default();
            *active_for_key += 1;
            let mut max_by_key = self.metrics.max_writes_by_key.lock().unwrap();
            let max_for_key = max_by_key.entry(self.key.clone()).or_default();
            *max_for_key = (*max_for_key).max(*active_for_key);
        }

        sleep(self.write_delay).await;
        {
            let mut files = self.inner.files.lock().unwrap();
            let file = files.get_mut(&self.key).ok_or(SmbError::NotFound)?;
            let start = offset as usize;
            let end = start + data.len();
            if file.len() < end {
                file.resize(end, 0);
            }
            file[start..end].copy_from_slice(data);
        }

        {
            let mut active_by_key = self.metrics.active_writes_by_key.lock().unwrap();
            let active_for_key = active_by_key
                .get_mut(&self.key)
                .expect("active write key exists");
            *active_for_key -= 1;
        }
        self.metrics.active_writes.fetch_sub(1, Ordering::SeqCst);
        Ok(data.len() as u32)
    }

    async fn flush(&self) -> SmbResult<()> {
        self.metrics.flushes.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    async fn stat(&self) -> SmbResult<FileInfo> {
        let files = self.inner.files.lock().unwrap();
        let size = files.get(&self.key).ok_or(SmbError::NotFound)?.len() as u64;
        Ok(FileInfo {
            name: self.key.clone(),
            end_of_file: size,
            allocation_size: size,
            creation_time: 0x01D9_0000_0000_0000,
            last_access_time: 0x01D9_0000_0000_0000,
            last_write_time: 0x01D9_0000_0000_0000,
            change_time: 0x01D9_0000_0000_0000,
            is_directory: false,
            file_index: 0,
            file_attributes: FILE_ATTRIBUTE_ARCHIVE,
        })
    }

    async fn set_times(&self, _times: FileTimes) -> SmbResult<()> {
        Ok(())
    }

    async fn truncate(&self, len: u64) -> SmbResult<()> {
        let mut files = self.inner.files.lock().unwrap();
        let file = files.get_mut(&self.key).ok_or(SmbError::NotFound)?;
        file.resize(len as usize, 0);
        Ok(())
    }

    async fn list_dir(&self, _pattern: Option<&str>) -> SmbResult<Vec<DirEntry>> {
        Ok(Vec::new())
    }

    async fn close(self: Box<Self>) -> SmbResult<()> {
        Ok(())
    }
}

fn update_max(max: &AtomicUsize, value: usize) {
    let mut current = max.load(Ordering::SeqCst);
    while value > current {
        match max.compare_exchange(current, value, Ordering::SeqCst, Ordering::SeqCst) {
            Ok(_) => break,
            Err(next) => current = next,
        }
    }
}

async fn open_root_directory(
    s: &mut TcpStream,
    message_id: u64,
    session_id: u64,
    tree_id: u32,
) -> FileId {
    let (_, create) = send_create_request(
        s,
        message_id,
        session_id,
        tree_id,
        create_request("", 0x0012_0089, 0, 1, 0x0000_0001),
    )
    .await;
    create.expect("root create success").file_id
}

#[tokio::test]
async fn query_directory_continuation_skips_deleted_snapshot_entries() {
    let td = tempdir().expect("tempdir");
    std::fs::write(td.path().join("a.txt"), b"a").expect("write a.txt");
    std::fs::write(td.path().join("b.txt"), b"b").expect("write b.txt");
    std::fs::write(td.path().join("c.log"), b"c").expect("write c.log");

    let (handle, mut s, session_id, tree_id) = start_localfs_session(td.path()).await;
    let root_id = open_root_directory(&mut s, 4, session_id, tree_id).await;

    let (status, names) = query_directory_file_id_both_names(
        &mut s,
        5,
        session_id,
        tree_id,
        root_id,
        QueryDirectoryRequest::FLAG_RETURN_SINGLE_ENTRY,
        0,
        1024,
        "*",
    )
    .await;
    assert_eq!(status, STATUS_SUCCESS);
    assert_eq!(names, vec!["."]);

    std::fs::remove_file(td.path().join("a.txt")).expect("remove a.txt");

    let (status, names) = query_directory_file_id_both_names(
        &mut s, 6, session_id, tree_id, root_id, 0, 0, 4096, "*",
    )
    .await;
    assert_eq!(status, STATUS_SUCCESS);
    assert_eq!(names, vec!["..", "b.txt", "c.log"]);

    handle.abort();
}

#[tokio::test]
async fn query_directory_deleted_consumed_entry_does_not_shift_cursor() {
    let td = tempdir().expect("tempdir");
    std::fs::write(td.path().join("a.txt"), b"a").expect("write a.txt");
    std::fs::write(td.path().join("b.txt"), b"b").expect("write b.txt");
    std::fs::write(td.path().join("c.log"), b"c").expect("write c.log");

    let (handle, mut s, session_id, tree_id) = start_localfs_session(td.path()).await;
    let root_id = open_root_directory(&mut s, 4, session_id, tree_id).await;

    for (message_id, want) in [(5, "."), (6, ".."), (7, "a.txt")] {
        let (status, names) = query_directory_file_id_both_names(
            &mut s,
            message_id,
            session_id,
            tree_id,
            root_id,
            QueryDirectoryRequest::FLAG_RETURN_SINGLE_ENTRY,
            0,
            1024,
            "*",
        )
        .await;
        assert_eq!(status, STATUS_SUCCESS);
        assert_eq!(names, vec![want]);
    }

    std::fs::remove_file(td.path().join("a.txt")).expect("remove a.txt");

    let (status, names) = query_directory_file_id_both_names(
        &mut s, 8, session_id, tree_id, root_id, 0, 0, 4096, "*",
    )
    .await;
    assert_eq!(status, STATUS_SUCCESS);
    assert_eq!(names, vec!["b.txt", "c.log"]);

    handle.abort();
}

#[tokio::test]
async fn query_directory_tiny_output_buffer_resumes_with_file_names() {
    let td = tempdir().expect("tempdir");
    std::fs::write(td.path().join("a.txt"), b"a").expect("write a.txt");
    std::fs::write(td.path().join("b.txt"), b"b").expect("write b.txt");
    std::fs::write(td.path().join("c.log"), b"c").expect("write c.log");

    let (handle, mut s, session_id, tree_id) = start_localfs_session(td.path()).await;
    let root_id = open_root_directory(&mut s, 4, session_id, tree_id).await;

    let (status, names) = query_directory_names_for_class_with_controls(
        &mut s, 5, session_id, tree_id, root_id, 0x0c, 0, 0, 30, "*",
    )
    .await;
    assert_eq!(status, STATUS_SUCCESS);
    assert_eq!(names, vec!["."]);

    let (status, names) = query_directory_names_for_class_with_controls(
        &mut s, 6, session_id, tree_id, root_id, 0x0c, 0, 0, 30, "",
    )
    .await;
    assert_eq!(status, STATUS_SUCCESS);
    assert_eq!(names, vec![".."]);

    handle.abort();
}

#[tokio::test]
async fn query_directory_index_and_no_match_status_match_gosmb() {
    let td = tempdir().expect("tempdir");
    std::fs::write(td.path().join("a.txt"), b"a").expect("write a.txt");
    std::fs::write(td.path().join("b.txt"), b"b").expect("write b.txt");
    std::fs::write(td.path().join("c.log"), b"c").expect("write c.log");

    let (handle, mut s, session_id, tree_id) = start_localfs_session(td.path()).await;
    let root_id = open_root_directory(&mut s, 4, session_id, tree_id).await;

    let (status, names) = query_directory_file_id_both_names(
        &mut s,
        5,
        session_id,
        tree_id,
        root_id,
        QueryDirectoryRequest::FLAG_RETURN_SINGLE_ENTRY,
        0,
        1024,
        "*",
    )
    .await;
    assert_eq!(status, STATUS_SUCCESS);
    assert_eq!(names, vec!["."]);

    let (status, names) = query_directory_file_id_both_names(
        &mut s,
        6,
        session_id,
        tree_id,
        root_id,
        QueryDirectoryRequest::FLAG_RESTART_SCANS | QueryDirectoryRequest::FLAG_RETURN_SINGLE_ENTRY,
        0,
        1024,
        "*.log",
    )
    .await;
    assert_eq!(status, STATUS_SUCCESS);
    assert_eq!(names, vec!["c.log"]);

    let (status, names) = query_directory_file_id_both_names(
        &mut s,
        7,
        session_id,
        tree_id,
        root_id,
        QueryDirectoryRequest::FLAG_INDEX_SPECIFIED,
        1,
        4096,
        "*",
    )
    .await;
    assert_eq!(status, STATUS_SUCCESS);
    assert_eq!(names, vec!["..", "a.txt", "b.txt", "c.log"]);

    let (status, names) = query_directory_names_for_class_with_controls(
        &mut s,
        8,
        session_id,
        tree_id,
        root_id,
        0x0c,
        QueryDirectoryRequest::FLAG_INDEX_SPECIFIED,
        2,
        4096,
        "*",
    )
    .await;
    assert_eq!(status, STATUS_SUCCESS);
    assert_eq!(names, vec!["a.txt", "b.txt", "c.log"]);

    let (status, names) = query_directory_names_for_class_with_controls(
        &mut s,
        9,
        session_id,
        tree_id,
        root_id,
        0x02,
        QueryDirectoryRequest::FLAG_INDEX_SPECIFIED,
        3,
        4096,
        "*",
    )
    .await;
    assert_eq!(status, STATUS_SUCCESS);
    assert_eq!(names, vec!["b.txt", "c.log"]);

    let (status, buffer) = query_directory_buffer_for_class_with_controls(
        &mut s,
        10,
        session_id,
        tree_id,
        root_id,
        0x0c,
        QueryDirectoryRequest::FLAG_RESTART_SCANS | QueryDirectoryRequest::FLAG_RETURN_SINGLE_ENTRY,
        0,
        4096,
        "*",
    )
    .await;
    assert_eq!(status, STATUS_SUCCESS);
    let first = decode_query_directory_names_and_indexes_for_class(&buffer, 0x0c);
    assert_eq!(first, vec![(".".to_string(), 1)]);

    let (status, names) = query_directory_names_for_class_with_controls(
        &mut s,
        11,
        session_id,
        tree_id,
        root_id,
        0x0c,
        QueryDirectoryRequest::FLAG_INDEX_SPECIFIED,
        first[0].1,
        4096,
        "*",
    )
    .await;
    assert_eq!(status, STATUS_SUCCESS);
    assert_eq!(names, vec!["..", "a.txt", "b.txt", "c.log"]);

    let (status, buffer) = query_directory_buffer_for_class_with_controls(
        &mut s,
        12,
        session_id,
        tree_id,
        root_id,
        0x25,
        QueryDirectoryRequest::FLAG_RESTART_SCANS,
        0,
        4096,
        "*",
    )
    .await;
    assert_eq!(status, STATUS_SUCCESS);
    let all = decode_query_directory_names_and_indexes_for_class(&buffer, 0x25);
    assert_eq!(
        all.iter()
            .map(|(name, _)| name.as_str())
            .collect::<Vec<_>>(),
        vec![".", "..", "a.txt", "b.txt", "c.log"]
    );
    let last_resume_key = all.last().expect("last directory entry").1;
    let (status, names) = query_directory_names_for_class_with_controls(
        &mut s,
        13,
        session_id,
        tree_id,
        root_id,
        0x25,
        QueryDirectoryRequest::FLAG_INDEX_SPECIFIED,
        last_resume_key,
        4096,
        "*",
    )
    .await;
    assert_eq!(status, STATUS_NO_MORE_FILES);
    assert!(names.is_empty());

    let (status, names) = query_directory_file_id_both_names(
        &mut s,
        14,
        session_id,
        tree_id,
        root_id,
        QueryDirectoryRequest::FLAG_RESTART_SCANS,
        0,
        4096,
        "missing.*",
    )
    .await;
    assert_eq!(status, STATUS_NO_SUCH_FILE);
    assert!(names.is_empty());

    let (status, names) = query_directory_file_id_both_names(
        &mut s,
        15,
        session_id,
        tree_id,
        root_id,
        0,
        0,
        4096,
        "missing.*",
    )
    .await;
    assert_eq!(status, STATUS_NO_MORE_FILES);
    assert!(names.is_empty());

    handle.abort();
}

#[tokio::test]
async fn query_directory_invalid_class_returns_invalid_info_class() {
    let td = tempdir().expect("tempdir");
    std::fs::write(td.path().join("a.txt"), b"a").expect("write a.txt");

    let (handle, mut s, session_id, tree_id) = start_localfs_session(td.path()).await;
    let root_id = open_root_directory(&mut s, 4, session_id, tree_id).await;

    assert_eq!(
        query_directory_status_for_class(&mut s, 5, session_id, tree_id, root_id, 0xff).await,
        STATUS_INVALID_INFO_CLASS
    );

    handle.abort();
}

#[tokio::test]
async fn query_directory_extended_file_id_classes_return_names() {
    let td = tempdir().expect("tempdir");
    std::fs::write(td.path().join("a.txt"), b"a").expect("write a.txt");

    let (handle, mut s, session_id, tree_id) = start_localfs_session(td.path()).await;
    let root_id = open_root_directory(&mut s, 4, session_id, tree_id).await;

    for (idx, class) in [0x3c, 0x4e, 0x4f, 0x50, 0x51].into_iter().enumerate() {
        let (status, names) = query_directory_names_for_class(
            &mut s,
            5 + idx as u64,
            session_id,
            tree_id,
            root_id,
            class,
            "a.txt",
        )
        .await;
        assert_eq!(status, STATUS_SUCCESS, "class 0x{class:02x}");
        assert_eq!(names, vec!["a.txt"], "class 0x{class:02x}");
    }

    handle.abort();
}

#[tokio::test]
async fn query_directory_metadata_matches_query_info_across_classes() {
    let td = tempdir().expect("tempdir");
    std::fs::write(td.path().join("a.txt"), b"hello").expect("write a.txt");

    let (handle, mut s, session_id, tree_id) = start_localfs_session(td.path()).await;
    let (rh, opened) = send_create_request(
        &mut s,
        4,
        session_id,
        tree_id,
        create_request("a.txt", 0x0012_0089, 0, 1, 0x0000_0040),
    )
    .await;
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let file_id = opened.expect("file open").file_id;

    let all_info = query_file_all_information(&mut s, 5, session_id, tree_id, file_id).await;
    let expected = query_info_metadata(&all_info);
    let (status, internal_info) =
        query_file_information_class(&mut s, 6, session_id, tree_id, file_id, 0x06, 8).await;
    assert_eq!(status, STATUS_SUCCESS);
    let expected_file_id = u64::from_le_bytes(internal_info[0..8].try_into().unwrap());
    assert_ne!(expected_file_id, 0);
    assert_eq!(
        send_close_request(&mut s, 7, session_id, tree_id, file_id).await,
        STATUS_SUCCESS
    );

    let root_id = open_root_directory(&mut s, 8, session_id, tree_id).await;
    for (idx, class) in [0x01, 0x02, 0x03, 0x25, 0x26, 0x3c, 0x4e, 0x4f, 0x50, 0x51]
        .into_iter()
        .enumerate()
    {
        let (status, output) = query_directory_buffer_for_class(
            &mut s,
            9 + idx as u64,
            session_id,
            tree_id,
            root_id,
            class,
            "a.txt",
        )
        .await;
        assert_eq!(status, STATUS_SUCCESS, "class 0x{class:02x}");
        assert_eq!(
            decode_query_directory_names_for_class(&output, class),
            vec!["a.txt"],
            "class 0x{class:02x}"
        );
        assert_eq!(
            query_directory_common_metadata(&output),
            expected,
            "class 0x{class:02x}"
        );
        if let Some(offset) = query_directory_file_id_offset(class) {
            assert_eq!(
                u64::from_le_bytes(output[offset..offset + 8].try_into().unwrap()),
                expected_file_id,
                "class 0x{class:02x} file id at offset {offset}"
            );
        }
    }

    handle.abort();
}

#[tokio::test]
async fn query_directory_posix_information_uses_stored_metadata() {
    let td = tempdir().expect("tempdir");
    std::fs::write(td.path().join("a.txt"), b"a").expect("write a.txt");

    let (handle, mut s, session_id, tree_id) = start_localfs_session(td.path()).await;
    let posix_body = create_request_with_context(
        "a.txt",
        create_request("a.txt", 0x001f_01ff, 0, 1, 0x0000_0040),
        CreateContext {
            name: CreateContext::NAME_POSIX.to_vec(),
            data: 0o600u32.to_le_bytes().to_vec(),
        },
    );
    let hdr = build_header(Command::Create, 4, session_id, tree_id);
    write_frame(&mut s, &hdr, &posix_body).await;
    let resp = read_frame(&mut s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Create);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let file_id = CreateResponse::parse(rb)
        .expect("parse posix create resp")
        .file_id;
    assert_eq!(
        send_close_request(&mut s, 5, session_id, tree_id, file_id).await,
        STATUS_SUCCESS
    );

    let root_id = open_root_directory(&mut s, 6, session_id, tree_id).await;
    let (status, output) =
        query_directory_buffer_for_class(&mut s, 7, session_id, tree_id, root_id, 0x64, "a.txt")
            .await;
    assert_eq!(status, STATUS_SUCCESS);
    assert_eq!(
        decode_query_directory_names_for_class(&output, 0x64),
        vec!["a.txt"]
    );
    assert_ne!(u64::from_le_bytes(output[60..68].try_into().unwrap()), 0);
    assert_eq!(
        u32::from_le_bytes(output[84..88].try_into().unwrap()),
        0o600
    );
    assert_eq!(
        posix_sid_id(&output[88..116], 1),
        posix_sid_id(&output[116..144], 2)
    );
    assert_ne!(posix_sid_id(&output[88..116], 1), 0);

    handle.abort();
}

#[tokio::test]
async fn query_directory_restart_refreshes_virtual_backend_listing() {
    let backend = DynamicListingBackend::new(&["a.txt", "b.txt", "c.log"]);
    let control = backend.clone();
    let (handle, mut s, session_id, tree_id) = start_backend_session(backend).await;
    let root_id = open_root_directory(&mut s, 4, session_id, tree_id).await;

    let (status, names) = query_directory_names_for_class_with_controls(
        &mut s,
        5,
        session_id,
        tree_id,
        root_id,
        0x0c,
        QueryDirectoryRequest::FLAG_RESTART_SCANS,
        0,
        1024,
        "*",
    )
    .await;
    assert_eq!(status, STATUS_SUCCESS);
    assert_eq!(names, vec![".", "..", "a.txt", "b.txt", "c.log"]);

    control.add_file("d.txt");
    let (status, names) = query_directory_names_for_class_with_controls(
        &mut s,
        6,
        session_id,
        tree_id,
        root_id,
        0x0c,
        QueryDirectoryRequest::FLAG_RESTART_SCANS,
        0,
        1024,
        "*",
    )
    .await;
    assert_eq!(status, STATUS_SUCCESS);
    assert_eq!(names, vec![".", "..", "a.txt", "b.txt", "c.log", "d.txt"]);

    handle.abort();
}

#[tokio::test]
async fn create_posix_context_persists_through_reopen_and_rename_then_clears_on_recreate() {
    let td = tempdir().expect("tempdir");
    let (handle, mut s, session_id, tree_id) = start_localfs_session(td.path()).await;

    let posix_body = create_request_with_context(
        "posix.txt",
        create_request("posix.txt", 0x001f_01ff, 0, 2, 0x0000_0040),
        CreateContext {
            name: CreateContext::NAME_POSIX.to_vec(),
            data: 0o600u32.to_le_bytes().to_vec(),
        },
    );
    let hdr = build_header(Command::Create, 4, session_id, tree_id);
    write_frame(&mut s, &hdr, &posix_body).await;
    let resp = read_frame(&mut s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Create);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let create_resp = CreateResponse::parse(rb).expect("parse POSIX create resp");
    let contexts =
        CreateContext::parse_chain(&create_resp.create_contexts).expect("parse POSIX contexts");
    let posix = contexts
        .iter()
        .find(|ctx| ctx.name == CreateContext::NAME_POSIX.as_slice())
        .expect("POSIX response context");
    assert_eq!(posix.data.len(), 68);
    assert_eq!(
        u32::from_le_bytes(posix.data[8..12].try_into().unwrap()),
        0o600
    );
    let owner = posix_sid_id(&posix.data[12..40], 1);
    let group = posix_sid_id(&posix.data[40..68], 2);
    assert_ne!(owner, 0);
    assert_eq!(group, owner);

    let file_id = create_resp.file_id;
    let (status, posix_info) =
        query_file_information_class(&mut s, 5, session_id, tree_id, file_id, 0x64, 136).await;
    assert_eq!(status, STATUS_SUCCESS);
    assert_eq!(posix_info.len(), 136);
    assert_eq!(
        u32::from_le_bytes(posix_info[76..80].try_into().unwrap()),
        0o600
    );
    assert_eq!(posix_sid_id(&posix_info[80..108], 1), owner);
    assert_eq!(posix_sid_id(&posix_info[108..136], 2), group);

    assert_eq!(
        send_close_request(&mut s, 6, session_id, tree_id, file_id).await,
        STATUS_SUCCESS
    );

    let reopened = open_localfs_path(
        &mut s,
        session_id,
        tree_id,
        7,
        "posix.txt",
        0x001f_01ff,
        0x0000_0040,
    )
    .await;
    let (status, reopened_info) =
        query_file_information_class(&mut s, 8, session_id, tree_id, reopened, 0x64, 136).await;
    assert_eq!(status, STATUS_SUCCESS);
    assert_eq!(
        u32::from_le_bytes(reopened_info[76..80].try_into().unwrap()),
        0o600
    );
    assert_eq!(posix_sid_id(&reopened_info[80..108], 1), owner);

    assert_eq!(
        set_file_rename_status(
            &mut s,
            9,
            session_id,
            tree_id,
            reopened,
            "renamed-posix.txt",
            true,
        )
        .await,
        STATUS_SUCCESS
    );
    assert_eq!(
        send_close_request(&mut s, 10, session_id, tree_id, reopened).await,
        STATUS_SUCCESS
    );

    let renamed = open_localfs_path(
        &mut s,
        session_id,
        tree_id,
        11,
        "renamed-posix.txt",
        0x001f_01ff,
        0x0000_0040,
    )
    .await;
    let (status, renamed_info) =
        query_file_information_class(&mut s, 12, session_id, tree_id, renamed, 0x64, 136).await;
    assert_eq!(status, STATUS_SUCCESS);
    assert_eq!(
        u32::from_le_bytes(renamed_info[76..80].try_into().unwrap()),
        0o600
    );
    assert_eq!(posix_sid_id(&renamed_info[80..108], 1), owner);

    assert_eq!(
        set_file_disposition_status(&mut s, 13, session_id, tree_id, renamed, true).await,
        STATUS_SUCCESS
    );
    assert_eq!(
        send_close_request(&mut s, 14, session_id, tree_id, renamed).await,
        STATUS_SUCCESS
    );

    let (rh, recreated) = send_create_request(
        &mut s,
        15,
        session_id,
        tree_id,
        create_request("renamed-posix.txt", 0x001f_01ff, 0, 2, 0x0000_0040),
    )
    .await;
    assert_eq!(rh.command, Command::Create);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let recreated = recreated.expect("recreated POSIX file").file_id;
    let (status, recreated_info) =
        query_file_information_class(&mut s, 16, session_id, tree_id, recreated, 0x64, 136).await;
    assert_eq!(status, STATUS_SUCCESS);
    assert_eq!(
        u32::from_le_bytes(recreated_info[76..80].try_into().unwrap()),
        0o644
    );
    assert_eq!(posix_sid_id(&recreated_info[80..108], 1), 0);
    assert_eq!(posix_sid_id(&recreated_info[108..136], 2), 0);

    assert_eq!(
        send_close_request(&mut s, 17, session_id, tree_id, recreated).await,
        STATUS_SUCCESS
    );

    handle.abort();
}

#[tokio::test]
async fn query_directory_restart_and_reopen_reflect_mutations() {
    let td = tempdir().expect("tempdir");
    std::fs::write(td.path().join("a.txt"), b"a").expect("write a.txt");
    std::fs::write(td.path().join("b.txt"), b"b").expect("write b.txt");
    std::fs::write(td.path().join("c.log"), b"c").expect("write c.log");

    let (handle, mut s, session_id, tree_id) = start_localfs_session(td.path()).await;
    let root_id = open_root_directory(&mut s, 4, session_id, tree_id).await;

    let (status, names) = query_directory_file_id_both_names(
        &mut s,
        5,
        session_id,
        tree_id,
        root_id,
        QueryDirectoryRequest::FLAG_RETURN_SINGLE_ENTRY,
        0,
        1024,
        "*",
    )
    .await;
    assert_eq!(status, STATUS_SUCCESS);
    assert_eq!(names, vec!["."]);

    std::fs::remove_file(td.path().join("b.txt")).expect("remove b.txt");
    std::fs::write(td.path().join("d.txt"), b"d").expect("write d.txt");
    let a_id = open_localfs_path(&mut s, session_id, tree_id, 6, "a.txt", 0x0012_0189, 0).await;
    assert_eq!(
        set_basic_attributes(
            &mut s,
            7,
            session_id,
            tree_id,
            a_id,
            FILE_ATTRIBUTE_ARCHIVE | FILE_ATTRIBUTE_HIDDEN,
        )
        .await,
        STATUS_SUCCESS
    );

    let (status, entries) = query_directory_file_id_both_entries(
        &mut s,
        8,
        session_id,
        tree_id,
        root_id,
        QueryDirectoryRequest::FLAG_RESTART_SCANS,
        4096,
        "*",
    )
    .await;
    assert_eq!(status, STATUS_SUCCESS);
    let names: Vec<_> = entries.iter().map(|(name, _)| name.as_str()).collect();
    assert_eq!(names, vec![".", "..", "a.txt", "c.log", "d.txt"]);
    let attrs: std::collections::HashMap<_, _> = entries.into_iter().collect();
    assert_eq!(
        attrs["a.txt"] & FILE_ATTRIBUTE_HIDDEN,
        FILE_ATTRIBUTE_HIDDEN
    );
    assert_eq!(
        attrs["d.txt"] & FILE_ATTRIBUTE_ARCHIVE,
        FILE_ATTRIBUTE_ARCHIVE
    );
    assert!(!attrs.contains_key("b.txt"));

    std::fs::rename(td.path().join("d.txt"), td.path().join("e.txt")).expect("rename d to e");
    let (status, names) = query_directory_file_id_both_names(
        &mut s,
        9,
        session_id,
        tree_id,
        root_id,
        QueryDirectoryRequest::FLAG_REOPEN,
        0,
        4096,
        "*",
    )
    .await;
    assert_eq!(status, STATUS_SUCCESS);
    assert_eq!(names, vec![".", "..", "a.txt", "c.log", "e.txt"]);

    let (status, names) = query_directory_file_id_both_names(
        &mut s,
        10,
        session_id,
        tree_id,
        root_id,
        QueryDirectoryRequest::FLAG_RESTART_SCANS,
        0,
        4096,
        "*.LOG",
    )
    .await;
    assert_eq!(status, STATUS_SUCCESS);
    assert_eq!(names, vec!["c.log"]);

    std::fs::write(td.path().join("README"), b"r").expect("write README");
    let (status, names) = query_directory_file_id_both_names(
        &mut s,
        11,
        session_id,
        tree_id,
        root_id,
        QueryDirectoryRequest::FLAG_RESTART_SCANS,
        0,
        4096,
        "*.*",
    )
    .await;
    assert_eq!(status, STATUS_SUCCESS);
    assert_eq!(names, vec![".", "..", "README", "a.txt", "c.log", "e.txt"]);

    handle.abort();
}

#[tokio::test]
async fn query_directory_empty_directory_returns_dot_entries_once() {
    let td = tempdir().expect("tempdir");
    std::fs::create_dir(td.path().join("empty")).expect("mkdir empty");

    let (handle, mut s, session_id, tree_id) = start_localfs_session(td.path()).await;
    let empty_id = open_localfs_path(
        &mut s,
        session_id,
        tree_id,
        4,
        "empty",
        0x0012_0089,
        0x0000_0001,
    )
    .await;

    let (status, names) = query_directory_file_id_both_names(
        &mut s,
        5,
        session_id,
        tree_id,
        empty_id,
        QueryDirectoryRequest::FLAG_RESTART_SCANS,
        0,
        1024,
        "*",
    )
    .await;
    assert_eq!(status, STATUS_SUCCESS);
    assert_eq!(names, vec![".", ".."]);

    let (status, names) = query_directory_file_id_both_names(
        &mut s, 6, session_id, tree_id, empty_id, 0, 0, 1024, "*",
    )
    .await;
    assert_eq!(status, STATUS_NO_MORE_FILES);
    assert!(names.is_empty());

    handle.abort();
}

#[tokio::test]
async fn query_directory_empty_directory_file_names_information_is_deltree_safe() {
    const DELETE_ACCESS: u32 = 0x0001_0000;
    const FILE_READ_DATA: u32 = 0x0000_0001;
    const FILE_DIRECTORY_FILE: u32 = 0x0000_0001;
    const FILE_DELETE_ON_CLOSE: u32 = 0x0000_1000;

    let td = tempdir().expect("tempdir");
    std::fs::create_dir(td.path().join("empty")).expect("mkdir empty");

    let (handle, mut s, session_id, tree_id) = start_localfs_session(td.path()).await;
    let empty_id = open_localfs_path(
        &mut s,
        session_id,
        tree_id,
        4,
        "empty",
        FILE_READ_DATA,
        0x0000_0001,
    )
    .await;

    let (status, buffer) =
        query_directory_buffer_for_class(&mut s, 5, session_id, tree_id, empty_id, 0x0c, "*").await;
    assert_eq!(status, STATUS_SUCCESS);
    assert_eq!(
        decode_query_directory_names_for_class(&buffer, 0x0c),
        vec![".", ".."]
    );
    assert_eq!(u32::from_le_bytes(buffer[0..4].try_into().unwrap()), 16);
    assert_eq!(u32::from_le_bytes(buffer[8..12].try_into().unwrap()), 2);
    assert_eq!(&buffer[12..14], &utf16le("."));
    assert_eq!(u32::from_le_bytes(buffer[16..20].try_into().unwrap()), 0);
    assert_eq!(u32::from_le_bytes(buffer[24..28].try_into().unwrap()), 4);
    assert_eq!(&buffer[28..32], &utf16le(".."));

    let (status, names) = query_directory_names_for_class_with_controls(
        &mut s, 6, session_id, tree_id, empty_id, 0x0c, 0, 0, 1024, "*",
    )
    .await;
    assert_eq!(status, STATUS_NO_MORE_FILES);
    assert!(names.is_empty());

    close_file(&mut s, 7, session_id, tree_id, empty_id).await;

    let req = create_request(
        "empty",
        DELETE_ACCESS,
        FILE_ATTRIBUTE_NORMAL,
        1,
        FILE_DIRECTORY_FILE | FILE_DELETE_ON_CLOSE,
    );
    let (rh, delete_dir) = send_create_request(&mut s, 8, session_id, tree_id, req).await;
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    close_file(
        &mut s,
        9,
        session_id,
        tree_id,
        delete_dir.expect("delete dir handle").file_id,
    )
    .await;
    assert!(!td.path().join("empty").exists());

    handle.abort();
}

#[tokio::test]
async fn file_delete_on_close_with_other_open_removes_name_from_directory() {
    const DELETE_ACCESS: u32 = 0x0001_0000;
    const FILE_NON_DIRECTORY_FILE: u32 = 0x0000_0040;
    const FILE_DELETE_ON_CLOSE: u32 = 0x0000_1000;

    let td = tempdir().expect("tempdir");
    let (handle, mut s, session_id, tree_id) = start_localfs_session(td.path()).await;

    let first_req = create_request(
        "tname1",
        0x001f_01ff,
        FILE_ATTRIBUTE_ARCHIVE,
        2,
        FILE_NON_DIRECTORY_FILE,
    );
    let (rh, first) = send_create_request(&mut s, 4, session_id, tree_id, first_req).await;
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let first_id = first.expect("first open").file_id;

    let delete_req = create_request(
        "tname1",
        DELETE_ACCESS,
        FILE_ATTRIBUTE_NORMAL,
        1,
        FILE_NON_DIRECTORY_FILE | FILE_DELETE_ON_CLOSE,
    );
    let (rh, delete_open) = send_create_request(&mut s, 5, session_id, tree_id, delete_req).await;
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    close_file(
        &mut s,
        6,
        session_id,
        tree_id,
        delete_open.expect("delete-on-close open").file_id,
    )
    .await;

    assert!(
        !td.path().join("tname1").exists(),
        "delete-on-close left the directory entry visible"
    );

    let root_id = open_root_directory(&mut s, 7, session_id, tree_id).await;
    let (status, names) =
        query_directory_names_for_class(&mut s, 8, session_id, tree_id, root_id, 0x0c, "*").await;
    assert!(matches!(status, STATUS_SUCCESS | STATUS_NO_SUCH_FILE));
    assert!(
        !names.iter().any(|name| name == "tname1"),
        "delete-pending file was still enumerated: {names:?}"
    );

    close_file(&mut s, 9, session_id, tree_id, root_id).await;
    close_file(&mut s, 10, session_id, tree_id, first_id).await;

    handle.abort();
}

#[tokio::test]
async fn delete_on_close_open_missing_file_with_attributes_returns_object_name_not_found() {
    const DELETE_ACCESS: u32 = 0x0001_0000;
    const FILE_NON_DIRECTORY_FILE: u32 = 0x0000_0040;
    const FILE_DELETE_ON_CLOSE: u32 = 0x0000_1000;

    let td = tempdir().expect("tempdir");
    let (handle, mut s, session_id, tree_id) = start_localfs_session(td.path()).await;

    let missing_delete_req = create_request(
        "never-existed.txt",
        DELETE_ACCESS,
        FILE_ATTRIBUTE_NORMAL,
        1,
        FILE_NON_DIRECTORY_FILE | FILE_DELETE_ON_CLOSE,
    );
    let (rh, created) =
        send_create_request(&mut s, 4, session_id, tree_id, missing_delete_req).await;

    assert_eq!(rh.channel_sequence_status, STATUS_OBJECT_NAME_NOT_FOUND);
    assert!(created.is_none());
    assert!(!td.path().join("never-existed.txt").exists());

    handle.abort();
}

#[tokio::test]
async fn samba_cleanup_unlink_missing_file_without_reauth_returns_object_name_not_found() {
    const DELETE_ACCESS: u32 = 0x0001_0000;
    const FILE_NON_DIRECTORY_FILE: u32 = 0x0000_0040;
    const FILE_DELETE_ON_CLOSE: u32 = 0x0000_1000;

    let td = tempdir().expect("tempdir");
    let (handle, mut s, session_id, tree_id) = start_localfs_session(td.path()).await;

    let cleanup_req = create_request(
        "missing-cleanup.txt",
        DELETE_ACCESS,
        0,
        1,
        FILE_NON_DIRECTORY_FILE | FILE_DELETE_ON_CLOSE,
    );
    let (rh, cleanup_open) = send_create_request(&mut s, 4, session_id, tree_id, cleanup_req).await;
    assert_eq!(rh.channel_sequence_status, STATUS_OBJECT_NAME_NOT_FOUND);
    assert!(cleanup_open.is_none());
    assert!(!td.path().join("missing-cleanup.txt").exists());

    handle.abort();
}

#[tokio::test]
async fn query_directory_many_entries_continue_without_duplicates() {
    let td = tempdir().expect("tempdir");
    let many = td.path().join("many");
    std::fs::create_dir(&many).expect("mkdir many");
    const FILE_COUNT: usize = 1200;
    for i in 0..FILE_COUNT {
        let name = format!("{}-{i:04}.txt", "x".repeat(i % 200 + 1));
        std::fs::write(many.join(name), b"x").expect("seed many file");
    }

    let (handle, mut s, session_id, tree_id) = start_localfs_session(td.path()).await;
    let many_id = open_localfs_path(
        &mut s,
        session_id,
        tree_id,
        4,
        "many",
        0x0012_0089,
        0x0000_0001,
    )
    .await;

    let mut seen = std::collections::HashSet::new();
    let mut flags = QueryDirectoryRequest::FLAG_RESTART_SCANS;
    for message_id in 5.. {
        let (status, names) = query_directory_file_id_both_names(
            &mut s, message_id, session_id, tree_id, many_id, flags, 0, 512, "*",
        )
        .await;
        if status == STATUS_NO_MORE_FILES {
            break;
        }
        assert_eq!(status, STATUS_SUCCESS);
        for name in names {
            if name == "." || name == ".." {
                continue;
            }
            assert!(
                seen.insert(name.clone()),
                "duplicate directory entry {name}"
            );
        }
        flags = 0;
    }

    assert_eq!(seen.len(), FILE_COUNT);
    for i in 0..FILE_COUNT {
        let name = format!("{}-{i:04}.txt", "x".repeat(i % 200 + 1));
        assert!(seen.contains(&name), "missing directory entry {name}");
    }

    handle.abort();
}

async fn set_basic_attributes(
    s: &mut TcpStream,
    message_id: u64,
    session_id: u64,
    tree_id: u32,
    file_id: FileId,
    attributes: u32,
) -> u32 {
    let mut buffer = vec![0; 40];
    buffer[32..36].copy_from_slice(&attributes.to_le_bytes());
    let req = SetInfoRequest {
        structure_size: 33,
        info_type: InfoType::File as u8,
        file_information_class: 0x04,
        buffer_length: buffer.len() as u32,
        buffer_offset: 64 + 32,
        reserved: 0,
        additional_information: 0,
        file_id,
        buffer,
    };
    let mut body = Vec::new();
    req.write_to(&mut body).expect("write set basic");
    let hdr = build_header(Command::SetInfo, message_id, session_id, tree_id);
    write_frame(s, &hdr, &body).await;
    let resp = read_frame(s).await;
    let (rh, _rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::SetInfo);
    rh.channel_sequence_status
}

async fn set_basic_information_status(
    s: &mut TcpStream,
    message_id: u64,
    session_id: u64,
    tree_id: u32,
    file_id: FileId,
    buffer: Vec<u8>,
) -> u32 {
    let req = SetInfoRequest {
        structure_size: 33,
        info_type: InfoType::File as u8,
        file_information_class: 0x04,
        buffer_length: buffer.len() as u32,
        buffer_offset: 64 + 32,
        reserved: 0,
        additional_information: 0,
        file_id,
        buffer,
    };
    let mut body = Vec::new();
    req.write_to(&mut body).expect("write set basic");
    let hdr = build_header(Command::SetInfo, message_id, session_id, tree_id);
    write_frame(s, &hdr, &body).await;
    let resp = read_frame(s).await;
    let (rh, _rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::SetInfo);
    rh.channel_sequence_status
}

async fn set_end_of_file_status(
    s: &mut TcpStream,
    message_id: u64,
    session_id: u64,
    tree_id: u32,
    file_id: FileId,
    end_of_file: u64,
) -> u32 {
    let req = SetInfoRequest {
        structure_size: 33,
        info_type: InfoType::File as u8,
        file_information_class: 0x14,
        buffer_length: 8,
        buffer_offset: 64 + 32,
        reserved: 0,
        additional_information: 0,
        file_id,
        buffer: end_of_file.to_le_bytes().to_vec(),
    };
    let mut body = Vec::new();
    req.write_to(&mut body).expect("write set eof");
    let hdr = build_header(Command::SetInfo, message_id, session_id, tree_id);
    write_frame(s, &hdr, &body).await;
    let resp = read_frame(s).await;
    let (rh, _rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::SetInfo);
    rh.channel_sequence_status
}

async fn query_basic_information(
    s: &mut TcpStream,
    message_id: u64,
    session_id: u64,
    tree_id: u32,
    file_id: FileId,
) -> Vec<u8> {
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
    req.write_to(&mut body).expect("write query basic");
    let hdr = build_header(Command::QueryInfo, message_id, session_id, tree_id);
    write_frame(s, &hdr, &body).await;
    let resp = read_frame(s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::QueryInfo);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    QueryInfoResponse::parse(rb)
        .expect("parse basic info resp")
        .buffer
}

async fn close_file(
    s: &mut TcpStream,
    message_id: u64,
    session_id: u64,
    tree_id: u32,
    file_id: FileId,
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
    let _ = CloseResponse::parse(rb).expect("parse close resp");
}

async fn change_notify_status(
    s: &mut TcpStream,
    message_id: u64,
    session_id: u64,
    tree_id: u32,
    req: ChangeNotifyRequest,
) -> u32 {
    let mut body = Vec::new();
    req.write_to(&mut body).expect("write change notify");
    let hdr = build_header(Command::ChangeNotify, message_id, session_id, tree_id);
    write_frame(s, &hdr, &body).await;
    let resp = read_frame(s).await;
    let (rh, _rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::ChangeNotify);
    rh.channel_sequence_status
}

async fn send_change_notify(
    s: &mut TcpStream,
    message_id: u64,
    session_id: u64,
    tree_id: u32,
    req: ChangeNotifyRequest,
) -> Smb2Header {
    let mut body = Vec::new();
    req.write_to(&mut body).expect("write change notify");
    let hdr = build_header(Command::ChangeNotify, message_id, session_id, tree_id);
    write_frame(s, &hdr, &body).await;
    let resp = read_frame(s).await;
    let (rh, _rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::ChangeNotify);
    rh
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

async fn read_frame_with_test_timeout(s: &mut TcpStream, label: &str) -> Vec<u8> {
    tokio::time::timeout(std::time::Duration::from_secs(2), read_frame(s))
        .await
        .unwrap_or_else(|_| panic!("timed out reading {label}"))
}

async fn send_sync_cancel(
    s: &mut TcpStream,
    original_message_id: u64,
    session_id: u64,
    tree_id: u32,
) {
    let mut body = Vec::new();
    CancelRequest::default()
        .write_to(&mut body)
        .expect("write cancel");
    let hdr = build_header(Command::Cancel, original_message_id, session_id, tree_id);
    write_frame(s, &hdr, &body).await;
}

fn decode_file_notify_information(buf: &[u8]) -> (u32, String) {
    assert!(buf.len() >= 12, "short FILE_NOTIFY_INFORMATION");
    let next_entry_offset = u32::from_le_bytes(buf[0..4].try_into().unwrap());
    assert_eq!(next_entry_offset, 0);
    let action = u32::from_le_bytes(buf[4..8].try_into().unwrap());
    let name_len = u32::from_le_bytes(buf[8..12].try_into().unwrap()) as usize;
    assert!(buf.len() >= 12 + name_len, "short notify file name");
    let name = buf[12..12 + name_len]
        .chunks_exact(2)
        .map(|chunk| u16::from_le_bytes(chunk.try_into().unwrap()))
        .collect::<Vec<_>>();
    (
        action,
        String::from_utf16(&name).expect("utf16 notify name"),
    )
}

fn decode_file_notify_records(mut buf: &[u8]) -> Vec<(u32, String)> {
    let mut out = Vec::new();
    while !buf.is_empty() {
        assert!(buf.len() >= 12, "short FILE_NOTIFY_INFORMATION");
        let next_entry_offset = u32::from_le_bytes(buf[0..4].try_into().unwrap()) as usize;
        let action = u32::from_le_bytes(buf[4..8].try_into().unwrap());
        let name_len = u32::from_le_bytes(buf[8..12].try_into().unwrap()) as usize;
        assert!(buf.len() >= 12 + name_len, "short notify file name");
        let name = buf[12..12 + name_len]
            .chunks_exact(2)
            .map(|chunk| u16::from_le_bytes(chunk.try_into().unwrap()))
            .collect::<Vec<_>>();
        out.push((
            action,
            String::from_utf16(&name).expect("utf16 notify name"),
        ));
        if next_entry_offset == 0 {
            break;
        }
        assert!(next_entry_offset <= buf.len(), "invalid notify next offset");
        buf = &buf[next_entry_offset..];
    }
    out
}

async fn create_child_and_expect_notify(
    s: &mut TcpStream,
    message_id: u64,
    session_id: u64,
    tree_id: u32,
    child_name: &str,
    async_id: u64,
    expected_notify_status: u32,
) -> (ChangeNotifyResponse, FileId) {
    let create_req = create_request(
        child_name,
        0x001f_01ff,
        FILE_ATTRIBUTE_NORMAL,
        2,
        0x0000_0040,
    );
    let mut body = Vec::new();
    create_req.write_to(&mut body).expect("write create");
    let hdr = build_header(Command::Create, message_id, session_id, tree_id);
    write_frame(s, &hdr, &body).await;

    let mut notify = None;
    let mut created_file = None;
    for _ in 0..2 {
        let resp = read_frame(s).await;
        let (rh, rb) = parse_response_header(&resp);
        match rh.command {
            Command::Create => {
                assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
                created_file = Some(
                    CreateResponse::parse(rb)
                        .expect("parse create resp")
                        .file_id,
                );
            }
            Command::ChangeNotify => {
                assert_eq!(rh.channel_sequence_status, expected_notify_status);
                assert!(rh.is_async());
                assert_eq!(rh.async_id(), Some(async_id));
                assert_eq!(rh.credit_request_response, 0);
                notify = Some(ChangeNotifyResponse::parse(rb).expect("parse notify resp"));
            }
            other => panic!("unexpected response {other:?}"),
        }
    }
    (
        notify.expect("missing change notify response"),
        created_file.expect("missing create response"),
    )
}

#[tokio::test]
async fn end_to_end_anon_read_localfs() {
    // 1. Pre-populate a temp dir: one file with known contents + one empty subdir.
    let td = tempdir().expect("tempdir");
    std::fs::write(td.path().join("hello.txt"), b"hi").expect("write hello.txt");
    std::fs::write(td.path().join("held-delete.txt"), b"held open").expect("write held-delete.txt");
    std::fs::create_dir(td.path().join("sub")).expect("mkdir sub");

    // 2. Stand up an `SmbServer` with a single anonymous share over LocalFsBackend.
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

    // ---- COMPOUND: CREATE root + QUERY_INFO(FileAll) + CLOSE -------------
    let cr_compound_req = CreateRequest {
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
        name_length: 0,
        create_contexts_offset: 0,
        create_contexts_length: 0,
        name: vec![],
        create_contexts: vec![],
    };
    let mut create_body = Vec::new();
    cr_compound_req.write_to(&mut create_body).expect("write");
    let mut create_hdr = build_header(Command::Create, 4, session_id, tree_id);

    let qi_req = QueryInfoRequest {
        structure_size: 41,
        info_type: InfoType::File as u8,
        file_information_class: 0x12,
        output_buffer_length: 4096,
        input_buffer_offset: 0,
        reserved: 0,
        input_buffer_length: 0,
        additional_information: 0,
        flags: 0,
        file_id: FileId::any(),
        input_buffer: vec![],
    };
    let mut qi_body = Vec::new();
    qi_req.write_to(&mut qi_body).expect("write");
    let mut qi_hdr = build_header(Command::QueryInfo, 5, u64::MAX, u32::MAX);
    qi_hdr.flags |= SMB2_FLAGS_RELATED_OPERATIONS;

    let close_req = CloseRequest {
        structure_size: 24,
        flags: 0,
        reserved: 0,
        file_id: FileId::any(),
    };
    let mut close_body = Vec::new();
    close_req.write_to(&mut close_body).expect("write");
    let mut close_hdr = build_header(Command::Close, 6, u64::MAX, u32::MAX);
    close_hdr.flags |= SMB2_FLAGS_RELATED_OPERATIONS;

    let mut compound = Vec::new();
    append_compound_part(&mut compound, &mut create_hdr, &create_body, true);
    append_compound_part(&mut compound, &mut qi_hdr, &qi_body, true);
    append_compound_part(&mut compound, &mut close_hdr, &close_body, false);
    let mut framed = Vec::new();
    encode_frame(&compound, &mut framed);
    s.write_all(&framed).await.expect("write compound");

    let resp = read_frame(&mut s).await;
    let (create_resp_hdr, create_resp_body) = parse_response_header(&resp);
    assert_eq!(create_resp_hdr.command, Command::Create);
    assert_eq!(create_resp_hdr.channel_sequence_status, STATUS_SUCCESS);
    assert_ne!(create_resp_hdr.next_command, 0);
    let create_next = create_resp_hdr.next_command as usize;
    let cr_compound_resp =
        CreateResponse::parse(create_resp_body).expect("parse compound create resp");
    assert_ne!(cr_compound_resp.file_id, FileId::any());

    let (query_resp_hdr, query_resp_body) = parse_response_header(&resp[create_next..]);
    assert_eq!(query_resp_hdr.command, Command::QueryInfo);
    assert_eq!(query_resp_hdr.channel_sequence_status, STATUS_SUCCESS);
    assert_ne!(query_resp_hdr.next_command, 0);
    let qi_resp = QueryInfoResponse::parse(query_resp_body).expect("parse compound query resp");
    assert!(qi_resp.buffer.len() >= 101);

    let close_offset = create_next + query_resp_hdr.next_command as usize;
    let (close_resp_hdr, close_resp_body) = parse_response_header(&resp[close_offset..]);
    assert_eq!(close_resp_hdr.command, Command::Close);
    assert_eq!(close_resp_hdr.channel_sequence_status, STATUS_SUCCESS);
    assert_eq!(close_resp_hdr.next_command, 0);
    let _ = CloseResponse::parse(close_resp_body).expect("parse compound close resp");

    // ---- CREATE share root without FILE_DIRECTORY_FILE -------------------
    // Windows Explorer opens directories this way before issuing
    // FileIdBothDirectoryInformation queries.
    let cr_root_req = CreateRequest {
        structure_size: 57,
        security_flags: 0,
        requested_oplock_level: 0,
        impersonation_level: 2,
        smb_create_flags: 0,
        reserved: 0,
        desired_access: 0x0012_0089, // FILE_GENERIC_READ
        file_attributes: 0,
        share_access: 0x0000_0007,
        create_disposition: 1, // FILE_OPEN
        create_options: 0,
        name_offset: 0x78,
        name_length: 0,
        create_contexts_offset: 0,
        create_contexts_length: 0,
        name: vec![],
        create_contexts: vec![],
    };
    let mut body = Vec::new();
    cr_root_req.write_to(&mut body).expect("write");
    let hdr = build_header(Command::Create, 7, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Create);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let cr_root_resp = CreateResponse::parse(rb).expect("parse root create resp");
    let root_dir_id = cr_root_resp.file_id;
    assert_ne!(
        cr_root_resp.file_attributes & 0x10,
        0,
        "root is a directory"
    );

    // ---- QUERY_INFO FileFullEaInformation returns empty EA blob -----------
    let ea_req = QueryInfoRequest {
        structure_size: 41,
        info_type: InfoType::File as u8,
        file_information_class: 0x0F,
        output_buffer_length: 4096,
        input_buffer_offset: 0,
        reserved: 0,
        input_buffer_length: 0,
        additional_information: 0,
        flags: 0,
        file_id: root_dir_id,
        input_buffer: vec![],
    };
    let mut body = Vec::new();
    ea_req.write_to(&mut body).expect("write");
    let hdr = build_header(Command::QueryInfo, 8, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::QueryInfo);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let ea_resp = QueryInfoResponse::parse(rb).expect("parse empty EA query resp");
    assert_eq!(ea_resp.buffer, vec![0; 4]);

    let denied_ea = full_ea_information("DeniedEA", b"value");
    let denied_ea_req = SetInfoRequest {
        structure_size: 33,
        info_type: InfoType::File as u8,
        file_information_class: 0x0F,
        buffer_length: denied_ea.len() as u32,
        buffer_offset: 64 + 32,
        reserved: 0,
        additional_information: 0,
        file_id: root_dir_id,
        buffer: denied_ea,
    };
    let mut body = Vec::new();
    denied_ea_req.write_to(&mut body).expect("write");
    let hdr = build_header(Command::SetInfo, 9, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, _rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::SetInfo);
    assert_eq!(rh.channel_sequence_status, 0xC000_0022);

    // ---- QUERY_INFO FileSystem classes and SMB2 buffer status ------------
    let fs_attr_too_small_req = QueryInfoRequest {
        structure_size: 41,
        info_type: InfoType::FileSystem as u8,
        file_information_class: 0x05,
        output_buffer_length: 15,
        input_buffer_offset: 0,
        reserved: 0,
        input_buffer_length: 0,
        additional_information: 0,
        flags: 0,
        file_id: root_dir_id,
        input_buffer: vec![],
    };
    let mut body = Vec::new();
    fs_attr_too_small_req.write_to(&mut body).expect("write");
    let hdr = build_header(Command::QueryInfo, 109, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, _rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::QueryInfo);
    assert_eq!(rh.channel_sequence_status, 0xC000_0004);

    let fs_attr_truncated_req = QueryInfoRequest {
        output_buffer_length: 16,
        ..fs_attr_too_small_req.clone()
    };
    let mut body = Vec::new();
    fs_attr_truncated_req.write_to(&mut body).expect("write");
    let hdr = build_header(Command::QueryInfo, 110, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::QueryInfo);
    assert_eq!(rh.channel_sequence_status, 0x8000_0005);
    let fs_attr = QueryInfoResponse::parse(rb).expect("parse truncated fs attr resp");
    assert_eq!(fs_attr.buffer.len(), 16);

    for (message_id, class, fixed_len) in [
        (111, 0x02, 48),
        (112, 0x06, 48),
        (113, 0x08, 64),
        (114, 0x0b, 28),
    ] {
        let fs_req = QueryInfoRequest {
            file_information_class: class,
            output_buffer_length: fixed_len,
            ..fs_attr_too_small_req.clone()
        };
        let mut body = Vec::new();
        fs_req.write_to(&mut body).expect("write");
        let hdr = build_header(Command::QueryInfo, message_id, session_id, tree_id);
        write_frame(&mut s, &hdr, &body).await;
        let resp = read_frame(&mut s).await;
        let (rh, rb) = parse_response_header(&resp);
        assert_eq!(rh.command, Command::QueryInfo);
        assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
        let fs_info = QueryInfoResponse::parse(rb).expect("parse fs info resp");
        assert_eq!(fs_info.buffer.len(), fixed_len as usize);
    }

    // ---- QUERY_DIRECTORY FileIdBothDirectoryInformation ------------------
    let pat = utf16le("*");
    let qd_req = QueryDirectoryRequest {
        structure_size: 33,
        file_information_class: 0x25, // FileIdBothDirectoryInformation
        flags: QueryDirectoryRequest::FLAG_RESTART_SCANS,
        file_index: 0,
        file_id: root_dir_id,
        file_name_offset: 64 + 32,
        file_name_length: pat.len() as u16,
        output_buffer_length: 4096,
        file_name: pat,
    };
    let mut body = Vec::new();
    qd_req.write_to(&mut body).expect("write");
    let hdr = build_header(Command::QueryDirectory, 10, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::QueryDirectory);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let qd_resp = QueryDirectoryResponse::parse(rb).expect("parse query directory resp");
    assert!(qd_resp.output_buffer_length >= 104);
    let names = decode_file_id_both_names(&qd_resp.buffer);
    assert!(names.iter().any(|n| n == "hello.txt"), "names={names:?}");
    assert!(names.iter().any(|n| n == "sub"), "names={names:?}");

    // ---- CLOSE root dir --------------------------------------------------
    let cl_root_req = CloseRequest {
        structure_size: 24,
        flags: 0,
        reserved: 0,
        file_id: root_dir_id,
    };
    let mut body = Vec::new();
    cl_root_req.write_to(&mut body).expect("write");
    let hdr = build_header(Command::Close, 11, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Close);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let _ = CloseResponse::parse(rb).expect("parse root close resp");

    // ---- Directory default stream status/listing -------------------------
    let sub_default_stream_name = utf16le("sub::$DATA");
    let sub_default_dir_req = CreateRequest {
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
        create_options: 0x0000_0001,
        name_offset: 0x78,
        name_length: sub_default_stream_name.len() as u16,
        create_contexts_offset: 0,
        create_contexts_length: 0,
        name: sub_default_stream_name.clone(),
        create_contexts: vec![],
    };
    let mut body = Vec::new();
    sub_default_dir_req.write_to(&mut body).expect("write");
    let hdr = build_header(Command::Create, 60, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, _rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Create);
    assert_eq!(rh.channel_sequence_status, 0xC000_0103);

    let sub_default_req = CreateRequest {
        create_options: 0,
        ..sub_default_dir_req
    };
    let mut body = Vec::new();
    sub_default_req.write_to(&mut body).expect("write");
    let hdr = build_header(Command::Create, 61, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, _rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Create);
    assert_eq!(rh.channel_sequence_status, 0xC000_00BA);

    let sub_name = utf16le("sub");
    let sub_dir_req = CreateRequest {
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
        create_options: 0x0000_0001,
        name_offset: 0x78,
        name_length: sub_name.len() as u16,
        create_contexts_offset: 0,
        create_contexts_length: 0,
        name: sub_name,
        create_contexts: vec![],
    };
    let mut body = Vec::new();
    sub_dir_req.write_to(&mut body).expect("write");
    let hdr = build_header(Command::Create, 62, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Create);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let sub_dir_id = CreateResponse::parse(rb)
        .expect("parse sub dir create resp")
        .file_id;

    let sub_stream_info_req = QueryInfoRequest {
        structure_size: 41,
        info_type: InfoType::File as u8,
        file_information_class: 0x16,
        output_buffer_length: 4096,
        input_buffer_offset: 0,
        reserved: 0,
        input_buffer_length: 0,
        additional_information: 0,
        flags: 0,
        file_id: sub_dir_id,
        input_buffer: vec![],
    };
    let mut body = Vec::new();
    sub_stream_info_req.write_to(&mut body).expect("write");
    let hdr = build_header(Command::QueryInfo, 63, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::QueryInfo);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let sub_stream_info = QueryInfoResponse::parse(rb).expect("parse sub dir stream info resp");
    assert!(sub_stream_info.buffer.is_empty());

    let sub_named_stream_name = utf16le("sub:streamtwo");
    let sub_named_stream_req = CreateRequest {
        structure_size: 57,
        security_flags: 0,
        requested_oplock_level: 0,
        impersonation_level: 2,
        smb_create_flags: 0,
        reserved: 0,
        desired_access: 0x0013_019F,
        file_attributes: 0,
        share_access: 0x0000_0007,
        create_disposition: 2,
        create_options: 0x0000_0040,
        name_offset: 0x78,
        name_length: sub_named_stream_name.len() as u16,
        create_contexts_offset: 0,
        create_contexts_length: 0,
        name: sub_named_stream_name,
        create_contexts: vec![],
    };
    let mut body = Vec::new();
    sub_named_stream_req.write_to(&mut body).expect("write");
    let hdr = build_header(Command::Create, 65, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Create);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let sub_named_stream_id = CreateResponse::parse(rb)
        .expect("parse sub named stream create resp")
        .file_id;

    let wr_req = smb_server::wire::messages::WriteRequest {
        structure_size: 49,
        data_offset: 64 + 48,
        length: 10,
        offset: 0,
        file_id: sub_named_stream_id,
        channel: 0,
        remaining_bytes: 0,
        write_channel_info_offset: 0,
        write_channel_info_length: 0,
        flags: 0,
        data: b"dir-stream".to_vec(),
    };
    let mut body = Vec::new();
    wr_req.write_to(&mut body).expect("write");
    let hdr = build_header(Command::Write, 66, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, _rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Write);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);

    let mut body = Vec::new();
    sub_stream_info_req.write_to(&mut body).expect("write");
    let hdr = build_header(Command::QueryInfo, 67, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::QueryInfo);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let sub_stream_info =
        QueryInfoResponse::parse(rb).expect("parse sub dir named stream info resp");
    let streams = decode_stream_information(&sub_stream_info.buffer);
    assert_eq!(streams, vec![(":streamtwo:$DATA".to_string(), 10)]);

    let cl_sub_named_stream_req = CloseRequest {
        structure_size: 24,
        flags: 0,
        reserved: 0,
        file_id: sub_named_stream_id,
    };
    let mut body = Vec::new();
    cl_sub_named_stream_req.write_to(&mut body).expect("write");
    let hdr = build_header(Command::Close, 68, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Close);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let _ = CloseResponse::parse(rb).expect("parse sub named stream close resp");

    let cl_sub_dir_req = CloseRequest {
        structure_size: 24,
        flags: 0,
        reserved: 0,
        file_id: sub_dir_id,
    };
    let mut body = Vec::new();
    cl_sub_dir_req.write_to(&mut body).expect("write");
    let hdr = build_header(Command::Close, 64, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Close);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let _ = CloseResponse::parse(rb).expect("parse sub dir close resp");

    // ---- CREATE hello.txt (read-only intent) -----------------------------
    let name_u16 = utf16le("hello.txt");
    let cr_req = CreateRequest {
        structure_size: 57,
        security_flags: 0,
        requested_oplock_level: 0,
        impersonation_level: 2,
        smb_create_flags: 0,
        reserved: 0,
        desired_access: 0x0012_0089 | 0x0000_0010 | 0x0004_0000, // FILE_GENERIC_READ | FILE_WRITE_EA | WRITE_DAC
        file_attributes: 0,
        share_access: 0x0000_0007, // FILE_SHARE_READ|WRITE|DELETE
        create_disposition: 1,     // FILE_OPEN
        create_options: 0,
        name_offset: 0x78,
        name_length: name_u16.len() as u16,
        create_contexts_offset: 0,
        create_contexts_length: 0,
        name: name_u16,
        create_contexts: vec![],
    };
    let mut body = Vec::new();
    cr_req.write_to(&mut body).expect("write");
    let hdr = build_header(Command::Create, 12, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Create);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let cr_resp = CreateResponse::parse(rb).expect("parse create resp");
    let file_id = cr_resp.file_id;
    assert_eq!(
        cr_resp.end_of_file, 2,
        "hello.txt was pre-populated as b\"hi\""
    );

    let attr_only_req = CreateRequest {
        structure_size: 57,
        security_flags: 0,
        requested_oplock_level: 0,
        impersonation_level: 2,
        smb_create_flags: 0,
        reserved: 0,
        desired_access: 0x0000_0080,
        file_attributes: 0,
        share_access: 0x0000_0007,
        create_disposition: 1,
        create_options: 0,
        name_offset: 0x78,
        name_length: utf16le("hello.txt").len() as u16,
        create_contexts_offset: 0,
        create_contexts_length: 0,
        name: utf16le("hello.txt"),
        create_contexts: vec![],
    };
    let mut body = Vec::new();
    attr_only_req.write_to(&mut body).expect("write");
    let hdr = build_header(Command::Create, 13, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Create);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let attr_only_id = CreateResponse::parse(rb)
        .expect("parse attr-only create resp")
        .file_id;

    let denied_full_ea_req = QueryInfoRequest {
        structure_size: 41,
        info_type: InfoType::File as u8,
        file_information_class: 0x0F,
        output_buffer_length: 4096,
        input_buffer_offset: 0,
        reserved: 0,
        input_buffer_length: 0,
        additional_information: 0,
        flags: 0,
        file_id: attr_only_id,
        input_buffer: vec![],
    };
    let mut body = Vec::new();
    denied_full_ea_req.write_to(&mut body).expect("write");
    let hdr = build_header(Command::QueryInfo, 14, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, _rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::QueryInfo);
    assert_eq!(rh.channel_sequence_status, 0xC000_0022);

    let denied_ea_size_req = QueryInfoRequest {
        file_information_class: 0x07,
        output_buffer_length: 4,
        ..denied_full_ea_req.clone()
    };
    let mut body = Vec::new();
    denied_ea_size_req.write_to(&mut body).expect("write");
    let hdr = build_header(Command::QueryInfo, 103, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, _rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::QueryInfo);
    assert_eq!(rh.channel_sequence_status, 0xC000_0022);

    let access_info_req = QueryInfoRequest {
        file_information_class: 0x08,
        output_buffer_length: 4,
        ..denied_full_ea_req
    };
    let mut body = Vec::new();
    access_info_req.write_to(&mut body).expect("write");
    let hdr = build_header(Command::QueryInfo, 107, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::QueryInfo);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let access_info = QueryInfoResponse::parse(rb).expect("parse attr-only access info resp");
    assert_eq!(access_info.buffer.len(), 4);
    assert_eq!(
        u32::from_le_bytes(access_info.buffer[0..4].try_into().unwrap()),
        0x0000_0080
    );

    let all_info_req = QueryInfoRequest {
        file_information_class: 0x12,
        output_buffer_length: 4096,
        ..access_info_req
    };
    let mut body = Vec::new();
    all_info_req.write_to(&mut body).expect("write");
    let hdr = build_header(Command::QueryInfo, 108, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::QueryInfo);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let all_info = QueryInfoResponse::parse(rb).expect("parse attr-only all info resp");
    assert!(all_info.buffer.len() >= 80);
    assert_eq!(
        u32::from_le_bytes(all_info.buffer[76..80].try_into().unwrap()),
        0x0000_0080
    );

    let denied_security_req = QueryInfoRequest {
        structure_size: 41,
        info_type: InfoType::Security as u8,
        file_information_class: 0,
        output_buffer_length: 4096,
        input_buffer_offset: 0,
        reserved: 0,
        input_buffer_length: 0,
        additional_information: 0,
        flags: 0,
        file_id: attr_only_id,
        input_buffer: vec![],
    };
    let mut body = Vec::new();
    denied_security_req.write_to(&mut body).expect("write");
    let hdr = build_header(Command::QueryInfo, 77, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, _rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::QueryInfo);
    assert_eq!(rh.channel_sequence_status, 0xC000_0022);

    let cl_attr_req = CloseRequest {
        structure_size: 24,
        flags: 0,
        reserved: 0,
        file_id: attr_only_id,
    };
    let mut body = Vec::new();
    cl_attr_req.write_to(&mut body).expect("write");
    let hdr = build_header(Command::Close, 15, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Close);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let _ = CloseResponse::parse(rb).expect("parse attr-only close resp");

    let read_ea_only_req = CreateRequest {
        desired_access: 0x0000_0008,
        ..attr_only_req
    };
    let mut body = Vec::new();
    read_ea_only_req.write_to(&mut body).expect("write");
    let hdr = build_header(Command::Create, 104, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Create);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let read_ea_only_id = CreateResponse::parse(rb)
        .expect("parse read-ea-only create resp")
        .file_id;

    let read_ea_basic_req = QueryInfoRequest {
        structure_size: 41,
        info_type: InfoType::File as u8,
        file_information_class: 0x04,
        output_buffer_length: 40,
        input_buffer_offset: 0,
        reserved: 0,
        input_buffer_length: 0,
        additional_information: 0,
        flags: 0,
        file_id: read_ea_only_id,
        input_buffer: vec![],
    };
    let mut body = Vec::new();
    read_ea_basic_req.write_to(&mut body).expect("write");
    let hdr = build_header(Command::QueryInfo, 105, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::QueryInfo);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let _ = QueryInfoResponse::parse(rb).expect("parse read-ea basic info resp");

    let cl_read_ea_req = CloseRequest {
        structure_size: 24,
        flags: 0,
        reserved: 0,
        file_id: read_ea_only_id,
    };
    let mut body = Vec::new();
    cl_read_ea_req.write_to(&mut body).expect("write");
    let hdr = build_header(Command::Close, 106, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Close);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let _ = CloseResponse::parse(rb).expect("parse read-ea-only close resp");

    let sync_name = utf16le("hello.txt");
    let sync_only_req = CreateRequest {
        structure_size: 57,
        security_flags: 0,
        requested_oplock_level: 0,
        impersonation_level: 2,
        smb_create_flags: 0,
        reserved: 0,
        desired_access: 0x0010_0000,
        file_attributes: 0,
        share_access: 0x0000_0007,
        create_disposition: 1,
        create_options: 0x0000_0040,
        name_offset: 0x78,
        name_length: sync_name.len() as u16,
        create_contexts_offset: 0,
        create_contexts_length: 0,
        name: sync_name,
        create_contexts: vec![],
    };
    let mut body = Vec::new();
    sync_only_req.write_to(&mut body).expect("write");
    let hdr = build_header(Command::Create, 78, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Create);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let sync_only_id = CreateResponse::parse(rb)
        .expect("parse sync-only create resp")
        .file_id;

    let denied_basic_req = QueryInfoRequest {
        structure_size: 41,
        info_type: InfoType::File as u8,
        file_information_class: 0x04,
        output_buffer_length: 40,
        input_buffer_offset: 0,
        reserved: 0,
        input_buffer_length: 0,
        additional_information: 0,
        flags: 0,
        file_id: sync_only_id,
        input_buffer: vec![],
    };
    let mut body = Vec::new();
    denied_basic_req.write_to(&mut body).expect("write");
    let hdr = build_header(Command::QueryInfo, 79, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, _rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::QueryInfo);
    assert_eq!(rh.channel_sequence_status, 0xC000_0022);

    let allowed_stream_req = QueryInfoRequest {
        file_information_class: 0x16,
        output_buffer_length: 4096,
        ..denied_basic_req
    };
    let mut body = Vec::new();
    allowed_stream_req.write_to(&mut body).expect("write");
    let hdr = build_header(Command::QueryInfo, 80, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::QueryInfo);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let _ = QueryInfoResponse::parse(rb).expect("parse sync-only stream info resp");

    let denied_set_basic_req = SetInfoRequest {
        structure_size: 33,
        info_type: InfoType::File as u8,
        file_information_class: 0x04,
        buffer_length: 40,
        buffer_offset: 64 + 32,
        reserved: 0,
        additional_information: 0,
        file_id: sync_only_id,
        buffer: vec![0; 40],
    };
    let mut body = Vec::new();
    denied_set_basic_req.write_to(&mut body).expect("write");
    let hdr = build_header(Command::SetInfo, 82, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, _rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::SetInfo);
    assert_eq!(rh.channel_sequence_status, 0xC000_0022);

    let denied_set_eof_req = SetInfoRequest {
        file_information_class: 0x14,
        buffer_length: 8,
        buffer: 2u64.to_le_bytes().to_vec(),
        ..denied_set_basic_req.clone()
    };
    let mut body = Vec::new();
    denied_set_eof_req.write_to(&mut body).expect("write");
    let hdr = build_header(Command::SetInfo, 83, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, _rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::SetInfo);
    assert_eq!(rh.channel_sequence_status, 0xC000_0022);

    let denied_set_disposition_req = SetInfoRequest {
        file_information_class: 0x0D,
        buffer_length: 1,
        buffer: vec![1],
        ..denied_set_basic_req
    };
    let mut body = Vec::new();
    denied_set_disposition_req
        .write_to(&mut body)
        .expect("write");
    let hdr = build_header(Command::SetInfo, 84, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, _rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::SetInfo);
    assert_eq!(rh.channel_sequence_status, 0xC000_0022);

    let cl_sync_req = CloseRequest {
        structure_size: 24,
        flags: 0,
        reserved: 0,
        file_id: sync_only_id,
    };
    let mut body = Vec::new();
    cl_sync_req.write_to(&mut body).expect("write");
    let hdr = build_header(Command::Close, 81, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Close);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let _ = CloseResponse::parse(rb).expect("parse sync-only close resp");

    // ---- SET_INFO / QUERY_INFO ExtendedAttributes -----------------------
    let ea = full_ea_information("NewEA", b"testme");
    let set_ea_req = SetInfoRequest {
        structure_size: 33,
        info_type: InfoType::File as u8,
        file_information_class: 0x0F,
        buffer_length: ea.len() as u32,
        buffer_offset: 64 + 32,
        reserved: 0,
        additional_information: 0,
        file_id,
        buffer: ea.clone(),
    };
    let mut body = Vec::new();
    set_ea_req.write_to(&mut body).expect("write");
    let hdr = build_header(Command::SetInfo, 16, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, _rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::SetInfo);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);

    let query_ea_req = QueryInfoRequest {
        structure_size: 41,
        info_type: InfoType::File as u8,
        file_information_class: 0x0F,
        output_buffer_length: 4096,
        input_buffer_offset: 0,
        reserved: 0,
        input_buffer_length: 0,
        additional_information: 0,
        flags: 0,
        file_id,
        input_buffer: vec![],
    };
    let mut body = Vec::new();
    query_ea_req.write_to(&mut body).expect("write");
    let hdr = build_header(Command::QueryInfo, 17, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::QueryInfo);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let query_ea_resp = QueryInfoResponse::parse(rb).expect("parse EA query resp");
    assert_eq!(query_ea_resp.buffer, ea);

    let query_ea_size_req = QueryInfoRequest {
        structure_size: 41,
        info_type: InfoType::File as u8,
        file_information_class: 0x07,
        output_buffer_length: 4,
        input_buffer_offset: 0,
        reserved: 0,
        input_buffer_length: 0,
        additional_information: 0,
        flags: 0,
        file_id,
        input_buffer: vec![],
    };
    let mut body = Vec::new();
    query_ea_size_req.write_to(&mut body).expect("write");
    let hdr = build_header(Command::QueryInfo, 18, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::QueryInfo);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let query_ea_size_resp = QueryInfoResponse::parse(rb).expect("parse EA size query resp");
    assert_eq!(
        u32::from_le_bytes(query_ea_size_resp.buffer[0..4].try_into().unwrap()),
        ea.len() as u32
    );

    // ---- SET_INFO / QUERY_INFO SecurityDescriptor -----------------------
    let sd = minimal_self_relative_security_descriptor();
    let set_sd_req = SetInfoRequest {
        structure_size: 33,
        info_type: InfoType::Security as u8,
        file_information_class: 0,
        buffer_length: sd.len() as u32,
        buffer_offset: 64 + 32,
        reserved: 0,
        additional_information: 0,
        file_id,
        buffer: sd.clone(),
    };
    let mut body = Vec::new();
    set_sd_req.write_to(&mut body).expect("write");
    let hdr = build_header(Command::SetInfo, 19, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, _rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::SetInfo);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);

    let query_sd_req = QueryInfoRequest {
        structure_size: 41,
        info_type: InfoType::Security as u8,
        file_information_class: 0,
        output_buffer_length: 4096,
        input_buffer_offset: 0,
        reserved: 0,
        input_buffer_length: 0,
        additional_information: 0,
        flags: 0,
        file_id,
        input_buffer: vec![],
    };
    let mut body = Vec::new();
    query_sd_req.write_to(&mut body).expect("write");
    let hdr = build_header(Command::QueryInfo, 20, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::QueryInfo);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let query_sd_resp = QueryInfoResponse::parse(rb).expect("parse security query resp");
    assert_eq!(query_sd_resp.buffer, sd);

    for (message_id, output_buffer_length) in [(115, 0), (116, 1)] {
        let small_query_sd_req = QueryInfoRequest {
            output_buffer_length,
            ..query_sd_req.clone()
        };
        let mut body = Vec::new();
        small_query_sd_req.write_to(&mut body).expect("write");
        let hdr = build_header(Command::QueryInfo, message_id, session_id, tree_id);
        write_frame(&mut s, &hdr, &body).await;
        let resp = read_frame(&mut s).await;
        let (rh, _rb) = parse_response_header(&resp);
        assert_eq!(rh.command, Command::QueryInfo);
        assert_eq!(rh.channel_sequence_status, 0xC000_0023);
    }

    // ---- SET_INFO / QUERY_INFO per-open position and mode ----------------
    let position = 123_456u64;
    let set_position_req = SetInfoRequest {
        structure_size: 33,
        info_type: InfoType::File as u8,
        file_information_class: 0x0E,
        buffer_length: 8,
        buffer_offset: 64 + 32,
        reserved: 0,
        additional_information: 0,
        file_id,
        buffer: position.to_le_bytes().to_vec(),
    };
    let mut body = Vec::new();
    set_position_req.write_to(&mut body).expect("write");
    let hdr = build_header(Command::SetInfo, 85, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, _rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::SetInfo);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);

    let query_position_req = QueryInfoRequest {
        structure_size: 41,
        info_type: InfoType::File as u8,
        file_information_class: 0x0E,
        output_buffer_length: 8,
        input_buffer_offset: 0,
        reserved: 0,
        input_buffer_length: 0,
        additional_information: 0,
        flags: 0,
        file_id,
        input_buffer: vec![],
    };
    let mut body = Vec::new();
    query_position_req.write_to(&mut body).expect("write");
    let hdr = build_header(Command::QueryInfo, 86, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::QueryInfo);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let query_position_resp = QueryInfoResponse::parse(rb).expect("parse position query resp");
    assert_eq!(
        u64::from_le_bytes(query_position_resp.buffer[0..8].try_into().unwrap()),
        position
    );

    let mode = 2u32;
    let set_mode_req = SetInfoRequest {
        file_information_class: 0x10,
        buffer_length: 4,
        buffer: mode.to_le_bytes().to_vec(),
        ..set_position_req.clone()
    };
    let mut body = Vec::new();
    set_mode_req.write_to(&mut body).expect("write");
    let hdr = build_header(Command::SetInfo, 87, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, _rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::SetInfo);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);

    let query_mode_req = QueryInfoRequest {
        file_information_class: 0x10,
        output_buffer_length: 4,
        ..query_position_req.clone()
    };
    let mut body = Vec::new();
    query_mode_req.write_to(&mut body).expect("write");
    let hdr = build_header(Command::QueryInfo, 88, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::QueryInfo);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let query_mode_resp = QueryInfoResponse::parse(rb).expect("parse mode query resp");
    assert_eq!(
        u32::from_le_bytes(query_mode_resp.buffer[0..4].try_into().unwrap()),
        mode
    );

    let query_all_req = QueryInfoRequest {
        file_information_class: 0x12,
        output_buffer_length: 4096,
        ..query_position_req
    };
    let mut body = Vec::new();
    query_all_req.write_to(&mut body).expect("write");
    let hdr = build_header(Command::QueryInfo, 89, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::QueryInfo);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let query_all_resp = QueryInfoResponse::parse(rb).expect("parse all-info query resp");
    assert_eq!(
        u64::from_le_bytes(query_all_resp.buffer[80..88].try_into().unwrap()),
        position
    );
    assert_eq!(
        u32::from_le_bytes(query_all_resp.buffer[88..92].try_into().unwrap()),
        mode
    );

    let invalid_mode_req = SetInfoRequest {
        buffer: 1u32.to_le_bytes().to_vec(),
        ..set_mode_req.clone()
    };
    let mut body = Vec::new();
    invalid_mode_req.write_to(&mut body).expect("write");
    let hdr = build_header(Command::SetInfo, 90, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, _rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::SetInfo);
    assert_eq!(rh.channel_sequence_status, 0xC000_000D);

    let clear_mode_req = SetInfoRequest {
        buffer: 0u32.to_le_bytes().to_vec(),
        ..set_mode_req
    };
    let mut body = Vec::new();
    clear_mode_req.write_to(&mut body).expect("write");
    let hdr = build_header(Command::SetInfo, 91, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, _rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::SetInfo);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);

    let mut body = Vec::new();
    query_mode_req.write_to(&mut body).expect("write");
    let hdr = build_header(Command::QueryInfo, 92, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::QueryInfo);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let query_mode_resp = QueryInfoResponse::parse(rb).expect("parse cleared mode query resp");
    assert_eq!(
        u32::from_le_bytes(query_mode_resp.buffer[0..4].try_into().unwrap()),
        0
    );

    // ---- CREATE share-mode conflict -------------------------------------
    let shared_read_name = utf16le("hello.txt");
    let shared_read_req = CreateRequest {
        structure_size: 57,
        security_flags: 0,
        requested_oplock_level: 0,
        impersonation_level: 2,
        smb_create_flags: 0,
        reserved: 0,
        desired_access: 0x0000_0001,
        file_attributes: 0,
        share_access: 0x0000_0001,
        create_disposition: 1,
        create_options: 0x0000_0040,
        name_offset: 0x78,
        name_length: shared_read_name.len() as u16,
        create_contexts_offset: 0,
        create_contexts_length: 0,
        name: shared_read_name,
        create_contexts: vec![],
    };
    let mut body = Vec::new();
    shared_read_req.write_to(&mut body).expect("write");
    let hdr = build_header(Command::Create, 91, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Create);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let shared_read_id = CreateResponse::parse(rb)
        .expect("parse shared read create resp")
        .file_id;

    let write_conflict_req = CreateRequest {
        desired_access: 0x0000_0002,
        share_access: 0x0000_0007,
        ..shared_read_req
    };
    let mut body = Vec::new();
    write_conflict_req.write_to(&mut body).expect("write");
    let hdr = build_header(Command::Create, 92, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, _rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Create);
    assert_eq!(rh.channel_sequence_status, 0xC000_0043);

    let mut s2 = TcpStream::connect(addr)
        .await
        .expect("connect second client");
    let _ = negotiate(&mut s2).await;
    let session2_id = anonymous_session_setup(&mut s2).await;
    let tree2_id = tree_connect(&mut s2, "\\\\127.0.0.1\\share", session2_id, 3).await;
    let second_client_conflict_req = CreateRequest {
        desired_access: 0x0000_0002,
        share_access: 0x0000_0007,
        ..write_conflict_req
    };
    let mut body = Vec::new();
    second_client_conflict_req
        .write_to(&mut body)
        .expect("write");
    let hdr = build_header(Command::Create, 94, session2_id, tree2_id);
    write_frame(&mut s2, &hdr, &body).await;
    let resp = read_frame(&mut s2).await;
    let (rh, _rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Create);
    assert_eq!(rh.channel_sequence_status, 0xC000_0043);

    let cl_shared_read_req = CloseRequest {
        structure_size: 24,
        flags: 0,
        reserved: 0,
        file_id: shared_read_id,
    };
    let mut body = Vec::new();
    cl_shared_read_req.write_to(&mut body).expect("write");
    let hdr = build_header(Command::Close, 93, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Close);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let _ = CloseResponse::parse(rb).expect("parse shared read close resp");

    // ---- Delete-on-close waits for the last live open --------------------
    let held_name = utf16le("held-delete.txt");
    let held_req = CreateRequest {
        structure_size: 57,
        security_flags: 0,
        requested_oplock_level: 0,
        impersonation_level: 2,
        smb_create_flags: 0,
        reserved: 0,
        desired_access: 0x0000_0081,
        file_attributes: 0,
        share_access: 0x0000_0007,
        create_disposition: 1,
        create_options: 0x0000_0040,
        name_offset: 0x78,
        name_length: held_name.len() as u16,
        create_contexts_offset: 0,
        create_contexts_length: 0,
        name: held_name.clone(),
        create_contexts: vec![],
    };
    let mut body = Vec::new();
    held_req.write_to(&mut body).expect("write");
    let hdr = build_header(Command::Create, 95, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Create);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let held_id = CreateResponse::parse(rb)
        .expect("parse held-delete create resp")
        .file_id;

    let delete_req = CreateRequest {
        desired_access: 0x0001_0080,
        ..held_req
    };
    let mut body = Vec::new();
    delete_req.write_to(&mut body).expect("write");
    let hdr = build_header(Command::Create, 96, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Create);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let delete_id = CreateResponse::parse(rb)
        .expect("parse delete handle create resp")
        .file_id;

    let disposition_req = SetInfoRequest {
        structure_size: 33,
        info_type: InfoType::File as u8,
        file_information_class: 0x0D,
        buffer_length: 1,
        buffer_offset: 64 + 32,
        reserved: 0,
        additional_information: 0,
        file_id: delete_id,
        buffer: vec![1],
    };
    let mut body = Vec::new();
    disposition_req.write_to(&mut body).expect("write");
    let hdr = build_header(Command::SetInfo, 97, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, _rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::SetInfo);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);

    let query_delete_pending_req = QueryInfoRequest {
        structure_size: 41,
        info_type: InfoType::File as u8,
        file_information_class: 0x12,
        output_buffer_length: 4096,
        input_buffer_offset: 0,
        reserved: 0,
        input_buffer_length: 0,
        additional_information: 0,
        flags: 0,
        file_id: delete_id,
        input_buffer: vec![],
    };
    let mut body = Vec::new();
    query_delete_pending_req.write_to(&mut body).expect("write");
    let hdr = build_header(Command::QueryInfo, 101, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::QueryInfo);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let query_delete_pending_resp =
        QueryInfoResponse::parse(rb).expect("parse delete-pending all-info resp");
    assert_eq!(query_delete_pending_resp.buffer[60], 1);

    let cl_delete_req = CloseRequest {
        structure_size: 24,
        flags: 0,
        reserved: 0,
        file_id: delete_id,
    };
    let mut body = Vec::new();
    cl_delete_req.write_to(&mut body).expect("write");
    let hdr = build_header(Command::Close, 98, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Close);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let _ = CloseResponse::parse(rb).expect("parse delete handle close resp");

    let query_held_pending_req = QueryInfoRequest {
        file_id: held_id,
        ..query_delete_pending_req
    };
    let mut body = Vec::new();
    query_held_pending_req.write_to(&mut body).expect("write");
    let hdr = build_header(Command::QueryInfo, 102, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::QueryInfo);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let query_held_pending_resp =
        QueryInfoResponse::parse(rb).expect("parse held pending all-info resp");
    assert_eq!(query_held_pending_resp.buffer[60], 1);

    let pending_open_req = CreateRequest {
        desired_access: 0x0000_0001,
        ..delete_req
    };
    let mut body = Vec::new();
    pending_open_req.write_to(&mut body).expect("write");
    let hdr = build_header(Command::Create, 99, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, _rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Create);
    assert_eq!(rh.channel_sequence_status, 0xC000_0056);

    let cl_held_req = CloseRequest {
        structure_size: 24,
        flags: 0,
        reserved: 0,
        file_id: held_id,
    };
    let mut body = Vec::new();
    cl_held_req.write_to(&mut body).expect("write");
    let hdr = build_header(Command::Close, 100, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Close);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let _ = CloseResponse::parse(rb).expect("parse held-delete close resp");
    assert!(
        !td.path().join("held-delete.txt").exists(),
        "pending delete should complete after last close"
    );

    // ---- READ ------------------------------------------------------------
    let rd_req = ReadRequest {
        structure_size: 49,
        padding: ReadResponse::STANDARD_DATA_OFFSET,
        flags: 0,
        length: 64,
        offset: 0,
        file_id,
        minimum_count: 0,
        channel: 0,
        remaining_bytes: 0,
        read_channel_info_offset: 0,
        read_channel_info_length: 0,
        buffer: vec![0],
    };
    let mut body = Vec::new();
    rd_req.write_to(&mut body).expect("write");
    let hdr = build_header(Command::Read, 21, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Read);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let rd_resp = ReadResponse::parse(rb).expect("parse read resp");
    assert_eq!(rd_resp.data, b"hi");

    // ---- Default stream alias opens the base file ------------------------
    let default_stream_name = utf16le("hello.txt::$DATA");
    let default_stream_req = CreateRequest {
        structure_size: 57,
        security_flags: 0,
        requested_oplock_level: 0,
        impersonation_level: 2,
        smb_create_flags: 0,
        reserved: 0,
        desired_access: 0x0013_0089,
        file_attributes: 0,
        share_access: 0x0000_0007,
        create_disposition: 1,
        create_options: 0x0000_0040,
        name_offset: 0x78,
        name_length: default_stream_name.len() as u16,
        create_contexts_offset: 0,
        create_contexts_length: 0,
        name: default_stream_name,
        create_contexts: vec![],
    };
    let mut body = Vec::new();
    default_stream_req.write_to(&mut body).expect("write");
    let hdr = build_header(Command::Create, 25, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Create);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let default_stream_id = CreateResponse::parse(rb)
        .expect("parse default stream create resp")
        .file_id;
    let rd_req = ReadRequest {
        structure_size: 49,
        padding: ReadResponse::STANDARD_DATA_OFFSET,
        flags: 0,
        length: 64,
        offset: 0,
        file_id: default_stream_id,
        minimum_count: 0,
        channel: 0,
        remaining_bytes: 0,
        read_channel_info_offset: 0,
        read_channel_info_length: 0,
        buffer: vec![0],
    };
    let mut body = Vec::new();
    rd_req.write_to(&mut body).expect("write");
    let hdr = build_header(Command::Read, 26, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Read);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let rd_resp = ReadResponse::parse(rb).expect("parse default stream read resp");
    assert_eq!(rd_resp.data, b"hi");
    let cl_default_req = CloseRequest {
        structure_size: 24,
        flags: 0,
        reserved: 0,
        file_id: default_stream_id,
    };
    let mut body = Vec::new();
    cl_default_req.write_to(&mut body).expect("write");
    let hdr = build_header(Command::Close, 27, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Close);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let _ = CloseResponse::parse(rb).expect("parse default stream close resp");

    // ---- Missing-base stream create rules --------------------------------
    let missing_open_if_name = utf16le("missing-open-if.txt:streamtwo");
    let missing_open_if_req = CreateRequest {
        structure_size: 57,
        security_flags: 0,
        requested_oplock_level: 0,
        impersonation_level: 2,
        smb_create_flags: 0,
        reserved: 0,
        desired_access: 0x0013_019F,
        file_attributes: 0,
        share_access: 0x0000_0007,
        create_disposition: 3,
        create_options: 0x0000_0040,
        name_offset: 0x78,
        name_length: missing_open_if_name.len() as u16,
        create_contexts_offset: 0,
        create_contexts_length: 0,
        name: missing_open_if_name,
        create_contexts: vec![],
    };
    let mut body = Vec::new();
    missing_open_if_req.write_to(&mut body).expect("write");
    let hdr = build_header(Command::Create, 28, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Create);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    assert!(td.path().join("missing-open-if.txt").exists());
    let missing_open_if_id = CreateResponse::parse(rb)
        .expect("parse missing open-if stream create resp")
        .file_id;
    let cl_missing_open_if_req = CloseRequest {
        structure_size: 24,
        flags: 0,
        reserved: 0,
        file_id: missing_open_if_id,
    };
    let mut body = Vec::new();
    cl_missing_open_if_req
        .write_to(&mut body)
        .expect("write missing open-if close");
    let hdr = build_header(Command::Close, 29, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Close);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let _ = CloseResponse::parse(rb).expect("parse missing open-if close resp");

    let missing_create_name = utf16le("missing-create.txt:streamtwo:$DATA");
    let missing_create_req = CreateRequest {
        structure_size: 57,
        security_flags: 0,
        requested_oplock_level: 0,
        impersonation_level: 2,
        smb_create_flags: 0,
        reserved: 0,
        desired_access: 0x0013_011F,
        file_attributes: 0,
        share_access: 0x0000_0007,
        create_disposition: 2,
        create_options: 0x0000_0040,
        name_offset: 0x78,
        name_length: missing_create_name.len() as u16,
        create_contexts_offset: 0,
        create_contexts_length: 0,
        name: missing_create_name,
        create_contexts: vec![],
    };
    let mut body = Vec::new();
    missing_create_req.write_to(&mut body).expect("write");
    let hdr = build_header(Command::Create, 30, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Create);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let missing_stream_id = CreateResponse::parse(rb)
        .expect("parse missing-base stream create resp")
        .file_id;
    let cl_missing_stream_req = CloseRequest {
        structure_size: 24,
        flags: 0,
        reserved: 0,
        file_id: missing_stream_id,
    };
    let mut body = Vec::new();
    cl_missing_stream_req.write_to(&mut body).expect("write");
    let hdr = build_header(Command::Close, 34, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Close);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let _ = CloseResponse::parse(rb).expect("parse missing stream close resp");

    let missing_overwrite_if_name = utf16le("missing-overwrite-if.txt:streamtwo");
    let missing_overwrite_if_req = CreateRequest {
        create_disposition: 5,
        name_length: missing_overwrite_if_name.len() as u16,
        name: missing_overwrite_if_name,
        ..missing_create_req
    };
    let mut body = Vec::new();
    missing_overwrite_if_req.write_to(&mut body).expect("write");
    let hdr = build_header(Command::Create, 35, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Create);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let missing_overwrite_stream_id = CreateResponse::parse(rb)
        .expect("parse missing-base overwrite-if stream create resp")
        .file_id;
    assert!(td.path().join("missing-overwrite-if.txt").exists());
    let cl_missing_overwrite_stream_req = CloseRequest {
        structure_size: 24,
        flags: 0,
        reserved: 0,
        file_id: missing_overwrite_stream_id,
    };
    let mut body = Vec::new();
    cl_missing_overwrite_stream_req
        .write_to(&mut body)
        .expect("write");
    let hdr = build_header(Command::Close, 36, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Close);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let _ = CloseResponse::parse(rb).expect("parse missing overwrite stream close resp");

    let missing_overwrite_base_id = open_localfs_path(
        &mut s,
        session_id,
        tree_id,
        37,
        "missing-overwrite-if.txt",
        0x0012_0089,
        0,
    )
    .await;
    assert_eq!(
        query_file_stream_information(&mut s, 38, session_id, tree_id, missing_overwrite_base_id)
            .await,
        vec![
            ("::$DATA".to_string(), 0),
            (":streamtwo:$DATA".to_string(), 0),
        ]
    );
    assert_eq!(
        send_close_request(&mut s, 39, session_id, tree_id, missing_overwrite_base_id,).await,
        STATUS_SUCCESS
    );

    // ---- CREATE/WRITE named stream + QUERY_INFO FileStreamInformation ----
    let target_stream_name = utf16le("hello.txt:streamone");
    let target_stream_req = CreateRequest {
        structure_size: 57,
        security_flags: 0,
        requested_oplock_level: 0,
        impersonation_level: 2,
        smb_create_flags: 0,
        reserved: 0,
        desired_access: 0x0012_011F,
        file_attributes: 0,
        share_access: 0x0000_0007,
        create_disposition: 3,
        create_options: 0x0000_0040,
        name_offset: 0x78,
        name_length: target_stream_name.len() as u16,
        create_contexts_offset: 0,
        create_contexts_length: 0,
        name: target_stream_name,
        create_contexts: vec![],
    };
    let mut body = Vec::new();
    target_stream_req.write_to(&mut body).expect("write");
    let hdr = build_header(Command::Create, 42, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Create);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let target_stream_id = CreateResponse::parse(rb)
        .expect("parse target stream create resp")
        .file_id;

    let wr_req = smb_server::wire::messages::WriteRequest {
        structure_size: 49,
        data_offset: 64 + 48,
        length: 5,
        offset: 0,
        file_id: target_stream_id,
        channel: 0,
        remaining_bytes: 0,
        write_channel_info_offset: 0,
        write_channel_info_length: 0,
        flags: 0,
        data: b"first".to_vec(),
    };
    let mut body = Vec::new();
    wr_req.write_to(&mut body).expect("write");
    let hdr = build_header(Command::Write, 43, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, _rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Write);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);

    let cl_target_stream_req = CloseRequest {
        structure_size: 24,
        flags: 0,
        reserved: 0,
        file_id: target_stream_id,
    };
    let mut body = Vec::new();
    cl_target_stream_req.write_to(&mut body).expect("write");
    let hdr = build_header(Command::Close, 44, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Close);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let _ = CloseResponse::parse(rb).expect("parse target stream close resp");

    let stream_name = utf16le("hello.txt:streamtwo");
    let stream_cr_req = CreateRequest {
        structure_size: 57,
        security_flags: 0,
        requested_oplock_level: 0,
        impersonation_level: 2,
        smb_create_flags: 0,
        reserved: 0,
        desired_access: 0x0013_019F,
        file_attributes: 0,
        share_access: 0x0000_0007,
        create_disposition: 3,
        create_options: 0x0000_0040,
        name_offset: 0x78,
        name_length: stream_name.len() as u16,
        create_contexts_offset: 0,
        create_contexts_length: 0,
        name: stream_name,
        create_contexts: vec![],
    };
    let mut body = Vec::new();
    stream_cr_req.write_to(&mut body).expect("write");
    let hdr = build_header(Command::Create, 30, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Create);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let stream_id = CreateResponse::parse(rb)
        .expect("parse stream create resp")
        .file_id;

    let wr_req = smb_server::wire::messages::WriteRequest {
        structure_size: 49,
        data_offset: 64 + 48,
        length: 12,
        offset: 0,
        file_id: stream_id,
        channel: 0,
        remaining_bytes: 0,
        write_channel_info_offset: 0,
        write_channel_info_length: 0,
        flags: 0,
        data: b"named-stream".to_vec(),
    };
    let mut body = Vec::new();
    wr_req.write_to(&mut body).expect("write");
    let hdr = build_header(Command::Write, 31, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, _rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Write);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);

    let stream_write_time = 133_650_450_000_000_000u64;
    let mut stream_basic = vec![0; 40];
    stream_basic[16..24].copy_from_slice(&stream_write_time.to_le_bytes());
    let set_stream_basic_req = SetInfoRequest {
        structure_size: 33,
        info_type: InfoType::File as u8,
        file_information_class: 0x04,
        buffer_length: stream_basic.len() as u32,
        buffer_offset: 64 + 32,
        reserved: 0,
        additional_information: 0,
        file_id: stream_id,
        buffer: stream_basic,
    };
    let mut body = Vec::new();
    set_stream_basic_req.write_to(&mut body).expect("write");
    let hdr = build_header(Command::SetInfo, 75, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, _rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::SetInfo);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);

    let query_stream_basic_req = QueryInfoRequest {
        structure_size: 41,
        info_type: InfoType::File as u8,
        file_information_class: 0x04,
        output_buffer_length: 40,
        input_buffer_offset: 0,
        reserved: 0,
        input_buffer_length: 0,
        additional_information: 0,
        flags: 0,
        file_id: stream_id,
        input_buffer: vec![],
    };
    let mut body = Vec::new();
    query_stream_basic_req.write_to(&mut body).expect("write");
    let hdr = build_header(Command::QueryInfo, 76, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::QueryInfo);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let stream_basic_resp = QueryInfoResponse::parse(rb).expect("parse stream basic info resp");
    assert_eq!(
        u64::from_le_bytes(stream_basic_resp.buffer[16..24].try_into().unwrap()),
        stream_write_time
    );

    let rename_stream_req = SetInfoRequest {
        structure_size: 33,
        info_type: InfoType::File as u8,
        file_information_class: 0x41,
        buffer_length: file_rename_information_ex(":streamone", 0x0000_0003).len() as u32,
        buffer_offset: 64 + 32,
        reserved: 0,
        additional_information: 0,
        file_id: stream_id,
        buffer: file_rename_information_ex(":streamone", 0x0000_0003),
    };
    let mut body = Vec::new();
    rename_stream_req.write_to(&mut body).expect("write");
    let hdr = build_header(Command::SetInfo, 45, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, _rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::SetInfo);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);

    let rd_req = ReadRequest {
        structure_size: 49,
        padding: ReadResponse::STANDARD_DATA_OFFSET,
        flags: 0,
        length: 64,
        offset: 0,
        file_id: stream_id,
        minimum_count: 0,
        channel: 0,
        remaining_bytes: 0,
        read_channel_info_offset: 0,
        read_channel_info_length: 0,
        buffer: vec![0],
    };
    let mut body = Vec::new();
    rd_req.write_to(&mut body).expect("write");
    let hdr = build_header(Command::Read, 46, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Read);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let rd_resp = ReadResponse::parse(rb).expect("parse renamed stream read resp");
    assert_eq!(rd_resp.data, b"named-stream");

    let stream_info_req = QueryInfoRequest {
        structure_size: 41,
        info_type: InfoType::File as u8,
        file_information_class: 0x16,
        output_buffer_length: 4096,
        input_buffer_offset: 0,
        reserved: 0,
        input_buffer_length: 0,
        additional_information: 0,
        flags: 0,
        file_id,
        input_buffer: vec![],
    };
    let mut body = Vec::new();
    stream_info_req.write_to(&mut body).expect("write");
    let hdr = build_header(Command::QueryInfo, 32, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::QueryInfo);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let stream_info = QueryInfoResponse::parse(rb).expect("parse stream info resp");
    let streams = decode_stream_information(&stream_info.buffer);
    assert_eq!(streams[0], ("::$DATA".to_string(), 2));
    assert_eq!(streams[1], (":streamone:$DATA".to_string(), 12));

    let delete_stream_req = SetInfoRequest {
        structure_size: 33,
        info_type: InfoType::File as u8,
        file_information_class: 0x40,
        buffer_length: 4,
        buffer_offset: 64 + 32,
        reserved: 0,
        additional_information: 0,
        file_id: stream_id,
        buffer: 0x0000_0009u32.to_le_bytes().to_vec(),
    };
    let mut body = Vec::new();
    delete_stream_req.write_to(&mut body).expect("write");
    let hdr = build_header(Command::SetInfo, 35, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, _rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::SetInfo);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);

    let cl_stream_req = CloseRequest {
        structure_size: 24,
        flags: 0,
        reserved: 0,
        file_id: stream_id,
    };
    let mut body = Vec::new();
    cl_stream_req.write_to(&mut body).expect("write");
    let hdr = build_header(Command::Close, 33, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Close);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let _ = CloseResponse::parse(rb).expect("parse stream close resp");

    let mut body = Vec::new();
    stream_info_req.write_to(&mut body).expect("write");
    let hdr = build_header(Command::QueryInfo, 36, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::QueryInfo);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let stream_info = QueryInfoResponse::parse(rb).expect("parse stream info after delete resp");
    let streams = decode_stream_information(&stream_info.buffer);
    assert_eq!(streams, vec![("::$DATA".to_string(), 2)]);

    let stream_name = utf16le("hello.txt:streamthree");
    let stream_cr_req = CreateRequest {
        structure_size: 57,
        security_flags: 0,
        requested_oplock_level: 0,
        impersonation_level: 2,
        smb_create_flags: 0,
        reserved: 0,
        desired_access: 0x0012_011F,
        file_attributes: 0,
        share_access: 0x0000_0007,
        create_disposition: 3,
        create_options: 0x0000_0040,
        name_offset: 0x78,
        name_length: stream_name.len() as u16,
        create_contexts_offset: 0,
        create_contexts_length: 0,
        name: stream_name,
        create_contexts: vec![],
    };
    let mut body = Vec::new();
    stream_cr_req.write_to(&mut body).expect("write");
    let hdr = build_header(Command::Create, 37, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Create);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let stream_id = CreateResponse::parse(rb)
        .expect("parse second stream create resp")
        .file_id;

    let hello_name = utf16le("hello.txt");
    let base_overwrite_req = CreateRequest {
        structure_size: 57,
        security_flags: 0,
        requested_oplock_level: 0,
        impersonation_level: 2,
        smb_create_flags: 0,
        reserved: 0,
        desired_access: 0x0012_011F,
        file_attributes: 0,
        share_access: 0x0000_0007,
        create_disposition: 5,
        create_options: 0x0000_0040,
        name_offset: 0x78,
        name_length: hello_name.len() as u16,
        create_contexts_offset: 0,
        create_contexts_length: 0,
        name: hello_name,
        create_contexts: vec![],
    };
    let mut body = Vec::new();
    base_overwrite_req.write_to(&mut body).expect("write");
    let hdr = build_header(Command::Create, 38, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Create);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let base_overwrite_id = CreateResponse::parse(rb)
        .expect("parse base overwrite create resp")
        .file_id;

    let stream_info_req = QueryInfoRequest {
        structure_size: 41,
        info_type: InfoType::File as u8,
        file_information_class: 0x16,
        output_buffer_length: 4096,
        input_buffer_offset: 0,
        reserved: 0,
        input_buffer_length: 0,
        additional_information: 0,
        flags: 0,
        file_id: base_overwrite_id,
        input_buffer: vec![],
    };
    let mut body = Vec::new();
    stream_info_req.write_to(&mut body).expect("write");
    let hdr = build_header(Command::QueryInfo, 39, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::QueryInfo);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let stream_info = QueryInfoResponse::parse(rb).expect("parse stream info after overwrite resp");
    let streams = decode_stream_information(&stream_info.buffer);
    assert_eq!(streams, vec![("::$DATA".to_string(), 0)]);

    for (message_id, file_id) in [(40, stream_id), (41, base_overwrite_id)] {
        let close_req = CloseRequest {
            structure_size: 24,
            flags: 0,
            reserved: 0,
            file_id,
        };
        let mut body = Vec::new();
        close_req.write_to(&mut body).expect("write");
        let hdr = build_header(Command::Close, message_id, session_id, tree_id);
        write_frame(&mut s, &hdr, &body).await;
        let resp = read_frame(&mut s).await;
        let (rh, rb) = parse_response_header(&resp);
        assert_eq!(rh.command, Command::Close);
        assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
        let _ = CloseResponse::parse(rb).expect("parse overwrite cleanup close resp");
    }

    let stream_caps_name = utf16le("hello.txt:StreamCaps");
    let stream_caps_req = CreateRequest {
        structure_size: 57,
        security_flags: 0,
        requested_oplock_level: 0,
        impersonation_level: 2,
        smb_create_flags: 0,
        reserved: 0,
        desired_access: 0x0012_011F,
        file_attributes: 0,
        share_access: 0x0000_0007,
        create_disposition: 3,
        create_options: 0x0000_0040,
        name_offset: 0x78,
        name_length: stream_caps_name.len() as u16,
        create_contexts_offset: 0,
        create_contexts_length: 0,
        name: stream_caps_name,
        create_contexts: vec![],
    };
    let mut body = Vec::new();
    stream_caps_req.write_to(&mut body).expect("write");
    let hdr = build_header(Command::Create, 69, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Create);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let stream_caps_id = CreateResponse::parse(rb)
        .expect("parse stream caps create resp")
        .file_id;

    let cl_stream_caps_req = CloseRequest {
        structure_size: 24,
        flags: 0,
        reserved: 0,
        file_id: stream_caps_id,
    };
    let mut body = Vec::new();
    cl_stream_caps_req.write_to(&mut body).expect("write");
    let hdr = build_header(Command::Close, 70, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Close);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let _ = CloseResponse::parse(rb).expect("parse stream caps close resp");

    let stream_caps_lower_name = utf16le("hello.txt:streamcaps:$data");
    let stream_caps_lower_req = CreateRequest {
        structure_size: 57,
        security_flags: 0,
        requested_oplock_level: 0,
        impersonation_level: 2,
        smb_create_flags: 0,
        reserved: 0,
        desired_access: 0x0013_0089,
        file_attributes: 0,
        share_access: 0x0000_0007,
        create_disposition: 1,
        create_options: 0x0000_0040,
        name_offset: 0x78,
        name_length: stream_caps_lower_name.len() as u16,
        create_contexts_offset: 0,
        create_contexts_length: 0,
        name: stream_caps_lower_name,
        create_contexts: vec![],
    };
    let mut body = Vec::new();
    stream_caps_lower_req.write_to(&mut body).expect("write");
    let hdr = build_header(Command::Create, 71, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Create);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let stream_caps_lower_id = CreateResponse::parse(rb)
        .expect("parse lower stream caps create resp")
        .file_id;

    let stream_info_req = QueryInfoRequest {
        structure_size: 41,
        info_type: InfoType::File as u8,
        file_information_class: 0x16,
        output_buffer_length: 4096,
        input_buffer_offset: 0,
        reserved: 0,
        input_buffer_length: 0,
        additional_information: 0,
        flags: 0,
        file_id: stream_caps_lower_id,
        input_buffer: vec![],
    };
    let mut body = Vec::new();
    stream_info_req.write_to(&mut body).expect("write");
    let hdr = build_header(Command::QueryInfo, 72, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::QueryInfo);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let stream_info = QueryInfoResponse::parse(rb).expect("parse lower stream caps info resp");
    let streams = decode_stream_information(&stream_info.buffer);
    assert_eq!(streams[0], ("::$DATA".to_string(), 0));
    assert_eq!(streams[1], (":StreamCaps:$DATA".to_string(), 0));

    let delete_stream_caps_req = SetInfoRequest {
        structure_size: 33,
        info_type: InfoType::File as u8,
        file_information_class: 0x0D,
        buffer_length: 1,
        buffer_offset: 64 + 32,
        reserved: 0,
        additional_information: 0,
        file_id: stream_caps_lower_id,
        buffer: vec![1],
    };
    let mut body = Vec::new();
    delete_stream_caps_req.write_to(&mut body).expect("write");
    let hdr = build_header(Command::SetInfo, 74, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, _rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::SetInfo);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);

    let cl_stream_caps_lower_req = CloseRequest {
        structure_size: 24,
        flags: 0,
        reserved: 0,
        file_id: stream_caps_lower_id,
    };
    let mut body = Vec::new();
    cl_stream_caps_lower_req.write_to(&mut body).expect("write");
    let hdr = build_header(Command::Close, 73, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Close);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let _ = CloseResponse::parse(rb).expect("parse lower stream caps close resp");

    let default_rename_stream_name = utf16le("hello.txt:streamdefault");
    let default_rename_stream_req = CreateRequest {
        structure_size: 57,
        security_flags: 0,
        requested_oplock_level: 0,
        impersonation_level: 2,
        smb_create_flags: 0,
        reserved: 0,
        desired_access: 0x0013_011F,
        file_attributes: 0,
        share_access: 0x0000_0007,
        create_disposition: 3,
        create_options: 0x0000_0040,
        name_offset: 0x78,
        name_length: default_rename_stream_name.len() as u16,
        create_contexts_offset: 0,
        create_contexts_length: 0,
        name: default_rename_stream_name,
        create_contexts: vec![],
    };
    let mut body = Vec::new();
    default_rename_stream_req
        .write_to(&mut body)
        .expect("write");
    let hdr = build_header(Command::Create, 47, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Create);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let default_rename_stream_id = CreateResponse::parse(rb)
        .expect("parse default rename stream create resp")
        .file_id;

    let wr_req = smb_server::wire::messages::WriteRequest {
        structure_size: 49,
        data_offset: 64 + 48,
        length: 11,
        offset: 0,
        file_id: default_rename_stream_id,
        channel: 0,
        remaining_bytes: 0,
        write_channel_info_offset: 0,
        write_channel_info_length: 0,
        flags: 0,
        data: b"default-now".to_vec(),
    };
    let mut body = Vec::new();
    wr_req.write_to(&mut body).expect("write");
    let hdr = build_header(Command::Write, 48, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, _rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Write);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);

    let default_rename_req = SetInfoRequest {
        structure_size: 33,
        info_type: InfoType::File as u8,
        file_information_class: 0x0A,
        buffer_length: file_rename_information("::$DATA", true).len() as u32,
        buffer_offset: 64 + 32,
        reserved: 0,
        additional_information: 0,
        file_id: default_rename_stream_id,
        buffer: file_rename_information("::$DATA", true),
    };
    let mut body = Vec::new();
    default_rename_req.write_to(&mut body).expect("write");
    let hdr = build_header(Command::SetInfo, 49, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, _rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::SetInfo);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);

    let stream_info_req = QueryInfoRequest {
        structure_size: 41,
        info_type: InfoType::File as u8,
        file_information_class: 0x16,
        output_buffer_length: 4096,
        input_buffer_offset: 0,
        reserved: 0,
        input_buffer_length: 0,
        additional_information: 0,
        flags: 0,
        file_id,
        input_buffer: vec![],
    };
    let mut body = Vec::new();
    stream_info_req.write_to(&mut body).expect("write");
    let hdr = build_header(Command::QueryInfo, 50, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::QueryInfo);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let stream_info =
        QueryInfoResponse::parse(rb).expect("parse stream info after default rename resp");
    let streams = decode_stream_information(&stream_info.buffer);
    assert_eq!(streams, vec![("::$DATA".to_string(), 11)]);

    let rd_req = ReadRequest {
        structure_size: 49,
        padding: ReadResponse::STANDARD_DATA_OFFSET,
        flags: 0,
        length: 64,
        offset: 0,
        file_id,
        minimum_count: 0,
        channel: 0,
        remaining_bytes: 0,
        read_channel_info_offset: 0,
        read_channel_info_length: 0,
        buffer: vec![0],
    };
    let mut body = Vec::new();
    rd_req.write_to(&mut body).expect("write");
    let hdr = build_header(Command::Read, 51, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Read);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let rd_resp = ReadResponse::parse(rb).expect("parse default-renamed stream read resp");
    assert_eq!(rd_resp.data, b"default-now");

    let cl_default_renamed_req = CloseRequest {
        structure_size: 24,
        flags: 0,
        reserved: 0,
        file_id: default_rename_stream_id,
    };
    let mut body = Vec::new();
    cl_default_renamed_req.write_to(&mut body).expect("write");
    let hdr = build_header(Command::Close, 52, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Close);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let _ = CloseResponse::parse(rb).expect("parse default-renamed stream close resp");

    let wildcard_stream_name = utf16le("hello.txt:?stream*");
    let wildcard_stream_req = CreateRequest {
        structure_size: 57,
        security_flags: 0,
        requested_oplock_level: 0,
        impersonation_level: 2,
        smb_create_flags: 0,
        reserved: 0,
        desired_access: 0x0012_011F,
        file_attributes: 0,
        share_access: 0x0000_0007,
        create_disposition: 3,
        create_options: 0x0000_0040,
        name_offset: 0x78,
        name_length: wildcard_stream_name.len() as u16,
        create_contexts_offset: 0,
        create_contexts_length: 0,
        name: wildcard_stream_name,
        create_contexts: vec![],
    };
    let mut body = Vec::new();
    wildcard_stream_req.write_to(&mut body).expect("write");
    let hdr = build_header(Command::Create, 53, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Create);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let wildcard_stream_id = CreateResponse::parse(rb)
        .expect("parse wildcard stream create resp")
        .file_id;
    let cl_wildcard_stream_req = CloseRequest {
        structure_size: 24,
        flags: 0,
        reserved: 0,
        file_id: wildcard_stream_id,
    };
    let mut body = Vec::new();
    cl_wildcard_stream_req.write_to(&mut body).expect("write");
    let hdr = build_header(Command::Close, 54, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Close);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let _ = CloseResponse::parse(rb).expect("parse wildcard stream close resp");

    // ---- CLOSE -----------------------------------------------------------
    let cl_req = CloseRequest {
        structure_size: 24,
        flags: 0,
        reserved: 0,
        file_id,
    };
    let mut body = Vec::new();
    cl_req.write_to(&mut body).expect("write");
    let hdr = build_header(Command::Close, 22, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Close);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let _ = CloseResponse::parse(rb).expect("parse close resp");

    // ---- TREE_DISCONNECT -------------------------------------------------
    let td_req = TreeDisconnectRequest::default();
    let mut body = Vec::new();
    td_req.write_to(&mut body).expect("write");
    let hdr = build_header(Command::TreeDisconnect, 23, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::TreeDisconnect);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let _ = TreeDisconnectResponse::parse(rb).expect("parse td resp");

    // ---- LOGOFF ----------------------------------------------------------
    let lo_req = LogoffRequest::default();
    let mut body = Vec::new();
    lo_req.write_to(&mut body).expect("write");
    let hdr = build_header(Command::Logoff, 24, session_id, 0);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Logoff);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let _ = LogoffResponse::parse(rb).expect("parse logoff resp");

    drop(s);
    handle.abort();
}

#[tokio::test]
async fn session_lifecycle_requires_active_session_and_logoff_invalidates_tree() {
    let td = tempdir().expect("tempdir");
    std::fs::write(td.path().join("hello.txt"), b"hello").expect("write hello");

    let (handle, mut s, session_id, tree_id) = start_localfs_session(td.path()).await;
    let wrong_session_id = session_id ^ 0x55;

    let status = tree_connect_status(&mut s, "\\\\127.0.0.1\\share", wrong_session_id, 4).await;
    assert_eq!(status, STATUS_USER_SESSION_DELETED);

    let (rh, create) = send_create_request(
        &mut s,
        5,
        session_id,
        tree_id,
        create_request("hello.txt", 0x0012_0089, 0, 1, 0x0000_0040),
    )
    .await;
    assert_eq!(rh.command, Command::Create);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let file_id = create.expect("create hello.txt").file_id;

    let status = read_localfs_custom_status(
        &mut s,
        wrong_session_id,
        tree_id,
        6,
        read_request(file_id, 1, 0),
    )
    .await;
    assert_eq!(status, STATUS_USER_SESSION_DELETED);

    let lo_req = LogoffRequest::default();
    let mut body = Vec::new();
    lo_req.write_to(&mut body).expect("write logoff");
    let hdr = build_header(Command::Logoff, 7, session_id, 0);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Logoff);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let _ = LogoffResponse::parse(rb).expect("parse logoff resp");

    let status =
        read_localfs_custom_status(&mut s, session_id, tree_id, 8, read_request(file_id, 1, 0))
            .await;
    assert_eq!(status, STATUS_USER_SESSION_DELETED);

    assert_eq!(
        send_echo_status(&mut s, 9, session_id).await,
        STATUS_SUCCESS
    );

    drop(s);
    handle.abort();
}

#[tokio::test]
async fn tree_disconnect_invalidates_tree_and_open_handles() {
    let td = tempdir().expect("tempdir");
    std::fs::write(td.path().join("hello.txt"), b"hello").expect("write hello");

    let (handle, mut s, session_id, tree_id) = start_localfs_session(td.path()).await;

    let (rh, create) = send_create_request(
        &mut s,
        4,
        session_id,
        tree_id,
        create_request("hello.txt", 0x0012_0089, 0, 1, 0x0000_0040),
    )
    .await;
    assert_eq!(rh.command, Command::Create);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let file_id = create.expect("create hello.txt").file_id;

    let td_req = TreeDisconnectRequest::default();
    let mut body = Vec::new();
    td_req.write_to(&mut body).expect("write tree disconnect");
    let hdr = build_header(Command::TreeDisconnect, 5, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::TreeDisconnect);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let _ = TreeDisconnectResponse::parse(rb).expect("parse tree disconnect resp");

    let status =
        read_localfs_custom_status(&mut s, session_id, tree_id, 6, read_request(file_id, 1, 0))
            .await;
    assert_eq!(status, STATUS_NETWORK_NAME_DELETED);

    drop(s);
    handle.abort();
}

#[tokio::test]
async fn query_info_file_name_information_strips_stream_data_type() {
    let td = tempdir().expect("tempdir");
    std::fs::write(td.path().join("streamed.txt"), b"base").expect("write streamed.txt");

    let (handle, mut s, session_id, tree_id) = start_localfs_session(td.path()).await;

    let (rh, stream) = send_create_request(
        &mut s,
        4,
        session_id,
        tree_id,
        create_request(
            "streamed.txt:StreamName:$DATA",
            0x0000_0080,
            0,
            3,
            0x0000_0040,
        ),
    )
    .await;
    assert_eq!(rh.command, Command::Create);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let stream_id = stream.expect("stream open").file_id;
    assert_eq!(
        query_file_name_information(&mut s, 5, session_id, tree_id, stream_id).await,
        "streamed.txt:StreamName"
    );

    let (rh, default_stream) = send_create_request(
        &mut s,
        6,
        session_id,
        tree_id,
        create_request("streamed.txt::$DATA", 0x0000_0080, 0, 1, 0x0000_0040),
    )
    .await;
    assert_eq!(rh.command, Command::Create);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let default_id = default_stream.expect("default stream open").file_id;
    assert_eq!(
        query_file_name_information(&mut s, 7, session_id, tree_id, default_id).await,
        "streamed.txt"
    );

    assert_eq!(
        send_close_request(&mut s, 8, session_id, tree_id, stream_id).await,
        STATUS_SUCCESS
    );
    assert_eq!(
        send_close_request(&mut s, 9, session_id, tree_id, default_id).await,
        STATUS_SUCCESS
    );

    handle.abort();
}

#[tokio::test]
async fn query_info_file_name_and_all_information_use_handle_path() {
    let td = tempdir().expect("tempdir");
    std::fs::create_dir(td.path().join("dir")).expect("mkdir dir");
    std::fs::write(td.path().join("dir").join("file.txt"), b"hello").expect("write file");

    let (handle, mut s, session_id, tree_id) = start_localfs_session(td.path()).await;
    let (rh, opened) = send_create_request(
        &mut s,
        4,
        session_id,
        tree_id,
        create_request("dir/file.txt", 0x0000_0080, 0, 1, 0x0000_0040),
    )
    .await;
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let file_id = opened.expect("file open").file_id;

    assert_eq!(
        query_file_name_information(&mut s, 5, session_id, tree_id, file_id).await,
        "dir\\file.txt"
    );
    assert_eq!(
        decode_file_all_information_name(
            &query_file_all_information(&mut s, 6, session_id, tree_id, file_id).await
        ),
        "dir\\file.txt"
    );
    assert_eq!(
        send_close_request(&mut s, 7, session_id, tree_id, file_id).await,
        STATUS_SUCCESS
    );

    handle.abort();
}

#[tokio::test]
async fn query_info_file_remote_protocol_information_uses_dialect() {
    let td = tempdir().expect("tempdir");
    std::fs::write(td.path().join("hello.txt"), b"hello").expect("write hello");

    let (handle, mut s, session_id, tree_id) = start_localfs_session_smb311(td.path()).await;
    let (rh, opened) = send_create_request(
        &mut s,
        4,
        session_id,
        tree_id,
        create_request("hello.txt", 0x0000_0080, 0, 1, 0x0000_0040),
    )
    .await;
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let file_id = opened.expect("file open").file_id;

    let (status, output) =
        query_file_information_class(&mut s, 5, session_id, tree_id, file_id, 0x37, 180).await;
    assert_eq!(status, STATUS_SUCCESS);
    assert_eq!(output.len(), 180);
    assert_eq!(u16::from_le_bytes(output[0..2].try_into().unwrap()), 1);
    assert_eq!(u16::from_le_bytes(output[2..4].try_into().unwrap()), 180);
    assert_eq!(
        u32::from_le_bytes(output[4..8].try_into().unwrap()),
        0x0002_0000
    );
    assert_eq!(u16::from_le_bytes(output[8..10].try_into().unwrap()), 3);
    assert_eq!(u16::from_le_bytes(output[10..12].try_into().unwrap()), 1);
    assert_eq!(u16::from_le_bytes(output[12..14].try_into().unwrap()), 1);
    assert_eq!(
        send_close_request(&mut s, 6, session_id, tree_id, file_id).await,
        STATUS_SUCCESS
    );

    handle.abort();
}

#[tokio::test]
async fn query_info_file_additional_classes_have_minimum_sizes() {
    let td = tempdir().expect("tempdir");
    std::fs::write(td.path().join("hello.txt"), b"hello").expect("write hello");

    let (handle, mut s, session_id, tree_id) = start_localfs_session_smb311(td.path()).await;
    let (rh, opened) = send_create_request(
        &mut s,
        4,
        session_id,
        tree_id,
        create_request("hello.txt", 0x001f_01ff, 0, 1, 0x0000_0040),
    )
    .await;
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let file_id = opened.expect("file open").file_id;

    let classes = [
        (0x07, 4, "FileEaInformation"),
        (0x0f, 4, "FileFullEaInformation"),
        (0x09, 4, "FileNameInformation"),
        (0x0e, 8, "FilePositionInformation"),
        (0x10, 4, "FileModeInformation"),
        (0x11, 4, "FileAlignmentInformation"),
        (0x15, 4, "FileAlternateNameInformation"),
        (0x16, 24, "FileStreamInformation"),
        (0x1c, 16, "FileCompressionInformation"),
        (0x37, 180, "FileRemoteProtocolInformation"),
        (0x3b, 24, "FileIdInformation"),
        (0x64, 136, "FilePOSIXInformation"),
    ];
    for (idx, (class, min_size, name)) in classes.into_iter().enumerate() {
        let (status, output) = query_file_information_class(
            &mut s,
            5 + idx as u64,
            session_id,
            tree_id,
            file_id,
            class,
            4096,
        )
        .await;
        assert_eq!(status, STATUS_SUCCESS, "{name}");
        assert!(
            output.len() >= min_size,
            "{name} length = {}, want at least {min_size}",
            output.len()
        );
    }

    assert_eq!(
        send_close_request(&mut s, 17, session_id, tree_id, file_id).await,
        STATUS_SUCCESS
    );
    handle.abort();
}

#[tokio::test]
async fn query_info_unknown_file_and_filesystem_classes_are_invalid() {
    let td = tempdir().expect("tempdir");
    std::fs::write(td.path().join("hello.txt"), b"hello").expect("write hello");

    let (handle, mut s, session_id, tree_id) = start_localfs_session(td.path()).await;
    let (rh, opened) = send_create_request(
        &mut s,
        4,
        session_id,
        tree_id,
        create_request("hello.txt", 0x0000_0080, 0, 1, 0x0000_0040),
    )
    .await;
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let file_id = opened.expect("file open").file_id;
    let root_id = open_root_directory(&mut s, 5, session_id, tree_id).await;

    let (status, output) =
        query_file_information_class(&mut s, 6, session_id, tree_id, file_id, 0xff, 4096).await;
    assert_eq!(status, STATUS_INVALID_INFO_CLASS);
    assert!(output.is_empty());

    let (status, output) =
        query_filesystem_information_class(&mut s, 7, session_id, tree_id, root_id, 0xff, 4096)
            .await;
    assert_eq!(status, STATUS_INVALID_INFO_CLASS);
    assert!(output.is_empty());

    assert_eq!(
        send_close_request(&mut s, 8, session_id, tree_id, file_id).await,
        STATUS_SUCCESS
    );
    assert_eq!(
        send_close_request(&mut s, 9, session_id, tree_id, root_id).await,
        STATUS_SUCCESS
    );

    handle.abort();
}

#[tokio::test]
async fn query_info_alternate_name_uses_handle_basename() {
    let td = tempdir().expect("tempdir");
    std::fs::create_dir(td.path().join("dir")).expect("mkdir dir");
    std::fs::write(td.path().join("dir").join("torture_search.txt"), b"hello")
        .expect("write torture_search.txt");

    let (handle, mut s, session_id, tree_id) = start_localfs_session(td.path()).await;
    let (rh, opened) = send_create_request(
        &mut s,
        4,
        session_id,
        tree_id,
        create_request("dir/torture_search.txt", 0x0000_0080, 0, 1, 0x0000_0040),
    )
    .await;
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let file_id = opened.expect("file open").file_id;

    let (status, output) =
        query_file_information_class(&mut s, 5, session_id, tree_id, file_id, 0x15, 4096).await;
    assert_eq!(status, STATUS_SUCCESS);
    assert_eq!(decode_file_name_information(&output), "TORTUR~1.TXT");
    assert_eq!(
        send_close_request(&mut s, 6, session_id, tree_id, file_id).await,
        STATUS_SUCCESS
    );

    handle.abort();
}

#[tokio::test]
async fn query_info_file_buffer_status_matches_gosmb() {
    let td = tempdir().expect("tempdir");
    std::fs::write(td.path().join("bufsize.txt"), b"hello").expect("write bufsize.txt");

    let (handle, mut s, session_id, tree_id) = start_localfs_session(td.path()).await;
    let (rh, opened) = send_create_request(
        &mut s,
        4,
        session_id,
        tree_id,
        create_request("bufsize.txt", 0x0012_0089, 0, 1, 0x0000_0040),
    )
    .await;
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let file_id = opened.expect("file open").file_id;

    let (status, output) =
        query_file_information_class(&mut s, 5, session_id, tree_id, file_id, 0x04, 39).await;
    assert_eq!(status, STATUS_INFO_LENGTH_MISMATCH);
    assert!(output.is_empty());

    let (status, output) =
        query_file_information_class(&mut s, 6, session_id, tree_id, file_id, 0x12, 103).await;
    assert_eq!(status, STATUS_INFO_LENGTH_MISMATCH);
    assert!(output.is_empty());

    let (status, output) =
        query_file_information_class(&mut s, 7, session_id, tree_id, file_id, 0x12, 104).await;
    assert_eq!(status, STATUS_BUFFER_OVERFLOW);
    assert_eq!(output.len(), 104);

    let (status, output) =
        query_file_information_class(&mut s, 8, session_id, tree_id, file_id, 0x12, 4096).await;
    assert_eq!(status, STATUS_SUCCESS);
    assert!(output.len() > 104, "full FileAllInformation includes name");

    assert_eq!(
        send_close_request(&mut s, 9, session_id, tree_id, file_id).await,
        STATUS_SUCCESS
    );

    handle.abort();
}

#[tokio::test]
async fn flush_closed_handle_fails_and_directory_succeeds() {
    let td = tempdir().expect("tempdir");
    std::fs::create_dir(td.path().join("docs")).expect("mkdir docs");

    let (handle, mut s, session_id, tree_id) = start_localfs_session(td.path()).await;

    assert_eq!(
        send_flush_status(&mut s, 4, session_id, tree_id, FileId::new(1, 0x404),).await,
        STATUS_FILE_CLOSED
    );

    let dir_id = open_localfs_path(
        &mut s,
        session_id,
        tree_id,
        5,
        "docs",
        0x001f_01ff,
        0x0000_0001,
    )
    .await;
    assert_eq!(
        send_flush_status(&mut s, 6, session_id, tree_id, dir_id).await,
        STATUS_SUCCESS
    );
    assert_eq!(
        send_close_request(&mut s, 7, session_id, tree_id, dir_id).await,
        STATUS_SUCCESS
    );

    handle.abort();
}

#[tokio::test]
async fn flush_calls_backend_handle_flush() {
    let backend = DelayedBackend::new(Duration::ZERO, Duration::ZERO).with_file("flush.txt", b"hi");
    let metrics = backend.metrics.clone();
    let (handle, mut s, session_id, tree_id) = start_delayed_session(backend).await;

    let (rh, opened) = send_create_request(
        &mut s,
        4,
        session_id,
        tree_id,
        create_request("flush.txt", 0x0012_0089, 0, 1, 0x0000_0040),
    )
    .await;
    assert_eq!(rh.command, Command::Create);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let file_id = opened.expect("open flush target").file_id;

    assert_eq!(
        send_flush_status(&mut s, 5, session_id, tree_id, file_id).await,
        STATUS_SUCCESS
    );
    assert_eq!(metrics.flushes.load(Ordering::SeqCst), 1);

    assert_eq!(
        send_close_request(&mut s, 6, session_id, tree_id, file_id).await,
        STATUS_SUCCESS
    );
    handle.abort();
}

#[tokio::test]
async fn query_info_file_access_information_allowed_for_write_only_handle() {
    let td = tempdir().expect("tempdir");
    std::fs::write(td.path().join("write.txt"), b"hello").expect("write write.txt");

    let (handle, mut s, session_id, tree_id) = start_localfs_session(td.path()).await;
    let (rh, opened) = send_create_request(
        &mut s,
        4,
        session_id,
        tree_id,
        create_request("write.txt", 0x0000_0002, 0, 1, 0x0000_0040),
    )
    .await;
    assert_eq!(rh.command, Command::Create);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let file_id = opened.expect("write-only open").file_id;

    let (status, output) =
        query_file_information_class(&mut s, 5, session_id, tree_id, file_id, 0x08, 4).await;
    assert_eq!(status, STATUS_SUCCESS);
    assert_eq!(
        u32::from_le_bytes(output[0..4].try_into().unwrap()),
        0x0000_0002
    );

    assert_eq!(
        send_close_request(&mut s, 6, session_id, tree_id, file_id).await,
        STATUS_SUCCESS
    );
    handle.abort();
}

#[tokio::test]
async fn query_info_metadata_classes_match_gosmb_wire_contents() {
    const FILE_READ_DATA: u32 = 0x0000_0001;
    const FILE_WRITE_DATA: u32 = 0x0000_0002;
    const FILE_APPEND_DATA: u32 = 0x0000_0004;
    const FILE_READ_ATTRIBUTES: u32 = 0x0000_0080;

    let td = tempdir().expect("tempdir");
    std::fs::write(td.path().join("hello.txt"), b"hello").expect("write hello.txt");

    let (handle, mut s, session_id, tree_id) = start_localfs_session(td.path()).await;
    let granted_access = FILE_READ_DATA | FILE_WRITE_DATA | FILE_APPEND_DATA;
    let (rh, opened) = send_create_request(
        &mut s,
        4,
        session_id,
        tree_id,
        create_request("hello.txt", granted_access, 0, 1, 0x0000_0040),
    )
    .await;
    assert_eq!(rh.command, Command::Create);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let file_id = opened.expect("open hello.txt").file_id;

    let (status, access) =
        query_file_information_class(&mut s, 5, session_id, tree_id, file_id, 0x08, 4).await;
    assert_eq!(status, STATUS_SUCCESS);
    assert_eq!(access.len(), 4);
    assert_eq!(
        u32::from_le_bytes(access[0..4].try_into().unwrap()),
        granted_access
    );

    assert_eq!(
        send_close_request(&mut s, 6, session_id, tree_id, file_id).await,
        STATUS_SUCCESS
    );

    let metadata_file_id = open_localfs_path(
        &mut s,
        session_id,
        tree_id,
        7,
        "hello.txt",
        FILE_READ_ATTRIBUTES,
        0x0000_0040,
    )
    .await;

    let (status, network_open) =
        query_file_information_class(&mut s, 8, session_id, tree_id, metadata_file_id, 0x22, 56)
            .await;
    assert_eq!(status, STATUS_SUCCESS);
    assert_eq!(network_open.len(), 56);
    assert_eq!(
        u64::from_le_bytes(network_open[32..40].try_into().unwrap()),
        4096
    );
    assert_eq!(
        u64::from_le_bytes(network_open[40..48].try_into().unwrap()),
        5
    );
    assert_eq!(
        u32::from_le_bytes(network_open[48..52].try_into().unwrap()),
        FILE_ATTRIBUTE_ARCHIVE
    );
    assert!(network_open[52..56].iter().all(|byte| *byte == 0));

    let (status, attribute_tag) =
        query_file_information_class(&mut s, 9, session_id, tree_id, metadata_file_id, 0x23, 8)
            .await;
    assert_eq!(status, STATUS_SUCCESS);
    assert_eq!(attribute_tag.len(), 8);
    assert_eq!(
        u32::from_le_bytes(attribute_tag[0..4].try_into().unwrap()),
        FILE_ATTRIBUTE_ARCHIVE
    );
    assert_eq!(
        u32::from_le_bytes(attribute_tag[4..8].try_into().unwrap()),
        0
    );

    assert_eq!(
        send_close_request(&mut s, 10, session_id, tree_id, metadata_file_id).await,
        STATUS_SUCCESS
    );
    handle.abort();
}

#[tokio::test]
async fn query_info_file_buffer_fixed_sizes_match_smb2_get_info() {
    let td = tempdir().expect("tempdir");
    std::fs::write(td.path().join("bufsize.txt"), b"hello").expect("write bufsize.txt");

    let (handle, mut s, session_id, tree_id) = start_localfs_session_smb311(td.path()).await;
    let (rh, opened) = send_create_request(
        &mut s,
        4,
        session_id,
        tree_id,
        create_request("bufsize.txt", 0x0012_0089, 0, 1, 0x0000_0040),
    )
    .await;
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let file_id = opened.expect("file open").file_id;

    for (idx, (class, fixed_len)) in [
        (0x04, 40),
        (0x05, 24),
        (0x06, 8),
        (0x07, 4),
        (0x08, 4),
        (0x10, 4),
        (0x11, 4),
        (0x12, 104),
        (0x15, 8),
        (0x16, 32),
        (0x1c, 16),
        (0x22, 56),
        (0x23, 8),
    ]
    .into_iter()
    .enumerate()
    {
        let class_name = format!("class 0x{class:02x}");
        let message_id = 5 + (idx as u64 * 3);
        let (status, output) = query_file_information_class(
            &mut s, message_id, session_id, tree_id, file_id, class, 4096,
        )
        .await;
        assert_eq!(status, STATUS_SUCCESS, "{class_name} full query");
        let full_len = output.len();

        let (status, output) = query_file_information_class(
            &mut s,
            message_id + 1,
            session_id,
            tree_id,
            file_id,
            class,
            fixed_len - 1,
        )
        .await;
        assert_eq!(status, STATUS_INFO_LENGTH_MISMATCH, "{class_name} short");
        assert!(output.is_empty(), "{class_name} short output");

        let (status, output) = query_file_information_class(
            &mut s,
            message_id + 2,
            session_id,
            tree_id,
            file_id,
            class,
            fixed_len,
        )
        .await;
        if full_len > fixed_len as usize {
            assert_eq!(status, STATUS_BUFFER_OVERFLOW, "{class_name} fixed");
            assert_eq!(output.len(), fixed_len as usize, "{class_name} fixed len");
        } else {
            assert_eq!(status, STATUS_SUCCESS, "{class_name} fixed");
            assert_eq!(output.len(), full_len, "{class_name} fixed len");
        }
    }

    assert_eq!(
        send_close_request(&mut s, 44, session_id, tree_id, file_id).await,
        STATUS_SUCCESS
    );

    handle.abort();
}

#[tokio::test]
async fn query_info_filesystem_buffer_fixed_sizes_match_smb2_get_info() {
    let td = tempdir().expect("tempdir");
    std::fs::write(td.path().join("fsbufsize.txt"), b"hello").expect("write fsbufsize.txt");

    let (handle, mut s, session_id, tree_id) = start_localfs_session(td.path()).await;
    let file_id = open_localfs_path(
        &mut s,
        session_id,
        tree_id,
        4,
        "fsbufsize.txt",
        0x0012_0089,
        0x0000_0040,
    )
    .await;

    for (idx, (class, fixed_len)) in [
        (0x01, 24),
        (0x03, 24),
        (0x04, 8),
        (0x05, 16),
        (0x06, 48),
        (0x07, 32),
        (0x08, 64),
        (0x0b, 28),
    ]
    .into_iter()
    .enumerate()
    {
        let class_name = format!("fs class 0x{class:02x}");
        let message_id = 5 + (idx as u64 * 3);
        let (status, output) = query_filesystem_information_class(
            &mut s, message_id, session_id, tree_id, file_id, class, 4096,
        )
        .await;
        assert_eq!(status, STATUS_SUCCESS, "{class_name} full query");
        let full_len = output.len();

        let (status, output) = query_filesystem_information_class(
            &mut s,
            message_id + 1,
            session_id,
            tree_id,
            file_id,
            class,
            fixed_len - 1,
        )
        .await;
        assert_eq!(status, STATUS_INFO_LENGTH_MISMATCH, "{class_name} short");
        assert!(output.is_empty(), "{class_name} short output");

        let (status, output) = query_filesystem_information_class(
            &mut s,
            message_id + 2,
            session_id,
            tree_id,
            file_id,
            class,
            fixed_len,
        )
        .await;
        if full_len > fixed_len as usize {
            assert_eq!(status, STATUS_BUFFER_OVERFLOW, "{class_name} fixed");
            assert_eq!(output.len(), fixed_len as usize, "{class_name} fixed len");
        } else {
            assert_eq!(status, STATUS_SUCCESS, "{class_name} fixed");
            assert_eq!(output.len(), full_len, "{class_name} fixed len");
        }
    }

    assert_eq!(
        send_close_request(&mut s, 30, session_id, tree_id, file_id).await,
        STATUS_SUCCESS
    );
    handle.abort();
}

#[tokio::test]
async fn query_info_full_ea_requires_file_read_ea() {
    let td = tempdir().expect("tempdir");
    std::fs::write(td.path().join("ea.txt"), b"hello").expect("write ea");

    let (handle, mut s, session_id, tree_id) = start_localfs_session(td.path()).await;
    let attr_only_id = open_localfs_path(
        &mut s,
        session_id,
        tree_id,
        4,
        "ea.txt",
        0x0000_0080,
        0x0000_0040,
    )
    .await;
    let (status, output) =
        query_file_information_class(&mut s, 5, session_id, tree_id, attr_only_id, 0x0f, 4096)
            .await;
    assert_eq!(status, STATUS_ACCESS_DENIED);
    assert!(output.is_empty());

    let read_ea_id = open_localfs_path(
        &mut s,
        session_id,
        tree_id,
        6,
        "ea.txt",
        0x0000_0008,
        0x0000_0040,
    )
    .await;
    let (status, output) =
        query_file_information_class(&mut s, 7, session_id, tree_id, read_ea_id, 0x0f, 4096).await;
    assert_eq!(status, STATUS_SUCCESS);
    assert_eq!(output, vec![0; 4]);

    assert_eq!(
        send_close_request(&mut s, 8, session_id, tree_id, read_ea_id).await,
        STATUS_SUCCESS
    );
    assert_eq!(
        send_close_request(&mut s, 9, session_id, tree_id, attr_only_id).await,
        STATUS_SUCCESS
    );
    handle.abort();
}

#[tokio::test]
async fn create_exta_context_persists_extended_attributes() {
    let td = tempdir().expect("tempdir");
    let (handle, mut s, session_id, tree_id) = start_localfs_session(td.path()).await;

    let eas = full_ea_information("EAONE", b"VALUE1");
    let create = create_request("ea-create.txt", 0x001f_01ff, 0, 2, 0x0000_0040);
    let body = create_request_with_context(
        "ea-create.txt",
        create,
        CreateContext {
            name: CreateContext::NAME_EXTA.to_vec(),
            data: eas.clone(),
        },
    );
    let hdr = build_header(Command::Create, 4, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Create);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let file_id = CreateResponse::parse(rb)
        .expect("parse ExtA create response")
        .file_id;

    let (status, queried) =
        query_file_information_class(&mut s, 5, session_id, tree_id, file_id, 0x0f, 4096).await;
    assert_eq!(status, STATUS_SUCCESS);
    assert_eq!(queried, eas);

    let (status, ea_size) =
        query_file_information_class(&mut s, 6, session_id, tree_id, file_id, 0x07, 4).await;
    assert_eq!(status, STATUS_SUCCESS);
    assert_eq!(
        u32::from_le_bytes(ea_size[0..4].try_into().unwrap()),
        eas.len() as u32
    );

    assert_eq!(
        send_close_request(&mut s, 7, session_id, tree_id, file_id).await,
        STATUS_SUCCESS
    );
    handle.abort();
}

#[tokio::test]
async fn query_info_access_requirements_match_smb2_get_info() {
    const SYNCHRONIZE: u32 = 0x0010_0000;
    const FILE_WRITE_DATA: u32 = 0x0000_0002;
    const FILE_READ_EA: u32 = 0x0000_0008;
    const FILE_READ_ATTRIBUTES: u32 = 0x0000_0080;

    struct Case {
        name: &'static str,
        class: u8,
        unrestricted_access: u32,
        unrestricted_status: u32,
        required_access: u32,
    }

    let td = tempdir().expect("tempdir");
    std::fs::write(td.path().join("meta.txt"), b"meta").expect("write meta");

    let (handle, mut s, session_id, tree_id) = start_localfs_session_smb311(td.path()).await;
    let mut message_id = 4u64;
    let cases = [
        Case {
            name: "standard",
            class: 0x05,
            unrestricted_access: SYNCHRONIZE,
            unrestricted_status: STATUS_SUCCESS,
            required_access: FILE_READ_ATTRIBUTES,
        },
        Case {
            name: "internal",
            class: 0x06,
            unrestricted_access: SYNCHRONIZE,
            unrestricted_status: STATUS_SUCCESS,
            required_access: FILE_READ_ATTRIBUTES,
        },
        Case {
            name: "access",
            class: 0x08,
            unrestricted_access: SYNCHRONIZE,
            unrestricted_status: STATUS_SUCCESS,
            required_access: FILE_READ_ATTRIBUTES,
        },
        Case {
            name: "position",
            class: 0x0E,
            unrestricted_access: SYNCHRONIZE,
            unrestricted_status: STATUS_SUCCESS,
            required_access: FILE_READ_ATTRIBUTES,
        },
        Case {
            name: "mode",
            class: 0x10,
            unrestricted_access: SYNCHRONIZE,
            unrestricted_status: STATUS_SUCCESS,
            required_access: FILE_READ_ATTRIBUTES,
        },
        Case {
            name: "alignment",
            class: 0x11,
            unrestricted_access: SYNCHRONIZE,
            unrestricted_status: STATUS_SUCCESS,
            required_access: FILE_READ_ATTRIBUTES,
        },
        Case {
            name: "alternate-name",
            class: 0x15,
            unrestricted_access: SYNCHRONIZE,
            unrestricted_status: STATUS_SUCCESS,
            required_access: FILE_READ_ATTRIBUTES,
        },
        Case {
            name: "stream",
            class: 0x16,
            unrestricted_access: SYNCHRONIZE,
            unrestricted_status: STATUS_SUCCESS,
            required_access: FILE_WRITE_DATA,
        },
        Case {
            name: "compression",
            class: 0x1C,
            unrestricted_access: SYNCHRONIZE,
            unrestricted_status: STATUS_SUCCESS,
            required_access: FILE_READ_ATTRIBUTES,
        },
        Case {
            name: "normalized-name",
            class: 0x30,
            unrestricted_access: SYNCHRONIZE,
            unrestricted_status: STATUS_SUCCESS,
            required_access: FILE_READ_ATTRIBUTES,
        },
        Case {
            name: "ea",
            class: 0x07,
            unrestricted_access: SYNCHRONIZE,
            unrestricted_status: STATUS_SUCCESS,
            required_access: FILE_READ_EA,
        },
        Case {
            name: "basic",
            class: 0x04,
            unrestricted_access: SYNCHRONIZE,
            unrestricted_status: STATUS_ACCESS_DENIED,
            required_access: FILE_READ_ATTRIBUTES,
        },
        Case {
            name: "all",
            class: 0x12,
            unrestricted_access: SYNCHRONIZE,
            unrestricted_status: STATUS_ACCESS_DENIED,
            required_access: FILE_READ_ATTRIBUTES,
        },
        Case {
            name: "network-open",
            class: 0x22,
            unrestricted_access: SYNCHRONIZE,
            unrestricted_status: STATUS_ACCESS_DENIED,
            required_access: FILE_READ_ATTRIBUTES,
        },
        Case {
            name: "attribute-tag",
            class: 0x23,
            unrestricted_access: SYNCHRONIZE,
            unrestricted_status: STATUS_ACCESS_DENIED,
            required_access: FILE_READ_ATTRIBUTES,
        },
        Case {
            name: "full-ea-wrong-access",
            class: 0x0F,
            unrestricted_access: FILE_READ_ATTRIBUTES,
            unrestricted_status: STATUS_ACCESS_DENIED,
            required_access: FILE_READ_EA,
        },
    ];

    for case in cases {
        let file_id = open_localfs_path(
            &mut s,
            session_id,
            tree_id,
            message_id,
            "meta.txt",
            case.unrestricted_access,
            0x0000_0040,
        )
        .await;
        message_id += 1;
        let (status, _) = query_file_information_class(
            &mut s, message_id, session_id, tree_id, file_id, case.class, 4096,
        )
        .await;
        message_id += 1;
        assert_eq!(status, case.unrestricted_status, "{}", case.name);
        assert_eq!(
            send_close_request(&mut s, message_id, session_id, tree_id, file_id).await,
            STATUS_SUCCESS
        );
        message_id += 1;

        let file_id = open_localfs_path(
            &mut s,
            session_id,
            tree_id,
            message_id,
            "meta.txt",
            case.required_access,
            0x0000_0040,
        )
        .await;
        message_id += 1;
        let (status, _) = query_file_information_class(
            &mut s, message_id, session_id, tree_id, file_id, case.class, 4096,
        )
        .await;
        message_id += 1;
        assert_eq!(status, STATUS_SUCCESS, "{} required access", case.name);
        assert_eq!(
            send_close_request(&mut s, message_id, session_id, tree_id, file_id).await,
            STATUS_SUCCESS
        );
        message_id += 1;
    }

    handle.abort();
}

#[tokio::test]
async fn query_info_normalized_name_requires_smb311() {
    let td = tempdir().expect("tempdir");
    std::fs::create_dir(td.path().join("dir")).expect("mkdir dir");
    std::fs::write(td.path().join("dir").join("file.txt"), b"ignored").expect("write file");

    let (handle, mut s, session_id, tree_id) = start_localfs_session(td.path()).await;
    let (rh, opened) = send_create_request(
        &mut s,
        4,
        session_id,
        tree_id,
        create_request("dir/file.txt", 0x0000_0080, 0, 1, 0x0000_0040),
    )
    .await;
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let file_id = opened.expect("file open").file_id;

    let (status, name) =
        query_file_normalized_name_information_status(&mut s, 5, session_id, tree_id, file_id)
            .await;
    assert_eq!(status, STATUS_NOT_SUPPORTED);
    assert!(name.is_none());
    assert_eq!(
        send_close_request(&mut s, 6, session_id, tree_id, file_id).await,
        STATUS_SUCCESS
    );

    handle.abort();

    let (handle, mut s, session_id, tree_id) = start_localfs_session_smb311(td.path()).await;
    let (rh, opened) = send_create_request(
        &mut s,
        4,
        session_id,
        tree_id,
        create_request("dir/file.txt", 0x0000_0080, 0, 1, 0x0000_0040),
    )
    .await;
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let file_id = opened.expect("smb311 file open").file_id;
    assert_eq!(
        query_file_normalized_name_information(&mut s, 5, session_id, tree_id, file_id).await,
        "dir\\file.txt"
    );
    assert_eq!(
        send_close_request(&mut s, 6, session_id, tree_id, file_id).await,
        STATUS_SUCCESS
    );

    handle.abort();
}

#[tokio::test]
async fn query_info_normalized_root_name_is_empty() {
    let td = tempdir().expect("tempdir");
    let (handle, mut s, session_id, tree_id) = start_localfs_session_smb311(td.path()).await;
    let root_id = open_root_directory(&mut s, 4, session_id, tree_id).await;

    assert_eq!(
        query_file_normalized_name_information(&mut s, 5, session_id, tree_id, root_id).await,
        ""
    );
    assert_eq!(
        send_close_request(&mut s, 6, session_id, tree_id, root_id).await,
        STATUS_SUCCESS
    );

    handle.abort();
}

#[tokio::test]
async fn query_info_normalized_name_uses_canonical_backend_casing() {
    let td = tempdir().expect("tempdir");
    std::fs::create_dir(td.path().join("MiXeD")).expect("mkdir mixed");
    std::fs::write(td.path().join("MiXeD").join("Name.TXT"), b"hello").expect("write file");

    let (handle, mut s, session_id, tree_id) = start_localfs_session_smb311(td.path()).await;
    let (rh, opened) = send_create_request(
        &mut s,
        4,
        session_id,
        tree_id,
        create_request("mixed/name.txt", 0x0000_0080, 0, 1, 0x0000_0040),
    )
    .await;
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let file_id = opened.expect("file open").file_id;

    assert_eq!(
        query_file_normalized_name_information(&mut s, 5, session_id, tree_id, file_id).await,
        "MiXeD\\Name.TXT"
    );
    assert_eq!(
        send_close_request(&mut s, 6, session_id, tree_id, file_id).await,
        STATUS_SUCCESS
    );

    handle.abort();
}

#[tokio::test]
async fn query_info_normalized_name_uses_canonical_named_stream_casing() {
    let td = tempdir().expect("tempdir");
    std::fs::create_dir(td.path().join("MiXeD")).expect("mkdir mixed");
    std::fs::write(td.path().join("MiXeD").join("Name.TXT"), b"base").expect("write base");

    let (handle, mut s, session_id, tree_id) = start_localfs_session_smb311(td.path()).await;

    let (rh, created) = send_create_request(
        &mut s,
        4,
        session_id,
        tree_id,
        create_request(
            "MiXeD/Name.TXT:StreamName:$DATA",
            0x001f_01ff,
            0,
            2,
            0x0000_0040,
        ),
    )
    .await;
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let created_id = created.expect("stream create").file_id;
    assert_eq!(
        send_close_request(&mut s, 5, session_id, tree_id, created_id).await,
        STATUS_SUCCESS
    );

    let (rh, reopened) = send_create_request(
        &mut s,
        6,
        session_id,
        tree_id,
        create_request(
            "mixed/name.txt:streamname:$data",
            0x0000_0080,
            0,
            1,
            0x0000_0040,
        ),
    )
    .await;
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let reopened_id = reopened.expect("stream reopen").file_id;

    assert_eq!(
        query_file_normalized_name_information(&mut s, 7, session_id, tree_id, reopened_id).await,
        "MiXeD\\Name.TXT:StreamName"
    );
    assert_eq!(
        send_close_request(&mut s, 8, session_id, tree_id, reopened_id).await,
        STATUS_SUCCESS
    );

    handle.abort();
}

#[tokio::test]
async fn named_stream_missing_base_create_dispositions_match_smbtorture() {
    let td = tempdir().expect("tempdir");
    let (handle, mut s, session_id, tree_id) = start_localfs_session(td.path()).await;

    let (rh, open_if) = send_create_request(
        &mut s,
        4,
        session_id,
        tree_id,
        create_request(
            "missing-open-if.txt:streamtwo",
            0x0013_019f,
            0,
            3,
            0x0000_0040,
        ),
    )
    .await;
    assert_eq!(rh.command, Command::Create);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    assert!(td.path().join("missing-open-if.txt").exists());
    let open_if_id = open_if.expect("open-if stream").file_id;
    assert_eq!(
        write_localfs_path_status(&mut s, session_id, tree_id, 5, open_if_id, 0, b"open-if").await,
        STATUS_SUCCESS
    );
    assert_eq!(
        send_close_request(&mut s, 6, session_id, tree_id, open_if_id).await,
        STATUS_SUCCESS
    );

    let open_if_base_id = open_localfs_path(
        &mut s,
        session_id,
        tree_id,
        7,
        "missing-open-if.txt",
        0x0012_0089,
        0,
    )
    .await;
    assert_eq!(
        query_file_stream_information(&mut s, 8, session_id, tree_id, open_if_base_id).await,
        vec![
            ("::$DATA".to_string(), 0),
            (":streamtwo:$DATA".to_string(), 7),
        ]
    );
    assert_eq!(
        send_close_request(&mut s, 9, session_id, tree_id, open_if_base_id).await,
        STATUS_SUCCESS
    );

    let (rh, created) = send_create_request(
        &mut s,
        10,
        session_id,
        tree_id,
        create_request(
            "missing-create.txt:Stream One:$DATA",
            0x0013_019f,
            0,
            2,
            0x0000_0040,
        ),
    )
    .await;
    assert_eq!(rh.command, Command::Create);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    assert!(td.path().join("missing-create.txt").exists());
    assert_eq!(
        send_close_request(
            &mut s,
            11,
            session_id,
            tree_id,
            created.expect("created stream").file_id,
        )
        .await,
        STATUS_SUCCESS
    );

    let (rh, overwrite_if) = send_create_request(
        &mut s,
        12,
        session_id,
        tree_id,
        create_request(
            "missing-overwrite-if.txt:streamtwo",
            0x0013_019f,
            0,
            5,
            0x0000_0040,
        ),
    )
    .await;
    assert_eq!(rh.command, Command::Create);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    assert!(td.path().join("missing-overwrite-if.txt").exists());
    let stream_id = overwrite_if.expect("overwrite-if stream").file_id;
    assert_eq!(
        send_close_request(&mut s, 13, session_id, tree_id, stream_id).await,
        STATUS_SUCCESS
    );

    let base_id = open_localfs_path(
        &mut s,
        session_id,
        tree_id,
        14,
        "missing-overwrite-if.txt",
        0x0012_0089,
        0,
    )
    .await;
    assert_eq!(
        query_file_stream_information(&mut s, 15, session_id, tree_id, base_id).await,
        vec![
            ("::$DATA".to_string(), 0),
            (":streamtwo:$DATA".to_string(), 0),
        ]
    );
    assert_eq!(
        send_close_request(&mut s, 16, session_id, tree_id, base_id).await,
        STATUS_SUCCESS
    );

    handle.abort();
}

#[tokio::test]
async fn named_stream_opens_are_case_insensitive_and_duplicate_create_collides() {
    let td = tempdir().expect("tempdir");
    std::fs::write(td.path().join("streamed.txt"), b"base").expect("write streamed.txt");

    let (handle, mut s, session_id, tree_id) = start_localfs_session(td.path()).await;

    let (rh, created) = send_create_request(
        &mut s,
        4,
        session_id,
        tree_id,
        create_request("streamed.txt:StreamName", 0x001f_01ff, 0, 2, 0x0000_0040),
    )
    .await;
    assert_eq!(rh.command, Command::Create);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let created_id = created.expect("stream create").file_id;
    assert_eq!(
        write_localfs_path_status(
            &mut s,
            session_id,
            tree_id,
            5,
            created_id,
            0,
            b"named-stream",
        )
        .await,
        STATUS_SUCCESS
    );
    assert_eq!(
        send_close_request(&mut s, 6, session_id, tree_id, created_id).await,
        STATUS_SUCCESS
    );

    let mut message_id = 7u64;
    for name in [
        "streamed.txt:streamname",
        "streamed.txt:STREAMNAME",
        "streamed.txt:StreamName:$dAtA",
        "streamed.txt:streamname:$data",
        "streamed.txt:STREAMNAME:$DATA",
    ] {
        let (rh, reopened) = send_create_request(
            &mut s,
            message_id,
            session_id,
            tree_id,
            create_request(name, 0x0000_0001, 0, 1, 0x0000_0040),
        )
        .await;
        message_id += 1;
        assert_eq!(rh.command, Command::Create, "{name}");
        assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS, "{name}");
        let file_id = reopened.expect("case-insensitive stream reopen").file_id;
        let (status, data) =
            read_localfs_path_status(&mut s, session_id, tree_id, message_id, file_id, 12, 0, 0)
                .await;
        message_id += 1;
        assert_eq!(status, STATUS_SUCCESS, "{name}");
        assert_eq!(data.expect("stream data"), b"named-stream", "{name}");
        assert_eq!(
            send_close_request(&mut s, message_id, session_id, tree_id, file_id).await,
            STATUS_SUCCESS,
            "{name}"
        );
        message_id += 1;
    }

    let (rh, duplicate) = send_create_request(
        &mut s,
        message_id,
        session_id,
        tree_id,
        create_request("streamed.txt:streamname", 0x001f_01ff, 0, 2, 0x0000_0040),
    )
    .await;
    message_id += 1;
    assert_eq!(rh.command, Command::Create);
    assert_eq!(rh.channel_sequence_status, STATUS_OBJECT_NAME_COLLISION);
    assert!(duplicate.is_none());

    let base_id = open_localfs_path(
        &mut s,
        session_id,
        tree_id,
        message_id,
        "streamed.txt",
        0x0000_0080,
        0x0000_0040,
    )
    .await;
    message_id += 1;
    assert_eq!(
        query_file_stream_information(&mut s, message_id, session_id, tree_id, base_id).await,
        vec![
            ("::$DATA".to_string(), 4),
            (":StreamName:$DATA".to_string(), 12),
        ]
    );
    message_id += 1;
    assert_eq!(
        send_close_request(&mut s, message_id, session_id, tree_id, base_id).await,
        STATUS_SUCCESS
    );

    handle.abort();
}

#[tokio::test]
async fn stream_end_of_file_updates_only_named_stream_size() {
    let td = tempdir().expect("tempdir");
    std::fs::write(td.path().join("streamed.txt"), b"base").expect("write streamed.txt");

    let (handle, mut s, session_id, tree_id) = start_localfs_session(td.path()).await;

    let (rh, stream) = send_create_request(
        &mut s,
        4,
        session_id,
        tree_id,
        create_request("streamed.txt:streamtwo", 0x0013_019F, 0, 3, 0x0000_0040),
    )
    .await;
    assert_eq!(rh.command, Command::Create);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let stream_id = stream.expect("stream open").file_id;

    assert_eq!(
        set_end_of_file_status(&mut s, 5, session_id, tree_id, stream_id, 8192).await,
        STATUS_SUCCESS
    );

    let all_info = query_file_all_information(&mut s, 6, session_id, tree_id, stream_id).await;
    assert_eq!(
        u64::from_le_bytes(all_info[48..56].try_into().unwrap()),
        8192
    );

    let base_id = open_localfs_path(
        &mut s,
        session_id,
        tree_id,
        7,
        "streamed.txt",
        0x0000_0080,
        0x0000_0040,
    )
    .await;
    assert_eq!(
        query_file_stream_information(&mut s, 8, session_id, tree_id, base_id).await,
        vec![
            ("::$DATA".to_string(), 4),
            (":streamtwo:$DATA".to_string(), 8192),
        ]
    );
    assert_eq!(
        query_file_stream_information(&mut s, 9, session_id, tree_id, stream_id).await,
        vec![
            ("::$DATA".to_string(), 4),
            (":streamtwo:$DATA".to_string(), 8192),
        ]
    );

    assert_eq!(
        send_close_request(&mut s, 10, session_id, tree_id, stream_id).await,
        STATUS_SUCCESS
    );
    assert_eq!(
        send_close_request(&mut s, 11, session_id, tree_id, base_id).await,
        STATUS_SUCCESS
    );

    handle.abort();
}

#[tokio::test]
async fn base_basic_info_attributes_propagate_to_registered_streams() {
    let td = tempdir().expect("tempdir");
    std::fs::write(td.path().join("streamed.txt"), b"base").expect("write streamed.txt");

    let (handle, mut s, session_id, tree_id) = start_localfs_session(td.path()).await;

    let (rh, stream) = send_create_request(
        &mut s,
        4,
        session_id,
        tree_id,
        create_request("streamed.txt:streamtwo", 0x0000_0180, 0, 3, 0x0000_0040),
    )
    .await;
    assert_eq!(rh.command, Command::Create);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let stream_id = stream.expect("stream open").file_id;

    let base_id = open_localfs_path(
        &mut s,
        session_id,
        tree_id,
        5,
        "streamed.txt",
        0x0000_0180,
        0x0000_0040,
    )
    .await;
    assert_eq!(
        set_basic_attributes(
            &mut s,
            6,
            session_id,
            tree_id,
            base_id,
            FILE_ATTRIBUTE_HIDDEN,
        )
        .await,
        STATUS_SUCCESS
    );

    let stream_basic = query_basic_information(&mut s, 7, session_id, tree_id, stream_id).await;
    let attrs = u32::from_le_bytes(stream_basic[32..36].try_into().unwrap());
    assert_eq!(attrs & FILE_ATTRIBUTE_HIDDEN, FILE_ATTRIBUTE_HIDDEN);

    assert_eq!(
        send_close_request(&mut s, 8, session_id, tree_id, stream_id).await,
        STATUS_SUCCESS
    );
    assert_eq!(
        send_close_request(&mut s, 9, session_id, tree_id, base_id).await,
        STATUS_SUCCESS
    );

    handle.abort();
}

#[tokio::test]
async fn stream_basic_info_timestamps_and_attributes_propagate_to_base() {
    let td = tempdir().expect("tempdir");
    std::fs::write(td.path().join("streamed.txt"), b"base").expect("write streamed.txt");

    let (handle, mut s, session_id, tree_id) = start_localfs_session(td.path()).await;

    let (rh, stream) = send_create_request(
        &mut s,
        4,
        session_id,
        tree_id,
        create_request("streamed.txt:streamtwo", 0x0000_0180, 0, 3, 0x0000_0040),
    )
    .await;
    assert_eq!(rh.command, Command::Create);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let stream_id = stream.expect("stream open").file_id;

    let want_write_time = 133_650_450_000_000_000u64;
    let mut basic = vec![0; 40];
    basic[16..24].copy_from_slice(&want_write_time.to_le_bytes());
    assert_eq!(
        set_basic_information_status(&mut s, 5, session_id, tree_id, stream_id, basic).await,
        STATUS_SUCCESS
    );

    let base_id = open_localfs_path(
        &mut s,
        session_id,
        tree_id,
        6,
        "streamed.txt",
        0x0000_0080,
        0x0000_0040,
    )
    .await;
    let base_basic = query_basic_information(&mut s, 7, session_id, tree_id, base_id).await;
    assert_eq!(
        u64::from_le_bytes(base_basic[16..24].try_into().unwrap()),
        want_write_time
    );

    let mut attr_only = vec![0; 40];
    attr_only[32..36].copy_from_slice(&FILE_ATTRIBUTE_READONLY.to_le_bytes());
    assert_eq!(
        set_basic_information_status(&mut s, 8, session_id, tree_id, stream_id, attr_only).await,
        STATUS_SUCCESS
    );
    let base_basic = query_basic_information(&mut s, 9, session_id, tree_id, base_id).await;
    let attrs = u32::from_le_bytes(base_basic[32..36].try_into().unwrap());
    assert_eq!(attrs & FILE_ATTRIBUTE_READONLY, FILE_ATTRIBUTE_READONLY);

    assert_eq!(
        send_close_request(&mut s, 10, session_id, tree_id, stream_id).await,
        STATUS_SUCCESS
    );
    assert_eq!(
        send_close_request(&mut s, 11, session_id, tree_id, base_id).await,
        STATUS_SUCCESS
    );

    handle.abort();
}

#[tokio::test]
async fn delete_base_file_removes_named_stream_information() {
    let td = tempdir().expect("tempdir");
    std::fs::write(td.path().join("streamed.txt"), b"base").expect("write streamed.txt");

    let (handle, mut s, session_id, tree_id) = start_localfs_session(td.path()).await;

    let (rh, stream) = send_create_request(
        &mut s,
        4,
        session_id,
        tree_id,
        create_request("streamed.txt:streamtwo", 0x0000_0002, 0, 3, 0x0000_0040),
    )
    .await;
    assert_eq!(rh.command, Command::Create);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let stream_id = stream.expect("stream open").file_id;
    assert_eq!(
        write_localfs_path_status(
            &mut s,
            session_id,
            tree_id,
            5,
            stream_id,
            0,
            b"named-stream",
        )
        .await,
        STATUS_SUCCESS
    );
    assert_eq!(
        send_close_request(&mut s, 6, session_id, tree_id, stream_id).await,
        STATUS_SUCCESS
    );

    let (rh, base) = send_create_request(
        &mut s,
        7,
        session_id,
        tree_id,
        create_request("streamed.txt", 0x0001_0080, 0, 1, 0x0000_0040),
    )
    .await;
    assert_eq!(rh.command, Command::Create);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let base_id = base.expect("base open").file_id;
    assert_eq!(
        set_file_disposition_status(&mut s, 8, session_id, tree_id, base_id, true).await,
        STATUS_SUCCESS
    );
    assert_eq!(
        send_close_request(&mut s, 9, session_id, tree_id, base_id).await,
        STATUS_SUCCESS
    );

    std::fs::write(td.path().join("streamed.txt"), b"base").expect("recreate streamed.txt");
    let (rh, recreated) = send_create_request(
        &mut s,
        10,
        session_id,
        tree_id,
        create_request("streamed.txt", 0x0000_0080, 0, 1, 0x0000_0040),
    )
    .await;
    assert_eq!(rh.command, Command::Create);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let recreated_id = recreated.expect("recreated base open").file_id;
    assert_eq!(
        query_file_stream_information(&mut s, 11, session_id, tree_id, recreated_id).await,
        vec![("::$DATA".to_string(), 4)]
    );
    assert_eq!(
        send_close_request(&mut s, 12, session_id, tree_id, recreated_id).await,
        STATUS_SUCCESS
    );

    handle.abort();
}

#[tokio::test]
async fn rename_base_file_rekeys_named_stream_information() {
    let td = tempdir().expect("tempdir");
    std::fs::write(td.path().join("streamed.txt"), b"base").expect("write streamed.txt");

    let (handle, mut s, session_id, tree_id) = start_localfs_session(td.path()).await;

    let (rh, stream) = send_create_request(
        &mut s,
        4,
        session_id,
        tree_id,
        create_request("streamed.txt:streamtwo", 0x0000_0002, 0, 3, 0x0000_0040),
    )
    .await;
    assert_eq!(rh.command, Command::Create);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let stream_id = stream.expect("stream open").file_id;
    assert_eq!(
        write_localfs_path_status(
            &mut s,
            session_id,
            tree_id,
            5,
            stream_id,
            0,
            b"named-stream",
        )
        .await,
        STATUS_SUCCESS
    );
    assert_eq!(
        send_close_request(&mut s, 6, session_id, tree_id, stream_id).await,
        STATUS_SUCCESS
    );

    let (rh, base) = send_create_request(
        &mut s,
        7,
        session_id,
        tree_id,
        create_request("streamed.txt", 0x001f_01ff, 0, 1, 0x0000_0040),
    )
    .await;
    assert_eq!(rh.command, Command::Create);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let base_id = base.expect("base open").file_id;
    assert_eq!(
        set_file_rename_status(
            &mut s,
            8,
            session_id,
            tree_id,
            base_id,
            "renamed.txt",
            false,
        )
        .await,
        STATUS_SUCCESS
    );
    assert!(!td.path().join("streamed.txt").exists());
    assert!(td.path().join("renamed.txt").exists());
    assert_eq!(
        query_file_stream_information(&mut s, 9, session_id, tree_id, base_id).await,
        vec![
            ("::$DATA".to_string(), 4),
            (":streamtwo:$DATA".to_string(), 12),
        ]
    );

    let (rh, renamed_stream) = send_create_request(
        &mut s,
        10,
        session_id,
        tree_id,
        create_request("renamed.txt:streamtwo", 0x0000_0001, 0, 1, 0x0000_0040),
    )
    .await;
    assert_eq!(rh.command, Command::Create);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let renamed_stream_id = renamed_stream.expect("renamed stream open").file_id;
    let (status, data) =
        read_localfs_path_status(&mut s, session_id, tree_id, 11, renamed_stream_id, 12, 0, 0)
            .await;
    assert_eq!(status, STATUS_SUCCESS);
    assert_eq!(data.expect("renamed stream data"), b"named-stream");

    assert_eq!(
        send_close_request(&mut s, 12, session_id, tree_id, renamed_stream_id).await,
        STATUS_SUCCESS
    );
    assert_eq!(
        send_close_request(&mut s, 13, session_id, tree_id, base_id).await,
        STATUS_SUCCESS
    );

    handle.abort();
}

#[tokio::test]
async fn open_stream_without_share_delete_blocks_base_delete_on_close() {
    let td = tempdir().expect("tempdir");
    std::fs::write(td.path().join("streamed.txt"), b"base").expect("write streamed.txt");

    let (handle, mut s, session_id, tree_id) = start_localfs_session(td.path()).await;

    let (rh, base) = send_create_request(
        &mut s,
        4,
        session_id,
        tree_id,
        create_request("streamed.txt", 0x0001_0080, 0, 1, 0x0000_0040),
    )
    .await;
    assert_eq!(rh.command, Command::Create);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let base_id = base.expect("base open").file_id;

    let mut stream_req = create_request("streamed.txt:streamtwo", 0x0000_0003, 0, 3, 0x0000_0040);
    stream_req.share_access = 0x0000_0003;
    let (rh, stream) = send_create_request(&mut s, 5, session_id, tree_id, stream_req).await;
    assert_eq!(rh.command, Command::Create);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let stream_id = stream.expect("stream open").file_id;

    assert_eq!(
        set_file_disposition_status(&mut s, 6, session_id, tree_id, base_id, true).await,
        STATUS_SHARING_VIOLATION
    );

    assert_eq!(
        send_close_request(&mut s, 7, session_id, tree_id, stream_id).await,
        STATUS_SUCCESS
    );
    assert_eq!(
        send_close_request(&mut s, 8, session_id, tree_id, base_id).await,
        STATUS_SUCCESS
    );

    handle.abort();
}

#[tokio::test]
async fn open_stream_without_share_delete_blocks_base_delete_access() {
    let td = tempdir().expect("tempdir");
    std::fs::write(td.path().join("streamed.txt"), b"base").expect("write streamed.txt");

    let (handle, mut s, session_id, tree_id) = start_localfs_session(td.path()).await;

    let mut stream_req = create_request("streamed.txt:streamtwo", 0x0000_0003, 0, 3, 0x0000_0040);
    stream_req.share_access = 0x0000_0003;
    let (rh, stream) = send_create_request(&mut s, 4, session_id, tree_id, stream_req).await;
    assert_eq!(rh.command, Command::Create);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let stream_id = stream.expect("stream open").file_id;

    let (rh, base) = send_create_request(
        &mut s,
        5,
        session_id,
        tree_id,
        create_request("streamed.txt", 0x0001_0000, 0, 1, 0x0000_0040),
    )
    .await;
    assert_eq!(rh.command, Command::Create);
    assert_eq!(rh.channel_sequence_status, STATUS_SHARING_VIOLATION);
    assert!(base.is_none());

    assert_eq!(
        send_close_request(&mut s, 6, session_id, tree_id, stream_id).await,
        STATUS_SUCCESS
    );

    handle.abort();
}

#[tokio::test]
async fn directory_default_stream_open_returns_not_a_directory_before_share_conflict() {
    let td = tempdir().expect("tempdir");
    std::fs::create_dir(td.path().join("streamdir")).expect("create streamdir");
    std::fs::write(td.path().join("streamdir").join("stream.txt"), b"base")
        .expect("seed stream file");

    let (handle, mut s, session_id, tree_id) = start_localfs_session(td.path()).await;

    let mut named_stream_dir_req = create_request(
        "streamdir/stream.txt:Stream One",
        0x0000_0002,
        0,
        2,
        0x0000_0001,
    );
    named_stream_dir_req.share_access = 0;
    let (rh, create) =
        send_create_request(&mut s, 4, session_id, tree_id, named_stream_dir_req).await;
    assert_eq!(rh.command, Command::Create);
    assert_eq!(rh.channel_sequence_status, STATUS_NOT_A_DIRECTORY);
    assert!(create.is_none());

    let mut default_stream_req =
        create_request("streamdir::$DATA", 0x0000_0002, 0x10, 1, 0x0000_0001);
    default_stream_req.share_access = 0;
    let (rh, create) =
        send_create_request(&mut s, 5, session_id, tree_id, default_stream_req).await;
    assert_eq!(rh.command, Command::Create);
    assert_eq!(rh.channel_sequence_status, STATUS_NOT_A_DIRECTORY);
    assert!(create.is_none());

    let mut default_stream_file_req = create_request("streamdir::$DATA", 0x0000_0002, 0x10, 1, 0);
    default_stream_file_req.share_access = 0;
    let (rh, create) =
        send_create_request(&mut s, 6, session_id, tree_id, default_stream_file_req).await;
    assert_eq!(rh.command, Command::Create);
    assert_eq!(rh.channel_sequence_status, STATUS_FILE_IS_A_DIRECTORY);
    assert!(create.is_none());

    let mut dir_req = create_request("streamdir", 0x0000_0001, 0x10, 1, 0x0000_0001);
    dir_req.share_access = 0;
    let (rh, dir) = send_create_request(&mut s, 7, session_id, tree_id, dir_req).await;
    assert_eq!(rh.command, Command::Create);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let dir_id = dir.expect("directory open").file_id;

    assert_eq!(
        query_file_stream_information(&mut s, 8, session_id, tree_id, dir_id).await,
        Vec::<(String, u64)>::new()
    );

    assert_eq!(
        send_close_request(&mut s, 9, session_id, tree_id, dir_id).await,
        STATUS_SUCCESS
    );

    handle.abort();
}

#[tokio::test]
async fn stream_delete_on_close_allows_next_stream_create_after_close() {
    let td = tempdir().expect("tempdir");

    let (handle, mut s, session_id, tree_id) = start_localfs_session(td.path()).await;

    let mut first_req = create_request("streamed.txt:first", 0x0000_0002, 0x80, 2, 0);
    first_req.share_access = 0;
    let (rh, first) = send_create_request(&mut s, 4, session_id, tree_id, first_req).await;
    assert_eq!(rh.command, Command::Create);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    assert_eq!(
        send_close_request(
            &mut s,
            5,
            session_id,
            tree_id,
            first.expect("first stream").file_id,
        )
        .await,
        STATUS_SUCCESS
    );

    let mut second_req = create_request("streamed.txt:second:$DaTa", 0x0000_0002, 0x80, 3, 0);
    second_req.share_access = 0;
    let (rh, second) = send_create_request(&mut s, 6, session_id, tree_id, second_req).await;
    assert_eq!(rh.command, Command::Create);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    assert_eq!(
        send_close_request(
            &mut s,
            7,
            session_id,
            tree_id,
            second.expect("second stream").file_id,
        )
        .await,
        STATUS_SUCCESS
    );

    let mut delete_second_req = create_request(
        "streamed.txt:second:$DATA",
        0x001f_01ff,
        0x80,
        1,
        0x0000_1000,
    );
    delete_second_req.share_access = 0x0000_0004;
    let (rh, delete_second) =
        send_create_request(&mut s, 8, session_id, tree_id, delete_second_req).await;
    assert_eq!(rh.command, Command::Create);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    assert_eq!(
        send_close_request(
            &mut s,
            9,
            session_id,
            tree_id,
            delete_second.expect("delete second stream").file_id,
        )
        .await,
        STATUS_SUCCESS
    );

    let mut missing_second_req = create_request(
        "streamed.txt:second:$DATA",
        0x001f_01ff,
        0x80,
        1,
        0x0000_1000,
    );
    missing_second_req.share_access = 0x0000_0004;
    let (rh, missing_second) =
        send_create_request(&mut s, 10, session_id, tree_id, missing_second_req).await;
    assert_eq!(rh.command, Command::Create);
    assert_eq!(rh.channel_sequence_status, STATUS_OBJECT_NAME_NOT_FOUND);
    assert!(missing_second.is_none());

    let mut base_req = create_request("streamed.txt", 0x001f_01ff, 0x80, 1, 0x0000_1000);
    base_req.share_access = 0x0000_0004;
    let (rh, base) = send_create_request(&mut s, 11, session_id, tree_id, base_req).await;
    assert_eq!(rh.command, Command::Create);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    assert_eq!(
        send_close_request(
            &mut s,
            12,
            session_id,
            tree_id,
            base.expect("base open").file_id,
        )
        .await,
        STATUS_SUCCESS
    );

    for (message_id, name) in [(13, "streamed.txt:first"), (15, "streamed.txt:second")] {
        let mut req = create_request(name, 0x001f_01ff, 0x80, 2, 0x0000_1000);
        req.share_access = 0x0000_0004;
        let (rh, create) = send_create_request(&mut s, message_id, session_id, tree_id, req).await;
        assert_eq!(rh.command, Command::Create);
        assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS, "{name}");
        let file_id = create.expect("stream open").file_id;
        assert_eq!(
            send_close_request(&mut s, message_id + 1, session_id, tree_id, file_id).await,
            STATUS_SUCCESS
        );
    }

    handle.abort();
}

#[tokio::test]
async fn rename_base_file_denied_while_named_stream_open() {
    let td = tempdir().expect("tempdir");
    std::fs::write(td.path().join("streamed.txt"), b"base").expect("write streamed.txt");

    let (handle, mut s, session_id, tree_id) = start_localfs_session(td.path()).await;

    let stream_req = create_request("streamed.txt:streamtwo", 0x001f_01ff, 0, 3, 0x0000_0040);
    let (rh, stream) = send_create_request(&mut s, 4, session_id, tree_id, stream_req).await;
    assert_eq!(rh.command, Command::Create);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let stream_id = stream.expect("stream open").file_id;

    let (rh, base) = send_create_request(
        &mut s,
        5,
        session_id,
        tree_id,
        create_request("streamed.txt", 0x001f_01ff, 0, 1, 0x0000_0040),
    )
    .await;
    assert_eq!(rh.command, Command::Create);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let base_id = base.expect("base open").file_id;

    assert_eq!(
        set_file_rename_status(
            &mut s,
            6,
            session_id,
            tree_id,
            base_id,
            "renamed.txt",
            false
        )
        .await,
        STATUS_ACCESS_DENIED
    );
    assert!(td.path().join("streamed.txt").exists());
    assert!(!td.path().join("renamed.txt").exists());

    assert_eq!(
        send_close_request(&mut s, 7, session_id, tree_id, stream_id).await,
        STATUS_SUCCESS
    );
    assert_eq!(
        send_close_request(&mut s, 8, session_id, tree_id, base_id).await,
        STATUS_SUCCESS
    );

    handle.abort();
}

#[tokio::test]
async fn rename_named_stream_with_full_base_name_returns_sharing_violation() {
    let td = tempdir().expect("tempdir");
    std::fs::write(td.path().join("streamed.txt"), b"base").expect("write streamed.txt");

    let (handle, mut s, session_id, tree_id) = start_localfs_session(td.path()).await;

    let (rh, first) = send_create_request(
        &mut s,
        4,
        session_id,
        tree_id,
        create_request("streamed.txt:streamone", 0x001f_01ff, 0, 3, 0x0000_0040),
    )
    .await;
    assert_eq!(rh.command, Command::Create);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    close_file(
        &mut s,
        5,
        session_id,
        tree_id,
        first.expect("first stream").file_id,
    )
    .await;

    let (rh, second) = send_create_request(
        &mut s,
        6,
        session_id,
        tree_id,
        create_request("streamed.txt:streamtwo", 0x001f_01ff, 0, 3, 0x0000_0040),
    )
    .await;
    assert_eq!(rh.command, Command::Create);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let second_id = second.expect("second stream").file_id;

    assert_eq!(
        set_file_rename_status(
            &mut s,
            7,
            session_id,
            tree_id,
            second_id,
            "streamed.txt:streamone",
            true
        )
        .await,
        STATUS_SHARING_VIOLATION
    );

    assert_eq!(
        send_close_request(&mut s, 8, session_id, tree_id, second_id).await,
        STATUS_SUCCESS
    );
    handle.abort();
}

#[tokio::test]
async fn stream_overwrite_keeps_named_stream_entry() {
    let td = tempdir().expect("tempdir");
    std::fs::write(td.path().join("streamed.txt"), b"base").expect("write streamed.txt");

    let (handle, mut s, session_id, tree_id) = start_localfs_session(td.path()).await;

    let (status, old_stream) = create_localfs_path_status(
        &mut s,
        session_id,
        tree_id,
        4,
        "streamed.txt:streamtwo",
        0x001f_01ff,
        3,
        0x0000_0040,
    )
    .await;
    assert_eq!(status, STATUS_SUCCESS);
    let old_stream_id = old_stream.expect("old stream");
    assert_eq!(
        write_localfs_path_status(
            &mut s,
            session_id,
            tree_id,
            5,
            old_stream_id,
            0,
            b"old-stream",
        )
        .await,
        STATUS_SUCCESS
    );
    close_file(&mut s, 6, session_id, tree_id, old_stream_id).await;

    let (rh, overwritten) = send_create_request(
        &mut s,
        7,
        session_id,
        tree_id,
        create_request("streamed.txt:streamtwo", 0x001f_01ff, 0, 5, 0x0000_0040),
    )
    .await;
    assert_eq!(rh.command, Command::Create);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let stream = overwritten.expect("overwritten stream");
    assert_eq!(stream.create_action, 0x0000_0003);
    assert_eq!(
        write_localfs_path_status(&mut s, session_id, tree_id, 8, stream.file_id, 0, b"new").await,
        STATUS_SUCCESS
    );

    let base_id = open_localfs_path(
        &mut s,
        session_id,
        tree_id,
        9,
        "streamed.txt",
        0x0000_0080,
        0x0000_0040,
    )
    .await;
    assert_eq!(
        query_file_stream_information(&mut s, 10, session_id, tree_id, base_id).await,
        vec![
            ("::$DATA".to_string(), 4),
            (":streamtwo:$DATA".to_string(), 3)
        ]
    );

    close_file(&mut s, 11, session_id, tree_id, stream.file_id).await;
    close_file(&mut s, 12, session_id, tree_id, base_id).await;
    handle.abort();
}

#[tokio::test]
async fn base_delete_with_share_delete_stream_stays_pending_until_stream_close() {
    let td = tempdir().expect("tempdir");
    std::fs::write(td.path().join("streamed.txt"), b"base").expect("write streamed.txt");

    let (handle, mut s, session_id, tree_id) = start_localfs_session(td.path()).await;

    let (rh, stream) = send_create_request(
        &mut s,
        4,
        session_id,
        tree_id,
        create_request("streamed.txt:streamtwo", 0x0000_0003, 0, 3, 0x0000_0040),
    )
    .await;
    assert_eq!(rh.command, Command::Create);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let stream_id = stream.expect("stream open").file_id;

    assert_eq!(
        write_localfs_path_status(
            &mut s,
            session_id,
            tree_id,
            5,
            stream_id,
            0,
            b"named-stream",
        )
        .await,
        STATUS_SUCCESS
    );

    let (rh, base) = send_create_request(
        &mut s,
        6,
        session_id,
        tree_id,
        create_request("streamed.txt", 0x0001_0080, 0, 1, 0x0000_0040),
    )
    .await;
    assert_eq!(rh.command, Command::Create);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let base_id = base.expect("base open").file_id;

    assert_eq!(
        set_file_disposition_status(&mut s, 7, session_id, tree_id, base_id, true).await,
        STATUS_SUCCESS
    );
    assert_eq!(
        send_close_request(&mut s, 8, session_id, tree_id, base_id).await,
        STATUS_SUCCESS
    );

    let mut unlink_again_req = create_request("streamed.txt", 0x001f_01ff, 0, 1, 0x0000_1000);
    unlink_again_req.share_access = 0x0000_0004;
    let (rh, unlink_again) =
        send_create_request(&mut s, 9, session_id, tree_id, unlink_again_req).await;
    assert_eq!(rh.command, Command::Create);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    assert_eq!(
        send_close_request(
            &mut s,
            10,
            session_id,
            tree_id,
            unlink_again.expect("idempotent delete open").file_id,
        )
        .await,
        STATUS_SUCCESS
    );

    let (status, data) =
        read_localfs_path_status(&mut s, session_id, tree_id, 11, stream_id, 12, 0, 0).await;
    assert_eq!(status, STATUS_SUCCESS);
    assert_eq!(data.expect("stream read data"), b"named-stream");

    for (message_id, name) in [(12, "streamed.txt"), (13, "streamed.txt:streamtwo")] {
        let (rh, create) = send_create_request(
            &mut s,
            message_id,
            session_id,
            tree_id,
            create_request(name, 0x0000_0001, 0, 3, 0x0000_0040),
        )
        .await;
        assert_eq!(rh.command, Command::Create);
        assert_eq!(rh.channel_sequence_status, STATUS_DELETE_PENDING, "{name}");
        assert!(create.is_none(), "{name}");
    }

    assert_eq!(
        send_close_request(&mut s, 14, session_id, tree_id, stream_id).await,
        STATUS_SUCCESS
    );

    let (rh, create) = send_create_request(
        &mut s,
        15,
        session_id,
        tree_id,
        create_request("streamed.txt", 0x0000_0001, 0, 1, 0x0000_0040),
    )
    .await;
    assert_eq!(rh.command, Command::Create);
    assert_eq!(rh.channel_sequence_status, STATUS_OBJECT_NAME_NOT_FOUND);
    assert!(create.is_none());

    handle.abort();
}

#[tokio::test]
async fn named_stream_share_modes_are_independent_per_stream() {
    let td = tempdir().expect("tempdir");
    std::fs::write(td.path().join("streamed.txt"), b"base").expect("write streamed.txt");

    let (handle, mut s, session_id, tree_id) = start_localfs_session(td.path()).await;

    let mut first_req = create_request("streamed.txt:Stream One", 0x0000_0002, 0, 2, 0x0000_0040);
    first_req.share_access = 0;
    let (rh, first) = send_create_request(&mut s, 4, session_id, tree_id, first_req).await;
    assert_eq!(rh.command, Command::Create);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let first_id = first.expect("first stream open").file_id;

    let mut second_req = create_request(
        "streamed.txt:Second Stream:$DaTa",
        0x0000_0002,
        0,
        2,
        0x0000_0040,
    );
    second_req.share_access = 0;
    let (rh, second) = send_create_request(&mut s, 5, session_id, tree_id, second_req).await;
    assert_eq!(rh.command, Command::Create);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let second_id = second.expect("second stream open").file_id;

    let mut reopen_first_req =
        create_request("streamed.txt:Stream One", 0x0000_0002, 0, 0, 0x0000_0040);
    reopen_first_req.share_access = 0;
    let (rh, reopen_first) =
        send_create_request(&mut s, 6, session_id, tree_id, reopen_first_req).await;
    assert_eq!(rh.command, Command::Create);
    assert_eq!(rh.channel_sequence_status, STATUS_SHARING_VIOLATION);
    assert!(reopen_first.is_none());

    let mut reopen_second_req = create_request(
        "streamed.txt:Second Stream:$DATA",
        0x0000_0002,
        0,
        0,
        0x0000_0040,
    );
    reopen_second_req.share_access = 0;
    let (rh, reopen_second) =
        send_create_request(&mut s, 7, session_id, tree_id, reopen_second_req).await;
    assert_eq!(rh.command, Command::Create);
    assert_eq!(rh.channel_sequence_status, STATUS_SHARING_VIOLATION);
    assert!(reopen_second.is_none());

    assert_eq!(
        send_close_request(&mut s, 8, session_id, tree_id, first_id).await,
        STATUS_SUCCESS
    );
    assert_eq!(
        send_close_request(&mut s, 9, session_id, tree_id, second_id).await,
        STATUS_SUCCESS
    );

    handle.abort();
}

#[tokio::test]
async fn stream_names_list_matches_smbtorture_names_matrix() {
    let td = tempdir().expect("tempdir");
    let (handle, mut s, session_id, tree_id) = start_localfs_session(td.path()).await;

    let mut first_req =
        create_request("streamed.txt:\u{0005}Stream\n One", 0x0000_0002, 0x80, 2, 0);
    first_req.share_access = 0;
    let (rh, first) = send_create_request(&mut s, 4, session_id, tree_id, first_req).await;
    assert_eq!(rh.command, Command::Create);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let first_id = first.expect("first stream open").file_id;

    let mut second_req = create_request("streamed.txt:MStream Two:$DaTa", 0x0000_0002, 0x80, 3, 0);
    second_req.share_access = 0;
    let (rh, second) = send_create_request(&mut s, 5, session_id, tree_id, second_req).await;
    assert_eq!(rh.command, Command::Create);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let second_id = second.expect("second stream open").file_id;

    let mut wildcard_req = create_request("streamed.txt:?Stream*:$DATA", 0x0000_0002, 0x80, 3, 0);
    wildcard_req.share_access = 0;
    let (rh, wildcard) = send_create_request(&mut s, 6, session_id, tree_id, wildcard_req).await;
    assert_eq!(rh.command, Command::Create);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let wildcard_id = wildcard.expect("wildcard stream open").file_id;

    let (rh, base) = send_create_request(
        &mut s,
        7,
        session_id,
        tree_id,
        create_request("streamed.txt", 0x0000_0002, 0x80, 1, 0),
    )
    .await;
    assert_eq!(rh.command, Command::Create);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let base_id = base.expect("base open").file_id;
    let mut streams = query_file_stream_information(&mut s, 8, session_id, tree_id, base_id).await;
    streams.sort_by(|left, right| left.0.cmp(&right.0));
    let mut expected = vec![
        (":\u{0005}Stream\n One:$DATA".to_string(), 0),
        (":?Stream*:$DATA".to_string(), 0),
        (":MStream Two:$DATA".to_string(), 0),
        ("::$DATA".to_string(), 0),
    ];
    expected.sort_by(|left, right| left.0.cmp(&right.0));
    assert_eq!(streams, expected);

    for (message_id, file_id) in [
        (9, first_id),
        (10, second_id),
        (11, wildcard_id),
        (12, base_id),
    ] {
        assert_eq!(
            send_close_request(&mut s, message_id, session_id, tree_id, file_id).await,
            STATUS_SUCCESS
        );
    }

    handle.abort();
}

#[tokio::test]
async fn new_stream_inherits_base_creation_time() {
    let td = tempdir().expect("tempdir");
    std::fs::write(td.path().join("streamed.txt"), b"base").expect("write streamed.txt");

    let (handle, mut s, session_id, tree_id) = start_localfs_session(td.path()).await;

    let base_id = open_localfs_path(
        &mut s,
        session_id,
        tree_id,
        4,
        "streamed.txt",
        0x0000_0080,
        0x0000_0040,
    )
    .await;
    let base_basic = query_basic_information(&mut s, 5, session_id, tree_id, base_id).await;
    let base_creation_time = u64::from_le_bytes(base_basic[0..8].try_into().unwrap());
    assert_eq!(
        send_close_request(&mut s, 6, session_id, tree_id, base_id).await,
        STATUS_SUCCESS
    );

    let (rh, stream) = send_create_request(
        &mut s,
        7,
        session_id,
        tree_id,
        create_request("streamed.txt:streamtwo", 0x0000_0180, 0, 2, 0x0000_0040),
    )
    .await;
    assert_eq!(rh.command, Command::Create);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let stream_id = stream.expect("stream open").file_id;

    let stream_basic = query_basic_information(&mut s, 8, session_id, tree_id, stream_id).await;
    assert_eq!(
        u64::from_le_bytes(stream_basic[0..8].try_into().unwrap()),
        base_creation_time
    );
    assert_eq!(
        send_close_request(&mut s, 9, session_id, tree_id, stream_id).await,
        STATUS_SUCCESS
    );

    handle.abort();
}

#[tokio::test]
async fn stream_name_validation_matches_gosmb_matrix_rows() {
    let td = tempdir().expect("tempdir");
    std::fs::write(td.path().join("streamed.txt"), b"base").expect("write streamed.txt");

    let (handle, mut s, session_id, tree_id) = start_localfs_session(td.path()).await;

    let mut wildcard_req = create_request("streamed.txt:?Stream*", 0x0000_0002, 0, 2, 0x0000_0040);
    wildcard_req.share_access = 0;
    let (rh, wildcard) = send_create_request(&mut s, 4, session_id, tree_id, wildcard_req).await;
    assert_eq!(rh.command, Command::Create);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    assert_eq!(
        send_close_request(
            &mut s,
            5,
            session_id,
            tree_id,
            wildcard.expect("wildcard stream open").file_id,
        )
        .await,
        STATUS_SUCCESS
    );

    for (message_id, name) in [
        (6, "streamed.txt:Stream One:"),
        (7, "streamed.txt:Stream One:$FOO"),
        (8, "streamed.txt:Stream One:?D*a"),
        (9, "stream*.txt:?Stream*:$DATA"),
    ] {
        let mut req = create_request(name, 0x0000_0002, 0, 3, 0x0000_0040);
        req.share_access = 0;
        let (rh, create) = send_create_request(&mut s, message_id, session_id, tree_id, req).await;
        assert_eq!(rh.command, Command::Create);
        assert_eq!(
            rh.channel_sequence_status, STATUS_OBJECT_NAME_INVALID,
            "{name}"
        );
        assert!(create.is_none(), "{name}");
    }

    handle.abort();
}

#[tokio::test]
async fn stream_name_control_character_sweep_matches_gosmb() {
    let td = tempdir().expect("tempdir");
    std::fs::write(td.path().join("streamed.txt"), b"base").expect("write streamed.txt");

    let (handle, mut s, session_id, tree_id) = start_localfs_session(td.path()).await;

    for byte in 0x01u8..0x7f {
        let name = format!(
            "streamed.txt:Stream{}0x{:02X}:$DATA",
            char::from(byte),
            byte
        );
        let want = match byte {
            b'/' | b':' | b'\\' => STATUS_OBJECT_NAME_INVALID,
            _ => STATUS_OBJECT_NAME_NOT_FOUND,
        };
        let mut req = create_request(&name, 0x0000_0002, 0, 1, 0x0000_0040);
        req.share_access = 0;
        let (rh, create) =
            send_create_request(&mut s, 100 + byte as u64, session_id, tree_id, req).await;
        assert_eq!(rh.command, Command::Create);
        assert_eq!(rh.channel_sequence_status, want, "byte 0x{byte:02X}");
        assert!(create.is_none(), "byte 0x{byte:02X}");
    }

    handle.abort();
}

#[tokio::test]
async fn file_basic_attributes_create_and_set_info_round_trip() {
    let td = tempdir().expect("tempdir");
    std::fs::write(td.path().join("attrs.txt"), b"hello").expect("write attrs.txt");
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
    let handle = tokio::spawn(async move { server.serve().await });
    tokio::task::yield_now().await;

    let mut s = TcpStream::connect(addr).await.expect("connect");
    let _ = negotiate(&mut s).await;
    let session_id = anonymous_session_setup(&mut s).await;
    let tree_id = tree_connect(&mut s, "\\\\127.0.0.1\\share", session_id, 3).await;

    let (rh, create) = send_create_request(
        &mut s,
        4,
        session_id,
        tree_id,
        create_request(
            "created-readonly.txt",
            0x001f_01ff,
            FILE_ATTRIBUTE_READONLY,
            5,
            0x0000_0040,
        ),
    )
    .await;
    assert_eq!(rh.command, Command::Create);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let created = create.expect("created readonly response");
    assert_eq!(
        created.file_attributes,
        FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_ARCHIVE
    );
    assert_eq!(
        query_basic_attributes(&mut s, 5, session_id, tree_id, created.file_id).await,
        FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_ARCHIVE
    );

    let (rh, temporary) = send_create_request(
        &mut s,
        6,
        session_id,
        tree_id,
        create_request(
            "temporary.txt",
            0x001f_01ff,
            FILE_ATTRIBUTE_TEMPORARY,
            5,
            0x0000_0040,
        ),
    )
    .await;
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    assert_eq!(
        temporary.expect("temporary response").file_attributes,
        FILE_ATTRIBUTE_TEMPORARY | FILE_ATTRIBUTE_ARCHIVE
    );

    let (rh, directory_attr_file) = send_create_request(
        &mut s,
        7,
        session_id,
        tree_id,
        create_request(
            "directory-attr-file.txt",
            0x001f_01ff,
            FILE_ATTRIBUTE_DIRECTORY,
            5,
            0x0000_0040,
        ),
    )
    .await;
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    assert_eq!(
        directory_attr_file
            .expect("directory attr file response")
            .file_attributes,
        FILE_ATTRIBUTE_ARCHIVE
    );

    let (rh, directory) = send_create_request(
        &mut s,
        8,
        session_id,
        tree_id,
        create_request(
            "hidden-system",
            0x001f_01ff,
            FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM,
            2,
            0x0000_0001,
        ),
    )
    .await;
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    assert_eq!(
        directory.expect("directory response").file_attributes,
        FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_DIRECTORY
    );
    assert!(
        td.path().join("hidden-system").is_dir(),
        "FILE_DIRECTORY_FILE create should materialize a directory"
    );

    let (rh, open) = send_create_request(
        &mut s,
        9,
        session_id,
        tree_id,
        create_request("attrs.txt", 0x001f_01ff, 0, 1, 0x0000_0040),
    )
    .await;
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let file_id = open.expect("attrs open response").file_id;
    assert_eq!(
        query_basic_attributes(&mut s, 10, session_id, tree_id, file_id).await,
        FILE_ATTRIBUTE_ARCHIVE
    );

    assert_eq!(
        set_basic_attributes(
            &mut s,
            11,
            session_id,
            tree_id,
            file_id,
            FILE_ATTRIBUTE_HIDDEN
        )
        .await,
        STATUS_SUCCESS
    );
    assert_eq!(
        query_basic_attributes(&mut s, 12, session_id, tree_id, file_id).await,
        FILE_ATTRIBUTE_HIDDEN
    );

    assert_eq!(
        set_basic_attributes(&mut s, 13, session_id, tree_id, file_id, 0).await,
        STATUS_SUCCESS
    );
    assert_eq!(
        query_basic_attributes(&mut s, 14, session_id, tree_id, file_id).await,
        FILE_ATTRIBUTE_HIDDEN
    );

    assert_eq!(
        set_basic_attributes(
            &mut s,
            15,
            session_id,
            tree_id,
            file_id,
            FILE_ATTRIBUTE_NORMAL
        )
        .await,
        STATUS_SUCCESS
    );
    assert_eq!(
        query_basic_attributes(&mut s, 16, session_id, tree_id, file_id).await,
        FILE_ATTRIBUTE_NORMAL
    );

    assert_eq!(
        set_basic_attributes(
            &mut s,
            17,
            session_id,
            tree_id,
            file_id,
            FILE_ATTRIBUTE_DIRECTORY
        )
        .await,
        STATUS_INVALID_PARAMETER
    );

    let (rh, docs) = send_create_request(
        &mut s,
        18,
        session_id,
        tree_id,
        create_request("docs", 0x001f_01ff, 0, 1, 0x0000_0001),
    )
    .await;
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    assert_eq!(
        set_basic_attributes(
            &mut s,
            19,
            session_id,
            tree_id,
            docs.expect("docs open response").file_id,
            FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_TEMPORARY
        )
        .await,
        STATUS_INVALID_PARAMETER
    );

    drop(s);
    handle.abort();
}

#[tokio::test]
async fn set_info_end_of_file_can_grow_and_shrink_file() {
    let td = tempdir().expect("tempdir");
    std::fs::write(td.path().join("eof.txt"), b"hello").expect("write eof.txt");

    let (handle, mut s, session_id, tree_id) = start_localfs_session(td.path()).await;
    let (rh, opened) = send_create_request(
        &mut s,
        4,
        session_id,
        tree_id,
        create_request("eof.txt", 0x001f_01ff, 0, 1, 0x0000_0040),
    )
    .await;
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let file_id = opened.expect("file open").file_id;

    assert_eq!(
        set_end_of_file_status(&mut s, 5, session_id, tree_id, file_id, 37).await,
        STATUS_SUCCESS
    );
    let all_info = query_file_all_information(&mut s, 6, session_id, tree_id, file_id).await;
    assert_eq!(u64::from_le_bytes(all_info[48..56].try_into().unwrap()), 37);
    assert_eq!(
        std::fs::metadata(td.path().join("eof.txt")).unwrap().len(),
        37
    );

    assert_eq!(
        set_end_of_file_status(&mut s, 7, session_id, tree_id, file_id, 7).await,
        STATUS_SUCCESS
    );
    let all_info = query_file_all_information(&mut s, 8, session_id, tree_id, file_id).await;
    assert_eq!(u64::from_le_bytes(all_info[48..56].try_into().unwrap()), 7);
    assert_eq!(
        std::fs::metadata(td.path().join("eof.txt")).unwrap().len(),
        7
    );

    assert_eq!(
        send_close_request(&mut s, 9, session_id, tree_id, file_id).await,
        STATUS_SUCCESS
    );

    handle.abort();
}

#[tokio::test]
async fn set_info_rename_eof_and_basic_info_keep_handle_state() {
    let td = tempdir().expect("tempdir");
    std::fs::write(td.path().join("hello.txt"), b"hello world").expect("write hello.txt");

    let (handle, mut s, session_id, tree_id) = start_localfs_session(td.path()).await;
    let (rh, opened) = send_create_request(
        &mut s,
        4,
        session_id,
        tree_id,
        create_request("hello.txt", 0x001f_01ff, 0, 1, 0x0000_0040),
    )
    .await;
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let file_id = opened.expect("file open").file_id;

    let rename = file_rename_information("renamed.txt", false);
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
    req.write_to(&mut body).expect("write rename");
    let hdr = build_header(Command::SetInfo, 5, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, _rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::SetInfo);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    assert!(!td.path().join("hello.txt").exists());
    assert!(td.path().join("renamed.txt").exists());

    assert_eq!(
        set_end_of_file_status(&mut s, 6, session_id, tree_id, file_id, 5).await,
        STATUS_SUCCESS
    );
    assert_eq!(
        std::fs::metadata(td.path().join("renamed.txt"))
            .expect("renamed metadata")
            .len(),
        5
    );

    let modified = 116_444_736_000_000_000u64 + 1_700_000_000u64 * 10_000_000;
    let mut basic = vec![0; 40];
    basic[16..24].copy_from_slice(&modified.to_le_bytes());
    basic[32..36].copy_from_slice(
        &(FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_ARCHIVE).to_le_bytes(),
    );
    assert_eq!(
        set_basic_information_status(&mut s, 7, session_id, tree_id, file_id, basic).await,
        STATUS_SUCCESS
    );
    let basic = query_basic_information(&mut s, 8, session_id, tree_id, file_id).await;
    assert_eq!(
        u64::from_le_bytes(basic[16..24].try_into().unwrap()),
        modified
    );
    assert_eq!(
        u32::from_le_bytes(basic[32..36].try_into().unwrap())
            & (FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_ARCHIVE),
        FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_ARCHIVE
    );

    assert_eq!(
        send_close_request(&mut s, 9, session_id, tree_id, file_id).await,
        STATUS_SUCCESS
    );

    handle.abort();
}

#[tokio::test]
async fn set_info_full_ea_information_merges_and_deletes_zero_length_eas() {
    let td = tempdir().expect("tempdir");
    std::fs::write(td.path().join("ea.txt"), b"hello").expect("write ea");

    let (handle, mut s, session_id, tree_id) = start_localfs_session(td.path()).await;
    let (rh, opened) = send_create_request(
        &mut s,
        4,
        session_id,
        tree_id,
        create_request("ea.txt", 0x001f_01ff, 0, 1, 0x0000_0040),
    )
    .await;
    assert_eq!(rh.command, Command::Create);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let file_id = opened.expect("ea open").file_id;

    let new_ea = full_ea_information("NewEA", b"testme");
    assert_eq!(
        set_full_ea_information_status(&mut s, 5, session_id, tree_id, file_id, new_ea.clone())
            .await,
        STATUS_SUCCESS
    );
    let (status, queried) =
        query_file_information_class(&mut s, 6, session_id, tree_id, file_id, 0x0f, 4096).await;
    assert_eq!(status, STATUS_SUCCESS);
    assert_eq!(queried, new_ea);
    let (status, ea_size) =
        query_file_information_class(&mut s, 7, session_id, tree_id, file_id, 0x07, 4).await;
    assert_eq!(status, STATUS_SUCCESS);
    assert_eq!(
        u32::from_le_bytes(ea_size[0..4].try_into().unwrap()),
        new_ea.len() as u32
    );

    assert_eq!(
        set_full_ea_information_status(
            &mut s,
            8,
            session_id,
            tree_id,
            file_id,
            full_ea_information("NewEA", &[]),
        )
        .await,
        STATUS_SUCCESS
    );
    let (status, queried) =
        query_file_information_class(&mut s, 9, session_id, tree_id, file_id, 0x0f, 4096).await;
    assert_eq!(status, STATUS_SUCCESS);
    assert_eq!(queried, vec![0; 4]);
    let (status, ea_size) =
        query_file_information_class(&mut s, 10, session_id, tree_id, file_id, 0x07, 4).await;
    assert_eq!(status, STATUS_SUCCESS);
    assert_eq!(u32::from_le_bytes(ea_size[0..4].try_into().unwrap()), 0);

    let multi = full_ea_information_list(&[
        ("EAONE", b"VALUE1".as_slice()),
        ("SECONDEA", b"ValueTwo".as_slice()),
    ]);
    assert_eq!(
        set_full_ea_information_status(&mut s, 11, session_id, tree_id, file_id, multi.clone())
            .await,
        STATUS_SUCCESS
    );
    assert_eq!(
        set_full_ea_information_status(
            &mut s,
            12,
            session_id,
            tree_id,
            file_id,
            full_ea_information("ZeroEA", &[]),
        )
        .await,
        STATUS_SUCCESS
    );
    let (status, queried) =
        query_file_information_class(&mut s, 13, session_id, tree_id, file_id, 0x0f, 4096).await;
    assert_eq!(status, STATUS_SUCCESS);
    assert_eq!(queried, multi);
    let (status, ea_size) =
        query_file_information_class(&mut s, 14, session_id, tree_id, file_id, 0x07, 4).await;
    assert_eq!(status, STATUS_SUCCESS);
    assert_eq!(
        u32::from_le_bytes(ea_size[0..4].try_into().unwrap()),
        multi.len() as u32
    );

    assert_eq!(
        send_close_request(&mut s, 15, session_id, tree_id, file_id).await,
        STATUS_SUCCESS
    );
    handle.abort();
}

#[tokio::test]
async fn set_info_full_ea_information_requires_file_write_ea() {
    let td = tempdir().expect("tempdir");
    std::fs::write(td.path().join("ea-denied.txt"), b"hello").expect("write ea-denied");

    let (handle, mut s, session_id, tree_id) = start_localfs_session(td.path()).await;
    let file_id = open_localfs_path(
        &mut s,
        session_id,
        tree_id,
        4,
        "ea-denied.txt",
        0x0000_0002 | 0x0000_0008,
        0x0000_0040,
    )
    .await;

    assert_eq!(
        set_full_ea_information_status(
            &mut s,
            5,
            session_id,
            tree_id,
            file_id,
            full_ea_information("DeniedEA", b"value"),
        )
        .await,
        STATUS_ACCESS_DENIED
    );
    let (status, queried) =
        query_file_information_class(&mut s, 6, session_id, tree_id, file_id, 0x0f, 4096).await;
    assert_eq!(status, STATUS_SUCCESS);
    assert_eq!(queried, vec![0; 4]);

    assert_eq!(
        send_close_request(&mut s, 7, session_id, tree_id, file_id).await,
        STATUS_SUCCESS
    );
    handle.abort();
}

#[tokio::test]
async fn set_info_disposition_can_clear_delete_on_close() {
    let td = tempdir().expect("tempdir");
    std::fs::write(td.path().join("delete-me.txt"), b"bye").expect("write delete-me");

    let (handle, mut s, session_id, tree_id) = start_localfs_session(td.path()).await;
    let (rh, opened) = send_create_request(
        &mut s,
        4,
        session_id,
        tree_id,
        create_request("delete-me.txt", 0x001f_01ff, 0, 1, 0x0000_0040),
    )
    .await;
    assert_eq!(rh.command, Command::Create);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let file_id = opened.expect("delete-me open").file_id;

    assert_eq!(
        set_file_disposition_status(&mut s, 5, session_id, tree_id, file_id, true).await,
        STATUS_SUCCESS
    );
    let all_info = query_file_all_information(&mut s, 6, session_id, tree_id, file_id).await;
    assert_eq!(u32::from_le_bytes(all_info[56..60].try_into().unwrap()), 0);
    assert_eq!(all_info[60], 1);

    assert_eq!(
        set_file_disposition_status(&mut s, 7, session_id, tree_id, file_id, false).await,
        STATUS_SUCCESS
    );
    let all_info = query_file_all_information(&mut s, 8, session_id, tree_id, file_id).await;
    assert_eq!(u32::from_le_bytes(all_info[56..60].try_into().unwrap()), 1);
    assert_eq!(all_info[60], 0);

    assert_eq!(
        send_close_request(&mut s, 9, session_id, tree_id, file_id).await,
        STATUS_SUCCESS
    );
    assert!(
        td.path().join("delete-me.txt").exists(),
        "cleared delete-on-close should keep the file"
    );

    let (rh, reopened) = send_create_request(
        &mut s,
        10,
        session_id,
        tree_id,
        create_request("delete-me.txt", 0x001f_01ff, 0, 1, 0x0000_0040),
    )
    .await;
    assert_eq!(rh.command, Command::Create);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let reopened_id = reopened.expect("delete-me reopen").file_id;
    assert_eq!(
        set_file_disposition_status(&mut s, 11, session_id, tree_id, reopened_id, true).await,
        STATUS_SUCCESS
    );
    assert_eq!(
        send_close_request(&mut s, 12, session_id, tree_id, reopened_id).await,
        STATUS_SUCCESS
    );
    assert!(
        !td.path().join("delete-me.txt").exists(),
        "delete-on-close should unlink on final close"
    );

    handle.abort();
}

#[tokio::test]
async fn directory_create_delete_on_close_removes_directory_on_close() {
    const DELETE_ACCESS: u32 = 0x0001_0000;
    const FILE_DIRECTORY_FILE: u32 = 0x0000_0001;
    const FILE_DELETE_ON_CLOSE: u32 = 0x0000_1000;

    let td = tempdir().expect("tempdir");
    std::fs::create_dir(td.path().join("empty-dir")).expect("mkdir empty-dir");
    let (handle, mut s, session_id, tree_id) = start_localfs_session(td.path()).await;

    let req = create_request(
        "empty-dir",
        DELETE_ACCESS,
        FILE_ATTRIBUTE_NORMAL,
        1,
        FILE_DIRECTORY_FILE | FILE_DELETE_ON_CLOSE,
    );
    let mut body = Vec::new();
    req.write_to(&mut body)
        .expect("write delete-on-close dir create");
    let hdr = build_header(Command::Create, 4, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Create);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let file_id = CreateResponse::parse(rb)
        .expect("parse delete-on-close dir create")
        .file_id;

    close_file(&mut s, 5, session_id, tree_id, file_id).await;

    assert!(
        !td.path().join("empty-dir").exists(),
        "directory delete-on-close left the directory behind"
    );

    drop(s);
    handle.abort();
}

#[tokio::test]
async fn directory_can_be_removed_after_read_enumeration_handle_closes() {
    const DELETE_ACCESS: u32 = 0x0001_0000;
    const FILE_READ_DATA: u32 = 0x0000_0001;
    const FILE_DIRECTORY_FILE: u32 = 0x0000_0001;
    const FILE_DELETE_ON_CLOSE: u32 = 0x0000_1000;

    let td = tempdir().expect("tempdir");
    std::fs::create_dir(td.path().join("empty-dir")).expect("mkdir empty-dir");
    let (handle, mut s, session_id, tree_id) = start_localfs_session(td.path()).await;

    let mut open_req = create_request(
        "empty-dir",
        FILE_READ_DATA,
        FILE_ATTRIBUTE_NORMAL,
        1,
        FILE_DIRECTORY_FILE,
    );
    open_req.share_access = 0x0000_0003;
    let mut body = Vec::new();
    open_req.write_to(&mut body).expect("write read dir create");
    let hdr = build_header(Command::Create, 4, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Create);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let read_dir_id = CreateResponse::parse(rb).expect("parse read dir").file_id;

    let _status =
        query_directory_status_for_class(&mut s, 5, session_id, tree_id, read_dir_id, 0x0c).await;
    close_file(&mut s, 6, session_id, tree_id, read_dir_id).await;

    let req = create_request(
        "empty-dir",
        DELETE_ACCESS,
        FILE_ATTRIBUTE_NORMAL,
        1,
        FILE_DIRECTORY_FILE | FILE_DELETE_ON_CLOSE,
    );
    let mut body = Vec::new();
    req.write_to(&mut body)
        .expect("write delete-on-close dir create");
    let hdr = build_header(Command::Create, 7, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Create);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let delete_dir_id = CreateResponse::parse(rb)
        .expect("parse delete-on-close dir create")
        .file_id;
    close_file(&mut s, 8, session_id, tree_id, delete_dir_id).await;

    assert!(
        !td.path().join("empty-dir").exists(),
        "directory read enumeration left stale state blocking rmdir"
    );

    drop(s);
    handle.abort();
}

#[tokio::test]
async fn delete_on_close_waits_for_other_open_handle() {
    let td = tempdir().expect("tempdir");
    std::fs::write(td.path().join("held.txt"), b"held open").expect("write held");

    let (handle, mut s, session_id, tree_id) = start_localfs_session(td.path()).await;
    let held_id = open_localfs_path(
        &mut s,
        session_id,
        tree_id,
        4,
        "held.txt",
        0x0000_0001 | 0x0000_0080,
        0x0000_0040,
    )
    .await;
    let delete_id = open_localfs_path(
        &mut s,
        session_id,
        tree_id,
        5,
        "held.txt",
        0x0001_0000 | 0x0000_0080,
        0x0000_0040,
    )
    .await;

    assert_eq!(
        set_file_disposition_status(&mut s, 6, session_id, tree_id, delete_id, true).await,
        STATUS_SUCCESS
    );
    assert_eq!(
        send_close_request(&mut s, 7, session_id, tree_id, delete_id).await,
        STATUS_SUCCESS
    );
    assert!(
        td.path().join("held.txt").exists(),
        "delete-pending file should remain while another handle is open"
    );

    let (status, reopened) = create_localfs_path_status(
        &mut s,
        session_id,
        tree_id,
        8,
        "held.txt",
        0x0000_0001,
        1,
        0x0000_0040,
    )
    .await;
    assert_eq!(status, STATUS_DELETE_PENDING);
    assert!(reopened.is_none());

    assert_eq!(
        send_close_request(&mut s, 9, session_id, tree_id, held_id).await,
        STATUS_SUCCESS
    );
    assert!(
        !td.path().join("held.txt").exists(),
        "delete-pending file should unlink after the final handle closes"
    );

    handle.abort();
}

#[tokio::test]
async fn set_info_basic_information_timestamp_round_trip() {
    let td = tempdir().expect("tempdir");
    std::fs::write(td.path().join("times.txt"), b"hello").expect("write times.txt");

    let (handle, mut s, session_id, tree_id) = start_localfs_session(td.path()).await;
    let (rh, opened) = send_create_request(
        &mut s,
        4,
        session_id,
        tree_id,
        create_request("times.txt", 0x001f_01ff, 0, 1, 0x0000_0040),
    )
    .await;
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let file_id = opened.expect("file open").file_id;

    let created = 116_444_736_000_000_000u64 + 1_767_222_245u64 * 10_000_000;
    let accessed = created + 3_600 * 10_000_000;
    let modified = created + 7_200 * 10_000_000;
    let changed = created + 10_800 * 10_000_000;
    let mut basic = vec![0; 40];
    basic[0..8].copy_from_slice(&created.to_le_bytes());
    basic[8..16].copy_from_slice(&accessed.to_le_bytes());
    basic[16..24].copy_from_slice(&modified.to_le_bytes());
    basic[24..32].copy_from_slice(&changed.to_le_bytes());
    assert_eq!(
        set_basic_information_status(&mut s, 5, session_id, tree_id, file_id, basic).await,
        STATUS_SUCCESS
    );

    let output = query_basic_information(&mut s, 6, session_id, tree_id, file_id).await;
    assert_eq!(
        u64::from_le_bytes(output[0..8].try_into().unwrap()),
        created
    );
    assert_eq!(
        u64::from_le_bytes(output[8..16].try_into().unwrap()),
        accessed
    );
    assert_eq!(
        u64::from_le_bytes(output[16..24].try_into().unwrap()),
        modified
    );
    assert_eq!(
        u64::from_le_bytes(output[24..32].try_into().unwrap()),
        changed
    );

    assert_eq!(
        set_basic_information_status(&mut s, 7, session_id, tree_id, file_id, vec![0; 40]).await,
        STATUS_SUCCESS
    );
    let output = query_basic_information(&mut s, 8, session_id, tree_id, file_id).await;
    assert_eq!(
        u64::from_le_bytes(output[0..8].try_into().unwrap()),
        created
    );
    assert_eq!(
        u64::from_le_bytes(output[8..16].try_into().unwrap()),
        accessed
    );
    assert_eq!(
        u64::from_le_bytes(output[16..24].try_into().unwrap()),
        modified
    );
    assert_eq!(
        u64::from_le_bytes(output[24..32].try_into().unwrap()),
        changed
    );

    let mut message_id = 9;
    for sentinel in [u64::MAX, u64::MAX - 1] {
        let mut unchanged = vec![0; 40];
        unchanged[0..8].copy_from_slice(&sentinel.to_le_bytes());
        unchanged[8..16].copy_from_slice(&sentinel.to_le_bytes());
        unchanged[16..24].copy_from_slice(&sentinel.to_le_bytes());
        unchanged[24..32].copy_from_slice(&sentinel.to_le_bytes());
        assert_eq!(
            set_basic_information_status(
                &mut s, message_id, session_id, tree_id, file_id, unchanged,
            )
            .await,
            STATUS_SUCCESS
        );
        message_id += 1;
        let output =
            query_basic_information(&mut s, message_id, session_id, tree_id, file_id).await;
        message_id += 1;
        assert_eq!(
            u64::from_le_bytes(output[0..8].try_into().unwrap()),
            created
        );
        assert_eq!(
            u64::from_le_bytes(output[8..16].try_into().unwrap()),
            accessed
        );
        assert_eq!(
            u64::from_le_bytes(output[16..24].try_into().unwrap()),
            modified
        );
        assert_eq!(
            u64::from_le_bytes(output[24..32].try_into().unwrap()),
            changed
        );
    }

    let mut attr_only = vec![0; 40];
    attr_only[32..36].copy_from_slice(&FILE_ATTRIBUTE_HIDDEN.to_le_bytes());
    assert_eq!(
        set_basic_information_status(&mut s, message_id, session_id, tree_id, file_id, attr_only)
            .await,
        STATUS_SUCCESS
    );
    message_id += 1;
    let output = query_basic_information(&mut s, message_id, session_id, tree_id, file_id).await;
    message_id += 1;
    assert_eq!(
        u64::from_le_bytes(output[0..8].try_into().unwrap()),
        created
    );
    assert_eq!(
        u64::from_le_bytes(output[8..16].try_into().unwrap()),
        accessed
    );
    assert_eq!(
        u64::from_le_bytes(output[16..24].try_into().unwrap()),
        modified
    );
    assert_eq!(
        u64::from_le_bytes(output[24..32].try_into().unwrap()),
        changed
    );
    assert_eq!(
        u32::from_le_bytes(output[32..36].try_into().unwrap()) & FILE_ATTRIBUTE_HIDDEN,
        FILE_ATTRIBUTE_HIDDEN
    );

    assert_eq!(
        send_close_request(&mut s, message_id, session_id, tree_id, file_id).await,
        STATUS_SUCCESS
    );

    handle.abort();
}

#[tokio::test]
async fn create_delete_access_on_readonly_file_and_clear_readonly() {
    let td = tempdir().expect("tempdir");
    std::fs::create_dir(td.path().join("torture_create.dir")).expect("mkdir torture dir");
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
    let name = "torture_create.dir\\torture_open_for_delete.txt";

    let (rh, create) = send_create_request(
        &mut s,
        4,
        session_id,
        tree_id,
        create_request(name, 0x001f_01ff, FILE_ATTRIBUTE_READONLY, 2, 0),
    )
    .await;
    assert_eq!(rh.command, Command::Create);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let readonly_id = create.expect("readonly create response").file_id;
    assert_eq!(
        query_basic_attributes(&mut s, 5, session_id, tree_id, readonly_id).await,
        FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_ARCHIVE
    );
    close_file(&mut s, 6, session_id, tree_id, readonly_id).await;

    let (rh, delete_open) = send_create_request(
        &mut s,
        7,
        session_id,
        tree_id,
        create_request(name, 0x0001_0000, 0, 1, 0),
    )
    .await;
    assert_eq!(rh.command, Command::Create);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    close_file(
        &mut s,
        8,
        session_id,
        tree_id,
        delete_open.expect("delete open response").file_id,
    )
    .await;

    let (rh, attr_open) = send_create_request(
        &mut s,
        9,
        session_id,
        tree_id,
        create_request(name, 0x0000_0180, 0, 1, 0),
    )
    .await;
    assert_eq!(rh.command, Command::Create);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let attr_id = attr_open.expect("attribute open response").file_id;
    assert_eq!(
        set_basic_attributes(
            &mut s,
            10,
            session_id,
            tree_id,
            attr_id,
            FILE_ATTRIBUTE_ARCHIVE
        )
        .await,
        STATUS_SUCCESS
    );
    assert_eq!(
        query_basic_attributes(&mut s, 11, session_id, tree_id, attr_id).await,
        FILE_ATTRIBUTE_ARCHIVE
    );
    close_file(&mut s, 12, session_id, tree_id, attr_id).await;

    drop(s);
    handle.abort();
}

#[tokio::test]
async fn create_share_mode_matrix_rows_match_gosmb() {
    let td = tempdir().expect("tempdir");
    let cases = [
        (
            "delete access requires peer share delete",
            0x0000_0001 | 0x0001_0000,
            0x0000_0001 | 0x0000_0002,
            0x0000_0001,
            0x0000_0001 | 0x0000_0002,
            STATUS_SHARING_VIOLATION,
        ),
        (
            "delete access allowed by peer share delete",
            0x0000_0001 | 0x0001_0000,
            0x0000_0001 | 0x0000_0002,
            0x0000_0001,
            0x0000_0001 | 0x0000_0002 | 0x0000_0004,
            STATUS_SUCCESS,
        ),
        (
            "sec file all without delete bit does not require peer share delete",
            0x0000_01ff,
            0x0000_0001 | 0x0000_0002,
            0x0000_0001,
            0x0000_0001 | 0x0000_0002,
            STATUS_SUCCESS,
        ),
        (
            "share-none read open rejects later read",
            0x0000_0001,
            0,
            0x0000_0001,
            0x0000_0001 | 0x0000_0002 | 0x0000_0004,
            STATUS_SHARING_VIOLATION,
        ),
        (
            "existing read share rejects later write",
            0x0000_0001,
            0x0000_0001,
            0x0000_0002,
            0x0000_0001 | 0x0000_0002 | 0x0000_0004,
            STATUS_SHARING_VIOLATION,
        ),
        (
            "execute access requires peer share read",
            0x001f_01ff,
            0x0000_0002,
            0x0000_0020,
            0x0000_0001 | 0x0000_0002 | 0x0000_0004,
            STATUS_SHARING_VIOLATION,
        ),
        (
            "second read-only open allowed by first read-write share",
            0x0000_0001 | 0x0000_0002,
            0x0000_0001 | 0x0000_0002,
            0x0000_0001,
            0x0000_0001 | 0x0000_0002,
            STATUS_SUCCESS,
        ),
        (
            "all-access first open requires peer share delete",
            0x001f_01ff,
            0x0000_0001 | 0x0000_0002,
            0x0000_0001,
            0x0000_0001 | 0x0000_0002,
            STATUS_SHARING_VIOLATION,
        ),
        (
            "metadata access does not require share read write delete",
            0x0000_0080,
            0,
            0x0000_0001,
            0x0000_0001 | 0x0000_0002 | 0x0000_0004,
            STATUS_SUCCESS,
        ),
        (
            "metadata share none does not block existing read data handle",
            0x0000_0001,
            0x0000_0001 | 0x0000_0002 | 0x0000_0004,
            0x0000_0080,
            0,
            STATUS_SUCCESS,
        ),
    ];
    for (idx, _) in cases.iter().enumerate() {
        std::fs::write(td.path().join(format!("sharemode-{idx}.txt")), b"hello")
            .expect("write sharemode file");
    }
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

    for (idx, (case, first_access, first_share, second_access, second_share, expected_status)) in
        cases.into_iter().enumerate()
    {
        let name = format!("sharemode-{idx}.txt");
        let mut first_req = create_request(&name, first_access, 0, 1, 0x0000_0040);
        first_req.share_access = first_share;
        let (rh, first) =
            send_create_request(&mut s, 20 + idx as u64 * 3, session_id, tree_id, first_req).await;
        assert_eq!(rh.command, Command::Create);
        assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS, "{case}");
        let first_id = first.expect("first share-mode open response").file_id;

        let mut second_req = create_request(&name, second_access, 0, 1, 0x0000_0040);
        second_req.share_access = second_share;
        let (rh, second) =
            send_create_request(&mut s, 21 + idx as u64 * 3, session_id, tree_id, second_req).await;
        assert_eq!(rh.command, Command::Create);
        assert_eq!(rh.channel_sequence_status, expected_status, "{case}");
        if let Some(second) = second {
            close_file(
                &mut s,
                22 + idx as u64 * 3,
                session_id,
                tree_id,
                second.file_id,
            )
            .await;
        }
        close_file(&mut s, 60 + idx as u64, session_id, tree_id, first_id).await;
    }

    drop(s);
    handle.abort();
}

#[tokio::test]
async fn file_create_collision_precedes_share_violation() {
    let td = tempdir().expect("tempdir");
    std::fs::write(td.path().join("replay-regular.dat"), b"hello").expect("write file");
    let (handle, mut s, session_id, tree_id) = start_localfs_session(td.path()).await;

    let desired_access = 0x0010_0000
        | 0x0002_0000
        | 0x0001_0000
        | 0x0000_0100
        | 0x0000_0080
        | 0x0000_0010
        | 0x0000_0004
        | 0x0000_0002;
    let mut first_req = create_request("replay-regular.dat", desired_access, 0, 1, 0);
    first_req.share_access = 0x0000_0004;
    let (rh, first) = send_create_request(&mut s, 4, session_id, tree_id, first_req).await;
    assert_eq!(rh.command, Command::Create);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let first_id = first.expect("first open").file_id;

    let mut create_again_req = create_request("replay-regular.dat", desired_access, 0, 2, 0);
    create_again_req.share_access = 0x0000_0004;
    let (rh, duplicate) =
        send_create_request(&mut s, 5, session_id, tree_id, create_again_req).await;
    assert_eq!(rh.command, Command::Create);
    assert_eq!(rh.channel_sequence_status, STATUS_OBJECT_NAME_COLLISION);
    assert!(duplicate.is_none());

    let mut open_if_req = create_request("replay-regular.dat", desired_access, 0, 3, 0);
    open_if_req.share_access = 0x0000_0004;
    let (rh, opened) = send_create_request(&mut s, 6, session_id, tree_id, open_if_req).await;
    assert_eq!(rh.command, Command::Create);
    assert_eq!(rh.channel_sequence_status, STATUS_SHARING_VIOLATION);
    assert!(opened.is_none());

    assert_eq!(
        send_close_request(&mut s, 7, session_id, tree_id, first_id).await,
        STATUS_SUCCESS
    );
    handle.abort();
}

#[tokio::test]
async fn change_notify_validates_request_and_open_state() {
    let td = tempdir().expect("tempdir");
    std::fs::create_dir(td.path().join("watch")).expect("mkdir watch");
    std::fs::write(td.path().join("file.txt"), b"hello").expect("write file");
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

    let metadata_dir = open_localfs_path(
        &mut s,
        session_id,
        tree_id,
        4,
        "watch",
        0x0000_0080,
        0x0000_0001,
    )
    .await;
    let list_dir = open_localfs_path(
        &mut s,
        session_id,
        tree_id,
        5,
        "watch",
        0x0000_0001,
        0x0000_0001,
    )
    .await;
    let file_id = open_localfs_path(
        &mut s,
        session_id,
        tree_id,
        6,
        "file.txt",
        0x001f_01ff,
        0x0000_0040,
    )
    .await;

    let notify = |file_id: FileId| ChangeNotifyRequest {
        structure_size: 32,
        flags: 0,
        output_buffer_length: 4096,
        file_id,
        completion_filter: 0x0000_0001,
        reserved: 0,
    };

    assert_eq!(
        change_notify_status(&mut s, 7, session_id, tree_id, notify(metadata_dir)).await,
        STATUS_ACCESS_DENIED
    );
    assert_eq!(
        change_notify_status(&mut s, 8, session_id, tree_id, notify(file_id)).await,
        STATUS_INVALID_PARAMETER
    );
    assert_eq!(
        change_notify_status(&mut s, 9, session_id, tree_id, notify(FileId::new(1, 404))).await,
        STATUS_FILE_CLOSED
    );
    assert_eq!(
        change_notify_status(
            &mut s,
            10,
            session_id,
            tree_id,
            ChangeNotifyRequest {
                flags: 0x0002,
                ..notify(list_dir)
            },
        )
        .await,
        STATUS_INVALID_PARAMETER
    );
    assert_eq!(
        change_notify_status(
            &mut s,
            11,
            session_id,
            tree_id,
            ChangeNotifyRequest {
                output_buffer_length: 8 * 1024 * 1024 + 1,
                ..notify(list_dir)
            },
        )
        .await,
        STATUS_INVALID_PARAMETER
    );
    let pending = send_change_notify(&mut s, 12, session_id, tree_id, notify(list_dir)).await;
    assert_eq!(pending.channel_sequence_status, STATUS_PENDING);
    assert!(pending.is_async());
    let pending_async_id = pending.async_id().expect("async id");
    assert_ne!(pending_async_id, 0);
    send_async_cancel(&mut s, 13, session_id, pending_async_id).await;
    let final_resp = read_frame(&mut s).await;
    let (rh, rb) = parse_response_header(&final_resp);
    assert_eq!(rh.command, Command::ChangeNotify);
    assert_eq!(rh.channel_sequence_status, STATUS_CANCELLED);
    assert_eq!(rh.async_id(), Some(pending_async_id));
    let notify = ChangeNotifyResponse::parse(rb).expect("parse notify cancel resp");
    assert_eq!(notify.output_buffer_length, 0);

    close_file(&mut s, 14, session_id, tree_id, metadata_dir).await;
    close_file(&mut s, 15, session_id, tree_id, list_dir).await;
    close_file(&mut s, 16, session_id, tree_id, file_id).await;
    drop(s);
    handle.abort();
}

#[tokio::test]
async fn change_notify_completes_async_for_created_child() {
    let td = tempdir().expect("tempdir");
    std::fs::create_dir(td.path().join("watch")).expect("mkdir watch");
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

    let watch_dir = open_localfs_path(
        &mut s,
        session_id,
        tree_id,
        4,
        "watch",
        0x0000_0001,
        0x0000_0001,
    )
    .await;

    let notify_req = ChangeNotifyRequest {
        structure_size: 32,
        flags: 0,
        output_buffer_length: 4096,
        file_id: watch_dir,
        completion_filter: 0x0000_0001,
        reserved: 0,
    };
    let pending = send_change_notify(&mut s, 5, session_id, tree_id, notify_req).await;
    assert_eq!(pending.channel_sequence_status, STATUS_PENDING);
    assert!(pending.is_async());
    let pending_async_id = pending.async_id().expect("async id");

    let create_req = create_request(
        "watch\\changed.txt",
        0x001f_01ff,
        FILE_ATTRIBUTE_NORMAL,
        2,
        0x0000_0040,
    );
    let mut body = Vec::new();
    create_req.write_to(&mut body).expect("write create");
    let hdr = build_header(Command::Create, 6, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;

    let mut created_file = None;
    let mut saw_notify = false;
    for _ in 0..2 {
        let resp = read_frame(&mut s).await;
        let (rh, rb) = parse_response_header(&resp);
        match rh.command {
            Command::Create => {
                assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
                let create = CreateResponse::parse(rb).expect("parse create resp");
                created_file = Some(create.file_id);
            }
            Command::ChangeNotify => {
                assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
                assert!(rh.is_async());
                assert_eq!(rh.async_id(), Some(pending_async_id));
                let notify = ChangeNotifyResponse::parse(rb).expect("parse notify resp");
                assert_eq!(notify.structure_size, 9);
                assert_eq!(notify.output_buffer_offset, 72);
                assert!(notify.output_buffer_length > 0);
                let (action, name) = decode_file_notify_information(&notify.buffer);
                assert_eq!(action, 0x0000_0001);
                assert_eq!(name, "changed.txt");
                saw_notify = true;
            }
            other => panic!("unexpected response {other:?}"),
        }
    }
    assert!(saw_notify, "missing change notify completion");

    close_file(
        &mut s,
        7,
        session_id,
        tree_id,
        created_file.expect("created file"),
    )
    .await;
    close_file(&mut s, 8, session_id, tree_id, watch_dir).await;
    drop(s);
    handle.abort();
}

#[tokio::test]
async fn change_notify_completes_for_external_localfs_create() {
    let td = tempdir().expect("tempdir");
    std::fs::create_dir(td.path().join("watch")).expect("mkdir watch");
    let (handle, mut s, session_id, tree_id) = start_localfs_session(td.path()).await;

    let watch_dir = open_localfs_path(
        &mut s,
        session_id,
        tree_id,
        4,
        "watch",
        0x0000_0001,
        0x0000_0001,
    )
    .await;
    let notify_req = ChangeNotifyRequest {
        structure_size: 32,
        flags: 0,
        output_buffer_length: 4096,
        file_id: watch_dir,
        completion_filter: 0x0000_0001 | 0x0000_0008 | 0x0000_0010,
        reserved: 0,
    };
    let pending = send_change_notify(&mut s, 5, session_id, tree_id, notify_req).await;
    assert_eq!(pending.channel_sequence_status, STATUS_PENDING);
    let pending_async_id = pending.async_id().expect("async id");

    sleep(Duration::from_millis(100)).await;
    std::fs::write(td.path().join("watch").join("external.txt"), b"external")
        .expect("external create");

    let resp = tokio::time::timeout(Duration::from_secs(15), read_frame(&mut s))
        .await
        .expect("external create notify timed out");
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::ChangeNotify);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    assert!(rh.is_async());
    assert_eq!(rh.async_id(), Some(pending_async_id));
    let notify = ChangeNotifyResponse::parse(rb).expect("parse notify resp");
    let records = decode_file_notify_records(&notify.buffer);
    assert!(
        records.iter().any(|(action, name)| {
            matches!(*action, 0x0000_0001 | 0x0000_0003) && name == "external.txt"
        }),
        "external notify records = {records:?}"
    );

    close_file(&mut s, 6, session_id, tree_id, watch_dir).await;
    drop(s);
    handle.abort();
}

#[tokio::test]
async fn change_notify_recursive_reports_name_relative_to_watch_root() {
    let td = tempdir().expect("tempdir");
    std::fs::create_dir_all(td.path().join("watch").join("sub")).expect("mkdir watch/sub");
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

    let watch_dir = open_localfs_path(
        &mut s,
        session_id,
        tree_id,
        4,
        "watch",
        0x0000_0001,
        0x0000_0001,
    )
    .await;

    let notify_req = ChangeNotifyRequest {
        structure_size: 32,
        flags: ChangeNotifyRequest::FLAG_WATCH_TREE,
        output_buffer_length: 4096,
        file_id: watch_dir,
        completion_filter: 0x0000_0001,
        reserved: 0,
    };
    let pending = send_change_notify(&mut s, 5, session_id, tree_id, notify_req).await;
    assert_eq!(pending.channel_sequence_status, STATUS_PENDING);
    let pending_async_id = pending.async_id().expect("async id");

    let create_req = create_request(
        "watch\\sub\\nested.txt",
        0x001f_01ff,
        FILE_ATTRIBUTE_NORMAL,
        2,
        0x0000_0040,
    );
    let mut body = Vec::new();
    create_req.write_to(&mut body).expect("write create");
    let hdr = build_header(Command::Create, 6, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;

    let mut created_file = None;
    let mut saw_notify = false;
    for _ in 0..2 {
        let resp = read_frame(&mut s).await;
        let (rh, rb) = parse_response_header(&resp);
        match rh.command {
            Command::Create => {
                assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
                let create = CreateResponse::parse(rb).expect("parse create resp");
                created_file = Some(create.file_id);
            }
            Command::ChangeNotify => {
                assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
                assert!(rh.is_async());
                assert_eq!(rh.async_id(), Some(pending_async_id));
                let notify = ChangeNotifyResponse::parse(rb).expect("parse notify resp");
                let (action, name) = decode_file_notify_information(&notify.buffer);
                assert_eq!(action, 0x0000_0001);
                assert_eq!(name, "sub\\nested.txt");
                saw_notify = true;
            }
            other => panic!("unexpected response {other:?}"),
        }
    }
    assert!(saw_notify, "missing recursive change notify completion");

    close_file(
        &mut s,
        7,
        session_id,
        tree_id,
        created_file.expect("created file"),
    )
    .await;
    close_file(&mut s, 8, session_id, tree_id, watch_dir).await;
    drop(s);
    handle.abort();
}

#[tokio::test]
async fn change_notify_zero_filter_matches_created_child() {
    let td = tempdir().expect("tempdir");
    std::fs::create_dir(td.path().join("watch")).expect("mkdir watch");
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

    let watch_dir = open_localfs_path(
        &mut s,
        session_id,
        tree_id,
        4,
        "watch",
        0x0000_0001,
        0x0000_0001,
    )
    .await;
    let notify_req = ChangeNotifyRequest {
        structure_size: 32,
        flags: 0,
        output_buffer_length: 4096,
        file_id: watch_dir,
        completion_filter: 0,
        reserved: 0,
    };
    let pending = send_change_notify(&mut s, 5, session_id, tree_id, notify_req).await;
    assert_eq!(pending.channel_sequence_status, STATUS_PENDING);
    let pending_async_id = pending.async_id().expect("async id");

    let (notify, created_file) = create_child_and_expect_notify(
        &mut s,
        6,
        session_id,
        tree_id,
        "watch\\any.txt",
        pending_async_id,
        STATUS_SUCCESS,
    )
    .await;
    let (action, name) = decode_file_notify_information(&notify.buffer);
    assert_eq!(action, 0x0000_0001);
    assert_eq!(name, "any.txt");

    close_file(&mut s, 7, session_id, tree_id, created_file).await;
    close_file(&mut s, 8, session_id, tree_id, watch_dir).await;
    drop(s);
    handle.abort();
}

#[tokio::test]
async fn change_notify_cancel_then_rearm_preserves_per_handle_mask_for_dir_create() {
    const FILE_NOTIFY_CHANGE_FILE_NAME: u32 = 0x0000_0001;
    const FILE_NOTIFY_CHANGE_DIR_NAME: u32 = 0x0000_0002;
    const FILE_ACTION_ADDED: u32 = 0x0000_0001;

    let td = tempdir().expect("tempdir");
    std::fs::create_dir(td.path().join("watch")).expect("mkdir watch");
    let (handle, mut s, session_id, tree_id) = start_localfs_session(td.path()).await;

    async fn arm_cancel_and_rearm(
        s: &mut TcpStream,
        session_id: u64,
        tree_id: u32,
        watch_dir: FileId,
        first_message_id: u64,
        filter: u32,
    ) -> u64 {
        let notify_req = ChangeNotifyRequest {
            structure_size: 32,
            flags: ChangeNotifyRequest::FLAG_WATCH_TREE,
            output_buffer_length: 1000,
            file_id: watch_dir,
            completion_filter: filter,
            reserved: 0,
        };
        let pending =
            send_change_notify(s, first_message_id, session_id, tree_id, notify_req.clone()).await;
        assert_eq!(pending.channel_sequence_status, STATUS_PENDING);
        let pending_async_id = pending.async_id().expect("first async id");
        send_async_cancel(s, first_message_id + 1, session_id, pending_async_id).await;
        let cancel_frame = read_frame_with_test_timeout(s, "initial cancelled notify").await;
        let (cancel_hdr, cancel_body) = parse_response_header(&cancel_frame);
        assert_eq!(cancel_hdr.command, Command::ChangeNotify);
        assert_eq!(cancel_hdr.channel_sequence_status, STATUS_CANCELLED);
        assert_eq!(cancel_hdr.async_id(), Some(pending_async_id));
        let cancel = ChangeNotifyResponse::parse(cancel_body).expect("parse cancel notify");
        assert_eq!(cancel.output_buffer_length, 0);

        let pending =
            send_change_notify(s, first_message_id + 2, session_id, tree_id, notify_req).await;
        assert_eq!(pending.channel_sequence_status, STATUS_PENDING);
        pending.async_id().expect("second async id")
    }

    async fn create_child_dir(
        s: &mut TcpStream,
        message_id: u64,
        session_id: u64,
        tree_id: u32,
        name: &str,
    ) -> FileId {
        let req = create_request(name, 0x001f_01ff, FILE_ATTRIBUTE_NORMAL, 2, 0x0000_0001);
        let mut body = Vec::new();
        req.write_to(&mut body).expect("write create dir");
        let hdr = build_header(Command::Create, message_id, session_id, tree_id);
        write_frame(s, &hdr, &body).await;
        let resp = read_frame_with_test_timeout(s, "directory create response").await;
        let (rh, rb) = parse_response_header(&resp);
        assert_eq!(rh.command, Command::Create);
        assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
        CreateResponse::parse(rb).expect("parse create dir").file_id
    }

    let watch_dir_file_filter = open_localfs_path(
        &mut s,
        session_id,
        tree_id,
        4,
        "watch",
        0x001f_01ff,
        0x0000_0001,
    )
    .await;

    let file_name_async = arm_cancel_and_rearm(
        &mut s,
        session_id,
        tree_id,
        watch_dir_file_filter,
        5,
        FILE_NOTIFY_CHANGE_FILE_NAME,
    )
    .await;
    let nonmatching_dir =
        create_child_dir(&mut s, 8, session_id, tree_id, "watch\\tname-file-filter").await;
    let no_notify =
        tokio::time::timeout(std::time::Duration::from_millis(100), read_frame(&mut s)).await;
    assert!(
        no_notify.is_err(),
        "directory create satisfied file-name notify filter"
    );
    send_async_cancel(&mut s, 9, session_id, file_name_async).await;
    let cancel_frame = read_frame_with_test_timeout(&mut s, "nonmatching cancelled notify").await;
    let (cancel_hdr, cancel_body) = parse_response_header(&cancel_frame);
    assert_eq!(cancel_hdr.command, Command::ChangeNotify);
    assert_eq!(cancel_hdr.channel_sequence_status, STATUS_CANCELLED);
    assert_eq!(cancel_hdr.async_id(), Some(file_name_async));
    let cancel = ChangeNotifyResponse::parse(cancel_body).expect("parse unmatched cancel");
    assert_eq!(cancel.output_buffer_length, 0);
    close_file(&mut s, 10, session_id, tree_id, nonmatching_dir).await;
    close_file(&mut s, 11, session_id, tree_id, watch_dir_file_filter).await;

    let watch_dir_dir_filter = open_localfs_path(
        &mut s,
        session_id,
        tree_id,
        12,
        "watch",
        0x001f_01ff,
        0x0000_0001,
    )
    .await;
    let dir_name_async = arm_cancel_and_rearm(
        &mut s,
        session_id,
        tree_id,
        watch_dir_dir_filter,
        13,
        FILE_NOTIFY_CHANGE_DIR_NAME,
    )
    .await;
    let matching_dir = create_child_dir(&mut s, 16, session_id, tree_id, "watch\\tname1").await;
    let notify_frame = read_frame_with_test_timeout(&mut s, "matching notify response").await;
    let (notify_hdr, notify_body) = parse_response_header(&notify_frame);
    assert_eq!(notify_hdr.command, Command::ChangeNotify);
    assert_eq!(notify_hdr.channel_sequence_status, STATUS_SUCCESS);
    assert_eq!(notify_hdr.async_id(), Some(dir_name_async));
    let notify = ChangeNotifyResponse::parse(notify_body).expect("parse matching notify");
    let records = decode_file_notify_records(&notify.buffer);
    assert_eq!(records, vec![(FILE_ACTION_ADDED, "tname1".to_string())]);

    close_file(&mut s, 17, session_id, tree_id, matching_dir).await;
    close_file(&mut s, 18, session_id, tree_id, watch_dir_dir_filter).await;
    drop(s);
    handle.abort();
}

#[tokio::test]
async fn change_notify_write_mask_cleanup_allows_parent_deltree() {
    const FILE_NOTIFY_CHANGE_SIZE: u32 = 0x0000_0008;
    const FILE_ACTION_MODIFIED: u32 = 0x0000_0003;
    const DELETE_ACCESS: u32 = 0x0001_0000;
    const FILE_DELETE_ON_CLOSE: u32 = 0x0000_1000;

    let td = tempdir().expect("tempdir");
    std::fs::create_dir(td.path().join("watch")).expect("mkdir watch");
    std::fs::write(td.path().join("watch").join("tname1"), b"seed").expect("seed file");
    let (handle, mut s, session_id, tree_id) = start_localfs_session(td.path()).await;

    let watch_dir = open_localfs_path(
        &mut s,
        session_id,
        tree_id,
        4,
        "watch",
        0x001f_01ff,
        0x0000_0001,
    )
    .await;
    let file_id = open_localfs_path(
        &mut s,
        session_id,
        tree_id,
        5,
        "watch\\tname1",
        0x001f_01ff,
        0,
    )
    .await;

    let notify_req = ChangeNotifyRequest {
        structure_size: 32,
        flags: ChangeNotifyRequest::FLAG_WATCH_TREE,
        output_buffer_length: 1000,
        file_id: watch_dir,
        completion_filter: FILE_NOTIFY_CHANGE_SIZE,
        reserved: 0,
    };
    let initial = send_change_notify(&mut s, 6, session_id, tree_id, notify_req.clone()).await;
    assert_eq!(initial.channel_sequence_status, STATUS_PENDING);
    let initial_async_id = initial.async_id().expect("initial async id");
    send_async_cancel(&mut s, 7, session_id, initial_async_id).await;
    let cancel_frame = read_frame_with_test_timeout(&mut s, "initial write-mask cancel").await;
    let (cancel_hdr, cancel_body) = parse_response_header(&cancel_frame);
    assert_eq!(cancel_hdr.command, Command::ChangeNotify);
    assert_eq!(cancel_hdr.channel_sequence_status, STATUS_CANCELLED);
    assert_eq!(cancel_hdr.async_id(), Some(initial_async_id));
    let cancel = ChangeNotifyResponse::parse(cancel_body).expect("parse initial cancel");
    assert_eq!(cancel.output_buffer_length, 0);

    let pending = send_change_notify(&mut s, 8, session_id, tree_id, notify_req).await;
    assert_eq!(pending.channel_sequence_status, STATUS_PENDING);
    let pending_async_id = pending.async_id().expect("write async id");

    let write_req = write_request(file_id, 10_000, &[1]);
    let mut body = Vec::new();
    write_req.write_to(&mut body).expect("write write request");
    let hdr = build_header(Command::Write, 9, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;

    let mut saw_write = false;
    let mut saw_notify = false;
    for _ in 0..2 {
        let frame = read_frame_with_test_timeout(&mut s, "write notify pair").await;
        let (rh, rb) = parse_response_header(&frame);
        match rh.command {
            Command::Write => {
                assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
                let write = smb_server::wire::messages::WriteResponse::parse(rb)
                    .expect("parse write response");
                assert_eq!(write.count, 1);
                saw_write = true;
            }
            Command::ChangeNotify => {
                assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
                assert_eq!(rh.async_id(), Some(pending_async_id));
                let notify = ChangeNotifyResponse::parse(rb).expect("parse write notify");
                let records = decode_file_notify_records(&notify.buffer);
                assert_eq!(records, vec![(FILE_ACTION_MODIFIED, "tname1".to_string())]);
                saw_notify = true;
            }
            other => panic!("unexpected response {other:?}"),
        }
    }
    assert!(saw_write, "missing write response");
    assert!(saw_notify, "missing notify response");

    close_file(&mut s, 10, session_id, tree_id, file_id).await;

    let unlink_req = create_request(
        "watch\\tname1",
        DELETE_ACCESS,
        FILE_ATTRIBUTE_NORMAL,
        1,
        FILE_DELETE_ON_CLOSE,
    );
    let mut body = Vec::new();
    unlink_req.write_to(&mut body).expect("write unlink create");
    let hdr = build_header(Command::Create, 11, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame_with_test_timeout(&mut s, "unlink create").await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Create);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let unlink_id = CreateResponse::parse(rb)
        .expect("parse unlink create")
        .file_id;
    close_file(&mut s, 12, session_id, tree_id, unlink_id).await;

    close_file(&mut s, 13, session_id, tree_id, watch_dir).await;
    assert!(
        !td.path().join("watch").join("tname1").exists(),
        "write cleanup left child file behind"
    );

    let dir_id = open_localfs_path(
        &mut s,
        session_id,
        tree_id,
        14,
        "watch",
        DELETE_ACCESS,
        0x0000_0001 | FILE_DELETE_ON_CLOSE,
    )
    .await;
    close_file(&mut s, 15, session_id, tree_id, dir_id).await;
    assert!(
        !td.path().join("watch").exists(),
        "write cleanup left parent directory undeletable"
    );

    drop(s);
    handle.abort();
}

#[tokio::test]
async fn change_notify_write_mask_matrix_completes_all_filters() {
    const FILE_NOTIFY_CHANGE_SIZE: u32 = 0x0000_0008;
    const FILE_NOTIFY_CHANGE_LAST_WRITE: u32 = 0x0000_0010;
    const FILE_ACTION_MODIFIED: u32 = 0x0000_0003;
    const DELETE_ACCESS: u32 = 0x0001_0000;
    const FILE_DELETE_ON_CLOSE: u32 = 0x0000_1000;

    let td = tempdir().expect("tempdir");
    std::fs::create_dir(td.path().join("watch")).expect("mkdir watch");
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

    let mut watch_conn = TcpStream::connect(addr).await.expect("connect watch");
    let _ = negotiate(&mut watch_conn).await;
    let watch_session_id = anonymous_session_setup(&mut watch_conn).await;
    let watch_tree_id =
        tree_connect(&mut watch_conn, "\\\\127.0.0.1\\share", watch_session_id, 3).await;

    let mut op_conn = TcpStream::connect(addr).await.expect("connect op");
    let _ = negotiate(&mut op_conn).await;
    let op_session_id = anonymous_session_setup(&mut op_conn).await;
    let op_tree_id = tree_connect(&mut op_conn, "\\\\127.0.0.1\\share", op_session_id, 3).await;

    async fn create_matrix_file(
        s: &mut TcpStream,
        message_id: u64,
        session_id: u64,
        tree_id: u32,
    ) -> FileId {
        let req = create_request("watch\\tname1", 0x001f_01ff, FILE_ATTRIBUTE_NORMAL, 2, 0);
        let mut body = Vec::new();
        req.write_to(&mut body).expect("write matrix create");
        let hdr = build_header(Command::Create, message_id, session_id, tree_id);
        write_frame(s, &hdr, &body).await;
        let resp = read_frame_with_test_timeout(s, "matrix file create").await;
        let (rh, rb) = parse_response_header(&resp);
        assert_eq!(rh.command, Command::Create);
        assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
        CreateResponse::parse(rb)
            .expect("parse matrix create")
            .file_id
    }

    async fn unlink_matrix_file(s: &mut TcpStream, message_id: u64, session_id: u64, tree_id: u32) {
        let req = create_request(
            "watch\\tname1",
            DELETE_ACCESS,
            FILE_ATTRIBUTE_NORMAL,
            1,
            FILE_DELETE_ON_CLOSE,
        );
        let mut body = Vec::new();
        req.write_to(&mut body).expect("write matrix unlink");
        let hdr = build_header(Command::Create, message_id, session_id, tree_id);
        write_frame(s, &hdr, &body).await;
        let resp = read_frame_with_test_timeout(s, "matrix unlink create").await;
        let (rh, rb) = parse_response_header(&resp);
        assert_eq!(rh.command, Command::Create);
        assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
        let file_id = CreateResponse::parse(rb)
            .expect("parse matrix unlink")
            .file_id;
        close_file(s, message_id + 1, session_id, tree_id, file_id).await;
    }

    let mut watch_message_id = 4;
    let mut op_message_id = 4;
    for bit in 0..32 {
        let filter = 1u32 << bit;
        let watch_dir = open_localfs_path(
            &mut watch_conn,
            watch_session_id,
            watch_tree_id,
            watch_message_id,
            "watch",
            0x001f_01ff,
            0x0000_0001,
        )
        .await;
        watch_message_id += 1;
        let file_id =
            create_matrix_file(&mut op_conn, op_message_id, op_session_id, op_tree_id).await;
        op_message_id += 1;

        let notify_req = ChangeNotifyRequest {
            structure_size: 32,
            flags: ChangeNotifyRequest::FLAG_WATCH_TREE,
            output_buffer_length: 1000,
            file_id: watch_dir,
            completion_filter: filter,
            reserved: 0,
        };
        let initial = send_change_notify(
            &mut watch_conn,
            watch_message_id,
            watch_session_id,
            watch_tree_id,
            notify_req.clone(),
        )
        .await;
        watch_message_id += 1;
        assert_eq!(
            initial.channel_sequence_status, STATUS_PENDING,
            "filter 0x{filter:08x} initial notify"
        );
        let initial_async_id = initial.async_id().expect("initial async id");
        send_async_cancel(
            &mut watch_conn,
            watch_message_id,
            watch_session_id,
            initial_async_id,
        )
        .await;
        watch_message_id += 1;
        let cancel_frame =
            read_frame_with_test_timeout(&mut watch_conn, "matrix initial cancel").await;
        let (cancel_hdr, cancel_body) = parse_response_header(&cancel_frame);
        assert_eq!(cancel_hdr.command, Command::ChangeNotify);
        assert_eq!(
            cancel_hdr.channel_sequence_status, STATUS_CANCELLED,
            "filter 0x{filter:08x} initial cancel"
        );
        assert_eq!(cancel_hdr.async_id(), Some(initial_async_id));
        let cancel = ChangeNotifyResponse::parse(cancel_body).expect("parse initial cancel");
        assert_eq!(cancel.output_buffer_length, 0);

        let pending = send_change_notify(
            &mut watch_conn,
            watch_message_id,
            watch_session_id,
            watch_tree_id,
            notify_req,
        )
        .await;
        watch_message_id += 1;
        assert_eq!(
            pending.channel_sequence_status, STATUS_PENDING,
            "filter 0x{filter:08x} rearm notify"
        );
        let pending_async_id = pending.async_id().expect("write async id");

        let write_req = write_request(file_id, 10_000, &[1]);
        let mut body = Vec::new();
        write_req.write_to(&mut body).expect("write matrix write");
        let hdr = build_header(Command::Write, op_message_id, op_session_id, op_tree_id);
        write_frame(&mut op_conn, &hdr, &body).await;
        op_message_id += 1;
        let write_frame = read_frame_with_test_timeout(&mut op_conn, "matrix write response").await;
        let (write_hdr, write_body) = parse_response_header(&write_frame);
        assert_eq!(write_hdr.command, Command::Write);
        assert_eq!(write_hdr.channel_sequence_status, STATUS_SUCCESS);
        let write = smb_server::wire::messages::WriteResponse::parse(write_body)
            .expect("parse matrix write");
        assert_eq!(write.count, 1);

        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        send_async_cancel(
            &mut watch_conn,
            watch_message_id,
            watch_session_id,
            pending_async_id,
        )
        .await;
        watch_message_id += 1;
        let notify_frame =
            read_frame_with_test_timeout(&mut watch_conn, "matrix write notify").await;
        let (notify_hdr, notify_body) = parse_response_header(&notify_frame);
        assert_eq!(notify_hdr.command, Command::ChangeNotify);
        assert_eq!(notify_hdr.async_id(), Some(pending_async_id));
        if filter & (FILE_NOTIFY_CHANGE_SIZE | FILE_NOTIFY_CHANGE_LAST_WRITE) != 0 {
            assert_eq!(
                notify_hdr.channel_sequence_status, STATUS_SUCCESS,
                "filter 0x{filter:08x} write notify should complete"
            );
            let notify = ChangeNotifyResponse::parse(notify_body).expect("parse matrix notify");
            let records = decode_file_notify_records(&notify.buffer);
            assert_eq!(
                records,
                vec![(FILE_ACTION_MODIFIED, "tname1".to_string())],
                "filter 0x{filter:08x} records"
            );
        } else {
            assert_eq!(
                notify_hdr.channel_sequence_status, STATUS_CANCELLED,
                "filter 0x{filter:08x} write notify should cancel"
            );
            let notify = ChangeNotifyResponse::parse(notify_body).expect("parse matrix cancel");
            assert_eq!(notify.output_buffer_length, 0);
        }

        close_file(
            &mut op_conn,
            op_message_id,
            op_session_id,
            op_tree_id,
            file_id,
        )
        .await;
        op_message_id += 1;
        unlink_matrix_file(&mut op_conn, op_message_id, op_session_id, op_tree_id).await;
        op_message_id += 2;
        close_file(
            &mut watch_conn,
            watch_message_id,
            watch_session_id,
            watch_tree_id,
            watch_dir,
        )
        .await;
        watch_message_id += 1;
    }

    let dir_id = open_localfs_path(
        &mut op_conn,
        op_session_id,
        op_tree_id,
        op_message_id,
        "watch",
        DELETE_ACCESS,
        0x0000_0001 | FILE_DELETE_ON_CLOSE,
    )
    .await;
    close_file(
        &mut op_conn,
        op_message_id + 1,
        op_session_id,
        op_tree_id,
        dir_id,
    )
    .await;
    assert!(!td.path().join("watch").exists());

    drop(watch_conn);
    drop(op_conn);
    handle.abort();
}

#[tokio::test]
async fn change_notify_returns_enum_dir_when_record_does_not_fit() {
    let td = tempdir().expect("tempdir");
    std::fs::create_dir(td.path().join("watch")).expect("mkdir watch");
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
    let watch_dir = open_localfs_path(
        &mut s,
        session_id,
        tree_id,
        4,
        "watch",
        0x0000_0001,
        0x0000_0001,
    )
    .await;

    let pending = send_change_notify(
        &mut s,
        5,
        session_id,
        tree_id,
        ChangeNotifyRequest {
            structure_size: 32,
            flags: 0,
            output_buffer_length: 8,
            file_id: watch_dir,
            completion_filter: 0x0000_0001,
            reserved: 0,
        },
    )
    .await;
    assert_eq!(pending.channel_sequence_status, STATUS_PENDING);
    let pending_async_id = pending.async_id().expect("async id");
    let (notify, created) = create_child_and_expect_notify(
        &mut s,
        6,
        session_id,
        tree_id,
        "watch\\changed.txt",
        pending_async_id,
        STATUS_NOTIFY_ENUM_DIR,
    )
    .await;
    assert_eq!(notify.output_buffer_length, 0);

    close_file(&mut s, 7, session_id, tree_id, created).await;
    close_file(&mut s, 8, session_id, tree_id, watch_dir).await;
    drop(s);
    handle.abort();
}

#[tokio::test]
async fn change_notify_first_overflow_sticks_enum_dir_for_handle() {
    let td = tempdir().expect("tempdir");
    std::fs::create_dir(td.path().join("watch")).expect("mkdir watch");
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
    let watch_dir = open_localfs_path(
        &mut s,
        session_id,
        tree_id,
        4,
        "watch",
        0x0000_0001,
        0x0000_0001,
    )
    .await;

    let notify_req = |output_buffer_length| ChangeNotifyRequest {
        structure_size: 32,
        flags: 0,
        output_buffer_length,
        file_id: watch_dir,
        completion_filter: 0x0000_0001,
        reserved: 0,
    };

    let first = send_change_notify(&mut s, 5, session_id, tree_id, notify_req(1)).await;
    assert_eq!(first.channel_sequence_status, STATUS_PENDING);
    let (first_notify, first_created) = create_child_and_expect_notify(
        &mut s,
        6,
        session_id,
        tree_id,
        "watch\\first.txt",
        first.async_id().expect("first async id"),
        STATUS_NOTIFY_ENUM_DIR,
    )
    .await;
    assert_eq!(first_notify.output_buffer_length, 0);

    let second = send_change_notify(&mut s, 7, session_id, tree_id, notify_req(4096)).await;
    assert_eq!(second.channel_sequence_status, STATUS_PENDING);
    let (second_notify, second_created) = create_child_and_expect_notify(
        &mut s,
        8,
        session_id,
        tree_id,
        "watch\\second.txt",
        second.async_id().expect("second async id"),
        STATUS_NOTIFY_ENUM_DIR,
    )
    .await;
    assert_eq!(second_notify.output_buffer_length, 0);

    close_file(&mut s, 9, session_id, tree_id, first_created).await;
    close_file(&mut s, 10, session_id, tree_id, second_created).await;
    close_file(&mut s, 11, session_id, tree_id, watch_dir).await;
    drop(s);
    handle.abort();
}

#[tokio::test]
async fn change_notify_overflow_after_success_does_not_stick_enum_dir() {
    let td = tempdir().expect("tempdir");
    std::fs::create_dir(td.path().join("watch")).expect("mkdir watch");
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
    let watch_dir = open_localfs_path(
        &mut s,
        session_id,
        tree_id,
        4,
        "watch",
        0x0000_0001,
        0x0000_0001,
    )
    .await;

    let notify_req = |output_buffer_length| ChangeNotifyRequest {
        structure_size: 32,
        flags: 0,
        output_buffer_length,
        file_id: watch_dir,
        completion_filter: 0x0000_0001,
        reserved: 0,
    };

    let first = send_change_notify(&mut s, 5, session_id, tree_id, notify_req(4096)).await;
    assert_eq!(first.channel_sequence_status, STATUS_PENDING);
    let (first_notify, first_created) = create_child_and_expect_notify(
        &mut s,
        6,
        session_id,
        tree_id,
        "watch\\first.txt",
        first.async_id().expect("first async id"),
        STATUS_SUCCESS,
    )
    .await;
    let (action, name) = decode_file_notify_information(&first_notify.buffer);
    assert_eq!(action, 0x0000_0001);
    assert_eq!(name, "first.txt");

    let second = send_change_notify(&mut s, 7, session_id, tree_id, notify_req(1)).await;
    assert_eq!(second.channel_sequence_status, STATUS_PENDING);
    let (second_notify, second_created) = create_child_and_expect_notify(
        &mut s,
        8,
        session_id,
        tree_id,
        "watch\\second.txt",
        second.async_id().expect("second async id"),
        STATUS_NOTIFY_ENUM_DIR,
    )
    .await;
    assert_eq!(second_notify.output_buffer_length, 0);

    let third = send_change_notify(&mut s, 9, session_id, tree_id, notify_req(4096)).await;
    assert_eq!(third.channel_sequence_status, STATUS_PENDING);
    let (third_notify, third_created) = create_child_and_expect_notify(
        &mut s,
        10,
        session_id,
        tree_id,
        "watch\\third.txt",
        third.async_id().expect("third async id"),
        STATUS_SUCCESS,
    )
    .await;
    let (action, name) = decode_file_notify_information(&third_notify.buffer);
    assert_eq!(action, 0x0000_0001);
    assert_eq!(name, "third.txt");

    close_file(&mut s, 11, session_id, tree_id, first_created).await;
    close_file(&mut s, 12, session_id, tree_id, second_created).await;
    close_file(&mut s, 13, session_id, tree_id, third_created).await;
    close_file(&mut s, 14, session_id, tree_id, watch_dir).await;
    drop(s);
    handle.abort();
}

#[tokio::test]
async fn change_notify_cancel_completes_original_request() {
    let td = tempdir().expect("tempdir");
    std::fs::create_dir(td.path().join("watch")).expect("mkdir watch");
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

    let watch_dir = open_localfs_path(
        &mut s,
        session_id,
        tree_id,
        4,
        "watch",
        0x0000_0001,
        0x0000_0001,
    )
    .await;
    let notify_req = ChangeNotifyRequest {
        structure_size: 32,
        flags: 0,
        output_buffer_length: 4096,
        file_id: watch_dir,
        completion_filter: 0x0000_0001,
        reserved: 0,
    };
    let pending = send_change_notify(&mut s, 5, session_id, tree_id, notify_req).await;
    assert_eq!(pending.channel_sequence_status, STATUS_PENDING);
    let pending_async_id = pending.async_id().expect("async id");

    send_async_cancel(&mut s, 6, session_id + 1, pending_async_id).await;
    let no_frame =
        tokio::time::timeout(std::time::Duration::from_millis(50), read_frame(&mut s)).await;
    assert!(no_frame.is_err(), "wrong-session CANCEL completed notify");

    send_async_cancel(&mut s, 7, session_id, pending_async_id).await;
    let final_resp = read_frame(&mut s).await;
    let (rh, rb) = parse_response_header(&final_resp);
    assert_eq!(rh.command, Command::ChangeNotify);
    assert_eq!(rh.channel_sequence_status, STATUS_CANCELLED);
    assert!(rh.is_async());
    assert_eq!(rh.async_id(), Some(pending_async_id));
    assert_eq!(rh.credit_request_response, 0);
    let notify = ChangeNotifyResponse::parse(rb).expect("parse notify cancel resp");
    assert_eq!(notify.output_buffer_length, 0);

    close_file(&mut s, 8, session_id, tree_id, watch_dir).await;
    drop(s);
    handle.abort();
}

#[tokio::test]
async fn change_notify_sync_cancel_by_message_id_completes_original_request() {
    let td = tempdir().expect("tempdir");
    std::fs::create_dir(td.path().join("watch")).expect("mkdir watch");
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

    let watch_dir = open_localfs_path(
        &mut s,
        session_id,
        tree_id,
        4,
        "watch",
        0x0000_0001,
        0x0000_0001,
    )
    .await;
    let notify_req = ChangeNotifyRequest {
        structure_size: 32,
        flags: 0,
        output_buffer_length: 4096,
        file_id: watch_dir,
        completion_filter: 0x0000_0001,
        reserved: 0,
    };
    let mut body = Vec::new();
    notify_req.write_to(&mut body).expect("write notify");
    let notify_message_id = 5;
    let hdr = build_header(
        Command::ChangeNotify,
        notify_message_id,
        session_id,
        tree_id,
    );
    write_frame(&mut s, &hdr, &body).await;
    send_sync_cancel(&mut s, notify_message_id, session_id, tree_id).await;

    let pending_resp = read_frame(&mut s).await;
    let (pending_hdr, _) = parse_response_header(&pending_resp);
    assert_eq!(pending_hdr.command, Command::ChangeNotify);
    assert_eq!(pending_hdr.channel_sequence_status, STATUS_PENDING);
    let async_id = pending_hdr.async_id().expect("async id");

    let final_resp = read_frame(&mut s).await;
    let (rh, rb) = parse_response_header(&final_resp);
    assert_eq!(rh.command, Command::ChangeNotify);
    assert_eq!(rh.channel_sequence_status, STATUS_CANCELLED);
    assert!(rh.is_async());
    assert_eq!(rh.async_id(), Some(async_id));
    let notify = ChangeNotifyResponse::parse(rb).expect("parse notify cancel resp");
    assert_eq!(notify.output_buffer_length, 0);

    close_file(&mut s, 6, session_id, tree_id, watch_dir).await;
    drop(s);
    handle.abort();
}

#[tokio::test]
async fn change_notify_close_completes_pending_with_cleanup() {
    let td = tempdir().expect("tempdir");
    std::fs::create_dir(td.path().join("watch")).expect("mkdir watch");
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

    let watch_dir = open_localfs_path(
        &mut s,
        session_id,
        tree_id,
        4,
        "watch",
        0x0000_0001,
        0x0000_0001,
    )
    .await;
    let notify_req = ChangeNotifyRequest {
        structure_size: 32,
        flags: 0,
        output_buffer_length: 4096,
        file_id: watch_dir,
        completion_filter: 0x0000_0001,
        reserved: 0,
    };
    let pending = send_change_notify(&mut s, 5, session_id, tree_id, notify_req).await;
    assert_eq!(pending.channel_sequence_status, STATUS_PENDING);
    let pending_async_id = pending.async_id().expect("async id");

    let close_req = CloseRequest {
        structure_size: 24,
        flags: 0,
        reserved: 0,
        file_id: watch_dir,
    };
    let mut body = Vec::new();
    close_req.write_to(&mut body).expect("write close");
    let hdr = build_header(Command::Close, 6, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;

    let mut saw_close = false;
    let mut saw_cleanup = false;
    for _ in 0..2 {
        let resp = read_frame(&mut s).await;
        let (rh, rb) = parse_response_header(&resp);
        match rh.command {
            Command::Close => {
                assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
                let _ = CloseResponse::parse(rb).expect("parse close resp");
                saw_close = true;
            }
            Command::ChangeNotify => {
                assert_eq!(rh.channel_sequence_status, STATUS_NOTIFY_CLEANUP);
                assert!(rh.is_async());
                assert_eq!(rh.async_id(), Some(pending_async_id));
                assert_eq!(rh.credit_request_response, 0);
                let notify = ChangeNotifyResponse::parse(rb).expect("parse notify cleanup resp");
                assert_eq!(notify.output_buffer_length, 0);
                saw_cleanup = true;
            }
            other => panic!("unexpected response {other:?}"),
        }
    }
    assert!(saw_close, "missing close response");
    assert!(saw_cleanup, "missing change notify cleanup");

    drop(s);
    handle.abort();
}

#[tokio::test]
async fn change_notify_logoff_completes_pending_with_cleanup() {
    let td = tempdir().expect("tempdir");
    std::fs::create_dir(td.path().join("watch")).expect("mkdir watch");
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

    let watch_dir = open_localfs_path(
        &mut s,
        session_id,
        tree_id,
        4,
        "watch",
        0x0000_0001,
        0x0000_0001,
    )
    .await;
    let notify_req = ChangeNotifyRequest {
        structure_size: 32,
        flags: 0,
        output_buffer_length: 4096,
        file_id: watch_dir,
        completion_filter: 0x0000_0001,
        reserved: 0,
    };
    let pending = send_change_notify(&mut s, 5, session_id, tree_id, notify_req).await;
    assert_eq!(pending.channel_sequence_status, STATUS_PENDING);
    let pending_async_id = pending.async_id().expect("async id");

    let logoff_req = LogoffRequest::default();
    let mut body = Vec::new();
    logoff_req.write_to(&mut body).expect("write logoff");
    let hdr = build_header(Command::Logoff, 6, session_id, 0);
    write_frame(&mut s, &hdr, &body).await;

    let mut saw_logoff = false;
    let mut saw_cleanup = false;
    for _ in 0..2 {
        let resp = read_frame(&mut s).await;
        let (rh, rb) = parse_response_header(&resp);
        match rh.command {
            Command::Logoff => {
                assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
                let _ = LogoffResponse::parse(rb).expect("parse logoff resp");
                saw_logoff = true;
            }
            Command::ChangeNotify => {
                assert_eq!(rh.channel_sequence_status, STATUS_NOTIFY_CLEANUP);
                assert!(rh.is_async());
                assert_eq!(rh.async_id(), Some(pending_async_id));
                assert_eq!(rh.credit_request_response, 0);
                let notify = ChangeNotifyResponse::parse(rb).expect("parse notify cleanup resp");
                assert_eq!(notify.output_buffer_length, 0);
                saw_cleanup = true;
            }
            other => panic!("unexpected response {other:?}"),
        }
    }
    assert!(saw_logoff, "missing logoff response");
    assert!(saw_cleanup, "missing change notify cleanup");

    drop(s);
    handle.abort();
}

#[tokio::test]
async fn change_notify_tree_disconnect_completes_pending_with_cleanup() {
    let td = tempdir().expect("tempdir");
    std::fs::create_dir(td.path().join("watch")).expect("mkdir watch");
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

    let watch_dir = open_localfs_path(
        &mut s,
        session_id,
        tree_id,
        4,
        "watch",
        0x0000_0001,
        0x0000_0001,
    )
    .await;
    let notify_req = ChangeNotifyRequest {
        structure_size: 32,
        flags: 0,
        output_buffer_length: 4096,
        file_id: watch_dir,
        completion_filter: 0x0000_0001,
        reserved: 0,
    };
    let pending = send_change_notify(&mut s, 5, session_id, tree_id, notify_req).await;
    assert_eq!(pending.channel_sequence_status, STATUS_PENDING);
    let pending_async_id = pending.async_id().expect("async id");

    let disconnect_req = TreeDisconnectRequest::default();
    let mut body = Vec::new();
    disconnect_req
        .write_to(&mut body)
        .expect("write tree disconnect");
    let hdr = build_header(Command::TreeDisconnect, 6, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;

    let mut saw_disconnect = false;
    let mut saw_cleanup = false;
    for _ in 0..2 {
        let resp = read_frame(&mut s).await;
        let (rh, rb) = parse_response_header(&resp);
        match rh.command {
            Command::TreeDisconnect => {
                assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
                let _ = TreeDisconnectResponse::parse(rb).expect("parse tree disconnect resp");
                saw_disconnect = true;
            }
            Command::ChangeNotify => {
                assert_eq!(rh.channel_sequence_status, STATUS_NOTIFY_CLEANUP);
                assert!(rh.is_async());
                assert_eq!(rh.async_id(), Some(pending_async_id));
                assert_eq!(rh.credit_request_response, 0);
                let notify = ChangeNotifyResponse::parse(rb).expect("parse notify cleanup resp");
                assert_eq!(notify.output_buffer_length, 0);
                saw_cleanup = true;
            }
            other => panic!("unexpected response {other:?}"),
        }
    }
    assert!(saw_disconnect, "missing tree disconnect response");
    assert!(saw_cleanup, "missing change notify cleanup");

    drop(s);
    handle.abort();
}

#[tokio::test]
async fn change_notify_directory_delete_pending_completes_watcher() {
    let td = tempdir().expect("tempdir");
    std::fs::create_dir(td.path().join("gone")).expect("mkdir gone");
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

    let watch_dir = open_localfs_path(
        &mut s,
        session_id,
        tree_id,
        4,
        "gone",
        0x001f_01ff,
        0x0000_0001,
    )
    .await;
    let notify_req = ChangeNotifyRequest {
        structure_size: 32,
        flags: 0,
        output_buffer_length: 4096,
        file_id: watch_dir,
        completion_filter: 0x0000_0001,
        reserved: 0,
    };
    let pending = send_change_notify(&mut s, 5, session_id, tree_id, notify_req).await;
    assert_eq!(pending.channel_sequence_status, STATUS_PENDING);
    let pending_async_id = pending.async_id().expect("async id");

    let delete_dir = open_localfs_path(
        &mut s,
        session_id,
        tree_id,
        6,
        "gone",
        0x001f_01ff,
        0x0000_0001,
    )
    .await;
    let disposition_req = SetInfoRequest {
        structure_size: 33,
        info_type: InfoType::File as u8,
        file_information_class: 0x0D,
        buffer_length: 1,
        buffer_offset: 64 + 32,
        reserved: 0,
        additional_information: 0,
        file_id: delete_dir,
        buffer: vec![1],
    };
    let mut body = Vec::new();
    disposition_req
        .write_to(&mut body)
        .expect("write disposition");
    let hdr = build_header(Command::SetInfo, 7, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, _rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::SetInfo);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);

    let close_req = CloseRequest {
        structure_size: 24,
        flags: 0,
        reserved: 0,
        file_id: delete_dir,
    };
    let mut body = Vec::new();
    close_req.write_to(&mut body).expect("write close");
    let hdr = build_header(Command::Close, 8, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;

    let mut saw_close = false;
    let mut saw_delete_pending = false;
    for _ in 0..2 {
        let resp = read_frame(&mut s).await;
        let (rh, rb) = parse_response_header(&resp);
        match rh.command {
            Command::Close => {
                assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
                let _ = CloseResponse::parse(rb).expect("parse close resp");
                saw_close = true;
            }
            Command::ChangeNotify => {
                assert_eq!(rh.channel_sequence_status, STATUS_DELETE_PENDING);
                assert!(rh.is_async());
                assert_eq!(rh.async_id(), Some(pending_async_id));
                assert_eq!(rh.credit_request_response, 0);
                let notify = ChangeNotifyResponse::parse(rb).expect("parse delete-pending notify");
                assert_eq!(notify.output_buffer_length, 0);
                saw_delete_pending = true;
            }
            other => panic!("unexpected response {other:?}"),
        }
    }
    assert!(saw_close, "missing close response");
    assert!(saw_delete_pending, "missing delete-pending notify");

    close_file(&mut s, 9, session_id, tree_id, watch_dir).await;
    drop(s);
    handle.abort();
}

#[tokio::test]
async fn change_notify_reports_removed_file_on_delete_close() {
    let td = tempdir().expect("tempdir");
    std::fs::write(td.path().join("gone.txt"), b"gone").expect("write gone");
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

    let root_dir =
        open_localfs_path(&mut s, session_id, tree_id, 4, "", 0x0000_0001, 0x0000_0001).await;
    let notify_req = ChangeNotifyRequest {
        structure_size: 32,
        flags: 0,
        output_buffer_length: 4096,
        file_id: root_dir,
        completion_filter: 0x0000_0001,
        reserved: 0,
    };
    let pending = send_change_notify(&mut s, 5, session_id, tree_id, notify_req).await;
    assert_eq!(pending.channel_sequence_status, STATUS_PENDING);
    let pending_async_id = pending.async_id().expect("async id");

    let delete_file = open_localfs_path(
        &mut s,
        session_id,
        tree_id,
        6,
        "gone.txt",
        0x001f_01ff,
        0x0000_0040,
    )
    .await;
    let disposition_req = SetInfoRequest {
        structure_size: 33,
        info_type: InfoType::File as u8,
        file_information_class: 0x0D,
        buffer_length: 1,
        buffer_offset: 64 + 32,
        reserved: 0,
        additional_information: 0,
        file_id: delete_file,
        buffer: vec![1],
    };
    let mut body = Vec::new();
    disposition_req
        .write_to(&mut body)
        .expect("write disposition");
    let hdr = build_header(Command::SetInfo, 7, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, _rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::SetInfo);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);

    let close_req = CloseRequest {
        structure_size: 24,
        flags: 0,
        reserved: 0,
        file_id: delete_file,
    };
    let mut body = Vec::new();
    close_req.write_to(&mut body).expect("write close");
    let hdr = build_header(Command::Close, 8, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;

    let mut saw_close = false;
    let mut saw_notify = false;
    for _ in 0..2 {
        let resp = read_frame(&mut s).await;
        let (rh, rb) = parse_response_header(&resp);
        match rh.command {
            Command::Close => {
                assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
                let _ = CloseResponse::parse(rb).expect("parse close resp");
                saw_close = true;
            }
            Command::ChangeNotify => {
                assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
                assert!(rh.is_async());
                assert_eq!(rh.async_id(), Some(pending_async_id));
                assert_eq!(rh.credit_request_response, 0);
                let notify = ChangeNotifyResponse::parse(rb).expect("parse removed notify");
                let (action, name) = decode_file_notify_information(&notify.buffer);
                assert_eq!(action, 0x0000_0002);
                assert_eq!(name, "gone.txt");
                saw_notify = true;
            }
            other => panic!("unexpected response {other:?}"),
        }
    }
    assert!(saw_close, "missing close response");
    assert!(saw_notify, "missing removed notify");
    assert!(!td.path().join("gone.txt").exists());

    close_file(&mut s, 9, session_id, tree_id, root_dir).await;
    drop(s);
    handle.abort();
}

#[tokio::test]
async fn change_notify_rename_reports_old_and_new_actions() {
    let td = tempdir().expect("tempdir");
    std::fs::write(td.path().join("old.txt"), b"old").expect("write old");
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

    let root_dir =
        open_localfs_path(&mut s, session_id, tree_id, 4, "", 0x0000_0001, 0x0000_0001).await;
    let file_id = open_localfs_path(
        &mut s,
        session_id,
        tree_id,
        5,
        "old.txt",
        0x001f_01ff,
        0x0000_0040,
    )
    .await;

    let notify_req = ChangeNotifyRequest {
        structure_size: 32,
        flags: 0,
        output_buffer_length: 4096,
        file_id: root_dir,
        completion_filter: 0x0000_0001,
        reserved: 0,
    };
    let pending = send_change_notify(&mut s, 6, session_id, tree_id, notify_req).await;
    assert_eq!(pending.channel_sequence_status, STATUS_PENDING);
    let pending_async_id = pending.async_id().expect("async id");

    let rename = file_rename_information("new.txt", false);
    let rename_req = SetInfoRequest {
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
    rename_req.write_to(&mut body).expect("write rename");
    let hdr = build_header(Command::SetInfo, 7, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;

    let mut saw_set_info = false;
    let mut saw_notify = false;
    for _ in 0..2 {
        let resp = read_frame(&mut s).await;
        let (rh, rb) = parse_response_header(&resp);
        match rh.command {
            Command::SetInfo => {
                assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
                saw_set_info = true;
            }
            Command::ChangeNotify => {
                assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
                assert!(rh.is_async());
                assert_eq!(rh.async_id(), Some(pending_async_id));
                let notify = ChangeNotifyResponse::parse(rb).expect("parse notify resp");
                let records = decode_file_notify_records(&notify.buffer);
                assert_eq!(
                    records,
                    vec![
                        (0x0000_0004, "old.txt".to_string()),
                        (0x0000_0005, "new.txt".to_string()),
                    ]
                );
                saw_notify = true;
            }
            other => panic!("unexpected response {other:?}"),
        }
    }
    assert!(saw_set_info, "missing set-info response");
    assert!(saw_notify, "missing rename notify");
    assert!(!td.path().join("old.txt").exists());
    assert_eq!(std::fs::read(td.path().join("new.txt")).unwrap(), b"old");

    close_file(&mut s, 8, session_id, tree_id, file_id).await;
    close_file(&mut s, 9, session_id, tree_id, root_dir).await;
    drop(s);
    handle.abort();
}

#[tokio::test]
async fn change_notify_size_filter_completes_on_write_modify() {
    let td = tempdir().expect("tempdir");
    std::fs::write(td.path().join("changed.txt"), b"old").expect("write changed");
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

    let root_dir =
        open_localfs_path(&mut s, session_id, tree_id, 4, "", 0x0000_0001, 0x0000_0001).await;
    let file_id = open_localfs_path(
        &mut s,
        session_id,
        tree_id,
        5,
        "changed.txt",
        0x001f_01ff,
        0x0000_0040,
    )
    .await;

    let notify_req = ChangeNotifyRequest {
        structure_size: 32,
        flags: 0,
        output_buffer_length: 4096,
        file_id: root_dir,
        completion_filter: 0x0000_0008,
        reserved: 0,
    };
    let pending = send_change_notify(&mut s, 6, session_id, tree_id, notify_req).await;
    assert_eq!(pending.channel_sequence_status, STATUS_PENDING);
    let pending_async_id = pending.async_id().expect("async id");

    let create_req = create_request(
        "ignored.txt",
        0x001f_01ff,
        FILE_ATTRIBUTE_NORMAL,
        2,
        0x0000_0040,
    );
    let mut body = Vec::new();
    create_req.write_to(&mut body).expect("write create");
    let hdr = build_header(Command::Create, 7, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Create);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let ignored_id = CreateResponse::parse(rb)
        .expect("parse ignored create resp")
        .file_id;
    close_file(&mut s, 8, session_id, tree_id, ignored_id).await;

    let write_req = write_request(file_id, 0, b"new contents");
    let mut body = Vec::new();
    write_req.write_to(&mut body).expect("write write");
    let hdr = build_header(Command::Write, 9, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;

    let mut saw_write = false;
    let mut saw_notify = false;
    for _ in 0..2 {
        let resp = read_frame(&mut s).await;
        let (rh, rb) = parse_response_header(&resp);
        match rh.command {
            Command::Write => {
                assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
                let write =
                    smb_server::wire::messages::WriteResponse::parse(rb).expect("parse write");
                assert_eq!(write.count, b"new contents".len() as u32);
                saw_write = true;
            }
            Command::ChangeNotify => {
                assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
                assert!(rh.is_async());
                assert_eq!(rh.async_id(), Some(pending_async_id));
                let notify = ChangeNotifyResponse::parse(rb).expect("parse notify resp");
                let (action, name) = decode_file_notify_information(&notify.buffer);
                assert_eq!(action, 0x0000_0003);
                assert_eq!(name, "changed.txt");
                saw_notify = true;
            }
            other => panic!("unexpected response {other:?}"),
        }
    }
    assert!(saw_write, "missing write response");
    assert!(saw_notify, "missing modified notify");
    assert_eq!(
        std::fs::read(td.path().join("changed.txt")).unwrap(),
        b"new contents"
    );

    close_file(&mut s, 10, session_id, tree_id, file_id).await;
    close_file(&mut s, 11, session_id, tree_id, root_dir).await;
    drop(s);
    handle.abort();
}

#[tokio::test]
async fn change_notify_name_filter_distinguishes_files_and_directories() {
    let td = tempdir().expect("tempdir");
    std::fs::create_dir(td.path().join("watch")).expect("mkdir watch");
    let (handle, mut s, session_id, tree_id) = start_localfs_session(td.path()).await;

    let watch_dir = open_localfs_path(
        &mut s,
        session_id,
        tree_id,
        4,
        "watch",
        0x0000_0001,
        0x0000_0001,
    )
    .await;
    let notify_req = ChangeNotifyRequest {
        structure_size: 32,
        flags: 0,
        output_buffer_length: 4096,
        file_id: watch_dir,
        completion_filter: 0x0000_0001,
        reserved: 0,
    };
    let pending = send_change_notify(&mut s, 5, session_id, tree_id, notify_req).await;
    assert_eq!(pending.channel_sequence_status, STATUS_PENDING);
    let pending_async_id = pending.async_id().expect("async id");

    let (_, dir_create) = send_create_request(
        &mut s,
        6,
        session_id,
        tree_id,
        create_request("watch\\dir", 0x001f_01ff, 0, 2, 0x0000_0001),
    )
    .await;
    let dir_id = dir_create.expect("dir create response").file_id;
    let no_notify =
        tokio::time::timeout(std::time::Duration::from_millis(50), read_frame(&mut s)).await;
    assert!(
        no_notify.is_err(),
        "directory create matched file-name filter"
    );

    let (notify, file_id) = create_child_and_expect_notify(
        &mut s,
        7,
        session_id,
        tree_id,
        "watch\\file.txt",
        pending_async_id,
        STATUS_SUCCESS,
    )
    .await;
    let (action, name) = decode_file_notify_information(&notify.buffer);
    assert_eq!(action, 0x0000_0001);
    assert_eq!(name, "file.txt");

    close_file(&mut s, 8, session_id, tree_id, file_id).await;
    close_file(&mut s, 9, session_id, tree_id, dir_id).await;
    close_file(&mut s, 10, session_id, tree_id, watch_dir).await;
    drop(s);
    handle.abort();
}

#[tokio::test]
async fn change_notify_attribute_filter_distinguishes_metadata_from_write() {
    let td = tempdir().expect("tempdir");
    std::fs::write(td.path().join("file.txt"), b"old").expect("write file");
    let (handle, mut s, session_id, tree_id) = start_localfs_session(td.path()).await;

    let root_dir =
        open_localfs_path(&mut s, session_id, tree_id, 4, "", 0x0000_0001, 0x0000_0001).await;
    let file_id = open_localfs_path(
        &mut s,
        session_id,
        tree_id,
        5,
        "file.txt",
        0x001f_01ff,
        0x0000_0040,
    )
    .await;

    let notify_req = ChangeNotifyRequest {
        structure_size: 32,
        flags: 0,
        output_buffer_length: 4096,
        file_id: root_dir,
        completion_filter: 0x0000_0004,
        reserved: 0,
    };
    let pending = send_change_notify(&mut s, 6, session_id, tree_id, notify_req).await;
    assert_eq!(pending.channel_sequence_status, STATUS_PENDING);
    let pending_async_id = pending.async_id().expect("async id");

    let write_req = write_request(file_id, 0, b"new contents");
    let mut body = Vec::new();
    write_req.write_to(&mut body).expect("write write");
    let hdr = build_header(Command::Write, 7, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Write);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let write = smb_server::wire::messages::WriteResponse::parse(rb).expect("parse write");
    assert_eq!(write.count, b"new contents".len() as u32);
    let no_notify =
        tokio::time::timeout(std::time::Duration::from_millis(50), read_frame(&mut s)).await;
    assert!(no_notify.is_err(), "write matched attributes filter");

    let mut buffer = vec![0; 40];
    buffer[32..36].copy_from_slice(&(FILE_ATTRIBUTE_ARCHIVE | FILE_ATTRIBUTE_HIDDEN).to_le_bytes());
    let req = SetInfoRequest {
        structure_size: 33,
        info_type: InfoType::File as u8,
        file_information_class: 0x04,
        buffer_length: buffer.len() as u32,
        buffer_offset: 64 + 32,
        reserved: 0,
        additional_information: 0,
        file_id,
        buffer,
    };
    let mut body = Vec::new();
    req.write_to(&mut body).expect("write set basic");
    let hdr = build_header(Command::SetInfo, 8, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;

    let mut saw_set_info = false;
    let mut saw_notify = false;
    for _ in 0..2 {
        let resp = read_frame(&mut s).await;
        let (rh, rb) = parse_response_header(&resp);
        match rh.command {
            Command::SetInfo => {
                assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
                saw_set_info = true;
            }
            Command::ChangeNotify => {
                assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
                assert_eq!(rh.async_id(), Some(pending_async_id));
                let notify = ChangeNotifyResponse::parse(rb).expect("parse notify resp");
                let (action, name) = decode_file_notify_information(&notify.buffer);
                assert_eq!(action, 0x0000_0003);
                assert_eq!(name, "file.txt");
                saw_notify = true;
            }
            other => panic!("unexpected response {other:?}"),
        }
    }
    assert!(saw_set_info, "missing set-info response");
    assert!(saw_notify, "missing attributes notify");

    close_file(&mut s, 9, session_id, tree_id, file_id).await;
    close_file(&mut s, 10, session_id, tree_id, root_dir).await;
    drop(s);
    handle.abort();
}

#[tokio::test]
async fn change_notify_returns_insufficient_resources_at_async_limit() {
    const MAX_PENDING_CHANGE_NOTIFIES: usize = 511;

    let td = tempdir().expect("tempdir");
    std::fs::create_dir(td.path().join("watch")).expect("mkdir watch");
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

    let watch_dir = open_localfs_path(
        &mut s,
        session_id,
        tree_id,
        4,
        "watch",
        0x0000_0001,
        0x0000_0001,
    )
    .await;

    let notify_req = || ChangeNotifyRequest {
        structure_size: 32,
        flags: 0,
        output_buffer_length: 4096,
        file_id: watch_dir,
        completion_filter: 0x0000_0001,
        reserved: 0,
    };

    let mut async_ids = Vec::with_capacity(MAX_PENDING_CHANGE_NOTIFIES);
    for index in 0..MAX_PENDING_CHANGE_NOTIFIES {
        let pending =
            send_change_notify(&mut s, 5 + index as u64, session_id, tree_id, notify_req()).await;
        assert_eq!(pending.channel_sequence_status, STATUS_PENDING);
        async_ids.push(pending.async_id().expect("async id"));
    }

    assert_eq!(
        change_notify_status(
            &mut s,
            5 + MAX_PENDING_CHANGE_NOTIFIES as u64,
            session_id,
            tree_id,
            notify_req()
        )
        .await,
        STATUS_INSUFFICIENT_RESOURCES
    );

    for (index, async_id) in async_ids.iter().copied().enumerate() {
        send_async_cancel(
            &mut s,
            6 + MAX_PENDING_CHANGE_NOTIFIES as u64 + index as u64,
            session_id,
            async_id,
        )
        .await;
        let resp = read_frame(&mut s).await;
        let (rh, rb) = parse_response_header(&resp);
        assert_eq!(rh.command, Command::ChangeNotify);
        assert_eq!(rh.channel_sequence_status, STATUS_CANCELLED);
        assert_eq!(rh.async_id(), Some(async_id));
        let notify = ChangeNotifyResponse::parse(rb).expect("parse notify cancel resp");
        assert_eq!(notify.output_buffer_length, 0);
    }

    close_file(
        &mut s,
        6 + 2 * MAX_PENDING_CHANGE_NOTIFIES as u64,
        session_id,
        tree_id,
        watch_dir,
    )
    .await;
    drop(s);
    handle.abort();
}

#[tokio::test]
async fn create_rejects_invalid_file_attributes() {
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
    let handle = tokio::spawn(async move { server.serve().await });
    tokio::task::yield_now().await;

    let mut s = TcpStream::connect(addr).await.expect("connect");
    let _ = negotiate(&mut s).await;
    let session_id = anonymous_session_setup(&mut s).await;
    let tree_id = tree_connect(&mut s, "\\\\127.0.0.1\\share", session_id, 3).await;

    for (message_id, name, attributes, expected) in [
        (4, "bad-device.txt", 0x0000_0040, STATUS_INVALID_PARAMETER),
        (
            5,
            "encrypted.txt",
            FILE_ATTRIBUTE_ENCRYPTED,
            STATUS_ACCESS_DENIED,
        ),
        (6, "bad-high.txt", 0x0000_8000, STATUS_INVALID_PARAMETER),
    ] {
        let (rh, create) = send_create_request(
            &mut s,
            message_id,
            session_id,
            tree_id,
            create_request(name, 0x001f_01ff, attributes, 5, 0x0000_0040),
        )
        .await;
        assert_eq!(rh.command, Command::Create);
        assert_eq!(rh.channel_sequence_status, expected, "{name}");
        assert!(create.is_none(), "{name} unexpectedly opened");
    }

    drop(s);
    handle.abort();
}

#[tokio::test]
async fn create_missing_parent_returns_object_path_not_found() {
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
    let handle = tokio::spawn(async move { server.serve().await });
    tokio::task::yield_now().await;

    let mut s = TcpStream::connect(addr).await.expect("connect");
    let _ = negotiate(&mut s).await;
    let session_id = anonymous_session_setup(&mut s).await;
    let tree_id = tree_connect(&mut s, "\\\\127.0.0.1\\share", session_id, 3).await;

    let (rh, create) = send_create_request(
        &mut s,
        4,
        session_id,
        tree_id,
        create_request("missing/child.txt", 0x0000_0002, 0, 2, 0x0000_0040),
    )
    .await;
    assert_eq!(rh.command, Command::Create);
    assert_eq!(rh.channel_sequence_status, STATUS_OBJECT_PATH_NOT_FOUND);
    assert!(
        create.is_none(),
        "missing-parent create unexpectedly opened"
    );

    drop(s);
    handle.abort();
}

#[tokio::test]
async fn create_security_descriptor_context_persists_and_defaults_missing_dacl() {
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
    let handle = tokio::spawn(async move { server.serve().await });
    tokio::task::yield_now().await;

    let mut s = TcpStream::connect(addr).await.expect("connect");
    let _ = negotiate(&mut s).await;
    let session_id = anonymous_session_setup(&mut s).await;
    let tree_id = tree_connect(&mut s, "\\\\127.0.0.1\\share", session_id, 3).await;

    let mut sd = minimal_self_relative_security_descriptor();
    sd.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd]);
    let create_sd_req = create_request("acl.txt", 0x001f_01ff, 0, 2, 0x0000_0040);
    let body = create_request_with_context(
        "acl.txt",
        create_sd_req,
        CreateContext {
            name: CreateContext::NAME_SECD.to_vec(),
            data: sd.clone(),
        },
    );
    let hdr = build_header(Command::Create, 4, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Create);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let acl_id = CreateResponse::parse(rb)
        .expect("parse acl create resp")
        .file_id;
    assert_eq!(
        query_security_descriptor(&mut s, 5, session_id, tree_id, acl_id).await,
        sd
    );

    let mut no_dacl = vec![0; 20];
    no_dacl[0] = 1;
    no_dacl[2..4].copy_from_slice(&0x8000u16.to_le_bytes());
    let create_default_req = create_request("default-acl.txt", 0x001f_01ff, 0, 2, 0x0000_0040);
    let body = create_request_with_context(
        "default-acl.txt",
        create_default_req,
        CreateContext {
            name: CreateContext::NAME_SECD.to_vec(),
            data: no_dacl,
        },
    );
    let hdr = build_header(Command::Create, 6, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Create);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let default_acl_id = CreateResponse::parse(rb)
        .expect("parse default acl create resp")
        .file_id;
    assert_eq!(
        query_security_descriptor(&mut s, 7, session_id, tree_id, default_acl_id).await,
        minimal_self_relative_security_descriptor()
    );

    drop(s);
    handle.abort();
}

#[tokio::test]
async fn query_info_security_buffer_too_small() {
    let td = tempdir().expect("tempdir");
    std::fs::write(td.path().join("hello.txt"), b"hello").expect("write hello");
    let (handle, mut s, session_id, tree_id) = start_localfs_session(td.path()).await;

    let (rh, opened) = send_create_request(
        &mut s,
        4,
        session_id,
        tree_id,
        create_request("hello.txt", 0x0002_0080, 0, 1, 0x0000_0040),
    )
    .await;
    assert_eq!(rh.command, Command::Create);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let file_id = opened.expect("file open").file_id;

    for (message_id, output_buffer_length) in [(5, 0), (6, 1)] {
        assert_eq!(
            query_security_descriptor_status(
                &mut s,
                message_id,
                session_id,
                tree_id,
                file_id,
                output_buffer_length,
            )
            .await,
            STATUS_BUFFER_TOO_SMALL,
            "output buffer length {output_buffer_length}"
        );
    }
    assert_eq!(
        send_close_request(&mut s, 7, session_id, tree_id, file_id).await,
        STATUS_SUCCESS
    );

    handle.abort();
}

#[tokio::test]
async fn query_info_security_requires_read_control() {
    let td = tempdir().expect("tempdir");
    std::fs::write(td.path().join("acl.txt"), b"hello").expect("write acl.txt");

    let (handle, mut s, session_id, tree_id) = start_localfs_session(td.path()).await;
    let (rh, attr_only) = send_create_request(
        &mut s,
        4,
        session_id,
        tree_id,
        create_request("acl.txt", 0x0000_0080, 0, 1, 0x0000_0040),
    )
    .await;
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let attr_only_id = attr_only.expect("attr-only open").file_id;
    let (status, output) =
        query_security_descriptor_with_flags(&mut s, 5, session_id, tree_id, attr_only_id, 0).await;
    assert_eq!(status, STATUS_ACCESS_DENIED);
    assert!(output.is_empty());

    let (rh, read_control) = send_create_request(
        &mut s,
        6,
        session_id,
        tree_id,
        create_request("acl.txt", 0x0002_0000, 0, 1, 0x0000_0040),
    )
    .await;
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let read_control_id = read_control.expect("read-control open").file_id;
    let (status, output) =
        query_security_descriptor_with_flags(&mut s, 7, session_id, tree_id, read_control_id, 0)
            .await;
    assert_eq!(status, STATUS_SUCCESS);
    assert!(!output.is_empty());

    assert_eq!(
        send_close_request(&mut s, 8, session_id, tree_id, attr_only_id).await,
        STATUS_SUCCESS
    );
    assert_eq!(
        send_close_request(&mut s, 9, session_id, tree_id, read_control_id).await,
        STATUS_SUCCESS
    );

    handle.abort();
}

#[tokio::test]
async fn query_info_security_descriptor_honors_security_information() {
    let td = tempdir().expect("tempdir");
    std::fs::write(td.path().join("acl.txt"), b"hello").expect("write acl.txt");

    let (handle, mut s, session_id, tree_id) = start_localfs_session(td.path()).await;
    let (rh, opened) = send_create_request(
        &mut s,
        4,
        session_id,
        tree_id,
        create_request("acl.txt", 0x0002_0000, 0, 1, 0x0000_0040),
    )
    .await;
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let file_id = opened.expect("read-control open").file_id;

    let full = minimal_self_relative_security_descriptor();
    let (status, owner_group_dacl) =
        query_security_descriptor_with_flags(&mut s, 5, session_id, tree_id, file_id, 0x7).await;
    assert_eq!(status, STATUS_SUCCESS);
    assert_eq!(owner_group_dacl, full);

    let (status, owner_only) =
        query_security_descriptor_with_flags(&mut s, 6, session_id, tree_id, file_id, 0x1).await;
    assert_eq!(status, STATUS_SUCCESS);
    assert!(owner_only.len() >= 20);
    assert_ne!(u32::from_le_bytes(owner_only[4..8].try_into().unwrap()), 0);
    assert_eq!(u32::from_le_bytes(owner_only[8..12].try_into().unwrap()), 0);
    assert_eq!(
        u32::from_le_bytes(owner_only[16..20].try_into().unwrap()),
        0
    );
    assert_eq!(
        u16::from_le_bytes(owner_only[2..4].try_into().unwrap()),
        0x8000
    );

    assert_eq!(
        send_close_request(&mut s, 7, session_id, tree_id, file_id).await,
        STATUS_SUCCESS
    );

    handle.abort();
}

#[tokio::test]
async fn create_validates_options_access_name_and_impersonation() {
    let td = tempdir().expect("tempdir");
    std::fs::write(td.path().join("sync-only.txt"), b"hello").expect("write sync-only.txt");
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

    for (message_id, name, desired_access, create_options, expected) in [
        (
            4,
            "bad-options.txt",
            0x001f_01ff,
            0xf000_0000,
            STATUS_INVALID_PARAMETER,
        ),
        (
            5,
            "unsupported-options.txt",
            0x001f_01ff,
            0x0000_0080,
            STATUS_NOT_SUPPORTED,
        ),
        (
            6,
            "bad-access.txt",
            0x0800_0000,
            0x0000_0040,
            STATUS_ACCESS_DENIED,
        ),
        (7, "zero-access.txt", 0, 0x0000_0040, STATUS_ACCESS_DENIED),
        (
            8,
            "\\leading-slash",
            0x001f_01ff,
            0x0000_0001,
            STATUS_INVALID_PARAMETER,
        ),
    ] {
        let (rh, create) = send_create_request(
            &mut s,
            message_id,
            session_id,
            tree_id,
            create_request(name, desired_access, 0, 5, create_options),
        )
        .await;
        assert_eq!(rh.command, Command::Create);
        assert_eq!(rh.channel_sequence_status, expected, "{name}");
        assert!(create.is_none(), "{name} unexpectedly opened");
    }

    let mut bad_impersonation =
        create_request("bad-impersonation.txt", 0x001f_01ff, 0, 2, 0x0000_0040);
    bad_impersonation.impersonation_level = 0x1234_5678;
    let (rh, create) = send_create_request(&mut s, 9, session_id, tree_id, bad_impersonation).await;
    assert_eq!(rh.command, Command::Create);
    assert_eq!(rh.channel_sequence_status, STATUS_BAD_IMPERSONATION_LEVEL);
    assert!(create.is_none(), "bad impersonation unexpectedly opened");

    let (rh, sync_only) = send_create_request(
        &mut s,
        10,
        session_id,
        tree_id,
        create_request("sync-only.txt", 0x0010_0000, 0, 1, 0x0000_0040),
    )
    .await;
    assert_eq!(rh.command, Command::Create);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let sync_only = sync_only.expect("sync-only open response");
    assert_eq!(
        read_localfs_custom_status(
            &mut s,
            session_id,
            tree_id,
            11,
            read_request(sync_only.file_id, 1, 0),
        )
        .await,
        STATUS_ACCESS_DENIED
    );

    drop(s);
    handle.abort();
}

#[tokio::test]
async fn create_timewarp_context_returns_object_name_not_found() {
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
    let handle = tokio::spawn(async move { server.serve().await });
    tokio::task::yield_now().await;

    let mut s = TcpStream::connect(addr).await.expect("connect");
    let _ = negotiate(&mut s).await;
    let session_id = anonymous_session_setup(&mut s).await;
    let tree_id = tree_connect(&mut s, "\\\\127.0.0.1\\share", session_id, 3).await;

    let body = create_request_with_context(
        "hello.txt",
        create_request("hello.txt", 0x001f_01ff, 0, 5, 0x0000_0040),
        CreateContext {
            name: CreateContext::NAME_TWRP.to_vec(),
            data: 10000u64.to_le_bytes().to_vec(),
        },
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
async fn create_rejects_malformed_known_contexts_and_invalid_oplock() {
    let td = tempdir().expect("tempdir");
    std::fs::write(td.path().join("hello.txt"), b"hello").expect("write hello.txt");
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

    let mut bad_oplock = create_request("hello.txt", 0x001f_01ff, 0, 1, 0x0000_0040);
    bad_oplock.requested_oplock_level = 0x7f;
    let (rh, create) = send_create_request(&mut s, 5, session_id, tree_id, bad_oplock).await;
    assert_eq!(rh.command, Command::Create);
    assert_eq!(rh.channel_sequence_status, STATUS_INVALID_PARAMETER);
    assert!(create.is_none());

    let mut lease_bad_state = vec![0; 32];
    lease_bad_state[16..20].copy_from_slice(&0x8000_0000u32.to_le_bytes());
    let mut lease_v1_bad_flags = vec![0; 32];
    lease_v1_bad_flags[16..20].copy_from_slice(&1u32.to_le_bytes());
    lease_v1_bad_flags[20..24].copy_from_slice(&4u32.to_le_bytes());
    let mut lease_v2_bad_flags = vec![0; 52];
    lease_v2_bad_flags[16..20].copy_from_slice(&1u32.to_le_bytes());
    lease_v2_bad_flags[20..24].copy_from_slice(&0x8000_0000u32.to_le_bytes());
    let mut durable_v2_bad_flags = vec![0; 32];
    durable_v2_bad_flags[4..8].copy_from_slice(&4u32.to_le_bytes());
    let mut app_instance_bad_size = vec![0; 20];
    app_instance_bad_size[0..2].copy_from_slice(&18u16.to_le_bytes());

    let malformed = [
        (
            6,
            0xff,
            vec![CreateContext {
                name: CreateContext::NAME_RQLS.to_vec(),
                data: vec![0; 36],
            }],
        ),
        (
            7,
            0xff,
            vec![CreateContext {
                name: CreateContext::NAME_RQLS.to_vec(),
                data: lease_bad_state,
            }],
        ),
        (
            8,
            0xff,
            vec![CreateContext {
                name: CreateContext::NAME_RQLS.to_vec(),
                data: lease_v1_bad_flags,
            }],
        ),
        (
            9,
            0xff,
            vec![CreateContext {
                name: CreateContext::NAME_RQLS.to_vec(),
                data: lease_v2_bad_flags,
            }],
        ),
        (
            10,
            0,
            vec![CreateContext {
                name: CreateContext::NAME_DH2Q.to_vec(),
                data: durable_v2_bad_flags,
            }],
        ),
        (
            11,
            0,
            vec![CreateContext {
                name: CreateContext::NAME_APP_INSTANCE_ID.to_vec(),
                data: app_instance_bad_size,
            }],
        ),
        (
            12,
            0,
            vec![CreateContext {
                name: CreateContext::NAME_APP_INSTANCE_VERSION.to_vec(),
                data: vec![0; 20],
            }],
        ),
        (
            13,
            0,
            vec![
                CreateContext {
                    name: CreateContext::NAME_DHNQ.to_vec(),
                    data: vec![0; 16],
                },
                CreateContext {
                    name: CreateContext::NAME_DH2Q.to_vec(),
                    data: vec![0; 32],
                },
            ],
        ),
    ];

    for (message_id, oplock, contexts) in malformed {
        let mut req = create_request("hello.txt", 0x001f_01ff, 0, 1, 0x0000_0040);
        req.requested_oplock_level = oplock;
        let body = create_request_with_contexts("hello.txt", req, &contexts);
        let hdr = build_header(Command::Create, message_id, session_id, tree_id);
        write_frame(&mut s, &hdr, &body).await;
        let resp = read_frame(&mut s).await;
        let (rh, _rb) = parse_response_header(&resp);
        assert_eq!(rh.command, Command::Create);
        assert_eq!(rh.channel_sequence_status, STATUS_INVALID_PARAMETER);
    }

    drop(s);
    handle.abort();
}

#[tokio::test]
async fn allocation_size_context_and_set_info_persist_for_queries() {
    let td = tempdir().expect("tempdir");
    std::fs::write(td.path().join("default.txt"), b"hello").expect("write default.txt");
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

    let default_name = utf16le("default.txt");
    let default_create = CreateRequest {
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
        create_options: 0x0000_0040,
        name_offset: 0x78,
        name_length: default_name.len() as u16,
        create_contexts_offset: 0,
        create_contexts_length: 0,
        name: default_name,
        create_contexts: vec![],
    };
    let mut body = Vec::new();
    default_create.write_to(&mut body).expect("write");
    let hdr = build_header(Command::Create, 100, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Create);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let default_id = CreateResponse::parse(rb)
        .expect("parse default create resp")
        .file_id;

    let default_query_all_req = QueryInfoRequest {
        structure_size: 41,
        info_type: InfoType::File as u8,
        file_information_class: 0x12,
        output_buffer_length: 4096,
        input_buffer_offset: 0,
        reserved: 0,
        input_buffer_length: 0,
        additional_information: 0,
        flags: 0,
        file_id: default_id,
        input_buffer: vec![],
    };
    let mut body = Vec::new();
    default_query_all_req.write_to(&mut body).expect("write");
    let hdr = build_header(Command::QueryInfo, 101, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::QueryInfo);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let default_info = QueryInfoResponse::parse(rb).expect("parse default all-info resp");
    assert_eq!(
        u64::from_le_bytes(default_info.buffer[40..48].try_into().unwrap()),
        4096
    );
    assert_eq!(
        u64::from_le_bytes(default_info.buffer[48..56].try_into().unwrap()),
        5
    );

    let default_close = CloseRequest {
        structure_size: 24,
        flags: 0,
        reserved: 0,
        file_id: default_id,
    };
    let mut body = Vec::new();
    default_close.write_to(&mut body).expect("write");
    let hdr = build_header(Command::Close, 102, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Close);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let _ = CloseResponse::parse(rb).expect("parse default close resp");

    let base_create = CreateRequest {
        structure_size: 57,
        security_flags: 0,
        requested_oplock_level: 0,
        impersonation_level: 2,
        smb_create_flags: 0,
        reserved: 0,
        desired_access: 0x001f_01ff,
        file_attributes: 0,
        share_access: 0x0000_0007,
        create_disposition: 5,
        create_options: 0x0000_0040,
        name_offset: 0,
        name_length: 0,
        create_contexts_offset: 0,
        create_contexts_length: 0,
        name: Vec::new(),
        create_contexts: Vec::new(),
    };
    let create_body = create_request_with_context(
        "allocated.txt",
        base_create,
        CreateContext {
            name: CreateContext::NAME_ALSI.to_vec(),
            data: 0x0010_0000u64.to_le_bytes().to_vec(),
        },
    );
    let hdr = build_header(Command::Create, 4, session_id, tree_id);
    write_frame(&mut s, &hdr, &create_body).await;
    let resp = read_frame(&mut s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Create);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let create_resp = CreateResponse::parse(rb).expect("parse create resp");
    assert_eq!(create_resp.allocation_size, 0x0010_0000);
    let file_id = create_resp.file_id;

    let query_all_req = QueryInfoRequest {
        structure_size: 41,
        info_type: InfoType::File as u8,
        file_information_class: 0x12,
        output_buffer_length: 4096,
        input_buffer_offset: 0,
        reserved: 0,
        input_buffer_length: 0,
        additional_information: 0,
        flags: 0,
        file_id,
        input_buffer: vec![],
    };
    let mut body = Vec::new();
    query_all_req.write_to(&mut body).expect("write");
    let hdr = build_header(Command::QueryInfo, 5, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::QueryInfo);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let query_all_resp = QueryInfoResponse::parse(rb).expect("parse all-info resp");
    assert_eq!(
        u64::from_le_bytes(query_all_resp.buffer[40..48].try_into().unwrap()),
        0x0010_0000
    );

    let set_allocation = |file_id: FileId, allocation: u64| SetInfoRequest {
        structure_size: 33,
        info_type: InfoType::File as u8,
        file_information_class: 0x13,
        buffer_length: 8,
        buffer_offset: 64 + 32,
        reserved: 0,
        additional_information: 0,
        file_id,
        buffer: allocation.to_le_bytes().to_vec(),
    };

    let mut body = Vec::new();
    set_allocation(file_id, 0)
        .write_to(&mut body)
        .expect("write");
    let hdr = build_header(Command::SetInfo, 6, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, _rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::SetInfo);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);

    let mut body = Vec::new();
    query_all_req.write_to(&mut body).expect("write");
    let hdr = build_header(Command::QueryInfo, 7, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::QueryInfo);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let query_all_resp = QueryInfoResponse::parse(rb).expect("parse shrink all-info resp");
    assert_eq!(
        u64::from_le_bytes(query_all_resp.buffer[40..48].try_into().unwrap()),
        0
    );
    assert_eq!(
        u64::from_le_bytes(query_all_resp.buffer[48..56].try_into().unwrap()),
        0
    );

    let mut body = Vec::new();
    set_allocation(file_id, 4096)
        .write_to(&mut body)
        .expect("write");
    let hdr = build_header(Command::SetInfo, 8, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, _rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::SetInfo);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);

    let mut body = Vec::new();
    query_all_req.write_to(&mut body).expect("write");
    let hdr = build_header(Command::QueryInfo, 9, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::QueryInfo);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let query_all_resp = QueryInfoResponse::parse(rb).expect("parse grow all-info resp");
    assert_eq!(
        u64::from_le_bytes(query_all_resp.buffer[40..48].try_into().unwrap()),
        4096
    );
    assert_eq!(
        u64::from_le_bytes(query_all_resp.buffer[48..56].try_into().unwrap()),
        0
    );

    let root_create = CreateRequest {
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
        name_length: 0,
        create_contexts_offset: 0,
        create_contexts_length: 0,
        name: vec![],
        create_contexts: vec![],
    };
    let mut body = Vec::new();
    root_create.write_to(&mut body).expect("write");
    let hdr = build_header(Command::Create, 10, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Create);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let root_id = CreateResponse::parse(rb)
        .expect("parse root create resp")
        .file_id;

    let pattern = utf16le("allocated.txt");
    let qd_req = QueryDirectoryRequest {
        structure_size: 33,
        file_information_class: FileInfoClass::FileIdFullDirectoryInformation as u8,
        flags: QueryDirectoryRequest::FLAG_RESTART_SCANS,
        file_index: 0,
        file_id: root_id,
        file_name_offset: 64 + 32,
        file_name_length: pattern.len() as u16,
        output_buffer_length: 1024,
        file_name: pattern,
    };
    let mut body = Vec::new();
    qd_req.write_to(&mut body).expect("write");
    let hdr = build_header(Command::QueryDirectory, 11, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::QueryDirectory);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let qd_resp = QueryDirectoryResponse::parse(rb).expect("parse query directory resp");
    assert!(qd_resp.output_buffer_length >= 56);
    assert_eq!(
        u64::from_le_bytes(qd_resp.buffer[40..48].try_into().unwrap()),
        0
    );
    assert_eq!(
        u64::from_le_bytes(qd_resp.buffer[48..56].try_into().unwrap()),
        4096
    );

    let close_req = |file_id: FileId| CloseRequest {
        structure_size: 24,
        flags: 0,
        reserved: 0,
        file_id,
    };
    let mut body = Vec::new();
    close_req(root_id).write_to(&mut body).expect("write");
    let hdr = build_header(Command::Close, 12, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Close);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let _ = CloseResponse::parse(rb).expect("parse root close resp");

    let mut body = Vec::new();
    close_req(file_id).write_to(&mut body).expect("write");
    let hdr = build_header(Command::Close, 13, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Close);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let _ = CloseResponse::parse(rb).expect("parse file close resp");

    handle.abort();
}

#[tokio::test]
async fn directory_create_reports_zero_size_and_ignores_allocation_context() {
    let td = tempdir().expect("tempdir");
    let (handle, mut s, session_id, tree_id) = start_localfs_session(td.path()).await;

    let (rh, created) = send_create_request(
        &mut s,
        4,
        session_id,
        tree_id,
        create_request(
            "created-dir",
            0x001f_01ff,
            FILE_ATTRIBUTE_NORMAL,
            2,
            0x0000_0001,
        ),
    )
    .await;
    assert_eq!(rh.command, Command::Create);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let created = created.expect("directory create response");
    assert_eq!(
        created.file_attributes & FILE_ATTRIBUTE_DIRECTORY,
        FILE_ATTRIBUTE_DIRECTORY
    );
    assert_eq!(created.allocation_size, 0);
    assert_eq!(created.end_of_file, 0);
    assert_eq!(
        send_close_request(&mut s, 5, session_id, tree_id, created.file_id).await,
        STATUS_SUCCESS
    );

    let request = create_request(
        "allocated-dir",
        0x001f_01ff,
        FILE_ATTRIBUTE_DIRECTORY,
        2,
        0x0000_0001,
    );
    let body = create_request_with_context(
        "allocated-dir",
        request,
        CreateContext {
            name: CreateContext::NAME_ALSI.to_vec(),
            data: (1024u64 * 1024 * 1024).to_le_bytes().to_vec(),
        },
    );
    let hdr = build_header(Command::Create, 6, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Create);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let allocated = CreateResponse::parse(rb).expect("parse allocated directory create resp");
    assert_eq!(allocated.allocation_size, 0);
    assert_eq!(allocated.end_of_file, 0);
    assert_eq!(
        send_close_request(&mut s, 7, session_id, tree_id, allocated.file_id).await,
        STATUS_SUCCESS
    );

    handle.abort();
}

#[tokio::test]
async fn create_aapl_context_response_precedes_maximal_access() {
    const AAPL_SERVER_QUERY: u32 = 0x0000_0001;
    const AAPL_SERVER_CAPS: u64 = 0x0000_0001;
    const AAPL_VOLUME_CAPS: u64 = 0x0000_0002;
    const AAPL_MODEL_INFO: u64 = 0x0000_0004;

    let td = tempdir().expect("tempdir");
    std::fs::write(td.path().join("aapl.txt"), b"aapl").expect("write aapl.txt");
    let backend = LocalFsBackend::new(td.path()).expect("open root");
    let server = SmbServer::builder()
        .listen("127.0.0.1:0".parse().unwrap())
        .share(Share::new("share", backend).public())
        .build()
        .expect("server builds");
    server.bind().await.expect("bind");
    let addr = server.local_addr().await.expect("addr");
    let handle = tokio::spawn(async move { server.serve().await });
    tokio::task::yield_now().await;

    let mut s = TcpStream::connect(addr).await.expect("connect");
    let _ = negotiate(&mut s).await;
    let session_id = anonymous_session_setup(&mut s).await;
    let tree_id = tree_connect(&mut s, "\\\\127.0.0.1\\share", session_id, 3).await;

    let mut aapl_req = vec![0; 24];
    aapl_req[0..4].copy_from_slice(&AAPL_SERVER_QUERY.to_le_bytes());
    aapl_req[8..16]
        .copy_from_slice(&(AAPL_SERVER_CAPS | AAPL_VOLUME_CAPS | AAPL_MODEL_INFO).to_le_bytes());
    aapl_req[16..24].copy_from_slice(&0x7u64.to_le_bytes());

    let body = create_request_with_contexts(
        "aapl.txt",
        create_request("aapl.txt", 0x0012_0089, 0, 1, 0x0000_0040),
        &[
            CreateContext {
                name: CreateContext::NAME_MXAC.to_vec(),
                data: Vec::new(),
            },
            CreateContext {
                name: CreateContext::NAME_AAPL.to_vec(),
                data: aapl_req,
            },
        ],
    );
    let hdr = build_header(Command::Create, 4, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Create);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let create_resp = CreateResponse::parse(rb).expect("parse create resp");
    let contexts =
        CreateContext::parse_chain(&create_resp.create_contexts).expect("parse create contexts");
    assert_eq!(contexts[0].name, CreateContext::NAME_AAPL.as_slice());
    assert_eq!(contexts[1].name, CreateContext::NAME_MXAC.as_slice());
    let aapl = &contexts[0].data;
    assert_eq!(
        u32::from_le_bytes(aapl[0..4].try_into().unwrap()),
        AAPL_SERVER_QUERY
    );
    assert_eq!(
        u64::from_le_bytes(aapl[8..16].try_into().unwrap()),
        AAPL_SERVER_CAPS | AAPL_VOLUME_CAPS | AAPL_MODEL_INFO
    );
    assert_eq!(u64::from_le_bytes(aapl[16..24].try_into().unwrap()), 0);
    assert_eq!(u64::from_le_bytes(aapl[24..32].try_into().unwrap()), 0);
    assert_eq!(u32::from_le_bytes(aapl[36..40].try_into().unwrap()), 10);
    assert_eq!(&aapl[40..50], utf16le("GoSMB").as_slice());

    drop(s);
    handle.abort();
}

#[tokio::test]
async fn qfid_and_file_identity_use_localfs_stable_ids() {
    let td = tempdir().expect("tempdir");
    std::fs::write(td.path().join("identity.txt"), b"identity").expect("write identity.txt");

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

    let base_create = CreateRequest {
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
        create_options: 0x0000_0040,
        name_offset: 0,
        name_length: 0,
        create_contexts_offset: 0,
        create_contexts_length: 0,
        name: Vec::new(),
        create_contexts: Vec::new(),
    };
    let create_body = create_request_with_context(
        "identity.txt",
        base_create,
        CreateContext {
            name: CreateContext::NAME_QFID.to_vec(),
            data: Vec::new(),
        },
    );
    let hdr = build_header(Command::Create, 4, session_id, tree_id);
    write_frame(&mut s, &hdr, &create_body).await;
    let resp = read_frame(&mut s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Create);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let create_resp = CreateResponse::parse(rb).expect("parse create resp");
    let contexts =
        CreateContext::parse_chain(&create_resp.create_contexts).expect("parse create contexts");
    let qfid = contexts
        .iter()
        .find(|ctx| ctx.name == CreateContext::NAME_QFID.as_slice())
        .expect("QFid response context");
    assert_eq!(qfid.data.len(), 32);
    let disk_file_id = u64::from_le_bytes(qfid.data[0..8].try_into().unwrap());
    let volume_id = u64::from_le_bytes(qfid.data[8..16].try_into().unwrap());
    assert_ne!(disk_file_id, 0);
    assert_ne!(volume_id, 0);
    assert!(qfid.data[16..32].iter().all(|byte| *byte == 0));

    let internal_req = QueryInfoRequest {
        structure_size: 41,
        info_type: InfoType::File as u8,
        file_information_class: 0x06,
        output_buffer_length: 8,
        input_buffer_offset: 0,
        reserved: 0,
        input_buffer_length: 0,
        additional_information: 0,
        flags: 0,
        file_id: create_resp.file_id,
        input_buffer: vec![],
    };
    let mut body = Vec::new();
    internal_req.write_to(&mut body).expect("write");
    let hdr = build_header(Command::QueryInfo, 5, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::QueryInfo);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let internal_resp = QueryInfoResponse::parse(rb).expect("parse internal info resp");
    assert_eq!(internal_resp.buffer.len(), 8);
    assert_eq!(
        u64::from_le_bytes(internal_resp.buffer[0..8].try_into().unwrap()),
        disk_file_id
    );

    let file_id_req = QueryInfoRequest {
        structure_size: 41,
        info_type: InfoType::File as u8,
        file_information_class: 0x3b,
        output_buffer_length: 24,
        input_buffer_offset: 0,
        reserved: 0,
        input_buffer_length: 0,
        additional_information: 0,
        flags: 0,
        file_id: create_resp.file_id,
        input_buffer: vec![],
    };
    let mut body = Vec::new();
    file_id_req.write_to(&mut body).expect("write");
    let hdr = build_header(Command::QueryInfo, 6, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::QueryInfo);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let file_id_resp = QueryInfoResponse::parse(rb).expect("parse file-id info resp");
    assert_eq!(file_id_resp.buffer.len(), 24);
    assert_eq!(
        u64::from_le_bytes(file_id_resp.buffer[0..8].try_into().unwrap()),
        volume_id
    );
    assert_eq!(
        u64::from_le_bytes(file_id_resp.buffer[16..24].try_into().unwrap()),
        disk_file_id
    );

    let close_req = CloseRequest {
        structure_size: 24,
        flags: 0,
        reserved: 0,
        file_id: create_resp.file_id,
    };
    let mut body = Vec::new();
    close_req.write_to(&mut body).expect("write");
    let hdr = build_header(Command::Close, 7, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Close);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let _ = CloseResponse::parse(rb).expect("parse close resp");

    handle.abort();
}

#[cfg(unix)]
#[tokio::test]
async fn posix_disposition_deletes_name_but_keeps_open_handle_readable() {
    let td = tempdir().expect("tempdir");
    std::fs::write(td.path().join("posix-delete.txt"), b"open data")
        .expect("write posix-delete.txt");

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

    let name = utf16le("posix-delete.txt");
    let create_req = CreateRequest {
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
        create_options: 0x0000_0040,
        name_offset: 0x78,
        name_length: name.len() as u16,
        create_contexts_offset: 0,
        create_contexts_length: 0,
        name,
        create_contexts: vec![],
    };
    let mut body = Vec::new();
    create_req.write_to(&mut body).expect("write");
    let hdr = build_header(Command::Create, 4, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Create);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let file_id = CreateResponse::parse(rb)
        .expect("parse create resp")
        .file_id;

    let disposition_req = SetInfoRequest {
        structure_size: 33,
        info_type: InfoType::File as u8,
        file_information_class: 0x40,
        buffer_length: 4,
        buffer_offset: 64 + 32,
        reserved: 0,
        additional_information: 0,
        file_id,
        buffer: 0x0000_0003u32.to_le_bytes().to_vec(),
    };
    let mut body = Vec::new();
    disposition_req.write_to(&mut body).expect("write");
    let hdr = build_header(Command::SetInfo, 5, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, _rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::SetInfo);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    assert!(!td.path().join("posix-delete.txt").exists());

    let reopen_req = CreateRequest {
        desired_access: 0x8000_0000,
        ..create_req
    };
    let mut body = Vec::new();
    reopen_req.write_to(&mut body).expect("write");
    let hdr = build_header(Command::Create, 6, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, _rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Create);
    assert_ne!(rh.channel_sequence_status, STATUS_SUCCESS);

    let read_req = ReadRequest {
        structure_size: 49,
        padding: ReadResponse::STANDARD_DATA_OFFSET,
        flags: 0,
        length: 9,
        offset: 0,
        file_id,
        minimum_count: 0,
        channel: 0,
        remaining_bytes: 0,
        read_channel_info_offset: 0,
        read_channel_info_length: 0,
        buffer: vec![0],
    };
    let mut body = Vec::new();
    read_req.write_to(&mut body).expect("write");
    let hdr = build_header(Command::Read, 7, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Read);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let read_resp = ReadResponse::parse(rb).expect("parse read resp");
    assert_eq!(read_resp.data, b"open data");

    let query_all_req = QueryInfoRequest {
        structure_size: 41,
        info_type: InfoType::File as u8,
        file_information_class: 0x12,
        output_buffer_length: 4096,
        input_buffer_offset: 0,
        reserved: 0,
        input_buffer_length: 0,
        additional_information: 0,
        flags: 0,
        file_id,
        input_buffer: vec![],
    };
    let mut body = Vec::new();
    query_all_req.write_to(&mut body).expect("write");
    let hdr = build_header(Command::QueryInfo, 8, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::QueryInfo);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let query_all_resp = QueryInfoResponse::parse(rb).expect("parse all-info resp");
    assert_eq!(
        u32::from_le_bytes(query_all_resp.buffer[56..60].try_into().unwrap()),
        0
    );
    assert_eq!(query_all_resp.buffer[60], 1);

    let close_req = CloseRequest {
        structure_size: 24,
        flags: 0,
        reserved: 0,
        file_id,
    };
    let mut body = Vec::new();
    close_req.write_to(&mut body).expect("write");
    let hdr = build_header(Command::Close, 9, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Close);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let _ = CloseResponse::parse(rb).expect("parse close resp");

    handle.abort();
}

#[cfg(unix)]
#[tokio::test]
async fn posix_rename_replaces_open_target_but_preserves_old_handles() {
    let td = tempdir().expect("tempdir");
    std::fs::write(td.path().join("source.txt"), b"source").expect("write source.txt");
    std::fs::write(td.path().join("target.txt"), b"target").expect("write target.txt");

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

    let open_file = |name: &str, message_id: u64| -> (Smb2Header, Vec<u8>) {
        let name = utf16le(name);
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
            create_options: 0x0000_0040,
            name_offset: 0x78,
            name_length: name.len() as u16,
            create_contexts_offset: 0,
            create_contexts_length: 0,
            name,
            create_contexts: vec![],
        };
        let mut body = Vec::new();
        req.write_to(&mut body).expect("write");
        (
            build_header(Command::Create, message_id, session_id, tree_id),
            body,
        )
    };

    let (hdr, body) = open_file("target.txt", 4);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Create);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let target_id = CreateResponse::parse(rb)
        .expect("parse target create resp")
        .file_id;

    let (hdr, body) = open_file("source.txt", 5);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Create);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let source_id = CreateResponse::parse(rb)
        .expect("parse source create resp")
        .file_id;

    let rename = file_rename_information_ex("target.txt", 0x0000_0003);
    let rename_req = SetInfoRequest {
        structure_size: 33,
        info_type: InfoType::File as u8,
        file_information_class: 0x41,
        buffer_length: rename.len() as u32,
        buffer_offset: 64 + 32,
        reserved: 0,
        additional_information: 0,
        file_id: source_id,
        buffer: rename,
    };
    let mut body = Vec::new();
    rename_req.write_to(&mut body).expect("write");
    let hdr = build_header(Command::SetInfo, 6, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, _rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::SetInfo);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    assert!(!td.path().join("source.txt").exists());
    assert_eq!(
        std::fs::read(td.path().join("target.txt")).expect("read renamed target"),
        b"source"
    );

    let read_file = |file_id: FileId, message_id: u64| -> (Smb2Header, Vec<u8>) {
        let req = ReadRequest {
            structure_size: 49,
            padding: ReadResponse::STANDARD_DATA_OFFSET,
            flags: 0,
            length: 6,
            offset: 0,
            file_id,
            minimum_count: 0,
            channel: 0,
            remaining_bytes: 0,
            read_channel_info_offset: 0,
            read_channel_info_length: 0,
            buffer: vec![0],
        };
        let mut body = Vec::new();
        req.write_to(&mut body).expect("write");
        (
            build_header(Command::Read, message_id, session_id, tree_id),
            body,
        )
    };

    let (hdr, body) = read_file(target_id, 7);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Read);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let target_read = ReadResponse::parse(rb).expect("parse target read resp");
    assert_eq!(target_read.data, b"target");

    let (hdr, body) = read_file(source_id, 8);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Read);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let source_read = ReadResponse::parse(rb).expect("parse source read resp");
    assert_eq!(source_read.data, b"source");

    let query_all_req = QueryInfoRequest {
        structure_size: 41,
        info_type: InfoType::File as u8,
        file_information_class: 0x12,
        output_buffer_length: 4096,
        input_buffer_offset: 0,
        reserved: 0,
        input_buffer_length: 0,
        additional_information: 0,
        flags: 0,
        file_id: target_id,
        input_buffer: vec![],
    };
    let mut body = Vec::new();
    query_all_req.write_to(&mut body).expect("write");
    let hdr = build_header(Command::QueryInfo, 9, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::QueryInfo);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let target_info = QueryInfoResponse::parse(rb).expect("parse target all-info resp");
    assert_eq!(
        u32::from_le_bytes(target_info.buffer[56..60].try_into().unwrap()),
        0
    );
    assert_eq!(target_info.buffer[60], 1);

    let (hdr, body) = open_file("target.txt", 10);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Create);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let reopened_id = CreateResponse::parse(rb)
        .expect("parse reopened target resp")
        .file_id;
    let (hdr, body) = read_file(reopened_id, 11);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Read);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let reopened_read = ReadResponse::parse(rb).expect("parse reopened read resp");
    assert_eq!(reopened_read.data, b"source");

    for (message_id, file_id) in [(12, reopened_id), (13, source_id), (14, target_id)] {
        let close_req = CloseRequest {
            structure_size: 24,
            flags: 0,
            reserved: 0,
            file_id,
        };
        let mut body = Vec::new();
        close_req.write_to(&mut body).expect("write");
        let hdr = build_header(Command::Close, message_id, session_id, tree_id);
        write_frame(&mut s, &hdr, &body).await;
        let resp = read_frame(&mut s).await;
        let (rh, rb) = parse_response_header(&resp);
        assert_eq!(rh.command, Command::Close);
        assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
        let _ = CloseResponse::parse(rb).expect("parse close resp");
    }

    handle.abort();
}

#[tokio::test]
async fn rename_respects_parent_directory_delete_access() {
    let td = tempdir().expect("tempdir");
    std::fs::create_dir(td.path().join("blocked")).expect("mkdir blocked");
    std::fs::write(td.path().join("blocked/source.txt"), b"source").expect("write blocked source");
    std::fs::create_dir(td.path().join("allowed")).expect("mkdir allowed");
    std::fs::write(td.path().join("allowed/source.txt"), b"source").expect("write allowed source");

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

    let mut next_message = 4u64;
    let mut opened = Vec::new();
    let blocked_parent = open_localfs_path(
        &mut s,
        session_id,
        tree_id,
        next_message,
        "blocked",
        0x0001_0080,
        0x0000_0001,
    )
    .await;
    next_message += 1;
    opened.push(blocked_parent);
    let blocked_source = open_localfs_path(
        &mut s,
        session_id,
        tree_id,
        next_message,
        "blocked/source.txt",
        0x001f_01ff,
        0x0000_0040,
    )
    .await;
    next_message += 1;
    opened.push(blocked_source);
    let rename = file_rename_information("blocked/renamed.txt", true);
    let rename_req = SetInfoRequest {
        structure_size: 33,
        info_type: InfoType::File as u8,
        file_information_class: 0x0A,
        buffer_length: rename.len() as u32,
        buffer_offset: 64 + 32,
        reserved: 0,
        additional_information: 0,
        file_id: blocked_source,
        buffer: rename,
    };
    let mut body = Vec::new();
    rename_req.write_to(&mut body).expect("write");
    let hdr = build_header(Command::SetInfo, next_message, session_id, tree_id);
    next_message += 1;
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, _rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::SetInfo);
    assert_eq!(rh.channel_sequence_status, 0xC000_0043);
    assert!(td.path().join("blocked/source.txt").exists());
    assert!(!td.path().join("blocked/renamed.txt").exists());

    let allowed_parent = open_localfs_path(
        &mut s,
        session_id,
        tree_id,
        next_message,
        "allowed",
        0x001f_01ff & !0x0001_0000,
        0x0000_0001,
    )
    .await;
    next_message += 1;
    opened.push(allowed_parent);
    let allowed_source = open_localfs_path(
        &mut s,
        session_id,
        tree_id,
        next_message,
        "allowed/source.txt",
        0x001f_01ff,
        0x0000_0040,
    )
    .await;
    next_message += 1;
    opened.push(allowed_source);
    let rename = file_rename_information("allowed/renamed.txt", true);
    let rename_req = SetInfoRequest {
        structure_size: 33,
        info_type: InfoType::File as u8,
        file_information_class: 0x0A,
        buffer_length: rename.len() as u32,
        buffer_offset: 64 + 32,
        reserved: 0,
        additional_information: 0,
        file_id: allowed_source,
        buffer: rename,
    };
    let mut body = Vec::new();
    rename_req.write_to(&mut body).expect("write");
    let hdr = build_header(Command::SetInfo, next_message, session_id, tree_id);
    next_message += 1;
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, _rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::SetInfo);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    assert!(!td.path().join("allowed/source.txt").exists());
    assert!(td.path().join("allowed/renamed.txt").exists());

    for file_id in opened {
        let close_req = CloseRequest {
            structure_size: 24,
            flags: 0,
            reserved: 0,
            file_id,
        };
        let mut body = Vec::new();
        close_req.write_to(&mut body).expect("write");
        let hdr = build_header(Command::Close, next_message, session_id, tree_id);
        next_message += 1;
        write_frame(&mut s, &hdr, &body).await;
        let resp = read_frame(&mut s).await;
        let (rh, rb) = parse_response_header(&resp);
        assert_eq!(rh.command, Command::Close);
        assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
        let _ = CloseResponse::parse(rb).expect("parse close resp");
    }

    handle.abort();
}

#[tokio::test]
async fn set_info_security_descriptor_without_dacl_becomes_nil_dacl() {
    let td = tempdir().expect("tempdir");
    std::fs::write(td.path().join("default.txt"), b"hello").expect("write default");

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

    let file_id = open_localfs_path(
        &mut s,
        session_id,
        tree_id,
        4,
        "default.txt",
        0x001f_01ff,
        0x0000_0040,
    )
    .await;

    set_localfs_security_descriptor(
        &mut s,
        session_id,
        tree_id,
        5,
        file_id,
        security_descriptor_without_dacl(),
    )
    .await;
    assert_eq!(
        query_security_descriptor(&mut s, 6, session_id, tree_id, file_id).await,
        nil_dacl_security_descriptor()
    );

    let close_req = CloseRequest {
        structure_size: 24,
        flags: 0,
        reserved: 0,
        file_id,
    };
    let mut body = Vec::new();
    close_req.write_to(&mut body).expect("write");
    let hdr = build_header(Command::Close, 7, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Close);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let _ = CloseResponse::parse(rb).expect("parse close resp");

    handle.abort();
}

#[tokio::test]
async fn set_info_requires_matching_open_access() {
    let td = tempdir().expect("tempdir");
    std::fs::write(td.path().join("hello.txt"), b"hello").expect("write hello");

    let (handle, mut s, session_id, tree_id) = start_localfs_session(td.path()).await;
    let file_id = open_localfs_path(
        &mut s,
        session_id,
        tree_id,
        4,
        "hello.txt",
        0x0000_0003,
        0x0000_0040,
    )
    .await;

    let mut basic = vec![0; 40];
    basic[32..36].copy_from_slice(&FILE_ATTRIBUTE_HIDDEN.to_le_bytes());
    assert_eq!(
        set_basic_information_status(&mut s, 5, session_id, tree_id, file_id, basic).await,
        STATUS_ACCESS_DENIED
    );
    assert_eq!(
        set_file_disposition_status(&mut s, 6, session_id, tree_id, file_id, true).await,
        STATUS_ACCESS_DENIED
    );
    assert_eq!(
        set_file_rename_status(
            &mut s,
            7,
            session_id,
            tree_id,
            file_id,
            "renamed.txt",
            false
        )
        .await,
        STATUS_ACCESS_DENIED
    );
    assert!(td.path().join("hello.txt").exists());
    assert!(!td.path().join("renamed.txt").exists());

    assert_eq!(
        send_close_request(&mut s, 8, session_id, tree_id, file_id).await,
        STATUS_SUCCESS
    );
    handle.abort();
}

#[tokio::test]
async fn set_info_security_descriptor_replaces_existing_dacl() {
    let td = tempdir().expect("tempdir");
    std::fs::write(td.path().join("acl.txt"), b"hello").expect("write acl");

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

    let file_id = open_localfs_path(
        &mut s,
        session_id,
        tree_id,
        4,
        "acl.txt",
        0x001f_01ff,
        0x0000_0040,
    )
    .await;

    let with_extra_ace = security_descriptor_with_aces(&[(0, 0, 0x0012_0089), (0, 0, 0x0000_0002)]);
    set_localfs_security_descriptor(
        &mut s,
        session_id,
        tree_id,
        5,
        file_id,
        with_extra_ace.clone(),
    )
    .await;
    assert_eq!(
        query_security_descriptor(&mut s, 6, session_id, tree_id, file_id).await,
        with_extra_ace
    );

    let replacement = security_descriptor_with_ace(0, 0, 0x0012_0089);
    set_localfs_security_descriptor(&mut s, session_id, tree_id, 7, file_id, replacement.clone())
        .await;
    assert_eq!(
        query_security_descriptor(&mut s, 8, session_id, tree_id, file_id).await,
        replacement
    );

    let close_req = CloseRequest {
        structure_size: 24,
        flags: 0,
        reserved: 0,
        file_id,
    };
    let mut body = Vec::new();
    close_req.write_to(&mut body).expect("write");
    let hdr = build_header(Command::Close, 9, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Close);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let _ = CloseResponse::parse(rb).expect("parse close resp");

    handle.abort();
}

#[tokio::test]
async fn security_descriptors_deny_unallowed_create_access() {
    let td = tempdir().expect("tempdir");
    std::fs::write(td.path().join("empty-dacl.txt"), b"hello").expect("write empty-dacl");
    std::fs::write(td.path().join("allow-read.txt"), b"hello").expect("write allow-read");

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

    let empty_id = open_localfs_path(
        &mut s,
        session_id,
        tree_id,
        4,
        "empty-dacl.txt",
        0x001f_01ff,
        0x0000_0040,
    )
    .await;
    set_localfs_security_descriptor(
        &mut s,
        session_id,
        tree_id,
        5,
        empty_id,
        empty_dacl_security_descriptor(),
    )
    .await;
    let (status, _) = create_localfs_path_status(
        &mut s,
        session_id,
        tree_id,
        6,
        "empty-dacl.txt",
        0x0000_0002,
        1,
        0x0000_0040,
    )
    .await;
    assert_eq!(status, 0xC000_0022);

    let allow_id = open_localfs_path(
        &mut s,
        session_id,
        tree_id,
        7,
        "allow-read.txt",
        0x001f_01ff,
        0x0000_0040,
    )
    .await;
    set_localfs_security_descriptor(
        &mut s,
        session_id,
        tree_id,
        8,
        allow_id,
        security_descriptor_with_ace(0, 0, 0x0012_0089),
    )
    .await;
    let (status, _) = create_localfs_path_status(
        &mut s,
        session_id,
        tree_id,
        9,
        "allow-read.txt",
        0x0000_0002,
        1,
        0x0000_0040,
    )
    .await;
    assert_eq!(status, 0xC000_0022);
    let (status, read_id) = create_localfs_path_status(
        &mut s,
        session_id,
        tree_id,
        10,
        "allow-read.txt",
        0x0000_0001,
        1,
        0x0000_0040,
    )
    .await;
    assert_eq!(status, STATUS_SUCCESS);

    for (message_id, file_id) in [(11, empty_id), (12, allow_id), (13, read_id.unwrap())] {
        let close_req = CloseRequest {
            structure_size: 24,
            flags: 0,
            reserved: 0,
            file_id,
        };
        let mut body = Vec::new();
        close_req.write_to(&mut body).expect("write");
        let hdr = build_header(Command::Close, message_id, session_id, tree_id);
        write_frame(&mut s, &hdr, &body).await;
        let resp = read_frame(&mut s).await;
        let (rh, rb) = parse_response_header(&resp);
        assert_eq!(rh.command, Command::Close);
        assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
        let _ = CloseResponse::parse(rb).expect("parse close resp");
    }

    handle.abort();
}

#[tokio::test]
async fn parent_directory_dacl_denies_child_file_create() {
    let td = tempdir().expect("tempdir");
    std::fs::create_dir(td.path().join("locked")).expect("mkdir locked");

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

    let dir_id = open_localfs_path(
        &mut s,
        session_id,
        tree_id,
        4,
        "locked",
        0x001f_01ff,
        0x0000_0001,
    )
    .await;
    set_localfs_security_descriptor(
        &mut s,
        session_id,
        tree_id,
        5,
        dir_id,
        security_descriptor_with_ace(1, 0x02, 0x0000_0002),
    )
    .await;

    let (status, _) = create_localfs_path_status(
        &mut s,
        session_id,
        tree_id,
        6,
        "locked/child.txt",
        0x0000_0002,
        2,
        0x0000_0040,
    )
    .await;
    assert_eq!(status, 0xC000_0022);
    assert!(!td.path().join("locked/child.txt").exists());

    let close_req = CloseRequest {
        structure_size: 24,
        flags: 0,
        reserved: 0,
        file_id: dir_id,
    };
    let mut body = Vec::new();
    close_req.write_to(&mut body).expect("write");
    let hdr = build_header(Command::Close, 7, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Close);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let _ = CloseResponse::parse(rb).expect("parse close resp");

    handle.abort();
}

#[tokio::test]
async fn directory_dacl_inherits_to_child_directory() {
    let td = tempdir().expect("tempdir");
    std::fs::create_dir(td.path().join("locked")).expect("mkdir locked");

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

    let dir_id = open_localfs_path(
        &mut s,
        session_id,
        tree_id,
        4,
        "locked",
        0x001f_01ff,
        0x0000_0001,
    )
    .await;
    set_localfs_security_descriptor(
        &mut s,
        session_id,
        tree_id,
        5,
        dir_id,
        security_descriptor_with_ace(1, 0x02, 0x0000_0002),
    )
    .await;

    let (status, child_id) = create_localfs_path_status(
        &mut s,
        session_id,
        tree_id,
        6,
        "locked/child",
        0x001f_01ff,
        2,
        0x0000_0001,
    )
    .await;
    assert_eq!(status, STATUS_SUCCESS);
    assert!(td.path().join("locked/child").is_dir());

    let (status, _) = create_localfs_path_status(
        &mut s,
        session_id,
        tree_id,
        7,
        "locked/child/grandchild.txt",
        0x0000_0002,
        2,
        0x0000_0040,
    )
    .await;
    assert_eq!(status, 0xC000_0022);
    assert!(!td.path().join("locked/child/grandchild.txt").exists());

    for (message_id, file_id) in [(8, child_id.unwrap()), (9, dir_id)] {
        let close_req = CloseRequest {
            structure_size: 24,
            flags: 0,
            reserved: 0,
            file_id,
        };
        let mut body = Vec::new();
        close_req.write_to(&mut body).expect("write");
        let hdr = build_header(Command::Close, message_id, session_id, tree_id);
        write_frame(&mut s, &hdr, &body).await;
        let resp = read_frame(&mut s).await;
        let (rh, rb) = parse_response_header(&resp);
        assert_eq!(rh.command, Command::Close);
        assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
        let _ = CloseResponse::parse(rb).expect("parse close resp");
    }

    handle.abort();
}

#[tokio::test]
async fn directory_dacl_inherits_to_child_directory_created_by_open_if() {
    let td = tempdir().expect("tempdir");
    std::fs::create_dir(td.path().join("locked")).expect("mkdir locked");

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

    let dir_id = open_localfs_path(
        &mut s,
        session_id,
        tree_id,
        4,
        "locked",
        0x001f_01ff,
        0x0000_0001,
    )
    .await;
    set_localfs_security_descriptor(
        &mut s,
        session_id,
        tree_id,
        5,
        dir_id,
        security_descriptor_with_ace(1, 0x02, 0x0000_0002),
    )
    .await;

    let (status, child_id) = create_localfs_path_status(
        &mut s,
        session_id,
        tree_id,
        6,
        "locked/child",
        0x001f_01ff,
        3,
        0x0000_0001,
    )
    .await;
    assert_eq!(status, STATUS_SUCCESS);
    assert!(td.path().join("locked/child").is_dir());

    let (status, _) = create_localfs_path_status(
        &mut s,
        session_id,
        tree_id,
        7,
        "locked/child/grandchild.txt",
        0x0000_0002,
        2,
        0x0000_0040,
    )
    .await;
    assert_eq!(status, 0xC000_0022);
    assert!(!td.path().join("locked/child/grandchild.txt").exists());

    for (message_id, file_id) in [(8, child_id.unwrap()), (9, dir_id)] {
        let close_req = CloseRequest {
            structure_size: 24,
            flags: 0,
            reserved: 0,
            file_id,
        };
        let mut body = Vec::new();
        close_req.write_to(&mut body).expect("write");
        let hdr = build_header(Command::Close, message_id, session_id, tree_id);
        write_frame(&mut s, &hdr, &body).await;
        let resp = read_frame(&mut s).await;
        let (rh, rb) = parse_response_header(&resp);
        assert_eq!(rh.command, Command::Close);
        assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
        let _ = CloseResponse::parse(rb).expect("parse close resp");
    }

    handle.abort();
}

#[tokio::test]
async fn create_delete_on_close_requires_delete_access() {
    let td = tempdir().expect("tempdir");
    std::fs::write(td.path().join("denied.txt"), b"hello").expect("write denied");
    std::fs::write(td.path().join("allowed.txt"), b"hello").expect("write allowed");

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

    let (status, _) = create_localfs_path_status(
        &mut s,
        session_id,
        tree_id,
        4,
        "denied.txt",
        0x0000_0001,
        1,
        0x0000_1000,
    )
    .await;
    assert_eq!(status, 0xC000_0022);
    assert!(td.path().join("denied.txt").exists());

    let (status, file_id) = create_localfs_path_status(
        &mut s,
        session_id,
        tree_id,
        5,
        "allowed.txt",
        0x0001_0080,
        1,
        0x0000_1000,
    )
    .await;
    assert_eq!(status, STATUS_SUCCESS);

    let close_req = CloseRequest {
        structure_size: 24,
        flags: 0,
        reserved: 0,
        file_id: file_id.unwrap(),
    };
    let mut body = Vec::new();
    close_req.write_to(&mut body).expect("write");
    let hdr = build_header(Command::Close, 6, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Close);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let _ = CloseResponse::parse(rb).expect("parse close resp");
    assert!(!td.path().join("allowed.txt").exists());

    handle.abort();
}

#[tokio::test]
async fn read_enforces_open_access_and_updates_current_offset() {
    let td = tempdir().expect("tempdir");
    std::fs::write(td.path().join("hello.txt"), b"hello").expect("write hello");
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
    let handle = tokio::spawn(async move { server.serve().await });
    tokio::task::yield_now().await;

    let mut s = TcpStream::connect(addr).await.expect("connect");
    let _ = negotiate(&mut s).await;
    let session_id = anonymous_session_setup(&mut s).await;
    let tree_id = tree_connect(&mut s, "\\\\127.0.0.1\\share", session_id, 3).await;

    let attr_only = open_localfs_path(
        &mut s,
        session_id,
        tree_id,
        4,
        "hello.txt",
        0x0000_0080,
        0x0000_0040,
    )
    .await;
    let (status, _) =
        read_localfs_path_status(&mut s, session_id, tree_id, 5, attr_only, 5, 0, 0).await;
    assert_eq!(status, 0xC000_0022);

    let execute_id = open_localfs_path(
        &mut s,
        session_id,
        tree_id,
        6,
        "hello.txt",
        0x0000_00A0,
        0x0000_0040,
    )
    .await;
    let (status, data) =
        read_localfs_path_status(&mut s, session_id, tree_id, 7, execute_id, 5, 0, 0).await;
    assert_eq!(status, STATUS_SUCCESS);
    assert_eq!(data, Some(b"hello".to_vec()));

    let query_all_req = QueryInfoRequest {
        structure_size: 41,
        info_type: InfoType::File as u8,
        file_information_class: 0x12,
        output_buffer_length: 4096,
        input_buffer_offset: 0,
        reserved: 0,
        input_buffer_length: 0,
        additional_information: 0,
        flags: 0,
        file_id: execute_id,
        input_buffer: vec![],
    };
    let mut body = Vec::new();
    query_all_req.write_to(&mut body).expect("write");
    let hdr = build_header(Command::QueryInfo, 8, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::QueryInfo);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let query_all_resp = QueryInfoResponse::parse(rb).expect("parse all-info resp");
    assert_eq!(
        u64::from_le_bytes(query_all_resp.buffer[80..88].try_into().unwrap()),
        5
    );

    let dir_id = open_localfs_path(
        &mut s,
        session_id,
        tree_id,
        9,
        "docs",
        0x001f_01ff,
        0x0000_0001,
    )
    .await;
    let (status, _) =
        read_localfs_path_status(&mut s, session_id, tree_id, 10, dir_id, 1, 0, 0).await;
    assert_eq!(status, 0xC000_0010);

    for (message_id, file_id) in [(11, attr_only), (12, execute_id), (13, dir_id)] {
        let close_req = CloseRequest {
            structure_size: 24,
            flags: 0,
            reserved: 0,
            file_id,
        };
        let mut body = Vec::new();
        close_req.write_to(&mut body).expect("write");
        let hdr = build_header(Command::Close, message_id, session_id, tree_id);
        write_frame(&mut s, &hdr, &body).await;
        let resp = read_frame(&mut s).await;
        let (rh, rb) = parse_response_header(&resp);
        assert_eq!(rh.command, Command::Close);
        assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
        let _ = CloseResponse::parse(rb).expect("parse close resp");
    }

    handle.abort();
}

#[tokio::test]
async fn mkdir_visible_children_retry_until_inherited_dacl_denies_create() {
    let td = tempdir().expect("tempdir");
    std::fs::create_dir(td.path().join("mkdir_visible")).expect("mkdir base");

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

    let dir_id = open_localfs_path(
        &mut s,
        session_id,
        tree_id,
        4,
        "mkdir_visible",
        0x001f_01ff,
        0x0000_0001,
    )
    .await;
    let (status, file_ok) = create_localfs_path_status(
        &mut s,
        session_id,
        tree_id,
        5,
        r"mkdir_visible\file_ok",
        0x001f_01ff,
        2,
        0x0000_0040,
    )
    .await;
    assert_eq!(status, STATUS_SUCCESS);
    let close_req = CloseRequest {
        structure_size: 24,
        flags: 0,
        reserved: 0,
        file_id: file_ok.expect("file_ok id"),
    };
    let mut body = Vec::new();
    close_req.write_to(&mut body).expect("write");
    let hdr = build_header(Command::Close, 6, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Close);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let _ = CloseResponse::parse(rb).expect("parse close resp");

    set_localfs_security_descriptor(
        &mut s,
        session_id,
        tree_id,
        7,
        dir_id,
        security_descriptor_with_aces(&[(1, 0x02, 0x0000_0002), (0, 0x03, 0x001f_01ff)]),
    )
    .await;

    let (status, _) = create_localfs_path_status(
        &mut s,
        session_id,
        tree_id,
        8,
        r"mkdir_visible\file_fail",
        0x0000_0080,
        2,
        0x0000_0040,
    )
    .await;
    assert_eq!(status, STATUS_ACCESS_DENIED);

    let close_req = CloseRequest {
        structure_size: 24,
        flags: 0,
        reserved: 0,
        file_id: dir_id,
    };
    let mut body = Vec::new();
    close_req.write_to(&mut body).expect("write");
    let hdr = build_header(Command::Close, 9, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Close);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let _ = CloseResponse::parse(rb).expect("parse close resp");

    let child_count = 8;
    let start = Arc::new(Barrier::new(child_count + 1));
    let mut children = Vec::new();
    for idx in 0..child_count {
        let start = Arc::clone(&start);
        children.push(tokio::spawn(async move {
            let mut child = TcpStream::connect(addr).await.expect("child connect");
            let _ = negotiate(&mut child).await;
            let child_session = anonymous_session_setup(&mut child).await;
            let child_tree =
                tree_connect(&mut child, "\\\\127.0.0.1\\share", child_session, 3).await;
            start.wait().await;

            let name = format!(r"mkdir_visible\visible_dir\file_{idx}");
            for message_id in (4..).take(100) {
                let (status, _) = create_localfs_path_status(
                    &mut child,
                    child_session,
                    child_tree,
                    message_id,
                    &name,
                    0x0000_0080,
                    2,
                    0x0000_0040,
                )
                .await;
                if status == STATUS_ACCESS_DENIED {
                    return status;
                }
                assert_eq!(status, STATUS_OBJECT_PATH_NOT_FOUND);
                tokio::task::yield_now().await;
            }
            STATUS_OBJECT_PATH_NOT_FOUND
        }));
    }

    start.wait().await;
    sleep(Duration::from_millis(25)).await;
    let (status, visible_dir_id) = create_localfs_path_status(
        &mut s,
        session_id,
        tree_id,
        10,
        r"mkdir_visible\visible_dir",
        0x001f_01ff,
        2,
        0x0000_0001,
    )
    .await;
    assert_eq!(status, STATUS_SUCCESS);
    assert!(td.path().join("mkdir_visible").join("visible_dir").is_dir());

    let statuses = tokio::time::timeout(Duration::from_secs(5), async {
        let mut statuses = Vec::new();
        for child in children {
            statuses.push(child.await.expect("child task"));
        }
        statuses
    })
    .await
    .expect("children settled after visible directory create");
    assert_eq!(statuses, vec![STATUS_ACCESS_DENIED; child_count]);

    let (status, delete_id) = create_localfs_path_status(
        &mut s,
        session_id,
        tree_id,
        11,
        r"mkdir_visible\visible_dir",
        0x0001_0000,
        1,
        0x0000_1001,
    )
    .await;
    assert_eq!(status, STATUS_SUCCESS);

    let close_req = CloseRequest {
        structure_size: 24,
        flags: 0,
        reserved: 0,
        file_id: delete_id.expect("delete-on-close dir id"),
    };
    let mut body = Vec::new();
    close_req.write_to(&mut body).expect("write");
    let hdr = build_header(Command::Close, 12, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Close);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let _ = CloseResponse::parse(rb).expect("parse close resp");
    assert!(!td.path().join("mkdir_visible").join("visible_dir").exists());

    let (status, delete_file_id) = create_localfs_path_status(
        &mut s,
        session_id,
        tree_id,
        13,
        r"mkdir_visible\file_ok",
        0x0001_0000,
        1,
        0x0000_1040,
    )
    .await;
    assert_eq!(status, STATUS_SUCCESS);
    let close_req = CloseRequest {
        structure_size: 24,
        flags: 0,
        reserved: 0,
        file_id: delete_file_id.expect("delete-on-close file id"),
    };
    let mut body = Vec::new();
    close_req.write_to(&mut body).expect("write");
    let hdr = build_header(Command::Close, 14, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Close);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let _ = CloseResponse::parse(rb).expect("parse close resp");
    assert!(!td.path().join("mkdir_visible").join("file_ok").exists());

    let close_req = CloseRequest {
        structure_size: 24,
        flags: 0,
        reserved: 0,
        file_id: visible_dir_id.expect("visible dir id"),
    };
    let mut body = Vec::new();
    close_req.write_to(&mut body).expect("write");
    let hdr = build_header(Command::Close, 15, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Close);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let _ = CloseResponse::parse(rb).expect("parse close resp");

    handle.abort();
}

#[tokio::test]
async fn create_directory_file_open_if_creates_directory() {
    let td = tempdir().expect("tempdir");

    let (handle, mut s, session_id, tree_id) = start_localfs_session(td.path()).await;
    let (rh, created) = send_create_request(
        &mut s,
        4,
        session_id,
        tree_id,
        create_request("docs", 0x001f_01ff, 0, 3, 0x0000_0001),
    )
    .await;
    assert_eq!(rh.command, Command::Create);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    assert!(td.path().join("docs").is_dir());
    let dir_id = created.expect("directory create").file_id;

    let (status, names) = query_directory_file_id_both_names(
        &mut s,
        5,
        session_id,
        tree_id,
        dir_id,
        QueryDirectoryRequest::FLAG_RESTART_SCANS,
        0,
        1024,
        "*",
    )
    .await;
    assert_eq!(status, STATUS_SUCCESS);
    assert_eq!(names, vec![".", ".."]);

    assert_eq!(
        send_close_request(&mut s, 6, session_id, tree_id, dir_id).await,
        STATUS_SUCCESS
    );
    handle.abort();
}

#[tokio::test]
async fn open_if_existing_readonly_file_does_not_request_backend_write() {
    const GENERIC_READ: u32 = 0x8000_0000;
    const FILE_OPEN_IF: u32 = 0x0000_0003;
    const FILE_NON_DIRECTORY_FILE: u32 = 0x0000_0040;

    let td = tempdir().expect("tempdir");
    let path = td.path().join("hello.txt");
    std::fs::write(&path, b"hello").expect("write hello");
    let mut perms = std::fs::metadata(&path).expect("metadata").permissions();
    perms.set_readonly(true);
    std::fs::set_permissions(&path, perms).expect("make readonly");

    let (handle, mut s, session_id, tree_id) = start_localfs_session(td.path()).await;

    let (hdr, create) = send_create_request(
        &mut s,
        4,
        session_id,
        tree_id,
        create_request(
            "hello.txt",
            GENERIC_READ,
            FILE_ATTRIBUTE_ARCHIVE,
            FILE_OPEN_IF,
            FILE_NON_DIRECTORY_FILE,
        ),
    )
    .await;
    assert_eq!(hdr.channel_sequence_status, STATUS_SUCCESS);
    let file_id = create.expect("create response").file_id;

    let (status, data) =
        read_localfs_path_status(&mut s, session_id, tree_id, 5, file_id, 5, 0, 0).await;
    assert_eq!(status, STATUS_SUCCESS);
    assert_eq!(data, Some(b"hello".to_vec()));
    assert_eq!(
        send_close_request(&mut s, 6, session_id, tree_id, file_id).await,
        STATUS_SUCCESS
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let mut perms = std::fs::metadata(&path).expect("metadata").permissions();
        perms.set_mode(perms.mode() | 0o600);
        std::fs::set_permissions(&path, perms).expect("restore writable");
    }
    #[cfg(not(unix))]
    {
        let mut perms = std::fs::metadata(&path).expect("metadata").permissions();
        perms.set_readonly(false);
        std::fs::set_permissions(&path, perms).expect("restore writable");
    }
    handle.abort();
}

#[tokio::test]
async fn read_write_reject_payloads_above_negotiated_maximum() {
    let td = tempdir().expect("tempdir");
    std::fs::write(td.path().join("hello.txt"), b"hello").expect("write hello");

    let backend = LocalFsBackend::new(td.path()).expect("open root");
    let server = SmbServer::builder()
        .listen("127.0.0.1:0".parse().unwrap())
        .share(Share::new("share", backend).public())
        .netbios_name("TESTSERVER")
        .max_read_size(4)
        .max_write_size(4)
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

    let read_id = open_localfs_path(
        &mut s,
        session_id,
        tree_id,
        4,
        "hello.txt",
        0x0000_0001,
        0x0000_0040,
    )
    .await;
    let (status, data) =
        read_localfs_path_status(&mut s, session_id, tree_id, 5, read_id, 5, 0, 0).await;
    assert_eq!(status, STATUS_INVALID_PARAMETER);
    assert!(data.is_none());

    let write_id = open_localfs_path(
        &mut s,
        session_id,
        tree_id,
        6,
        "hello.txt",
        0x0000_0002,
        0x0000_0040,
    )
    .await;
    let status =
        write_localfs_path_status(&mut s, session_id, tree_id, 7, write_id, 0, b"hello").await;
    assert_eq!(status, STATUS_INVALID_PARAMETER);
    assert_eq!(
        std::fs::read(td.path().join("hello.txt")).expect("read hello"),
        b"hello"
    );

    assert_eq!(
        send_close_request(&mut s, 8, session_id, tree_id, read_id).await,
        STATUS_SUCCESS
    );
    assert_eq!(
        send_close_request(&mut s, 9, session_id, tree_id, write_id).await,
        STATUS_SUCCESS
    );
    handle.abort();
}

#[tokio::test]
async fn write_enforces_open_access_and_updates_current_offset() {
    let td = tempdir().expect("tempdir");
    std::fs::write(td.path().join("hello.txt"), b"hello").expect("write hello");
    std::fs::write(td.path().join("append.txt"), b"hello").expect("write append");

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

    let read_only = open_localfs_path(
        &mut s,
        session_id,
        tree_id,
        4,
        "hello.txt",
        0x0000_0001,
        0x0000_0040,
    )
    .await;
    let status =
        write_localfs_path_status(&mut s, session_id, tree_id, 5, read_only, 0, b"x").await;
    assert_eq!(status, 0xC000_0022);
    assert_eq!(
        std::fs::read(td.path().join("hello.txt")).unwrap(),
        b"hello"
    );

    let append_id = open_localfs_path(
        &mut s,
        session_id,
        tree_id,
        6,
        "append.txt",
        0x0000_0084,
        0x0000_0040,
    )
    .await;
    let status =
        write_localfs_path_status(&mut s, session_id, tree_id, 7, append_id, 1, b"XYZ").await;
    assert_eq!(status, STATUS_SUCCESS);
    assert_eq!(
        std::fs::read(td.path().join("append.txt")).unwrap(),
        b"hXYZo"
    );

    let query_all_req = QueryInfoRequest {
        structure_size: 41,
        info_type: InfoType::File as u8,
        file_information_class: 0x12,
        output_buffer_length: 4096,
        input_buffer_offset: 0,
        reserved: 0,
        input_buffer_length: 0,
        additional_information: 0,
        flags: 0,
        file_id: append_id,
        input_buffer: vec![],
    };
    let mut body = Vec::new();
    query_all_req.write_to(&mut body).expect("write");
    let hdr = build_header(Command::QueryInfo, 8, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::QueryInfo);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let query_all_resp = QueryInfoResponse::parse(rb).expect("parse all-info resp");
    assert_eq!(
        u64::from_le_bytes(query_all_resp.buffer[80..88].try_into().unwrap()),
        4
    );

    for (message_id, file_id) in [(9, read_only), (10, append_id)] {
        let close_req = CloseRequest {
            structure_size: 24,
            flags: 0,
            reserved: 0,
            file_id,
        };
        let mut body = Vec::new();
        close_req.write_to(&mut body).expect("write");
        let hdr = build_header(Command::Close, message_id, session_id, tree_id);
        write_frame(&mut s, &hdr, &body).await;
        let resp = read_frame(&mut s).await;
        let (rh, rb) = parse_response_header(&resp);
        assert_eq!(rh.command, Command::Close);
        assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
        let _ = CloseResponse::parse(rb).expect("parse close resp");
    }

    handle.abort();
}

#[tokio::test]
async fn transport_dispatches_pipelined_reads_concurrently() {
    let content = b"0123456789abcdef".repeat(4096);
    let backend = DelayedBackend::new(Duration::from_millis(75), Duration::ZERO)
        .with_file("large.bin", content.clone());
    let metrics = backend.metrics.clone();
    let (handle, mut s, session_id, tree_id) = start_delayed_session(backend).await;
    let file_id = open_localfs_path(
        &mut s,
        session_id,
        tree_id,
        4,
        "large.bin",
        0x0000_0001,
        0x0000_0040,
    )
    .await;

    const REQUEST_COUNT: usize = 4;
    const CHUNK_SIZE: usize = 16 * 1024;
    for i in 0..REQUEST_COUNT {
        let req = read_request(file_id, CHUNK_SIZE as u32, (i * CHUNK_SIZE) as u64);
        let mut body = Vec::new();
        req.write_to(&mut body).expect("write read");
        let hdr = build_header(Command::Read, 5 + i as u64, session_id, tree_id);
        write_frame(&mut s, &hdr, &body).await;
    }

    let mut responses = std::collections::HashMap::new();
    for _ in 0..REQUEST_COUNT {
        let resp = tokio::time::timeout(Duration::from_secs(2), read_frame(&mut s))
            .await
            .expect("read response");
        let (rh, rb) = parse_response_header(&resp);
        assert_eq!(rh.command, Command::Read);
        assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
        responses.insert(
            rh.message_id,
            ReadResponse::parse(rb).expect("parse read").data,
        );
    }

    for i in 0..REQUEST_COUNT {
        let message_id = 5 + i as u64;
        assert_eq!(
            responses.get(&message_id).map(Vec::as_slice),
            Some(&content[i * CHUNK_SIZE..(i + 1) * CHUNK_SIZE])
        );
    }
    assert!(
        metrics.max_reads.load(Ordering::SeqCst) >= 2,
        "pipelined reads did not overlap"
    );

    assert_eq!(
        send_close_request(&mut s, 20, session_id, tree_id, file_id).await,
        STATUS_SUCCESS
    );
    handle.abort();
}

#[tokio::test]
async fn transport_dispatches_pipelined_writes_with_per_open_serialization() {
    let backend = DelayedBackend::new(Duration::ZERO, Duration::from_millis(75))
        .with_file("same.bin", vec![0; 64 * 1024])
        .with_file("left.bin", vec![0; 16 * 1024])
        .with_file("right.bin", vec![0; 16 * 1024]);
    let metrics = backend.metrics.clone();
    let (handle, mut s, session_id, tree_id) = start_delayed_session(backend).await;
    let same = open_localfs_path(
        &mut s,
        session_id,
        tree_id,
        4,
        "same.bin",
        0x0000_0002,
        0x0000_0040,
    )
    .await;
    let left = open_localfs_path(
        &mut s,
        session_id,
        tree_id,
        5,
        "left.bin",
        0x0000_0002,
        0x0000_0040,
    )
    .await;
    let right = open_localfs_path(
        &mut s,
        session_id,
        tree_id,
        6,
        "right.bin",
        0x0000_0002,
        0x0000_0040,
    )
    .await;

    let write_specs = [
        (same, 0, b'a', 7),
        (same, 16 * 1024, b'b', 8),
        (left, 0, b'c', 9),
        (right, 0, b'd', 10),
    ];
    let write_count = write_specs.len();
    for (file_id, offset, byte, message_id) in write_specs {
        let data = vec![byte; 16 * 1024];
        let req = write_request(file_id, offset, &data);
        let mut body = Vec::new();
        req.write_to(&mut body).expect("write request");
        let hdr = build_header(Command::Write, message_id, session_id, tree_id);
        write_frame(&mut s, &hdr, &body).await;
    }

    for _ in 0..write_count {
        let resp = tokio::time::timeout(Duration::from_secs(2), read_frame(&mut s))
            .await
            .expect("write response");
        let (rh, rb) = parse_response_header(&resp);
        assert_eq!(rh.command, Command::Write);
        assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
        let write = smb_server::wire::messages::WriteResponse::parse(rb).expect("parse write");
        assert_eq!(write.count, 16 * 1024);
    }

    assert!(
        metrics.max_writes.load(Ordering::SeqCst) >= 2,
        "writes to independent handles did not overlap"
    );
    assert_eq!(
        metrics.max_writes_for("same.bin"),
        1,
        "writes to one open handle must stay serialized"
    );

    for (message_id, file_id) in [(20, same), (21, left), (22, right)] {
        assert_eq!(
            send_close_request(&mut s, message_id, session_id, tree_id, file_id).await,
            STATUS_SUCCESS
        );
    }
    handle.abort();
}

#[tokio::test]
async fn transport_invalid_frame_disconnects_non_durable_handles() {
    let td = tempdir().expect("tempdir");
    std::fs::write(td.path().join("large.bin"), b"hello").expect("write large.bin");

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

    let mut first = TcpStream::connect(addr).await.expect("connect first");
    let _ = negotiate(&mut first).await;
    let first_session_id = anonymous_session_setup(&mut first).await;
    let first_tree_id = tree_connect(&mut first, "\\\\127.0.0.1\\share", first_session_id, 3).await;
    let mut exclusive_req = create_request("large.bin", 0x0000_0001, 0, 1, 0x0000_0040);
    exclusive_req.share_access = 0;
    let (rh, first_open) = send_create_request(
        &mut first,
        4,
        first_session_id,
        first_tree_id,
        exclusive_req,
    )
    .await;
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    assert!(first_open.is_some());

    let mut second = TcpStream::connect(addr).await.expect("connect second");
    let _ = negotiate(&mut second).await;
    let second_session_id = anonymous_session_setup(&mut second).await;
    let second_tree_id =
        tree_connect(&mut second, "\\\\127.0.0.1\\share", second_session_id, 3).await;
    let (rh, blocked) = send_create_request(
        &mut second,
        4,
        second_session_id,
        second_tree_id,
        create_request("large.bin", 0x0000_0001, 0, 1, 0x0000_0040),
    )
    .await;
    assert_eq!(rh.channel_sequence_status, STATUS_SHARING_VIOLATION);
    assert!(blocked.is_none());

    let mut invalid = Vec::new();
    encode_frame(&[0xff], &mut invalid);
    first
        .write_all(&invalid)
        .await
        .expect("write invalid frame");
    let mut eof = [0u8; 1];
    let n = tokio::time::timeout(Duration::from_secs(1), first.read(&mut eof))
        .await
        .expect("invalid frame should close connection")
        .expect("read eof");
    assert_eq!(n, 0);

    let (rh, reopened) = send_create_request(
        &mut second,
        5,
        second_session_id,
        second_tree_id,
        create_request("large.bin", 0x0000_0001, 0, 1, 0x0000_0040),
    )
    .await;
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let reopened_id = reopened.expect("reopened after invalid frame").file_id;
    assert_eq!(
        send_close_request(
            &mut second,
            6,
            second_session_id,
            second_tree_id,
            reopened_id
        )
        .await,
        STATUS_SUCCESS
    );

    handle.abort();
}

#[tokio::test]
async fn read_eof_and_minimum_count_match_gosmb() {
    let td = tempdir().expect("tempdir");
    std::fs::write(td.path().join("hello.txt"), b"hello").expect("write hello");

    let (handle, mut s, session_id, tree_id) = start_localfs_session(td.path()).await;
    let file_id = open_localfs_path(
        &mut s,
        session_id,
        tree_id,
        4,
        "hello.txt",
        0x0000_0001,
        0x0000_0040,
    )
    .await;

    let (status, data) =
        read_localfs_path_status(&mut s, session_id, tree_id, 5, file_id, 0, 0, 5).await;
    assert_eq!(status, STATUS_SUCCESS);
    assert_eq!(data, Some(Vec::new()));

    let (status, data) =
        read_localfs_path_status(&mut s, session_id, tree_id, 6, file_id, 1, 0, 5).await;
    assert_eq!(status, STATUS_END_OF_FILE);
    assert!(data.is_none());

    let (status, data) =
        read_localfs_path_status(&mut s, session_id, tree_id, 7, file_id, 0, 1, 5).await;
    assert_eq!(status, STATUS_END_OF_FILE);
    assert!(data.is_none());

    let (status, data) =
        read_localfs_path_status(&mut s, session_id, tree_id, 8, file_id, 2, 2, 4).await;
    assert_eq!(status, STATUS_END_OF_FILE);
    assert!(data.is_none());

    let (status, data) =
        read_localfs_path_status(&mut s, session_id, tree_id, 9, file_id, 1, 10, 0).await;
    assert_eq!(status, STATUS_END_OF_FILE);
    assert!(data.is_none());

    assert_eq!(
        send_close_request(&mut s, 10, session_id, tree_id, file_id).await,
        STATUS_SUCCESS
    );
    handle.abort();
}

#[tokio::test]
async fn read_rejects_invalid_offsets_and_channel_info() {
    let td = tempdir().expect("tempdir");
    std::fs::write(td.path().join("hello.txt"), b"hello").expect("write hello");

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
    let file_id = open_localfs_path(
        &mut s,
        session_id,
        tree_id,
        4,
        "hello.txt",
        0x0000_0001,
        0x0000_0040,
    )
    .await;
    const MAX_INT64_OFFSET: u64 = (1u64 << 63) - 1;

    let (status, _) = read_localfs_path_status(
        &mut s,
        session_id,
        tree_id,
        5,
        file_id,
        0,
        0,
        MAX_INT64_OFFSET,
    )
    .await;
    assert_eq!(status, STATUS_SUCCESS);
    let (status, _) = read_localfs_path_status(
        &mut s,
        session_id,
        tree_id,
        6,
        file_id,
        1,
        0,
        MAX_INT64_OFFSET,
    )
    .await;
    assert_eq!(status, 0xC000_000D);
    let (status, _) = read_localfs_path_status(
        &mut s,
        session_id,
        tree_id,
        7,
        file_id,
        0,
        0,
        MAX_INT64_OFFSET + 1,
    )
    .await;
    assert_eq!(status, 0xC000_000D);

    let status = read_localfs_custom_status(
        &mut s,
        session_id,
        tree_id,
        8,
        ReadRequest {
            channel: 1,
            ..read_request(file_id, 1, 0)
        },
    )
    .await;
    assert_eq!(status, 0xC000_000D);
    let status = read_localfs_custom_status(
        &mut s,
        session_id,
        tree_id,
        9,
        ReadRequest {
            read_channel_info_length: 8,
            ..read_request(file_id, 1, 0)
        },
    )
    .await;
    assert_eq!(status, 0xC000_000D);

    let close_req = CloseRequest {
        structure_size: 24,
        flags: 0,
        reserved: 0,
        file_id,
    };
    let mut body = Vec::new();
    close_req.write_to(&mut body).expect("write");
    let hdr = build_header(Command::Close, 10, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Close);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let _ = CloseResponse::parse(rb).expect("parse close resp");

    handle.abort();
}

#[tokio::test]
async fn write_rejects_invalid_offsets_and_channel_info() {
    let td = tempdir().expect("tempdir");
    std::fs::write(td.path().join("hello.txt"), b"hello").expect("write hello");

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
    let file_id = open_localfs_path(
        &mut s,
        session_id,
        tree_id,
        4,
        "hello.txt",
        0x0000_0002,
        0x0000_0040,
    )
    .await;
    const MAX_INT64_OFFSET: u64 = (1u64 << 63) - 1;
    const MAX_SMB_FILE_SIZE: u64 = 0x0fff_ffff_0000;

    let status = write_localfs_path_status(
        &mut s,
        session_id,
        tree_id,
        5,
        file_id,
        MAX_INT64_OFFSET,
        &[],
    )
    .await;
    assert_eq!(status, STATUS_SUCCESS);
    let status = write_localfs_path_status(
        &mut s,
        session_id,
        tree_id,
        6,
        file_id,
        MAX_INT64_OFFSET,
        &[1],
    )
    .await;
    assert_eq!(status, 0xC000_000D);
    let status = write_localfs_path_status(
        &mut s,
        session_id,
        tree_id,
        7,
        file_id,
        MAX_INT64_OFFSET + 1,
        &[],
    )
    .await;
    assert_eq!(status, 0xC000_000D);
    let status = write_localfs_path_status(
        &mut s,
        session_id,
        tree_id,
        8,
        file_id,
        MAX_SMB_FILE_SIZE,
        &[1],
    )
    .await;
    assert_eq!(status, 0xC000_000D);
    let status = write_localfs_path_status(
        &mut s,
        session_id,
        tree_id,
        9,
        file_id,
        MAX_SMB_FILE_SIZE - 1,
        &[1],
    )
    .await;
    assert_eq!(status, 0xC000_007F);

    let status = write_localfs_custom_status(
        &mut s,
        session_id,
        tree_id,
        10,
        smb_server::wire::messages::WriteRequest {
            channel: 1,
            ..write_request(file_id, 0, &[1])
        },
    )
    .await;
    assert_eq!(status, 0xC000_000D);
    let status = write_localfs_custom_status(
        &mut s,
        session_id,
        tree_id,
        11,
        smb_server::wire::messages::WriteRequest {
            write_channel_info_length: 8,
            ..write_request(file_id, 0, &[1])
        },
    )
    .await;
    assert_eq!(status, 0xC000_000D);

    let close_req = CloseRequest {
        structure_size: 24,
        flags: 0,
        reserved: 0,
        file_id,
    };
    let mut body = Vec::new();
    close_req.write_to(&mut body).expect("write");
    let hdr = build_header(Command::Close, 12, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Close);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let _ = CloseResponse::parse(rb).expect("parse close resp");

    handle.abort();
}

async fn open_localfs_path(
    s: &mut TcpStream,
    session_id: u64,
    tree_id: u32,
    message_id: u64,
    name: &str,
    desired_access: u32,
    create_options: u32,
) -> FileId {
    let name = utf16le(name);
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
        create_disposition: 1,
        create_options,
        name_offset: 0x78,
        name_length: name.len() as u16,
        create_contexts_offset: 0,
        create_contexts_length: 0,
        name,
        create_contexts: vec![],
    };
    let mut body = Vec::new();
    req.write_to(&mut body).expect("write");
    let hdr = build_header(Command::Create, message_id, session_id, tree_id);
    write_frame(s, &hdr, &body).await;
    let resp = read_frame(s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Create);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    CreateResponse::parse(rb)
        .expect("parse create resp")
        .file_id
}

async fn read_localfs_path_status(
    s: &mut TcpStream,
    session_id: u64,
    tree_id: u32,
    message_id: u64,
    file_id: FileId,
    length: u32,
    minimum_count: u32,
    offset: u64,
) -> (u32, Option<Vec<u8>>) {
    let req = read_request(file_id, length, offset);
    let req = ReadRequest {
        minimum_count,
        ..req
    };
    read_localfs_custom_status_with_data(s, session_id, tree_id, message_id, req).await
}

fn read_request(file_id: FileId, length: u32, offset: u64) -> ReadRequest {
    ReadRequest {
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
    }
}

async fn read_localfs_custom_status(
    s: &mut TcpStream,
    session_id: u64,
    tree_id: u32,
    message_id: u64,
    req: ReadRequest,
) -> u32 {
    read_localfs_custom_status_with_data(s, session_id, tree_id, message_id, req)
        .await
        .0
}

async fn read_localfs_custom_status_with_data(
    s: &mut TcpStream,
    session_id: u64,
    tree_id: u32,
    message_id: u64,
    req: ReadRequest,
) -> (u32, Option<Vec<u8>>) {
    let mut body = Vec::new();
    req.write_to(&mut body).expect("write");
    let hdr = build_header(Command::Read, message_id, session_id, tree_id);
    write_frame(s, &hdr, &body).await;
    let resp = read_frame(s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Read);
    if rh.channel_sequence_status == STATUS_SUCCESS {
        (
            rh.channel_sequence_status,
            Some(ReadResponse::parse(rb).expect("parse read resp").data),
        )
    } else {
        (rh.channel_sequence_status, None)
    }
}

fn write_request(
    file_id: FileId,
    offset: u64,
    data: &[u8],
) -> smb_server::wire::messages::WriteRequest {
    smb_server::wire::messages::WriteRequest {
        structure_size: 49,
        data_offset: smb_server::wire::messages::WriteRequest::STANDARD_DATA_OFFSET,
        length: data.len() as u32,
        offset,
        file_id,
        channel: 0,
        remaining_bytes: 0,
        write_channel_info_offset: 0,
        write_channel_info_length: 0,
        flags: 0,
        data: if data.is_empty() {
            vec![0]
        } else {
            data.to_vec()
        },
    }
}

async fn write_localfs_path_status(
    s: &mut TcpStream,
    session_id: u64,
    tree_id: u32,
    message_id: u64,
    file_id: FileId,
    offset: u64,
    data: &[u8],
) -> u32 {
    write_localfs_custom_status(
        s,
        session_id,
        tree_id,
        message_id,
        write_request(file_id, offset, data),
    )
    .await
}

async fn write_localfs_custom_status(
    s: &mut TcpStream,
    session_id: u64,
    tree_id: u32,
    message_id: u64,
    req: smb_server::wire::messages::WriteRequest,
) -> u32 {
    let mut body = Vec::new();
    req.write_to(&mut body).expect("write");
    let hdr = build_header(Command::Write, message_id, session_id, tree_id);
    write_frame(s, &hdr, &body).await;
    let resp = read_frame(s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Write);
    if rh.channel_sequence_status == STATUS_SUCCESS {
        let _ = smb_server::wire::messages::WriteResponse::parse(rb).expect("parse write resp");
    }
    rh.channel_sequence_status
}

async fn create_localfs_path_status(
    s: &mut TcpStream,
    session_id: u64,
    tree_id: u32,
    message_id: u64,
    name: &str,
    desired_access: u32,
    create_disposition: u32,
    create_options: u32,
) -> (u32, Option<FileId>) {
    let name = utf16le(name);
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
    req.write_to(&mut body).expect("write");
    let hdr = build_header(Command::Create, message_id, session_id, tree_id);
    write_frame(s, &hdr, &body).await;
    let resp = read_frame(s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Create);
    if rh.channel_sequence_status == STATUS_SUCCESS {
        (
            rh.channel_sequence_status,
            Some(
                CreateResponse::parse(rb)
                    .expect("parse create resp")
                    .file_id,
            ),
        )
    } else {
        (rh.channel_sequence_status, None)
    }
}

async fn set_localfs_security_descriptor(
    s: &mut TcpStream,
    session_id: u64,
    tree_id: u32,
    message_id: u64,
    file_id: FileId,
    descriptor: Vec<u8>,
) {
    let req = SetInfoRequest {
        structure_size: 33,
        info_type: InfoType::Security as u8,
        file_information_class: 0,
        buffer_length: descriptor.len() as u32,
        buffer_offset: 64 + 32,
        reserved: 0,
        additional_information: 0,
        file_id,
        buffer: descriptor,
    };
    let mut body = Vec::new();
    req.write_to(&mut body).expect("write");
    let hdr = build_header(Command::SetInfo, message_id, session_id, tree_id);
    write_frame(s, &hdr, &body).await;
    let resp = read_frame(s).await;
    let (rh, _rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::SetInfo);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
}

async fn set_full_ea_information_status(
    s: &mut TcpStream,
    message_id: u64,
    session_id: u64,
    tree_id: u32,
    file_id: FileId,
    buffer: Vec<u8>,
) -> u32 {
    let req = SetInfoRequest {
        structure_size: 33,
        info_type: InfoType::File as u8,
        file_information_class: 0x0F,
        buffer_length: buffer.len() as u32,
        buffer_offset: 64 + 32,
        reserved: 0,
        additional_information: 0,
        file_id,
        buffer,
    };
    let mut body = Vec::new();
    req.write_to(&mut body).expect("write full EA set-info");
    let hdr = build_header(Command::SetInfo, message_id, session_id, tree_id);
    write_frame(s, &hdr, &body).await;
    let resp = read_frame(s).await;
    let (rh, _rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::SetInfo);
    rh.channel_sequence_status
}

fn empty_dacl_security_descriptor() -> Vec<u8> {
    let mut sd = vec![0; 28];
    sd[0] = 1;
    sd[2..4].copy_from_slice(&0x8004u16.to_le_bytes());
    sd[16..20].copy_from_slice(&20u32.to_le_bytes());
    sd[20] = 2;
    sd[22..24].copy_from_slice(&8u16.to_le_bytes());
    sd
}

fn security_descriptor_without_dacl() -> Vec<u8> {
    let mut sd = vec![0; 20];
    sd[0] = 1;
    sd[2..4].copy_from_slice(&0x8000u16.to_le_bytes());
    sd
}

fn nil_dacl_security_descriptor() -> Vec<u8> {
    let mut sd = vec![0; 20];
    sd[0] = 1;
    sd[2..4].copy_from_slice(&0x8004u16.to_le_bytes());
    sd
}

fn security_descriptor_with_ace(ace_type: u8, ace_flags: u8, mask: u32) -> Vec<u8> {
    security_descriptor_with_aces(&[(ace_type, ace_flags, mask)])
}

fn security_descriptor_with_aces(aces: &[(u8, u8, u32)]) -> Vec<u8> {
    let everyone = [
        0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
    ];

    let mut ace_bytes = Vec::new();
    for (ace_type, ace_flags, mask) in aces {
        ace_bytes.extend_from_slice(&[*ace_type, *ace_flags]);
        ace_bytes.extend_from_slice(&(8 + everyone.len() as u16).to_le_bytes());
        ace_bytes.extend_from_slice(&mask.to_le_bytes());
        ace_bytes.extend_from_slice(&everyone);
    }

    let mut dacl = Vec::new();
    dacl.extend_from_slice(&[0x02, 0x00]);
    dacl.extend_from_slice(&(8 + ace_bytes.len() as u16).to_le_bytes());
    dacl.extend_from_slice(&(aces.len() as u16).to_le_bytes());
    dacl.extend_from_slice(&0u16.to_le_bytes());
    dacl.extend_from_slice(&ace_bytes);

    let mut sd = Vec::new();
    sd.extend_from_slice(&[0x01, 0x00]);
    sd.extend_from_slice(&0x8004u16.to_le_bytes());
    sd.extend_from_slice(&20u32.to_le_bytes());
    sd.extend_from_slice(&0u32.to_le_bytes());
    sd.extend_from_slice(&0u32.to_le_bytes());
    sd.extend_from_slice(&(20 + everyone.len() as u32).to_le_bytes());
    sd.extend_from_slice(&everyone);
    sd.extend_from_slice(&dacl);
    sd
}

fn minimal_self_relative_security_descriptor() -> Vec<u8> {
    let everyone = [
        0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
    ];

    let mut ace = Vec::new();
    ace.extend_from_slice(&[0x00, 0x00]);
    ace.extend_from_slice(&(20u16).to_le_bytes());
    ace.extend_from_slice(&0x001F_01FFu32.to_le_bytes());
    ace.extend_from_slice(&everyone);

    let mut dacl = Vec::new();
    dacl.extend_from_slice(&[0x02, 0x00]);
    dacl.extend_from_slice(&(8 + ace.len() as u16).to_le_bytes());
    dacl.extend_from_slice(&1u16.to_le_bytes());
    dacl.extend_from_slice(&0u16.to_le_bytes());
    dacl.extend_from_slice(&ace);

    let mut sd = Vec::new();
    sd.extend_from_slice(&[0x01, 0x00]);
    sd.extend_from_slice(&0x8004u16.to_le_bytes());
    sd.extend_from_slice(&20u32.to_le_bytes());
    sd.extend_from_slice(&0u32.to_le_bytes());
    sd.extend_from_slice(&0u32.to_le_bytes());
    sd.extend_from_slice(&32u32.to_le_bytes());
    sd.extend_from_slice(&everyone);
    sd.extend_from_slice(&dacl);
    sd
}

fn full_ea_information(name: &str, value: &[u8]) -> Vec<u8> {
    full_ea_information_list(&[(name, value)])
}

fn full_ea_information_list(records: &[(&str, &[u8])]) -> Vec<u8> {
    let mut out = Vec::new();
    for (idx, (name, value)) in records.iter().enumerate() {
        let name_bytes = name.as_bytes();
        let size = 8 + name_bytes.len() + 1 + value.len();
        let padded = (size + 3) & !3;
        let start = out.len();
        out.resize(start + padded, 0);
        let record = &mut out[start..start + padded];
        if idx + 1 < records.len() {
            record[0..4].copy_from_slice(&(padded as u32).to_le_bytes());
        }
        record[5] = name_bytes.len() as u8;
        record[6..8].copy_from_slice(&(value.len() as u16).to_le_bytes());
        record[8..8 + name_bytes.len()].copy_from_slice(name_bytes);
        record[8 + name_bytes.len()] = 0;
        record[8 + name_bytes.len() + 1..8 + name_bytes.len() + 1 + value.len()]
            .copy_from_slice(value);
    }
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

fn file_rename_information_ex(name: &str, flags: u32) -> Vec<u8> {
    let name = utf16le(name);
    let mut out = Vec::with_capacity(20 + name.len());
    out.extend_from_slice(&flags.to_le_bytes());
    out.extend_from_slice(&[0; 12]);
    out.extend_from_slice(&(name.len() as u32).to_le_bytes());
    out.extend_from_slice(&name);
    out
}

fn decode_stream_information(mut buf: &[u8]) -> Vec<(String, u64)> {
    let mut out = Vec::new();
    if buf.is_empty() {
        return out;
    }
    loop {
        assert!(buf.len() >= 24, "short FileStreamInformation entry");
        let next = u32::from_le_bytes(buf[0..4].try_into().unwrap()) as usize;
        let name_len = u32::from_le_bytes(buf[4..8].try_into().unwrap()) as usize;
        let size = u64::from_le_bytes(buf[8..16].try_into().unwrap());
        assert!(buf.len() >= 24 + name_len, "short stream name");
        let units: Vec<u16> = buf[24..24 + name_len]
            .chunks_exact(2)
            .map(|b| u16::from_le_bytes([b[0], b[1]]))
            .collect();
        out.push((String::from_utf16(&units).expect("utf16 stream name"), size));
        if next == 0 {
            break;
        }
        assert!(buf.len() >= next, "invalid stream next offset");
        buf = &buf[next..];
    }
    out
}

fn decode_file_name_information(buf: &[u8]) -> String {
    assert!(buf.len() >= 4, "short FileNameInformation");
    let name_len = u32::from_le_bytes(buf[0..4].try_into().unwrap()) as usize;
    assert!(buf.len() >= 4 + name_len, "short file name");
    let units: Vec<u16> = buf[4..4 + name_len]
        .chunks_exact(2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
        .collect();
    String::from_utf16(&units).expect("utf16 file name")
}

fn decode_file_all_information_name(buf: &[u8]) -> String {
    const FILE_ALL_INFORMATION_NAME_OFFSET: usize = 96;
    assert!(
        buf.len() >= FILE_ALL_INFORMATION_NAME_OFFSET + 4,
        "short FileAllInformation"
    );
    decode_file_name_information(&buf[FILE_ALL_INFORMATION_NAME_OFFSET..])
}

fn decode_file_id_both_names(mut buf: &[u8]) -> Vec<String> {
    let mut names = Vec::new();
    loop {
        assert!(
            buf.len() >= 104,
            "short FileIdBothDirectoryInformation entry"
        );
        let next = u32::from_le_bytes(buf[0..4].try_into().unwrap()) as usize;
        let name_len = u32::from_le_bytes(buf[60..64].try_into().unwrap()) as usize;
        let name_start = 104;
        let name_end = name_start + name_len;
        assert!(buf.len() >= name_end, "short file name");
        let units: Vec<u16> = buf[name_start..name_end]
            .chunks_exact(2)
            .map(|b| u16::from_le_bytes([b[0], b[1]]))
            .collect();
        names.push(String::from_utf16(&units).expect("utf16 name"));
        if next == 0 {
            break;
        }
        assert!(buf.len() >= next, "invalid NextEntryOffset");
        buf = &buf[next..];
    }
    names
}

fn decode_file_id_both_entries(mut buf: &[u8]) -> Vec<(String, u32)> {
    let mut entries = Vec::new();
    loop {
        assert!(
            buf.len() >= 104,
            "short FileIdBothDirectoryInformation entry"
        );
        let next = u32::from_le_bytes(buf[0..4].try_into().unwrap()) as usize;
        let attrs = u32::from_le_bytes(buf[56..60].try_into().unwrap());
        let name_len = u32::from_le_bytes(buf[60..64].try_into().unwrap()) as usize;
        let name_start = 104;
        let name_end = name_start + name_len;
        assert!(buf.len() >= name_end, "short file name");
        let units: Vec<u16> = buf[name_start..name_end]
            .chunks_exact(2)
            .map(|b| u16::from_le_bytes([b[0], b[1]]))
            .collect();
        entries.push((String::from_utf16(&units).expect("utf16 name"), attrs));
        if next == 0 {
            break;
        }
        assert!(buf.len() >= next, "invalid NextEntryOffset");
        buf = &buf[next..];
    }
    entries
}

fn decode_query_directory_names_for_class(mut buf: &[u8], class: u8) -> Vec<String> {
    let (name_len_offset, name_offset) = query_directory_name_offsets(class);
    let mut names = Vec::new();
    loop {
        assert!(
            buf.len() >= name_offset,
            "short query directory class 0x{class:02x} entry"
        );
        let next = u32::from_le_bytes(buf[0..4].try_into().unwrap()) as usize;
        let name_len = u32::from_le_bytes(
            buf[name_len_offset..name_len_offset + 4]
                .try_into()
                .unwrap(),
        ) as usize;
        let name_end = name_offset + name_len;
        assert!(buf.len() >= name_end, "short query directory name");
        let units: Vec<u16> = buf[name_offset..name_end]
            .chunks_exact(2)
            .map(|b| u16::from_le_bytes([b[0], b[1]]))
            .collect();
        names.push(String::from_utf16(&units).expect("utf16 query directory name"));
        if next == 0 {
            break;
        }
        assert!(buf.len() >= next, "invalid query directory next offset");
        buf = &buf[next..];
    }
    names
}

fn decode_query_directory_names_and_indexes_for_class(
    mut buf: &[u8],
    class: u8,
) -> Vec<(String, u32)> {
    let (name_len_offset, name_offset) = query_directory_name_offsets(class);
    let mut entries = Vec::new();
    loop {
        assert!(
            buf.len() >= name_offset,
            "short query directory class 0x{class:02x} entry"
        );
        let next = u32::from_le_bytes(buf[0..4].try_into().unwrap()) as usize;
        let file_index = u32::from_le_bytes(buf[4..8].try_into().unwrap());
        let name_len = u32::from_le_bytes(
            buf[name_len_offset..name_len_offset + 4]
                .try_into()
                .unwrap(),
        ) as usize;
        let name_end = name_offset + name_len;
        assert!(buf.len() >= name_end, "short query directory name");
        let units: Vec<u16> = buf[name_offset..name_end]
            .chunks_exact(2)
            .map(|b| u16::from_le_bytes([b[0], b[1]]))
            .collect();
        entries.push((
            String::from_utf16(&units).expect("utf16 query directory name"),
            file_index,
        ));
        if next == 0 {
            break;
        }
        assert!(buf.len() >= next, "invalid query directory next offset");
        buf = &buf[next..];
    }
    entries
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DirectoryCommonMetadata {
    creation_time: u64,
    last_access_time: u64,
    last_write_time: u64,
    change_time: u64,
    end_of_file: u64,
    allocation_size: u64,
    attributes: u32,
}

fn query_info_metadata(buf: &[u8]) -> DirectoryCommonMetadata {
    assert!(buf.len() >= 64, "short FileAllInformation");
    DirectoryCommonMetadata {
        creation_time: u64::from_le_bytes(buf[0..8].try_into().unwrap()),
        last_access_time: u64::from_le_bytes(buf[8..16].try_into().unwrap()),
        last_write_time: u64::from_le_bytes(buf[16..24].try_into().unwrap()),
        change_time: u64::from_le_bytes(buf[24..32].try_into().unwrap()),
        attributes: u32::from_le_bytes(buf[32..36].try_into().unwrap()),
        allocation_size: u64::from_le_bytes(buf[40..48].try_into().unwrap()),
        end_of_file: u64::from_le_bytes(buf[48..56].try_into().unwrap()),
    }
}

fn query_directory_common_metadata(buf: &[u8]) -> DirectoryCommonMetadata {
    assert!(buf.len() >= 60, "short directory information entry");
    DirectoryCommonMetadata {
        creation_time: u64::from_le_bytes(buf[8..16].try_into().unwrap()),
        last_access_time: u64::from_le_bytes(buf[16..24].try_into().unwrap()),
        last_write_time: u64::from_le_bytes(buf[24..32].try_into().unwrap()),
        change_time: u64::from_le_bytes(buf[32..40].try_into().unwrap()),
        end_of_file: u64::from_le_bytes(buf[40..48].try_into().unwrap()),
        allocation_size: u64::from_le_bytes(buf[48..56].try_into().unwrap()),
        attributes: u32::from_le_bytes(buf[56..60].try_into().unwrap()),
    }
}

fn query_directory_file_id_offset(class: u8) -> Option<usize> {
    match class {
        0x25 => Some(96),
        0x26 | 0x3c | 0x4e | 0x4f | 0x50 | 0x51 => Some(72),
        _ => None,
    }
}

fn query_directory_name_offsets(class: u8) -> (usize, usize) {
    match class {
        0x01 => (60, 64),
        0x02 => (60, 68),
        0x03 => (60, 94),
        0x0c => (8, 12),
        0x25 => (60, 104),
        0x26 => (60, 80),
        0x3c => (60, 88),
        0x4e => (60, 80),
        0x4f => (60, 106),
        0x50 => (60, 96),
        0x51 => (60, 122),
        0x64 => (144, 148),
        _ => panic!("unsupported query directory class 0x{class:02x}"),
    }
}

fn posix_sid_id(buf: &[u8], kind: u32) -> u32 {
    assert!(buf.len() >= 20, "short POSIX SID");
    assert_eq!(buf[0], 1);
    assert_eq!(buf[1], 3);
    assert_eq!(buf[7], 5);
    assert_eq!(u32::from_le_bytes(buf[8..12].try_into().unwrap()), 88);
    assert_eq!(u32::from_le_bytes(buf[12..16].try_into().unwrap()), kind);
    u32::from_le_bytes(buf[16..20].try_into().unwrap())
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
