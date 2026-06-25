//! IPC$ named-pipe integration tests over the TCP dispatcher.

#[allow(dead_code)]
mod common;

use common::{
    anonymous_session_setup, build_header, negotiate, parse_response_header, read_frame, utf16le,
    write_frame,
};
use smb_server::wire::header::{Command, SMB2_FLAGS_ASYNC_COMMAND, Smb2Header};
use smb_server::wire::messages::{
    CancelRequest, CloseRequest, CloseResponse, CreateRequest, CreateResponse, FileId,
    FlushRequest, FlushResponse, Fsctl, IoctlRequest, IoctlResponse, ReadRequest, ReadResponse,
    TreeConnectRequest, TreeConnectResponse, TreeDisconnectRequest, TreeDisconnectResponse,
};
use smb_server::{LocalFsBackend, Share, SmbServer};
use tempfile::{TempDir, tempdir};
use tokio::net::TcpStream;

const STATUS_SUCCESS: u32 = 0x0000_0000;
const STATUS_PENDING: u32 = 0x0000_0103;
const STATUS_OBJECT_NAME_NOT_FOUND: u32 = 0xC000_0034;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_FS_DRIVER_REQUIRED: u32 = 0xC000_019C;
const STATUS_NOT_SUPPORTED: u32 = 0xC000_00BB;
const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;
const STATUS_CANCELLED: u32 = 0xC000_0120;
const STATUS_NOTIFY_CLEANUP: u32 = 0x0000_010B;
const GOSMB_MAX_PENDING_ASYNC_REQUESTS: u64 = 511;

fn pipe_create_request(name: &str) -> CreateRequest {
    let name = utf16le(name);
    CreateRequest {
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
    }
}

async fn start_ipc_server(max_credits: u16) -> (tokio::task::JoinHandle<()>, TempDir, TcpStream) {
    let td = tempdir().expect("tempdir");
    let backend = LocalFsBackend::new(td.path()).expect("open root");
    let server = SmbServer::builder()
        .listen("127.0.0.1:0".parse().unwrap())
        .netbios_name("TESTSERVER")
        .max_credits(max_credits)
        .share(Share::new("share", backend).public())
        .build()
        .expect("build");
    server.bind().await.expect("bind");
    let addr = server.local_addr().await.expect("addr");
    let handle = tokio::spawn(async move {
        let _ = server.serve().await;
    });
    tokio::task::yield_now().await;
    let stream = TcpStream::connect(addr).await.expect("connect");
    (handle, td, stream)
}

async fn open_pipe(
    s: &mut TcpStream,
    message_id: u64,
    session_id: u64,
    tree_id: u32,
    name: &str,
) -> FileId {
    let req = pipe_create_request(name);
    let mut body = Vec::new();
    req.write_to(&mut body).expect("write create");
    let hdr = build_header(Command::Create, message_id, session_id, tree_id);
    write_frame(s, &hdr, &body).await;
    let resp = read_frame(s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Create);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    CreateResponse::parse(rb)
        .expect("parse pipe create")
        .file_id
}

async fn open_pipe_status(
    s: &mut TcpStream,
    message_id: u64,
    session_id: u64,
    tree_id: u32,
    name: &str,
) -> (u32, Option<CreateResponse>) {
    let req = pipe_create_request(name);
    let mut body = Vec::new();
    req.write_to(&mut body).expect("write create");
    let hdr = build_header(Command::Create, message_id, session_id, tree_id);
    write_frame(s, &hdr, &body).await;
    let resp = read_frame(s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Create);
    let create = if rh.channel_sequence_status == STATUS_SUCCESS {
        Some(CreateResponse::parse(rb).expect("parse pipe create"))
    } else {
        None
    };
    (rh.channel_sequence_status, create)
}

async fn tree_connect_ipc(s: &mut TcpStream, session_id: u64, message_id: u64) -> u32 {
    let (tree_id, tree) =
        tree_connect_response(s, "\\\\127.0.0.1\\IPC$", session_id, message_id).await;
    assert_eq!(tree.share_type, TreeConnectResponse::SHARE_TYPE_PIPE);
    tree_id
}

async fn tree_connect_response(
    s: &mut TcpStream,
    path: &str,
    session_id: u64,
    message_id: u64,
) -> (u32, TreeConnectResponse) {
    let path = utf16le(path);
    let req = TreeConnectRequest {
        structure_size: 9,
        flags: 0,
        path_offset: 64 + 8,
        path_length: path.len() as u16,
        path,
    };
    let mut body = Vec::new();
    req.write_to(&mut body).expect("write tree connect");
    let hdr = build_header(Command::TreeConnect, message_id, session_id, 0);
    write_frame(s, &hdr, &body).await;
    let resp = read_frame(s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::TreeConnect);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let tree_id = rh.tree_id().expect("tree id");
    assert_ne!(tree_id, 0);
    let tree = TreeConnectResponse::parse(rb).expect("parse tree connect");
    (tree_id, tree)
}

#[tokio::test]
async fn tree_connect_disk_and_ipc_response_types_and_flags() {
    let (handle, _td, mut s) = start_ipc_server(16).await;
    let _ = negotiate(&mut s).await;
    let session_id = anonymous_session_setup(&mut s).await;

    let (disk_tree_id, disk) =
        tree_connect_response(&mut s, "\\\\127.0.0.1\\share", session_id, 3).await;
    assert_ne!(disk_tree_id, 0);
    assert_eq!(disk.share_type, TreeConnectResponse::SHARE_TYPE_DISK);
    assert_eq!(
        disk.share_flags,
        TreeConnectResponse::SHARE_FLAG_MANUAL_CACHING
    );

    let (ipc_tree_id, ipc) =
        tree_connect_response(&mut s, "\\\\127.0.0.1\\IPC$", session_id, 4).await;
    assert_ne!(ipc_tree_id, 0);
    assert_ne!(ipc_tree_id, disk_tree_id);
    assert_eq!(ipc.share_type, TreeConnectResponse::SHARE_TYPE_PIPE);
    assert_eq!(ipc.share_flags, TreeConnectResponse::SHARE_FLAG_NO_CACHING);

    drop(s);
    handle.abort();
}

async fn send_pipe_read(
    s: &mut TcpStream,
    message_id: u64,
    session_id: u64,
    tree_id: u32,
    file_id: FileId,
) -> Smb2Header {
    let req = ReadRequest {
        structure_size: 49,
        padding: ReadResponse::STANDARD_DATA_OFFSET,
        flags: 0,
        length: 1024,
        offset: u64::MAX,
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
    let (rh, _rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Read);
    rh
}

async fn send_async_cancel(s: &mut TcpStream, message_id: u64, session_id: u64, async_id: u64) {
    let mut body = Vec::new();
    CancelRequest::default()
        .write_to(&mut body)
        .expect("write cancel");
    let mut hdr = build_header(Command::Cancel, message_id, session_id, 0);
    hdr.flags |= SMB2_FLAGS_ASYNC_COMMAND;
    hdr.tail = smb_server::wire::header::HeaderTail::async_(async_id);
    write_frame(s, &hdr, &body).await;
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
    let _ = CloseResponse::parse(rb).expect("parse close");
}

async fn send_pipe_flush_status(
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
        let _ = FlushResponse::parse(rb).expect("parse flush");
    }
    rh.channel_sequence_status
}

fn rpc_bind_request(call_id: u32) -> Vec<u8> {
    let mut req = vec![0u8; 72];
    req[0] = 5;
    req[1] = 0;
    req[2] = 11;
    req[3] = 0x03;
    req[4] = 0x10;
    let len = req.len() as u16;
    req[8..10].copy_from_slice(&len.to_le_bytes());
    req[12..16].copy_from_slice(&call_id.to_le_bytes());
    req
}

fn rpc_request(call_id: u32, context_id: u16, opnum: u16) -> Vec<u8> {
    let mut req = vec![0u8; 24];
    req[0] = 5;
    req[1] = 0;
    req[2] = 0;
    req[3] = 0x03;
    req[4] = 0x10;
    let len = req.len() as u16;
    req[8..10].copy_from_slice(&len.to_le_bytes());
    req[12..16].copy_from_slice(&call_id.to_le_bytes());
    req[20..22].copy_from_slice(&context_id.to_le_bytes());
    req[22..24].copy_from_slice(&opnum.to_le_bytes());
    req
}

async fn pipe_transceive(
    s: &mut TcpStream,
    message_id: u64,
    session_id: u64,
    tree_id: u32,
    file_id: FileId,
    input: Vec<u8>,
    max_output_response: u32,
) -> IoctlResponse {
    let req = IoctlRequest {
        structure_size: 57,
        reserved: 0,
        ctl_code: Fsctl::PIPE_TRANSCEIVE,
        file_id,
        input_offset: 64 + 56,
        input_count: input.len() as u32,
        max_input_response: 0,
        output_offset: 0,
        output_count: 0,
        max_output_response,
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
    IoctlResponse::parse(rb).expect("parse ioctl response")
}

async fn send_ioctl_status(
    s: &mut TcpStream,
    message_id: u64,
    session_id: u64,
    tree_id: u32,
    ctl_code: u32,
    flags: u32,
) -> u32 {
    let req = IoctlRequest {
        structure_size: 57,
        reserved: 0,
        ctl_code,
        file_id: FileId::any(),
        input_offset: 64 + 56,
        input_count: 0,
        max_input_response: 0,
        output_offset: 0,
        output_count: 0,
        max_output_response: 4096,
        flags,
        reserved2: 0,
        input: vec![],
    };
    let mut body = Vec::new();
    req.write_to(&mut body).expect("write ioctl");
    let hdr = build_header(Command::Ioctl, message_id, session_id, tree_id);
    write_frame(s, &hdr, &body).await;
    let resp = read_frame(s).await;
    let (rh, _rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Ioctl);
    rh.channel_sequence_status
}

async fn send_create_or_get_object_id(
    s: &mut TcpStream,
    message_id: u64,
    session_id: u64,
    tree_id: u32,
    file_id: FileId,
    max_output_response: u32,
) -> (u32, Option<IoctlResponse>) {
    let req = IoctlRequest {
        structure_size: 57,
        reserved: 0,
        ctl_code: Fsctl::CREATE_OR_GET_OBJECT_ID,
        file_id,
        input_offset: 64 + 56,
        input_count: 0,
        max_input_response: 0,
        output_offset: 0,
        output_count: 0,
        max_output_response,
        flags: IoctlRequest::FLAG_IS_FSCTL,
        reserved2: 0,
        input: vec![],
    };
    let mut body = Vec::new();
    req.write_to(&mut body).expect("write object id ioctl");
    let hdr = build_header(Command::Ioctl, message_id, session_id, tree_id);
    write_frame(s, &hdr, &body).await;
    let resp = read_frame(s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Ioctl);
    let ioctl = if rh.channel_sequence_status == STATUS_SUCCESS {
        Some(IoctlResponse::parse(rb).expect("parse object id ioctl response"))
    } else {
        None
    };
    (rh.channel_sequence_status, ioctl)
}

fn rpc_packet_type(output: &[u8]) -> u8 {
    output[2]
}

fn rpc_call_id(output: &[u8]) -> u32 {
    u32::from_le_bytes(output[12..16].try_into().expect("call id bytes"))
}

fn utf16le_bytes(value: &str) -> Vec<u8> {
    value.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

#[tokio::test]
async fn ipc_create_opens_supported_pipes_and_rejects_unknown_pipe() {
    let (handle, _td, mut s) = start_ipc_server(8).await;
    let _ = negotiate(&mut s).await;
    let session_id = anonymous_session_setup(&mut s).await;
    let tree_id = tree_connect_ipc(&mut s, session_id, 3).await;

    for (message_id, name) in [(4, "lsarpc"), (6, r"\PIPE\srvsvc")] {
        let (status, opened) =
            open_pipe_status(&mut s, message_id, session_id, tree_id, name).await;
        assert_eq!(status, STATUS_SUCCESS, "{name}");
        let create = opened.expect("supported pipe create");
        assert_ne!(create.file_id, FileId::any(), "{name}");
        close_file(&mut s, message_id + 1, session_id, tree_id, create.file_id).await;
    }

    let (status, opened) = open_pipe_status(&mut s, 8, session_id, tree_id, r"\PIPE\spoolss").await;
    assert_eq!(status, STATUS_OBJECT_NAME_NOT_FOUND);
    assert!(opened.is_none());

    drop(s);
    handle.abort();
}

#[tokio::test]
async fn pipe_flush_succeeds() {
    let (handle, _td, mut s) = start_ipc_server(8).await;
    let _ = negotiate(&mut s).await;
    let session_id = anonymous_session_setup(&mut s).await;
    let tree_id = tree_connect_ipc(&mut s, session_id, 3).await;
    let file_id = open_pipe(&mut s, 4, session_id, tree_id, "srvsvc").await;

    assert_eq!(
        send_pipe_flush_status(&mut s, 5, session_id, tree_id, file_id).await,
        STATUS_SUCCESS
    );
    close_file(&mut s, 6, session_id, tree_id, file_id).await;
    handle.abort();
}

#[tokio::test]
async fn unsupported_fsctls_return_gosmb_statuses() {
    let (handle, _td, mut s) = start_ipc_server(8).await;
    let _ = negotiate(&mut s).await;
    let session_id = anonymous_session_setup(&mut s).await;
    let (tree_id, tree) =
        tree_connect_response(&mut s, "\\\\127.0.0.1\\share", session_id, 3).await;
    assert_eq!(tree.share_type, TreeConnectResponse::SHARE_TYPE_DISK);

    for (message_id, ctl_code, flags, expected) in [
        (
            4,
            Fsctl::DFS_GET_REFERRALS,
            IoctlRequest::FLAG_IS_FSCTL,
            STATUS_FS_DRIVER_REQUIRED,
        ),
        (
            5,
            Fsctl::DFS_GET_REFERRALS_EX,
            IoctlRequest::FLAG_IS_FSCTL,
            STATUS_FS_DRIVER_REQUIRED,
        ),
        (
            6,
            Fsctl::PIPE_PEEK,
            IoctlRequest::FLAG_IS_FSCTL,
            STATUS_NOT_SUPPORTED,
        ),
        (
            7,
            Fsctl::PIPE_WAIT,
            IoctlRequest::FLAG_IS_FSCTL,
            STATUS_NOT_SUPPORTED,
        ),
        (
            8,
            Fsctl::QUERY_NETWORK_INTERFACE_INFO,
            IoctlRequest::FLAG_IS_FSCTL,
            STATUS_FS_DRIVER_REQUIRED,
        ),
        (9, Fsctl::PIPE_TRANSCEIVE, 0, STATUS_NOT_SUPPORTED),
    ] {
        assert_eq!(
            send_ioctl_status(&mut s, message_id, session_id, tree_id, ctl_code, flags).await,
            expected,
            "ctl_code=0x{ctl_code:08x}"
        );
    }

    drop(s);
    handle.abort();
}

#[tokio::test]
async fn create_or_get_object_id_returns_gosmb_object_buffer() {
    let (handle, td, mut s) = start_ipc_server(8).await;
    std::fs::write(td.path().join("hello.txt"), b"hello").expect("write hello");
    let _ = negotiate(&mut s).await;
    let session_id = anonymous_session_setup(&mut s).await;
    let (tree_id, tree) =
        tree_connect_response(&mut s, "\\\\127.0.0.1\\share", session_id, 3).await;
    assert_eq!(tree.share_type, TreeConnectResponse::SHARE_TYPE_DISK);
    let file_id = open_pipe(&mut s, 4, session_id, tree_id, "hello.txt").await;

    let (status, response) =
        send_create_or_get_object_id(&mut s, 5, session_id, tree_id, file_id, 64).await;
    assert_eq!(status, STATUS_SUCCESS);
    let response = response.expect("object id response");
    assert_eq!(response.ctl_code, Fsctl::CREATE_OR_GET_OBJECT_ID);
    assert_eq!(response.file_id, file_id);
    assert_eq!(response.output_count, 64);
    assert_eq!(response.output.len(), 64);
    assert_eq!(&response.output[0..8], b"GoSMBObj");

    let (status, response) =
        send_create_or_get_object_id(&mut s, 6, session_id, tree_id, file_id, 63).await;
    assert_eq!(status, STATUS_INVALID_PARAMETER);
    assert!(response.is_none());

    close_file(&mut s, 7, session_id, tree_id, file_id).await;
    drop(s);
    handle.abort();
}

#[tokio::test]
async fn srvsvc_pipe_transceive_accepts_bind() {
    let (handle, _td, mut s) = start_ipc_server(8).await;
    let _ = negotiate(&mut s).await;
    let session_id = anonymous_session_setup(&mut s).await;
    let tree_id = tree_connect_ipc(&mut s, session_id, 3).await;
    let pipe_id = open_pipe(&mut s, 4, session_id, tree_id, "srvsvc").await;

    let ioctl = pipe_transceive(
        &mut s,
        5,
        session_id,
        tree_id,
        pipe_id,
        rpc_bind_request(7),
        1024,
    )
    .await;

    assert_eq!(rpc_packet_type(&ioctl.output), 12);
    assert_eq!(rpc_call_id(&ioctl.output), 7);
    assert!(
        ioctl
            .output
            .windows(br"\PIPE\srvsvc".len())
            .any(|window| window == br"\PIPE\srvsvc"),
        "srvsvc bind ack missing pipe name: {:x?}",
        ioctl.output
    );

    close_file(&mut s, 6, session_id, tree_id, pipe_id).await;
    handle.abort();
}

#[tokio::test]
async fn pipe_transceive_truncates_output_to_max_response() {
    let (handle, _td, mut s) = start_ipc_server(8).await;
    let _ = negotiate(&mut s).await;
    let session_id = anonymous_session_setup(&mut s).await;
    let tree_id = tree_connect_ipc(&mut s, session_id, 3).await;
    let pipe_id = open_pipe(&mut s, 4, session_id, tree_id, "srvsvc").await;

    let ioctl = pipe_transceive(
        &mut s,
        5,
        session_id,
        tree_id,
        pipe_id,
        rpc_bind_request(77),
        16,
    )
    .await;
    assert_eq!(ioctl.ctl_code, Fsctl::PIPE_TRANSCEIVE);
    assert_eq!(ioctl.file_id, pipe_id);
    assert_eq!(ioctl.output.len(), 16);
    assert_eq!(ioctl.output_count, 16);
    assert_eq!(&ioctl.output[12..16], &77u32.to_le_bytes());

    close_file(&mut s, 6, session_id, tree_id, pipe_id).await;
    drop(s);
    handle.abort();
}

#[tokio::test]
async fn srvsvc_pipe_transceive_enumerates_configured_shares() {
    let (handle, _td, mut s) = start_ipc_server(8).await;
    let _ = negotiate(&mut s).await;
    let session_id = anonymous_session_setup(&mut s).await;
    let tree_id = tree_connect_ipc(&mut s, session_id, 3).await;
    let pipe_id = open_pipe(&mut s, 4, session_id, tree_id, "srvsvc").await;

    let ioctl = pipe_transceive(
        &mut s,
        5,
        session_id,
        tree_id,
        pipe_id,
        rpc_request(8, 0, 15),
        4096,
    )
    .await;

    assert_eq!(rpc_packet_type(&ioctl.output), 2);
    assert_eq!(rpc_call_id(&ioctl.output), 8);
    let stub = &ioctl.output[24..];
    assert_eq!(u32::from_le_bytes(stub[0..4].try_into().unwrap()), 1);
    assert_eq!(u32::from_le_bytes(stub[12..16].try_into().unwrap()), 1);
    let share_name = utf16le_bytes("share");
    assert!(
        ioctl
            .output
            .windows(share_name.len())
            .any(|window| window == share_name.as_slice()),
        "srvsvc response did not include configured share name: {:x?}",
        ioctl.output
    );

    close_file(&mut s, 6, session_id, tree_id, pipe_id).await;
    handle.abort();
}

#[tokio::test]
async fn srvsvc_pipe_transceive_faults_unknown_opnum() {
    let (handle, _td, mut s) = start_ipc_server(8).await;
    let _ = negotiate(&mut s).await;
    let session_id = anonymous_session_setup(&mut s).await;
    let tree_id = tree_connect_ipc(&mut s, session_id, 3).await;
    let pipe_id = open_pipe(&mut s, 4, session_id, tree_id, "srvsvc").await;

    let ioctl = pipe_transceive(
        &mut s,
        5,
        session_id,
        tree_id,
        pipe_id,
        rpc_request(9, 3, 0xffff),
        1024,
    )
    .await;

    assert_eq!(rpc_packet_type(&ioctl.output), 3);
    assert_eq!(rpc_call_id(&ioctl.output), 9);
    assert_eq!(
        u16::from_le_bytes(ioctl.output[20..22].try_into().unwrap()),
        3
    );
    assert_eq!(
        u32::from_le_bytes(ioctl.output[24..28].try_into().unwrap()),
        0x0000_06d1
    );

    close_file(&mut s, 6, session_id, tree_id, pipe_id).await;
    handle.abort();
}

#[tokio::test]
async fn lsarpc_pipe_transceive_accepts_bind() {
    let (handle, _td, mut s) = start_ipc_server(8).await;
    let _ = negotiate(&mut s).await;
    let session_id = anonymous_session_setup(&mut s).await;
    let tree_id = tree_connect_ipc(&mut s, session_id, 3).await;
    let pipe_id = open_pipe(&mut s, 4, session_id, tree_id, "lsarpc").await;

    let ioctl = pipe_transceive(
        &mut s,
        5,
        session_id,
        tree_id,
        pipe_id,
        rpc_bind_request(7),
        1024,
    )
    .await;
    assert_eq!(ioctl.ctl_code, Fsctl::PIPE_TRANSCEIVE);
    assert_eq!(ioctl.file_id, pipe_id);
    assert!(
        ioctl
            .output
            .windows(br"\PIPE\lsarpc".len())
            .any(|window| window == br"\PIPE\lsarpc"),
        "lsarpc bind ack missing pipe name: {:x?}",
        ioctl.output
    );

    close_file(&mut s, 6, session_id, tree_id, pipe_id).await;
    handle.abort();
}

#[tokio::test]
async fn pipe_read_pends_until_cancel() {
    let (handle, _td, mut s) = start_ipc_server(8).await;
    let _ = negotiate(&mut s).await;
    let session_id = anonymous_session_setup(&mut s).await;
    let tree_id = tree_connect_ipc(&mut s, session_id, 3).await;
    let pipe_id = open_pipe(&mut s, 4, session_id, tree_id, r"\PIPE\lsarpc").await;

    let pending = send_pipe_read(&mut s, 5, session_id, tree_id, pipe_id).await;
    assert_eq!(pending.channel_sequence_status, STATUS_PENDING);
    assert!(pending.is_async());
    let async_id = pending.async_id().expect("async id");

    send_async_cancel(&mut s, 6, session_id, async_id).await;
    let final_resp = read_frame(&mut s).await;
    let (rh, _rb) = parse_response_header(&final_resp);
    assert_eq!(rh.command, Command::Read);
    assert_eq!(rh.channel_sequence_status, STATUS_CANCELLED);
    assert!(rh.is_async());
    assert_eq!(rh.async_id(), Some(async_id));
    assert_eq!(rh.credit_request_response, 0);

    close_file(&mut s, 7, session_id, tree_id, pipe_id).await;
    drop(s);
    handle.abort();
}

#[tokio::test]
async fn pipe_read_completes_with_cleanup_on_close() {
    let (handle, _td, mut s) = start_ipc_server(8).await;
    let _ = negotiate(&mut s).await;
    let session_id = anonymous_session_setup(&mut s).await;
    let tree_id = tree_connect_ipc(&mut s, session_id, 3).await;
    let pipe_id = open_pipe(&mut s, 4, session_id, tree_id, "lsarpc").await;

    let pending = send_pipe_read(&mut s, 5, session_id, tree_id, pipe_id).await;
    assert_eq!(pending.channel_sequence_status, STATUS_PENDING);
    assert!(pending.is_async());
    let async_id = pending.async_id().expect("async id");

    let close_req = CloseRequest {
        structure_size: 24,
        flags: 0,
        reserved: 0,
        file_id: pipe_id,
    };
    let mut body = Vec::new();
    close_req.write_to(&mut body).expect("write close");
    let hdr = build_header(Command::Close, 6, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;

    let frames = [read_frame(&mut s).await, read_frame(&mut s).await];
    let mut saw_close = false;
    let mut saw_cleanup = false;
    for frame in frames {
        let (rh, rb) = parse_response_header(&frame);
        match rh.command {
            Command::Close => {
                assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
                let _ = CloseResponse::parse(rb).expect("parse close");
                saw_close = true;
            }
            Command::Read => {
                assert_eq!(rh.channel_sequence_status, STATUS_NOTIFY_CLEANUP);
                assert!(rh.is_async());
                assert_eq!(rh.async_id(), Some(async_id));
                assert_eq!(rh.credit_request_response, 0);
                saw_cleanup = true;
            }
            other => panic!("unexpected response command {other:?}"),
        }
    }
    assert!(saw_close, "missing close response");
    assert!(saw_cleanup, "missing async pipe read cleanup response");

    drop(s);
    handle.abort();
}

#[tokio::test]
async fn pipe_read_completes_with_cleanup_on_tree_disconnect() {
    let (handle, _td, mut s) = start_ipc_server(8).await;
    let _ = negotiate(&mut s).await;
    let session_id = anonymous_session_setup(&mut s).await;
    let tree_id = tree_connect_ipc(&mut s, session_id, 3).await;
    let pipe_id = open_pipe(&mut s, 4, session_id, tree_id, "lsarpc").await;

    let pending = send_pipe_read(&mut s, 5, session_id, tree_id, pipe_id).await;
    assert_eq!(pending.channel_sequence_status, STATUS_PENDING);
    assert!(pending.is_async());
    let async_id = pending.async_id().expect("async id");

    let mut body = Vec::new();
    TreeDisconnectRequest::default()
        .write_to(&mut body)
        .expect("write tree disconnect");
    let hdr = build_header(Command::TreeDisconnect, 6, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;

    let frames = [read_frame(&mut s).await, read_frame(&mut s).await];
    let mut saw_tree_disconnect = false;
    let mut saw_cleanup = false;
    for frame in frames {
        let (rh, rb) = parse_response_header(&frame);
        match rh.command {
            Command::TreeDisconnect => {
                assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
                let _ = TreeDisconnectResponse::parse(rb).expect("parse tree disconnect");
                saw_tree_disconnect = true;
            }
            Command::Read => {
                assert_eq!(rh.channel_sequence_status, STATUS_NOTIFY_CLEANUP);
                assert!(rh.is_async());
                assert_eq!(rh.async_id(), Some(async_id));
                assert_eq!(rh.credit_request_response, 0);
                saw_cleanup = true;
            }
            other => panic!("unexpected response command {other:?}"),
        }
    }
    assert!(saw_tree_disconnect, "missing tree disconnect response");
    assert!(saw_cleanup, "missing async pipe read cleanup response");

    drop(s);
    handle.abort();
}

#[tokio::test]
async fn pipe_read_returns_insufficient_resources_at_async_limit() {
    let (handle, _td, mut s) = start_ipc_server(8192).await;
    let _ = negotiate(&mut s).await;
    let session_id = anonymous_session_setup(&mut s).await;
    let tree_id = tree_connect_ipc(&mut s, session_id, 3).await;
    let pipe_id = open_pipe(&mut s, 4, session_id, tree_id, "lsarpc").await;

    for i in 0..GOSMB_MAX_PENDING_ASYNC_REQUESTS {
        let pending = send_pipe_read(&mut s, 5 + i, session_id, tree_id, pipe_id).await;
        assert_eq!(pending.channel_sequence_status, STATUS_PENDING, "read {i}");
        assert!(pending.is_async(), "read {i}");
    }

    let second = send_pipe_read(
        &mut s,
        5 + GOSMB_MAX_PENDING_ASYNC_REQUESTS,
        session_id,
        tree_id,
        pipe_id,
    )
    .await;
    assert_eq!(
        second.channel_sequence_status,
        STATUS_INSUFFICIENT_RESOURCES
    );
    assert!(!second.is_async());

    drop(s);
    handle.abort();
}
