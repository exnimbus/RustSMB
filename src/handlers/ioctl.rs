//! IOCTL handler.

use std::sync::Arc;

use crate::proto::header::Smb2Header;
use crate::proto::messages::{Dialect, Fsctl, IoctlRequest, IoctlResponse};

use crate::conn::state::Connection;
use crate::dispatch::HandlerResponse;
use crate::handlers::dcerpc::{RpcShare, handle_lsarpc_rpc, handle_srvsvc_rpc};
use crate::handlers::negotiate::{negotiate_capabilities_for_dialect, negotiate_security_mode};
use crate::handlers::shared::{lookup_open, lookup_session_tree};
use crate::ntstatus;
use crate::server::ServerState;

const DEFAULT_RESILIENCY_TIMEOUT_MS: u32 = 300_000;

pub async fn handle(
    server: &Arc<ServerState>,
    conn: &Arc<Connection>,
    hdr: &Smb2Header,
    body: &[u8],
) -> HandlerResponse {
    let req = match IoctlRequest::parse(body) {
        Ok(r) => r,
        Err(_) => return HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER),
    };
    if req.flags & IoctlRequest::FLAG_IS_FSCTL == 0 {
        return HandlerResponse::err(ntstatus::STATUS_NOT_SUPPORTED);
    }

    match req.fsctl() {
        Fsctl::ValidateNegotiateInfo => {
            // Build VALIDATE_NEGOTIATE_INFO_RESPONSE per MS-SMB2 §2.2.32.6:
            // Capabilities (4) | Guid (16) | SecurityMode (2) | Dialect (2) = 24 bytes.
            let dialect = *conn.dialect.read().await;
            let advertise_smb_encryption = matches!(
                dialect,
                Some(Dialect::Smb300 | Dialect::Smb302 | Dialect::Smb311)
            ) && !*conn.transport_security.read().await;
            let mut out = Vec::with_capacity(24);
            out.extend_from_slice(
                &negotiate_capabilities_for_dialect(dialect, advertise_smb_encryption)
                    .to_le_bytes(),
            );
            out.extend_from_slice(server.config.server_guid.as_bytes());
            out.extend_from_slice(
                &negotiate_security_mode(server.config.require_signing).to_le_bytes(),
            );
            out.extend_from_slice(&dialect.map(Dialect::as_u16).unwrap_or(0).to_le_bytes());

            let resp = IoctlResponse {
                structure_size: 49,
                reserved: 0,
                ctl_code: req.ctl_code,
                file_id: req.file_id,
                input_offset: 0,
                input_count: 0,
                output_offset: 0x70,
                output_count: out.len() as u32,
                flags: 0,
                reserved2: 0,
                output: out,
            };
            let mut buf = Vec::new();
            resp.write_to(&mut buf).expect("IOCTL response encodes");
            HandlerResponse::ok(buf)
        }
        Fsctl::PipeTranscede => pipe_transceive(server, conn, hdr, req).await,
        Fsctl::CreateOrGetObjectId => create_or_get_object_id(conn, hdr, req).await,
        Fsctl::LmrRequestResiliency => request_resiliency(conn, hdr, req).await,
        Fsctl::SmbTortureForceUnackedTimeout => {
            conn.enable_force_unacked_timeout();
            ioctl_response(&req, Vec::new())
        }
        Fsctl::DfsGetReferrals | Fsctl::DfsGetReferralsEx | Fsctl::QueryNetworkInterfaceInfo => {
            HandlerResponse::err(ntstatus::STATUS_FS_DRIVER_REQUIRED)
        }
        _ => HandlerResponse::err(ntstatus::STATUS_NOT_SUPPORTED),
    }
}

async fn pipe_transceive(
    server: &Arc<ServerState>,
    conn: &Arc<Connection>,
    hdr: &Smb2Header,
    req: IoctlRequest,
) -> HandlerResponse {
    let tree_arc = match lookup_session_tree(conn, hdr).await {
        Ok(t) => t,
        Err(s) => return HandlerResponse::err(s),
    };
    let open_arc = match lookup_open(&tree_arc, req.file_id).await {
        Some(open) => open,
        None => return HandlerResponse::err(ntstatus::STATUS_FILE_CLOSED),
    };
    let pipe_name = {
        let tree = tree_arc.read().await;
        if !tree.share.is_ipc {
            return HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER);
        }
        let open = open_arc.read().await;
        open.last_path
            .file_name()
            .unwrap_or("")
            .to_ascii_lowercase()
    };

    let mut output = match pipe_name.as_str() {
        "srvsvc" => {
            let shares = rpc_shares(server).await;
            handle_srvsvc_rpc(&req.input, &shares)
        }
        "lsarpc" => handle_lsarpc_rpc(&req.input),
        _ => return HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER),
    }
    .unwrap_or_else(Vec::new);
    if output.is_empty() {
        return HandlerResponse::err(ntstatus::STATUS_NOT_SUPPORTED);
    }
    if req.max_output_response > 0 && output.len() > req.max_output_response as usize {
        output.truncate(req.max_output_response as usize);
    }

    let resp = IoctlResponse {
        structure_size: 49,
        reserved: 0,
        ctl_code: req.ctl_code,
        file_id: req.file_id,
        input_offset: 0,
        input_count: 0,
        output_offset: 0x70,
        output_count: output.len() as u32,
        flags: 0,
        reserved2: 0,
        output,
    };
    let mut buf = Vec::new();
    resp.write_to(&mut buf).expect("IOCTL response encodes");
    HandlerResponse::ok(buf)
}

async fn create_or_get_object_id(
    conn: &Arc<Connection>,
    hdr: &Smb2Header,
    req: IoctlRequest,
) -> HandlerResponse {
    let tree_arc = match lookup_session_tree(conn, hdr).await {
        Ok(t) => t,
        Err(s) => return HandlerResponse::err(s),
    };
    {
        let tree = tree_arc.read().await;
        if tree.share.is_ipc {
            return HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER);
        }
    }
    let open_arc = match lookup_open(&tree_arc, req.file_id).await {
        Some(open) => open,
        None => return HandlerResponse::err(ntstatus::STATUS_FILE_CLOSED),
    };
    if req.input_count != 0 || req.max_output_response < 64 {
        return HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER);
    }
    let (file_id, stat) = {
        let open = open_arc.read().await;
        match open.handle.as_ref() {
            Some(handle) => (open.file_id, handle.stat().await),
            None => return HandlerResponse::err(ntstatus::STATUS_FILE_CLOSED),
        }
    };
    let info = match stat {
        Ok(info) => info,
        Err(e) => return HandlerResponse::err(e.to_nt_status()),
    };
    let object_file_id = if info.file_index == 0 {
        file_id.volatile
    } else {
        info.file_index
    };
    let mut output = vec![0u8; 64];
    output[0..8].copy_from_slice(b"GoSMBObj");
    output[8..16].copy_from_slice(&object_file_id.to_le_bytes());
    ioctl_response(&req, output)
}

async fn request_resiliency(
    conn: &Arc<Connection>,
    hdr: &Smb2Header,
    req: IoctlRequest,
) -> HandlerResponse {
    if req.input.len() != 8 || req.max_output_response != 0 {
        return HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER);
    }
    let timeout_ms = u32::from_le_bytes(req.input[0..4].try_into().expect("slice is 4 bytes"));
    let reserved = u32::from_le_bytes(req.input[4..8].try_into().expect("slice is 4 bytes"));
    if reserved != 0 {
        return HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER);
    }

    let tree_arc = match lookup_session_tree(conn, hdr).await {
        Ok(t) => t,
        Err(s) => return HandlerResponse::err(s),
    };
    {
        let tree = tree_arc.read().await;
        if tree.share.is_ipc {
            return HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER);
        }
    }
    let open_arc = match lookup_open(&tree_arc, req.file_id).await {
        Some(open) => open,
        None => return HandlerResponse::err(ntstatus::STATUS_FILE_CLOSED),
    };
    {
        let mut open = open_arc.write().await;
        if open.handle.is_none() {
            return HandlerResponse::err(ntstatus::STATUS_FILE_CLOSED);
        }
        open.resilient = true;
        open.durable_timeout_ms = resiliency_timeout_ms(timeout_ms);
    }
    ioctl_response(&req, Vec::new())
}

fn resiliency_timeout_ms(requested: u32) -> u32 {
    if requested == 0 {
        DEFAULT_RESILIENCY_TIMEOUT_MS
    } else {
        requested.min(DEFAULT_RESILIENCY_TIMEOUT_MS)
    }
}

fn ioctl_response(req: &IoctlRequest, output: Vec<u8>) -> HandlerResponse {
    let resp = IoctlResponse {
        structure_size: 49,
        reserved: 0,
        ctl_code: req.ctl_code,
        file_id: req.file_id,
        input_offset: 0,
        input_count: 0,
        output_offset: 0x70,
        output_count: output.len() as u32,
        flags: 0,
        reserved2: 0,
        output,
    };
    let mut buf = Vec::new();
    resp.write_to(&mut buf).expect("IOCTL response encodes");
    HandlerResponse::ok(buf)
}

async fn rpc_shares(server: &Arc<ServerState>) -> Vec<RpcShare> {
    server
        .shares
        .all()
        .await
        .into_iter()
        .filter(|share| !share.is_ipc)
        .map(|share| RpcShare {
            name: share.name.clone(),
            share_type: 0,
            comment: String::new(),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SmbServer;
    use crate::backend::{DirEntry, FileInfo, FileTimes, Handle, PipeHandle};
    use crate::builder::Access;
    use crate::conn::state::{Open, Session, TreeConnect};
    use crate::error::{SmbError, SmbResult};
    use crate::proto::auth::ntlm::Identity;
    use crate::proto::header::{Command, HeaderTail};
    use crate::proto::messages::FileId;
    use crate::server::{ShareBindings, ShareMode};
    use async_trait::async_trait;
    use bytes::Bytes;
    use std::collections::HashMap;
    use uuid::Uuid;

    struct TestHandle {
        info: FileInfo,
    }

    impl TestHandle {
        fn new(file_index: u64) -> Self {
            Self {
                info: FileInfo {
                    name: "hello.txt".to_string(),
                    end_of_file: 5,
                    allocation_size: 5,
                    creation_time: 0,
                    last_access_time: 0,
                    last_write_time: 0,
                    change_time: 0,
                    is_directory: false,
                    file_index,
                    file_attributes: crate::backend::default_file_attributes(false),
                },
            }
        }
    }

    #[async_trait]
    impl Handle for TestHandle {
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
            Ok(self.info.clone())
        }

        async fn set_times(&self, _times: FileTimes) -> SmbResult<()> {
            Ok(())
        }

        async fn truncate(&self, _len: u64) -> SmbResult<()> {
            Ok(())
        }

        async fn list_dir(&self, _pattern: Option<&str>) -> SmbResult<Vec<DirEntry>> {
            Err(SmbError::NotSupported)
        }

        async fn close(self: Box<Self>) -> SmbResult<()> {
            Ok(())
        }
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

    fn pipe_transceive_body(file_id: FileId, input: Vec<u8>, max_output: u32) -> Vec<u8> {
        ioctl_body(file_id, Fsctl::PIPE_TRANSCEIVE, input, max_output)
    }

    fn ioctl_body(file_id: FileId, ctl_code: u32, input: Vec<u8>, max_output: u32) -> Vec<u8> {
        let req = IoctlRequest {
            structure_size: 57,
            reserved: 0,
            ctl_code,
            file_id,
            input_offset: 64 + 56,
            input_count: input.len() as u32,
            max_input_response: 0,
            output_offset: 0,
            output_count: 0,
            max_output_response: max_output,
            flags: IoctlRequest::FLAG_IS_FSCTL,
            reserved2: 0,
            input,
        };
        let mut out = Vec::new();
        req.write_to(&mut out).expect("ioctl request encodes");
        out
    }

    async fn regular_file_state(
        stat_file_index: u64,
    ) -> (
        Arc<ServerState>,
        Arc<Connection>,
        Smb2Header,
        FileId,
        Arc<tokio::sync::RwLock<Open>>,
    ) {
        let server = SmbServer::builder()
            .listen("127.0.0.1:0".parse().unwrap())
            .build()
            .expect("server builds")
            .state();
        let conn = Arc::new(Connection::new(
            Uuid::nil(),
            8 * 1024 * 1024,
            8 * 1024 * 1024,
            8,
        ));
        let session = Arc::new(tokio::sync::RwLock::new(Session::new(
            42,
            Identity::Anonymous,
            [0; 16],
            [0; 16],
            false,
            None,
        )));
        let tree = Arc::new(tokio::sync::RwLock::new(TreeConnect::new(
            2,
            ShareBindings::new(
                "share".to_string(),
                Arc::new(crate::backend::NotSupportedBackend),
                ShareMode::AuthenticatedOnly,
                HashMap::new(),
                false,
            ),
            Access::ReadWrite,
        )));
        let file_id = FileId::new(11, 12);
        let open = Open::new(
            file_id,
            Box::new(TestHandle::new(stat_file_index)),
            Access::ReadWrite,
            0x001f_01ff,
            0x7,
            "hello.txt".parse().expect("file path"),
            false,
            false,
            None,
        );
        let open_arc = Arc::new(tokio::sync::RwLock::new(open));
        tree.write()
            .await
            .opens
            .write()
            .await
            .insert(file_id, Arc::clone(&open_arc));
        session.write().await.trees.write().await.insert(2, tree);
        conn.sessions.write().await.insert(42, session);
        let hdr = Smb2Header {
            command: Command::Ioctl,
            session_id: 42,
            tail: HeaderTail::sync(2),
            ..Default::default()
        };
        (server, conn, hdr, file_id, open_arc)
    }

    async fn ipc_pipe_state(
        pipe_name: &str,
    ) -> (Arc<ServerState>, Arc<Connection>, Smb2Header, FileId) {
        let server = SmbServer::builder()
            .listen("127.0.0.1:0".parse().unwrap())
            .build()
            .expect("server builds")
            .state();
        let conn = Arc::new(Connection::new(
            Uuid::nil(),
            8 * 1024 * 1024,
            8 * 1024 * 1024,
            8,
        ));
        let session = Arc::new(tokio::sync::RwLock::new(Session::new(
            42,
            Identity::Anonymous,
            [0; 16],
            [0; 16],
            false,
            None,
        )));
        let tree = Arc::new(tokio::sync::RwLock::new(TreeConnect::new(
            2,
            ShareBindings::ipc(),
            Access::Read,
        )));
        let file_id = FileId::new(1, 1);
        let open = Open::new(
            file_id,
            Box::new(PipeHandle::new(pipe_name.to_string(), file_id.volatile)),
            Access::ReadWrite,
            0x001f_01ff,
            0x7,
            pipe_name.parse().expect("pipe path"),
            false,
            false,
            None,
        );
        tree.write()
            .await
            .opens
            .write()
            .await
            .insert(file_id, Arc::new(tokio::sync::RwLock::new(open)));
        session.write().await.trees.write().await.insert(2, tree);
        conn.sessions.write().await.insert(42, session);
        let hdr = Smb2Header {
            command: Command::Ioctl,
            session_id: 42,
            tail: HeaderTail::sync(2),
            ..Default::default()
        };
        (server, conn, hdr, file_id)
    }

    #[tokio::test]
    async fn lsarpc_pipe_transceive_accepts_bind() {
        let (server, conn, hdr, file_id) = ipc_pipe_state("lsarpc").await;
        let body = pipe_transceive_body(file_id, rpc_bind_request(7), 1024);

        let resp = handle(&server, &conn, &hdr, &body).await;

        assert_eq!(resp.status, ntstatus::STATUS_SUCCESS);
        let ioctl = IoctlResponse::parse(&resp.body).expect("parse ioctl response");
        assert_eq!(ioctl.ctl_code, Fsctl::PIPE_TRANSCEIVE);
        assert_eq!(ioctl.file_id, file_id);
        assert_eq!(ioctl.output[2], 12);
        assert!(
            ioctl
                .output
                .windows(br"\PIPE\lsarpc".len())
                .any(|window| window == br"\PIPE\lsarpc")
        );
    }

    #[tokio::test]
    async fn ioctl_rejects_non_fsctl_requests() {
        let (server, conn, hdr, file_id, _open) = regular_file_state(1).await;
        let mut req = IoctlRequest {
            structure_size: 57,
            reserved: 0,
            ctl_code: Fsctl::QUERY_NETWORK_INTERFACE_INFO,
            file_id,
            input_offset: 0,
            input_count: 0,
            max_input_response: 0,
            output_offset: 0,
            output_count: 0,
            max_output_response: 0,
            flags: 0,
            reserved2: 0,
            input: Vec::new(),
        };
        let mut body = Vec::new();
        req.write_to(&mut body).expect("ioctl request encodes");

        let resp = handle(&server, &conn, &hdr, &body).await;
        assert_eq!(resp.status, ntstatus::STATUS_NOT_SUPPORTED);

        req.flags = IoctlRequest::FLAG_IS_FSCTL;
        body.clear();
        req.write_to(&mut body).expect("ioctl request encodes");
        let resp = handle(&server, &conn, &hdr, &body).await;
        assert_eq!(resp.status, ntstatus::STATUS_FS_DRIVER_REQUIRED);
    }

    #[tokio::test]
    async fn dfs_referral_fsctls_return_fs_driver_required() {
        let (server, conn, hdr, file_id, _open) = regular_file_state(1).await;

        for ctl_code in [Fsctl::DFS_GET_REFERRALS, Fsctl::DFS_GET_REFERRALS_EX] {
            let body = ioctl_body(file_id, ctl_code, Vec::new(), 1024);
            let resp = handle(&server, &conn, &hdr, &body).await;
            assert_eq!(resp.status, ntstatus::STATUS_FS_DRIVER_REQUIRED);
        }
    }

    #[tokio::test]
    async fn unsupported_pipe_fsctls_return_not_supported() {
        let (server, conn, hdr, file_id) = ipc_pipe_state("srvsvc").await;

        for ctl_code in [Fsctl::PIPE_PEEK, Fsctl::PIPE_WAIT] {
            let body = ioctl_body(file_id, ctl_code, Vec::new(), 1024);
            let resp = handle(&server, &conn, &hdr, &body).await;
            assert_eq!(resp.status, ntstatus::STATUS_NOT_SUPPORTED);
        }
    }

    #[tokio::test]
    async fn create_or_get_object_id_returns_gosmb_object_buffer() {
        let (server, conn, hdr, file_id, _open) = regular_file_state(0x1122_3344_5566_7788).await;
        let body = ioctl_body(file_id, Fsctl::CREATE_OR_GET_OBJECT_ID, Vec::new(), 64);

        let resp = handle(&server, &conn, &hdr, &body).await;

        assert_eq!(resp.status, ntstatus::STATUS_SUCCESS);
        let ioctl = IoctlResponse::parse(&resp.body).expect("parse ioctl response");
        assert_eq!(ioctl.ctl_code, Fsctl::CREATE_OR_GET_OBJECT_ID);
        assert_eq!(ioctl.output.len(), 64);
        assert_eq!(&ioctl.output[0..8], b"GoSMBObj");
        assert_eq!(
            u64::from_le_bytes(ioctl.output[8..16].try_into().unwrap()),
            0x1122_3344_5566_7788
        );
    }

    #[tokio::test]
    async fn create_or_get_object_id_uses_file_id_when_backend_has_no_file_index() {
        let (server, conn, hdr, file_id, _open) = regular_file_state(0).await;
        let body = ioctl_body(file_id, Fsctl::CREATE_OR_GET_OBJECT_ID, Vec::new(), 64);

        let resp = handle(&server, &conn, &hdr, &body).await;

        assert_eq!(resp.status, ntstatus::STATUS_SUCCESS);
        let ioctl = IoctlResponse::parse(&resp.body).expect("parse ioctl response");
        assert_eq!(
            u64::from_le_bytes(ioctl.output[8..16].try_into().unwrap()),
            file_id.volatile
        );
    }

    #[tokio::test]
    async fn create_or_get_object_id_rejects_too_small_output_buffer() {
        let (server, conn, hdr, file_id, _open) = regular_file_state(1).await;
        let body = ioctl_body(file_id, Fsctl::CREATE_OR_GET_OBJECT_ID, Vec::new(), 63);

        let resp = handle(&server, &conn, &hdr, &body).await;

        assert_eq!(resp.status, ntstatus::STATUS_INVALID_PARAMETER);
    }

    #[tokio::test]
    async fn request_resiliency_marks_open_with_clamped_timeout() {
        let (server, conn, hdr, file_id, open) = regular_file_state(1).await;
        let mut input = Vec::new();
        input.extend_from_slice(&600_000u32.to_le_bytes());
        input.extend_from_slice(&0u32.to_le_bytes());
        let body = ioctl_body(file_id, Fsctl::LMR_REQUEST_RESILIENCY, input, 0);

        let resp = handle(&server, &conn, &hdr, &body).await;

        assert_eq!(resp.status, ntstatus::STATUS_SUCCESS);
        let ioctl = IoctlResponse::parse(&resp.body).expect("parse ioctl response");
        assert_eq!(ioctl.ctl_code, Fsctl::LMR_REQUEST_RESILIENCY);
        assert!(ioctl.output.is_empty());
        let open = open.read().await;
        assert!(open.resilient);
        assert_eq!(open.durable_timeout_ms, DEFAULT_RESILIENCY_TIMEOUT_MS);
    }

    #[tokio::test]
    async fn request_resiliency_rejects_nonzero_reserved_field() {
        let (server, conn, hdr, file_id, _open) = regular_file_state(1).await;
        let mut input = Vec::new();
        input.extend_from_slice(&1_000u32.to_le_bytes());
        input.extend_from_slice(&1u32.to_le_bytes());
        let body = ioctl_body(file_id, Fsctl::LMR_REQUEST_RESILIENCY, input, 0);

        let resp = handle(&server, &conn, &hdr, &body).await;

        assert_eq!(resp.status, ntstatus::STATUS_INVALID_PARAMETER);
    }
}
