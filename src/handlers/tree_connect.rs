//! TREE_CONNECT handler — share lookup + authorization.

use std::sync::Arc;

use crate::proto::auth::ntlm::Identity;
use crate::proto::header::Smb2Header;
use crate::proto::messages::{Dialect, TreeConnectRequest, TreeConnectResponse};
use tracing::{info, warn};

use crate::builder::Access;
use crate::conn::state::{Connection, TreeConnect};
use crate::dispatch::HandlerResponse;
use crate::handlers::shared::lookup_session;
use crate::ntstatus;
use crate::server::{ServerState, ShareMode};

const SHARE_TYPE_DISK: u8 = 0x01;
const SHARE_TYPE_PIPE: u8 = 0x02;

const FILE_GENERIC_READ: u32 = 0x0012_0089;
const FILE_GENERIC_EXECUTE: u32 = 0x0012_00A0;
const FILE_ALL_ACCESS: u32 = 0x001F_01FF;

pub async fn handle(
    server: &Arc<ServerState>,
    conn: &Arc<Connection>,
    hdr: &Smb2Header,
    body: &[u8],
) -> HandlerResponse {
    let req = match TreeConnectRequest::parse(body) {
        Ok(r) => r,
        Err(_) => return HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER),
    };
    let path = req.path_str().unwrap_or_default();
    tracing::debug!(%path, "tree connect path");
    let share_name = match extract_share_name(&path) {
        Some(s) => s,
        None => {
            tracing::warn!(%path, "tree connect: malformed UNC path");
            return HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER);
        }
    };
    tracing::debug!(%share_name, "tree connect lookup");
    let sess_arc = match lookup_session(conn, hdr.session_id).await {
        Ok(s) => s,
        Err(s) => return HandlerResponse::err(s),
    };
    let sess = sess_arc.read().await;
    let identity = sess.identity.clone();
    drop(sess);

    // IPC$: synthetic share. Accept at TREE_CONNECT (Windows always probes
    // it before mounting an actual share); downstream CREATE/IOCTL on it
    // return NotSupported via the no-op backend.
    let share = if share_name.eq_ignore_ascii_case("IPC$") {
        crate::server::ShareBindings::ipc()
    } else {
        match server.find_share(&share_name).await {
            Some(s) => s,
            None => return HandlerResponse::err(ntstatus::STATUS_BAD_NETWORK_NAME),
        }
    };

    // Authorize.
    let acl = share.acl.read().await;
    let granted = match authorize(&acl.mode, &acl.users, &identity) {
        Some(a) => a,
        None => {
            warn!(?identity, share = %share.name, "TREE_CONNECT denied");
            return HandlerResponse::err(ntstatus::STATUS_ACCESS_DENIED);
        }
    };
    drop(acl);
    // Backend cap.
    let granted = if share.backend.capabilities().is_read_only {
        granted.clamp_to(Access::Read)
    } else {
        granted
    };

    let tree_id = sess_arc.read().await.alloc_tree_id();
    let tc = Arc::new(tokio::sync::RwLock::new(TreeConnect::new(
        tree_id,
        share.clone(),
        granted,
    )));
    {
        let sess = sess_arc.read().await;
        let mut trees = sess.trees.write().await;
        trees.insert(tree_id, tc);
    }

    let maximal_access = match granted {
        Access::Read => FILE_GENERIC_READ | FILE_GENERIC_EXECUTE,
        Access::ReadWrite => FILE_ALL_ACCESS,
    };
    let share_type = if share.is_ipc {
        SHARE_TYPE_PIPE
    } else {
        SHARE_TYPE_DISK
    };
    let resp = TreeConnectResponse {
        structure_size: 16,
        share_type,
        reserved: 0,
        share_flags: share_flags(server, conn, share_type).await,
        capabilities: 0,
        maximal_access,
    };
    let mut buf = Vec::new();
    resp.write_to(&mut buf).expect("encode");
    info!(tree_id, share = %share.name, ?granted, "tree connect");
    let mut hr = HandlerResponse::ok(buf);
    hr.override_tree_id = Some(tree_id);
    hr
}

async fn share_flags(server: &Arc<ServerState>, conn: &Arc<Connection>, share_type: u8) -> u32 {
    if share_type == SHARE_TYPE_PIPE {
        return TreeConnectResponse::SHARE_FLAG_NO_CACHING;
    }

    let mut flags = TreeConnectResponse::SHARE_FLAG_MANUAL_CACHING;
    let transport_security = *conn.transport_security.read().await;
    if server.config.encrypt_data && !transport_security {
        flags |= TreeConnectResponse::SHARE_FLAG_ENCRYPT_DATA;
    }
    let dialect = *conn.dialect.read().await;
    let compression_algorithm = *conn.compression_algorithm.read().await;
    if dialect == Some(Dialect::Smb311) && compression_algorithm != 0 {
        flags |= TreeConnectResponse::SHARE_FLAG_COMPRESS_DATA;
    }
    if dialect == Some(Dialect::Smb311) && transport_security {
        flags |= TreeConnectResponse::SHARE_FLAG_ISOLATED_TRANSPORT;
    }
    flags
}

fn extract_share_name(unc: &str) -> Option<String> {
    let normalized = unc.replace('/', "\\");
    if !normalized.starts_with(r"\\") {
        return None;
    }

    let parts: Vec<&str> = normalized.trim_matches('\\').split('\\').collect();
    if parts.len() != 2 || parts[0].is_empty() || parts[1].is_empty() {
        return None;
    }

    Some(parts[1].to_ascii_lowercase())
}

fn authorize(
    mode: &ShareMode,
    users: &std::collections::HashMap<String, Access>,
    identity: &Identity,
) -> Option<Access> {
    match mode {
        ShareMode::Public => Some(Access::ReadWrite),
        ShareMode::PublicReadOnly => Some(Access::Read),
        ShareMode::AuthenticatedOnly => match identity {
            Identity::Anonymous => None,
            Identity::User { user, .. } => users.get(user).copied(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SmbServer;
    use crate::proto::messages::CompressionCapabilities;
    use uuid::Uuid;

    fn test_conn() -> Arc<Connection> {
        Arc::new(Connection::new(
            Uuid::nil(),
            8 * 1024 * 1024,
            8 * 1024 * 1024,
            8,
        ))
    }

    fn test_server(encrypt_data: bool) -> Arc<ServerState> {
        SmbServer::builder()
            .listen("127.0.0.1:0".parse().unwrap())
            .encrypt_data(encrypt_data)
            .build()
            .expect("server builds")
            .state()
    }

    #[test]
    fn extract_share_name_accepts_unc_server_and_share() {
        assert_eq!(
            extract_share_name(r"\\host\VIRTUAL"),
            Some("virtual".to_string())
        );
        assert_eq!(
            extract_share_name(r"\\host\VIRTUAL\"),
            Some("virtual".to_string())
        );
        assert_eq!(
            extract_share_name("//host/VIRTUAL"),
            Some("virtual".to_string())
        );
    }

    #[test]
    fn extract_share_name_rejects_malformed_unc_paths() {
        for path in [
            "VIRTUAL",
            r"\host\VIRTUAL",
            r"\\host",
            r"\\host\",
            r"\\host\VIRTUAL\extra",
        ] {
            assert_eq!(extract_share_name(path), None, "path {path:?}");
        }
    }

    #[tokio::test]
    async fn disk_share_flags_reflect_encryption_and_compression_policy() {
        let server = test_server(true);
        let conn = test_conn();
        *conn.dialect.write().await = Some(Dialect::Smb311);
        *conn.compression_algorithm.write().await = CompressionCapabilities::ALGORITHM_LZ77;

        let flags = share_flags(&server, &conn, SHARE_TYPE_DISK).await;

        assert_ne!(flags & TreeConnectResponse::SHARE_FLAG_ENCRYPT_DATA, 0);
        assert_ne!(flags & TreeConnectResponse::SHARE_FLAG_COMPRESS_DATA, 0);
        assert_eq!(
            flags & TreeConnectResponse::SHARE_FLAG_ISOLATED_TRANSPORT,
            0
        );
    }

    #[tokio::test]
    async fn disk_share_flags_use_isolated_transport_when_transport_security_is_accepted() {
        let server = test_server(true);
        let conn = test_conn();
        *conn.dialect.write().await = Some(Dialect::Smb311);
        *conn.transport_security.write().await = true;

        let flags = share_flags(&server, &conn, SHARE_TYPE_DISK).await;

        assert_eq!(flags & TreeConnectResponse::SHARE_FLAG_ENCRYPT_DATA, 0);
        assert_ne!(
            flags & TreeConnectResponse::SHARE_FLAG_ISOLATED_TRANSPORT,
            0
        );
    }

    #[tokio::test]
    async fn disk_share_flags_default_to_manual_caching() {
        let server = test_server(false);
        let conn = test_conn();

        let flags = share_flags(&server, &conn, SHARE_TYPE_DISK).await;

        assert_eq!(flags, TreeConnectResponse::SHARE_FLAG_MANUAL_CACHING);
    }

    #[tokio::test]
    async fn ipc_share_flags_use_no_caching_without_disk_policy_bits() {
        let server = test_server(true);
        let conn = test_conn();
        *conn.dialect.write().await = Some(Dialect::Smb311);
        *conn.compression_algorithm.write().await = CompressionCapabilities::ALGORITHM_LZ77;

        let flags = share_flags(&server, &conn, SHARE_TYPE_PIPE).await;

        assert_eq!(flags, TreeConnectResponse::SHARE_FLAG_NO_CACHING);
    }
}
