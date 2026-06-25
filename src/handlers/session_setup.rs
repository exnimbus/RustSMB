//! SESSION_SETUP handler — drives the SPNEGO + NTLMv2 state machine.

use std::sync::Arc;

use crate::proto::auth::ntlm::{Identity, NtlmServer, NtlmTargetInfo, UserCreds};
use crate::proto::auth::spnego::{
    NegState, OID_NTLMSSP, decode_init_token, decode_resp_token, encode_resp_token,
};
use crate::proto::crypto::encryption::{encryption_key_300_c2s, encryption_key_300_s2c};
use crate::proto::crypto::{SigningAlgo, signing_key_30};
use crate::proto::error::ProtoError;
use crate::proto::header::Smb2Header;
use crate::proto::messages::{Dialect, SessionSetupRequest, SessionSetupResponse};
use tracing::{debug, info, warn};

use crate::conn::state::{Connection, PendingAuthState, Session};
use crate::dispatch::{HandlerResponse, ResponseSigningOverride};
use crate::ntstatus;
use crate::server::ServerState;
use crate::utils::{fill_random, now_filetime};

const SESSION_SETUP_SIGNING_REQUIRED: u8 = 0x02;

pub async fn handle(
    server: &Arc<ServerState>,
    conn: &Arc<Connection>,
    hdr: &Smb2Header,
    body: &[u8],
) -> HandlerResponse {
    let req = match SessionSetupRequest::parse(body) {
        Ok(r) => r,
        Err(_) => return HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER),
    };
    if req.security_mode & SESSION_SETUP_SIGNING_REQUIRED != 0 {
        *conn.client_requires_signing.write().await = true;
    }
    let dialect = *conn.dialect.read().await;
    if req.flags & SessionSetupRequest::FLAG_BINDING != 0
        && !matches!(
            dialect,
            Some(Dialect::Smb300 | Dialect::Smb302 | Dialect::Smb311)
        )
    {
        if hdr.session_id != 0
            && let Some((_, original_signing_algo, original_signing_context, _, _, _)) =
                server.session_signing_material(hdr.session_id).await
            && original_signing_context
            && original_signing_algo == SigningAlgo::AesGmac
            && original_signing_algo != *conn.signing_algo.read().await
        {
            return signed_session_setup_status_response(
                server,
                hdr.session_id,
                ntstatus::STATUS_REQUEST_OUT_OF_SEQUENCE,
            )
            .await;
        }
        return signed_session_setup_status_response(
            server,
            hdr.session_id,
            ntstatus::STATUS_REQUEST_NOT_ACCEPTED,
        )
        .await;
    }
    if hdr.session_id != 0
        && req.flags & SessionSetupRequest::FLAG_BINDING != 0
        && let Some((
            _,
            original_signing_algo,
            original_signing_context,
            original_dialect,
            _original_client_guid,
            original_cipher,
        )) = server.session_signing_material(hdr.session_id).await
    {
        let current_signing_algo = *conn.signing_algo.read().await;
        let current_signing_context = *conn.signing_context_present.read().await;
        let signing_algo_changed = original_signing_algo != current_signing_algo;
        if signing_algo_changed
            && original_signing_context
            && original_signing_algo == SigningAlgo::AesGmac
        {
            return signed_session_setup_status_response(
                server,
                hdr.session_id,
                ntstatus::STATUS_REQUEST_OUT_OF_SEQUENCE,
            )
            .await;
        }
        if signing_algo_changed
            && current_signing_context
            && current_signing_algo == SigningAlgo::AesGmac
        {
            return signed_session_setup_status_response(
                server,
                hdr.session_id,
                ntstatus::STATUS_NOT_SUPPORTED,
            )
            .await;
        }
        let current_cipher = *conn.encryption_cipher.read().await;
        if original_dialect != dialect || original_cipher != current_cipher {
            return signed_session_setup_status_response(
                server,
                hdr.session_id,
                ntstatus::STATUS_INVALID_PARAMETER,
            )
            .await;
        }
    }
    if hdr.session_id != 0 && req.flags & SessionSetupRequest::FLAG_BINDING == 0 {
        let local_session = {
            let sessions = conn.sessions.read().await;
            sessions.contains_key(&hdr.session_id)
        };
        if !local_session
            && server
                .session_signing_material(hdr.session_id)
                .await
                .is_some()
        {
            return signed_session_setup_status_response(
                server,
                hdr.session_id,
                ntstatus::STATUS_USER_SESSION_DELETED,
            )
            .await;
        }
    }

    let blob = req.security_buffer;
    if blob.is_empty() {
        return HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER);
    }
    if tracing::enabled!(tracing::Level::DEBUG) {
        let mut first8 = String::with_capacity(16);
        for b in blob.iter().take(8) {
            use std::fmt::Write as _;
            write!(&mut first8, "{b:02x}").expect("writing to String cannot fail");
        }
        tracing::debug!(
            first8 = %first8,
            len = blob.len(),
            sid = hdr.session_id,
            "session setup blob"
        );
    }

    // Decide which form the security blob takes:
    //   * GSS-API NegTokenInit       — starts with 0x60.
    //   * SPNEGO NegTokenResp        — starts with 0xa1 ([1] context tag).
    //   * Raw NTLMSSP message        — starts with "NTLMSSP\0" (RFC 4178
    //     §4.2.1 lets the client skip SPNEGO once the mech is settled; both
    //     Win11 reauth and Linux cifs.ko use this form).
    const NTLMSSP_MAGIC: &[u8] = b"NTLMSSP\0";
    let inner_token: Vec<u8>;
    let mut mech_list = Vec::new();
    let is_first_round: bool;
    let is_raw_ntlmssp: bool;
    if blob.starts_with(NTLMSSP_MAGIC) {
        // Raw NTLMSSP. Decide round by message-type at offset 8.
        let msg_type = if blob.len() >= 12 {
            u32::from_le_bytes([blob[8], blob[9], blob[10], blob[11]])
        } else {
            0
        };
        // 1 = NEGOTIATE (first), 3 = AUTHENTICATE (second). 2 is server-only.
        is_first_round = msg_type == 1;
        is_raw_ntlmssp = true;
        inner_token = blob.to_vec();
    } else if blob[0] == 0x60 {
        // GSS-API outer wrapper — NegTokenInit.
        let init = match decode_init_token(&blob) {
            Ok(t) => t,
            Err(e) => {
                warn!(error = %e, "SPNEGO init decode failed");
                return HandlerResponse::err(ntstatus::STATUS_LOGON_FAILURE);
            }
        };
        if !init.mech_types.iter().any(|m| m == OID_NTLMSSP) {
            if !server.anonymous_allowed().await {
                return HandlerResponse::err(ntstatus::STATUS_NOT_SUPPORTED);
            }
            return establish_anonymous_session(
                server,
                conn,
                hdr,
                req.previous_session_id,
                SessionSetupResponse::FLAG_IS_NULL,
                Some(empty_completed()),
            )
            .await;
        }
        mech_list = init.mech_list.clone();
        inner_token = init.mech_token.unwrap_or_default();
        is_first_round = true;
        is_raw_ntlmssp = false;
    } else {
        // NegTokenResp follow-up.
        let resp = match decode_resp_token(&blob) {
            Ok(r) => r,
            Err(e) => {
                warn!(error = %e, "SPNEGO resp decode failed");
                return HandlerResponse::err(ntstatus::STATUS_LOGON_FAILURE);
            }
        };
        inner_token = resp.response_token.unwrap_or_default();
        is_first_round = false;
        is_raw_ntlmssp = false;
    }

    if is_first_round {
        // Allocate a fresh session id for a new login; reauth on an existing
        // session keeps the current session id and can sign the challenge with
        // the current channel key.
        let reauth_existing_session = hdr.session_id != 0;
        let new_sid = if hdr.session_id != 0 {
            hdr.session_id
        } else {
            server.alloc_session_id()
        };
        let mut server_challenge = [0u8; 8];
        fill_random(&mut server_challenge);
        let netbios = server.config.netbios_name.clone();
        let mut acceptor = NtlmServer::new(
            server_challenge,
            NtlmTargetInfo::new(netbios.clone(), netbios.clone(), netbios, "", ""),
            now_filetime(),
        );

        // Step 1: parse client NEGOTIATE.
        if let Err(e) = acceptor.step1_negotiate(&inner_token) {
            warn!(error = %e, "NTLM step1 failed");
            return HandlerResponse::err(ntstatus::STATUS_LOGON_FAILURE);
        }
        let challenge_blob = acceptor.challenge();
        // Reply form mirrors the request: raw NTLMSSP if the client skipped
        // SPNEGO, else SPNEGO-wrapped.
        let outbound = if is_raw_ntlmssp {
            challenge_blob
        } else {
            encode_resp_token(
                NegState::AcceptIncomplete,
                Some(OID_NTLMSSP),
                Some(&challenge_blob),
                None,
            )
        };

        // Stash the acceptor for the next round; remember the form so the
        // success response can match.
        {
            let mut pa = conn.pending_auths.write().await;
            pa.insert(
                new_sid,
                Arc::new(std::sync::Mutex::new(PendingAuthState {
                    acceptor,
                    raw_ntlmssp: is_raw_ntlmssp,
                    mech_list,
                })),
            );
        }
        if req.previous_session_id != 0 {
            conn.pending_previous_session_ids
                .write()
                .await
                .insert(new_sid, req.previous_session_id);
        }

        let body_out =
            build_session_setup_response(ntstatus::STATUS_MORE_PROCESSING_REQUIRED, &outbound, 0);
        let signing_override = if req.flags & SessionSetupRequest::FLAG_BINDING != 0 {
            session_signing_override(server, hdr.session_id).await
        } else {
            None
        };
        return HandlerResponse {
            body: body_out,
            status: ntstatus::STATUS_MORE_PROCESSING_REQUIRED,
            override_tree_id: None,
            override_session_id: Some(new_sid),
            skip_signing: !reauth_existing_session && signing_override.is_none(),
            take_preauth_snapshot_for_session: None,
            take_preauth_snapshot_for_channel: None,
            async_id: None,
            async_final: false,
            signing_override,
        };
    }

    // Follow-up round: look up pending acceptor by session id from header.
    let sid = hdr.session_id;
    if sid == 0 {
        return HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER);
    }
    let acceptor_arc = {
        let mut pa = conn.pending_auths.write().await;
        pa.remove(&sid)
    };
    let acceptor_arc = match acceptor_arc {
        Some(a) => a,
        None => return HandlerResponse::err(ntstatus::STATUS_USER_SESSION_DELETED),
    };
    let users = server.users.table.read().await.clone();
    let (auth_result, raw_form, mech_list) = {
        let pair = acceptor_arc
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let acceptor = &pair.acceptor;
        let lookup = |u: &str, _d: &str| -> Option<UserCreds> { users.get(u).cloned() };
        let outcome = acceptor.authenticate(&inner_token, lookup);
        (outcome, pair.raw_ntlmssp, pair.mech_list.clone())
    };
    let outcome = match auth_result {
        Ok(outcome) => outcome,
        Err(e) => {
            info!(error = %e, "NTLM authenticate failed");
            server
                .cleanup_change_notifies_for_session_id(sid, ntstatus::STATUS_NOTIFY_CLEANUP)
                .await;
            conn.close_session(sid).await;
            let status = if matches!(e, ProtoError::Malformed(_)) {
                ntstatus::STATUS_INVALID_PARAMETER
            } else {
                ntstatus::STATUS_LOGON_FAILURE
            };
            return session_setup_status_response(status);
        }
    };

    let existing_session = {
        let sessions = conn.sessions.read().await;
        sessions.get(&sid).cloned()
    };
    let is_reauth = existing_session.is_some();
    let is_binding = req.flags & SessionSetupRequest::FLAG_BINDING != 0 && hdr.session_id != 0;

    let session_base_key = outcome.session_key;
    let signing_key = match dialect {
        Some(Dialect::Smb202 | Dialect::Smb210) => session_base_key,
        Some(Dialect::Smb300 | Dialect::Smb302) => signing_key_30(&session_base_key),
        Some(Dialect::Smb311) => [0u8; 16],
        Some(Dialect::Smb2Wildcard) | None => {
            return HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER);
        }
    };

    let is_anonymous = matches!(outcome.identity, Identity::Anonymous);
    let allow_anonymous_encryption =
        is_anonymous && connection_has_authenticated_session(conn, sid).await;
    let enable_smb_encryption =
        server.config.encrypt_data && !*conn.transport_security.read().await;
    let session_flags = if is_reauth {
        0
    } else if is_anonymous {
        SessionSetupResponse::FLAG_IS_GUEST
    } else if server.config.encrypt_data && enable_smb_encryption {
        SessionSetupResponse::FLAG_ENCRYPT_DATA
    } else {
        0
    };
    let has_exported_session_key = session_base_key != [0u8; 16];
    let anonymous_can_sign = is_anonymous && has_exported_session_key;
    let signing_required = !is_anonymous
        && (server.config.require_signing || *conn.client_requires_signing.read().await);

    let previous_session_id = {
        let mut pending_previous = conn.pending_previous_session_ids.write().await;
        let pending = pending_previous.remove(&sid).unwrap_or(0);
        if req.previous_session_id != 0 {
            req.previous_session_id
        } else {
            pending
        }
    };
    if previous_session_id != 0 {
        server.takeover_previous_session(previous_session_id).await;
    }

    let mut decrypt_key = None;
    let mut encrypt_key = None;
    let encryption_allowed = !is_reauth
        && (!is_anonymous || allow_anonymous_encryption)
        && !*conn.transport_security.read().await;
    if encryption_allowed && matches!(dialect, Some(Dialect::Smb300 | Dialect::Smb302)) {
        decrypt_key = Some(encryption_key_300_c2s(&session_base_key));
        encrypt_key = Some(encryption_key_300_s2c(&session_base_key));
    }
    if is_reauth {
        if let Some(session) = existing_session {
            let mut session = session.write().await;
            session.identity = outcome.identity.clone();
            session.reauth_anonymous = is_anonymous;
        }
    } else if is_binding {
        let Some(session_arc) = server.session_state(sid).await else {
            return signed_session_setup_status_response(
                server,
                sid,
                ntstatus::STATUS_USER_SESSION_DELETED,
            )
            .await;
        };
        conn.sessions.write().await.insert(sid, session_arc);
        if matches!(dialect, Some(Dialect::Smb300 | Dialect::Smb302)) {
            conn.session_signing_keys
                .write()
                .await
                .insert(sid, signing_key);
        }
    } else {
        let mut session = Session::new(
            sid,
            outcome.identity.clone(),
            session_base_key,
            signing_key,
            signing_required,
            None,
        );
        session.decrypt_key = decrypt_key;
        session.encrypt_key = encrypt_key;
        session.encryption_allowed = encryption_allowed;
        let session_arc = Arc::new(tokio::sync::RwLock::new(session));
        conn.sessions.write().await.insert(sid, session_arc);
    }

    // Empty buffer for raw NTLMSSP path; SPNEGO accept-completed for SPNEGO.
    let success_buf: Vec<u8> = if raw_form {
        Vec::new()
    } else {
        let mic = if !is_anonymous && !mech_list.is_empty() {
            match NtlmServer::sign_server_message(
                &outcome.session_key,
                outcome.flags,
                0,
                &mech_list,
            ) {
                Ok(mic) => Some(mic),
                Err(e) => {
                    warn!(error = %e, "NTLM mechListMIC signing failed");
                    return HandlerResponse::err(ntstatus::STATUS_LOGON_FAILURE);
                }
            }
        } else {
            None
        };
        encode_resp_token(NegState::AcceptCompleted, None, None, mic.as_deref())
    };
    let body_out =
        build_session_setup_response(ntstatus::STATUS_SUCCESS, &success_buf, session_flags);

    let take_snapshot = if !is_reauth
        && !is_binding
        && dialect == Some(Dialect::Smb311)
        && (!is_anonymous || allow_anonymous_encryption || anonymous_can_sign)
    {
        Some(sid)
    } else {
        None
    };
    let take_channel_snapshot = if is_binding && dialect == Some(Dialect::Smb311) {
        Some((sid, session_base_key))
    } else {
        None
    };

    info!(?outcome.identity, "session established");

    HandlerResponse {
        body: body_out,
        status: ntstatus::STATUS_SUCCESS,
        override_tree_id: None,
        override_session_id: Some(sid),
        // Anonymous responses are not signed (no key). Signed responses for
        // authenticated sessions get signed by the dispatcher's normal path.
        skip_signing: is_anonymous && !is_reauth,
        take_preauth_snapshot_for_session: take_snapshot,
        take_preauth_snapshot_for_channel: take_channel_snapshot,
        async_id: None,
        async_final: false,
        signing_override: None,
    }
}

async fn establish_anonymous_session(
    server: &Arc<ServerState>,
    conn: &Arc<Connection>,
    hdr: &Smb2Header,
    previous_session_id: u64,
    session_flags: u16,
    success_buf: Option<Vec<u8>>,
) -> HandlerResponse {
    let sid = if hdr.session_id != 0 {
        hdr.session_id
    } else {
        server.alloc_session_id()
    };
    if previous_session_id != 0 {
        server.takeover_previous_session(previous_session_id).await;
    }
    let session = Session::new(sid, Identity::Anonymous, [0; 16], [0; 16], false, None);
    let session_arc = Arc::new(tokio::sync::RwLock::new(session));
    conn.sessions.write().await.insert(sid, session_arc);

    let body_out = build_session_setup_response(
        ntstatus::STATUS_SUCCESS,
        success_buf.as_deref().unwrap_or(&[]),
        session_flags,
    );
    HandlerResponse {
        body: body_out,
        status: ntstatus::STATUS_SUCCESS,
        override_tree_id: None,
        override_session_id: Some(sid),
        skip_signing: true,
        take_preauth_snapshot_for_session: None,
        take_preauth_snapshot_for_channel: None,
        async_id: None,
        async_final: false,
        signing_override: None,
    }
}

async fn connection_has_authenticated_session(conn: &Arc<Connection>, excluding_sid: u64) -> bool {
    let sessions = conn.sessions.read().await;
    let session_arcs = sessions
        .iter()
        .filter(|(sid, _)| **sid != excluding_sid)
        .map(|(_, session)| session.clone())
        .collect::<Vec<_>>();
    drop(sessions);

    for session in session_arcs {
        let session = session.read().await;
        if !matches!(session.identity, Identity::Anonymous) {
            return true;
        }
    }
    false
}

fn build_session_setup_response(_status: u32, spnego_blob: &[u8], session_flags: u16) -> Vec<u8> {
    let resp = SessionSetupResponse {
        structure_size: 9,
        session_flags,
        security_buffer_offset: 64 + 8, // SMB2 header + fixed prefix
        security_buffer_length: spnego_blob.len() as u16,
        security_buffer: spnego_blob.to_vec(),
    };
    let mut buf = Vec::new();
    resp.write_to(&mut buf)
        .expect("SESSION_SETUP response encodes");
    debug!(len = buf.len(), "SESSION_SETUP response built");
    buf
}

fn session_setup_status_response(status: u32) -> HandlerResponse {
    HandlerResponse {
        body: build_session_setup_response(status, &[], 0),
        status,
        override_tree_id: None,
        override_session_id: None,
        skip_signing: true,
        take_preauth_snapshot_for_session: None,
        take_preauth_snapshot_for_channel: None,
        async_id: None,
        async_final: false,
        signing_override: None,
    }
}

async fn signed_session_setup_status_response(
    server: &Arc<ServerState>,
    session_id: u64,
    status: u32,
) -> HandlerResponse {
    let mut response = session_setup_status_response(status);
    if let Some(signing) = session_signing_override(server, session_id).await {
        response.signing_override = Some(signing);
        response.skip_signing = false;
    }
    response
}

async fn session_signing_override(
    server: &Arc<ServerState>,
    session_id: u64,
) -> Option<ResponseSigningOverride> {
    let (key, algo, _, _, _, _) = server.session_signing_material(session_id).await?;
    Some(ResponseSigningOverride { key, algo })
}

fn empty_completed() -> Vec<u8> {
    encode_resp_token(NegState::AcceptCompleted, None, None, None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conn::state::Connection;
    use crate::proto::header::{Command, Smb2Header};
    use crate::proto::messages::SessionSetupRequest;
    use crate::{LocalFsBackend, Share, SmbServer};
    use tempfile::tempdir;
    use uuid::Uuid;

    fn anonymous_ntlm_negotiate_token() -> Vec<u8> {
        let mut ntlm_negotiate = Vec::new();
        ntlm_negotiate.extend_from_slice(b"NTLMSSP\0");
        ntlm_negotiate.extend_from_slice(&1u32.to_le_bytes());
        ntlm_negotiate.extend_from_slice(&0x6209_8215u32.to_le_bytes());
        ntlm_negotiate.extend_from_slice(&[0u8; 16]);
        ntlm_negotiate.extend_from_slice(&[0u8; 8]);
        ntlm_negotiate
    }

    fn anonymous_ntlm_authenticate_token() -> Vec<u8> {
        let mut ntlm_auth = Vec::new();
        ntlm_auth.extend_from_slice(b"NTLMSSP\0");
        ntlm_auth.extend_from_slice(&3u32.to_le_bytes());
        let header_len: u32 = 72;
        for _ in 0..6 {
            ntlm_auth.extend_from_slice(&0u16.to_le_bytes());
            ntlm_auth.extend_from_slice(&0u16.to_le_bytes());
            ntlm_auth.extend_from_slice(&header_len.to_le_bytes());
        }
        ntlm_auth.extend_from_slice(&0x0000_0800u32.to_le_bytes());
        ntlm_auth.extend_from_slice(&[0u8; 8]);
        ntlm_auth
    }

    fn session_setup_body(security_mode: u8, security_buffer: Vec<u8>) -> Vec<u8> {
        let req = SessionSetupRequest {
            structure_size: 25,
            flags: 0,
            security_mode,
            capabilities: 0,
            channel: 0,
            security_buffer_offset: 88,
            security_buffer_length: security_buffer.len() as u16,
            previous_session_id: 0,
            security_buffer,
        };
        let mut body = Vec::new();
        req.write_to(&mut body).expect("session setup encodes");
        body
    }

    fn session_setup_header(message_id: u64, session_id: u64) -> Smb2Header {
        Smb2Header {
            command: Command::SessionSetup,
            message_id,
            session_id,
            ..Default::default()
        }
    }

    async fn public_server_state_and_conn() -> (Arc<ServerState>, Arc<Connection>, tempfile::TempDir)
    {
        let td = tempdir().expect("tempdir");
        let backend = LocalFsBackend::new(td.path()).expect("local backend");
        let server = SmbServer::builder()
            .listen("127.0.0.1:0".parse().unwrap())
            .share(Share::new("share", backend).public())
            .build()
            .expect("server builds");
        let state = server.state();
        let conn = Arc::new(Connection::new(
            Uuid::nil(),
            state.config.max_read_size,
            state.config.max_write_size,
            state.config.max_credits,
        ));
        *conn.dialect.write().await = Some(Dialect::Smb311);
        (state, conn, td)
    }

    #[tokio::test]
    async fn signing_required_session_setup_records_client_bit_but_guest_session_is_unsigned() {
        let (server, conn, _td) = public_server_state_and_conn().await;

        let first = handle(
            &server,
            &conn,
            &session_setup_header(1, 0),
            &session_setup_body(
                SESSION_SETUP_SIGNING_REQUIRED,
                anonymous_ntlm_negotiate_token(),
            ),
        )
        .await;
        assert_eq!(first.status, ntstatus::STATUS_MORE_PROCESSING_REQUIRED);
        assert!(*conn.client_requires_signing.read().await);
        let sid = first
            .override_session_id
            .expect("first response should allocate a session id");

        let second = handle(
            &server,
            &conn,
            &session_setup_header(2, sid),
            &session_setup_body(
                SESSION_SETUP_SIGNING_REQUIRED,
                anonymous_ntlm_authenticate_token(),
            ),
        )
        .await;
        assert_eq!(second.status, ntstatus::STATUS_SUCCESS);
        assert!(second.skip_signing, "anonymous final response is unsigned");

        let sessions = conn.sessions.read().await;
        let session = sessions.get(&sid).expect("guest session").read().await;
        assert!(
            !session.signing_required,
            "guest/null sessions do not require signing even when the client requested it"
        );
    }
}
