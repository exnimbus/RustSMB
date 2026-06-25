//! Per-frame dispatch: parse header, route to handler, sign response, encode.

use std::sync::Arc;

use crate::proto::auth::ntlm::Identity;
use crate::proto::crypto::encryption::{
    decrypt_ccm, decrypt_gcm, encrypt_ccm, encrypt_gcm, encryption_key_311_c2s,
    encryption_key_311_c2s_256, encryption_key_311_s2c, encryption_key_311_s2c_256,
    is_encryption_transform,
};
use crate::proto::crypto::{
    PreauthIntegrity, SigningAlgo, compress_response, decompress_transform, sign,
};
use crate::proto::header::{
    Command, HeaderTail, SMB2_FLAGS_ASYNC_COMMAND, SMB2_FLAGS_RELATED_OPERATIONS,
    SMB2_FLAGS_SERVER_TO_REDIR, SMB2_FLAGS_SIGNED, SMB2_HEADER_LEN, Smb2Header,
};
use crate::proto::messages::{
    CreateContext, CreateRequest, Dialect, EncryptionCapabilities, ErrorResponse, FileId,
    IoctlRequest, QueryDirectoryRequest, QueryInfoRequest, ReadRequest, SetInfoRequest,
    WriteRequest,
};
use tracing::{Instrument, debug, debug_span, error, warn};

use crate::conn::state::Connection;
use crate::handlers;
use crate::ntstatus;
use crate::server::ServerState;

/// Result of a handler: a complete (unsigned) response payload + the NTSTATUS
/// to set in the header. The dispatcher patches the header, applies signing
/// (if required), and ships the bytes.
pub struct HandlerResponse {
    /// Bytes after the SMB2 header — the body. The handler owns body
    /// construction.
    pub body: Vec<u8>,
    /// NTSTATUS for the response header.
    pub status: u32,
    /// Optional override for `tree_id` on the response header (e.g.
    /// TREE_CONNECT returns the freshly minted tree id).
    pub override_tree_id: Option<u32>,
    /// Optional override for `session_id` on the response header (e.g.
    /// SESSION_SETUP returns the freshly minted session id).
    pub override_session_id: Option<u64>,
    /// If true, the dispatcher will not sign the response. Used for
    /// pre-session-setup messages where no key exists yet.
    pub skip_signing: bool,
    /// If set, take the per-session 3.1.1 preauth snapshot after hashing the
    /// SESSION_SETUP request but before hashing the response. Set by
    /// SESSION_SETUP on the round that produces STATUS_SUCCESS, so the
    /// session's KDF context can use the snapshot.
    pub take_preauth_snapshot_for_session: Option<u64>,
    /// Same snapshot timing as `take_preauth_snapshot_for_session`, but stores
    /// keys on this connection for a bound SMB 3.1.1 channel instead of
    /// mutating the shared session.
    pub take_preauth_snapshot_for_channel: Option<(u64, [u8; 16])>,
    /// AsyncId for SMB2 async-form responses such as STATUS_PENDING.
    pub async_id: Option<u64>,
    /// True for final async completions. Pending responses grant credits;
    /// final async completions do not.
    pub async_final: bool,
    /// Optional signing material for responses that must be signed with a
    /// session from another connection, such as rejected SMB2 session binding.
    pub signing_override: Option<ResponseSigningOverride>,
}

#[derive(Debug, Clone, Copy)]
pub struct ResponseSigningOverride {
    pub key: [u8; 16],
    pub algo: SigningAlgo,
}

impl HandlerResponse {
    pub fn ok(body: Vec<u8>) -> Self {
        Self {
            body,
            status: ntstatus::STATUS_SUCCESS,
            override_tree_id: None,
            override_session_id: None,
            skip_signing: false,
            take_preauth_snapshot_for_session: None,
            take_preauth_snapshot_for_channel: None,
            async_id: None,
            async_final: false,
            signing_override: None,
        }
    }

    pub fn err(status: u32) -> Self {
        let er = ErrorResponse::status(status);
        let mut buf = Vec::new();
        er.write_to(&mut buf).expect("error response encodes");
        Self {
            body: buf,
            status,
            override_tree_id: None,
            override_session_id: None,
            skip_signing: false,
            take_preauth_snapshot_for_session: None,
            take_preauth_snapshot_for_channel: None,
            async_id: None,
            async_final: false,
            signing_override: None,
        }
    }

    pub fn pending_async(async_id: u64, body: Vec<u8>) -> Self {
        Self {
            body,
            status: ntstatus::STATUS_PENDING,
            override_tree_id: None,
            override_session_id: None,
            skip_signing: false,
            take_preauth_snapshot_for_session: None,
            take_preauth_snapshot_for_channel: None,
            async_id: Some(async_id),
            async_final: false,
            signing_override: None,
        }
    }

    pub fn final_async(async_id: u64, status: u32, body: Vec<u8>) -> Self {
        Self {
            body,
            status,
            override_tree_id: None,
            override_session_id: None,
            skip_signing: false,
            take_preauth_snapshot_for_session: None,
            take_preauth_snapshot_for_channel: None,
            async_id: Some(async_id),
            async_final: true,
            signing_override: None,
        }
    }
}

pub(crate) fn build_unsolicited_response_bytes(command: Command, body: Vec<u8>) -> Vec<u8> {
    let hdr = Smb2Header {
        credit_charge: 0,
        channel_sequence_status: ntstatus::STATUS_SUCCESS,
        command,
        credit_request_response: 0,
        flags: SMB2_FLAGS_SERVER_TO_REDIR,
        next_command: 0,
        message_id: u64::MAX,
        tail: HeaderTail::sync(0),
        session_id: 0,
        signature: [0u8; 16],
    };

    let mut out = Vec::with_capacity(SMB2_HEADER_LEN + body.len());
    hdr.write(&mut out).expect("SMB2 header encodes");
    out.extend_from_slice(&body);
    out
}

/// Top-level frame dispatch. Returns the bytes to push into the writer
/// channel, or `None` if the request elicits no response (CANCEL).
pub async fn dispatch_frame(
    server: &Arc<ServerState>,
    conn: &Arc<Connection>,
    frame: &[u8],
) -> Option<Vec<u8>> {
    let decrypted;
    let request_was_encrypted = is_encryption_transform(frame);
    let frame = if request_was_encrypted {
        match decrypt_request_transform(conn, frame).await {
            Ok(plain) => {
                decrypted = plain;
                decrypted.as_slice()
            }
            Err(e) => {
                warn!(error = %e, "failed to decrypt SMB encryption transform");
                conn.request_disconnect();
                return None;
            }
        }
    } else {
        frame
    };

    let decompressed;
    let frame = if crate::proto::crypto::is_compression_transform(frame) {
        let algorithm = *conn.compression_algorithm.read().await;
        let allowed = if algorithm == 0 {
            Vec::new()
        } else {
            vec![algorithm]
        };
        match decompress_transform(frame, &allowed, crate::proto::framing::MAX_FRAME_PAYLOAD) {
            Ok(plain) => {
                decompressed = plain;
                decompressed.as_slice()
            }
            Err(e) => {
                warn!(error = %e, "failed to decompress SMB compression transform");
                return None;
            }
        }
    } else {
        frame
    };

    // SMB1 multi-protocol bootstrap (MS-SMB2 §3.3.5.3.1). The only SMB1 we
    // accept: a NEGOTIATE_REQUEST listing "SMB 2.???" or "SMB 2.002".
    // Reply with an SMB2 NEGOTIATE response and the client follows up with
    // a real SMB2 NEGOTIATE.
    if let Some(bytes) = handle_smb1_multi_protocol(server, conn, frame).await {
        return Some(bytes);
    }
    if frame.len() < SMB2_HEADER_LEN {
        warn!(len = frame.len(), "frame too short for SMB2 header");
        return None;
    }

    let first_hdr = match Smb2Header::parse(frame) {
        Ok((hdr, _)) => hdr,
        Err(e) => {
            warn!(error = %e, "failed to parse first header");
            return None;
        }
    };
    if !request_was_encrypted && requires_encrypted_request(server, conn, &first_hdr).await {
        let response = build_response_bytes(
            conn,
            &first_hdr,
            HandlerResponse::err(ntstatus::STATUS_ACCESS_DENIED),
        )
        .await;
        return Some(
            maybe_encrypt_response(
                conn,
                Some(first_hdr.command),
                first_hdr.session_id,
                response,
                server.config.encrypt_data || request_was_encrypted,
            )
            .await,
        );
    }

    let mut sub_offset = 0;
    let mut responses = Vec::new();
    let mut prev_session_id = 0;
    let mut prev_tree_id = 0;
    let mut prev_related_file_id = None;
    let mut related_setup_status = ntstatus::STATUS_SUCCESS;
    let mut related_context_valid = false;
    let mut first_command = None;

    while sub_offset < frame.len() {
        let available = &frame[sub_offset..];
        if available.len() < SMB2_HEADER_LEN {
            warn!(remaining = available.len(), "compound tail too short");
            return None;
        }

        let (mut req_hdr, _) = match Smb2Header::parse(available) {
            Ok(p) => p,
            Err(e) => {
                warn!(error = %e, "failed to parse compound sub-header");
                return None;
            }
        };
        first_command.get_or_insert(req_hdr.command);

        let next = req_hdr.next_command as usize;
        let sub_len = if next == 0 {
            available.len()
        } else if next < SMB2_HEADER_LEN || next > available.len() {
            warn!(
                next,
                remaining = available.len(),
                "invalid compound NextCommand"
            );
            return None;
        } else {
            next
        };

        let related = req_hdr.flags & SMB2_FLAGS_RELATED_OPERATIONS != 0;
        let mut sub_frame = available[..sub_len].to_vec();
        if related {
            inherit_related_context(
                &mut sub_frame,
                &mut req_hdr,
                prev_session_id,
                prev_tree_id,
                prev_related_file_id,
            );
        } else {
            prev_related_file_id = None;
        }

        prev_session_id = req_hdr.session_id;
        prev_tree_id = req_hdr.tree_id().unwrap_or(0);

        let response = if related && !related_context_valid {
            Some(
                build_response_bytes(
                    conn,
                    &req_hdr,
                    HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER),
                )
                .await,
            )
        } else if related
            && prev_related_file_id.is_none()
            && related_setup_status != ntstatus::STATUS_SUCCESS
        {
            Some(
                build_response_bytes(conn, &req_hdr, HandlerResponse::err(related_setup_status))
                    .await,
            )
        } else {
            dispatch_one(server, conn, &sub_frame, request_was_encrypted).await
        };

        if let Some(mut response) = response {
            if let Some(async_id) = pending_async_response_id(&response) {
                let tail_start = sub_offset + sub_len;
                let tail = frame[tail_start..].to_vec();
                let tail_for_final = tail.clone();
                let mut prefix_responses = std::mem::take(&mut responses);
                let keep_async_final = prefix_responses.is_empty();
                let prefix_responses_for_final = if keep_async_final {
                    Vec::new()
                } else {
                    prefix_responses.clone()
                };
                let prev_related_file_id_before_pending = prev_related_file_id;
                let server_for_final = Arc::clone(server);
                let conn_for_final = Arc::clone(conn);
                let pending_req_hdr = req_hdr;
                let deferred_first_command = first_command;
                let first_session_id = first_hdr.session_id;
                let attached = server.attach_cache_break_compound_completion(
                    conn,
                    async_id,
                    Box::new(move |final_response| {
                        Box::pin(async move {
                            build_deferred_compound_response(
                                server_for_final,
                                conn_for_final,
                                deferred_first_command,
                                first_session_id,
                                prefix_responses_for_final,
                                pending_req_hdr,
                                final_response,
                                keep_async_final,
                                prev_related_file_id_before_pending,
                                tail_for_final,
                                request_was_encrypted,
                            )
                            .await
                        })
                    }),
                );
                if attached {
                    if keep_async_final {
                        let compressed =
                            maybe_compress_response(conn, first_command, response).await;
                        return Some(
                            maybe_encrypt_response(
                                conn,
                                first_command,
                                first_hdr.session_id,
                                compressed,
                                server.config.encrypt_data || request_was_encrypted,
                            )
                            .await,
                        );
                    }
                    return None;
                }
                if !tail.is_empty() {
                    let _ = server.discard_pending_async(conn, async_id);
                    responses = prefix_responses;
                    response = build_response_bytes(
                        conn,
                        &req_hdr,
                        HandlerResponse::err(ntstatus::STATUS_INTERNAL_ERROR),
                    )
                    .await;
                } else if !prefix_responses.is_empty() {
                    prefix_responses.push(response);
                    let stitched = stitch_responses(conn, prefix_responses).await;
                    let compressed = maybe_compress_response(conn, first_command, stitched).await;
                    return Some(
                        maybe_encrypt_response(
                            conn,
                            first_command,
                            first_hdr.session_id,
                            compressed,
                            server.config.encrypt_data || request_was_encrypted,
                        )
                        .await,
                    );
                } else {
                    responses = Vec::new();
                }
            }
            let status = read_u32(&response, 0x08);
            if req_hdr.command == Command::Create {
                if let Some(file_id) = capture_create_file_id(&response) {
                    prev_related_file_id = Some(file_id);
                }
            } else if status == ntstatus::STATUS_SUCCESS
                && let Some(file_id) = capture_request_file_id(&sub_frame, req_hdr.command)
            {
                prev_related_file_id = Some(file_id);
            }
            if (related || req_hdr.command == Command::Create)
                && prev_related_file_id.is_none()
                && status != ntstatus::STATUS_SUCCESS
                && status != ntstatus::STATUS_PENDING
            {
                related_setup_status = status;
            }
            related_context_valid = if related || req_hdr.command == Command::Create {
                true
            } else {
                status != ntstatus::STATUS_USER_SESSION_DELETED
            };
            responses.push(response);
        }

        if next == 0 {
            break;
        }
        sub_offset += next;
    }

    if responses.is_empty() {
        return None;
    }

    let stitched = stitch_responses(conn, responses).await;
    let compressed = maybe_compress_response(conn, first_command, stitched).await;
    Some(
        maybe_encrypt_response(
            conn,
            first_command,
            first_hdr.session_id,
            compressed,
            server.config.encrypt_data || request_was_encrypted,
        )
        .await,
    )
}

async fn build_deferred_compound_response(
    server: Arc<ServerState>,
    conn: Arc<Connection>,
    first_command: Option<Command>,
    first_session_id: u64,
    mut responses: Vec<Vec<u8>>,
    pending_req_hdr: Smb2Header,
    mut final_response: HandlerResponse,
    keep_async_final: bool,
    mut prev_related_file_id: Option<[u8; 16]>,
    tail: Vec<u8>,
    request_was_encrypted: bool,
) -> Vec<u8> {
    if !keep_async_final {
        final_response.async_id = None;
        final_response.async_final = false;
    }
    let final_bytes = build_response_bytes(&conn, &pending_req_hdr, final_response).await;
    let final_status = read_u32(&final_bytes, 0x08);
    let mut related_setup_status = ntstatus::STATUS_SUCCESS;
    if pending_req_hdr.command == Command::Create
        && let Some(file_id) = capture_create_file_id(&final_bytes)
    {
        prev_related_file_id = Some(file_id);
    }
    if pending_req_hdr.command == Command::Create
        && prev_related_file_id.is_none()
        && final_status != ntstatus::STATUS_SUCCESS
        && final_status != ntstatus::STATUS_PENDING
    {
        related_setup_status = final_status;
    }
    let mut prev_session_id = pending_req_hdr.session_id;
    let mut prev_tree_id = pending_req_hdr.tree_id().unwrap_or(0);
    let mut related_context_valid =
        pending_req_hdr.command == Command::Create || final_status == ntstatus::STATUS_SUCCESS;
    responses.push(final_bytes);

    let mut sub_offset = 0;
    while sub_offset < tail.len() {
        let available = &tail[sub_offset..];
        if available.len() < SMB2_HEADER_LEN {
            warn!(
                remaining = available.len(),
                "compound deferred tail too short"
            );
            break;
        }

        let (mut req_hdr, _) = match Smb2Header::parse(available) {
            Ok(p) => p,
            Err(e) => {
                warn!(error = %e, "failed to parse deferred compound sub-header");
                break;
            }
        };
        let next = req_hdr.next_command as usize;
        let sub_len = if next == 0 {
            available.len()
        } else if next < SMB2_HEADER_LEN || next > available.len() {
            warn!(
                next,
                remaining = available.len(),
                "invalid deferred compound NextCommand"
            );
            break;
        } else {
            next
        };

        let related = req_hdr.flags & SMB2_FLAGS_RELATED_OPERATIONS != 0;
        let mut sub_frame = available[..sub_len].to_vec();
        if related {
            inherit_related_context(
                &mut sub_frame,
                &mut req_hdr,
                prev_session_id,
                prev_tree_id,
                prev_related_file_id,
            );
        } else {
            prev_related_file_id = None;
        }
        prev_session_id = req_hdr.session_id;
        prev_tree_id = req_hdr.tree_id().unwrap_or(0);

        let response = if related && !related_context_valid {
            Some(
                build_response_bytes(
                    &conn,
                    &req_hdr,
                    HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER),
                )
                .await,
            )
        } else if related
            && prev_related_file_id.is_none()
            && related_setup_status != ntstatus::STATUS_SUCCESS
        {
            Some(
                build_response_bytes(&conn, &req_hdr, HandlerResponse::err(related_setup_status))
                    .await,
            )
        } else {
            dispatch_one(&server, &conn, &sub_frame, request_was_encrypted).await
        };

        if let Some(response) = response {
            let status = read_u32(&response, 0x08);
            if req_hdr.command == Command::Create {
                if let Some(file_id) = capture_create_file_id(&response) {
                    prev_related_file_id = Some(file_id);
                }
            } else if status == ntstatus::STATUS_SUCCESS
                && let Some(file_id) = capture_request_file_id(&sub_frame, req_hdr.command)
            {
                prev_related_file_id = Some(file_id);
            }
            if (related || req_hdr.command == Command::Create)
                && prev_related_file_id.is_none()
                && status != ntstatus::STATUS_SUCCESS
                && status != ntstatus::STATUS_PENDING
            {
                related_setup_status = status;
            }
            related_context_valid = if related || req_hdr.command == Command::Create {
                true
            } else {
                status != ntstatus::STATUS_USER_SESSION_DELETED
            };
            responses.push(response);
        }

        if next == 0 {
            break;
        }
        sub_offset += next;
    }

    let stitched = stitch_responses(&conn, responses).await;
    let compressed = maybe_compress_response(&conn, first_command, stitched).await;
    maybe_encrypt_response(
        &conn,
        first_command,
        first_session_id,
        compressed,
        server.config.encrypt_data || request_was_encrypted,
    )
    .await
}

fn pending_async_response_id(response: &[u8]) -> Option<u64> {
    let (hdr, _) = Smb2Header::parse(response).ok()?;
    if hdr.channel_sequence_status == ntstatus::STATUS_PENDING {
        hdr.async_id()
    } else {
        None
    }
}

/// True when a frame can be dispatched concurrently with other independent
/// I/O frames on the same connection. This intentionally accepts only the
/// GoSMB-compatible fast path: one cleartext, standalone READ or WRITE with a
/// real FileId and no channel-info payload. Everything else stays behind the
/// ordered connection dispatch gate.
pub(crate) async fn can_dispatch_independent_frame(
    server: &Arc<ServerState>,
    conn: &Arc<Connection>,
    frame: &[u8],
) -> bool {
    if is_encryption_transform(frame) || crate::proto::crypto::is_compression_transform(frame) {
        return false;
    }
    let Ok((hdr, body)) = Smb2Header::parse(frame) else {
        return false;
    };
    if hdr.next_command != 0
        || hdr.flags & (SMB2_FLAGS_RELATED_OPERATIONS | SMB2_FLAGS_ASYNC_COMMAND) != 0
        || hdr.session_id == 0
        || hdr.tree_id().unwrap_or(0) == 0
        || requires_encrypted_request(server, conn, &hdr).await
    {
        return false;
    }

    match hdr.command {
        Command::Read => {
            let Ok(req) = ReadRequest::parse(body) else {
                return false;
            };
            req.channel == 0
                && req.read_channel_info_offset == 0
                && req.read_channel_info_length == 0
                && req.file_id != crate::proto::messages::FileId::any()
        }
        Command::Write => {
            let Ok(req) = WriteRequest::parse(body) else {
                return false;
            };
            req.channel == 0
                && req.write_channel_info_offset == 0
                && req.write_channel_info_length == 0
                && req.file_id != crate::proto::messages::FileId::any()
        }
        _ => false,
    }
}

async fn maybe_compress_response(
    conn: &Arc<Connection>,
    first_command: Option<Command>,
    response: Vec<u8>,
) -> Vec<u8> {
    if matches!(
        first_command,
        Some(Command::Negotiate | Command::SessionSetup)
    ) {
        return response;
    }
    let algorithm = *conn.compression_algorithm.read().await;
    if algorithm == 0 {
        return response;
    }
    compress_response(&response, algorithm).unwrap_or(response)
}

async fn decrypt_request_transform(
    conn: &Arc<Connection>,
    frame: &[u8],
) -> Result<Vec<u8>, &'static str> {
    let session_id = encrypted_transform_session_id(frame).ok_or("invalid transform header")?;
    let (cipher, key) = session_encryption_key(conn, session_id, EncryptionDirection::Decrypt)
        .await
        .ok_or("encrypted session key not found")?;
    decrypt_with_cipher(cipher, &key, frame)
}

async fn maybe_encrypt_response(
    conn: &Arc<Connection>,
    first_command: Option<Command>,
    session_id: u64,
    response: Vec<u8>,
    encrypt_response: bool,
) -> Vec<u8> {
    if matches!(
        first_command,
        Some(Command::Negotiate | Command::SessionSetup)
    ) {
        return response;
    }
    if !encrypt_response {
        return response;
    }
    let Some((cipher, key)) =
        session_encryption_key(conn, session_id, EncryptionDirection::Encrypt).await
    else {
        return response;
    };
    match encrypt_with_cipher(cipher, &key, session_id, &response) {
        Ok(encrypted) => encrypted,
        Err(e) => {
            error!(error = %e, "failed to encrypt SMB response");
            response
        }
    }
}

async fn requires_encrypted_request(
    server: &Arc<ServerState>,
    conn: &Arc<Connection>,
    hdr: &Smb2Header,
) -> bool {
    if matches!(hdr.command, Command::Negotiate | Command::SessionSetup) || hdr.session_id == 0 {
        return false;
    }
    if !server.config.encrypt_data {
        return false;
    }
    session_encryption_key(conn, hdr.session_id, EncryptionDirection::Decrypt)
        .await
        .is_some()
}

#[derive(Clone, Copy)]
enum EncryptionDirection {
    Decrypt,
    Encrypt,
}

async fn session_encryption_key(
    conn: &Arc<Connection>,
    session_id: u64,
    direction: EncryptionDirection,
) -> Option<(u16, Vec<u8>)> {
    if *conn.transport_security.read().await {
        return None;
    }
    let cipher = *conn.encryption_cipher.read().await;
    if cipher == 0 {
        return None;
    }
    let channel_key = match direction {
        EncryptionDirection::Decrypt => conn
            .session_decrypt_keys
            .read()
            .await
            .get(&session_id)
            .cloned(),
        EncryptionDirection::Encrypt => conn
            .session_encrypt_keys
            .read()
            .await
            .get(&session_id)
            .cloned(),
    };
    if let Some(key) = channel_key {
        return Some((cipher, key));
    }
    let sessions = conn.sessions.read().await;
    let sess_arc = sessions.get(&session_id)?.clone();
    drop(sessions);
    let sess = sess_arc.read().await;
    let key = match direction {
        EncryptionDirection::Decrypt => sess.decrypt_key.clone(),
        EncryptionDirection::Encrypt => sess.encrypt_key.clone(),
    }?;
    Some((cipher, key))
}

async fn session_signing_key(conn: &Arc<Connection>, session_id: u64) -> Option<[u8; 16]> {
    if let Some(key) = conn
        .session_signing_keys
        .read()
        .await
        .get(&session_id)
        .copied()
    {
        return Some(key);
    }
    let sessions = conn.sessions.read().await;
    let sess_arc = sessions.get(&session_id)?.clone();
    drop(sessions);
    let sess = sess_arc.read().await;
    Some(sess.signing_key)
}

async fn store_channel_signing_key_from_snapshot(
    conn: &Arc<Connection>,
    session_id: u64,
    session_base_key: [u8; 16],
    preauth_snapshot: &[u8; 64],
) {
    let signing_key = crate::proto::crypto::signing_key_311(&session_base_key, preauth_snapshot);
    conn.session_signing_keys
        .write()
        .await
        .insert(session_id, signing_key);
}

fn decrypt_with_cipher(cipher: u16, key: &[u8], frame: &[u8]) -> Result<Vec<u8>, &'static str> {
    match cipher {
        EncryptionCapabilities::CIPHER_AES_128_CCM | EncryptionCapabilities::CIPHER_AES_256_CCM => {
            decrypt_ccm(key, frame).map_err(|_| "AES-CCM decrypt failed")
        }
        EncryptionCapabilities::CIPHER_AES_128_GCM | EncryptionCapabilities::CIPHER_AES_256_GCM => {
            decrypt_gcm(key, frame).map_err(|_| "AES-GCM decrypt failed")
        }
        _ => Err("unsupported encryption cipher"),
    }
}

fn encrypt_with_cipher(
    cipher: u16,
    key: &[u8],
    session_id: u64,
    frame: &[u8],
) -> Result<Vec<u8>, &'static str> {
    match cipher {
        EncryptionCapabilities::CIPHER_AES_128_CCM | EncryptionCapabilities::CIPHER_AES_256_CCM => {
            encrypt_ccm(key, session_id, frame).map_err(|_| "AES-CCM encrypt failed")
        }
        EncryptionCapabilities::CIPHER_AES_128_GCM | EncryptionCapabilities::CIPHER_AES_256_GCM => {
            encrypt_gcm(key, session_id, frame).map_err(|_| "AES-GCM encrypt failed")
        }
        _ => Err("unsupported encryption cipher"),
    }
}

fn encrypted_transform_session_id(frame: &[u8]) -> Option<u64> {
    if frame.len() < 52 || !is_encryption_transform(frame) {
        return None;
    }
    Some(u64::from_le_bytes(frame[44..52].try_into().ok()?))
}

fn inherit_related_context(
    sub_frame: &mut [u8],
    req_hdr: &mut Smb2Header,
    prev_session_id: u64,
    prev_tree_id: u32,
    prev_related_file_id: Option<[u8; 16]>,
) {
    if read_u64(sub_frame, 0x28) == u64::MAX {
        sub_frame[0x28..0x30].copy_from_slice(&prev_session_id.to_le_bytes());
        req_hdr.session_id = prev_session_id;
    }

    if read_u32(sub_frame, 0x24) == u32::MAX {
        sub_frame[0x24..0x28].copy_from_slice(&prev_tree_id.to_le_bytes());
        if let HeaderTail::Sync { reserved, .. } = req_hdr.tail {
            req_hdr.tail = HeaderTail::Sync {
                reserved,
                tree_id: prev_tree_id,
            };
        }
    }

    let Some(file_id) = prev_related_file_id else {
        return;
    };
    let Some(body_offset) = file_id_body_offset(req_hdr.command) else {
        return;
    };
    let offset = SMB2_HEADER_LEN + body_offset;
    if offset + 16 <= sub_frame.len()
        && is_related_file_id_placeholder(
            read_u64(sub_frame, offset),
            read_u64(sub_frame, offset + 8),
        )
    {
        sub_frame[offset..offset + 16].copy_from_slice(&file_id);
    }
}

fn is_related_file_id_placeholder(persistent: u64, volatile: u64) -> bool {
    persistent == u64::MAX || volatile == u64::MAX || (persistent == 0 && volatile == 0)
}

fn file_id_body_offset(command: Command) -> Option<usize> {
    match command {
        Command::Close
        | Command::Flush
        | Command::Lock
        | Command::Ioctl
        | Command::QueryDirectory
        | Command::ChangeNotify
        | Command::OplockBreak => Some(8),
        Command::Read | Command::Write => Some(16),
        Command::QueryInfo => Some(24),
        Command::SetInfo => Some(16),
        _ => None,
    }
}

fn capture_create_file_id(response: &[u8]) -> Option<[u8; 16]> {
    if response.len() < SMB2_HEADER_LEN + 80 || read_u32(response, 0x08) != ntstatus::STATUS_SUCCESS
    {
        return None;
    }

    let mut file_id = [0u8; 16];
    let offset = SMB2_HEADER_LEN + 64;
    file_id.copy_from_slice(&response[offset..offset + 16]);
    Some(file_id)
}

fn capture_request_file_id(frame: &[u8], command: Command) -> Option<[u8; 16]> {
    let body_offset = file_id_body_offset(command)?;
    let offset = SMB2_HEADER_LEN + body_offset;
    let file_id = frame.get(offset..offset + 16)?;
    file_id.try_into().ok()
}

async fn stitch_responses(conn: &Arc<Connection>, responses: Vec<Vec<u8>>) -> Vec<u8> {
    let mut out = Vec::new();
    let mut ranges = Vec::with_capacity(responses.len());
    let response_count = responses.len();

    for (index, mut response) in responses.into_iter().enumerate() {
        let start = out.len();
        let actual_len = response.len();
        let padded_len = if response_count > 1 {
            align_8(actual_len)
        } else {
            actual_len
        };
        if index + 1 < response_count {
            response[0x14..0x18].copy_from_slice(&(padded_len as u32).to_le_bytes());
        }
        out.extend_from_slice(&response);
        ranges.push((start, actual_len));

        if response_count > 1 {
            out.resize(start + padded_len, 0);
        }
    }

    let algo = *conn.signing_algo.read().await;
    for (start, len) in ranges {
        let flags = read_u32(&out, start + 0x10);
        if flags & SMB2_FLAGS_SIGNED == 0 {
            continue;
        }

        let session_id = read_u64(&out, start + 0x28);
        let session = {
            let sessions = conn.sessions.read().await;
            sessions.get(&session_id).cloned()
        };
        let Some(session) = session else {
            continue;
        };
        let session = session.read().await;
        if matches!(session.identity, Identity::Anonymous) {
            continue;
        }
        drop(session);
        let Some(signing_key) = session_signing_key(conn, session_id).await else {
            continue;
        };

        if let Err(e) = sign(&mut out[start..start + len], &signing_key, algo) {
            error!(error = %e, "failed to sign compound response");
        }
    }

    out
}

const fn align_8(n: usize) -> usize {
    (n + 7) & !7
}

fn read_u32(buf: &[u8], offset: usize) -> u32 {
    let mut bytes = [0u8; 4];
    bytes.copy_from_slice(&buf[offset..offset + 4]);
    u32::from_le_bytes(bytes)
}

fn read_u64(buf: &[u8], offset: usize) -> u64 {
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&buf[offset..offset + 8]);
    u64::from_le_bytes(bytes)
}

async fn dispatch_one(
    server: &Arc<ServerState>,
    conn: &Arc<Connection>,
    frame: &[u8],
    request_was_encrypted: bool,
) -> Option<Vec<u8>> {
    let (req_hdr, body_bytes) = match Smb2Header::parse(frame) {
        Ok(p) => p,
        Err(e) => {
            warn!(error = %e, "failed to parse header");
            return None;
        }
    };

    let cmd = req_hdr.command;
    let mid = req_hdr.message_id;
    let sid = req_hdr.session_id;
    let tid = req_hdr.tree_id().unwrap_or(0);

    let span = debug_span!("dispatch", cmd = ?cmd, mid, sid, tid);
    async move {
        debug!("dispatch start");

        // Encrypted SMB transform requests are authenticated by the transform
        // itself; plain SMB signing is only verified on cleartext requests.
        if !request_was_encrypted
            && let Err(status) = verify_request_signature(server, conn, &req_hdr, frame).await
        {
            return Some(build_response_bytes(conn, &req_hdr, HandlerResponse::err(status)).await);
        }

        // CANCEL is fire-and-forget — no response.
        if cmd == Command::Cancel {
            if let Some(async_id) = req_hdr.async_id() {
                server
                    .cancel_change_notify(
                        conn,
                        async_id,
                        req_hdr.session_id,
                        ntstatus::STATUS_CANCELLED,
                    )
                    .await;
                server
                    .cancel_pipe_read(
                        conn,
                        async_id,
                        req_hdr.session_id,
                        ntstatus::STATUS_CANCELLED,
                    )
                    .await;
                server
                    .cancel_byte_range_lock_wait(
                        conn,
                        async_id,
                        req_hdr.session_id,
                        ntstatus::STATUS_CANCELLED,
                    )
                    .await;
                server
                    .cancel_cache_break_create(
                        conn,
                        async_id,
                        req_hdr.session_id,
                        ntstatus::STATUS_CANCELLED,
                    )
                    .await;
                server
                    .cancel_cache_break_write(
                        conn,
                        async_id,
                        req_hdr.session_id,
                        ntstatus::STATUS_CANCELLED,
                    )
                    .await;
                server
                    .cancel_cache_break_task(
                        conn,
                        async_id,
                        req_hdr.session_id,
                        ntstatus::STATUS_CANCELLED,
                    )
                    .await;
            } else {
                server
                    .cancel_change_notify_by_message_id(
                        conn,
                        req_hdr.message_id,
                        req_hdr.session_id,
                        ntstatus::STATUS_CANCELLED,
                    )
                    .await;
            }
            debug!("CANCEL received; no response");
            return None;
        }

        if let Err(status) = validate_credit_charge(conn, &req_hdr, body_bytes).await {
            return Some(
                build_response_bytes_with_credits(
                    conn,
                    &req_hdr,
                    HandlerResponse::err(status),
                    Some(0),
                )
                .await,
            );
        }

        if let Err(status) = conn.debit_credits(&req_hdr) {
            return Some(
                build_response_bytes_with_credits(
                    conn,
                    &req_hdr,
                    HandlerResponse::err(status),
                    Some(0),
                )
                .await,
            );
        }

        let dialect = *conn.dialect.read().await;
        let mut session_preauth = None;

        // 3.1.1 preauth is connection-scoped for NEGOTIATE, then per
        // SESSION_SETUP authentication exchange.
        if cmd == Command::Negotiate {
            let mut p = conn
                .preauth
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            p.update(frame);
        } else if cmd == Command::SessionSetup
            && dialect == Some(crate::proto::messages::Dialect::Smb311)
        {
            let mut p = take_session_preauth(conn, req_hdr.session_id).await;
            p.update(frame);
            session_preauth = Some(p);
        }

        let resp = match validate_channel_sequence(conn, &req_hdr, body_bytes).await {
            Ok(()) => {
                mark_replay_handle_used(conn, &req_hdr, body_bytes).await;
                handlers::dispatch_command(server, conn, &req_hdr, body_bytes).await
            }
            Err(status) => HandlerResponse::err(status),
        };

        // If the handler asked for a preauth snapshot (3.1.1), take it now.
        if let Some(sid) = resp.take_preauth_snapshot_for_session {
            let snap = session_preauth
                .as_ref()
                .expect("SMB 3.1.1 SessionSetup snapshot requires per-session preauth")
                .snapshot();
            // Stash on the session — the handler already created it.
            let sessions = conn.sessions.read().await;
            if let Some(sess_arc) = sessions.get(&sid) {
                let mut sess = sess_arc.write().await;
                sess.preauth_snapshot = Some(snap);
                // For 3.1.1, recompute signing key now that we have the snapshot.
                let dialect = *conn.dialect.read().await;
                if dialect == Some(crate::proto::messages::Dialect::Smb311) {
                    sess.signing_key =
                        crate::proto::crypto::signing_key_311(&sess.session_base_key, &snap);
                    if sess.encryption_allowed && !*conn.transport_security.read().await {
                        let cipher = *conn.encryption_cipher.read().await;
                        if cipher == EncryptionCapabilities::CIPHER_AES_256_CCM
                            || cipher == EncryptionCapabilities::CIPHER_AES_256_GCM
                        {
                            sess.decrypt_key =
                                Some(encryption_key_311_c2s_256(&sess.session_base_key, &snap));
                            sess.encrypt_key =
                                Some(encryption_key_311_s2c_256(&sess.session_base_key, &snap));
                        } else if cipher != 0 {
                            sess.decrypt_key =
                                Some(encryption_key_311_c2s(&sess.session_base_key, &snap));
                            sess.encrypt_key =
                                Some(encryption_key_311_s2c(&sess.session_base_key, &snap));
                        }
                    }
                }
            }
        }
        if let Some((sid, session_base_key)) = resp.take_preauth_snapshot_for_channel {
            let snap = session_preauth
                .as_ref()
                .expect("SMB 3.1.1 SessionSetup channel snapshot requires per-session preauth")
                .snapshot();
            store_channel_signing_key_from_snapshot(conn, sid, session_base_key, &snap).await;
        }

        let took_preauth_snapshot = resp.take_preauth_snapshot_for_session.is_some()
            || resp.take_preauth_snapshot_for_channel.is_some();
        let bytes = build_response_bytes(conn, &req_hdr, resp).await;

        if cmd == Command::Negotiate {
            let mut p = conn
                .preauth
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            p.update(&bytes);
        } else if cmd == Command::SessionSetup
            && dialect == Some(crate::proto::messages::Dialect::Smb311)
        {
            if read_u32(&bytes, 0x08) == ntstatus::STATUS_MORE_PROCESSING_REQUIRED {
                if let Some(mut p) = session_preauth {
                    p.update(&bytes);
                    let sid = read_u64(&bytes, 0x28);
                    conn.session_preauth.write().await.insert(sid, p);
                }
            } else {
                if req_hdr.session_id == 0
                    && !took_preauth_snapshot
                    && let Some(p) = session_preauth
                {
                    *conn
                        .preauth
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner()) = p;
                }
                conn.session_preauth
                    .write()
                    .await
                    .remove(&req_hdr.session_id);
            }
        }

        Some(bytes)
    }
    .instrument(span)
    .await
}

async fn validate_credit_charge(
    conn: &Arc<Connection>,
    hdr: &Smb2Header,
    body: &[u8],
) -> Result<(), u32> {
    let dialect = *conn.dialect.read().await;
    if !matches!(
        dialect,
        Some(Dialect::Smb210 | Dialect::Smb300 | Dialect::Smb302 | Dialect::Smb311)
    ) {
        return Ok(());
    }
    let Some(size) = multi_credit_payload_size(hdr.command, body) else {
        return Ok(());
    };
    const CREDIT_UNIT: u64 = 64 * 1024;
    if hdr.credit_charge == 0 {
        if size > CREDIT_UNIT {
            return Err(ntstatus::STATUS_INVALID_PARAMETER);
        }
        return Ok(());
    }
    if expected_credit_charge(size) > u64::from(hdr.credit_charge) {
        return Err(ntstatus::STATUS_INVALID_PARAMETER);
    }
    Ok(())
}

fn multi_credit_payload_size(command: Command, body: &[u8]) -> Option<u64> {
    match command {
        Command::Read => ReadRequest::parse(body)
            .ok()
            .map(|req| u64::from(req.length)),
        Command::Write => WriteRequest::parse(body)
            .ok()
            .map(|req| req.data.len() as u64),
        Command::QueryDirectory => QueryDirectoryRequest::parse(body)
            .ok()
            .map(|req| u64::from(req.output_buffer_length)),
        Command::Ioctl => IoctlRequest::parse(body)
            .ok()
            .map(|req| u64::from(req.input_count).max(u64::from(req.max_output_response))),
        _ => None,
    }
}

async fn validate_channel_sequence(
    conn: &Arc<Connection>,
    hdr: &Smb2Header,
    body: &[u8],
) -> Result<(), u32> {
    let file_id = match hdr.command {
        Command::Write => WriteRequest::parse(body).ok().map(|req| req.file_id),
        Command::Ioctl => IoctlRequest::parse(body).ok().map(|req| req.file_id),
        Command::SetInfo => SetInfoRequest::parse(body).ok().map(|req| req.file_id),
        _ => None,
    };
    let Some(file_id) = file_id else {
        return Ok(());
    };

    let Ok(tree) = crate::handlers::shared::lookup_session_tree(conn, hdr).await else {
        return Ok(());
    };
    let Some(open) = crate::handlers::shared::lookup_open(&tree, file_id).await else {
        return Ok(());
    };

    let channel_sequence = hdr.channel_sequence_status as u16;
    let mut open = open.write().await;
    if !open.durable {
        return Ok(());
    }
    if channel_sequence.wrapping_sub(open.channel_sequence) > 0x7fff {
        return Err(ntstatus::STATUS_FILE_NOT_AVAILABLE);
    }
    open.channel_sequence = channel_sequence;
    Ok(())
}

async fn mark_replay_handle_used(conn: &Arc<Connection>, hdr: &Smb2Header, body: &[u8]) {
    let file_id = match hdr.command {
        Command::Read => ReadRequest::parse(body).ok().map(|req| req.file_id),
        Command::Write => WriteRequest::parse(body).ok().map(|req| req.file_id),
        Command::Ioctl => IoctlRequest::parse(body).ok().map(|req| req.file_id),
        Command::QueryInfo => QueryInfoRequest::parse(body).ok().map(|req| req.file_id),
        Command::SetInfo => SetInfoRequest::parse(body).ok().map(|req| req.file_id),
        _ => None,
    };
    let Some(file_id) = file_id else {
        return;
    };
    let Ok(tree) = crate::handlers::shared::lookup_session_tree(conn, hdr).await else {
        return;
    };
    let Some(open) = crate::handlers::shared::lookup_open(&tree, file_id).await else {
        return;
    };
    let mut open = open.write().await;
    if open.replay_consumed {
        open.replay_used = true;
    }
}

fn expected_credit_charge(size: u64) -> u64 {
    if size == 0 {
        1
    } else {
        ((size - 1) / (64 * 1024)) + 1
    }
}

async fn take_session_preauth(conn: &Arc<Connection>, session_id: u64) -> PreauthIntegrity {
    if session_id != 0
        && let Some(preauth) = conn.session_preauth.write().await.remove(&session_id)
    {
        return preauth;
    }

    conn.preauth
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone()
}

async fn verify_request_signature(
    server: &Arc<ServerState>,
    conn: &Arc<Connection>,
    hdr: &Smb2Header,
    frame: &[u8],
) -> Result<(), u32> {
    if hdr.command == Command::Negotiate {
        return Ok(());
    }
    if hdr.session_id == 0 {
        return Ok(());
    }
    let sessions = conn.sessions.read().await;
    let sess_arc = match sessions.get(&hdr.session_id) {
        Some(s) => s.clone(),
        None => {
            // Unknown session.
            if hdr.flags & SMB2_FLAGS_SIGNED == 0 {
                return Ok(());
            }
            if hdr.command == Command::SessionSetup
                && let Some((key, algo, _, _, _, _)) =
                    server.session_signing_material(hdr.session_id).await
            {
                if let Err(e) = crate::proto::crypto::verify(frame, &key, algo) {
                    warn!(error = %e, "global session signature verification failed");
                }
                return Ok(());
            }
            if hdr.command == Command::Create
                && let Some(file_id) = durable_reconnect_file_id(frame)
            {
                let client_guid = *conn.client_guid.read().await;
                if server.durable_open_client_guid_mismatch(file_id, client_guid) {
                    return Err(ntstatus::STATUS_OBJECT_NAME_NOT_FOUND);
                }
            }
            return Err(ntstatus::STATUS_USER_SESSION_DELETED);
        }
    };
    drop(sessions);

    if hdr.flags & SMB2_FLAGS_SIGNED != 0 {
        let is_anonymous = {
            let sess = sess_arc.read().await;
            matches!(sess.identity, Identity::Anonymous)
        };
        let Some(key) = session_signing_key(conn, hdr.session_id).await else {
            return Err(ntstatus::STATUS_ACCESS_DENIED);
        };
        if is_anonymous && key == [0u8; 16] {
            return Ok(());
        }
        let algo = *conn.signing_algo.read().await;
        if let Err(e) = crate::proto::crypto::verify(frame, &key, algo) {
            warn!(error = %e, "request signature verification failed");
            return Err(ntstatus::STATUS_ACCESS_DENIED);
        }
    } else {
        let sess = sess_arc.read().await;
        let need = sess.signing_required;
        drop(sess);
        if need {
            warn!(?hdr.command, "missing required signature on request");
            return Err(ntstatus::STATUS_ACCESS_DENIED);
        }
    }
    Ok(())
}

fn durable_reconnect_file_id(frame: &[u8]) -> Option<FileId> {
    let body = frame.get(SMB2_HEADER_LEN..)?;
    let req = CreateRequest::parse(body).ok()?;
    let contexts = CreateContext::parse_chain(&req.create_contexts).ok()?;
    contexts
        .iter()
        .find(|ctx| ctx.name == CreateContext::NAME_DHNC.as_slice() && ctx.data.len() == 16)
        .and_then(file_id_from_durable_reconnect_data)
        .or_else(|| {
            contexts
                .iter()
                .find(|ctx| ctx.name == CreateContext::NAME_DH2C.as_slice() && ctx.data.len() == 36)
                .and_then(file_id_from_durable_reconnect_data)
        })
}

fn file_id_from_durable_reconnect_data(ctx: &CreateContext) -> Option<FileId> {
    Some(FileId {
        persistent: u64::from_le_bytes(ctx.data.get(0..8)?.try_into().ok()?),
        volatile: u64::from_le_bytes(ctx.data.get(8..16)?.try_into().ok()?),
    })
}

/// Build the final on-the-wire bytes: header + body, with signing applied
/// when the session has a key.
pub(crate) async fn build_response_bytes(
    conn: &Arc<Connection>,
    req_hdr: &Smb2Header,
    handler_resp: HandlerResponse,
) -> Vec<u8> {
    let response_credits = if handler_resp.async_final {
        0
    } else {
        conn.grant_credits(req_hdr)
    };
    build_response_bytes_with_credits(conn, req_hdr, handler_resp, Some(response_credits)).await
}

pub(crate) async fn build_standalone_response_frame(
    conn: &Arc<Connection>,
    req_hdr: &Smb2Header,
    handler_resp: HandlerResponse,
) -> Vec<u8> {
    let response = build_response_bytes(conn, req_hdr, handler_resp).await;
    let compressed = maybe_compress_response(conn, Some(req_hdr.command), response).await;
    maybe_encrypt_response(
        conn,
        Some(req_hdr.command),
        req_hdr.session_id,
        compressed,
        true,
    )
    .await
}

async fn build_response_bytes_with_credits(
    conn: &Arc<Connection>,
    req_hdr: &Smb2Header,
    handler_resp: HandlerResponse,
    response_credits: Option<u16>,
) -> Vec<u8> {
    let mut hdr = *req_hdr;
    hdr.flags |= SMB2_FLAGS_SERVER_TO_REDIR;
    hdr.next_command = 0;
    hdr.channel_sequence_status = handler_resp.status;
    if handler_resp.async_final {
        hdr.credit_request_response = 0;
    } else if let Some(credits) = response_credits {
        hdr.credit_request_response = credits;
    }
    if let Some(async_id) = handler_resp.async_id {
        hdr.flags |= SMB2_FLAGS_ASYNC_COMMAND;
        hdr.tail = HeaderTail::async_(async_id);
    } else {
        hdr.flags &= !SMB2_FLAGS_ASYNC_COMMAND;
        hdr.tail = HeaderTail::sync(
            handler_resp
                .override_tree_id
                .unwrap_or_else(|| req_hdr.tree_id().unwrap_or(0)),
        );
    }
    if let Some(sid) = handler_resp.override_session_id {
        hdr.session_id = sid;
    }
    hdr.signature = [0u8; 16];

    let request_was_signed = req_hdr.flags & SMB2_FLAGS_SIGNED != 0;
    // MS-SMB2 §3.3.5.5.3 step 12: SessionSetup SUCCESS must be signed for
    // non-anon/non-guest sessions even though the request cannot be signed yet.
    let is_session_setup_success =
        req_hdr.command == Command::SessionSetup && handler_resp.status == ntstatus::STATUS_SUCCESS;
    let mut should_sign = false;
    let mut key = [0u8; 16];
    let mut algo = *conn.signing_algo.read().await;
    if !handler_resp.skip_signing {
        if let Some(signing) = handler_resp.signing_override {
            key = signing.key;
            algo = signing.algo;
            should_sign = key != [0u8; 16];
        } else if hdr.session_id != 0 {
            let sess_arc = {
                let sessions = conn.sessions.read().await;
                sessions.get(&hdr.session_id).cloned()
            };
            if let Some(sess_arc) = sess_arc {
                let sess = sess_arc.read().await;
                let is_guest_response = is_session_setup_success
                    && handler_resp.body.len() >= 4
                    && (handler_resp.body[2] & 0x01) != 0;
                let session_requires_signing = sess.signing_required;
                drop(sess);
                let signing_key = session_signing_key(conn, hdr.session_id)
                    .await
                    .unwrap_or([0u8; 16]);
                if !is_guest_response
                    && signing_key != [0u8; 16]
                    && (request_was_signed || is_session_setup_success || session_requires_signing)
                {
                    key = signing_key;
                    should_sign = true;
                }
            }
        }
    }
    if should_sign {
        hdr.flags |= SMB2_FLAGS_SIGNED;
    } else {
        hdr.flags &= !SMB2_FLAGS_SIGNED;
    }
    let mut out = Vec::with_capacity(SMB2_HEADER_LEN + handler_resp.body.len());
    if let Err(e) = hdr.write(&mut out) {
        error!(error = %e, "failed to encode response header");
        return Vec::new();
    }
    out.extend_from_slice(&handler_resp.body);

    if should_sign && let Err(e) = sign(&mut out, &key, algo) {
        error!(error = %e, "failed to sign response");
    }
    out
}

/// Detect and answer an SMB1 multi-protocol NEGOTIATE_REQUEST.
///
/// SMB1 frame layout for the request we accept:
/// * `[0..4]`  — magic `0xFF 'S' 'M' 'B'`
/// * `[4]`     — command (0x72 = SMB_COM_NEGOTIATE)
/// * `[5..32]` — rest of SMB1 header (status, flags, pid, tid, mid …)
/// * `[32]`    — `WordCount` (0 for NEGOTIATE)
/// * `[33..35]`— `ByteCount` (u16 LE)
/// * `[35..]`  — dialect strings, each `0x02 <ASCII> 0x00`.
///
/// Returns `Some(reply_bytes)` only for a SMB1 NEGOTIATE that lists at least
/// one SMB2 dialect we recognise; otherwise `None` so the caller can fall
/// through to the normal SMB2 path.
async fn handle_smb1_multi_protocol(
    server: &Arc<ServerState>,
    conn: &Arc<Connection>,
    frame: &[u8],
) -> Option<Vec<u8>> {
    if frame.len() < 35 || frame[0..4] != [0xFF, b'S', b'M', b'B'] || frame[4] != 0x72 {
        return None;
    }
    let body_start = 33; // 32-byte header + 1-byte WordCount(=0)
    let byte_count = u16::from_le_bytes([frame[body_start], frame[body_start + 1]]) as usize;
    let blob_start = body_start + 2;
    let blob_end = (blob_start + byte_count).min(frame.len());
    let blob = &frame[blob_start..blob_end];

    let mut wants_wildcard = false;
    let mut wants_smb202 = false;
    let mut i = 0;
    while i < blob.len() {
        if blob[i] != 0x02 {
            break;
        }
        i += 1;
        let nul = match blob[i..].iter().position(|&b| b == 0) {
            Some(p) => p,
            None => break,
        };
        let s = std::str::from_utf8(&blob[i..i + nul]).unwrap_or("");
        match s {
            "SMB 2.???" => wants_wildcard = true,
            "SMB 2.002" => wants_smb202 = true,
            _ => {}
        }
        i += nul + 1;
    }

    let chosen = if wants_wildcard {
        crate::proto::messages::Dialect::Smb2Wildcard.as_u16()
    } else if wants_smb202 {
        crate::proto::messages::Dialect::Smb202.as_u16()
    } else {
        return None;
    };

    debug!(
        chosen = %format_args!("0x{chosen:04X}"),
        "SMB1 multi-protocol negotiate"
    );

    // Synthesize a request header so build_response_bytes can mint the
    // SERVER_TO_REDIR response. Per MS-SMB2 §3.3.5.3.1 the response uses
    // message_id=0, tree_id=0xFFFF, session_id=0.
    let req_hdr = Smb2Header {
        command: Command::Negotiate,
        message_id: 0,
        session_id: 0,
        tail: HeaderTail::Sync {
            reserved: 0,
            tree_id: 0xFFFF,
        },
        ..Default::default()
    };
    let resp = handlers::negotiate::multi_protocol_response(server, conn, chosen).await;
    Some(build_response_bytes(conn, &req_hdr, resp).await)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SmbServer;
    use crate::conn::state::Session;
    use crate::proto::crypto::encryption::{decrypt_gcm, encrypt_gcm};
    use crate::proto::messages::{
        EchoRequest, NegotiateContext, NegotiateRequest, NegotiateResponse,
        PreauthIntegrityCapabilities,
    };
    use binrw::BinWrite;
    use uuid::Uuid;

    fn test_conn() -> Arc<Connection> {
        Arc::new(Connection::new(
            Uuid::nil(),
            8 * 1024 * 1024,
            8 * 1024 * 1024,
            8,
        ))
    }

    fn test_conn_with_max_credits(max_credits: u16) -> Arc<Connection> {
        Arc::new(Connection::new(
            Uuid::nil(),
            8 * 1024 * 1024,
            8 * 1024 * 1024,
            max_credits,
        ))
    }

    fn echo_request(credits: u16) -> Smb2Header {
        Smb2Header {
            command: Command::Echo,
            credit_charge: 1,
            credit_request_response: credits,
            message_id: 1,
            ..Default::default()
        }
    }

    fn echo_body() -> Vec<u8> {
        let mut out = Vec::new();
        EchoRequest::default()
            .write_to(&mut out)
            .expect("echo request encodes");
        out
    }

    fn raw_response(command: Command, message_id: u64, body: &[u8]) -> Vec<u8> {
        let header = Smb2Header {
            command,
            message_id,
            flags: SMB2_FLAGS_SERVER_TO_REDIR,
            tail: HeaderTail::sync(1),
            ..Default::default()
        };
        let mut out = Vec::new();
        header.write(&mut out).expect("header encodes");
        out.extend_from_slice(body);
        out
    }

    #[tokio::test]
    async fn compound_stitching_aligns_next_command_and_pads_last_response() {
        let conn = test_conn();
        let first = raw_response(Command::Echo, 1, &[0xaa; 5]);
        let second = raw_response(Command::Echo, 2, &[0xbb; 3]);

        let stitched = stitch_responses(&conn, vec![first, second]).await;

        let first_len = SMB2_HEADER_LEN + 5;
        let first_padded = align_8(first_len);
        let second_len = SMB2_HEADER_LEN + 3;
        let second_padded = align_8(second_len);
        assert_eq!(stitched.len(), first_padded + second_padded);

        let (first_hdr, _) = Smb2Header::parse(&stitched).expect("first header");
        assert_eq!(first_hdr.next_command as usize, first_padded);
        assert!(stitched[first_len..first_padded].iter().all(|b| *b == 0));

        let (second_hdr, _) = Smb2Header::parse(&stitched[first_padded..]).expect("second header");
        assert_eq!(second_hdr.next_command, 0);
        assert!(
            stitched[first_padded + second_len..]
                .iter()
                .all(|b| *b == 0)
        );
    }

    fn preauth_context() -> NegotiateContext {
        let preauth = PreauthIntegrityCapabilities {
            hash_algorithm_count: 1,
            salt_length: 0,
            hash_algorithms: vec![PreauthIntegrityCapabilities::HASH_SHA512],
            salt: Vec::new(),
        };
        let mut cursor = std::io::Cursor::new(Vec::new());
        BinWrite::write(&preauth, &mut cursor).expect("preauth context encodes");
        let data = cursor.into_inner();
        NegotiateContext {
            context_type: NegotiateContext::TYPE_PREAUTH_INTEGRITY,
            data_length: data.len() as u16,
            reserved: 0,
            data,
        }
    }

    fn smb311_negotiate_body() -> Vec<u8> {
        let contexts = [preauth_context()];
        let mut contexts_bytes = Vec::new();
        NegotiateContext::encode_list(&contexts, &mut contexts_bytes)
            .expect("negotiate context list encodes");
        let fixed_and_dialects = 36 + 2;
        let contexts_offset = ((SMB2_HEADER_LEN + fixed_and_dialects + 7) & !7) as u32;
        let req = NegotiateRequest {
            structure_size: 36,
            dialect_count: 1,
            security_mode: 1,
            reserved: 0,
            capabilities: 0,
            client_guid: [0x55; 16],
            negotiate_context_offset_or_client_start_time: u64::from(contexts_offset)
                | (u64::from(contexts.len() as u16) << 32),
            dialects: vec![Dialect::Smb311.as_u16()],
        };
        let mut body = Vec::new();
        req.write_to(&mut body).expect("negotiate request encodes");
        body.resize(contexts_offset as usize - SMB2_HEADER_LEN, 0);
        body.extend_from_slice(&contexts_bytes);
        body
    }

    fn request_frame(hdr: &Smb2Header, body: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        hdr.write(&mut out).expect("header encodes");
        out.extend_from_slice(body);
        out
    }

    fn smb1_negotiate_frame(dialects: &[&str]) -> Vec<u8> {
        let mut dialect_bytes = Vec::new();
        for dialect in dialects {
            dialect_bytes.push(0x02);
            dialect_bytes.extend_from_slice(dialect.as_bytes());
            dialect_bytes.push(0);
        }
        let mut frame = vec![0u8; 35 + dialect_bytes.len()];
        frame[0..4].copy_from_slice(&[0xFF, b'S', b'M', b'B']);
        frame[4] = 0x72;
        frame[9] = 0x18;
        frame[10..12].copy_from_slice(&0xc853_u16.to_le_bytes());
        frame[32] = 0;
        frame[33..35].copy_from_slice(&(dialect_bytes.len() as u16).to_le_bytes());
        frame[35..].copy_from_slice(&dialect_bytes);
        frame
    }

    fn test_server(encrypt_data: bool) -> Arc<ServerState> {
        SmbServer::builder()
            .listen("127.0.0.1:0".parse().unwrap())
            .encrypt_data(encrypt_data)
            .build()
            .expect("server builds")
            .state()
    }

    #[tokio::test]
    async fn smb1_multi_protocol_negotiate_selects_smb2_wildcard() {
        let server = test_server(false);
        let conn = test_conn();
        let frame = smb1_negotiate_frame(&["NT LM 0.12", "SMB 2.002", "SMB 2.???"]);

        let response = handle_smb1_multi_protocol(&server, &conn, &frame)
            .await
            .expect("SMB1 bridge should answer SMB2 dialects");

        let (hdr, body) = Smb2Header::parse(&response).expect("parse SMB2 response");
        assert_eq!(hdr.command, Command::Negotiate);
        assert_eq!(hdr.channel_sequence_status, ntstatus::STATUS_SUCCESS);
        assert_eq!(hdr.message_id, 0);
        assert_eq!(hdr.session_id, 0);
        assert_eq!(hdr.tree_id(), Some(0xFFFF));
        assert_eq!(
            hdr.flags & SMB2_FLAGS_SERVER_TO_REDIR,
            SMB2_FLAGS_SERVER_TO_REDIR
        );

        let negotiate = NegotiateResponse::parse(body).expect("parse negotiate response");
        assert_eq!(negotiate.dialect_revision, Dialect::Smb2Wildcard.as_u16());
        assert!(!negotiate.security_buffer.is_empty());
    }

    async fn encrypted_test_conn() -> (Arc<Connection>, Vec<u8>) {
        let conn = test_conn();
        *conn.encryption_cipher.write().await = EncryptionCapabilities::CIPHER_AES_128_GCM;
        let key = b"0123456789abcdef".to_vec();
        let mut session = Session::new(
            7,
            Identity::User {
                user: "alice".to_string(),
                domain: "DOMAIN".to_string(),
            },
            [0x11; 16],
            [0x22; 16],
            false,
            None,
        );
        session.decrypt_key = Some(key.clone());
        session.encrypt_key = Some(key.clone());
        conn.sessions
            .write()
            .await
            .insert(7, Arc::new(tokio::sync::RwLock::new(session)));
        (conn, key)
    }

    fn request_header(command: Command, credit_charge: u16) -> Smb2Header {
        Smb2Header {
            command,
            credit_charge,
            credit_request_response: 1,
            ..Default::default()
        }
    }

    async fn set_dialect(conn: &Arc<Connection>, dialect: Dialect) {
        *conn.dialect.write().await = Some(dialect);
    }

    fn read_body(length: u32) -> Vec<u8> {
        let req = ReadRequest {
            structure_size: 49,
            padding: 0,
            flags: 0,
            length,
            offset: 0,
            file_id: crate::proto::messages::FileId::new(1, 1),
            minimum_count: 0,
            channel: 0,
            remaining_bytes: 0,
            read_channel_info_offset: 0,
            read_channel_info_length: 0,
            buffer: vec![0],
        };
        let mut out = Vec::new();
        req.write_to(&mut out).expect("read request encodes");
        out
    }

    fn write_body(length: usize) -> Vec<u8> {
        let req = WriteRequest {
            structure_size: 49,
            data_offset: WriteRequest::STANDARD_DATA_OFFSET,
            length: length as u32,
            offset: 0,
            file_id: crate::proto::messages::FileId::new(1, 1),
            channel: 0,
            remaining_bytes: 0,
            write_channel_info_offset: 0,
            write_channel_info_length: 0,
            flags: 0,
            data: vec![0x5a; length.max(1)],
        };
        let mut out = Vec::new();
        req.write_to(&mut out).expect("write request encodes");
        out
    }

    fn query_directory_body(output_buffer_length: u32) -> Vec<u8> {
        let req = QueryDirectoryRequest {
            structure_size: 33,
            file_information_class: crate::proto::messages::FileInfoClass::FileNamesInformation
                as u8,
            flags: 0,
            file_index: 0,
            file_id: crate::proto::messages::FileId::new(1, 1),
            file_name_offset: 0,
            file_name_length: 0,
            output_buffer_length,
            file_name: Vec::new(),
        };
        let mut out = Vec::new();
        req.write_to(&mut out)
            .expect("query directory request encodes");
        out
    }

    fn ioctl_body(input_count: usize, max_output_response: u32) -> Vec<u8> {
        let req = IoctlRequest {
            structure_size: 57,
            reserved: 0,
            ctl_code: crate::proto::messages::Fsctl::VALIDATE_NEGOTIATE_INFO,
            file_id: crate::proto::messages::FileId::any(),
            input_offset: if input_count == 0 {
                0
            } else {
                (SMB2_HEADER_LEN + 56) as u32
            },
            input_count: input_count as u32,
            max_input_response: 0,
            output_offset: 0,
            output_count: 0,
            max_output_response,
            flags: IoctlRequest::FLAG_IS_FSCTL,
            reserved2: 0,
            input: vec![0; input_count],
        };
        let mut out = Vec::new();
        req.write_to(&mut out).expect("ioctl request encodes");
        out
    }

    fn negotiated_preauth() -> PreauthIntegrity {
        let mut preauth = PreauthIntegrity::new();
        preauth.update(b"negotiate request");
        preauth.update(b"negotiate response");
        preauth
    }

    #[tokio::test]
    async fn new_session_setup_preauth_starts_from_negotiate_base() {
        let conn = test_conn();
        let base = negotiated_preauth();
        *conn.preauth.lock().expect("preauth lock") = base.clone();

        let mut first_session = take_session_preauth(&conn, 0).await;
        first_session.update(b"session one request");
        first_session.update(b"session one response");
        conn.session_preauth.write().await.insert(1, first_session);

        let mut second_session = take_session_preauth(&conn, 0).await;
        second_session.update(b"session two request");

        let mut expected = base.clone();
        expected.update(b"session two request");

        let mut polluted = base;
        polluted.update(b"session one request");
        polluted.update(b"session one response");
        polluted.update(b"session two request");

        assert_eq!(second_session.snapshot(), expected.snapshot());
        assert_ne!(second_session.snapshot(), polluted.snapshot());
    }

    #[tokio::test]
    async fn followup_session_setup_consumes_stored_session_preauth() {
        let conn = test_conn();
        let mut stored = negotiated_preauth();
        stored.update(b"session setup request");
        stored.update(b"session setup more-processing response");
        let expected = stored.snapshot();
        conn.session_preauth.write().await.insert(7, stored);

        let got = take_session_preauth(&conn, 7).await;

        assert_eq!(got.snapshot(), expected);
        assert!(!conn.session_preauth.read().await.contains_key(&7));
    }

    #[tokio::test]
    async fn failed_first_session_setup_preauth_keeps_request_not_error_response() {
        let server = test_server(false);
        let conn = test_conn();

        let negotiate_hdr = Smb2Header {
            command: Command::Negotiate,
            credit_charge: 1,
            credit_request_response: 1,
            message_id: 1,
            ..Default::default()
        };
        let negotiate_req = request_frame(&negotiate_hdr, &smb311_negotiate_body());
        let negotiate_resp = dispatch_frame(&server, &conn, &negotiate_req)
            .await
            .expect("negotiate response");
        assert_eq!(read_u32(&negotiate_resp, 0x08), ntstatus::STATUS_SUCCESS);

        let mut expected = PreauthIntegrity::new();
        expected.update(&negotiate_req);
        expected.update(&negotiate_resp);
        assert_eq!(
            conn.preauth.lock().expect("preauth lock").snapshot(),
            expected.snapshot()
        );

        let setup_hdr = Smb2Header {
            command: Command::SessionSetup,
            credit_charge: 1,
            credit_request_response: 1,
            message_id: 2,
            ..Default::default()
        };
        let bad_setup_req = request_frame(&setup_hdr, &[0]);
        let bad_setup_resp = dispatch_frame(&server, &conn, &bad_setup_req)
            .await
            .expect("bad session setup response");
        assert_eq!(
            read_u32(&bad_setup_resp, 0x08),
            ntstatus::STATUS_INVALID_PARAMETER
        );

        expected.update(&bad_setup_req);
        assert_eq!(
            conn.preauth.lock().expect("preauth lock").snapshot(),
            expected.snapshot()
        );

        let mut with_error_response = expected.clone();
        with_error_response.update(&bad_setup_resp);
        assert_ne!(
            conn.preauth.lock().expect("preauth lock").snapshot(),
            with_error_response.snapshot()
        );
        assert!(conn.session_preauth.read().await.is_empty());
    }

    #[tokio::test]
    async fn response_credits_are_granted_within_connection_limit() {
        let conn = test_conn();
        let req = echo_request(4);
        conn.debit_credits(&req).expect("initial credit debit");

        let resp = build_response_bytes(&conn, &req, HandlerResponse::ok(vec![4, 0, 0, 0])).await;
        let (hdr, _) = Smb2Header::parse(&resp).expect("response header");

        assert_eq!(hdr.credit_request_response, 4);
        assert_eq!(conn.credit_balance(), 4);

        let req = Smb2Header {
            message_id: 2,
            ..echo_request(10)
        };
        conn.debit_credits(&req).expect("second credit debit");
        let resp = build_response_bytes(&conn, &req, HandlerResponse::ok(vec![4, 0, 0, 0])).await;
        let (hdr, _) = Smb2Header::parse(&resp).expect("response header");

        assert_eq!(hdr.credit_request_response, 5);
        assert_eq!(conn.credit_balance(), 8);
    }

    #[tokio::test]
    async fn default_credit_window_covers_high_rtt_bandwidth_delay_product() {
        const CREDIT_BYTES: u64 = 64 * 1024;
        const BANDWIDTH_MBPS: u64 = 10_000;
        const RTT_MILLIS: u64 = 200;
        const DEFAULT_MAX_CREDITS: u16 = 8192;

        let bdp_bytes = BANDWIDTH_MBPS * 1_000_000 / 8 * RTT_MILLIS / 1_000;
        let default_window_bytes = u64::from(DEFAULT_MAX_CREDITS) * CREDIT_BYTES;
        assert!(
            default_window_bytes >= bdp_bytes,
            "default credit window {default_window_bytes} bytes must cover {bdp_bytes} bytes"
        );

        let conn = test_conn_with_max_credits(DEFAULT_MAX_CREDITS);
        let req = echo_request(DEFAULT_MAX_CREDITS);
        conn.debit_credits(&req).expect("credit debit");
        let resp = build_response_bytes(&conn, &req, HandlerResponse::ok(vec![4, 0, 0, 0])).await;
        let (hdr, _) = Smb2Header::parse(&resp).expect("response header");

        assert_eq!(hdr.credit_request_response, DEFAULT_MAX_CREDITS);
        assert!(u64::from(hdr.credit_request_response) * CREDIT_BYTES >= bdp_bytes);
        assert_eq!(conn.credit_balance(), u32::from(DEFAULT_MAX_CREDITS));
    }

    #[tokio::test]
    async fn credits_can_grow_from_single_credit_to_large_window() {
        const DEFAULT_MAX_CREDITS: u16 = 8192;

        let conn = test_conn_with_max_credits(DEFAULT_MAX_CREDITS);
        let req = echo_request(1);
        conn.debit_credits(&req).expect("initial credit debit");
        let resp = build_response_bytes(&conn, &req, HandlerResponse::ok(vec![4, 0, 0, 0])).await;
        let (hdr, _) = Smb2Header::parse(&resp).expect("response header");

        assert_eq!(hdr.credit_request_response, 1);
        assert_eq!(conn.credit_balance(), 1);

        let req = Smb2Header {
            message_id: 2,
            ..echo_request(DEFAULT_MAX_CREDITS)
        };
        conn.debit_credits(&req).expect("large-window credit debit");
        let resp = build_response_bytes(&conn, &req, HandlerResponse::ok(vec![4, 0, 0, 0])).await;
        let (hdr, _) = Smb2Header::parse(&resp).expect("response header");

        assert_eq!(hdr.credit_request_response, DEFAULT_MAX_CREDITS);
        assert_eq!(conn.credit_balance(), u32::from(DEFAULT_MAX_CREDITS));
    }

    #[tokio::test]
    async fn credit_overdraw_returns_zero_response_credits() {
        let conn = test_conn();
        let req = Smb2Header {
            credit_charge: 2,
            ..echo_request(1)
        };

        assert_eq!(
            conn.debit_credits(&req),
            Err(ntstatus::STATUS_INVALID_PARAMETER)
        );
        let resp = build_response_bytes_with_credits(
            &conn,
            &req,
            HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER),
            Some(0),
        )
        .await;
        let (hdr, _) = Smb2Header::parse(&resp).expect("response header");

        assert_eq!(
            hdr.channel_sequence_status,
            ntstatus::STATUS_INVALID_PARAMETER
        );
        assert_eq!(hdr.credit_request_response, 0);
        assert_eq!(conn.credit_balance(), 1);
    }

    #[tokio::test]
    async fn signing_required_error_response_is_signed() {
        let conn = test_conn();
        *conn.signing_algo.write().await = crate::proto::crypto::SigningAlgo::AesCmac;
        let signing_key = [0x5a; 16];
        let session = Session::new(
            7,
            Identity::User {
                user: "alice".to_string(),
                domain: "DOMAIN".to_string(),
            },
            [0x11; 16],
            signing_key,
            true,
            None,
        );
        conn.sessions
            .write()
            .await
            .insert(7, Arc::new(tokio::sync::RwLock::new(session)));

        let req = Smb2Header {
            command: Command::Echo,
            message_id: 9,
            session_id: 7,
            credit_charge: 1,
            credit_request_response: 1,
            ..Default::default()
        };
        let resp = build_response_bytes_with_credits(
            &conn,
            &req,
            HandlerResponse::err(ntstatus::STATUS_ACCESS_DENIED),
            Some(1),
        )
        .await;
        let (hdr, _) = Smb2Header::parse(&resp).expect("response header");

        assert_eq!(hdr.channel_sequence_status, ntstatus::STATUS_ACCESS_DENIED);
        assert_ne!(hdr.flags & SMB2_FLAGS_SIGNED, 0);
        crate::proto::crypto::verify(
            &resp,
            &signing_key,
            crate::proto::crypto::SigningAlgo::AesCmac,
        )
        .expect("signed access-denied response verifies");
    }

    #[tokio::test]
    async fn signing_required_error_response_uses_negotiated_gmac() {
        let conn = test_conn();
        *conn.signing_algo.write().await = crate::proto::crypto::SigningAlgo::AesGmac;
        let signing_key = *b"0123456789abcdef";
        let session = Session::new(
            7,
            Identity::User {
                user: "alice".to_string(),
                domain: "DOMAIN".to_string(),
            },
            [0x11; 16],
            signing_key,
            true,
            None,
        );
        conn.sessions
            .write()
            .await
            .insert(7, Arc::new(tokio::sync::RwLock::new(session)));

        let req = Smb2Header {
            command: Command::Echo,
            message_id: 9,
            session_id: 7,
            credit_charge: 1,
            credit_request_response: 1,
            ..Default::default()
        };
        let resp = build_response_bytes_with_credits(
            &conn,
            &req,
            HandlerResponse::err(ntstatus::STATUS_ACCESS_DENIED),
            Some(1),
        )
        .await;
        let (hdr, _) = Smb2Header::parse(&resp).expect("response header");

        assert_eq!(hdr.channel_sequence_status, ntstatus::STATUS_ACCESS_DENIED);
        assert_ne!(hdr.flags & SMB2_FLAGS_SIGNED, 0);

        let mut expected_gmac = resp.clone();
        crate::proto::crypto::sign(
            &mut expected_gmac,
            &signing_key,
            crate::proto::crypto::SigningAlgo::AesGmac,
        )
        .expect("expected GMAC signs");
        assert_eq!(&resp[0x30..0x40], &expected_gmac[0x30..0x40]);

        let mut expected_cmac = resp.clone();
        crate::proto::crypto::sign(
            &mut expected_cmac,
            &signing_key,
            crate::proto::crypto::SigningAlgo::AesCmac,
        )
        .expect("expected CMAC signs");
        assert_ne!(&resp[0x30..0x40], &expected_cmac[0x30..0x40]);
        assert!(
            crate::proto::crypto::verify(
                &resp,
                &signing_key,
                crate::proto::crypto::SigningAlgo::AesCmac,
            )
            .is_err(),
            "GMAC-signed response should not verify as CMAC"
        );
    }

    #[tokio::test]
    async fn encrypted_session_rejects_cleartext_request_with_encrypted_error() {
        let server = test_server(true);
        let (conn, key) = encrypted_test_conn().await;
        let req = Smb2Header {
            command: Command::Echo,
            message_id: 10,
            session_id: 7,
            credit_charge: 1,
            credit_request_response: 1,
            ..Default::default()
        };
        let frame = request_frame(&req, &echo_body());

        let resp = dispatch_frame(&server, &conn, &frame)
            .await
            .expect("response");

        assert!(is_encryption_transform(&resp));
        let plain = decrypt_gcm(&key, &resp).expect("decrypt response");
        let (hdr, _) = Smb2Header::parse(&plain).expect("plain header");
        assert_eq!(hdr.channel_sequence_status, ntstatus::STATUS_ACCESS_DENIED);
    }

    #[tokio::test]
    async fn transport_security_allows_cleartext_request_without_smb_encryption() {
        let server = test_server(true);
        let (conn, _key) = encrypted_test_conn().await;
        *conn.transport_security.write().await = true;
        let req = Smb2Header {
            command: Command::Echo,
            message_id: 12,
            session_id: 7,
            credit_charge: 1,
            credit_request_response: 1,
            ..Default::default()
        };
        let frame = request_frame(&req, &echo_body());

        let resp = dispatch_frame(&server, &conn, &frame)
            .await
            .expect("response");

        assert!(!is_encryption_transform(&resp));
        let (hdr, _) = Smb2Header::parse(&resp).expect("response header");
        assert_eq!(hdr.channel_sequence_status, ntstatus::STATUS_SUCCESS);
        assert_eq!(hdr.command, Command::Echo);
    }

    #[tokio::test]
    async fn transport_security_still_enforces_required_signing() {
        let server = test_server(true);
        let (conn, _key) = encrypted_test_conn().await;
        *conn.transport_security.write().await = true;
        *conn.signing_algo.write().await = crate::proto::crypto::SigningAlgo::AesCmac;
        let signing_key = [0x5a; 16];
        let sessions = conn.sessions.read().await;
        let sess_arc = sessions.get(&7).expect("session").clone();
        drop(sessions);
        {
            let mut sess = sess_arc.write().await;
            sess.signing_key = signing_key;
            sess.signing_required = true;
        }
        let req = Smb2Header {
            command: Command::Echo,
            message_id: 13,
            session_id: 7,
            credit_charge: 1,
            credit_request_response: 1,
            ..Default::default()
        };
        let frame = request_frame(&req, &echo_body());

        let resp = dispatch_frame(&server, &conn, &frame)
            .await
            .expect("response");

        assert!(!is_encryption_transform(&resp));
        let (hdr, _) = Smb2Header::parse(&resp).expect("response header");
        assert_eq!(hdr.channel_sequence_status, ntstatus::STATUS_ACCESS_DENIED);
        assert_ne!(hdr.flags & SMB2_FLAGS_SIGNED, 0);
        crate::proto::crypto::verify(
            &resp,
            &signing_key,
            crate::proto::crypto::SigningAlgo::AesCmac,
        )
        .expect("signed access-denied response verifies");
    }

    #[tokio::test]
    async fn transport_security_accepts_signed_required_request() {
        let server = test_server(true);
        let (conn, _key) = encrypted_test_conn().await;
        *conn.transport_security.write().await = true;
        *conn.signing_algo.write().await = crate::proto::crypto::SigningAlgo::AesCmac;
        let signing_key = [0x5a; 16];
        let sessions = conn.sessions.read().await;
        let sess_arc = sessions.get(&7).expect("session").clone();
        drop(sessions);
        {
            let mut sess = sess_arc.write().await;
            sess.signing_key = signing_key;
            sess.signing_required = true;
        }
        let req = Smb2Header {
            command: Command::Echo,
            message_id: 14,
            session_id: 7,
            credit_charge: 1,
            credit_request_response: 1,
            flags: SMB2_FLAGS_SIGNED,
            ..Default::default()
        };
        let mut frame = request_frame(&req, &echo_body());
        crate::proto::crypto::sign(
            &mut frame,
            &signing_key,
            crate::proto::crypto::SigningAlgo::AesCmac,
        )
        .expect("request signs");

        let resp = dispatch_frame(&server, &conn, &frame)
            .await
            .expect("response");

        assert!(!is_encryption_transform(&resp));
        let (hdr, _) = Smb2Header::parse(&resp).expect("response header");
        assert_eq!(hdr.channel_sequence_status, ntstatus::STATUS_SUCCESS);
        assert_eq!(hdr.command, Command::Echo);
        assert_ne!(hdr.flags & SMB2_FLAGS_SIGNED, 0);
        crate::proto::crypto::verify(
            &resp,
            &signing_key,
            crate::proto::crypto::SigningAlgo::AesCmac,
        )
        .expect("signed success response verifies");
    }

    #[tokio::test]
    async fn anonymous_request_with_bad_signature_is_rejected() {
        let server = test_server(false);
        let conn = test_conn();
        *conn.signing_algo.write().await = crate::proto::crypto::SigningAlgo::AesCmac;
        let signing_key = [0x71; 16];
        let session = Session::new(7, Identity::Anonymous, [0x22; 16], signing_key, false, None);
        conn.sessions
            .write()
            .await
            .insert(7, Arc::new(tokio::sync::RwLock::new(session)));

        let req = Smb2Header {
            command: Command::Echo,
            message_id: 21,
            session_id: 7,
            credit_charge: 1,
            credit_request_response: 1,
            flags: SMB2_FLAGS_SIGNED,
            ..Default::default()
        };
        let mut frame = request_frame(&req, &echo_body());
        crate::proto::crypto::sign(
            &mut frame,
            &[0x13; 16],
            crate::proto::crypto::SigningAlgo::AesCmac,
        )
        .expect("request signs with wrong key");

        let resp = dispatch_frame(&server, &conn, &frame)
            .await
            .expect("response");
        let (hdr, _) = Smb2Header::parse(&resp).expect("response header");

        assert_eq!(hdr.channel_sequence_status, ntstatus::STATUS_ACCESS_DENIED);
        assert_ne!(hdr.flags & SMB2_FLAGS_SIGNED, 0);
        crate::proto::crypto::verify(
            &resp,
            &signing_key,
            crate::proto::crypto::SigningAlgo::AesCmac,
        )
        .expect("anonymous access-denied response verifies");
    }

    #[tokio::test]
    async fn anonymous_unsigned_request_is_allowed_when_signing_key_exists() {
        let server = test_server(false);
        let conn = test_conn();
        *conn.signing_algo.write().await = crate::proto::crypto::SigningAlgo::AesCmac;
        let signing_key = [0x73; 16];
        let session = Session::new(7, Identity::Anonymous, [0x44; 16], signing_key, false, None);
        conn.sessions
            .write()
            .await
            .insert(7, Arc::new(tokio::sync::RwLock::new(session)));

        let req = Smb2Header {
            command: Command::Echo,
            message_id: 23,
            session_id: 7,
            credit_charge: 1,
            credit_request_response: 1,
            ..Default::default()
        };
        let frame = request_frame(&req, &echo_body());

        let resp = dispatch_frame(&server, &conn, &frame)
            .await
            .expect("response");
        let (hdr, _) = Smb2Header::parse(&resp).expect("response header");

        assert_eq!(hdr.channel_sequence_status, ntstatus::STATUS_SUCCESS);
        assert_eq!(hdr.command, Command::Echo);
        assert_eq!(hdr.flags & SMB2_FLAGS_SIGNED, 0);
    }

    #[tokio::test]
    async fn anonymous_signed_request_verifies_and_response_is_signed() {
        let server = test_server(false);
        let conn = test_conn();
        *conn.signing_algo.write().await = crate::proto::crypto::SigningAlgo::AesCmac;
        let signing_key = [0x72; 16];
        let session = Session::new(7, Identity::Anonymous, [0x33; 16], signing_key, true, None);
        conn.sessions
            .write()
            .await
            .insert(7, Arc::new(tokio::sync::RwLock::new(session)));

        let req = Smb2Header {
            command: Command::Echo,
            message_id: 22,
            session_id: 7,
            credit_charge: 1,
            credit_request_response: 1,
            flags: SMB2_FLAGS_SIGNED,
            ..Default::default()
        };
        let mut frame = request_frame(&req, &echo_body());
        crate::proto::crypto::sign(
            &mut frame,
            &signing_key,
            crate::proto::crypto::SigningAlgo::AesCmac,
        )
        .expect("anonymous request signs");

        let resp = dispatch_frame(&server, &conn, &frame)
            .await
            .expect("response");
        let (hdr, _) = Smb2Header::parse(&resp).expect("response header");

        assert_eq!(hdr.channel_sequence_status, ntstatus::STATUS_SUCCESS);
        assert_eq!(hdr.command, Command::Echo);
        assert_ne!(hdr.flags & SMB2_FLAGS_SIGNED, 0);
        crate::proto::crypto::verify(
            &resp,
            &signing_key,
            crate::proto::crypto::SigningAlgo::AesCmac,
        )
        .expect("anonymous signed response verifies");
    }

    #[tokio::test]
    async fn encrypted_session_accepts_encrypted_echo_request() {
        let server = test_server(true);
        let (conn, key) = encrypted_test_conn().await;
        let req = Smb2Header {
            command: Command::Echo,
            message_id: 11,
            session_id: 7,
            credit_charge: 1,
            credit_request_response: 1,
            ..Default::default()
        };
        let frame = request_frame(&req, &echo_body());
        let encrypted = encrypt_gcm(&key, 7, &frame).expect("encrypt request");

        let resp = dispatch_frame(&server, &conn, &encrypted)
            .await
            .expect("response");

        assert!(is_encryption_transform(&resp));
        let plain = decrypt_gcm(&key, &resp).expect("decrypt response");
        let (hdr, _) = Smb2Header::parse(&plain).expect("plain header");
        assert_eq!(hdr.channel_sequence_status, ntstatus::STATUS_SUCCESS);
        assert_eq!(hdr.command, Command::Echo);
    }

    #[tokio::test]
    async fn encrypted_session_skips_plain_signature_verification() {
        let server = test_server(true);
        let (conn, key) = encrypted_test_conn().await;
        let req = Smb2Header {
            command: Command::Echo,
            message_id: 15,
            session_id: 7,
            credit_charge: 1,
            credit_request_response: 1,
            flags: SMB2_FLAGS_SIGNED,
            ..Default::default()
        };
        let frame = request_frame(&req, &echo_body());
        let encrypted = encrypt_gcm(&key, 7, &frame).expect("encrypt request");

        let resp = dispatch_frame(&server, &conn, &encrypted)
            .await
            .expect("response");

        assert!(is_encryption_transform(&resp));
        let plain = decrypt_gcm(&key, &resp).expect("decrypt response");
        let (hdr, _) = Smb2Header::parse(&plain).expect("plain header");
        assert_eq!(hdr.channel_sequence_status, ntstatus::STATUS_SUCCESS);
        assert_eq!(hdr.command, Command::Echo);
    }

    #[tokio::test]
    async fn negotiated_compression_wraps_non_session_responses() {
        let conn = test_conn();
        *conn.compression_algorithm.write().await =
            crate::proto::messages::CompressionCapabilities::ALGORITHM_PATTERN_V1;
        let req = echo_request(1);
        let mut response = build_response_bytes(
            &conn,
            &req,
            HandlerResponse::ok(std::iter::repeat_n(0x44, 256).collect()),
        )
        .await;
        assert_eq!(&response[..4], &[0xFE, b'S', b'M', b'B']);

        response = maybe_compress_response(&conn, Some(Command::Echo), response).await;
        assert_eq!(
            &response[..4],
            &crate::proto::crypto::compression::COMPRESSION_MAGIC
        );

        let negotiate = build_response_bytes(
            &conn,
            &Smb2Header {
                command: Command::Negotiate,
                ..req
            },
            HandlerResponse::ok(std::iter::repeat_n(0x44, 256).collect()),
        )
        .await;
        let negotiate = maybe_compress_response(&conn, Some(Command::Negotiate), negotiate).await;
        assert_eq!(&negotiate[..4], &[0xFE, b'S', b'M', b'B']);
    }

    #[tokio::test]
    async fn compressed_request_is_decompressed_before_dispatch() {
        let server = test_server(false);
        let conn = test_conn();
        *conn.dialect.write().await = Some(Dialect::Smb311);
        *conn.compression_algorithm.write().await =
            crate::proto::messages::CompressionCapabilities::ALGORITHM_PATTERN_V1;

        let req = Smb2Header {
            command: Command::Echo,
            credit_charge: 1,
            credit_request_response: 1,
            message_id: 12,
            ..Default::default()
        };
        let mut plain = request_frame(&req, &echo_body());
        plain.extend(std::iter::repeat_n(0, 128));
        let compressed = crate::proto::crypto::compression::compress_pattern_transform(&plain)
            .expect("pattern request compresses");

        let resp = dispatch_frame(&server, &conn, &compressed)
            .await
            .expect("response");
        let (hdr, _) = Smb2Header::parse(&resp).expect("response header");

        assert_eq!(hdr.channel_sequence_status, ntstatus::STATUS_SUCCESS);
        assert_eq!(hdr.command, Command::Echo);
    }

    #[tokio::test]
    async fn related_compound_operations_do_not_change_credits() {
        let conn = test_conn();
        let req = Smb2Header {
            flags: SMB2_FLAGS_RELATED_OPERATIONS,
            credit_request_response: 8,
            ..echo_request(8)
        };
        conn.debit_credits(&req).expect("related debit ignored");

        let resp = build_response_bytes(&conn, &req, HandlerResponse::ok(vec![4, 0, 0, 0])).await;
        let (hdr, _) = Smb2Header::parse(&resp).expect("response header");

        assert_eq!(hdr.credit_request_response, 0);
        assert_eq!(conn.credit_balance(), 1);
    }

    #[tokio::test]
    async fn async_pending_grants_credits_but_final_completion_does_not() {
        let conn = test_conn();
        let req = Smb2Header {
            command: Command::ChangeNotify,
            message_id: 10,
            session_id: 2,
            credit_charge: 1,
            credit_request_response: 5,
            tail: HeaderTail::sync(1),
            ..Default::default()
        };
        conn.debit_credits(&req).expect("request credit debit");
        let notify_body = vec![9, 0, 72, 0, 0, 0, 0, 0, 0];

        let pending = build_response_bytes(
            &conn,
            &req,
            HandlerResponse::pending_async(123, notify_body.clone()),
        )
        .await;
        let (pending_hdr, pending_body) =
            Smb2Header::parse(&pending).expect("pending response header");
        assert_eq!(
            pending_hdr.channel_sequence_status,
            ntstatus::STATUS_PENDING
        );
        assert_ne!(pending_hdr.flags & SMB2_FLAGS_ASYNC_COMMAND, 0);
        assert_eq!(pending_hdr.async_id(), Some(123));
        assert_eq!(pending_hdr.credit_request_response, 5);
        assert_eq!(
            u16::from_le_bytes(pending_body[0..2].try_into().unwrap()),
            9
        );

        let final_resp = build_response_bytes(
            &conn,
            &req,
            HandlerResponse::final_async(123, ntstatus::STATUS_NOTIFY_ENUM_DIR, notify_body),
        )
        .await;
        let (final_hdr, _) = Smb2Header::parse(&final_resp).expect("final response header");
        assert_eq!(
            final_hdr.channel_sequence_status,
            ntstatus::STATUS_NOTIFY_ENUM_DIR
        );
        assert_ne!(final_hdr.flags & SMB2_FLAGS_ASYNC_COMMAND, 0);
        assert_eq!(final_hdr.async_id(), Some(123));
        assert_eq!(final_hdr.credit_request_response, 0);
    }

    #[tokio::test]
    async fn large_payloads_require_sufficient_credit_charge() {
        let conn = test_conn();
        set_dialect(&conn, Dialect::Smb311).await;
        let large = 64 * 1024 + 1;
        let cases = [
            (
                Command::Read,
                request_header(Command::Read, 1),
                read_body(large),
            ),
            (
                Command::Read,
                request_header(Command::Read, 0),
                read_body(large),
            ),
            (
                Command::Write,
                request_header(Command::Write, 1),
                write_body(large as usize),
            ),
            (
                Command::QueryDirectory,
                request_header(Command::QueryDirectory, 1),
                query_directory_body(large),
            ),
            (
                Command::Ioctl,
                request_header(Command::Ioctl, 1),
                ioctl_body(1, large),
            ),
        ];

        for (command, hdr, body) in cases {
            assert_eq!(
                validate_credit_charge(&conn, &hdr, &body).await,
                Err(ntstatus::STATUS_INVALID_PARAMETER),
                "{command:?} accepted an undercharged large request"
            );
        }
    }

    #[tokio::test]
    async fn large_payloads_accept_exact_credit_charge() {
        let conn = test_conn();
        set_dialect(&conn, Dialect::Smb311).await;
        let large = 64 * 1024 + 1;
        let cases = [
            (request_header(Command::Read, 2), read_body(large)),
            (
                request_header(Command::Write, 2),
                write_body(large as usize),
            ),
            (
                request_header(Command::QueryDirectory, 2),
                query_directory_body(large),
            ),
            (request_header(Command::Ioctl, 2), ioctl_body(1, large)),
        ];

        for (hdr, body) in cases {
            validate_credit_charge(&conn, &hdr, &body)
                .await
                .expect("exact credit charge should be accepted");
        }
    }

    #[tokio::test]
    async fn smb202_does_not_enforce_multi_credit_charge() {
        let conn = test_conn();
        set_dialect(&conn, Dialect::Smb202).await;
        let hdr = request_header(Command::Read, 0);
        let body = read_body(64 * 1024 + 1);

        validate_credit_charge(&conn, &hdr, &body)
            .await
            .expect("SMB 2.0.2 ignores multi-credit charge validation");
    }
}
