#![allow(clippy::too_many_arguments)]

//! Integration test: drive a real `SmbServer` over a TCP loopback through a
//! NEGOTIATE → SESSION_SETUP (anonymous) → TREE_CONNECT → CREATE → READ flow.
//!
//! We hand-craft the request bytes since we don't depend on a Rust SMB client
//! crate.

mod common;

use common::{
    NTLMSSP_SIGNATURE, STATUS_ACCESS_DENIED, STATUS_MORE_PROCESSING_REQUIRED, STATUS_SUCCESS,
    anonymous_ntlm_authenticate_token, anonymous_ntlm_negotiate_token, anonymous_session_setup,
    build_header, build_spnego_init, build_spnego_kerberos_only_init, build_spnego_resp,
    decrypt_aes_ccm_transform, decrypt_aes_gcm_transform, encode_frame, encrypt_aes_ccm_transform,
    encrypt_aes_gcm_transform, is_encryption_transform, negotiate, parse_response_header,
    raw_ntlm_negotiate, raw_ntlmv2_authenticate, read_frame, sign_smb300_payload,
    sign_smb311_payload, smb300_encryption_key_c2s, smb300_encryption_key_s2c, smb300_signing_key,
    smb311_encryption_key_c2s, smb311_encryption_key_c2s_256, smb311_encryption_key_s2c,
    smb311_encryption_key_s2c_256, smb311_preauth_update, smb311_signing_key, tree_connect,
    tree_connect_status, utf16le, verify_smb300_signed_payload, verify_smb311_signed_payload,
    write_frame,
};

use smb_server::wire::crypto::SigningAlgo;
use smb_server::wire::header::{Command, Smb2Header};
use smb_server::wire::messages::{
    CloseRequest, CloseResponse, CompressionCapabilities, CreateRequest, CreateResponse,
    EchoRequest, EchoResponse, EncryptionCapabilities, FileId, Fsctl, IoctlRequest, IoctlResponse,
    NegotiateContext, NegotiateRequest, NegotiateResponse, PreauthIntegrityCapabilities,
    RdmaTransformCapabilities, ReadRequest, ReadResponse, SessionSetupRequest,
    SessionSetupResponse, SigningCapabilities, TreeConnectRequest, TreeConnectResponse,
    WriteRequest, WriteResponse,
};
use smb_server::{Access, LocalFsBackend, Share, SmbServer};
use tempfile::tempdir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_SMB_NO_PREAUTH_INTEGRITY_HASH_OVERLAP: u32 = 0xC05D_0000;
const SMB2_NEGOTIATE_SIGNING_REQUIRED: u16 = 0x0002;
const SMB2_GLOBAL_CAP_LEASING: u32 = 0x0000_0002;
const SMB2_GLOBAL_CAP_ENCRYPTION: u32 = 0x0000_0040;

#[tokio::test]
async fn netbios_session_request_is_accepted_before_direct_tcp_negotiate() {
    let td = tempdir().expect("tempdir");
    let backend = LocalFsBackend::new(td.path()).expect("open root");
    let server = SmbServer::builder()
        .listen("127.0.0.1:0".parse().unwrap())
        .share(Share::new("virtual", backend).public())
        .netbios_name("TESTSERVER")
        .build()
        .expect("build");

    server.bind().await.expect("bind");
    let addr = server.local_addr().await.expect("addr");
    let handle = tokio::spawn(async move { server.serve().await });
    tokio::task::yield_now().await;

    let mut s = TcpStream::connect(addr).await.expect("connect");
    s.write_all(&[0x81, 0x00, 0x00, 0x04])
        .await
        .expect("write netbios session request header");
    s.write_all(b"CALL")
        .await
        .expect("write netbios called name placeholder");

    let mut accepted = [0u8; 4];
    s.read_exact(&mut accepted)
        .await
        .expect("read netbios session response");
    assert_eq!(accepted, [0x82, 0x00, 0x00, 0x00]);

    let neg_resp = negotiate(&mut s).await;
    assert!(matches!(neg_resp.dialect_revision, 0x0202 | 0x0210));

    handle.abort();
}

#[tokio::test]
async fn tree_connect_rejects_malformed_unc_paths() {
    let td = tempdir().expect("tempdir");
    let backend = LocalFsBackend::new(td.path()).expect("open root");
    let server = SmbServer::builder()
        .listen("127.0.0.1:0".parse().unwrap())
        .share(Share::new("virtual", backend).public())
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

    assert_eq!(
        tree_connect_status(&mut s, "VIRTUAL", session_id, 3).await,
        STATUS_INVALID_PARAMETER
    );
    assert_eq!(
        tree_connect_status(&mut s, "\\\\host\\VIRTUAL\\extra", session_id, 4).await,
        STATUS_INVALID_PARAMETER
    );

    handle.abort();
}

#[tokio::test]
async fn require_signing_advertises_security_mode_and_validate_info() {
    let td = tempdir().expect("tempdir");
    let backend = LocalFsBackend::new(td.path()).expect("open root");
    let server = SmbServer::builder()
        .listen("127.0.0.1:0".parse().unwrap())
        .share(Share::new("downloads", backend).public())
        .netbios_name("TESTSERVER")
        .require_signing(true)
        .build()
        .expect("build");

    server.bind().await.expect("bind");
    let addr = server.local_addr().await.expect("addr");
    let handle = tokio::spawn(async move { server.serve().await });
    tokio::task::yield_now().await;

    let mut s = TcpStream::connect(addr).await.expect("connect");
    let neg_req = NegotiateRequest {
        structure_size: 36,
        dialect_count: 2,
        security_mode: 0x0001,
        reserved: 0,
        capabilities: 0,
        client_guid: [0xCD; 16],
        negotiate_context_offset_or_client_start_time: 0,
        dialects: vec![0x0202, 0x0210],
    };
    let mut body = Vec::new();
    neg_req.write_to(&mut body).expect("write negotiate");
    let hdr = build_header(Command::Negotiate, 0, 0, 0);
    write_frame(&mut s, &hdr, &body).await;

    let resp = read_frame(&mut s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Negotiate);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let neg_resp = NegotiateResponse::parse(rb).expect("parse neg resp");
    assert_ne!(neg_resp.security_mode & SMB2_NEGOTIATE_SIGNING_REQUIRED, 0);

    let session_id = anonymous_session_setup(&mut s).await;
    let tree_id = tree_connect(&mut s, "\\\\TESTSERVER\\downloads", session_id, 3).await;
    let ioctl_req = IoctlRequest {
        structure_size: 57,
        reserved: 0,
        ctl_code: Fsctl::VALIDATE_NEGOTIATE_INFO,
        file_id: FileId::any(),
        input_offset: 0,
        input_count: 0,
        max_input_response: 0,
        output_offset: 0,
        output_count: 0,
        max_output_response: 24,
        flags: IoctlRequest::FLAG_IS_FSCTL,
        reserved2: 0,
        input: vec![],
    };
    let mut body = Vec::new();
    ioctl_req.write_to(&mut body).expect("write ioctl");
    let hdr = build_header(Command::Ioctl, 4, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;

    let resp = read_frame(&mut s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Ioctl);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let ioctl_resp = IoctlResponse::parse(rb).expect("parse ioctl resp");
    let validate_security_mode = u16::from_le_bytes([ioctl_resp.output[20], ioctl_resp.output[21]]);
    assert_eq!(validate_security_mode, neg_resp.security_mode);

    handle.abort();
}

#[tokio::test]
async fn required_signing_rejects_unsigned_and_accepts_signed_smb302_echo() {
    let td = tempdir().expect("tempdir");
    let backend = LocalFsBackend::new(td.path()).expect("open root");
    let server = SmbServer::builder()
        .listen("127.0.0.1:0".parse().unwrap())
        .user("alice", "Password")
        .share(Share::new("secure", backend).user("alice", Access::ReadWrite))
        .netbios_name("TESTSERVER")
        .require_signing(true)
        .build()
        .expect("build");

    server.bind().await.expect("bind");
    let addr = server.local_addr().await.expect("addr");
    let handle = tokio::spawn(async move { server.serve().await });
    tokio::task::yield_now().await;

    let mut s = TcpStream::connect(addr).await.expect("connect");
    let negotiate_body = smb_negotiate_with_contexts(&[0x0302], &[]).0;
    let negotiate_header = build_header(Command::Negotiate, 0, 0, 0);
    write_frame(&mut s, &negotiate_header, &negotiate_body).await;
    let negotiate_response = read_frame(&mut s).await;
    let (rh, rb) = parse_response_header(&negotiate_response);
    assert_eq!(rh.command, Command::Negotiate);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let neg_resp = NegotiateResponse::parse(rb).expect("parse negotiate");
    assert_eq!(neg_resp.dialect_revision, 0x0302);
    assert_ne!(neg_resp.security_mode & SMB2_NEGOTIATE_SIGNING_REQUIRED, 0);

    let (session_id, session_key) =
        authenticated_raw_ntlm_session_setup_without_encryption(&mut s, 1).await;
    let signing_key = smb300_signing_key(&session_key);

    let mut body = Vec::new();
    EchoRequest::default()
        .write_to(&mut body)
        .expect("write unsigned echo");
    let unsigned_header = build_header(Command::Echo, 3, session_id, 0);
    write_frame(&mut s, &unsigned_header, &body).await;
    let unsigned_response = read_frame(&mut s).await;
    verify_smb300_signed_payload(&unsigned_response, &signing_key);
    let (rh, _) = parse_response_header(&unsigned_response);
    assert_eq!(rh.command, Command::Echo);
    assert_eq!(rh.channel_sequence_status, STATUS_ACCESS_DENIED);

    let mut signed_payload = smb_payload(&build_header(Command::Echo, 4, session_id, 0), &body);
    sign_smb300_payload(&mut signed_payload, &signing_key);
    write_payload_frame(&mut s, &signed_payload).await;
    let signed_response = read_frame(&mut s).await;
    verify_smb300_signed_payload(&signed_response, &signing_key);
    let (rh, rb) = parse_response_header(&signed_response);
    assert_eq!(rh.command, Command::Echo);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let _ = EchoResponse::parse(rb).expect("parse signed echo response");

    drop(s);
    handle.abort();
}

#[tokio::test]
async fn required_signing_accepts_negotiated_smb311_signing_algorithms() {
    for (offered, expected_selected, algo) in [
        (
            &[
                SigningCapabilities::ALGORITHM_AES_GMAC,
                SigningCapabilities::ALGORITHM_AES_CMAC,
            ][..],
            SigningCapabilities::ALGORITHM_AES_GMAC,
            SigningAlgo::AesGmac,
        ),
        (
            &[SigningCapabilities::ALGORITHM_AES_CMAC][..],
            SigningCapabilities::ALGORITHM_AES_CMAC,
            SigningAlgo::AesCmac,
        ),
    ] {
        smb311_signed_echo_round_trip(offered, expected_selected, algo).await;
    }
}

async fn smb311_signed_echo_round_trip(
    offered_signing_algorithms: &[u16],
    expected_selected: u16,
    algo: SigningAlgo,
) {
    let td = tempdir().expect("tempdir");
    let backend = LocalFsBackend::new(td.path()).expect("open root");
    let server = SmbServer::builder()
        .listen("127.0.0.1:0".parse().unwrap())
        .user("alice", "Password")
        .share(Share::new("secure", backend).user("alice", Access::ReadWrite))
        .netbios_name("TESTSERVER")
        .require_signing(true)
        .build()
        .expect("build");

    server.bind().await.expect("bind");
    let addr = server.local_addr().await.expect("addr");
    let handle = tokio::spawn(async move { server.serve().await });
    tokio::task::yield_now().await;

    let mut s = TcpStream::connect(addr).await.expect("connect");
    let mut preauth = [0u8; 64];
    let negotiate_contexts = vec![
        preauth_context(&[PreauthIntegrityCapabilities::HASH_SHA512]),
        signing_context(offered_signing_algorithms),
    ];
    let negotiate_body = smb311_negotiate_with_contexts(&negotiate_contexts).0;
    let negotiate_header = build_header(Command::Negotiate, 0, 0, 0);
    let negotiate_payload = smb_payload(&negotiate_header, &negotiate_body);
    smb311_preauth_update(&mut preauth, &negotiate_payload);
    write_payload_frame(&mut s, &negotiate_payload).await;

    let negotiate_response = read_frame(&mut s).await;
    smb311_preauth_update(&mut preauth, &negotiate_response);
    let (rh, rb) = parse_response_header(&negotiate_response);
    assert_eq!(rh.command, Command::Negotiate);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let neg_resp = NegotiateResponse::parse(rb).expect("parse negotiate");
    assert_eq!(neg_resp.dialect_revision, 0x0311);
    assert_ne!(neg_resp.security_mode & SMB2_NEGOTIATE_SIGNING_REQUIRED, 0);
    assert_eq!(response_signing_algorithm(rb), expected_selected);

    let (session_id, session_key) =
        authenticated_raw_ntlm_session_setup_with_preauth_without_encryption(
            &mut s,
            1,
            &mut preauth,
        )
        .await;
    let signing_key = smb311_signing_key(&session_key, &preauth);

    let mut body = Vec::new();
    EchoRequest::default()
        .write_to(&mut body)
        .expect("write unsigned echo");
    let unsigned_header = build_header(Command::Echo, 3, session_id, 0);
    write_frame(&mut s, &unsigned_header, &body).await;
    let unsigned_response = read_frame(&mut s).await;
    verify_smb311_signed_payload(&unsigned_response, &signing_key, algo);
    let (rh, _) = parse_response_header(&unsigned_response);
    assert_eq!(rh.command, Command::Echo);
    assert_eq!(rh.channel_sequence_status, STATUS_ACCESS_DENIED);

    let mut signed_payload = smb_payload(&build_header(Command::Echo, 4, session_id, 0), &body);
    sign_smb311_payload(&mut signed_payload, &signing_key, algo);
    write_payload_frame(&mut s, &signed_payload).await;
    let signed_response = read_frame(&mut s).await;
    verify_smb311_signed_payload(&signed_response, &signing_key, algo);
    let (rh, rb) = parse_response_header(&signed_response);
    assert_eq!(rh.command, Command::Echo);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let _ = EchoResponse::parse(rb).expect("parse signed echo response");

    drop(s);
    handle.abort();
}

#[tokio::test]
async fn negotiate_advertises_leasing_capability() {
    let smb202 = assert_negotiate_status(
        smb_negotiate_with_contexts(&[0x0202], &[]).0,
        STATUS_SUCCESS,
    )
    .await;
    let smb202_resp = NegotiateResponse::parse(&smb202).expect("parse SMB 2.0.2 negotiate");
    assert_eq!(smb202_resp.dialect_revision, 0x0202);
    assert_eq!(smb202_resp.capabilities, 0);

    let smb210 = assert_negotiate_status(
        smb_negotiate_with_contexts(&[0x0210], &[]).0,
        STATUS_SUCCESS,
    )
    .await;
    let smb210_resp = NegotiateResponse::parse(&smb210).expect("parse SMB 2.1 negotiate");
    assert_eq!(smb210_resp.dialect_revision, 0x0210);
    assert_ne!(smb210_resp.capabilities & SMB2_GLOBAL_CAP_LEASING, 0);

    let contexts = vec![preauth_context(&[
        PreauthIntegrityCapabilities::HASH_SHA512,
    ])];
    let smb311 =
        assert_negotiate_status(smb311_negotiate_with_contexts(&contexts).0, STATUS_SUCCESS).await;
    let smb311_resp = NegotiateResponse::parse(&smb311).expect("parse SMB 3.1.1 negotiate");
    assert_eq!(smb311_resp.dialect_revision, 0x0311);
    assert_ne!(smb311_resp.capabilities & SMB2_GLOBAL_CAP_LEASING, 0);
}

#[tokio::test]
async fn guest_session_setup_without_ntlm_completes_null_session() {
    let td = tempdir().expect("tempdir");
    let backend = LocalFsBackend::new(td.path()).expect("open root");
    let server = SmbServer::builder()
        .listen("127.0.0.1:0".parse().unwrap())
        .share(Share::new("downloads", backend).public())
        .netbios_name("TESTSERVER")
        .build()
        .expect("build");

    server.bind().await.expect("bind");
    let addr = server.local_addr().await.expect("addr");
    let handle = tokio::spawn(async move { server.serve().await });
    tokio::task::yield_now().await;

    let mut s = TcpStream::connect(addr).await.expect("connect");
    let _ = negotiate(&mut s).await;

    let spnego_init = build_spnego_kerberos_only_init();
    let ss_req = SessionSetupRequest {
        structure_size: 25,
        flags: 0,
        security_mode: 0x01,
        capabilities: 0,
        channel: 0,
        security_buffer_offset: 88,
        security_buffer_length: spnego_init.len() as u16,
        previous_session_id: 0,
        security_buffer: spnego_init,
    };
    let mut body = Vec::new();
    ss_req.write_to(&mut body).expect("write session setup");
    let hdr = build_header(Command::SessionSetup, 1, 0, 0);
    write_frame(&mut s, &hdr, &body).await;

    let resp = read_frame(&mut s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::SessionSetup);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    assert_ne!(rh.session_id, 0);
    let ss_resp = SessionSetupResponse::parse(rb).expect("parse session setup");
    assert_eq!(
        ss_resp.session_flags & SessionSetupResponse::FLAG_IS_NULL,
        SessionSetupResponse::FLAG_IS_NULL
    );
    assert_eq!(
        ss_resp.session_flags & SessionSetupResponse::FLAG_IS_GUEST,
        0
    );
    assert!(!ss_resp.security_buffer.is_empty());

    drop(s);
    handle.abort();
}

#[tokio::test]
async fn guest_session_setup_returns_real_ntlm_challenge() {
    let td = tempdir().expect("tempdir");
    let backend = LocalFsBackend::new(td.path()).expect("open root");
    let server = SmbServer::builder()
        .listen("127.0.0.1:0".parse().unwrap())
        .share(Share::new("downloads", backend).public())
        .netbios_name("TESTSERVER")
        .build()
        .expect("build");

    server.bind().await.expect("bind");
    let addr = server.local_addr().await.expect("addr");
    let handle = tokio::spawn(async move { server.serve().await });
    tokio::task::yield_now().await;

    let mut s = TcpStream::connect(addr).await.expect("connect");
    let _ = negotiate(&mut s).await;

    let spnego_init = build_spnego_init(&anonymous_ntlm_negotiate_token());
    let ss_req = SessionSetupRequest {
        structure_size: 25,
        flags: 0,
        security_mode: 0x01,
        capabilities: 0,
        channel: 0,
        security_buffer_offset: 88,
        security_buffer_length: spnego_init.len() as u16,
        previous_session_id: 0,
        security_buffer: spnego_init,
    };
    let mut body = Vec::new();
    ss_req.write_to(&mut body).expect("write session setup");
    let hdr = build_header(Command::SessionSetup, 1, 0, 0);
    write_frame(&mut s, &hdr, &body).await;

    let resp = read_frame(&mut s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::SessionSetup);
    assert_eq!(rh.channel_sequence_status, STATUS_MORE_PROCESSING_REQUIRED);
    assert_ne!(rh.session_id, 0);
    let ss_resp = SessionSetupResponse::parse(rb).expect("parse challenge session setup");
    assert!(contains_ntlmssp_message_type(&ss_resp.security_buffer, 2));

    let spnego_resp_blob = build_spnego_resp(&anonymous_ntlm_authenticate_token());
    let ss_req = SessionSetupRequest {
        structure_size: 25,
        flags: 0,
        security_mode: 0x01,
        capabilities: 0,
        channel: 0,
        security_buffer_offset: 88,
        security_buffer_length: spnego_resp_blob.len() as u16,
        previous_session_id: 0,
        security_buffer: spnego_resp_blob,
    };
    let mut body = Vec::new();
    ss_req
        .write_to(&mut body)
        .expect("write final session setup");
    let hdr = build_header(Command::SessionSetup, 2, rh.session_id, 0);
    write_frame(&mut s, &hdr, &body).await;

    let resp = read_frame(&mut s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::SessionSetup);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let ss_resp = SessionSetupResponse::parse(rb).expect("parse success session setup");
    assert_eq!(
        ss_resp.session_flags & SessionSetupResponse::FLAG_IS_GUEST,
        SessionSetupResponse::FLAG_IS_GUEST
    );

    drop(s);
    handle.abort();
}

#[tokio::test]
async fn encrypt_data_prefers_aes256_gcm_for_smb311() {
    let contexts = vec![
        preauth_context(&[PreauthIntegrityCapabilities::HASH_SHA512]),
        encryption_context(&[
            EncryptionCapabilities::CIPHER_AES_128_CCM,
            EncryptionCapabilities::CIPHER_AES_128_GCM,
            EncryptionCapabilities::CIPHER_AES_256_CCM,
            EncryptionCapabilities::CIPHER_AES_256_GCM,
        ]),
    ];
    let rb = assert_negotiate_status_encrypted(
        smb311_negotiate_with_contexts(&contexts).0,
        STATUS_SUCCESS,
    )
    .await;
    let neg_resp = NegotiateResponse::parse(&rb).expect("parse negotiate");

    assert_eq!(neg_resp.dialect_revision, 0x0311);
    assert_ne!(neg_resp.capabilities & SMB2_GLOBAL_CAP_ENCRYPTION, 0);
    assert_eq!(
        response_encryption_cipher(&rb),
        EncryptionCapabilities::CIPHER_AES_256_GCM
    );
}

#[tokio::test]
async fn encrypt_data_accepts_aes256_gcm_only_for_smb311() {
    let contexts = vec![
        preauth_context(&[PreauthIntegrityCapabilities::HASH_SHA512]),
        encryption_context(&[EncryptionCapabilities::CIPHER_AES_256_GCM]),
    ];
    let rb = assert_negotiate_status_encrypted(
        smb_negotiate_with_contexts(&[0x0311, 0x0302], &contexts).0,
        STATUS_SUCCESS,
    )
    .await;
    let neg_resp = NegotiateResponse::parse(&rb).expect("parse negotiate");

    assert_eq!(neg_resp.dialect_revision, 0x0311);
    assert_ne!(neg_resp.capabilities & SMB2_GLOBAL_CAP_ENCRYPTION, 0);
    assert_eq!(
        response_encryption_cipher(&rb),
        EncryptionCapabilities::CIPHER_AES_256_GCM
    );
}

fn contains_ntlmssp_message_type(blob: &[u8], message_type: u32) -> bool {
    blob.windows(NTLMSSP_SIGNATURE.len() + 4).any(|window| {
        window.starts_with(NTLMSSP_SIGNATURE)
            && u32::from_le_bytes(
                window[NTLMSSP_SIGNATURE.len()..NTLMSSP_SIGNATURE.len() + 4]
                    .try_into()
                    .expect("message type bytes"),
            ) == message_type
    })
}

#[tokio::test]
async fn encrypt_data_falls_back_to_aes128_gcm_for_smb311() {
    let contexts = vec![
        preauth_context(&[PreauthIntegrityCapabilities::HASH_SHA512]),
        encryption_context(&[
            EncryptionCapabilities::CIPHER_AES_128_CCM,
            EncryptionCapabilities::CIPHER_AES_128_GCM,
        ]),
    ];
    let rb = assert_negotiate_status_encrypted(
        smb_negotiate_with_contexts(&[0x0311, 0x0302], &contexts).0,
        STATUS_SUCCESS,
    )
    .await;
    let neg_resp = NegotiateResponse::parse(&rb).expect("parse negotiate");

    assert_eq!(neg_resp.dialect_revision, 0x0311);
    assert_ne!(neg_resp.capabilities & SMB2_GLOBAL_CAP_ENCRYPTION, 0);
    assert_eq!(
        response_encryption_cipher(&rb),
        EncryptionCapabilities::CIPHER_AES_128_GCM
    );
}

#[tokio::test]
async fn encrypt_data_falls_back_without_smb311_cipher_context() {
    let contexts = vec![preauth_context(&[
        PreauthIntegrityCapabilities::HASH_SHA512,
    ])];
    let rb = assert_negotiate_status_encrypted(
        smb_negotiate_with_contexts(&[0x0311, 0x0302], &contexts).0,
        STATUS_SUCCESS,
    )
    .await;
    let neg_resp = NegotiateResponse::parse(&rb).expect("parse negotiate");

    assert_eq!(neg_resp.dialect_revision, 0x0302);
    assert_eq!(neg_resp.negotiate_context_count_or_reserved, 0);
    assert_ne!(neg_resp.capabilities & SMB2_GLOBAL_CAP_ENCRYPTION, 0);
}

#[tokio::test]
async fn authenticated_smb311_encrypted_tcp_write_read_round_trip() {
    let td = tempdir().expect("tempdir");
    let backend = LocalFsBackend::new(td.path()).expect("open root");
    let server = SmbServer::builder()
        .listen("127.0.0.1:0".parse().unwrap())
        .user("alice", "Password")
        .share(Share::new("secure", backend).user("alice", Access::ReadWrite))
        .netbios_name("TESTSERVER")
        .encrypt_data(true)
        .build()
        .expect("build");

    server.bind().await.expect("bind");
    let addr = server.local_addr().await.expect("addr");
    let handle = tokio::spawn(async move { server.serve().await });
    tokio::task::yield_now().await;

    let mut s = TcpStream::connect(addr).await.expect("connect");
    let mut preauth = [0u8; 64];

    let negotiate_contexts = vec![
        preauth_context(&[PreauthIntegrityCapabilities::HASH_SHA512]),
        encryption_context(&[EncryptionCapabilities::CIPHER_AES_128_GCM]),
    ];
    let negotiate_body = smb311_negotiate_with_contexts(&negotiate_contexts).0;
    let negotiate_header = build_header(Command::Negotiate, 0, 0, 0);
    let negotiate_payload = smb_payload(&negotiate_header, &negotiate_body);
    smb311_preauth_update(&mut preauth, &negotiate_payload);
    write_payload_frame(&mut s, &negotiate_payload).await;

    let negotiate_response = read_frame(&mut s).await;
    smb311_preauth_update(&mut preauth, &negotiate_response);
    let (rh, rb) = parse_response_header(&negotiate_response);
    assert_eq!(rh.command, Command::Negotiate);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let neg_resp = NegotiateResponse::parse(rb).expect("parse negotiate");
    assert_eq!(neg_resp.dialect_revision, 0x0311);
    assert_ne!(neg_resp.capabilities & SMB2_GLOBAL_CAP_ENCRYPTION, 0);
    assert_eq!(
        response_encryption_cipher(rb),
        EncryptionCapabilities::CIPHER_AES_128_GCM
    );

    let ntlm_negotiate = raw_ntlm_negotiate();
    let ss_req = SessionSetupRequest {
        structure_size: 25,
        flags: 0,
        security_mode: 0x01,
        capabilities: 0,
        channel: 0,
        security_buffer_offset: 88,
        security_buffer_length: ntlm_negotiate.len() as u16,
        previous_session_id: 0,
        security_buffer: ntlm_negotiate,
    };
    let mut body = Vec::new();
    ss_req.write_to(&mut body).expect("write session setup");
    let ss_header = build_header(Command::SessionSetup, 1, 0, 0);
    let ss_payload = smb_payload(&ss_header, &body);
    smb311_preauth_update(&mut preauth, &ss_payload);
    write_payload_frame(&mut s, &ss_payload).await;

    let challenge_response = read_frame(&mut s).await;
    smb311_preauth_update(&mut preauth, &challenge_response);
    let (rh, rb) = parse_response_header(&challenge_response);
    assert_eq!(rh.command, Command::SessionSetup);
    assert_eq!(rh.channel_sequence_status, STATUS_MORE_PROCESSING_REQUIRED);
    let session_id = rh.session_id;
    assert_ne!(session_id, 0);
    let challenge_resp = SessionSetupResponse::parse(rb).expect("parse challenge session setup");
    assert!(
        challenge_resp
            .security_buffer
            .starts_with(NTLMSSP_SIGNATURE)
    );
    assert_eq!(
        u32::from_le_bytes(challenge_resp.security_buffer[8..12].try_into().unwrap()),
        2
    );

    let authenticate = raw_ntlmv2_authenticate(
        &challenge_resp.security_buffer,
        "alice",
        "TESTSERVER",
        "Password",
    );
    let session_key = authenticate.session_key;
    let ss_req = SessionSetupRequest {
        structure_size: 25,
        flags: 0,
        security_mode: 0x01,
        capabilities: 0,
        channel: 0,
        security_buffer_offset: 88,
        security_buffer_length: authenticate.message.len() as u16,
        previous_session_id: 0,
        security_buffer: authenticate.message,
    };
    let mut body = Vec::new();
    ss_req
        .write_to(&mut body)
        .expect("write final session setup");
    let ss_header = build_header(Command::SessionSetup, 2, session_id, 0);
    let ss_payload = smb_payload(&ss_header, &body);
    smb311_preauth_update(&mut preauth, &ss_payload);
    write_payload_frame(&mut s, &ss_payload).await;

    let final_setup = read_frame(&mut s).await;
    let (rh, rb) = parse_response_header(&final_setup);
    assert_eq!(rh.command, Command::SessionSetup);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    assert_eq!(rh.session_id, session_id);
    let ss_resp = SessionSetupResponse::parse(rb).expect("parse session setup success");
    assert_eq!(
        ss_resp.session_flags & SessionSetupResponse::FLAG_IS_GUEST,
        0
    );
    assert_eq!(
        ss_resp.session_flags & SessionSetupResponse::FLAG_IS_NULL,
        0
    );
    assert_ne!(
        ss_resp.session_flags & SessionSetupResponse::FLAG_ENCRYPT_DATA,
        0
    );

    let c2s_key = smb311_encryption_key_c2s(&session_key, &preauth);
    let s2c_key = smb311_encryption_key_s2c(&session_key, &preauth);

    let tree_path = utf16le("\\\\TESTSERVER\\secure");
    let tree_req = TreeConnectRequest {
        structure_size: 9,
        flags: 0,
        path_offset: 64 + 8,
        path_length: tree_path.len() as u16,
        path: tree_path,
    };
    let mut body = Vec::new();
    tree_req.write_to(&mut body).expect("write tree connect");
    let (rh, rb) = encrypted_exchange(
        &mut s,
        Command::TreeConnect,
        3,
        session_id,
        0,
        &body,
        &c2s_key,
        &s2c_key,
    )
    .await;
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let tree_id = rh.tree_id().expect("tree id");
    let tree_resp = TreeConnectResponse::parse(&rb).expect("parse tree connect");
    assert_eq!(tree_resp.share_type, TreeConnectResponse::SHARE_TYPE_DISK);

    let name = utf16le("encrypted-auth.txt");
    let create_req = CreateRequest {
        structure_size: 57,
        security_flags: 0,
        requested_oplock_level: 0,
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
    let mut body = Vec::new();
    create_req.write_to(&mut body).expect("write create");
    let (rh, rb) = encrypted_exchange(
        &mut s,
        Command::Create,
        4,
        session_id,
        tree_id,
        &body,
        &c2s_key,
        &s2c_key,
    )
    .await;
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let file_id = CreateResponse::parse(&rb)
        .expect("parse create response")
        .file_id;

    let payload = b"authenticated tcp smb encryption";
    let write_req = WriteRequest {
        structure_size: 49,
        data_offset: WriteRequest::STANDARD_DATA_OFFSET,
        length: payload.len() as u32,
        offset: 0,
        file_id,
        channel: 0,
        remaining_bytes: 0,
        write_channel_info_offset: 0,
        write_channel_info_length: 0,
        flags: 0,
        data: payload.to_vec(),
    };
    let mut body = Vec::new();
    write_req.write_to(&mut body).expect("write write request");
    let (rh, rb) = encrypted_exchange(
        &mut s,
        Command::Write,
        5,
        session_id,
        tree_id,
        &body,
        &c2s_key,
        &s2c_key,
    )
    .await;
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let write_resp = WriteResponse::parse(&rb).expect("parse write response");
    assert_eq!(write_resp.count, payload.len() as u32);

    let read_req = ReadRequest {
        structure_size: 49,
        padding: ReadResponse::STANDARD_DATA_OFFSET,
        flags: 0,
        length: payload.len() as u32,
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
    read_req.write_to(&mut body).expect("write read request");
    let (rh, rb) = encrypted_exchange(
        &mut s,
        Command::Read,
        6,
        session_id,
        tree_id,
        &body,
        &c2s_key,
        &s2c_key,
    )
    .await;
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let read_resp = ReadResponse::parse(&rb).expect("parse read response");
    assert_eq!(read_resp.data, payload);

    let close_req = CloseRequest {
        structure_size: 24,
        flags: 0,
        reserved: 0,
        file_id,
    };
    let mut body = Vec::new();
    close_req.write_to(&mut body).expect("write close request");
    let (rh, rb) = encrypted_exchange(
        &mut s,
        Command::Close,
        7,
        session_id,
        tree_id,
        &body,
        &c2s_key,
        &s2c_key,
    )
    .await;
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let _ = CloseResponse::parse(&rb).expect("parse close response");
    assert_eq!(
        std::fs::read(td.path().join("encrypted-auth.txt")).expect("file on disk"),
        payload
    );

    drop(s);
    handle.abort();
}

#[tokio::test]
async fn authenticated_smb311_remaining_encryption_ciphers_accept_encrypted_echo() {
    for (cipher, transform) in [
        (
            EncryptionCapabilities::CIPHER_AES_256_GCM,
            TestEncryptionTransform::Gcm,
        ),
        (
            EncryptionCapabilities::CIPHER_AES_128_CCM,
            TestEncryptionTransform::Ccm,
        ),
        (
            EncryptionCapabilities::CIPHER_AES_256_CCM,
            TestEncryptionTransform::Ccm,
        ),
    ] {
        smb311_encrypted_echo_round_trip(cipher, transform).await;
    }
}

async fn smb311_encrypted_echo_round_trip(cipher: u16, transform: TestEncryptionTransform) {
    let td = tempdir().expect("tempdir");
    let backend = LocalFsBackend::new(td.path()).expect("open root");
    let server = SmbServer::builder()
        .listen("127.0.0.1:0".parse().unwrap())
        .user("alice", "Password")
        .share(Share::new("secure", backend).user("alice", Access::ReadWrite))
        .netbios_name("TESTSERVER")
        .encrypt_data(true)
        .build()
        .expect("build");

    server.bind().await.expect("bind");
    let addr = server.local_addr().await.expect("addr");
    let handle = tokio::spawn(async move { server.serve().await });
    tokio::task::yield_now().await;

    let mut s = TcpStream::connect(addr).await.expect("connect");
    let mut preauth = [0u8; 64];

    let negotiate_contexts = vec![
        preauth_context(&[PreauthIntegrityCapabilities::HASH_SHA512]),
        encryption_context(&[cipher]),
    ];
    let negotiate_body = smb311_negotiate_with_contexts(&negotiate_contexts).0;
    let negotiate_header = build_header(Command::Negotiate, 0, 0, 0);
    let negotiate_payload = smb_payload(&negotiate_header, &negotiate_body);
    smb311_preauth_update(&mut preauth, &negotiate_payload);
    write_payload_frame(&mut s, &negotiate_payload).await;

    let negotiate_response = read_frame(&mut s).await;
    smb311_preauth_update(&mut preauth, &negotiate_response);
    let (rh, rb) = parse_response_header(&negotiate_response);
    assert_eq!(rh.command, Command::Negotiate);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let neg_resp = NegotiateResponse::parse(rb).expect("parse negotiate");
    assert_eq!(neg_resp.dialect_revision, 0x0311);
    assert_eq!(response_encryption_cipher(rb), cipher);

    let (session_id, session_key) =
        authenticated_raw_ntlm_session_setup_with_preauth(&mut s, 1, &mut preauth).await;
    let (c2s_key, s2c_key) = if matches!(
        cipher,
        EncryptionCapabilities::CIPHER_AES_256_CCM | EncryptionCapabilities::CIPHER_AES_256_GCM
    ) {
        (
            smb311_encryption_key_c2s_256(&session_key, &preauth),
            smb311_encryption_key_s2c_256(&session_key, &preauth),
        )
    } else {
        (
            smb311_encryption_key_c2s(&session_key, &preauth),
            smb311_encryption_key_s2c(&session_key, &preauth),
        )
    };

    let mut body = Vec::new();
    EchoRequest::default()
        .write_to(&mut body)
        .expect("write echo");
    let (rh, rb) = encrypted_exchange_with_transform(
        &mut s,
        Command::Echo,
        3,
        session_id,
        0,
        &body,
        &c2s_key,
        &s2c_key,
        transform,
    )
    .await;
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let _ = EchoResponse::parse(&rb).expect("parse encrypted echo response");

    drop(s);
    handle.abort();
}

#[tokio::test]
async fn authenticated_smb302_encrypted_tcp_write_read_round_trip() {
    let td = tempdir().expect("tempdir");
    let backend = LocalFsBackend::new(td.path()).expect("open root");
    let server = SmbServer::builder()
        .listen("127.0.0.1:0".parse().unwrap())
        .user("alice", "Password")
        .share(Share::new("secure", backend).user("alice", Access::ReadWrite))
        .netbios_name("TESTSERVER")
        .encrypt_data(true)
        .build()
        .expect("build");

    server.bind().await.expect("bind");
    let addr = server.local_addr().await.expect("addr");
    let handle = tokio::spawn(async move { server.serve().await });
    tokio::task::yield_now().await;

    let mut s = TcpStream::connect(addr).await.expect("connect");
    let negotiate_body = smb_negotiate_with_contexts(&[0x0302], &[]).0;
    let negotiate_header = build_header(Command::Negotiate, 0, 0, 0);
    write_frame(&mut s, &negotiate_header, &negotiate_body).await;
    let negotiate_response = read_frame(&mut s).await;
    let (rh, rb) = parse_response_header(&negotiate_response);
    assert_eq!(rh.command, Command::Negotiate);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let neg_resp = NegotiateResponse::parse(rb).expect("parse negotiate");
    assert_eq!(neg_resp.dialect_revision, 0x0302);
    assert_eq!(neg_resp.negotiate_context_count_or_reserved, 0);
    assert_ne!(neg_resp.capabilities & SMB2_GLOBAL_CAP_ENCRYPTION, 0);

    let (session_id, session_key) = authenticated_raw_ntlm_session_setup(&mut s, 1).await;
    let c2s_key = smb300_encryption_key_c2s(&session_key);
    let s2c_key = smb300_encryption_key_s2c(&session_key);

    let tree_path = utf16le("\\\\TESTSERVER\\secure");
    let tree_req = TreeConnectRequest {
        structure_size: 9,
        flags: 0,
        path_offset: 64 + 8,
        path_length: tree_path.len() as u16,
        path: tree_path,
    };
    let mut body = Vec::new();
    tree_req.write_to(&mut body).expect("write tree connect");
    let (rh, rb) = encrypted_ccm_exchange(
        &mut s,
        Command::TreeConnect,
        3,
        session_id,
        0,
        &body,
        &c2s_key,
        &s2c_key,
    )
    .await;
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let tree_id = rh.tree_id().expect("tree id");
    let tree_resp = TreeConnectResponse::parse(&rb).expect("parse tree connect");
    assert_eq!(tree_resp.share_type, TreeConnectResponse::SHARE_TYPE_DISK);

    let name = utf16le("encrypted-smb302.txt");
    let create_req = CreateRequest {
        structure_size: 57,
        security_flags: 0,
        requested_oplock_level: 0,
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
    let mut body = Vec::new();
    create_req.write_to(&mut body).expect("write create");
    let (rh, rb) = encrypted_ccm_exchange(
        &mut s,
        Command::Create,
        4,
        session_id,
        tree_id,
        &body,
        &c2s_key,
        &s2c_key,
    )
    .await;
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let file_id = CreateResponse::parse(&rb)
        .expect("parse create response")
        .file_id;

    let payload = b"authenticated smb302 tcp encryption";
    let write_req = WriteRequest {
        structure_size: 49,
        data_offset: WriteRequest::STANDARD_DATA_OFFSET,
        length: payload.len() as u32,
        offset: 0,
        file_id,
        channel: 0,
        remaining_bytes: 0,
        write_channel_info_offset: 0,
        write_channel_info_length: 0,
        flags: 0,
        data: payload.to_vec(),
    };
    let mut body = Vec::new();
    write_req.write_to(&mut body).expect("write write request");
    let (rh, rb) = encrypted_ccm_exchange(
        &mut s,
        Command::Write,
        5,
        session_id,
        tree_id,
        &body,
        &c2s_key,
        &s2c_key,
    )
    .await;
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let write_resp = WriteResponse::parse(&rb).expect("parse write response");
    assert_eq!(write_resp.count, payload.len() as u32);

    let read_req = ReadRequest {
        structure_size: 49,
        padding: ReadResponse::STANDARD_DATA_OFFSET,
        flags: 0,
        length: payload.len() as u32,
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
    read_req.write_to(&mut body).expect("write read request");
    let (rh, rb) = encrypted_ccm_exchange(
        &mut s,
        Command::Read,
        6,
        session_id,
        tree_id,
        &body,
        &c2s_key,
        &s2c_key,
    )
    .await;
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let read_resp = ReadResponse::parse(&rb).expect("parse read response");
    assert_eq!(read_resp.data, payload);

    let close_req = CloseRequest {
        structure_size: 24,
        flags: 0,
        reserved: 0,
        file_id,
    };
    let mut body = Vec::new();
    close_req.write_to(&mut body).expect("write close request");
    let (rh, rb) = encrypted_ccm_exchange(
        &mut s,
        Command::Close,
        7,
        session_id,
        tree_id,
        &body,
        &c2s_key,
        &s2c_key,
    )
    .await;
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let _ = CloseResponse::parse(&rb).expect("parse close response");
    assert_eq!(
        std::fs::read(td.path().join("encrypted-smb302.txt")).expect("file on disk"),
        payload
    );

    drop(s);
    handle.abort();
}

#[tokio::test]
async fn transport_security_context_is_not_accepted_on_tcp() {
    let contexts = vec![
        preauth_context(&[PreauthIntegrityCapabilities::HASH_SHA512]),
        transport_context(),
    ];
    let rb = assert_negotiate_status_encrypted(
        smb_negotiate_with_contexts(&[0x0311, 0x0302], &contexts).0,
        STATUS_SUCCESS,
    )
    .await;
    let neg_resp = NegotiateResponse::parse(&rb).expect("parse negotiate");

    assert_eq!(neg_resp.dialect_revision, 0x0302);
    assert_ne!(neg_resp.capabilities & SMB2_GLOBAL_CAP_ENCRYPTION, 0);
    assert!(!response_transport_security_accepted(&rb));
}

#[tokio::test]
async fn end_to_end_anon_read() {
    // 1. Build a server with one public share and one in-memory file.
    let td = tempdir().expect("tempdir");
    std::fs::write(td.path().join("hello.txt"), b"hello world\n").expect("write hello.txt");
    let backend = LocalFsBackend::new(td.path()).expect("open root");
    let server = SmbServer::builder()
        .listen("127.0.0.1:0".parse().unwrap())
        .share(Share::new("downloads", backend).public())
        .netbios_name("TESTSERVER")
        .build()
        .expect("build");

    server.bind().await.expect("bind");
    let addr = server.local_addr().await.expect("addr");

    // Spawn the server.
    let handle = tokio::spawn(async move { server.serve().await });

    // Tiny grace period.
    tokio::task::yield_now().await;

    let mut s = TcpStream::connect(addr).await.expect("connect");

    let neg_resp = negotiate(&mut s).await;
    let session_id = anonymous_session_setup(&mut s).await;
    let tree_id = tree_connect(&mut s, "\\\\TESTSERVER\\downloads", session_id, 3).await;

    // ---- FSCTL_VALIDATE_NEGOTIATE_INFO mirrors NEGOTIATE ----------------
    let ioctl_req = IoctlRequest {
        structure_size: 57,
        reserved: 0,
        ctl_code: Fsctl::VALIDATE_NEGOTIATE_INFO,
        file_id: FileId::any(),
        input_offset: 0,
        input_count: 0,
        max_input_response: 0,
        output_offset: 0,
        output_count: 0,
        max_output_response: 24,
        flags: IoctlRequest::FLAG_IS_FSCTL,
        reserved2: 0,
        input: vec![],
    };
    let mut body = Vec::new();
    ioctl_req.write_to(&mut body).expect("write");
    let hdr = build_header(Command::Ioctl, 4, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;

    let resp = read_frame(&mut s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Ioctl);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let ioctl_resp = IoctlResponse::parse(rb).expect("parse ioctl resp");
    assert_eq!(ioctl_resp.output.len(), 24);
    let validate_security_mode = u16::from_le_bytes([ioctl_resp.output[20], ioctl_resp.output[21]]);
    assert_eq!(validate_security_mode, neg_resp.security_mode);

    // ---- CREATE hello.txt ------------------------------------------------
    let name_u16 = utf16le("hello.txt");
    let cr_req = CreateRequest {
        structure_size: 57,
        security_flags: 0,
        requested_oplock_level: 0,
        impersonation_level: 2,
        smb_create_flags: 0,
        reserved: 0,
        desired_access: 0x0012_0089, // FILE_GENERIC_READ
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
    let hdr = build_header(Command::Create, 5, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;

    let resp = read_frame(&mut s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Create);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let cr_resp = CreateResponse::parse(rb).expect("parse create resp");
    let file_id = cr_resp.file_id;
    assert_eq!(cr_resp.end_of_file, 12); // "hello world\n"

    // ---- READ ------------------------------------------------------------
    let rd_req = ReadRequest {
        structure_size: 49,
        padding: ReadResponse::STANDARD_DATA_OFFSET,
        flags: 0,
        length: 32,
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
    let hdr = build_header(Command::Read, 6, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;

    let resp = read_frame(&mut s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Read);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let rd_resp = ReadResponse::parse(rb).expect("parse read resp");
    assert_eq!(rd_resp.data, b"hello world\n");

    drop(s);
    // The server keeps accepting; abort the spawned task so the test
    // process exits cleanly.
    handle.abort();
}

#[tokio::test]
async fn negotiate_prefers_aes_gmac_signing_capability() {
    assert_negotiate_selected_signing_algorithm(
        &[
            SigningCapabilities::ALGORITHM_AES_GMAC,
            SigningCapabilities::ALGORITHM_AES_CMAC,
        ],
        SigningCapabilities::ALGORITHM_AES_GMAC,
    )
    .await;
}

#[tokio::test]
async fn negotiate_falls_back_to_aes_cmac_signing_capability() {
    assert_negotiate_selected_signing_algorithm(
        &[SigningCapabilities::ALGORITHM_AES_CMAC],
        SigningCapabilities::ALGORITHM_AES_CMAC,
    )
    .await;
}

#[tokio::test]
async fn negotiate_accepts_hmac_sha256_signing_capability() {
    assert_negotiate_selected_signing_algorithm(
        &[SigningCapabilities::ALGORITHM_HMAC_SHA256],
        SigningCapabilities::ALGORITHM_HMAC_SHA256,
    )
    .await;
}

async fn assert_negotiate_selected_signing_algorithm(offered: &[u16], expected_selected: u16) {
    let td = tempdir().expect("tempdir");
    let backend = LocalFsBackend::new(td.path()).expect("open root");
    let server = SmbServer::builder()
        .listen("127.0.0.1:0".parse().unwrap())
        .share(Share::new("downloads", backend).public())
        .netbios_name("TESTSERVER")
        .build()
        .expect("build");

    server.bind().await.expect("bind");
    let addr = server.local_addr().await.expect("addr");
    let handle = tokio::spawn(async move { server.serve().await });
    tokio::task::yield_now().await;

    let mut s = TcpStream::connect(addr).await.expect("connect");
    let (body, contexts_offset) = smb311_negotiate_with_signing_context(offered);
    let hdr = build_header(Command::Negotiate, 0, 0, 0);
    write_frame(&mut s, &hdr, &body).await;

    let resp = read_frame(&mut s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Negotiate);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let neg_resp = NegotiateResponse::parse(rb).expect("parse negotiate");
    assert_eq!(neg_resp.dialect_revision, 0x0311);
    assert_ne!(
        neg_resp.negotiate_context_offset_or_reserved2, contexts_offset,
        "response chooses its own context offset after security blob"
    );

    let response_context_body_offset = neg_resp.negotiate_context_offset_or_reserved2 as usize - 64;
    let contexts = NegotiateContext::parse_list(
        &rb[response_context_body_offset..],
        neg_resp.negotiate_context_count_or_reserved,
    )
    .expect("parse response contexts");
    let signing = contexts
        .iter()
        .find(|ctx| ctx.context_type == NegotiateContext::TYPE_SIGNING)
        .expect("response signing context");
    assert_eq!(signing.data[0..2], 1u16.to_le_bytes());
    assert_eq!(
        u16::from_le_bytes(signing.data[2..4].try_into().unwrap()),
        expected_selected
    );

    drop(s);
    handle.abort();
}

#[tokio::test]
async fn negotiate_rejects_smb311_without_preauth() {
    let signing = signing_context(&[SigningCapabilities::ALGORITHM_AES_CMAC]);
    assert_negotiate_status(
        smb311_negotiate_with_contexts(&[signing]).0,
        STATUS_INVALID_PARAMETER,
    )
    .await;
}

#[tokio::test]
async fn negotiate_allows_smb311_with_preauth_only_when_encryption_is_optional() {
    let preauth = preauth_context(&[PreauthIntegrityCapabilities::HASH_SHA512]);
    let rb =
        assert_negotiate_status(smb311_negotiate_with_contexts(&[preauth]).0, STATUS_SUCCESS).await;
    let neg_resp = NegotiateResponse::parse(&rb).expect("parse negotiate");

    assert_eq!(neg_resp.dialect_revision, 0x0311);
    assert_eq!(neg_resp.negotiate_context_count_or_reserved, 1);

    let response_context_body_offset = neg_resp.negotiate_context_offset_or_reserved2 as usize - 64;
    let contexts = NegotiateContext::parse_list(
        &rb[response_context_body_offset..],
        neg_resp.negotiate_context_count_or_reserved,
    )
    .expect("parse response contexts");
    let preauth_resp = contexts.first().expect("preauth response context");

    assert_eq!(
        preauth_resp.context_type,
        NegotiateContext::TYPE_PREAUTH_INTEGRITY
    );
    assert_eq!(preauth_resp.data[0..2], 1u16.to_le_bytes());
    let salt_len = u16::from_le_bytes(preauth_resp.data[2..4].try_into().unwrap()) as usize;
    assert_eq!(
        u16::from_le_bytes(preauth_resp.data[4..6].try_into().unwrap()),
        PreauthIntegrityCapabilities::HASH_SHA512
    );
    assert_eq!(preauth_resp.data.len(), 6 + salt_len);
    assert_ne!(salt_len, 0);
}

#[tokio::test]
async fn negotiate_rejects_smb311_preauth_hash_no_overlap() {
    let preauth = preauth_context(&[0x9999]);
    assert_negotiate_status(
        smb311_negotiate_with_contexts(&[preauth]).0,
        STATUS_SMB_NO_PREAUTH_INTEGRITY_HASH_OVERLAP,
    )
    .await;
}

#[tokio::test]
async fn negotiate_rejects_duplicate_smb311_singleton_contexts() {
    for duplicate in [
        NegotiateContext::TYPE_PREAUTH_INTEGRITY,
        NegotiateContext::TYPE_ENCRYPTION,
        NegotiateContext::TYPE_COMPRESSION,
        NegotiateContext::TYPE_RDMA_TRANSFORM,
        NegotiateContext::TYPE_SIGNING,
        NegotiateContext::TYPE_TRANSPORT_CAPS,
        NegotiateContext::TYPE_POSIX,
    ] {
        let mut contexts = vec![preauth_context(&[
            PreauthIntegrityCapabilities::HASH_SHA512,
        ])];
        let dup = match duplicate {
            NegotiateContext::TYPE_PREAUTH_INTEGRITY => {
                preauth_context(&[PreauthIntegrityCapabilities::HASH_SHA512])
            }
            NegotiateContext::TYPE_SIGNING => {
                signing_context(&[SigningCapabilities::ALGORITHM_AES_CMAC])
            }
            NegotiateContext::TYPE_POSIX => posix_context(),
            context_type => simple_context(context_type),
        };
        contexts.push(dup.clone());
        contexts.push(dup);

        assert_negotiate_status(
            smb311_negotiate_with_contexts(&contexts).0,
            STATUS_INVALID_PARAMETER,
        )
        .await;
    }
}

#[tokio::test]
async fn negotiate_rejects_malformed_supported_smb311_contexts() {
    for malformed in [
        NegotiateContext {
            context_type: NegotiateContext::TYPE_SIGNING,
            data_length: 2,
            reserved: 0,
            data: 0u16.to_le_bytes().to_vec(),
        },
        NegotiateContext {
            context_type: NegotiateContext::TYPE_POSIX,
            data_length: 3,
            reserved: 0,
            data: vec![1, 2, 3],
        },
        NegotiateContext {
            context_type: NegotiateContext::TYPE_COMPRESSION,
            data_length: 8,
            reserved: 0,
            data: vec![0; 8],
        },
    ] {
        let contexts = vec![
            preauth_context(&[PreauthIntegrityCapabilities::HASH_SHA512]),
            malformed,
        ];
        assert_negotiate_status(
            smb311_negotiate_with_contexts(&contexts).0,
            STATUS_INVALID_PARAMETER,
        )
        .await;
    }
}

#[tokio::test]
async fn negotiate_ignores_malformed_unsupported_contexts() {
    for malformed in [
        NegotiateContext {
            context_type: NegotiateContext::TYPE_ENCRYPTION,
            data_length: 2,
            reserved: 0,
            data: 0u16.to_le_bytes().to_vec(),
        },
        NegotiateContext {
            context_type: NegotiateContext::TYPE_RDMA_TRANSFORM,
            data_length: 8,
            reserved: 0,
            data: vec![0; 8],
        },
    ] {
        let contexts = vec![
            preauth_context(&[PreauthIntegrityCapabilities::HASH_SHA512]),
            malformed,
        ];
        assert_negotiate_status(smb311_negotiate_with_contexts(&contexts).0, STATUS_SUCCESS).await;
    }
}

#[tokio::test]
async fn negotiate_accepts_request_only_netname_context() {
    let contexts = vec![
        preauth_context(&[PreauthIntegrityCapabilities::HASH_SHA512]),
        netname_context("quic.test"),
    ];
    let body = smb311_negotiate_with_contexts(&contexts).0;
    let rb = assert_negotiate_status(body, STATUS_SUCCESS).await;
    let neg_resp = NegotiateResponse::parse(&rb).expect("parse negotiate");
    let response_context_body_offset = neg_resp.negotiate_context_offset_or_reserved2 as usize - 64;
    let contexts = NegotiateContext::parse_list(
        &rb[response_context_body_offset..],
        neg_resp.negotiate_context_count_or_reserved,
    )
    .expect("parse response contexts");
    assert!(
        !contexts
            .iter()
            .any(|ctx| ctx.context_type == NegotiateContext::TYPE_NETNAME_NEGOTIATE),
        "NETNAME is request-only and must not be included in the response"
    );
}

#[tokio::test]
async fn negotiate_advertises_optional_encryption_support() {
    let contexts = vec![
        preauth_context(&[PreauthIntegrityCapabilities::HASH_SHA512]),
        encryption_context(&[
            EncryptionCapabilities::CIPHER_AES_128_CCM,
            EncryptionCapabilities::CIPHER_AES_128_GCM,
            EncryptionCapabilities::CIPHER_AES_256_CCM,
            EncryptionCapabilities::CIPHER_AES_256_GCM,
        ]),
    ];
    let rb =
        assert_negotiate_status(smb311_negotiate_with_contexts(&contexts).0, STATUS_SUCCESS).await;
    let neg_resp = NegotiateResponse::parse(&rb).expect("parse negotiate");
    let response_context_body_offset = neg_resp.negotiate_context_offset_or_reserved2 as usize - 64;
    let contexts = NegotiateContext::parse_list(
        &rb[response_context_body_offset..],
        neg_resp.negotiate_context_count_or_reserved,
    )
    .expect("parse response contexts");
    assert_ne!(neg_resp.capabilities & SMB2_GLOBAL_CAP_ENCRYPTION, 0);
    assert_eq!(
        response_encryption_cipher(&rb),
        EncryptionCapabilities::CIPHER_AES_256_GCM
    );
    assert!(
        contexts
            .iter()
            .any(|ctx| ctx.context_type == NegotiateContext::TYPE_ENCRYPTION),
        "SMB3 encryption support should be advertised when the client offers ciphers"
    );
}

#[tokio::test]
async fn negotiate_records_rdma_but_does_not_advertise() {
    let contexts = vec![
        preauth_context(&[PreauthIntegrityCapabilities::HASH_SHA512]),
        rdma_transform_context(&[
            RdmaTransformCapabilities::TRANSFORM_ENCRYPTION,
            RdmaTransformCapabilities::TRANSFORM_SIGNING,
        ]),
    ];
    let rb =
        assert_negotiate_status(smb311_negotiate_with_contexts(&contexts).0, STATUS_SUCCESS).await;
    let neg_resp = NegotiateResponse::parse(&rb).expect("parse negotiate");
    let response_context_body_offset = neg_resp.negotiate_context_offset_or_reserved2 as usize - 64;
    let contexts = NegotiateContext::parse_list(
        &rb[response_context_body_offset..],
        neg_resp.negotiate_context_count_or_reserved,
    )
    .expect("parse response contexts");
    assert!(
        !contexts
            .iter()
            .any(|ctx| ctx.context_type == NegotiateContext::TYPE_RDMA_TRANSFORM),
        "RDMA transform capabilities are request-only for this TCP/QUIC server"
    );
}

#[tokio::test]
async fn negotiate_advertises_selected_compression_algorithm() {
    let contexts = vec![
        preauth_context(&[PreauthIntegrityCapabilities::HASH_SHA512]),
        compression_context(
            true,
            &[
                CompressionCapabilities::ALGORITHM_PATTERN_V1,
                CompressionCapabilities::ALGORITHM_LZ77,
            ],
        ),
    ];
    let rb =
        assert_negotiate_status(smb311_negotiate_with_contexts(&contexts).0, STATUS_SUCCESS).await;
    assert_eq!(
        response_compression_algorithms(&rb),
        vec![CompressionCapabilities::ALGORITHM_LZ77]
    );

    let contexts = vec![
        preauth_context(&[PreauthIntegrityCapabilities::HASH_SHA512]),
        compression_context(true, &[CompressionCapabilities::ALGORITHM_PATTERN_V1]),
    ];
    let rb =
        assert_negotiate_status(smb311_negotiate_with_contexts(&contexts).0, STATUS_SUCCESS).await;
    assert_eq!(
        response_compression_algorithms(&rb),
        vec![CompressionCapabilities::ALGORITHM_PATTERN_V1]
    );
}

#[tokio::test]
async fn negotiate_does_not_advertise_unsupported_compression_algorithm() {
    let contexts = vec![
        preauth_context(&[PreauthIntegrityCapabilities::HASH_SHA512]),
        compression_context(true, &[CompressionCapabilities::ALGORITHM_LZ77_HUFFMAN]),
    ];
    let rb =
        assert_negotiate_status(smb311_negotiate_with_contexts(&contexts).0, STATUS_SUCCESS).await;
    assert!(response_compression_algorithms(&rb).is_empty());
}

#[tokio::test]
async fn negotiate_can_disable_compression() {
    let contexts = vec![
        preauth_context(&[PreauthIntegrityCapabilities::HASH_SHA512]),
        compression_context(
            true,
            &[
                CompressionCapabilities::ALGORITHM_PATTERN_V1,
                CompressionCapabilities::ALGORITHM_LZ77,
            ],
        ),
    ];
    let rb = assert_negotiate_status_with_builder(
        smb311_negotiate_with_contexts(&contexts).0,
        STATUS_SUCCESS,
        |builder| builder.disable_compression(true),
    )
    .await;
    assert!(response_compression_algorithms(&rb).is_empty());
}

async fn assert_negotiate_status(body: Vec<u8>, expected_status: u32) -> Vec<u8> {
    assert_negotiate_status_with_encrypt_data(body, expected_status, false).await
}

async fn assert_negotiate_status_encrypted(body: Vec<u8>, expected_status: u32) -> Vec<u8> {
    assert_negotiate_status_with_encrypt_data(body, expected_status, true).await
}

async fn assert_negotiate_status_with_encrypt_data(
    body: Vec<u8>,
    expected_status: u32,
    encrypt_data: bool,
) -> Vec<u8> {
    assert_negotiate_status_with_builder(body, expected_status, |builder| {
        builder.encrypt_data(encrypt_data)
    })
    .await
}

async fn assert_negotiate_status_with_builder(
    body: Vec<u8>,
    expected_status: u32,
    configure: impl FnOnce(smb_server::SmbServerBuilder) -> smb_server::SmbServerBuilder,
) -> Vec<u8> {
    let td = tempdir().expect("tempdir");
    let backend = LocalFsBackend::new(td.path()).expect("open root");
    let builder = SmbServer::builder()
        .listen("127.0.0.1:0".parse().unwrap())
        .share(Share::new("downloads", backend).public())
        .netbios_name("TESTSERVER");
    let server = configure(builder).build().expect("build");

    server.bind().await.expect("bind");
    let addr = server.local_addr().await.expect("addr");
    let handle = tokio::spawn(async move { server.serve().await });
    tokio::task::yield_now().await;

    let mut s = TcpStream::connect(addr).await.expect("connect");
    let hdr = build_header(Command::Negotiate, 0, 0, 0);
    write_frame(&mut s, &hdr, &body).await;

    let resp = read_frame(&mut s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Negotiate);
    assert_eq!(rh.channel_sequence_status, expected_status);

    drop(s);
    handle.abort();
    rb.to_vec()
}

fn smb311_negotiate_with_signing_context(signing_algorithms: &[u16]) -> (Vec<u8>, u32) {
    let contexts = vec![
        preauth_context(&[PreauthIntegrityCapabilities::HASH_SHA512]),
        signing_context(signing_algorithms),
    ];
    smb311_negotiate_with_contexts(&contexts)
}

fn preauth_context(hash_algorithms: &[u16]) -> NegotiateContext {
    use binrw::BinWrite;
    let preauth = PreauthIntegrityCapabilities {
        hash_algorithm_count: hash_algorithms.len() as u16,
        salt_length: 0,
        hash_algorithms: hash_algorithms.to_vec(),
        salt: vec![],
    };
    let mut cursor = std::io::Cursor::new(Vec::new());
    BinWrite::write(&preauth, &mut cursor).expect("write preauth");
    let data = cursor.into_inner();
    NegotiateContext {
        context_type: NegotiateContext::TYPE_PREAUTH_INTEGRITY,
        data_length: data.len() as u16,
        reserved: 0,
        data,
    }
}

fn signing_context(signing_algorithms: &[u16]) -> NegotiateContext {
    use binrw::BinWrite;
    let signing = SigningCapabilities {
        signing_algorithm_count: signing_algorithms.len() as u16,
        signing_algorithms: signing_algorithms.to_vec(),
    };
    let mut cursor = std::io::Cursor::new(Vec::new());
    BinWrite::write(&signing, &mut cursor).expect("write signing");
    let signing_data = cursor.into_inner();
    NegotiateContext {
        context_type: NegotiateContext::TYPE_SIGNING,
        data_length: signing_data.len() as u16,
        reserved: 0,
        data: signing_data,
    }
}

fn posix_context() -> NegotiateContext {
    NegotiateContext {
        context_type: NegotiateContext::TYPE_POSIX,
        data_length: NegotiateContext::POSIX_EXTENSIONS_GUID.len() as u16,
        reserved: 0,
        data: NegotiateContext::POSIX_EXTENSIONS_GUID.to_vec(),
    }
}

fn simple_context(context_type: u16) -> NegotiateContext {
    let data = 1u16.to_le_bytes().to_vec();
    NegotiateContext {
        context_type,
        data_length: data.len() as u16,
        reserved: 0,
        data,
    }
}

fn netname_context(name: &str) -> NegotiateContext {
    let data = utf16le(name);
    NegotiateContext {
        context_type: NegotiateContext::TYPE_NETNAME_NEGOTIATE,
        data_length: data.len() as u16,
        reserved: 0,
        data,
    }
}

fn compression_context(chained: bool, algorithms: &[u16]) -> NegotiateContext {
    use binrw::BinWrite;
    let caps = CompressionCapabilities {
        compression_algorithm_count: algorithms.len() as u16,
        padding: 0,
        flags: if chained {
            CompressionCapabilities::FLAG_CHAINED
        } else {
            0
        },
        compression_algorithms: algorithms.to_vec(),
    };
    let mut cursor = std::io::Cursor::new(Vec::new());
    BinWrite::write(&caps, &mut cursor).expect("write compression");
    let data = cursor.into_inner();
    NegotiateContext {
        context_type: NegotiateContext::TYPE_COMPRESSION,
        data_length: data.len() as u16,
        reserved: 0,
        data,
    }
}

fn encryption_context(ciphers: &[u16]) -> NegotiateContext {
    use binrw::BinWrite;
    let caps = EncryptionCapabilities {
        cipher_count: ciphers.len() as u16,
        ciphers: ciphers.to_vec(),
    };
    let mut cursor = std::io::Cursor::new(Vec::new());
    BinWrite::write(&caps, &mut cursor).expect("write encryption");
    let data = cursor.into_inner();
    NegotiateContext {
        context_type: NegotiateContext::TYPE_ENCRYPTION,
        data_length: data.len() as u16,
        reserved: 0,
        data,
    }
}

fn rdma_transform_context(transform_ids: &[u16]) -> NegotiateContext {
    use binrw::BinWrite;
    let caps = RdmaTransformCapabilities {
        transform_count: transform_ids.len() as u16,
        reserved1: 0,
        reserved2: 0,
        rdma_transform_ids: transform_ids.to_vec(),
    };
    let mut cursor = std::io::Cursor::new(Vec::new());
    BinWrite::write(&caps, &mut cursor).expect("write rdma transform");
    let data = cursor.into_inner();
    NegotiateContext {
        context_type: NegotiateContext::TYPE_RDMA_TRANSFORM,
        data_length: data.len() as u16,
        reserved: 0,
        data,
    }
}

fn transport_context() -> NegotiateContext {
    NegotiateContext {
        context_type: NegotiateContext::TYPE_TRANSPORT_CAPS,
        data_length: 4,
        reserved: 0,
        data: NegotiateContext::TRANSPORT_CAP_ACCEPT_TRANSPORT_SECURITY
            .to_le_bytes()
            .to_vec(),
    }
}

fn response_compression_algorithms(rb: &[u8]) -> Vec<u16> {
    let neg_resp = NegotiateResponse::parse(rb).expect("parse negotiate");
    let response_context_body_offset = neg_resp.negotiate_context_offset_or_reserved2 as usize - 64;
    let contexts = NegotiateContext::parse_list(
        &rb[response_context_body_offset..],
        neg_resp.negotiate_context_count_or_reserved,
    )
    .expect("parse response contexts");
    contexts
        .iter()
        .find(|ctx| ctx.context_type == NegotiateContext::TYPE_COMPRESSION)
        .and_then(|ctx| {
            use binrw::BinRead;
            CompressionCapabilities::read(&mut std::io::Cursor::new(&ctx.data)).ok()
        })
        .map(|caps| caps.compression_algorithms)
        .unwrap_or_default()
}

fn response_encryption_cipher(rb: &[u8]) -> u16 {
    let neg_resp = NegotiateResponse::parse(rb).expect("parse negotiate");
    let response_context_body_offset = neg_resp.negotiate_context_offset_or_reserved2 as usize - 64;
    let contexts = NegotiateContext::parse_list(
        &rb[response_context_body_offset..],
        neg_resp.negotiate_context_count_or_reserved,
    )
    .expect("parse response contexts");
    contexts
        .iter()
        .find(|ctx| ctx.context_type == NegotiateContext::TYPE_ENCRYPTION)
        .and_then(|ctx| {
            use binrw::BinRead;
            EncryptionCapabilities::read(&mut std::io::Cursor::new(&ctx.data)).ok()
        })
        .and_then(|caps| caps.ciphers.first().copied())
        .unwrap_or_default()
}

fn response_signing_algorithm(rb: &[u8]) -> u16 {
    let neg_resp = NegotiateResponse::parse(rb).expect("parse negotiate");
    let response_context_body_offset = neg_resp.negotiate_context_offset_or_reserved2 as usize - 64;
    let contexts = NegotiateContext::parse_list(
        &rb[response_context_body_offset..],
        neg_resp.negotiate_context_count_or_reserved,
    )
    .expect("parse response contexts");
    let signing = contexts
        .iter()
        .find(|ctx| ctx.context_type == NegotiateContext::TYPE_SIGNING)
        .expect("response signing context");
    assert_eq!(signing.data[0..2], 1u16.to_le_bytes());
    u16::from_le_bytes(signing.data[2..4].try_into().unwrap())
}

fn response_transport_security_accepted(rb: &[u8]) -> bool {
    let neg_resp = NegotiateResponse::parse(rb).expect("parse negotiate");
    if neg_resp.negotiate_context_count_or_reserved == 0
        || neg_resp.negotiate_context_offset_or_reserved2 < 64
    {
        return false;
    }
    let response_context_body_offset = neg_resp.negotiate_context_offset_or_reserved2 as usize - 64;
    let contexts = NegotiateContext::parse_list(
        &rb[response_context_body_offset..],
        neg_resp.negotiate_context_count_or_reserved,
    )
    .expect("parse response contexts");
    contexts
        .iter()
        .find(|ctx| ctx.context_type == NegotiateContext::TYPE_TRANSPORT_CAPS)
        .is_some_and(|ctx| {
            ctx.data.len() >= 4
                && u32::from_le_bytes(ctx.data[0..4].try_into().unwrap())
                    & NegotiateContext::TRANSPORT_CAP_ACCEPT_TRANSPORT_SECURITY
                    != 0
        })
}

fn smb311_negotiate_with_contexts(contexts: &[NegotiateContext]) -> (Vec<u8>, u32) {
    smb_negotiate_with_contexts(&[0x0311], contexts)
}

fn smb_negotiate_with_contexts(dialects: &[u16], contexts: &[NegotiateContext]) -> (Vec<u8>, u32) {
    let mut contexts_bytes = Vec::new();
    NegotiateContext::encode_list(contexts, &mut contexts_bytes).expect("encode contexts");
    let fixed_and_dialects = 36 + dialects.len() * 2;
    let contexts_offset = if contexts.is_empty() {
        0
    } else {
        align_8(64 + fixed_and_dialects) as u32
    };

    let req = NegotiateRequest {
        structure_size: 36,
        dialect_count: dialects.len() as u16,
        security_mode: 0x0001,
        reserved: 0,
        capabilities: 0,
        client_guid: [0xAB; 16],
        negotiate_context_offset_or_client_start_time: (contexts_offset as u64)
            | ((contexts.len() as u64) << 32),
        dialects: dialects.to_vec(),
    };

    let mut body = Vec::new();
    req.write_to(&mut body).expect("write negotiate");
    if !contexts.is_empty() {
        body.resize(contexts_offset as usize - 64, 0);
        body.extend_from_slice(&contexts_bytes);
    }
    (body, contexts_offset)
}

fn smb_payload(header: &Smb2Header, body: &[u8]) -> Vec<u8> {
    let mut payload = Vec::new();
    header.write(&mut payload).expect("write SMB2 header");
    payload.extend_from_slice(body);
    payload
}

async fn write_payload_frame(s: &mut TcpStream, payload: &[u8]) {
    let mut framed = Vec::new();
    encode_frame(payload, &mut framed);
    s.write_all(&framed).await.expect("write frame");
}

async fn authenticated_raw_ntlm_session_setup(
    s: &mut TcpStream,
    first_message_id: u64,
) -> (u64, [u8; 16]) {
    authenticated_raw_ntlm_session_setup_with_encryption_expectation(s, first_message_id, true)
        .await
}

async fn authenticated_raw_ntlm_session_setup_without_encryption(
    s: &mut TcpStream,
    first_message_id: u64,
) -> (u64, [u8; 16]) {
    authenticated_raw_ntlm_session_setup_with_encryption_expectation(s, first_message_id, false)
        .await
}

async fn authenticated_raw_ntlm_session_setup_with_encryption_expectation(
    s: &mut TcpStream,
    first_message_id: u64,
    expect_encryption: bool,
) -> (u64, [u8; 16]) {
    let ntlm_negotiate = raw_ntlm_negotiate();
    let ss_req = SessionSetupRequest {
        structure_size: 25,
        flags: 0,
        security_mode: 0x01,
        capabilities: 0,
        channel: 0,
        security_buffer_offset: 88,
        security_buffer_length: ntlm_negotiate.len() as u16,
        previous_session_id: 0,
        security_buffer: ntlm_negotiate,
    };
    let mut body = Vec::new();
    ss_req.write_to(&mut body).expect("write session setup");
    let ss_header = build_header(Command::SessionSetup, first_message_id, 0, 0);
    write_frame(s, &ss_header, &body).await;

    let challenge_response = read_frame(s).await;
    let (rh, rb) = parse_response_header(&challenge_response);
    assert_eq!(rh.command, Command::SessionSetup);
    assert_eq!(rh.channel_sequence_status, STATUS_MORE_PROCESSING_REQUIRED);
    let session_id = rh.session_id;
    assert_ne!(session_id, 0);
    let challenge_resp = SessionSetupResponse::parse(rb).expect("parse challenge session setup");
    assert!(
        challenge_resp
            .security_buffer
            .starts_with(NTLMSSP_SIGNATURE)
    );
    assert_eq!(
        u32::from_le_bytes(challenge_resp.security_buffer[8..12].try_into().unwrap()),
        2
    );

    let authenticate = raw_ntlmv2_authenticate(
        &challenge_resp.security_buffer,
        "alice",
        "TESTSERVER",
        "Password",
    );
    let session_key = authenticate.session_key;
    let ss_req = SessionSetupRequest {
        structure_size: 25,
        flags: 0,
        security_mode: 0x01,
        capabilities: 0,
        channel: 0,
        security_buffer_offset: 88,
        security_buffer_length: authenticate.message.len() as u16,
        previous_session_id: 0,
        security_buffer: authenticate.message,
    };
    let mut body = Vec::new();
    ss_req
        .write_to(&mut body)
        .expect("write final session setup");
    let ss_header = build_header(Command::SessionSetup, first_message_id + 1, session_id, 0);
    write_frame(s, &ss_header, &body).await;

    let final_setup = read_frame(s).await;
    let (rh, rb) = parse_response_header(&final_setup);
    assert_eq!(rh.command, Command::SessionSetup);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    assert_eq!(rh.session_id, session_id);
    let ss_resp = SessionSetupResponse::parse(rb).expect("parse session setup success");
    assert_eq!(
        ss_resp.session_flags & SessionSetupResponse::FLAG_IS_GUEST,
        0
    );
    assert_eq!(
        ss_resp.session_flags & SessionSetupResponse::FLAG_IS_NULL,
        0
    );
    if expect_encryption {
        assert_ne!(
            ss_resp.session_flags & SessionSetupResponse::FLAG_ENCRYPT_DATA,
            0
        );
    } else {
        assert_eq!(
            ss_resp.session_flags & SessionSetupResponse::FLAG_ENCRYPT_DATA,
            0
        );
    }

    (session_id, session_key)
}

async fn authenticated_raw_ntlm_session_setup_with_preauth(
    s: &mut TcpStream,
    first_message_id: u64,
    preauth: &mut [u8; 64],
) -> (u64, [u8; 16]) {
    authenticated_raw_ntlm_session_setup_with_preauth_and_encryption_expectation(
        s,
        first_message_id,
        preauth,
        true,
    )
    .await
}

async fn authenticated_raw_ntlm_session_setup_with_preauth_without_encryption(
    s: &mut TcpStream,
    first_message_id: u64,
    preauth: &mut [u8; 64],
) -> (u64, [u8; 16]) {
    authenticated_raw_ntlm_session_setup_with_preauth_and_encryption_expectation(
        s,
        first_message_id,
        preauth,
        false,
    )
    .await
}

async fn authenticated_raw_ntlm_session_setup_with_preauth_and_encryption_expectation(
    s: &mut TcpStream,
    first_message_id: u64,
    preauth: &mut [u8; 64],
    expect_encryption: bool,
) -> (u64, [u8; 16]) {
    let ntlm_negotiate = raw_ntlm_negotiate();
    let ss_req = SessionSetupRequest {
        structure_size: 25,
        flags: 0,
        security_mode: 0x01,
        capabilities: 0,
        channel: 0,
        security_buffer_offset: 88,
        security_buffer_length: ntlm_negotiate.len() as u16,
        previous_session_id: 0,
        security_buffer: ntlm_negotiate,
    };
    let mut body = Vec::new();
    ss_req.write_to(&mut body).expect("write session setup");
    let ss_header = build_header(Command::SessionSetup, first_message_id, 0, 0);
    let ss_payload = smb_payload(&ss_header, &body);
    smb311_preauth_update(preauth, &ss_payload);
    write_payload_frame(s, &ss_payload).await;

    let challenge_response = read_frame(s).await;
    smb311_preauth_update(preauth, &challenge_response);
    let (rh, rb) = parse_response_header(&challenge_response);
    assert_eq!(rh.command, Command::SessionSetup);
    assert_eq!(rh.channel_sequence_status, STATUS_MORE_PROCESSING_REQUIRED);
    let session_id = rh.session_id;
    assert_ne!(session_id, 0);
    let challenge_resp = SessionSetupResponse::parse(rb).expect("parse challenge session setup");
    assert!(
        challenge_resp
            .security_buffer
            .starts_with(NTLMSSP_SIGNATURE)
    );
    assert_eq!(
        u32::from_le_bytes(challenge_resp.security_buffer[8..12].try_into().unwrap()),
        2
    );

    let authenticate = raw_ntlmv2_authenticate(
        &challenge_resp.security_buffer,
        "alice",
        "TESTSERVER",
        "Password",
    );
    let session_key = authenticate.session_key;
    let ss_req = SessionSetupRequest {
        structure_size: 25,
        flags: 0,
        security_mode: 0x01,
        capabilities: 0,
        channel: 0,
        security_buffer_offset: 88,
        security_buffer_length: authenticate.message.len() as u16,
        previous_session_id: 0,
        security_buffer: authenticate.message,
    };
    let mut body = Vec::new();
    ss_req
        .write_to(&mut body)
        .expect("write final session setup");
    let ss_header = build_header(Command::SessionSetup, first_message_id + 1, session_id, 0);
    let ss_payload = smb_payload(&ss_header, &body);
    smb311_preauth_update(preauth, &ss_payload);
    write_payload_frame(s, &ss_payload).await;

    let final_setup = read_frame(s).await;
    let (rh, rb) = parse_response_header(&final_setup);
    assert_eq!(rh.command, Command::SessionSetup);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    assert_eq!(rh.session_id, session_id);
    let ss_resp = SessionSetupResponse::parse(rb).expect("parse session setup success");
    assert_eq!(
        ss_resp.session_flags & SessionSetupResponse::FLAG_IS_GUEST,
        0
    );
    assert_eq!(
        ss_resp.session_flags & SessionSetupResponse::FLAG_IS_NULL,
        0
    );
    if expect_encryption {
        assert_ne!(
            ss_resp.session_flags & SessionSetupResponse::FLAG_ENCRYPT_DATA,
            0
        );
    } else {
        assert_eq!(
            ss_resp.session_flags & SessionSetupResponse::FLAG_ENCRYPT_DATA,
            0
        );
    }

    (session_id, session_key)
}

#[derive(Clone, Copy)]
enum TestEncryptionTransform {
    Ccm,
    Gcm,
}

async fn encrypted_exchange(
    s: &mut TcpStream,
    command: Command,
    message_id: u64,
    session_id: u64,
    tree_id: u32,
    body: &[u8],
    c2s_key: &[u8],
    s2c_key: &[u8],
) -> (Smb2Header, Vec<u8>) {
    encrypted_exchange_with_transform(
        s,
        command,
        message_id,
        session_id,
        tree_id,
        body,
        c2s_key,
        s2c_key,
        TestEncryptionTransform::Gcm,
    )
    .await
}

async fn encrypted_ccm_exchange(
    s: &mut TcpStream,
    command: Command,
    message_id: u64,
    session_id: u64,
    tree_id: u32,
    body: &[u8],
    c2s_key: &[u8],
    s2c_key: &[u8],
) -> (Smb2Header, Vec<u8>) {
    encrypted_exchange_with_transform(
        s,
        command,
        message_id,
        session_id,
        tree_id,
        body,
        c2s_key,
        s2c_key,
        TestEncryptionTransform::Ccm,
    )
    .await
}

async fn encrypted_exchange_with_transform(
    s: &mut TcpStream,
    command: Command,
    message_id: u64,
    session_id: u64,
    tree_id: u32,
    body: &[u8],
    c2s_key: &[u8],
    s2c_key: &[u8],
    transform: TestEncryptionTransform,
) -> (Smb2Header, Vec<u8>) {
    let header = build_header(command, message_id, session_id, tree_id);
    let payload = smb_payload(&header, body);
    let encrypted = match transform {
        TestEncryptionTransform::Ccm => {
            encrypt_aes_ccm_transform(c2s_key, session_id, &payload, message_id)
        }
        TestEncryptionTransform::Gcm => {
            encrypt_aes_gcm_transform(c2s_key, session_id, &payload, message_id)
        }
    };
    write_payload_frame(s, &encrypted).await;

    let encrypted_response = read_frame(s).await;
    assert!(
        is_encryption_transform(&encrypted_response),
        "{command:?} response was not encrypted"
    );
    let plain = match transform {
        TestEncryptionTransform::Ccm => decrypt_aes_ccm_transform(s2c_key, &encrypted_response),
        TestEncryptionTransform::Gcm => decrypt_aes_gcm_transform(s2c_key, &encrypted_response),
    };
    let (rh, rb) = parse_response_header(&plain);
    assert_eq!(rh.command, command);
    (rh, rb.to_vec())
}

const fn align_8(n: usize) -> usize {
    (n + 7) & !7
}
