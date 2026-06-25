#![cfg(feature = "quic")]
#![allow(clippy::too_many_arguments)]

mod common;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use binrw::{BinRead, BinWrite};
use quinn::crypto::rustls::QuicClientConfig;
use quinn::rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use smb_server::wire::header::Command;
use smb_server::wire::messages::{
    CloseRequest, CloseResponse, CreateRequest, CreateResponse, EncryptionCapabilities,
    NegotiateContext, NegotiateRequest, NegotiateResponse, PreauthIntegrityCapabilities,
    ReadRequest, ReadResponse, SessionSetupRequest, SessionSetupResponse, TreeConnectRequest,
    TreeConnectResponse, WriteRequest, WriteResponse,
};
use smb_server::{
    Access, LocalFsBackend, SMB_QUIC_ALPN, Share, SmbQuicConfig, SmbServer, smb_quic_endpoint,
};
use tempfile::tempdir;
use tokio::net::UdpSocket;
use tokio::task::JoinHandle;

use common::{
    NTLMSSP_SIGNATURE, STATUS_MORE_PROCESSING_REQUIRED, STATUS_SUCCESS, build_header,
    build_spnego_init, build_spnego_resp, encode_frame, parse_response_header, raw_ntlm_negotiate,
    raw_ntlmv2_authenticate, utf16le,
};

#[tokio::test]
async fn quic_listener_negotiates_transport_security() {
    let td = tempdir().expect("tempdir");
    let backend = LocalFsBackend::new(td.path()).expect("open root");
    let server = SmbServer::builder()
        .listen("127.0.0.1:0".parse().unwrap())
        .share(Share::new("share", backend).public())
        .netbios_name("TESTSERVER")
        .encrypt_data(true)
        .build()
        .expect("build");
    let shutdown = server.shutdown_handle();

    let (server_tls, cert_der) = quic_test_tls_config();
    let endpoint = smb_quic_endpoint(
        "127.0.0.1:0".parse().unwrap(),
        server_tls,
        SmbQuicConfig::default(),
    )
    .expect("quic endpoint");
    let addr = endpoint.local_addr().expect("local addr");
    let server_task = tokio::spawn(async move { server.serve_quic(endpoint).await });

    let client = quic_client_endpoint(cert_der);
    let conn = client
        .connect(addr, "localhost")
        .expect("connect start")
        .await
        .expect("connect");
    let (mut send, mut recv) = conn.open_bi().await.expect("open stream");

    write_quic_frame(&mut send, &quic_transport_negotiate_frame()).await;
    let resp = read_quic_frame(&mut recv).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Negotiate);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let neg_resp = NegotiateResponse::parse(rb).expect("parse negotiate");
    assert_eq!(neg_resp.dialect_revision, 0x0311);
    assert_eq!(response_encryption_cipher(rb), 0);
    assert!(response_transport_security_accepted(rb));

    conn.close(0u32.into(), b"");
    client.close(0u32.into(), b"");
    shutdown.shutdown();
    server_task.await.expect("join").expect("serve quic");
}

#[tokio::test]
async fn quic_guest_can_tree_connect_and_read_file() {
    let td = tempdir().expect("tempdir");
    let payload = b"hello over smb quic\n";
    std::fs::write(td.path().join("hello.txt"), payload).expect("seed file");
    let backend = LocalFsBackend::new(td.path()).expect("open root");
    let server = SmbServer::builder()
        .listen("127.0.0.1:0".parse().unwrap())
        .share(Share::new("share", backend).public())
        .netbios_name("TESTSERVER")
        .encrypt_data(true)
        .build()
        .expect("build");
    let shutdown = server.shutdown_handle();

    let (server_tls, cert_der) = quic_test_tls_config();
    let endpoint = smb_quic_endpoint(
        "127.0.0.1:0".parse().unwrap(),
        server_tls,
        SmbQuicConfig::default(),
    )
    .expect("quic endpoint");
    let addr = endpoint.local_addr().expect("local addr");
    let server_task = tokio::spawn(async move { server.serve_quic(endpoint).await });

    let client = quic_client_endpoint(cert_der);
    let conn = client
        .connect(addr, "localhost")
        .expect("connect start")
        .await
        .expect("connect");
    let (mut send, mut recv) = conn.open_bi().await.expect("open stream");

    write_quic_frame(&mut send, &quic_transport_negotiate_frame()).await;
    let resp = read_quic_frame(&mut recv).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Negotiate);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    assert!(response_transport_security_accepted(rb));

    let session_id = quic_anonymous_session_setup(&mut send, &mut recv).await;
    let tree_id =
        quic_tree_connect(&mut send, &mut recv, r"\\TESTSERVER\share", session_id, 3).await;
    let file_id =
        quic_create_read_only(&mut send, &mut recv, "hello.txt", session_id, tree_id, 4).await;
    let got = quic_read_file(
        &mut send,
        &mut recv,
        file_id,
        payload.len() as u32,
        session_id,
        tree_id,
        5,
    )
    .await;
    assert_eq!(got, payload);
    quic_close_file(&mut send, &mut recv, file_id, session_id, tree_id, 6).await;

    conn.close(0u32.into(), b"");
    client.close(0u32.into(), b"");
    shutdown.shutdown();
    server_task.await.expect("join").expect("serve quic");
}

#[tokio::test]
async fn quic_guest_can_write_and_read_file() {
    let td = tempdir().expect("tempdir");
    let backend = LocalFsBackend::new(td.path()).expect("open root");
    let server = SmbServer::builder()
        .listen("127.0.0.1:0".parse().unwrap())
        .share(Share::new("share", backend).public())
        .netbios_name("TESTSERVER")
        .encrypt_data(true)
        .build()
        .expect("build");
    let shutdown = server.shutdown_handle();

    let (server_tls, cert_der) = quic_test_tls_config();
    let endpoint = smb_quic_endpoint(
        "127.0.0.1:0".parse().unwrap(),
        server_tls,
        SmbQuicConfig::default(),
    )
    .expect("quic endpoint");
    let addr = endpoint.local_addr().expect("local addr");
    let server_task = tokio::spawn(async move { server.serve_quic(endpoint).await });

    let client = quic_client_endpoint(cert_der);
    let conn = client
        .connect(addr, "localhost")
        .expect("connect start")
        .await
        .expect("connect");
    let (mut send, mut recv) = conn.open_bi().await.expect("open stream");

    write_quic_frame(&mut send, &quic_transport_negotiate_frame()).await;
    let resp = read_quic_frame(&mut recv).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Negotiate);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    assert!(response_transport_security_accepted(rb));

    let session_id = quic_anonymous_session_setup(&mut send, &mut recv).await;
    let tree_id =
        quic_tree_connect(&mut send, &mut recv, r"\\TESTSERVER\share", session_id, 3).await;
    let file_id = quic_create_file(
        &mut send,
        &mut recv,
        "quic-write.txt",
        0x0012_0089 | 0x0012_0116,
        5,
        session_id,
        tree_id,
        4,
    )
    .await;

    let payload = b"written over smb quic";
    quic_write_file(
        &mut send, &mut recv, file_id, payload, session_id, tree_id, 5,
    )
    .await;
    let got = quic_read_file(
        &mut send,
        &mut recv,
        file_id,
        payload.len() as u32,
        session_id,
        tree_id,
        6,
    )
    .await;
    assert_eq!(got, payload);
    quic_close_file(&mut send, &mut recv, file_id, session_id, tree_id, 7).await;
    assert_eq!(
        std::fs::read(td.path().join("quic-write.txt")).expect("file on disk"),
        payload
    );

    conn.close(0u32.into(), b"");
    client.close(0u32.into(), b"");
    shutdown.shutdown();
    server_task.await.expect("join").expect("serve quic");
}

#[tokio::test]
async fn quic_authenticated_user_can_write_and_read_file() {
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
    let shutdown = server.shutdown_handle();

    let (server_tls, cert_der) = quic_test_tls_config();
    let endpoint = smb_quic_endpoint(
        "127.0.0.1:0".parse().unwrap(),
        server_tls,
        SmbQuicConfig::default(),
    )
    .expect("quic endpoint");
    let addr = endpoint.local_addr().expect("local addr");
    let server_task = tokio::spawn(async move { server.serve_quic(endpoint).await });

    let client = quic_client_endpoint(cert_der);
    let conn = client
        .connect(addr, "localhost")
        .expect("connect start")
        .await
        .expect("connect");
    let (mut send, mut recv) = conn.open_bi().await.expect("open stream");

    write_quic_frame(&mut send, &quic_transport_negotiate_frame()).await;
    let resp = read_quic_frame(&mut recv).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Negotiate);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    assert!(response_transport_security_accepted(rb));

    let session_id =
        quic_authenticated_session_setup(&mut send, &mut recv, "alice", "TESTSERVER", "Password")
            .await;
    let tree_id =
        quic_tree_connect(&mut send, &mut recv, r"\\TESTSERVER\secure", session_id, 3).await;
    let file_id = quic_create_file(
        &mut send,
        &mut recv,
        "auth-quic-write.txt",
        0x0012_0089 | 0x0012_0116,
        5,
        session_id,
        tree_id,
        4,
    )
    .await;

    let payload = b"authenticated over smb quic";
    quic_write_file(
        &mut send, &mut recv, file_id, payload, session_id, tree_id, 5,
    )
    .await;
    let got = quic_read_file(
        &mut send,
        &mut recv,
        file_id,
        payload.len() as u32,
        session_id,
        tree_id,
        6,
    )
    .await;
    assert_eq!(got, payload);
    quic_close_file(&mut send, &mut recv, file_id, session_id, tree_id, 7).await;
    assert_eq!(
        std::fs::read(td.path().join("auth-quic-write.txt")).expect("file on disk"),
        payload
    );

    conn.close(0u32.into(), b"");
    client.close(0u32.into(), b"");
    shutdown.shutdown();
    server_task.await.expect("join").expect("serve quic");
}

#[tokio::test]
async fn quic_config_limits_incoming_streams_to_single_smb_bidi_stream() {
    let (server_tls, cert_der) = quic_test_tls_config();
    let endpoint = smb_quic_endpoint(
        "127.0.0.1:0".parse().unwrap(),
        server_tls,
        SmbQuicConfig::default(),
    )
    .expect("server endpoint");
    let server_addr = endpoint.local_addr().expect("server addr");
    let server_task = tokio::spawn(async move {
        let incoming = endpoint.accept().await.expect("incoming conn");
        let conn = incoming.await.expect("server connection");
        tokio::time::sleep(Duration::from_millis(200)).await;
        conn.close(0u32.into(), b"");
        endpoint.close(0u32.into(), b"");
    });

    let client = quic_client_endpoint(cert_der);
    let conn = client
        .connect(server_addr, "localhost")
        .expect("connect")
        .await
        .expect("client connection");
    let first = conn.open_bi().await.expect("first bidi stream");
    let second = tokio::time::timeout(Duration::from_millis(75), conn.open_bi()).await;
    let uni = tokio::time::timeout(Duration::from_millis(75), conn.open_uni()).await;

    assert!(
        second.is_err(),
        "SMB over QUIC should allow only one concurrent client-opened bidirectional stream"
    );
    assert!(
        uni.is_err(),
        "SMB over QUIC should not allow client-opened unidirectional streams"
    );

    drop(first);
    conn.close(0u32.into(), b"");
    client.close(0u32.into(), b"");
    server_task.await.expect("server task");
}

#[tokio::test]
async fn quic_write_read_survives_one_gbps_forty_ms_wan_profile() {
    let td = tempdir().expect("tempdir");
    let backend = LocalFsBackend::new(td.path()).expect("open root");
    let server = SmbServer::builder()
        .listen("127.0.0.1:0".parse().unwrap())
        .share(Share::new("share", backend).public())
        .netbios_name("TESTSERVER")
        .encrypt_data(true)
        .build()
        .expect("build");
    let shutdown = server.shutdown_handle();

    let (server_tls, cert_der) = quic_test_tls_config();
    let endpoint = smb_quic_endpoint(
        "127.0.0.1:0".parse().unwrap(),
        server_tls,
        SmbQuicConfig::default(),
    )
    .expect("quic endpoint");
    let server_addr = endpoint.local_addr().expect("local addr");
    let server_task = tokio::spawn(async move { server.serve_quic(endpoint).await });
    let (proxy_addr, proxy_task) =
        spawn_udp_wan_proxy(server_addr, Duration::from_millis(20), 1_000).await;

    let client = quic_client_endpoint(cert_der);
    let conn = client
        .connect(proxy_addr, "localhost")
        .expect("connect start")
        .await
        .expect("connect through WAN proxy");
    let (mut send, mut recv) = conn.open_bi().await.expect("open stream");

    write_quic_frame(&mut send, &quic_transport_negotiate_frame()).await;
    let resp = read_quic_frame(&mut recv).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Negotiate);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    assert!(response_transport_security_accepted(rb));

    let session_id = quic_anonymous_session_setup(&mut send, &mut recv).await;
    let tree_id =
        quic_tree_connect(&mut send, &mut recv, r"\\TESTSERVER\share", session_id, 3).await;
    let file_id = quic_create_file(
        &mut send,
        &mut recv,
        "wan-profile.bin",
        0x0012_0089 | 0x0012_0116,
        5,
        session_id,
        tree_id,
        4,
    )
    .await;

    let payload = deterministic_payload(1024 * 1024);
    quic_write_file(
        &mut send, &mut recv, file_id, &payload, session_id, tree_id, 5,
    )
    .await;
    let got = quic_read_file(
        &mut send,
        &mut recv,
        file_id,
        payload.len() as u32,
        session_id,
        tree_id,
        6,
    )
    .await;
    assert_eq!(got, payload);
    quic_close_file(&mut send, &mut recv, file_id, session_id, tree_id, 7).await;

    conn.close(0u32.into(), b"");
    client.close(0u32.into(), b"");
    proxy_task.abort();
    shutdown.shutdown();
    server_task.await.expect("join").expect("serve quic");
}

fn quic_test_tls_config() -> (quinn::rustls::ServerConfig, CertificateDer<'static>) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).expect("cert");
    let cert_der = cert.cert.der().clone();
    let key = PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der());
    let server_tls = quinn::rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der.clone()], PrivateKeyDer::from(key))
        .expect("server tls");
    (server_tls, cert_der)
}

async fn spawn_udp_wan_proxy(
    server_addr: SocketAddr,
    one_way_delay: Duration,
    bandwidth_mbps: u64,
) -> (SocketAddr, JoinHandle<()>) {
    let socket = Arc::new(
        UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("bind UDP WAN proxy"),
    );
    let proxy_addr = socket.local_addr().expect("proxy addr");
    let client_addr = Arc::new(tokio::sync::Mutex::new(None::<SocketAddr>));
    let task = tokio::spawn({
        let socket = socket.clone();
        let client_addr = client_addr.clone();
        async move {
            let mut buf = vec![0u8; 65_535];
            while let Ok((len, src)) = socket.recv_from(&mut buf).await {
                let target = if src == server_addr {
                    let Some(addr) = *client_addr.lock().await else {
                        continue;
                    };
                    addr
                } else {
                    *client_addr.lock().await = Some(src);
                    server_addr
                };
                let packet = buf[..len].to_vec();
                let socket = socket.clone();
                let delay = one_way_delay + serialization_delay(packet.len(), bandwidth_mbps);
                tokio::spawn(async move {
                    tokio::time::sleep(delay).await;
                    let _ = socket.send_to(&packet, target).await;
                });
            }
        }
    });
    (proxy_addr, task)
}

fn serialization_delay(bytes: usize, bandwidth_mbps: u64) -> Duration {
    let bits_per_second = bandwidth_mbps as f64 * 1_000_000.0;
    Duration::from_secs_f64((bytes as f64 * 8.0) / bits_per_second)
}

fn deterministic_payload(len: usize) -> Vec<u8> {
    (0..len).map(|i| ((i * 31) % 251) as u8).collect()
}

fn quic_client_endpoint(cert_der: CertificateDer<'static>) -> quinn::Endpoint {
    let mut roots = quinn::rustls::RootCertStore::empty();
    roots.add(cert_der).expect("add cert");
    let mut client_tls = quinn::rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    client_tls.alpn_protocols = vec![SMB_QUIC_ALPN.to_vec()];
    let client_config =
        quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(client_tls).unwrap()));
    let mut client = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).expect("client");
    client.set_default_client_config(client_config);
    client
}

fn quic_transport_negotiate_frame() -> Vec<u8> {
    let preauth = PreauthIntegrityCapabilities {
        hash_algorithm_count: 1,
        salt_length: 0,
        hash_algorithms: vec![PreauthIntegrityCapabilities::HASH_SHA512],
        salt: vec![],
    };
    let mut preauth_data = Vec::new();
    BinWrite::write(&preauth, &mut std::io::Cursor::new(&mut preauth_data)).expect("write preauth");
    let transport_data = NegotiateContext::TRANSPORT_CAP_ACCEPT_TRANSPORT_SECURITY.to_le_bytes();
    let contexts = [
        NegotiateContext {
            context_type: NegotiateContext::TYPE_PREAUTH_INTEGRITY,
            data_length: preauth_data.len() as u16,
            reserved: 0,
            data: preauth_data,
        },
        NegotiateContext {
            context_type: NegotiateContext::TYPE_TRANSPORT_CAPS,
            data_length: transport_data.len() as u16,
            reserved: 0,
            data: transport_data.to_vec(),
        },
    ];
    let mut contexts_bytes = Vec::new();
    NegotiateContext::encode_list(&contexts, &mut contexts_bytes).expect("encode contexts");
    let fixed_and_dialects = 36 + 2;
    let contexts_offset = align_8(64 + fixed_and_dialects) as u32;
    let req = NegotiateRequest {
        structure_size: 36,
        dialect_count: 1,
        security_mode: 0x0001,
        reserved: 0,
        capabilities: 0,
        client_guid: [0x51; 16],
        negotiate_context_offset_or_client_start_time: (contexts_offset as u64)
            | ((contexts.len() as u64) << 32),
        dialects: vec![0x0311],
    };

    let mut body = Vec::new();
    req.write_to(&mut body).expect("write negotiate");
    body.resize(contexts_offset as usize - 64, 0);
    body.extend_from_slice(&contexts_bytes);

    let hdr = build_header(Command::Negotiate, 0, 0, 0);
    let mut payload = Vec::new();
    hdr.write(&mut payload).expect("write header");
    payload.extend_from_slice(&body);
    payload
}

async fn quic_anonymous_session_setup(
    send: &mut quinn::SendStream,
    recv: &mut quinn::RecvStream,
) -> u64 {
    let mut ntlm_negotiate = Vec::new();
    ntlm_negotiate.extend_from_slice(NTLMSSP_SIGNATURE);
    ntlm_negotiate.extend_from_slice(&1u32.to_le_bytes());
    ntlm_negotiate.extend_from_slice(&0x6209_8215u32.to_le_bytes());
    ntlm_negotiate.extend_from_slice(&[0u8; 16]);
    ntlm_negotiate.extend_from_slice(&[0u8; 8]);

    let spnego_init = build_spnego_init(&ntlm_negotiate);
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
    write_quic_request(send, Command::SessionSetup, 1, 0, 0, &body).await;

    let resp = read_quic_frame(recv).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::SessionSetup);
    assert_eq!(rh.channel_sequence_status, STATUS_MORE_PROCESSING_REQUIRED);
    let session_id = rh.session_id;
    assert_ne!(session_id, 0);
    let ss_resp = SessionSetupResponse::parse(rb).expect("parse ss resp");
    assert!(!ss_resp.security_buffer.is_empty());

    let mut ntlm_auth = Vec::new();
    ntlm_auth.extend_from_slice(NTLMSSP_SIGNATURE);
    ntlm_auth.extend_from_slice(&3u32.to_le_bytes());
    let header_len: u32 = 72;
    for _ in 0..6 {
        ntlm_auth.extend_from_slice(&0u16.to_le_bytes());
        ntlm_auth.extend_from_slice(&0u16.to_le_bytes());
        ntlm_auth.extend_from_slice(&header_len.to_le_bytes());
    }
    ntlm_auth.extend_from_slice(&0x0000_0800u32.to_le_bytes());
    ntlm_auth.extend_from_slice(&[0u8; 8]);

    let spnego_resp_blob = build_spnego_resp(&ntlm_auth);
    let ss_req2 = SessionSetupRequest {
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
    ss_req2.write_to(&mut body).expect("write session setup");
    write_quic_request(send, Command::SessionSetup, 2, session_id, 0, &body).await;

    let resp = read_quic_frame(recv).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::SessionSetup);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    assert_eq!(rh.session_id, session_id);
    let ss_resp = SessionSetupResponse::parse(rb).expect("parse ss success resp");
    assert_eq!(
        ss_resp.session_flags & SessionSetupResponse::FLAG_IS_GUEST,
        SessionSetupResponse::FLAG_IS_GUEST
    );
    session_id
}

async fn quic_authenticated_session_setup(
    send: &mut quinn::SendStream,
    recv: &mut quinn::RecvStream,
    user: &str,
    domain: &str,
    password: &str,
) -> u64 {
    let negotiate = raw_ntlm_negotiate();
    let ss_req = SessionSetupRequest {
        structure_size: 25,
        flags: 0,
        security_mode: 0x01,
        capabilities: 0,
        channel: 0,
        security_buffer_offset: 88,
        security_buffer_length: negotiate.len() as u16,
        previous_session_id: 0,
        security_buffer: negotiate,
    };
    let mut body = Vec::new();
    ss_req.write_to(&mut body).expect("write session setup");
    write_quic_request(send, Command::SessionSetup, 1, 0, 0, &body).await;

    let resp = read_quic_frame(recv).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::SessionSetup);
    assert_eq!(rh.channel_sequence_status, STATUS_MORE_PROCESSING_REQUIRED);
    let session_id = rh.session_id;
    assert_ne!(session_id, 0);
    let challenge_resp = SessionSetupResponse::parse(rb).expect("parse challenge session setup");
    let challenge = challenge_resp.security_buffer;
    assert!(challenge.starts_with(NTLMSSP_SIGNATURE));
    assert_eq!(u32::from_le_bytes(challenge[8..12].try_into().unwrap()), 2);

    let authenticate = raw_ntlmv2_authenticate(&challenge, user, domain, password);
    let ss_req2 = SessionSetupRequest {
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
    ss_req2.write_to(&mut body).expect("write session setup");
    write_quic_request(send, Command::SessionSetup, 2, session_id, 0, &body).await;

    let resp = read_quic_frame(recv).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::SessionSetup);
    assert_eq!(
        rh.channel_sequence_status, STATUS_SUCCESS,
        "authenticated SESSION_SETUP failed with status {:#010x}",
        rh.channel_sequence_status
    );
    assert_eq!(rh.session_id, session_id);
    let ss_resp = SessionSetupResponse::parse(rb).expect("parse ss success resp");
    assert_eq!(
        ss_resp.session_flags & SessionSetupResponse::FLAG_IS_GUEST,
        0
    );
    assert_eq!(
        ss_resp.session_flags & SessionSetupResponse::FLAG_IS_NULL,
        0
    );
    assert_eq!(
        ss_resp.session_flags & SessionSetupResponse::FLAG_ENCRYPT_DATA,
        0,
        "transport security should avoid SMB transform encryption"
    );
    session_id
}

async fn quic_tree_connect(
    send: &mut quinn::SendStream,
    recv: &mut quinn::RecvStream,
    path: &str,
    session_id: u64,
    message_id: u64,
) -> u32 {
    let path_u16 = utf16le(path);
    let req = TreeConnectRequest {
        structure_size: 9,
        flags: 0,
        path_offset: 64 + 8,
        path_length: path_u16.len() as u16,
        path: path_u16,
    };
    let mut body = Vec::new();
    req.write_to(&mut body).expect("write tree connect");
    write_quic_request(send, Command::TreeConnect, message_id, session_id, 0, &body).await;

    let resp = read_quic_frame(recv).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::TreeConnect);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let tree_id = rh.tree_id().expect("tree id");
    assert_ne!(tree_id, 0);
    let tree = TreeConnectResponse::parse(rb).expect("parse tree connect");
    assert_eq!(tree.share_type, TreeConnectResponse::SHARE_TYPE_DISK);
    assert_ne!(
        tree.share_flags & TreeConnectResponse::SHARE_FLAG_ISOLATED_TRANSPORT,
        0
    );
    tree_id
}

async fn quic_create_read_only(
    send: &mut quinn::SendStream,
    recv: &mut quinn::RecvStream,
    name: &str,
    session_id: u64,
    tree_id: u32,
    message_id: u64,
) -> smb_server::wire::messages::FileId {
    quic_create_file(
        send,
        recv,
        name,
        0x0012_0089,
        1,
        session_id,
        tree_id,
        message_id,
    )
    .await
}

async fn quic_create_file(
    send: &mut quinn::SendStream,
    recv: &mut quinn::RecvStream,
    name: &str,
    desired_access: u32,
    create_disposition: u32,
    session_id: u64,
    tree_id: u32,
    message_id: u64,
) -> smb_server::wire::messages::FileId {
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
    write_quic_request(
        send,
        Command::Create,
        message_id,
        session_id,
        tree_id,
        &body,
    )
    .await;

    let resp = read_quic_frame(recv).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Create);
    assert_eq!(
        rh.channel_sequence_status, STATUS_SUCCESS,
        "CREATE failed with status {:#010x}",
        rh.channel_sequence_status
    );
    CreateResponse::parse(rb)
        .expect("parse create response")
        .file_id
}

async fn quic_write_file(
    send: &mut quinn::SendStream,
    recv: &mut quinn::RecvStream,
    file_id: smb_server::wire::messages::FileId,
    data: &[u8],
    session_id: u64,
    tree_id: u32,
    message_id: u64,
) {
    let req = WriteRequest {
        structure_size: 49,
        data_offset: WriteRequest::STANDARD_DATA_OFFSET,
        length: data.len() as u32,
        offset: 0,
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
    write_quic_request_with_credit(
        send,
        Command::Write,
        message_id,
        session_id,
        tree_id,
        credit_charge_for_len(data.len()),
        &body,
    )
    .await;

    let resp = read_quic_frame(recv).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Write);
    assert_eq!(
        rh.channel_sequence_status, STATUS_SUCCESS,
        "WRITE failed with status {:#010x}",
        rh.channel_sequence_status
    );
    let write = WriteResponse::parse(rb).expect("parse write");
    assert_eq!(write.count as usize, data.len());
}

async fn quic_read_file(
    send: &mut quinn::SendStream,
    recv: &mut quinn::RecvStream,
    file_id: smb_server::wire::messages::FileId,
    length: u32,
    session_id: u64,
    tree_id: u32,
    message_id: u64,
) -> Vec<u8> {
    let req = ReadRequest {
        structure_size: 49,
        padding: ReadResponse::STANDARD_DATA_OFFSET,
        flags: 0,
        length,
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
    req.write_to(&mut body).expect("write read");
    write_quic_request_with_credit(
        send,
        Command::Read,
        message_id,
        session_id,
        tree_id,
        credit_charge_for_len(length as usize),
        &body,
    )
    .await;

    let resp = read_quic_frame(recv).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Read);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    ReadResponse::parse(rb).expect("parse read").data
}

async fn quic_close_file(
    send: &mut quinn::SendStream,
    recv: &mut quinn::RecvStream,
    file_id: smb_server::wire::messages::FileId,
    session_id: u64,
    tree_id: u32,
    message_id: u64,
) {
    let req = CloseRequest {
        structure_size: 24,
        flags: 0,
        reserved: 0,
        file_id,
    };
    let mut body = Vec::new();
    req.write_to(&mut body).expect("write close");
    write_quic_request(send, Command::Close, message_id, session_id, tree_id, &body).await;

    let resp = read_quic_frame(recv).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Close);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let _ = CloseResponse::parse(rb).expect("parse close");
}

async fn write_quic_request(
    send: &mut quinn::SendStream,
    command: Command,
    message_id: u64,
    session_id: u64,
    tree_id: u32,
    body: &[u8],
) {
    write_quic_request_with_credit(send, command, message_id, session_id, tree_id, 1, body).await;
}

async fn write_quic_request_with_credit(
    send: &mut quinn::SendStream,
    command: Command,
    message_id: u64,
    session_id: u64,
    tree_id: u32,
    credit_charge: u16,
    body: &[u8],
) {
    let hdr = build_header(command, message_id, session_id, tree_id);
    let hdr = smb_server::wire::header::Smb2Header {
        credit_charge,
        ..hdr
    };
    let mut payload = Vec::new();
    hdr.write(&mut payload).expect("write header");
    payload.extend_from_slice(body);
    write_quic_frame(send, &payload).await;
}

fn credit_charge_for_len(len: usize) -> u16 {
    len.div_ceil(64 * 1024).max(1) as u16
}

async fn write_quic_frame(send: &mut quinn::SendStream, payload: &[u8]) {
    let mut framed = Vec::new();
    encode_frame(payload, &mut framed);
    send.write_all(&framed).await.expect("write");
}

async fn read_quic_frame(recv: &mut quinn::RecvStream) -> Vec<u8> {
    let mut hdr = [0u8; 4];
    recv.read_exact(&mut hdr).await.expect("read frame header");
    assert_eq!(hdr[0], 0);
    let len = ((hdr[1] as usize) << 16) | ((hdr[2] as usize) << 8) | hdr[3] as usize;
    let mut frame = vec![0u8; len];
    recv.read_exact(&mut frame).await.expect("read frame");
    frame
}

fn response_encryption_cipher(rb: &[u8]) -> u16 {
    response_contexts(rb)
        .iter()
        .find(|ctx| ctx.context_type == NegotiateContext::TYPE_ENCRYPTION)
        .and_then(|ctx| EncryptionCapabilities::read(&mut std::io::Cursor::new(&ctx.data)).ok())
        .and_then(|caps| caps.ciphers.first().copied())
        .unwrap_or_default()
}

fn response_transport_security_accepted(rb: &[u8]) -> bool {
    response_contexts(rb)
        .iter()
        .find(|ctx| ctx.context_type == NegotiateContext::TYPE_TRANSPORT_CAPS)
        .is_some_and(|ctx| {
            ctx.data.len() >= 4
                && u32::from_le_bytes(ctx.data[0..4].try_into().unwrap())
                    & NegotiateContext::TRANSPORT_CAP_ACCEPT_TRANSPORT_SECURITY
                    != 0
        })
}

fn response_contexts(rb: &[u8]) -> Vec<NegotiateContext> {
    let neg_resp = NegotiateResponse::parse(rb).expect("parse negotiate");
    let offset = neg_resp.negotiate_context_offset_or_reserved2 as usize - 64;
    NegotiateContext::parse_list(&rb[offset..], neg_resp.negotiate_context_count_or_reserved)
        .expect("parse contexts")
}

const fn align_8(n: usize) -> usize {
    (n + 7) & !7
}
