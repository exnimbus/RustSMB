//! Helpers for hand-building SMB2 client requests in integration tests.

use aes::cipher::{BlockEncrypt, KeyInit as AesBlockKeyInit, generic_array::GenericArray};
use aes::{Aes128, Aes256};
use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes128Gcm, Aes256Gcm, KeyInit as AesGcmKeyInit};
use binrw::BinWrite;
use hmac::{Hmac, Mac};
use md4::{Digest, Md4};
use md5::Md5;
use sha2::{Sha256, Sha512};
use smb_server::wire::crypto::{SigningAlgo, sign, signing_key_30, signing_key_311, verify};
use smb_server::wire::header::{
    Command, HeaderTail, SMB2_FLAGS_SERVER_TO_REDIR, SMB2_FLAGS_SIGNED, Smb2Header,
};
use smb_server::wire::messages::{
    NegotiateContext, NegotiateRequest, NegotiateResponse, PreauthIntegrityCapabilities,
    SessionSetupRequest, SessionSetupResponse, TreeConnectRequest, TreeConnectResponse,
};
use std::io::Cursor;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

pub const NTLMSSP_SIGNATURE: &[u8] = b"NTLMSSP\0";
pub const OID_SPNEGO: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x02];
pub const OID_NTLMSSP: &[u8] = &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a];
#[allow(dead_code)]
pub const OID_KERBEROS: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02];
const FRAME_HEADER_LEN: usize = 4;

pub const STATUS_SUCCESS: u32 = 0x0000_0000;
pub const STATUS_MORE_PROCESSING_REQUIRED: u32 = 0xC000_0016;
#[allow(dead_code)]
pub const STATUS_ACCESS_DENIED: u32 = 0xC000_0022;

const ENCRYPTION_MAGIC: [u8; 4] = [0xFD, b'S', b'M', b'B'];
const TRANSFORM_HEADER_SIZE: usize = 52;
const TAG_OFFSET: usize = 4;
const TAG_LEN: usize = 16;
const NONCE_OFFSET: usize = 20;
const GCM_NONCE_LEN: usize = 12;
const CCM_NONCE_LEN: usize = 11;
const ORIGINAL_SIZE_OFFSET: usize = 36;
const FLAGS_OFFSET: usize = 42;
const SESSION_ID_OFFSET: usize = 44;
const TRANSFORM_FLAG_ENCRYPTED: u16 = 0x0001;
const SMB2_SIGNATURE_OFFSET: usize = 48;
const SMB2_SIGNATURE_LEN: usize = 16;

type HmacMd5 = Hmac<Md5>;
type HmacSha256 = Hmac<Sha256>;

pub fn utf16le(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

pub fn build_header(
    command: Command,
    message_id: u64,
    session_id: u64,
    tree_id: u32,
) -> Smb2Header {
    Smb2Header {
        credit_charge: 1,
        channel_sequence_status: 0,
        command,
        credit_request_response: 64,
        flags: 0,
        next_command: 0,
        message_id,
        tail: HeaderTail::sync(tree_id),
        session_id,
        signature: [0u8; 16],
    }
}

pub async fn write_frame(s: &mut TcpStream, header: &Smb2Header, body: &[u8]) {
    let mut payload = Vec::new();
    header.write(&mut payload).expect("hdr");
    payload.extend_from_slice(body);
    let mut framed = Vec::new();
    encode_frame(&payload, &mut framed);
    s.write_all(&framed).await.expect("write");
}

pub fn encode_frame(payload: &[u8], out: &mut Vec<u8>) {
    assert!(payload.len() <= 0x00FF_FFFF);
    out.push(0);
    out.push(((payload.len() >> 16) & 0xff) as u8);
    out.push(((payload.len() >> 8) & 0xff) as u8);
    out.push((payload.len() & 0xff) as u8);
    out.extend_from_slice(payload);
}

fn decode_frame_header(hdr: &[u8; FRAME_HEADER_LEN]) -> usize {
    assert_eq!(hdr[0], 0, "unsupported direct TCP frame marker");
    ((hdr[1] as usize) << 16) | ((hdr[2] as usize) << 8) | hdr[3] as usize
}

pub async fn read_frame(s: &mut TcpStream) -> Vec<u8> {
    let mut hdr = [0u8; FRAME_HEADER_LEN];
    s.read_exact(&mut hdr).await.expect("hdr");
    let len = decode_frame_header(&hdr);
    let mut body = vec![0u8; len];
    s.read_exact(&mut body).await.expect("body");
    body
}

pub fn parse_response_header(frame: &[u8]) -> (Smb2Header, &[u8]) {
    let (h, rest) = Smb2Header::parse(frame).expect("parse hdr");
    assert!(
        h.flags & SMB2_FLAGS_SERVER_TO_REDIR != 0,
        "must be a response"
    );
    (h, rest)
}

fn write_tlv(tag: u8, content: &[u8], out: &mut Vec<u8>) {
    out.push(tag);
    if content.len() < 0x80 {
        out.push(content.len() as u8);
    } else {
        let mut tmp = Vec::new();
        let mut n = content.len();
        while n > 0 {
            tmp.push((n & 0xff) as u8);
            n >>= 8;
        }
        out.push(0x80 | tmp.len() as u8);
        for b in tmp.into_iter().rev() {
            out.push(b);
        }
    }
    out.extend_from_slice(content);
}

pub fn build_spnego_init(ntlm: &[u8]) -> Vec<u8> {
    let mut mts = Vec::new();
    write_tlv(0x06, OID_NTLMSSP, &mut mts);
    let mut mts_seq = Vec::new();
    write_tlv(0x30, &mts, &mut mts_seq);
    let mut mts_ctx0 = Vec::new();
    write_tlv(0xa0, &mts_seq, &mut mts_ctx0);

    let mut tok_oct = Vec::new();
    write_tlv(0x04, ntlm, &mut tok_oct);
    let mut tok_ctx2 = Vec::new();
    write_tlv(0xa2, &tok_oct, &mut tok_ctx2);

    let mut seq = Vec::new();
    seq.extend_from_slice(&mts_ctx0);
    seq.extend_from_slice(&tok_ctx2);
    let mut neg_token_init = Vec::new();
    write_tlv(0x30, &seq, &mut neg_token_init);

    let mut choice = Vec::new();
    write_tlv(0xa0, &neg_token_init, &mut choice);

    let mut gss_inner = Vec::new();
    write_tlv(0x06, OID_SPNEGO, &mut gss_inner);
    gss_inner.extend_from_slice(&choice);

    let mut blob = Vec::new();
    write_tlv(0x60, &gss_inner, &mut blob);
    blob
}

#[allow(dead_code)]
pub fn build_spnego_kerberos_only_init() -> Vec<u8> {
    let mut mts = Vec::new();
    write_tlv(0x06, OID_KERBEROS, &mut mts);
    let mut mts_seq = Vec::new();
    write_tlv(0x30, &mts, &mut mts_seq);
    let mut mts_ctx0 = Vec::new();
    write_tlv(0xa0, &mts_seq, &mut mts_ctx0);

    let mut neg_token_init = Vec::new();
    write_tlv(0x30, &mts_ctx0, &mut neg_token_init);

    let mut choice = Vec::new();
    write_tlv(0xa0, &neg_token_init, &mut choice);

    let mut gss_inner = Vec::new();
    write_tlv(0x06, OID_SPNEGO, &mut gss_inner);
    gss_inner.extend_from_slice(&choice);

    let mut blob = Vec::new();
    write_tlv(0x60, &gss_inner, &mut blob);
    blob
}

pub fn build_spnego_resp(ntlm: &[u8]) -> Vec<u8> {
    let mut enum_state = Vec::new();
    write_tlv(0x0a, &[1], &mut enum_state);
    let mut state_ctx0 = Vec::new();
    write_tlv(0xa0, &enum_state, &mut state_ctx0);

    let mut mech_oid = Vec::new();
    write_tlv(0x06, OID_NTLMSSP, &mut mech_oid);
    let mut mech_ctx1 = Vec::new();
    write_tlv(0xa1, &mech_oid, &mut mech_ctx1);

    let mut tok_oct = Vec::new();
    write_tlv(0x04, ntlm, &mut tok_oct);
    let mut tok_ctx2 = Vec::new();
    write_tlv(0xa2, &tok_oct, &mut tok_ctx2);

    let mut seq = Vec::new();
    seq.extend_from_slice(&state_ctx0);
    seq.extend_from_slice(&mech_ctx1);
    seq.extend_from_slice(&tok_ctx2);

    let mut seq_outer = Vec::new();
    write_tlv(0x30, &seq, &mut seq_outer);
    let mut out = Vec::new();
    write_tlv(0xa1, &seq_outer, &mut out);
    out
}

#[allow(dead_code)]
pub fn anonymous_ntlm_negotiate_token() -> Vec<u8> {
    let mut ntlm_negotiate = Vec::new();
    ntlm_negotiate.extend_from_slice(NTLMSSP_SIGNATURE);
    ntlm_negotiate.extend_from_slice(&1u32.to_le_bytes());
    ntlm_negotiate.extend_from_slice(&0x6209_8215u32.to_le_bytes());
    ntlm_negotiate.extend_from_slice(&[0u8; 16]);
    ntlm_negotiate.extend_from_slice(&[0u8; 8]);
    ntlm_negotiate
}

#[allow(dead_code)]
pub fn anonymous_ntlm_authenticate_token() -> Vec<u8> {
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
    ntlm_auth
}

#[allow(dead_code)]
pub struct RawNtlmV2Authenticate {
    pub message: Vec<u8>,
    pub session_key: [u8; 16],
}

#[allow(dead_code)]
pub fn raw_ntlm_negotiate() -> Vec<u8> {
    const FLAGS: u32 = 0x0000_0001
        | 0x0000_0004
        | 0x0000_0010
        | 0x0000_0200
        | 0x0000_8000
        | 0x0008_0000
        | 0x0080_0000
        | 0x0200_0000
        | 0x2000_0000
        | 0x8000_0000;
    let mut out = Vec::new();
    out.extend_from_slice(NTLMSSP_SIGNATURE);
    out.extend_from_slice(&1u32.to_le_bytes());
    out.extend_from_slice(&FLAGS.to_le_bytes());
    out.extend_from_slice(&[0u8; 8]);
    out.extend_from_slice(&[0u8; 8]);
    out.extend_from_slice(&[0u8; 8]);
    out
}

#[allow(dead_code)]
pub fn raw_ntlmv2_authenticate(
    challenge: &[u8],
    user: &str,
    domain: &str,
    password: &str,
) -> RawNtlmV2Authenticate {
    let server_challenge: [u8; 8] = challenge[24..32].try_into().expect("server challenge");
    let client_challenge_blob = ntlmv2_client_challenge_blob(challenge);
    let response_key_nt = ntowf_v2(&nt_hash(password), user, domain);
    let mut proof_mac = <HmacMd5 as Mac>::new_from_slice(&response_key_nt).expect("hmac");
    proof_mac.update(&server_challenge);
    proof_mac.update(&client_challenge_blob);
    let nt_proof = proof_mac.finalize().into_bytes();

    let mut session_mac = <HmacMd5 as Mac>::new_from_slice(&response_key_nt).expect("hmac");
    session_mac.update(&nt_proof);
    let session_digest = session_mac.finalize().into_bytes();
    let mut session_key = [0u8; 16];
    session_key.copy_from_slice(&session_digest);

    let mut nt_response = Vec::new();
    nt_response.extend_from_slice(&nt_proof);
    nt_response.extend_from_slice(&client_challenge_blob);

    let user_u16 = utf16le(user);
    let domain_u16 = utf16le(domain);
    let workstation_u16 = utf16le("RUSTCLIENT");
    let lm_response = vec![0u8; 24];
    const FLAGS: u32 = 0x0000_0001
        | 0x0000_0010
        | 0x0000_0200
        | 0x0000_8000
        | 0x0008_0000
        | 0x0080_0000
        | 0x0200_0000
        | 0x2000_0000
        | 0x8000_0000;
    let header_len: u32 = 72;
    let mut payload = Vec::new();
    let lm_off = header_len;
    payload.extend_from_slice(&lm_response);
    let nt_off = header_len + payload.len() as u32;
    payload.extend_from_slice(&nt_response);
    let domain_off = header_len + payload.len() as u32;
    payload.extend_from_slice(&domain_u16);
    let user_off = header_len + payload.len() as u32;
    payload.extend_from_slice(&user_u16);
    let workstation_off = header_len + payload.len() as u32;
    payload.extend_from_slice(&workstation_u16);
    let key_off = header_len + payload.len() as u32;

    let mut message = Vec::new();
    message.extend_from_slice(NTLMSSP_SIGNATURE);
    message.extend_from_slice(&3u32.to_le_bytes());
    write_ntlm_field(&mut message, lm_response.len(), lm_off);
    write_ntlm_field(&mut message, nt_response.len(), nt_off);
    write_ntlm_field(&mut message, domain_u16.len(), domain_off);
    write_ntlm_field(&mut message, user_u16.len(), user_off);
    write_ntlm_field(&mut message, workstation_u16.len(), workstation_off);
    write_ntlm_field(&mut message, 0, key_off);
    message.extend_from_slice(&FLAGS.to_le_bytes());
    message.extend_from_slice(&[0u8; 8]);
    assert_eq!(message.len() as u32, header_len);
    message.extend_from_slice(&payload);

    RawNtlmV2Authenticate {
        message,
        session_key,
    }
}

#[allow(dead_code)]
pub fn is_encryption_transform(frame: &[u8]) -> bool {
    frame.len() >= 4 && frame[..4] == ENCRYPTION_MAGIC
}

#[allow(dead_code)]
pub fn smb311_preauth_update(hash: &mut [u8; 64], frame: &[u8]) {
    let mut hasher = Sha512::new();
    hasher.update(*hash);
    hasher.update(frame);
    hash.copy_from_slice(&hasher.finalize());
}

#[allow(dead_code)]
pub fn smb311_encryption_key_c2s(session_key: &[u8], preauth_hash: &[u8; 64]) -> Vec<u8> {
    smb2_kdf_bytes(session_key, b"SMBC2SCipherKey\x00", preauth_hash, 16)
}

#[allow(dead_code)]
pub fn smb311_encryption_key_s2c(session_key: &[u8], preauth_hash: &[u8; 64]) -> Vec<u8> {
    smb2_kdf_bytes(session_key, b"SMBS2CCipherKey\x00", preauth_hash, 16)
}

#[allow(dead_code)]
pub fn smb311_encryption_key_c2s_256(session_key: &[u8], preauth_hash: &[u8; 64]) -> Vec<u8> {
    smb2_kdf_bytes(session_key, b"SMBC2SCipherKey\x00", preauth_hash, 32)
}

#[allow(dead_code)]
pub fn smb311_encryption_key_s2c_256(session_key: &[u8], preauth_hash: &[u8; 64]) -> Vec<u8> {
    smb2_kdf_bytes(session_key, b"SMBS2CCipherKey\x00", preauth_hash, 32)
}

#[allow(dead_code)]
pub fn smb300_encryption_key_c2s(session_key: &[u8]) -> Vec<u8> {
    smb2_kdf_bytes(session_key, b"SMB2AESCCM\x00", b"ServerIn \x00", 16)
}

#[allow(dead_code)]
pub fn smb300_encryption_key_s2c(session_key: &[u8]) -> Vec<u8> {
    smb2_kdf_bytes(session_key, b"SMB2AESCCM\x00", b"ServerOut\x00", 16)
}

#[allow(dead_code)]
pub fn smb300_signing_key(session_key: &[u8]) -> [u8; 16] {
    signing_key_30(session_key)
}

#[allow(dead_code)]
pub fn sign_smb300_payload(payload: &mut [u8], signing_key: &[u8; 16]) {
    assert!(payload.len() >= 64, "SMB2 payload must include a header");
    let mut flags = u32::from_le_bytes(payload[16..20].try_into().unwrap());
    flags |= SMB2_FLAGS_SIGNED;
    payload[16..20].copy_from_slice(&flags.to_le_bytes());
    sign(payload, signing_key, SigningAlgo::AesCmac).expect("sign SMB 3.0 payload");
}

#[allow(dead_code)]
pub fn verify_smb300_signed_payload(payload: &[u8], signing_key: &[u8; 16]) {
    assert!(payload.len() >= 64, "SMB2 payload must include a header");
    let flags = u32::from_le_bytes(payload[16..20].try_into().unwrap());
    assert_ne!(flags & SMB2_FLAGS_SIGNED, 0, "SMB2 payload is not signed");
    verify(payload, signing_key, SigningAlgo::AesCmac).expect("verify SMB 3.0 signature");
}

#[allow(dead_code)]
pub fn smb311_signing_key(session_key: &[u8], preauth_hash: &[u8; 64]) -> [u8; 16] {
    signing_key_311(session_key, preauth_hash)
}

#[allow(dead_code)]
pub fn sign_smb311_payload(payload: &mut [u8], signing_key: &[u8; 16], algo: SigningAlgo) {
    set_signed_flag(payload);
    match algo {
        SigningAlgo::AesCmac => {
            sign(payload, signing_key, SigningAlgo::AesCmac).expect("sign SMB 3.1.1 CMAC payload");
        }
        SigningAlgo::AesGmac => {
            let tag = gmac_signing_tag(payload, signing_key, false);
            payload[SMB2_SIGNATURE_OFFSET..SMB2_SIGNATURE_OFFSET + SMB2_SIGNATURE_LEN]
                .copy_from_slice(&tag);
        }
        SigningAlgo::HmacSha256 => panic!("SMB 3.1.1 signing does not use HMAC-SHA256"),
    }
}

#[allow(dead_code)]
pub fn verify_smb311_signed_payload(payload: &[u8], signing_key: &[u8; 16], algo: SigningAlgo) {
    assert_signed(payload);
    match algo {
        SigningAlgo::AesCmac => {
            verify(payload, signing_key, SigningAlgo::AesCmac)
                .expect("verify SMB 3.1.1 CMAC response signature");
        }
        SigningAlgo::AesGmac => {
            let expected = gmac_signing_tag(payload, signing_key, true);
            assert_eq!(
                &payload[SMB2_SIGNATURE_OFFSET..SMB2_SIGNATURE_OFFSET + SMB2_SIGNATURE_LEN],
                expected.as_slice(),
                "verify SMB 3.1.1 GMAC response signature"
            );
        }
        SigningAlgo::HmacSha256 => panic!("SMB 3.1.1 signing does not use HMAC-SHA256"),
    }
}

#[allow(dead_code)]
pub fn encrypt_aes128_gcm_transform(
    key: &[u8],
    session_id: u64,
    plain: &[u8],
    nonce_seed: u64,
) -> Vec<u8> {
    encrypt_aes_gcm_transform(key, session_id, plain, nonce_seed)
}

#[allow(dead_code)]
pub fn encrypt_aes_gcm_transform(
    key: &[u8],
    session_id: u64,
    plain: &[u8],
    nonce_seed: u64,
) -> Vec<u8> {
    let mut nonce = [0u8; GCM_NONCE_LEN];
    nonce[..8].copy_from_slice(&nonce_seed.to_le_bytes());
    nonce[8..].copy_from_slice(&0x47534d42u32.to_le_bytes());

    let mut out = transform_header(session_id, plain.len());
    out[NONCE_OFFSET..NONCE_OFFSET + GCM_NONCE_LEN].copy_from_slice(&nonce);
    let aad = &out[NONCE_OFFSET..TRANSFORM_HEADER_SIZE];
    let sealed = match key.len() {
        16 => {
            let cipher =
                <Aes128Gcm as AesGcmKeyInit>::new_from_slice(key).expect("AES-128-GCM key");
            cipher
                .encrypt(&nonce.into(), Payload { msg: plain, aad })
                .expect("encrypt AES-128-GCM transform")
        }
        32 => {
            let cipher =
                <Aes256Gcm as AesGcmKeyInit>::new_from_slice(key).expect("AES-256-GCM key");
            cipher
                .encrypt(&nonce.into(), Payload { msg: plain, aad })
                .expect("encrypt AES-256-GCM transform")
        }
        _ => panic!("unsupported AES-GCM key length {}", key.len()),
    };
    write_sealed(&mut out, plain.len(), &sealed);
    out
}

#[allow(dead_code)]
pub fn decrypt_aes128_gcm_transform(key: &[u8], transform: &[u8]) -> Vec<u8> {
    decrypt_aes_gcm_transform(key, transform)
}

#[allow(dead_code)]
pub fn decrypt_aes_gcm_transform(key: &[u8], transform: &[u8]) -> Vec<u8> {
    assert!(
        transform.len() >= TRANSFORM_HEADER_SIZE && is_encryption_transform(transform),
        "invalid encryption transform"
    );
    let flags = u16::from_le_bytes([transform[FLAGS_OFFSET], transform[FLAGS_OFFSET + 1]]);
    assert_eq!(flags, TRANSFORM_FLAG_ENCRYPTED);
    let nonce = &transform[NONCE_OFFSET..NONCE_OFFSET + GCM_NONCE_LEN];
    let aad = &transform[NONCE_OFFSET..TRANSFORM_HEADER_SIZE];
    let mut sealed = Vec::with_capacity(transform.len() - TRANSFORM_HEADER_SIZE + TAG_LEN);
    sealed.extend_from_slice(&transform[TRANSFORM_HEADER_SIZE..]);
    sealed.extend_from_slice(&transform[TAG_OFFSET..TAG_OFFSET + TAG_LEN]);
    let plain = match key.len() {
        16 => {
            let cipher =
                <Aes128Gcm as AesGcmKeyInit>::new_from_slice(key).expect("AES-128-GCM key");
            cipher
                .decrypt(nonce.into(), Payload { msg: &sealed, aad })
                .expect("decrypt AES-128-GCM transform")
        }
        32 => {
            let cipher =
                <Aes256Gcm as AesGcmKeyInit>::new_from_slice(key).expect("AES-256-GCM key");
            cipher
                .decrypt(nonce.into(), Payload { msg: &sealed, aad })
                .expect("decrypt AES-256-GCM transform")
        }
        _ => panic!("unsupported AES-GCM key length {}", key.len()),
    };
    let original = u32::from_le_bytes(
        transform[ORIGINAL_SIZE_OFFSET..ORIGINAL_SIZE_OFFSET + 4]
            .try_into()
            .expect("original size"),
    ) as usize;
    assert_eq!(plain.len(), original);
    plain
}

#[allow(dead_code)]
pub fn encrypt_aes128_ccm_transform(
    key: &[u8],
    session_id: u64,
    plain: &[u8],
    nonce_seed: u64,
) -> Vec<u8> {
    encrypt_aes_ccm_transform(key, session_id, plain, nonce_seed)
}

#[allow(dead_code)]
pub fn encrypt_aes_ccm_transform(
    key: &[u8],
    session_id: u64,
    plain: &[u8],
    nonce_seed: u64,
) -> Vec<u8> {
    let mut nonce = [0u8; CCM_NONCE_LEN];
    nonce[..8].copy_from_slice(&nonce_seed.to_le_bytes());
    nonce[8..].copy_from_slice(b"CCM");

    let mut out = transform_header(session_id, plain.len());
    out[NONCE_OFFSET..NONCE_OFFSET + CCM_NONCE_LEN].copy_from_slice(&nonce);
    let aad = &out[NONCE_OFFSET..TRANSFORM_HEADER_SIZE];
    let sealed = ccm_seal(key, &nonce, plain, aad);
    write_sealed(&mut out, plain.len(), &sealed);
    out
}

#[allow(dead_code)]
pub fn decrypt_aes128_ccm_transform(key: &[u8], transform: &[u8]) -> Vec<u8> {
    decrypt_aes_ccm_transform(key, transform)
}

#[allow(dead_code)]
pub fn decrypt_aes_ccm_transform(key: &[u8], transform: &[u8]) -> Vec<u8> {
    assert!(
        transform.len() >= TRANSFORM_HEADER_SIZE && is_encryption_transform(transform),
        "invalid encryption transform"
    );
    let flags = u16::from_le_bytes([transform[FLAGS_OFFSET], transform[FLAGS_OFFSET + 1]]);
    assert_eq!(flags, TRANSFORM_FLAG_ENCRYPTED);
    let nonce = &transform[NONCE_OFFSET..NONCE_OFFSET + CCM_NONCE_LEN];
    let aad = &transform[NONCE_OFFSET..TRANSFORM_HEADER_SIZE];
    let mut sealed = Vec::with_capacity(transform.len() - TRANSFORM_HEADER_SIZE + TAG_LEN);
    sealed.extend_from_slice(&transform[TRANSFORM_HEADER_SIZE..]);
    sealed.extend_from_slice(&transform[TAG_OFFSET..TAG_OFFSET + TAG_LEN]);
    let plain = ccm_open(key, nonce, &sealed, aad);
    let original = u32::from_le_bytes(
        transform[ORIGINAL_SIZE_OFFSET..ORIGINAL_SIZE_OFFSET + 4]
            .try_into()
            .expect("original size"),
    ) as usize;
    assert_eq!(plain.len(), original);
    plain
}

fn ntlmv2_client_challenge_blob(challenge: &[u8]) -> Vec<u8> {
    let target_info_len = u16::from_le_bytes(challenge[40..42].try_into().unwrap()) as usize;
    let target_info_off = u32::from_le_bytes(challenge[44..48].try_into().unwrap()) as usize;
    let target_info = challenge
        .get(target_info_off..target_info_off + target_info_len)
        .unwrap_or(&[0, 0, 0, 0]);
    let mut blob = Vec::new();
    blob.extend_from_slice(&[0x01, 0x01, 0x00, 0x00]);
    blob.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    blob.extend_from_slice(&0u64.to_le_bytes());
    blob.extend_from_slice(&[0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5]);
    blob.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    blob.extend_from_slice(target_info);
    if !target_info.ends_with(&[0, 0, 0, 0]) {
        blob.extend_from_slice(&[0, 0, 0, 0]);
    }
    blob
}

fn write_ntlm_field(out: &mut Vec<u8>, len: usize, offset: u32) {
    out.extend_from_slice(&(len as u16).to_le_bytes());
    out.extend_from_slice(&(len as u16).to_le_bytes());
    out.extend_from_slice(&offset.to_le_bytes());
}

fn nt_hash(password: &str) -> [u8; 16] {
    let mut h = Md4::new();
    h.update(utf16le(password));
    let digest = h.finalize();
    let mut out = [0u8; 16];
    out.copy_from_slice(&digest);
    out
}

fn ntowf_v2(nt_hash: &[u8; 16], user: &str, domain: &str) -> [u8; 16] {
    let mut mac = <HmacMd5 as Mac>::new_from_slice(nt_hash).expect("hmac");
    mac.update(&utf16le(&user.to_uppercase()));
    mac.update(&utf16le(domain));
    let digest = mac.finalize().into_bytes();
    let mut out = [0u8; 16];
    out.copy_from_slice(&digest);
    out
}

fn smb2_kdf_bytes(key: &[u8], label: &[u8], context: &[u8], len: usize) -> Vec<u8> {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key).expect("hmac");
    mac.update(&[0x00, 0x00, 0x00, 0x01]);
    mac.update(label);
    mac.update(&[0x00]);
    mac.update(context);
    mac.update(&((len as u32) * 8).to_be_bytes());
    let full = mac.finalize().into_bytes();
    full[..len].to_vec()
}

fn set_signed_flag(payload: &mut [u8]) {
    assert!(payload.len() >= 64, "SMB2 payload must include a header");
    let mut flags = u32::from_le_bytes(payload[16..20].try_into().unwrap());
    flags |= SMB2_FLAGS_SIGNED;
    payload[16..20].copy_from_slice(&flags.to_le_bytes());
}

fn assert_signed(payload: &[u8]) {
    assert!(payload.len() >= 64, "SMB2 payload must include a header");
    let flags = u32::from_le_bytes(payload[16..20].try_into().unwrap());
    assert_ne!(flags & SMB2_FLAGS_SIGNED, 0, "SMB2 payload is not signed");
}

fn gmac_signing_tag(payload: &[u8], signing_key: &[u8; 16], server: bool) -> [u8; 16] {
    assert!(payload.len() >= 64, "SMB2 payload must include a header");
    let mut signed = Vec::with_capacity(payload.len());
    signed.extend_from_slice(&payload[..SMB2_SIGNATURE_OFFSET]);
    signed.extend_from_slice(&[0u8; SMB2_SIGNATURE_LEN]);
    signed.extend_from_slice(&payload[SMB2_SIGNATURE_OFFSET + SMB2_SIGNATURE_LEN..]);
    signed[16] |= SMB2_FLAGS_SIGNED as u8;

    let mut nonce = [0u8; 12];
    nonce[..8].copy_from_slice(&signed[24..32]);
    let command = u16::from_le_bytes([signed[12], signed[13]]);
    let mut flags = 0u32;
    if server {
        flags |= 1;
    }
    if command == Command::Cancel.as_u16() {
        flags |= 2;
    }
    nonce[8..].copy_from_slice(&flags.to_le_bytes());

    let cipher = <Aes128Gcm as AesGcmKeyInit>::new_from_slice(signing_key).expect("AES-128 key");
    let tag = cipher
        .encrypt(
            &nonce.into(),
            Payload {
                msg: &[],
                aad: &signed,
            },
        )
        .expect("AES-GMAC signing tag");
    assert_eq!(tag.len(), SMB2_SIGNATURE_LEN);
    let mut out = [0u8; SMB2_SIGNATURE_LEN];
    out.copy_from_slice(&tag);
    out
}

fn ccm_seal(key: &[u8], nonce: &[u8], plaintext: &[u8], aad: &[u8]) -> Vec<u8> {
    match key.len() {
        16 => {
            let cipher = <Aes128 as AesBlockKeyInit>::new_from_slice(key).expect("AES-128 key");
            ccm_seal_with_cipher(&cipher, nonce, plaintext, aad)
        }
        32 => {
            let cipher = <Aes256 as AesBlockKeyInit>::new_from_slice(key).expect("AES-256 key");
            ccm_seal_with_cipher(&cipher, nonce, plaintext, aad)
        }
        _ => panic!("unsupported AES-CCM key length {}", key.len()),
    }
}

fn ccm_seal_with_cipher<C: BlockEncrypt>(
    cipher: &C,
    nonce: &[u8],
    plaintext: &[u8],
    aad: &[u8],
) -> Vec<u8> {
    let tag = ccm_mac(cipher, nonce, plaintext, aad);
    let mut out = vec![0u8; plaintext.len() + TAG_LEN];
    ccm_crypt(cipher, nonce, &mut out[..plaintext.len()], plaintext, 1);
    let mut s0 = [0u8; 16];
    ccm_counter_block(&mut s0, nonce, 0);
    ccm_encrypt_block(cipher, &mut s0);
    for i in 0..TAG_LEN {
        out[plaintext.len() + i] = tag[i] ^ s0[i];
    }
    out
}

fn ccm_open(key: &[u8], nonce: &[u8], ciphertext: &[u8], aad: &[u8]) -> Vec<u8> {
    match key.len() {
        16 => {
            let cipher = <Aes128 as AesBlockKeyInit>::new_from_slice(key).expect("AES-128 key");
            ccm_open_with_cipher(&cipher, nonce, ciphertext, aad)
        }
        32 => {
            let cipher = <Aes256 as AesBlockKeyInit>::new_from_slice(key).expect("AES-256 key");
            ccm_open_with_cipher(&cipher, nonce, ciphertext, aad)
        }
        _ => panic!("unsupported AES-CCM key length {}", key.len()),
    }
}

fn ccm_open_with_cipher<C: BlockEncrypt>(
    cipher: &C,
    nonce: &[u8],
    ciphertext: &[u8],
    aad: &[u8],
) -> Vec<u8> {
    assert!(ciphertext.len() >= TAG_LEN, "short AES-CCM ciphertext");
    let n = ciphertext.len() - TAG_LEN;
    let mut plain = vec![0u8; n];
    ccm_crypt(cipher, nonce, &mut plain, &ciphertext[..n], 1);
    let mut want = ccm_mac(cipher, nonce, &plain, aad);
    let mut s0 = [0u8; 16];
    ccm_counter_block(&mut s0, nonce, 0);
    ccm_encrypt_block(cipher, &mut s0);
    for i in 0..TAG_LEN {
        want[i] ^= s0[i];
    }
    assert!(
        constant_time_eq(&want, &ciphertext[n..]),
        "AES-CCM tag mismatch"
    );
    plain
}

fn ccm_mac<C: BlockEncrypt>(cipher: &C, nonce: &[u8], plaintext: &[u8], aad: &[u8]) -> [u8; 16] {
    assert!(
        (7..=13).contains(&nonce.len()),
        "invalid AES-CCM nonce length"
    );
    let mut y = [0u8; 16];
    let mut b = [0u8; 16];
    b[0] = 0x40 | (((TAG_LEN - 2) / 2) as u8) << 3 | ((15 - nonce.len() - 1) as u8);
    b[1..1 + nonce.len()].copy_from_slice(nonce);
    ccm_put_length(
        &mut b[1 + nonce.len()..],
        plaintext.len() as u64,
        15 - nonce.len(),
    );
    xor_block(&mut y, &b);
    ccm_encrypt_block(cipher, &mut y);
    if !aad.is_empty() {
        let mut aad_block = Vec::with_capacity(2 + aad.len());
        aad_block.extend_from_slice(&(aad.len() as u16).to_be_bytes());
        aad_block.extend_from_slice(aad);
        ccm_mac_blocks(cipher, &mut y, &aad_block);
    }
    ccm_mac_blocks(cipher, &mut y, plaintext);
    y
}

fn ccm_mac_blocks<C: BlockEncrypt>(cipher: &C, y: &mut [u8; 16], mut data: &[u8]) {
    while !data.is_empty() {
        let mut b = [0u8; 16];
        let n = data.len().min(16);
        b[..n].copy_from_slice(&data[..n]);
        xor_block(y, &b);
        ccm_encrypt_block(cipher, y);
        data = &data[n..];
    }
}

fn ccm_crypt<C: BlockEncrypt>(
    cipher: &C,
    nonce: &[u8],
    mut dst: &mut [u8],
    mut src: &[u8],
    mut counter: u64,
) {
    while !src.is_empty() {
        let mut stream = [0u8; 16];
        ccm_counter_block(&mut stream, nonce, counter);
        ccm_encrypt_block(cipher, &mut stream);
        let n = src.len().min(16);
        for i in 0..n {
            dst[i] = src[i] ^ stream[i];
        }
        dst = &mut dst[n..];
        src = &src[n..];
        counter += 1;
    }
}

fn ccm_counter_block(dst: &mut [u8], nonce: &[u8], counter: u64) {
    let q = 15 - nonce.len();
    dst.fill(0);
    dst[0] = (q - 1) as u8;
    dst[1..1 + nonce.len()].copy_from_slice(nonce);
    ccm_put_length(&mut dst[1 + nonce.len()..], counter, q);
}

fn ccm_put_length(dst: &mut [u8], mut value: u64, n: usize) {
    for i in (0..n).rev() {
        dst[i] = value as u8;
        value >>= 8;
    }
}

fn ccm_encrypt_block<C: BlockEncrypt>(cipher: &C, block: &mut [u8; 16]) {
    let mut generic = GenericArray::clone_from_slice(block);
    cipher.encrypt_block(&mut generic);
    block.copy_from_slice(&generic);
}

fn xor_block(dst: &mut [u8; 16], src: &[u8; 16]) {
    for i in 0..16 {
        dst[i] ^= src[i];
    }
}

fn constant_time_eq(a: &[u8; 16], b: &[u8]) -> bool {
    if b.len() != 16 {
        return false;
    }
    let mut diff = 0u8;
    for i in 0..16 {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

fn transform_header(session_id: u64, plain_len: usize) -> Vec<u8> {
    let mut out = vec![0u8; TRANSFORM_HEADER_SIZE + plain_len];
    out[..4].copy_from_slice(&ENCRYPTION_MAGIC);
    out[ORIGINAL_SIZE_OFFSET..ORIGINAL_SIZE_OFFSET + 4]
        .copy_from_slice(&(plain_len as u32).to_le_bytes());
    out[FLAGS_OFFSET..FLAGS_OFFSET + 2].copy_from_slice(&TRANSFORM_FLAG_ENCRYPTED.to_le_bytes());
    out[SESSION_ID_OFFSET..SESSION_ID_OFFSET + 8].copy_from_slice(&session_id.to_le_bytes());
    out
}

fn write_sealed(out: &mut [u8], plain_len: usize, sealed: &[u8]) {
    out[TRANSFORM_HEADER_SIZE..].copy_from_slice(&sealed[..plain_len]);
    out[TAG_OFFSET..TAG_OFFSET + TAG_LEN].copy_from_slice(&sealed[plain_len..]);
}

#[allow(dead_code)]
pub async fn negotiate(s: &mut TcpStream) -> NegotiateResponse {
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
    write_frame(s, &hdr, &body).await;

    let resp = read_frame(s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Negotiate);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let neg_resp = NegotiateResponse::parse(rb).expect("parse neg resp");
    assert!(matches!(neg_resp.dialect_revision, 0x0202 | 0x0210));
    assert_eq!(neg_resp.security_mode, 0x0001);
    neg_resp
}

#[allow(dead_code)]
pub async fn negotiate_smb311(s: &mut TcpStream) -> NegotiateResponse {
    let preauth = PreauthIntegrityCapabilities {
        hash_algorithm_count: 1,
        salt_length: 0,
        hash_algorithms: vec![PreauthIntegrityCapabilities::HASH_SHA512],
        salt: vec![],
    };
    let mut cursor = Cursor::new(Vec::new());
    BinWrite::write(&preauth, &mut cursor).expect("write preauth context");
    let preauth_data = cursor.into_inner();
    let contexts = [NegotiateContext {
        context_type: NegotiateContext::TYPE_PREAUTH_INTEGRITY,
        data_length: preauth_data.len() as u16,
        reserved: 0,
        data: preauth_data,
    }];
    let mut contexts_bytes = Vec::new();
    NegotiateContext::encode_list(&contexts, &mut contexts_bytes).expect("encode contexts");
    let fixed_and_dialects = 36 + 2;
    let contexts_offset = align_8(64 + fixed_and_dialects) as u32;

    let neg_req = NegotiateRequest {
        structure_size: 36,
        dialect_count: 1,
        security_mode: 0x0001,
        reserved: 0,
        capabilities: 0,
        client_guid: [0x31; 16],
        negotiate_context_offset_or_client_start_time: (contexts_offset as u64)
            | ((contexts.len() as u64) << 32),
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
    let neg_resp = NegotiateResponse::parse(rb).expect("parse smb311 neg resp");
    assert_eq!(neg_resp.dialect_revision, 0x0311);
    assert_eq!(neg_resp.security_mode, 0x0001);
    neg_resp
}

#[allow(dead_code)]
pub async fn anonymous_session_setup(s: &mut TcpStream) -> u64 {
    anonymous_session_setup_with_previous(s, 0).await
}

#[allow(dead_code)]
pub async fn anonymous_session_setup_with_previous(
    s: &mut TcpStream,
    previous_session_id: u64,
) -> u64 {
    let spnego_init = build_spnego_init(&anonymous_ntlm_negotiate_token());
    let ss_req = SessionSetupRequest {
        structure_size: 25,
        flags: 0,
        security_mode: 0x01,
        capabilities: 0,
        channel: 0,
        security_buffer_offset: 88,
        security_buffer_length: spnego_init.len() as u16,
        previous_session_id,
        security_buffer: spnego_init,
    };
    let mut body = Vec::new();
    ss_req.write_to(&mut body).expect("write session setup");
    let hdr = build_header(Command::SessionSetup, 1, 0, 0);
    write_frame(s, &hdr, &body).await;

    let resp = read_frame(s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::SessionSetup);
    assert_eq!(rh.channel_sequence_status, STATUS_MORE_PROCESSING_REQUIRED);
    let session_id = rh.session_id;
    assert_ne!(session_id, 0);
    let ss_resp = SessionSetupResponse::parse(rb).expect("parse ss resp");
    assert!(!ss_resp.security_buffer.is_empty());

    let spnego_resp_blob = build_spnego_resp(&anonymous_ntlm_authenticate_token());
    let ss_req2 = SessionSetupRequest {
        structure_size: 25,
        flags: 0,
        security_mode: 0x01,
        capabilities: 0,
        channel: 0,
        security_buffer_offset: 88,
        security_buffer_length: spnego_resp_blob.len() as u16,
        previous_session_id,
        security_buffer: spnego_resp_blob,
    };
    let mut body = Vec::new();
    ss_req2.write_to(&mut body).expect("write session setup");
    let hdr = build_header(Command::SessionSetup, 2, session_id, 0);
    write_frame(s, &hdr, &body).await;

    let resp = read_frame(s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::SessionSetup);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    assert_eq!(rh.session_id, session_id);
    let ss_resp = SessionSetupResponse::parse(rb).expect("parse ss success resp");
    assert_eq!(
        ss_resp.session_flags & SessionSetupResponse::FLAG_IS_GUEST,
        SessionSetupResponse::FLAG_IS_GUEST
    );
    assert_eq!(
        ss_resp.session_flags & SessionSetupResponse::FLAG_IS_NULL,
        0
    );
    session_id
}

#[allow(dead_code)]
const fn align_8(n: usize) -> usize {
    (n + 7) & !7
}

#[allow(dead_code)]
pub async fn tree_connect(s: &mut TcpStream, path: &str, session_id: u64, message_id: u64) -> u32 {
    let path_u16 = utf16le(path);
    let tc_req = TreeConnectRequest {
        structure_size: 9,
        flags: 0,
        path_offset: 64 + 8,
        path_length: path_u16.len() as u16,
        path: path_u16,
    };
    let mut body = Vec::new();
    tc_req.write_to(&mut body).expect("write tree connect");
    let hdr = build_header(Command::TreeConnect, message_id, session_id, 0);
    write_frame(s, &hdr, &body).await;

    let resp = read_frame(s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::TreeConnect);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let tree_id = rh.tree_id().expect("tree id");
    assert_ne!(tree_id, 0);
    let tc_resp = TreeConnectResponse::parse(rb).expect("parse tc resp");
    assert_eq!(tc_resp.share_type, TreeConnectResponse::SHARE_TYPE_DISK);
    tree_id
}

#[allow(dead_code)]
pub async fn tree_connect_status(
    s: &mut TcpStream,
    path: &str,
    session_id: u64,
    message_id: u64,
) -> u32 {
    let path_u16 = utf16le(path);
    let tc_req = TreeConnectRequest {
        structure_size: 9,
        flags: 0,
        path_offset: 64 + 8,
        path_length: path_u16.len() as u16,
        path: path_u16,
    };
    let mut body = Vec::new();
    tc_req.write_to(&mut body).expect("write tree connect");
    let hdr = build_header(Command::TreeConnect, message_id, session_id, 0);
    write_frame(s, &hdr, &body).await;

    let resp = read_frame(s).await;
    let (rh, _) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::TreeConnect);
    rh.channel_sequence_status
}
