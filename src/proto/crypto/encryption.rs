//! SMB 3.x encryption transform helpers.
//!
//! This covers the wire-level transform used by SMB encryption:
//! `0xFD 'S' 'M' 'B'` header, 16-byte authentication tag, nonce, original
//! size, encrypted flag, session id, and ciphertext.

#![allow(dead_code)]

use aes::cipher::{BlockEncrypt, KeyInit, generic_array::GenericArray};
use aes::{Aes128, Aes256};
use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes128Gcm, Aes256Gcm};
use hmac::digest::generic_array::typenum::{U16, U32};

use crate::proto::crypto::kdf::{smb2_kdf, smb2_kdf_bytes};
use crate::proto::error::{ProtoError, ProtoResult};
use crate::utils::fill_random;

pub const ENCRYPTION_MAGIC: [u8; 4] = [0xFD, b'S', b'M', b'B'];
pub const TRANSFORM_HEADER_SIZE: usize = 52;
const TAG_OFFSET: usize = 4;
const TAG_LEN: usize = 16;
const NONCE_OFFSET: usize = 20;
const GCM_NONCE_LEN: usize = 12;
const CCM_NONCE_LEN: usize = 11;
const ORIGINAL_SIZE_OFFSET: usize = 36;
const FLAGS_OFFSET: usize = 42;
const SESSION_ID_OFFSET: usize = 44;
const TRANSFORM_FLAG_ENCRYPTED: u16 = 0x0001;

type Aes128Key = GenericArray<u8, U16>;
type Aes256Key = GenericArray<u8, U32>;

pub fn is_encryption_transform(frame: &[u8]) -> bool {
    frame.len() >= 4 && frame[..4] == ENCRYPTION_MAGIC
}

pub fn encryption_key_311_c2s(session_key: &[u8], preauth_hash: &[u8; 64]) -> Vec<u8> {
    smb2_kdf(session_key, b"SMBC2SCipherKey\x00", preauth_hash).to_vec()
}

pub fn encryption_key_311_s2c(session_key: &[u8], preauth_hash: &[u8; 64]) -> Vec<u8> {
    smb2_kdf(session_key, b"SMBS2CCipherKey\x00", preauth_hash).to_vec()
}

pub fn encryption_key_311_c2s_256(session_key: &[u8], preauth_hash: &[u8; 64]) -> Vec<u8> {
    smb2_kdf_bytes(session_key, b"SMBC2SCipherKey\x00", preauth_hash, 32)
}

pub fn encryption_key_311_s2c_256(session_key: &[u8], preauth_hash: &[u8; 64]) -> Vec<u8> {
    smb2_kdf_bytes(session_key, b"SMBS2CCipherKey\x00", preauth_hash, 32)
}

pub fn encryption_key_300_c2s(session_key: &[u8]) -> Vec<u8> {
    smb2_kdf(session_key, b"SMB2AESCCM\x00", b"ServerIn \x00").to_vec()
}

pub fn encryption_key_300_s2c(session_key: &[u8]) -> Vec<u8> {
    smb2_kdf(session_key, b"SMB2AESCCM\x00", b"ServerOut\x00").to_vec()
}

pub fn encrypt_gcm(key: &[u8], session_id: u64, plain: &[u8]) -> ProtoResult<Vec<u8>> {
    let mut nonce = [0u8; GCM_NONCE_LEN];
    fill_random(&mut nonce);
    encrypt_gcm_with_nonce(key, session_id, plain, &nonce)
}

pub fn decrypt_gcm(key: &[u8], transform: &[u8]) -> ProtoResult<Vec<u8>> {
    validate_transform_header(transform)?;
    let nonce = &transform[NONCE_OFFSET..NONCE_OFFSET + GCM_NONCE_LEN];
    let aad = &transform[NONCE_OFFSET..TRANSFORM_HEADER_SIZE];
    let sealed = sealed_from_transform(transform);
    let plain = match key.len() {
        16 => {
            let cipher = Aes128Gcm::new(Aes128Key::from_slice(key));
            cipher.decrypt(
                GenericArray::from_slice(nonce),
                Payload { msg: &sealed, aad },
            )
        }
        32 => {
            let cipher = Aes256Gcm::new(Aes256Key::from_slice(key));
            cipher.decrypt(
                GenericArray::from_slice(nonce),
                Payload { msg: &sealed, aad },
            )
        }
        _ => return Err(ProtoError::Crypto("unsupported AES-GCM key length")),
    }
    .map_err(|_| ProtoError::Crypto("AES-GCM decrypt failed"))?;
    validate_original_size(transform, plain.len())?;
    Ok(plain)
}

pub fn encrypt_ccm(key: &[u8], session_id: u64, plain: &[u8]) -> ProtoResult<Vec<u8>> {
    let mut nonce = [0u8; CCM_NONCE_LEN];
    fill_random(&mut nonce);
    encrypt_ccm_with_nonce(key, session_id, plain, &nonce)
}

pub fn decrypt_ccm(key: &[u8], transform: &[u8]) -> ProtoResult<Vec<u8>> {
    validate_transform_header(transform)?;
    let nonce = &transform[NONCE_OFFSET..NONCE_OFFSET + CCM_NONCE_LEN];
    let aad = &transform[NONCE_OFFSET..TRANSFORM_HEADER_SIZE];
    let sealed = sealed_from_transform(transform);
    let plain = ccm_open(key, nonce, &sealed, aad)?;
    validate_original_size(transform, plain.len())?;
    Ok(plain)
}

fn encrypt_gcm_with_nonce(
    key: &[u8],
    session_id: u64,
    plain: &[u8],
    nonce: &[u8; GCM_NONCE_LEN],
) -> ProtoResult<Vec<u8>> {
    let mut out = transform_header(session_id, plain.len());
    out[NONCE_OFFSET..NONCE_OFFSET + GCM_NONCE_LEN].copy_from_slice(nonce);
    let aad = &out[NONCE_OFFSET..TRANSFORM_HEADER_SIZE];
    let sealed = match key.len() {
        16 => {
            let cipher = Aes128Gcm::new(Aes128Key::from_slice(key));
            cipher.encrypt(GenericArray::from_slice(nonce), Payload { msg: plain, aad })
        }
        32 => {
            let cipher = Aes256Gcm::new(Aes256Key::from_slice(key));
            cipher.encrypt(GenericArray::from_slice(nonce), Payload { msg: plain, aad })
        }
        _ => return Err(ProtoError::Crypto("unsupported AES-GCM key length")),
    }
    .map_err(|_| ProtoError::Crypto("AES-GCM encrypt failed"))?;
    write_sealed(&mut out, plain.len(), &sealed);
    Ok(out)
}

fn encrypt_ccm_with_nonce(
    key: &[u8],
    session_id: u64,
    plain: &[u8],
    nonce: &[u8; CCM_NONCE_LEN],
) -> ProtoResult<Vec<u8>> {
    let mut out = transform_header(session_id, plain.len());
    out[NONCE_OFFSET..NONCE_OFFSET + CCM_NONCE_LEN].copy_from_slice(nonce);
    let aad = &out[NONCE_OFFSET..TRANSFORM_HEADER_SIZE];
    let sealed = ccm_seal(key, nonce, plain, aad)?;
    write_sealed(&mut out, plain.len(), &sealed);
    Ok(out)
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

fn validate_transform_header(transform: &[u8]) -> ProtoResult<()> {
    if transform.len() < TRANSFORM_HEADER_SIZE || transform[..4] != ENCRYPTION_MAGIC {
        return Err(ProtoError::Crypto("invalid SMB encryption transform"));
    }
    let flags = u16::from_le_bytes([transform[FLAGS_OFFSET], transform[FLAGS_OFFSET + 1]]);
    if flags != TRANSFORM_FLAG_ENCRYPTED {
        return Err(ProtoError::Crypto("SMB transform is not encrypted"));
    }
    Ok(())
}

fn validate_original_size(transform: &[u8], plain_len: usize) -> ProtoResult<()> {
    let original = u32::from_le_bytes([
        transform[ORIGINAL_SIZE_OFFSET],
        transform[ORIGINAL_SIZE_OFFSET + 1],
        transform[ORIGINAL_SIZE_OFFSET + 2],
        transform[ORIGINAL_SIZE_OFFSET + 3],
    ]);
    if original as usize != plain_len {
        return Err(ProtoError::Crypto("SMB transform size mismatch"));
    }
    Ok(())
}

fn sealed_from_transform(transform: &[u8]) -> Vec<u8> {
    let mut sealed = Vec::with_capacity(transform.len() - TRANSFORM_HEADER_SIZE + TAG_LEN);
    sealed.extend_from_slice(&transform[TRANSFORM_HEADER_SIZE..]);
    sealed.extend_from_slice(&transform[TAG_OFFSET..TAG_OFFSET + TAG_LEN]);
    sealed
}

fn write_sealed(out: &mut [u8], plain_len: usize, sealed: &[u8]) {
    out[TRANSFORM_HEADER_SIZE..].copy_from_slice(&sealed[..plain_len]);
    out[TAG_OFFSET..TAG_OFFSET + TAG_LEN].copy_from_slice(&sealed[plain_len..]);
}

fn ccm_seal(key: &[u8], nonce: &[u8], plaintext: &[u8], aad: &[u8]) -> ProtoResult<Vec<u8>> {
    match key.len() {
        16 => ccm_seal_with_cipher(
            &Aes128::new(Aes128Key::from_slice(key)),
            nonce,
            plaintext,
            aad,
        ),
        32 => ccm_seal_with_cipher(
            &Aes256::new(Aes256Key::from_slice(key)),
            nonce,
            plaintext,
            aad,
        ),
        _ => Err(ProtoError::Crypto("unsupported AES-CCM key length")),
    }
}

fn ccm_open(key: &[u8], nonce: &[u8], ciphertext: &[u8], aad: &[u8]) -> ProtoResult<Vec<u8>> {
    match key.len() {
        16 => ccm_open_with_cipher(
            &Aes128::new(Aes128Key::from_slice(key)),
            nonce,
            ciphertext,
            aad,
        ),
        32 => ccm_open_with_cipher(
            &Aes256::new(Aes256Key::from_slice(key)),
            nonce,
            ciphertext,
            aad,
        ),
        _ => Err(ProtoError::Crypto("unsupported AES-CCM key length")),
    }
}

fn ccm_seal_with_cipher<C: BlockEncrypt>(
    cipher: &C,
    nonce: &[u8],
    plaintext: &[u8],
    aad: &[u8],
) -> ProtoResult<Vec<u8>> {
    validate_ccm_nonce(nonce)?;
    let tag = ccm_mac(cipher, nonce, plaintext, aad);
    let mut out = vec![0u8; plaintext.len() + TAG_LEN];
    ccm_crypt(cipher, nonce, &mut out[..plaintext.len()], plaintext, 1);
    let mut s0 = [0u8; 16];
    counter_block(&mut s0, nonce, 0);
    encrypt_block(cipher, &mut s0);
    for i in 0..TAG_LEN {
        out[plaintext.len() + i] = tag[i] ^ s0[i];
    }
    Ok(out)
}

fn ccm_open_with_cipher<C: BlockEncrypt>(
    cipher: &C,
    nonce: &[u8],
    ciphertext: &[u8],
    aad: &[u8],
) -> ProtoResult<Vec<u8>> {
    validate_ccm_nonce(nonce)?;
    if ciphertext.len() < TAG_LEN {
        return Err(ProtoError::Crypto("short AES-CCM ciphertext"));
    }
    let n = ciphertext.len() - TAG_LEN;
    let mut plain = vec![0u8; n];
    ccm_crypt(cipher, nonce, &mut plain, &ciphertext[..n], 1);
    let mut want = ccm_mac(cipher, nonce, &plain, aad);
    let mut s0 = [0u8; 16];
    counter_block(&mut s0, nonce, 0);
    encrypt_block(cipher, &mut s0);
    for i in 0..TAG_LEN {
        want[i] ^= s0[i];
    }
    if !constant_time_eq(&want, &ciphertext[n..]) {
        return Err(ProtoError::Crypto("AES-CCM tag mismatch"));
    }
    Ok(plain)
}

fn validate_ccm_nonce(nonce: &[u8]) -> ProtoResult<()> {
    if !(7..=13).contains(&nonce.len()) {
        return Err(ProtoError::Crypto("invalid AES-CCM nonce length"));
    }
    Ok(())
}

fn ccm_mac<C: BlockEncrypt>(cipher: &C, nonce: &[u8], plaintext: &[u8], aad: &[u8]) -> [u8; 16] {
    let mut y = [0u8; 16];
    let mut b = [0u8; 16];
    b[0] = 0x40 | (((TAG_LEN - 2) / 2) as u8) << 3 | ((15 - nonce.len() - 1) as u8);
    b[1..1 + nonce.len()].copy_from_slice(nonce);
    put_length(
        &mut b[1 + nonce.len()..],
        plaintext.len() as u64,
        15 - nonce.len(),
    );
    xor_block(&mut y, &b);
    encrypt_block(cipher, &mut y);
    if !aad.is_empty() {
        let mut a = Vec::with_capacity(2 + aad.len());
        a.extend_from_slice(&(aad.len() as u16).to_be_bytes());
        a.extend_from_slice(aad);
        ccm_mac_blocks(cipher, &mut y, &a);
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
        encrypt_block(cipher, y);
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
        counter_block(&mut stream, nonce, counter);
        encrypt_block(cipher, &mut stream);
        let n = src.len().min(16);
        for i in 0..n {
            dst[i] = src[i] ^ stream[i];
        }
        dst = &mut dst[n..];
        src = &src[n..];
        counter += 1;
    }
}

fn counter_block(dst: &mut [u8], nonce: &[u8], counter: u64) {
    let q = 15 - nonce.len();
    dst.fill(0);
    dst[0] = (q - 1) as u8;
    dst[1..1 + nonce.len()].copy_from_slice(nonce);
    put_length(&mut dst[1 + nonce.len()..], counter, q);
}

fn put_length(dst: &mut [u8], mut value: u64, n: usize) {
    for i in (0..n).rev() {
        dst[i] = value as u8;
        value >>= 8;
    }
}

fn encrypt_block<C: BlockEncrypt>(cipher: &C, block: &mut [u8; 16]) {
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

#[cfg(test)]
mod tests {
    use super::*;

    const KEY_128: &[u8] = b"0123456789abcdef";
    const KEY_256: &[u8] = b"0123456789abcdef0123456789abcdef";
    const PLAIN: &[u8] = &[0xFE, b'S', b'M', b'B', 1, 2, 3, 4];

    #[test]
    fn encrypt_decrypt_ccm_transform() {
        let encrypted = encrypt_ccm(KEY_128, 42, PLAIN).expect("encrypt");

        assert_eq!(&encrypted[..4], &ENCRYPTION_MAGIC);
        assert_eq!(decrypt_ccm(KEY_128, &encrypted).expect("decrypt"), PLAIN);

        let mut tampered = encrypted;
        let last = tampered.len() - 1;
        tampered[last] ^= 0xFF;
        assert!(decrypt_ccm(KEY_128, &tampered).is_err());
    }

    #[test]
    fn encrypt_decrypt_ccm_transform_aes256_key() {
        let encrypted = encrypt_ccm(KEY_256, 42, PLAIN).expect("encrypt");
        assert_eq!(decrypt_ccm(KEY_256, &encrypted).expect("decrypt"), PLAIN);
    }

    #[test]
    fn encrypt_decrypt_gcm_transform() {
        let encrypted = encrypt_gcm(KEY_128, 42, PLAIN).expect("encrypt");

        assert_eq!(&encrypted[..4], &ENCRYPTION_MAGIC);
        assert_eq!(
            u16::from_le_bytes([encrypted[FLAGS_OFFSET], encrypted[FLAGS_OFFSET + 1]]),
            TRANSFORM_FLAG_ENCRYPTED
        );
        assert_eq!(&encrypted[32..36], &[0, 0, 0, 0]);
        assert_eq!(decrypt_gcm(KEY_128, &encrypted).expect("decrypt"), PLAIN);

        let mut tampered = encrypted;
        let last = tampered.len() - 1;
        tampered[last] ^= 0xFF;
        assert!(decrypt_gcm(KEY_128, &tampered).is_err());
    }

    #[test]
    fn encrypt_decrypt_gcm_transform_aes256_key() {
        let encrypted = encrypt_gcm(KEY_256, 42, PLAIN).expect("encrypt");
        assert_eq!(decrypt_gcm(KEY_256, &encrypted).expect("decrypt"), PLAIN);
    }

    #[test]
    fn gcm_rejects_ccm_transform() {
        let encrypted = encrypt_ccm(KEY_128, 42, b"hello").expect("encrypt");
        assert!(decrypt_gcm(KEY_128, &encrypted).is_err());
    }

    #[test]
    fn encryption_key_311_aes256_length() {
        let session_key = b"0123456789abcdef";
        let preauth = [0u8; 64];

        assert_eq!(encryption_key_311_c2s(session_key, &preauth).len(), 16);
        assert_eq!(encryption_key_311_s2c(session_key, &preauth).len(), 16);
        assert_eq!(encryption_key_311_c2s_256(session_key, &preauth).len(), 32);
        assert_eq!(encryption_key_311_s2c_256(session_key, &preauth).len(), 32);
    }

    #[test]
    fn deterministic_nonce_gcm_round_trip_matches_transform_layout() {
        let nonce = [7u8; GCM_NONCE_LEN];
        let encrypted = encrypt_gcm_with_nonce(KEY_128, 0x1122, PLAIN, &nonce).expect("encrypt");

        assert_eq!(
            &encrypted[NONCE_OFFSET..NONCE_OFFSET + GCM_NONCE_LEN],
            &nonce
        );
        assert_eq!(
            u64::from_le_bytes(
                encrypted[SESSION_ID_OFFSET..SESSION_ID_OFFSET + 8]
                    .try_into()
                    .unwrap()
            ),
            0x1122
        );
        assert_eq!(decrypt_gcm(KEY_128, &encrypted).expect("decrypt"), PLAIN);
    }
}
