//! NEGOTIATE Request/Response (MS-SMB2 §2.2.3 / §2.2.4) including the SMB
//! 3.1.1 negotiate-context machinery from §2.2.3.1.x and §2.2.4.x.

use binrw::{BinWrite, binrw};
use std::io::Cursor;

use crate::proto::error::{ProtoError, ProtoResult};

const NEGOTIATE_REQUEST_FIXED_LEN: usize = 36;
const NEGOTIATE_RESPONSE_FIXED_LEN: usize = 64;

// ---------------------------------------------------------------------------
// Dialect
// ---------------------------------------------------------------------------

/// SMB2 dialect revision codes (MS-SMB2 §2.2.3 — DialectRevision).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum Dialect {
    Smb202 = 0x0202,
    Smb210 = 0x0210,
    Smb300 = 0x0300,
    Smb302 = 0x0302,
    Smb311 = 0x0311,
    /// Sent by SMB 2.0.2/2.1 clients via SMB1 negotiate; we accept it as a
    /// signal to multi-protocol-negotiate. Value 0x02FF.
    Smb2Wildcard = 0x02FF,
}

impl Dialect {
    pub fn from_u16(v: u16) -> Option<Self> {
        Some(match v {
            0x0202 => Self::Smb202,
            0x0210 => Self::Smb210,
            0x0300 => Self::Smb300,
            0x0302 => Self::Smb302,
            0x0311 => Self::Smb311,
            0x02FF => Self::Smb2Wildcard,
            _ => return None,
        })
    }

    pub const fn as_u16(self) -> u16 {
        self as u16
    }
}

// ---------------------------------------------------------------------------
// Negotiate request
// ---------------------------------------------------------------------------

/// MS-SMB2 §2.2.3 NEGOTIATE Request.
///
/// `dialects` is a sequence of u16 little-endian dialect codes; for SMB 3.1.1
/// the trailing `negotiate_context_list` carries variable-length contexts at
/// `negotiate_context_offset`.
///
/// Note on parsing: we validate the trailing `negotiate_context_list` when the
/// context count is nonzero, because its position is given by an absolute
/// offset from the start of the SMB2 header. The server handler still owns
/// typed interpretation of those contexts via [`NegotiateContext::parse_list`].
#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NegotiateRequest {
    pub structure_size: u16,
    pub dialect_count: u16,
    pub security_mode: u16,
    pub reserved: u16,
    pub capabilities: u32,
    pub client_guid: [u8; 16],
    /// 3.1.1: NegotiateContextOffset. 2.x/3.0/3.0.2: ClientStartTime.
    pub negotiate_context_offset_or_client_start_time: u64,
    #[br(count = dialect_count as usize)]
    pub dialects: Vec<u16>,
}

impl NegotiateRequest {
    pub fn parse(buf: &[u8]) -> ProtoResult<Self> {
        if buf.len() < NEGOTIATE_REQUEST_FIXED_LEN {
            return Err(ProtoError::Malformed("negotiate request too short"));
        }
        let structure_size = read_u16(buf, 0)?;
        if structure_size != 36 {
            return Err(ProtoError::Malformed(
                "negotiate request structure_size != 36",
            ));
        }
        let dialect_count = read_u16(buf, 2)?;
        let dialect_bytes = (dialect_count as usize)
            .checked_mul(2)
            .ok_or(ProtoError::Malformed("negotiate request dialect overflow"))?;
        let dialects_end = NEGOTIATE_REQUEST_FIXED_LEN
            .checked_add(dialect_bytes)
            .ok_or(ProtoError::Malformed("negotiate request dialect overflow"))?;
        if dialects_end > buf.len() {
            return Err(ProtoError::Malformed(
                "negotiate request dialects truncated",
            ));
        }

        let security_mode = read_u16(buf, 4)?;
        let reserved = read_u16(buf, 6)?;
        let capabilities = read_u32(buf, 8)?;
        let mut client_guid = [0u8; 16];
        client_guid.copy_from_slice(&buf[12..28]);
        let negotiate_context_offset_or_client_start_time = read_u64(buf, 28)?;
        let context_offset = (negotiate_context_offset_or_client_start_time & 0xFFFF_FFFF) as usize;
        let context_count = ((negotiate_context_offset_or_client_start_time >> 32) & 0xFFFF) as u16;
        if context_count > 0 {
            let body_offset = context_offset
                .checked_sub(crate::proto::header::SMB2_HEADER_LEN)
                .ok_or(ProtoError::Malformed(
                    "negotiate request context offset before SMB2 body",
                ))?;
            if body_offset < NEGOTIATE_REQUEST_FIXED_LEN || body_offset > buf.len() {
                return Err(ProtoError::Malformed(
                    "negotiate request context offset out of range",
                ));
            }
            NegotiateContext::parse_list(&buf[body_offset..], context_count)?;
        }

        let mut dialects = Vec::with_capacity(dialect_count as usize);
        for i in 0..dialect_count as usize {
            dialects.push(read_u16(buf, NEGOTIATE_REQUEST_FIXED_LEN + i * 2)?);
        }
        Ok(Self {
            structure_size,
            dialect_count,
            security_mode,
            reserved,
            capabilities,
            client_guid,
            negotiate_context_offset_or_client_start_time,
            dialects,
        })
    }
    pub fn write_to(&self, out: &mut Vec<u8>) -> ProtoResult<()> {
        let mut c = Cursor::new(Vec::new());
        BinWrite::write(self, &mut c)?;
        out.extend_from_slice(&c.into_inner());
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Negotiate response
// ---------------------------------------------------------------------------

/// MS-SMB2 §2.2.4 NEGOTIATE Response.
///
/// The trailing `security_buffer` and (3.1.1) `negotiate_context_list` are
/// referenced by absolute offsets from the start of the SMB2 header. This
/// struct encodes the *fixed* portion plus a `security_buffer` that we treat
/// as a length-counted blob immediately following the fixed portion (the
/// common server layout). For 3.1.1 contexts, the server crate writes the
/// fixed portion via [`NegotiateResponse::write_to`], then appends 8-byte-
/// aligned negotiate contexts and patches `negotiate_context_offset` to the
/// post-padding offset.
#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NegotiateResponse {
    pub structure_size: u16,
    pub security_mode: u16,
    pub dialect_revision: u16,
    /// 3.1.1: NegotiateContextCount. 2.x/3.0/3.0.2: Reserved.
    pub negotiate_context_count_or_reserved: u16,
    pub server_guid: [u8; 16],
    pub capabilities: u32,
    pub max_transact_size: u32,
    pub max_read_size: u32,
    pub max_write_size: u32,
    /// 100ns ticks since 1601-01-01 UTC.
    pub system_time: u64,
    pub server_start_time: u64,
    pub security_buffer_offset: u16,
    pub security_buffer_length: u16,
    /// 3.1.1: NegotiateContextOffset. 2.x/3.0/3.0.2: Reserved2.
    pub negotiate_context_offset_or_reserved2: u32,
    #[br(count = security_buffer_length as usize)]
    pub security_buffer: Vec<u8>,
}

impl NegotiateResponse {
    pub fn parse(buf: &[u8]) -> ProtoResult<Self> {
        if buf.len() < NEGOTIATE_RESPONSE_FIXED_LEN {
            return Err(ProtoError::Malformed("negotiate response too short"));
        }
        let structure_size = read_u16(buf, 0)?;
        if structure_size != 65 {
            return Err(ProtoError::Malformed(
                "negotiate response structure_size != 65",
            ));
        }

        let security_buffer_offset = read_u16(buf, 56)?;
        let security_buffer_length = read_u16(buf, 58)?;
        let negotiate_context_count_or_reserved = read_u16(buf, 6)?;
        let negotiate_context_offset_or_reserved2 = read_u32(buf, 60)?;

        let security_buffer = if security_buffer_length == 0 {
            Vec::new()
        } else {
            let offset = (security_buffer_offset as usize)
                .checked_sub(crate::proto::header::SMB2_HEADER_LEN)
                .ok_or(ProtoError::Malformed(
                    "negotiate response security buffer offset before SMB2 body",
                ))?;
            let end = offset.checked_add(security_buffer_length as usize).ok_or(
                ProtoError::Malformed("negotiate response security buffer range overflow"),
            )?;
            if offset < NEGOTIATE_RESPONSE_FIXED_LEN || end > buf.len() {
                return Err(ProtoError::Malformed(
                    "negotiate response security buffer out of range",
                ));
            }
            buf[offset..end].to_vec()
        };

        if negotiate_context_count_or_reserved > 0 {
            let body_offset = (negotiate_context_offset_or_reserved2 as usize)
                .checked_sub(crate::proto::header::SMB2_HEADER_LEN)
                .ok_or(ProtoError::Malformed(
                    "negotiate response context offset before SMB2 body",
                ))?;
            if body_offset < NEGOTIATE_RESPONSE_FIXED_LEN || body_offset > buf.len() {
                return Err(ProtoError::Malformed(
                    "negotiate response context offset out of range",
                ));
            }
            NegotiateContext::parse_list(&buf[body_offset..], negotiate_context_count_or_reserved)?;
        }

        Ok(Self {
            structure_size,
            security_mode: read_u16(buf, 2)?,
            dialect_revision: read_u16(buf, 4)?,
            negotiate_context_count_or_reserved,
            server_guid: {
                let mut guid = [0u8; 16];
                guid.copy_from_slice(&buf[8..24]);
                guid
            },
            capabilities: read_u32(buf, 24)?,
            max_transact_size: read_u32(buf, 28)?,
            max_read_size: read_u32(buf, 32)?,
            max_write_size: read_u32(buf, 36)?,
            system_time: read_u64(buf, 40)?,
            server_start_time: read_u64(buf, 48)?,
            security_buffer_offset,
            security_buffer_length,
            negotiate_context_offset_or_reserved2,
            security_buffer,
        })
    }
    pub fn write_to(&self, out: &mut Vec<u8>) -> ProtoResult<()> {
        let mut c = Cursor::new(Vec::new());
        BinWrite::write(self, &mut c)?;
        out.extend_from_slice(&c.into_inner());
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Negotiate contexts (SMB 3.1.1)
// ---------------------------------------------------------------------------

/// MS-SMB2 §2.2.3.1 / §2.2.4.x — NEGOTIATE_CONTEXT generic header.
///
/// Contexts are 8-byte-aligned in the chain (the trailing padding is between
/// contexts; see §2.2.3.1 "Each NEGOTIATE_CONTEXT MUST be 8-byte aligned").
/// `parse_list` / `encode_list` handle the alignment.
#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NegotiateContext {
    pub context_type: u16,
    pub data_length: u16,
    pub reserved: u32,
    #[br(count = data_length as usize)]
    pub data: Vec<u8>,
}

impl NegotiateContext {
    pub const TYPE_PREAUTH_INTEGRITY: u16 = 0x0001;
    pub const TYPE_ENCRYPTION: u16 = 0x0002;
    pub const TYPE_COMPRESSION: u16 = 0x0003;
    pub const TYPE_NETNAME_NEGOTIATE: u16 = 0x0005;
    pub const TYPE_TRANSPORT_CAPS: u16 = 0x0006;
    pub const TYPE_RDMA_TRANSFORM: u16 = 0x0007;
    pub const TYPE_SIGNING: u16 = 0x0008;
    pub const TYPE_POSIX: u16 = 0x0100;
    pub const TRANSPORT_CAP_ACCEPT_TRANSPORT_SECURITY: u32 = 0x0000_0001;
    pub const POSIX_EXTENSIONS_GUID: [u8; 16] = [
        0x93, 0xAD, 0x25, 0x50, 0x9C, 0xB4, 0x11, 0xE7, 0xB4, 0x23, 0x83, 0xDE, 0x96, 0x8B, 0xCD,
        0x7C,
    ];

    /// Parse a chain of negotiate contexts from `buf`. The chain is a series
    /// of (8-byte-aligned) [`NegotiateContext`] entries. `count` comes from
    /// the parent message's `NegotiateContextCount`.
    pub fn parse_list(buf: &[u8], count: u16) -> ProtoResult<Vec<NegotiateContext>> {
        let mut out = Vec::with_capacity(count as usize);
        let mut offset = 0usize;
        for _ in 0..count {
            // Pad to 8-byte alignment relative to the start of the list.
            let pad = (8 - (offset % 8)) % 8;
            offset = offset.checked_add(pad).ok_or(ProtoError::Malformed(
                "negotiate context alignment overflow",
            ))?;
            if offset
                .checked_add(8)
                .is_none_or(|header_end| header_end > buf.len())
            {
                return Err(ProtoError::Malformed("negotiate context too short"));
            }
            let context_type = read_u16(buf, offset)?;
            let data_length = read_u16(buf, offset + 2)?;
            let reserved = read_u32(buf, offset + 4)?;
            let data_start = offset + 8;
            let data_end = data_start
                .checked_add(data_length as usize)
                .ok_or(ProtoError::Malformed("negotiate context data overflow"))?;
            if data_end > buf.len() {
                return Err(ProtoError::Malformed("negotiate context data truncated"));
            }
            out.push(NegotiateContext {
                context_type,
                data_length,
                reserved,
                data: buf[data_start..data_end].to_vec(),
            });
            offset = data_end;
        }
        Ok(out)
    }

    /// Encode a chain of negotiate contexts into `out`, inserting 8-byte
    /// padding between entries.
    pub fn encode_list(list: &[NegotiateContext], out: &mut Vec<u8>) -> ProtoResult<()> {
        let start = out.len();
        for (i, ctx) in list.iter().enumerate() {
            if i > 0 {
                let pad = (8 - ((out.len() - start) % 8)) % 8;
                out.extend(std::iter::repeat_n(0u8, pad));
            }
            let mut c = Cursor::new(Vec::new());
            BinWrite::write(ctx, &mut c)?;
            out.extend_from_slice(&c.into_inner());
        }
        Ok(())
    }
}

/// Parsed payload of a known [`NegotiateContext`] type. Convenience wrapper —
/// the wire form is always [`NegotiateContext`]; this enum is for callers who
/// prefer typed access.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NegotiateContextData {
    PreauthIntegrity(PreauthIntegrityCapabilities),
    Encryption(EncryptionCapabilities),
    Compression(CompressionCapabilities),
    RdmaTransform(RdmaTransformCapabilities),
    Signing(SigningCapabilities),
    /// Unknown / unhandled context — preserve raw bytes for round-tripping.
    Other {
        context_type: u16,
        data: Vec<u8>,
    },
}

/// MS-SMB2 §2.2.3.1.1 / §2.2.4.1 SMB2_PREAUTH_INTEGRITY_CAPABILITIES.
#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreauthIntegrityCapabilities {
    pub hash_algorithm_count: u16,
    pub salt_length: u16,
    #[br(count = hash_algorithm_count as usize)]
    pub hash_algorithms: Vec<u16>,
    #[br(count = salt_length as usize)]
    pub salt: Vec<u8>,
}

impl PreauthIntegrityCapabilities {
    /// Hash algorithm: SHA-512 (the only one defined in MS-SMB2 §2.2.3.1.1).
    pub const HASH_SHA512: u16 = 0x0001;
}

/// MS-SMB2 §2.2.3.1.2 / §2.2.4.2 SMB2_ENCRYPTION_CAPABILITIES.
#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptionCapabilities {
    pub cipher_count: u16,
    #[br(count = cipher_count as usize)]
    pub ciphers: Vec<u16>,
}

impl EncryptionCapabilities {
    pub const CIPHER_AES_128_CCM: u16 = 0x0001;
    pub const CIPHER_AES_128_GCM: u16 = 0x0002;
    pub const CIPHER_AES_256_CCM: u16 = 0x0003;
    pub const CIPHER_AES_256_GCM: u16 = 0x0004;
}

/// MS-SMB2 §2.2.3.1.3 / §2.2.4.3 SMB2_COMPRESSION_CAPABILITIES.
#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompressionCapabilities {
    pub compression_algorithm_count: u16,
    pub padding: u16,
    pub flags: u32,
    #[br(count = compression_algorithm_count as usize)]
    pub compression_algorithms: Vec<u16>,
}

impl CompressionCapabilities {
    pub const FLAG_CHAINED: u32 = 0x0000_0001;

    pub const ALGORITHM_NONE: u16 = 0x0000;
    pub const ALGORITHM_LZNT1: u16 = 0x0001;
    pub const ALGORITHM_LZ77: u16 = 0x0002;
    pub const ALGORITHM_LZ77_HUFFMAN: u16 = 0x0003;
    pub const ALGORITHM_PATTERN_V1: u16 = 0x0004;
    pub const ALGORITHM_LZ4: u16 = 0x0005;
}

/// MS-SMB2 §2.2.3.1.6 SMB2_RDMA_TRANSFORM_CAPABILITIES.
#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RdmaTransformCapabilities {
    pub transform_count: u16,
    pub reserved1: u16,
    pub reserved2: u32,
    #[br(count = transform_count as usize)]
    pub rdma_transform_ids: Vec<u16>,
}

impl RdmaTransformCapabilities {
    pub const TRANSFORM_NONE: u16 = 0x0000;
    pub const TRANSFORM_ENCRYPTION: u16 = 0x0001;
    pub const TRANSFORM_SIGNING: u16 = 0x0002;
}

/// MS-SMB2 §2.2.3.1.7 / §2.2.4.7 SMB2_SIGNING_CAPABILITIES.
#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SigningCapabilities {
    pub signing_algorithm_count: u16,
    #[br(count = signing_algorithm_count as usize)]
    pub signing_algorithms: Vec<u16>,
}

impl SigningCapabilities {
    pub const ALGORITHM_HMAC_SHA256: u16 = 0x0000;
    pub const ALGORITHM_AES_CMAC: u16 = 0x0001;
    pub const ALGORITHM_AES_GMAC: u16 = 0x0002;
}

fn read_u16(buf: &[u8], offset: usize) -> ProtoResult<u16> {
    let bytes = buf
        .get(offset..offset + 2)
        .ok_or(ProtoError::Malformed("negotiate u16 out of range"))?;
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn read_u32(buf: &[u8], offset: usize) -> ProtoResult<u32> {
    let bytes = buf
        .get(offset..offset + 4)
        .ok_or(ProtoError::Malformed("negotiate u32 out of range"))?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn read_u64(buf: &[u8], offset: usize) -> ProtoResult<u64> {
    let bytes = buf
        .get(offset..offset + 8)
        .ok_or(ProtoError::Malformed("negotiate u64 out of range"))?;
    Ok(u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use binrw::BinRead;

    fn assert_malformed<T>(result: ProtoResult<T>) {
        assert!(matches!(result, Err(ProtoError::Malformed(_))));
    }

    fn signing_context() -> NegotiateContext {
        NegotiateContext {
            context_type: NegotiateContext::TYPE_SIGNING,
            data_length: 4,
            reserved: 0,
            data: vec![0x01, 0x00, 0x01, 0x00],
        }
    }

    #[test]
    fn negotiate_request_round_trips() {
        let req = NegotiateRequest {
            structure_size: 36,
            dialect_count: 5,
            security_mode: 0x0001, // signing enabled
            reserved: 0,
            capabilities: 0x0000_007F,
            client_guid: [0xAB; 16],
            negotiate_context_offset_or_client_start_time: 0,
            dialects: vec![0x0202, 0x0210, 0x0300, 0x0302, 0x0311],
        };
        let mut buf = Vec::new();
        req.write_to(&mut buf).unwrap();
        let decoded = NegotiateRequest::parse(&buf).unwrap();
        assert_eq!(decoded, req);
    }

    #[test]
    fn negotiate_request_with_contexts_round_trips() {
        let contexts = [signing_context()];
        let mut req = NegotiateRequest {
            structure_size: 36,
            dialect_count: 1,
            security_mode: 0x0001,
            reserved: 0,
            capabilities: 0,
            client_guid: [0xAB; 16],
            negotiate_context_offset_or_client_start_time: 0,
            dialects: vec![Dialect::Smb311.as_u16()],
        };
        let mut buf = Vec::new();
        req.write_to(&mut buf).unwrap();
        let context_offset = crate::proto::header::SMB2_HEADER_LEN + ((buf.len() + 7) & !7);
        req.negotiate_context_offset_or_client_start_time =
            context_offset as u64 | ((contexts.len() as u64) << 32);
        buf.clear();
        req.write_to(&mut buf).unwrap();
        buf.resize(context_offset - crate::proto::header::SMB2_HEADER_LEN, 0);
        NegotiateContext::encode_list(&contexts, &mut buf).unwrap();

        let decoded = NegotiateRequest::parse(&buf).unwrap();
        assert_eq!(decoded, req);
    }

    #[test]
    fn negotiate_request_rejects_wrong_structure_size() {
        let req = NegotiateRequest {
            structure_size: 36,
            dialect_count: 1,
            security_mode: 0x0001,
            reserved: 0,
            capabilities: 0,
            client_guid: [0xAB; 16],
            negotiate_context_offset_or_client_start_time: 0,
            dialects: vec![Dialect::Smb311.as_u16()],
        };
        let mut buf = Vec::new();
        req.write_to(&mut buf).unwrap();
        buf[0..2].copy_from_slice(&35u16.to_le_bytes());

        assert_malformed(NegotiateRequest::parse(&buf));
    }

    #[test]
    fn negotiate_request_rejects_truncated_dialects() {
        let req = NegotiateRequest {
            structure_size: 36,
            dialect_count: 2,
            security_mode: 0x0001,
            reserved: 0,
            capabilities: 0,
            client_guid: [0xAB; 16],
            negotiate_context_offset_or_client_start_time: 0,
            dialects: vec![Dialect::Smb302.as_u16(), Dialect::Smb311.as_u16()],
        };
        let mut buf = Vec::new();
        req.write_to(&mut buf).unwrap();
        buf.truncate(38);

        assert_malformed(NegotiateRequest::parse(&buf));
    }

    #[test]
    fn negotiate_request_rejects_context_offset_before_header() {
        let req = NegotiateRequest {
            structure_size: 36,
            dialect_count: 1,
            security_mode: 0x0001,
            reserved: 0,
            capabilities: 0,
            client_guid: [0xAB; 16],
            negotiate_context_offset_or_client_start_time: 63 | (1u64 << 32),
            dialects: vec![Dialect::Smb311.as_u16()],
        };
        let mut buf = Vec::new();
        req.write_to(&mut buf).unwrap();

        assert_malformed(NegotiateRequest::parse(&buf));
    }

    #[test]
    fn negotiate_response_round_trips() {
        let resp = NegotiateResponse {
            structure_size: 65,
            security_mode: 0x0003,
            dialect_revision: Dialect::Smb311.as_u16(),
            negotiate_context_count_or_reserved: 0,
            server_guid: [0xCD; 16],
            capabilities: 0x0000_007F,
            max_transact_size: 0x0010_0000,
            max_read_size: 0x0010_0000,
            max_write_size: 0x0010_0000,
            system_time: 0x01D9_1234_5678_9ABC,
            server_start_time: 0,
            security_buffer_offset: 0x80,
            security_buffer_length: 8,
            negotiate_context_offset_or_reserved2: 0,
            security_buffer: vec![1, 2, 3, 4, 5, 6, 7, 8],
        };
        let mut buf = Vec::new();
        resp.write_to(&mut buf).unwrap();
        let decoded = NegotiateResponse::parse(&buf).unwrap();
        assert_eq!(decoded, resp);
    }

    #[test]
    fn negotiate_response_with_contexts_round_trips() {
        let contexts = [signing_context()];
        let context_offset = 136u32;
        let resp = NegotiateResponse {
            structure_size: 65,
            security_mode: 0x0003,
            dialect_revision: Dialect::Smb311.as_u16(),
            negotiate_context_count_or_reserved: 1,
            server_guid: [0xCD; 16],
            capabilities: 0x0000_007F,
            max_transact_size: 0x0010_0000,
            max_read_size: 0x0010_0000,
            max_write_size: 0x0010_0000,
            system_time: 0x01D9_1234_5678_9ABC,
            server_start_time: 0,
            security_buffer_offset: 0x80,
            security_buffer_length: 3,
            negotiate_context_offset_or_reserved2: context_offset,
            security_buffer: vec![1, 2, 3],
        };
        let mut buf = Vec::new();
        resp.write_to(&mut buf).unwrap();
        buf.resize(
            context_offset as usize - crate::proto::header::SMB2_HEADER_LEN,
            0,
        );
        NegotiateContext::encode_list(&contexts, &mut buf).unwrap();

        let decoded = NegotiateResponse::parse(&buf).unwrap();
        assert_eq!(decoded, resp);
    }

    #[test]
    fn negotiate_response_rejects_wrong_structure_size() {
        let resp = NegotiateResponse {
            structure_size: 65,
            security_mode: 0x0003,
            dialect_revision: Dialect::Smb311.as_u16(),
            negotiate_context_count_or_reserved: 0,
            server_guid: [0xCD; 16],
            capabilities: 0x0000_007F,
            max_transact_size: 0x0010_0000,
            max_read_size: 0x0010_0000,
            max_write_size: 0x0010_0000,
            system_time: 0x01D9_1234_5678_9ABC,
            server_start_time: 0,
            security_buffer_offset: 0x80,
            security_buffer_length: 1,
            negotiate_context_offset_or_reserved2: 0,
            security_buffer: vec![1],
        };
        let mut buf = Vec::new();
        resp.write_to(&mut buf).unwrap();
        buf[0..2].copy_from_slice(&64u16.to_le_bytes());

        assert_malformed(NegotiateResponse::parse(&buf));
    }

    #[test]
    fn negotiate_response_rejects_security_buffer_out_of_range() {
        let resp = NegotiateResponse {
            structure_size: 65,
            security_mode: 0x0003,
            dialect_revision: Dialect::Smb311.as_u16(),
            negotiate_context_count_or_reserved: 0,
            server_guid: [0xCD; 16],
            capabilities: 0x0000_007F,
            max_transact_size: 0x0010_0000,
            max_read_size: 0x0010_0000,
            max_write_size: 0x0010_0000,
            system_time: 0x01D9_1234_5678_9ABC,
            server_start_time: 0,
            security_buffer_offset: 0x80,
            security_buffer_length: 4,
            negotiate_context_offset_or_reserved2: 0,
            security_buffer: vec![1, 2, 3, 4],
        };
        let mut buf = Vec::new();
        resp.write_to(&mut buf).unwrap();
        buf[56..58].copy_from_slice(&63u16.to_le_bytes());

        assert_malformed(NegotiateResponse::parse(&buf));
    }

    #[test]
    fn negotiate_response_rejects_truncated_contexts() {
        let resp = NegotiateResponse {
            structure_size: 65,
            security_mode: 0x0003,
            dialect_revision: Dialect::Smb311.as_u16(),
            negotiate_context_count_or_reserved: 1,
            server_guid: [0xCD; 16],
            capabilities: 0x0000_007F,
            max_transact_size: 0x0010_0000,
            max_read_size: 0x0010_0000,
            max_write_size: 0x0010_0000,
            system_time: 0x01D9_1234_5678_9ABC,
            server_start_time: 0,
            security_buffer_offset: 0,
            security_buffer_length: 0,
            negotiate_context_offset_or_reserved2: 0x80,
            security_buffer: vec![],
        };
        let mut buf = Vec::new();
        resp.write_to(&mut buf).unwrap();
        buf.extend_from_slice(&[0, 0, 0, 0]);

        assert_malformed(NegotiateResponse::parse(&buf));
    }

    #[test]
    fn negotiate_response_wildcard_has_no_contexts() {
        let resp = NegotiateResponse {
            structure_size: 65,
            security_mode: 0x0001,
            dialect_revision: Dialect::Smb2Wildcard.as_u16(),
            negotiate_context_count_or_reserved: 0,
            server_guid: [0xCD; 16],
            capabilities: 0,
            max_transact_size: 0,
            max_read_size: 0,
            max_write_size: 0,
            system_time: 0,
            server_start_time: 0,
            security_buffer_offset: 0,
            security_buffer_length: 0,
            negotiate_context_offset_or_reserved2: 0,
            security_buffer: vec![],
        };
        let mut buf = Vec::new();
        resp.write_to(&mut buf).unwrap();
        let decoded = NegotiateResponse::parse(&buf).unwrap();

        assert_eq!(decoded.dialect_revision, Dialect::Smb2Wildcard.as_u16());
        assert_eq!(decoded.negotiate_context_count_or_reserved, 0);
        assert_eq!(decoded.negotiate_context_offset_or_reserved2, 0);
    }

    #[test]
    fn dialect_round_trips() {
        for d in [
            Dialect::Smb202,
            Dialect::Smb210,
            Dialect::Smb300,
            Dialect::Smb302,
            Dialect::Smb311,
            Dialect::Smb2Wildcard,
        ] {
            assert_eq!(Dialect::from_u16(d.as_u16()), Some(d));
        }
        assert_eq!(Dialect::from_u16(0xBEEF), None);
    }

    #[test]
    fn preauth_caps_round_trips() {
        let p = PreauthIntegrityCapabilities {
            hash_algorithm_count: 1,
            salt_length: 32,
            hash_algorithms: vec![PreauthIntegrityCapabilities::HASH_SHA512],
            salt: vec![0xAA; 32],
        };
        let mut buf = Vec::new();
        let mut c = Cursor::new(&mut buf);
        BinWrite::write(&p, &mut c).unwrap();
        let decoded = PreauthIntegrityCapabilities::read(&mut Cursor::new(&buf)).unwrap();
        assert_eq!(decoded, p);
    }

    #[test]
    fn compression_caps_round_trips() {
        let caps = CompressionCapabilities {
            compression_algorithm_count: 2,
            padding: 0,
            flags: CompressionCapabilities::FLAG_CHAINED,
            compression_algorithms: vec![
                CompressionCapabilities::ALGORITHM_PATTERN_V1,
                CompressionCapabilities::ALGORITHM_LZ77,
            ],
        };
        let mut buf = Vec::new();
        let mut c = Cursor::new(&mut buf);
        BinWrite::write(&caps, &mut c).unwrap();
        let decoded = CompressionCapabilities::read(&mut Cursor::new(&buf)).unwrap();
        assert_eq!(decoded, caps);
    }

    #[test]
    fn rdma_transform_caps_round_trips() {
        let caps = RdmaTransformCapabilities {
            transform_count: 2,
            reserved1: 0,
            reserved2: 0,
            rdma_transform_ids: vec![
                RdmaTransformCapabilities::TRANSFORM_ENCRYPTION,
                RdmaTransformCapabilities::TRANSFORM_SIGNING,
            ],
        };
        let mut buf = Vec::new();
        let mut c = Cursor::new(&mut buf);
        BinWrite::write(&caps, &mut c).unwrap();
        let decoded = RdmaTransformCapabilities::read(&mut Cursor::new(&buf)).unwrap();
        assert_eq!(decoded, caps);
    }

    #[test]
    fn negotiate_context_list_round_trips() {
        let list = vec![
            NegotiateContext {
                context_type: NegotiateContext::TYPE_PREAUTH_INTEGRITY,
                data_length: 6,
                reserved: 0,
                data: vec![0x01, 0x00, 0x20, 0x00, 0x01, 0x00],
            },
            NegotiateContext {
                context_type: NegotiateContext::TYPE_ENCRYPTION,
                data_length: 4,
                reserved: 0,
                data: vec![0x02, 0x00, 0x02, 0x00],
            },
            NegotiateContext {
                context_type: NegotiateContext::TYPE_SIGNING,
                data_length: 4,
                reserved: 0,
                data: vec![0x01, 0x00, 0x01, 0x00],
            },
        ];
        let mut buf = Vec::new();
        NegotiateContext::encode_list(&list, &mut buf).unwrap();
        let parsed = NegotiateContext::parse_list(&buf, 3).unwrap();
        assert_eq!(parsed, list);
    }

    #[test]
    fn negotiate_context_list_rejects_truncated_entry() {
        let mut buf = Vec::new();
        NegotiateContext::encode_list(&[signing_context()], &mut buf).unwrap();
        buf.truncate(10);

        assert_malformed(NegotiateContext::parse_list(&buf, 1));
    }

    #[test]
    fn posix_negotiate_context_constant_matches_create_context_guid() {
        let ctx = NegotiateContext {
            context_type: NegotiateContext::TYPE_POSIX,
            data_length: NegotiateContext::POSIX_EXTENSIONS_GUID.len() as u16,
            reserved: 0,
            data: NegotiateContext::POSIX_EXTENSIONS_GUID.to_vec(),
        };
        let mut buf = Vec::new();
        NegotiateContext::encode_list(std::slice::from_ref(&ctx), &mut buf).unwrap();
        assert_eq!(&buf[0..2], &0x0100u16.to_le_bytes());
        assert_eq!(&buf[2..4], &16u16.to_le_bytes());
        assert_eq!(&buf[8..24], &NegotiateContext::POSIX_EXTENSIONS_GUID);
        assert_eq!(NegotiateContext::parse_list(&buf, 1).unwrap(), vec![ctx]);
    }
}
