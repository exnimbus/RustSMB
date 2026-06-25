//! SESSION_SETUP Request/Response (MS-SMB2 §2.2.5 / §2.2.6).

use binrw::{BinWrite, binrw};
use std::io::Cursor;

use crate::proto::error::{ProtoError, ProtoResult};

/// SMB2_SESSION_SETUP_REQUEST (MS-SMB2 §2.2.5).
///
/// `security_buffer` is opaque GSS-API/SPNEGO data — the auth agent decodes it.
/// The wire offset is from the start of the SMB2 header; we encode/decode it
/// as length-counted data immediately following the fixed prefix, which is
/// the canonical layout. Server crate may patch the offset if it needs an
/// unusual layout.
#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionSetupRequest {
    pub structure_size: u16,
    pub flags: u8,
    pub security_mode: u8,
    pub capabilities: u32,
    pub channel: u32,
    pub security_buffer_offset: u16,
    pub security_buffer_length: u16,
    pub previous_session_id: u64,
    #[br(count = security_buffer_length as usize)]
    pub security_buffer: Vec<u8>,
}

impl SessionSetupRequest {
    /// Flag: SMB2_SESSION_FLAG_BINDING — bind to existing session (3.x).
    pub const FLAG_BINDING: u8 = 0x01;

    pub fn parse(buf: &[u8]) -> ProtoResult<Self> {
        if buf.len() < 24 {
            return Err(ProtoError::Malformed("session setup request too short"));
        }
        let structure_size = read_u16(buf, 0)?;
        if structure_size != 25 {
            return Err(ProtoError::Malformed(
                "session setup request structure_size != 25",
            ));
        }
        let security_buffer_offset = read_u16(buf, 12)?;
        let security_buffer_length = read_u16(buf, 14)?;
        let offset = (security_buffer_offset as usize)
            .checked_sub(crate::proto::header::SMB2_HEADER_LEN)
            .ok_or(ProtoError::Malformed(
                "session setup request security buffer offset before SMB2 body",
            ))?;
        let end =
            offset
                .checked_add(security_buffer_length as usize)
                .ok_or(ProtoError::Malformed(
                    "session setup request security buffer range overflow",
                ))?;
        if offset < 24 || end > buf.len() {
            return Err(ProtoError::Malformed(
                "session setup request security buffer out of range",
            ));
        }
        Ok(Self {
            structure_size,
            flags: buf[2],
            security_mode: buf[3],
            capabilities: read_u32(buf, 4)?,
            channel: read_u32(buf, 8)?,
            security_buffer_offset,
            security_buffer_length,
            previous_session_id: read_u64(buf, 16)?,
            security_buffer: buf[offset..end].to_vec(),
        })
    }
    pub fn write_to(&self, out: &mut Vec<u8>) -> ProtoResult<()> {
        let mut c = Cursor::new(Vec::new());
        BinWrite::write(self, &mut c)?;
        out.extend_from_slice(&c.into_inner());
        Ok(())
    }
}

/// SMB2_SESSION_SETUP_RESPONSE (MS-SMB2 §2.2.6).
#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionSetupResponse {
    pub structure_size: u16,
    pub session_flags: u16,
    pub security_buffer_offset: u16,
    pub security_buffer_length: u16,
    #[br(count = security_buffer_length as usize)]
    pub security_buffer: Vec<u8>,
}

impl SessionSetupResponse {
    /// Session flag: IS_GUEST.
    pub const FLAG_IS_GUEST: u16 = 0x0001;
    /// Session flag: IS_NULL (anonymous).
    pub const FLAG_IS_NULL: u16 = 0x0002;
    /// Session flag: ENCRYPT_DATA.
    pub const FLAG_ENCRYPT_DATA: u16 = 0x0004;

    pub fn parse(buf: &[u8]) -> ProtoResult<Self> {
        if buf.len() < 8 {
            return Err(ProtoError::Malformed("session setup response too short"));
        }
        let structure_size = read_u16(buf, 0)?;
        if structure_size != 9 {
            return Err(ProtoError::Malformed(
                "session setup response structure_size != 9",
            ));
        }
        let security_buffer_offset = read_u16(buf, 4)?;
        let security_buffer_length = read_u16(buf, 6)?;
        let offset = (security_buffer_offset as usize)
            .checked_sub(crate::proto::header::SMB2_HEADER_LEN)
            .ok_or(ProtoError::Malformed(
                "session setup response security buffer offset before SMB2 body",
            ))?;
        let end =
            offset
                .checked_add(security_buffer_length as usize)
                .ok_or(ProtoError::Malformed(
                    "session setup response security buffer range overflow",
                ))?;
        if offset < 8 || end > buf.len() {
            return Err(ProtoError::Malformed(
                "session setup response security buffer out of range",
            ));
        }
        Ok(Self {
            structure_size,
            session_flags: read_u16(buf, 2)?,
            security_buffer_offset,
            security_buffer_length,
            security_buffer: buf[offset..end].to_vec(),
        })
    }
    pub fn write_to(&self, out: &mut Vec<u8>) -> ProtoResult<()> {
        let mut c = Cursor::new(Vec::new());
        BinWrite::write(self, &mut c)?;
        out.extend_from_slice(&c.into_inner());
        Ok(())
    }
}

fn read_u16(buf: &[u8], offset: usize) -> ProtoResult<u16> {
    let bytes = buf
        .get(offset..offset + 2)
        .ok_or(ProtoError::Malformed("session setup u16 out of range"))?;
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn read_u32(buf: &[u8], offset: usize) -> ProtoResult<u32> {
    let bytes = buf
        .get(offset..offset + 4)
        .ok_or(ProtoError::Malformed("session setup u32 out of range"))?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn read_u64(buf: &[u8], offset: usize) -> ProtoResult<u64> {
    let bytes = buf
        .get(offset..offset + 8)
        .ok_or(ProtoError::Malformed("session setup u64 out of range"))?;
    Ok(u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_round_trips() {
        let r = SessionSetupRequest {
            structure_size: 25,
            flags: 0,
            security_mode: 0x01,
            capabilities: 0x01,
            channel: 0,
            security_buffer_offset: 0x58,
            security_buffer_length: 6,
            previous_session_id: 0,
            security_buffer: vec![0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02],
        };
        let mut buf = Vec::new();
        r.write_to(&mut buf).unwrap();
        assert_eq!(SessionSetupRequest::parse(&buf).unwrap(), r);
    }

    #[test]
    fn request_decodes_padded_security_buffer_from_header_relative_offset() {
        let mut buf = vec![0; 32];
        buf[0..2].copy_from_slice(&25u16.to_le_bytes());
        buf[2] = SessionSetupRequest::FLAG_BINDING;
        buf[3] = 0x02;
        buf[4..8].copy_from_slice(&0x1234_5678u32.to_le_bytes());
        buf[8..12].copy_from_slice(&7u32.to_le_bytes());
        buf[12..14]
            .copy_from_slice(&(crate::proto::header::SMB2_HEADER_LEN as u16 + 28).to_le_bytes());
        buf[14..16].copy_from_slice(&4u16.to_le_bytes());
        buf[16..24].copy_from_slice(&99u64.to_le_bytes());
        buf[28..32].copy_from_slice(&[1, 2, 3, 4]);

        let decoded = SessionSetupRequest::parse(&buf).unwrap();

        assert_eq!(decoded.flags, SessionSetupRequest::FLAG_BINDING);
        assert_eq!(decoded.security_mode, 0x02);
        assert_eq!(decoded.capabilities, 0x1234_5678);
        assert_eq!(decoded.channel, 7);
        assert_eq!(decoded.previous_session_id, 99);
        assert_eq!(decoded.security_buffer, [1, 2, 3, 4]);
    }

    #[test]
    fn request_decodes_canonical_gosmb_security_buffer_fixture() {
        let mut buf = vec![0; 29];
        buf[0..2].copy_from_slice(&25u16.to_le_bytes());
        buf[2] = SessionSetupRequest::FLAG_BINDING;
        buf[3] = 0x02;
        buf[4..8].copy_from_slice(&(0x0000_0001u32 | 0x0000_0002u32).to_le_bytes());
        buf[8..12].copy_from_slice(&7u32.to_le_bytes());
        buf[12..14]
            .copy_from_slice(&(crate::proto::header::SMB2_HEADER_LEN as u16 + 24).to_le_bytes());
        buf[14..16].copy_from_slice(&5u16.to_le_bytes());
        buf[16..24].copy_from_slice(&99u64.to_le_bytes());
        buf[24..29].copy_from_slice(b"token");

        let decoded = SessionSetupRequest::parse(&buf).unwrap();

        assert_eq!(decoded.flags, SessionSetupRequest::FLAG_BINDING);
        assert_eq!(decoded.security_mode, 0x02);
        assert_eq!(decoded.capabilities, 0x0000_0001 | 0x0000_0002);
        assert_eq!(decoded.channel, 7);
        assert_eq!(decoded.previous_session_id, 99);
        assert_eq!(decoded.security_buffer, b"token");
    }

    #[test]
    fn request_rejects_wrong_structure_size() {
        let mut buf = vec![0; 24];
        buf[0..2].copy_from_slice(&24u16.to_le_bytes());
        buf[12..14]
            .copy_from_slice(&(crate::proto::header::SMB2_HEADER_LEN as u16 + 24).to_le_bytes());

        assert!(matches!(
            SessionSetupRequest::parse(&buf),
            Err(ProtoError::Malformed(_))
        ));
    }

    #[test]
    fn request_rejects_security_buffer_before_body() {
        let mut buf = vec![0; 24];
        buf[0..2].copy_from_slice(&25u16.to_le_bytes());
        buf[12..14]
            .copy_from_slice(&(crate::proto::header::SMB2_HEADER_LEN as u16 + 16).to_le_bytes());

        assert!(matches!(
            SessionSetupRequest::parse(&buf),
            Err(ProtoError::Malformed(_))
        ));
    }

    #[test]
    fn request_rejects_security_buffer_out_of_range() {
        let mut buf = vec![0; 24];
        buf[0..2].copy_from_slice(&25u16.to_le_bytes());
        buf[12..14]
            .copy_from_slice(&(crate::proto::header::SMB2_HEADER_LEN as u16 + 24).to_le_bytes());
        buf[14..16].copy_from_slice(&1u16.to_le_bytes());

        assert!(matches!(
            SessionSetupRequest::parse(&buf),
            Err(ProtoError::Malformed(_))
        ));
    }

    #[test]
    fn response_round_trips() {
        let r = SessionSetupResponse {
            structure_size: 9,
            session_flags: SessionSetupResponse::FLAG_IS_GUEST,
            security_buffer_offset: 0x48,
            security_buffer_length: 4,
            security_buffer: vec![1, 2, 3, 4],
        };
        let mut buf = Vec::new();
        r.write_to(&mut buf).unwrap();
        assert_eq!(SessionSetupResponse::parse(&buf).unwrap(), r);
    }

    #[test]
    fn response_decodes_padded_security_buffer_from_header_relative_offset() {
        let mut buf = vec![0; 16];
        buf[0..2].copy_from_slice(&9u16.to_le_bytes());
        buf[2..4].copy_from_slice(&SessionSetupResponse::FLAG_IS_NULL.to_le_bytes());
        buf[4..6]
            .copy_from_slice(&(crate::proto::header::SMB2_HEADER_LEN as u16 + 12).to_le_bytes());
        buf[6..8].copy_from_slice(&4u16.to_le_bytes());
        buf[12..16].copy_from_slice(&[5, 6, 7, 8]);

        let decoded = SessionSetupResponse::parse(&buf).unwrap();

        assert_eq!(decoded.session_flags, SessionSetupResponse::FLAG_IS_NULL);
        assert_eq!(decoded.security_buffer, [5, 6, 7, 8]);
    }

    #[test]
    fn response_accepts_empty_security_buffer_at_fixed_prefix_end() {
        let r = SessionSetupResponse {
            structure_size: 9,
            session_flags: 0,
            security_buffer_offset: crate::proto::header::SMB2_HEADER_LEN as u16 + 8,
            security_buffer_length: 0,
            security_buffer: Vec::new(),
        };
        let mut buf = Vec::new();
        r.write_to(&mut buf).unwrap();

        assert_eq!(buf.len(), 8);
        assert_eq!(SessionSetupResponse::parse(&buf).unwrap(), r);
    }

    #[test]
    fn response_rejects_wrong_structure_size() {
        let mut buf = vec![0; 8];
        buf[0..2].copy_from_slice(&8u16.to_le_bytes());
        buf[4..6]
            .copy_from_slice(&(crate::proto::header::SMB2_HEADER_LEN as u16 + 8).to_le_bytes());

        assert!(matches!(
            SessionSetupResponse::parse(&buf),
            Err(ProtoError::Malformed(_))
        ));
    }

    #[test]
    fn response_rejects_security_buffer_out_of_range() {
        let mut buf = vec![0; 8];
        buf[0..2].copy_from_slice(&9u16.to_le_bytes());
        buf[4..6]
            .copy_from_slice(&(crate::proto::header::SMB2_HEADER_LEN as u16 + 8).to_le_bytes());
        buf[6..8].copy_from_slice(&1u16.to_le_bytes());

        assert!(matches!(
            SessionSetupResponse::parse(&buf),
            Err(ProtoError::Malformed(_))
        ));
    }
}
