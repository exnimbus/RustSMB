//! LOCK Request/Response (MS-SMB2 §2.2.26 / §2.2.27).

use binrw::{BinWrite, binrw};
use std::io::Cursor;

use super::create::FileId;
use crate::proto::error::{ProtoError, ProtoResult};

/// SMB2_LOCK_ELEMENT (MS-SMB2 §2.2.26.1) — exactly 24 bytes.
#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LockElement {
    pub offset: u64,
    pub length: u64,
    pub flags: u32,
    pub reserved: u32,
}

impl LockElement {
    pub const FLAG_SHARED_LOCK: u32 = 0x0000_0001;
    pub const FLAG_EXCLUSIVE_LOCK: u32 = 0x0000_0002;
    pub const FLAG_UNLOCK: u32 = 0x0000_0004;
    pub const FLAG_FAIL_IMMEDIATELY: u32 = 0x0000_0010;
}

#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LockRequest {
    pub structure_size: u16,
    pub lock_count: u16,
    pub lock_sequence: u32,
    pub file_id: FileId,
    #[br(count = lock_count as usize)]
    pub locks: Vec<LockElement>,
}

impl LockRequest {
    pub fn parse(buf: &[u8]) -> ProtoResult<Self> {
        if buf.len() < 48 {
            return Err(ProtoError::Malformed("lock request too short"));
        }
        let structure_size = read_u16(buf, 0)?;
        if structure_size != 48 {
            return Err(ProtoError::Malformed("lock request structure_size != 48"));
        }
        let lock_count = read_u16(buf, 2)?;
        if lock_count == 0 {
            return Err(ProtoError::Malformed("lock request lock_count == 0"));
        }
        let lock_bytes = (lock_count as usize)
            .checked_mul(24)
            .ok_or(ProtoError::Malformed("lock request element count overflow"))?;
        let required_len = 24usize
            .checked_add(lock_bytes)
            .ok_or(ProtoError::Malformed("lock request length overflow"))?;
        if buf.len() < required_len {
            return Err(ProtoError::Malformed("lock request elements truncated"));
        }
        let mut locks = Vec::with_capacity(lock_count as usize);
        for i in 0..lock_count as usize {
            let offset = 24 + i * 24;
            locks.push(LockElement {
                offset: read_u64(buf, offset)?,
                length: read_u64(buf, offset + 8)?,
                flags: read_u32(buf, offset + 16)?,
                reserved: read_u32(buf, offset + 20)?,
            });
        }
        Ok(Self {
            structure_size,
            lock_count,
            lock_sequence: read_u32(buf, 4)?,
            file_id: FileId::new(read_u64(buf, 8)?, read_u64(buf, 16)?),
            locks,
        })
    }
    pub fn write_to(&self, out: &mut Vec<u8>) -> ProtoResult<()> {
        let mut c = Cursor::new(Vec::new());
        BinWrite::write(self, &mut c)?;
        out.extend_from_slice(&c.into_inner());
        Ok(())
    }
}

#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LockResponse {
    pub structure_size: u16,
    pub reserved: u16,
}

impl Default for LockResponse {
    fn default() -> Self {
        Self {
            structure_size: 4,
            reserved: 0,
        }
    }
}

impl LockResponse {
    pub fn parse(buf: &[u8]) -> ProtoResult<Self> {
        if buf.len() < 4 {
            return Err(ProtoError::Malformed("lock response too short"));
        }
        let response = Self {
            structure_size: read_u16(buf, 0)?,
            reserved: read_u16(buf, 2)?,
        };
        if response.structure_size != 4 {
            return Err(ProtoError::Malformed("lock response structure_size != 4"));
        }
        Ok(response)
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
        .ok_or(ProtoError::Malformed("lock u16 out of range"))?;
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn read_u32(buf: &[u8], offset: usize) -> ProtoResult<u32> {
    let bytes = buf
        .get(offset..offset + 4)
        .ok_or(ProtoError::Malformed("lock u32 out of range"))?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn read_u64(buf: &[u8], offset: usize) -> ProtoResult<u64> {
    let bytes = buf
        .get(offset..offset + 8)
        .ok_or(ProtoError::Malformed("lock u64 out of range"))?;
    Ok(u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_round_trips() {
        let r = LockRequest {
            structure_size: 48,
            lock_count: 2,
            lock_sequence: 0,
            file_id: FileId::new(1, 2),
            locks: vec![
                LockElement {
                    offset: 0,
                    length: 16,
                    flags: LockElement::FLAG_EXCLUSIVE_LOCK,
                    reserved: 0,
                },
                LockElement {
                    offset: 0,
                    length: 16,
                    flags: LockElement::FLAG_UNLOCK,
                    reserved: 0,
                },
            ],
        };
        let mut buf = Vec::new();
        r.write_to(&mut buf).unwrap();
        assert_eq!(LockRequest::parse(&buf).unwrap(), r);
    }

    #[test]
    fn response_round_trips() {
        let r = LockResponse::default();
        let mut buf = Vec::new();
        r.write_to(&mut buf).unwrap();
        assert_eq!(LockResponse::parse(&buf).unwrap(), r);
    }

    #[test]
    fn request_rejects_wrong_structure_size() {
        let mut buf = vec![0; 48];
        buf[0..2].copy_from_slice(&47u16.to_le_bytes());
        buf[2..4].copy_from_slice(&1u16.to_le_bytes());

        assert!(matches!(
            LockRequest::parse(&buf),
            Err(ProtoError::Malformed(_))
        ));
    }

    #[test]
    fn request_rejects_zero_lock_count() {
        let mut buf = vec![0; 48];
        buf[0..2].copy_from_slice(&48u16.to_le_bytes());

        assert!(matches!(
            LockRequest::parse(&buf),
            Err(ProtoError::Malformed(_))
        ));
    }

    #[test]
    fn request_rejects_truncated_lock_elements() {
        let mut buf = vec![0; 48];
        buf[0..2].copy_from_slice(&48u16.to_le_bytes());
        buf[2..4].copy_from_slice(&2u16.to_le_bytes());

        assert!(matches!(
            LockRequest::parse(&buf),
            Err(ProtoError::Malformed(_))
        ));
    }

    #[test]
    fn response_rejects_wrong_structure_size() {
        let buf = [3, 0, 0, 0];

        assert!(matches!(
            LockResponse::parse(&buf),
            Err(ProtoError::Malformed(_))
        ));
    }
}
