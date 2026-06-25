//! CHANGE_NOTIFY Request/Response (MS-SMB2 §2.2.35 / §2.2.36).
//!
//! The handler implements GoSMB-compatible validation plus a first async
//! pending/completion path for child create notifications.

use binrw::{BinWrite, binrw};
use std::io::Cursor;

use super::create::FileId;
use crate::proto::error::{ProtoError, ProtoResult};

#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChangeNotifyRequest {
    pub structure_size: u16,
    pub flags: u16,
    pub output_buffer_length: u32,
    pub file_id: FileId,
    pub completion_filter: u32,
    pub reserved: u32,
}

impl ChangeNotifyRequest {
    /// Flag: SMB2_WATCH_TREE.
    pub const FLAG_WATCH_TREE: u16 = 0x0001;

    pub fn parse(buf: &[u8]) -> ProtoResult<Self> {
        if buf.len() < 32 {
            return Err(ProtoError::Malformed("change notify request too short"));
        }
        let structure_size = read_u16(buf, 0)?;
        if structure_size != 32 {
            return Err(ProtoError::Malformed(
                "change notify request structure_size != 32",
            ));
        }
        Ok(Self {
            structure_size,
            flags: read_u16(buf, 2)?,
            output_buffer_length: read_u32(buf, 4)?,
            file_id: FileId::new(read_u64(buf, 8)?, read_u64(buf, 16)?),
            completion_filter: read_u32(buf, 24)?,
            reserved: read_u32(buf, 28)?,
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
pub struct ChangeNotifyResponse {
    pub structure_size: u16,
    pub output_buffer_offset: u16,
    pub output_buffer_length: u32,
    #[br(count = output_buffer_length as usize)]
    pub buffer: Vec<u8>,
}

impl ChangeNotifyResponse {
    pub fn parse(buf: &[u8]) -> ProtoResult<Self> {
        if buf.len() < 8 {
            return Err(ProtoError::Malformed("change notify response too short"));
        }
        let structure_size = read_u16(buf, 0)?;
        if structure_size != 9 {
            return Err(ProtoError::Malformed(
                "change notify response structure_size != 9",
            ));
        }
        let output_buffer_offset = read_u16(buf, 2)?;
        let output_buffer_length = read_u32(buf, 4)?;
        let buffer = if output_buffer_length == 0 {
            Vec::new()
        } else {
            let offset = (output_buffer_offset as usize)
                .checked_sub(crate::proto::header::SMB2_HEADER_LEN)
                .ok_or(ProtoError::Malformed(
                    "change notify buffer offset before SMB2 body",
                ))?;
            let end = offset
                .checked_add(output_buffer_length as usize)
                .ok_or(ProtoError::Malformed("change notify buffer overflow"))?;
            if offset < 8 || end > buf.len() {
                return Err(ProtoError::Malformed("change notify buffer out of range"));
            }
            buf[offset..end].to_vec()
        };
        Ok(Self {
            structure_size,
            output_buffer_offset,
            output_buffer_length,
            buffer,
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
        .ok_or(ProtoError::Malformed("change notify u16 out of range"))?;
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn read_u32(buf: &[u8], offset: usize) -> ProtoResult<u32> {
    let bytes = buf
        .get(offset..offset + 4)
        .ok_or(ProtoError::Malformed("change notify u32 out of range"))?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn read_u64(buf: &[u8], offset: usize) -> ProtoResult<u64> {
    let bytes = buf
        .get(offset..offset + 8)
        .ok_or(ProtoError::Malformed("change notify u64 out of range"))?;
    Ok(u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_round_trips() {
        let r = ChangeNotifyRequest {
            structure_size: 32,
            flags: ChangeNotifyRequest::FLAG_WATCH_TREE,
            output_buffer_length: 0x1000,
            file_id: FileId::new(1, 2),
            completion_filter: 0xFF,
            reserved: 0,
        };
        let mut buf = Vec::new();
        r.write_to(&mut buf).unwrap();
        assert_eq!(ChangeNotifyRequest::parse(&buf).unwrap(), r);
    }

    #[test]
    fn response_round_trips() {
        let r = ChangeNotifyResponse {
            structure_size: 9,
            output_buffer_offset: 0x48,
            output_buffer_length: 0,
            buffer: vec![],
        };
        let mut buf = Vec::new();
        r.write_to(&mut buf).unwrap();
        assert_eq!(ChangeNotifyResponse::parse(&buf).unwrap(), r);
    }

    #[test]
    fn request_rejects_wrong_structure_size() {
        let mut buf = vec![0; 32];
        buf[0..2].copy_from_slice(&31u16.to_le_bytes());

        assert!(matches!(
            ChangeNotifyRequest::parse(&buf),
            Err(ProtoError::Malformed(_))
        ));
    }

    #[test]
    fn response_decodes_padded_buffer_from_header_relative_offset() {
        let mut buf = vec![0; 16];
        buf[0..2].copy_from_slice(&9u16.to_le_bytes());
        buf[2..4]
            .copy_from_slice(&(crate::proto::header::SMB2_HEADER_LEN as u16 + 12).to_le_bytes());
        buf[4..8].copy_from_slice(&4u32.to_le_bytes());
        buf[12..16].copy_from_slice(&[1, 2, 3, 4]);

        let decoded = ChangeNotifyResponse::parse(&buf).unwrap();

        assert_eq!(decoded.buffer, [1, 2, 3, 4]);
    }

    #[test]
    fn response_rejects_wrong_structure_size() {
        let buf = [8, 0, 0, 0, 0, 0, 0, 0];

        assert!(matches!(
            ChangeNotifyResponse::parse(&buf),
            Err(ProtoError::Malformed(_))
        ));
    }

    #[test]
    fn response_rejects_buffer_out_of_range() {
        let mut buf = vec![0; 8];
        buf[0..2].copy_from_slice(&9u16.to_le_bytes());
        buf[2..4]
            .copy_from_slice(&(crate::proto::header::SMB2_HEADER_LEN as u16 + 8).to_le_bytes());
        buf[4..8].copy_from_slice(&1u32.to_le_bytes());

        assert!(matches!(
            ChangeNotifyResponse::parse(&buf),
            Err(ProtoError::Malformed(_))
        ));
    }
}
