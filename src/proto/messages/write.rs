//! WRITE Request/Response (MS-SMB2 §2.2.21 / §2.2.22).
//!
//! ## Data buffer offsets
//!
//! `DataOffset` is from the **start of the SMB2 header**, not from the start
//! of this structure (MS-SMB2 §2.2.21). The canonical layout puts the data
//! immediately after the fixed 48-byte prefix, giving 64 + 48 = 112 = 0x70.

use binrw::{BinRead, BinWrite, binrw};
use std::io::Cursor;

use super::create::FileId;
use crate::proto::error::{ProtoError, ProtoResult};

/// SMB2_WRITE_REQUEST (MS-SMB2 §2.2.21).
#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriteRequest {
    pub structure_size: u16,
    pub data_offset: u16,
    pub length: u32,
    pub offset: u64,
    pub file_id: FileId,
    pub channel: u32,
    pub remaining_bytes: u32,
    pub write_channel_info_offset: u16,
    pub write_channel_info_length: u16,
    pub flags: u32,
    /// MS-SMB2: at least 1 byte of payload buffer is required on the wire
    /// even when length=0.
    #[br(count = if length == 0 { 1 } else { length as usize })]
    pub data: Vec<u8>,
}

impl WriteRequest {
    /// Canonical `DataOffset` placing the data buffer immediately after the
    /// fixed 48-byte WRITE prefix: 64 (SMB2 header) + 48 = 112 = 0x70.
    pub const STANDARD_DATA_OFFSET: u16 = 0x70;
    /// Flag: SMB2_WRITEFLAG_WRITE_THROUGH.
    pub const FLAG_WRITE_THROUGH: u32 = 0x0000_0001;
    /// Flag: SMB2_WRITEFLAG_WRITE_UNBUFFERED (3.0.2+).
    pub const FLAG_WRITE_UNBUFFERED: u32 = 0x0000_0002;

    pub fn parse(buf: &[u8]) -> ProtoResult<Self> {
        if buf.len() < 48 {
            return Err(ProtoError::Malformed("write request too short"));
        }
        let structure_size = read_u16(buf, 0)?;
        if structure_size != 49 {
            return Err(ProtoError::Malformed("write request structure_size != 49"));
        }
        let data_offset = read_u16(buf, 2)?;
        let length = read_u32(buf, 4)?;
        let offset = (data_offset as usize)
            .checked_sub(crate::proto::header::SMB2_HEADER_LEN)
            .ok_or(ProtoError::Malformed("write data offset before SMB2 body"))?;
        let end = offset
            .checked_add(length as usize)
            .ok_or(ProtoError::Malformed("write data overflow"))?;
        if offset < 48 || end > buf.len() {
            return Err(ProtoError::Malformed("write data out of range"));
        }

        Ok(Self {
            structure_size,
            data_offset,
            length,
            offset: read_u64(buf, 8)?,
            file_id: FileId::new(read_u64(buf, 16)?, read_u64(buf, 24)?),
            channel: read_u32(buf, 32)?,
            remaining_bytes: read_u32(buf, 36)?,
            write_channel_info_offset: read_u16(buf, 40)?,
            write_channel_info_length: read_u16(buf, 42)?,
            flags: read_u32(buf, 44)?,
            data: buf[offset..end].to_vec(),
        })
    }
    pub fn write_to(&self, out: &mut Vec<u8>) -> ProtoResult<()> {
        let mut c = Cursor::new(Vec::new());
        BinWrite::write(self, &mut c)?;
        out.extend_from_slice(&c.into_inner());
        Ok(())
    }
}

/// SMB2_WRITE_RESPONSE (MS-SMB2 §2.2.22).
#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct WriteResponse {
    pub structure_size: u16,
    pub reserved: u16,
    pub count: u32,
    pub remaining: u32,
    pub write_channel_info_offset: u16,
    pub write_channel_info_length: u16,
}

impl WriteResponse {
    pub fn new(count: u32) -> Self {
        Self {
            structure_size: 17,
            reserved: 0,
            count,
            remaining: 0,
            write_channel_info_offset: 0,
            write_channel_info_length: 0,
        }
    }

    pub fn parse(buf: &[u8]) -> ProtoResult<Self> {
        let response = Self::read(&mut Cursor::new(buf))?;
        if response.structure_size != 17 {
            return Err(ProtoError::Malformed("write response structure_size != 17"));
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
        .ok_or(ProtoError::Malformed("write u16 out of range"))?;
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn read_u32(buf: &[u8], offset: usize) -> ProtoResult<u32> {
    let bytes = buf
        .get(offset..offset + 4)
        .ok_or(ProtoError::Malformed("write u32 out of range"))?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn read_u64(buf: &[u8], offset: usize) -> ProtoResult<u64> {
    let bytes = buf
        .get(offset..offset + 8)
        .ok_or(ProtoError::Malformed("write u64 out of range"))?;
    Ok(u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_round_trips() {
        let r = WriteRequest {
            structure_size: 49,
            data_offset: WriteRequest::STANDARD_DATA_OFFSET,
            length: 4,
            offset: 0x100,
            file_id: FileId::new(0xAA, 0xBB),
            channel: 0,
            remaining_bytes: 0,
            write_channel_info_offset: 0,
            write_channel_info_length: 0,
            flags: 0,
            data: vec![1, 2, 3, 4],
        };
        let mut buf = Vec::new();
        r.write_to(&mut buf).unwrap();
        assert_eq!(WriteRequest::parse(&buf).unwrap(), r);
    }

    #[test]
    fn response_round_trips() {
        let r = WriteResponse::new(0x1000);
        let mut buf = Vec::new();
        r.write_to(&mut buf).unwrap();
        assert_eq!(WriteResponse::parse(&buf).unwrap(), r);
    }

    #[test]
    fn request_decodes_padded_data_from_header_relative_offset() {
        let mut buf = vec![0; 56];
        buf[0..2].copy_from_slice(&49u16.to_le_bytes());
        buf[2..4]
            .copy_from_slice(&(crate::proto::header::SMB2_HEADER_LEN as u16 + 52).to_le_bytes());
        buf[4..8].copy_from_slice(&4u32.to_le_bytes());
        buf[8..16].copy_from_slice(&0x100u64.to_le_bytes());
        buf[16..24].copy_from_slice(&0x11u64.to_le_bytes());
        buf[24..32].copy_from_slice(&0x22u64.to_le_bytes());
        buf[32..36].copy_from_slice(&1u32.to_le_bytes());
        buf[36..40].copy_from_slice(&512u32.to_le_bytes());
        buf[40..42].copy_from_slice(&48u16.to_le_bytes());
        buf[42..44].copy_from_slice(&8u16.to_le_bytes());
        buf[44..48].copy_from_slice(&WriteRequest::FLAG_WRITE_UNBUFFERED.to_le_bytes());
        buf[52..56].copy_from_slice(&[1, 2, 3, 4]);

        let decoded = WriteRequest::parse(&buf).unwrap();

        assert_eq!(decoded.file_id, FileId::new(0x11, 0x22));
        assert_eq!(decoded.offset, 0x100);
        assert_eq!(decoded.channel, 1);
        assert_eq!(decoded.remaining_bytes, 512);
        assert_eq!(decoded.write_channel_info_offset, 48);
        assert_eq!(decoded.write_channel_info_length, 8);
        assert_eq!(decoded.flags, WriteRequest::FLAG_WRITE_UNBUFFERED);
        assert_eq!(decoded.data, [1, 2, 3, 4]);
    }

    #[test]
    fn request_rejects_wrong_structure_size() {
        let mut buf = vec![0; 48];
        buf[0..2].copy_from_slice(&48u16.to_le_bytes());

        assert!(matches!(
            WriteRequest::parse(&buf),
            Err(ProtoError::Malformed(_))
        ));
    }

    #[test]
    fn request_rejects_data_out_of_range() {
        let mut buf = vec![0; 48];
        buf[0..2].copy_from_slice(&49u16.to_le_bytes());
        buf[2..4]
            .copy_from_slice(&(crate::proto::header::SMB2_HEADER_LEN as u16 + 48).to_le_bytes());
        buf[4..8].copy_from_slice(&1u32.to_le_bytes());

        assert!(matches!(
            WriteRequest::parse(&buf),
            Err(ProtoError::Malformed(_))
        ));
    }

    #[test]
    fn response_rejects_wrong_structure_size() {
        let buf = [16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

        assert!(matches!(
            WriteResponse::parse(&buf),
            Err(ProtoError::Malformed(_))
        ));
    }
}
