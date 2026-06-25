//! READ Request/Response (MS-SMB2 §2.2.19 / §2.2.20).
//!
//! ## Data buffer offsets
//!
//! Both the READ request `ReadChannelInfoOffset` and the READ response
//! `DataOffset` are measured from the **start of the SMB2 header**, not from
//! the start of this structure (MS-SMB2 §2.2.20 explicitly: "DataOffset (1
//! byte): The offset, in bytes, from the beginning of the SMB2 header to the
//! data being read"). When constructing a response, the server crate must
//! compute `DataOffset = SMB2_HEADER_LEN + offset_within_body_of_data`.

use binrw::{BinWrite, binrw};
use std::io::Cursor;

use super::create::FileId;
use crate::proto::error::{ProtoError, ProtoResult};

/// SMB2_READ_REQUEST (MS-SMB2 §2.2.19).
#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadRequest {
    pub structure_size: u16,
    pub padding: u8,
    /// 3.0+ flags (`SMB2_READFLAG_*`); reserved on 2.x.
    pub flags: u8,
    pub length: u32,
    pub offset: u64,
    pub file_id: FileId,
    pub minimum_count: u32,
    pub channel: u32,
    pub remaining_bytes: u32,
    pub read_channel_info_offset: u16,
    pub read_channel_info_length: u16,
    /// MS-SMB2: "If ReadChannelInfoOffset and ReadChannelInfoLength are both
    /// 0, the client MUST set this field to a single 0 byte." We follow that
    /// — at least one byte of buffer is required on the wire.
    #[br(count = if read_channel_info_length == 0 { 1 } else { read_channel_info_length as usize })]
    pub buffer: Vec<u8>,
}

impl ReadRequest {
    /// Flag: SMB2_READFLAG_READ_UNBUFFERED (3.0.2+).
    pub const FLAG_READ_UNBUFFERED: u8 = 0x01;
    /// Flag: SMB2_READFLAG_REQUEST_COMPRESSED (3.1.1+).
    pub const FLAG_REQUEST_COMPRESSED: u8 = 0x02;

    pub fn parse(buf: &[u8]) -> ProtoResult<Self> {
        if buf.len() < 48 {
            return Err(ProtoError::Malformed("read request too short"));
        }
        let structure_size = read_u16(buf, 0)?;
        if structure_size != 49 {
            return Err(ProtoError::Malformed("read request structure_size != 49"));
        }
        Ok(Self {
            structure_size,
            padding: buf[2],
            flags: buf[3],
            length: read_u32(buf, 4)?,
            offset: read_u64(buf, 8)?,
            file_id: FileId::new(read_u64(buf, 16)?, read_u64(buf, 24)?),
            minimum_count: read_u32(buf, 32)?,
            channel: read_u32(buf, 36)?,
            remaining_bytes: read_u32(buf, 40)?,
            read_channel_info_offset: read_u16(buf, 44)?,
            read_channel_info_length: read_u16(buf, 46)?,
            buffer: buf.get(48..).unwrap_or(&[]).to_vec(),
        })
    }
    pub fn write_to(&self, out: &mut Vec<u8>) -> ProtoResult<()> {
        let mut c = Cursor::new(Vec::new());
        BinWrite::write(self, &mut c)?;
        out.extend_from_slice(&c.into_inner());
        Ok(())
    }
}

/// SMB2_READ_RESPONSE (MS-SMB2 §2.2.20).
///
/// `data_offset` is from the start of the SMB2 header. Use
/// [`ReadResponse::standard_data_offset`] for the canonical "data immediately
/// after the fixed prefix" layout.
#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadResponse {
    pub structure_size: u16,
    pub data_offset: u8,
    pub reserved: u8,
    pub data_length: u32,
    pub data_remaining: u32,
    /// 3.x: `Flags`. 2.x: reserved.
    pub flags: u32,
    #[br(count = data_length as usize)]
    pub data: Vec<u8>,
}

impl ReadResponse {
    /// Canonical `DataOffset` value when the data buffer immediately follows
    /// the fixed 16-byte response prefix and the SMB2 header (64 + 16 = 80).
    ///
    /// Most servers (ksmbd, Samba) emit 0x50 = 80 here.
    pub const STANDARD_DATA_OFFSET: u8 = 0x50;

    pub const fn standard_data_offset() -> u8 {
        Self::STANDARD_DATA_OFFSET
    }

    pub fn parse(buf: &[u8]) -> ProtoResult<Self> {
        if buf.len() < 16 {
            return Err(ProtoError::Malformed("read response too short"));
        }
        let structure_size = read_u16(buf, 0)?;
        if structure_size != 17 {
            return Err(ProtoError::Malformed("read response structure_size != 17"));
        }
        let data_offset = buf[2];
        let data_length = read_u32(buf, 4)?;
        let data = if data_length == 0 {
            Vec::new()
        } else {
            let offset = (data_offset as usize)
                .checked_sub(crate::proto::header::SMB2_HEADER_LEN)
                .ok_or(ProtoError::Malformed("read data offset before SMB2 body"))?;
            let end = offset
                .checked_add(data_length as usize)
                .ok_or(ProtoError::Malformed("read data overflow"))?;
            if offset < 16 || end > buf.len() {
                return Err(ProtoError::Malformed("read data out of range"));
            }
            buf[offset..end].to_vec()
        };
        Ok(Self {
            structure_size,
            data_offset,
            reserved: buf[3],
            data_length,
            data_remaining: read_u32(buf, 8)?,
            flags: read_u32(buf, 12)?,
            data,
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
        .ok_or(ProtoError::Malformed("read u16 out of range"))?;
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn read_u32(buf: &[u8], offset: usize) -> ProtoResult<u32> {
    let bytes = buf
        .get(offset..offset + 4)
        .ok_or(ProtoError::Malformed("read u32 out of range"))?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn read_u64(buf: &[u8], offset: usize) -> ProtoResult<u64> {
    let bytes = buf
        .get(offset..offset + 8)
        .ok_or(ProtoError::Malformed("read u64 out of range"))?;
    Ok(u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_round_trips() {
        let r = ReadRequest {
            structure_size: 49,
            padding: 0x50,
            flags: 0,
            length: 0x1000,
            offset: 0x2000,
            file_id: FileId::new(0xAAAA, 0xBBBB),
            minimum_count: 1,
            channel: 0,
            remaining_bytes: 0,
            read_channel_info_offset: 0,
            read_channel_info_length: 0,
            buffer: vec![0],
        };
        let mut buf = Vec::new();
        r.write_to(&mut buf).unwrap();
        assert_eq!(ReadRequest::parse(&buf).unwrap(), r);
    }

    #[test]
    fn response_round_trips() {
        let r = ReadResponse {
            structure_size: 17,
            data_offset: ReadResponse::STANDARD_DATA_OFFSET,
            reserved: 0,
            data_length: 5,
            data_remaining: 0,
            flags: 0,
            data: vec![1, 2, 3, 4, 5],
        };
        let mut buf = Vec::new();
        r.write_to(&mut buf).unwrap();
        assert_eq!(ReadResponse::parse(&buf).unwrap(), r);
    }

    #[test]
    fn request_accepts_fixed_body_without_trailing_padding_byte() {
        let mut buf = vec![0; 48];
        buf[0..2].copy_from_slice(&49u16.to_le_bytes());
        buf[2] = ReadResponse::STANDARD_DATA_OFFSET;
        buf[4..8].copy_from_slice(&0x1000u32.to_le_bytes());
        buf[8..16].copy_from_slice(&0x2000u64.to_le_bytes());
        buf[16..24].copy_from_slice(&0x11u64.to_le_bytes());
        buf[24..32].copy_from_slice(&0x22u64.to_le_bytes());
        buf[32..36].copy_from_slice(&128u32.to_le_bytes());
        buf[36..40].copy_from_slice(&1u32.to_le_bytes());
        buf[40..44].copy_from_slice(&256u32.to_le_bytes());
        buf[44..46].copy_from_slice(&48u16.to_le_bytes());
        buf[46..48].copy_from_slice(&8u16.to_le_bytes());

        let decoded = ReadRequest::parse(&buf).unwrap();

        assert_eq!(decoded.file_id, FileId::new(0x11, 0x22));
        assert_eq!(decoded.length, 0x1000);
        assert_eq!(decoded.offset, 0x2000);
        assert_eq!(decoded.minimum_count, 128);
        assert_eq!(decoded.channel, 1);
        assert_eq!(decoded.remaining_bytes, 256);
        assert_eq!(decoded.read_channel_info_offset, 48);
        assert_eq!(decoded.read_channel_info_length, 8);
        assert!(decoded.buffer.is_empty());
    }

    #[test]
    fn request_rejects_wrong_structure_size() {
        let mut buf = vec![0; 48];
        buf[0..2].copy_from_slice(&48u16.to_le_bytes());

        assert!(matches!(
            ReadRequest::parse(&buf),
            Err(ProtoError::Malformed(_))
        ));
    }

    #[test]
    fn response_decodes_padded_data_from_header_relative_offset() {
        let mut buf = vec![0; 24];
        buf[0..2].copy_from_slice(&17u16.to_le_bytes());
        buf[2] = crate::proto::header::SMB2_HEADER_LEN as u8 + 20;
        buf[4..8].copy_from_slice(&4u32.to_le_bytes());
        buf[8..12].copy_from_slice(&2u32.to_le_bytes());
        buf[12..16].copy_from_slice(&1u32.to_le_bytes());
        buf[20..24].copy_from_slice(&[9, 8, 7, 6]);

        let decoded = ReadResponse::parse(&buf).unwrap();

        assert_eq!(decoded.data, [9, 8, 7, 6]);
        assert_eq!(decoded.data_remaining, 2);
        assert_eq!(decoded.flags, 1);
    }

    #[test]
    fn response_rejects_wrong_structure_size() {
        let buf = [16, 0, ReadResponse::STANDARD_DATA_OFFSET, 0, 0, 0, 0, 0];

        assert!(matches!(
            ReadResponse::parse(&buf),
            Err(ProtoError::Malformed(_))
        ));
    }

    #[test]
    fn response_rejects_data_out_of_range() {
        let mut buf = vec![0; 16];
        buf[0..2].copy_from_slice(&17u16.to_le_bytes());
        buf[2] = ReadResponse::STANDARD_DATA_OFFSET;
        buf[4..8].copy_from_slice(&1u32.to_le_bytes());

        assert!(matches!(
            ReadResponse::parse(&buf),
            Err(ProtoError::Malformed(_))
        ));
    }
}
