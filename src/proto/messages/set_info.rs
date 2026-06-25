//! SET_INFO Request/Response (MS-SMB2 §2.2.39 / §2.2.40).

use binrw::{BinRead, BinWrite, binrw};
use std::io::Cursor;

use super::create::FileId;
use crate::proto::error::{ProtoError, ProtoResult};

/// SMB2_SET_INFO_REQUEST (MS-SMB2 §2.2.39).
#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetInfoRequest {
    pub structure_size: u16,
    pub info_type: u8,
    pub file_information_class: u8,
    pub buffer_length: u32,
    pub buffer_offset: u16,
    pub reserved: u16,
    pub additional_information: u32,
    pub file_id: FileId,
    #[br(count = buffer_length as usize)]
    pub buffer: Vec<u8>,
}

impl SetInfoRequest {
    pub fn parse(buf: &[u8]) -> ProtoResult<Self> {
        if buf.len() < 32 {
            return Err(ProtoError::Malformed("set info request too short"));
        }
        let structure_size = read_u16(buf, 0)?;
        if structure_size != 33 {
            return Err(ProtoError::Malformed(
                "set info request structure_size != 33",
            ));
        }
        let buffer_length = read_u32(buf, 4)?;
        let buffer_offset = read_u16(buf, 8)?;
        let buffer = if buffer_length == 0 {
            Vec::new()
        } else {
            let offset = (buffer_offset as usize)
                .checked_sub(crate::proto::header::SMB2_HEADER_LEN)
                .ok_or(ProtoError::Malformed(
                    "set info buffer offset before SMB2 body",
                ))?;
            let length = buffer_length as usize;
            let end = offset
                .checked_add(length)
                .ok_or(ProtoError::Malformed("set info buffer overflow"))?;
            if offset < 32 || end > buf.len() {
                return Err(ProtoError::Malformed("set info buffer out of range"));
            }
            buf[offset..end].to_vec()
        };

        Ok(Self {
            structure_size,
            info_type: buf[2],
            file_information_class: buf[3],
            buffer_length,
            buffer_offset,
            reserved: read_u16(buf, 10)?,
            additional_information: read_u32(buf, 12)?,
            file_id: FileId::new(read_u64(buf, 16)?, read_u64(buf, 24)?),
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

/// SMB2_SET_INFO_RESPONSE (MS-SMB2 §2.2.40).
#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetInfoResponse {
    pub structure_size: u16,
}

impl Default for SetInfoResponse {
    fn default() -> Self {
        Self { structure_size: 2 }
    }
}

impl SetInfoResponse {
    pub fn parse(buf: &[u8]) -> ProtoResult<Self> {
        let response = Self::read(&mut Cursor::new(buf))?;
        if response.structure_size != 2 {
            return Err(ProtoError::Malformed(
                "set info response structure_size != 2",
            ));
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
        .ok_or(ProtoError::Malformed("set info u16 out of range"))?;
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn read_u32(buf: &[u8], offset: usize) -> ProtoResult<u32> {
    let bytes = buf
        .get(offset..offset + 4)
        .ok_or(ProtoError::Malformed("set info u32 out of range"))?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn read_u64(buf: &[u8], offset: usize) -> ProtoResult<u64> {
    let bytes = buf
        .get(offset..offset + 8)
        .ok_or(ProtoError::Malformed("set info u64 out of range"))?;
    Ok(u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_round_trips() {
        let r = SetInfoRequest {
            structure_size: 33,
            info_type: 0x01,              // File
            file_information_class: 0x14, // FileEndOfFileInformation
            buffer_length: 8,
            buffer_offset: 0x60,
            reserved: 0,
            additional_information: 0,
            file_id: FileId::new(1, 2),
            buffer: vec![0, 0, 0, 0x10, 0, 0, 0, 0],
        };
        let mut buf = Vec::new();
        r.write_to(&mut buf).unwrap();
        assert_eq!(SetInfoRequest::parse(&buf).unwrap(), r);
    }

    #[test]
    fn response_round_trips() {
        let r = SetInfoResponse::default();
        let mut buf = Vec::new();
        r.write_to(&mut buf).unwrap();
        assert_eq!(SetInfoResponse::parse(&buf).unwrap(), r);
        assert_eq!(buf.len(), 2);
    }

    #[test]
    fn request_decodes_file_id_and_padded_buffer() {
        let mut buf = vec![0; 40];
        buf[0..2].copy_from_slice(&33u16.to_le_bytes());
        buf[2] = 0x01;
        buf[3] = 0x14;
        buf[4..8].copy_from_slice(&4u32.to_le_bytes());
        buf[8..10]
            .copy_from_slice(&(crate::proto::header::SMB2_HEADER_LEN as u16 + 36).to_le_bytes());
        buf[12..16].copy_from_slice(&0x08u32.to_le_bytes());
        buf[16..24].copy_from_slice(&11u64.to_le_bytes());
        buf[24..32].copy_from_slice(&22u64.to_le_bytes());
        buf[36..40].copy_from_slice(&[5, 6, 7, 8]);

        let decoded = SetInfoRequest::parse(&buf).unwrap();

        assert_eq!(decoded.file_id, FileId::new(11, 22));
        assert_eq!(decoded.additional_information, 0x08);
        assert_eq!(decoded.buffer, [5, 6, 7, 8]);
    }

    #[test]
    fn request_rejects_wrong_structure_size() {
        let mut buf = vec![0; 32];
        buf[0..2].copy_from_slice(&32u16.to_le_bytes());

        assert!(matches!(
            SetInfoRequest::parse(&buf),
            Err(ProtoError::Malformed(_))
        ));
    }

    #[test]
    fn request_rejects_buffer_out_of_range() {
        let mut buf = vec![0; 32];
        buf[0..2].copy_from_slice(&33u16.to_le_bytes());
        buf[4..8].copy_from_slice(&1u32.to_le_bytes());
        buf[8..10]
            .copy_from_slice(&(crate::proto::header::SMB2_HEADER_LEN as u16 + 32).to_le_bytes());

        assert!(matches!(
            SetInfoRequest::parse(&buf),
            Err(ProtoError::Malformed(_))
        ));
    }

    #[test]
    fn response_rejects_wrong_structure_size() {
        let buf = [3, 0];

        assert!(matches!(
            SetInfoResponse::parse(&buf),
            Err(ProtoError::Malformed(_))
        ));
    }
}
