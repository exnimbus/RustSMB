//! QUERY_INFO Request/Response (MS-SMB2 §2.2.37 / §2.2.38).

use binrw::{BinRead, BinWrite, binrw};
use std::io::Cursor;

use super::create::FileId;
use crate::proto::error::{ProtoError, ProtoResult};

/// `InfoType` values (MS-SMB2 §2.2.37 InfoType field).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum InfoType {
    File = 0x01,
    FileSystem = 0x02,
    Security = 0x03,
    Quota = 0x04,
}

impl InfoType {
    pub fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            0x01 => Self::File,
            0x02 => Self::FileSystem,
            0x03 => Self::Security,
            0x04 => Self::Quota,
            _ => return None,
        })
    }
}

/// SMB2_QUERY_INFO_REQUEST (MS-SMB2 §2.2.37).
#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryInfoRequest {
    pub structure_size: u16,
    pub info_type: u8,
    pub file_information_class: u8,
    pub output_buffer_length: u32,
    pub input_buffer_offset: u16,
    pub reserved: u16,
    pub input_buffer_length: u32,
    /// `AdditionalInformation`: which fields of the security descriptor to
    /// return when `info_type == Security`. Otherwise an additional info-class
    /// selector for FS info.
    pub additional_information: u32,
    pub flags: u32,
    pub file_id: FileId,
    /// Optional input buffer (used by FILE/FS info classes that need it, e.g.
    /// `FileFullEaInformation` extended-attribute name lists).
    #[br(count = input_buffer_length as usize)]
    pub input_buffer: Vec<u8>,
}

impl QueryInfoRequest {
    /// Flag: SL_RESTART_SCAN.
    pub const FLAG_RESTART_SCAN: u32 = 0x0000_0001;
    /// Flag: SL_RETURN_SINGLE_ENTRY.
    pub const FLAG_RETURN_SINGLE_ENTRY: u32 = 0x0000_0002;
    /// Flag: SL_INDEX_SPECIFIED.
    pub const FLAG_INDEX_SPECIFIED: u32 = 0x0000_0004;

    pub fn info_type_enum(&self) -> Option<InfoType> {
        InfoType::from_u8(self.info_type)
    }

    pub fn parse(buf: &[u8]) -> ProtoResult<Self> {
        if buf.len() < 40 {
            return Err(ProtoError::Malformed("query info request too short"));
        }
        let structure_size = read_u16(buf, 0)?;
        if structure_size != 41 {
            return Err(ProtoError::Malformed(
                "query info request structure_size != 41",
            ));
        }
        let input_buffer_offset = read_u16(buf, 8)?;
        let input_buffer_length = read_u32(buf, 12)?;
        let input_buffer = if input_buffer_length == 0 {
            Vec::new()
        } else {
            let offset = (input_buffer_offset as usize)
                .checked_sub(crate::proto::header::SMB2_HEADER_LEN)
                .ok_or(ProtoError::Malformed(
                    "query info input buffer offset before SMB2 body",
                ))?;
            let length = input_buffer_length as usize;
            let end = offset
                .checked_add(length)
                .ok_or(ProtoError::Malformed("query info input buffer overflow"))?;
            if offset < 40 || end > buf.len() {
                return Err(ProtoError::Malformed(
                    "query info input buffer out of range",
                ));
            }
            buf[offset..end].to_vec()
        };

        Ok(Self {
            structure_size,
            info_type: buf[2],
            file_information_class: buf[3],
            output_buffer_length: read_u32(buf, 4)?,
            input_buffer_offset,
            reserved: read_u16(buf, 10)?,
            input_buffer_length,
            additional_information: read_u32(buf, 16)?,
            flags: read_u32(buf, 20)?,
            file_id: FileId::new(read_u64(buf, 24)?, read_u64(buf, 32)?),
            input_buffer,
        })
    }
    pub fn write_to(&self, out: &mut Vec<u8>) -> ProtoResult<()> {
        let mut c = Cursor::new(Vec::new());
        BinWrite::write(self, &mut c)?;
        out.extend_from_slice(&c.into_inner());
        Ok(())
    }
}

/// SMB2_QUERY_INFO_RESPONSE (MS-SMB2 §2.2.38).
#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryInfoResponse {
    pub structure_size: u16,
    pub output_buffer_offset: u16,
    pub output_buffer_length: u32,
    #[br(count = output_buffer_length as usize)]
    pub buffer: Vec<u8>,
}

impl QueryInfoResponse {
    pub fn parse(buf: &[u8]) -> ProtoResult<Self> {
        let response = Self::read(&mut Cursor::new(buf))?;
        if response.structure_size != 9 {
            return Err(ProtoError::Malformed(
                "query info response structure_size != 9",
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
        .ok_or(ProtoError::Malformed("query info u16 out of range"))?;
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn read_u32(buf: &[u8], offset: usize) -> ProtoResult<u32> {
    let bytes = buf
        .get(offset..offset + 4)
        .ok_or(ProtoError::Malformed("query info u32 out of range"))?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn read_u64(buf: &[u8], offset: usize) -> ProtoResult<u64> {
    let bytes = buf
        .get(offset..offset + 8)
        .ok_or(ProtoError::Malformed("query info u64 out of range"))?;
    Ok(u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_round_trips() {
        let r = QueryInfoRequest {
            structure_size: 41,
            info_type: InfoType::File as u8,
            file_information_class: 0x05, // FileStandardInformation
            output_buffer_length: 0x1000,
            input_buffer_offset: 0,
            reserved: 0,
            input_buffer_length: 0,
            additional_information: 0,
            flags: 0,
            file_id: FileId::new(1, 2),
            input_buffer: vec![],
        };
        let mut buf = Vec::new();
        r.write_to(&mut buf).unwrap();
        let decoded = QueryInfoRequest::parse(&buf).unwrap();
        assert_eq!(decoded, r);
        assert_eq!(decoded.info_type_enum(), Some(InfoType::File));
    }

    #[test]
    fn response_round_trips() {
        let r = QueryInfoResponse {
            structure_size: 9,
            output_buffer_offset: 0x48,
            output_buffer_length: 4,
            buffer: vec![0xAB, 0xCD, 0xEF, 0x01],
        };
        let mut buf = Vec::new();
        r.write_to(&mut buf).unwrap();
        assert_eq!(QueryInfoResponse::parse(&buf).unwrap(), r);
    }

    #[test]
    fn request_decodes_file_id_and_padded_input_buffer() {
        let mut buf = vec![0; 48];
        buf[0..2].copy_from_slice(&41u16.to_le_bytes());
        buf[2] = InfoType::Security as u8;
        buf[4..8].copy_from_slice(&1024u32.to_le_bytes());
        buf[8..10]
            .copy_from_slice(&(crate::proto::header::SMB2_HEADER_LEN as u16 + 44).to_le_bytes());
        buf[12..16].copy_from_slice(&4u32.to_le_bytes());
        buf[16..20].copy_from_slice(&0x07u32.to_le_bytes());
        buf[20..24].copy_from_slice(&0x02u32.to_le_bytes());
        buf[24..32].copy_from_slice(&33u64.to_le_bytes());
        buf[32..40].copy_from_slice(&44u64.to_le_bytes());
        buf[44..48].copy_from_slice(&[1, 2, 3, 4]);

        let decoded = QueryInfoRequest::parse(&buf).unwrap();

        assert_eq!(decoded.file_id, FileId::new(33, 44));
        assert_eq!(decoded.input_buffer, [1, 2, 3, 4]);
        assert_eq!(decoded.additional_information, 0x07);
        assert_eq!(decoded.flags, 0x02);
    }

    #[test]
    fn request_rejects_wrong_structure_size() {
        let mut buf = vec![0; 40];
        buf[0..2].copy_from_slice(&40u16.to_le_bytes());

        assert!(matches!(
            QueryInfoRequest::parse(&buf),
            Err(ProtoError::Malformed(_))
        ));
    }

    #[test]
    fn request_rejects_input_buffer_out_of_range() {
        let mut buf = vec![0; 40];
        buf[0..2].copy_from_slice(&41u16.to_le_bytes());
        buf[8..10]
            .copy_from_slice(&(crate::proto::header::SMB2_HEADER_LEN as u16 + 40).to_le_bytes());
        buf[12..16].copy_from_slice(&1u32.to_le_bytes());

        assert!(matches!(
            QueryInfoRequest::parse(&buf),
            Err(ProtoError::Malformed(_))
        ));
    }

    #[test]
    fn response_rejects_wrong_structure_size() {
        let buf = [8, 0, 0, 0, 0, 0, 0, 0];

        assert!(matches!(
            QueryInfoResponse::parse(&buf),
            Err(ProtoError::Malformed(_))
        ));
    }
}
