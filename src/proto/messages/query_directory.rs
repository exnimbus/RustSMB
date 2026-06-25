//! QUERY_DIRECTORY Request/Response (MS-SMB2 §2.2.33 / §2.2.34).

use binrw::{BinRead, BinWrite, binrw};
use std::io::Cursor;

use super::create::FileId;
use crate::proto::error::{ProtoError, ProtoResult};

/// File-info-class identifiers used in QUERY_DIRECTORY (MS-SMB2 §2.2.33
/// FileInformationClass).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FileInfoClass {
    FileDirectoryInformation = 0x01,
    FileFullDirectoryInformation = 0x02,
    FileBothDirectoryInformation = 0x03,
    FileNamesInformation = 0x0C,
    FileIdBothDirectoryInformation = 0x25,
    FileIdFullDirectoryInformation = 0x26,
    FileIdExtdDirectoryInformation = 0x3C,
    FileId64ExtdDirectoryInformation = 0x4E,
    FileId64ExtdBothDirectoryInformation = 0x4F,
    FileIdAllExtdDirectoryInformation = 0x50,
    FileIdAllExtdBothDirectoryInformation = 0x51,
    FilePosixInformation = 0x64,
}

impl FileInfoClass {
    pub fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            0x01 => Self::FileDirectoryInformation,
            0x02 => Self::FileFullDirectoryInformation,
            0x03 => Self::FileBothDirectoryInformation,
            0x0C => Self::FileNamesInformation,
            0x25 => Self::FileIdBothDirectoryInformation,
            0x26 => Self::FileIdFullDirectoryInformation,
            0x3C => Self::FileIdExtdDirectoryInformation,
            0x4E => Self::FileId64ExtdDirectoryInformation,
            0x4F => Self::FileId64ExtdBothDirectoryInformation,
            0x50 => Self::FileIdAllExtdDirectoryInformation,
            0x51 => Self::FileIdAllExtdBothDirectoryInformation,
            0x64 => Self::FilePosixInformation,
            _ => return None,
        })
    }
}

/// SMB2_QUERY_DIRECTORY_REQUEST (MS-SMB2 §2.2.33).
#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryDirectoryRequest {
    pub structure_size: u16,
    pub file_information_class: u8,
    pub flags: u8,
    pub file_index: u32,
    pub file_id: FileId,
    pub file_name_offset: u16,
    pub file_name_length: u16,
    pub output_buffer_length: u32,
    /// UTF-16LE search pattern (e.g. "*").
    #[br(count = file_name_length as usize)]
    pub file_name: Vec<u8>,
}

impl QueryDirectoryRequest {
    pub const FLAG_RESTART_SCANS: u8 = 0x01;
    pub const FLAG_RETURN_SINGLE_ENTRY: u8 = 0x02;
    pub const FLAG_INDEX_SPECIFIED: u8 = 0x04;
    pub const FLAG_REOPEN: u8 = 0x10;

    pub fn parse(buf: &[u8]) -> ProtoResult<Self> {
        if buf.len() < 32 {
            return Err(ProtoError::Malformed("query directory request too short"));
        }
        let structure_size = read_u16(buf, 0)?;
        if structure_size != 33 {
            return Err(ProtoError::Malformed(
                "query directory request structure_size != 33",
            ));
        }
        let file_name_offset = read_u16(buf, 24)?;
        let file_name_length = read_u16(buf, 26)?;
        let file_name = if file_name_length == 0 {
            Vec::new()
        } else {
            if file_name_length % 2 != 0 {
                return Err(ProtoError::Malformed(
                    "query directory file name length is not UTF-16 aligned",
                ));
            }
            let offset = (file_name_offset as usize)
                .checked_sub(crate::proto::header::SMB2_HEADER_LEN)
                .ok_or(ProtoError::Malformed(
                    "query directory file name offset before SMB2 body",
                ))?;
            let length = file_name_length as usize;
            let end = offset
                .checked_add(length)
                .ok_or(ProtoError::Malformed("query directory file name overflow"))?;
            if offset < 32 || end > buf.len() {
                return Err(ProtoError::Malformed(
                    "query directory file name out of range",
                ));
            }
            buf[offset..end].to_vec()
        };

        Ok(Self {
            structure_size,
            file_information_class: buf[2],
            flags: buf[3],
            file_index: read_u32(buf, 4)?,
            file_id: FileId::new(read_u64(buf, 8)?, read_u64(buf, 16)?),
            file_name_offset,
            file_name_length,
            output_buffer_length: read_u32(buf, 28)?,
            file_name,
        })
    }
    pub fn write_to(&self, out: &mut Vec<u8>) -> ProtoResult<()> {
        let mut c = Cursor::new(Vec::new());
        BinWrite::write(self, &mut c)?;
        out.extend_from_slice(&c.into_inner());
        Ok(())
    }
}

/// SMB2_QUERY_DIRECTORY_RESPONSE (MS-SMB2 §2.2.34).
#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryDirectoryResponse {
    pub structure_size: u16,
    /// `OutputBufferOffset` is from the start of the SMB2 header.
    pub output_buffer_offset: u16,
    pub output_buffer_length: u32,
    /// Variable-length info-class-specific buffer.
    #[br(count = output_buffer_length as usize)]
    pub buffer: Vec<u8>,
}

impl QueryDirectoryResponse {
    pub fn parse(buf: &[u8]) -> ProtoResult<Self> {
        let response = Self::read(&mut Cursor::new(buf))?;
        if response.structure_size != 9 {
            return Err(ProtoError::Malformed(
                "query directory response structure_size != 9",
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
        .ok_or(ProtoError::Malformed("query directory u16 out of range"))?;
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn read_u32(buf: &[u8], offset: usize) -> ProtoResult<u32> {
    let bytes = buf
        .get(offset..offset + 4)
        .ok_or(ProtoError::Malformed("query directory u32 out of range"))?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn read_u64(buf: &[u8], offset: usize) -> ProtoResult<u64> {
    let bytes = buf
        .get(offset..offset + 8)
        .ok_or(ProtoError::Malformed("query directory u64 out of range"))?;
    Ok(u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ]))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn utf16le(s: &str) -> Vec<u8> {
        s.encode_utf16().flat_map(u16::to_le_bytes).collect()
    }

    #[test]
    fn request_round_trips() {
        let pat = utf16le("*");
        let r = QueryDirectoryRequest {
            structure_size: 33,
            file_information_class: FileInfoClass::FileIdBothDirectoryInformation as u8,
            flags: QueryDirectoryRequest::FLAG_RESTART_SCANS,
            file_index: 0,
            file_id: FileId::new(1, 2),
            file_name_offset: 0x60,
            file_name_length: pat.len() as u16,
            output_buffer_length: 0x10000,
            file_name: pat,
        };
        let mut buf = Vec::new();
        r.write_to(&mut buf).unwrap();
        assert_eq!(QueryDirectoryRequest::parse(&buf).unwrap(), r);
    }

    #[test]
    fn response_round_trips() {
        let r = QueryDirectoryResponse {
            structure_size: 9,
            output_buffer_offset: 0x48,
            output_buffer_length: 8,
            buffer: vec![1, 2, 3, 4, 5, 6, 7, 8],
        };
        let mut buf = Vec::new();
        r.write_to(&mut buf).unwrap();
        assert_eq!(QueryDirectoryResponse::parse(&buf).unwrap(), r);
    }

    #[test]
    fn request_decodes_file_id_and_padded_pattern() {
        let pattern = utf16le("*.log");
        let mut buf = vec![0; 40 + pattern.len()];
        buf[0..2].copy_from_slice(&33u16.to_le_bytes());
        buf[2] = FileInfoClass::FileNamesInformation as u8;
        buf[3] = QueryDirectoryRequest::FLAG_RESTART_SCANS;
        buf[4..8].copy_from_slice(&7u32.to_le_bytes());
        buf[8..16].copy_from_slice(&13u64.to_le_bytes());
        buf[16..24].copy_from_slice(&17u64.to_le_bytes());
        buf[24..26]
            .copy_from_slice(&(crate::proto::header::SMB2_HEADER_LEN as u16 + 40).to_le_bytes());
        buf[26..28].copy_from_slice(&(pattern.len() as u16).to_le_bytes());
        buf[28..32].copy_from_slice(&4096u32.to_le_bytes());
        buf[40..40 + pattern.len()].copy_from_slice(&pattern);

        let decoded = QueryDirectoryRequest::parse(&buf).unwrap();

        assert_eq!(decoded.file_id, FileId::new(13, 17));
        assert_eq!(decoded.file_name, pattern);
        assert_eq!(decoded.file_index, 7);
        assert_eq!(decoded.output_buffer_length, 4096);
    }

    #[test]
    fn request_rejects_wrong_structure_size() {
        let mut buf = vec![0; 32];
        buf[0..2].copy_from_slice(&32u16.to_le_bytes());

        assert!(matches!(
            QueryDirectoryRequest::parse(&buf),
            Err(ProtoError::Malformed(_))
        ));
    }

    #[test]
    fn request_rejects_odd_file_name_length() {
        let mut buf = vec![0; 33];
        buf[0..2].copy_from_slice(&33u16.to_le_bytes());
        buf[24..26]
            .copy_from_slice(&(crate::proto::header::SMB2_HEADER_LEN as u16 + 32).to_le_bytes());
        buf[26..28].copy_from_slice(&1u16.to_le_bytes());
        buf[32] = b'*';

        assert!(matches!(
            QueryDirectoryRequest::parse(&buf),
            Err(ProtoError::Malformed(_))
        ));
    }

    #[test]
    fn request_rejects_file_name_out_of_range() {
        let mut buf = vec![0; 32];
        buf[0..2].copy_from_slice(&33u16.to_le_bytes());
        buf[24..26]
            .copy_from_slice(&(crate::proto::header::SMB2_HEADER_LEN as u16 + 32).to_le_bytes());
        buf[26..28].copy_from_slice(&2u16.to_le_bytes());

        assert!(matches!(
            QueryDirectoryRequest::parse(&buf),
            Err(ProtoError::Malformed(_))
        ));
    }

    #[test]
    fn response_rejects_wrong_structure_size() {
        let buf = [8, 0, 0, 0, 0, 0, 0, 0];

        assert!(matches!(
            QueryDirectoryResponse::parse(&buf),
            Err(ProtoError::Malformed(_))
        ));
    }
}
