//! FLUSH Request/Response (MS-SMB2 §2.2.17 / §2.2.18).

use binrw::{BinRead, BinWrite, binrw};
use std::io::Cursor;

use crate::proto::error::{ProtoError, ProtoResult};

#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlushRequest {
    pub structure_size: u16,
    pub reserved1: u16,
    pub reserved2: u32,
    /// Volatile portion of the FileId.
    pub file_id_persistent: u64,
    /// Persistent portion of the FileId.
    pub file_id_volatile: u64,
}

impl FlushRequest {
    pub fn new(persistent: u64, volatile: u64) -> Self {
        Self {
            structure_size: 24,
            reserved1: 0,
            reserved2: 0,
            file_id_persistent: persistent,
            file_id_volatile: volatile,
        }
    }

    pub fn parse(buf: &[u8]) -> ProtoResult<Self> {
        if buf.len() < 24 {
            return Err(ProtoError::Malformed("flush request too short"));
        }
        let request = Self::read(&mut Cursor::new(buf))?;
        if request.structure_size != 24 {
            return Err(ProtoError::Malformed("flush request structure_size != 24"));
        }
        Ok(request)
    }
}

#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlushResponse {
    pub structure_size: u16,
    pub reserved: u16,
}

impl Default for FlushResponse {
    fn default() -> Self {
        Self {
            structure_size: 4,
            reserved: 0,
        }
    }
}

impl FlushRequest {
    pub fn write_to(&self, out: &mut Vec<u8>) -> ProtoResult<()> {
        let mut c = Cursor::new(Vec::new());
        BinWrite::write(self, &mut c)?;
        out.extend_from_slice(&c.into_inner());
        Ok(())
    }
}

impl FlushResponse {
    pub fn parse(buf: &[u8]) -> ProtoResult<Self> {
        if buf.len() < 4 {
            return Err(ProtoError::Malformed("flush response too short"));
        }
        let response = Self::read(&mut Cursor::new(buf))?;
        if response.structure_size != 4 {
            return Err(ProtoError::Malformed("flush response structure_size != 4"));
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips() {
        let r = FlushRequest::new(0x1122_3344_5566_7788, 0xAABB_CCDD_EEFF_0011);
        let mut buf = Vec::new();
        r.write_to(&mut buf).unwrap();
        assert_eq!(buf.len(), 24);
        assert_eq!(FlushRequest::parse(&buf).unwrap(), r);

        let r = FlushResponse::default();
        let mut buf = Vec::new();
        r.write_to(&mut buf).unwrap();
        assert_eq!(FlushResponse::parse(&buf).unwrap(), r);
    }

    #[test]
    fn request_rejects_wrong_structure_size() {
        let mut buf = vec![0; 24];
        buf[0..2].copy_from_slice(&23u16.to_le_bytes());

        assert!(matches!(
            FlushRequest::parse(&buf),
            Err(ProtoError::Malformed(_))
        ));
    }

    #[test]
    fn response_rejects_wrong_structure_size() {
        let buf = [3, 0, 0, 0];

        assert!(matches!(
            FlushResponse::parse(&buf),
            Err(ProtoError::Malformed(_))
        ));
    }
}
