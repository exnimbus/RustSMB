//! CANCEL Request (MS-SMB2 §2.2.30). No response — server cancels in place.

use binrw::{BinRead, BinWrite, binrw};
use std::io::Cursor;

use crate::proto::error::{ProtoError, ProtoResult};

#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CancelRequest {
    pub structure_size: u16,
    pub reserved: u16,
}

impl Default for CancelRequest {
    fn default() -> Self {
        Self {
            structure_size: 4,
            reserved: 0,
        }
    }
}

impl CancelRequest {
    pub fn parse(buf: &[u8]) -> ProtoResult<Self> {
        let request = Self::read(&mut Cursor::new(buf))?;
        if request.structure_size != 4 {
            return Err(ProtoError::Malformed("cancel request structure_size != 4"));
        }
        Ok(request)
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
        let r = CancelRequest::default();
        let mut buf = Vec::new();
        r.write_to(&mut buf).unwrap();
        assert_eq!(buf.len(), 4);
        assert_eq!(CancelRequest::parse(&buf).unwrap(), r);
    }

    #[test]
    fn rejects_wrong_structure_size() {
        let buf = [5, 0, 0, 0];
        assert!(matches!(
            CancelRequest::parse(&buf),
            Err(ProtoError::Malformed(_))
        ));
    }
}
