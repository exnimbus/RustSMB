//! TREE_DISCONNECT Request/Response (MS-SMB2 §2.2.11 / §2.2.12).

use binrw::{BinRead, BinWrite, binrw};
use std::io::Cursor;

use crate::proto::error::{ProtoError, ProtoResult};

#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TreeDisconnectRequest {
    pub structure_size: u16,
    pub reserved: u16,
}

impl Default for TreeDisconnectRequest {
    fn default() -> Self {
        Self {
            structure_size: 4,
            reserved: 0,
        }
    }
}

#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TreeDisconnectResponse {
    pub structure_size: u16,
    pub reserved: u16,
}

impl Default for TreeDisconnectResponse {
    fn default() -> Self {
        Self {
            structure_size: 4,
            reserved: 0,
        }
    }
}

macro_rules! impl_codec {
    ($t:ty) => {
        impl $t {
            pub fn parse(buf: &[u8]) -> ProtoResult<Self> {
                let message = <Self as BinRead>::read(&mut Cursor::new(buf))?;
                if message.structure_size != 4 {
                    return Err(ProtoError::Malformed("tree disconnect structure_size != 4"));
                }
                Ok(message)
            }
            pub fn write_to(&self, out: &mut Vec<u8>) -> ProtoResult<()> {
                let mut c = Cursor::new(Vec::new());
                BinWrite::write(self, &mut c)?;
                out.extend_from_slice(&c.into_inner());
                Ok(())
            }
        }
    };
}

impl_codec!(TreeDisconnectRequest);
impl_codec!(TreeDisconnectResponse);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips() {
        let r = TreeDisconnectRequest::default();
        let mut buf = Vec::new();
        r.write_to(&mut buf).unwrap();
        assert_eq!(TreeDisconnectRequest::parse(&buf).unwrap(), r);

        let r = TreeDisconnectResponse::default();
        let mut buf = Vec::new();
        r.write_to(&mut buf).unwrap();
        assert_eq!(TreeDisconnectResponse::parse(&buf).unwrap(), r);
    }

    #[test]
    fn request_rejects_wrong_structure_size() {
        let buf = [5, 0, 0, 0];
        assert!(matches!(
            TreeDisconnectRequest::parse(&buf),
            Err(ProtoError::Malformed(_))
        ));
    }

    #[test]
    fn response_rejects_wrong_structure_size() {
        let buf = [5, 0, 0, 0];
        assert!(matches!(
            TreeDisconnectResponse::parse(&buf),
            Err(ProtoError::Malformed(_))
        ));
    }
}
