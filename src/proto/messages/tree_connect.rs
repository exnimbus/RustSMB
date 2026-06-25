//! TREE_CONNECT Request/Response (MS-SMB2 §2.2.9 / §2.2.10).

use binrw::{BinWrite, binrw};
use std::io::Cursor;

use crate::proto::error::{ProtoError, ProtoResult};

/// SMB2_TREE_CONNECT_REQUEST (MS-SMB2 §2.2.9).
///
/// `path` is UTF-16LE. The wire format gives `PathOffset` (from the start of
/// the SMB2 header) and `PathLength`; we encode/decode the path immediately
/// following the fixed prefix. The 3.1.1 tree-connect-context machinery
/// (extension `flags`, `path_offset`/`path_length` interpretation) is
/// preserved on the wire and the server crate inspects `flags` if needed.
#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TreeConnectRequest {
    pub structure_size: u16,
    /// 3.1.1: flags. 2.x/3.0/3.0.2: reserved.
    pub flags: u16,
    pub path_offset: u16,
    pub path_length: u16,
    /// UTF-16LE share path bytes (e.g. `\\server\share`).
    #[br(count = path_length as usize)]
    pub path: Vec<u8>,
}

impl TreeConnectRequest {
    /// Flag: SMB2_TREE_CONNECT_FLAG_CLUSTER_RECONNECT (3.1.1).
    pub const FLAG_CLUSTER_RECONNECT: u16 = 0x0001;
    /// Flag: SMB2_TREE_CONNECT_FLAG_REDIRECT_TO_OWNER (3.1.1).
    pub const FLAG_REDIRECT_TO_OWNER: u16 = 0x0002;
    /// Flag: SMB2_TREE_CONNECT_FLAG_EXTENSION_PRESENT (3.1.1).
    pub const FLAG_EXTENSION_PRESENT: u16 = 0x0004;

    /// Decode the UTF-16LE share path into a `String`. Returns `None` if the
    /// stored bytes are not an even length (malformed UTF-16LE).
    pub fn path_str(&self) -> Option<String> {
        if !self.path.len().is_multiple_of(2) {
            return None;
        }
        let units: Vec<u16> = self
            .path
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        Some(String::from_utf16_lossy(&units))
    }

    pub fn parse(buf: &[u8]) -> ProtoResult<Self> {
        if buf.len() < 8 {
            return Err(ProtoError::Malformed("tree connect request too short"));
        }
        let structure_size = read_u16(buf, 0)?;
        if structure_size != 9 {
            return Err(ProtoError::Malformed(
                "tree connect request structure_size != 9",
            ));
        }
        let path_offset = read_u16(buf, 4)?;
        let path_length = read_u16(buf, 6)?;
        if path_length % 2 != 0 {
            return Err(ProtoError::Malformed(
                "tree connect request path length is not UTF-16 aligned",
            ));
        }
        let offset = (path_offset as usize)
            .checked_sub(crate::proto::header::SMB2_HEADER_LEN)
            .ok_or(ProtoError::Malformed(
                "tree connect path offset before SMB2 body",
            ))?;
        let end = offset
            .checked_add(path_length as usize)
            .ok_or(ProtoError::Malformed("tree connect path range overflow"))?;
        if offset < 8 || end > buf.len() {
            return Err(ProtoError::Malformed("tree connect path out of range"));
        }
        Ok(Self {
            structure_size,
            flags: read_u16(buf, 2)?,
            path_offset,
            path_length,
            path: buf[offset..end].to_vec(),
        })
    }
    pub fn write_to(&self, out: &mut Vec<u8>) -> ProtoResult<()> {
        let mut c = Cursor::new(Vec::new());
        BinWrite::write(self, &mut c)?;
        out.extend_from_slice(&c.into_inner());
        Ok(())
    }
}

/// SMB2_TREE_CONNECT_RESPONSE (MS-SMB2 §2.2.10).
#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TreeConnectResponse {
    pub structure_size: u16,
    pub share_type: u8,
    pub reserved: u8,
    pub share_flags: u32,
    pub capabilities: u32,
    pub maximal_access: u32,
}

impl TreeConnectResponse {
    /// Share type: SMB2_SHARE_TYPE_DISK.
    pub const SHARE_TYPE_DISK: u8 = 0x01;
    pub const SHARE_TYPE_PIPE: u8 = 0x02;
    pub const SHARE_TYPE_PRINT: u8 = 0x03;
    pub const SHARE_FLAG_MANUAL_CACHING: u32 = 0x0000_0000;
    pub const SHARE_FLAG_NO_CACHING: u32 = 0x0000_0030;
    pub const SHARE_FLAG_ENCRYPT_DATA: u32 = 0x0000_8000;
    pub const SHARE_FLAG_COMPRESS_DATA: u32 = 0x0010_0000;
    pub const SHARE_FLAG_ISOLATED_TRANSPORT: u32 = 0x0020_0000;

    pub fn parse(buf: &[u8]) -> ProtoResult<Self> {
        if buf.len() < 16 {
            return Err(ProtoError::Malformed("tree connect response too short"));
        }
        let response = Self {
            structure_size: read_u16(buf, 0)?,
            share_type: read_u8(buf, 2)?,
            reserved: read_u8(buf, 3)?,
            share_flags: read_u32(buf, 4)?,
            capabilities: read_u32(buf, 8)?,
            maximal_access: read_u32(buf, 12)?,
        };
        if response.structure_size != 16 {
            return Err(ProtoError::Malformed(
                "tree connect response structure_size != 16",
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

fn read_u8(buf: &[u8], offset: usize) -> ProtoResult<u8> {
    buf.get(offset)
        .copied()
        .ok_or(ProtoError::Malformed("tree connect u8 out of range"))
}

fn read_u16(buf: &[u8], offset: usize) -> ProtoResult<u16> {
    let bytes = buf
        .get(offset..offset + 2)
        .ok_or(ProtoError::Malformed("tree connect u16 out of range"))?;
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn read_u32(buf: &[u8], offset: usize) -> ProtoResult<u32> {
    let bytes = buf
        .get(offset..offset + 4)
        .ok_or(ProtoError::Malformed("tree connect u32 out of range"))?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn utf16le(s: &str) -> Vec<u8> {
        s.encode_utf16().flat_map(u16::to_le_bytes).collect()
    }

    #[test]
    fn request_round_trips() {
        let path = utf16le(r"\\server\share");
        let r = TreeConnectRequest {
            structure_size: 9,
            flags: 0,
            path_offset: 0x48,
            path_length: path.len() as u16,
            path,
        };
        let mut buf = Vec::new();
        r.write_to(&mut buf).unwrap();
        let decoded = TreeConnectRequest::parse(&buf).unwrap();
        assert_eq!(decoded, r);
        assert_eq!(decoded.path_str().unwrap(), r"\\server\share");
    }

    #[test]
    fn request_decodes_padded_path_from_header_relative_offset() {
        let path = utf16le(r"\\server\share");
        let mut buf = vec![0; 16 + path.len()];
        buf[0..2].copy_from_slice(&9u16.to_le_bytes());
        buf[4..6]
            .copy_from_slice(&(crate::proto::header::SMB2_HEADER_LEN as u16 + 16).to_le_bytes());
        buf[6..8].copy_from_slice(&(path.len() as u16).to_le_bytes());
        buf[16..16 + path.len()].copy_from_slice(&path);

        let decoded = TreeConnectRequest::parse(&buf).unwrap();

        assert_eq!(decoded.path, path);
        assert_eq!(decoded.path_str().unwrap(), r"\\server\share");
    }

    #[test]
    fn request_rejects_wrong_structure_size() {
        let mut buf = vec![0; 8];
        buf[0..2].copy_from_slice(&8u16.to_le_bytes());

        assert!(matches!(
            TreeConnectRequest::parse(&buf),
            Err(ProtoError::Malformed(_))
        ));
    }

    #[test]
    fn request_rejects_odd_path_length() {
        let mut buf = vec![0; 9];
        buf[0..2].copy_from_slice(&9u16.to_le_bytes());
        buf[4..6]
            .copy_from_slice(&(crate::proto::header::SMB2_HEADER_LEN as u16 + 8).to_le_bytes());
        buf[6..8].copy_from_slice(&1u16.to_le_bytes());

        assert!(matches!(
            TreeConnectRequest::parse(&buf),
            Err(ProtoError::Malformed(_))
        ));
    }

    #[test]
    fn request_rejects_path_out_of_range() {
        let mut buf = vec![0; 8];
        buf[0..2].copy_from_slice(&9u16.to_le_bytes());
        buf[4..6]
            .copy_from_slice(&(crate::proto::header::SMB2_HEADER_LEN as u16 + 8).to_le_bytes());
        buf[6..8].copy_from_slice(&2u16.to_le_bytes());

        assert!(matches!(
            TreeConnectRequest::parse(&buf),
            Err(ProtoError::Malformed(_))
        ));
    }

    #[test]
    fn response_round_trips() {
        let r = TreeConnectResponse {
            structure_size: 16,
            share_type: TreeConnectResponse::SHARE_TYPE_DISK,
            reserved: 0,
            share_flags: 0,
            capabilities: 0,
            maximal_access: 0x001F_01FF,
        };
        let mut buf = Vec::new();
        r.write_to(&mut buf).unwrap();
        assert_eq!(TreeConnectResponse::parse(&buf).unwrap(), r);
    }

    #[test]
    fn response_rejects_wrong_structure_size() {
        let mut buf = vec![0; 16];
        buf[0..2].copy_from_slice(&15u16.to_le_bytes());

        assert!(matches!(
            TreeConnectResponse::parse(&buf),
            Err(ProtoError::Malformed(_))
        ));
    }
}
