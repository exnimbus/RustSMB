//! CREATE Request/Response (MS-SMB2 §2.2.13 / §2.2.14).
//!
//! `create_contexts` is a chained sequence of `SMB2_CREATE_CONTEXT` records
//! (MS-SMB2 §2.2.13.2). Each record has `Next` (offset to the next entry,
//! relative to the start of *this* entry; 0 marks the last), a name + data
//! pair, and 8-byte alignment.

use binrw::{BinWrite, binrw};
use std::io::Cursor;

use crate::proto::error::{ProtoError, ProtoResult};

/// SMB2 FileId — opaque 16 bytes (volatile + persistent).
///
/// MS-SMB2 §2.2.14.1. We expose both halves; the server uses identical values
/// for both since durable handles are out of scope (spec §2 in the v1 design).
#[binrw]
#[brw(little)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct FileId {
    pub persistent: u64,
    pub volatile: u64,
}

impl FileId {
    pub const fn new(persistent: u64, volatile: u64) -> Self {
        Self {
            persistent,
            volatile,
        }
    }

    /// MS-SMB2: the "any" FileId is `0xFFFF…FFFF`.
    pub const fn any() -> Self {
        Self {
            persistent: u64::MAX,
            volatile: u64::MAX,
        }
    }
}

/// MS-SMB2 §2.2.13 CREATE Request — fixed prefix.
///
/// Variable-length tail: the file `name` (UTF-16LE) and `create_contexts`
/// blob, each at absolute offsets from the start of the SMB2 header. We hold
/// them as length-counted byte buffers immediately following the fixed
/// portion. The server crate parses contexts with [`CreateContext::parse_chain`].
#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateRequest {
    pub structure_size: u16,
    pub security_flags: u8,
    pub requested_oplock_level: u8,
    pub impersonation_level: u32,
    pub smb_create_flags: u64,
    pub reserved: u64,
    pub desired_access: u32,
    pub file_attributes: u32,
    pub share_access: u32,
    pub create_disposition: u32,
    pub create_options: u32,
    pub name_offset: u16,
    pub name_length: u16,
    pub create_contexts_offset: u32,
    pub create_contexts_length: u32,
    /// UTF-16LE filename.
    #[br(count = name_length as usize)]
    pub name: Vec<u8>,
    /// Raw create-contexts chain bytes; parse with
    /// [`CreateContext::parse_chain`].
    #[br(count = create_contexts_length as usize)]
    pub create_contexts: Vec<u8>,
}

impl CreateRequest {
    /// Decode the UTF-16LE filename.
    pub fn name_str(&self) -> Option<String> {
        if !self.name.len().is_multiple_of(2) {
            return None;
        }
        let units: Vec<u16> = self
            .name
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        Some(String::from_utf16_lossy(&units))
    }

    pub fn parse(buf: &[u8]) -> ProtoResult<Self> {
        if buf.len() < 56 {
            return Err(ProtoError::Malformed("create request too short"));
        }
        let structure_size = read_u16(buf, 0)?;
        if structure_size != 57 {
            return Err(ProtoError::Malformed("create request structure_size != 57"));
        }
        let name_offset = read_u16(buf, 44)?;
        let name_length = read_u16(buf, 46)?;
        if name_length % 2 != 0 {
            return Err(ProtoError::Malformed("create request name length is odd"));
        }
        let name_start = (name_offset as usize)
            .checked_sub(crate::proto::header::SMB2_HEADER_LEN)
            .ok_or(ProtoError::Malformed(
                "create request name offset before SMB2 body",
            ))?;
        let name_end = name_start
            .checked_add(name_length as usize)
            .ok_or(ProtoError::Malformed("create request name range overflow"))?;
        if name_start < 56 || name_end > buf.len() {
            return Err(ProtoError::Malformed("create request name out of range"));
        }

        let create_contexts_offset = read_u32(buf, 48)?;
        let create_contexts_length = read_u32(buf, 52)?;
        let create_contexts =
            if create_contexts_length == 0 {
                Vec::new()
            } else {
                let start = (create_contexts_offset as usize)
                    .checked_sub(crate::proto::header::SMB2_HEADER_LEN)
                    .ok_or(ProtoError::Malformed(
                        "create request context offset before SMB2 body",
                    ))?;
                let end = start.checked_add(create_contexts_length as usize).ok_or(
                    ProtoError::Malformed("create request context range overflow"),
                )?;
                if start < 56 || end > buf.len() {
                    return Err(ProtoError::Malformed("create request context out of range"));
                }
                let chain = &buf[start..end];
                CreateContext::parse_chain(chain)?;
                chain.to_vec()
            };

        Ok(Self {
            structure_size,
            security_flags: buf[2],
            requested_oplock_level: buf[3],
            impersonation_level: read_u32(buf, 4)?,
            smb_create_flags: read_u64(buf, 8)?,
            reserved: read_u64(buf, 16)?,
            desired_access: read_u32(buf, 24)?,
            file_attributes: read_u32(buf, 28)?,
            share_access: read_u32(buf, 32)?,
            create_disposition: read_u32(buf, 36)?,
            create_options: read_u32(buf, 40)?,
            name_offset,
            name_length,
            create_contexts_offset,
            create_contexts_length,
            name: buf[name_start..name_end].to_vec(),
            create_contexts,
        })
    }
    pub fn write_to(&self, out: &mut Vec<u8>) -> ProtoResult<()> {
        let mut c = Cursor::new(Vec::new());
        BinWrite::write(self, &mut c)?;
        out.extend_from_slice(&c.into_inner());
        Ok(())
    }
}

/// MS-SMB2 §2.2.14 CREATE Response.
#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateResponse {
    pub structure_size: u16,
    pub oplock_level: u8,
    pub flags: u8,
    pub create_action: u32,
    pub creation_time: u64,
    pub last_access_time: u64,
    pub last_write_time: u64,
    pub change_time: u64,
    pub allocation_size: u64,
    pub end_of_file: u64,
    pub file_attributes: u32,
    pub reserved2: u32,
    pub file_id: FileId,
    pub create_contexts_offset: u32,
    pub create_contexts_length: u32,
    #[br(count = create_contexts_length as usize)]
    pub create_contexts: Vec<u8>,
}

impl CreateResponse {
    pub fn parse(buf: &[u8]) -> ProtoResult<Self> {
        if buf.len() < 88 {
            return Err(ProtoError::Malformed("create response too short"));
        }
        let structure_size = read_u16(buf, 0)?;
        if structure_size != 89 {
            return Err(ProtoError::Malformed(
                "create response structure_size != 89",
            ));
        }
        let create_contexts_offset = read_u32(buf, 80)?;
        let create_contexts_length = read_u32(buf, 84)?;
        let create_contexts =
            if create_contexts_length == 0 {
                Vec::new()
            } else {
                let start = (create_contexts_offset as usize)
                    .checked_sub(crate::proto::header::SMB2_HEADER_LEN)
                    .ok_or(ProtoError::Malformed(
                        "create response context offset before SMB2 body",
                    ))?;
                let end = start.checked_add(create_contexts_length as usize).ok_or(
                    ProtoError::Malformed("create response context range overflow"),
                )?;
                if start < 88 || end > buf.len() {
                    return Err(ProtoError::Malformed(
                        "create response context out of range",
                    ));
                }
                let chain = &buf[start..end];
                CreateContext::parse_chain(chain)?;
                chain.to_vec()
            };

        Ok(Self {
            structure_size,
            oplock_level: buf[2],
            flags: buf[3],
            create_action: read_u32(buf, 4)?,
            creation_time: read_u64(buf, 8)?,
            last_access_time: read_u64(buf, 16)?,
            last_write_time: read_u64(buf, 24)?,
            change_time: read_u64(buf, 32)?,
            allocation_size: read_u64(buf, 40)?,
            end_of_file: read_u64(buf, 48)?,
            file_attributes: read_u32(buf, 56)?,
            reserved2: read_u32(buf, 60)?,
            file_id: FileId::new(read_u64(buf, 64)?, read_u64(buf, 72)?),
            create_contexts_offset,
            create_contexts_length,
            create_contexts,
        })
    }
    pub fn write_to(&self, out: &mut Vec<u8>) -> ProtoResult<()> {
        let mut c = Cursor::new(Vec::new());
        BinWrite::write(self, &mut c)?;
        out.extend_from_slice(&c.into_inner());
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Create contexts (MS-SMB2 §2.2.13.2)
// ---------------------------------------------------------------------------

/// Generic SMB2_CREATE_CONTEXT envelope.
///
/// Per MS-SMB2 §2.2.13.2 each entry has:
/// * `Next` — offset (bytes) from the start of *this* entry to the start of
///   the next entry in the chain, or 0 for the last entry.
/// * `NameOffset`/`NameLength` — name (typically a 4-byte ASCII tag) at an
///   offset relative to the entry start.
/// * `Reserved` — 2 bytes.
/// * `DataOffset`/`DataLength` — payload at an offset relative to the entry
///   start.
///
/// We model the entry as `name` + `data` byte vectors plus the raw flags. The
/// chain reader / writer below handles `Next` and 8-byte alignment between
/// entries.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CreateContext {
    pub name: Vec<u8>,
    pub data: Vec<u8>,
}

impl CreateContext {
    // Well-known names (MS-SMB2 §2.2.13.2 table). 4-byte ASCII tags.
    pub const NAME_EXTA: &'static [u8; 4] = b"ExtA"; // SMB2_CREATE_EA_BUFFER
    pub const NAME_SECD: &'static [u8; 4] = b"SecD"; // SMB2_CREATE_SD_BUFFER
    pub const NAME_DHNQ: &'static [u8; 4] = b"DHnQ"; // DURABLE_HANDLE_REQUEST
    pub const NAME_DHNC: &'static [u8; 4] = b"DHnC"; // DURABLE_HANDLE_RECONNECT
    pub const NAME_ALSI: &'static [u8; 4] = b"AlSi"; // ALLOCATION_SIZE
    pub const NAME_MXAC: &'static [u8; 4] = b"MxAc"; // QUERY_MAXIMAL_ACCESS
    pub const NAME_TWRP: &'static [u8; 4] = b"TWrp"; // TIMEWARP_TOKEN
    pub const NAME_QFID: &'static [u8; 4] = b"QFid"; // QUERY_ON_DISK_ID
    pub const NAME_RQLS: &'static [u8; 4] = b"RqLs"; // REQUEST_LEASE
    pub const NAME_DH2Q: &'static [u8; 4] = b"DH2Q"; // DURABLE_HANDLE_REQUEST_V2
    pub const NAME_DH2C: &'static [u8; 4] = b"DH2C"; // DURABLE_HANDLE_RECONNECT_V2
    pub const NAME_AAPL: &'static [u8; 4] = b"AAPL"; // Apple SMB2 extension query
    pub const NAME_APP_INSTANCE_ID: &'static [u8; 16] = &[
        0x45, 0xBC, 0xA6, 0x6A, 0xEF, 0xA7, 0xF7, 0x4A, 0x90, 0x08, 0xFA, 0x46, 0x2E, 0x14, 0x4D,
        0x74,
    ];
    pub const NAME_APP_INSTANCE_VERSION: &'static [u8; 16] = &[
        0xB9, 0x82, 0xD0, 0xB7, 0x3B, 0x56, 0x07, 0x4F, 0xA0, 0x7B, 0x52, 0x4A, 0x81, 0x16, 0xA0,
        0x10,
    ];
    pub const NAME_POSIX: &'static [u8; 16] = &[
        0x93, 0xAD, 0x25, 0x50, 0x9C, 0xB4, 0x11, 0xE7, 0xB4, 0x23, 0x83, 0xDE, 0x96, 0x8B, 0xCD,
        0x7C,
    ];

    /// Parse a chain of create-contexts from the raw chain bytes.
    ///
    /// The chain is empty if `chain.is_empty()`. Otherwise we walk `Next`
    /// offsets until we hit a zero terminator, validating bounds at each step.
    pub fn parse_chain(chain: &[u8]) -> ProtoResult<Vec<CreateContext>> {
        let mut out = Vec::new();
        if chain.is_empty() {
            return Ok(out);
        }
        let mut cursor_off = 0usize;
        loop {
            if cursor_off >= chain.len() {
                return Err(ProtoError::Malformed("create context out of range"));
            }
            if cursor_off + 16 > chain.len() {
                return Err(ProtoError::Malformed("create context too short"));
            }
            let header = &chain[cursor_off..];
            let next = u32::from_le_bytes([header[0], header[1], header[2], header[3]]) as usize;
            let ctx_end = if next == 0 {
                chain.len()
            } else {
                if next < 16 || !next.is_multiple_of(8) {
                    return Err(ProtoError::Malformed("create context invalid next"));
                }
                cursor_off
                    .checked_add(next)
                    .ok_or(ProtoError::Malformed("create context next overflow"))?
            };
            if ctx_end > chain.len() {
                return Err(ProtoError::Malformed("create context next out of range"));
            }
            let entry = &chain[cursor_off..ctx_end];

            let name_offset = u16::from_le_bytes([entry[4], entry[5]]) as usize;
            let name_length = u16::from_le_bytes([entry[6], entry[7]]) as usize;
            // entry[8..10] = reserved
            let data_offset = u16::from_le_bytes([entry[10], entry[11]]) as usize;
            let data_length =
                u32::from_le_bytes([entry[12], entry[13], entry[14], entry[15]]) as usize;

            if name_length < 4 || name_offset < 16 || !name_offset.is_multiple_of(8) {
                return Err(ProtoError::Malformed("create context invalid name range"));
            }
            let name = entry
                .get(name_offset..name_offset + name_length)
                .ok_or(ProtoError::Malformed("create context name out of range"))?
                .to_vec();
            let data = if data_length == 0 {
                Vec::new()
            } else {
                if data_offset < 16 || !data_offset.is_multiple_of(8) {
                    return Err(ProtoError::Malformed("create context invalid data range"));
                }
                entry
                    .get(data_offset..data_offset + data_length)
                    .ok_or(ProtoError::Malformed("create context data out of range"))?
                    .to_vec()
            };
            out.push(CreateContext { name, data });

            if next == 0 {
                break;
            }
            cursor_off = ctx_end;
        }
        Ok(out)
    }

    /// Encode a chain of create-contexts into `out`. Inserts `Next` offsets
    /// and 8-byte alignment padding between entries.
    pub fn encode_chain(list: &[CreateContext], out: &mut Vec<u8>) -> ProtoResult<()> {
        if list.is_empty() {
            return Ok(());
        }
        // We build the chain in a scratch buffer, then copy. Each entry is:
        //   16-byte header + name + (pad to 8) + data + (pad to 8 if not last)
        // The `Next` of every entry except the last is the size from this
        // entry's start to the next entry's start.
        let mut scratch: Vec<u8> = Vec::new();
        let mut entry_starts: Vec<usize> = Vec::with_capacity(list.len());

        for (i, ctx) in list.iter().enumerate() {
            // Pad to 8-byte boundary before each entry (except possibly first
            // — but contexts must be 8-byte aligned, and the chain itself is
            // anchored at an 8-aligned offset by the server).
            while !scratch.len().is_multiple_of(8) {
                scratch.push(0);
            }
            entry_starts.push(scratch.len());

            // Reserve 16 bytes for the header; will fill in once we know
            // the actual offsets.
            let header_pos = scratch.len();
            scratch.extend_from_slice(&[0u8; 16]);

            // Name immediately follows the header.
            let name_offset_rel = (scratch.len() - header_pos) as u16;
            scratch.extend_from_slice(&ctx.name);
            // Pad to 8 before data.
            while !(scratch.len() - header_pos).is_multiple_of(8) {
                scratch.push(0);
            }
            let data_offset_rel = (scratch.len() - header_pos) as u16;
            scratch.extend_from_slice(&ctx.data);

            // Now backfill the header bytes (Next is patched after the loop).
            let hdr = &mut scratch[header_pos..header_pos + 16];
            hdr[0..4].copy_from_slice(&0u32.to_le_bytes()); // Next, fixed up below
            hdr[4..6].copy_from_slice(&name_offset_rel.to_le_bytes());
            hdr[6..8].copy_from_slice(&(ctx.name.len() as u16).to_le_bytes());
            hdr[8..10].copy_from_slice(&0u16.to_le_bytes()); // Reserved
            hdr[10..12].copy_from_slice(&data_offset_rel.to_le_bytes());
            hdr[12..16].copy_from_slice(&(ctx.data.len() as u32).to_le_bytes());

            // For non-last, pad the trailing data area to 8 so the next
            // entry starts aligned.
            if i + 1 < list.len() {
                while !scratch.len().is_multiple_of(8) {
                    scratch.push(0);
                }
            }
        }

        // Patch `Next` offsets.
        for i in 0..(entry_starts.len() - 1) {
            let this = entry_starts[i];
            let next = entry_starts[i + 1];
            let delta = (next - this) as u32;
            scratch[this..this + 4].copy_from_slice(&delta.to_le_bytes());
        }
        // Last entry's Next stays 0.

        out.extend_from_slice(&scratch);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Helper enums (oplock level, impersonation level)
// ---------------------------------------------------------------------------

/// MS-SMB2 §2.2.13 RequestedOplockLevel / §2.2.14 OplockLevel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum OplockLevel {
    None = 0x00,
    Ii = 0x01,
    Exclusive = 0x08,
    Batch = 0x09,
    Lease = 0xFF,
}

impl OplockLevel {
    pub fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            0x00 => Self::None,
            0x01 => Self::Ii,
            0x08 => Self::Exclusive,
            0x09 => Self::Batch,
            0xFF => Self::Lease,
            _ => return None,
        })
    }
}

/// MS-SMB2 §2.2.13 ImpersonationLevel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum ImpersonationLevel {
    Anonymous = 0x0000_0000,
    Identification = 0x0000_0001,
    Impersonation = 0x0000_0002,
    Delegate = 0x0000_0003,
}

fn read_u16(buf: &[u8], offset: usize) -> ProtoResult<u16> {
    let bytes = buf
        .get(offset..offset + 2)
        .ok_or(ProtoError::Malformed("create u16 out of range"))?;
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn read_u32(buf: &[u8], offset: usize) -> ProtoResult<u32> {
    let bytes = buf
        .get(offset..offset + 4)
        .ok_or(ProtoError::Malformed("create u32 out of range"))?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn read_u64(buf: &[u8], offset: usize) -> ProtoResult<u64> {
    let bytes = buf
        .get(offset..offset + 8)
        .ok_or(ProtoError::Malformed("create u64 out of range"))?;
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

    fn create_request_with_raw_contexts(contexts: &[u8]) -> Vec<u8> {
        let mut body = vec![0; 56];
        body[0..2].copy_from_slice(&57u16.to_le_bytes());
        body[44..46]
            .copy_from_slice(&(crate::proto::header::SMB2_HEADER_LEN as u16 + 56).to_le_bytes());
        body[48..52]
            .copy_from_slice(&(crate::proto::header::SMB2_HEADER_LEN as u32 + 56).to_le_bytes());
        body[52..56].copy_from_slice(&(contexts.len() as u32).to_le_bytes());
        body.extend_from_slice(contexts);
        body
    }

    #[test]
    fn request_round_trips() {
        let name = utf16le("dir\\file.txt");
        let r = CreateRequest {
            structure_size: 57,
            security_flags: 0,
            requested_oplock_level: 0,
            impersonation_level: ImpersonationLevel::Impersonation as u32,
            smb_create_flags: 0,
            reserved: 0,
            desired_access: 0x0012_0089,
            file_attributes: 0,
            share_access: 0x0000_0007,
            create_disposition: 1,
            create_options: 0x0000_0040,
            name_offset: 0x78,
            name_length: name.len() as u16,
            create_contexts_offset: 0,
            create_contexts_length: 0,
            name,
            create_contexts: vec![],
        };
        let mut buf = Vec::new();
        r.write_to(&mut buf).unwrap();
        let decoded = CreateRequest::parse(&buf).unwrap();
        assert_eq!(decoded, r);
        assert_eq!(decoded.name_str().unwrap(), "dir\\file.txt");
    }

    #[test]
    fn request_decodes_padded_name_from_header_relative_offset() {
        let name = utf16le("hi");
        let mut buf = vec![0; 68];
        buf[0..2].copy_from_slice(&57u16.to_le_bytes());
        buf[3] = 0x02;
        buf[4..8].copy_from_slice(&(ImpersonationLevel::Impersonation as u32).to_le_bytes());
        buf[24..28].copy_from_slice(&0x0012_0089u32.to_le_bytes());
        buf[32..36].copy_from_slice(&0x7u32.to_le_bytes());
        buf[36..40].copy_from_slice(&1u32.to_le_bytes());
        buf[44..46]
            .copy_from_slice(&(crate::proto::header::SMB2_HEADER_LEN as u16 + 64).to_le_bytes());
        buf[46..48].copy_from_slice(&(name.len() as u16).to_le_bytes());
        buf[64..68].copy_from_slice(&name);

        let decoded = CreateRequest::parse(&buf).unwrap();

        assert_eq!(decoded.requested_oplock_level, 0x02);
        assert_eq!(decoded.name, name);
        assert_eq!(decoded.name_str().as_deref(), Some("hi"));
    }

    #[test]
    fn request_decodes_gosmb_requested_oplock_fixture() {
        let name = utf16le("hello.txt");
        let mut buf = vec![0; 56 + name.len()];
        buf[0..2].copy_from_slice(&57u16.to_le_bytes());
        buf[3] = OplockLevel::Lease as u8;
        buf[4..8].copy_from_slice(&(ImpersonationLevel::Impersonation as u32).to_le_bytes());
        buf[24..28].copy_from_slice(&0x8000_0000u32.to_le_bytes());
        buf[32..36].copy_from_slice(&0x0000_0007u32.to_le_bytes());
        buf[36..40].copy_from_slice(&1u32.to_le_bytes());
        buf[40..44].copy_from_slice(&0x0000_0040u32.to_le_bytes());
        buf[44..46]
            .copy_from_slice(&(crate::proto::header::SMB2_HEADER_LEN as u16 + 56).to_le_bytes());
        buf[46..48].copy_from_slice(&(name.len() as u16).to_le_bytes());
        buf[56..].copy_from_slice(&name);

        let decoded = CreateRequest::parse(&buf).unwrap();

        assert_eq!(decoded.requested_oplock_level, OplockLevel::Lease as u8);
        assert_eq!(
            decoded.impersonation_level,
            ImpersonationLevel::Impersonation as u32
        );
        assert_eq!(decoded.desired_access, 0x8000_0000);
        assert_eq!(decoded.share_access, 0x0000_0007);
        assert_eq!(decoded.create_disposition, 1);
        assert_eq!(decoded.create_options, 0x0000_0040);
        assert_eq!(decoded.name_str().as_deref(), Some("hello.txt"));
    }

    #[test]
    fn request_rejects_wrong_structure_size() {
        let mut buf = vec![0; 56];
        buf[0..2].copy_from_slice(&56u16.to_le_bytes());
        buf[44..46]
            .copy_from_slice(&(crate::proto::header::SMB2_HEADER_LEN as u16 + 56).to_le_bytes());

        assert!(matches!(
            CreateRequest::parse(&buf),
            Err(ProtoError::Malformed(_))
        ));
    }

    #[test]
    fn request_rejects_odd_name_length() {
        let mut buf = vec![0; 57];
        buf[0..2].copy_from_slice(&57u16.to_le_bytes());
        buf[44..46]
            .copy_from_slice(&(crate::proto::header::SMB2_HEADER_LEN as u16 + 56).to_le_bytes());
        buf[46..48].copy_from_slice(&1u16.to_le_bytes());

        assert!(matches!(
            CreateRequest::parse(&buf),
            Err(ProtoError::Malformed(_))
        ));
    }

    #[test]
    fn request_rejects_name_out_of_range() {
        let mut buf = vec![0; 56];
        buf[0..2].copy_from_slice(&57u16.to_le_bytes());
        buf[44..46]
            .copy_from_slice(&(crate::proto::header::SMB2_HEADER_LEN as u16 + 56).to_le_bytes());
        buf[46..48].copy_from_slice(&2u16.to_le_bytes());

        assert!(matches!(
            CreateRequest::parse(&buf),
            Err(ProtoError::Malformed(_))
        ));
    }

    #[test]
    fn request_rejects_short_create_context_name() {
        let mut ctx = vec![0; 24];
        ctx[4..6].copy_from_slice(&16u16.to_le_bytes());
        ctx[6..8].copy_from_slice(&3u16.to_le_bytes());
        ctx[16..19].copy_from_slice(b"Bad");

        assert!(matches!(
            CreateRequest::parse(&create_request_with_raw_contexts(&ctx)),
            Err(ProtoError::Malformed(_))
        ));
    }

    #[test]
    fn request_bounds_context_data_by_next_entry() {
        let mut first = vec![0; 24];
        let first_len = first.len() as u32;
        first[0..4].copy_from_slice(&first_len.to_le_bytes());
        first[4..6].copy_from_slice(&16u16.to_le_bytes());
        first[6..8].copy_from_slice(&4u16.to_le_bytes());
        first[10..12].copy_from_slice(&24u16.to_le_bytes());
        first[12..16].copy_from_slice(&16u32.to_le_bytes());
        first[16..20].copy_from_slice(CreateContext::NAME_MXAC);

        let mut second = vec![0; 24];
        second[4..6].copy_from_slice(&16u16.to_le_bytes());
        second[6..8].copy_from_slice(&4u16.to_le_bytes());
        second[16..20].copy_from_slice(CreateContext::NAME_QFID);

        let mut contexts = first;
        contexts.extend_from_slice(&second);

        assert!(matches!(
            CreateRequest::parse(&create_request_with_raw_contexts(&contexts)),
            Err(ProtoError::Malformed(_))
        ));
    }

    #[test]
    fn response_round_trips() {
        let r = CreateResponse {
            structure_size: 89,
            oplock_level: 0,
            flags: 0,
            create_action: 1,
            creation_time: 0x01D9_0000_0000_0000,
            last_access_time: 0x01D9_0000_0000_0000,
            last_write_time: 0x01D9_0000_0000_0000,
            change_time: 0x01D9_0000_0000_0000,
            allocation_size: 0x1000,
            end_of_file: 0x800,
            file_attributes: 0x0020,
            reserved2: 0,
            file_id: FileId::new(0x1234, 0x5678),
            create_contexts_offset: 0,
            create_contexts_length: 0,
            create_contexts: vec![],
        };
        let mut buf = Vec::new();
        r.write_to(&mut buf).unwrap();
        let decoded = CreateResponse::parse(&buf).unwrap();
        assert_eq!(decoded, r);
    }

    #[test]
    fn response_encodes_gosmb_granted_oplock_fixture() {
        let response = CreateResponse {
            structure_size: 89,
            oplock_level: OplockLevel::Ii as u8,
            flags: 0,
            create_action: 1,
            creation_time: 0,
            last_access_time: 0,
            last_write_time: 0,
            change_time: 0,
            allocation_size: 0,
            end_of_file: 0,
            file_attributes: 0,
            reserved2: 0,
            file_id: FileId::new(1, 2),
            create_contexts_offset: 0,
            create_contexts_length: 0,
            create_contexts: Vec::new(),
        };
        let mut body = Vec::new();
        response.write_to(&mut body).unwrap();

        assert_eq!(body[2], OplockLevel::Ii as u8);
        assert_eq!(CreateResponse::parse(&body).unwrap().oplock_level, body[2]);
    }

    #[test]
    fn response_decodes_padded_contexts_from_header_relative_offset() {
        let ctxs = [CreateContext {
            name: CreateContext::NAME_QFID.to_vec(),
            data: Vec::new(),
        }];
        let mut contexts = Vec::new();
        CreateContext::encode_chain(&ctxs, &mut contexts).unwrap();
        let mut buf = vec![0; 96 + contexts.len()];
        buf[0..2].copy_from_slice(&89u16.to_le_bytes());
        buf[4..8].copy_from_slice(&1u32.to_le_bytes());
        buf[64..72].copy_from_slice(&1u64.to_le_bytes());
        buf[72..80].copy_from_slice(&2u64.to_le_bytes());
        buf[80..84]
            .copy_from_slice(&(crate::proto::header::SMB2_HEADER_LEN as u32 + 96).to_le_bytes());
        buf[84..88].copy_from_slice(&(contexts.len() as u32).to_le_bytes());
        buf[96..].copy_from_slice(&contexts);

        let decoded = CreateResponse::parse(&buf).unwrap();

        assert_eq!(decoded.file_id, FileId::new(1, 2));
        assert_eq!(decoded.create_contexts, contexts);
    }

    #[test]
    fn response_rejects_wrong_structure_size() {
        let mut buf = vec![0; 88];
        buf[0..2].copy_from_slice(&88u16.to_le_bytes());

        assert!(matches!(
            CreateResponse::parse(&buf),
            Err(ProtoError::Malformed(_))
        ));
    }

    #[test]
    fn response_rejects_context_out_of_range() {
        let mut buf = vec![0; 88];
        buf[0..2].copy_from_slice(&89u16.to_le_bytes());
        buf[80..84]
            .copy_from_slice(&(crate::proto::header::SMB2_HEADER_LEN as u32 + 88).to_le_bytes());
        buf[84..88].copy_from_slice(&1u32.to_le_bytes());

        assert!(matches!(
            CreateResponse::parse(&buf),
            Err(ProtoError::Malformed(_))
        ));
    }

    #[test]
    fn create_context_chain_round_trips_single() {
        let ctxs = vec![CreateContext {
            name: b"MxAc".to_vec(),
            data: vec![],
        }];
        let mut buf = Vec::new();
        CreateContext::encode_chain(&ctxs, &mut buf).unwrap();
        let decoded = CreateContext::parse_chain(&buf).unwrap();
        assert_eq!(decoded, ctxs);
    }

    #[test]
    fn create_context_chain_round_trips_multi() {
        let ctxs = vec![
            CreateContext {
                name: b"DHnQ".to_vec(),
                data: vec![0u8; 16],
            },
            CreateContext {
                name: b"MxAc".to_vec(),
                data: vec![],
            },
            CreateContext {
                name: b"QFid".to_vec(),
                data: vec![0xAA; 32],
            },
        ];
        let mut buf = Vec::new();
        CreateContext::encode_chain(&ctxs, &mut buf).unwrap();
        let decoded = CreateContext::parse_chain(&buf).unwrap();
        assert_eq!(decoded, ctxs);
    }

    #[test]
    fn empty_chain_round_trips() {
        let ctxs: Vec<CreateContext> = vec![];
        let mut buf = Vec::new();
        CreateContext::encode_chain(&ctxs, &mut buf).unwrap();
        assert!(buf.is_empty());
        let decoded = CreateContext::parse_chain(&buf).unwrap();
        assert!(decoded.is_empty());
    }
}
