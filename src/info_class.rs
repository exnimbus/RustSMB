//! File / FileSystem / Security info-class encoders used by QUERY_INFO,
//! SET_INFO, and QUERY_DIRECTORY.
//!
//! These are byte-for-byte wire encodings per MS-FSCC §2.4 (file info) /
//! §2.5 (filesystem info) / MS-DTYP §2.4 (security descriptor).

use crate::backend::{DirEntry, FileInfo};
use crate::proto::messages::Dialect;
use crate::utils::utf16le;

// ---------------------------------------------------------------------------
// File info classes (MS-FSCC §2.4)
// ---------------------------------------------------------------------------

pub const FILE_DIRECTORY_INFORMATION: u8 = 0x01;
pub const FILE_FULL_DIRECTORY_INFORMATION: u8 = 0x02;
pub const FILE_BOTH_DIRECTORY_INFORMATION: u8 = 0x03;
pub const FILE_BASIC_INFORMATION: u8 = 0x04;
pub const FILE_STANDARD_INFORMATION: u8 = 0x05;
pub const FILE_INTERNAL_INFORMATION: u8 = 0x06;
pub const FILE_EA_INFORMATION: u8 = 0x07;
pub const FILE_ACCESS_INFORMATION: u8 = 0x08;
pub const FILE_NAME_INFORMATION: u8 = 0x09;
pub const FILE_NAMES_INFORMATION: u8 = 0x0C;
pub const FILE_POSITION_INFORMATION: u8 = 0x0E;
pub const FILE_FULL_EA_INFORMATION: u8 = 0x0F;
pub const FILE_MODE_INFORMATION: u8 = 0x10;
pub const FILE_ALIGNMENT_INFORMATION: u8 = 0x11;
pub const FILE_ALL_INFORMATION: u8 = 0x12;
pub const FILE_ALLOCATION_INFORMATION: u8 = 0x13;
pub const FILE_END_OF_FILE_INFORMATION: u8 = 0x14;
pub const FILE_ALTERNATE_NAME_INFORMATION: u8 = 0x15;
pub const FILE_STREAM_INFORMATION: u8 = 0x16;
pub const FILE_COMPRESSION_INFORMATION: u8 = 0x1C;
pub const FILE_DISPOSITION_INFORMATION: u8 = 0x0D;
pub const FILE_RENAME_INFORMATION: u8 = 0x0A;
pub const FILE_DISPOSITION_INFORMATION_EX: u8 = 0x40;
pub const FILE_RENAME_INFORMATION_EX: u8 = 0x41;
pub const FILE_NETWORK_OPEN_INFORMATION: u8 = 0x22;
pub const FILE_ATTRIBUTE_TAG_INFORMATION: u8 = 0x23;
pub const FILE_ID_BOTH_DIRECTORY_INFORMATION: u8 = 0x25;
pub const FILE_ID_FULL_DIRECTORY_INFORMATION: u8 = 0x26;
pub const FILE_NORMALIZED_NAME_INFORMATION: u8 = 0x30;
pub const FILE_REMOTE_PROTOCOL_INFORMATION: u8 = 0x37;
pub const FILE_ID_INFORMATION: u8 = 0x3B;
pub const FILE_ID_EXTD_DIRECTORY_INFORMATION: u8 = 0x3C;
pub const FILE_ID_64_EXTD_DIRECTORY_INFORMATION: u8 = 0x4E;
pub const FILE_ID_64_EXTD_BOTH_DIRECTORY_INFORMATION: u8 = 0x4F;
pub const FILE_ID_ALL_EXTD_DIRECTORY_INFORMATION: u8 = 0x50;
pub const FILE_ID_ALL_EXTD_BOTH_DIRECTORY_INFORMATION: u8 = 0x51;
pub const FILE_POSIX_INFORMATION: u8 = 0x64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PosixMetadata {
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtendedAttribute {
    pub flags: u8,
    pub name: String,
    pub value: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileStream {
    pub name: String,
    pub size: u64,
    pub allocation: u64,
}

// ---------------------------------------------------------------------------
// FileBasicInformation (MS-FSCC §2.4.7) — 40 bytes
// ---------------------------------------------------------------------------

pub fn encode_file_basic_information(info: &FileInfo) -> Vec<u8> {
    let mut out = Vec::with_capacity(40);
    out.extend_from_slice(&info.creation_time.to_le_bytes());
    out.extend_from_slice(&info.last_access_time.to_le_bytes());
    out.extend_from_slice(&info.last_write_time.to_le_bytes());
    out.extend_from_slice(&info.change_time.to_le_bytes());
    out.extend_from_slice(&info.attributes().to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes()); // Reserved
    out
}

// ---------------------------------------------------------------------------
// FileStandardInformation (MS-FSCC §2.4.41) — 24 bytes
// ---------------------------------------------------------------------------

pub fn encode_file_standard_information(info: &FileInfo, delete_pending: bool) -> Vec<u8> {
    encode_file_standard_information_with_links(info, delete_pending, 1)
}

pub fn encode_file_standard_information_with_links(
    info: &FileInfo,
    delete_pending: bool,
    number_of_links: u32,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(24);
    out.extend_from_slice(&info.allocation_size.to_le_bytes());
    out.extend_from_slice(&info.end_of_file.to_le_bytes());
    out.extend_from_slice(&number_of_links.to_le_bytes());
    out.push(u8::from(delete_pending)); // DeletePending
    out.push(if info.is_directory { 1 } else { 0 }); // Directory
    out.extend_from_slice(&0u16.to_le_bytes()); // Reserved
    out
}

// ---------------------------------------------------------------------------
// FileInternalInformation (MS-FSCC §2.4.20) — 8 bytes
// ---------------------------------------------------------------------------

pub fn encode_file_internal_information(file_index: u64) -> Vec<u8> {
    file_index.to_le_bytes().to_vec()
}

// ---------------------------------------------------------------------------
// FileEaInformation (MS-FSCC §2.4.12) — 4 bytes
// ---------------------------------------------------------------------------

pub fn encode_file_ea_information(eas: &[ExtendedAttribute]) -> Vec<u8> {
    full_ea_information_size(eas).to_le_bytes().to_vec()
}

pub fn encode_file_full_ea_information(eas: &[ExtendedAttribute]) -> Vec<u8> {
    if eas.is_empty() {
        return vec![0; 4];
    }

    let mut out = Vec::new();
    for (idx, ea) in eas.iter().enumerate() {
        let name = ea.name.as_bytes();
        let value = ea.value.as_slice();
        let size = 8 + name.len() + 1 + value.len();
        let padded = roundup(size, 4);
        let start = out.len();
        out.resize(start + padded, 0);
        let rec = &mut out[start..];
        if idx < eas.len() - 1 {
            rec[0..4].copy_from_slice(&(padded as u32).to_le_bytes());
        }
        rec[4] = ea.flags;
        rec[5] = name.len() as u8;
        rec[6..8].copy_from_slice(&(value.len() as u16).to_le_bytes());
        rec[8..8 + name.len()].copy_from_slice(name);
        rec[8 + name.len()] = 0;
        rec[8 + name.len() + 1..8 + name.len() + 1 + value.len()].copy_from_slice(value);
    }
    out
}

pub fn full_ea_information_size(eas: &[ExtendedAttribute]) -> u32 {
    if eas.is_empty() {
        0
    } else {
        encode_file_full_ea_information(eas).len() as u32
    }
}

pub fn decode_file_full_ea_information(data: &[u8]) -> Result<Vec<ExtendedAttribute>, ()> {
    if data.is_empty() || data.iter().all(|b| *b == 0) {
        return Ok(Vec::new());
    }

    let mut out = Vec::new();
    let mut offset = 0usize;
    loop {
        let rec = data.get(offset..).ok_or(())?;
        if rec.len() < 8 {
            return Err(());
        }
        let next = u32::from_le_bytes(rec[0..4].try_into().unwrap()) as usize;
        let flags = rec[4];
        let name_len = rec[5] as usize;
        let value_len = u16::from_le_bytes(rec[6..8].try_into().unwrap()) as usize;
        let end = 8usize
            .checked_add(name_len)
            .and_then(|n| n.checked_add(1))
            .and_then(|n| n.checked_add(value_len))
            .ok_or(())?;
        if name_len == 0 || rec.len() < end || rec[8 + name_len] != 0 {
            return Err(());
        }
        let name = std::str::from_utf8(&rec[8..8 + name_len]).map_err(|_| ())?;
        out.push(ExtendedAttribute {
            flags,
            name: name.to_string(),
            value: rec[8 + name_len + 1..end].to_vec(),
        });

        if next == 0 {
            break;
        }
        if next < end || !next.is_multiple_of(4) {
            return Err(());
        }
        let Some(new_offset) = offset.checked_add(next) else {
            return Err(());
        };
        if new_offset >= data.len() {
            return Err(());
        }
        offset = new_offset;
    }
    Ok(out)
}

fn roundup(value: usize, align: usize) -> usize {
    debug_assert!(align.is_power_of_two());
    (value + align - 1) & !(align - 1)
}

// ---------------------------------------------------------------------------
// FileAccessInformation (MS-FSCC §2.4.1) — 4 bytes
// ---------------------------------------------------------------------------

pub fn encode_file_access_information(access_mask: u32) -> Vec<u8> {
    access_mask.to_le_bytes().to_vec()
}

// ---------------------------------------------------------------------------
// FilePositionInformation (MS-FSCC §2.4.32) — 8 bytes
// ---------------------------------------------------------------------------

pub fn encode_file_position_information(current_offset: u64) -> Vec<u8> {
    current_offset.to_le_bytes().to_vec()
}

// ---------------------------------------------------------------------------
// FileModeInformation (MS-FSCC §2.4.24) — 4 bytes
// ---------------------------------------------------------------------------

pub fn encode_file_mode_information(mode: u32) -> Vec<u8> {
    mode.to_le_bytes().to_vec()
}

// ---------------------------------------------------------------------------
// FileAlignmentInformation (MS-FSCC §2.4.3) — 4 bytes
// ---------------------------------------------------------------------------

pub fn encode_file_alignment_information() -> Vec<u8> {
    // FILE_BYTE_ALIGNMENT (0) — no alignment requirement.
    0u32.to_le_bytes().to_vec()
}

// ---------------------------------------------------------------------------
// FileNameInformation (MS-FSCC §2.4.27) — 4 bytes + UTF-16LE name
// ---------------------------------------------------------------------------

pub fn encode_file_name_information(name: &str) -> Vec<u8> {
    let n = utf16le(name);
    let mut out = Vec::with_capacity(4 + n.len());
    out.extend_from_slice(&(n.len() as u32).to_le_bytes());
    out.extend_from_slice(&n);
    out
}

// ---------------------------------------------------------------------------
// FileAlternateNameInformation (MS-FSCC §2.4.4) — 4 bytes + UTF-16LE 8.3 name
// ---------------------------------------------------------------------------

pub fn encode_file_alternate_name_information(name: &str) -> Vec<u8> {
    encode_file_name_information(&make_short_name(name))
}

fn make_short_name(name: &str) -> String {
    let name = name.trim();
    if name.is_empty() || name == "." || name == ".." {
        return String::new();
    }

    let (base, ext) = match name.split_once('.') {
        Some((base, ext)) => (base, Some(ext)),
        None => (name, None),
    };
    let base = {
        let part = short_name_part(base, 6);
        if part.is_empty() {
            "FILE".to_string()
        } else {
            part
        }
    };
    let ext = ext.map(|ext| short_name_part(ext, 3)).unwrap_or_default();
    if ext.is_empty() {
        format!("{base}~1")
    } else {
        format!("{base}~1.{ext}")
    }
}

fn short_name_part(part: &str, max: usize) -> String {
    let mut out = String::new();
    for ch in part.chars() {
        let mapped = if ch.is_ascii_lowercase() {
            ch.to_ascii_uppercase()
        } else if ch.is_ascii_uppercase() || ch.is_ascii_digit() {
            ch
        } else if ch.is_alphanumeric() {
            ch.to_uppercase().next().unwrap_or(ch)
        } else {
            continue;
        };
        out.push(mapped);
        if out.len() >= max {
            break;
        }
    }
    out
}

// ---------------------------------------------------------------------------
// FileAllInformation (MS-FSCC §2.4.2) — concatenation of basic, standard,
// internal, EA, access, position, mode, alignment, name.
// ---------------------------------------------------------------------------

pub fn encode_file_all_information(
    info: &FileInfo,
    file_index: u64,
    access_mask: u32,
    current_offset: u64,
    mode: u32,
    delete_pending: bool,
) -> Vec<u8> {
    encode_file_all_information_with_links(
        info,
        file_index,
        access_mask,
        current_offset,
        mode,
        delete_pending,
        1,
    )
}

pub fn encode_file_all_information_with_links(
    info: &FileInfo,
    file_index: u64,
    access_mask: u32,
    current_offset: u64,
    mode: u32,
    delete_pending: bool,
    number_of_links: u32,
) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&encode_file_basic_information(info));
    out.extend_from_slice(&encode_file_standard_information_with_links(
        info,
        delete_pending,
        number_of_links,
    ));
    out.extend_from_slice(&encode_file_internal_information(file_index));
    out.extend_from_slice(&encode_file_ea_information(&[]));
    out.extend_from_slice(&encode_file_access_information(access_mask));
    out.extend_from_slice(&encode_file_position_information(current_offset));
    out.extend_from_slice(&encode_file_mode_information(mode));
    out.extend_from_slice(&encode_file_alignment_information());
    out.extend_from_slice(&encode_file_name_information(&info.name));
    // Linux cifs checks FileAllInformation against its struct with
    // FileName[1], so the empty-name root case must still be at least 101
    // bytes.
    if out.len() < 101 {
        out.push(0);
    }
    out
}

// ---------------------------------------------------------------------------
// FileNetworkOpenInformation (MS-FSCC §2.4.30) — 56 bytes
// ---------------------------------------------------------------------------

pub fn encode_file_network_open_information(info: &FileInfo) -> Vec<u8> {
    let mut out = Vec::with_capacity(56);
    out.extend_from_slice(&info.creation_time.to_le_bytes());
    out.extend_from_slice(&info.last_access_time.to_le_bytes());
    out.extend_from_slice(&info.last_write_time.to_le_bytes());
    out.extend_from_slice(&info.change_time.to_le_bytes());
    out.extend_from_slice(&info.allocation_size.to_le_bytes());
    out.extend_from_slice(&info.end_of_file.to_le_bytes());
    out.extend_from_slice(&info.attributes().to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes()); // Reserved
    out
}

// ---------------------------------------------------------------------------
// FileStreamInformation (MS-FSCC §2.4.43) — for non-directories, include the
// default stream entry (`::$DATA`); for directories, list only named streams.
// ---------------------------------------------------------------------------

pub fn encode_file_stream_information(info: &FileInfo, streams: &[FileStream]) -> Vec<u8> {
    if info.is_directory && streams.is_empty() {
        return Vec::new();
    }
    let mut out = Vec::new();
    let records = if streams.is_empty() {
        vec![FileStream {
            name: "::$DATA".to_string(),
            size: info.end_of_file,
            allocation: info.allocation_size,
        }]
    } else {
        streams.to_vec()
    };

    for (index, stream) in records.iter().enumerate() {
        let name = utf16le(&stream.name);
        let start = out.len();
        out.extend_from_slice(&0u32.to_le_bytes()); // NextEntryOffset
        out.extend_from_slice(&(name.len() as u32).to_le_bytes()); // StreamNameLength
        out.extend_from_slice(&stream.size.to_le_bytes()); // StreamSize
        out.extend_from_slice(&stream.allocation.to_le_bytes()); // StreamAllocationSize
        out.extend_from_slice(&name);
        let aligned_len = align8(out.len() - start);
        if index < records.len() - 1 {
            out[start..start + 4].copy_from_slice(&(aligned_len as u32).to_le_bytes());
        }
        out.resize(start + aligned_len, 0);
    }
    out
}

// ---------------------------------------------------------------------------
// FileCompressionInformation (MS-FSCC §2.4.8) — 16 bytes. The backend does not
// expose compressed allocation state, so report uncompressed storage.
// ---------------------------------------------------------------------------

pub fn encode_file_compression_information() -> Vec<u8> {
    vec![0; 16]
}

// ---------------------------------------------------------------------------
// FileAttributeTagInformation (MS-FSCC §2.4.6) — 8 bytes.
// ---------------------------------------------------------------------------

pub fn encode_file_attribute_tag_information(info: &FileInfo) -> Vec<u8> {
    let mut out = Vec::with_capacity(8);
    out.extend_from_slice(&info.attributes().to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes()); // ReparseTag
    out
}

// ---------------------------------------------------------------------------
// FileRemoteProtocolInformation (MS-FSCC §2.4.35) — 180 bytes.
// ---------------------------------------------------------------------------

pub fn encode_file_remote_protocol_information(dialect: Option<Dialect>) -> Vec<u8> {
    const STRUCTURE_VERSION: u16 = 1;
    const STRUCTURE_SIZE: u16 = 180;
    const PROTOCOL_SMB: u32 = 0x0002_0000;

    let (major, minor, revision) = remote_protocol_version(dialect);
    let mut out = vec![0; STRUCTURE_SIZE as usize];
    out[0..2].copy_from_slice(&STRUCTURE_VERSION.to_le_bytes());
    out[2..4].copy_from_slice(&STRUCTURE_SIZE.to_le_bytes());
    out[4..8].copy_from_slice(&PROTOCOL_SMB.to_le_bytes());
    out[8..10].copy_from_slice(&major.to_le_bytes());
    out[10..12].copy_from_slice(&minor.to_le_bytes());
    out[12..14].copy_from_slice(&revision.to_le_bytes());
    out
}

fn remote_protocol_version(dialect: Option<Dialect>) -> (u16, u16, u16) {
    match dialect {
        Some(Dialect::Smb202) => (2, 0, 2),
        Some(Dialect::Smb210) => (2, 1, 0),
        Some(Dialect::Smb300) => (3, 0, 0),
        Some(Dialect::Smb302) => (3, 0, 2),
        Some(Dialect::Smb311) => (3, 1, 1),
        Some(Dialect::Smb2Wildcard) | None => (3, 0, 0),
    }
}

// ---------------------------------------------------------------------------
// FileIdInformation (MS-FSCC §2.4.18) — 24 bytes.
// ---------------------------------------------------------------------------

pub fn encode_file_id_information(volume_id: u64, file_id: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(24);
    out.extend_from_slice(&volume_id.to_le_bytes());
    out.extend_from_slice(&0u64.to_le_bytes()); // Reserved
    out.extend_from_slice(&file_id.to_le_bytes());
    out
}

// ---------------------------------------------------------------------------
// FilePOSIXInformation (SMB POSIX extensions) — 136 bytes.
// ---------------------------------------------------------------------------

pub fn encode_file_posix_information(
    info: &FileInfo,
    file_id: u64,
    posix: Option<PosixMetadata>,
) -> Vec<u8> {
    encode_file_posix_information_with_links(info, file_id, posix, 1)
}

pub fn encode_file_posix_information_with_links(
    info: &FileInfo,
    file_id: u64,
    posix: Option<PosixMetadata>,
    number_of_links: u32,
) -> Vec<u8> {
    let mut out = vec![0; 136];
    out[0..8].copy_from_slice(&info.creation_time.to_le_bytes());
    out[8..16].copy_from_slice(&info.last_access_time.to_le_bytes());
    out[16..24].copy_from_slice(&info.last_write_time.to_le_bytes());
    out[24..32].copy_from_slice(&info.change_time.to_le_bytes());
    out[32..40].copy_from_slice(&info.allocation_size.to_le_bytes());
    out[40..48].copy_from_slice(&info.end_of_file.to_le_bytes());
    out[48..52].copy_from_slice(&info.attributes().to_le_bytes());
    out[52..60].copy_from_slice(&file_id.to_le_bytes());
    out[68..136].copy_from_slice(&encode_posix_create_context_response_with_links(
        info,
        posix,
        number_of_links,
    ));
    out
}

pub fn encode_posix_create_context_response(
    info: &FileInfo,
    posix: Option<PosixMetadata>,
) -> [u8; 68] {
    encode_posix_create_context_response_with_links(info, posix, 1)
}

pub fn encode_posix_create_context_response_with_links(
    info: &FileInfo,
    posix: Option<PosixMetadata>,
    number_of_links: u32,
) -> [u8; 68] {
    let posix = posix.unwrap_or_else(|| default_posix_metadata(info));
    let mut out = [0; 68];
    out[0..4].copy_from_slice(&number_of_links.to_le_bytes());
    out[8..12].copy_from_slice(&(posix.mode & 0o7777).to_le_bytes());
    put_posix_sid(&mut out[12..40], 1, posix.uid);
    put_posix_sid(&mut out[40..68], 2, posix.gid);
    out
}

pub fn default_posix_metadata(info: &FileInfo) -> PosixMetadata {
    PosixMetadata {
        mode: default_posix_mode(info),
        uid: 0,
        gid: 0,
    }
}

pub fn default_posix_mode(info: &FileInfo) -> u32 {
    if info.is_directory { 0o755 } else { 0o644 }
}

fn put_posix_sid(dst: &mut [u8], kind: u32, id: u32) {
    if dst.len() < 20 {
        return;
    }
    dst[0] = 1;
    dst[1] = 3;
    dst[7] = 5;
    dst[8..12].copy_from_slice(&88u32.to_le_bytes());
    dst[12..16].copy_from_slice(&kind.to_le_bytes());
    dst[16..20].copy_from_slice(&id.to_le_bytes());
}

// ---------------------------------------------------------------------------
// FS info classes (MS-FSCC §2.5)
// ---------------------------------------------------------------------------

pub const FS_VOLUME_INFORMATION: u8 = 0x01;
pub const FS_CONTROL_INFORMATION: u8 = 0x02;
pub const FS_SIZE_INFORMATION: u8 = 0x03;
pub const FS_DEVICE_INFORMATION: u8 = 0x04;
pub const FS_ATTRIBUTE_INFORMATION: u8 = 0x05;
pub const FS_QUOTA_INFORMATION: u8 = 0x06;
pub const FS_FULL_SIZE_INFORMATION: u8 = 0x07;
pub const FS_OBJECT_ID_INFORMATION: u8 = 0x08;
pub const FS_SECTOR_SIZE_INFORMATION: u8 = 0x0b;

/// FileFsVolumeInformation (MS-FSCC §2.5.9). Volume creation time, serial,
/// label.
pub fn encode_fs_volume_information(creation_time: u64, serial: u32, label: &str) -> Vec<u8> {
    let label_u16 = utf16le(label);
    let mut out = Vec::new();
    out.extend_from_slice(&creation_time.to_le_bytes());
    out.extend_from_slice(&serial.to_le_bytes());
    out.extend_from_slice(&(label_u16.len() as u32).to_le_bytes());
    out.push(0); // SupportsObjects
    out.push(0); // Reserved
    out.extend_from_slice(&label_u16);
    out
}

/// FileFsControlInformation (MS-FSCC §2.5.2) — 48 bytes.
pub fn encode_fs_control_information() -> Vec<u8> {
    vec![0; 48]
}

/// FileFsSizeInformation (MS-FSCC §2.5.7) — 24 bytes.
pub fn encode_fs_size_information(
    total_alloc_units: u64,
    avail_alloc_units: u64,
    sectors_per_unit: u32,
    bytes_per_sector: u32,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(24);
    out.extend_from_slice(&total_alloc_units.to_le_bytes());
    out.extend_from_slice(&avail_alloc_units.to_le_bytes());
    out.extend_from_slice(&sectors_per_unit.to_le_bytes());
    out.extend_from_slice(&bytes_per_sector.to_le_bytes());
    out
}

/// FileFsDeviceInformation (MS-FSCC §2.5.10) — 8 bytes.
pub fn encode_fs_device_information(device_type: u32, characteristics: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(8);
    out.extend_from_slice(&device_type.to_le_bytes());
    out.extend_from_slice(&characteristics.to_le_bytes());
    out
}

/// FileFsAttributeInformation (MS-FSCC §2.5.1) — variable.
pub fn encode_fs_attribute_information(
    attributes: u32,
    max_component_len: u32,
    fs_name: &str,
) -> Vec<u8> {
    let name_u16 = utf16le(fs_name);
    let mut out = Vec::new();
    out.extend_from_slice(&attributes.to_le_bytes());
    out.extend_from_slice(&max_component_len.to_le_bytes());
    out.extend_from_slice(&(name_u16.len() as u32).to_le_bytes());
    out.extend_from_slice(&name_u16);
    out
}

/// FileFsQuotaInformation (MS-FSCC §2.5.6) — 48 bytes.
pub fn encode_fs_quota_information(total_alloc_units: u64, avail_alloc_units: u64) -> Vec<u8> {
    let mut out = vec![0; 48];
    out[0..8].copy_from_slice(&total_alloc_units.to_le_bytes());
    out[8..16].copy_from_slice(&avail_alloc_units.to_le_bytes());
    out
}

/// FileFsFullSizeInformation (MS-FSCC §2.5.4) — 32 bytes.
pub fn encode_fs_full_size_information(
    total_alloc_units: u64,
    caller_avail_alloc_units: u64,
    actual_avail_alloc_units: u64,
    sectors_per_unit: u32,
    bytes_per_sector: u32,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(32);
    out.extend_from_slice(&total_alloc_units.to_le_bytes());
    out.extend_from_slice(&caller_avail_alloc_units.to_le_bytes());
    out.extend_from_slice(&actual_avail_alloc_units.to_le_bytes());
    out.extend_from_slice(&sectors_per_unit.to_le_bytes());
    out.extend_from_slice(&bytes_per_sector.to_le_bytes());
    out
}

/// FileFsObjectIdInformation (MS-FSCC §2.5.5) — 64 bytes.
pub fn encode_fs_object_id_information(object_id: &[u8; 16]) -> Vec<u8> {
    let mut out = vec![0; 64];
    out[0..16].copy_from_slice(object_id);
    out
}

/// FileFsSectorSizeInformation (MS-FSCC §2.5.8) — 28 bytes.
pub fn encode_fs_sector_size_information(bytes_per_sector: u32) -> Vec<u8> {
    let mut out = vec![0; 28];
    out[0..4].copy_from_slice(&bytes_per_sector.to_le_bytes());
    out[4..8].copy_from_slice(&bytes_per_sector.to_le_bytes());
    out[8..12].copy_from_slice(&bytes_per_sector.to_le_bytes());
    out[12..16].copy_from_slice(&bytes_per_sector.to_le_bytes());
    out
}

// ---------------------------------------------------------------------------
// Minimal SECURITY_DESCRIPTOR with owner=Everyone, DACL=Everyone allowed.
// ---------------------------------------------------------------------------

/// Build a minimal absolute-form SECURITY_DESCRIPTOR per MS-DTYP §2.4.6.
///
/// Owner = Everyone (S-1-1-0). No group. DACL = single Allow ACE granting
/// `0x001F_01FF` (FILE_ALL_ACCESS) to Everyone. Self-relative format so it
/// embeds cleanly in the QUERY_INFO buffer.
pub fn encode_minimal_security_descriptor() -> Vec<u8> {
    // SID Everyone (S-1-1-0): 1, 1, [0,0,0,0,0,1], [0,0,0,0]
    // Total length: 1 (Revision) + 1 (SubAuthorityCount=1) + 6 (Identifier) + 4 (subauth) = 12
    let everyone: Vec<u8> = vec![
        0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
    ];

    // Build ACE: AccessAllowedAce
    //   Header: 4 bytes (Type=0, Flags=0, Size)
    //   Mask: 4 bytes
    //   Sid: variable
    let mut ace = Vec::new();
    ace.push(0x00); // ACCESS_ALLOWED_ACE_TYPE
    ace.push(0x00); // AceFlags
    let ace_size: u16 = (4 + 4 + everyone.len()) as u16;
    ace.extend_from_slice(&ace_size.to_le_bytes());
    ace.extend_from_slice(&0x001F_01FFu32.to_le_bytes()); // FILE_ALL_ACCESS
    ace.extend_from_slice(&everyone);

    // ACL: Revision (1), Sbz1 (1), AclSize (2), AceCount (2), Sbz2 (2), then ACEs.
    let acl_size: u16 = (8 + ace.len()) as u16;
    let mut dacl = Vec::new();
    dacl.push(0x02); // Revision = ACL_REVISION
    dacl.push(0x00); // Sbz1
    dacl.extend_from_slice(&acl_size.to_le_bytes());
    dacl.extend_from_slice(&1u16.to_le_bytes()); // AceCount
    dacl.extend_from_slice(&0u16.to_le_bytes()); // Sbz2
    dacl.extend_from_slice(&ace);

    // SECURITY_DESCRIPTOR (self-relative):
    //   Revision (1), Sbz1 (1), Control (2),
    //   OwnerOffset (4), GroupOffset (4), SaclOffset (4), DaclOffset (4)
    //   Then concatenated entities.
    const SE_DACL_PRESENT: u16 = 0x0004;
    const SE_SELF_RELATIVE: u16 = 0x8000;
    let mut sd = Vec::new();
    sd.push(0x01); // Revision = SECURITY_DESCRIPTOR_REVISION
    sd.push(0x00); // Sbz1
    sd.extend_from_slice(&(SE_DACL_PRESENT | SE_SELF_RELATIVE).to_le_bytes());
    let header_len: u32 = 20;
    let owner_off = header_len;
    let group_off = 0u32;
    let sacl_off = 0u32;
    let dacl_off = owner_off + everyone.len() as u32;
    sd.extend_from_slice(&owner_off.to_le_bytes());
    sd.extend_from_slice(&group_off.to_le_bytes());
    sd.extend_from_slice(&sacl_off.to_le_bytes());
    sd.extend_from_slice(&dacl_off.to_le_bytes());
    sd.extend_from_slice(&everyone);
    sd.extend_from_slice(&dacl);
    sd
}

pub fn encode_nil_dacl_security_descriptor() -> Vec<u8> {
    let mut out = vec![0; 20];
    out[0] = 1;
    out[2..4].copy_from_slice(&0x8004u16.to_le_bytes());
    out
}

pub fn normalize_set_security_descriptor(descriptor: &[u8]) -> Option<Vec<u8>> {
    if descriptor.len() < 20 {
        return None;
    }
    if security_descriptor_has_dacl(descriptor) {
        Some(descriptor.to_vec())
    } else {
        Some(encode_nil_dacl_security_descriptor())
    }
}

fn security_descriptor_has_dacl(descriptor: &[u8]) -> bool {
    if descriptor.len() < 20 {
        return false;
    }
    const SE_DACL_PRESENT: u16 = 0x0004;
    u16::from_le_bytes(descriptor[2..4].try_into().unwrap()) & SE_DACL_PRESENT != 0
}

pub fn security_descriptor_denies_access(descriptor: &[u8], access: u32) -> bool {
    if !security_descriptor_has_dacl(descriptor) {
        return false;
    }
    if security_descriptor_has_empty_dacl(descriptor) {
        return true;
    }
    let Some((allowed, denied)) = security_descriptor_access_masks(descriptor) else {
        return false;
    };
    if denied & access != 0 {
        return true;
    }
    if allowed == 0 {
        return access != 0;
    }
    access & !allowed != 0
}

pub fn security_descriptor_has_deny_ace(descriptor: &[u8], access: u32) -> bool {
    let Some(aces) = security_descriptor_aces(descriptor) else {
        return false;
    };
    aces.iter()
        .any(|ace| ace.ace_type == ACCESS_DENIED_ACE_TYPE && ace.mask & access != 0)
}

pub fn security_descriptor_has_inheritable_ace(descriptor: &[u8], directory: bool) -> bool {
    let Some(aces) = security_descriptor_aces(descriptor) else {
        return false;
    };
    aces.iter().any(|ace| {
        if directory {
            ace.flags & CONTAINER_INHERIT_ACE != 0
        } else {
            ace.flags & OBJECT_INHERIT_ACE != 0
        }
    })
}

fn security_descriptor_has_empty_dacl(descriptor: &[u8]) -> bool {
    let Some(dacl) = security_descriptor_dacl(descriptor) else {
        return false;
    };
    u16::from_le_bytes(dacl[4..6].try_into().unwrap()) == 0
}

fn security_descriptor_access_masks(descriptor: &[u8]) -> Option<(u32, u32)> {
    let mut allowed = 0;
    let mut denied = 0;
    for ace in security_descriptor_aces(descriptor)? {
        match ace.ace_type {
            ACCESS_ALLOWED_ACE_TYPE => allowed |= expand_file_access_mask(ace.mask),
            ACCESS_DENIED_ACE_TYPE => denied |= expand_file_access_mask(ace.mask),
            _ => {}
        }
    }
    Some((allowed, denied))
}

#[derive(Debug, Clone, Copy)]
struct SecurityAce {
    ace_type: u8,
    flags: u8,
    mask: u32,
}

const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;
const ACCESS_DENIED_ACE_TYPE: u8 = 1;
const OBJECT_INHERIT_ACE: u8 = 0x01;
const CONTAINER_INHERIT_ACE: u8 = 0x02;

fn security_descriptor_aces(descriptor: &[u8]) -> Option<Vec<SecurityAce>> {
    let dacl = security_descriptor_dacl(descriptor)?;
    let dacl_size = usize::from(u16::from_le_bytes(dacl[2..4].try_into().unwrap()));
    if dacl_size < 8 || dacl_size > dacl.len() {
        return None;
    }
    let ace_count = usize::from(u16::from_le_bytes(dacl[4..6].try_into().unwrap()));
    let mut offset = 8usize;
    let mut out = Vec::with_capacity(ace_count);
    for _ in 0..ace_count {
        if offset + 8 > dacl_size {
            return None;
        }
        let ace_size = usize::from(u16::from_le_bytes(
            dacl[offset + 2..offset + 4].try_into().unwrap(),
        ));
        if ace_size < 8 || offset + ace_size > dacl_size {
            return None;
        }
        out.push(SecurityAce {
            ace_type: dacl[offset],
            flags: dacl[offset + 1],
            mask: u32::from_le_bytes(dacl[offset + 4..offset + 8].try_into().unwrap()),
        });
        offset += ace_size;
    }
    Some(out)
}

fn security_descriptor_dacl(descriptor: &[u8]) -> Option<&[u8]> {
    if !security_descriptor_has_dacl(descriptor) {
        return None;
    }
    let dacl_offset = u32::from_le_bytes(descriptor[16..20].try_into().unwrap()) as usize;
    if dacl_offset == 0 || dacl_offset < 20 || dacl_offset + 8 > descriptor.len() {
        return None;
    }
    let dacl_size = usize::from(u16::from_le_bytes(
        descriptor[dacl_offset + 2..dacl_offset + 4]
            .try_into()
            .unwrap(),
    ));
    if dacl_size < 8 || dacl_offset + dacl_size > descriptor.len() {
        return None;
    }
    Some(&descriptor[dacl_offset..dacl_offset + dacl_size])
}

fn expand_file_access_mask(access: u32) -> u32 {
    const FILE_PIPE_PRINTER_ACCESS_ALL: u32 = 0x001f_01ff;
    const FILE_READ_DATA: u32 = 0x0000_0001;
    const FILE_WRITE_DATA: u32 = 0x0000_0002;
    const FILE_APPEND_DATA: u32 = 0x0000_0004;
    const FILE_READ_EA: u32 = 0x0000_0008;
    const FILE_WRITE_EA: u32 = 0x0000_0010;
    const FILE_EXECUTE: u32 = 0x0000_0020;
    const FILE_READ_ATTRIBUTES: u32 = 0x0000_0080;
    const FILE_WRITE_ATTRIBUTES: u32 = 0x0000_0100;
    const READ_CONTROL: u32 = 0x0002_0000;
    const SYNCHRONIZE: u32 = 0x0010_0000;
    const MAXIMUM_ALLOWED: u32 = 0x0200_0000;
    const GENERIC_ALL: u32 = 0x1000_0000;
    const GENERIC_EXECUTE: u32 = 0x2000_0000;
    const GENERIC_WRITE: u32 = 0x4000_0000;
    const GENERIC_READ: u32 = 0x8000_0000;

    if access & MAXIMUM_ALLOWED != 0 {
        return FILE_PIPE_PRINTER_ACCESS_ALL;
    }
    let mut expanded = access & FILE_PIPE_PRINTER_ACCESS_ALL;
    if access & GENERIC_ALL != 0 {
        expanded |= FILE_PIPE_PRINTER_ACCESS_ALL;
    }
    if access & GENERIC_READ != 0 {
        expanded |=
            FILE_READ_DATA | FILE_READ_EA | FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE;
    }
    if access & GENERIC_WRITE != 0 {
        expanded |= FILE_WRITE_DATA
            | FILE_APPEND_DATA
            | FILE_WRITE_EA
            | FILE_WRITE_ATTRIBUTES
            | READ_CONTROL
            | SYNCHRONIZE;
    }
    if access & GENERIC_EXECUTE != 0 {
        expanded |= FILE_EXECUTE | FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE;
    }
    expanded
}

pub fn filter_security_descriptor(descriptor: &[u8], security_information: u32) -> Vec<u8> {
    if security_information == 0 || descriptor.len() < 20 {
        return descriptor.to_vec();
    }

    const OWNER_SECURITY_INFORMATION: u32 = 0x0000_0001;
    const GROUP_SECURITY_INFORMATION: u32 = 0x0000_0002;
    const DACL_SECURITY_INFORMATION: u32 = 0x0000_0004;
    const SACL_SECURITY_INFORMATION: u32 = 0x0000_0008;
    const SE_DACL_PRESENT: u16 = 0x0004;
    const SE_SACL_PRESENT: u16 = 0x0010;
    const SE_SELF_RELATIVE: u16 = 0x8000;

    let mut out = vec![0; 20];
    out[0] = descriptor[0];
    out[1] = descriptor[1];
    let mut control = u16::from_le_bytes(descriptor[2..4].try_into().unwrap()) & SE_SELF_RELATIVE;
    let mut next = 20usize;

    copy_security_descriptor_section(
        descriptor,
        &mut out,
        &mut next,
        &mut control,
        4,
        security_information & OWNER_SECURITY_INFORMATION != 0,
        0,
    );
    copy_security_descriptor_section(
        descriptor,
        &mut out,
        &mut next,
        &mut control,
        8,
        security_information & GROUP_SECURITY_INFORMATION != 0,
        0,
    );
    copy_security_descriptor_section(
        descriptor,
        &mut out,
        &mut next,
        &mut control,
        12,
        security_information & SACL_SECURITY_INFORMATION != 0,
        SE_SACL_PRESENT,
    );
    copy_security_descriptor_section(
        descriptor,
        &mut out,
        &mut next,
        &mut control,
        16,
        security_information & DACL_SECURITY_INFORMATION != 0,
        SE_DACL_PRESENT,
    );
    out[2..4].copy_from_slice(&control.to_le_bytes());
    out
}

fn copy_security_descriptor_section(
    descriptor: &[u8],
    out: &mut Vec<u8>,
    next: &mut usize,
    control: &mut u16,
    field_offset: usize,
    requested: bool,
    present_bit: u16,
) {
    if !requested {
        return;
    }
    if present_bit != 0
        && u16::from_le_bytes(descriptor[2..4].try_into().unwrap()) & present_bit != 0
    {
        *control |= present_bit;
    }
    let Some(offset_bytes) = descriptor.get(field_offset..field_offset + 4) else {
        return;
    };
    let src_offset = u32::from_le_bytes(offset_bytes.try_into().unwrap()) as usize;
    if src_offset == 0 || src_offset < 20 || src_offset >= descriptor.len() {
        return;
    }
    let Some(src_len) = security_descriptor_section_length(&descriptor[src_offset..]) else {
        return;
    };
    let Some(section) = descriptor.get(src_offset..src_offset + src_len) else {
        return;
    };
    out[field_offset..field_offset + 4].copy_from_slice(&(*next as u32).to_le_bytes());
    out.extend_from_slice(section);
    *next += src_len;
    *control |= present_bit;
}

fn security_descriptor_section_length(section: &[u8]) -> Option<usize> {
    if section.len() < 8 {
        return None;
    }
    match section[0] {
        1 => {
            let len = 8 + usize::from(section[1]) * 4;
            (len <= section.len()).then_some(len)
        }
        2 => {
            let len = usize::from(u16::from_le_bytes(section[2..4].try_into().unwrap()));
            (len >= 8 && len <= section.len()).then_some(len)
        }
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Directory information classes (MS-FSCC §2.4.{8,14,17,30,31})
// ---------------------------------------------------------------------------

/// Encode a single directory-information entry. Returns the encoded bytes.
/// The caller patches `NextEntryOffset` for chained entries.
pub fn encode_dir_entry_with_index(
    class: u8,
    entry: &DirEntry,
    directory_index: u32,
    file_id: u64,
) -> Vec<u8> {
    encode_dir_entry_with_index_and_posix(class, entry, directory_index, file_id, None)
}

pub fn encode_dir_entry_with_index_and_posix(
    class: u8,
    entry: &DirEntry,
    directory_index: u32,
    file_id: u64,
    posix: Option<PosixMetadata>,
) -> Vec<u8> {
    let info = &entry.info;
    let name_u16 = utf16le(&info.name);
    match class {
        FILE_DIRECTORY_INFORMATION => {
            // 64 bytes fixed + name
            let mut out = Vec::new();
            write_dir_entry_prefix(&mut out, info, directory_index, name_u16.len());
            out.extend_from_slice(&name_u16);
            out
        }
        FILE_FULL_DIRECTORY_INFORMATION => {
            let mut out = Vec::new();
            write_dir_entry_prefix(&mut out, info, directory_index, name_u16.len());
            out.extend_from_slice(&0u32.to_le_bytes()); // EaSize
            out.extend_from_slice(&name_u16);
            out
        }
        FILE_BOTH_DIRECTORY_INFORMATION => {
            let mut out = Vec::new();
            write_dir_entry_prefix(&mut out, info, directory_index, name_u16.len());
            out.extend_from_slice(&0u32.to_le_bytes()); // EaSize
            write_short_name_fields(&mut out, &info.name);
            out.extend_from_slice(&name_u16);
            out
        }
        FILE_ID_BOTH_DIRECTORY_INFORMATION => {
            let mut out = Vec::new();
            write_dir_entry_prefix(&mut out, info, directory_index, name_u16.len());
            out.extend_from_slice(&0u32.to_le_bytes()); // EaSize
            write_short_name_fields(&mut out, &info.name);
            out.extend_from_slice(&0u16.to_le_bytes()); // Reserved2
            out.extend_from_slice(&file_id.to_le_bytes()); // FileId
            out.extend_from_slice(&name_u16);
            out
        }
        FILE_ID_FULL_DIRECTORY_INFORMATION => {
            let mut out = Vec::new();
            write_dir_entry_prefix(&mut out, info, directory_index, name_u16.len());
            out.extend_from_slice(&0u32.to_le_bytes()); // EaSize
            out.extend_from_slice(&0u32.to_le_bytes()); // Reserved
            out.extend_from_slice(&file_id.to_le_bytes()); // FileId
            out.extend_from_slice(&name_u16);
            out
        }
        FILE_ID_EXTD_DIRECTORY_INFORMATION => {
            let mut out = Vec::new();
            write_dir_entry_prefix(&mut out, info, directory_index, name_u16.len());
            out.extend_from_slice(&0u32.to_le_bytes()); // EaSize
            out.extend_from_slice(&0u32.to_le_bytes()); // ReparsePointTag
            out.extend_from_slice(&file_id.to_le_bytes()); // FileId
            out.extend_from_slice(&0u64.to_le_bytes()); // ExtendedDirectoryInfoReserved
            out.extend_from_slice(&name_u16);
            out
        }
        FILE_ID_64_EXTD_DIRECTORY_INFORMATION => {
            let mut out = Vec::new();
            write_dir_entry_prefix(&mut out, info, directory_index, name_u16.len());
            out.extend_from_slice(&0u32.to_le_bytes()); // EaSize
            out.extend_from_slice(&0u32.to_le_bytes()); // ReparsePointTag
            out.extend_from_slice(&file_id.to_le_bytes()); // FileId
            out.extend_from_slice(&name_u16);
            out
        }
        FILE_ID_64_EXTD_BOTH_DIRECTORY_INFORMATION => {
            let mut out = Vec::new();
            write_dir_entry_prefix(&mut out, info, directory_index, name_u16.len());
            out.extend_from_slice(&0u32.to_le_bytes()); // EaSize
            out.extend_from_slice(&0u32.to_le_bytes()); // ReparsePointTag
            out.extend_from_slice(&file_id.to_le_bytes()); // FileId
            write_short_name_fields(&mut out, &info.name);
            out.extend_from_slice(&name_u16);
            out
        }
        FILE_ID_ALL_EXTD_DIRECTORY_INFORMATION => {
            let mut out = Vec::new();
            write_dir_entry_prefix(&mut out, info, directory_index, name_u16.len());
            out.extend_from_slice(&0u32.to_le_bytes()); // EaSize
            out.extend_from_slice(&0u32.to_le_bytes()); // ReparsePointTag
            out.extend_from_slice(&file_id.to_le_bytes()); // FileId
            out.extend_from_slice(&file_id.to_le_bytes()); // FileId128 low bits
            out.extend_from_slice(&0u64.to_le_bytes()); // FileId128 high bits
            out.extend_from_slice(&name_u16);
            out
        }
        FILE_ID_ALL_EXTD_BOTH_DIRECTORY_INFORMATION => {
            let mut out = Vec::new();
            write_dir_entry_prefix(&mut out, info, directory_index, name_u16.len());
            out.extend_from_slice(&0u32.to_le_bytes()); // EaSize
            out.extend_from_slice(&0u32.to_le_bytes()); // ReparsePointTag
            out.extend_from_slice(&file_id.to_le_bytes()); // FileId
            out.extend_from_slice(&file_id.to_le_bytes()); // FileId128 low bits
            out.extend_from_slice(&0u64.to_le_bytes()); // FileId128 high bits
            write_short_name_fields(&mut out, &info.name);
            out.extend_from_slice(&name_u16);
            out
        }
        FILE_NAMES_INFORMATION => {
            let mut out = Vec::new();
            out.extend_from_slice(&0u32.to_le_bytes());
            out.extend_from_slice(&directory_index.to_le_bytes());
            out.extend_from_slice(&(name_u16.len() as u32).to_le_bytes());
            out.extend_from_slice(&name_u16);
            out
        }
        FILE_POSIX_INFORMATION => {
            let mut out = Vec::new();
            out.extend_from_slice(&0u32.to_le_bytes()); // NextEntryOffset
            out.extend_from_slice(&directory_index.to_le_bytes()); // FileIndex
            out.extend_from_slice(&encode_file_posix_information(info, file_id, posix));
            out.extend_from_slice(&(name_u16.len() as u32).to_le_bytes());
            out.extend_from_slice(&name_u16);
            out
        }
        _ => Vec::new(),
    }
}

fn write_short_name_fields(out: &mut Vec<u8>, name: &str) {
    if name == "." || name == ".." {
        out.push(0);
        out.push(0);
        out.extend_from_slice(&[0u8; 24]);
        return;
    }

    let short = make_short_name(name);
    let short_u16 = utf16le(&short);
    let len = short_u16.len().min(24);
    let mut buf = [0u8; 24];
    buf[..len].copy_from_slice(&short_u16[..len]);
    out.push(len as u8);
    out.push(0);
    out.extend_from_slice(&buf);
}

fn write_dir_entry_prefix(
    out: &mut Vec<u8>,
    info: &FileInfo,
    directory_index: u32,
    name_len: usize,
) {
    out.extend_from_slice(&0u32.to_le_bytes()); // NextEntryOffset (patched later)
    out.extend_from_slice(&directory_index.to_le_bytes()); // FileIndex
    out.extend_from_slice(&info.creation_time.to_le_bytes());
    out.extend_from_slice(&info.last_access_time.to_le_bytes());
    out.extend_from_slice(&info.last_write_time.to_le_bytes());
    out.extend_from_slice(&info.change_time.to_le_bytes());
    out.extend_from_slice(&info.end_of_file.to_le_bytes());
    out.extend_from_slice(&info.allocation_size.to_le_bytes());
    out.extend_from_slice(&info.attributes().to_le_bytes());
    out.extend_from_slice(&(name_len as u32).to_le_bytes());
}

/// Round up `n` to the next multiple of 8.
pub fn align8(n: usize) -> usize {
    (n + 7) & !7
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fake_info() -> FileInfo {
        FileInfo {
            name: "file.txt".to_string(),
            end_of_file: 100,
            allocation_size: 100,
            creation_time: 0x01D9_0000_0000_0000,
            last_access_time: 0x01D9_0000_0000_0000,
            last_write_time: 0x01D9_0000_0000_0000,
            change_time: 0x01D9_0000_0000_0000,
            is_directory: false,
            file_index: 1,
            file_attributes: crate::backend::default_file_attributes(false),
        }
    }

    #[test]
    fn basic_information_is_40_bytes() {
        let bytes = encode_file_basic_information(&fake_info());
        assert_eq!(bytes.len(), 40);
    }

    #[test]
    fn standard_information_is_24_bytes() {
        let bytes = encode_file_standard_information(&fake_info(), false);
        assert_eq!(bytes.len(), 24);
    }

    #[test]
    fn standard_information_includes_delete_pending() {
        let bytes = encode_file_standard_information(&fake_info(), true);
        assert_eq!(bytes[20], 1);
    }

    #[test]
    fn network_open_information_is_56_bytes() {
        let bytes = encode_file_network_open_information(&fake_info());
        assert_eq!(bytes.len(), 56);
    }

    #[test]
    fn file_stream_information_multi_record_chain_matches_gosmb_fixture() {
        let streams = [
            FileStream {
                name: "::$DATA".to_string(),
                size: 4,
                allocation: 4096,
            },
            FileStream {
                name: ":streamtwo:$DATA".to_string(),
                size: 12,
                allocation: 4096,
            },
        ];

        let output = encode_file_stream_information(&fake_info(), &streams);
        let first_next = u32::from_le_bytes(output[0..4].try_into().unwrap()) as usize;
        assert!(first_next > 0 && first_next < output.len());
        assert_eq!(u64::from_le_bytes(output[8..16].try_into().unwrap()), 4);

        let first_name_len = u32::from_le_bytes(output[4..8].try_into().unwrap()) as usize;
        assert_eq!(
            &output[24..24 + first_name_len],
            utf16le("::$DATA").as_slice()
        );

        let second = &output[first_next..];
        assert_eq!(u32::from_le_bytes(second[0..4].try_into().unwrap()), 0);
        assert_eq!(u64::from_le_bytes(second[8..16].try_into().unwrap()), 12);

        let second_name_len = u32::from_le_bytes(second[4..8].try_into().unwrap()) as usize;
        assert_eq!(
            &second[24..24 + second_name_len],
            utf16le(":streamtwo:$DATA").as_slice()
        );
    }

    #[test]
    fn alternate_name_information_uses_dos_short_name() {
        let bytes = encode_file_alternate_name_information("torture_search.txt");
        assert_eq!(
            u32::from_le_bytes(bytes[0..4].try_into().unwrap()),
            "TORTUR~1.TXT".len() as u32 * 2
        );
        assert_eq!(&bytes[4..], &utf16le("TORTUR~1.TXT"));
    }

    #[test]
    fn both_directory_information_includes_dos_short_name() {
        let mut info = fake_info();
        info.name = "torture_search.txt".to_string();
        let entry = DirEntry { info };

        let bytes = encode_dir_entry_with_index(FILE_BOTH_DIRECTORY_INFORMATION, &entry, 1, 1);

        let short = utf16le("TORTUR~1.TXT");
        assert_eq!(bytes[68], short.len() as u8);
        assert_eq!(&bytes[70..70 + short.len()], short.as_slice());
    }

    #[test]
    fn file_id_both_directory_information_keeps_file_id_with_dos_short_name() {
        let mut info = fake_info();
        info.name = "another long name.bin".to_string();
        let entry = DirEntry { info };

        let bytes = encode_dir_entry_with_index(
            FILE_ID_BOTH_DIRECTORY_INFORMATION,
            &entry,
            1,
            0x1122_3344_5566_7788,
        );

        let short = utf16le("ANOTHE~1.BIN");
        assert_eq!(bytes[68], short.len() as u8);
        assert_eq!(&bytes[70..70 + short.len()], short.as_slice());
        assert_eq!(
            u64::from_le_bytes(bytes[96..104].try_into().unwrap()),
            0x1122_3344_5566_7788
        );
    }

    #[test]
    fn extended_directory_information_classes_match_gosmb_offsets() {
        let mut info = fake_info();
        info.name = "extended name.txt".to_string();
        info.end_of_file = 5;
        info.allocation_size = 4096;
        info.file_attributes = 0x20;
        let entry = DirEntry { info };
        let name = utf16le("extended name.txt");

        struct Case {
            class: u8,
            header_size: usize,
            file_id_off: usize,
            file_id128_off: Option<usize>,
            short_off: Option<usize>,
            name_off: usize,
            short_name: Option<&'static str>,
        }

        for case in [
            Case {
                class: FILE_ID_EXTD_DIRECTORY_INFORMATION,
                header_size: 88,
                file_id_off: 72,
                file_id128_off: Some(72),
                short_off: None,
                name_off: 88,
                short_name: None,
            },
            Case {
                class: FILE_ID_64_EXTD_DIRECTORY_INFORMATION,
                header_size: 80,
                file_id_off: 72,
                file_id128_off: None,
                short_off: None,
                name_off: 80,
                short_name: None,
            },
            Case {
                class: FILE_ID_64_EXTD_BOTH_DIRECTORY_INFORMATION,
                header_size: 106,
                file_id_off: 72,
                file_id128_off: None,
                short_off: Some(80),
                name_off: 106,
                short_name: Some("EXTEND~1.TXT"),
            },
            Case {
                class: FILE_ID_ALL_EXTD_DIRECTORY_INFORMATION,
                header_size: 96,
                file_id_off: 72,
                file_id128_off: Some(80),
                short_off: None,
                name_off: 96,
                short_name: None,
            },
            Case {
                class: FILE_ID_ALL_EXTD_BOTH_DIRECTORY_INFORMATION,
                header_size: 122,
                file_id_off: 72,
                file_id128_off: Some(80),
                short_off: Some(96),
                name_off: 122,
                short_name: Some("EXTEND~1.TXT"),
            },
        ] {
            let bytes = encode_dir_entry_with_index(case.class, &entry, 7, 0x1122_3344_5566_7788);
            assert!(bytes.len() >= case.header_size);
            assert_eq!(u32::from_le_bytes(bytes[4..8].try_into().unwrap()), 7);
            assert_eq!(u64::from_le_bytes(bytes[40..48].try_into().unwrap()), 5);
            assert_eq!(u64::from_le_bytes(bytes[48..56].try_into().unwrap()), 4096);
            assert_eq!(u32::from_le_bytes(bytes[56..60].try_into().unwrap()), 0x20);
            assert_eq!(
                u32::from_le_bytes(bytes[60..64].try_into().unwrap()) as usize,
                name.len()
            );
            assert_eq!(u32::from_le_bytes(bytes[64..68].try_into().unwrap()), 0);
            assert_eq!(u32::from_le_bytes(bytes[68..72].try_into().unwrap()), 0);
            assert_eq!(
                u64::from_le_bytes(
                    bytes[case.file_id_off..case.file_id_off + 8]
                        .try_into()
                        .unwrap()
                ),
                0x1122_3344_5566_7788
            );
            if let Some(off) = case.file_id128_off {
                assert_eq!(
                    u64::from_le_bytes(bytes[off..off + 8].try_into().unwrap()),
                    0x1122_3344_5566_7788
                );
                assert_eq!(
                    u64::from_le_bytes(bytes[off + 8..off + 16].try_into().unwrap()),
                    0
                );
            }
            if let (Some(off), Some(short)) = (case.short_off, case.short_name) {
                let short_len = bytes[off] as usize;
                assert_eq!(
                    &bytes[off + 2..off + 2 + short_len],
                    utf16le(short).as_slice()
                );
            }
            assert_eq!(
                &bytes[case.name_off..case.name_off + name.len()],
                name.as_slice()
            );
        }
    }

    #[test]
    fn normalized_name_information_reuses_name_encoding() {
        let bytes = encode_file_name_information("dir\\file.txt");
        assert_eq!(
            u32::from_le_bytes(bytes[0..4].try_into().unwrap()),
            "dir\\file.txt".len() as u32 * 2
        );
        assert_eq!(&bytes[4..], &utf16le("dir\\file.txt"));
    }

    #[test]
    fn compression_information_reports_uncompressed_storage() {
        let bytes = encode_file_compression_information();
        assert_eq!(bytes.len(), 16);
        assert!(bytes.iter().all(|b| *b == 0));
    }

    #[test]
    fn attribute_tag_information_includes_attributes_and_zero_reparse_tag() {
        let bytes = encode_file_attribute_tag_information(&fake_info());
        assert_eq!(bytes.len(), 8);
        assert_eq!(u32::from_le_bytes(bytes[0..4].try_into().unwrap()), 0x20);
        assert_eq!(u32::from_le_bytes(bytes[4..8].try_into().unwrap()), 0);
    }

    #[test]
    fn remote_protocol_information_includes_dialect_version() {
        let bytes = encode_file_remote_protocol_information(Some(Dialect::Smb311));
        assert_eq!(bytes.len(), 180);
        assert_eq!(u16::from_le_bytes(bytes[0..2].try_into().unwrap()), 1);
        assert_eq!(u16::from_le_bytes(bytes[2..4].try_into().unwrap()), 180);
        assert_eq!(
            u32::from_le_bytes(bytes[4..8].try_into().unwrap()),
            0x0002_0000
        );
        assert_eq!(u16::from_le_bytes(bytes[8..10].try_into().unwrap()), 3);
        assert_eq!(u16::from_le_bytes(bytes[10..12].try_into().unwrap()), 1);
        assert_eq!(u16::from_le_bytes(bytes[12..14].try_into().unwrap()), 1);
    }

    #[test]
    fn file_id_information_is_24_bytes_with_reserved_gap() {
        let bytes = encode_file_id_information(0xAABB_CCDD_EEFF_0011, 0x1122_3344_5566_7788);
        assert_eq!(bytes.len(), 24);
        assert_eq!(
            u64::from_le_bytes(bytes[0..8].try_into().unwrap()),
            0xAABB_CCDD_EEFF_0011
        );
        assert_eq!(u64::from_le_bytes(bytes[8..16].try_into().unwrap()), 0);
        assert_eq!(
            u64::from_le_bytes(bytes[16..24].try_into().unwrap()),
            0x1122_3344_5566_7788
        );
    }

    #[test]
    fn posix_information_uses_default_mode_and_root_identity() {
        let bytes = encode_file_posix_information(&fake_info(), 0x1020_3040_5060_7080, None);
        assert_eq!(bytes.len(), 136);
        assert_eq!(
            u64::from_le_bytes(bytes[40..48].try_into().unwrap()),
            fake_info().end_of_file
        );
        assert_eq!(
            u64::from_le_bytes(bytes[52..60].try_into().unwrap()),
            0x1020_3040_5060_7080
        );
        assert_eq!(u32::from_le_bytes(bytes[68..72].try_into().unwrap()), 1);
        assert_eq!(u32::from_le_bytes(bytes[76..80].try_into().unwrap()), 0o644);
        assert_eq!(u32::from_le_bytes(bytes[88..92].try_into().unwrap()), 88);
        assert_eq!(u32::from_le_bytes(bytes[92..96].try_into().unwrap()), 1);
        assert_eq!(u32::from_le_bytes(bytes[96..100].try_into().unwrap()), 0);
        assert_eq!(u32::from_le_bytes(bytes[116..120].try_into().unwrap()), 88);
        assert_eq!(u32::from_le_bytes(bytes[120..124].try_into().unwrap()), 2);
        assert_eq!(u32::from_le_bytes(bytes[124..128].try_into().unwrap()), 0);
    }

    #[test]
    fn posix_information_uses_stored_mode_and_identity() {
        let bytes = encode_file_posix_information(
            &fake_info(),
            1,
            Some(PosixMetadata {
                mode: 0o600,
                uid: 1001,
                gid: 1001,
            }),
        );
        assert_eq!(u32::from_le_bytes(bytes[76..80].try_into().unwrap()), 0o600);
        assert_eq!(u32::from_le_bytes(bytes[96..100].try_into().unwrap()), 1001);
        assert_eq!(
            u32::from_le_bytes(bytes[124..128].try_into().unwrap()),
            1001
        );
    }

    #[test]
    fn posix_directory_entry_has_148_byte_fixed_prefix() {
        let mut info = fake_info();
        info.name = "posix name.txt".to_string();
        info.end_of_file = 37;
        info.allocation_size = 4096;
        info.file_attributes = 0x20;
        let entry = DirEntry { info };
        let name = utf16le("posix name.txt");

        let bytes = encode_dir_entry_with_index_and_posix(
            FILE_POSIX_INFORMATION,
            &entry,
            9,
            0x1020_3040_5060_7080,
            Some(PosixMetadata {
                mode: 0o600,
                uid: 1001,
                gid: 1002,
            }),
        );
        assert_eq!(u32::from_le_bytes(bytes[4..8].try_into().unwrap()), 9);
        assert_eq!(u64::from_le_bytes(bytes[40..48].try_into().unwrap()), 4096);
        assert_eq!(u64::from_le_bytes(bytes[48..56].try_into().unwrap()), 37);
        assert_eq!(u32::from_le_bytes(bytes[56..60].try_into().unwrap()), 0x20);
        assert_eq!(
            u64::from_le_bytes(bytes[60..68].try_into().unwrap()),
            0x1020_3040_5060_7080
        );
        assert_eq!(u32::from_le_bytes(bytes[84..88].try_into().unwrap()), 0o600);
        assert_eq!(
            u32::from_le_bytes(bytes[144..148].try_into().unwrap()) as usize,
            name.len()
        );
        assert_eq!(&bytes[148..], name.as_slice());
    }

    #[test]
    fn file_all_information_empty_name_keeps_linux_minimum_size() {
        let mut info = fake_info();
        info.name.clear();
        let bytes = encode_file_all_information(&info, 1, 0x001F_01FF, 0, 0, false);
        assert_eq!(bytes.len(), 101);
    }

    #[test]
    fn file_all_information_ea_size_slot_matches_gosmb_zero() {
        let bytes = encode_file_all_information(&fake_info(), 1, 0x001F_01FF, 0, 0, false);
        assert_eq!(u32::from_le_bytes(bytes[72..76].try_into().unwrap()), 0);
    }

    #[test]
    fn filesystem_information_encoders_match_gosmb_wire_sizes() {
        let size = encode_fs_size_information(1024, 512, 8, 512);
        assert_eq!(size.len(), 24);
        assert_ne!(u32::from_le_bytes(size[16..20].try_into().unwrap()), 0);

        let full = encode_fs_full_size_information(1024, 512, 512, 8, 512);
        assert_eq!(full.len(), 32);

        let control = encode_fs_control_information();
        assert_eq!(control.len(), 48);

        let attrs = encode_fs_attribute_information(0x0000_0007, 255, "GOSMB");
        assert!(attrs.len() > 12);
    }

    #[test]
    fn file_all_information_includes_position_and_mode() {
        let bytes = encode_file_all_information(&fake_info(), 1, 0x001F_01FF, 123456, 2, false);
        assert_eq!(
            u64::from_le_bytes(bytes[80..88].try_into().unwrap()),
            123456
        );
        assert_eq!(u32::from_le_bytes(bytes[88..92].try_into().unwrap()), 2);
    }

    #[test]
    fn file_all_information_includes_delete_pending() {
        let bytes = encode_file_all_information(&fake_info(), 1, 0x001F_01FF, 0, 0, true);
        assert_eq!(bytes[60], 1);
    }

    #[test]
    fn full_ea_information_empty_is_four_zero_bytes_but_size_is_zero() {
        let bytes = encode_file_full_ea_information(&[]);
        assert_eq!(bytes, vec![0; 4]);
        assert_eq!(full_ea_information_size(&[]), 0);
        assert_eq!(decode_file_full_ea_information(&bytes).unwrap(), Vec::new());
    }

    #[test]
    fn full_ea_information_round_trips_multiple_records() {
        let eas = vec![
            ExtendedAttribute {
                flags: 0,
                name: "EAONE".to_string(),
                value: b"VALUE1".to_vec(),
            },
            ExtendedAttribute {
                flags: 0x80,
                name: "SECONDEA".to_string(),
                value: b"ValueTwo".to_vec(),
            },
        ];
        let bytes = encode_file_full_ea_information(&eas);
        assert_eq!(full_ea_information_size(&eas), bytes.len() as u32);
        assert_eq!(decode_file_full_ea_information(&bytes).unwrap(), eas);
        assert_eq!(u32::from_le_bytes(bytes[0..4].try_into().unwrap()) % 4, 0);
    }

    #[test]
    fn full_ea_information_rejects_missing_name_terminator() {
        let mut bytes = encode_file_full_ea_information(&[ExtendedAttribute {
            flags: 0,
            name: "EAONE".to_string(),
            value: b"VALUE1".to_vec(),
        }]);
        bytes[13] = b'!';
        assert!(decode_file_full_ea_information(&bytes).is_err());
    }

    #[test]
    fn security_descriptor_is_self_relative() {
        let sd = encode_minimal_security_descriptor();
        assert!(sd.len() >= 20);
        assert_eq!(sd[0], 0x01);
        let control = u16::from_le_bytes(sd[2..4].try_into().unwrap());
        assert!(control & 0x8000 != 0);
        assert!(control & 0x0004 != 0);

        let owner = u32::from_le_bytes(sd[4..8].try_into().unwrap()) as usize;
        assert!((20..sd.len()).contains(&owner));

        let dacl = u32::from_le_bytes(sd[16..20].try_into().unwrap()) as usize;
        assert!((20..sd.len()).contains(&dacl));
    }

    #[test]
    fn security_descriptor_filter_returns_full_for_zero_information() {
        let sd = encode_minimal_security_descriptor();
        assert_eq!(filter_security_descriptor(&sd, 0), sd);
    }

    #[test]
    fn security_descriptor_filter_can_return_owner_only() {
        let sd = encode_minimal_security_descriptor();
        let filtered = filter_security_descriptor(&sd, 0x1);
        assert!(filtered.len() >= 20);
        assert_ne!(u32::from_le_bytes(filtered[4..8].try_into().unwrap()), 0);
        assert_eq!(u32::from_le_bytes(filtered[8..12].try_into().unwrap()), 0);
        assert_eq!(u32::from_le_bytes(filtered[16..20].try_into().unwrap()), 0);
        assert_eq!(
            u16::from_le_bytes(filtered[2..4].try_into().unwrap()),
            0x8000
        );
    }

    #[test]
    fn security_descriptor_filter_preserves_dacl_present_when_requested() {
        let sd = encode_minimal_security_descriptor();
        let filtered = filter_security_descriptor(&sd, 0x4);
        assert_eq!(u32::from_le_bytes(filtered[4..8].try_into().unwrap()), 0);
        assert_eq!(u32::from_le_bytes(filtered[16..20].try_into().unwrap()), 20);
        assert_eq!(
            u16::from_le_bytes(filtered[2..4].try_into().unwrap()) & 0x8004,
            0x8004
        );
    }

    #[test]
    fn set_security_descriptor_rejects_short_descriptor() {
        assert!(normalize_set_security_descriptor(&[0; 19]).is_none());
    }

    #[test]
    fn set_security_descriptor_without_dacl_becomes_nil_dacl() {
        let mut sd = vec![0; 20];
        sd[0] = 1;
        sd[2..4].copy_from_slice(&0x8000u16.to_le_bytes());

        assert_eq!(
            normalize_set_security_descriptor(&sd).unwrap(),
            encode_nil_dacl_security_descriptor()
        );
    }

    #[test]
    fn set_security_descriptor_with_dacl_is_preserved() {
        let mut sd = encode_minimal_security_descriptor();
        sd.extend_from_slice(&[0x11, 0x22]);
        assert_eq!(normalize_set_security_descriptor(&sd).unwrap(), sd);
    }

    #[test]
    fn empty_dacl_denies_non_security_open_access() {
        let sd = test_empty_dacl_security_descriptor();
        assert!(security_descriptor_denies_access(&sd, 0x0000_0002));
    }

    #[test]
    fn allow_only_dacl_denies_access_outside_allowed_mask() {
        let sd = test_security_descriptor_with_ace(ACCESS_ALLOWED_ACE_TYPE, 0, 0x0012_0089);
        assert!(!security_descriptor_denies_access(&sd, 0x0000_0001));
        assert!(security_descriptor_denies_access(&sd, 0x0000_0002));
    }

    #[test]
    fn deny_ace_detection_matches_requested_access() {
        let sd = test_security_descriptor_with_ace(ACCESS_DENIED_ACE_TYPE, 0x02, 0x0000_0002);
        assert!(security_descriptor_has_deny_ace(&sd, 0x0000_0002));
        assert!(!security_descriptor_has_deny_ace(&sd, 0x0000_0004));
    }

    #[test]
    fn inheritable_ace_detection_distinguishes_file_and_directory_children() {
        let object_sd = test_security_descriptor_with_ace(
            ACCESS_DENIED_ACE_TYPE,
            OBJECT_INHERIT_ACE,
            0x0000_0002,
        );
        assert!(security_descriptor_has_inheritable_ace(&object_sd, false));
        assert!(!security_descriptor_has_inheritable_ace(&object_sd, true));

        let container_sd = test_security_descriptor_with_ace(
            ACCESS_DENIED_ACE_TYPE,
            CONTAINER_INHERIT_ACE,
            0x0000_0002,
        );
        assert!(!security_descriptor_has_inheritable_ace(
            &container_sd,
            false
        ));
        assert!(security_descriptor_has_inheritable_ace(&container_sd, true));
    }

    fn test_security_descriptor_with_ace(ace_type: u8, ace_flags: u8, mask: u32) -> Vec<u8> {
        let everyone = [
            0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        ];

        let mut ace = Vec::new();
        ace.extend_from_slice(&[ace_type, ace_flags]);
        ace.extend_from_slice(&(8 + everyone.len() as u16).to_le_bytes());
        ace.extend_from_slice(&mask.to_le_bytes());
        ace.extend_from_slice(&everyone);

        let mut dacl = Vec::new();
        dacl.extend_from_slice(&[0x02, 0x00]);
        dacl.extend_from_slice(&(8 + ace.len() as u16).to_le_bytes());
        dacl.extend_from_slice(&1u16.to_le_bytes());
        dacl.extend_from_slice(&0u16.to_le_bytes());
        dacl.extend_from_slice(&ace);

        let mut sd = Vec::new();
        sd.extend_from_slice(&[0x01, 0x00]);
        sd.extend_from_slice(&0x8004u16.to_le_bytes());
        sd.extend_from_slice(&20u32.to_le_bytes());
        sd.extend_from_slice(&0u32.to_le_bytes());
        sd.extend_from_slice(&0u32.to_le_bytes());
        sd.extend_from_slice(&(20 + everyone.len() as u32).to_le_bytes());
        sd.extend_from_slice(&everyone);
        sd.extend_from_slice(&dacl);
        sd
    }

    fn test_empty_dacl_security_descriptor() -> Vec<u8> {
        let mut sd = vec![0; 28];
        sd[0] = 1;
        sd[2..4].copy_from_slice(&0x8004u16.to_le_bytes());
        sd[16..20].copy_from_slice(&20u32.to_le_bytes());
        sd[20] = 2;
        sd[22..24].copy_from_slice(&8u16.to_le_bytes());
        sd
    }
}
