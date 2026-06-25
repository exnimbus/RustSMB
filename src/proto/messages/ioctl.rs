//! IOCTL Request/Response (MS-SMB2 §2.2.31 / §2.2.32).

use binrw::{BinWrite, binrw};
use std::io::Cursor;

use super::create::FileId;
use crate::proto::error::{ProtoError, ProtoResult};

/// File-system control codes we recognize at the wire layer.
///
/// MS-FSCC catalogues the FSCTL codes; we only enumerate the ones referenced
/// in the spec for v1. Unknown codes round-trip via [`Fsctl::Other`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fsctl {
    /// `FSCTL_VALIDATE_NEGOTIATE_INFO` — required handler in v1.
    ValidateNegotiateInfo,
    /// `FSCTL_DFS_GET_REFERRALS`.
    DfsGetReferrals,
    /// `FSCTL_DFS_GET_REFERRALS_EX`.
    DfsGetReferralsEx,
    /// `FSCTL_PIPE_TRANSCEIVE`.
    PipeTranscede,
    /// `FSCTL_PIPE_PEEK`.
    PipePeek,
    /// `FSCTL_PIPE_WAIT`.
    PipeWait,
    /// `FSCTL_CREATE_OR_GET_OBJECT_ID`.
    CreateOrGetObjectId,
    /// `FSCTL_LMR_REQUEST_RESILIENCY`.
    LmrRequestResiliency,
    /// `FSCTL_QUERY_NETWORK_INTERFACE_INFO`.
    QueryNetworkInterfaceInfo,
    /// Samba smbtorture private FSCTL for forced unacked cache-break timeout.
    SmbTortureForceUnackedTimeout,
    /// Anything else.
    Other(u32),
}

impl Fsctl {
    pub const VALIDATE_NEGOTIATE_INFO: u32 = 0x0014_0204;
    pub const DFS_GET_REFERRALS: u32 = 0x0006_0194;
    pub const DFS_GET_REFERRALS_EX: u32 = 0x0006_0198;
    pub const PIPE_TRANSCEIVE: u32 = 0x0011_C017;
    pub const PIPE_PEEK: u32 = 0x0011_400C;
    pub const PIPE_WAIT: u32 = 0x0011_C018;
    pub const CREATE_OR_GET_OBJECT_ID: u32 = 0x0009_00C0;
    pub const LMR_REQUEST_RESILIENCY: u32 = 0x0014_01D4;
    pub const QUERY_NETWORK_INTERFACE_INFO: u32 = 0x0014_01FC;
    pub const SMBTORTURE_FORCE_UNACKED_TIMEOUT: u32 = 0x8384_8003;

    pub fn from_u32(code: u32) -> Self {
        match code {
            Self::VALIDATE_NEGOTIATE_INFO => Self::ValidateNegotiateInfo,
            Self::DFS_GET_REFERRALS => Self::DfsGetReferrals,
            Self::DFS_GET_REFERRALS_EX => Self::DfsGetReferralsEx,
            Self::PIPE_TRANSCEIVE => Self::PipeTranscede,
            Self::PIPE_PEEK => Self::PipePeek,
            Self::PIPE_WAIT => Self::PipeWait,
            Self::CREATE_OR_GET_OBJECT_ID => Self::CreateOrGetObjectId,
            Self::LMR_REQUEST_RESILIENCY => Self::LmrRequestResiliency,
            Self::QUERY_NETWORK_INTERFACE_INFO => Self::QueryNetworkInterfaceInfo,
            Self::SMBTORTURE_FORCE_UNACKED_TIMEOUT => Self::SmbTortureForceUnackedTimeout,
            other => Self::Other(other),
        }
    }

    pub fn as_u32(self) -> u32 {
        match self {
            Self::ValidateNegotiateInfo => Self::VALIDATE_NEGOTIATE_INFO,
            Self::DfsGetReferrals => Self::DFS_GET_REFERRALS,
            Self::DfsGetReferralsEx => Self::DFS_GET_REFERRALS_EX,
            Self::PipeTranscede => Self::PIPE_TRANSCEIVE,
            Self::PipePeek => Self::PIPE_PEEK,
            Self::PipeWait => Self::PIPE_WAIT,
            Self::CreateOrGetObjectId => Self::CREATE_OR_GET_OBJECT_ID,
            Self::LmrRequestResiliency => Self::LMR_REQUEST_RESILIENCY,
            Self::QueryNetworkInterfaceInfo => Self::QUERY_NETWORK_INTERFACE_INFO,
            Self::SmbTortureForceUnackedTimeout => Self::SMBTORTURE_FORCE_UNACKED_TIMEOUT,
            Self::Other(c) => c,
        }
    }
}

/// SMB2_IOCTL_REQUEST (MS-SMB2 §2.2.31).
///
/// `input_offset` and `output_offset` are absolute (from the start of the
/// SMB2 header). We model the input buffer immediately following the fixed
/// prefix; the output buffer area is unused on requests but kept for round
/// tripping and extension scenarios.
#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IoctlRequest {
    pub structure_size: u16,
    pub reserved: u16,
    pub ctl_code: u32,
    pub file_id: FileId,
    pub input_offset: u32,
    pub input_count: u32,
    pub max_input_response: u32,
    pub output_offset: u32,
    pub output_count: u32,
    pub max_output_response: u32,
    pub flags: u32,
    pub reserved2: u32,
    #[br(count = input_count as usize)]
    pub input: Vec<u8>,
}

impl IoctlRequest {
    /// Flag: SMB2_0_IOCTL_IS_FSCTL.
    pub const FLAG_IS_FSCTL: u32 = 0x0000_0001;

    pub fn fsctl(&self) -> Fsctl {
        Fsctl::from_u32(self.ctl_code)
    }

    pub fn parse(buf: &[u8]) -> ProtoResult<Self> {
        if buf.len() < 56 {
            return Err(ProtoError::Malformed("ioctl request too short"));
        }
        let structure_size = read_u16(buf, 0)?;
        if structure_size != 57 {
            return Err(ProtoError::Malformed("ioctl request structure_size != 57"));
        }
        let input_offset = read_u32(buf, 24)?;
        let input_count = read_u32(buf, 28)?;
        let input = if input_count == 0 {
            Vec::new()
        } else {
            let offset = (input_offset as usize)
                .checked_sub(crate::proto::header::SMB2_HEADER_LEN)
                .ok_or(ProtoError::Malformed(
                    "ioctl request input offset before SMB2 body",
                ))?;
            let end = offset
                .checked_add(input_count as usize)
                .ok_or(ProtoError::Malformed("ioctl request input range overflow"))?;
            if offset < 56 || end > buf.len() {
                return Err(ProtoError::Malformed("ioctl request input out of range"));
            }
            buf[offset..end].to_vec()
        };
        Ok(Self {
            structure_size,
            reserved: read_u16(buf, 2)?,
            ctl_code: read_u32(buf, 4)?,
            file_id: FileId::new(read_u64(buf, 8)?, read_u64(buf, 16)?),
            input_offset,
            input_count,
            max_input_response: read_u32(buf, 32)?,
            output_offset: read_u32(buf, 36)?,
            output_count: read_u32(buf, 40)?,
            max_output_response: read_u32(buf, 44)?,
            flags: read_u32(buf, 48)?,
            reserved2: read_u32(buf, 52)?,
            input,
        })
    }
    pub fn write_to(&self, out: &mut Vec<u8>) -> ProtoResult<()> {
        let mut c = Cursor::new(Vec::new());
        BinWrite::write(self, &mut c)?;
        out.extend_from_slice(&c.into_inner());
        Ok(())
    }
}

/// SMB2_IOCTL_RESPONSE (MS-SMB2 §2.2.32).
#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IoctlResponse {
    pub structure_size: u16,
    pub reserved: u16,
    pub ctl_code: u32,
    pub file_id: FileId,
    pub input_offset: u32,
    pub input_count: u32,
    pub output_offset: u32,
    pub output_count: u32,
    pub flags: u32,
    pub reserved2: u32,
    /// Output buffer immediately following the fixed prefix.
    #[br(count = output_count as usize)]
    pub output: Vec<u8>,
}

impl IoctlResponse {
    pub fn parse(buf: &[u8]) -> ProtoResult<Self> {
        if buf.len() < 48 {
            return Err(ProtoError::Malformed("ioctl response too short"));
        }
        let structure_size = read_u16(buf, 0)?;
        if structure_size != 49 {
            return Err(ProtoError::Malformed("ioctl response structure_size != 49"));
        }
        let output_offset = read_u32(buf, 32)?;
        let output_count = read_u32(buf, 36)?;
        let output = if output_count == 0 {
            Vec::new()
        } else {
            let offset = (output_offset as usize)
                .checked_sub(crate::proto::header::SMB2_HEADER_LEN)
                .ok_or(ProtoError::Malformed(
                    "ioctl response output offset before SMB2 body",
                ))?;
            let end = offset
                .checked_add(output_count as usize)
                .ok_or(ProtoError::Malformed(
                    "ioctl response output range overflow",
                ))?;
            if offset < 48 || end > buf.len() {
                return Err(ProtoError::Malformed("ioctl response output out of range"));
            }
            buf[offset..end].to_vec()
        };
        Ok(Self {
            structure_size,
            reserved: read_u16(buf, 2)?,
            ctl_code: read_u32(buf, 4)?,
            file_id: FileId::new(read_u64(buf, 8)?, read_u64(buf, 16)?),
            input_offset: read_u32(buf, 24)?,
            input_count: read_u32(buf, 28)?,
            output_offset,
            output_count,
            flags: read_u32(buf, 40)?,
            reserved2: read_u32(buf, 44)?,
            output,
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
        .ok_or(ProtoError::Malformed("ioctl u16 out of range"))?;
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn read_u32(buf: &[u8], offset: usize) -> ProtoResult<u32> {
    let bytes = buf
        .get(offset..offset + 4)
        .ok_or(ProtoError::Malformed("ioctl u32 out of range"))?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn read_u64(buf: &[u8], offset: usize) -> ProtoResult<u64> {
    let bytes = buf
        .get(offset..offset + 8)
        .ok_or(ProtoError::Malformed("ioctl u64 out of range"))?;
    Ok(u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fsctl_decode_known() {
        assert_eq!(Fsctl::from_u32(0x0014_0204), Fsctl::ValidateNegotiateInfo);
        assert_eq!(Fsctl::from_u32(0x0009_00C0), Fsctl::CreateOrGetObjectId);
        assert_eq!(Fsctl::from_u32(0x0014_01D4), Fsctl::LmrRequestResiliency);
        assert_eq!(Fsctl::from_u32(0xDEAD_BEEF), Fsctl::Other(0xDEAD_BEEF));
        assert_eq!(Fsctl::ValidateNegotiateInfo.as_u32(), 0x0014_0204);
        assert_eq!(Fsctl::CreateOrGetObjectId.as_u32(), 0x0009_00C0);
        assert_eq!(Fsctl::LmrRequestResiliency.as_u32(), 0x0014_01D4);
        assert_eq!(Fsctl::Other(0xDEAD_BEEF).as_u32(), 0xDEAD_BEEF);
    }

    #[test]
    fn request_round_trips() {
        let r = IoctlRequest {
            structure_size: 57,
            reserved: 0,
            ctl_code: Fsctl::VALIDATE_NEGOTIATE_INFO,
            file_id: FileId::any(),
            input_offset: 0x78,
            input_count: 4,
            max_input_response: 0,
            output_offset: 0,
            output_count: 0,
            max_output_response: 0x1000,
            flags: IoctlRequest::FLAG_IS_FSCTL,
            reserved2: 0,
            input: vec![0xCA, 0xFE, 0xBA, 0xBE],
        };
        let mut buf = Vec::new();
        r.write_to(&mut buf).unwrap();
        let decoded = IoctlRequest::parse(&buf).unwrap();
        assert_eq!(decoded, r);
        assert_eq!(decoded.fsctl(), Fsctl::ValidateNegotiateInfo);
    }

    #[test]
    fn request_decodes_padded_input_from_header_relative_offset() {
        let mut buf = vec![0; 64];
        buf[0..2].copy_from_slice(&57u16.to_le_bytes());
        buf[4..8].copy_from_slice(&Fsctl::PIPE_TRANSCEIVE.to_le_bytes());
        buf[8..16].copy_from_slice(&1u64.to_le_bytes());
        buf[16..24].copy_from_slice(&2u64.to_le_bytes());
        buf[24..28]
            .copy_from_slice(&(crate::proto::header::SMB2_HEADER_LEN as u32 + 60).to_le_bytes());
        buf[28..32].copy_from_slice(&4u32.to_le_bytes());
        buf[48..52].copy_from_slice(&IoctlRequest::FLAG_IS_FSCTL.to_le_bytes());
        buf[60..64].copy_from_slice(&[1, 2, 3, 4]);

        let decoded = IoctlRequest::parse(&buf).unwrap();

        assert_eq!(decoded.file_id, FileId::new(1, 2));
        assert_eq!(decoded.input, [1, 2, 3, 4]);
        assert_eq!(decoded.fsctl(), Fsctl::PipeTranscede);
    }

    #[test]
    fn request_rejects_wrong_structure_size() {
        let mut buf = vec![0; 56];
        buf[0..2].copy_from_slice(&56u16.to_le_bytes());

        assert!(matches!(
            IoctlRequest::parse(&buf),
            Err(ProtoError::Malformed(_))
        ));
    }

    #[test]
    fn request_rejects_input_out_of_range() {
        let mut buf = vec![0; 56];
        buf[0..2].copy_from_slice(&57u16.to_le_bytes());
        buf[24..28]
            .copy_from_slice(&(crate::proto::header::SMB2_HEADER_LEN as u32 + 56).to_le_bytes());
        buf[28..32].copy_from_slice(&1u32.to_le_bytes());

        assert!(matches!(
            IoctlRequest::parse(&buf),
            Err(ProtoError::Malformed(_))
        ));
    }

    #[test]
    fn response_round_trips() {
        let r = IoctlResponse {
            structure_size: 49,
            reserved: 0,
            ctl_code: Fsctl::VALIDATE_NEGOTIATE_INFO,
            file_id: FileId::any(),
            input_offset: 0,
            input_count: 0,
            output_offset: 0x70,
            output_count: 4,
            flags: 0,
            reserved2: 0,
            output: vec![1, 2, 3, 4],
        };
        let mut buf = Vec::new();
        r.write_to(&mut buf).unwrap();
        assert_eq!(IoctlResponse::parse(&buf).unwrap(), r);
    }

    #[test]
    fn response_decodes_padded_output_from_header_relative_offset() {
        let mut buf = vec![0; 56];
        buf[0..2].copy_from_slice(&49u16.to_le_bytes());
        buf[4..8].copy_from_slice(&Fsctl::VALIDATE_NEGOTIATE_INFO.to_le_bytes());
        buf[8..16].copy_from_slice(&1u64.to_le_bytes());
        buf[16..24].copy_from_slice(&2u64.to_le_bytes());
        buf[32..36]
            .copy_from_slice(&(crate::proto::header::SMB2_HEADER_LEN as u32 + 52).to_le_bytes());
        buf[36..40].copy_from_slice(&4u32.to_le_bytes());
        buf[52..56].copy_from_slice(&[5, 6, 7, 8]);

        let decoded = IoctlResponse::parse(&buf).unwrap();

        assert_eq!(decoded.file_id, FileId::new(1, 2));
        assert_eq!(decoded.output, [5, 6, 7, 8]);
    }

    #[test]
    fn response_rejects_wrong_structure_size() {
        let mut buf = vec![0; 48];
        buf[0..2].copy_from_slice(&48u16.to_le_bytes());

        assert!(matches!(
            IoctlResponse::parse(&buf),
            Err(ProtoError::Malformed(_))
        ));
    }

    #[test]
    fn response_rejects_output_out_of_range() {
        let mut buf = vec![0; 48];
        buf[0..2].copy_from_slice(&49u16.to_le_bytes());
        buf[32..36]
            .copy_from_slice(&(crate::proto::header::SMB2_HEADER_LEN as u32 + 48).to_le_bytes());
        buf[36..40].copy_from_slice(&1u32.to_le_bytes());

        assert!(matches!(
            IoctlResponse::parse(&buf),
            Err(ProtoError::Malformed(_))
        ));
    }
}
