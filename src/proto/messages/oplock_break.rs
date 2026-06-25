//! OPLOCK_BREAK Notification + Acknowledgement (MS-SMB2 §2.2.23 / §2.2.24).
//!
//! V1 never grants oplocks, so we never *send* a notification, but the
//! handler exists for safety. A client may send an OPLOCK_BREAK ACK before
//! the server has cleared its oplock state in the (rare) edge case during
//! teardown.

use binrw::{BinRead, BinWrite, binrw};
use std::io::Cursor;

use super::create::FileId;
use crate::proto::error::{ProtoError, ProtoResult};

/// SMB2_OPLOCK_BREAK_NOTIFICATION (MS-SMB2 §2.2.23.1).
#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OplockBreakNotification {
    pub structure_size: u16,
    pub oplock_level: u8,
    pub reserved: u8,
    pub reserved2: u32,
    pub file_id: FileId,
}

impl OplockBreakNotification {
    pub fn parse(buf: &[u8]) -> ProtoResult<Self> {
        let message = Self::read(&mut Cursor::new(buf))?;
        if message.structure_size != 24 {
            return Err(ProtoError::Malformed("oplock break structure_size != 24"));
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

/// SMB2_OPLOCK_BREAK_ACK (MS-SMB2 §2.2.24.1) — same wire shape as the
/// notification.
pub type OplockBreakAck = OplockBreakNotification;

/// SMB2_LEASE_BREAK_ACKNOWLEDGEMENT (MS-SMB2 §2.2.24.2).
#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeaseBreakAck {
    pub structure_size: u16,
    pub reserved: u16,
    pub flags: u32,
    pub lease_key: [u8; 16],
    pub lease_state: u32,
    pub lease_duration: u64,
}

impl LeaseBreakAck {
    pub fn parse(buf: &[u8]) -> ProtoResult<Self> {
        let message = Self::read(&mut Cursor::new(buf))?;
        if message.structure_size != 36 {
            return Err(ProtoError::Malformed(
                "lease break ack structure_size != 36",
            ));
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

/// SMB2_LEASE_BREAK_RESPONSE (MS-SMB2 §2.2.25.2) uses the same fixed layout
/// fields as the acknowledgement for the state the server accepted.
pub type LeaseBreakResponse = LeaseBreakAck;

/// SMB2_LEASE_BREAK_NOTIFICATION (MS-SMB2 §2.2.23.2).
#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeaseBreakNotification {
    pub structure_size: u16,
    pub new_epoch: u16,
    pub flags: u32,
    pub lease_key: [u8; 16],
    pub current_lease_state: u32,
    pub new_lease_state: u32,
    pub break_reason: u32,
    pub access_mask_hint: u32,
    pub share_mask_hint: u32,
}

impl LeaseBreakNotification {
    pub fn parse(buf: &[u8]) -> ProtoResult<Self> {
        let message = Self::read(&mut Cursor::new(buf))?;
        if message.structure_size != 44 {
            return Err(ProtoError::Malformed(
                "lease break notification structure_size != 44",
            ));
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips() {
        let r = OplockBreakNotification {
            structure_size: 24,
            oplock_level: 0,
            reserved: 0,
            reserved2: 0,
            file_id: FileId::new(1, 2),
        };
        let mut buf = Vec::new();
        r.write_to(&mut buf).unwrap();
        assert_eq!(OplockBreakNotification::parse(&buf).unwrap(), r);
    }

    #[test]
    fn oplock_break_rejects_wrong_structure_size() {
        let mut buf = vec![0; 24];
        buf[0..2].copy_from_slice(&25u16.to_le_bytes());

        assert!(matches!(
            OplockBreakNotification::parse(&buf),
            Err(ProtoError::Malformed(_))
        ));
    }

    #[test]
    fn lease_break_ack_round_trips() {
        let r = LeaseBreakAck {
            structure_size: 36,
            reserved: 0,
            flags: 0,
            lease_key: *b"0123456789abcdef",
            lease_state: 1,
            lease_duration: 0,
        };
        let mut buf = Vec::new();
        r.write_to(&mut buf).unwrap();
        assert_eq!(buf.len(), 36);
        assert_eq!(LeaseBreakAck::parse(&buf).unwrap(), r);
    }

    #[test]
    fn lease_break_ack_rejects_wrong_structure_size() {
        let mut buf = vec![0; 36];
        buf[0..2].copy_from_slice(&44u16.to_le_bytes());

        assert!(matches!(
            LeaseBreakAck::parse(&buf),
            Err(ProtoError::Malformed(_))
        ));
    }

    #[test]
    fn lease_break_notification_round_trips() {
        let r = LeaseBreakNotification {
            structure_size: 44,
            new_epoch: 2,
            flags: 1,
            lease_key: *b"0123456789abcdef",
            current_lease_state: 7,
            new_lease_state: 1,
            break_reason: 0,
            access_mask_hint: 0,
            share_mask_hint: 0,
        };
        let mut buf = Vec::new();
        r.write_to(&mut buf).unwrap();
        assert_eq!(buf.len(), 44);
        assert_eq!(LeaseBreakNotification::parse(&buf).unwrap(), r);
    }

    #[test]
    fn lease_break_wire_fields_match_gosmb_offsets() {
        let key = *b"0123456789abcdef";
        let ack = LeaseBreakAck {
            structure_size: 36,
            reserved: 0,
            flags: 0,
            lease_key: key,
            lease_state: 0,
            lease_duration: 0,
        };
        let mut ack_buf = Vec::new();
        ack.write_to(&mut ack_buf).unwrap();
        assert_eq!(u16::from_le_bytes(ack_buf[0..2].try_into().unwrap()), 36);
        assert_eq!(&ack_buf[8..24], &key);
        assert_eq!(u32::from_le_bytes(ack_buf[24..28].try_into().unwrap()), 0);

        let notification = LeaseBreakNotification {
            structure_size: 44,
            new_epoch: 8,
            flags: 1,
            lease_key: key,
            current_lease_state: 1,
            new_lease_state: 0,
            break_reason: 0,
            access_mask_hint: 0,
            share_mask_hint: 0,
        };
        let mut notify_buf = Vec::new();
        notification.write_to(&mut notify_buf).unwrap();
        assert_eq!(u16::from_le_bytes(notify_buf[0..2].try_into().unwrap()), 44);
        assert_eq!(u16::from_le_bytes(notify_buf[2..4].try_into().unwrap()), 8);
        assert_eq!(u32::from_le_bytes(notify_buf[4..8].try_into().unwrap()), 1);
        assert_eq!(&notify_buf[8..24], &key);
        assert_eq!(
            u32::from_le_bytes(notify_buf[24..28].try_into().unwrap()),
            1
        );
        assert_eq!(
            u32::from_le_bytes(notify_buf[28..32].try_into().unwrap()),
            0
        );
    }

    #[test]
    fn oplock_break_wire_fields_match_gosmb_offsets() {
        let file_id = FileId::new(0x1122_3344_5566_7788, 0x99aa_bbcc_ddee_ff00);
        let message = OplockBreakNotification {
            structure_size: 24,
            oplock_level: 0x01,
            reserved: 0,
            reserved2: 0,
            file_id,
        };
        let mut buf = Vec::new();
        message.write_to(&mut buf).unwrap();

        assert_eq!(u16::from_le_bytes(buf[0..2].try_into().unwrap()), 24);
        assert_eq!(buf[2], 0x01);
        assert_eq!(
            u64::from_le_bytes(buf[8..16].try_into().unwrap()),
            file_id.persistent
        );
        assert_eq!(
            u64::from_le_bytes(buf[16..24].try_into().unwrap()),
            file_id.volatile
        );
    }

    #[test]
    fn lease_break_notification_rejects_wrong_structure_size() {
        let mut buf = vec![0; 44];
        buf[0..2].copy_from_slice(&36u16.to_le_bytes());

        assert!(matches!(
            LeaseBreakNotification::parse(&buf),
            Err(ProtoError::Malformed(_))
        ));
    }
}
