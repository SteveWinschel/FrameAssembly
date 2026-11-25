//! Internet Small Computer Systems Interface (iSCSI, RFC 7143) Layer 7 payload builder.
//!
//! This module implements [`build_iscsi_payload`], which serializes an [`IscsiSpec`] AST
//! specification into an RFC 7143 iSCSI storage Protocol Data Unit over TCP port 3260. It
//! constructs the 48-byte big-endian Basic Header Segment (BHS) covering `Login Request` (`0x43`),
//! `Login Response` (`0x23`), `Logout Request` (`0x46`), `Logout Response` (`0x26`), `SCSI
//! Command` (`0x01` with `INQUIRY`, `READ(10)`, or `WRITE(10)` CDBs), `SCSI Response` (`0x21`),
//! `SCSI Data-In`/`Data-Out` (`0x25`/`0x05`), `NOP-Out`/`NOP-In` (`0x00`/`0x20`), `Text`
//! (`0x04`/`0x24`), and `Reject` (`0x3F`), followed by 4-byte-padded DataSegments.

use crate::ast::*;
use crate::builders::WireContext;
use alloc::format;
use alloc::vec::Vec;

/// Maps a normalized iSCSI command name or raw opcode byte to a canonical command tag.
fn resolve_iscsi_cmd_norm(spec: &IscsiSpec) -> alloc::string::String {
    if let Some(cmd) = spec.cmd {
        return cmd.trim().to_ascii_uppercase().replace(['_', '-'], "");
    }
    if let Some(op) = spec.opcode {
        return alloc::string::String::from(match op & 0x3F {
            0x00 => "NOP",
            0x01 => "COMMAND",
            0x03 => "LOGIN",
            0x04 => "TEXT",
            0x05 => "DATAOUT",
            0x06 => "LOGOUT",
            0x20 => "NOPIN",
            0x21 => "RESPONSE",
            0x23 => "LOGINRESPONSE",
            0x24 => "TEXTRESPONSE",
            0x25 => "DATA",
            0x26 => "LOGOUTRESPONSE",
            0x3F => "REJECT",
            _ => "LOGIN",
        });
    }
    if spec.lun.is_some() || spec.offset.is_some() {
        alloc::string::String::from("READ")
    } else if spec.status.is_some() {
        alloc::string::String::from("RESPONSE")
    } else {
        alloc::string::String::from("LOGIN")
    }
}

/// Writes a 24-bit big-endian `DataSegmentLength` into `bhs[5..8]`.
fn set_data_seg_len(bhs: &mut [u8; 48], len: usize) {
    let clamped = u32::try_from(len).unwrap_or(0x00FF_FFFF).min(0x00FF_FFFF);
    bhs[5] = (clamped >> 16) as u8;
    bhs[6] = (clamped >> 8) as u8;
    bhs[7] = clamped as u8;
}

/// Writes an 8-byte SAM-2 / RFC 7143 Logical Unit Number into `bhs[8..16]`.
fn set_lun(bhs: &mut [u8; 48], lun: u16) {
    bhs[8] = (lun >> 8) as u8;
    bhs[9] = lun as u8;
}

/// Builds an RFC 7143 iSCSI Basic Header Segment (BHS) and padded DataSegment payload.
pub fn build_iscsi_payload(
    _ctx: &WireContext,
    spec: &IscsiSpec,
    payload_bytes: &[u8],
) -> Vec<u8> {
    let cmd_norm = resolve_iscsi_cmd_norm(spec);
    let mut bhs = [0u8; 48];
    let mut data = Vec::new();

    let itt = spec.itt.unwrap_or(1);
    let cmdsn = spec.cmdsn.unwrap_or(1);
    let statsn = spec.statsn.unwrap_or(0);
    let lun = spec.lun.unwrap_or(0);
    let status = spec.status.unwrap_or(0);
    let offset = spec.offset.unwrap_or(0);

    match cmd_norm.as_str() {
        "LOGIN" | "LOGINREQUEST" => {
            bhs[0] = 0x43; // I=1, Opcode=0x03 Login Request
            bhs[1] = 0x87; // T=1, CSG=1, NSG=3
            bhs[8..14].copy_from_slice(&[0x40, 0x00, 0x01, 0x37, 0x00, 0x00]); // ISID
            bhs[16..20].copy_from_slice(&itt.to_be_bytes());
            bhs[20..22].copy_from_slice(&1u16.to_be_bytes()); // CID = 1
            bhs[24..28].copy_from_slice(&cmdsn.to_be_bytes());
            bhs[28..32].copy_from_slice(&statsn.to_be_bytes()); // ExpStatSN
            let init = spec
                .initiator
                .unwrap_or("iqn.2026-01.dev.frameassembly:initiator");
            let tgt = spec
                .target
                .unwrap_or("iqn.2026-01.dev.frameassembly:target");
            let kv = format!(
                "InitiatorName={init}\0TargetName={tgt}\0SessionType=Normal\0AuthMethod=None\0"
            );
            data.extend_from_slice(kv.as_bytes());
            data.extend_from_slice(payload_bytes);
        }
        "LOGINRESPONSE" => {
            bhs[0] = 0x23;
            bhs[1] = 0x87;
            bhs[8..14].copy_from_slice(&[0x40, 0x00, 0x01, 0x37, 0x00, 0x00]);
            bhs[14..16].copy_from_slice(&1u16.to_be_bytes()); // TSIH = 1
            bhs[16..20].copy_from_slice(&itt.to_be_bytes());
            bhs[24..28].copy_from_slice(&statsn.to_be_bytes()); // StatSN
            bhs[28..32].copy_from_slice(&cmdsn.saturating_add(1).to_be_bytes()); // ExpCmdSN
            bhs[32..36].copy_from_slice(&32u32.to_be_bytes()); // MaxCmdSN
            bhs[36] = status; // Status-Class
            data.extend_from_slice(b"TargetPortalGroupTag=1\0AuthMethod=None\0");
            data.extend_from_slice(payload_bytes);
        }
        "LOGOUT" | "LOGOUTREQUEST" => {
            bhs[0] = 0x46; // I=1, Opcode=0x06
            bhs[1] = 0x80; // Close session
            bhs[16..20].copy_from_slice(&itt.to_be_bytes());
            bhs[20..22].copy_from_slice(&1u16.to_be_bytes());
            bhs[24..28].copy_from_slice(&cmdsn.to_be_bytes());
            bhs[28..32].copy_from_slice(&statsn.to_be_bytes());
            data.extend_from_slice(payload_bytes);
        }
        "LOGOUTRESPONSE" => {
            bhs[0] = 0x26;
            bhs[1] = 0x80;
            bhs[2] = status;
            bhs[16..20].copy_from_slice(&itt.to_be_bytes());
            bhs[24..28].copy_from_slice(&statsn.to_be_bytes());
            bhs[28..32].copy_from_slice(&cmdsn.saturating_add(1).to_be_bytes());
            bhs[32..36].copy_from_slice(&32u32.to_be_bytes());
            data.extend_from_slice(payload_bytes);
        }
        "READ" => {
            bhs[0] = 0x01; // SCSI Command
            bhs[1] = 0xC1; // F=1, R=1, Simple
            set_lun(&mut bhs, lun);
            bhs[16..20].copy_from_slice(&itt.to_be_bytes());
            bhs[20..24].copy_from_slice(&4096u32.to_be_bytes()); // ExpectedDataTransferLength
            bhs[24..28].copy_from_slice(&cmdsn.to_be_bytes());
            bhs[28..32].copy_from_slice(&statsn.to_be_bytes());
            // SCSI READ(10) CDB
            bhs[32] = 0x28;
            bhs[34..38].copy_from_slice(&offset.to_be_bytes());
            bhs[40] = 8; // Transfer length = 8 blocks
            data.extend_from_slice(payload_bytes);
        }
        "WRITE" => {
            bhs[0] = 0x01; // SCSI Command
            bhs[1] = 0xA1; // F=1, W=1, Simple
            set_lun(&mut bhs, lun);
            bhs[16..20].copy_from_slice(&itt.to_be_bytes());
            let xfer_len = if payload_bytes.is_empty() {
                4096u32
            } else {
                u32::try_from(payload_bytes.len()).unwrap_or(u32::MAX)
            };
            bhs[20..24].copy_from_slice(&xfer_len.to_be_bytes());
            bhs[24..28].copy_from_slice(&cmdsn.to_be_bytes());
            bhs[28..32].copy_from_slice(&statsn.to_be_bytes());
            // SCSI WRITE(10) CDB
            bhs[32] = 0x2A;
            bhs[34..38].copy_from_slice(&offset.to_be_bytes());
            bhs[40] = 8;
            data.extend_from_slice(payload_bytes);
        }
        "COMMAND" | "SCSICOMMAND" => {
            bhs[0] = 0x01;
            bhs[1] = 0xC1;
            set_lun(&mut bhs, lun);
            bhs[16..20].copy_from_slice(&itt.to_be_bytes());
            bhs[20..24].copy_from_slice(&36u32.to_be_bytes());
            bhs[24..28].copy_from_slice(&cmdsn.to_be_bytes());
            bhs[28..32].copy_from_slice(&statsn.to_be_bytes());
            // SCSI INQUIRY CDB
            bhs[32] = 0x12;
            bhs[36] = 36;
            data.extend_from_slice(payload_bytes);
        }
        "RESPONSE" | "SCSIRESPONSE" => {
            bhs[0] = 0x21;
            bhs[1] = 0x80;
            bhs[3] = status; // SCSI status (0x00 GOOD)
            bhs[16..20].copy_from_slice(&itt.to_be_bytes());
            bhs[24..28].copy_from_slice(&statsn.to_be_bytes());
            bhs[28..32].copy_from_slice(&cmdsn.saturating_add(1).to_be_bytes());
            bhs[32..36].copy_from_slice(&32u32.to_be_bytes());
            data.extend_from_slice(payload_bytes);
        }
        "DATA" | "DATAIN" | "SCSIDATAIN" => {
            bhs[0] = 0x25; // SCSI Data-In
            bhs[1] = 0x81; // F=1, S=1
            bhs[3] = status;
            set_lun(&mut bhs, lun);
            bhs[16..20].copy_from_slice(&itt.to_be_bytes());
            bhs[20..24].copy_from_slice(&0xFFFF_FFFFu32.to_be_bytes()); // TTT
            bhs[24..28].copy_from_slice(&statsn.to_be_bytes());
            bhs[28..32].copy_from_slice(&cmdsn.saturating_add(1).to_be_bytes());
            bhs[32..36].copy_from_slice(&32u32.to_be_bytes());
            bhs[40..44].copy_from_slice(&offset.to_be_bytes()); // BufferOffset
            data.extend_from_slice(payload_bytes);
        }
        "DATAOUT" | "SCSIDATAOUT" => {
            bhs[0] = 0x05;
            bhs[1] = 0x80;
            set_lun(&mut bhs, lun);
            bhs[16..20].copy_from_slice(&itt.to_be_bytes());
            bhs[20..24].copy_from_slice(&0xFFFF_FFFFu32.to_be_bytes());
            bhs[28..32].copy_from_slice(&statsn.to_be_bytes());
            bhs[40..44].copy_from_slice(&offset.to_be_bytes());
            data.extend_from_slice(payload_bytes);
        }
        "NOP" | "NOPOUT" => {
            bhs[0] = 0x00;
            bhs[1] = 0x80;
            set_lun(&mut bhs, lun);
            bhs[16..20].copy_from_slice(&itt.to_be_bytes());
            bhs[20..24].copy_from_slice(&0xFFFF_FFFFu32.to_be_bytes());
            bhs[24..28].copy_from_slice(&cmdsn.to_be_bytes());
            bhs[28..32].copy_from_slice(&statsn.to_be_bytes());
            data.extend_from_slice(payload_bytes);
        }
        "NOPIN" => {
            bhs[0] = 0x20;
            bhs[1] = 0x80;
            set_lun(&mut bhs, lun);
            bhs[16..20].copy_from_slice(&itt.to_be_bytes());
            bhs[20..24].copy_from_slice(&0xFFFF_FFFFu32.to_be_bytes());
            bhs[24..28].copy_from_slice(&statsn.to_be_bytes());
            bhs[28..32].copy_from_slice(&cmdsn.saturating_add(1).to_be_bytes());
            bhs[32..36].copy_from_slice(&32u32.to_be_bytes());
            data.extend_from_slice(payload_bytes);
        }
        "TEXT" => {
            bhs[0] = 0x04;
            bhs[1] = 0x80;
            bhs[16..20].copy_from_slice(&itt.to_be_bytes());
            bhs[20..24].copy_from_slice(&0xFFFF_FFFFu32.to_be_bytes());
            bhs[24..28].copy_from_slice(&cmdsn.to_be_bytes());
            bhs[28..32].copy_from_slice(&statsn.to_be_bytes());
            let st = spec.target.unwrap_or("All");
            let kv = format!("SendTargets={st}\0");
            data.extend_from_slice(kv.as_bytes());
            data.extend_from_slice(payload_bytes);
        }
        "TEXTRESPONSE" => {
            bhs[0] = 0x24;
            bhs[1] = 0x80;
            bhs[16..20].copy_from_slice(&itt.to_be_bytes());
            bhs[20..24].copy_from_slice(&0xFFFF_FFFFu32.to_be_bytes());
            bhs[24..28].copy_from_slice(&statsn.to_be_bytes());
            bhs[28..32].copy_from_slice(&cmdsn.saturating_add(1).to_be_bytes());
            bhs[32..36].copy_from_slice(&32u32.to_be_bytes());
            data.extend_from_slice(payload_bytes);
        }
        "REJECT" => {
            bhs[0] = 0x3F;
            bhs[1] = 0x80;
            bhs[2] = status;
            bhs[16..20].copy_from_slice(&0xFFFF_FFFFu32.to_be_bytes());
            bhs[24..28].copy_from_slice(&statsn.to_be_bytes());
            bhs[28..32].copy_from_slice(&cmdsn.saturating_add(1).to_be_bytes());
            bhs[32..36].copy_from_slice(&32u32.to_be_bytes());
            data.extend_from_slice(payload_bytes);
        }
        _ => {
            bhs[0] = 0x43;
            bhs[1] = 0x87;
            bhs[16..20].copy_from_slice(&itt.to_be_bytes());
            bhs[24..28].copy_from_slice(&cmdsn.to_be_bytes());
            bhs[28..32].copy_from_slice(&statsn.to_be_bytes());
            data.extend_from_slice(payload_bytes);
        }
    }

    if let Some(op) = spec.opcode {
        bhs[0] = op;
    }
    if let Some(fl) = spec.flags {
        bhs[1] = fl;
    }

    let data_len = data.len();
    set_data_seg_len(&mut bhs, data_len);
    let pad = (4 - (data_len % 4)) % 4;
    let mut pkt = Vec::with_capacity(48 + data_len + pad);
    pkt.extend_from_slice(&bhs);
    pkt.extend_from_slice(&data);
    pkt.resize(pkt.len() + pad, 0x00);
    pkt
}
