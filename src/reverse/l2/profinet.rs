//! PROFINET IO Real-Time (`0x8892`) and UDP Context Manager (`34964`) PCAP-to-`.frasm` decompiler.
//!
//! This module implements the fuzz-safe dual-mode PCAP and PCAPNG decompiler for IEC 61158-6-10
//! PROFINET IO frames across both native Layer 2 Ethernet (`0x8892`) and UDP Context Manager
//! (`34964`). Layer 2 dissection distinguishes Acyclic DCP (`FrameID` `0xFEFC..=0xFEFF`,
//! decoding `service`, `request`/`response`, `xid`, and default `All` block elision) from Cyclic
//! RT (`frameid`, `cycle`, `datastatus`, `transferstatus`, and 40-byte default SDU elision). UDP
//! dissection decodes DCE/RPC v4 `PNIO-CM` Device Control PDUs (`Connect`, `Release`, `Read`,
//! `Write`, `Control`) and preserves `transport udp` via `explicit_transport`.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write as _;

use crate::ast::{Protocol, TransportProto};
use crate::reverse::{ProtocolDissection, push_hex, push_if, sd, sd_tp};

/// Reads a checked big-endian `u16` at `off`.
fn read_be_u16(b: &[u8], off: usize) -> Option<u16> {
    let s = b.get(off..off.checked_add(2)?)?;
    Some(u16::from_be_bytes([s[0], s[1]]))
}

/// Reads a checked big-endian `u32` at `off`.
fn read_be_u32(b: &[u8], off: usize) -> Option<u32> {
    let s = b.get(off..off.checked_add(4)?)?;
    Some(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
}

/// Reads a checked little-endian `u16` at `off`.
fn read_le_u16(b: &[u8], off: usize) -> Option<u16> {
    let s = b.get(off..off.checked_add(2)?)?;
    Some(u16::from_le_bytes([s[0], s[1]]))
}

/// Reads a checked little-endian `u32` at `off`.
fn read_le_u32(b: &[u8], off: usize) -> Option<u32> {
    let s = b.get(off..off.checked_add(4)?)?;
    Some(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

/// Decompiles a Layer 2 PROFINET Real-Time / DCP Ethernet payload (`0x8892`) or raw PN-RT bytes.
fn dissect_profinet_rt_or_dcp(
    b: &[u8],
    explicit_tp: Option<TransportProto>,
) -> Option<ProtocolDissection> {
    let frame_id = read_be_u16(b, 0)?;

    if (0xFEFC..=0xFEFF).contains(&frame_id) {
        if b.len() < 12 {
            return None;
        }
        let service_id = b[2];
        let service_type = b[3];
        let xid = read_be_u32(b, 4)?;
        let _resp_delay = read_be_u16(b, 8)?;
        let dcp_len = usize::from(read_be_u16(b, 10)?);
        let blk_end = 12usize.checked_add(dcp_len)?;
        if blk_end > b.len() {
            return None;
        }
        // Reject non-zero trailing bytes after the DCP data length + standard 46B min padding
        let tail = b.get(blk_end..)?;
        if tail.iter().any(|&x| x != 0) {
            return None;
        }

        let mut t = String::from("profinet");
        let svc_name = match service_id {
            3 => "get",
            4 => "set",
            5 => "identify",
            6 => "hello",
            _ => "dcp",
        };
        let is_resp = (service_type & 0x01) != 0;
        let def_fid: u16 = match (service_id, is_resp) {
            (6, _) => 0xFEFC,
            (5, false) => 0xFEFD,
            (5, true) => 0xFEFE,
            _ => 0xFEFF,
        };
        let _ = write!(t, " service \"{svc_name}\"");
        if frame_id != def_fid {
            push_hex(&mut t, "frameid", u64::from(frame_id), u64::from(def_fid), 4);
        }
        if is_resp {
            t.push_str(" response");
        }
        push_if(&mut t, "xid", xid, 1);

        let block_bytes = b.get(12..blk_end)?;
        let res = if block_bytes == [0xFF, 0xFF, 0x00, 0x00] {
            Vec::new()
        } else {
            block_bytes.to_vec()
        };
        return Some(match explicit_tp {
            Some(tp) => sd_tp(Protocol::Profinet, t, res, tp),
            None => sd(Protocol::Profinet, t, res),
        });
    }

    if b.len() < 6 {
        return None;
    }
    let sdu_end = b.len() - 4;
    let sdu = b.get(2..sdu_end)?;
    let cycle = read_be_u16(b, sdu_end)?;
    let data_status = *b.get(sdu_end + 2)?;
    let transfer_status = *b.get(sdu_end + 3)?;

    let mut t = String::from("profinet");
    push_hex(&mut t, "frameid", u64::from(frame_id), 0x8000, 4);
    push_if(&mut t, "cycle", cycle, 1);
    push_hex(&mut t, "datastatus", u64::from(data_status), 0x35, 2);
    push_hex(&mut t, "transferstatus", u64::from(transfer_status), 0x00, 2);

    let res = if sdu.len() == 40 && sdu.iter().all(|&x| x == 0) {
        Vec::new()
    } else {
        sdu.to_vec()
    };

    Some(match explicit_tp {
        Some(tp) => sd_tp(Protocol::Profinet, t, res, tp),
        None => sd(Protocol::Profinet, t, res),
    })
}

/// Decompiles a native Layer 2 PROFINET Ethernet payload (`EtherType = 0x8892`).
pub(crate) fn dissect_profinet_l2(b: &[u8]) -> Option<ProtocolDissection> {
    dissect_profinet_rt_or_dcp(b, None)
}

/// Decompiles a UDP `34964` PROFINET IO payload (DCE/RPC v4 `PNIO-CM` or PN-RT fallback),
/// preserving `transport udp`.
pub(crate) fn dissect_profinet_udp(b: &[u8]) -> Option<ProtocolDissection> {
    if b.len() >= 100
        && b[0] == 4
        && matches!(b[1], 0 | 2)
        && b.get(24..40) == Some(crate::builders::l2::profinet::PNIO_CM_IF_UUID.as_slice())
    {
        let is_resp = b[1] == 2;
        let xid = read_le_u32(b, 40)?;
        let frame_id = read_be_u16(b, 44)?;
        let data_status = *b.get(46)?;
        let transfer_status = *b.get(47)?;
        let cycle = read_le_u32(b, 64)?;
        let opnum = read_le_u16(b, 68)?;
        let frag_len = usize::from(read_le_u16(b, 74)?);
        let stub_end = 80usize.checked_add(frag_len)?;
        if stub_end != b.len() {
            return None;
        }
        let stub = b.get(80..stub_end)?;
        let ndr_hdr_len = 20usize;
        let actual_count = read_le_u32(stub, 16)? as usize;
        let blk_end = ndr_hdr_len.checked_add(actual_count)?;
        if blk_end > stub.len() {
            return None;
        }

        let mut t = String::from("profinet");
        let svc_name = match opnum {
            0 => Some("connect"),
            1 => None, // Release default
            2 => Some("read"),
            3 => Some("write"),
            4 => Some("control"),
            _ => return None,
        };
        if let Some(svc) = svc_name {
            let _ = write!(t, " service \"{svc}\"");
        }
        if is_resp {
            t.push_str(" response");
        }
        push_hex(&mut t, "frameid", u64::from(frame_id), 0x8000, 4);
        push_if(&mut t, "cycle", cycle, 1);
        push_hex(&mut t, "datastatus", u64::from(data_status), 0x35, 2);
        push_hex(&mut t, "transferstatus", u64::from(transfer_status), 0x00, 2);
        push_if(&mut t, "xid", xid, 1);

        let block = stub.get(ndr_hdr_len..blk_end)?;
        let fixed_blk_len = match (opnum, is_resp) {
            (0, false) => 58usize,
            (0, true) => 34usize,
            (1 | 4, _) => 32usize,
            (2 | 3, _) => 64usize,
            _ => return None,
        };
        if block.len() < fixed_blk_len {
            return None;
        }

        let res = if (opnum == 3 && !is_resp) || (opnum == 2 && is_resp) {
            if blk_end != stub.len() {
                return None;
            }
            block.get(fixed_blk_len..)?.to_vec()
        } else {
            if block.len() != fixed_blk_len {
                return None;
            }
            stub.get(blk_end..)?.to_vec()
        };

        return Some(sd_tp(Protocol::Profinet, t, res, TransportProto::Udp));
    }

    dissect_profinet_rt_or_dcp(b, Some(TransportProto::Udp))
}
