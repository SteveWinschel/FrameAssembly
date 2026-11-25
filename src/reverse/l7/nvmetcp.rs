//! NVM Express over Fabrics TCP Transport (`nvmetcp`) Layer 7 PCAP-to-`.frasm` decompiler.
//!
//! This module implements fuzz-safe wire-to-AST dissection for `nvmetcp` PDUs over TCP and SCTP
//! ports `4420` and `8009` (plus custom-port `ICReq`/`ICResp` frames matching the 128-byte
//! handshake signature). It validates `HLEN`, `PDO`, `PLEN`, and optional Castagnoli CRC-32C
//! header (`HDGST`) and data (`DDGST`) digests across `ICReq`, `ICResp`, `H2CTermReq`,
//! `C2HTermReq`, `CapsuleCmd`, `CapsuleResp`, `H2CData`, `C2HData`, and `R2T`.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write as _;

use crate::ast::{Protocol, TransportProto};
use crate::reverse::{ProtocolDissection, le_u32};

/// Reflected Castagnoli CRC-32C polynomial used for NVMe/TCP digests.
const CRC32C_POLY: u32 = 0x82F6_3B78;

/// Computes the Castagnoli CRC-32C digest over `data`.
fn crc32c(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &b in data {
        crc ^= u32::from(b);
        for _ in 0..8 {
            crc = if (crc & 1) != 0 {
                (crc >> 1) ^ CRC32C_POLY
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

/// Reads a little-endian `u16` from `b[off..off + 2]` safely.
fn checked_le_u16(b: &[u8], off: usize) -> Option<u16> {
    let s = b.get(off..off.checked_add(2)?)?;
    Some(u16::from_le_bytes([s[0], s[1]]))
}

/// Reads a little-endian `u32` from `b[off..off + 4]` safely.
fn checked_le_u32(b: &[u8], off: usize) -> Option<u32> {
    let s = b.get(off..off.checked_add(4)?)?;
    Some(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

/// Reads a little-endian `u64` from `b[off..off + 8]` safely.
fn checked_le_u64(b: &[u8], off: usize) -> Option<u64> {
    let s = b.get(off..off.checked_add(8)?)?;
    let mut arr = [0u8; 8];
    arr.copy_from_slice(s);
    Some(u64::from_le_bytes(arr))
}

/// Dissects an NVMe/TCP Protocol Data Unit over TCP or SCTP.
pub(crate) fn dissect_nvmetcp(
    transport: TransportProto,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Option<ProtocolDissection> {
    if !matches!(transport, TransportProto::Tcp | TransportProto::Sctp) || payload.len() < 24 {
        return None;
    }
    let pdu_type = payload[0];
    let flags = payload[1];
    let hlen = payload[2] as usize;
    let pdo = payload[3] as usize;
    let plen = le_u32(payload, 4) as usize;
    if plen != payload.len() || hlen < 24 || hlen > plen {
        return None;
    }

    let on_nvme_port = matches!(src_port, 4420 | 8009) || matches!(dst_port, 4420 | 8009);
    if !on_nvme_port && !matches!(pdu_type, 0x00 | 0x01) {
        return None;
    }

    let has_hdgst = (flags & 0x01) != 0;
    let has_ddgst = (flags & 0x02) != 0;
    let hdgst_len = if has_hdgst { 4 } else { 0 };
    if has_hdgst {
        let hdgst_val = checked_le_u32(payload, hlen)?;
        if crc32c(payload.get(..hlen)?) != hdgst_val {
            return None;
        }
    }

    let data_start = if pdo == 0 { hlen + hdgst_len } else { pdo };
    if data_start < hlen + hdgst_len || data_start > plen {
        return None;
    }
    let data: &[u8] = if data_start == plen {
        &[]
    } else if has_ddgst {
        if plen < data_start + 4 {
            return None;
        }
        let d_end = plen - 4;
        let slice = payload.get(data_start..d_end)?;
        if crc32c(slice) != checked_le_u32(payload, d_end)? {
            return None;
        }
        slice
    } else {
        payload.get(data_start..plen)?
    };
    if data.is_empty() && pdo != 0 {
        return None;
    }
    if !data.is_empty() && pdo != hlen + hdgst_len {
        return None;
    }

    let mut tokens = String::from("nvmetcp");
    let mut default_flags = 0u8;

    match pdu_type {
        0x00 => {
            if hlen != 128
                || !data.is_empty()
                || checked_le_u16(payload, 8)? != 0
                || payload[10] != 0
                || payload[11] != 0
                || le_u32(payload, 12) != 16
                || payload.get(16..128)?.iter().any(|&b| b != 0)
            {
                return None;
            }
        }
        0x01 => {
            if hlen != 128
                || !data.is_empty()
                || checked_le_u16(payload, 8)? != 0
                || payload[10] != 0
                || payload[11] != 0
                || le_u32(payload, 12) != 131_072
                || payload.get(16..128)?.iter().any(|&b| b != 0)
            {
                return None;
            }
            tokens.push_str(" icresp");
        }
        0x02 | 0x03 => {
            if hlen != 24 || !data.is_empty() {
                return None;
            }
            let kw = if pdu_type == 0x02 { "h2cterm" } else { "c2hterm" };
            let fes = checked_le_u16(payload, 8)?;
            let _ = write!(tokens, " msgtype \"{kw}\"");
            if fes != 1 {
                let _ = write!(tokens, " status {fes}");
            }
        }
        0x04 => {
            if hlen != 72 || payload[9] != 0x40 {
                return None;
            }
            let sqe_opc = payload[8];
            let cid = checked_le_u16(payload, 10)?;
            let nsid = le_u32(payload, 12);
            let slba = checked_le_u64(payload, 48)?;
            let nlb = le_u32(payload, 56);
            let count = nlb.saturating_add(1);
            match sqe_opc {
                0x02 => tokens.push_str(" read"),
                0x01 => tokens.push_str(" write"),
                other => {
                    let _ = write!(tokens, " cmd \"capsulecmd\" opcode 0x{other:02x}");
                }
            }
            let default_nsid = if sqe_opc == 0x06 { 0 } else { 1 };
            if nsid != default_nsid {
                let _ = write!(tokens, " nsid {nsid}");
            }
            if cid != 1 {
                let _ = write!(tokens, " reqid {cid}");
            }
            if slba != 0 {
                let _ = write!(tokens, " offset {slba}");
            }
            if count != 8 {
                let _ = write!(tokens, " count {count}");
            }
        }
        0x05 => {
            if hlen != 24 || !data.is_empty() {
                return None;
            }
            let qid = checked_le_u16(payload, 18)?;
            let cid = checked_le_u16(payload, 20)?;
            let cqe_status = checked_le_u16(payload, 22)?;
            let status = cqe_status >> 1;
            tokens.push_str(" response");
            if qid != 1 {
                let _ = write!(tokens, " qid {qid}");
            }
            if cid != 1 {
                let _ = write!(tokens, " reqid {cid}");
            }
            if status != 0 {
                let _ = write!(tokens, " status {status}");
            }
        }
        0x06 | 0x07 => {
            if hlen != 24 {
                return None;
            }
            default_flags = if pdu_type == 0x06 { 0x04 } else { 0x0C };
            let kw = if pdu_type == 0x06 { "h2cdata" } else { "c2hdata" };
            let cid = checked_le_u16(payload, 8)?;
            let offset = le_u32(payload, 12);
            let datal = le_u32(payload, 16) as usize;
            if datal != data.len() {
                return None;
            }
            let _ = write!(tokens, " {kw}");
            if cid != 1 {
                let _ = write!(tokens, " reqid {cid}");
            }
            if offset != 0 {
                let _ = write!(tokens, " offset {offset}");
            }
        }
        0x09 => {
            if hlen != 24 || !data.is_empty() {
                return None;
            }
            let cid = checked_le_u16(payload, 8)?;
            let offset = le_u32(payload, 12);
            let r2tl = le_u32(payload, 16);
            tokens.push_str(" r2t");
            if cid != 1 {
                let _ = write!(tokens, " reqid {cid}");
            }
            if offset != 0 {
                let _ = write!(tokens, " offset {offset}");
            }
            if r2tl != 4096 {
                let _ = write!(tokens, " count {r2tl}");
            }
        }
        _ => return None,
    }

    if flags != default_flags {
        let _ = write!(tokens, " flags 0x{flags:02x}");
    }

    let residual: Vec<u8> = data.to_vec();
    Some(ProtocolDissection {
        protocol: Protocol::Nvmetcp,
        tokens,
        residual_payload: residual,
        explicit_transport: None,
    })
}
