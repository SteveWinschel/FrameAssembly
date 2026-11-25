//! Distributed Computing Environment / Remote Procedure Call (`dcerpc`) Layer 7 PCAP-to-`.frasm` decompiler.
//!
//! This module implements the fuzz-safe reverse dissector for connection-oriented DCE/RPC v5
//! (`dcerpc`, MS-RPCE) frames carried over TCP or SCTP port `135` and dynamic RPC high ports. It
//! validates the 16-byte common header (`rpc_vers = 5.0`, little-endian `packed_drep`, `frag_length`),
//! decodes `bind`, `bindack`, `bindnak`, `altercontext`, `request`, `response`, and `fault` PDUs
//! along with mixed-endian UUIDs, interface versions, `opnum`, `callid`, `ctxid`, `flags`, and
//! `status`, and elides default fields while preserving stub bytes in `residual_payload`.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write as _;

use crate::ast::Protocol;
use crate::reverse::ProtocolDissection;

use super::quote_raw_str;

/// Endpoint Mapper (`epm`) canonical lowercase UUID string.
const EPM_UUID_STR: &str = "e1af8308-5d1f-11c9-91a4-08002b14a0fa";

/// NDR 2.0 transfer syntax UUID in Microsoft mixed-endian wire representation.
const NDR20_UUID_LE: [u8; 16] = [
    0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11, 0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60,
];

/// Reads a checked little-endian `u16` at `off` from `buf`.
fn le_u16(buf: &[u8], off: usize) -> Option<u16> {
    let b = buf.get(off..off.checked_add(2)?)?;
    Some(u16::from_le_bytes([b[0], b[1]]))
}

/// Reads a checked little-endian `u32` at `off` from `buf`.
fn le_u32(buf: &[u8], off: usize) -> Option<u32> {
    let b = buf.get(off..off.checked_add(4)?)?;
    Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

/// Formats a 16-byte Microsoft mixed-endian UUID slice into canonical dashed lowercase string form.
fn format_uuid_mixed_endian(b: &[u8]) -> Option<String> {
    let u = b.get(..16)?;
    Some(format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        u[3], u[2], u[1], u[0], u[5], u[4], u[7], u[6], u[8], u[9], u[10], u[11], u[12], u[13],
        u[14], u[15]
    ))
}

/// Dissects a connection-oriented DCE/RPC v5 (`dcerpc`) TCP/SCTP payload.
pub(crate) fn dissect_dcerpc(payload: &[u8]) -> Option<ProtocolDissection> {
    if payload.len() < 16
        || payload.first() != Some(&5)
        || payload.get(1) != Some(&0)
        || payload.get(4..8) != Some(&[0x10, 0x00, 0x00, 0x00][..])
    {
        return None;
    }
    let ptype = *payload.get(2)?;
    let pfc_flags = *payload.get(3)?;
    let frag_len = usize::from(le_u16(payload, 8)?);
    let auth_len = le_u16(payload, 10)?;
    let call_id = le_u32(payload, 12)?;
    if frag_len != payload.len() || auth_len != 0 {
        return None;
    }

    let body = payload.get(16..)?;
    let mut tokens = String::from("dcerpc");
    let mut ctx_id: Option<u16> = None;
    let mut opnum: Option<u16> = None;
    let mut uuid_str: Option<String> = None;
    let mut if_ver_str: Option<String> = None;
    let mut status_val: Option<(u32, u32)> = None; // (val, default)
    let mut eff_flags = pfc_flags;
    let residual: Vec<u8>;

    match ptype {
        11 | 14 => {
            if ptype == 14 {
                tokens.push_str(" altercontext");
            }
            if body.len() < 56 || body.get(8) != Some(&1) || body.get(14) != Some(&1) {
                return None;
            }
            ctx_id = Some(le_u16(body, 12)?);
            let u = format_uuid_mixed_endian(body.get(16..32)?)?;
            let maj = le_u16(body, 32)?;
            let min = le_u16(body, 34)?;
            let v = format!("{maj}.{min}");
            if body.get(36..52) != Some(&NDR20_UUID_LE[..]) {
                return None;
            }
            if u != EPM_UUID_STR {
                uuid_str = Some(u);
            }
            if v != "3.0" {
                if_ver_str = Some(v);
            }
            residual = body.get(56..)?.to_vec();
        }
        12 | 15 => {
            if ptype == 12 {
                tokens.push_str(" bindack");
            } else {
                tokens.push_str(" msgtype \"altercontextresp\"");
            }
            if body.len() < 44 {
                return None;
            }
            let sec_len = usize::from(le_u16(body, 8)?);
            let after_sec = 10usize.checked_add(sec_len)?;
            let pad = (4 - ((16 + after_sec) % 4)) % 4;
            let res_off = after_sec.checked_add(pad)?;
            if body.len() < res_off.checked_add(28)? || body.get(res_off) != Some(&1) {
                return None;
            }
            let result_code = le_u16(body, res_off + 4)?;
            status_val = Some((u32::from(result_code), 0));
            residual = body.get(res_off + 28..)?.to_vec();
        }
        13 => {
            if body.len() < 5 {
                return None;
            }
            tokens.push_str(" bindnak");
            let reason = le_u16(body, 0)?;
            status_val = Some((u32::from(reason), 1));
            let n_proto = usize::from(*body.get(2)?);
            let end_off = 3usize.checked_add(n_proto.checked_mul(2)?)?;
            residual = body.get(end_off..)?.to_vec();
        }
        0 => {
            if body.len() < 8 {
                return None;
            }
            tokens.push_str(" request");
            let alloc_hint = le_u32(body, 0)? as usize;
            ctx_id = Some(le_u16(body, 4)?);
            opnum = Some(le_u16(body, 6)?);
            let stub_off = if (pfc_flags & 0x80) != 0 {
                eff_flags &= !0x80;
                uuid_str = Some(format_uuid_mixed_endian(body.get(8..24)?)?);
                24usize
            } else {
                8usize
            };
            let stub = body.get(stub_off..)?;
            if alloc_hint != stub.len() && alloc_hint != 0 {
                return None;
            }
            residual = stub.to_vec();
        }
        2 => {
            if body.len() < 8 {
                return None;
            }
            tokens.push_str(" response");
            let alloc_hint = le_u32(body, 0)? as usize;
            ctx_id = Some(le_u16(body, 4)?);
            let stub = body.get(8..)?;
            if alloc_hint != stub.len() && alloc_hint != 0 {
                return None;
            }
            residual = stub.to_vec();
        }
        3 => {
            if body.len() < 16 {
                return None;
            }
            tokens.push_str(" fault");
            ctx_id = Some(le_u16(body, 4)?);
            let fault_code = le_u32(body, 8)?;
            status_val = Some((fault_code, 0x1c01_0002));
            residual = body.get(16..)?.to_vec();
        }
        other => {
            let _ = write!(tokens, " msgtype {other}");
            residual = body.to_vec();
        }
    }

    if let Some(u) = uuid_str {
        let _ = write!(tokens, " uuid \"{}\"", quote_raw_str(&u));
    }
    if let Some(v) = if_ver_str {
        let _ = write!(tokens, " vers \"{}\"", quote_raw_str(&v));
    }
    if let Some(op) = opnum
        && op != 0
    {
        let _ = write!(tokens, " opnum {op}");
    }
    if call_id != 1 {
        let _ = write!(tokens, " callid {call_id}");
    }
    if let Some(cid) = ctx_id
        && cid != 0
    {
        let _ = write!(tokens, " ctxid {cid}");
    }
    if eff_flags != 0x03 {
        let _ = write!(tokens, " flags 0x{eff_flags:02x}");
    }
    if let Some((st, def)) = status_val
        && st != def
    {
        let _ = write!(tokens, " status 0x{st:08x}");
    }

    Some(ProtocolDissection {
        protocol: Protocol::Dcerpc,
        tokens,
        residual_payload: residual,
        explicit_transport: None,
    })
}
