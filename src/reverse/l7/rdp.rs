//! Remote Desktop Protocol (`rdp`, MS-RDPBCGR over TPKT + X.224) Layer 7 PCAP-to-`.frasm` decompiler.
//!
//! This module implements the fuzz-safe reverse dissector for Microsoft Remote Desktop Protocol
//! (`rdp`) frames carried over TCP port `3389`. It validates RFC 1006 TPKT (`0x03 0x00`) headers
//! and ISO 8073 X.224 COTP frames, decoding `x224cr` (Connection Request with optional `Cookie:
//! mstshash=...` and `RDP_NEG_REQ`), `x224cc` (Connection Confirm with `RDP_NEG_RSP` /
//! `RDP_NEG_FAILURE`), and `mcs` (T.125 `Connect-Initial` + GCC + `CS_CORE` desktop geometry and
//! client name) while preserving residual bytes.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write as _;

use crate::ast::Protocol;
use crate::reverse::{ProtocolDissection, be_u16, sd};

use super::{find_subslice, push_str_mod};

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

/// Parses an ASN.1 BER definite length at offset `0` of `input`, returning `(len, hdr_bytes)`.
fn parse_ber_len(input: &[u8]) -> Option<(usize, usize)> {
    let b0 = *input.first()?;
    if (b0 & 0x80) == 0 {
        Some((usize::from(b0), 1))
    } else {
        let num = usize::from(b0 & 0x7F);
        if num == 0 || num > 4 || input.len() < 1 + num {
            return None;
        }
        let mut len = 0usize;
        for &b in input.get(1..1 + num)? {
            len = (len << 8) | usize::from(b);
        }
        Some((len, 1 + num))
    }
}

/// Parses a single-byte-tag ASN.1 BER TLV, returning `(tag, value_slice, rest_slice)`.
fn parse_ber_tlv1(input: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let tag = *input.first()?;
    let (len, lbytes) = parse_ber_len(input.get(1..)?)?;
    let start = 1usize.checked_add(lbytes)?;
    let end = start.checked_add(len)?;
    Some((tag, input.get(start..end)?, input.get(end..)?))
}

/// Extracts `width`, `height`, and `clientName` from a `CS_CORE` (`0xC001`) User Data block.
fn parse_cs_core(cs_core: &[u8]) -> Option<(u16, u16, String)> {
    if cs_core.len() < 132 || le_u16(cs_core, 0)? != 0xC001 {
        return None;
    }
    let block_len = usize::from(le_u16(cs_core, 2)?);
    if block_len < 132 || block_len > cs_core.len() {
        return None;
    }
    let width = le_u16(cs_core, 8)?;
    let height = le_u16(cs_core, 10)?;
    let name_raw = cs_core.get(24..56)?;
    let mut units = Vec::with_capacity(16);
    for &pair in name_raw.as_chunks::<2>().0 {
        let u = u16::from_le_bytes(pair);
        if u == 0 {
            break;
        }
        units.push(u);
    }
    let name = String::from_utf16(&units).ok()?;
    Some((width, height, name))
}

/// Dissects a Microsoft Remote Desktop Protocol (`rdp`) TPKT + X.224 + RDP handshake payload.
pub(crate) fn dissect_rdp(payload: &[u8]) -> Option<ProtocolDissection> {
    if payload.len() < 11
        || payload.get(0..2) != Some(&[0x03, 0x00][..])
        || usize::from(be_u16(payload, 2)) != payload.len()
    {
        return None;
    }
    let li = usize::from(*payload.get(4)?);
    let pdu_code = *payload.get(5)?;
    let mut tokens = String::from("rdp");
    let residual: Vec<u8>;

    match pdu_code {
        0xE0 => {
            // X.224 Connection Request
            if payload.len() != 5usize.checked_add(li)? || li < 6 {
                return None;
            }
            let src_ref = be_u16(payload, 8);
            let mut rest = payload.get(11..)?;
            if let Some(after_prefix) = rest.strip_prefix(b"Cookie: mstshash=")
                && let Some(crlf) = find_subslice(after_prefix, b"\r\n")
                && let Ok(cookie) = core::str::from_utf8(after_prefix.get(..crlf)?)
                && !cookie.chars().any(char::is_control)
            {
                push_str_mod(&mut tokens, "cookie", cookie);
                rest = after_prefix.get(crlf + 2..)?;
            }
            if rest.len() >= 8 && rest.first() == Some(&0x01) && le_u16(rest, 2) == Some(8) {
                let flags = *rest.get(1)?;
                let proto = le_u32(rest, 4)?;
                if proto != 3 {
                    let _ = write!(tokens, " proto {proto}");
                }
                if flags != 0 {
                    let _ = write!(tokens, " flags 0x{flags:02x}");
                }
                rest = rest.get(8..)?;
            }
            if src_ref != 0 {
                let _ = write!(tokens, " sessionid {src_ref}");
            }
            residual = rest.to_vec();
        }
        0xD0 => {
            // X.224 Connection Confirm
            if payload.len() != 5usize.checked_add(li)? || li < 6 {
                return None;
            }
            tokens.push_str(" x224cc");
            let src_ref = be_u16(payload, 8);
            let mut rest = payload.get(11..)?;
            if rest.len() >= 8
                && matches!(rest.first(), Some(0x02 | 0x03))
                && le_u16(rest, 2) == Some(8)
            {
                let flags = *rest.get(1)?;
                let proto = le_u32(rest, 4)?;
                if proto != 2 {
                    let _ = write!(tokens, " proto {proto}");
                }
                if flags != 0 {
                    let _ = write!(tokens, " flags 0x{flags:02x}");
                }
                rest = rest.get(8..)?;
            }
            if src_ref != 0x1234 {
                let _ = write!(tokens, " sessionid {src_ref}");
            }
            residual = rest.to_vec();
        }
        0xF0 if li == 2 && payload.get(6) == Some(&0x80) => {
            // X.224 DT Data + T.125 MCS Connect-Initial (0x7F 0x65)
            let dt_body = payload.get(7..)?;
            if dt_body.get(0..2) != Some(&[0x7f, 0x65][..]) {
                return None;
            }
            let (ci_len, lbytes) = parse_ber_len(dt_body.get(2..)?)?;
            let ci_start = 2usize.checked_add(lbytes)?;
            let ci_end = ci_start.checked_add(ci_len)?;
            let mut cur = dt_body.get(ci_start..ci_end)?;
            residual = dt_body.get(ci_end..)?.to_vec();

            // Walk 6 fields (callingSel, calledSel, upwardFlag, 3x DomainParameters) -> userData (7th)
            for _ in 0..6 {
                let (_, _, next) = parse_ber_tlv1(cur)?;
                cur = next;
            }
            let (ud_tag, gcc, rem) = parse_ber_tlv1(cur)?;
            if ud_tag != 0x04 || !rem.is_empty() {
                return None;
            }
            let duca_pos = find_subslice(gcc, b"Duca")?;
            let after_duca = gcc.get(duca_pos + 4..)?;
            let cs_rel = find_subslice(after_duca, &[0x01, 0xC0])?;
            let (width, height, client_name) = parse_cs_core(after_duca.get(cs_rel..)?)?;
            tokens.push_str(" mcs");
            if !client_name.is_empty()
                && client_name != "WORKSTATION"
                && !client_name.chars().any(char::is_control)
            {
                push_str_mod(&mut tokens, "cookie", &client_name);
            }
            if width != 1024 {
                let _ = write!(tokens, " width {width}");
            }
            if height != 768 {
                let _ = write!(tokens, " height {height}");
            }
        }
        _ => return None,
    }

    Some(sd(Protocol::Rdp, tokens, residual))
}
