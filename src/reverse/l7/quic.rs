//! QUIC Transport Protocol (`quic`, RFC 9000 / RFC 9001) Layer 7 PCAP-to-`.frasm` decompiler.
//!
//! This module implements the fuzz-safe reverse dissector for unencrypted outer RFC 9000 `quic`
//! Long Header (`initial`, `zerortt`, `handshake`, `retry`) and 1-RTT Short Header (`short`) UDP
//! datagrams on ports `443`, `8443`, `6443`, `4433`, `853`, `179`, and `5684`. It decodes
//! `version`, variable `0..=20`-byte destination and source connection IDs (`dcid`, `scid`),
//! retry/initial `token` strings, RFC 9000 §16 variable-length integers, 1..=4-byte packet numbers
//! (`pktnum`), and default `Initial` `CRYPTO` TLS 1.3 `ClientHello` frames with `PADDING`.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write as _;

use crate::ast::Protocol;
use crate::reverse::{ProtocolDissection, bytes_to_hex_lower, sd};

use super::{checked_be_u16, checked_be_u32, is_valid_raw_string_body, push_str_mod};

/// Encodes minimal big-endian byte width (`1..=4`) of an unprotected QUIC Packet Number.
const fn minimal_pn_len(pn: u32) -> usize {
    if pn <= 0xFF {
        1
    } else if pn <= 0xFFFF {
        2
    } else if pn <= 0x00FF_FFFF {
        3
    } else {
        4
    }
}

/// Formats a `0..=20`-byte Connection ID modifier when it differs from `default_4b`.
fn append_cid_mod(tokens: &mut String, key: &str, cid: &[u8], default_4b: [u8; 4]) {
    if cid == default_4b {
        return;
    }
    if cid.len() == 4 {
        let val = u32::from_be_bytes([cid[0], cid[1], cid[2], cid[3]]);
        let _ = write!(tokens, " {key} 0x{val:08x}");
    } else if cid.len() == 8 && cid[..4] != [0, 0, 0, 0] {
        let val = read_be_uint(cid);
        let _ = write!(tokens, " {key} 0x{val:016x}");
    } else {
        let _ = write!(tokens, " {key} \"{}\"", bytes_to_hex_lower(cid));
    }
}

/// Appends an RFC 9000 §16 variable-length integer (`1`, `2`, or `4` bytes) to `buf`.
fn push_quic_varint_min(buf: &mut Vec<u8>, val: usize) {
    if val < 64 {
        buf.push(val as u8);
    } else if val < 16384 {
        buf.extend_from_slice(&(0x4000u16 | (val as u16)).to_be_bytes());
    } else {
        let clamped = (val as u32) & 0x3FFF_FFFF;
        buf.extend_from_slice(&(0x8000_0000u32 | clamped).to_be_bytes());
    }
}

/// Builds the deterministic RFC 9000 `Initial` `CRYPTO` + `PADDING` body for comparison against `body`.
fn build_expected_initial_body(scid: &[u8], hdr_before_len_varint: usize, pn_len: usize) -> Vec<u8> {
    let mut tp = Vec::with_capacity(8 + scid.len());
    tp.extend_from_slice(&[0x01, 0x02, 0x67, 0x10]);
    tp.push(0x0f);
    tp.push(scid.len() as u8);
    tp.extend_from_slice(scid);

    let mut tp_ext = Vec::with_capacity(4 + tp.len());
    tp_ext.extend_from_slice(&0x0039u16.to_be_bytes());
    tp_ext.extend_from_slice(&(tp.len() as u16).to_be_bytes());
    tp_ext.extend_from_slice(&tp);

    let tls_ch =
        crate::builders::l7::tls::build_tls_client_hello_handshake(None, Some("h3"), 0x1301, &tp_ext);
    let mut crypto = Vec::with_capacity(6 + tls_ch.len());
    crypto.push(0x06);
    crypto.push(0x00);
    push_quic_varint_min(&mut crypto, tls_ch.len());
    crypto.extend_from_slice(&tls_ch);

    let min_body_len = 1200usize.saturating_sub(hdr_before_len_varint + 2 + pn_len);
    if crypto.len() < min_body_len && pn_len + min_body_len <= 0x3FFF {
        crypto.resize(min_body_len, 0x00);
    }
    crypto
}

/// Resolves Short Header DCID slice length (`0..=20`) so packet number and payload round-trip cleanly.
fn choose_short_cid_len(tail: &[u8], pn_len: usize) -> Option<usize> {
    if tail.len() < pn_len {
        return None;
    }
    let matches_pn = |offset: usize| {
        let pn = read_be_uint(&tail[offset..offset + pn_len]) as u32;
        minimal_pn_len(pn) == pn_len
    };
    if tail.starts_with(&[0x01, 0x02, 0x03, 0x04]) && tail.len() >= 4 + pn_len && matches_pn(4) {
        return Some(4);
    }
    let exact_cid_len = tail.len() - pn_len;
    if exact_cid_len <= 20 && exact_cid_len != 4 && matches_pn(exact_cid_len) {
        return Some(exact_cid_len);
    }
    for cand in [4usize, 8, 16, 20, 0, 1, 2, 3, 5, 6, 7, 9, 10, 12] {
        if cand + pn_len <= tail.len() && matches_pn(cand) {
            return Some(cand);
        }
    }
    (0..=20usize.min(tail.len() - pn_len)).find(|&cand| matches_pn(cand))
}

/// Dissects an RFC 9000 QUIC Long Header or 1-RTT Short Header UDP datagram.
pub(crate) fn dissect_quic(payload: &[u8]) -> Option<ProtocolDissection> {
    let b0 = *payload.first()?;
    if (b0 & 0xFC) == 0x40 {
        let pn_len = ((b0 & 0x03) as usize) + 1;
        let tail = payload.get(1..)?;
        let dcid_len = choose_short_cid_len(tail, pn_len)?;
        let dcid = &tail[..dcid_len];
        let pkt_num = read_be_uint(&tail[dcid_len..dcid_len + pn_len]) as u32;
        let mut tokens = String::from("quic short");
        append_cid_mod(&mut tokens, "dcid", dcid, [0x01, 0x02, 0x03, 0x04]);
        if pkt_num != 1 {
            let _ = write!(tokens, " pktnum {pkt_num}");
        }
        return Some(sd(
            Protocol::Quic,
            tokens,
            tail[dcid_len + pn_len..].to_vec(),
        ));
    }

    let hdr_type = (b0 >> 4) & 0x03;
    if hdr_type == 3 {
        if b0 != 0xF0 {
            return None;
        }
    } else if (b0 & 0xCC) != 0xC0 {
        return None;
    }

    let type_kw = match hdr_type {
        0 => "initial",
        1 => "zerortt",
        2 => "handshake",
        _ => "retry",
    };
    let version = checked_be_u32(payload, 1)?;
    let dcid_len = *payload.get(5)? as usize;
    if dcid_len > 20 {
        return None;
    }
    let mut pos = 6usize;
    let dcid = payload.get(pos..pos.checked_add(dcid_len)?)?;
    pos += dcid_len;

    let scid_len = *payload.get(pos)? as usize;
    if scid_len > 20 {
        return None;
    }
    pos += 1;
    let scid = payload.get(pos..pos.checked_add(scid_len)?)?;
    pos += scid_len;

    let mut tokens = format!("quic {type_kw}");
    if version != 1 {
        let _ = write!(tokens, " version 0x{version:08x}");
    }
    append_cid_mod(&mut tokens, "dcid", dcid, [0x01, 0x02, 0x03, 0x04]);
    append_cid_mod(&mut tokens, "scid", scid, [0x05, 0x06, 0x07, 0x08]);

    if hdr_type == 3 {
        let rest = payload.get(pos..)?;
        let residual = if let Some(tok_bytes) = rest.strip_suffix(&[0u8; 16]) {
            if tok_bytes.is_empty() {
                Vec::new()
            } else if let Ok(tok_str) = core::str::from_utf8(tok_bytes)
                && is_valid_raw_string_body(tok_str)
            {
                push_str_mod(&mut tokens, "token", tok_str);
                Vec::new()
            } else {
                rest.to_vec()
            }
        } else {
            rest.to_vec()
        };
        return Some(sd(Protocol::Quic, tokens, residual));
    }

    if hdr_type == 0 {
        let (tok_len, consumed) = read_quic_varint(payload, pos)?;
        pos += consumed;
        let tok_bytes = payload.get(pos..pos.checked_add(tok_len)?)?;
        if tok_len > 0 {
            let tok_str = core::str::from_utf8(tok_bytes).ok()?;
            if !is_valid_raw_string_body(tok_str) {
                return None;
            }
            push_str_mod(&mut tokens, "token", tok_str);
        }
        pos += tok_len;
    }

    let hdr_before_len_varint = pos;
    let first_len_b = *payload.get(pos)?;
    let (inner_len, len_bytes) = match first_len_b >> 6 {
        1 => ((checked_be_u16(payload, pos)? & 0x3FFF) as usize, 2usize),
        2 => (
            (checked_be_u32(payload, pos)? & 0x3FFF_FFFF) as usize,
            4usize,
        ),
        _ => return None,
    };
    pos += len_bytes;

    let pn_len = ((b0 & 0x03) as usize) + 1;
    if inner_len < pn_len || pos.checked_add(inner_len)? != payload.len() {
        return None;
    }
    let pn_bytes = payload.get(pos..pos + pn_len)?;
    let pkt_num = read_be_uint(pn_bytes) as u32;
    if minimal_pn_len(pkt_num) != pn_len {
        return None;
    }
    if pkt_num != 1 {
        let _ = write!(tokens, " pktnum {pkt_num}");
    }

    let body = payload.get(pos + pn_len..)?;
    let residual = if hdr_type == 0
        && body == build_expected_initial_body(scid, hdr_before_len_varint, pn_len).as_slice()
    {
        Vec::new()
    } else {
        body.to_vec()
    };

    Some(sd(Protocol::Quic, tokens, residual))
}

/// Decodes an RFC 9000 §16 variable-length integer (`1`, `2`, or `4` bytes) at `pos`.
fn read_quic_varint(payload: &[u8], pos: usize) -> Option<(usize, usize)> {
    let b0 = *payload.get(pos)?;
    match b0 >> 6 {
        0 => Some((b0 as usize, 1)),
        1 => Some(((checked_be_u16(payload, pos)? & 0x3FFF) as usize, 2)),
        2 => Some(((checked_be_u32(payload, pos)? & 0x3FFF_FFFF) as usize, 4)),
        _ => None,
    }
}

/// Reads up to 8 big-endian bytes into a `u64`.
fn read_be_uint(bytes: &[u8]) -> u64 {
    bytes
        .iter()
        .take(8)
        .fold(0u64, |acc, &b| (acc << 8) | (b as u64))
}
