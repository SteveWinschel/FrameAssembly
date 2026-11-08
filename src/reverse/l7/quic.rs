//! QUIC Transport Protocol (`QUIC`, RFC 9000) Layer 7 PCAP-to-`.fasm` decompiler.
//!
//! This module implements the fuzz-safe reverse dissector for unencrypted outer RFC 9000 `QUIC`
//! Long Header (`initial`, `zero_rtt`, `handshake`, `retry`) and 1-RTT Short Header (`short`) UDP
//! datagrams on ports `443`, `8443`, `6443`, `4433`, `853`, `179`, and `5684`. It decodes
//! `version`, destination and source connection IDs (`dcid`, `scid`), retry/initial `token`
//! strings, RFC 9000 §16 2-byte variable-length integers, and packet numbers (`pkt_num`). It never
//! attempts header protection removal or payload decryption, preserving remaining encrypted frame
//! bytes via residual payload or returning `None` to step down cleanly to `udp`.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write as _;

use crate::ast::Protocol;
use crate::reverse::{ProtocolDissection, sd};

use super::{checked_be_u16, checked_be_u32, is_valid_raw_string_body, push_str_mod};

/// Dissects an RFC 9000 QUIC Long Header or 1-RTT Short Header UDP datagram.
pub(crate) fn dissect_quic(payload: &[u8]) -> Option<ProtocolDissection> {
    let b0 = *payload.first()?;
    if b0 == 0x40 {
        let dcid = checked_be_u32(payload, 1)? as u64;
        let pkt_num = *payload.get(5)? as u32;
        let mut tokens = String::from("quic short");
        if dcid != 0x01020304 {
            let _ = write!(tokens, " dcid 0x{dcid:08x}");
        }
        if pkt_num != 1 {
            let _ = write!(tokens, " pkt_num {pkt_num}");
        }
        return Some(sd(Protocol::Quic, tokens, payload.get(6..)?.to_vec()));
    }
    if (b0 & 0xCF) != 0xC0 {
        return None;
    }

    let hdr_type = (b0 >> 4) & 0x03;
    let type_kw = match hdr_type {
        0 => "initial",
        1 => "zero_rtt",
        2 => "handshake",
        _ => "retry",
    };
    let version = checked_be_u32(payload, 1)?;
    let dcid_len = *payload.get(5)? as usize;
    let mut pos = 6usize;
    let dcid = read_be_uint(payload.get(pos..pos.checked_add(dcid_len)?)?);
    pos += dcid_len;

    let scid_len = *payload.get(pos)? as usize;
    pos += 1;
    let scid = read_be_uint(payload.get(pos..pos.checked_add(scid_len)?)?);
    pos += scid_len;

    let mut tokens = format!("quic {type_kw}");
    if version != 1 {
        let _ = write!(tokens, " version 0x{version:08x}");
    }
    if dcid != 0x01020304 {
        let _ = write!(tokens, " dcid 0x{dcid:08x}");
    }
    if scid != 0x05060708 {
        let _ = write!(tokens, " scid 0x{scid:08x}");
    }

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
        let tok_len = *payload.get(pos)? as usize;
        pos += 1;
        let tok_bytes = payload.get(pos..pos.checked_add(tok_len)?)?;
        if tok_len > 0 {
            push_str_mod(&mut tokens, "token", core::str::from_utf8(tok_bytes).ok()?);
        }
        pos += tok_len;
    }

    let varint_len = checked_be_u16(payload, pos)?;
    if (varint_len & 0xC000) != 0x4000 {
        return None;
    }
    let inner_len = (varint_len & 0x3FFF) as usize;
    pos += 2;
    if inner_len < 1 || pos.checked_add(inner_len)? != payload.len() {
        return None;
    }
    let pkt_num = *payload.get(pos)? as u32;
    if pkt_num != 1 {
        let _ = write!(tokens, " pkt_num {pkt_num}");
    }
    Some(sd(Protocol::Quic, tokens, payload.get(pos + 1..)?.to_vec()))
}

/// Reads up to 8 big-endian bytes into a `u64`.
fn read_be_uint(bytes: &[u8]) -> u64 {
    bytes
        .iter()
        .take(8)
        .fold(0u64, |acc, &b| (acc << 8) | (b as u64))
}
