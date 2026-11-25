//! GE Fanuc Service Request Transport Protocol (GE-SRTP) wire payload builder.
//!
//! This module implements [`build_gesrtp_payload`], which serializes a [`GesrtpSpec`] AST node
//! into a GE Fanuc Series 90 / PACSystems RX3i/RX7i Service Request Transport Protocol (`gesrtp`)
//! frame over TCP port 18245. It constructs the 56-byte little-endian SRTP header encoding packet
//! types (`0x00` Init, `0x01` InitAck, `0x02` Request with mailbox `0xC0`, `0x03` Response with
//! mailbox `0xD4`/`0x94`), sequence number, service function code (`0x04` Read System Memory,
//! `0x07` Write System Memory), memory segment selector (`%R`, `%AI`, `%AQ`, `%I`, `%Q`, `%M`,
//! `%T`, `%G`), offset, element count, inline value or status, and trailing `text_len` octets.

use crate::ast::*;
use crate::builders::WireContext;
use alloc::vec::Vec;

/// Parses a GE-SRTP packet type string or numeric byte (`0x00`..`0x03`).
fn parse_gesrtp_ptype(raw: &str) -> u8 {
    let trimmed = raw.trim();
    if let Some(hex) = trimmed.strip_prefix("0x").or_else(|| trimmed.strip_prefix("0X"))
        && let Ok(val) = u8::from_str_radix(hex, 16)
    {
        return val;
    }
    if let Ok(val) = trimmed.parse::<u8>() {
        return val;
    }
    match trimmed.to_ascii_uppercase().replace(['_', '-'], "").as_str() {
        "INIT" => 0x00,
        "INITACK" => 0x01,
        "REQUEST" | "REQ" => 0x02,
        "RESPONSE" | "RESP" => 0x03,
        _ => 0x02,
    }
}

/// Parses a GE-SRTP service request function name or numeric code into an 8-bit opcode.
fn parse_gesrtp_func(raw: &str) -> u8 {
    let trimmed = raw.trim();
    if let Some(hex) = trimmed.strip_prefix("0x").or_else(|| trimmed.strip_prefix("0X"))
        && let Ok(val) = u8::from_str_radix(hex, 16)
    {
        return val;
    }
    if let Ok(val) = trimmed.parse::<u8>() {
        return val;
    }
    match trimmed.to_ascii_uppercase().replace(['_', '-'], "").as_str() {
        "ID" | "PLCID" | "RETURNPLCID" => 0x00,
        "PROGRAMNAME" | "RETURNPROGRAMNAME" => 0x03,
        "READSYSMEM" | "READ" => 0x04,
        "READTASKMEM" => 0x05,
        "WRITESYSMEM" | "WRITE" => 0x07,
        "WRITETASKMEM" => 0x08,
        "GETPRIV" | "RETURNPRIV" => 0x20,
        "SETPRIV" | "CHANGEPRIV" => 0x21,
        "CPUCTRL" => 0x23,
        "SETTIME" => 0x4F,
        _ => 0x04,
    }
}

/// Builds a GE Fanuc Service Request Transport Protocol (GE-SRTP) TCP payload.
pub fn build_gesrtp_payload(
    _ctx: &WireContext,
    spec: &GesrtpSpec,
    payload_bytes: &[u8],
) -> Vec<u8> {
    let ptype = match spec.ptype {
        Some(p) => parse_gesrtp_ptype(p),
        None if spec.status.is_some() => 0x03,
        None => 0x02,
    };
    let seq = spec.seq_num.unwrap_or(if ptype <= 0x01 { 0 } else { 1 });
    let text_len = u16::try_from(payload_bytes.len()).unwrap_or(u16::MAX);
    let extra_len = usize::from(text_len);

    let mut pkt = alloc::vec![0u8; 56 + extra_len];
    pkt[0] = ptype;
    pkt[1] = 0x00;
    pkt[2..4].copy_from_slice(&seq.to_le_bytes());
    pkt[4..6].copy_from_slice(&text_len.to_le_bytes());

    if ptype == 0x02 {
        pkt[9] = 0x01;
        pkt[17] = 0x01;
        pkt[30] = 0xC0;
        pkt[31] = (seq & 0xFF) as u8;
        pkt[42] = parse_gesrtp_func(spec.func.unwrap_or("readsysmem"));
        pkt[43] = spec.area.unwrap_or(0x08); // Default %R registers
        pkt[44..46].copy_from_slice(&spec.addr.unwrap_or(0).to_le_bytes());
        pkt[46..48].copy_from_slice(&spec.count.unwrap_or(1).to_le_bytes());
        if let Some(val) = spec.value {
            pkt[48..52].copy_from_slice(&val.to_le_bytes());
        }
    } else if ptype == 0x03 {
        pkt[9] = 0x01;
        pkt[17] = 0x01;
        pkt[30] = if text_len > 0 { 0x94 } else { 0xD4 };
        pkt[31] = (seq & 0xFF) as u8;
        pkt[42..44].copy_from_slice(&spec.status.unwrap_or(0).to_le_bytes());
        if let Some(val) = spec.value {
            pkt[44..48].copy_from_slice(&val.to_le_bytes());
        }
    }

    if extra_len > 0 {
        pkt[56..].copy_from_slice(&payload_bytes[..extra_len]);
    }
    pkt
}
