//! Omron Factory Interface Network Service (FINS) wire payload builder.
//!
//! This module implements [`build_fins_payload`], which serializes a [`FinsSpec`] AST node into
//! an Omron FINS PDU over UDP port 9600 (default) or FINS/TCP (`"FINS"` magic + 32-bit length +
//! `0x00000002` Frame Send command + 32-bit error code) when `transport tcp` is active. It
//! builds the 10-byte FINS header (`icf`, `rsv=0`, `gct=2`, `dna`/`da1`/`da2`, `sna`/`sa1`/`sa2`,
//! `sid`), 2-byte MRC/SRC command codes (`0x0101` Memory Area Read, `0x0102` Memory Area Write,
//! `0x0501` Controller Data Read, `0x0601` Controller Status Read), memory area addressing, and
//! `mres`/`sres` response bodies.

use alloc::vec::Vec;

use crate::ast::*;
use crate::builders::WireContext;

/// Parses a FINS MRC/SRC command name or numeric code into a 16-bit command identifier.
fn parse_fins_cmd(raw: &str) -> u16 {
    let norm = raw.trim().to_ascii_uppercase().replace(['_', '-'], "");
    match norm.as_str() {
        "READ" | "MEMORYAREAREAD" => 0x0101,
        "WRITE" | "MEMORYAREAWRITE" => 0x0102,
        "CONTROLLERDATAREAD" => 0x0501,
        "CONTROLLERSTATUSREAD" => 0x0601,
        "RUN" => 0x0401,
        "STOP" => 0x0402,
        _ => {
            if let Some(hex) = norm.strip_prefix("0X") {
                u16::from_str_radix(hex, 16).unwrap_or(0x0101)
            } else {
                norm.parse::<u16>().unwrap_or(0x0101)
            }
        }
    }
}

/// Appends `count` uniform FINS word (`area >= 0x80`) or byte (`area < 0x80`) items of `val`.
fn push_fins_items(out: &mut Vec<u8>, area: u8, count: u16, val: u16) {
    if area >= 0x80 {
        let word = val.to_be_bytes();
        for _ in 0..count {
            out.extend_from_slice(&word);
        }
    } else {
        out.resize(out.len() + usize::from(count), (val & 0xFF) as u8);
    }
}

/// Builds an Omron FINS UDP or FINS/TCP application-layer payload from [`FinsSpec`].
pub fn build_fins_payload(
    ctx: &WireContext,
    spec: &FinsSpec,
    payload_bytes: &[u8],
) -> Vec<u8> {
    let cmd_code = parse_fins_cmd(spec.cmd.unwrap_or("read"));
    let is_resp = spec.is_response
        || spec.errcode.is_some()
        || spec.icf.is_some_and(|v| (v & 0x40) != 0);
    let icf = spec.icf.unwrap_or(if is_resp { 0xC0 } else { 0x80 });
    let area = spec.area.unwrap_or(0x82);
    let addr = spec.addr.unwrap_or(0);
    let val = spec.value.unwrap_or(0);

    let mut fins = Vec::with_capacity(24 + payload_bytes.len());
    fins.push(icf);
    fins.push(0x00); // RSV
    fins.push(0x02); // GCT (Gateway Count)
    fins.push(spec.dna.unwrap_or(0));
    fins.push(spec.da1.unwrap_or(0));
    fins.push(spec.da2.unwrap_or(0));
    fins.push(spec.sna.unwrap_or(0));
    fins.push(spec.sa1.unwrap_or(0));
    fins.push(spec.sa2.unwrap_or(0));
    fins.push(spec.sid.unwrap_or(1));
    fins.extend_from_slice(&cmd_code.to_be_bytes());

    if is_resp {
        let errcode = spec.errcode.unwrap_or(0);
        fins.extend_from_slice(&errcode.to_be_bytes());
        if !payload_bytes.is_empty() {
            fins.extend_from_slice(payload_bytes);
        } else if cmd_code == 0x0101 && errcode == 0 {
            let count = spec.count.unwrap_or(1).clamp(1, 999);
            push_fins_items(&mut fins, area, count, val);
        }
    } else if cmd_code == 0x0101 {
        fins.push(area);
        fins.extend_from_slice(&addr.to_be_bytes());
        fins.push(0x00); // Bit offset
        let count = spec.count.unwrap_or(1).clamp(1, 999);
        fins.extend_from_slice(&count.to_be_bytes());
        if !payload_bytes.is_empty() {
            fins.extend_from_slice(payload_bytes);
        }
    } else if cmd_code == 0x0102 {
        fins.push(area);
        fins.extend_from_slice(&addr.to_be_bytes());
        fins.push(0x00); // Bit offset
        let item_width = if area >= 0x80 { 2usize } else { 1usize };
        if !payload_bytes.is_empty() {
            let default_cnt = payload_bytes.len().div_ceil(item_width).clamp(1, 999) as u16;
            let count = spec.count.unwrap_or(default_cnt);
            fins.extend_from_slice(&count.to_be_bytes());
            fins.extend_from_slice(payload_bytes);
        } else {
            let count = spec.count.unwrap_or(1).clamp(1, 999);
            fins.extend_from_slice(&count.to_be_bytes());
            push_fins_items(&mut fins, area, count, val);
        }
    } else if !payload_bytes.is_empty() {
        fins.extend_from_slice(payload_bytes);
    }

    if ctx.transport == Some(TransportProto::Tcp) {
        let tcp_len = u32::try_from(8usize.saturating_add(fins.len())).unwrap_or(u32::MAX);
        let mut framed = Vec::with_capacity(16 + fins.len());
        framed.extend_from_slice(b"FINS");
        framed.extend_from_slice(&tcp_len.to_be_bytes());
        framed.extend_from_slice(&2u32.to_be_bytes()); // FINS Frame Send
        framed.extend_from_slice(&0u32.to_be_bytes()); // Error Code 0
        framed.extend_from_slice(&fins);
        return framed;
    }

    fins
}
