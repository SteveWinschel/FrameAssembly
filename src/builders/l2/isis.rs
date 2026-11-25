//! ISO/IEC 10589 IS-IS (Intermediate System to Intermediate System) wire frame builder.
//!
//! Synthesizes CLNS/ISO 10589 IS-IS PDUs (Level 1/Level 2 LAN IIH, Point-to-Point IIH, L1/L2 LSP,
//! L1/L2 CSNP, and L1/L2 PSNP) encapsulated in IEEE 802.3 Ethernet frames with an ISO CLNS LLC
//! header (`DSAP = 0xFE`, `SSAP = 0xFE`, `Control = 0x03`). Emits the Intradomain Routing Protocol
//! Discriminator (`0x83`), PDU-specific fixed header, Area Addresses TLV (`1`), Protocols
//! Supported TLV (`129`), optional Dynamic Hostname TLV (`137`), and RFC 905 Fletcher-16 LSP
//! checksum.
//!
//! Canonical `.frasm` syntax:
//! `a -> b isis [l1iih|l2iih|p2piih|l1lsp|l2lsp|l1csnp|l2csnp|l1psnp|l2psnp] [sysid "<str>"] [area "<hex>"] [holdtime <u16>] [priority <u8>] [lanid "<str>"] [circuittype <u8>] [lifetime <u16>] [seqnum <u32>] [hostname "<str>"]`

use crate::ast::*;
use crate::builders::WireContext;
use crate::error::CompilerError;
use crate::packet::build_ieee8023_llc_frame;
use alloc::format;
use alloc::vec::Vec;

/// Decodes hexadecimal bytes from an IS-IS identifier or area string, ignoring `.`, `:`, `-`, and spaces.
fn parse_isis_hex(input: &str, label: &str) -> Result<Vec<u8>, CompilerError> {
    let mut digits = Vec::with_capacity(input.len());
    for b in input.bytes() {
        if matches!(b, b'.' | b':' | b'-' | b'_' | b' ') {
            continue;
        }
        if !b.is_ascii_hexdigit() {
            return Err(CompilerError::BackendError(format!(
                "Invalid non-hex character in IS-IS {label}: '{input}'"
            )));
        }
        digits.push(b);
    }
    if digits.len() % 2 != 0 {
        return Err(CompilerError::BackendError(format!(
            "IS-IS {label} must contain an even number of hex digits: '{input}'"
        )));
    }
    let mut out = Vec::with_capacity(digits.len() / 2);
    for pair in digits.as_chunks::<2>().0 {
        let s = core::str::from_utf8(pair).unwrap_or("00");
        let val = u8::from_str_radix(s, 16).unwrap_or(0);
        out.push(val);
    }
    Ok(out)
}

/// Parses a fixed-width IS-IS identifier (`sysid` = 6B, `lanid` = 7B) with an explicit fallback.
fn parse_fixed_isis_id<const N: usize>(
    raw: Option<&str>,
    fallback: [u8; N],
    label: &str,
) -> Result<[u8; N], CompilerError> {
    let Some(s) = raw else {
        return Ok(fallback);
    };
    let bytes = parse_isis_hex(s, label)?;
    if bytes.len() != N {
        return Err(CompilerError::BackendError(format!(
            "IS-IS {label} must be exactly {N} bytes ({} hex chars), got {} bytes",
            N * 2,
            bytes.len()
        )));
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// Appends an 8-bit Length IS-IS TLV (`Type: u8`, `Length: u8`, `Value: [u8]`).
fn push_isis_tlv(out: &mut Vec<u8>, tlv_type: u8, value: &[u8]) -> Result<(), CompilerError> {
    let len_u8 = u8::try_from(value.len()).map_err(|_| {
        CompilerError::BackendError(format!(
            "IS-IS TLV {tlv_type} length ({} bytes) exceeds 255-byte maximum",
            value.len()
        ))
    })?;
    out.push(tlv_type);
    out.push(len_u8);
    out.extend_from_slice(value);
    Ok(())
}

/// Computes ISO/IEC 9577 / RFC 905 Fletcher-16 checksum over `buf` with checksum bytes at `csum_off`.
fn fletcher16_isis_checksum(buf: &[u8], csum_off: usize) -> [u8; 2] {
    let mut c0: i64 = 0;
    let mut c1: i64 = 0;
    for &b in buf {
        c0 = (c0 + i64::from(b)) % 255;
        c1 = (c1 + c0) % 255;
    }
    let dist = buf.len() as i64 - csum_off as i64 - 1;
    let mut x = (dist * c0 - c1).rem_euclid(255);
    let mut y = (-c0 - x).rem_euclid(255);
    if x == 0 {
        x = 255;
    }
    if y == 0 {
        y = 255;
    }
    [x as u8, y as u8]
}

/// Builds an ISO/IEC 10589 IS-IS frame encapsulated over IEEE 802.3 LLC (`FE:FE:03`).
///
/// # Errors
/// Returns `CompilerError::BackendError` if identifier/area lengths are invalid or 802.3 LLC exceeds 1500 bytes.
pub fn build_isis_frame(
    ctx: &WireContext,
    spec: &IsisSpec,
    payload: &[u8],
) -> Result<Vec<u8>, CompilerError> {
    let pdu_type = spec.pdu_type.unwrap_or(IsisPduType::L1Iih);
    let (pdu_code, hdr_len, is_l2): (u8, u8, bool) = match pdu_type {
        IsisPduType::L1Iih => (15, 27, false),
        IsisPduType::L2Iih => (16, 27, true),
        IsisPduType::P2pIih => (17, 20, false),
        IsisPduType::L1Lsp => (18, 27, false),
        IsisPduType::L2Lsp => (20, 27, true),
        IsisPduType::L1Csnp => (24, 33, false),
        IsisPduType::L2Csnp => (25, 33, true),
        IsisPduType::L1Psnp => (26, 17, false),
        IsisPduType::L2Psnp => (27, 17, true),
    };

    let sys_id = parse_fixed_isis_id(spec.sys_id, ctx.src_mac, "sysid")?;
    let mut default_lan = [0u8; 7];
    default_lan[..6].copy_from_slice(&sys_id);
    default_lan[6] = match pdu_type {
        IsisPduType::L1Lsp | IsisPduType::L2Lsp => 0x00,
        _ => 0x01,
    };
    let lan_id = parse_fixed_isis_id(spec.lan_id, default_lan, "lanid")?;

    let mut pdu = Vec::with_capacity(usize::from(hdr_len) + 32 + payload.len());
    // Common ISO 10589 8-byte header
    pdu.push(0x83);
    pdu.push(hdr_len);
    pdu.push(0x01);
    pdu.push(0x00); // System ID length = 6
    pdu.push(pdu_code);
    pdu.push(0x01); // Version
    pdu.push(0x00); // Reserved
    pdu.push(0x00); // Max Area Addresses = 3

    let pdu_len_off = match pdu_type {
        IsisPduType::L1Iih | IsisPduType::L2Iih => {
            let def_ckt = if is_l2 { 2 } else { 1 };
            pdu.push(spec.circuit_type.unwrap_or(def_ckt) & 0x03);
            pdu.extend_from_slice(&sys_id);
            pdu.extend_from_slice(&spec.hold_time.unwrap_or(30).to_be_bytes());
            pdu.extend_from_slice(&[0x00, 0x00]); // PDU Length placeholder
            pdu.push(spec.priority.unwrap_or(64) & 0x7F);
            pdu.extend_from_slice(&lan_id);
            17usize
        }
        IsisPduType::P2pIih => {
            pdu.push(spec.circuit_type.unwrap_or(3) & 0x03);
            pdu.extend_from_slice(&sys_id);
            pdu.extend_from_slice(&spec.hold_time.unwrap_or(30).to_be_bytes());
            pdu.extend_from_slice(&[0x00, 0x00]); // PDU Length placeholder
            pdu.push(0x01); // Local Circuit ID
            17usize
        }
        IsisPduType::L1Lsp | IsisPduType::L2Lsp => {
            pdu.extend_from_slice(&[0x00, 0x00]); // PDU Length placeholder
            pdu.extend_from_slice(&spec.lifetime.unwrap_or(1200).to_be_bytes());
            pdu.extend_from_slice(&lan_id); // 6B System ID + 1B Pseudonode ID
            pdu.push(0x00); // LSP Number
            pdu.extend_from_slice(&spec.seq_num.unwrap_or(1).to_be_bytes());
            pdu.extend_from_slice(&[0x00, 0x00]); // Fletcher-16 Checksum placeholder
            pdu.push(if is_l2 { 0x03 } else { 0x01 }); // Type Block (IS-Type)
            8usize
        }
        IsisPduType::L1Csnp | IsisPduType::L2Csnp => {
            pdu.extend_from_slice(&[0x00, 0x00]); // PDU Length placeholder
            pdu.extend_from_slice(&sys_id);
            pdu.push(0x00); // Source Circuit ID
            pdu.extend_from_slice(&[0x00; 8]); // Start LSP ID
            pdu.extend_from_slice(&[0xFF; 8]); // End LSP ID
            8usize
        }
        IsisPduType::L1Psnp | IsisPduType::L2Psnp => {
            pdu.extend_from_slice(&[0x00, 0x00]); // PDU Length placeholder
            pdu.extend_from_slice(&sys_id);
            pdu.push(0x00); // Source Circuit ID
            8usize
        }
    };

    let emit_hello_lsp_tlvs = matches!(
        pdu_type,
        IsisPduType::L1Iih
            | IsisPduType::L2Iih
            | IsisPduType::P2pIih
            | IsisPduType::L1Lsp
            | IsisPduType::L2Lsp
    );
    if emit_hello_lsp_tlvs || spec.area.is_some() {
        let area_bytes = match spec.area {
            Some(a) => parse_isis_hex(a, "area")?,
            None => alloc::vec![0x49, 0x00, 0x01],
        };
        if area_bytes.is_empty() || area_bytes.len() > 13 {
            return Err(CompilerError::BackendError(format!(
                "IS-IS area address length ({} bytes) must be 1..=13 bytes",
                area_bytes.len()
            )));
        }
        let mut tlv1 = Vec::with_capacity(1 + area_bytes.len());
        tlv1.push(area_bytes.len() as u8);
        tlv1.extend_from_slice(&area_bytes);
        push_isis_tlv(&mut pdu, 1, &tlv1)?;
        if emit_hello_lsp_tlvs {
            push_isis_tlv(&mut pdu, 129, &[0xCC])?; // IPv4 NLPID
        }
    }

    if let Some(hostname) = spec.hostname {
        push_isis_tlv(&mut pdu, 137, hostname.as_bytes())?;
    }

    pdu.extend_from_slice(payload);

    let llc_len = 3usize.saturating_add(pdu.len());
    if llc_len > 1500 {
        return Err(CompilerError::BackendError(format!(
            "IEEE 802.3 IS-IS LLC length ({llc_len} bytes) exceeds 1500-byte maximum"
        )));
    }

    let total_u16 = pdu.len() as u16;
    pdu[pdu_len_off..pdu_len_off + 2].copy_from_slice(&total_u16.to_be_bytes());

    if matches!(pdu_type, IsisPduType::L1Lsp | IsisPduType::L2Lsp) {
        let csum = fletcher16_isis_checksum(&pdu[12..], 12);
        pdu[24..26].copy_from_slice(&csum);
    }

    let default_dst = if is_l2 {
        [0x01, 0x80, 0xc2, 0x00, 0x00, 0x15]
    } else {
        [0x01, 0x80, 0xc2, 0x00, 0x00, 0x14]
    };
    let dst_mac = ctx.l2.dst_mac.unwrap_or(default_dst);
    Ok(build_ieee8023_llc_frame(
        ctx.src_mac,
        dst_mac,
        ctx.l2,
        0xFE,
        0xFE,
        0x03,
        &pdu,
    ))
}
