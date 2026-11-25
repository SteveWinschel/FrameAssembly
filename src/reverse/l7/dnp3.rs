//! Distributed Network Protocol 3 (DNP3, IEEE 1815) Layer 7 PCAP-to-`.frasm` decompiler.
//!
//! This module implements fuzz-safe wire-to-AST dissection for `dnp3` IEEE 1815 frames (`0x05 0x64`
//! start bytes with `0xC4` master or `0x44` outstation control byte) over TCP, UDP, and SCTP
//! transports (port `20000` and custom serial terminal server ports). It reassembles multi-segment
//! transport streams (`FIR`/`FIN`/`SEQ`), strips per-16-byte block CRC-16 trailers safely for any
//! `link_len` up to `255`, checks the segment-0 link-header CRC-16, and decodes `confirm`, `read`,
//! `write`, `select`, `operate`, `directoperate`, `response`, `unsolicitedresponse`, numeric `func`,
//! `src`, `dst`, `group`, `variation`, and `crc`.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use crate::ast::{Protocol, TransportProto};
use crate::builders::l7::dnp3::calculate_dnp3_crc;
use crate::reverse::ProtocolDissection;

/// Parsed DNP3 Data Link frame fields `(ctrl, dst, src, hdr_crc, expected_crc, transport_bytes, rest)`.
type Dnp3LinkFrame<'a> = (u8, u16, u16, u16, u16, Vec<u8>, &'a [u8]);

/// Dissects a single `dnp3` Data Link frame header and extracts its de-chunked transport bytes.
fn parse_dnp3_link_frame(buf: &[u8]) -> Option<Dnp3LinkFrame<'_>> {
    if buf.len() < 10 || &buf[0..2] != b"\x05\x64" {
        return None;
    }
    let link_len = buf[2] as usize;
    let ctrl = buf[3];
    if link_len < 6 || !matches!(ctrl, 0x44 | 0xC4) {
        return None;
    }
    let dst = u16::from_le_bytes([buf[4], buf[5]]);
    let src = u16::from_le_bytes([buf[6], buf[7]]);
    let hdr_crc = u16::from_le_bytes([buf[8], buf[9]]);
    let expected_crc = calculate_dnp3_crc(&buf[0..8]);

    let user_len = link_len - 5;
    let full_blocks = user_len / 16;
    let last_data = user_len % 16;
    let wire_data_len = full_blocks
        .checked_mul(18)?
        .checked_add(if last_data > 0 { last_data + 2 } else { 0 })?;
    let frame_end = 10usize.checked_add(wire_data_len)?;
    if buf.len() < frame_end {
        return None;
    }

    let mut transport_bytes = Vec::with_capacity(user_len);
    let mut rem = &buf[10..frame_end];
    while !rem.is_empty() {
        if rem.len() < 3 {
            return None;
        }
        let block_len = rem.len().min(18);
        let data_len = block_len - 2;
        transport_bytes.extend_from_slice(&rem[..data_len]);
        rem = &rem[block_len..];
    }

    Some((
        ctrl,
        dst,
        src,
        hdr_crc,
        expected_crc,
        transport_bytes,
        &buf[frame_end..],
    ))
}

/// Dissects a single- or multi-segment `dnp3` IEEE 1815 frame (`0x05 0x64`), stripping block CRCs.
pub(crate) fn dissect_dnp3(
    transport: TransportProto,
    _src_port: u16,
    _dst_port: u16,
    payload: &[u8],
) -> Option<ProtocolDissection> {
    if !matches!(
        transport,
        TransportProto::Tcp | TransportProto::Udp | TransportProto::Sctp
    ) {
        return None;
    }

    let mut rest = payload;
    let mut app_bytes = Vec::new();
    let mut seg_idx = 0usize;
    let mut ctrl0 = 0u8;
    let mut dst0 = 0u16;
    let mut src0 = 0u16;
    let mut hdr_crc0 = 0u16;
    let mut expected_crc0 = 0u16;

    loop {
        let (ctrl, dst, src, hdr_crc, expected_crc, tbytes, next) = parse_dnp3_link_frame(rest)?;
        let th = *tbytes.first()?;
        let fir = (th & 0x40) != 0;
        let fin = (th & 0x80) != 0;
        let seq = th & 0x3F;
        if seg_idx == 0 {
            if !fir || seq != 0 {
                return None;
            }
            ctrl0 = ctrl;
            dst0 = dst;
            src0 = src;
            hdr_crc0 = hdr_crc;
            expected_crc0 = expected_crc;
        } else {
            if fir
                || seq != ((seg_idx & 0x3F) as u8)
                || ctrl != ctrl0
                || dst != dst0
                || src != src0
                || hdr_crc != expected_crc
            {
                return None;
            }
        }
        app_bytes.extend_from_slice(&tbytes[1..]);
        rest = next;
        seg_idx += 1;
        if fin {
            if !rest.is_empty() {
                return None;
            }
            break;
        }
        if rest.is_empty() {
            return None;
        }
    }

    if app_bytes.len() < 2 || app_bytes[0] != 0xC0 {
        return None;
    }

    let func = app_bytes[1];
    let expected_ctrl = if matches!(func, 129 | 130) { 0x44 } else { 0xC4 };
    if ctrl0 != expected_ctrl {
        return None;
    }

    let mut tokens = String::from("dnp3");
    match func {
        0 => tokens.push_str(" confirm"),
        1 => {}
        2 => tokens.push_str(" write"),
        3 => tokens.push_str(" select"),
        4 => tokens.push_str(" operate"),
        5 => tokens.push_str(" directoperate"),
        129 => tokens.push_str(" response"),
        130 => tokens.push_str(" unsolicitedresponse"),
        other => tokens.push_str(&format!(" func \"{other}\"")),
    }
    if src0 != 1 {
        tokens.push_str(&format!(" src {src0}"));
    }
    if dst0 != 10 {
        tokens.push_str(&format!(" dst {dst0}"));
    }

    let app_rem = if func == 129 || func == 130 {
        app_bytes[2..].strip_prefix(&[0x00, 0x00])?
    } else {
        &app_bytes[2..]
    };

    let residual = if app_rem.len() >= 3 && app_rem[2] == 0x06 {
        let g = app_rem[0];
        let v = app_rem[1];
        tokens.push_str(&format!(" group {g}"));
        if v != 1 {
            tokens.push_str(&format!(" variation {v}"));
        }
        app_rem[3..].to_vec()
    } else {
        app_rem.to_vec()
    };

    if hdr_crc0 != expected_crc0 {
        tokens.push_str(&format!(" crc 0x{hdr_crc0:04x}"));
    }

    Some(ProtocolDissection {
        protocol: Protocol::Dnp3,
        tokens,
        residual_payload: residual,
        explicit_transport: if matches!(transport, TransportProto::Udp) {
            Some(TransportProto::Udp)
        } else {
            None
        },
    })
}
