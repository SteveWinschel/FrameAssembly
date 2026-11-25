//! ANSI C12.22 / IEEE 1703 Smart Grid metering Layer 7 PCAP-to-`.frasm` decompiler.
//!
//! This module implements fuzz-safe ASN.1 BER wire-to-AST dissection for ANSI `c1222`
//! (`C1222-Message`, outer tag `0x60`) frames carried over UDP, TCP, and SCTP port `1153`.
//! It decodes ACSE `called-AP-title` (`[2]`), `called-AP-invocation-id` (`[4]`),
//! `calling-AP-title` (`[6]`), `calling-AP-invocation-id` (`[8]`), and `user-information`
//! (`[30]` `0xBE -> 0x28 -> 0x81`) EPSEM control flags, optional `edclass`, and C12.19 table
//! services (`read`, `write`, `identify`, `logon`, `logoff`, `terminate`, `response`,
//! `errcode`, `tableid`, `value`) while emitting `transport tcp` on TCP captures.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write as _;

use crate::ast::{Protocol, TransportProto};
use crate::reverse::ProtocolDissection;
use crate::reverse::l7::quote_raw_str;

/// Default Called Application Process Title OID (`2.16.840.1.114416.1`).
const DEFAULT_CALLED_AP: &str = "2.16.840.1.114416.1";

/// Default Calling Application Process Title OID (`2.16.840.1.114416.2`).
const DEFAULT_CALLING_AP: &str = "2.16.840.1.114416.2";

/// Parses one ASN.1 BER TLV (`tag`, `value`, `rest`) with definite-length overflow protection.
fn parse_ber_tlv(input: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    if input.len() < 2 {
        return None;
    }
    let tag = input[0];
    let b1 = input[1];
    let (len, hdr_len) = if (b1 & 0x80) == 0 {
        (usize::from(b1), 2usize)
    } else {
        let num_octets = usize::from(b1 & 0x7F);
        if num_octets == 0 || num_octets > 4 || input.len() < 2 + num_octets {
            return None;
        }
        let mut l = 0usize;
        for &b in &input[2..2 + num_octets] {
            l = (l << 8) | usize::from(b);
        }
        (l, 2 + num_octets)
    };
    let end = hdr_len.checked_add(len)?;
    if input.len() < end {
        return None;
    }
    Some((tag, &input[hdr_len..end], &input[end..]))
}

/// Parses a definite BER length prefix directly (used for EPSEM service lengths).
fn parse_ber_len_prefix(input: &[u8]) -> Option<(usize, &[u8])> {
    let b0 = *input.first()?;
    if (b0 & 0x80) == 0 {
        Some((usize::from(b0), &input[1..]))
    } else {
        let num = usize::from(b0 & 0x7F);
        if num == 0 || num > 4 || input.len() < 1 + num {
            return None;
        }
        let mut l = 0usize;
        for &b in &input[1..1 + num] {
            l = (l << 8) | usize::from(b);
        }
        Some((l, &input[1 + num..]))
    }
}

/// Decodes a BER `OBJECT IDENTIFIER` (`0x06`) body into a dotted numeric string.
fn decode_ber_oid(bytes: &[u8]) -> Option<String> {
    if bytes.is_empty() {
        return None;
    }
    let mut arcs = Vec::new();
    let mut idx = 0usize;
    let mut acc = 0u32;
    let mut steps = 0usize;
    while idx < bytes.len() {
        let b = bytes[idx];
        idx += 1;
        steps += 1;
        if steps > 5 {
            return None;
        }
        acc = acc.checked_shl(7)?.checked_add(u32::from(b & 0x7F))?;
        if (b & 0x80) == 0 {
            if arcs.is_empty() {
                if acc < 40 {
                    arcs.push(0);
                    arcs.push(acc);
                } else if acc < 80 {
                    arcs.push(1);
                    arcs.push(acc - 40);
                } else {
                    arcs.push(2);
                    arcs.push(acc - 80);
                }
            } else {
                arcs.push(acc);
            }
            acc = 0;
            steps = 0;
        } else if idx == bytes.len() {
            return None;
        }
    }
    if arcs.len() < 2 {
        return None;
    }
    let mut out = String::new();
    for (i, arc) in arcs.iter().enumerate() {
        if i > 0 {
            out.push('.');
        }
        let _ = write!(out, "{arc}");
    }
    Some(out)
}

/// Decodes an unsigned BER `INTEGER` (`0x02`) body into a `u32`.
fn decode_ber_u32(bytes: &[u8]) -> Option<u32> {
    if bytes.is_empty() || bytes.len() > 5 || (bytes[0] & 0x80) != 0 {
        return None;
    }
    let mut v = 0u64;
    for &b in bytes {
        v = (v << 8) | u64::from(b);
    }
    u32::try_from(v).ok()
}

/// Dissects an ANSI `c1222` (IEEE 1703) BER ACSE + EPSEM message over UDP, TCP, or SCTP.
pub(crate) fn dissect_c1222(
    transport: TransportProto,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Option<ProtocolDissection> {
    if payload.len() < 10
        || !matches!(
            transport,
            TransportProto::Udp | TransportProto::Tcp | TransportProto::Sctp
        )
        || (src_port != 1153 && dst_port != 1153 && payload[0] != 0x60)
    {
        return None;
    }

    let (outer_tag, mut seq_rem, outer_tail) = parse_ber_tlv(payload)?;
    if outer_tag != 0x60 || !outer_tail.is_empty() {
        return None;
    }

    let mut called_ap: Option<String> = None;
    let mut calling_ap: Option<String> = None;
    let mut called_id: Option<u32> = None;
    let mut calling_id: Option<u32> = None;
    let mut epsem: Option<&[u8]> = None;

    while !seq_rem.is_empty() {
        let (tag, body, next) = parse_ber_tlv(seq_rem)?;
        seq_rem = next;
        match tag {
            0xA2 => {
                let (itag, ibody, irem) = parse_ber_tlv(body)?;
                if itag != 0x06 || !irem.is_empty() {
                    return None;
                }
                called_ap = Some(decode_ber_oid(ibody)?);
            }
            0xA4 => {
                let (itag, ibody, irem) = parse_ber_tlv(body)?;
                if itag != 0x02 || !irem.is_empty() {
                    return None;
                }
                called_id = Some(decode_ber_u32(ibody)?);
            }
            0xA6 => {
                let (itag, ibody, irem) = parse_ber_tlv(body)?;
                if itag != 0x06 || !irem.is_empty() {
                    return None;
                }
                calling_ap = Some(decode_ber_oid(ibody)?);
            }
            0xA8 => {
                let (itag, ibody, irem) = parse_ber_tlv(body)?;
                if itag != 0x02 || !irem.is_empty() {
                    return None;
                }
                calling_id = Some(decode_ber_u32(ibody)?);
            }
            0xBE => {
                let (etag, ebody, erem) = parse_ber_tlv(body)?;
                if etag != 0x28 || !erem.is_empty() {
                    return None;
                }
                let (otag, obody, orem) = parse_ber_tlv(ebody)?;
                if otag != 0x81 || !orem.is_empty() {
                    return None;
                }
                epsem = Some(obody);
            }
            _ => return None,
        }
    }

    let epsem_bytes = epsem?;
    let epsem_ctrl = *epsem_bytes.first()?;
    let mut cursor = &epsem_bytes[1..];
    let mut ed_class: Option<u32> = None;
    if (epsem_ctrl & 0x10) != 0 {
        if cursor.len() < 4 {
            return None;
        }
        ed_class = Some(u32::from_be_bytes([
            cursor[0], cursor[1], cursor[2], cursor[3],
        ]));
        cursor = &cursor[4..];
    }

    let (svc_len, after_len) = parse_ber_len_prefix(cursor)?;
    if after_len.len() != svc_len || svc_len == 0 {
        return None;
    }
    let svc_code = after_len[0];
    let svc_body = &after_len[1..];

    let mut tokens = String::from("c1222");
    let explicit_transport = if matches!(transport, TransportProto::Tcp) {
        Some(TransportProto::Tcp)
    } else {
        None
    };

    let residual: Vec<u8>;
    match svc_code {
        0x30 => {
            if svc_body.len() < 2 {
                return None;
            }
            let table_id = u16::from_be_bytes([svc_body[0], svc_body[1]]);
            if table_id != 1 {
                let _ = write!(tokens, " tableid {table_id}");
            }
            residual = svc_body[2..].to_vec();
        }
        0x40 => {
            if svc_body.len() < 5 {
                return None;
            }
            tokens.push_str(" write");
            let table_id = u16::from_be_bytes([svc_body[0], svc_body[1]]);
            let data_len = u16::from_be_bytes([svc_body[2], svc_body[3]]) as usize;
            if 4usize.checked_add(data_len)?.checked_add(1) != Some(svc_body.len()) {
                return None;
            }
            let data = &svc_body[4..4 + data_len];
            let expected_sum = (!data.iter().fold(0u8, |a, &b| a.wrapping_add(b))).wrapping_add(1);
            if svc_body[4 + data_len] != expected_sum {
                return None;
            }
            if table_id != 1 {
                let _ = write!(tokens, " tableid {table_id}");
            }
            if data.len() == 2 {
                let val = u16::from_be_bytes([data[0], data[1]]);
                if val != 0 {
                    let _ = write!(tokens, " value {val}");
                }
                residual = Vec::new();
            } else {
                residual = data.to_vec();
            }
        }
        0x20 => {
            tokens.push_str(" identify");
            residual = svc_body.to_vec();
        }
        0x50 => {
            tokens.push_str(" logon");
            residual = if svc_body == b"\x00\x00FRAMEASM  \x00\x3c" {
                Vec::new()
            } else {
                svc_body.to_vec()
            };
        }
        0x52 => {
            tokens.push_str(" logoff");
            residual = svc_body.to_vec();
        }
        0x21 => {
            tokens.push_str(" terminate");
            residual = svc_body.to_vec();
        }
        0x00 => {
            tokens.push_str(" response");
            if svc_body.len() == 2 {
                let val = u16::from_be_bytes([svc_body[0], svc_body[1]]);
                let _ = write!(tokens, " value {val}");
                residual = Vec::new();
            } else {
                residual = svc_body.to_vec();
            }
        }
        0x01..=0x0A => {
            let _ = write!(tokens, " errcode {svc_code}");
            residual = svc_body.to_vec();
        }
        other => {
            let _ = write!(tokens, " service 0x{other:02x}");
            residual = svc_body.to_vec();
        }
    }

    if let Some(ref cap) = calling_ap
        && cap != DEFAULT_CALLING_AP
    {
        let _ = write!(tokens, " callingap \"{}\"", quote_raw_str(cap));
    }
    if let Some(ref cap) = called_ap
        && cap != DEFAULT_CALLED_AP
    {
        let _ = write!(tokens, " calledap \"{}\"", quote_raw_str(cap));
    }
    if let Some(cid) = calling_id {
        let _ = write!(tokens, " callingid {cid}");
    }
    if let Some(cid) = called_id {
        let _ = write!(tokens, " calledid {cid}");
    }
    let clean_ctrl = if ed_class.is_some() {
        epsem_ctrl & !0x10
    } else {
        epsem_ctrl
    };
    if clean_ctrl != 0x00 {
        let _ = write!(tokens, " epsemctrl 0x{clean_ctrl:02x}");
    }
    if let Some(ed) = ed_class {
        let _ = write!(tokens, " edclass 0x{ed:08x}");
    }

    Some(ProtocolDissection {
        protocol: Protocol::C1222,
        tokens,
        residual_payload: residual,
        explicit_transport,
    })
}
