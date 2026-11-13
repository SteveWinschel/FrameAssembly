//! Lightweight Directory Access Protocol v3 (LDAPv3, RFC 4511) Layer 7 PCAP-to-`.frasm` decompiler.
//!
//! This module implements fuzz-safe ASN.1 BER wire-to-AST dissection for `ldap` v3 `LDAPMessage`
//! envelopes over TCP and UDP ports `389`, `636`, `3268`, and `1389`. It decodes outer ASN.1 BER
//! message identifiers (`msgid`) and protocol operations—`BindRequest` (`0x60`), `BindResponse`
//! (`0x61`), `SearchRequest` (`0x63`), `SearchResultEntry` (`0x64`), `SearchResultDone` (`0x65`),
//! and `UnbindRequest` (`0x42`)—along with `basedn`, `filter`, and `resultcode` fields while
//! preserving trailing bytes in `residual_payload`.

use alloc::format;
use alloc::string::String;

use crate::ast::{Protocol, TransportProto};
use crate::reverse::ProtocolDissection;

/// Checks whether `s` can be emitted inside `"..."` for a parser field that uses
/// `parse_raw_string_lit` (which strips outer quotes without unescaping).
fn is_valid_raw_str(s: &str) -> bool {
    !s.contains('"')
        && s.chars().all(|c| !c.is_control())
        && (s.bytes().rev().take_while(|&b| b == b'\\').count() % 2 == 0)
}

/// Parses a single ASN.1 BER/DER TLV header and returns `(tag, value_slice, rest_slice)`.
fn parse_ber_tlv(input: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    if input.len() < 2 {
        return None;
    }
    let tag = input[0];
    let b1 = input[1];
    let (len, hdr_len) = if (b1 & 0x80) == 0 {
        (b1 as usize, 2usize)
    } else {
        let num_octets = (b1 & 0x7F) as usize;
        if num_octets == 0 || num_octets > 4 || input.len() < 2 + num_octets {
            return None;
        }
        let mut l = 0usize;
        for &b in &input[2..2 + num_octets] {
            l = (l << 8) | (b as usize);
        }
        (l, 2 + num_octets)
    };
    if input.len() < hdr_len + len {
        return None;
    }
    Some((tag, &input[hdr_len..hdr_len + len], &input[hdr_len + len..]))
}

/// Parses a signed ASN.1 BER/DER INTEGER body into an `i64`.
fn parse_ber_int(bytes: &[u8]) -> Option<i64> {
    if bytes.is_empty() || bytes.len() > 8 {
        return None;
    }
    let mut val = if (bytes[0] & 0x80) != 0 { -1i64 } else { 0i64 };
    for &b in bytes {
        val = (val << 8) | (b as i64);
    }
    Some(val)
}

/// Dissects an `ldap` v3 BER `LDAPMessage` envelope over ports `389`, `636`, `3268`, or `1389`.
pub(crate) fn dissect_ldap(
    transport: TransportProto,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Option<ProtocolDissection> {
    if payload.is_empty()
        || !matches!(transport, TransportProto::Tcp | TransportProto::Udp)
        || !(matches!(dst_port, 389 | 636 | 3268 | 1389)
            || matches!(src_port, 389 | 636 | 3268 | 1389))
    {
        return None;
    }

    let (outer_tag, outer_body, residual) = parse_ber_tlv(payload)?;
    if outer_tag != 0x30 {
        return None;
    }
    let (id_tag, id_bytes, op_slice) = parse_ber_tlv(outer_body)?;
    if id_tag != 0x02 {
        return None;
    }
    let msgid = u32::try_from(parse_ber_int(id_bytes)?).ok()?;
    let (op_tag, op_body, op_rem) = parse_ber_tlv(op_slice)?;
    if !op_rem.is_empty() {
        return None;
    }

    let mut tokens = String::from("ldap");
    if msgid != 1 {
        tokens.push_str(&format!(" msgid {msgid}"));
    }

    match op_tag {
        0x60 => {
            let (v_tag, _, rest) = parse_ber_tlv(op_body)?;
            if v_tag != 0x02 {
                return None;
            }
            let (dn_tag, dn_bytes, _) = parse_ber_tlv(rest)?;
            if dn_tag != 0x04 {
                return None;
            }
            let dn = core::str::from_utf8(dn_bytes).ok()?;
            if !is_valid_raw_str(dn) {
                return None;
            }
            if dn != "dc=corp,dc=local" {
                tokens.push_str(&format!(" basedn \"{dn}\""));
            }
        }
        0x61 | 0x65 => {
            tokens.push_str(if op_tag == 0x61 {
                " bindres"
            } else {
                " searchdone"
            });
            let (rc_tag, rc_bytes, rest) = parse_ber_tlv(op_body)?;
            if rc_tag != 0x0A {
                return None;
            }
            let rc = u8::try_from(parse_ber_int(rc_bytes)?).ok()?;
            let (dn_tag, dn_bytes, _) = parse_ber_tlv(rest)?;
            if dn_tag != 0x04 {
                return None;
            }
            let dn = core::str::from_utf8(dn_bytes).ok()?;
            if !is_valid_raw_str(dn) {
                return None;
            }
            if rc != 0 {
                tokens.push_str(&format!(" resultcode {rc}"));
            }
            if !dn.is_empty() {
                tokens.push_str(&format!(" basedn \"{dn}\""));
            }
        }
        0x63 => {
            tokens.push_str(" searchreq");
            let (dn_tag, dn_bytes, mut rest) = parse_ber_tlv(op_body)?;
            if dn_tag != 0x04 {
                return None;
            }
            let dn = core::str::from_utf8(dn_bytes).ok()?;
            if !is_valid_raw_str(dn) {
                return None;
            }
            if dn != "dc=corp,dc=local" {
                tokens.push_str(&format!(" basedn \"{dn}\""));
            }
            for _ in 0..5 {
                let (_, _, next) = parse_ber_tlv(rest)?;
                rest = next;
            }
            if let Some((0x87, flt_bytes, _)) = parse_ber_tlv(rest) {
                let flt = core::str::from_utf8(flt_bytes).ok()?;
                if !is_valid_raw_str(flt) {
                    return None;
                }
                if flt != "objectClass" {
                    tokens.push_str(&format!(" filter \"{flt}\""));
                }
            }
        }
        0x64 => {
            tokens.push_str(" searchentry");
            let (dn_tag, dn_bytes, _) = parse_ber_tlv(op_body)?;
            if dn_tag != 0x04 {
                return None;
            }
            let dn = core::str::from_utf8(dn_bytes).ok()?;
            if !is_valid_raw_str(dn) {
                return None;
            }
            if dn != "dc=corp,dc=local" {
                tokens.push_str(&format!(" basedn \"{dn}\""));
            }
        }
        0x42 => {
            tokens.push_str(" unbindreq");
        }
        _ => return None,
    }

    Some(ProtocolDissection {
        protocol: Protocol::Ldap,
        tokens,
        residual_payload: residual.to_vec(),
        explicit_transport: None,
    })
}
