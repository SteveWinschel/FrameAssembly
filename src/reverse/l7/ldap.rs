//! Lightweight Directory Access Protocol v3 (LDAPv3, RFC 4511) Layer 7 PCAP-to-`.frasm` decompiler.
//!
//! This module implements fuzz-safe ASN.1 BER wire-to-AST dissection for `ldap` v3 `LDAPMessage`
//! envelopes over TCP, UDP, and SCTP ports `389`, `636`, `3268`, and `1389`. It decodes multi-
//! byte BER lengths above `127`, signed 32-bit BER `msgid` integers, protocol operations (`BindRequest`,
//! `BindResponse`, `SearchRequest`, `SearchResultEntry`, `SearchResultDone`, and `UnbindRequest`),
//! nested RFC 4515 filter trees (`and`, `or`, `not`, `equalityMatch`, `substrings`, `>=`, `<=`, `~=`,
//! and `present`), `basedn`, and `resultcode` fields while preserving trailing bytes in
//! `residual_payload`.

use alloc::format;
use alloc::string::String;

use crate::ast::{Protocol, TransportProto};
use crate::reverse::ProtocolDissection;

use super::quote_raw_str;

/// Maximum recursive nesting depth permitted while decoding an ASN.1 BER search filter tree.
const MAX_LDAP_FILTER_DEPTH: usize = 32;

/// Checks whether `s` contains no control characters so it can safely be formatted into a quoted modifier.
fn is_printable_ldap_str(s: &str) -> bool {
    s.chars().all(|c| !c.is_control())
}

/// Parses a single ASN.1 BER/DER TLV header (short or multi-byte definite length) and returns
/// `(tag, value_slice, rest_slice)`.
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
    let end = hdr_len.checked_add(len)?;
    if input.len() < end {
        return None;
    }
    Some((tag, &input[hdr_len..end], &input[end..]))
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

/// Decodes a BER `AttributeValueAssertion` (`OCTET STRING`, `OCTET STRING`) pair.
fn decode_ldap_ava(body: &[u8]) -> Option<(&str, &str)> {
    let (atag, abytes, rem) = parse_ber_tlv(body)?;
    if atag != 0x04 {
        return None;
    }
    let (vtag, vbytes, rem2) = parse_ber_tlv(rem)?;
    if vtag != 0x04 || !rem2.is_empty() {
        return None;
    }
    let attr = core::str::from_utf8(abytes).ok()?;
    let val = core::str::from_utf8(vbytes).ok()?;
    if attr.is_empty()
        || !is_printable_ldap_str(attr)
        || !is_printable_ldap_str(val)
        || attr.contains(['(', ')', '=', '<', '>', '~', '*'])
        || val.contains(['(', ')'])
    {
        return None;
    }
    Some((attr, val))
}

/// Recursively decodes an ASN.1 BER RFC 4511 `Filter` tree into its RFC 4515 string form.
fn decode_ldap_filter(tag: u8, body: &[u8], depth: usize) -> Option<String> {
    if depth >= MAX_LDAP_FILTER_DEPTH {
        return None;
    }
    match tag {
        0x87 => {
            let attr = core::str::from_utf8(body).ok()?;
            if attr.is_empty()
                || !is_printable_ldap_str(attr)
                || attr.contains(['(', ')', '*', '='])
            {
                return None;
            }
            Some(format!("({attr}=*)"))
        }
        0xA3 | 0xA5 | 0xA6 | 0xA8 => {
            let (attr, val) = decode_ldap_ava(body)?;
            let op = match tag {
                0xA3 => "=",
                0xA5 => ">=",
                0xA6 => "<=",
                _ => "~=",
            };
            if tag == 0xA3
                && (val.contains(">=")
                    || val.contains("<=")
                    || val.contains("~=")
                    || val.contains('*'))
            {
                return None;
            }
            Some(format!("({attr}{op}{val})"))
        }
        0xA4 => {
            let (atag, abytes, rem) = parse_ber_tlv(body)?;
            if atag != 0x04 {
                return None;
            }
            let attr = core::str::from_utf8(abytes).ok()?;
            if attr.is_empty()
                || !is_printable_ldap_str(attr)
                || attr.contains(['(', ')', '=', '<', '>', '~', '*'])
            {
                return None;
            }
            let (stag, mut sub_seq, rem2) = parse_ber_tlv(rem)?;
            if stag != 0x30 || !rem2.is_empty() || sub_seq.is_empty() {
                return None;
            }
            let mut pattern = String::new();
            let mut idx = 0usize;
            let mut saw_final = false;
            while !sub_seq.is_empty() {
                let (ptag, pbytes, next) = parse_ber_tlv(sub_seq)?;
                sub_seq = next;
                let part = core::str::from_utf8(pbytes).ok()?;
                if !is_printable_ldap_str(part) || part.contains(['(', ')', '*']) || saw_final {
                    return None;
                }
                match ptag {
                    0x80 if idx == 0 => pattern.push_str(part),
                    0x81 => {
                        pattern.push('*');
                        pattern.push_str(part);
                    }
                    0x82 if sub_seq.is_empty() => {
                        pattern.push('*');
                        pattern.push_str(part);
                        saw_final = true;
                    }
                    _ => return None,
                }
                idx += 1;
            }
            if !saw_final {
                pattern.push('*');
            }
            Some(format!("({attr}={pattern})"))
        }
        0xA0 | 0xA1 => {
            let op = if tag == 0xA0 { '&' } else { '|' };
            let mut out = String::new();
            out.push('(');
            out.push(op);
            let mut cur = body;
            let mut count = 0usize;
            while !cur.is_empty() {
                let (ctag, cbody, next) = parse_ber_tlv(cur)?;
                cur = next;
                let child = decode_ldap_filter(ctag, cbody, depth + 1)?;
                out.push_str(&child);
                count += 1;
            }
            if count == 0 {
                return None;
            }
            out.push(')');
            Some(out)
        }
        0xA2 => {
            let (ctag, cbody, rem) = parse_ber_tlv(body)?;
            if !rem.is_empty() {
                return None;
            }
            let child = decode_ldap_filter(ctag, cbody, depth + 1)?;
            Some(format!("(!{child})"))
        }
        _ => None,
    }
}

/// Dissects an `ldap` v3 BER `LDAPMessage` envelope over ports `389`, `636`, `3268`, or `1389`.
pub(crate) fn dissect_ldap(
    transport: TransportProto,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Option<ProtocolDissection> {
    if payload.is_empty()
        || !matches!(
            transport,
            TransportProto::Tcp | TransportProto::Udp | TransportProto::Sctp
        )
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
    let msgid = i32::try_from(parse_ber_int(id_bytes)?).ok()?;
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
            if !is_printable_ldap_str(dn) {
                return None;
            }
            if dn != "dc=corp,dc=local" {
                tokens.push_str(&format!(" basedn \"{}\"", quote_raw_str(dn)));
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
            if !is_printable_ldap_str(dn) {
                return None;
            }
            if rc != 0 {
                tokens.push_str(&format!(" resultcode {rc}"));
            }
            if !dn.is_empty() {
                tokens.push_str(&format!(" basedn \"{}\"", quote_raw_str(dn)));
            }
        }
        0x63 => {
            tokens.push_str(" searchreq");
            let (dn_tag, dn_bytes, mut rest) = parse_ber_tlv(op_body)?;
            if dn_tag != 0x04 {
                return None;
            }
            let dn = core::str::from_utf8(dn_bytes).ok()?;
            if !is_printable_ldap_str(dn) {
                return None;
            }
            if dn != "dc=corp,dc=local" {
                tokens.push_str(&format!(" basedn \"{}\"", quote_raw_str(dn)));
            }
            for _ in 0..5 {
                let (_, _, next) = parse_ber_tlv(rest)?;
                rest = next;
            }
            let (flt_tag, flt_body, after_flt) = parse_ber_tlv(rest)?;
            let (attrs_tag, _, attrs_rem) = parse_ber_tlv(after_flt)?;
            if attrs_tag != 0x30 || !attrs_rem.is_empty() {
                return None;
            }
            if flt_tag == 0x87 {
                let flt = core::str::from_utf8(flt_body).ok()?;
                if flt.is_empty()
                    || !is_printable_ldap_str(flt)
                    || flt.contains(['(', ')', '*', '='])
                {
                    return None;
                }
                if flt != "objectClass" {
                    tokens.push_str(&format!(" filter \"{}\"", quote_raw_str(flt)));
                }
            } else {
                let flt = decode_ldap_filter(flt_tag, flt_body, 0)?;
                tokens.push_str(&format!(" filter \"{}\"", quote_raw_str(&flt)));
            }
        }
        0x64 => {
            tokens.push_str(" searchentry");
            let (dn_tag, dn_bytes, _) = parse_ber_tlv(op_body)?;
            if dn_tag != 0x04 {
                return None;
            }
            let dn = core::str::from_utf8(dn_bytes).ok()?;
            if !is_printable_ldap_str(dn) {
                return None;
            }
            if dn != "dc=corp,dc=local" {
                tokens.push_str(&format!(" basedn \"{}\"", quote_raw_str(dn)));
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
        explicit_transport: if matches!(transport, TransportProto::Udp) {
            Some(TransportProto::Udp)
        } else {
            None
        },
    })
}
