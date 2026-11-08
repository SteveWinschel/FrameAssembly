//! Kerberos Network Authentication Service v5 (RFC 4120) Layer 7 PCAP-to-`.fasm` decompiler.
//!
//! This module implements fuzz-safe ASN.1 DER wire-to-AST dissection for `KERBEROS` v5 messages
//! (`AS-REQ`, `AS-REP`, `TGS-REQ`, `TGS-REP`, and `KRB-ERROR`) over UDP and 4-byte record-marked
//! TCP transports (port `88` and custom ports with valid ASN.1 APPLICATION tags `0x6A..=0x6D` or
//! `0x7E`). It dissects outer unencrypted ASN.1 DER fields (`realm`, `cname`, `sname`, and
//! `etype`) into canonical `.fasm` tokens without attempting to decrypt encrypted ticket or
//! cipher payloads, and preserves trailing bytes in `residual_payload`.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

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

/// Parses a Kerberos `PrincipalName` SEQUENCE into a `"/"`-joined string.
fn parse_krb_principal(input: &[u8]) -> Option<String> {
    let (seq_tag, mut seq_body, _) = parse_ber_tlv(input)?;
    if seq_tag != 0x30 {
        return None;
    }
    while !seq_body.is_empty() {
        let (ctx_tag, ctx_val, next) = parse_ber_tlv(seq_body)?;
        seq_body = next;
        if ctx_tag == 0xA1 {
            let (inner_tag, mut names_seq, _) = parse_ber_tlv(ctx_val)?;
            if inner_tag != 0x30 {
                return None;
            }
            let mut parts = Vec::new();
            while !names_seq.is_empty() {
                let (gs_tag, gs_bytes, rem) = parse_ber_tlv(names_seq)?;
                names_seq = rem;
                if gs_tag != 0x1B {
                    return None;
                }
                let s = core::str::from_utf8(gs_bytes).ok()?;
                if !is_valid_raw_str(s) {
                    return None;
                }
                parts.push(s);
            }
            return Some(parts.join("/"));
        }
    }
    None
}

/// Dissects a `KERBEROS` v5 ASN.1 DER message (`AS-REQ`, `AS-REP`, `TGS-REQ`, `TGS-REP`, `KRB-ERROR`).
pub(crate) fn dissect_kerberos(
    transport: TransportProto,
    _src_port: u16,
    _dst_port: u16,
    payload: &[u8],
) -> Option<ProtocolDissection> {
    if payload.is_empty() || !matches!(transport, TransportProto::Tcp | TransportProto::Udp) {
        return None;
    }
    let is_tcp = matches!(transport, TransportProto::Tcp);

    let data = if matches!(payload.first(), Some(0x6A..=0x6D | 0x7E)) {
        payload
    } else if is_tcp
        && payload.len() > 4
        && matches!(payload.get(4), Some(0x6A..=0x6D | 0x7E))
        && (u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]) as usize + 4
            <= payload.len())
    {
        &payload[4..]
    } else {
        return None;
    };

    let (app_tag, app_body, residual) = parse_ber_tlv(data)?;
    let msg_type = match app_tag {
        0x6A => 10u8,
        0x6B => 11u8,
        0x6C => 12u8,
        0x6D => 13u8,
        0x7E => 30u8,
        _ => return None,
    };

    let (seq_tag, mut seq_body, seq_rem) = parse_ber_tlv(app_body)?;
    if seq_tag != 0x30 || !seq_rem.is_empty() {
        return None;
    }

    let mut realm: Option<String> = None;
    let mut cname: Option<String> = None;
    let mut sname: Option<String> = None;
    let mut etype: Option<i32> = None;

    while !seq_body.is_empty() {
        let (ctx_tag, ctx_val, next) = parse_ber_tlv(seq_body)?;
        seq_body = next;
        match (msg_type, ctx_tag) {
            (10 | 12, 0xA4) => {
                let (rb_tag, mut rb_body, _) = parse_ber_tlv(ctx_val)?;
                if rb_tag != 0x30 {
                    return None;
                }
                while !rb_body.is_empty() {
                    let (f_tag, f_val, f_next) = parse_ber_tlv(rb_body)?;
                    rb_body = f_next;
                    match f_tag {
                        0xA1 => cname = parse_krb_principal(f_val),
                        0xA2 => {
                            let (t, v, _) = parse_ber_tlv(f_val)?;
                            if t == 0x1B {
                                let s = core::str::from_utf8(v).ok()?;
                                if is_valid_raw_str(s) {
                                    realm = Some(s.to_string());
                                }
                            }
                        }
                        0xA3 => sname = parse_krb_principal(f_val),
                        0xA8 | 0xA9 => {
                            let (t, et_seq, _) = parse_ber_tlv(f_val)?;
                            if t == 0x30 && !et_seq.is_empty() {
                                let (it, iv, _) = parse_ber_tlv(et_seq)?;
                                if it == 0x02 {
                                    etype = parse_ber_int(iv).map(|n| n as i32);
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
            (11 | 13, 0xA3) => {
                let (t, v, _) = parse_ber_tlv(ctx_val)?;
                if t == 0x1B {
                    let s = core::str::from_utf8(v).ok()?;
                    if is_valid_raw_str(s) {
                        realm = Some(s.to_string());
                    }
                }
            }
            (11 | 13, 0xA4) => cname = parse_krb_principal(ctx_val),
            (11 | 13, 0xA5) => {
                if let Some((0x61, tkt_app, _)) = parse_ber_tlv(ctx_val)
                    && let Some((0x30, mut tkt_seq, _)) = parse_ber_tlv(tkt_app)
                {
                    while !tkt_seq.is_empty() {
                        let (tt, tv, tn) = parse_ber_tlv(tkt_seq)?;
                        tkt_seq = tn;
                        if tt == 0xA2 {
                            sname = parse_krb_principal(tv);
                        }
                    }
                }
            }
            (11 | 13, 0xA6) => {
                if let Some((0x30, mut ed_seq, _)) = parse_ber_tlv(ctx_val) {
                    while !ed_seq.is_empty() {
                        let (et, ev, en) = parse_ber_tlv(ed_seq)?;
                        ed_seq = en;
                        if et == 0xA0
                            && let Some((0x02, iv, _)) = parse_ber_tlv(ev)
                        {
                            etype = parse_ber_int(iv).map(|n| n as i32);
                        }
                    }
                }
            }
            (30, 0xA8) => cname = parse_krb_principal(ctx_val),
            (30, 0xA9) => {
                let (t, v, _) = parse_ber_tlv(ctx_val)?;
                if t == 0x1B {
                    let s = core::str::from_utf8(v).ok()?;
                    if is_valid_raw_str(s) {
                        realm = Some(s.to_string());
                    }
                }
            }
            (30, 0xAA) => sname = parse_krb_principal(ctx_val),
            _ => {}
        }
    }

    let mut tokens = String::from("kerberos");
    match msg_type {
        10 => {}
        11 => tokens.push_str(" as_rep"),
        12 => tokens.push_str(" tgs_req"),
        13 => tokens.push_str(" tgs_rep"),
        30 => tokens.push_str(" krb_error"),
        _ => {}
    }
    if let Some(r) = realm.as_deref()
        && r != "CORP.LOCAL"
    {
        tokens.push_str(&format!(" realm \"{r}\""));
    }
    if let Some(c) = cname.as_deref()
        && c != "user"
    {
        tokens.push_str(&format!(" cname \"{c}\""));
    }
    if let Some(s) = sname.as_deref()
        && s != "krbtgt"
    {
        tokens.push_str(&format!(" sname \"{s}\""));
    }
    if let Some(e) = etype
        && e != 18
    {
        tokens.push_str(&format!(" etype {e}"));
    }

    Some(ProtocolDissection {
        protocol: Protocol::Kerberos,
        tokens,
        residual_payload: residual.to_vec(),
        explicit_transport: if is_tcp {
            Some(TransportProto::Tcp)
        } else {
            None
        },
    })
}
