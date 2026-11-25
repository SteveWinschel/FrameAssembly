//! Kerberos Network Authentication Service v5 (RFC 4120) Layer 7 PCAP-to-`.frasm` decompiler.
//!
//! This module implements fuzz-safe ASN.1 DER wire-to-AST dissection for `kerberos` v5 messages
//! (`asreq`, `asrep`, `tgsreq`, `tgsrep`, and `krberror`) over UDP, SCTP, and 4-byte record-marked
//! TCP transports (port `88` and custom ports with valid ASN.1 APPLICATION tags `0x6A..=0x6D` or
//! `0x7E`). It dissects outer unencrypted ASN.1 DER fields (`realm`, `cname`, `sname`, signed 32-bit
//! `etype`, `PA-ETYPE-INFO2`/`ETYPE-INFO2` padata, and `GeneralizedTime` `stime`) into canonical
//! `.frasm` tokens while preserving trailing bytes in `residual_payload`.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::ast::{Protocol, TransportProto};
use crate::reverse::ProtocolDissection;

use super::quote_raw_str;

/// Checks whether `s` contains no control characters for safe quoted string emission.
fn is_printable_krb_str(s: &str) -> bool {
    s.chars().all(|c| !c.is_control())
}

/// Validates an RFC 4120 ASN.1 DER `GeneralizedTime` value (`YYYYMMDDHHMMSSZ`, 15 ASCII bytes).
fn is_valid_generalized_time(bytes: &[u8]) -> bool {
    bytes.len() == 15 && bytes[14] == b'Z' && bytes[..14].iter().all(|b| b.is_ascii_digit())
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
                if !is_printable_krb_str(s) {
                    return None;
                }
                parts.push(s);
            }
            return Some(parts.join("/"));
        }
    }
    None
}

/// Extracts the first signed `i32` `etype` from a `METHOD-DATA` (`PA-ETYPE-INFO2` = `19`) sequence.
fn extract_etype_from_method_data(method_data: &[u8]) -> Option<i32> {
    let (md_tag, mut pa_seq, _) = parse_ber_tlv(method_data)?;
    if md_tag != 0x30 {
        return None;
    }
    while !pa_seq.is_empty() {
        let (pa_tag, mut pa_fields, next_pa) = parse_ber_tlv(pa_seq)?;
        pa_seq = next_pa;
        if pa_tag != 0x30 {
            continue;
        }
        let mut padata_type: Option<i64> = None;
        let mut padata_val: Option<&[u8]> = None;
        while !pa_fields.is_empty() {
            let (ft, fv, fn_rem) = parse_ber_tlv(pa_fields)?;
            pa_fields = fn_rem;
            match ft {
                0xA1 => {
                    if let Some((0x02, ib, _)) = parse_ber_tlv(fv) {
                        padata_type = parse_ber_int(ib);
                    }
                }
                0xA2 => {
                    if let Some((0x04, ob, _)) = parse_ber_tlv(fv) {
                        padata_val = Some(ob);
                    }
                }
                _ => {}
            }
        }
        if padata_type == Some(19)
            && let Some(einfo_bytes) = padata_val
            && let Some((0x30, mut entries, _)) = parse_ber_tlv(einfo_bytes)
        {
            while !entries.is_empty() {
                let (et_tag, mut entry_fields, next_e) = parse_ber_tlv(entries)?;
                entries = next_e;
                if et_tag != 0x30 {
                    continue;
                }
                while !entry_fields.is_empty() {
                    let (eft, efv, ef_next) = parse_ber_tlv(entry_fields)?;
                    entry_fields = ef_next;
                    if eft == 0xA0
                        && let Some((0x02, iv, _)) = parse_ber_tlv(efv)
                    {
                        return i32::try_from(parse_ber_int(iv)?).ok();
                    }
                }
            }
        }
    }
    None
}

/// Dissects a `kerberos` v5 ASN.1 DER message (`AS-REQ`, `AS-REP`, `TGS-REQ`, `TGS-REP`, `KRB-ERROR`).
pub(crate) fn dissect_kerberos(
    transport: TransportProto,
    _src_port: u16,
    _dst_port: u16,
    payload: &[u8],
) -> Option<ProtocolDissection> {
    if payload.is_empty()
        || !matches!(
            transport,
            TransportProto::Tcp | TransportProto::Udp | TransportProto::Sctp
        )
    {
        return None;
    }
    let is_tcp = matches!(transport, TransportProto::Tcp);

    let data = if is_tcp {
        if payload.len() <= 4 {
            return None;
        }
        let rec_len = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]) as usize;
        let rec_end = 4usize.checked_add(rec_len)?;
        if rec_end > payload.len() || !matches!(payload.get(4), Some(0x6A..=0x6D | 0x7E)) {
            return None;
        }
        &payload[4..]
    } else if matches!(payload.first(), Some(0x6A..=0x6D | 0x7E)) {
        payload
    } else {
        return None;
    };

    let (app_tag, app_body, residual) = parse_ber_tlv(data)?;
    if is_tcp {
        let rec_len = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]) as usize;
        if data.len() - residual.len() != rec_len {
            return None;
        }
    }
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
                                if is_printable_krb_str(s) {
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
                                    etype = i32::try_from(parse_ber_int(iv)?).ok();
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
            (11, 0xA2) => {
                if etype.is_none() {
                    etype = extract_etype_from_method_data(ctx_val);
                }
            }
            (11 | 13, 0xA3) => {
                let (t, v, _) = parse_ber_tlv(ctx_val)?;
                if t == 0x1B {
                    let s = core::str::from_utf8(v).ok()?;
                    if is_printable_krb_str(s) {
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
                            etype = i32::try_from(parse_ber_int(iv)?).ok();
                        }
                    }
                }
            }
            (30, 0xA4) => {
                let (gt_tag, gt_bytes, _) = parse_ber_tlv(ctx_val)?;
                if gt_tag != 0x18 || !is_valid_generalized_time(gt_bytes) {
                    return None;
                }
            }
            (30, 0xA8) => cname = parse_krb_principal(ctx_val),
            (30, 0xA9) => {
                let (t, v, _) = parse_ber_tlv(ctx_val)?;
                if t == 0x1B {
                    let s = core::str::from_utf8(v).ok()?;
                    if is_printable_krb_str(s) {
                        realm = Some(s.to_string());
                    }
                }
            }
            (30, 0xAA) => sname = parse_krb_principal(ctx_val),
            (30, 0xAB) => {
                if let Some((0x04, md_bytes, _)) = parse_ber_tlv(ctx_val)
                    && let Some(e) = extract_etype_from_method_data(md_bytes)
                {
                    etype = Some(e);
                }
            }
            _ => {}
        }
    }

    let mut tokens = String::from("kerberos");
    match msg_type {
        10 => {}
        11 => tokens.push_str(" asrep"),
        12 => tokens.push_str(" tgsreq"),
        13 => tokens.push_str(" tgsrep"),
        30 => tokens.push_str(" krberror"),
        _ => {}
    }
    if let Some(r) = realm.as_deref()
        && r != "CORP.LOCAL"
    {
        tokens.push_str(&format!(" realm \"{}\"", quote_raw_str(r)));
    }
    if let Some(c) = cname.as_deref()
        && c != "user"
    {
        tokens.push_str(&format!(" cname \"{}\"", quote_raw_str(c)));
    }
    if let Some(s) = sname.as_deref()
        && s != "krbtgt"
    {
        tokens.push_str(&format!(" sname \"{}\"", quote_raw_str(s)));
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
