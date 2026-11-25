//! Manufacturing Message Specification (ISO 9506 / IEC 61850 MMS) Layer 7 PCAP-to-`.frasm` decompiler.
//!
//! This module implements fuzz-safe wire-to-AST dissection for `mms` frames carried inside RFC
//! 1006 TPKT (`0x03 0x00`), ISO 8073 COTP DT (`0x02 0xF0 0x80`), ISO 8327-1 Session (`CN`/`AC`
//! or `GT`+`DT`), ISO 8823 Presentation (`CP`/`CPA` or `User-data`), optional ISO 8650-1 ACSE
//! (`AARQ`/`AARE`), and ASN.1 BER MMS PDUs (`Initiate`, `GetNameList`, `Read`, `Write`,
//! `InformationReport`, `Conclude`) over TCP and SCTP port `102`.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use crate::ast::{Protocol, TransportProto};
use crate::reverse::ProtocolDissection;

use super::quote_raw_str;

/// Canonical MMS `Initiate-RequestPDU` (`0xA8`) BER payload.
const MMS_INITIATE_REQ: [u8; 39] = [
    0xA8, 0x26, 0x80, 0x02, 0x7D, 0x00, 0x81, 0x01, 0x05, 0x82, 0x01, 0x05, 0x83, 0x01, 0x0A,
    0xA4, 0x16, 0x80, 0x01, 0x01, 0x81, 0x03, 0x05, 0xF1, 0x00, 0x82, 0x0C, 0x03, 0xEE, 0x1C,
    0x00, 0x00, 0x04, 0x08, 0x00, 0x00, 0x79, 0xEF, 0x18,
];

/// Canonical MMS `Initiate-ResponsePDU` (`0xA9`) BER payload.
const MMS_INITIATE_RESP: [u8; 39] = [
    0xA9, 0x26, 0x80, 0x02, 0x7D, 0x00, 0x81, 0x01, 0x05, 0x82, 0x01, 0x05, 0x83, 0x01, 0x0A,
    0xA4, 0x16, 0x80, 0x01, 0x01, 0x81, 0x03, 0x05, 0xF1, 0x00, 0x82, 0x0C, 0x03, 0xEE, 0x1C,
    0x00, 0x00, 0x04, 0x08, 0x00, 0x00, 0x79, 0xEF, 0x18,
];

/// Fixed ISO 8327-1 Session `CN`/`AC` parameter prefix before `User-Data` PI (`0xC1`).
const SES_CONN_PARAMS: [u8; 12] = [
    0x05, 0x06, 0x13, 0x01, 0x00, 0x16, 0x01, 0x02, 0x14, 0x02, 0x00, 0x02,
];

/// Parses a single ASN.1 BER definite-length TLV, returning `(tag, value, rest)`.
fn parse_ber_tlv(input: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    if input.len() < 2 {
        return None;
    }
    let tag = input[0];
    let b1 = input[1];
    let (len, hdr_len) = if (b1 & 0x80) == 0 {
        (usize::from(b1), 2usize)
    } else {
        let octets = usize::from(b1 & 0x7F);
        if octets == 0 || octets > 4 || input.len() < 2 + octets {
            return None;
        }
        let mut l = 0usize;
        for &b in &input[2..2 + octets] {
            l = (l << 8) | usize::from(b);
        }
        (l, 2 + octets)
    };
    let end = hdr_len.checked_add(len)?;
    if input.len() < end {
        return None;
    }
    Some((tag, &input[hdr_len..end], &input[end..]))
}

/// Parses an ISO 8327-1 Session SPDU length (1-octet `< 255` or 3-octet `0xFF`).
fn parse_session_len(input: &[u8]) -> Option<(usize, &[u8])> {
    let first = *input.first()?;
    if first < 255 {
        Some((usize::from(first), &input[1..]))
    } else if input.len() >= 3 {
        let len = usize::from(u16::from_be_bytes([input[1], input[2]]));
        Some((len, &input[3..]))
    } else {
        None
    }
}

/// Parses a signed BER integer value into `i64`.
fn parse_ber_int(bytes: &[u8]) -> Option<i64> {
    if bytes.is_empty() || bytes.len() > 8 {
        return None;
    }
    let mut val = if (bytes[0] & 0x80) != 0 { -1i64 } else { 0i64 };
    for &b in bytes {
        val = (val << 8) | i64::from(b);
    }
    Some(val)
}

/// Parses an MMS `VisibleString` (`0x1A` or context-specific ASCII) ensuring printable characters.
fn parse_printable_str(bytes: &[u8]) -> Option<&str> {
    let s = core::str::from_utf8(bytes).ok()?;
    if s.chars().all(|c| !c.is_control()) {
        Some(s)
    } else {
        None
    }
}

/// Decodes an MMS `VariableAccessSpecification` (`listOfVariable [0]`), returning `(domain, item)`.
fn decode_var_access_spec(vas: &[u8]) -> Option<(Option<&str>, &str)> {
    let (vtag, var_item, rem) = parse_ber_tlv(vas)?;
    if vtag != 0xA0 || !rem.is_empty() {
        return None;
    }
    let (stag, seq_body, rem2) = parse_ber_tlv(var_item)?;
    if stag != 0x30 || !rem2.is_empty() {
        return None;
    }
    let (ntag, obj_name, rem3) = parse_ber_tlv(seq_body)?;
    if ntag != 0xA0 || !rem3.is_empty() {
        return None;
    }
    let (otag, obody, rem4) = parse_ber_tlv(obj_name)?;
    if !rem4.is_empty() {
        return None;
    }
    match otag {
        0x80 => Some((None, parse_printable_str(obody)?)),
        0xA1 => {
            let (dtag, dbytes, next) = parse_ber_tlv(obody)?;
            let (itag, ibytes, end) = parse_ber_tlv(next)?;
            if dtag != 0x1A || itag != 0x1A || !end.is_empty() {
                return None;
            }
            Some((
                Some(parse_printable_str(dbytes)?),
                parse_printable_str(ibytes)?,
            ))
        }
        _ => None,
    }
}

/// Decodes an MMS `Data` element (`0x85` integer or `0x89` octet-string residual).
fn decode_mms_data(data_tlv: &[u8]) -> Option<(Option<u32>, Vec<u8>)> {
    let (tag, body, rem) = parse_ber_tlv(data_tlv)?;
    if !rem.is_empty() {
        return None;
    }
    match tag {
        0x85 => {
            let v = parse_ber_int(body)?;
            let uv = u32::try_from(v).ok()?;
            Some((Some(uv), Vec::new()))
        }
        0x89 => Some((None, body.to_vec())),
        _ => None,
    }
}

/// Appends elided `domain` and `item` tokens for `read`, `write`, and `report` services.
fn push_domain_item_tokens(tokens: &mut String, domain: Option<&str>, item: &str) {
    match domain {
        Some("IED1") if item == "LLN0$ST$Mod" => {}
        Some(dom) => {
            tokens.push_str(&format!(" domain \"{}\"", quote_raw_str(dom)));
            if item != "LLN0$ST$Mod" {
                tokens.push_str(&format!(" item \"{}\"", quote_raw_str(item)));
            }
        }
        None => {
            tokens.push_str(&format!(" item \"{}\"", quote_raw_str(item)));
        }
    }
}

/// Dissects a Session `CN` (`0x0D`) or `AC` (`0x0E`) MMS Initiate envelope.
fn dissect_initiate(spdu: &[u8]) -> Option<ProtocolDissection> {
    let spdu_type = *spdu.first()?;
    if !matches!(spdu_type, 0x0D | 0x0E) {
        return None;
    }
    let (ses_len, ses_body) = parse_session_len(&spdu[1..])?;
    if ses_body.len() != ses_len || !ses_body.starts_with(&SES_CONN_PARAMS) {
        return None;
    }
    let after_params = &ses_body[SES_CONN_PARAMS.len()..];
    if *after_params.first()? != 0xC1 {
        return None;
    }
    let (ud_len, pres_cp) = parse_session_len(&after_params[1..])?;
    if pres_cp.len() != ud_len {
        return None;
    }
    let (ptag, pbody, prem) = parse_ber_tlv(pres_cp)?;
    if ptag != 0x31 || !prem.is_empty() {
        return None;
    }
    let (mtag, _mbody, after_mode) = parse_ber_tlv(pbody)?;
    let (nmtag, mut nmp, nrem) = parse_ber_tlv(after_mode)?;
    if mtag != 0xA0 || nmtag != 0xA2 || !nrem.is_empty() {
        return None;
    }
    let mut ud_tlv: Option<&[u8]> = None;
    while !nmp.is_empty() {
        let (t, b, next) = parse_ber_tlv(nmp)?;
        if t == 0x61 && next.is_empty() {
            ud_tlv = Some(b);
            break;
        }
        nmp = next;
    }
    let (pdv_tag, pdv_body, pdv_rem) = parse_ber_tlv(ud_tlv?)?;
    if pdv_tag != 0x30 || !pdv_rem.is_empty() {
        return None;
    }
    let (cid_tag, cid_bytes, after_cid) = parse_ber_tlv(pdv_body)?;
    let (atag, acse_pdu, arem) = parse_ber_tlv(after_cid)?;
    if cid_tag != 0x02 || cid_bytes != [0x01] || atag != 0xA0 || !arem.is_empty() {
        return None;
    }
    let expected_acse_tag = if spdu_type == 0x0D { 0x60 } else { 0x61 };
    let (acse_tag, mut acse_body, acse_rem) = parse_ber_tlv(acse_pdu)?;
    if acse_tag != expected_acse_tag || !acse_rem.is_empty() {
        return None;
    }
    let mut ext_bytes: Option<&[u8]> = None;
    let mut saw_mms_oid = false;
    while !acse_body.is_empty() {
        let (t, b, next) = parse_ber_tlv(acse_body)?;
        if t == 0xA1 && b == [0x06, 0x05, 0x28, 0xCA, 0x22, 0x02, 0x03] {
            saw_mms_oid = true;
        } else if t == 0xBE && next.is_empty() {
            ext_bytes = Some(b);
            break;
        }
        acse_body = next;
    }
    if !saw_mms_oid {
        return None;
    }
    let (etag, ebody, erem) = parse_ber_tlv(ext_bytes?)?;
    if etag != 0x28 || !erem.is_empty() {
        return None;
    }
    let mut cur = ebody;
    let mut mms_init: Option<&[u8]> = None;
    while !cur.is_empty() {
        let (t, b, next) = parse_ber_tlv(cur)?;
        if t == 0xA0 && next.is_empty() {
            mms_init = Some(b);
            break;
        }
        cur = next;
    }
    let mms_bytes = mms_init?;
    let mut tokens = String::from("mms");
    if spdu_type == 0x0D && mms_bytes == MMS_INITIATE_REQ {
    } else if spdu_type == 0x0E && mms_bytes == MMS_INITIATE_RESP {
        tokens.push_str(" isresponse");
    } else {
        return None;
    }

    Some(ProtocolDissection {
        protocol: Protocol::Mms,
        tokens,
        residual_payload: Vec::new(),
        explicit_transport: None,
    })
}

/// Dissects an ISO 9506 / IEC 61850 `mms` frame over RFC 1006 TPKT + COTP DT (TCP/SCTP port `102`).
pub(crate) fn dissect_mms(
    transport: TransportProto,
    _src_port: u16,
    _dst_port: u16,
    payload: &[u8],
) -> Option<ProtocolDissection> {
    if !matches!(transport, TransportProto::Tcp | TransportProto::Sctp)
        || payload.len() < 11
        || &payload[0..2] != b"\x03\x00"
        || usize::from(u16::from_be_bytes([payload[2], payload[3]])) != payload.len()
        || &payload[4..7] != b"\x02\xF0\x80"
    {
        return None;
    }
    let spdu = &payload[7..];
    if matches!(spdu[0], 0x0D | 0x0E) {
        return dissect_initiate(spdu);
    }
    if !spdu.starts_with(&[0x01, 0x00, 0x01, 0x00]) {
        return None;
    }
    let (ptag, pbody, prem) = parse_ber_tlv(&spdu[4..])?;
    if ptag != 0x61 || !prem.is_empty() {
        return None;
    }
    let (pdv_tag, pdv_body, pdv_rem) = parse_ber_tlv(pbody)?;
    if pdv_tag != 0x30 || !pdv_rem.is_empty() {
        return None;
    }
    let (cid_tag, cid_bytes, after_cid) = parse_ber_tlv(pdv_body)?;
    let (atag, mms_pdu, arem) = parse_ber_tlv(after_cid)?;
    if cid_tag != 0x02 || cid_bytes != [0x03] || atag != 0xA0 || !arem.is_empty() {
        return None;
    }

    let (pdu_tag, pdu_body, pdu_rem) = parse_ber_tlv(mms_pdu)?;
    if !pdu_rem.is_empty() {
        return None;
    }
    let mut tokens = String::from("mms");
    let mut residual = Vec::new();

    match pdu_tag {
        0x8B if pdu_body.is_empty() => tokens.push_str(" conclude"),
        0x8C if pdu_body.is_empty() => tokens.push_str(" conclude isresponse"),
        0xA3 => {
            let (stag, sbody, srem) = parse_ber_tlv(pdu_body)?;
            if stag != 0xA0 || !srem.is_empty() {
                return None;
            }
            let (vtag, _vbody, after_vas) = parse_ber_tlv(sbody)?;
            if vtag != 0xA0 {
                return None;
            }
            let vas_slice = &sbody[..sbody.len() - after_vas.len()];
            let (dom, item) = decode_var_access_spec(vas_slice)?;
            let (dtag, dbody, drem) = parse_ber_tlv(after_vas)?;
            if dtag != 0xA0 || !drem.is_empty() {
                return None;
            }
            let (val_opt, res) = decode_mms_data(dbody)?;
            tokens.push_str(" report");
            push_domain_item_tokens(&mut tokens, dom, item);
            if let Some(v) = val_opt
                && v != 0
            {
                tokens.push_str(&format!(" value {v}"));
            }
            residual = res;
        }
        0xA0 | 0xA1 => {
            let is_resp = pdu_tag == 0xA1;
            let (itag, ibytes, after_inv) = parse_ber_tlv(pdu_body)?;
            if itag != 0x02 {
                return None;
            }
            let invoke_id = u32::try_from(parse_ber_int(ibytes)?).ok()?;
            let (svc_tag, svc_body, svc_rem) = parse_ber_tlv(after_inv)?;
            if !svc_rem.is_empty() {
                return None;
            }
            match svc_tag {
                0xA1 => {
                    tokens.push_str(" getnamelist");
                    if is_resp {
                        tokens.push_str(" isresponse");
                        let (ltag, lbody, after_list) = parse_ber_tlv(svc_body)?;
                        if ltag != 0xA0 || after_list != [0x81, 0x01, 0x00] {
                            return None;
                        }
                        let (ntag, nbytes, nrem) = parse_ber_tlv(lbody)?;
                        if ntag != 0x1A || !nrem.is_empty() {
                            return None;
                        }
                        let name = parse_printable_str(nbytes)?;
                        if name != "IED1" {
                            tokens.push_str(&format!(" domain \"{}\"", quote_raw_str(name)));
                        }
                    } else {
                        let (ctag, cbody, after_cls) = parse_ber_tlv(svc_body)?;
                        let (stag, sbody, srem) = parse_ber_tlv(after_cls)?;
                        if ctag != 0xA0 || cbody != [0x0A, 0x01, 0x00] || stag != 0xA1 || !srem.is_empty() {
                            return None;
                        }
                        let (sctag, scbytes, screm) = parse_ber_tlv(sbody)?;
                        if !screm.is_empty() {
                            return None;
                        }
                        match sctag {
                            0x80 if scbytes.is_empty() => {}
                            0x81 => {
                                let dom = parse_printable_str(scbytes)?;
                                tokens.push_str(&format!(" domain \"{}\"", quote_raw_str(dom)));
                            }
                            _ => return None,
                        }
                    }
                }
                0xA4 => {
                    tokens.push_str(" read");
                    if is_resp {
                        tokens.push_str(" isresponse");
                        let (ltag, lbody, lrem) = parse_ber_tlv(svc_body)?;
                        if ltag != 0xA1 || !lrem.is_empty() {
                            return None;
                        }
                        let (val_opt, res) = decode_mms_data(lbody)?;
                        if let Some(v) = val_opt
                            && v != 0
                        {
                            tokens.push_str(&format!(" value {v}"));
                        }
                        residual = res;
                    } else {
                        let (ltag, lbody, lrem) = parse_ber_tlv(svc_body)?;
                        if ltag != 0xA1 || !lrem.is_empty() {
                            return None;
                        }
                        let (dom, item) = decode_var_access_spec(lbody)?;
                        push_domain_item_tokens(&mut tokens, dom, item);
                    }
                }
                0xA5 => {
                    tokens.push_str(" write");
                    if is_resp {
                        if svc_body != [0x81, 0x00] {
                            return None;
                        }
                        tokens.push_str(" isresponse");
                    } else {
                        let (vtag, _vbody, after_vas) = parse_ber_tlv(svc_body)?;
                        if vtag != 0xA0 {
                            return None;
                        }
                        let vas_slice = &svc_body[..svc_body.len() - after_vas.len()];
                        let (dom, item) = decode_var_access_spec(vas_slice)?;
                        let (dtag, dbody, drem) = parse_ber_tlv(after_vas)?;
                        if dtag != 0xA0 || !drem.is_empty() {
                            return None;
                        }
                        let (val_opt, res) = decode_mms_data(dbody)?;
                        push_domain_item_tokens(&mut tokens, dom, item);
                        if let Some(v) = val_opt
                            && v != 0
                        {
                            tokens.push_str(&format!(" value {v}"));
                        }
                        residual = res;
                    }
                }
                _ => return None,
            }
            if invoke_id != 1 {
                tokens.push_str(&format!(" invokeid {invoke_id}"));
            }
        }
        _ => return None,
    }

    Some(ProtocolDissection {
        protocol: Protocol::Mms,
        tokens,
        residual_payload: residual,
        explicit_transport: None,
    })
}
