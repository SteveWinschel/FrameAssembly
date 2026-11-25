//! ANSI C12.22 / IEEE 1703 Smart Grid metering ACSE + EPSEM wire payload builder.
//!
//! This module implements [`build_c1222_payload`], which serializes a [`C1222Spec`] AST node
//! into an ANSI C12.22 (IEEE Std 1703) BER-encoded `C1222-Message` (`0x60`) over UDP or TCP
//! port 1153. It encodes the ACSE `called-AP-title` (`[2]`), optional `called-AP-invocation-id`
//! (`[4]`), `calling-AP-title` (`[6]`), optional `calling-AP-invocation-id` (`[8]`), and
//! `user-information` (`[30]` `0xBE -> 0x28 -> 0x81`) wrapping the EPSEM control header and
//! C12.19 table service (`0x30` Full Read, `0x40` Full Write with two's-complement checksum,
//! `0x20` Identify, `0x50` Logon, `0x52` Logoff, `0x21` Terminate, or `0x00`..=`0x0A` responses).

use alloc::vec::Vec;

use crate::ast::*;
use crate::builders::WireContext;

/// Appends an ASN.1 BER definite length (`short` < 128, `long` >= 128) to `out`.
fn push_ber_len(out: &mut Vec<u8>, len: usize) {
    if len < 128 {
        out.push(len as u8);
    } else if len <= 0xFF {
        out.push(0x81);
        out.push(len as u8);
    } else if len <= 0xFFFF {
        out.push(0x82);
        out.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        out.push(0x84);
        out.extend_from_slice(&(u32::try_from(len).unwrap_or(u32::MAX)).to_be_bytes());
    }
}

/// Appends a BER TLV (`tag`, `len`, `value`) to `out`.
fn push_ber_tlv(out: &mut Vec<u8>, tag: u8, val: &[u8]) {
    out.push(tag);
    push_ber_len(out, val.len());
    out.extend_from_slice(val);
}

/// Appends a base-128 VLQ ASN.1 OID subidentifier to `out`.
fn push_oid_subid(out: &mut Vec<u8>, mut val: u32) {
    let mut tmp = [0u8; 5];
    let mut idx = 4usize;
    tmp[idx] = (val & 0x7F) as u8;
    val >>= 7;
    while val > 0 && idx > 0 {
        idx -= 1;
        tmp[idx] = ((val & 0x7F) as u8) | 0x80;
        val >>= 7;
    }
    out.extend_from_slice(&tmp[idx..]);
}

/// Encodes a dotted OID string into BER `OBJECT IDENTIFIER` (`0x06`) content octets.
fn encode_oid_body(raw: &str, fallback: &str) -> Vec<u8> {
    let mut arcs = Vec::new();
    for part in raw.split('.') {
        if let Ok(v) = part.parse::<u32>() {
            arcs.push(v);
        } else {
            arcs.clear();
            break;
        }
    }
    if arcs.len() < 2 || arcs[0] > 2 || (arcs[0] < 2 && arcs[1] >= 40) {
        arcs.clear();
        for part in fallback.split('.') {
            if let Ok(v) = part.parse::<u32>() {
                arcs.push(v);
            }
        }
    }
    let mut body = Vec::new();
    if arcs.len() >= 2 {
        let first = arcs[0].saturating_mul(40).saturating_add(arcs[1]);
        push_oid_subid(&mut body, first);
        for &arc in &arcs[2..] {
            push_oid_subid(&mut body, arc);
        }
    }
    body
}

/// Encodes a non-negative `u32` as minimal two's-complement BER `INTEGER` (`0x02`) octets.
fn encode_u32_int_tlv(val: u32) -> Vec<u8> {
    let bytes = i64::from(val).to_be_bytes();
    let mut start = 0usize;
    while start < 7 {
        if bytes[start] == 0x00 && (bytes[start + 1] & 0x80) == 0 {
            start += 1;
        } else {
            break;
        }
    }
    let mut out = Vec::new();
    push_ber_tlv(&mut out, 0x02, &bytes[start..]);
    out
}

/// Parses an EPSEM service name or numeric code string into an 8-bit C12.22 service ID.
fn parse_c1222_service(raw: &str) -> u8 {
    let norm = raw.trim().to_ascii_uppercase().replace(['_', '-'], "");
    match norm.as_str() {
        "OK" | "RESPONSE" => 0x00,
        "ERR" => 0x01,
        "IDENTIFY" => 0x20,
        "TERMINATE" => 0x21,
        "READ" | "FULLREAD" => 0x30,
        "WRITE" | "FULLWRITE" => 0x40,
        "LOGON" => 0x50,
        "SECURITY" => 0x51,
        "LOGOFF" => 0x52,
        "NEGOTIATE" => 0x60,
        "WAIT" => 0x70,
        _ => {
            if let Some(hex) = norm.strip_prefix("0X") {
                u8::from_str_radix(hex, 16).unwrap_or(0x30)
            } else {
                norm.parse::<u8>().unwrap_or(0x30)
            }
        }
    }
}

/// Builds an ANSI C12.22 / IEEE 1703 ACSE + EPSEM application payload from [`C1222Spec`].
pub fn build_c1222_payload(
    _ctx: &WireContext,
    spec: &C1222Spec,
    payload_bytes: &[u8],
) -> Vec<u8> {
    let called_oid = encode_oid_body(
        spec.called_ap.unwrap_or("2.16.840.1.114416.1"),
        "2.16.840.1.114416.1",
    );
    let calling_oid = encode_oid_body(
        spec.calling_ap.unwrap_or("2.16.840.1.114416.2"),
        "2.16.840.1.114416.2",
    );

    let mut called_ap_tlv = Vec::new();
    push_ber_tlv(&mut called_ap_tlv, 0x06, &called_oid);

    let mut calling_ap_tlv = Vec::new();
    push_ber_tlv(&mut calling_ap_tlv, 0x06, &calling_oid);

    let mut epsem = Vec::new();
    let mut ctrl = spec.epsem_ctrl.unwrap_or(0x00);
    if spec.ed_class.is_some() {
        ctrl |= 0x10;
    }
    epsem.push(ctrl);
    if (ctrl & 0x10) != 0 {
        epsem.extend_from_slice(&spec.ed_class.unwrap_or(0).to_be_bytes());
    }

    let svc_code = spec
        .errcode
        .unwrap_or_else(|| parse_c1222_service(spec.service.unwrap_or("read")));
    let table_id = spec.table_id.unwrap_or(1);

    let mut svc_elem = Vec::new();
    svc_elem.push(svc_code);
    match svc_code {
        0x30 => {
            svc_elem.extend_from_slice(&table_id.to_be_bytes());
            if !payload_bytes.is_empty() {
                svc_elem.extend_from_slice(payload_bytes);
            }
        }
        0x40 => {
            svc_elem.extend_from_slice(&table_id.to_be_bytes());
            let default_word = spec.value.unwrap_or(0).to_be_bytes();
            let data = if payload_bytes.is_empty() {
                default_word.as_slice()
            } else {
                payload_bytes
            };
            let len_u16 = u16::try_from(data.len()).unwrap_or(u16::MAX);
            let sum = data[..usize::from(len_u16)]
                .iter()
                .fold(0u8, |acc, &b| acc.wrapping_add(b));
            let cksum = (!sum).wrapping_add(1);
            svc_elem.extend_from_slice(&len_u16.to_be_bytes());
            svc_elem.extend_from_slice(&data[..usize::from(len_u16)]);
            svc_elem.push(cksum);
        }
        0x50 => {
            svc_elem.extend_from_slice(&0u16.to_be_bytes()); // User ID
            svc_elem.extend_from_slice(b"FRAMEASM  "); // 10-byte User Name
            svc_elem.extend_from_slice(&60u16.to_be_bytes()); // Session Idle Timeout
            if !payload_bytes.is_empty() {
                svc_elem.extend_from_slice(payload_bytes);
            }
        }
        0x00 => {
            if !payload_bytes.is_empty() {
                svc_elem.extend_from_slice(payload_bytes);
            } else if let Some(val) = spec.value {
                svc_elem.extend_from_slice(&val.to_be_bytes());
            }
        }
        _ => {
            if !payload_bytes.is_empty() {
                svc_elem.extend_from_slice(payload_bytes);
            }
        }
    }

    push_ber_len(&mut epsem, svc_elem.len());
    epsem.extend_from_slice(&svc_elem);

    let mut ext_inner = Vec::new();
    push_ber_tlv(&mut ext_inner, 0x81, &epsem);
    let mut user_info = Vec::new();
    push_ber_tlv(&mut user_info, 0x28, &ext_inner);

    let mut seq = Vec::new();
    push_ber_tlv(&mut seq, 0xA2, &called_ap_tlv);
    if let Some(called_id) = spec.called_id {
        let id_tlv = encode_u32_int_tlv(called_id);
        push_ber_tlv(&mut seq, 0xA4, &id_tlv);
    }
    push_ber_tlv(&mut seq, 0xA6, &calling_ap_tlv);
    if let Some(calling_id) = spec.calling_id {
        let id_tlv = encode_u32_int_tlv(calling_id);
        push_ber_tlv(&mut seq, 0xA8, &id_tlv);
    }
    push_ber_tlv(&mut seq, 0xBE, &user_info);

    let mut pkt = Vec::new();
    push_ber_tlv(&mut pkt, 0x60, &seq);
    pkt
}
