//! Kerberos Network Authentication Service v5 (RFC 4120) ASN.1 DER wire payload builder.
//!
//! This module implements [`build_kerberos_payload`], which encodes a [`KerberosSpec`]
//! AST node into a deterministic ASN.1 DER Kerberos v5 message over UDP or TCP port 88. It
//! constructs the outer `[APPLICATION <msg_type>]` tag (`0x6A` `AS-REQ`, `0x6B` `AS-REP`, `0x6C`
//! `TGS-REQ`, `0x6D` `TGS-REP`, or `0x7E` `KRB-ERROR`), wraps the inner `SEQUENCE` with `pvno` (5),
//! `msg-type`, `realm` (`GeneralString`), `cname` (`PrincipalName`), `sname` (`PrincipalName`), and
//! `etype`, and appends any additional trailer bytes.

use crate::ast::*;
use crate::builders::WireContext;
use alloc::vec::Vec;

/// Appends an ASN.1 DER definite-length field (`short` form `< 128`, `long` form `>= 128`).
fn push_der_length(out: &mut Vec<u8>, len: usize) {
    if len < 128 {
        out.push(len as u8);
    } else if len <= 0xFF {
        out.push(0x81);
        out.push(len as u8);
    } else if len <= 0xFFFF {
        out.push(0x82);
        out.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        out.push(0x83);
        out.push((len >> 16) as u8);
        out.extend_from_slice(&(len as u16).to_be_bytes());
    }
}

/// Encodes an ASN.1 DER TLV with the given `tag` and `content` bytes.
fn encode_der_tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + content.len());
    out.push(tag);
    push_der_length(&mut out, content.len());
    out.extend_from_slice(content);
    out
}

/// Encodes a minimal two's-complement ASN.1 DER `INTEGER` (`0x02`).
fn encode_der_int(val: i64) -> Vec<u8> {
    let bytes = val.to_be_bytes();
    let mut start = 0;
    while start < 7 {
        if (bytes[start] == 0x00 && (bytes[start + 1] & 0x80) == 0)
            || (bytes[start] == 0xFF && (bytes[start + 1] & 0x80) != 0)
        {
            start += 1;
        } else {
            break;
        }
    }
    encode_der_tlv(0x02, &bytes[start..])
}

/// Encodes an explicit context-specific constructed tag `[ctx_num]` (`0xA0 | ctx_num`) wrapping `inner`.
fn encode_explicit_ctx(ctx_num: u8, inner: &[u8]) -> Vec<u8> {
    encode_der_tlv(0xA0 | (ctx_num & 0x1F), inner)
}

/// Encodes an ASN.1 DER `GeneralString` (`0x1B`) used for Kerberos `Realm` and `KerberosString`.
fn encode_general_string(s: &str) -> Vec<u8> {
    encode_der_tlv(0x1B, s.as_bytes())
}

/// Encodes an RFC 4120 §5.2.2 `PrincipalName ::= SEQUENCE { [0] name-type Int32, [1] name-string SEQUENCE OF KerberosString }`.
fn encode_principal_name(name_type: i64, principal: &str) -> Vec<u8> {
    let mut seq_of_strings = Vec::new();
    for part in principal.split('/') {
        let part_str = if part.is_empty() { principal } else { part };
        seq_of_strings.extend_from_slice(&encode_general_string(part_str));
    }
    let name_type_field = encode_explicit_ctx(0, &encode_der_int(name_type));
    let name_string_seq = encode_der_tlv(0x30, &seq_of_strings);
    let name_string_field = encode_explicit_ctx(1, &name_string_seq);

    let mut body = Vec::with_capacity(name_type_field.len() + name_string_field.len());
    body.extend_from_slice(&name_type_field);
    body.extend_from_slice(&name_string_field);
    encode_der_tlv(0x30, &body)
}

/// Encodes an RFC 4120 §5.2.9 `EncryptedData ::= SEQUENCE { [0] etype Int32, [2] cipher OCTET STRING }`.
fn encode_encrypted_data(etype: i64, cipher: &[u8]) -> Vec<u8> {
    let mut seq = Vec::new();
    seq.extend_from_slice(&encode_explicit_ctx(0, &encode_der_int(etype)));
    seq.extend_from_slice(&encode_explicit_ctx(2, &encode_der_tlv(0x04, cipher)));
    encode_der_tlv(0x30, &seq)
}

/// Encodes an RFC 4120 §5.3 `Ticket ::= [APPLICATION 1] SEQUENCE { [0] tkt-vno (5), [1] realm, [2] sname, [3] enc-part }`.
fn encode_ticket(realm: &str, sname: &str, etype: i64) -> Vec<u8> {
    let mut seq = Vec::new();
    seq.extend_from_slice(&encode_explicit_ctx(0, &encode_der_int(5)));
    seq.extend_from_slice(&encode_explicit_ctx(1, &encode_general_string(realm)));
    seq.extend_from_slice(&encode_explicit_ctx(2, &encode_principal_name(2, sname)));
    seq.extend_from_slice(&encode_explicit_ctx(
        3,
        &encode_encrypted_data(etype, &[0xde, 0xad, 0xbe, 0xef]),
    ));
    let ticket_seq = encode_der_tlv(0x30, &seq);
    encode_der_tlv(0x61, &ticket_seq) // [APPLICATION 1]
}

/// Builds an RFC 4120 Kerberos authentication message payload.
///
/// Syntax mapping: `KERBEROS [AS_REQ | AS_REP | TGS_REQ | TGS_REP | KRB_ERROR] [REALM <str>] [CNAME <str>] [SNAME <str>] [ETYPE <i32>]`
#[doc(alias = "KERBEROS")]
#[doc(alias = "RFC4120")]
#[doc(alias = "AS_REQ")]
#[doc(alias = "AS_REP")]
#[doc(alias = "TGS_REQ")]
#[doc(alias = "TGS_REP")]
#[doc(alias = "KRB_ERROR")]
pub fn build_kerberos_payload(
    _ctx: &WireContext,
    spec: &KerberosSpec,
    payload_bytes: &[u8],
) -> Vec<u8> {
    let msg_type: u8 = if spec.is_as_req {
        10 // AS-REQ ([APPLICATION 10], 0x6A)
    } else if spec.is_as_rep {
        11 // AS-REP ([APPLICATION 11], 0x6B)
    } else if spec.is_tgs_req {
        12 // TGS-REQ ([APPLICATION 12], 0x6C)
    } else if spec.is_tgs_rep {
        13 // TGS-REP ([APPLICATION 13], 0x6D)
    } else if spec.is_krb_error {
        30 // KRB-ERROR ([APPLICATION 30], 0x7E)
    } else {
        10 // Default AS-REQ
    };

    let realm = spec.realm.unwrap_or("CORP.LOCAL");
    let cname = spec.cname.unwrap_or("user");
    let sname = spec.sname.unwrap_or("krbtgt");
    let etype = i64::from(spec.etype.unwrap_or(18)); // 18 = aes256-cts-hmac-sha1-96

    let mut pkt = match msg_type {
        11 | 13 => {
            // KDC-REP (AS-REP 0x6B or TGS-REP 0x6D, RFC 4120 §5.4.2)
            let mut kdc_rep = Vec::new();
            kdc_rep.extend_from_slice(&encode_explicit_ctx(0, &encode_der_int(5))); // [0] pvno (5)
            kdc_rep.extend_from_slice(&encode_explicit_ctx(
                1,
                &encode_der_int(i64::from(msg_type)),
            )); // [1] msg-type
            kdc_rep.extend_from_slice(&encode_explicit_ctx(3, &encode_general_string(realm))); // [3] crealm
            kdc_rep.extend_from_slice(&encode_explicit_ctx(4, &encode_principal_name(1, cname))); // [4] cname
            kdc_rep.extend_from_slice(&encode_explicit_ctx(5, &encode_ticket(realm, sname, etype))); // [5] ticket
            kdc_rep.extend_from_slice(&encode_explicit_ctx(
                6,
                &encode_encrypted_data(etype, &[0xca, 0xfe, 0xba, 0xbe]),
            )); // [6] enc-part
            let seq = encode_der_tlv(0x30, &kdc_rep);
            encode_der_tlv(0x60 | msg_type, &seq)
        }
        30 => {
            // KRB-ERROR ([APPLICATION 30] 0x7E, RFC 4120 §5.9.1)
            let mut err_seq = Vec::new();
            err_seq.extend_from_slice(&encode_explicit_ctx(0, &encode_der_int(5))); // [0] pvno (5)
            err_seq.extend_from_slice(&encode_explicit_ctx(1, &encode_der_int(30))); // [1] msg-type (30)
            err_seq.extend_from_slice(&encode_explicit_ctx(
                4,
                &encode_der_tlv(0x18, b"20261023000000Z"),
            )); // [4] stime GeneralizedTime
            err_seq.extend_from_slice(&encode_explicit_ctx(5, &encode_der_int(0))); // [5] susec
            err_seq.extend_from_slice(&encode_explicit_ctx(6, &encode_der_int(24))); // [6] error-code (KDC_ERR_PREAUTH_FAILED = 24)
            err_seq.extend_from_slice(&encode_explicit_ctx(7, &encode_general_string(realm))); // [7] crealm
            err_seq.extend_from_slice(&encode_explicit_ctx(8, &encode_principal_name(1, cname))); // [8] cname
            err_seq.extend_from_slice(&encode_explicit_ctx(9, &encode_general_string(realm))); // [9] realm
            err_seq.extend_from_slice(&encode_explicit_ctx(10, &encode_principal_name(2, sname))); // [10] sname
            let seq = encode_der_tlv(0x30, &err_seq);
            encode_der_tlv(0x7E, &seq)
        }
        _ => {
            // KDC-REQ (AS-REQ 0x6A or TGS-REQ 0x6C, RFC 4120 §5.4.1)
            let mut req_body = Vec::new();
            // [0] kdc-options KerberosFlags (32-bit BIT STRING)
            req_body.extend_from_slice(&encode_explicit_ctx(
                0,
                &encode_der_tlv(0x03, &[0x00, 0x40, 0x81, 0x00, 0x10]),
            ));
            // [1] cname PrincipalName
            req_body.extend_from_slice(&encode_explicit_ctx(1, &encode_principal_name(1, cname)));
            // [2] realm Realm (GeneralString)
            req_body.extend_from_slice(&encode_explicit_ctx(2, &encode_general_string(realm)));
            // [3] sname PrincipalName
            req_body.extend_from_slice(&encode_explicit_ctx(3, &encode_principal_name(2, sname)));
            // [7] till KerberosTime (GeneralizedTime)
            req_body.extend_from_slice(&encode_explicit_ctx(
                7,
                &encode_der_tlv(0x18, b"20370913024805Z"),
            ));
            // [8] nonce UInt32
            req_body.extend_from_slice(&encode_explicit_ctx(8, &encode_der_int(0x1234_5678)));
            // [9] etype SEQUENCE OF Int32
            let etype_seq = encode_der_tlv(0x30, &encode_der_int(etype));
            req_body.extend_from_slice(&encode_explicit_ctx(9, &etype_seq));

            let req_body_seq = encode_der_tlv(0x30, &req_body);

            let mut kdc_req = Vec::new();
            kdc_req.extend_from_slice(&encode_explicit_ctx(1, &encode_der_int(5))); // [1] pvno (5)
            kdc_req.extend_from_slice(&encode_explicit_ctx(
                2,
                &encode_der_int(i64::from(msg_type)),
            )); // [2] msg-type (10 or 12)
            kdc_req.extend_from_slice(&encode_explicit_ctx(4, &req_body_seq)); // [4] req-body

            let seq = encode_der_tlv(0x30, &kdc_req);
            encode_der_tlv(0x60 | msg_type, &seq)
        }
    };

    if !payload_bytes.is_empty() {
        pkt.extend_from_slice(payload_bytes);
    }
    pkt
}
