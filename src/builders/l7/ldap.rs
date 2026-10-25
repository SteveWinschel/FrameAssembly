//! Lightweight Directory Access Protocol v3 (LDAP, RFC 4511) ASN.1 BER wire payload builder.
//!
//! This module implements [`build_ldap_payload`], which encodes an [`LdapSpec`]
//! AST specification into an RFC 4511 `LDAPMessage` ASN.1 BER `SEQUENCE` (`0x30`) over TCP or UDP
//! port 389 (or TCP 636 for LDAPS). Each message encodes the integer `messageID` followed by the
//! selected protocol operation (`BindRequest` `0x60`, `BindResponse` `0x61`, `SearchRequest`
//! `0x63`, `SearchResultEntry` `0x64`, `SearchResultDone` `0x65`, or `UnbindRequest` `0x42`),
//! Distinguished Name (`BASE_DN`), filter string (`FILTER`), and result code (`RESULT_CODE`).

use crate::ast::*;
use crate::builders::WireContext;
use alloc::vec::Vec;

/// Appends an ASN.1 BER definite-length field (`short` form `< 128`, `long` form `>= 128`).
fn push_ber_length(out: &mut Vec<u8>, len: usize) {
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

/// Appends an ASN.1 BER TLV with the given `tag` and `content` slice.
fn push_ber_tlv(out: &mut Vec<u8>, tag: u8, content: &[u8]) {
    out.push(tag);
    push_ber_length(out, content.len());
    out.extend_from_slice(content);
}

/// Appends a minimal two's-complement ASN.1 BER `INTEGER` (`0x02`) or `ENUMERATED` (`0x0A`) TLV.
fn push_ber_int_with_tag(out: &mut Vec<u8>, tag: u8, val: i64) {
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
    push_ber_tlv(out, tag, &bytes[start..]);
}

/// Builds an RFC 4511 LDAP directory protocol message payload.
///
/// Syntax mapping: `LDAP [MSGID <i32>] [BIND_REQ | BIND_RES | SEARCH_REQ | SEARCH_ENTRY | SEARCH_DONE | UNBIND_REQ] [BASE_DN <str>] [FILTER <str>] [RESULT_CODE <u32>]`
#[doc(alias = "LDAP")]
#[doc(alias = "RFC4511")]
#[doc(alias = "MSGID")]
#[doc(alias = "BASE_DN")]
#[doc(alias = "FILTER")]
#[doc(alias = "RESULT_CODE")]
pub fn build_ldap_payload(
    _ctx: &WireContext,
    spec: &LdapSpec,
    payload_bytes: &[u8],
) -> Vec<u8> {
    let msgid = i64::from(spec.msgid.unwrap_or(1).max(0));
    let op_tag: u8 = if spec.is_bind_req {
        0x60 // BindRequest [APPLICATION 0]
    } else if spec.is_bind_res {
        0x61 // BindResponse [APPLICATION 1]
    } else if spec.is_search_req {
        0x63 // SearchRequest [APPLICATION 3]
    } else if spec.is_search_entry {
        0x64 // SearchResultEntry [APPLICATION 4]
    } else if spec.is_search_done {
        0x65 // SearchResultDone [APPLICATION 5]
    } else if spec.is_unbind_req {
        0x42 // UnbindRequest [APPLICATION 2] IMPLICIT NULL
    } else if spec.filter.is_some() {
        0x63 // Implied SearchRequest when FILTER is provided
    } else if spec.result_code.is_some() {
        0x61 // Implied BindResponse when RESULT_CODE is provided
    } else {
        0x60 // Default BindRequest [APPLICATION 0]
    };

    let mut op_body = Vec::new();
    match op_tag {
        0x42 => {
            // UnbindRequest ::= [APPLICATION 2] IMPLICIT NULL (RFC 4511 §4.3)
            op_body.extend_from_slice(&[0x42, 0x00]);
        }
        0x61 | 0x65 => {
            // BindResponse (0x61) or SearchResultDone (0x65) ::= [APPLICATION 1|5] LDAPResult
            let mut inner = Vec::new();
            let result_code = i64::from(spec.result_code.unwrap_or(0));
            let matched_dn = spec.base_dn.unwrap_or("");
            push_ber_int_with_tag(&mut inner, 0x0A, result_code); // 1. resultCode ENUMERATED
            push_ber_tlv(&mut inner, 0x04, matched_dn.as_bytes()); // 2. matchedDN LDAPDN
            push_ber_tlv(&mut inner, 0x04, b""); // 3. diagnosticMessage LDAPString
            push_ber_tlv(&mut op_body, op_tag, &inner);
        }
        0x63 => {
            // SearchRequest ::= [APPLICATION 3] SEQUENCE (all 8 mandatory RFC 4511 §4.5.1 fields)
            let mut inner = Vec::new();
            let base_dn = spec.base_dn.unwrap_or("dc=corp,dc=local");
            push_ber_tlv(&mut inner, 0x04, base_dn.as_bytes()); // 1. baseObject LDAPDN
            push_ber_int_with_tag(&mut inner, 0x0A, 2); // 2. scope ENUMERATED (wholeSubtree = 2)
            push_ber_int_with_tag(&mut inner, 0x0A, 0); // 3. derefAliases ENUMERATED (never = 0)
            push_ber_int_with_tag(&mut inner, 0x02, 0); // 4. sizeLimit INTEGER (0)
            push_ber_int_with_tag(&mut inner, 0x02, 0); // 5. timeLimit INTEGER (0)
            inner.extend_from_slice(&[0x01, 0x01, 0x00]); // 6. typesOnly BOOLEAN (FALSE)

            // 7. filter Filter (Present [7] IMPLICIT AttributeDescription, tag 0x87)
            let raw_filter = spec.filter.unwrap_or("objectClass");
            let trimmed = raw_filter
                .trim()
                .trim_start_matches('(')
                .trim_end_matches(')');
            let attr_name = trimmed.strip_suffix("=*").unwrap_or(trimmed);
            let filter_bytes = if attr_name.is_empty() {
                b"objectClass"
            } else {
                attr_name.as_bytes()
            };
            push_ber_tlv(&mut inner, 0x87, filter_bytes);

            // 8. attributes AttributeSelection (SEQUENCE OF LDAPString)
            push_ber_tlv(&mut inner, 0x30, &[]);

            push_ber_tlv(&mut op_body, 0x63, &inner);
        }
        0x64 => {
            // SearchResultEntry ::= [APPLICATION 4] SEQUENCE { objectName, attributes } (RFC 4511 §4.5.2)
            let mut inner = Vec::new();
            let object_name = spec.base_dn.unwrap_or("dc=corp,dc=local");
            push_ber_tlv(&mut inner, 0x04, object_name.as_bytes()); // 1. objectName LDAPDN
            push_ber_tlv(&mut inner, 0x30, &[]); // 2. attributes PartialAttributeList
            push_ber_tlv(&mut op_body, 0x64, &inner);
        }
        _ => {
            // BindRequest ::= [APPLICATION 0] SEQUENCE { version, name, authentication } (RFC 4511 §4.2)
            let mut inner = Vec::new();
            let bind_dn = spec.base_dn.unwrap_or("dc=corp,dc=local");
            push_ber_int_with_tag(&mut inner, 0x02, 3); // 1. version INTEGER (3)
            push_ber_tlv(&mut inner, 0x04, bind_dn.as_bytes()); // 2. name LDAPDN
            push_ber_tlv(&mut inner, 0x80, b""); // 3. authentication Simple [0] IMPLICIT OCTET STRING
            push_ber_tlv(&mut op_body, 0x60, &inner);
        }
    }

    let mut msg = Vec::new();
    push_ber_int_with_tag(&mut msg, 0x02, msgid); // messageID INTEGER
    msg.extend_from_slice(&op_body);

    let mut pkt = Vec::new();
    push_ber_tlv(&mut pkt, 0x30, &msg); // Top-level LDAPMessage SEQUENCE

    if !payload_bytes.is_empty() {
        pkt.extend_from_slice(payload_bytes);
    }
    pkt
}
