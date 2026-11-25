//! Lightweight Directory Access Protocol v3 (LDAP, RFC 4511) ASN.1 BER wire payload builder.
//!
//! This module implements [`build_ldap_payload`], which encodes an [`LdapSpec`] AST specification
//! into an RFC 4511 `LDAPMessage` ASN.1 BER `SEQUENCE` (`0x30`) over TCP or UDP port 389 (or TCP
//! 636 for LDAPS). Each message encodes the signed `messageID` (`i32`) and multi-byte BER lengths
//! (`> 127`) across `BindRequest` (`0x60`), `BindResponse` (`0x61`), `SearchRequest` (`0x63` with
//! RFC 4515 filter parsing for `and`, `or`, `not`, `equalityMatch`, `substrings`, and `present`),
//! `SearchResultEntry` (`0x64`), `SearchResultDone` (`0x65`), and `UnbindRequest` (`0x42`).

use crate::ast::*;
use crate::builders::WireContext;
use alloc::vec::Vec;

/// Maximum recursive nesting depth permitted when parsing RFC 4515 LDAP filter strings.
const MAX_LDAP_FILTER_DEPTH: usize = 32;

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
    } else if len <= 0xFF_FFFF {
        out.push(0x83);
        out.push((len >> 16) as u8);
        out.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        out.push(0x84);
        out.extend_from_slice(&(u32::try_from(len).unwrap_or(u32::MAX)).to_be_bytes());
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

/// Strips one balanced outer `(...)` pair if the opening parenthesis matches the final closing parenthesis.
fn strip_outer_parens(s: &str) -> &str {
    let t = s.trim();
    if t.starts_with('(') && t.ends_with(')') {
        let mut depth = 0usize;
        for (idx, ch) in t.char_indices() {
            match ch {
                '(' => depth += 1,
                ')' => {
                    depth = depth.saturating_sub(1);
                    if depth == 0 {
                        if idx + ch.len_utf8() == t.len() {
                            return t[1..t.len() - 1].trim();
                        }
                        return t;
                    }
                }
                _ => {}
            }
        }
    }
    t
}

/// Collects top-level balanced `(...)` filter children following `&`, `|`, or `!`.
fn split_balanced_filter_children(s: &str) -> Vec<&str> {
    let mut children = Vec::new();
    let mut depth = 0usize;
    let mut start_idx: Option<usize> = None;
    for (idx, ch) in s.char_indices() {
        match ch {
            '(' => {
                if depth == 0 {
                    start_idx = Some(idx);
                }
                depth += 1;
            }
            ')' if depth > 0 => {
                depth -= 1;
                if depth == 0
                    && let Some(start) = start_idx.take()
                {
                    children.push(&s[start..idx + 1]);
                }
            }
            _ => {}
        }
    }
    children
}

/// Encodes an RFC 4515 LDAP search filter string into ASN.1 BER `Filter` TLVs (`0xA0..=0xA8`, `0x87`).
fn encode_ldap_filter(out: &mut Vec<u8>, raw: &str, depth: usize) {
    let inner = strip_outer_parens(raw);
    if inner.is_empty() || depth >= MAX_LDAP_FILTER_DEPTH {
        push_ber_tlv(out, 0x87, b"objectClass");
        return;
    }

    if let Some(rest) = inner.strip_prefix('&') {
        let children = split_balanced_filter_children(rest);
        if !children.is_empty() {
            let mut body = Vec::new();
            for child in children {
                encode_ldap_filter(&mut body, child, depth + 1);
            }
            push_ber_tlv(out, 0xA0, &body); // and [0] SET OF Filter
            return;
        }
    } else if let Some(rest) = inner.strip_prefix('|') {
        let children = split_balanced_filter_children(rest);
        if !children.is_empty() {
            let mut body = Vec::new();
            for child in children {
                encode_ldap_filter(&mut body, child, depth + 1);
            }
            push_ber_tlv(out, 0xA1, &body); // or [1] SET OF Filter
            return;
        }
    } else if let Some(rest) = inner.strip_prefix('!') {
        let children = split_balanced_filter_children(rest);
        if let Some(first) = children.first() {
            let mut body = Vec::new();
            encode_ldap_filter(&mut body, first, depth + 1);
            push_ber_tlv(out, 0xA2, &body); // not [2] Filter
            return;
        }
    }

    for (op, tag) in [(">=", 0xA5u8), ("<=", 0xA6u8), ("~=", 0xA8u8)] {
        if let Some((attr, val)) = inner.split_once(op) {
            let attr = attr.trim();
            let val = val.trim();
            if !attr.is_empty() {
                let mut ava = Vec::new();
                push_ber_tlv(&mut ava, 0x04, attr.as_bytes());
                push_ber_tlv(&mut ava, 0x04, val.as_bytes());
                push_ber_tlv(out, tag, &ava);
                return;
            }
        }
    }

    if let Some((attr, val)) = inner.split_once('=') {
        let attr = attr.trim();
        let val = val.trim();
        let attr_bytes = if attr.is_empty() {
            b"objectClass"
        } else {
            attr.as_bytes()
        };
        if val == "*" {
            push_ber_tlv(out, 0x87, attr_bytes); // present [7] AttributeDescription
            return;
        }
        if val.contains('*') {
            let parts: Vec<&str> = val.split('*').collect();
            let mut subs = Vec::new();
            if let Some(&first) = parts.first()
                && !first.is_empty()
            {
                push_ber_tlv(&mut subs, 0x80, first.as_bytes()); // initial [0]
            }
            if parts.len() > 2 {
                for &mid in &parts[1..parts.len() - 1] {
                    if !mid.is_empty() {
                        push_ber_tlv(&mut subs, 0x81, mid.as_bytes()); // any [1]
                    }
                }
            }
            if parts.len() >= 2
                && let Some(&last) = parts.last()
                && !last.is_empty()
            {
                push_ber_tlv(&mut subs, 0x82, last.as_bytes()); // final [2]
            }
            if subs.is_empty() {
                push_ber_tlv(out, 0x87, attr_bytes);
                return;
            }
            let mut sub_body = Vec::new();
            push_ber_tlv(&mut sub_body, 0x04, attr_bytes);
            push_ber_tlv(&mut sub_body, 0x30, &subs);
            push_ber_tlv(out, 0xA4, &sub_body); // substrings [4] SubstringFilter
            return;
        }
        let mut ava = Vec::new();
        push_ber_tlv(&mut ava, 0x04, attr_bytes);
        push_ber_tlv(&mut ava, 0x04, val.as_bytes());
        push_ber_tlv(out, 0xA3, &ava); // equalityMatch [3] AttributeValueAssertion
        return;
    }

    push_ber_tlv(out, 0x87, inner.as_bytes());
}

/// Builds an RFC 4511 LDAP directory protocol message payload.
///
/// Syntax mapping: `ldap [msgid <i32>] [bindreq | bindres | searchreq | searchentry | searchdone | unbindreq] [basedn <str>] [filter <str>] [resultcode <u32>]`
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
    let msgid = i64::from(spec.msgid.unwrap_or(1));
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

            // 7. filter Filter (equalityMatch 0xA3, and 0xA0, or 0xA1, substrings 0xA4, present 0x87)
            encode_ldap_filter(&mut inner, spec.filter.unwrap_or("objectClass"), 0);

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
