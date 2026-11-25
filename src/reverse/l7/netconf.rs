//! Network Configuration Protocol (`netconf`, RFC 6241 / RFC 6242) Layer 7 PCAP-to-`.frasm` decompiler.
//!
//! This module implements the fuzz-safe reverse dissector for RFC 6241 and RFC 6242 `netconf`
//! XML framing streams over TCP port `830` (and signature-matched custom ports). It handles both
//! Section 4.3 `]]>]]>` end-of-message framing and Section 4.2 chunked `\n#<len>\n...\n##\n`
//! framing, decodes `<hello>`, `<rpc>`, `<rpc-reply>`, and `<notification>` envelopes alongside
//! `msgid`, `sessionid`, `capability`, `operation`, and custom XML `body` attributes using
//! `quote_raw_str`, and preserves trailing bytes in `residual_payload`.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write as _;

use crate::ast::Protocol;
use crate::reverse::ProtocolDissection;

use super::{find_subslice, is_printable_ascii_str, ok_dissect, push_str_if, quote_raw_str};

/// XML declaration prefix synthesized by the forward `netconf` builder.
const XML_DECL: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n";

/// Canonical NETCONF base 1.0 capability URN.
const DEFAULT_NETCONF_CAP: &str = "urn:ietf:params:netconf:base:1.0";

/// Unframes RFC 6242 chunked (`\n#<len>\n...\n##\n`) or EOM (`]]>]]>`) NETCONF framing.
fn unframe_netconf(payload: &[u8]) -> Option<(&str, bool, Vec<u8>)> {
    if let Some(after_hash) = payload.strip_prefix(b"\n#") {
        let lf = after_hash.iter().position(|&b| b == b'\n')?;
        let len_str = core::str::from_utf8(after_hash.get(..lf)?).ok()?;
        if len_str.is_empty() || !len_str.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        let xml_len = len_str.parse::<usize>().ok()?;
        let xml_start = 2usize.checked_add(lf)?.checked_add(1)?;
        let xml_end = xml_start.checked_add(xml_len)?;
        let xml_bytes = payload.get(xml_start..xml_end)?;
        let rest = payload.get(xml_end..)?;
        let trailing = rest.strip_prefix(b"\n##\n")?;
        let xml_str = core::str::from_utf8(xml_bytes).ok()?;
        return Some((xml_str, true, trailing.to_vec()));
    }

    let eom_pos = find_subslice(payload, b"]]>]]>")?;
    let xml_str = core::str::from_utf8(payload.get(..eom_pos)?).ok()?;
    let trailing = payload.get(eom_pos + 6..)?.to_vec();
    Some((xml_str, false, trailing))
}

/// Extracts an exact XML tag pair `open ... close` and returns the inner slice.
fn extract_between<'a>(s: &'a str, open: &str, close: &str) -> Option<&'a str> {
    let start = s.find(open)? + open.len();
    let tail = s.get(start..)?;
    let end = tail.find(close)?;
    tail.get(..end)
}

/// Decodes a canonical `<rpc>` inner XML fragment back into an `operation` keyword when matched.
fn decode_rpc_operation(inner: &str) -> Option<&str> {
    match inner {
        "<get-config><source><running/></source></get-config>" => Some("get-config"),
        "<get/>" => Some("get"),
        "<edit-config><target><running/></target></edit-config>" => Some("edit-config"),
        "<lock><target><running/></target></lock>" => Some("lock"),
        "<unlock><target><running/></target></unlock>" => Some("unlock"),
        "<close-session/>" => Some("close-session"),
        _ => {
            let trimmed = inner.strip_prefix('<')?.strip_suffix("/>")?;
            (!trimmed.is_empty()
                && !trimmed.contains(['<', '>', ' ', '"', '\\']))
            .then_some(trimmed)
        }
    }
}

/// Dissects an RFC 6241 / RFC 6242 `netconf` message on TCP port `830` or by NETCONF XML signature.
pub(crate) fn dissect_netconf(payload: &[u8]) -> Option<ProtocolDissection> {
    let (raw_xml, chunked, residual) = unframe_netconf(payload)?;
    let xml = raw_xml.strip_prefix(XML_DECL)?;

    let mut tokens = String::from("netconf");
    if let Some(body_xml) = xml
        .strip_prefix("<hello xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">")
        .and_then(|s| s.strip_suffix("</hello>"))
    {
        let caps_inner = extract_between(body_xml, "<capabilities>", "</capabilities>")?;
        let cap = extract_between(caps_inner, "<capability>", "</capability>")?;
        let after_caps_idx = body_xml.find("</capabilities>")? + "</capabilities>".len();
        let mut rem = body_xml.get(after_caps_idx..)?;
        let mut session_id: Option<u32> = None;
        if let Some(after_sid_open) = rem.strip_prefix("<session-id>") {
            let sid_end = after_sid_open.find("</session-id>")?;
            session_id = after_sid_open.get(..sid_end)?.parse::<u32>().ok();
            rem = after_sid_open.get(sid_end + "</session-id>".len()..)?;
        }
        if let Some(sid) = session_id {
            let _ = write!(tokens, " sessionid {sid}");
        }
        push_str_if(&mut tokens, "capability", cap, DEFAULT_NETCONF_CAP);
        if !rem.is_empty() {
            let clean = is_printable_ascii_str(rem.as_bytes())?;
            let _ = write!(tokens, " body \"{}\"", quote_raw_str(clean));
        }
    } else if let Some(after_prefix) = xml.strip_prefix("<rpc message-id=\"") {
        let q_end = after_prefix.find('"')?;
        let msg_id = after_prefix.get(..q_end)?;
        let rest = after_prefix
            .get(q_end + 1..)?
            .strip_prefix(" xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">")?
            .strip_suffix("</rpc>")?;
        tokens.push_str(" rpc");
        push_str_if(&mut tokens, "msgid", msg_id, "101");
        if let Some(op) = decode_rpc_operation(rest) {
            push_str_if(&mut tokens, "operation", op, "get-config");
        } else {
            let clean = is_printable_ascii_str(rest.as_bytes())?;
            let _ = write!(tokens, " body \"{}\"", quote_raw_str(clean));
        }
    } else if let Some(after_prefix) = xml.strip_prefix("<rpc-reply message-id=\"") {
        let q_end = after_prefix.find('"')?;
        let msg_id = after_prefix.get(..q_end)?;
        let rest = after_prefix
            .get(q_end + 1..)?
            .strip_prefix(" xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">")?
            .strip_suffix("</rpc-reply>")?;
        tokens.push_str(" rpcreply");
        push_str_if(&mut tokens, "msgid", msg_id, "101");
        if rest != "<ok/>" {
            let clean = is_printable_ascii_str(rest.as_bytes())?;
            let _ = write!(tokens, " body \"{}\"", quote_raw_str(clean));
        }
    } else {
        let rest = xml
            .strip_prefix("<notification xmlns=\"urn:ietf:params:xml:ns:netconf:notification:1.0\">")
            .and_then(|s| s.strip_suffix("</notification>"))?;
        tokens.push_str(" notification");
        if rest != "<eventTime>2026-10-23T00:00:00Z</eventTime>" {
            let clean = is_printable_ascii_str(rest.as_bytes())?;
            let _ = write!(tokens, " body \"{}\"", quote_raw_str(clean));
        }
    }

    if chunked {
        tokens.push_str(" chunked");
    }

    ok_dissect(Protocol::Netconf, tokens, residual)
}
