//! Web Services Dynamic Discovery (`wsdiscovery`, OASIS 1.1 SOAP-over-UDP) Layer 7 PCAP-to-`.frasm` decompiler.
//!
//! This module implements the fuzz-safe reverse dissector for OASIS WS-Discovery SOAP 1.2 /
//! WS-Addressing XML discovery datagrams carried over UDP or SCTP port `3702`. It recognizes
//! `Probe`, `ProbeMatches`, `Hello`, `Bye`, `Resolve`, and `ResolveMatches` actions, extracts
//! `msgid`, `types`, `scopes`, `xaddrs`, and `addr` values while unescaping XML entities and
//! eliding canonical defaults, and preserves trailing bytes in `residual_payload`.

use alloc::format;
use alloc::string::String;
use core::fmt::Write as _;

use crate::ast::{Protocol, TransportProto};
use crate::reverse::{ProtocolDissection, sd};

use super::{find_subslice, is_valid_raw_string_body, push_str_mod};

/// Default WS-Addressing `MessageID` URI elided during reverse dissection.
const DEFAULT_WSD_MSGID: &str = "urn:uuid:00000000-0000-0000-0000-000000000001";

/// Default WS-Addressing `EndpointReference/Address` URI elided during reverse dissection.
const DEFAULT_WSD_ADDR: &str = "urn:uuid:00000000-0000-0000-0000-000000000002";

/// Default WS-Discovery device `Types` QName elided during reverse dissection.
const DEFAULT_WSD_TYPES: &str = "wsdp:Device";

/// Default WS-Discovery `XAddrs` transport URL elided during reverse dissection.
const DEFAULT_WSD_XADDRS: &str = "http://127.0.0.1:5357/ws";

/// Unescapes standard XML character entities (`&amp;`, `&lt;`, `&gt;`).
fn unescape_xml_text(s: &str) -> String {
    s.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&amp;", "&")
}

/// Extracts the inner text of the first XML element matching `<*:local_tag>` or `<local_tag>`.
fn extract_xml_tag_text<'a>(xml: &'a str, local_tag: &str) -> Option<&'a str> {
    let mut search_from = 0usize;
    while let Some(rel_lt) = xml.get(search_from..)?.find('<') {
        let open_start = search_from + rel_lt;
        let after_lt = xml.get(open_start + 1..)?;
        let close_gt_rel = after_lt.find('>')?;
        let tag_header = after_lt.get(..close_gt_rel)?;
        let tag_name = tag_header.split_whitespace().next().unwrap_or("");
        let matches_local = tag_name == local_tag
            || tag_name
                .split_once(':')
                .is_some_and(|(_, local)| local == local_tag);
        if matches_local && !tag_header.ends_with('/') {
            let content_start = open_start + 1 + close_gt_rel + 1;
            let close_pat = format!("</{tag_name}>");
            if let Some(rel_end) = xml.get(content_start..)?.find(&close_pat) {
                return xml.get(content_start..content_start + rel_end);
            }
        }
        search_from = open_start + 1 + close_gt_rel + 1;
    }
    None
}

/// Dissects an OASIS WS-Discovery SOAP-over-UDP datagram on UDP or SCTP port `3702`.
pub(crate) fn dissect_wsdiscovery(
    transport: TransportProto,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Option<ProtocolDissection> {
    let on_wsd_port = src_port == 3702 || dst_port == 3702;
    let has_wsd_ns = find_subslice(payload, b"docs.oasis-open.org/ws-dd/ns/discovery").is_some()
        || find_subslice(payload, b"schemas.xmlsoap.org/ws/2005/04/discovery").is_some();
    if !matches!(transport, TransportProto::Udp | TransportProto::Sctp)
        || (!on_wsd_port && !has_wsd_ns)
        || !has_wsd_ns
    {
        return None;
    }

    let env_end = find_subslice(payload, b"</s:Envelope>")
        .map(|i| i + "</s:Envelope>".len())
        .or_else(|| find_subslice(payload, b"</soap:Envelope>").map(|i| i + "</soap:Envelope>".len()))
        .or_else(|| find_subslice(payload, b"</Envelope>").map(|i| i + "</Envelope>".len()))?;

    let xml = core::str::from_utf8(payload.get(..env_end)?).ok()?;
    let trailing = payload.get(env_end..)?.to_vec();

    let action_uri = extract_xml_tag_text(xml, "Action")?.trim();
    let action_kw = match action_uri.rsplit('/').next()? {
        "Probe" => "probe",
        "ProbeMatches" => "probematches",
        "Hello" => "hello",
        "Bye" => "bye",
        "Resolve" => "resolve",
        "ResolveMatches" => "resolvematches",
        _ => return None,
    };

    let mut tokens = String::from("wsdiscovery");
    match action_kw {
        "probe" => {}
        "hello" => tokens.push_str(" hello"),
        other => {
            let _ = write!(tokens, " msgtype \"{other}\"");
        }
    }

    if let Some(raw_msgid) = extract_xml_tag_text(xml, "MessageID") {
        let msgid = unescape_xml_text(raw_msgid.trim());
        if msgid != DEFAULT_WSD_MSGID && is_valid_raw_string_body(&msgid) {
            push_str_mod(&mut tokens, "msgid", &msgid);
        }
    }
    if let Some(raw_types) = extract_xml_tag_text(xml, "Types") {
        let types = unescape_xml_text(raw_types.trim());
        if types != DEFAULT_WSD_TYPES && is_valid_raw_string_body(&types) {
            push_str_mod(&mut tokens, "types", &types);
        }
    }
    if let Some(raw_scopes) = extract_xml_tag_text(xml, "Scopes") {
        let scopes = unescape_xml_text(raw_scopes.trim());
        if is_valid_raw_string_body(&scopes) {
            push_str_mod(&mut tokens, "scopes", &scopes);
        }
    }
    if let Some(raw_xaddrs) = extract_xml_tag_text(xml, "XAddrs") {
        let xaddrs = unescape_xml_text(raw_xaddrs.trim());
        if xaddrs != DEFAULT_WSD_XADDRS && is_valid_raw_string_body(&xaddrs) {
            push_str_mod(&mut tokens, "xaddrs", &xaddrs);
        }
    }
    if let Some(raw_addr) = extract_xml_tag_text(xml, "Address") {
        let addr = unescape_xml_text(raw_addr.trim());
        if addr != DEFAULT_WSD_ADDR && is_valid_raw_string_body(&addr) {
            push_str_mod(&mut tokens, "addr", &addr);
        }
    }

    Some(sd(Protocol::Wsdiscovery, tokens, trailing))
}
