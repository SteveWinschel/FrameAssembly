//! Session Initiation Protocol (SIP) (RFC 3261 / RFC 3262 (PRACK) / RFC 3428 (MESSAGE) / RFC 4566 (SDP)) Layer 7 wire packet builder.
//!
//! This module synthesizes deterministic on-the-wire Session Initiation Protocol (SIP) frames over UDP/TCP port 5060 (SIP) and TCP/TLS port 5061 (SIPS).
//! The wire encoder constructs a UTF-8 text signaling message starting with a Request-Line (`<METHOD> <URI> SIP/2.0\r\n` for `INVITE`, `ACK`, `BYE`, `CANCEL`, `REGISTER`, `OPTIONS`, `MESSAGE`) or Status-Line (`SIP/2.0 <STATUS> <REASON>\r\n` e.g. `100 Trying`, `180 Ringing`, `200 OK`, `401 Unauthorized`, `486 Busy Here`), followed by `Via:`, `From:`, `To:`, `Call-ID:`, `CSeq:`, `Contact:`, `Content-Type:`, `Content-Length:`, and optional `application/sdp` body. When optional fields in [`SipSpec`]
//! are omitted in the `.frasm` source, RFC-compliant default values are automatically populated.
//!
//! Canonical `.frasm` syntax:
//! `a -> b sip [invite | bye | cancel | method <str>] [uri <str>] [status <u16>] [reason <str>] [from <str>] [to <str>] [callid <str>] [cseq <u32>] [via <str>] [contact <str>] [contenttype <str>] [body <str>] [transport tcp]`

use crate::ast::*;
use crate::builders::WireContext;
use alloc::vec::Vec;

/// Brackets bare IPv6 host literals inside a SIP URI (`sip:alice@2001:db8::1` -> `sip:alice@[2001:db8::1]`).
fn bracket_sip_ipv6_uri(val: &str) -> String {
    if let Some((prefix, host_part)) = val.rsplit_once('@') {
        if !host_part.starts_with('[') && host_part.parse::<core::net::Ipv6Addr>().is_ok() {
            return format!("{prefix}@[{host_part}]");
        }
    } else if let Some(rest) = val.strip_prefix("sip:") {
        if !rest.starts_with('[') && rest.parse::<core::net::Ipv6Addr>().is_ok() {
            return format!("sip:[{rest}]");
        }
    } else if let Some(rest) = val.strip_prefix("sips:")
        && !rest.starts_with('[')
        && rest.parse::<core::net::Ipv6Addr>().is_ok()
    {
        return format!("sips:[{rest}]");
    }
    val.to_string()
}

/// Formats a SIP address header (`From` / `To`), bracketing IPv6 literals and appending `;tag=...` when required.
fn format_sip_addr_header(raw: &str, default_tag: Option<&str>) -> String {
    let base = if let Some(open) = raw.find('<')
        && let Some(rel_close) = raw[open + 1..].find('>')
    {
        let close = open + 1 + rel_close;
        let inner = bracket_sip_ipv6_uri(&raw[open + 1..close]);
        format!("{}{inner}{}", &raw[..open + 1], &raw[close..])
    } else if let Some((uri_part, params)) = raw.split_once(';') {
        format!("<{}>;{params}", bracket_sip_ipv6_uri(uri_part))
    } else {
        format!("<{}>", bracket_sip_ipv6_uri(raw))
    };
    if let Some(tag) = default_tag
        && !base.contains(";tag=")
    {
        format!("{base};tag={tag}")
    } else {
        base
    }
}

/// Formats a `Via` header value, ensuring RFC 3261 `branch=z9hG4bK` and IPv6 host bracketing.
fn format_sip_via_header(ctx: &WireContext, spec_via: Option<&str>, tp_str: &str) -> String {
    let src_host = match ctx.src_ip {
        core::net::IpAddr::V4(v4) => v4.to_string(),
        core::net::IpAddr::V6(v6) => format!("[{v6}]"),
    };
    if let Some(via) = spec_via {
        let mut formatted = via.to_string();
        if !formatted.contains('[')
            && let Some((proto_part, host_rest)) = formatted.split_once(' ')
        {
            let (host_part, params) = host_rest.split_once(';').unwrap_or((host_rest, ""));
            if host_part.parse::<core::net::Ipv6Addr>().is_ok() {
                formatted = if params.is_empty() {
                    format!("{proto_part} [{host_part}]")
                } else {
                    format!("{proto_part} [{host_part}];{params}")
                };
            }
        }
        if !formatted.contains(";branch=") {
            formatted.push_str(";branch=z9hG4bK-1");
        }
        formatted
    } else {
        format!("SIP/2.0/{tp_str} {src_host}:5060;branch=z9hG4bK-1")
    }
}

/// Appends optional `Contact`, `Content-Type`, matching `Content-Length`, and body bytes to a SIP message.
fn finalize_sip_message(
    mut out: String,
    spec: &SipSpec,
    payload_bytes: &[u8],
) -> Vec<u8> {
    if let Some(contact) = spec.contact {
        let c_hdr = format_sip_addr_header(contact, None);
        out.push_str(&format!("Contact: {c_hdr}\r\n"));
    }
    let body_slice = spec.body.map(str::as_bytes).unwrap_or(&[]);
    let total_len = body_slice.len() + payload_bytes.len();

    if let Some(ct) = spec.content_type {
        out.push_str(&format!("Content-Type: {ct}\r\n"));
    } else if !payload_bytes.is_empty() || spec.body.is_some_and(|b| b.starts_with("v=0")) {
        out.push_str("Content-Type: application/sdp\r\n");
    }

    out.push_str(&format!("Content-Length: {total_len}\r\n\r\n"));
    let mut bytes = out.into_bytes();
    if !body_slice.is_empty() {
        bytes.extend_from_slice(body_slice);
    }
    if !payload_bytes.is_empty() {
        bytes.extend_from_slice(payload_bytes);
    }
    bytes
}

/// Builds an RFC 3261 SIP VoIP message string.
/// Syntax mapping: `sip [invite | bye | cancel | method <str>] [uri <str>] [status <u16>] [reason <str>] [from <str>] [to <str>] [callid <str>] [cseq <u32>] [via <str>] [contact <str>] [contenttype <str>] [body <str>] [transport tcp]`
#[doc(alias = "SIP")]
#[doc(alias = "VOIP")]
#[doc(alias = "RFC3261")]
#[doc(alias = "INVITE")]
#[doc(alias = "CALL_ID")]
#[doc(alias = "CSEQ")]
pub fn build_sip_payload(
    ctx: &WireContext,
    spec: &SipSpec,
    payload_bytes: &[u8],
) -> Vec<u8> {
    let mut out = String::new();
    let call_id = spec.call_id.unwrap_or("call123@pbx");
    let cseq = spec.cseq.unwrap_or(1);
    let cseq_method = spec.method.unwrap_or("INVITE");
    let tp_str = match ctx.transport {
        Some(TransportProto::Tcp) => "TCP",
        Some(TransportProto::Sctp) => "SCTP",
        _ => "UDP",
    };
    let via = format_sip_via_header(ctx, spec.via, tp_str);
    let from_hdr = format_sip_addr_header(spec.from.unwrap_or("sip:alice@pbx"), Some("1"));
    let to_raw = spec.to.unwrap_or("sip:bob@pbx");

    if let Some(status) = spec.status {
        let reason = spec.reason.unwrap_or("OK");
        let to_hdr = format_sip_addr_header(to_raw, Some("2"));
        out.push_str(&format!(
            "SIP/2.0 {status} {reason}\r\nVia: {via}\r\nFrom: {from_hdr}\r\nTo: {to_hdr}\r\nCall-ID: {call_id}\r\nCSeq: {cseq} {cseq_method}\r\n"
        ));
    } else {
        let method = spec.method.unwrap_or("INVITE");
        let uri = bracket_sip_ipv6_uri(spec.uri.unwrap_or("sip:service@pbx.local"));
        let to_hdr = format_sip_addr_header(to_raw, None);
        out.push_str(&format!(
            "{method} {uri} SIP/2.0\r\nVia: {via}\r\nFrom: {from_hdr}\r\nTo: {to_hdr}\r\nCall-ID: {call_id}\r\nCSeq: {cseq} {method}\r\nMax-Forwards: 70\r\n"
        ));
    }

    finalize_sip_message(out, spec, payload_bytes)
}
