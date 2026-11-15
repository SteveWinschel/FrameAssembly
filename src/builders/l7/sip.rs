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
    let tp_str = if ctx.transport == Some(TransportProto::Tcp) {
        "TCP"
    } else {
        "UDP"
    };
    let src_host = match ctx.src_ip {
        core::net::IpAddr::V4(v4) => v4.to_string(),
        core::net::IpAddr::V6(v6) => format!("[{v6}]"),
    };
    let default_via = format!("SIP/2.0/{tp_str} {src_host}:5060;branch=z9hG4bK-1");
    let via = spec
        .via
        .map(|v| v.to_string())
        .unwrap_or(default_via);
    let from_uri = bracket_sip_ipv6_uri(spec.from.unwrap_or("sip:alice@pbx"));
    let from_hdr = if from_uri.starts_with('<') || from_uri.contains(";tag=") {
        from_uri
    } else {
        format!("<{from_uri}>;tag=1")
    };
    let to_uri = bracket_sip_ipv6_uri(spec.to.unwrap_or("sip:bob@pbx"));

    if let Some(status) = spec.status {
        let reason = spec.reason.unwrap_or("OK");
        let to_hdr = if to_uri.starts_with('<') || to_uri.contains(";tag=") {
            to_uri
        } else {
            format!("<{to_uri}>;tag=2")
        };
        out.push_str(&format!(
            "SIP/2.0 {} {}\r\nVia: {}\r\nFrom: {}\r\nTo: {}\r\nCall-ID: {}\r\nCSeq: {} {}\r\n",
            status, reason, via, from_hdr, to_hdr, call_id, cseq, cseq_method
        ));
        if let Some(contact) = spec.contact {
            let c_uri = bracket_sip_ipv6_uri(contact);
            if c_uri.starts_with('<') {
                out.push_str(&format!("Contact: {}\r\n", c_uri));
            } else {
                out.push_str(&format!("Contact: <{}>\r\n", c_uri));
            }
        }
        if let Some(ct) = spec.content_type {
            out.push_str(&format!("Content-Type: {}\r\n", ct));
        } else if !payload_bytes.is_empty() {
            out.push_str("Content-Type: application/sdp\r\n");
        }
        if let Some(body) = spec.body {
            out.push_str(&format!("Content-Length: {}\r\n\r\n{}", body.len(), body));
        } else if !payload_bytes.is_empty() {
            out.push_str(&format!("Content-Length: {}\r\n\r\n", payload_bytes.len()));
            let mut bytes = out.into_bytes();
            bytes.extend_from_slice(payload_bytes);
            return bytes;
        } else {
            out.push_str("Content-Length: 0\r\n\r\n");
        }
    } else {
        let method = spec.method.unwrap_or("INVITE");
        let uri = bracket_sip_ipv6_uri(spec.uri.unwrap_or("sip:service@pbx.local"));
        let to_hdr = if to_uri.starts_with('<') {
            to_uri
        } else {
            format!("<{to_uri}>")
        };

        out.push_str(&format!(
            "{} {} SIP/2.0\r\nVia: {}\r\nFrom: {}\r\nTo: {}\r\nCall-ID: {}\r\nCSeq: {} {}\r\n",
            method, uri, via, from_hdr, to_hdr, call_id, cseq, method
        ));
        if let Some(contact) = spec.contact {
            let c_uri = bracket_sip_ipv6_uri(contact);
            if c_uri.starts_with('<') {
                out.push_str(&format!("Contact: {}\r\n", c_uri));
            } else {
                out.push_str(&format!("Contact: <{}>\r\n", c_uri));
            }
        }
        if let Some(ct) = spec.content_type {
            out.push_str(&format!("Content-Type: {}\r\n", ct));
        } else if !payload_bytes.is_empty() {
            out.push_str("Content-Type: application/sdp\r\n");
        }
        if let Some(body) = spec.body {
            out.push_str(&format!("Content-Length: {}\r\n\r\n{}", body.len(), body));
        } else if !payload_bytes.is_empty() {
            out.push_str(&format!("Content-Length: {}\r\n\r\n", payload_bytes.len()));
            let mut bytes = out.into_bytes();
            bytes.extend_from_slice(payload_bytes);
            return bytes;
        } else {
            out.push_str("Content-Length: 0\r\n\r\n");
        }
    }

    out.into_bytes()
}
