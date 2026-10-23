//! SIP protocol wire builder.

use crate::ast::*;
use crate::builders::WireContext;
use alloc::vec::Vec;

/// Builds an RFC 3261 SIP VoIP message string.
pub fn build_sip_payload(
    ctx: &WireContext,
    spec: &SipSpec,
    payload_bytes: &[u8],
) -> Vec<u8> {
    let mut out = String::new();
    let call_id = spec.call_id.unwrap_or("call123@pbx");
    let cseq = spec.cseq.unwrap_or(1);

    if let Some(status) = spec.status {
        let reason = spec.reason.unwrap_or("OK");
        out.push_str(&format!("SIP/2.0 {} {}\r\n", status, reason));
        if let Some(via) = spec.via {
            out.push_str(&format!("Via: {}\r\n", via));
        }
        if let Some(from) = spec.from {
            out.push_str(&format!("From: {}\r\n", from));
        }
        if let Some(to) = spec.to {
            out.push_str(&format!("To: {}\r\n", to));
        }
        out.push_str(&format!("Call-ID: {}\r\nCSeq: {} INVITE\r\n", call_id, cseq));
        if let Some(body) = spec.body {
            out.push_str(&format!("Content-Length: {}\r\n\r\n{}", body.len(), body));
        } else {
            out.push_str("Content-Length: 0\r\n\r\n");
        }
    } else {
        let method = spec.method.unwrap_or("INVITE");
        let uri = spec.uri.unwrap_or("sip:service@pbx.local");
        let from = spec.from.unwrap_or("sip:alice@pbx");
        let to = spec.to.unwrap_or("sip:bob@pbx");
        let via = spec.via.map(|v| v.to_string()).unwrap_or_else(|| format!("SIP/2.0/UDP {}:5060;branch=z9hG4bK-1", ctx.src_ip));

        out.push_str(&format!("{} {} SIP/2.0\r\nVia: {}\r\nFrom: <{}>;tag=1\r\nTo: <{}>\r\nCall-ID: {}\r\nCSeq: {} {}\r\n", method, uri, via, from, to, call_id, cseq, method));
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
