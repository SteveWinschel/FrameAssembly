//! Session Initiation Protocol (`sip`, RFC 3261) Layer 7 VoIP signaling PCAP-to-`.fasm` decompiler.
//!
//! This module implements the fuzz-safe reverse dissector for RFC 3261 `sip` signaling requests
//! (`invite`, `ack`, `bye`, `cancel`, `register`, `options`, or `method`) and responses (`status`,
//! `reason`) carried over UDP or TCP ports `5060` and `5061`. It extracts `uri`, `via`, `from`,
//! `to`, `callid`, `cseq`, `contact`, `contenttype`, and Session Description Protocol (`SDP`)
//! `body` payloads, elides canonical builder defaults, emits `transport tcp` when dissected over
//! TCP streams, and preserves any non-text or trailing bytes in `residual_payload`.

use alloc::string::String;
use core::fmt::Write as _;

use crate::ast::{Protocol, TransportProto};
use crate::reverse::ProtocolDissection;

use super::{attach_text_body, first_crlf_line, push_str_mod, split_crlf_headers};

/// Checks whether `payload` begins with a SIP/2.0 request or response line.
pub(crate) fn is_sip_signature(payload: &[u8]) -> bool {
    first_crlf_line(payload).is_some_and(|l| l.starts_with("SIP/2.0 ") || l.ends_with(" SIP/2.0"))
}

/// Dissects an RFC 3261 SIP signaling request or response over UDP or TCP.
pub(crate) fn dissect_sip<'a>(payload: &'a [u8], is_tcp: bool) -> Option<ProtocolDissection> {
    let (hdr_str, body_bytes) = split_crlf_headers(payload)?;
    let mut lines = hdr_str.split("\r\n");
    let first_line = lines.next()?;

    let mut tokens = String::from("sip");
    let is_response = first_line.starts_with("SIP/2.0 ");
    let mut req_method = "INVITE";

    if is_response {
        let after_ver = first_line.strip_prefix("SIP/2.0 ")?;
        let (status_str, reason) = after_ver.split_once(' ').unwrap_or((after_ver, ""));
        let status: u16 = status_str.parse().ok()?;
        let _ = write!(tokens, " status {status}");
        if reason != "OK" {
            push_str_mod(&mut tokens, "reason", reason);
        }
    } else {
        let (method, uri) = first_line.strip_suffix(" SIP/2.0")?.split_once(' ')?;
        req_method = method;
        append_sip_method(&mut tokens, method);
        if uri != "sip:service@pbx.local" {
            push_str_mod(&mut tokens, "uri", uri);
        }
    }

    let (mut via_opt, mut from_opt, mut to_opt, mut call_id_opt, mut contact_opt, mut ct_opt) =
        (None, None, None, None, None, None);
    let mut cseq_opt: Option<(u32, &str)> = None;

    for hline in lines {
        let (k, v) = hline.split_once(": ")?;
        match k {
            "Via" => via_opt = Some(v),
            "From" => from_opt = Some(v),
            "To" => to_opt = Some(v),
            "Call-ID" => call_id_opt = Some(v),
            "CSeq" => {
                if let Some((num_s, m_s)) = v.split_once(' ')
                    && let Ok(cseq_num) = num_s.parse::<u32>()
                {
                    cseq_opt = Some((cseq_num, m_s));
                }
            }
            "Contact" => contact_opt = Some(v),
            "Content-Type" => ct_opt = Some(v),
            "Content-Length" => {}
            _ => return None,
        }
    }

    if is_response {
        if let Some((_, cseq_m)) = cseq_opt
            && cseq_m != "INVITE"
        {
            append_sip_method(&mut tokens, cseq_m);
        }
    } else if cseq_opt.is_some_and(|(_, m)| m != req_method) {
        return None;
    }
    let trim_angle = |s: &'a str, suf: &str| {
        s.strip_prefix('<')
            .and_then(|x| x.strip_suffix(suf))
            .unwrap_or(s)
    };
    if let Some(via) = via_opt {
        push_str_mod(&mut tokens, "via", via);
    }
    if let Some(f) = from_opt {
        let f = if is_response {
            f
        } else {
            trim_angle(f, ">;tag=1")
        };
        if is_response || f != "sip:alice@pbx" {
            push_str_mod(&mut tokens, "from", f);
        }
    }
    if let Some(t) = to_opt {
        let t = if is_response { t } else { trim_angle(t, ">") };
        if is_response || t != "sip:bob@pbx" {
            push_str_mod(&mut tokens, "to", t);
        }
    }
    if let Some(cid) = call_id_opt
        && cid != "call123@pbx"
    {
        push_str_mod(&mut tokens, "callid", cid);
    }
    if let Some((cseq_num, _)) = cseq_opt
        && cseq_num != 1
    {
        let _ = write!(tokens, " cseq {cseq_num}");
    }
    if let Some(c) = contact_opt {
        push_str_mod(&mut tokens, "contact", trim_angle(c, ">"));
    }
    if let Some(ct) = ct_opt {
        push_str_mod(&mut tokens, "contenttype", ct);
    }

    let residual_payload = attach_text_body(&mut tokens, "body", body_bytes);
    Some(ProtocolDissection {
        protocol: Protocol::Sip,
        tokens,
        residual_payload,
        explicit_transport: is_tcp.then_some(TransportProto::Tcp),
    })
}

/// Appends the canonical `.fasm` SIP method token or `method "<str>"` modifier.
fn append_sip_method(tokens: &mut String, method: &str) {
    if matches!(
        method,
        "INVITE" | "ACK" | "BYE" | "CANCEL" | "REGISTER" | "OPTIONS"
    ) {
        let _ = write!(tokens, " {}", method.to_ascii_lowercase());
    } else {
        push_str_mod(tokens, "method", method);
    }
}
