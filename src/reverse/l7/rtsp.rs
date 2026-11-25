//! Real Time Streaming Protocol (`rtsp`, RFC 7826 / RFC 2326) Layer 7 PCAP-to-`.frasm` decompiler.
//!
//! This module implements the fuzz-safe reverse dissector for RFC 2326 / RFC 7826 `rtsp` streaming
//! media control requests (`options`, `describe`, `setup`, `play`, `teardown`, or `method`) and
//! status responses (`status`) carried over TCP or SCTP ports `554` and `8554`. It validates CRLF
//! header framing and `Content-Length`, decodes `uri`, `cseq`, `session`, and `transporthdr`
//! fields, elides default `SETUP` transport and `CSeq` values, and preserves trailing bytes.

use alloc::string::String;
use core::fmt::Write as _;

use crate::ast::Protocol;
use crate::reverse::{ProtocolDissection, sd};

use super::{first_crlf_line, push_str_mod, split_crlf_headers};

/// Checks whether `payload` begins with an RTSP/1.0 request or response line.
pub(crate) fn is_rtsp_signature(payload: &[u8]) -> bool {
    first_crlf_line(payload).is_some_and(|l| l.starts_with("RTSP/1.0 ") || l.ends_with(" RTSP/1.0"))
}

/// Returns the canonical RTSP/1.0 reason phrase synthesized for `status`.
const fn expected_rtsp_reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        454 => "Session Not Found",
        500 => "Internal Server Error",
        _ => "OK",
    }
}

/// Dissects an RFC 7826 / RFC 2326 RTSP session control frame on TCP or SCTP port `554`.
pub(crate) fn dissect_rtsp(payload: &[u8]) -> Option<ProtocolDissection> {
    let (hdr_str, trailing) = split_crlf_headers(payload)?;
    let mut lines = hdr_str.split("\r\n");
    let first_line = lines.next()?;
    let mut tokens = String::from("rtsp");
    let mut is_setup = false;

    if let Some(after_ver) = first_line.strip_prefix("RTSP/1.0 ") {
        let (status_s, reason) = after_ver.split_once(' ').unwrap_or((after_ver, ""));
        let status: u16 = status_s.parse().ok()?;
        if reason != expected_rtsp_reason(status) {
            return None;
        }
        let _ = write!(tokens, " status {status}");
    } else {
        let before_ver = first_line.strip_suffix(" RTSP/1.0")?;
        let (method, uri) = before_ver.split_once(' ')?;
        is_setup = method.eq_ignore_ascii_case("SETUP");
        if matches!(
            method,
            "OPTIONS" | "DESCRIBE" | "SETUP" | "PLAY" | "TEARDOWN"
        ) {
            let _ = write!(tokens, " {}", method.to_ascii_lowercase());
        } else {
            push_str_mod(&mut tokens, "method", method);
        }
        if uri != "rtsp://localhost/live" {
            push_str_mod(&mut tokens, "uri", uri);
        }
    }

    let (mut cseq_opt, mut sess_opt, mut trans_opt, mut cl_seen) = (None, None, None, false);
    for hline in lines {
        let (k, v) = hline.split_once(": ")?;
        match k {
            "CSeq" if cseq_opt.is_none() => cseq_opt = Some(v.parse::<u32>().ok()?),
            "Session" if sess_opt.is_none() => sess_opt = Some(v),
            "Transport" if trans_opt.is_none() => trans_opt = Some(v),
            "Content-Length"
                if !cl_seen
                    && !trailing.is_empty()
                    && v.parse::<usize>().ok() == Some(trailing.len()) =>
            {
                cl_seen = true;
            }
            _ => return None,
        }
    }
    if !trailing.is_empty() && !cl_seen {
        return None;
    }
    if let Some(cseq) = cseq_opt
        && cseq != 1
    {
        let _ = write!(tokens, " cseq {cseq}");
    }
    if let Some(s) = sess_opt {
        push_str_mod(&mut tokens, "session", s);
    }
    if let Some(t) = trans_opt
        && !(is_setup && t == "RTP/AVP;unicast;client_port=8000-8001")
    {
        push_str_mod(&mut tokens, "transporthdr", t);
    }

    Some(sd(Protocol::Rtsp, tokens, trailing.to_vec()))
}
