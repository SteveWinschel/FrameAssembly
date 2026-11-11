//! Real Time Streaming Protocol (`rtsp`, RFC 7826 / RFC 2326) Layer 7 PCAP-to-`.fasm` decompiler.
//!
//! This module implements the fuzz-safe reverse dissector for RFC 2326 / RFC 7826 `rtsp` streaming
//! media control requests (`options`, `describe`, `setup`, `play`, `teardown`, or `method`) and
//! status responses (`status`) carried over TCP ports `554` and `8554`. It validates CRLF header
//! framing, decodes `uri`, `cseq`, `session`, and `transporthdr` fields into canonical `.fasm`
//! modifiers, elides default request URIs and sequence numbers, and preserves any trailing media
//! description bytes in `residual_payload`.

use alloc::string::String;
use core::fmt::Write as _;

use crate::ast::Protocol;
use crate::reverse::{ProtocolDissection, sd};

use super::{first_crlf_line, push_str_mod, split_crlf_headers};

/// Checks whether `payload` begins with an RTSP/1.0 request or response line.
pub(crate) fn is_rtsp_signature(payload: &[u8]) -> bool {
    first_crlf_line(payload).is_some_and(|l| l.starts_with("RTSP/1.0 ") || l.ends_with(" RTSP/1.0"))
}

/// Dissects an RFC 7826 / RFC 2326 RTSP session control frame on TCP port `554`.
pub(crate) fn dissect_rtsp(payload: &[u8]) -> Option<ProtocolDissection> {
    let (hdr_str, trailing) = split_crlf_headers(payload)?;
    let mut lines = hdr_str.split("\r\n");
    let first_line = lines.next()?;
    let mut tokens = String::from("rtsp");

    if let Some(after_ver) = first_line.strip_prefix("RTSP/1.0 ") {
        let (status_s, _) = after_ver.split_once(' ').unwrap_or((after_ver, ""));
        let status: u16 = status_s.parse().ok()?;
        let _ = write!(tokens, " status {status}");
    } else {
        let before_ver = first_line.strip_suffix(" RTSP/1.0")?;
        let (method, uri) = before_ver.split_once(' ')?;
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

    let (mut cseq_opt, mut sess_opt, mut trans_opt) = (None, None, None);
    for hline in lines {
        let (k, v) = hline.split_once(": ")?;
        match k {
            "CSeq" if cseq_opt.is_none() => cseq_opt = Some(v.parse::<u32>().ok()?),
            "Session" if sess_opt.is_none() => sess_opt = Some(v),
            "Transport" if trans_opt.is_none() => trans_opt = Some(v),
            _ => return None,
        }
    }
    if let Some(cseq) = cseq_opt
        && cseq != 1
    {
        let _ = write!(tokens, " cseq {cseq}");
    }
    if let Some(s) = sess_opt {
        push_str_mod(&mut tokens, "session", s);
    }
    if let Some(t) = trans_opt {
        push_str_mod(&mut tokens, "transporthdr", t);
    }

    Some(sd(Protocol::Rtsp, tokens, trailing.to_vec()))
}
