//! Media Gateway Control Protocol (`mgcp`, RFC 3435) Layer 7 PCAP-to-`.frasm` decompiler.
//!
//! This module implements the fuzz-safe reverse dissector for RFC 3435 `mgcp` gateway signaling
//! commands (`crcx`, `mdcx`, `dlcx`, `rqnt`, `ntfy`, `auep`, `aucx`, `rsip`) and status responses
//! carried over UDP (or TCP/SCTP) ports `2427` and `2727`. It parses CRLF-delimited headers
//! (`C:`, `I:`, `L:`, `M:`, `RM:`) and optional SDP session bodies, elides canonical defaults,
//! preserves explicit non-UDP transports, and encodes text/binary payloads cleanly.

use alloc::string::String;
use core::fmt::Write as _;

use crate::ast::{Protocol, TransportProto};
use crate::reverse::{ProtocolDissection, sd_tp};

use super::{attach_text_body, first_crlf_line, quote_raw_str, split_crlf_headers};

/// Checks whether `payload` begins with an MGCP 1.0 command line.
pub(crate) fn is_mgcp_signature(payload: &[u8]) -> bool {
    first_crlf_line(payload).is_some_and(|l| l.ends_with(" MGCP 1.0"))
}

/// Returns the default RFC 3435 reason phrase synthesized for an MGCP status code.
fn expected_mgcp_reason(status: u16) -> &'static str {
    match status {
        100 => "Transaction Executing",
        200 => "OK",
        250 => "Connection was deleted",
        400 => "Transient error",
        500 => "Endpoint unknown",
        510 => "Protocol error",
        _ => "OK",
    }
}

/// Dissects an RFC 3435 MGCP command or response message over UDP, TCP, or SCTP.
pub(crate) fn dissect_mgcp(
    transport: TransportProto,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Option<ProtocolDissection> {
    let on_mgcp_port = matches!(src_port, 2427 | 2727) || matches!(dst_port, 2427 | 2727);
    if !on_mgcp_port && !is_mgcp_signature(payload) {
        return None;
    }

    let (hdr_str, body_bytes) = if let Some((h, b)) = split_crlf_headers(payload) {
        (h, b)
    } else {
        let raw_hdr = payload.strip_suffix(b"\r\n")?;
        let text = core::str::from_utf8(raw_hdr).ok()?;
        (text, &[][..])
    };

    let mut lines = hdr_str.split("\r\n");
    let first_line = lines.next()?;
    let mut tokens = String::from("mgcp");
    let mut verb_upper = "";

    if let Some(before_ver) = first_line.strip_suffix(" MGCP 1.0") {
        let mut parts = before_ver.splitn(3, ' ');
        let verb = parts.next()?;
        let txid_s = parts.next()?;
        let endpoint = parts.next()?;
        if verb.is_empty() || endpoint.is_empty() {
            return None;
        }
        let txid: u32 = txid_s.parse().ok()?;
        verb_upper = verb;
        if verb != "CRCX" {
            if matches!(
                verb,
                "MDCX" | "DLCX" | "RQNT" | "NTFY" | "AUEP" | "AUCX" | "RSIP"
            ) {
                let _ = write!(tokens, " {}", verb.to_ascii_lowercase());
            } else {
                let _ = write!(tokens, " method \"{}\"", quote_raw_str(verb));
            }
        }
        if txid != 1 {
            let _ = write!(tokens, " txid {txid}");
        }
        if endpoint != "aaln/1@gw1.example.com" {
            let _ = write!(tokens, " endpoint \"{}\"", quote_raw_str(endpoint));
        }
    } else {
        if !on_mgcp_port {
            return None;
        }
        let mut parts = first_line.splitn(3, ' ');
        let status: u16 = parts.next()?.parse().ok()?;
        let txid: u32 = parts.next()?.parse().ok()?;
        let reason = parts.next().unwrap_or("");
        let _ = write!(tokens, " status {status}");
        if txid != 1 {
            let _ = write!(tokens, " txid {txid}");
        }
        if reason != expected_mgcp_reason(status) {
            let _ = write!(tokens, " reason \"{}\"", quote_raw_str(reason));
        }
    }

    let (mut cid_opt, mut iid_opt, mut lopts_opt, mut mode_opt, mut rm_seen) =
        (None, None, None, None, false);
    for hline in lines {
        let (k, v) = hline.split_once(": ")?;
        match k {
            "C" if cid_opt.is_none() => cid_opt = Some(v),
            "I" if iid_opt.is_none() => iid_opt = Some(v),
            "L" if lopts_opt.is_none() => lopts_opt = Some(v),
            "M" if mode_opt.is_none() => mode_opt = Some(v),
            "RM" if verb_upper == "RSIP" && !rm_seen && v == "graceful" => rm_seen = true,
            _ => return None,
        }
    }

    if let Some(cid) = cid_opt
        && !(matches!(verb_upper, "CRCX" | "MDCX" | "DLCX" | "AUCX") && cid == "1")
    {
        let _ = write!(tokens, " callid \"{}\"", quote_raw_str(cid));
    }
    if let Some(iid) = iid_opt {
        let _ = write!(tokens, " connid \"{}\"", quote_raw_str(iid));
    }
    if let Some(lopts) = lopts_opt
        && !(verb_upper == "CRCX" && lopts == "p:20, a:PCMU")
    {
        let _ = write!(tokens, " localopts \"{}\"", quote_raw_str(lopts));
    }
    if let Some(mode) = mode_opt
        && !(verb_upper == "CRCX" && mode == "sendrecv")
    {
        let _ = write!(tokens, " mode \"{}\"", quote_raw_str(mode));
    }

    let residual = attach_text_body(&mut tokens, "body", body_bytes);
    let explicit_transport = match transport {
        TransportProto::Udp => None,
        tp => Some(tp),
    };
    Some(sd_tp(Protocol::Mgcp, tokens, residual, explicit_transport))
}
