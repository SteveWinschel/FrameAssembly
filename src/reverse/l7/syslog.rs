//! Syslog (`SYSLOG`, RFC 5424 / RFC 3164 / RFC 6587) Layer 7 PCAP-to-`.fasm` decompiler.
//!
//! This module implements the fuzz-safe reverse dissector for RFC 5424 and RFC 3164 `SYSLOG`
//! messages carried over UDP or TCP ports `514`, `1514`, and `6514`. It parses the leading
//! `<PRI>` header, extracts RFC 5424 version `1` structured fields (`hostname`, `app`, `procid`,
//! `msgid`, `msg`), and records `transport tcp` when encapsulated over TCP.

use alloc::string::String;
use alloc::vec::Vec;

use crate::ast::{Protocol, TransportProto};
use crate::reverse::{ProtocolDissection, push_if};

use super::{is_printable_ascii_str, push_str_if};

/// Dissects an RFC 5424 / RFC 3164 `SYSLOG` message over UDP or TCP port `514`.
pub(crate) fn dissect_syslog(payload: &[u8], is_tcp: bool) -> Option<ProtocolDissection> {
    let text = is_printable_ascii_str(payload)?;
    if !text.starts_with('<') {
        return None;
    }
    let close_idx = text.find('>').filter(|&i| i <= 4)?;
    let pri = text[1..close_idx].parse::<u8>().ok()?;
    let after_pri = &text[close_idx + 1..];

    let mut tokens = String::from("syslog");
    push_if(&mut tokens, "pri", pri, 14);

    if let Some(rest) = after_pri.strip_prefix("1 ") {
        let (_ts, r1) = rest.split_once(' ')?;
        let (hostname, r2) = r1.split_once(' ')?;
        let (app, r3) = r2.split_once(' ')?;
        let (procid, r4) = r3.split_once(' ')?;
        let (msgid, r5) = r4.split_once(' ')?;
        let (_sd, msg) = r5.split_once(' ')?;

        push_str_if(&mut tokens, "hostname", hostname, "");
        push_str_if(&mut tokens, "app", app, "app");
        push_str_if(&mut tokens, "procid", procid, "-");
        push_str_if(&mut tokens, "msgid", msgid, "-");
        push_str_if(&mut tokens, "msg", msg, "System notification");
    } else {
        push_str_if(
            &mut tokens,
            "msg",
            after_pri.trim_start(),
            "System notification",
        );
    }

    Some(ProtocolDissection {
        protocol: Protocol::Syslog,
        tokens,
        residual_payload: Vec::new(),
        explicit_transport: is_tcp.then_some(TransportProto::Tcp),
    })
}
