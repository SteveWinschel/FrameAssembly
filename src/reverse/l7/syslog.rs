//! Syslog (`syslog`, RFC 5424 / RFC 3164 / RFC 6587) Layer 7 PCAP-to-`.frasm` decompiler.
//!
//! This module implements the fuzz-safe reverse dissector for RFC 5424 and RFC 3164 `syslog`
//! messages carried over UDP or TCP ports `514`, `1514`, and `6514`. When dissecting TCP streams
//! (such as RFC 6587 §3.4.1 octet-counting on port `6514`), it strips verified `<MSG-LEN> ` frame
//! prefixes before parsing `<PRI>`, RFC 5424 structured fields (`hostname`, `app`, `procid`,
//! `msgid`, `msg`), and `transport tcp`.

use alloc::string::String;
use alloc::vec::Vec;

use crate::ast::{Protocol, TransportProto};
use crate::reverse::{ProtocolDissection, push_if};

use super::{is_printable_ascii_str, push_str_if};

/// Strips an RFC 6587 §3.4.1 `<MSG-LEN> <SYSLOG-MSG>` octet-counting prefix on TCP Syslog frames.
fn strip_rfc6587_octet_count(payload: &[u8]) -> &[u8] {
    let Some(sp) = payload.iter().position(|&b| b == b' ') else {
        return payload;
    };
    if sp == 0 || sp > 6 || !payload[..sp].iter().all(u8::is_ascii_digit) {
        return payload;
    }
    let Ok(len_str) = core::str::from_utf8(&payload[..sp]) else {
        return payload;
    };
    let Ok(msg_len) = len_str.parse::<usize>() else {
        return payload;
    };
    let Some(msg_start) = sp.checked_add(1) else {
        return payload;
    };
    let Some(msg_end) = msg_start.checked_add(msg_len) else {
        return payload;
    };
    if msg_end == payload.len() && payload.get(msg_start) == Some(&b'<') {
        &payload[msg_start..msg_end]
    } else {
        payload
    }
}

/// Dissects an RFC 5424 / RFC 3164 `syslog` message over UDP or TCP port `514` (and `6514`).
pub(crate) fn dissect_syslog(payload: &[u8], is_tcp: bool) -> Option<ProtocolDissection> {
    let msg_bytes = if is_tcp {
        strip_rfc6587_octet_count(payload)
    } else {
        payload
    };
    let text = is_printable_ascii_str(msg_bytes)?;
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

        if hostname.is_empty() {
            tokens.push_str(" hostname \"\"");
        } else {
            push_str_if(&mut tokens, "hostname", hostname, "");
        }
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
