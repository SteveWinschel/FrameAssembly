//! Telnet Protocol (`telnet`, RFC 854) Layer 7 option negotiation and NVT PCAP-to-`.frasm` decompiler.
//!
//! This module implements the fuzz-safe reverse dissector for RFC 854 `telnet` Interpret As
//! Command (`0xFF` IAC) option negotiation sequences (`will`, `wont`, `do`, `dont`) and Network
//! Virtual Terminal (`NVT`) ASCII data streams carried over TCP ports `23`, `2323`, `2001`, and
//! `4000`. Printable UTF-8 text is emitted via the `data` modifier, while non-ASCII or binary
//! terminal escape sequences following an IAC command are preserved verbatim as residual payload
//! bytes.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write as _;

use crate::ast::Protocol;
use crate::reverse::{ProtocolDissection, sd};

use super::{is_valid_raw_string_body, push_str_mod};

/// Dissects an RFC 854 Telnet IAC option negotiation or NVT data stream on TCP port `23`.
pub(crate) fn dissect_telnet(payload: &[u8]) -> Option<ProtocolDissection> {
    let mut tokens = String::from("telnet");
    let mut offset = 0usize;

    if let &[0xFF, cmd @ 0xFB..=0xFE, opt, ..] = payload {
        let kw = ["will", "wont", "do", "dont"][(cmd - 0xFB) as usize];
        if cmd != 0xFD || opt != 1 || payload.len() > 3 {
            let _ = write!(tokens, " {kw} {opt}");
        }
        offset = 3;
    }

    let rest = payload.get(offset..)?;
    let mut residual = Vec::new();
    if offset == 0 || !rest.is_empty() {
        if let Ok(s) = core::str::from_utf8(rest)
            && is_valid_raw_string_body(s)
        {
            push_str_mod(&mut tokens, "data", s);
        } else {
            if offset == 0 {
                tokens.push_str(" data \"\"");
            }
            residual = rest.to_vec();
        }
    }

    Some(sd(Protocol::Telnet, tokens, residual))
}
