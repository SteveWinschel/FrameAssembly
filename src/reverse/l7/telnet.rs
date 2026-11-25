//! Telnet Protocol (`telnet`, RFC 854) Layer 7 option negotiation and NVT PCAP-to-`.frasm` decompiler.
//!
//! This module implements the fuzz-safe reverse dissector for RFC 854 `telnet` Interpret As
//! Command (`0xFF` IAC) multi-option negotiation sequences (`will`, `wont`, `do`, `dont`) and
//! Network Virtual Terminal (`NVT`) ASCII data streams carried over TCP and SCTP ports `23`,
//! `2323`, `2001`, and `4000`. Printable UTF-8 text is emitted via `data`, while trailing binary
//! terminal escape sequences or duplicate IAC commands stay in `residual_payload`.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write as _;

use crate::ast::Protocol;
use crate::reverse::{ProtocolDissection, sd};

use super::quote_raw_str;

/// Dissects an RFC 854 Telnet IAC option negotiation sequence or NVT data stream.
pub(crate) fn dissect_telnet(payload: &[u8]) -> Option<ProtocolDissection> {
    let mut tokens = String::from("telnet");
    let mut offset = 0usize;
    let mut seen_mask = 0u8;
    let mut iac_cmds: Vec<(u8, u8)> = Vec::new();

    while let Some(&[0xFF, cmd @ 0xFB..=0xFE, opt]) = payload.get(offset..offset + 3) {
        let bit = 1u8 << (cmd - 0xFB);
        if (seen_mask & bit) != 0 {
            break;
        }
        seen_mask |= bit;
        iac_cmds.push((cmd, opt));
        offset += 3;
    }

    let rest = payload.get(offset..)?;
    if iac_cmds.len() == 1 && iac_cmds[0] == (0xFD, 1) && rest.is_empty() {
        // Default bare `telnet` statement compiles to `do 1` with empty text.
    } else {
        for &(cmd, opt) in &iac_cmds {
            let kw = ["will", "wont", "do", "dont"][(cmd - 0xFB) as usize];
            let _ = write!(tokens, " {kw} {opt}");
        }
    }

    let mut residual = Vec::new();
    if offset == 0 || !rest.is_empty() {
        if let Ok(s) = core::str::from_utf8(rest)
            && s.chars().all(|c| !c.is_control())
        {
            tokens.push_str(&format!(" data \"{}\"", quote_raw_str(s)));
        } else {
            if offset == 0 {
                tokens.push_str(" data \"\"");
            }
            residual = rest.to_vec();
        }
    }

    Some(sd(Protocol::Telnet, tokens, residual))
}
