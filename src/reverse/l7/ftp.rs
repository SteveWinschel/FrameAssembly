//! File Transfer Protocol (`ftp`, RFC 959) Layer 7 control channel PCAP-to-`.frasm` decompiler.
//!
//! This module implements the fuzz-safe reverse dissector for RFC 959 `ftp` control commands and
//! 3-digit numeric server replies carried over TCP ports `21` and `2121`. It validates CRLF-delimited
//! UTF-8 command and status lines, decodes numeric status `code`, `reply` text, `cmd` verbs, and
//! `arg` parameters, and preserves any trailing bytes after the CRLF line terminator as residual
//! payload so multi-line or pipelined segments recompile byte-for-byte.

use alloc::string::String;
use core::fmt::Write as _;

use crate::ast::Protocol;
use crate::reverse::{ProtocolDissection, sd};

use super::{find_subslice, push_str_mod, quote_web_str};

/// Dissects an RFC 959 FTP control command or numeric reply on TCP port `21`.
pub(crate) fn dissect_ftp(payload: &[u8]) -> Option<ProtocolDissection> {
    let crlf = find_subslice(payload, b"\r\n")?;
    let line = core::str::from_utf8(payload.get(..crlf)?).ok()?;
    let trailing = payload.get(crlf + 2..)?;

    let mut tokens = String::from("ftp");
    if line.len() >= 4
        && line.as_bytes()[0..3].iter().all(|b| b.is_ascii_digit())
        && line.as_bytes()[3] == b' '
    {
        let code: u16 = line.get(0..3)?.parse().ok()?;
        let reply = line.get(4..)?;
        let _ = write!(tokens, " code {code}");
        if reply != "Service ready" {
            push_str_mod(&mut tokens, "reply", reply);
        }
    } else if line == "USER anonymous" {
        tokens.push_str(" cmd \"USER\" arg \"anonymous\"");
    } else if let Some((cmd, arg)) = line.split_once(' ') {
        let _ = write!(
            tokens,
            " cmd {} arg {}",
            quote_web_str(cmd),
            quote_web_str(arg)
        );
    } else if !line.is_empty() {
        push_str_mod(&mut tokens, "cmd", line);
    } else {
        return None;
    }

    Some(sd(Protocol::Ftp, tokens, trailing.to_vec()))
}
