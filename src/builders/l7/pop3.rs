//! Post Office Protocol Version 3 (POP3, RFC 1939) wire payload builder.
//!
//! This module implements [`build_pop3_payload`], which serializes a [`Pop3Spec`]
//! AST node into an RFC 1939 POP3 command or status response over TCP port 110 (or 995 for POP3S).
//! Server responses begin with the positive `+OK` or negative `-ERR` status indicator followed by
//! optional diagnostic text and CRLF (`\r\n`), while client commands emit `<CMD> [ARG]\r\n`
//! (defaulting to `STAT\r\n`) followed by any explicit multi-line message payload bytes.

use crate::ast::*;
use crate::builders::WireContext;
use alloc::vec::Vec;

/// Builds an RFC 1939 POP3 mail access message.
///
/// Syntax mapping: `POP3 [CMD <str>] [ARG <str>] [OK] [ERR] [RESPONSE <str>]`
#[doc(alias = "POP3")]
#[doc(alias = "RFC1939")]
pub fn build_pop3_payload(
    _ctx: &WireContext,
    spec: &Pop3Spec,
    payload_bytes: &[u8],
) -> Vec<u8> {
    let formatted = if spec.is_ok {
        let resp = spec.response.unwrap_or("OK");
        format!("+OK {}\r\n", resp)
    } else if spec.is_err {
        let resp = spec.response.unwrap_or("Error");
        format!("-ERR {}\r\n", resp)
    } else if spec.cmd.is_none()
        && let Some(resp) = spec.response
    {
        format!("+OK {}\r\n", resp)
    } else {
        let cmd = spec.cmd.unwrap_or("USER");
        if let Some(arg) = spec.arg {
            format!("{} {}\r\n", cmd, arg)
        } else {
            format!("{}\r\n", cmd)
        }
    };

    let mut bytes = formatted.into_bytes();
    if !payload_bytes.is_empty() {
        bytes.extend_from_slice(payload_bytes);
    }
    bytes
}
