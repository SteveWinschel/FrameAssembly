//! SMTP protocol wire builder.

use crate::ast::*;
use crate::builders::WireContext;
use alloc::vec::Vec;

/// Builds an RFC 5321 SMTP email transaction message.
pub fn build_smtp_payload(
    _ctx: &WireContext,
    spec: &SmtpSpec,
    payload_bytes: &[u8],
) -> Vec<u8> {
    let formatted = if let Some(code) = spec.code {
        let reply = spec.reply.unwrap_or("OK");
        format!("{} {}\r\n", code, reply)
    } else if let Some(cmd) = spec.cmd {
        if let Some(param) = spec.param {
            format!("{} {}\r\n", cmd, param)
        } else {
            format!("{}\r\n", cmd)
        }
    } else {
        "EHLO localhost\r\n".to_string()
    };

    let mut bytes = formatted.into_bytes();
    if let Some(body) = spec.body {
        bytes.extend_from_slice(body.as_bytes());
        bytes.extend_from_slice(b"\r\n.\r\n");
    } else if !payload_bytes.is_empty() {
        bytes.extend_from_slice(payload_bytes);
    }
    bytes
}
