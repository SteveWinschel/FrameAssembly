//! IMAP protocol wire builder.

use crate::ast::*;
use crate::builders::WireContext;
use alloc::vec::Vec;

/// Builds an RFC 9051 IMAP mail message.
pub fn build_imap_payload(
    _ctx: &WireContext,
    spec: &ImapSpec,
    payload_bytes: &[u8],
) -> Vec<u8> {
    let tag = spec.tag.unwrap_or("A01");
    let formatted = if let Some(status) = spec.status {
        let resp = spec.response.unwrap_or("Completed");
        format!("{} {} {}\r\n", tag, status, resp)
    } else {
        let cmd = spec.cmd.unwrap_or("NOOP");
        if let Some(arg) = spec.arg {
            format!("{} {} {}\r\n", tag, cmd, arg)
        } else {
            format!("{} {}\r\n", tag, cmd)
        }
    };

    let mut bytes = formatted.into_bytes();
    if !payload_bytes.is_empty() {
        bytes.extend_from_slice(payload_bytes);
    }
    bytes
}
