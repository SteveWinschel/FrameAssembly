//! POP3 protocol wire builder.

use crate::ast::*;
use crate::builders::WireContext;
use alloc::vec::Vec;

/// Builds an RFC 1939 POP3 mail access message.
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
