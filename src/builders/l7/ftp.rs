//! FTP protocol wire builder.

use crate::ast::*;
use crate::builders::WireContext;
use alloc::vec::Vec;

/// Builds an RFC 959 FTP command or reply string.
pub fn build_ftp_payload(
    _ctx: &WireContext,
    spec: &FtpSpec,
    payload_bytes: &[u8],
) -> Vec<u8> {
    let formatted = if let Some(code) = spec.code {
        let reply = spec.reply.unwrap_or("Service ready");
        format!("{} {}\r\n", code, reply)
    } else if let Some(cmd) = spec.cmd {
        if let Some(arg) = spec.arg {
            format!("{} {}\r\n", cmd, arg)
        } else {
            format!("{}\r\n", cmd)
        }
    } else {
        "USER anonymous\r\n".to_string()
    };

    let mut bytes = formatted.into_bytes();
    if !payload_bytes.is_empty() {
        bytes.extend_from_slice(payload_bytes);
    }
    bytes
}
