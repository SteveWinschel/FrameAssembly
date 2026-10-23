//! SSH protocol wire builder.

use crate::ast::*;
use crate::builders::WireContext;
use alloc::vec::Vec;

/// Builds an RFC 4253 SSH banner or binary packet payload.
pub fn build_ssh_payload(
    _ctx: &WireContext,
    spec: &SshSpec,
    payload_bytes: &[u8],
) -> Vec<u8> {
    if let Some(banner) = spec.banner {
        let mut bytes = format!("{}\r\n", banner).into_bytes();
        if !payload_bytes.is_empty() {
            bytes.extend_from_slice(payload_bytes);
        }
        bytes
    } else {
        // Default banner or binary KEXINIT
        let banner_str = "SSH-2.0-FrameAssembly_1.0\r\n";
        let mut bytes = banner_str.as_bytes().to_vec();
        if !payload_bytes.is_empty() {
            bytes.extend_from_slice(payload_bytes);
        }
        bytes
    }
}
