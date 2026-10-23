//! WHOIS protocol wire builder.

use crate::ast::*;
use crate::builders::WireContext;
use alloc::vec::Vec;

/// Builds an RFC 3912 WHOIS query or response string.
pub fn build_whois_payload(
    _ctx: &WireContext,
    spec: &WhoisSpec,
    payload_bytes: &[u8],
) -> Vec<u8> {
    let domain = spec.domain.unwrap_or("example.com");
    let formatted = format!("{}\r\n", domain);
    let mut bytes = formatted.into_bytes();
    if !payload_bytes.is_empty() {
        bytes.extend_from_slice(payload_bytes);
    }
    bytes
}
