//! SSDP protocol wire builder.

use crate::ast::*;
use crate::builders::WireContext;
use alloc::vec::Vec;

/// Builds an SSDP discovery request or notification string.
pub fn build_ssdp_payload(
    _ctx: &WireContext,
    spec: &SsdpSpec,
    payload_bytes: &[u8],
) -> Vec<u8> {
    let st = spec.st.unwrap_or("upnp:rootdevice");
    let formatted = format!("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\nST: {}\r\n\r\n", st);
    let mut bytes = formatted.into_bytes();
    if !payload_bytes.is_empty() {
        bytes.extend_from_slice(payload_bytes);
    }
    bytes
}
