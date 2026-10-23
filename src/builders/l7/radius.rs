//! RADIUS protocol wire builder.

use crate::ast::*;
use crate::builders::WireContext;
use alloc::vec::Vec;
use core::net::IpAddr;

/// Builds an RFC 2865 RADIUS packet payload and returns payload and UDP port (1812 or 1813).
pub fn build_radius_payload(
    _ctx: &WireContext,
    spec: &RadiusSpec,
    payload_bytes: &[u8],
) -> (Vec<u8>, u16) {
    let (code, dport) = match spec.code.unwrap_or("ACCESS_REQUEST").to_ascii_uppercase().as_str() {
        "ACCESS_REQUEST" => (1u8, 1812u16),
        "ACCESS_ACCEPT" => (2u8, 1812u16),
        "ACCESS_REJECT" => (3u8, 1812u16),
        "ACCOUNTING_REQUEST" => (4u8, 1813u16),
        "ACCOUNTING_RESPONSE" => (5u8, 1813u16),
        "ACCESS_CHALLENGE" => (11u8, 1812u16),
        _ => (1u8, 1812u16),
    };

    let id = spec.id.unwrap_or(1);
    let mut avps = Vec::new();

    // User-Name (Type 1)
    let user = spec.user.unwrap_or("user");
    let user_bytes = user.as_bytes();
    avps.push(1); // Type 1
    avps.push((user_bytes.len() + 2) as u8);
    avps.extend_from_slice(user_bytes);

    // NAS-IP-Address (Type 4)
    if let Some(IpAddr::V4(v4)) = spec.nas_ip {
        avps.push(4);
        avps.push(6);
        avps.extend_from_slice(&v4.octets());
    }

    // Service-Type (Type 6)
    if let Some(service_type) = spec.service_type {
        avps.push(6);
        avps.push(6);
        avps.extend_from_slice(&service_type.to_be_bytes());
    }

    // Framed-IP-Address (Type 8)
    if let Some(IpAddr::V4(v4)) = spec.framed_ip {
        avps.push(8);
        avps.push(6);
        avps.extend_from_slice(&v4.octets());
    }

    if !payload_bytes.is_empty() {
        avps.extend_from_slice(payload_bytes);
    }

    let total_len = 20 + avps.len() as u16;
    let mut pkt = Vec::with_capacity(total_len as usize);
    pkt.push(code);
    pkt.push(id);
    pkt.extend_from_slice(&total_len.to_be_bytes());
    // 16-byte Authenticator
    pkt.extend_from_slice(&[0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]);
    pkt.extend_from_slice(&avps);

    (pkt, dport)
}
