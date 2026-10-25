//! Remote Authentication Dial-In User Service (RADIUS) (RFC 2865 (Authentication) / RFC 2866 (Accounting) / RFC 5176 (CoA)) Layer 7 wire packet builder.
//!
//! This module synthesizes deterministic on-the-wire Remote Authentication Dial-In User Service (RADIUS) frames over UDP port 1812 (Authentication) and UDP port 1813 (Accounting).
//! The wire encoder constructs a 20-byte fixed RADIUS header (8-bit Code: 1 Access-Request, 2 Access-Accept, 3 Access-Reject, 4 Accounting-Request, 5 Accounting-Response, 11 Access-Challenge; 8-bit Identifier; 16-bit big-endian Length; 16-byte Request/Response Authenticator) followed by TLV Attribute-Value Pairs (AVPs: Type 1 User-Name, Type 4 NAS-IP-Address, Type 6 Service-Type, Type 8 Framed-IP-Address). When optional fields in [`RadiusSpec`]
//! are omitted in the `.fasm` source, RFC-compliant default values are automatically populated.
//!
//! Canonical `.fasm` syntax:
//! `a -> b RADIUS [ACCESS_REQUEST | ACCESS_ACCEPT | ACCESS_REJECT | ACCESS_CHALLENGE | ACCOUNTING_REQUEST | ACCOUNTING_RESPONSE | CODE <str>] [ID <u8>] [USER <str>] [NAS_IP <ip>] [SERVICE_TYPE <u32>] [FRAMED_IP <ip>]`

use crate::ast::*;
use crate::builders::WireContext;
use alloc::vec::Vec;
use core::net::IpAddr;

/// Builds an RFC 2865 RADIUS packet payload and returns payload and UDP port (1812 or 1813).
/// Syntax mapping: `RADIUS [ACCESS_REQUEST | ACCESS_ACCEPT | ACCESS_REJECT | ACCESS_CHALLENGE | ACCOUNTING_REQUEST | ACCOUNTING_RESPONSE | CODE <str>] [ID <u8>] [USER <str>] [NAS_IP <ip>] [SERVICE_TYPE <u32>] [FRAMED_IP <ip>]`
#[doc(alias = "RADIUS")]
#[doc(alias = "RFC2865")]
#[doc(alias = "RFC2866")]
#[doc(alias = "NAS_IP")]
#[doc(alias = "FRAMED_IP")]
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

    // NAS-IP-Address (Type 4) or NAS-IPv6-Address (Type 95, RFC 3162)
    match spec.nas_ip {
        Some(IpAddr::V4(v4)) => {
            avps.push(4);
            avps.push(6);
            avps.extend_from_slice(&v4.octets());
        }
        Some(IpAddr::V6(v6)) => {
            avps.push(95);
            avps.push(18);
            avps.extend_from_slice(&v6.octets());
        }
        None => {}
    }

    // Service-Type (Type 6)
    if let Some(service_type) = spec.service_type {
        avps.push(6);
        avps.push(6);
        avps.extend_from_slice(&service_type.to_be_bytes());
    }

    // Framed-IP-Address (Type 8) or Framed-IPv6-Address (Type 168, RFC 6911)
    match spec.framed_ip {
        Some(IpAddr::V4(v4)) => {
            avps.push(8);
            avps.push(6);
            avps.extend_from_slice(&v4.octets());
        }
        Some(IpAddr::V6(v6)) => {
            avps.push(168);
            avps.push(18);
            avps.extend_from_slice(&v6.octets());
        }
        None => {}
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
