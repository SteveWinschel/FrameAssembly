//! Internet Control Message Protocol (ICMPv4 RFC 792 / ICMPv6 RFC 4443) Layer 3 wire builder.
//!
//! Serializes an [`IcmpSpec`] into either an RFC 792 ICMPv4 packet (IP protocol `1`) when both
//! endpoints are IPv4 or an RFC 4443 ICMPv6 packet (Next Header `58`) when both endpoints are IPv6.
//! The builder automatically maps symbolic types (`echorequest`, `echoreply`, `destunreach`,
//! `timeexceeded`, `redirect`) to their address-family-specific wire codes (`8`/`0`/`3`/`11`/`5` for
//! IPv4; `128`/`129`/`1`/`3`/`137` for IPv6), populates `id`, `seq`, or `gateway`, and computes the
//! ones'-complement Internet checksum (including the 40-byte IPv6 pseudo-header for ICMPv6).
//!
//! Canonical `.frasm` syntax:
//! `a -> b icmp [echorequest | echoreply | destunreach | timeexceeded | redirect] [type <u8>] [code <u8>] [id <u16>] [seq <u16>] [gateway <ipv4>]`

use crate::ast::*;
use crate::builders::WireContext;
use crate::error::CompilerError;
use crate::packet::internet_checksum;
use alloc::string::ToString;
use alloc::vec::Vec;
use core::net::IpAddr;

/// Builds a deterministic 28-byte RFC 792 invoking IPv4 header + 8-byte UDP datagram header for
/// zero-payload ICMPv4 error messages (`destunreach`, `timeexceeded`, `redirect`).
pub(crate) fn default_icmpv4_invoking_stub(outer_src: [u8; 4], outer_dst: [u8; 4]) -> [u8; 28] {
    let mut stub = [
        0x45, 0x00, 0x00, 28, 0x00, 0x00, 0x00, 0x00, 64, 17, 0x00, 0x00, outer_dst[0],
        outer_dst[1], outer_dst[2], outer_dst[3], outer_src[0], outer_src[1], outer_src[2],
        outer_src[3], 0x30, 0x39, 0x82, 0x9a, 0x00, 0x08, 0x00, 0x00,
    ];
    let csum = internet_checksum(&[&stub[0..20]]);
    stub[10..12].copy_from_slice(&csum.to_be_bytes());
    stub
}

/// Builds a deterministic 48-byte RFC 4443 invoking IPv6 header + 8-byte UDP datagram header for
/// zero-payload ICMPv6 error messages (`destunreach`, `timeexceeded`).
pub(crate) fn default_icmpv6_invoking_stub(outer_src: [u8; 16], outer_dst: [u8; 16]) -> [u8; 48] {
    let mut stub = [0u8; 48];
    stub[0..8].copy_from_slice(&[0x60, 0x00, 0x00, 0x00, 0x00, 0x08, 17, 64]);
    stub[8..24].copy_from_slice(&outer_dst);
    stub[24..40].copy_from_slice(&outer_src);
    stub[40..46].copy_from_slice(&[0x30, 0x39, 0x82, 0x9a, 0x00, 0x08]);
    let mut pseudo = [0u8; 40];
    pseudo[0..16].copy_from_slice(&outer_dst);
    pseudo[16..32].copy_from_slice(&outer_src);
    pseudo[32..36].copy_from_slice(&8_u32.to_be_bytes());
    pseudo[39] = 17;
    let udp_csum = internet_checksum(&[&pseudo, &stub[40..48]]);
    let final_udp_csum = if udp_csum == 0 { 0xFFFF } else { udp_csum };
    stub[46..48].copy_from_slice(&final_udp_csum.to_be_bytes());
    stub
}

/// Builds an ICMP payload (RFC 792 for IPv4, RFC 4443 for IPv6).
///
/// Returns the serialized ICMP packet bytes and the IP protocol number (`1` for v4, `58` for v6).
///
/// # Errors
/// Returns `CompilerError::BackendError` if IP endpoints have mismatched address families.
pub fn build_icmp_payload(
    ctx: &WireContext,
    spec: &IcmpSpec,
    payload: &[u8],
) -> Result<(Vec<u8>, u8), CompilerError> {
    match (ctx.src_ip, ctx.dst_ip) {
        (IpAddr::V4(src_v4), IpAddr::V4(dst_v4)) => {
            let (icmp_type, icmp_code) = if let Some(t) = spec.icmp_type {
                (t, spec.icmp_code.unwrap_or(0))
            } else {
                match spec.type_choice.unwrap_or(IcmpTypeChoice::EchoRequest) {
                    IcmpTypeChoice::EchoRequest => (8, 0),
                    IcmpTypeChoice::EchoReply => (0, 0),
                    IcmpTypeChoice::DestUnreach => (3, spec.icmp_code.unwrap_or(0)),
                    IcmpTypeChoice::TimeExceeded => (11, spec.icmp_code.unwrap_or(0)),
                    IcmpTypeChoice::Redirect => (5, spec.icmp_code.unwrap_or(0)),
                }
            };

            let invoking_stub = default_icmpv4_invoking_stub(src_v4.octets(), dst_v4.octets());
            let default_echo = b"FrameAssembly ICMP Echo";
            let effective_data: &[u8] = if !payload.is_empty() {
                payload
            } else if icmp_type == 8 || icmp_type == 0 {
                &default_echo[..]
            } else {
                &invoking_stub[..]
            };

            let mut icmp_pkt = Vec::with_capacity(8 + effective_data.len());
            icmp_pkt.push(icmp_type);
            icmp_pkt.push(icmp_code);
            icmp_pkt.push(0); // Checksum placeholder
            icmp_pkt.push(0);

            if icmp_type == 8 || icmp_type == 0 {
                icmp_pkt.extend_from_slice(&spec.id.unwrap_or(0x1234).to_be_bytes());
                icmp_pkt.extend_from_slice(&spec.seq.unwrap_or(1).to_be_bytes());
            } else if icmp_type == 5 {
                let gw_octets = match spec.gateway {
                    Some(IpAddr::V4(g)) => g.octets(),
                    _ => [0, 0, 0, 0],
                };
                icmp_pkt.extend_from_slice(&gw_octets);
            } else {
                icmp_pkt.extend_from_slice(&[0u8; 4]);
            }
            icmp_pkt.extend_from_slice(effective_data);

            let cksum = internet_checksum(&[&icmp_pkt]);
            icmp_pkt[2..4].copy_from_slice(&cksum.to_be_bytes());

            Ok((icmp_pkt, 1))
        }
        (IpAddr::V6(src_v6), IpAddr::V6(dst_v6)) => {
            let (icmp_type, icmp_code) = if let Some(t) = spec.icmp_type {
                (t, spec.icmp_code.unwrap_or(0))
            } else {
                match spec.type_choice.unwrap_or(IcmpTypeChoice::EchoRequest) {
                    IcmpTypeChoice::EchoRequest => (128, 0),
                    IcmpTypeChoice::EchoReply => (129, 0),
                    IcmpTypeChoice::DestUnreach => (1, spec.icmp_code.unwrap_or(0)),
                    IcmpTypeChoice::TimeExceeded => (3, spec.icmp_code.unwrap_or(0)),
                    IcmpTypeChoice::Redirect => (137, spec.icmp_code.unwrap_or(0)),
                }
            };

            let mut icmp_pkt = Vec::with_capacity(56 + payload.len());
            icmp_pkt.push(icmp_type);
            icmp_pkt.push(icmp_code);
            icmp_pkt.push(0); // Checksum placeholder
            icmp_pkt.push(0);

            if icmp_type == 128 || icmp_type == 129 {
                icmp_pkt.extend_from_slice(&spec.id.unwrap_or(0x1234).to_be_bytes());
                icmp_pkt.extend_from_slice(&spec.seq.unwrap_or(1).to_be_bytes());
                if payload.is_empty() {
                    icmp_pkt.extend_from_slice(b"FrameAssembly ICMP Echo");
                } else {
                    icmp_pkt.extend_from_slice(payload);
                }
            } else if icmp_type == 137 {
                // RFC 4861 §4.5 40-byte ICMPv6 Redirect (Reserved 4B + Target 16B + Dest 16B)
                icmp_pkt.extend_from_slice(&[0u8; 4]);
                let target_octets = match spec.gateway {
                    Some(IpAddr::V6(g)) => g.octets(),
                    _ => dst_v6.octets(),
                };
                icmp_pkt.extend_from_slice(&target_octets);
                icmp_pkt.extend_from_slice(&dst_v6.octets());
                icmp_pkt.extend_from_slice(payload);
            } else {
                icmp_pkt.extend_from_slice(&[0u8; 4]);
                if payload.is_empty() {
                    let stub6 = default_icmpv6_invoking_stub(src_v6.octets(), dst_v6.octets());
                    icmp_pkt.extend_from_slice(&stub6);
                } else {
                    icmp_pkt.extend_from_slice(payload);
                }
            }

            let pseudo = {
                let mut p = Vec::with_capacity(40);
                p.extend_from_slice(&src_v6.octets());
                p.extend_from_slice(&dst_v6.octets());
                p.extend_from_slice(&(icmp_pkt.len() as u32).to_be_bytes());
                p.extend_from_slice(&[0, 0, 0, 58]);
                p
            };
            let cksum = internet_checksum(&[&pseudo, &icmp_pkt]);
            icmp_pkt[2..4].copy_from_slice(&cksum.to_be_bytes());

            Ok((icmp_pkt, 58))
        }
        _ => Err(CompilerError::BackendError(
            "ICMP endpoints must have matching address families".to_string(),
        )),
    }
}
