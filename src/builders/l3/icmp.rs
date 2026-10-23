//! ICMP Layer 3 protocol wire builder.

use crate::ast::*;
use crate::builders::WireContext;
use crate::error::CompilerError;
use crate::packet::internet_checksum;
use alloc::string::ToString;
use alloc::vec::Vec;
use core::net::IpAddr;

/// Builds an ICMP payload (RFC 792 for IPv4, RFC 4443 for IPv6).
///
/// Returns the serialized ICMP packet bytes and the IP protocol number (1 for v4, 58 for v6).
///
/// # Errors
/// Returns `CompilerError::BackendError` if IP endpoints fail resolution.
pub fn build_icmp_payload(
    ctx: &WireContext,
    spec: &IcmpSpec,
    payload: &[u8],
) -> Result<(Vec<u8>, u8), CompilerError> {
    match (ctx.src_ip, ctx.dst_ip) {
        (IpAddr::V4(_), IpAddr::V4(_)) => {
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

            let default_data = b"FrameAssembly ICMP Echo";
            let effective_data = if payload.is_empty() {
                &default_data[..]
            } else {
                payload
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

            let default_data = b"FrameAssembly ICMP Echo";
            let effective_data = if payload.is_empty() {
                &default_data[..]
            } else {
                payload
            };

            let mut icmp_pkt = Vec::with_capacity(8 + effective_data.len());
            icmp_pkt.push(icmp_type);
            icmp_pkt.push(icmp_code);
            icmp_pkt.push(0); // Checksum placeholder
            icmp_pkt.push(0);

            if icmp_type == 128 || icmp_type == 129 {
                icmp_pkt.extend_from_slice(&spec.id.unwrap_or(0x1234).to_be_bytes());
                icmp_pkt.extend_from_slice(&spec.seq.unwrap_or(1).to_be_bytes());
            } else {
                icmp_pkt.extend_from_slice(&[0u8; 4]);
            }
            icmp_pkt.extend_from_slice(effective_data);

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
