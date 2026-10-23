//! ARP Layer 2 protocol wire builder.

use crate::ast::*;
use crate::builders::WireContext;
use crate::error::CompilerError;
use crate::packet::{build_ethernet_and_l2, build_ip_packet, internet_checksum};
use alloc::string::ToString;
use alloc::vec::Vec;
use core::net::IpAddr;

/// Builds an ARP wire frame (RFC 826) or adapts to ICMPv6 Neighbor Discovery between IPv6 hosts.
///
/// # Errors
/// Returns `CompilerError::BackendError` if IP endpoints fail resolution.
pub fn build_arp_frame(
    ctx: &WireContext,
    spec: &ArpSpec,
    payload: &[u8],
) -> Result<Vec<u8>, CompilerError> {
    match (ctx.src_ip, ctx.dst_ip) {
        (IpAddr::V6(src_v6), IpAddr::V6(dst_v6)) => {
            // Polymorphic IPv6 adaptation: Map ARP Request to Neighbor Solicitation, Reply to Neighbor Advertisement
            let is_reply = spec.opcode == Some(ArpOpcode::Reply);
            if is_reply {
                // Neighbor Advertisement (Type 136, Code 0)
                let mut ndp_body = Vec::with_capacity(24 + payload.len());
                ndp_body.push(136); // Type
                ndp_body.push(0); // Code
                ndp_body.extend_from_slice(&[0, 0]); // Checksum placeholder
                ndp_body.extend_from_slice(&[0x60, 0, 0, 0]); // Flags: Solicited (0x40) + Override (0x20)
                ndp_body.extend_from_slice(&src_v6.octets()); // Target Address = caller
                // Option 2: Target Link-Layer Address (Type 2, Length 1 = 8 bytes)
                ndp_body.push(2);
                ndp_body.push(1);
                ndp_body.extend_from_slice(&ctx.src_mac);
                ndp_body.extend_from_slice(payload);

                // Compute ICMPv6 pseudo-header checksum
                let pseudo = {
                    let mut p = Vec::with_capacity(40);
                    p.extend_from_slice(&src_v6.octets());
                    p.extend_from_slice(&dst_v6.octets());
                    p.extend_from_slice(&(ndp_body.len() as u32).to_be_bytes());
                    p.extend_from_slice(&[0, 0, 0, 58]);
                    p
                };
                let cksum = internet_checksum(&[&pseudo, &ndp_body]);
                ndp_body[2..4].copy_from_slice(&cksum.to_be_bytes());

                let ip_pkt = build_ip_packet(ctx.src_ip, ctx.dst_ip, 58, ctx.l3, &ndp_body)?;
                Ok(build_ethernet_and_l2(ctx.src_mac, ctx.dst_mac, ctx.l2, 0x86DD, &ip_pkt))
            } else {
                // Neighbor Solicitation (Type 135, Code 0)
                let mut ndp_body = Vec::with_capacity(24 + payload.len());
                ndp_body.push(135); // Type
                ndp_body.push(0); // Code
                ndp_body.extend_from_slice(&[0, 0]); // Checksum placeholder
                ndp_body.extend_from_slice(&[0, 0, 0, 0]); // Reserved
                ndp_body.extend_from_slice(&dst_v6.octets()); // Target Address = callee
                // Option 1: Source Link-Layer Address (Type 1, Length 1 = 8 bytes)
                ndp_body.push(1);
                ndp_body.push(1);
                ndp_body.extend_from_slice(&ctx.src_mac);
                ndp_body.extend_from_slice(payload);

                // Target Solicited-Node Multicast IP and MAC
                let target_octets = dst_v6.octets();
                let mcast_ip = IpAddr::V6(core::net::Ipv6Addr::new(
                    0xff02, 0, 0, 0, 0, 1,
                    0xff00 | (target_octets[13] as u16),
                    ((target_octets[14] as u16) << 8) | (target_octets[15] as u16),
                ));
                let mcast_mac = [
                    0x33, 0x33, 0xff, target_octets[13], target_octets[14], target_octets[15],
                ];

                let pseudo = {
                    let mut p = Vec::with_capacity(40);
                    p.extend_from_slice(&src_v6.octets());
                    if let IpAddr::V6(m_ip) = mcast_ip {
                        p.extend_from_slice(&m_ip.octets());
                    }
                    p.extend_from_slice(&(ndp_body.len() as u32).to_be_bytes());
                    p.extend_from_slice(&[0, 0, 0, 58]);
                    p
                };
                let cksum = internet_checksum(&[&pseudo, &ndp_body]);
                ndp_body[2..4].copy_from_slice(&cksum.to_be_bytes());

                let ip_pkt = build_ip_packet(ctx.src_ip, mcast_ip, 58, ctx.l3, &ndp_body)?;
                let dst_mac = ctx.l2.dst_mac.unwrap_or(mcast_mac);
                Ok(build_ethernet_and_l2(ctx.src_mac, dst_mac, ctx.l2, 0x86DD, &ip_pkt))
            }
        }
        (IpAddr::V4(src_v4), IpAddr::V4(dst_v4)) => {
            let is_reply = spec.opcode == Some(ArpOpcode::Reply);
            let oper: u16 = if is_reply { 2 } else { 1 };

            let sha = spec.sha.unwrap_or(ctx.src_mac);
            let spa = match spec.spa {
                Some(IpAddr::V4(a)) => a.octets(),
                _ => src_v4.octets(),
            };

            let tha = if spec.is_gratuitous {
                [0u8; 6]
            } else if let Some(t) = spec.tha {
                t
            } else if is_reply {
                ctx.dst_mac
            } else {
                [0u8; 6]
            };

            let tpa = if spec.is_gratuitous {
                spa
            } else {
                match spec.tpa {
                    Some(IpAddr::V4(a)) => a.octets(),
                    _ => dst_v4.octets(),
                }
            };

            let mut arp_pkt = Vec::with_capacity(28 + payload.len());
            // Hardware Type: Ethernet (0x0001)
            arp_pkt.extend_from_slice(&1_u16.to_be_bytes());
            // Protocol Type: IPv4 (0x0800)
            arp_pkt.extend_from_slice(&0x0800_u16.to_be_bytes());
            // Hardware Size: 6
            arp_pkt.push(6);
            // Protocol Size: 4
            arp_pkt.push(4);
            // Opcode
            arp_pkt.extend_from_slice(&oper.to_be_bytes());
            // Sender MAC & IP
            arp_pkt.extend_from_slice(&sha);
            arp_pkt.extend_from_slice(&spa);
            // Target MAC & IP
            arp_pkt.extend_from_slice(&tha);
            arp_pkt.extend_from_slice(&tpa);
            arp_pkt.extend_from_slice(payload);

            let dst_mac = if let Some(m) = ctx.l2.dst_mac {
                m
            } else if is_reply {
                ctx.dst_mac
            } else {
                [0xFF; 6]
            };

            Ok(build_ethernet_and_l2(ctx.src_mac, dst_mac, ctx.l2, 0x0806, &arp_pkt))
        }
        _ => Err(CompilerError::BackendError(
            "ARP endpoints must have matching address families".to_string(),
        )),
    }
}
