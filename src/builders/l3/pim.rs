//! Protocol Independent Multicast - Sparse Mode (PIM-SM, RFC 7761) Layer 3 wire builder.
//!
//! Serializes a [`PimSpec`] into an 18-byte RFC 7761 PIMv2 packet encapsulated directly over IP
//! protocol `103` (`0x67`) and addressed to All-PIM-Routers (`224.0.0.13` for IPv4, `ff02::d` for
//! IPv6). The 4-byte PIMv2 header encodes `PIM Ver = 2` and `Type = 0` (`0x20`), an 8-bit `Reserved`
//! zero byte, and a 16-bit ones'-complement Internet Checksum, followed by Option `1` (`Holdtime`,
//! Length `2`, `HOLDTIME` default `105`s) and Option `19` (`DR Priority`, Length `4`, `DR_PRIORITY` default `1`).
//!
//! Canonical `.fasm` syntax:
//! `a -> b PIM [HELLO | JOIN_PRUNE | REGISTER] [HOLDTIME <u16>] [DR_PRIORITY <u32>] [GROUP <ip>] [SOURCE <ip>] [RP <ip>]`

use crate::ast::*;
use crate::builders::WireContext;
use crate::packet::internet_checksum;
use alloc::vec::Vec;
use core::net::IpAddr;

/// Extracts a 4-byte IPv4 representation from an `IpAddr` for PIMv2 encoded address records.
fn ipv4_octets_or(ip: Option<IpAddr>, fallback: [u8; 4]) -> [u8; 4] {
    match ip {
        Some(IpAddr::V4(v4)) => v4.octets(),
        Some(IpAddr::V6(v6)) => {
            let o = v6.octets();
            [o[12], o[13], o[14], o[15]]
        }
        None => fallback,
    }
}

/// Builds an RFC 7761 PIMv2 control payload over IP protocol `103`.
pub fn build_pim_payload(ctx: &WireContext, spec: &PimSpec, payload: &[u8]) -> (Vec<u8>, IpAddr, u8) {
    let mut pim = Vec::with_capacity(36 + payload.len());

    let is_register = spec.is_register || (spec.rp.is_some() && !spec.is_join_prune && !spec.is_hello);
    let is_join_prune =
        spec.is_join_prune || ((spec.group.is_some() || spec.source.is_some()) && !spec.is_hello && !is_register);

    if is_register {
        // PIMv2 Type 1: Register (RFC 7761 §4.9.3)
        pim.push(0x21); // Version 2, Type 1 (Register)
        pim.push(0); // Reserved
        pim.extend_from_slice(&[0, 0]); // Checksum placeholder
        pim.extend_from_slice(&0_u32.to_be_bytes()); // Border/Null-Register flags

        let src_v4 = ipv4_octets_or(spec.source.or(Some(ctx.src_ip)), [10, 0, 0, 1]);
        let grp_v4 = ipv4_octets_or(spec.group.or(spec.rp), [239, 1, 1, 1]);
        let mut inner_ip = [
            0x45, 0x00, 0x00, 20, 0x00, 0x01, 0x00, 0x00, 64, 17, 0x00, 0x00, src_v4[0],
            src_v4[1], src_v4[2], src_v4[3], grp_v4[0], grp_v4[1], grp_v4[2], grp_v4[3],
        ];
        let ip_cksum = internet_checksum(&[&inner_ip]);
        inner_ip[10..12].copy_from_slice(&ip_cksum.to_be_bytes());
        pim.extend_from_slice(&inner_ip);
    } else if is_join_prune {
        // PIMv2 Type 3: Join/Prune (RFC 7761 §4.9.5)
        pim.push(0x23); // Version 2, Type 3 (Join/Prune)
        pim.push(0); // Reserved
        pim.extend_from_slice(&[0, 0]); // Checksum placeholder

        // Encoded-Unicast Upstream Neighbor Address (Family 1 = IPv4, Encoding 0)
        let upstream = ipv4_octets_or(spec.rp.or(Some(ctx.dst_ip)), [10, 0, 0, 2]);
        pim.push(1);
        pim.push(0);
        pim.extend_from_slice(&upstream);

        pim.push(0); // Reserved
        pim.push(1); // Num groups = 1
        pim.extend_from_slice(&spec.holdtime.unwrap_or(210).to_be_bytes());

        // Encoded-Group Address (Family 1, Encoding 0, Reserved 0, Mask Len 32)
        let group = ipv4_octets_or(spec.group, [239, 1, 1, 1]);
        pim.extend_from_slice(&[1, 0, 0, 32]);
        pim.extend_from_slice(&group);

        pim.extend_from_slice(&1_u16.to_be_bytes()); // Number of Joined Sources = 1
        pim.extend_from_slice(&0_u16.to_be_bytes()); // Number of Pruned Sources = 0

        // Encoded-Source Address (Family 1, Encoding 0, Flags 0x04 Sparse, Mask Len 32)
        let source = ipv4_octets_or(spec.source.or(spec.rp).or(Some(ctx.src_ip)), [10, 0, 0, 1]);
        pim.extend_from_slice(&[1, 0, 0x04, 32]);
        pim.extend_from_slice(&source);
    } else {
        // PIMv2 Type 0: Hello (RFC 7761 §4.9.2)
        pim.push(0x20);
        pim.push(0); // Reserved
        pim.extend_from_slice(&[0, 0]); // Checksum placeholder

        // Option 1: Holdtime (Type 1, Length 2, Value 105)
        pim.extend_from_slice(&1_u16.to_be_bytes());
        pim.extend_from_slice(&2_u16.to_be_bytes());
        pim.extend_from_slice(&spec.holdtime.unwrap_or(105).to_be_bytes());

        // Option 19: DR Priority (Type 19, Length 4, Value 1)
        pim.extend_from_slice(&19_u16.to_be_bytes());
        pim.extend_from_slice(&4_u16.to_be_bytes());
        pim.extend_from_slice(&spec.dr_priority.unwrap_or(1).to_be_bytes());
    }

    pim.extend_from_slice(payload);

    let cksum = internet_checksum(&[&pim]);
    pim[2..4].copy_from_slice(&cksum.to_be_bytes());

    let dst_ip = match ctx.dst_ip {
        IpAddr::V6(_) => IpAddr::V6(core::net::Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0x0d)),
        _ => IpAddr::V4(core::net::Ipv4Addr::new(224, 0, 0, 13)),
    };

    (pim, dst_ip, 103)
}

