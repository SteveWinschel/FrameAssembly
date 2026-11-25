//! Cisco Gateway Load Balancing Protocol (GLBP) Layer 3 wire builder.
//!
//! Serializes a [`GlbpSpec`] into a Cisco GLBP packet carried over UDP port `3222` to IPv4
//! link-local multicast `224.0.0.102` (or IPv6 multicast `ff02::66`), while preserving explicit
//! unicast or multicast `dst_ip` targets. Encodes the 12-byte GLBP common header (`version`,
//! `group`, `ownerid` MAC) followed by a Type `1` Hello TLV (`state`, `priority`, `hellotime`,
//! `holdtime`, `redirect`, `timeout`, `vip`) or Type `2` Request/Response TLV (`forwarder`, `state`,
//! `priority`, `weight`, `vmac`), plus an optional Type `3` plain-text Auth TLV (`auth`).
//!
//! Canonical `.frasm` syntax:
//! `a -> b glbp [hello | request | response] [version <u8>] [group <0..1023>] [ownerid <mac>] [state <u8>] [priority <u8>] [weight <u8>] [forwarder <u8>] [hellotime <u32>] [holdtime <u32>] [redirect <u16>] [timeout <u16>] [vip <ip>] [vmac <mac>] [auth "<str>"]`

use crate::ast::*;
use crate::builders::WireContext;
use alloc::vec::Vec;
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Builds a Cisco GLBP payload over UDP port `3222` and returns `(bytes, target_ip, 3222)`.
pub fn build_glbp_payload(ctx: &WireContext, spec: &GlbpSpec, payload: &[u8]) -> (Vec<u8>, IpAddr, u16) {
    let is_v6 = ctx.src_ip.is_ipv6() || matches!(spec.vip, Some(IpAddr::V6(_)));
    let group = spec.group.unwrap_or(1) & 0x03FF;
    let owner_id = spec.owner_id.unwrap_or(ctx.src_mac);
    let msg_type = spec.msg_type.unwrap_or_else(|| {
        if spec.forwarder.is_some() || spec.weight.is_some() || spec.vmac.is_some() {
            GlbpType::Response
        } else {
            GlbpType::Hello
        }
    });

    let mut glbp = Vec::with_capacity(64 + payload.len());
    // 12-byte GLBP Common Header
    glbp.push(spec.version.unwrap_or(1));
    glbp.push(0); // Unknown1
    glbp.extend_from_slice(&group.to_be_bytes());
    glbp.extend_from_slice(&0_u16.to_be_bytes()); // Unknown2
    glbp.extend_from_slice(&owner_id);

    match msg_type {
        GlbpType::Hello => {
            let tlv_len: u8 = if is_v6 { 40 } else { 28 };
            glbp.push(1); // Type 1: Hello TLV
            glbp.push(tlv_len);
            glbp.push(0); // Unknown1-0
            glbp.push(spec.state.unwrap_or(0x20)); // VG State: Active (0x20)
            glbp.push(0); // Unknown1-1
            glbp.push(spec.priority.unwrap_or(100));
            glbp.extend_from_slice(&0_u16.to_be_bytes()); // Unknown1-2
            glbp.extend_from_slice(&spec.hellotime.unwrap_or(3000).to_be_bytes());
            glbp.extend_from_slice(&spec.holdtime.unwrap_or(10000).to_be_bytes());
            glbp.extend_from_slice(&spec.redirect.unwrap_or(600).to_be_bytes());
            glbp.extend_from_slice(&spec.timeout.unwrap_or(14400).to_be_bytes());
            glbp.extend_from_slice(&0_u16.to_be_bytes()); // Unknown1-3
            if is_v6 {
                glbp.push(2); // Address Type: IPv6
                glbp.push(16);
                let vip_octets = match spec.vip {
                    Some(IpAddr::V6(v6)) => v6.octets(),
                    _ => match ctx.src_ip {
                        IpAddr::V6(s) => s.octets(),
                        _ => Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1).octets(),
                    },
                };
                glbp.extend_from_slice(&vip_octets);
            } else {
                glbp.push(1); // Address Type: IPv4
                glbp.push(4);
                let vip_octets = match spec.vip {
                    Some(IpAddr::V4(v4)) => v4.octets(),
                    _ => match ctx.src_ip {
                        IpAddr::V4(s) => s.octets(),
                        _ => [192, 168, 1, 1],
                    },
                };
                glbp.extend_from_slice(&vip_octets);
            }
        }
        GlbpType::Request | GlbpType::Response => {
            let is_req = msg_type == GlbpType::Request;
            let fwd = spec.forwarder.unwrap_or(if is_req { 0 } else { 1 });
            let vf_state = spec.state.unwrap_or(if is_req { 0 } else { 0x20 });
            let vmac = spec.vmac.unwrap_or(if is_req {
                [0u8; 6]
            } else {
                [0x00, 0x07, 0xb4, 0x00, (group & 0xFF) as u8, fwd]
            });
            glbp.push(2); // Type 2: Request/Response TLV
            glbp.push(20);
            glbp.push(fwd);
            glbp.push(vf_state);
            glbp.push(0); // Unknown2-1
            glbp.push(spec.priority.unwrap_or(100));
            glbp.push(spec.weight.unwrap_or(100));
            glbp.extend_from_slice(&[0u8; 7]); // Unknown2-2
            glbp.extend_from_slice(&vmac);
        }
    }

    if let Some(auth) = spec.auth {
        let auth_bytes = auth.as_bytes();
        let alen = auth_bytes.len().min(251);
        glbp.push(3); // Type 3: Auth TLV
        glbp.push((4 + alen) as u8);
        glbp.push(1); // Plain text
        glbp.push(alen as u8);
        glbp.extend_from_slice(&auth_bytes[..alen]);
    }
    glbp.extend_from_slice(payload);

    let target_ip = if is_v6 {
        match ctx.dst_ip {
            IpAddr::V6(d) if !d.is_unspecified() => IpAddr::V6(d),
            _ => IpAddr::V6(Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0x66)),
        }
    } else {
        match ctx.dst_ip {
            IpAddr::V4(d) if !d.is_unspecified() => IpAddr::V4(d),
            _ => IpAddr::V4(Ipv4Addr::new(224, 0, 0, 102)),
        }
    };
    (glbp, target_ip, 3222)
}
