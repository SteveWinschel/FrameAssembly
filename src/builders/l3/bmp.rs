//! BGP Monitoring Protocol (BMP, RFC 7854 / RFC 8671 / RFC 9069) Layer 3 wire builder.
//!
//! Serializes a [`BmpSpec`] into an RFC 7854 BMP message carried over TCP destination port
//! `1790`. Every message opens with the 6-byte BMP common header (`version` `3`, 32-bit total
//! `Length`, and 8-bit `Message Type`). `routemon` (`0`), `statsreport` (`1`), `peerdown` (`2`),
//! and `peerup` (`3`) append the 42-byte Per-Peer Header (`peertype`, `flags`, `peerip`, `asn`,
//! `bgpid`, timestamp) followed by BGP PDUs, stat counters, reason codes, or Sent/Received BGP
//! `OPEN` messages; `initiation` (`4`) and `termination` (`5`) encode RFC 7854 Information TLVs.
//!
//! Canonical `.frasm` syntax:
//! `a -> b bmp [routemon | statsreport | peerdown | peerup | initiation | termination] [version <u8>] [peertype <u8>] [flags <u8>] [peerip <ip>] [asn <u32>] [bgpid <ipv4>] [sysname "<str>"] [sysdesc "<str>"] [reason <u16>]`

use crate::ast::*;
use crate::builders::WireContext;
use alloc::vec::Vec;
use core::net::IpAddr;

/// Appends the 42-byte RFC 7854 §4.2 Per-Peer Header onto `out`.
fn push_bmp_per_peer_header(out: &mut Vec<u8>, ctx: &WireContext, spec: &BmpSpec) {
    let peer_ip = spec.peer_ip.unwrap_or(ctx.dst_ip);
    let is_v6 = matches!(peer_ip, IpAddr::V6(_));
    let peer_type = spec.peer_type.unwrap_or(0);
    let flags = spec.peer_flags.unwrap_or(if is_v6 { 0x80 } else { 0x00 });

    out.push(peer_type);
    out.push(flags);
    out.extend_from_slice(&[0u8; 8]); // Peer Distinguisher (0 for Global Instance)

    match peer_ip {
        IpAddr::V4(v4) => {
            out.extend_from_slice(&[0u8; 12]);
            out.extend_from_slice(&v4.octets());
        }
        IpAddr::V6(v6) => {
            out.extend_from_slice(&v6.octets());
        }
    }

    let asn = spec.peer_asn.unwrap_or(65001);
    out.extend_from_slice(&asn.to_be_bytes());

    let bgpid = match spec.peer_bgpid {
        Some(IpAddr::V4(v4)) => v4.octets(),
        _ => match peer_ip {
            IpAddr::V4(v4) if !v4.is_unspecified() => v4.octets(),
            _ => [192, 0, 2, 2],
        },
    };
    out.extend_from_slice(&bgpid);
    out.extend_from_slice(&1_700_000_000_u32.to_be_bytes()); // Timestamp seconds
    out.extend_from_slice(&0_u32.to_be_bytes()); // Timestamp microseconds
}

/// Appends an RFC 7854 §4.4 Information TLV (`type: u16`, `len: u16`, `value`).
fn push_bmp_info_tlv(out: &mut Vec<u8>, tlv_type: u16, value: &[u8]) {
    let len = value.len().min(usize::from(u16::MAX)) as u16;
    out.extend_from_slice(&tlv_type.to_be_bytes());
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(&value[..usize::from(len)]);
}

/// Appends a minimal 29-byte RFC 4271 BGP `OPEN` message for BMP `Peer Up` notifications.
fn push_minimal_bgp_open(out: &mut Vec<u8>, asn32: u32, bgpid: [u8; 4]) {
    let asn16: u16 = if asn32 > 65535 { 23456 } else { asn32 as u16 };
    out.extend_from_slice(&[0xFF; 16]);
    out.extend_from_slice(&29_u16.to_be_bytes());
    out.push(1); // OPEN
    out.push(4); // BGP-4
    out.extend_from_slice(&asn16.to_be_bytes());
    out.extend_from_slice(&180_u16.to_be_bytes());
    out.extend_from_slice(&bgpid);
    out.push(0); // Opt Parm Len = 0
}

/// Builds an RFC 7854 BMP payload and returns `(bytes, 1790)` for TCP encapsulation.
pub fn build_bmp_payload(ctx: &WireContext, spec: &BmpSpec, payload: &[u8]) -> (Vec<u8>, u16) {
    let has_peer_fields = spec.peer_type.is_some()
        || spec.peer_flags.is_some()
        || spec.peer_ip.is_some()
        || spec.peer_asn.is_some()
        || spec.peer_bgpid.is_some();
    let msg_type = spec.msg_type.unwrap_or(if has_peer_fields {
        BmpType::RouteMonitoring
    } else if spec.reason.is_some() {
        BmpType::Termination
    } else {
        BmpType::Initiation
    });
    let type_code = match msg_type {
        BmpType::RouteMonitoring => 0_u8,
        BmpType::StatsReport => 1_u8,
        BmpType::PeerDown => 2_u8,
        BmpType::PeerUp => 3_u8,
        BmpType::Initiation => 4_u8,
        BmpType::Termination => 5_u8,
    };

    let mut bmp = Vec::with_capacity(64 + payload.len());
    bmp.push(spec.version.unwrap_or(3));
    bmp.extend_from_slice(&0_u32.to_be_bytes()); // Total Message Length placeholder
    bmp.push(type_code);

    match msg_type {
        BmpType::RouteMonitoring => {
            push_bmp_per_peer_header(&mut bmp, ctx, spec);
            if payload.is_empty() {
                // 23-byte RFC 4724 BGP End-of-RIB UPDATE marker
                bmp.extend_from_slice(&[0xFF; 16]);
                bmp.extend_from_slice(&23_u16.to_be_bytes());
                bmp.push(2); // UPDATE
                bmp.extend_from_slice(&0_u16.to_be_bytes()); // Withdrawn Routes Length
                bmp.extend_from_slice(&0_u16.to_be_bytes()); // Total Path Attribute Length
            } else {
                bmp.extend_from_slice(payload);
            }
        }
        BmpType::StatsReport => {
            push_bmp_per_peer_header(&mut bmp, ctx, spec);
            bmp.extend_from_slice(&1_u32.to_be_bytes()); // Stats Count = 1
            let stat_type = spec.reason.unwrap_or(0);
            bmp.extend_from_slice(&stat_type.to_be_bytes());
            bmp.extend_from_slice(&4_u16.to_be_bytes());
            bmp.extend_from_slice(&0_u32.to_be_bytes());
            bmp.extend_from_slice(payload);
        }
        BmpType::PeerDown => {
            push_bmp_per_peer_header(&mut bmp, ctx, spec);
            let reason = spec.reason.unwrap_or(3) as u8;
            bmp.push(reason);
            if payload.is_empty() {
                if reason == 1 {
                    // 21-byte BGP Cease NOTIFICATION
                    bmp.extend_from_slice(&[0xFF; 16]);
                    bmp.extend_from_slice(&21_u16.to_be_bytes());
                    bmp.extend_from_slice(&[3, 6, 0]);
                } else if reason == 2 {
                    bmp.extend_from_slice(&0_u16.to_be_bytes()); // 2B FSM Event Code
                }
            } else {
                bmp.extend_from_slice(payload);
            }
        }
        BmpType::PeerUp => {
            push_bmp_per_peer_header(&mut bmp, ctx, spec);
            match ctx.src_ip {
                IpAddr::V4(v4) => {
                    bmp.extend_from_slice(&[0u8; 12]);
                    bmp.extend_from_slice(&v4.octets());
                }
                IpAddr::V6(v6) => bmp.extend_from_slice(&v6.octets()),
            }
            bmp.extend_from_slice(&179_u16.to_be_bytes()); // Local Port
            bmp.extend_from_slice(&179_u16.to_be_bytes()); // Remote Port
            let asn32 = spec.peer_asn.unwrap_or(65001);
            let local_bgpid = match ctx.src_ip {
                IpAddr::V4(v4) if !v4.is_unspecified() => v4.octets(),
                _ => [192, 0, 2, 1],
            };
            let peer_ip = spec.peer_ip.unwrap_or(ctx.dst_ip);
            let peer_bgpid = match spec.peer_bgpid {
                Some(IpAddr::V4(v4)) => v4.octets(),
                _ => match peer_ip {
                    IpAddr::V4(v4) if !v4.is_unspecified() => v4.octets(),
                    _ => [192, 0, 2, 2],
                },
            };
            push_minimal_bgp_open(&mut bmp, asn32, local_bgpid);
            push_minimal_bgp_open(&mut bmp, asn32, peer_bgpid);
            bmp.extend_from_slice(payload);
        }
        BmpType::Initiation => {
            if let Some(desc) = spec.sysdesc {
                push_bmp_info_tlv(&mut bmp, 1, desc.as_bytes());
            }
            if let Some(name) = spec.sysname {
                push_bmp_info_tlv(&mut bmp, 2, name.as_bytes());
            } else if spec.sysdesc.is_none() && payload.is_empty() {
                push_bmp_info_tlv(&mut bmp, 2, b"FrameAssembly");
            }
            bmp.extend_from_slice(payload);
        }
        BmpType::Termination => {
            let reason = spec.reason.unwrap_or(0);
            push_bmp_info_tlv(&mut bmp, 1, &reason.to_be_bytes());
            bmp.extend_from_slice(payload);
        }
    }

    let total_len = u32::try_from(bmp.len()).unwrap_or(u32::MAX);
    bmp[1..5].copy_from_slice(&total_len.to_be_bytes());
    (bmp, 1790)
}
