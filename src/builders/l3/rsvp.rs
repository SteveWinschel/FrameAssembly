//! Resource Reservation Protocol (RSVP / RSVP-TE, RFC 2205 / RFC 3209) Layer 3 wire builder.
//!
//! Serializes an [`RsvpSpec`] into an RFC 2205 / RFC 3209 RSVP control packet carried directly
//! over IP protocol `46` (`0x2E`). Encodes the 8-byte RSVP common header (Version `1`, Message
//! Type `path`/`resv`/`patherr`/`resverr`/`pathtear`/`resvtear`/`resvconf`/`hello`, RFC 1071
//! RSVP checksum, Send TTL, and RSVP Length) followed by typed `SESSION`, `RSVP_HOP`,
//! `TIME_VALUES`, `STYLE`, `SENDER_TEMPLATE` / `FILTER_SPEC`, `ERROR_SPEC`, `RESV_CONFIRM`,
//! `LABEL`, and RFC 3209 `HELLO` objects across both IPv4 and IPv6 endpoints.
//!
//! Canonical `.frasm` syntax:
//! `a -> b rsvp [path | resv | patherr | resverr | pathtear | resvtear | resvconf | hello] [tunnelid <u16>] [lspid <u16>] [label <u32>] [refresh <u32>] [srcip <ip>] [dstip <ip>] [errcode <u8>]`

use crate::ast::*;
use crate::builders::WireContext;
use crate::packet::internet_checksum;
use alloc::vec::Vec;
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Appends an RSVP `SESSION` object (Class `1`, C-Type `1`/`2` or LSP_TUNNEL `7`/`8`).
fn push_session_obj(
    out: &mut Vec<u8>,
    is_v6: bool,
    dst: IpAddr,
    src: IpAddr,
    tunnel_id: Option<u16>,
) {
    match (is_v6, tunnel_id) {
        (false, Some(tid)) => {
            let d = match dst {
                IpAddr::V4(v4) => v4.octets(),
                _ => [10, 0, 0, 2],
            };
            let s = match src {
                IpAddr::V4(v4) => v4.octets(),
                _ => [10, 0, 0, 1],
            };
            out.extend_from_slice(&[0, 16, 1, 7]);
            out.extend_from_slice(&d);
            out.extend_from_slice(&[0, 0]);
            out.extend_from_slice(&tid.to_be_bytes());
            out.extend_from_slice(&s);
        }
        (false, None) => {
            let d = match dst {
                IpAddr::V4(v4) => v4.octets(),
                _ => [10, 0, 0, 2],
            };
            out.extend_from_slice(&[0, 12, 1, 1]);
            out.extend_from_slice(&d);
            out.extend_from_slice(&[0, 0, 0, 0]);
        }
        (true, Some(tid)) => {
            let d = match dst {
                IpAddr::V6(v6) => v6.octets(),
                _ => [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2],
            };
            let s = match src {
                IpAddr::V6(v6) => v6.octets(),
                _ => [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            };
            out.extend_from_slice(&[0, 40, 1, 8]);
            out.extend_from_slice(&d);
            out.extend_from_slice(&[0, 0]);
            out.extend_from_slice(&tid.to_be_bytes());
            out.extend_from_slice(&s);
        }
        (true, None) => {
            let d = match dst {
                IpAddr::V6(v6) => v6.octets(),
                _ => [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2],
            };
            out.extend_from_slice(&[0, 24, 1, 2]);
            out.extend_from_slice(&d);
            out.extend_from_slice(&[0, 0, 0, 0]);
        }
    }
}

/// Appends an RSVP `RSVP_HOP` object (Class `3`, C-Type `1` IPv4 or `2` IPv6).
fn push_hop_obj(out: &mut Vec<u8>, is_v6: bool, hop: IpAddr) {
    if is_v6 {
        let h = match hop {
            IpAddr::V6(v6) => v6.octets(),
            _ => [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
        };
        out.extend_from_slice(&[0, 24, 3, 2]);
        out.extend_from_slice(&h);
        out.extend_from_slice(&1_u32.to_be_bytes());
    } else {
        let h = match hop {
            IpAddr::V4(v4) => v4.octets(),
            _ => [10, 0, 0, 1],
        };
        out.extend_from_slice(&[0, 12, 3, 1]);
        out.extend_from_slice(&h);
        out.extend_from_slice(&1_u32.to_be_bytes());
    }
}

/// Appends an RSVP `SENDER_TEMPLATE` (`11`) or `FILTER_SPEC` (`10`) object.
fn push_sender_or_filter_obj(
    out: &mut Vec<u8>,
    class: u8,
    is_v6: bool,
    src: IpAddr,
    lsp_id: Option<u16>,
) {
    let ctype = match (is_v6, lsp_id.is_some()) {
        (false, false) => 1_u8,
        (false, true) => 7_u8,
        (true, false) => 2_u8,
        (true, true) => 8_u8,
    };
    let tail = lsp_id.unwrap_or(0);
    if is_v6 {
        let s = match src {
            IpAddr::V6(v6) => v6.octets(),
            _ => [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
        };
        out.extend_from_slice(&[0, 24, class, ctype]);
        out.extend_from_slice(&s);
        out.extend_from_slice(&[0, 0]);
        out.extend_from_slice(&tail.to_be_bytes());
    } else {
        let s = match src {
            IpAddr::V4(v4) => v4.octets(),
            _ => [10, 0, 0, 1],
        };
        out.extend_from_slice(&[0, 12, class, ctype]);
        out.extend_from_slice(&s);
        out.extend_from_slice(&[0, 0]);
        out.extend_from_slice(&tail.to_be_bytes());
    }
}

/// Appends an RSVP `ERROR_SPEC` object (Class `6`, C-Type `1` IPv4 or `2` IPv6).
fn push_error_spec_obj(out: &mut Vec<u8>, is_v6: bool, node: IpAddr, err_code: u8) {
    if is_v6 {
        let n = match node {
            IpAddr::V6(v6) => v6.octets(),
            _ => [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
        };
        out.extend_from_slice(&[0, 24, 6, 2]);
        out.extend_from_slice(&n);
        out.extend_from_slice(&[0, err_code, 0, 0]);
    } else {
        let n = match node {
            IpAddr::V4(v4) => v4.octets(),
            _ => [10, 0, 0, 1],
        };
        out.extend_from_slice(&[0, 12, 6, 1]);
        out.extend_from_slice(&n);
        out.extend_from_slice(&[0, err_code, 0, 0]);
    }
}

/// Builds an RFC 2205 / RFC 3209 RSVP control message payload over IP protocol `46`.
pub fn build_rsvp_payload(ctx: &WireContext, spec: &RsvpSpec, payload: &[u8]) -> (Vec<u8>, u8) {
    let is_v6 = ctx.src_ip.is_ipv6();
    let eff_src = match (is_v6, spec.src_ip) {
        (true, Some(IpAddr::V6(v6))) => IpAddr::V6(v6),
        (false, Some(IpAddr::V4(v4))) => IpAddr::V4(v4),
        _ => match ctx.src_ip {
            IpAddr::V6(v6) if !v6.is_unspecified() => IpAddr::V6(v6),
            IpAddr::V4(v4) if !v4.is_unspecified() => IpAddr::V4(v4),
            IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1)),
            IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        },
    };
    let eff_dst = match (is_v6, spec.dst_ip) {
        (true, Some(IpAddr::V6(v6))) => IpAddr::V6(v6),
        (false, Some(IpAddr::V4(v4))) => IpAddr::V4(v4),
        _ => match ctx.dst_ip {
            IpAddr::V6(v6) if !v6.is_unspecified() => IpAddr::V6(v6),
            IpAddr::V4(v4) if !v4.is_unspecified() => IpAddr::V4(v4),
            IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 2)),
            IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        },
    };

    let msg_type = spec.msg_type.unwrap_or(RsvpType::Path);
    let msg_code = match msg_type {
        RsvpType::Path => 1_u8,
        RsvpType::Resv => 2_u8,
        RsvpType::PathErr => 3_u8,
        RsvpType::ResvErr => 4_u8,
        RsvpType::PathTear => 5_u8,
        RsvpType::ResvTear => 6_u8,
        RsvpType::ResvConf => 7_u8,
        RsvpType::Hello => 20_u8,
    };

    let mut rsvp = Vec::with_capacity(96 + payload.len());
    rsvp.push(0x10); // Version 1, Flags 0
    rsvp.push(msg_code);
    rsvp.extend_from_slice(&[0, 0]); // Checksum placeholder
    rsvp.push(ctx.l3.ttl.unwrap_or(64)); // Send_TTL
    rsvp.push(0); // Reserved
    rsvp.extend_from_slice(&[0, 0]); // RSVP Length placeholder

    let refresh = spec.refresh.unwrap_or(30_000);
    let err_code = spec.err_code.unwrap_or(2);

    match msg_type {
        RsvpType::Hello => {
            // RFC 3209 §5 HELLO Object (Class 22, C-Type 1 Hello Request)
            rsvp.extend_from_slice(&[0, 12, 22, 1]);
            rsvp.extend_from_slice(&1_u32.to_be_bytes());
            rsvp.extend_from_slice(&0_u32.to_be_bytes());
        }
        RsvpType::Path => {
            push_session_obj(&mut rsvp, is_v6, eff_dst, eff_src, spec.tunnel_id);
            push_hop_obj(&mut rsvp, is_v6, eff_src);
            rsvp.extend_from_slice(&[0, 8, 5, 1]); // TIME_VALUES
            rsvp.extend_from_slice(&refresh.to_be_bytes());
            push_sender_or_filter_obj(&mut rsvp, 11, is_v6, eff_src, spec.lsp_id);
            if let Some(lbl) = spec.label {
                rsvp.extend_from_slice(&[0, 8, 16, 1]); // LABEL
                rsvp.extend_from_slice(&(lbl & 0x000F_FFFF).to_be_bytes());
            }
        }
        RsvpType::Resv => {
            push_session_obj(&mut rsvp, is_v6, eff_dst, eff_src, spec.tunnel_id);
            push_hop_obj(&mut rsvp, is_v6, eff_src);
            rsvp.extend_from_slice(&[0, 8, 5, 1]); // TIME_VALUES
            rsvp.extend_from_slice(&refresh.to_be_bytes());
            rsvp.extend_from_slice(&[0, 8, 8, 1, 0, 0, 0, 10]); // STYLE: Fixed Filter (FF)
            push_sender_or_filter_obj(&mut rsvp, 10, is_v6, eff_src, spec.lsp_id);
            if let Some(lbl) = spec.label {
                rsvp.extend_from_slice(&[0, 8, 16, 1]); // LABEL
                rsvp.extend_from_slice(&(lbl & 0x000F_FFFF).to_be_bytes());
            }
        }
        RsvpType::PathErr | RsvpType::ResvErr => {
            push_session_obj(&mut rsvp, is_v6, eff_dst, eff_src, spec.tunnel_id);
            push_error_spec_obj(&mut rsvp, is_v6, eff_src, err_code);
        }
        RsvpType::PathTear => {
            push_session_obj(&mut rsvp, is_v6, eff_dst, eff_src, spec.tunnel_id);
            push_hop_obj(&mut rsvp, is_v6, eff_src);
            push_sender_or_filter_obj(&mut rsvp, 11, is_v6, eff_src, spec.lsp_id);
        }
        RsvpType::ResvTear => {
            push_session_obj(&mut rsvp, is_v6, eff_dst, eff_src, spec.tunnel_id);
            push_hop_obj(&mut rsvp, is_v6, eff_src);
            rsvp.extend_from_slice(&[0, 8, 8, 1, 0, 0, 0, 10]); // STYLE: FF
            push_sender_or_filter_obj(&mut rsvp, 10, is_v6, eff_src, spec.lsp_id);
        }
        RsvpType::ResvConf => {
            push_session_obj(&mut rsvp, is_v6, eff_dst, eff_src, spec.tunnel_id);
            push_error_spec_obj(&mut rsvp, is_v6, eff_src, err_code);
            if is_v6 {
                let d = match eff_dst {
                    IpAddr::V6(v6) => v6.octets(),
                    _ => [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2],
                };
                rsvp.extend_from_slice(&[0, 20, 15, 2]);
                rsvp.extend_from_slice(&d);
            } else {
                let d = match eff_dst {
                    IpAddr::V4(v4) => v4.octets(),
                    _ => [10, 0, 0, 2],
                };
                rsvp.extend_from_slice(&[0, 8, 15, 1]);
                rsvp.extend_from_slice(&d);
            }
        }
    }

    let rsvp_len = u16::try_from(rsvp.len()).unwrap_or(u16::MAX);
    rsvp[6..8].copy_from_slice(&rsvp_len.to_be_bytes());
    rsvp.extend_from_slice(payload);

    let csum = internet_checksum(&[&rsvp[..usize::from(rsvp_len)]]);
    rsvp[2..4].copy_from_slice(&csum.to_be_bytes());

    (rsvp, 46)
}
