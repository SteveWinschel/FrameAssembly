//! Traversal Using Relays around NAT (TURN, RFC 8656 / RFC 5766) Layer 7 wire builder.
//!
//! This module implements [`build_turn_payload`], which synthesizes deterministic RFC 8656 / RFC
//! 5766 Traversal Using Relays around NAT (TURN) messages over UDP or TCP port 3478. It constructs
//! either 4-byte `ChannelData` relay headers (`0x4000..=0x7FFF`, 4-byte padded over TCP) or
//! STUN-formatted 20-byte TURN control messages (`Allocate` `0x0003`/`0x0103`/`0x0113`, `Refresh`
//! `0x0004`/`0x0104`/`0x0114`, `Send` `0x0016`, `Data` `0x0017`, `CreatePermission` `0x0008`,
//! `ChannelBind` `0x0009`) with Magic Cookie `0x2112A442` and 4-byte-aligned TLV attributes.

use alloc::vec::Vec;
use core::net::{IpAddr, Ipv4Addr};

use crate::ast::*;
use crate::builders::WireContext;

/// Fixed 8-byte tail completing the 96-bit STUN/TURN Transaction ID after the `u32` prefix.
const TURN_TXID_TAIL: [u8; 8] = [0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc];

/// Appends a 4-byte-aligned STUN/TURN TLV attribute (`type`, `len`, `val`, zero padding).
fn push_turn_attr(attrs: &mut Vec<u8>, attr_type: u16, val: &[u8]) {
    let clamped = &val[..val.len().min(usize::from(u16::MAX))];
    attrs.extend_from_slice(&attr_type.to_be_bytes());
    attrs.extend_from_slice(&(clamped.len() as u16).to_be_bytes());
    attrs.extend_from_slice(clamped);
    let pad = (4 - (clamped.len() % 4)) % 4;
    attrs.resize(attrs.len() + pad, 0);
}

/// Appends an XOR-encoded STUN/TURN address attribute (`0x0012`, `0x0016`, or `0x0020`).
fn push_xor_addr_attr(
    attrs: &mut Vec<u8>,
    attr_type: u16,
    ip: IpAddr,
    port: u16,
    txid_prefix: u32,
) {
    let xport = port ^ 0x2112;
    match ip {
        IpAddr::V4(v4) => {
            attrs.extend_from_slice(&attr_type.to_be_bytes());
            attrs.extend_from_slice(&8u16.to_be_bytes());
            attrs.push(0);
            attrs.push(1);
            attrs.extend_from_slice(&xport.to_be_bytes());
            let xaddr = u32::from_be_bytes(v4.octets()) ^ 0x2112_A442;
            attrs.extend_from_slice(&xaddr.to_be_bytes());
        }
        IpAddr::V6(v6) => {
            attrs.extend_from_slice(&attr_type.to_be_bytes());
            attrs.extend_from_slice(&20u16.to_be_bytes());
            attrs.push(0);
            attrs.push(2);
            attrs.extend_from_slice(&xport.to_be_bytes());
            let mut xor_mask = [0u8; 16];
            xor_mask[0..4].copy_from_slice(&0x2112_A442u32.to_be_bytes());
            xor_mask[4..8].copy_from_slice(&txid_prefix.to_be_bytes());
            xor_mask[8..16].copy_from_slice(&TURN_TXID_TAIL);
            let octets = v6.octets();
            for i in 0..16 {
                attrs.push(octets[i] ^ xor_mask[i]);
            }
        }
    }
}

/// Returns the canonical RFC 8656 / RFC 8489 reason phrase for a STUN/TURN error code.
fn default_turn_error_reason(code: u16) -> &'static str {
    match code {
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        420 => "Unknown Attribute",
        437 => "Allocation Mismatch",
        438 => "Stale Nonce",
        440 => "Address Family Not Supported",
        441 => "Wrong Credentials",
        442 => "Unsupported Transport Protocol",
        443 => "Peer Address Family Mismatch",
        486 => "Allocation Quota Reached",
        500 => "Server Error",
        508 => "Insufficient Capacity",
        _ => "Error",
    }
}

/// Checks whether `buf` is already a 4-byte-aligned sequence of non-extracted TURN TLV attributes.
fn is_valid_turn_attrs(buf: &[u8]) -> bool {
    if buf.is_empty() || !buf.len().is_multiple_of(4) {
        return false;
    }
    let mut pos = 0usize;
    while pos < buf.len() {
        let Some(hdr) = buf.get(pos..pos + 4) else {
            return false;
        };
        let atype = u16::from_be_bytes([hdr[0], hdr[1]]);
        let alen = usize::from(u16::from_be_bytes([hdr[2], hdr[3]]));
        if matches!(
            atype,
            0x0000 | 0x0009 | 0x000C | 0x000D | 0x0012 | 0x0013 | 0x0016 | 0x0019 | 0x0020 | 0x8022
        ) {
            return false;
        }
        let padded = (alen + 3) & !3;
        let Some(next) = pos.checked_add(4).and_then(|p| p.checked_add(padded)) else {
            return false;
        };
        if next > buf.len() {
            return false;
        }
        if !buf[pos + 4 + alen..next].iter().all(|&b| b == 0) {
            return false;
        }
        pos = next;
    }
    pos == buf.len()
}

/// Resolves the STUN-formatted TURN `msg_type` `u16` from [`TurnSpec`].
fn resolve_turn_msg_type(spec: &TurnSpec) -> u16 {
    let norm = spec
        .msg_type
        .unwrap_or("allocate")
        .to_ascii_uppercase()
        .replace(['_', '-'], "");
    let (method, default_class) = match norm.as_str() {
        "ALLOCATE" | "ALLOCATEREQUEST" => (0x0003u16, 0x0000u16),
        "ALLOCATERESPONSE" => (0x0003, 0x0100),
        "ALLOCATEERROR" => (0x0003, 0x0110),
        "REFRESH" | "REFRESHREQUEST" => (0x0004, 0x0000),
        "REFRESHRESPONSE" => (0x0004, 0x0100),
        "REFRESHERROR" => (0x0004, 0x0110),
        "SEND" | "SENDINDICATION" => (0x0006, 0x0010),
        "DATA" | "DATAINDICATION" => (0x0007, 0x0010),
        "CREATEPERMISSION" | "CREATEPERMISSIONREQUEST" => (0x0008, 0x0000),
        "CREATEPERMISSIONRESPONSE" => (0x0008, 0x0100),
        "CREATEPERMISSIONERROR" => (0x0008, 0x0110),
        "CHANNELBIND" | "CHANNELBINDREQUEST" => (0x0009, 0x0000),
        "CHANNELBINDRESPONSE" => (0x0009, 0x0100),
        "CHANNELBINDERROR" => (0x0009, 0x0110),
        _ => (0x0003, 0x0000),
    };
    if matches!(method, 0x0006 | 0x0007) {
        return method | 0x0010;
    }
    let class = if spec.is_error {
        0x0110
    } else if spec.is_response {
        0x0100
    } else if spec.is_request {
        0x0000
    } else {
        default_class
    };
    method | class
}

/// Builds an RFC 8656 / RFC 5766 TURN control or `ChannelData` relay packet payload.
///
/// Syntax mapping: `turn [allocate | refresh | createpermission | channelbind | channeldata | sendindication | dataindication | msgtype <str>] [request | response | error] [txid <u32>] [channel <u16>] [lifetime <u32>] [requestedtransport <udp|tcp|u8>] [xormappedaddr <ip> [<u16>]] [xorrelayedaddr <ip> [<u16>]] [xorpeeraddr <ip> [<u16>]] [errcode <u16>] [software <str>]`
#[doc(alias = "TURN")]
#[doc(alias = "RFC8656")]
#[doc(alias = "RFC5766")]
#[doc(alias = "CHANNELDATA")]
pub fn build_turn_payload(
    ctx: &WireContext,
    spec: &TurnSpec,
    payload_bytes: &[u8],
) -> Vec<u8> {
    let is_channel_data = spec
        .msg_type
        .is_some_and(|m| m.replace(['_', '-'], "").eq_ignore_ascii_case("channeldata"));

    if is_channel_data {
        let ch = (spec.channel.unwrap_or(0x4000) & 0x3FFF) | 0x4000;
        let data_len = payload_bytes.len().min(usize::from(u16::MAX));
        let data = &payload_bytes[..data_len];
        let mut pkt = Vec::with_capacity(4 + data_len + 3);
        pkt.extend_from_slice(&ch.to_be_bytes());
        pkt.extend_from_slice(&(data_len as u16).to_be_bytes());
        pkt.extend_from_slice(data);
        if ctx.transport == Some(TransportProto::Tcp) {
            let pad = (4 - (data_len % 4)) % 4;
            pkt.resize(pkt.len() + pad, 0);
        }
        return pkt;
    }

    let msg_type = resolve_turn_msg_type(spec);
    let txid = spec.txid.unwrap_or(0x1122_3344);
    let mut attrs = Vec::new();

    if let Some(proto) = spec.requested_transport {
        push_turn_attr(&mut attrs, 0x0019, &[proto, 0, 0, 0]);
    } else if msg_type == 0x0003 {
        push_turn_attr(&mut attrs, 0x0019, &[17, 0, 0, 0]);
    }

    if let Some(lifetime) = spec.lifetime {
        push_turn_attr(&mut attrs, 0x000D, &lifetime.to_be_bytes());
    } else if matches!(msg_type, 0x0103 | 0x0004 | 0x0104) {
        push_turn_attr(&mut attrs, 0x000D, &600u32.to_be_bytes());
    }

    if let Some(raw_ch) = spec.channel {
        let ch = (raw_ch & 0x3FFF) | 0x4000;
        push_turn_attr(&mut attrs, 0x000C, &[(ch >> 8) as u8, ch as u8, 0, 0]);
    } else if msg_type == 0x0009 {
        push_turn_attr(&mut attrs, 0x000C, &[0x40, 0x00, 0x00, 0x00]);
    }

    if let Some(relayed) = spec.xor_relayed_addr {
        let port = spec.xor_relayed_port.unwrap_or(49152);
        push_xor_addr_attr(&mut attrs, 0x0016, relayed, port, txid);
    } else if msg_type == 0x0103 {
        let def_ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10));
        let port = spec.xor_relayed_port.unwrap_or(49152);
        push_xor_addr_attr(&mut attrs, 0x0016, def_ip, port, txid);
    }

    if let Some(peer) = spec.xor_peer_addr {
        let port = spec.xor_peer_port.unwrap_or(5004);
        push_xor_addr_attr(&mut attrs, 0x0012, peer, port, txid);
    } else if matches!(msg_type, 0x0008 | 0x0009 | 0x0016 | 0x0017) {
        let def_ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        let port = spec.xor_peer_port.unwrap_or(5004);
        push_xor_addr_attr(&mut attrs, 0x0012, def_ip, port, txid);
    }

    if let Some(mapped) = spec.xor_mapped_addr {
        let port = spec.xor_mapped_port.unwrap_or(12345);
        push_xor_addr_attr(&mut attrs, 0x0020, mapped, port, txid);
    }

    if let Some(code) = spec.errcode {
        let reason = default_turn_error_reason(code);
        let mut val = Vec::with_capacity(4 + reason.len());
        val.extend_from_slice(&[0, 0, (code / 100) as u8, (code % 100) as u8]);
        val.extend_from_slice(reason.as_bytes());
        push_turn_attr(&mut attrs, 0x0009, &val);
    } else if matches!(msg_type, 0x0113 | 0x0114 | 0x0118 | 0x0119) {
        let mut val = Vec::with_capacity(16);
        val.extend_from_slice(&[0, 0, 4, 1]);
        val.extend_from_slice(b"Unauthorized");
        push_turn_attr(&mut attrs, 0x0009, &val);
    }

    if let Some(sw) = spec.software {
        let raw = sw.as_bytes();
        push_turn_attr(&mut attrs, 0x8022, &raw[..raw.len().min(763)]);
    }

    if !payload_bytes.is_empty() {
        if is_valid_turn_attrs(payload_bytes) {
            attrs.extend_from_slice(payload_bytes);
        } else {
            let max_p = usize::from(u16::MAX).saturating_sub(attrs.len().saturating_add(8));
            let p_slice = &payload_bytes[..payload_bytes.len().min(max_p)];
            let carrier_attr = if matches!(msg_type, 0x0016 | 0x0017) {
                0x0013
            } else {
                0xFFFF
            };
            push_turn_attr(&mut attrs, carrier_attr, p_slice);
        }
    }

    let attr_len = attrs.len().min(usize::from(u16::MAX)) as u16;
    let mut pkt = Vec::with_capacity(20 + attrs.len());
    pkt.extend_from_slice(&msg_type.to_be_bytes());
    pkt.extend_from_slice(&attr_len.to_be_bytes());
    pkt.extend_from_slice(&0x2112_A442u32.to_be_bytes());
    pkt.extend_from_slice(&txid.to_be_bytes());
    pkt.extend_from_slice(&TURN_TXID_TAIL);
    pkt.extend_from_slice(&attrs);
    pkt
}
