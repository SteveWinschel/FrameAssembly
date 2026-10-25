//! Virtual eXtensible Local Area Network (VXLAN, RFC 7348) Layer 3 wire builder.
//!
//! Serializes a [`VxlanSpec`] into an 8-byte RFC 7348 VXLAN header followed by an inner IEEE 802.3
//! Ethernet frame encapsulated over UDP destination port `4789`. Byte 0 sets the mandatory `I` flag
//! (`0x08`) indicating a valid 24-bit VXLAN Network Identifier, followed by 24 bits of zeroed
//! `Reserved` octets, the 24-bit big-endian `VNI` (`VNI`, default `4096`), and a trailing 8-bit
//! `Reserved` zero byte. When no explicit `PAYLOAD` or `HEXPAYLOAD` is supplied, a sensible default
//! inner Ethernet frame (`00:00:00:00:00:02 <- 00:00:00:00:00:01`, EtherType `0x0800`) is synthesized.
//!
//! Canonical `.fasm` syntax:
//! `a -> b VXLAN [VNI <u24>] [SRCPORT <u16>] [PAYLOAD "<str>" | HEXPAYLOAD "<hex>"]`

use crate::ast::*;
use alloc::vec::Vec;

/// Builds an RFC 7348 VXLAN overlay payload and returns `(bytes, 4789)` for UDP encapsulation.
pub fn build_vxlan_payload(spec: &VxlanSpec, payload: &[u8]) -> (Vec<u8>, u16) {
    let vni = spec.vni.unwrap_or(4096) & 0x00FF_FFFF;
    let mut vxlan = Vec::with_capacity(8 + payload.len());
    vxlan.push(0x08); // I flag
    vxlan.extend_from_slice(&[0, 0, 0]); // Reserved
    vxlan.push((vni >> 16) as u8);
    vxlan.push((vni >> 8) as u8);
    vxlan.push(vni as u8);
    vxlan.push(0); // Reserved

    if payload.is_empty() {
        // Synthesize a valid 14B Ethernet II + 20B IPv4 + 8B UDP inner passenger frame (42 bytes)
        let mut inner_ip = [
            0x45, 0x00, 0x00, 28, 0x00, 0x01, 0x00, 0x00, 64, 17, 0x00, 0x00, 10, 0, 0, 1, 10, 0,
            0, 2,
        ];
        let ip_cksum = crate::packet::internet_checksum(&[&inner_ip]);
        inner_ip[10..12].copy_from_slice(&ip_cksum.to_be_bytes());

        vxlan.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x02]);
        vxlan.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x01]);
        vxlan.extend_from_slice(&0x0800_u16.to_be_bytes());
        vxlan.extend_from_slice(&inner_ip);
        vxlan.extend_from_slice(&[0x30, 0x39, 0x00, 0x50, 0x00, 0x08, 0x00, 0x00]);
    } else {
        vxlan.extend_from_slice(payload);
    }

    (vxlan, 4789)
}

