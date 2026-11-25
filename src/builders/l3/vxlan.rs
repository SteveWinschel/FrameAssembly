//! Virtual eXtensible Local Area Network (VXLAN, RFC 7348) Layer 3 wire builder.
//!
//! Serializes a [`VxlanSpec`] into an 8-byte RFC 7348 VXLAN header followed by an inner IEEE 802.3
//! Ethernet frame encapsulated over UDP destination port `4789`. Byte 0 sets the mandatory `I` flag
//! (`0x08`) indicating a valid 24-bit VXLAN Network Identifier, followed by 24 bits of zeroed
//! `Reserved` octets, the 24-bit big-endian `VNI` (`vni`, default `4096`), and a trailing 8-bit
//! `Reserved` zero byte. When no explicit `payload` or `hexpayload` is supplied, a valid 42-byte
//! inner Ethernet + IPv4 + ICMPv4 Echo frame (`00:00:5e:00:53:02 <- 00:00:5e:00:53:01`, `0x0800`) is synthesized.
//!
//! Canonical `.frasm` syntax:
//! `a -> b vxlan [vni <u24>] [srcport <u16>] [payload "<str>" | hexpayload "<hex>"]`

use crate::ast::*;
use alloc::vec::Vec;

/// Builds an RFC 7348 VXLAN overlay payload and returns `(bytes, 4789)` for UDP encapsulation.
pub fn build_vxlan_payload(spec: &VxlanSpec, payload: &[u8]) -> (Vec<u8>, u16) {
    let vni = spec.vni.unwrap_or(4096) & 0x00FF_FFFF;
    let mut vxlan = Vec::with_capacity(8 + payload.len().max(42));
    vxlan.push(0x08); // I flag
    vxlan.extend_from_slice(&[0, 0, 0]); // Reserved
    vxlan.push((vni >> 16) as u8);
    vxlan.push((vni >> 8) as u8);
    vxlan.push(vni as u8);
    vxlan.push(0); // Reserved

    if payload.is_empty() {
        vxlan.extend_from_slice(&super::gre::default_overlay_inner_ethernet());
    } else {
        vxlan.extend_from_slice(payload);
    }

    (vxlan, 4789)
}

