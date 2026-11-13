//! Virtual eXtensible Local Area Network (VXLAN, RFC 7348) AST definitions.
//!
//! Defines the Layer 2-over-UDP network virtualization overlay encapsulation specified in RFC 7348
//! for multi-tenant cloud data centers and BGP EVPN (RFC 7432 / RFC 8365) Spine-Leaf fabrics. VXLAN
//! Tunnel Endpoints (VTEPs) encapsulate inner IEEE 802.3 Ethernet frames inside an 8-byte VXLAN header
//! carried over UDP destination port `4789` (with ECMP entropy hashed into the outer UDP source port).
//! The 8-byte VXLAN wire header consists of an 8-bit `Flags` byte (`0x08`, where bit 4 is the mandatory
//! `I` flag indicating a valid VNI), 24 bits of `Reserved` zeros, a 24-bit VXLAN Network Identifier
//! (`vni`, `0..=16_777_215`, default `4096`), and a trailing 8-bit `Reserved` zero field.
//!
//! Canonical `.frasm` syntax:
//! `a -> b vxlan [vni <u24>] [srcport <u16>] [payload "<str>" | hexpayload "<hex>"]`

use core::marker::PhantomData;

/// Virtual eXtensible Local Area Network (RFC 7348) specification over UDP port `4789`.
///
/// Syntax mapping: `vxlan [vni <0..16777215>]`
#[doc(alias = "vxlan")]
#[doc(alias = "RFC 7348")]
#[doc(alias = "RFC7348")]
#[doc(alias = "VTEP")]
#[doc(alias = "EVPN")]
#[doc(alias = "4789")]
#[doc(alias = "vni")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct VxlanSpec<'a> {
    /// 24-bit VXLAN Network Identifier (`vni <0..=16_777_215>` or `vnid`, default `4096`).
    pub vni: Option<u32>,
    /// Optional lifetime phantom marker for AST uniformity.
    pub _marker: PhantomData<&'a ()>,
}
