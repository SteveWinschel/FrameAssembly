//! Virtual Router Redundancy Protocol (VRRPv3 RFC 5798 / VRRPv2 RFC 3768) AST definitions.
//!
//! Defines the standards-based First Hop Redundancy Protocol (FHRP) advertisement packet specified
//! in RFC 5798 (VRRPv3 for IPv4 and IPv6) and RFC 3768 (VRRPv2) transmitted directly over IP protocol
//! `112` (`0x70`) with `TTL = 255` to multicast `224.0.0.18` (IPv4) or `ff02::12` (IPv6). The VRRPv3
//! wire header packs a 4-bit `Version` (`3`), a 4-bit `Type` (`1` Advertisement), an 8-bit Virtual
//! Router Identifier (`VRID`, `1..=255`), an 8-bit election `Priority` (`PRIORITY`, `1..=254`, `255`
//! for IP address owner), an 8-bit `Count IPvX Addr` (`1`), a 12-bit `Max Adver Int` in centiseconds
//! (`ADV_INT`, default `100` = 1.0s), a 16-bit Checksum, and the Virtual IP address (`VIP`).
//!
//! Canonical `.fasm` syntax:
//! `a -> b VRRP [VRID <1..255>] [PRIORITY <0..255>] [ADV_INT <u16>] [VIP <ip>] [VERSION <2|3>]`

use core::marker::PhantomData;
use core::net::IpAddr;

/// Virtual Router Redundancy Protocol (RFC 5798 VRRPv3 / RFC 3768 VRRPv2) specification over IP protocol `112`.
///
/// Syntax mapping: `VRRP [VRID <1..255>] [PRIORITY <0..255>] [ADV_INT <u16>] [VIP <ip>] [VERSION <2|3>]`
#[doc(alias = "VRRP")]
#[doc(alias = "VRRPv3")]
#[doc(alias = "VRRPv2")]
#[doc(alias = "RFC 5798")]
#[doc(alias = "RFC5798")]
#[doc(alias = "112")]
#[doc(alias = "VRID")]
#[doc(alias = "PRIORITY")]
#[doc(alias = "ADV_INT")]
#[doc(alias = "VIP")]
#[doc(alias = "VERSION")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct VrrpSpec<'a> {
    /// 8-bit Virtual Router Identifier (`VRID <1..=255>`, default `1`).
    pub vrid: Option<u8>,
    /// 8-bit Master election Priority (`PRIORITY <0..=255>`, default `100`; `255` = VIP owner, `0` = Master release).
    pub priority: Option<u8>,
    /// 12-bit Maximum Advertisement Interval in centiseconds for VRRPv3 (`ADV_INT <u16>`, default `100` = 1.00s).
    pub adv_int: Option<u16>,
    /// Virtual IPv4 or IPv6 gateway address protected by the VRRP group (`VIP <ip>`).
    pub vip: Option<IpAddr>,
    /// VRRP protocol version (`VERSION <2|3>`, default `3`).
    pub version: Option<u8>,
    /// Optional lifetime phantom marker for AST uniformity.
    pub _marker: PhantomData<&'a ()>,
}
