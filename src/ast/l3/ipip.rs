//! IP-in-IP Encapsulation (RFC 2003 / RFC 2473 / RFC 4213) AST definitions.
//!
//! Defines the [`IpipSpec`] abstract syntax tree node and [`IpipVersion`] inner address family
//! discriminator for encapsulating IPv4 packets (`ipip v4`, outer IP protocol `4` per RFC 2003)
//! and IPv6 packets (`ipip v6`, outer IP protocol `41` per RFC 4213 / RFC 2473) inside an outer
//! IPv4 or IPv6 header. Supports optional inner IP source and destination addresses (`srcip`,
//! `dstip`), inner Hop Limit / Time-to-Live (`innerttl`), inner Differentiated Services Code Point
//! (`innerdscp`), and inner IP protocol number (`proto`).
//!
//! Canonical `.frasm` syntax:
//! `a -> b ipip [v4 | v6 | version <4|6>] [srcip <ip>] [dstip <ip>] [innerttl <u8>] [innerdscp <u8>] [proto <u8>]`

use core::marker::PhantomData;
use core::net::IpAddr;

/// Inner IP address family encapsulated inside an IP-in-IP tunnel (`ipip`).
#[doc(alias = "version")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpipVersion {
    /// IPv4-in-IP encapsulation (`v4`, outer IP protocol `4`, RFC 2003).
    V4,
    /// IPv6-in-IP encapsulation (`v6`, outer IP protocol `41`, RFC 4213 / RFC 2473).
    V6,
}

/// IP-in-IP Encapsulation (RFC 2003 / RFC 2473 / RFC 4213) specification over IP protocol `4` or `41`.
///
/// Syntax mapping: `ipip [v4 | v6 | version <4|6>] [srcip <ip>] [dstip <ip>] [innerttl <u8>] [innerdscp <u8>] [proto <u8>]`
#[doc(alias = "ipip")]
#[doc(alias = "6in4")]
#[doc(alias = "4in6")]
#[doc(alias = "RFC 2003")]
#[doc(alias = "RFC2003")]
#[doc(alias = "RFC 2473")]
#[doc(alias = "RFC2473")]
#[doc(alias = "RFC 4213")]
#[doc(alias = "RFC4213")]
#[doc(alias = "v4")]
#[doc(alias = "v6")]
#[doc(alias = "version")]
#[doc(alias = "srcip")]
#[doc(alias = "dstip")]
#[doc(alias = "innerttl")]
#[doc(alias = "innerdscp")]
#[doc(alias = "proto")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct IpipSpec<'a> {
    /// Encapsulated inner IP version (`v4` -> outer proto `4`, `v6` -> outer proto `41`).
    pub version: Option<IpipVersion>,
    /// Inner IP source address (`srcip <ip>`).
    pub src_ip: Option<IpAddr>,
    /// Inner IP destination address (`dstip <ip>`).
    pub dst_ip: Option<IpAddr>,
    /// Inner IP TTL or Hop Limit (`innerttl <u8>`, default `64`).
    pub ttl: Option<u8>,
    /// Inner IP Differentiated Services Code Point (`innerdscp <u8>`, default `0`).
    pub dscp: Option<u8>,
    /// Inner IP protocol or Next Header (`proto <u8>`, default `1`/`58` empty or `253` with payload).
    pub proto: Option<u8>,
    /// Optional lifetime phantom marker for AST uniformity.
    pub _marker: PhantomData<&'a ()>,
}
