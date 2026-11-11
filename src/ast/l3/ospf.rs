//! Open Shortest Path First (OSPFv2 RFC 2328 / OSPFv3 RFC 5340) AST definitions.
//!
//! Defines link-state Interior Gateway Protocol (IGP) control packets transmitted directly over IP
//! protocol `89` (`0x59`) to multicast AllSPFRouters (`224.0.0.5` for IPv4, `ff02::5` for IPv6).
//! The 24-byte OSPF header encodes `Version` (`2`), `Type` (`1` `hello`, `2` `dbd`, `3` `lsr`, `4`
//! `lsu`, `5` `lsack`), 16-bit `Packet Length`, 32-bit `Router ID` (`routerid`), 32-bit `Area ID`
//! (`areaid`, default `0` backbone `0.0.0.0`), 16-bit Checksum, `AuType`, and 64-bit Authentication,
//! followed by a 20-byte Hello body specifying `Network Mask`, `HelloInterval` (`hellointerval`,
//! default `10`s), `Options`, `Rtr Pri` (`priority`, default `1`), and `RouterDeadInterval` (`deadinterval`, default `40`s).
//!
//! Canonical `.fasm` syntax:
//! `a -> b ospf [hello | dbd | lsr | lsu | lsack] [routerid <ipv4>] [areaid <u32>] [hellointerval <u16>] [deadinterval <u32>] [priority <u8>]`

use core::marker::PhantomData;
use core::net::IpAddr;

/// RFC 2328 / RFC 5340 OSPF packet type code.
#[doc(alias = "OspfPacketType")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OspfType {
    /// Type `1` (`hello`): Discovers and maintains neighbor adjacencies and elects DR/BDR on broadcast links.
    Hello,
    /// Type `2` (`dbd`): Database Description packet exchanging link-state database summary headers.
    Dbd,
    /// Type `3` (`lsr`): Link State Request querying specific LSA records from a neighbor.
    Lsr,
    /// Type `4` (`lsu`): Link State Update flooding full LSA instances across the OSPF area.
    Lsu,
    /// Type `5` (`lsack`): Link State Acknowledgment confirming reliable receipt of flooded LSAs.
    LsAck,
}

/// Open Shortest Path First (RFC 2328 OSPFv2 / RFC 5340 OSPFv3) specification over IP protocol `89`.
///
/// Syntax mapping: `ospf [hello | dbd | lsr | lsu | lsack] [routerid <ipv4>] [areaid <u32>] [hellointerval <u16>] [deadinterval <u32>] [priority <u8>]`
#[doc(alias = "ospf")]
#[doc(alias = "OSPFv2")]
#[doc(alias = "OSPFv3")]
#[doc(alias = "RFC 2328")]
#[doc(alias = "RFC2328")]
#[doc(alias = "RFC 5340")]
#[doc(alias = "RFC5340")]
#[doc(alias = "hello")]
#[doc(alias = "dbd")]
#[doc(alias = "lsr")]
#[doc(alias = "lsu")]
#[doc(alias = "lsack")]
#[doc(alias = "routerid")]
#[doc(alias = "areaid")]
#[doc(alias = "hellointerval")]
#[doc(alias = "deadinterval")]
#[doc(alias = "priority")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct OspfSpec<'a> {
    /// OSPF packet type (`hello`, `dbd`, `lsr`, `lsu`, or `lsack`; default `hello`).
    pub ospf_type: Option<OspfType>,
    /// 32-bit OSPF Router ID formatted as an IPv4 address (`routerid <ipv4>`).
    pub router_id: Option<IpAddr>,
    /// 32-bit OSPF Area ID (`areaid <u32>`, default `0` for Area `0.0.0.0`).
    pub area_id: Option<u32>,
    /// 16-bit Hello Interval in seconds (`hellointerval <u16>`, default `10`).
    pub hello_interval: Option<u16>,
    /// 32-bit Router Dead Interval in seconds (`deadinterval <u32>`, default `40`).
    pub dead_interval: Option<u32>,
    /// 8-bit Designated Router election Priority (`priority <u8>`, default `1`; `0` = ineligible).
    pub priority: Option<u8>,
    /// Optional lifetime phantom marker for AST uniformity.
    pub _marker: PhantomData<&'a ()>,
}
