//! Open Shortest Path First (OSPFv2 RFC 2328 / OSPFv3 RFC 5340) AST definitions.
//!
//! Defines link-state Interior Gateway Protocol (IGP) control packets transmitted directly over IP
//! protocol `89` (`0x59`) to multicast AllSPFRouters (`224.0.0.5` for IPv4, `ff02::5` for IPv6).
//! The 24-byte OSPF header encodes `Version` (`2`), `Type` (`1` `HELLO`, `2` `DBD`, `3` `LSR`, `4`
//! `LSU`, `5` `LSACK`), 16-bit `Packet Length`, 32-bit `Router ID` (`ROUTER_ID`), 32-bit `Area ID`
//! (`AREA_ID`, default `0` backbone `0.0.0.0`), 16-bit Checksum, `AuType`, and 64-bit Authentication,
//! followed by a 20-byte Hello body specifying `Network Mask`, `HelloInterval` (`HELLO_INTERVAL`,
//! default `10`s), `Options`, `Rtr Pri` (`PRIORITY`, default `1`), and `RouterDeadInterval` (`DEAD_INTERVAL`, default `40`s).
//!
//! Canonical `.fasm` syntax:
//! `a -> b OSPF [HELLO | DBD | LSR | LSU | LSACK] [ROUTER_ID <ipv4>] [AREA_ID <u32>] [HELLO_INTERVAL <u16>] [DEAD_INTERVAL <u32>] [PRIORITY <u8>]`

use core::marker::PhantomData;
use core::net::IpAddr;

/// RFC 2328 / RFC 5340 OSPF packet type code.
#[doc(alias = "OspfPacketType")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OspfType {
    /// Type `1` (`HELLO`): Discovers and maintains neighbor adjacencies and elects DR/BDR on broadcast links.
    Hello,
    /// Type `2` (`DBD`): Database Description packet exchanging link-state database summary headers.
    Dbd,
    /// Type `3` (`LSR`): Link State Request querying specific LSA records from a neighbor.
    Lsr,
    /// Type `4` (`LSU`): Link State Update flooding full LSA instances across the OSPF area.
    Lsu,
    /// Type `5` (`LSACK`): Link State Acknowledgment confirming reliable receipt of flooded LSAs.
    LsAck,
}

/// Open Shortest Path First (RFC 2328 OSPFv2 / RFC 5340 OSPFv3) specification over IP protocol `89`.
///
/// Syntax mapping: `OSPF [HELLO | DBD | LSR | LSU | LSACK] [ROUTER_ID <ipv4>] [AREA_ID <u32>] [HELLO_INTERVAL <u16>] [DEAD_INTERVAL <u32>] [PRIORITY <u8>]`
#[doc(alias = "OSPF")]
#[doc(alias = "OSPFv2")]
#[doc(alias = "OSPFv3")]
#[doc(alias = "RFC 2328")]
#[doc(alias = "RFC2328")]
#[doc(alias = "RFC 5340")]
#[doc(alias = "RFC5340")]
#[doc(alias = "HELLO")]
#[doc(alias = "DBD")]
#[doc(alias = "LSR")]
#[doc(alias = "LSU")]
#[doc(alias = "LSACK")]
#[doc(alias = "ROUTER_ID")]
#[doc(alias = "AREA_ID")]
#[doc(alias = "HELLO_INTERVAL")]
#[doc(alias = "DEAD_INTERVAL")]
#[doc(alias = "PRIORITY")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct OspfSpec<'a> {
    /// OSPF packet type (`HELLO`, `DBD`, `LSR`, `LSU`, or `LSACK`; default `HELLO`).
    pub ospf_type: Option<OspfType>,
    /// 32-bit OSPF Router ID formatted as an IPv4 address (`ROUTER_ID <ipv4>`).
    pub router_id: Option<IpAddr>,
    /// 32-bit OSPF Area ID (`AREA_ID <u32>`, default `0` for Area `0.0.0.0`).
    pub area_id: Option<u32>,
    /// 16-bit Hello Interval in seconds (`HELLO_INTERVAL <u16>`, default `10`).
    pub hello_interval: Option<u16>,
    /// 32-bit Router Dead Interval in seconds (`DEAD_INTERVAL <u32>`, default `40`).
    pub dead_interval: Option<u32>,
    /// 8-bit Designated Router election Priority (`PRIORITY <u8>`, default `1`; `0` = ineligible).
    pub priority: Option<u8>,
    /// Optional lifetime phantom marker for AST uniformity.
    pub _marker: PhantomData<&'a ()>,
}
