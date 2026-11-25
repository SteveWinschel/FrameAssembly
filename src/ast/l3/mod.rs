//! Layer 3 Network, Routing, Tunneling, and Security protocols and modifiers for FrameAssembly AST.
//!
//! This module defines the abstract syntax tree structures for IPv4 (RFC 791) and IPv6 (RFC 8200)
//! packet header modifiers alongside thirty-one Layer 3 control, routing, overlay tunneling,
//! redundancy, and cryptographic security protocols:
//! - **AH** (RFC 4302 IPsec Authentication Header, IP protocol `51`)
//! - **BFD** (RFC 5880 Bidirectional Forwarding Detection over UDP port `3784`)
//! - **BGP** (RFC 4271 Border Gateway Protocol v4 over TCP port `179`)
//! - **BMP** (RFC 7854 / RFC 8671 / RFC 9069 BGP Monitoring Protocol over TCP port `1790`)
//! - **ERSPAN** (Encapsulated Remote Switch Port Analyzer Type II & III over GRE IP protocol `47`)
//! - **ESP / IPsec** (RFC 4303 IPsec Encapsulating Security Payload, IP protocol `50`)
//! - **GENEVE** (RFC 8926 Generic Network Virtualization Encapsulation over UDP port `6081`)
//! - **GLBP** (Cisco Gateway Load Balancing Protocol over UDP port `3222`)
//! - **GRE** (RFC 2784 / RFC 2890 Generic Routing Encapsulation, IP protocol `47`)
//! - **GTP-U** (3GPP TS 29.281 GPRS Tunneling Protocol User Plane over UDP port `2152`)
//! - **HSRP** (RFC 2281 Cisco Hot Standby Router Protocol over UDP port `1985` / `2029`)
//! - **ICMP / ICMPv6** (RFC 792 / RFC 4443 Internet Control Message Protocol, IP protocol `1` / `58`)
//! - **IGMP** (RFC 2236 / RFC 3376 Internet Group Management Protocol, IP protocol `2`)
//! - **IKEv2** (RFC 7296 Internet Key Exchange Protocol Version 2 over UDP port `500`)
//! - **IP-in-IP** (RFC 2003 / RFC 2473 / RFC 4213 IP-in-IP encapsulation, IP protocol `4` / `41`)
//! - **L2TP** (RFC 2661 L2TPv2 over UDP port `1701` / RFC 3931 L2TPv3 over IP protocol `115`)
//! - **LDP** (RFC 5036 Label Distribution Protocol over TCP/UDP port `646`)
//! - **LISP** (RFC 9300 / RFC 9301 Locator/ID Separation Protocol over UDP ports `4341` / `4342`)
//! - **MLD** (RFC 2710 / RFC 3810 Multicast Listener Discovery for IPv6 over ICMPv6 `58`)
//! - **NDP** (RFC 4861 IPv6 Neighbor Discovery Protocol over ICMPv6 `58`)
//! - **OpenFlow** (ONF OpenFlow Switch Protocol v1.3+ over TCP port `6653`)
//! - **OSPF** (RFC 2328 OSPFv2 / RFC 5340 OSPFv3 over IP protocol `89`)
//! - **PIM** (RFC 7761 Protocol Independent Multicast Sparse Mode, IP protocol `103`)
//! - **RIP** (RFC 2453 RIPv2 over UDP `520` / RFC 2080 RIPng over UDP `521`)
//! - **RPKI-RTR** (RFC 6810 / RFC 8210 RPKI to Router Protocol over TCP port `323`)
//! - **RSVP** (RFC 2205 / RFC 3209 Resource Reservation Protocol over IP protocol `46`)
//! - **SRv6** (RFC 8754 Segment Routing over IPv6 Segment Routing Header, Routing Type `4` / `43`)
//! - **VRRP** (RFC 5798 Virtual Router Redundancy Protocol v3, IP protocol `112`)
//! - **VXLAN** (RFC 7348 Virtual eXtensible Local Area Network over UDP port `4789`)
//! - **WireGuard** (Noise_IK cryptographic VPN tunnel over UDP port `51820`)

pub mod ah;
pub mod bfd;
pub mod bgp;
pub mod bmp;
pub mod erspan;
pub mod esp;
pub mod geneve;
pub mod glbp;
pub mod gre;
pub mod gtpu;
pub mod hsrp;
pub mod icmp;
pub mod igmp;
pub mod ikev2;
pub mod ipip;
pub mod ipsec;
pub mod l2tp;
pub mod ldp;
pub mod lisp;
pub mod mld;
pub mod ndp;
pub mod openflow;
pub mod ospf;
pub mod pim;
pub mod rip;
pub mod rpkirtr;
pub mod rsvp;
pub mod srv6;
pub mod vrrp;
pub mod vxlan;
pub mod wireguard;

#[doc(inline)]
pub use ah::*;
#[doc(inline)]
pub use bfd::*;
#[doc(inline)]
pub use bgp::*;
#[doc(inline)]
pub use bmp::*;
#[doc(inline)]
pub use erspan::*;
#[doc(inline)]
pub use esp::*;
#[doc(inline)]
pub use geneve::*;
#[doc(inline)]
pub use glbp::*;
#[doc(inline)]
pub use gre::*;
#[doc(inline)]
pub use gtpu::*;
#[doc(inline)]
pub use hsrp::*;
#[doc(inline)]
pub use icmp::*;
#[doc(inline)]
pub use igmp::*;
#[doc(inline)]
pub use ikev2::*;
#[doc(inline)]
pub use ipip::*;
#[doc(inline)]
pub use ipsec::*;
#[doc(inline)]
pub use l2tp::*;
#[doc(inline)]
pub use ldp::*;
#[doc(inline)]
pub use lisp::*;
#[doc(inline)]
pub use mld::*;
#[doc(inline)]
pub use ndp::*;
#[doc(inline)]
pub use openflow::*;
#[doc(inline)]
pub use ospf::*;
#[doc(inline)]
pub use pim::*;
#[doc(inline)]
pub use rip::*;
#[doc(inline)]
pub use rpkirtr::*;
#[doc(inline)]
pub use rsvp::*;
#[doc(inline)]
pub use srv6::*;
#[doc(inline)]
pub use vrrp::*;
#[doc(inline)]
pub use vxlan::*;
#[doc(inline)]
pub use wireguard::*;

/// Re-export MPLS specification from L2 for backwards compatibility.
#[doc(inline)]
pub use crate::ast::l2::mpls::MplsSpec;

/// Layer 3 IPv4 (RFC 791) and IPv6 (RFC 8200) packet header modifiers applied to any frame statement.
///
/// Syntax mapping: `[ttl <0..255>] [dscp <0..63>] [ecn <0..3>] [flowlabel <0..1048575>] [ipid <u16>] [df] [mf] [fragoffset <u16>] [routeralert] [badipchecksum]`
#[doc(alias = "IPv4")]
#[doc(alias = "IPv6")]
#[doc(alias = "dscp")]
#[doc(alias = "ttl")]
#[doc(alias = "routeralert")]
#[doc(alias = "badipchecksum")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct L3Modifiers {
    /// IPv4 Time-to-Live or IPv6 Hop Limit (`ttl <0..=255>`, default `64`).
    pub ttl: Option<u8>,
    /// 6-bit Differentiated Services Code Point (`dscp <0..=63>`, RFC 2474, default `0`).
    pub dscp: Option<u8>,
    /// 2-bit Explicit Congestion Notification (`ecn <0..=3>`, RFC 3168, default `0`).
    pub ecn: Option<u8>,
    /// 20-bit IPv6 Flow Label (`flowlabel <0..=0xFFFFF>`, RFC 6437, default `0`).
    pub flowlabel: Option<u32>,
    /// 16-bit IPv4 Identification field (`ipid <u16>`, default `0x1234`).
    pub ipid: Option<u16>,
    /// IPv4 Don't Fragment flag (`df`, bit 1 of the IPv4 Flags field).
    pub df: bool,
    /// IPv4 More Fragments flag (`mf`, bit 2 of the IPv4 Flags field).
    pub mf: bool,
    /// 13-bit IPv4 Fragment Offset in 8-octet units (`fragoffset <0..=8191>`).
    pub frag_offset: Option<u16>,
    /// Emits RFC 2113 IPv4 Router Alert option (`0x94040000`) or RFC 2711 IPv6 Hop-by-Hop Router Alert (`NextHeader = 0`).
    pub router_alert: bool,
    /// Intentionally corrupts the IPv4 header checksum for negative IDS/stack testing (`badipchecksum`).
    pub bad_ip_checksum: bool,
}
