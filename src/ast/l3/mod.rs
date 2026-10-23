//! Layer 3 Network, routing, tunneling, and security protocols and modifiers.

/// IPsec Authentication Header.
pub mod ah;
/// Bidirectional Forwarding Detection.
pub mod bfd;
/// Border Gateway Protocol.
pub mod bgp;
/// IPsec ESP protocol alias.
pub mod esp;
/// Generic Network Virtualization Encapsulation.
pub mod geneve;
/// Generic Routing Encapsulation.
pub mod gre;
/// Hot Standby Router Protocol.
pub mod hsrp;
/// Internet Control Message Protocol (v4/v6).
pub mod icmp;
/// Internet Group Management Protocol.
pub mod igmp;
/// Internet Key Exchange Protocol Version 2.
pub mod ikev2;
/// IPsec Encapsulating Security Payload.
pub mod ipsec;
/// Multicast Listener Discovery.
pub mod mld;
/// IPv6 Neighbor Discovery Protocol.
pub mod ndp;
/// OpenFlow Switch Protocol.
pub mod openflow;
/// Open Shortest Path First.
pub mod ospf;
/// Protocol Independent Multicast.
pub mod pim;
/// Routing Information Protocol.
pub mod rip;
/// Virtual Router Redundancy Protocol.
pub mod vrrp;
/// Virtual eXtensible Local Area Network.
pub mod vxlan;
/// WireGuard Secure Network Tunnel.
pub mod wireguard;

pub use ah::*;
pub use bfd::*;
pub use bgp::*;
pub use esp::*;
pub use geneve::*;
pub use gre::*;
pub use hsrp::*;
pub use icmp::*;
pub use igmp::*;
pub use ikev2::*;
pub use ipsec::*;
pub use mld::*;
pub use ndp::*;
pub use openflow::*;
pub use ospf::*;
pub use pim::*;
pub use rip::*;
pub use vrrp::*;
pub use vxlan::*;
pub use wireguard::*;

/// Re-export MPLS specification from L2 for backwards compatibility.
pub use crate::ast::l2::mpls::MplsSpec;

/// Layer 3 packet modifiers.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct L3Modifiers {
    /// IPv4 TTL or IPv6 Hop Limit (0..=255).
    pub ttl: Option<u8>,
    /// 6-bit Differentiated Services Code Point (0..=63).
    pub dscp: Option<u8>,
    /// 2-bit Explicit Congestion Notification (0..=3).
    pub ecn: Option<u8>,
    /// 20-bit IPv6 Flow Label (0..=0xFFFFF).
    pub flowlabel: Option<u32>,
    /// IPv4 Identification field.
    pub ipid: Option<u16>,
    /// IPv4 Don't Fragment flag.
    pub df: bool,
    /// IPv4 More Fragments flag.
    pub mf: bool,
    /// IPv4 Fragment Offset.
    pub frag_offset: Option<u16>,
}
