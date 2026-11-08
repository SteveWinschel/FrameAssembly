//! Multi-Layer Wire Packet Builders for the FrameAssembly Compiler.
//!
//! This module hierarchy implements deterministic wire-format packet synthesis across all 81 native
//! protocols spanning OSI Layer 2 ([`l2`]: `ARP`, `VLAN`, `QINQ`, `LLDP`, `STP`, `LACP`, `EAPOL`,
//! and `MPLS`), Layer 3 ([`l3`]: `ICMP`, `NDP`, `IGMP`, `MLD`, `GRE`, `VXLAN`, `GENEVE`, `IPSEC`,
//! `ESP`, `AH`, `IKEV2`, `WIREGUARD`, `OSPF`, `BGP`, `RIP`, `VRRP`, `HSRP`, `PIM`, `BFD`, and
//! `OPENFLOW`), Layer 4 ([`l4`]: `TCP`, `UDP`, and `SCTP`), and Layer 7 ([`l7`]: 50 infrastructure,
//! web, cloud, mail, directory, storage, database, messaging, industrial OT/ICS, and
//! `SNMP1`/`SNMP2`/`SNMP3` protocols).

use crate::ast::{L2Modifiers, L3Modifiers, L4Modifiers, TransportProto};
use core::net::IpAddr;

/// Wire synthesis context holding resolved endpoint addresses, transport ports, and layer modifiers.
#[derive(Debug, Clone)]
pub struct WireContext<'a> {
    /// Resolved source IPv4 or IPv6 address.
    pub src_ip: IpAddr,
    /// Resolved destination IPv4 or IPv6 address.
    pub dst_ip: IpAddr,
    /// Resolved 6-byte source IEEE 802.3 MAC address.
    pub src_mac: [u8; 6],
    /// Resolved 6-byte destination IEEE 802.3 MAC address.
    pub dst_mac: [u8; 6],
    /// Optional explicit transport protocol override (`TCP` or `UDP`).
    pub transport: Option<TransportProto>,
    /// Resolved 16-bit source transport port (`SRCPORT`).
    pub src_port: u16,
    /// Resolved 16-bit destination transport port (`DSTPORT`).
    pub dst_port: u16,
    /// Optional explicit 32-bit TCP sequence number (`SEQ`).
    pub seq: Option<u32>,
    /// Optional explicit 32-bit TCP acknowledgment number (`ACKNUM`).
    pub ack: Option<u32>,
    /// Borrowed Layer 2 VLAN, QinQ, and MPLS modifiers.
    pub l2: &'a L2Modifiers,
    /// Borrowed Layer 3 TTL, DSCP, ECN, IPv4 fragment, and IPv6 flow-label modifiers.
    pub l3: &'a L3Modifiers,
    /// Borrowed Layer 4 TCP/UDP port, flag, window, and option modifiers.
    pub l4: &'a L4Modifiers,
}

pub mod l2;
pub mod l3;
pub mod l4;
pub mod l7;

/// Backwards-compatible alias for Layer 3 network and tunneling builders ([`l3`]).
#[doc(inline)]
pub use l3 as l3_tunnel;
/// Backwards-compatible alias for Layer 4 transport builders ([`l4`]).
#[doc(inline)]
pub use l4 as transport;
/// Backwards-compatible alias for Layer 7 infrastructure builders ([`l7`]).
#[doc(inline)]
pub use l7 as l7_infra;
/// Backwards-compatible alias for Layer 7 application builders ([`l7`]).
#[doc(inline)]
pub use l7 as l7_app;
/// Backwards-compatible alias for Layer 7 industrial OT/ICS builders ([`l7`]).
#[doc(inline)]
pub use l7 as l7_ot;
/// Backwards-compatible re-export of SNMPv1/v2c/v3 builders ([`l7::snmp`]).
#[doc(inline)]
pub use l7::snmp;
