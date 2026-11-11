//! Layer 2 Data Link protocols and frame modifiers for FrameAssembly AST representation.
//!
//! This module defines the abstract syntax tree structures for IEEE 802.3 Ethernet framing
//! overrides and Data Link layer control and encapsulation protocols:
//! - **ARP** (RFC 826 / RFC 5227, EtherType `0x0806`) with polymorphic IPv6 NDP adaptation
//! - **EAPOL** (IEEE 802.1X-2020 Port-Based Network Access Control, EtherType `0x888E`)
//! - **LACP** (IEEE 802.3ad / IEEE 802.1AX Link Aggregation Control Protocol, EtherType `0x8809`)
//! - **LLDP** (IEEE 802.1AB Station and Media Access Control Connectivity Discovery, EtherType `0x88CC`)
//! - **MPLS** (RFC 3032 Multi-Protocol Label Switching label stack encoding, EtherType `0x8847`)
//! - **QinQ** (IEEE 802.1ad Provider Bridges double VLAN tagging, outer TPID `0x88A8`, inner TPID `0x8100`)
//! - **STP / RSTP** (IEEE 802.1D / IEEE 802.1w Spanning Tree Protocol BPDUs over 802.3 LLC `0x424203`)
//! - **VLAN** (IEEE 802.1Q Virtual Bridged Local Area Networks 32-bit tag, TPID `0x8100`)

pub mod arp;
pub mod eapol;
pub mod lacp;
pub mod lldp;
pub mod mpls;
pub mod qinq;
pub mod stp;
pub mod vlan;

#[doc(inline)]
pub use arp::*;
#[doc(inline)]
pub use eapol::*;
#[doc(inline)]
pub use lacp::*;
#[doc(inline)]
pub use lldp::*;
#[doc(inline)]
pub use mpls::*;
#[doc(inline)]
pub use qinq::*;
#[doc(inline)]
pub use stp::*;
#[doc(inline)]
pub use vlan::*;

/// Layer 2 Ethernet header and shim encapsulation modifiers applied to any frame statement.
///
/// Syntax mapping: `[srcmac <mac>] [dstmac <mac>] [ethertype <u16>] [vlan <vid> [pcp <pcp>] [dei <dei>]] [qinq <svid> [innervlan <cvid>]] [mpls <label> [exp <tc>] [bos <s_bit>] [mplsttl <ttl>]]`
#[doc(alias = "Ethernet")]
#[doc(alias = "802.3")]
#[doc(alias = "802.1Q")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct L2Modifiers {
    /// Source 48-bit IEEE 802 MAC address override (`srcmac <mac>`).
    pub src_mac: Option<[u8; 6]>,
    /// Destination 48-bit IEEE 802 MAC address override (`dstmac <mac>`).
    pub dst_mac: Option<[u8; 6]>,
    /// Custom 16-bit IEEE 802.3 EtherType override (`ethertype <u16>`).
    pub ethertype: Option<u16>,
    /// Optional IEEE 802.1Q single VLAN tag (`vlan <vid> [pcp <u8>] [dei <u8>]`).
    pub vlan: Option<VlanSpec>,
    /// Optional IEEE 802.1ad QinQ double VLAN tag (`qinq <outer> [innervlan <inner>]`).
    pub qinq: Option<QinqSpec>,
    /// Optional RFC 3032 MPLS shim label (`mpls <label> [exp <u8>] [bos <u8>] [mplsttl <u8>]`).
    pub mpls: Option<MplsSpec>,
}
