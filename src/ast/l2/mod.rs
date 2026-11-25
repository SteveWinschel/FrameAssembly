//! Layer 2 Data Link protocols and frame modifiers for FrameAssembly AST representation.
//!
//! This module defines the abstract syntax tree structures for IEEE 802.3 Ethernet framing
//! overrides and all 18 Data Link layer control, industrial, and encapsulation protocols:
//! - **ARP** (RFC 826 / RFC 5227, EtherType `0x0806`) with polymorphic IPv6 NDP adaptation
//! - **CDP** (Cisco Discovery Protocol v2 over 802.3 LLC/SNAP PID `0x2000`)
//! - **EAPOL** (IEEE 802.1X-2020 Port-Based Network Access Control, EtherType `0x888E`)
//! - **EtherCAT** (IEC 61158-4-12 real-time industrial Ethernet, EtherType `0x88A4` / UDP `34980`)
//! - **GOOSE** (IEC 61850-8-1 Generic Object Oriented Substation Event, EtherType `0x88B8`)
//! - **IS-IS** (ISO/IEC 10589 Intermediate System to Intermediate System over 802.3 LLC `0xFEFE03`)
//! - **LACP** (IEEE 802.3ad / IEEE 802.1AX Link Aggregation Control Protocol, EtherType `0x8809`)
//! - **LLDP** (IEEE 802.1AB Station and Media Access Control Connectivity Discovery, EtherType `0x88CC`)
//! - **MACsec** (IEEE 802.1AE Media Access Control Security SecTAG, EtherType `0x88E5`)
//! - **MPLS** (RFC 3032 Multi-Protocol Label Switching label stack encoding, EtherType `0x8847`)
//! - **NSH** (RFC 8300 Network Service Header for Service Function Chaining, EtherType `0x894F`)
//! - **PFC** (IEEE 802.1Qbb Priority-based Flow Control MAC Control frame, EtherType `0x8808`)
//! - **PPPoE** (RFC 2516 Point-to-Point Protocol over Ethernet Discovery/Session, `0x8863` / `0x8864`)
//! - **PROFINET** (IEC 61158-6-10 PROFINET IO Real-Time and Context Manager, `0x8892` / UDP `34964`)
//! - **QinQ** (IEEE 802.1ad Provider Bridges double VLAN tagging, outer TPID `0x88A8`, inner TPID `0x8100`)
//! - **STP / RSTP** (IEEE 802.1D / IEEE 802.1w Spanning Tree Protocol BPDUs over 802.3 LLC `0x424203`)
//! - **SV** (IEC 61850-9-2LE Sampled Values substation telemetry, EtherType `0x88BA`)
//! - **VLAN** (IEEE 802.1Q Virtual Bridged Local Area Networks 32-bit tag, TPID `0x8100`)

pub mod arp;
pub mod cdp;
pub mod eapol;
pub mod ethercat;
pub mod goose;
pub mod isis;
pub mod lacp;
pub mod lldp;
pub mod macsec;
pub mod mpls;
pub mod nsh;
pub mod pfc;
pub mod pppoe;
pub mod profinet;
pub mod qinq;
pub mod stp;
pub mod sv;
pub mod vlan;

use alloc::vec::Vec;

#[doc(inline)]
pub use arp::*;
#[doc(inline)]
pub use cdp::*;
#[doc(inline)]
pub use eapol::*;
#[doc(inline)]
pub use ethercat::*;
#[doc(inline)]
pub use goose::*;
#[doc(inline)]
pub use isis::*;
#[doc(inline)]
pub use lacp::*;
#[doc(inline)]
pub use lldp::*;
#[doc(inline)]
pub use macsec::*;
#[doc(inline)]
pub use mpls::*;
#[doc(inline)]
pub use nsh::*;
#[doc(inline)]
pub use pfc::*;
#[doc(inline)]
pub use pppoe::*;
#[doc(inline)]
pub use profinet::*;
#[doc(inline)]
pub use qinq::*;
#[doc(inline)]
pub use stp::*;
#[doc(inline)]
pub use sv::*;
#[doc(inline)]
pub use vlan::*;

/// Layer 2 Ethernet header and shim encapsulation modifiers applied to any frame statement.
///
/// Syntax mapping: `[srcmac <mac>] [dstmac <mac>] [ethertype <u16>] [fcs] [badfcs] [vlan <vid> [pcp <pcp>] [dei <dei>]] [qinq <svid> [innervlan <cvid>]] [mpls <label> [exp <tc>] [bos <s_bit>] [mplsttl <ttl>]]...`
#[doc(alias = "Ethernet")]
#[doc(alias = "802.3")]
#[doc(alias = "802.1Q")]
#[doc(alias = "fcs")]
#[doc(alias = "badfcs")]
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
    /// Optional primary RFC 3032 MPLS shim label (`mpls <label> [exp <u8>] [bos <u8>] [mplsttl <u8>]`).
    pub mpls: Option<MplsSpec>,
    /// Ordered RFC 3032 MPLS label stack when one or more `mpls` entries are attached to a frame.
    pub mpls_stack: Vec<MplsSpec>,
    /// Appends a valid 4-byte IEEE 802.3 Ethernet FCS / CRC-32 trailer (`fcs`).
    pub fcs: bool,
    /// Appends a deliberately corrupted 4-byte Ethernet FCS / CRC-32 trailer for negative tests (`badfcs`).
    pub bad_fcs: bool,
}
