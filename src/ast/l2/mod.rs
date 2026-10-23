//! Layer 2 Data Link protocols and frame modifiers.


/// Address Resolution Protocol.
pub mod arp;
/// IEEE 802.1X EAPOL protocol.
pub mod eapol;
/// IEEE 802.3ad Link Aggregation Control Protocol.
pub mod lacp;
/// IEEE 802.1AB Link Layer Discovery Protocol.
pub mod lldp;
/// RFC 3032 Multi-Protocol Label Switching.
pub mod mpls;
/// IEEE 802.1ad QinQ dual VLAN protocol.
pub mod qinq;
/// IEEE 802.1D / IEEE 802.1w Spanning Tree Protocol.
pub mod stp;
/// IEEE 802.1Q Virtual Local Area Network protocol.
pub mod vlan;

pub use arp::*;
pub use eapol::*;
pub use lacp::*;
pub use lldp::*;
pub use mpls::*;
pub use qinq::*;
pub use stp::*;
pub use vlan::*;

/// Layer 2 frame modifiers.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct L2Modifiers {
    /// Source MAC address override.
    pub src_mac: Option<[u8; 6]>,
    /// Destination MAC address override.
    pub dst_mac: Option<[u8; 6]>,
    /// Custom EtherType override.
    pub ethertype: Option<u16>,
    /// Optional IEEE 802.1Q VLAN tag.
    pub vlan: Option<VlanSpec>,
    /// Optional IEEE 802.1ad QinQ double VLAN tag.
    pub qinq: Option<QinqSpec>,
    /// Optional RFC 3032 MPLS label.
    pub mpls: Option<MplsSpec>,
}
