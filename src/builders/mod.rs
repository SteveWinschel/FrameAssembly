//! FrameAssembly Protocol Builders.
//!
//! Dedicated builders per OSI layer and protocol.

use crate::ast::{L2Modifiers, L3Modifiers, L4Modifiers, TransportProto};
use core::net::IpAddr;

/// Wire synthesis context holding endpoints, transport ports, and layer modifiers.
#[derive(Debug, Clone)]
pub struct WireContext<'a> {
    /// Source IP address.
    pub src_ip: IpAddr,
    /// Destination IP address.
    pub dst_ip: IpAddr,
    /// Source MAC address.
    pub src_mac: [u8; 6],
    /// Destination MAC address.
    pub dst_mac: [u8; 6],
    /// Transport protocol override.
    pub transport: Option<TransportProto>,
    /// Resolved source port.
    pub src_port: u16,
    /// Resolved destination port.
    pub dst_port: u16,
    /// TCP sequence number.
    pub seq: Option<u32>,
    /// TCP acknowledgment number.
    pub ack: Option<u32>,
    /// Layer 2 modifiers.
    pub l2: &'a L2Modifiers,
    /// Layer 3 modifiers.
    pub l3: &'a L3Modifiers,
    /// Layer 4 modifiers.
    pub l4: &'a L4Modifiers,
}

/// Layer 2 data link protocol builders.
pub mod l2;
/// Layer 3 network and tunneling protocol builders.
pub mod l3;
/// Layer 4 transport protocol builders.
pub mod l4;
/// Layer 7 application protocol builders.
pub mod l7;

// Backwards-compatible aliases
/// Backwards-compatible alias for Layer 3 builders.
pub use l3 as l3_tunnel;
/// Backwards-compatible alias for Layer 4 transport builders.
pub use l4 as transport;
/// Backwards-compatible alias for Layer 7 infrastructure builders.
pub use l7 as l7_infra;
/// Backwards-compatible alias for Layer 7 application builders.
pub use l7 as l7_app;
/// Backwards-compatible alias for Layer 7 OT/ICS builders.
pub use l7 as l7_ot;
/// Backwards-compatible alias for SNMP builders.
pub use l7::snmp;

