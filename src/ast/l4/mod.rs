//! Layer 4 Transport layer protocols, TCP flags, options, and modifiers.

use alloc::vec::Vec;

/// Stream Control Transmission Protocol.
pub mod sctp;
/// Transmission Control Protocol.
pub mod tcp;
/// User Datagram Protocol.
pub mod udp;

pub use sctp::*;
pub use tcp::*;
pub use udp::*;

/// Transport layer protocol selector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportProto {
    /// Transmission Control Protocol.
    Tcp,
    /// User Datagram Protocol.
    Udp,
}

/// Layer 4 transport modifiers.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct L4Modifiers {
    /// Explicit source port override.
    pub src_port: Option<u16>,
    /// Explicit destination port override.
    pub dst_port: Option<u16>,
    /// Explicit transport protocol override.
    pub transport: Option<TransportProto>,
    /// TCP flags.
    pub tcp_flags: Vec<TcpFlag>,
    /// Optional TCP urgent pointer.
    pub urgent: Option<u16>,
    /// Optional TCP options.
    pub tcp_options: Option<TcpOptions>,
    /// Optional SCTP parameters.
    pub sctp_params: Option<SctpParams>,
}
