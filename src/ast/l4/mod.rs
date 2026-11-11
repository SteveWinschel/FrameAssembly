//! Layer 4 Transport protocols, TCP flags, header options, and transport modifiers.
//!
//! This module defines the abstract syntax tree structures for Layer 4 transport encapsulation
//! across IPv4 (`EtherType = 0x0800`) and IPv6 (`EtherType = 0x86DD`):
//! - **SCTP** (RFC 9260 / RFC 4960 Stream Control Transmission Protocol, IP Protocol `132`)
//!   with Castagnoli CRC32c checksumming and multi-stream chunk multiplexing
//! - **TCP** (RFC 9293 / RFC 7323 Transmission Control Protocol, IP Protocol `6`) with full
//!   control flags (`syn`, `ack`, `fin`, `rst`, `psh`, `urg`, `ece`, `cwr`) and RFC 7323 options
//! - **UDP** (RFC 768 User Datagram Protocol, IP Protocol `17`) connectionless datagram framing

use alloc::vec::Vec;

pub mod sctp;
pub mod tcp;
pub mod udp;

#[doc(inline)]
pub use sctp::*;
#[doc(inline)]
pub use tcp::*;
#[doc(inline)]
pub use udp::*;

/// Transport layer protocol selector for dual-transport application protocols (e.g., DNS, SIP, Syslog).
///
/// Syntax mapping: `[tcp | udp]`
#[doc(alias = "L4")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportProto {
    /// Transmission Control Protocol (RFC 9293, IP Protocol `6`).
    Tcp,
    /// User Datagram Protocol (RFC 768, IP Protocol `17`).
    Udp,
}

/// Layer 4 transport header modifiers applied to any transport or application frame statement.
///
/// Syntax mapping: `[srcport <u16>] [dstport <u16>] [seq <u32>] [acknum <u32>] [win <u16>] [urgent <u16>] [syn] [ack] [fin] [rst] [psh] [urg] [ece] [cwr] [mss <u16>] [wscale <u8>] [sackperm] [tsval <u32>] [tsecr <u32>]`
#[doc(alias = "Transport")]
#[doc(alias = "tcp")]
#[doc(alias = "udp")]
#[doc(alias = "sctp")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct L4Modifiers {
    /// Explicit 16-bit source port override (`srcport <u16>`).
    pub src_port: Option<u16>,
    /// Explicit 16-bit destination port override (`dstport <u16>`).
    pub dst_port: Option<u16>,
    /// Explicit transport protocol override (`tcp` or `udp`).
    pub transport: Option<TransportProto>,
    /// Ordered list of active TCP control flags (`syn`, `ack`, `fin`, `rst`, `psh`, `urg`, `ece`, `cwr`).
    pub tcp_flags: Vec<TcpFlag>,
    /// Optional 16-bit TCP Urgent Pointer override (`urgent <u16>`).
    pub urgent: Option<u16>,
    /// Optional RFC 7323 / RFC 2018 TCP header options (`mss`, `wscale`, `sackperm`, `tsval`, `tsecr`).
    pub tcp_options: Option<TcpOptions>,
    /// Optional RFC 9260 SCTP association and chunk parameters (`vtag`, `chunk`, `stream`, `ssn`, `ppid`).
    pub sctp_params: Option<SctpParams>,
}
