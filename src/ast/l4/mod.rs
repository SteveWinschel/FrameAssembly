//! Layer 4 Transport protocols, TCP flags, header options, and transport modifiers.
//!
//! This module defines the abstract syntax tree structures for Layer 4 transport encapsulation
//! across IPv4 (`EtherType = 0x0800`) and IPv6 (`EtherType = 0x86DD`):
//! - **SCTP** (RFC 9260 / RFC 4960 Stream Control Transmission Protocol, IP Protocol `132`)
//!   with Castagnoli CRC32c checksumming and multi-stream chunk multiplexing
//! - **TCP** (RFC 9293 / RFC 7323 Transmission Control Protocol, IP Protocol `6`) with full
//!   control flags (`SYN`, `ACK`, `FIN`, `RST`, `PSH`, `URG`, `ECE`, `CWR`) and RFC 7323 options
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
/// Syntax mapping: `[TCP | UDP]`
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
/// Syntax mapping: `[SRCPORT <u16>] [DSTPORT <u16>] [SEQ <u32>] [ACKNUM <u32>] [WIN <u16>] [URGENT <u16>] [SYN] [ACK] [FIN] [RST] [PSH] [URG] [ECE] [CWR] [MSS <u16>] [WSCALE <u8>] [SACK_PERM] [TSVAL <u32>] [TSECR <u32>]`
#[doc(alias = "Transport")]
#[doc(alias = "TCP")]
#[doc(alias = "UDP")]
#[doc(alias = "SCTP")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct L4Modifiers {
    /// Explicit 16-bit source port override (`SRCPORT <u16>`).
    pub src_port: Option<u16>,
    /// Explicit 16-bit destination port override (`DSTPORT <u16>`).
    pub dst_port: Option<u16>,
    /// Explicit transport protocol override (`TCP` or `UDP`).
    pub transport: Option<TransportProto>,
    /// Ordered list of active TCP control flags (`SYN`, `ACK`, `FIN`, `RST`, `PSH`, `URG`, `ECE`, `CWR`).
    pub tcp_flags: Vec<TcpFlag>,
    /// Optional 16-bit TCP Urgent Pointer override (`URGENT <u16>`).
    pub urgent: Option<u16>,
    /// Optional RFC 7323 / RFC 2018 TCP header options (`MSS`, `WSCALE`, `SACK_PERM`, `TSVAL`, `TSECR`).
    pub tcp_options: Option<TcpOptions>,
    /// Optional RFC 9260 SCTP association and chunk parameters (`VTAG`, `CHUNK`, `STREAM`, `SSN`, `PPID`).
    pub sctp_params: Option<SctpParams>,
}
