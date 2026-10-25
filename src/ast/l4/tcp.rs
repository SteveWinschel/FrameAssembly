//! Transmission Control Protocol (TCP, RFC 9293 / RFC 7323) AST definitions.
//!
//! Defines the control flags and header options for RFC 9293 Transmission Control Protocol
//! segments encapsulated over IPv4 or IPv6 using IP Protocol number `6`. The 20-byte base TCP
//! header contains 16-bit Source and Destination Ports, 32-bit Sequence Number (`SEQ`), 32-bit
//! Acknowledgment Number (`ACKNUM`), 4-bit Data Offset, 8-bit Control Flags (`CWR`, `ECE`,
//! `URG`, `ACK`, `PSH`, `RST`, `SYN`, `FIN`), 16-bit Window Size (`WIN`), 16-bit Checksum,
//! and 16-bit Urgent Pointer (`URGENT`), followed by 32-bit padded TLV options (`MSS`, `WSCALE`,
//! `SACK_PERM`, `TSVAL`, `TSECR`).
//!
//! Canonical `.fasm` syntax:
//! `a -> b TCP [SYN] [ACK] [FIN] [RST] [PSH] [URG] [ECE] [CWR] [SRCPORT <u16>] [DSTPORT <u16>] [SEQ <u32>] [ACKNUM <u32>] [WIN <u16>] [MSS <u16>] [WSCALE <u8>] [SACK_PERM] [TSVAL <u32>] [TSECR <u32>]`

/// TCP 8-bit control flags in byte 13 of the RFC 9293 TCP header (`CWR`, `ECE`, `URG`, `ACK`, `PSH`, `RST`, `SYN`, `FIN`).
///
/// Syntax mapping: `TCP [SYN] [ACK] [FIN] [RST] [PSH] [URG] [ECE] [CWR]`
///
/// # Examples
/// ```rust
/// use frameassembly::ast::TcpFlag;
/// let flag = TcpFlag::Syn;
/// ```
#[doc(alias = "TCP")]
#[doc(alias = "RFC 9293")]
#[doc(alias = "RFC 3168")]
#[doc(alias = "SYN")]
#[doc(alias = "ACK")]
#[doc(alias = "FIN")]
#[doc(alias = "RST")]
#[doc(alias = "PSH")]
#[doc(alias = "URG")]
#[doc(alias = "ECE")]
#[doc(alias = "CWR")]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum TcpFlag {
    /// Synchronize sequence numbers (`SYN`, bit mask `0x02`).
    Syn,
    /// Acknowledgment field significant (`ACK`, bit mask `0x10`).
    Ack,
    /// No more data from sender (`FIN`, bit mask `0x01`).
    Fin,
    /// Reset the connection (`RST`, bit mask `0x04`).
    Rst,
    /// Push Function (`PSH`, bit mask `0x08`).
    Psh,
    /// Urgent Pointer field significant (`URG`, bit mask `0x20`).
    Urg,
    /// ECN-Echo (`ECE`, bit mask `0x40`, RFC 3168).
    Ece,
    /// Congestion Window Reduced (`CWR`, bit mask `0x80`, RFC 3168).
    Cwr,
}

/// RFC 9293 / RFC 7323 / RFC 2018 TCP header options specification.
///
/// Syntax mapping: `TCP [SYN] [ACK] [FIN] [RST] [PSH] [URG] [ECE] [CWR] [SRCPORT <u16>] [DSTPORT <u16>] [SEQ <u32>] [ACKNUM <u32>] [WIN <u16>] [URGENT <u16>] [MSS <u16>] [WSCALE <u8>] [SACK_PERM] [TSVAL <u32>] [TSECR <u32>]`
#[doc(alias = "TCP")]
#[doc(alias = "RFC 9293")]
#[doc(alias = "RFC9293")]
#[doc(alias = "RFC 7323")]
#[doc(alias = "RFC7323")]
#[doc(alias = "RFC 2018")]
#[doc(alias = "proto 6")]
#[doc(alias = "TcpSpec")]
#[doc(alias = "MSS")]
#[doc(alias = "WSCALE")]
#[doc(alias = "SACK_PERM")]
#[doc(alias = "TSVAL")]
#[doc(alias = "TSECR")]
#[doc(alias = "SEQ")]
#[doc(alias = "ACKNUM")]
#[doc(alias = "WIN")]
#[doc(alias = "URGENT")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TcpOptions {
    /// Maximum Segment Size option (`MSS <u16>`, Kind `2`, Length `4`).
    pub mss: Option<u16>,
    /// Window Scale shift count option (`WSCALE <u8>`, Kind `3`, Length `3`, RFC 7323).
    pub wscale: Option<u8>,
    /// Selective Acknowledgment Permitted option (`SACK_PERM`, Kind `4`, Length `2`, RFC 2018).
    pub sack_perm: bool,
    /// TCP Timestamps Value (`TSVAL <u32>`, Kind `8`, Length `10`, RFC 7323).
    pub tsval: Option<u32>,
    /// TCP Timestamps Echo Reply (`TSECR <u32>`, Kind `8`, Length `10`, RFC 7323).
    pub tsecr: Option<u32>,
}

/// Type alias for Transmission Control Protocol (RFC 9293 / RFC 7323) specification ([`TcpOptions`]).
///
/// Syntax mapping: `TCP [SYN] [ACK] [FIN] [RST] [PSH] [URG] [ECE] [CWR] [SRCPORT <u16>] [DSTPORT <u16>] [SEQ <u32>] [ACKNUM <u32>] [WIN <u16>] [URGENT <u16>] [MSS <u16>] [WSCALE <u8>] [SACK_PERM] [TSVAL <u32>] [TSECR <u32>]`
#[doc(alias = "TCP")]
#[doc(alias = "RFC 9293")]
#[doc(alias = "RFC 7323")]
#[doc(alias = "MSS")]
#[doc(alias = "WSCALE")]
#[doc(alias = "SACK_PERM")]
#[doc(alias = "TSVAL")]
#[doc(alias = "TSECR")]
pub type TcpSpec = TcpOptions;
