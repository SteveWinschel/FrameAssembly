//! Transmission Control Protocol (TCP, RFC 9293 / RFC 7323) AST definitions.
//!
//! Defines the control flags and header options for RFC 9293 Transmission Control Protocol
//! segments encapsulated over IPv4 or IPv6 using IP Protocol number `6`. The 20-byte base TCP
//! header contains 16-bit Source and Destination Ports, 32-bit Sequence Number (`seq`), 32-bit
//! Acknowledgment Number (`acknum`), 4-bit Data Offset, 8-bit Control Flags (`cwr`, `ece`,
//! `urg`, `ack`, `psh`, `rst`, `syn`, `fin`), 16-bit Window Size (`win`), 16-bit Checksum,
//! and 16-bit Urgent Pointer (`urgent`), followed by 32-bit padded TLV options (`mss`, `wscale`,
//! `sackperm`, `tsval`, `tsecr`).
//!
//! Canonical `.fasm` syntax:
//! `a -> b tcp [syn] [ack] [fin] [rst] [psh] [urg] [ece] [cwr] [srcport <u16>] [dstport <u16>] [seq <u32>] [acknum <u32>] [win <u16>] [mss <u16>] [wscale <u8>] [sackperm] [tsval <u32>] [tsecr <u32>]`

/// TCP 8-bit control flags in byte 13 of the RFC 9293 TCP header (`cwr`, `ece`, `urg`, `ack`, `psh`, `rst`, `syn`, `fin`).
///
/// Syntax mapping: `tcp [syn] [ack] [fin] [rst] [psh] [urg] [ece] [cwr]`
///
/// # Examples
/// ```rust
/// use frameassembly::ast::TcpFlag;
/// let flag = TcpFlag::Syn;
/// ```
#[doc(alias = "tcp")]
#[doc(alias = "RFC 9293")]
#[doc(alias = "RFC 3168")]
#[doc(alias = "syn")]
#[doc(alias = "ack")]
#[doc(alias = "fin")]
#[doc(alias = "rst")]
#[doc(alias = "psh")]
#[doc(alias = "urg")]
#[doc(alias = "ece")]
#[doc(alias = "cwr")]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum TcpFlag {
    /// Synchronize sequence numbers (`syn`, bit mask `0x02`).
    Syn,
    /// Acknowledgment field significant (`ack`, bit mask `0x10`).
    Ack,
    /// No more data from sender (`fin`, bit mask `0x01`).
    Fin,
    /// Reset the connection (`rst`, bit mask `0x04`).
    Rst,
    /// Push Function (`psh`, bit mask `0x08`).
    Psh,
    /// Urgent Pointer field significant (`urg`, bit mask `0x20`).
    Urg,
    /// ECN-Echo (`ece`, bit mask `0x40`, RFC 3168).
    Ece,
    /// Congestion Window Reduced (`cwr`, bit mask `0x80`, RFC 3168).
    Cwr,
}

/// RFC 9293 / RFC 7323 / RFC 2018 TCP header options specification.
///
/// Syntax mapping: `tcp [syn] [ack] [fin] [rst] [psh] [urg] [ece] [cwr] [srcport <u16>] [dstport <u16>] [seq <u32>] [acknum <u32>] [win <u16>] [urgent <u16>] [mss <u16>] [wscale <u8>] [sackperm] [tsval <u32>] [tsecr <u32>]`
#[doc(alias = "tcp")]
#[doc(alias = "RFC 9293")]
#[doc(alias = "RFC9293")]
#[doc(alias = "RFC 7323")]
#[doc(alias = "RFC7323")]
#[doc(alias = "RFC 2018")]
#[doc(alias = "proto 6")]
#[doc(alias = "TcpSpec")]
#[doc(alias = "mss")]
#[doc(alias = "wscale")]
#[doc(alias = "sackperm")]
#[doc(alias = "tsval")]
#[doc(alias = "tsecr")]
#[doc(alias = "seq")]
#[doc(alias = "acknum")]
#[doc(alias = "win")]
#[doc(alias = "urgent")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TcpOptions {
    /// Maximum Segment Size option (`mss <u16>`, Kind `2`, Length `4`).
    pub mss: Option<u16>,
    /// Window Scale shift count option (`wscale <u8>`, Kind `3`, Length `3`, RFC 7323).
    pub wscale: Option<u8>,
    /// Selective Acknowledgment Permitted option (`sackperm`, Kind `4`, Length `2`, RFC 2018).
    pub sack_perm: bool,
    /// TCP Timestamps Value (`tsval <u32>`, Kind `8`, Length `10`, RFC 7323).
    pub tsval: Option<u32>,
    /// TCP Timestamps Echo Reply (`tsecr <u32>`, Kind `8`, Length `10`, RFC 7323).
    pub tsecr: Option<u32>,
}

/// Type alias for Transmission Control Protocol (RFC 9293 / RFC 7323) specification ([`TcpOptions`]).
///
/// Syntax mapping: `tcp [syn] [ack] [fin] [rst] [psh] [urg] [ece] [cwr] [srcport <u16>] [dstport <u16>] [seq <u32>] [acknum <u32>] [win <u16>] [urgent <u16>] [mss <u16>] [wscale <u8>] [sackperm] [tsval <u32>] [tsecr <u32>]`
#[doc(alias = "tcp")]
#[doc(alias = "RFC 9293")]
#[doc(alias = "RFC 7323")]
#[doc(alias = "mss")]
#[doc(alias = "wscale")]
#[doc(alias = "sackperm")]
#[doc(alias = "tsval")]
#[doc(alias = "tsecr")]
pub type TcpSpec = TcpOptions;
