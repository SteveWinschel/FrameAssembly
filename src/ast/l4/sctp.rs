//! Stream Control Transmission Protocol (SCTP, RFC 9260 / RFC 4960) AST definitions.
//!
//! Defines the abstract syntax tree parameters for RFC 9260 Stream Control Transmission Protocol
//! packets encapsulated directly over IPv4 or IPv6 using IP Protocol number `132` (`0x84`).
//! Every SCTP packet begins with a 12-byte Common Header containing the 16-bit Source Port,
//! 16-bit Destination Port, 32-bit Verification Tag (`vtag`), and 32-bit little-endian
//! Castagnoli CRC32c checksum, followed by one or more 32-bit aligned Chunks (`data`, `init`,
//! `initack`, `sack`, `heartbeat`, `heartbeatack`, `abort`, `shutdown`, `shutdownack`, `cookieecho`, `cookieack`).
//!
//! Canonical `.frasm` syntax:
//! `a -> b sctp [chunk <type>] [vtag <u32>] [stream <u16>] [ssn <u16>] [ppid <u32>] [srcport <u16>] [dstport <u16>]`

use alloc::string::String;

/// Stream Control Transmission Protocol (RFC 9260) association and chunk parameters specification.
///
/// Syntax mapping: `sctp [chunk <data|init|initack|sack|heartbeat|heartbeatack|abort|shutdown|shutdownack|cookieecho|cookieack>] [vtag <u32>] [stream <u16>] [ssn <u16>] [ppid <u32>]`
#[doc(alias = "sctp")]
#[doc(alias = "RFC 9260")]
#[doc(alias = "RFC9260")]
#[doc(alias = "RFC 4960")]
#[doc(alias = "proto 132")]
#[doc(alias = "SctpSpec")]
#[doc(alias = "chunk")]
#[doc(alias = "vtag")]
#[doc(alias = "stream")]
#[doc(alias = "ssn")]
#[doc(alias = "ppid")]
#[doc(alias = "init")]
#[doc(alias = "initack")]
#[doc(alias = "sack")]
#[doc(alias = "heartbeat")]
#[doc(alias = "shutdownack")]
#[doc(alias = "cookieecho")]
#[doc(alias = "cookieack")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SctpParams {
    /// 32-bit Verification Tag (`vtag <u32>`) authenticating the SCTP association in the Common Header.
    pub vtag: Option<u32>,
    /// 16-bit Stream Identifier (`stream <u16>`) inside an SCTP `data` chunk header.
    pub stream: Option<u16>,
    /// 16-bit Stream Sequence Number (`ssn <u16>`) for ordered delivery within a stream.
    pub ssn: Option<u16>,
    /// 32-bit Payload Protocol Identifier (`ppid <u32>`, e.g., `60` for 5G NGAP, `18` for LTE S1AP, `3` for M3UA).
    pub ppid: Option<u32>,
    /// SCTP Chunk Type name (`chunk <name>`, e.g., `"INIT"`, `"INIT_ACK"`, `"COOKIE_ECHO"`, `"COOKIE_ACK"`, `"DATA"`, `"SACK"`, `"SHUTDOWN_ACK"`).
    pub chunk: Option<String>,
}

/// Type alias for Stream Control Transmission Protocol (RFC 9260) specification ([`SctpParams`]).
///
/// Syntax mapping: `sctp [chunk <data|init|initack|sack|heartbeat|heartbeatack|abort|shutdown|shutdownack|cookieecho|cookieack>] [vtag <u32>] [stream <u16>] [ssn <u16>] [ppid <u32>]`
#[doc(alias = "sctp")]
#[doc(alias = "RFC 9260")]
#[doc(alias = "chunk")]
#[doc(alias = "vtag")]
#[doc(alias = "stream")]
#[doc(alias = "ssn")]
#[doc(alias = "ppid")]
pub type SctpSpec = SctpParams;
