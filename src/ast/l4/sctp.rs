//! Stream Control Transmission Protocol (SCTP, RFC 9260 / RFC 4960) AST definitions.
//!
//! Defines the abstract syntax tree parameters for RFC 9260 Stream Control Transmission Protocol
//! packets encapsulated directly over IPv4 or IPv6 using IP Protocol number `132` (`0x84`).
//! Every SCTP packet begins with a 12-byte Common Header containing the 16-bit Source Port,
//! 16-bit Destination Port, 32-bit Verification Tag (`VTAG`), and 32-bit little-endian
//! Castagnoli CRC32c checksum, followed by one or more 32-bit aligned Chunks (`DATA`, `INIT`,
//! `INIT_ACK`, `SACK`, `HEARTBEAT`, `HEARTBEAT_ACK`, `ABORT`, `SHUTDOWN`, `COOKIE_ECHO`, `COOKIE_ACK`).
//!
//! Canonical `.fasm` syntax:
//! `a -> b SCTP [CHUNK <type>] [VTAG <u32>] [STREAM <u16>] [SSN <u16>] [PPID <u32>] [SRCPORT <u16>] [DSTPORT <u16>]`

use alloc::string::String;

/// Stream Control Transmission Protocol (RFC 9260) association and chunk parameters specification.
///
/// Syntax mapping: `SCTP [CHUNK <DATA|INIT|INIT_ACK|SACK|HEARTBEAT|HEARTBEAT_ACK|ABORT|SHUTDOWN|COOKIE_ECHO|COOKIE_ACK>] [VTAG <u32>] [STREAM <u16>] [SSN <u16>] [PPID <u32>]`
#[doc(alias = "SCTP")]
#[doc(alias = "RFC 9260")]
#[doc(alias = "RFC9260")]
#[doc(alias = "RFC 4960")]
#[doc(alias = "proto 132")]
#[doc(alias = "SctpSpec")]
#[doc(alias = "CHUNK")]
#[doc(alias = "VTAG")]
#[doc(alias = "STREAM")]
#[doc(alias = "SSN")]
#[doc(alias = "PPID")]
#[doc(alias = "INIT")]
#[doc(alias = "INIT_ACK")]
#[doc(alias = "SACK")]
#[doc(alias = "HEARTBEAT")]
#[doc(alias = "COOKIE_ECHO")]
#[doc(alias = "COOKIE_ACK")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SctpParams {
    /// 32-bit Verification Tag (`VTAG <u32>`) authenticating the SCTP association in the Common Header.
    pub vtag: Option<u32>,
    /// 16-bit Stream Identifier (`STREAM <u16>`) inside an SCTP `DATA` chunk header.
    pub stream: Option<u16>,
    /// 16-bit Stream Sequence Number (`SSN <u16>`) for ordered delivery within a stream.
    pub ssn: Option<u16>,
    /// 32-bit Payload Protocol Identifier (`PPID <u32>`, e.g., `60` for 5G NGAP, `18` for LTE S1AP, `3` for M3UA).
    pub ppid: Option<u32>,
    /// SCTP Chunk Type name (`CHUNK <name>`, e.g., `"INIT"`, `"INIT_ACK"`, `"COOKIE_ECHO"`, `"COOKIE_ACK"`, `"DATA"`, `"SACK"`).
    pub chunk: Option<String>,
}

/// Type alias for Stream Control Transmission Protocol (RFC 9260) specification ([`SctpParams`]).
///
/// Syntax mapping: `SCTP [CHUNK <DATA|INIT|INIT_ACK|SACK|HEARTBEAT|HEARTBEAT_ACK|ABORT|SHUTDOWN|COOKIE_ECHO|COOKIE_ACK>] [VTAG <u32>] [STREAM <u16>] [SSN <u16>] [PPID <u32>]`
#[doc(alias = "SCTP")]
#[doc(alias = "RFC 9260")]
#[doc(alias = "CHUNK")]
#[doc(alias = "VTAG")]
#[doc(alias = "STREAM")]
#[doc(alias = "SSN")]
#[doc(alias = "PPID")]
pub type SctpSpec = SctpParams;
