//! Telnet Network Virtual Terminal (NVT) Protocol (RFC 854 (Telnet) / RFC 855 (Options) / RFC 857 (Echo) / RFC 858 (SGA) / RFC 1073 (NAWS)) Layer 7 AST definitions.
//!
//! This module defines the abstract syntax tree (AST) configuration parameters for synthesizing
//! Telnet Network Virtual Terminal (NVT) Protocol packets over TCP port 23. On the wire, the protocol uses a 7-bit/8-bit NVT-ASCII stream interspersed with 3-byte Interpret As Command (`IAC = 0xFF`) option negotiation sequences: `IAC WILL <opt>` (`0xFF 0xFB <opt>`), `IAC WONT <opt>` (`0xFF 0xFC <opt>`), `IAC DO <opt>` (`0xFF 0xFD <opt>`), `IAC DONT <opt>` (`0xFF 0xFE <opt>`), and `IAC SB <opt> ... IAC SE` (`0xFF 0xFA ... 0xFF 0xF0`) subnegotiations.
//! Every field in [`TelnetSpec`] is optional so authors can emit zero-configuration default
//! frames or override specific protocol header fields and attributes.
//!
//! Canonical `.fasm` syntax:
//! `a -> b TELNET [DO <u8>] [DONT <u8>] [WILL <u8>] [WONT <u8>] [OPTION <u8>] [DATA <str>] [PAYLOAD <str>]`

/// RFC 854 Telnet Protocol specification.
///
/// Syntax mapping: `TELNET [DO <u8>] [DONT <u8>] [WILL <u8>] [WONT <u8>] [OPTION <u8>] [DATA <str>] [PAYLOAD <str>]`
#[doc(alias = "TELNET")]
#[doc(alias = "RFC 854")]
#[doc(alias = "RFC854")]
#[doc(alias = "RFC 855")]
#[doc(alias = "RFC855")]
#[doc(alias = "NVT")]
#[doc(alias = "DO")]
#[doc(alias = "DONT")]
#[doc(alias = "WILL")]
#[doc(alias = "WONT")]
#[doc(alias = "OPTION")]
#[doc(alias = "DATA")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TelnetSpec<'a> {
    /// IAC WILL command option (`WILL <u8>`).
    pub will: Option<u8>,
    /// IAC WONT command option (`WONT <u8>`).
    pub wont: Option<u8>,
    /// IAC DO command option (`DO <u8>`).
    pub do_opt: Option<u8>,
    /// IAC DONT command option (`DONT <u8>`).
    pub dont: Option<u8>,
    /// Generic option byte (`OPTION <u8>`).
    pub option: Option<u8>,
    /// Text data payload (`DATA <str>`).
    pub data: Option<&'a str>,
}
