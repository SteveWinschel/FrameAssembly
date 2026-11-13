//! Telnet Network Virtual Terminal (NVT) Protocol (RFC 854 (Telnet) / RFC 855 (Options) / RFC 857 (Echo) / RFC 858 (SGA) / RFC 1073 (NAWS)) Layer 7 AST definitions.
//!
//! This module defines the abstract syntax tree (AST) configuration parameters for synthesizing
//! Telnet Network Virtual Terminal (NVT) Protocol packets over TCP port 23. On the wire, the protocol uses a 7-bit/8-bit NVT-ASCII stream interspersed with 3-byte Interpret As Command (`IAC = 0xFF`) option negotiation sequences: `IAC will <opt>` (`0xFF 0xFB <opt>`), `IAC wont <opt>` (`0xFF 0xFC <opt>`), `IAC do <opt>` (`0xFF 0xFD <opt>`), `IAC dont <opt>` (`0xFF 0xFE <opt>`), and `IAC SB <opt> ... IAC SE` (`0xFF 0xFA ... 0xFF 0xF0`) subnegotiations.
//! Every field in [`TelnetSpec`] is optional so authors can emit zero-configuration default
//! frames or override specific protocol header fields and attributes.
//!
//! Canonical `.frasm` syntax:
//! `a -> b telnet [do <u8>] [dont <u8>] [will <u8>] [wont <u8>] [option <u8>] [data <str>] [payload <str>]`

/// RFC 854 Telnet Protocol specification.
///
/// Syntax mapping: `telnet [do <u8>] [dont <u8>] [will <u8>] [wont <u8>] [option <u8>] [data <str>] [payload <str>]`
#[doc(alias = "telnet")]
#[doc(alias = "RFC 854")]
#[doc(alias = "RFC854")]
#[doc(alias = "RFC 855")]
#[doc(alias = "RFC855")]
#[doc(alias = "NVT")]
#[doc(alias = "do")]
#[doc(alias = "dont")]
#[doc(alias = "will")]
#[doc(alias = "wont")]
#[doc(alias = "option")]
#[doc(alias = "data")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TelnetSpec<'a> {
    /// IAC WILL command option (`will <u8>`).
    pub will: Option<u8>,
    /// IAC WONT command option (`wont <u8>`).
    pub wont: Option<u8>,
    /// IAC DO command option (`do <u8>`).
    pub do_opt: Option<u8>,
    /// IAC DONT command option (`dont <u8>`).
    pub dont: Option<u8>,
    /// Generic option byte (`option <u8>`).
    pub option: Option<u8>,
    /// Text data payload (`data <str>`).
    pub data: Option<&'a str>,
}
