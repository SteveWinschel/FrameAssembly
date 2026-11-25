//! SOCKS Version 5 Proxy Protocol (RFC 1928 / RFC 1929 Username-Password Authentication) Layer 7 AST definitions.
//!
//! This module defines the abstract syntax tree (AST) configuration parameters for synthesizing
//! SOCKS5 proxy control packets over TCP port 1080. On the wire, the protocol carries RFC 1928
//! client method-selection greetings (`0x05 <nmethods> <methods...>`), server method-selection
//! replies (`0x05 <method>`), RFC 1929 username/password authentication subnegotiations (`0x01`),
//! and `CONNECT` (`0x01`), `BIND` (`0x02`), or `UDP ASSOCIATE` (`0x03`) command requests and
//! replies with IPv4 (`0x01`), domain name (`0x03`), or IPv6 (`0x04`) target endpoints.
//! Every field in [`SocksSpec`] is optional so authors can emit zero-configuration default
//! frames or override specific protocol header fields and attributes.
//!
//! Canonical `.frasm` syntax:
//! `a -> b socks [greeting | reply] [connect | bind | udpassociate | cmd <str>] [version <u8>] [method <str>] [status <u8>] [addr <str>] [targetport <u16>] [user <str>] [password <str>]`

/// RFC 1928 / RFC 1929 SOCKS5 proxy control specification.
///
/// Syntax mapping: `socks [greeting | reply] [connect | bind | udpassociate | cmd <str>] [version <u8>] [method <str>] [status <u8>] [addr <str>] [targetport <u16>] [user <str>] [password <str>]`
#[doc(alias = "socks")]
#[doc(alias = "SOCKS5")]
#[doc(alias = "RFC 1928")]
#[doc(alias = "RFC1928")]
#[doc(alias = "RFC 1929")]
#[doc(alias = "RFC1929")]
#[doc(alias = "greeting")]
#[doc(alias = "reply")]
#[doc(alias = "connect")]
#[doc(alias = "bind")]
#[doc(alias = "udpassociate")]
#[doc(alias = "cmd")]
#[doc(alias = "version")]
#[doc(alias = "method")]
#[doc(alias = "status")]
#[doc(alias = "addr")]
#[doc(alias = "targetport")]
#[doc(alias = "user")]
#[doc(alias = "password")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SocksSpec<'a> {
    /// SOCKS protocol version (`version <u8>`, default `5`, or `1` for RFC 1929 subnegotiation).
    pub version: Option<u8>,
    /// Client method-selection greeting flag (`greeting`).
    pub is_greeting: bool,
    /// Server command or method reply flag (`reply`).
    pub is_reply: bool,
    /// SOCKS5 command verb or numeric opcode (`connect`, `bind`, `udpassociate`, or `cmd <str>`).
    pub cmd: Option<&'a str>,
    /// Authentication method code, name, or comma-separated list (`method <str>`).
    pub method: Option<&'a str>,
    /// SOCKS5 or RFC 1929 reply status code (`status <u8>`).
    pub status: Option<u8>,
    /// Target or bound endpoint IPv4, IPv6, or domain name (`addr <str>`).
    pub addr: Option<&'a str>,
    /// Target or bound destination port (`targetport <u16>`).
    pub target_port: Option<u16>,
    /// RFC 1929 username string (`user <str>`).
    pub user: Option<&'a str>,
    /// RFC 1929 password string (`password <str>`).
    pub password: Option<&'a str>,
}
