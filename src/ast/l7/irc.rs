//! Internet Relay Chat Protocol (IRC, RFC 1459 / RFC 2812) Layer 7 AST definitions.
//!
//! This module defines the abstract syntax tree (AST) configuration parameters for synthesizing
//! Internet Relay Chat (`irc`) client commands and server numeric/relayed messages over TCP port
//! 6667. On the wire, the protocol transmits CRLF-delimited ASCII/UTF-8 message lines formatted
//! according to `[:<prefix> ]<command>[ <target>[ <param>]][ :<trailing>]\r\n`, covering `NICK`,
//! `USER`, `JOIN`, `PRIVMSG`, `NOTICE`, `PING`, `PONG`, `QUIT`, `PASS`, and numeric server replies
//! (`001`, `332`, `433`). Every field in [`IrcSpec`] is optional so authors can emit
//! zero-configuration default frames or override individual IRC message fields.
//!
//! Canonical `.frasm` syntax:
//! `a -> b irc [prefix <str>] [nick [<str>] | join [<str>] | privmsg [<str>] | ping | pong | quit | cmd <str>] [channel <str> | target <str>] [param <str>] [msg <str>]`

/// RFC 1459 / RFC 2812 Internet Relay Chat specification.
///
/// Syntax mapping: `irc [prefix <str>] [nick [<str>] | join [<str>] | privmsg [<str>] | ping | pong | quit | cmd <str>] [channel <str> | target <str>] [param <str>] [msg <str>]`
#[doc(alias = "irc")]
#[doc(alias = "RFC 1459")]
#[doc(alias = "RFC1459")]
#[doc(alias = "RFC 2812")]
#[doc(alias = "RFC2812")]
#[doc(alias = "prefix")]
#[doc(alias = "nick")]
#[doc(alias = "join")]
#[doc(alias = "privmsg")]
#[doc(alias = "ping")]
#[doc(alias = "pong")]
#[doc(alias = "quit")]
#[doc(alias = "cmd")]
#[doc(alias = "channel")]
#[doc(alias = "target")]
#[doc(alias = "param")]
#[doc(alias = "msg")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct IrcSpec<'a> {
    /// Optional sender or server prefix without leading `:` (`prefix <str>`).
    pub prefix: Option<&'a str>,
    /// IRC command verb or 3-digit numeric code (`cmd <str>` or command shorthands).
    pub cmd: Option<&'a str>,
    /// Primary target channel or nickname (`channel <str>` or `target <str>`).
    pub target: Option<&'a str>,
    /// Additional middle parameters (`param <str>` or `nick <str>`).
    pub param: Option<&'a str>,
    /// Trailing message body serialized after ` :` (`msg <str>`).
    pub msg: Option<&'a str>,
}
