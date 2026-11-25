//! Network Configuration Protocol (`netconf`, RFC 6241 / RFC 6242) Layer 7 AST definitions.
//!
//! This module defines [`NetconfSpec`], the zero-copy abstract syntax tree (AST) representation for
//! synthesizing Network Configuration Protocol (`NETCONF`) XML framing messages over TCP port `830`.
//! It supports RFC 6242 end-of-message delimiter framing (`]]>]]>`) and RFC 6242 chunked framing
//! (`\n#<len>\n...\n##\n` via `chunked`), alongside `<hello>` capability exchange, `<rpc>`
//! operations (`get-config`, `get`, `edit-config`, `lock`, `unlock`, `close-session`),
//! `<rpc-reply>` responses, and `<notification>` events. Every field in [`NetconfSpec`] is
//! optional so bare `netconf` emits a valid RFC 6242 `<hello>` capability message.
//!
//! Canonical `.frasm` syntax:
//! `a -> b netconf [hello | rpc | rpcreply | reply | notification | msgtype <str>] [msgid <str>] [sessionid <u32>] [operation <str>] [capability <str>] [chunked] [body <str>]`

/// RFC 6241 / RFC 6242 Network Configuration Protocol (`netconf`) specification.
///
/// Syntax mapping: `netconf [hello | rpc | rpcreply | reply | notification | msgtype <str>] [msgid <str>] [sessionid <u32>] [operation <str>] [capability <str>] [chunked] [body <str>]`
#[doc(alias = "netconf")]
#[doc(alias = "RFC 6241")]
#[doc(alias = "RFC6241")]
#[doc(alias = "RFC 6242")]
#[doc(alias = "RFC6242")]
#[doc(alias = "830")]
#[doc(alias = "hello")]
#[doc(alias = "rpc")]
#[doc(alias = "rpcreply")]
#[doc(alias = "reply")]
#[doc(alias = "notification")]
#[doc(alias = "msgtype")]
#[doc(alias = "msgid")]
#[doc(alias = "sessionid")]
#[doc(alias = "operation")]
#[doc(alias = "capability")]
#[doc(alias = "chunked")]
#[doc(alias = "body")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NetconfSpec<'a> {
    /// NETCONF XML envelope type (`"hello"`, `"rpc"`, `"rpcreply"`, or `"notification"`; default `"hello"`).
    pub msg_type: Option<&'a str>,
    /// XML `message-id` attribute value on `<rpc>` and `<rpc-reply>` messages (default `"101"`).
    pub msg_id: Option<&'a str>,
    /// Optional numeric `<session-id>` element included inside `<hello>` advertisements (`sessionid <u32>`).
    pub session_id: Option<u32>,
    /// RPC operation tag inside `<rpc>` (`"get-config"`, `"get"`, `"edit-config"`, `"lock"`, `"unlock"`, `"close-session"`; default `"get-config"`).
    pub operation: Option<&'a str>,
    /// NETCONF capability URN advertised inside `<hello>` (`capability <str>`; default `"urn:ietf:params:netconf:base:1.0"`).
    pub capability: Option<&'a str>,
    /// Selects RFC 6242 chunked framing (`\n#<len>\n...\n##\n`) when `true` instead of EOM (`]]>]]>`).
    pub chunked: bool,
    /// Custom inner XML body placed inside `<rpc>`, `<rpc-reply>`, `<notification>`, or `<hello>` (`body <str>`).
    pub body: Option<&'a str>,
}
