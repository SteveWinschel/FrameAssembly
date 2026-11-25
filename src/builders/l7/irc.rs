//! Internet Relay Chat Protocol (IRC, RFC 1459 / RFC 2812) Layer 7 wire packet builder.
//!
//! This module synthesizes deterministic CRLF-terminated Internet Relay Chat (`irc`) commands
//! and server numeric/relayed messages over TCP port 6667. When optional fields in [`IrcSpec`]
//! are omitted, client frames emit `NICK guest\r\n` and server-originated frames emit
//! `:irc.example.com 001 guest :Welcome to IRC\r\n`. Explicit command verbs, prefixes, targets,
//! parameters, and trailing messages format according to RFC 1459 §2.3.1.
//!
//! Canonical `.frasm` syntax:
//! `a -> b irc [prefix <str>] [nick [<str>] | join [<str>] | privmsg [<str>] | ping | pong | quit | cmd <str>] [channel <str> | target <str>] [param <str>] [msg <str>]`

use crate::ast::*;
use crate::builders::WireContext;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

/// Returns `true` when the resolved source port identifies an IRC server endpoint.
fn is_irc_server_src(ctx: &WireContext) -> bool {
    let irc_port = |p: u16| matches!(p, 6665..=6669 | 6697);
    (irc_port(ctx.src_port) && !irc_port(ctx.dst_port))
        || (ctx.src_port < 1024 && ctx.dst_port >= 1024)
}

/// Builds an RFC 1459 / RFC 2812 IRC line payload.
///
/// Syntax mapping: `irc [prefix <str>] [nick [<str>] | join [<str>] | privmsg [<str>] | ping | pong | quit | cmd <str>] [channel <str> | target <str>] [param <str>] [msg <str>]`
#[doc(alias = "IRC")]
#[doc(alias = "RFC1459")]
#[doc(alias = "RFC2812")]
pub fn build_irc_payload(
    ctx: &WireContext,
    spec: &IrcSpec,
    payload_bytes: &[u8],
) -> Vec<u8> {
    let mut line = String::new();
    let has_any = spec.prefix.is_some()
        || spec.cmd.is_some()
        || spec.target.is_some()
        || spec.param.is_some()
        || spec.msg.is_some();

    if !has_any {
        if is_irc_server_src(ctx) {
            line.push_str(":irc.example.com 001 guest :Welcome to IRC\r\n");
        } else {
            line.push_str("NICK guest\r\n");
        }
    } else {
        if let Some(prefix) = spec.prefix {
            line.push(':');
            line.push_str(prefix);
            line.push(' ');
        }
        let raw_cmd = spec
            .cmd
            .unwrap_or(if spec.prefix.is_some() { "NOTICE" } else { "NICK" });
        let cmd = if raw_cmd.bytes().all(|b| b.is_ascii_alphabetic()) {
            raw_cmd.to_ascii_uppercase()
        } else {
            raw_cmd.to_string()
        };
        line.push_str(&cmd);

        if let Some(target) = spec.target {
            line.push(' ');
            line.push_str(target);
        }
        if let Some(param) = spec.param {
            line.push(' ');
            line.push_str(param);
        }

        if spec.target.is_none() && spec.param.is_none() && spec.msg.is_none() {
            match cmd.as_str() {
                "NICK" => line.push_str(" guest"),
                "JOIN" => line.push_str(" #general"),
                "PRIVMSG" | "NOTICE" => line.push_str(" #general :hello"),
                "PING" | "PONG" => line.push_str(" :irc.example.com"),
                "USER" => line.push_str(" guest 0 * :Guest User"),
                "QUIT" => line.push_str(" :Client Quit"),
                _ => {}
            }
        } else if matches!(cmd.as_str(), "PRIVMSG" | "NOTICE")
            && spec.target.is_none()
            && spec.param.is_none()
            && spec.msg.is_some()
        {
            line.push_str(" #general");
        }

        if let Some(msg) = spec.msg {
            line.push_str(" :");
            line.push_str(msg);
        }
        line.push_str("\r\n");
    }

    let mut bytes = line.into_bytes();
    if !payload_bytes.is_empty() {
        bytes.extend_from_slice(payload_bytes);
    }
    bytes
}
