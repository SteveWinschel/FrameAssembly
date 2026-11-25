//! Internet Relay Chat Protocol (`irc`, RFC 1459 / RFC 2812) Layer 7 PCAP-to-`.frasm` decompiler.
//!
//! This module implements the fuzz-safe reverse dissector for RFC 1459 / RFC 2812 `irc` client
//! commands and server numeric/relayed lines carried over TCP or SCTP ports `6665..=6669` and
//! `6697`. It parses optional `:prefix`, command verbs or 3-digit numerics, target channels or
//! nicknames, middle parameters, and ` :trailing` text while eliding defaults and preserving
//! pipelined trailing lines in `residual_payload`.

use alloc::string::String;
use core::fmt::Write as _;

use crate::ast::{Protocol, TransportProto};
use crate::reverse::{ProtocolDissection, sd};

use super::{find_subslice, is_valid_raw_string_body, push_str_mod};

/// Returns `true` when `(src_port, dst_port)` identifies an IRC server endpoint.
fn is_irc_server_src(src_port: u16, dst_port: u16) -> bool {
    let irc_port = |p: u16| matches!(p, 6665..=6669 | 6697);
    (irc_port(src_port) && !irc_port(dst_port)) || (src_port < 1024 && dst_port >= 1024)
}

/// Validates that `cmd` is a canonical RFC 1459 ASCII alphabetic command or 3-digit numeric code.
fn is_valid_irc_cmd(cmd: &str) -> bool {
    (!cmd.is_empty() && cmd.len() <= 32 && cmd.bytes().all(|b| b.is_ascii_alphabetic()))
        || (cmd.len() == 3 && cmd.bytes().all(|b| b.is_ascii_digit()))
}

/// Dissects an RFC 1459 / RFC 2812 IRC command or reply line over TCP or SCTP port `6667`.
pub(crate) fn dissect_irc(
    transport: TransportProto,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Option<ProtocolDissection> {
    if !matches!(transport, TransportProto::Tcp | TransportProto::Sctp)
        || (!matches!(src_port, 6665..=6669 | 6697) && !matches!(dst_port, 6665..=6669 | 6697))
    {
        return None;
    }

    let crlf = find_subslice(payload, b"\r\n")?;
    if crlf == 0 || crlf > 510 {
        return None;
    }
    let line = core::str::from_utf8(payload.get(..crlf)?).ok()?;
    if !is_valid_raw_string_body(line) {
        return None;
    }
    let trailing = payload.get(crlf + 2..)?.to_vec();
    let server_src = is_irc_server_src(src_port, dst_port);

    if (!server_src && line == "NICK guest")
        || (server_src && line == ":irc.example.com 001 guest :Welcome to IRC")
    {
        return Some(sd(Protocol::Irc, String::from("irc"), trailing));
    }

    let (prefix_opt, after_prefix) = if let Some(after_colon) = line.strip_prefix(':') {
        let (p, r) = after_colon.split_once(' ')?;
        if p.is_empty() {
            return None;
        }
        (Some(p), r)
    } else {
        (None, line)
    };

    let (head, msg_opt) = match after_prefix.find(" :") {
        Some(idx) => (&after_prefix[..idx], Some(&after_prefix[idx + 2..])),
        None => (after_prefix, None),
    };
    let (cmd, rest_args) = head.split_once(' ').unwrap_or((head, ""));
    if !is_valid_irc_cmd(cmd) {
        return None;
    }
    let cmd_up = cmd.to_ascii_uppercase();

    let mut tokens = String::from("irc");
    if let Some(prefix) = prefix_opt {
        push_str_mod(&mut tokens, "prefix", prefix);
    }

    if cmd_up == "NICK" && msg_opt.is_none() && !rest_args.is_empty() && !rest_args.contains(' ') {
        if rest_args == "guest" {
            tokens.push_str(" nick");
        } else {
            push_str_mod(&mut tokens, "nick", rest_args);
        }
        return Some(sd(Protocol::Irc, tokens, trailing));
    }
    if cmd_up == "JOIN" && msg_opt.is_none() && !rest_args.is_empty() && !rest_args.contains(' ') {
        if rest_args == "#general" {
            tokens.push_str(" join");
        } else {
            push_str_mod(&mut tokens, "join", rest_args);
        }
        return Some(sd(Protocol::Irc, tokens, trailing));
    }
    if cmd_up == "PRIVMSG" && !rest_args.is_empty() && !rest_args.contains(' ') {
        if rest_args == "#general" && msg_opt == Some("hello") {
            tokens.push_str(" privmsg");
        } else {
            push_str_mod(&mut tokens, "privmsg", rest_args);
            if let Some(msg) = msg_opt {
                push_str_mod(&mut tokens, "msg", msg);
            }
        }
        return Some(sd(Protocol::Irc, tokens, trailing));
    }
    if matches!(cmd_up.as_str(), "PING" | "PONG") && rest_args.is_empty() {
        let _ = write!(tokens, " {}", cmd_up.to_ascii_lowercase());
        if let Some(msg) = msg_opt
            && msg != "irc.example.com"
        {
            push_str_mod(&mut tokens, "msg", msg);
        }
        return Some(sd(Protocol::Irc, tokens, trailing));
    }
    if cmd_up == "QUIT" && rest_args.is_empty() {
        tokens.push_str(" quit");
        if let Some(msg) = msg_opt
            && msg != "Client Quit"
        {
            push_str_mod(&mut tokens, "msg", msg);
        }
        return Some(sd(Protocol::Irc, tokens, trailing));
    }

    push_str_mod(&mut tokens, "cmd", cmd);
    if !rest_args.is_empty() {
        if let Some((t, p)) = rest_args.split_once(' ') {
            if t.starts_with('#') || t.starts_with('&') {
                push_str_mod(&mut tokens, "channel", t);
            } else {
                push_str_mod(&mut tokens, "target", t);
            }
            push_str_mod(&mut tokens, "param", p);
        } else if rest_args.starts_with('#') || rest_args.starts_with('&') {
            push_str_mod(&mut tokens, "channel", rest_args);
        } else {
            push_str_mod(&mut tokens, "target", rest_args);
        }
    }
    if let Some(msg) = msg_opt {
        push_str_mod(&mut tokens, "msg", msg);
    }

    Some(sd(Protocol::Irc, tokens, trailing))
}
