//! Simple Mail Transfer Protocol (SMTP, RFC 5321) wire payload builder.
//!
//! This module implements [`build_smtp_payload`], which serializes an [`SmtpSpec`]
//! AST specification into a standards-compliant RFC 5321 SMTP command or server reply over TCP
//! ports 25 (MTA relay), 465 (SMTPS), and 587 (MSA submission). When `code` or `reply` is
//! specified, it emits a 3-digit status line (`<code> <reply>\r\n`); when `body` is present, it
//! appends `<body_text>\r\n.\r\n` without prepending spurious commands; otherwise it formats
//! client commands (`EHLO`, `HELO`, `MAIL FROM:<...>`, `RCPT TO:<...>`, `DATA`, `QUIT`) terminated by CRLF (`\r\n`).

use crate::ast::*;
use crate::builders::WireContext;
use alloc::vec::Vec;

/// Formats an RFC 5321 `MAIL FROM` or `RCPT TO` command with mandatory colon and angle brackets.
fn format_smtp_envelope_cmd(verb: &str, param: Option<&str>) -> String {
    let addr = param.unwrap_or("").trim().trim_start_matches(':').trim();
    if addr.is_empty() {
        format!("{}:<>\r\n", verb)
    } else if addr.starts_with('<') && addr.ends_with('>') {
        format!("{}:{}\r\n", verb, addr)
    } else {
        format!("{}:<{}>\r\n", verb, addr)
    }
}

/// Builds an RFC 5321 SMTP email transaction message.
///
/// Syntax mapping: `smtp [ehlo [<str>]] [helo [<str>]] [mailfrom <str>] [rcptto <str>] [data] [quit] [cmd <str>] [param <str>] [code <u16>] [reply <str>] [body <str>]`
#[doc(alias = "SMTP")]
#[doc(alias = "RFC5321")]
#[doc(alias = "EHLO")]
#[doc(alias = "HELO")]
#[doc(alias = "MAIL_FROM")]
#[doc(alias = "RCPT_TO")]
#[doc(alias = "DATA")]
pub fn build_smtp_payload(
    _ctx: &WireContext,
    spec: &SmtpSpec,
    payload_bytes: &[u8],
) -> Vec<u8> {
    let formatted = if let Some(code) = spec.code {
        let reply = spec.reply.unwrap_or("OK");
        format!("{} {}\r\n", code, reply)
    } else if let Some(reply) = spec.reply {
        format!("250 {}\r\n", reply)
    } else if let Some(cmd) = spec.cmd {
        let cmd_clean = cmd.trim().trim_end_matches(':');
        if cmd_clean.eq_ignore_ascii_case("MAIL FROM") {
            format_smtp_envelope_cmd("MAIL FROM", spec.param)
        } else if cmd_clean.eq_ignore_ascii_case("RCPT TO") {
            format_smtp_envelope_cmd("RCPT TO", spec.param)
        } else if let Some(param) = spec.param {
            format!("{} {}\r\n", cmd_clean, param)
        } else {
            format!("{}\r\n", cmd_clean)
        }
    } else if let Some(param) = spec.param {
        format!("EHLO {}\r\n", param)
    } else if spec.body.is_some() || !payload_bytes.is_empty() {
        String::new()
    } else {
        "EHLO localhost\r\n".to_string()
    };

    let mut bytes = formatted.into_bytes();
    if let Some(body) = spec.body {
        bytes.extend_from_slice(body.as_bytes());
        bytes.extend_from_slice(b"\r\n.\r\n");
    } else if !payload_bytes.is_empty() {
        bytes.extend_from_slice(payload_bytes);
    }
    bytes
}
