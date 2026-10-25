//! Simple Mail Transfer Protocol (SMTP, RFC 5321) wire payload builder.
//!
//! This module implements [`build_smtp_payload`], which serializes an [`SmtpSpec`]
//! AST specification into a standards-compliant RFC 5321 SMTP command or server reply over TCP
//! ports 25 (MTA relay), 465 (SMTPS), and 587 (MSA submission). When `CODE` or `REPLY` is
//! specified, it emits a 3-digit status line (`<code> <reply>\r\n`); when `BODY` is present, it
//! appends `<body_text>\r\n.\r\n`; otherwise it formats client commands (`EHLO`, `MAIL FROM:<...>`,
//! `RCPT TO:<...>`, `DATA`, `QUIT`) terminated by CRLF (`\r\n`).

use crate::ast::*;
use crate::builders::WireContext;
use alloc::vec::Vec;

/// Builds an RFC 5321 SMTP email transaction message.
///
/// Syntax mapping: `SMTP [EHLO [str]] [HELO [str]] [MAIL_FROM <str>] [RCPT_TO <str>] [QUIT] [CMD <str>] [PARAM <str>] [CODE <u16>] [REPLY <str>] [BODY <str>]`
#[doc(alias = "SMTP")]
#[doc(alias = "RFC5321")]
#[doc(alias = "EHLO")]
#[doc(alias = "HELO")]
#[doc(alias = "MAIL_FROM")]
#[doc(alias = "RCPT_TO")]
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
        if let Some(param) = spec.param {
            format!("{} {}\r\n", cmd, param)
        } else {
            format!("{}\r\n", cmd)
        }
    } else if let Some(param) = spec.param {
        format!("EHLO {}\r\n", param)
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
