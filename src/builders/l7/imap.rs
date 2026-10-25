//! Internet Message Access Protocol v4rev1/v4rev2 (IMAP, RFC 3501 / RFC 9051) wire payload builder.
//!
//! This module implements [`build_imap_payload`], which serializes an [`ImapSpec`]
//! AST node into an RFC 3501 / RFC 9051 IMAP wire line over TCP port 143 (or 993 for IMAPS).
//! Client commands are formatted with a leading alphanumeric tag (`<tag> <cmd> [arg]\r\n`,
//! defaulting to `A001 CAPABILITY\r\n`), whereas server completion and untagged responses are
//! formatted as `<tag_or_star> <status> <response_text>\r\n` and optionally followed by raw literal
//! or MIME body bytes.

use crate::ast::*;
use crate::builders::WireContext;
use alloc::vec::Vec;

/// Builds an RFC 9051 IMAP mail message.
///
/// Syntax mapping: `IMAP [TAG <str>] [CMD <str>] [ARG <str>] [STATUS <str>] [RESPONSE <str>]`
#[doc(alias = "IMAP")]
#[doc(alias = "RFC3501")]
#[doc(alias = "RFC9051")]
pub fn build_imap_payload(
    _ctx: &WireContext,
    spec: &ImapSpec,
    payload_bytes: &[u8],
) -> Vec<u8> {
    let tag = spec.tag.unwrap_or("A01");
    let formatted = if let Some(status) = spec.status {
        let resp = spec.response.unwrap_or("Completed");
        format!("{} {} {}\r\n", tag, status, resp)
    } else if spec.cmd.is_none()
        && let Some(resp) = spec.response
    {
        let status_tag = spec.tag.unwrap_or("*");
        format!("{} OK {}\r\n", status_tag, resp)
    } else {
        let cmd = spec.cmd.unwrap_or("NOOP");
        if let Some(arg) = spec.arg {
            format!("{} {} {}\r\n", tag, cmd, arg)
        } else {
            format!("{} {}\r\n", tag, cmd)
        }
    };

    let mut bytes = formatted.into_bytes();
    if !payload_bytes.is_empty() {
        bytes.extend_from_slice(payload_bytes);
    }
    bytes
}
