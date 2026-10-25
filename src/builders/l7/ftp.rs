//! File Transfer Protocol (FTP) (RFC 959 / RFC 2428 (EPSV/EPRT) / RFC 2228 (FTPS)) Layer 7 wire packet builder.
//!
//! This module synthesizes deterministic on-the-wire File Transfer Protocol (FTP) frames over TCP port 21 (Control channel) and TCP port 20 (Active data channel).
//! The wire encoder constructs a CRLF-terminated NVT-ASCII control commands (`USER`, `PASS`, `SYST`, `FEAT`, `PWD`, `CWD`, `TYPE`, `PASV`, `EPSV`, `PORT`, `RETR`, `STOR`, `LIST`, `DELE`, `QUIT`) and 3-digit numeric status replies (`220` Service ready, `331` User name okay, `230` User logged in, `227` Entering Passive Mode, `150` File status okay, `226` Closing data connection, `530` Not logged in). When optional fields in [`FtpSpec`]
//! are omitted in the `.fasm` source, RFC-compliant default values are automatically populated.
//!
//! Canonical `.fasm` syntax:
//! `a -> b FTP [CMD <str>] [ARG <str>] [CODE <u16>] [REPLY <str>]`

use crate::ast::*;
use crate::builders::WireContext;
use alloc::vec::Vec;

/// Builds an RFC 959 FTP command or reply string.
/// Syntax mapping: `FTP [CMD <str>] [ARG <str>] [CODE <u16>] [REPLY <str>]`
#[doc(alias = "FTP")]
#[doc(alias = "RFC959")]
#[doc(alias = "RFC2428")]
pub fn build_ftp_payload(
    _ctx: &WireContext,
    spec: &FtpSpec,
    payload_bytes: &[u8],
) -> Vec<u8> {
    let formatted = if spec.code.is_some() || spec.reply.is_some() {
        let code = spec.code.unwrap_or(220);
        let reply = spec.reply.unwrap_or("Service ready");
        format!("{} {}\r\n", code, reply)
    } else if spec.cmd.is_some() || spec.arg.is_some() {
        let cmd = spec.cmd.unwrap_or("USER");
        if let Some(arg) = spec.arg {
            format!("{} {}\r\n", cmd, arg)
        } else {
            format!("{}\r\n", cmd)
        }
    } else {
        "USER anonymous\r\n".to_string()
    };

    let mut bytes = formatted.into_bytes();
    if !payload_bytes.is_empty() {
        bytes.extend_from_slice(payload_bytes);
    }
    bytes
}
