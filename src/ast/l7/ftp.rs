//! File Transfer Protocol (FTP) (RFC 959 / RFC 2428 (EPSV/EPRT) / RFC 2228 (FTPS)) Layer 7 AST definitions.
//!
//! This module defines the abstract syntax tree (AST) configuration parameters for synthesizing
//! File Transfer Protocol (FTP) packets over TCP port 21 (Control channel) and TCP port 20 (Active data channel). On the wire, the protocol uses a CRLF-terminated NVT-ASCII control commands (`user`, `PASS`, `SYST`, `FEAT`, `PWD`, `CWD`, `type`, `PASV`, `EPSV`, `PORT`, `RETR`, `STOR`, `LIST`, `DELE`, `quit`) and 3-digit numeric status replies (`220` Service ready, `331` User name okay, `230` User logged in, `227` Entering Passive Mode, `150` File status okay, `226` Closing data connection, `530` Not logged in).
//! Every field in [`FtpSpec`] is optional so authors can emit zero-configuration default
//! frames or override specific protocol header fields and attributes.
//!
//! Canonical `.fasm` syntax:
//! `a -> b ftp [cmd <str>] [arg <str>] [code <u16>] [reply <str>]`

/// RFC 959 File Transfer Protocol specification.
///
/// Syntax mapping: `ftp [cmd <str>] [arg <str>] [code <u16>] [reply <str>]`
#[doc(alias = "ftp")]
#[doc(alias = "RFC 959")]
#[doc(alias = "RFC959")]
#[doc(alias = "RFC 2428")]
#[doc(alias = "RFC2428")]
#[doc(alias = "cmd")]
#[doc(alias = "arg")]
#[doc(alias = "code")]
#[doc(alias = "reply")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FtpSpec<'a> {
    /// FTP command verb (`cmd <str>`).
    pub cmd: Option<&'a str>,
    /// FTP command argument (`arg <str>`).
    pub arg: Option<&'a str>,
    /// Reply status code (`code <u16>`).
    pub code: Option<u16>,
    /// Reply explanation text (`reply <str>`).
    pub reply: Option<&'a str>,
}
