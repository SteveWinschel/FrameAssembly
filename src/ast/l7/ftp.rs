//! File Transfer Protocol (FTP) (RFC 959 / RFC 2428 (EPSV/EPRT) / RFC 2228 (FTPS)) Layer 7 AST definitions.
//!
//! This module defines the abstract syntax tree (AST) configuration parameters for synthesizing
//! File Transfer Protocol (FTP) packets over TCP port 21 (Control channel) and TCP port 20 (Active data channel). On the wire, the protocol uses a CRLF-terminated NVT-ASCII control commands (`USER`, `PASS`, `SYST`, `FEAT`, `PWD`, `CWD`, `TYPE`, `PASV`, `EPSV`, `PORT`, `RETR`, `STOR`, `LIST`, `DELE`, `QUIT`) and 3-digit numeric status replies (`220` Service ready, `331` User name okay, `230` User logged in, `227` Entering Passive Mode, `150` File status okay, `226` Closing data connection, `530` Not logged in).
//! Every field in [`FtpSpec`] is optional so authors can emit zero-configuration default
//! frames or override specific protocol header fields and attributes.
//!
//! Canonical `.fasm` syntax:
//! `a -> b FTP [CMD <str>] [ARG <str>] [CODE <u16>] [REPLY <str>]`

/// RFC 959 File Transfer Protocol specification.
///
/// Syntax mapping: `FTP [CMD <str>] [ARG <str>] [CODE <u16>] [REPLY <str>]`
#[doc(alias = "FTP")]
#[doc(alias = "RFC 959")]
#[doc(alias = "RFC959")]
#[doc(alias = "RFC 2428")]
#[doc(alias = "RFC2428")]
#[doc(alias = "CMD")]
#[doc(alias = "ARG")]
#[doc(alias = "CODE")]
#[doc(alias = "REPLY")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FtpSpec<'a> {
    /// FTP command verb (`CMD <str>`).
    pub cmd: Option<&'a str>,
    /// FTP command argument (`ARG <str>`).
    pub arg: Option<&'a str>,
    /// Reply status code (`CODE <u16>`).
    pub code: Option<u16>,
    /// Reply explanation text (`REPLY <str>`).
    pub reply: Option<&'a str>,
}
