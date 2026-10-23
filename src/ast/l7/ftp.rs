//! FTP protocol AST definitions.

/// RFC 959 File Transfer Protocol specification.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FtpSpec<'a> {
    /// FTP command verb.
    pub cmd: Option<&'a str>,
    /// FTP command argument.
    pub arg: Option<&'a str>,
    /// Reply status code.
    pub code: Option<u16>,
    /// Reply explanation text.
    pub reply: Option<&'a str>,
}
