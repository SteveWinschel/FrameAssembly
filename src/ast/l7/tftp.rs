//! TFTP protocol AST definitions.

/// RFC 1350 Trivial File Transfer Protocol specification.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TftpSpec<'a> {
    /// Read Request flag.
    pub is_rrq: bool,
    /// Write Request flag.
    pub is_wrq: bool,
    /// Data flag.
    pub is_data: bool,
    /// Acknowledgment flag.
    pub is_ack: bool,
    /// Error flag.
    pub is_error: bool,
    /// Filename string.
    pub filename: Option<&'a str>,
    /// Transfer mode string.
    pub mode: Option<&'a str>,
    /// Block number.
    pub block: Option<u16>,
    /// Error code.
    pub errcode: Option<u16>,
    /// Error message string.
    pub errmsg: Option<&'a str>,
}
