//! IMAP protocol AST definitions.

/// RFC 9051 Internet Message Access Protocol specification.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ImapSpec<'a> {
    /// Command tag string.
    pub tag: Option<&'a str>,
    /// IMAP command verb.
    pub cmd: Option<&'a str>,
    /// Command argument.
    pub arg: Option<&'a str>,
    /// Response status string.
    pub status: Option<&'a str>,
    /// Response explanation text.
    pub response: Option<&'a str>,
}
