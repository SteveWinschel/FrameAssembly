//! POP3 protocol AST definitions.

/// RFC 1939 Post Office Protocol version 3 specification.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Pop3Spec<'a> {
    /// Command verb.
    pub cmd: Option<&'a str>,
    /// Command argument.
    pub arg: Option<&'a str>,
    /// Positive response (+OK) flag.
    pub is_ok: bool,
    /// Negative response (-ERR) flag.
    pub is_err: bool,
    /// Response explanation text.
    pub response: Option<&'a str>,
}
