//! WHOIS protocol AST definitions.

/// RFC 3912 WHOIS Protocol specification.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct WhoisSpec<'a> {
    /// Query flag.
    pub is_query: bool,
    /// Response flag.
    pub is_response: bool,
    /// Domain query string.
    pub domain: Option<&'a str>,
    /// Registrar description string.
    pub registrar: Option<&'a str>,
}
