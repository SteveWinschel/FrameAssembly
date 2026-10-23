//! SMTP protocol AST definitions.

/// RFC 5321 Simple Mail Transfer Protocol specification.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SmtpSpec<'a> {
    /// SMTP command verb.
    pub cmd: Option<&'a str>,
    /// Command parameter.
    pub param: Option<&'a str>,
    /// Reply status code.
    pub code: Option<u16>,
    /// Reply explanation text.
    pub reply: Option<&'a str>,
    /// Email body string.
    pub body: Option<&'a str>,
}
