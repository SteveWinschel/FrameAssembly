//! SYSLOG protocol AST definitions.

/// RFC 5424 The Syslog Protocol specification.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SyslogSpec<'a> {
    /// Facility code (0..=23).
    pub facility: Option<u8>,
    /// Severity code (0..=7).
    pub severity: Option<u8>,
    /// Priority value override.
    pub pri: Option<u8>,
    /// Hostname string.
    pub hostname: Option<&'a str>,
    /// Application name string.
    pub app: Option<&'a str>,
    /// Process identifier string.
    pub procid: Option<&'a str>,
    /// Message identifier string.
    pub msgid: Option<&'a str>,
    /// Log message body.
    pub msg: Option<&'a str>,
}
