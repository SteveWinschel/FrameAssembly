//! TELNET protocol AST definitions.

/// RFC 854 Telnet Protocol specification.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TelnetSpec<'a> {
    /// IAC WILL command option.
    pub will: Option<u8>,
    /// IAC WONT command option.
    pub wont: Option<u8>,
    /// IAC DO command option.
    pub do_opt: Option<u8>,
    /// IAC DONT command option.
    pub dont: Option<u8>,
    /// Generic option byte.
    pub option: Option<u8>,
    /// Text data payload.
    pub data: Option<&'a str>,
}
