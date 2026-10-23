//! TACACS protocol AST definitions.

/// RFC 8907 TACACS+ authentication & authorization specification.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TacacsSpec<'a> {
    /// TACACS+ type (AUTHEN, AUTHOR, ACCT).
    pub tacacs_type: Option<&'a str>,
    /// Sequence number.
    pub seq: Option<u8>,
    /// Flags byte.
    pub flags: Option<u8>,
    /// Session identifier.
    pub session_id: Option<u32>,
    /// User name string.
    pub user: Option<&'a str>,
    /// Optional data payload.
    pub data: Option<&'a str>,
}
