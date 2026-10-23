//! MYSQL protocol AST definitions.

/// MySQL Client/Server Protocol specification.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MysqlSpec<'a> {
    /// Greeting handshake flag.
    pub is_greeting: bool,
    /// Login response flag.
    pub is_login: bool,
    /// Query command flag.
    pub is_query: bool,
    /// OK packet flag.
    pub is_ok: bool,
    /// Error packet flag.
    pub is_err: bool,
    /// EOF packet flag.
    pub is_eof: bool,
    /// Server version string.
    pub server_version: Option<&'a str>,
    /// User name string.
    pub user: Option<&'a str>,
    /// Database name string.
    pub db: Option<&'a str>,
    /// SQL query string.
    pub sql: Option<&'a str>,
    /// Error code.
    pub errcode: Option<u16>,
}
