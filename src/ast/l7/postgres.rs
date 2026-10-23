//! POSTGRES protocol AST definitions.

/// PostgreSQL Frontend/Backend Protocol 3.0 specification.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PostgresSpec<'a> {
    /// Startup message flag.
    pub is_startup: bool,
    /// Simple query flag.
    pub is_query: bool,
    /// ReadyForQuery flag.
    pub is_ready_for_query: bool,
    /// CommandComplete flag.
    pub is_command_complete: bool,
    /// ErrorResponse flag.
    pub is_error_response: bool,
    /// AuthenticationOk flag.
    pub is_auth_ok: bool,
    /// User name string.
    pub user: Option<&'a str>,
    /// Database name string.
    pub db: Option<&'a str>,
    /// SQL query string.
    pub sql: Option<&'a str>,
}
