//! PostgreSQL Frontend/Backend Wire Protocol v3.0 Abstract Syntax Tree (AST) definitions.
//!
//! This module defines [`PostgresSpec`], the zero-copy AST representation of a PostgreSQL
//! Frontend/Backend Protocol v3.0 (`0x00030000`) message over TCP port 5432. On the wire, the
//! initial `StartupMessage` begins with a 32-bit length and protocol version `196608` followed by
//! NUL-terminated parameter pairs (`user`, `database`), while all subsequent frontend and backend
//! messages start with a 1-byte type tag (`'Q'` Query, `'R'` AuthenticationOk, `'C'`
//! CommandComplete, `'Z'` ReadyForQuery, `'E'` ErrorResponse) and a 32-bit big-endian length.
//! Canonical `.fasm` syntax:
//! `postgres [startup | query | authok | commandcomplete | readyforquery | errorresponse] [user <str>] [db <str>] [sql <str>]`.

/// PostgreSQL Frontend/Backend Protocol 3.0 specification.
///
/// Syntax mapping: `postgres [startup | query | authok | commandcomplete | readyforquery | errorresponse] [user <str>] [db <str>] [sql <str>]`
#[doc(alias = "postgres")]
#[doc(alias = "PostgreSQL")]
#[doc(alias = "FEBE")]
#[doc(alias = "5432")]
#[doc(alias = "startup")]
#[doc(alias = "query")]
#[doc(alias = "sql")]
#[doc(alias = "readyforquery")]
#[doc(alias = "commandcomplete")]
#[doc(alias = "errorresponse")]
#[doc(alias = "authok")]
#[doc(alias = "user")]
#[doc(alias = "db")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PostgresSpec<'a> {
    /// Frontend `StartupMessage` (version 3.0) flag (`startup`).
    pub is_startup: bool,
    /// Frontend simple `Query` (`'Q'`) flag (`query`).
    pub is_query: bool,
    /// Backend `ReadyForQuery` (`'Z'`) message flag (`readyforquery`).
    pub is_ready_for_query: bool,
    /// Backend `CommandComplete` (`'C'`) message flag (`commandcomplete`).
    pub is_command_complete: bool,
    /// Backend `ErrorResponse` (`'E'`) message flag (`errorresponse`).
    pub is_error_response: bool,
    /// Backend `AuthenticationOk` (`'R'`, code 0) message flag (`authok`).
    pub is_auth_ok: bool,
    /// Database user parameter for `StartupMessage` (`user <str>`, default `"postgres"`).
    pub user: Option<&'a str>,
    /// Database name parameter for `StartupMessage` (`db <str>`, default `"postgres"`).
    pub db: Option<&'a str>,
    /// SQL query string for `'Q'` frontend messages (`sql <str>`).
    pub sql: Option<&'a str>,
}
