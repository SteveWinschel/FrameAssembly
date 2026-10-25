//! PostgreSQL Frontend/Backend Wire Protocol v3.0 Abstract Syntax Tree (AST) definitions.
//!
//! This module defines [`PostgresSpec`], the zero-copy AST representation of a PostgreSQL
//! Frontend/Backend Protocol v3.0 (`0x00030000`) message over TCP port 5432. On the wire, the
//! initial `StartupMessage` begins with a 32-bit length and protocol version `196608` followed by
//! NUL-terminated parameter pairs (`user`, `database`), while all subsequent frontend and backend
//! messages start with a 1-byte type tag (`'Q'` Query, `'R'` AuthenticationOk, `'C'`
//! CommandComplete, `'Z'` ReadyForQuery, `'E'` ErrorResponse) and a 32-bit big-endian length.
//! Canonical `.fasm` syntax:
//! `POSTGRES [STARTUP | QUERY | AUTH_OK | COMMAND_COMPLETE | READY_FOR_QUERY | ERROR_RESPONSE] [USER <str>] [DB <str>] [SQL <str>]`.

/// PostgreSQL Frontend/Backend Protocol 3.0 specification.
///
/// Syntax mapping: `POSTGRES [STARTUP | QUERY | AUTH_OK | COMMAND_COMPLETE | READY_FOR_QUERY | ERROR_RESPONSE] [USER <str>] [DB <str>] [SQL <str>]`
#[doc(alias = "POSTGRES")]
#[doc(alias = "PostgreSQL")]
#[doc(alias = "FEBE")]
#[doc(alias = "5432")]
#[doc(alias = "STARTUP")]
#[doc(alias = "QUERY")]
#[doc(alias = "SQL")]
#[doc(alias = "READY_FOR_QUERY")]
#[doc(alias = "COMMAND_COMPLETE")]
#[doc(alias = "ERROR_RESPONSE")]
#[doc(alias = "AUTH_OK")]
#[doc(alias = "USER")]
#[doc(alias = "DB")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PostgresSpec<'a> {
    /// Frontend `StartupMessage` (version 3.0) flag (`STARTUP`).
    pub is_startup: bool,
    /// Frontend simple `Query` (`'Q'`) flag (`QUERY`).
    pub is_query: bool,
    /// Backend `ReadyForQuery` (`'Z'`) message flag (`READY_FOR_QUERY`).
    pub is_ready_for_query: bool,
    /// Backend `CommandComplete` (`'C'`) message flag (`COMMAND_COMPLETE`).
    pub is_command_complete: bool,
    /// Backend `ErrorResponse` (`'E'`) message flag (`ERROR_RESPONSE`).
    pub is_error_response: bool,
    /// Backend `AuthenticationOk` (`'R'`, code 0) message flag (`AUTH_OK`).
    pub is_auth_ok: bool,
    /// Database user parameter for `StartupMessage` (`USER <str>`, default `"postgres"`).
    pub user: Option<&'a str>,
    /// Database name parameter for `StartupMessage` (`DB <str>`, default `"postgres"`).
    pub db: Option<&'a str>,
    /// SQL query string for `'Q'` frontend messages (`SQL <str>`).
    pub sql: Option<&'a str>,
}
