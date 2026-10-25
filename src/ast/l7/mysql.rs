//! MySQL Client/Server Wire Protocol v10 Abstract Syntax Tree (AST) definitions.
//!
//! This module defines [`MysqlSpec`], the zero-copy AST representation of a MySQL / MariaDB
//! client/server protocol packet over TCP port 3306. On the wire, every MySQL packet starts with a
//! 4-byte header consisting of a 24-bit little-endian payload length and a 1-byte sequence ID,
//! encapsulating Protocol v10 `HandshakeV10` greetings, `HandshakeResponse41` logins, `COM_QUERY`
//! (`0x03`) SQL statements, `OK_Packet` (`0x00`), `EOF_Packet` (`0xFE`), or `ERR_Packet` (`0xFF`).
//! Canonical FrameAssembly `.fasm` syntax models MySQL frames via
//! `MYSQL [GREETING | LOGIN | QUERY | OK | ERR | EOF] [SERVER_VERSION <str>] [USER <str>] [DB <str>] [SQL <str>] [ERRCODE <u16>]`.

/// MySQL / MariaDB Client/Server Wire Protocol v10 specification.
///
/// Syntax mapping: `MYSQL [GREETING | LOGIN | QUERY | OK | ERR | EOF] [SERVER_VERSION <str>] [USER <str>] [DB <str>] [SQL <str>] [ERRCODE <u16>]`
#[doc(alias = "MYSQL")]
#[doc(alias = "MySQL v10")]
#[doc(alias = "3306")]
#[doc(alias = "GREETING")]
#[doc(alias = "LOGIN")]
#[doc(alias = "QUERY")]
#[doc(alias = "SQL")]
#[doc(alias = "OK")]
#[doc(alias = "ERR")]
#[doc(alias = "EOF")]
#[doc(alias = "SERVER_VERSION")]
#[doc(alias = "USER")]
#[doc(alias = "DB")]
#[doc(alias = "ERRCODE")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MysqlSpec<'a> {
    /// Server `HandshakeV10` initial greeting packet flag (`GREETING`).
    pub is_greeting: bool,
    /// Client `HandshakeResponse41` login packet flag (`LOGIN`).
    pub is_login: bool,
    /// Client `COM_QUERY` (`0x03`) command flag (`QUERY`).
    pub is_query: bool,
    /// Server `OK_Packet` (`0x00`) response flag (`OK`).
    pub is_ok: bool,
    /// Server `ERR_Packet` (`0xFF`) response flag (`ERR`).
    pub is_err: bool,
    /// Server `EOF_Packet` (`0xFE`) response flag (`EOF`).
    pub is_eof: bool,
    /// Server version string in `HandshakeV10` (`SERVER_VERSION <str>`, default `"8.0.35"`).
    pub server_version: Option<&'a str>,
    /// Client username in `HandshakeResponse41` (`USER <str>`, default `"root"`).
    pub user: Option<&'a str>,
    /// Initial database schema name (`DB <str>`).
    pub db: Option<&'a str>,
    /// SQL statement text for `COM_QUERY` (`SQL <str>`).
    pub sql: Option<&'a str>,
    /// 16-bit MySQL error code in `ERR_Packet` (`ERRCODE <u16>`, default `1045`).
    pub errcode: Option<u16>,
}
