//! MySQL Client/Server Wire Protocol v10 Abstract Syntax Tree (AST) definitions.
//!
//! This module defines [`MysqlSpec`], the zero-copy AST representation of a MySQL / MariaDB
//! client/server protocol packet over TCP port 3306. On the wire, every MySQL packet starts with a
//! 4-byte header consisting of a 24-bit little-endian payload length and a 1-byte sequence ID,
//! encapsulating Protocol v10 `HandshakeV10` greetings, `HandshakeResponse41` logins, `COM_QUERY`
//! (`0x03`) SQL statements, `OK_Packet` (`0x00`), `EOF_Packet` (`0xFE`), or `ERR_Packet` (`0xFF`).
//! Canonical FrameAssembly `.fasm` syntax models MySQL frames via
//! `mysql [greeting | login | query | ok | err | eof] [serverversion <str>] [user <str>] [db <str>] [sql <str>] [errcode <u16>]`.

/// MySQL / MariaDB Client/Server Wire Protocol v10 specification.
///
/// Syntax mapping: `mysql [greeting | login | query | ok | err | eof] [serverversion <str>] [user <str>] [db <str>] [sql <str>] [errcode <u16>]`
#[doc(alias = "mysql")]
#[doc(alias = "MySQL v10")]
#[doc(alias = "3306")]
#[doc(alias = "greeting")]
#[doc(alias = "login")]
#[doc(alias = "query")]
#[doc(alias = "sql")]
#[doc(alias = "ok")]
#[doc(alias = "err")]
#[doc(alias = "eof")]
#[doc(alias = "serverversion")]
#[doc(alias = "user")]
#[doc(alias = "db")]
#[doc(alias = "errcode")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MysqlSpec<'a> {
    /// Server `HandshakeV10` initial greeting packet flag (`greeting`).
    pub is_greeting: bool,
    /// Client `HandshakeResponse41` login packet flag (`login`).
    pub is_login: bool,
    /// Client `COM_QUERY` (`0x03`) command flag (`query`).
    pub is_query: bool,
    /// Server `OK_Packet` (`0x00`) response flag (`ok`).
    pub is_ok: bool,
    /// Server `ERR_Packet` (`0xFF`) response flag (`err`).
    pub is_err: bool,
    /// Server `EOF_Packet` (`0xFE`) response flag (`eof`).
    pub is_eof: bool,
    /// Server version string in `HandshakeV10` (`serverversion <str>`, default `"8.0.35"`).
    pub server_version: Option<&'a str>,
    /// Client username in `HandshakeResponse41` (`user <str>`, default `"root"`).
    pub user: Option<&'a str>,
    /// Initial database schema name (`db <str>`).
    pub db: Option<&'a str>,
    /// SQL statement text for `COM_QUERY` (`sql <str>`).
    pub sql: Option<&'a str>,
    /// 16-bit MySQL error code in `ERR_Packet` (`errcode <u16>`, default `1045`).
    pub errcode: Option<u16>,
}
