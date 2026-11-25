//! Microsoft SQL Server Tabular Data Stream (MS-TDS, TCP port `1433`) Layer 7 AST definitions.
//!
//! This module defines the [`MssqlSpec`] AST payload specification for MS-TDS v7.4 client/server
//! sessions over TCP port `1433`. It models `Pre-Login` (`0x12`), `LOGIN7` (`0x10`), `SQLBatch`
//! (`0x01`, default with mandatory `ALL_HEADERS` and UTF-16LE SQL), `Tabular Result` `DONE` (`0x04`
//! `ok`) and `ERROR` (`0xAA` `err`), and `Attention` (`0x06`) messages.

/// Microsoft SQL Server Tabular Data Stream (`mssql`) message specification.
///
/// Syntax mapping: `mssql [prelogin|login|query|ok|err|attention] [response] [pkttype <str|u8>] [user <str>] [db <str>] [sql <str>] [errcode <u32>] [spid <u16>] [pktid <u8>]`
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[doc(alias = "mssql")]
#[doc(alias = "tds")]
#[doc(alias = "sqlserver")]
#[doc(alias = "login7")]
pub struct MssqlSpec<'a> {
    /// Explicit MS-TDS packet type selector (`"batch"`, `"prelogin"`, `"login"`, `"reply"`, `"attention"`, or numeric byte).
    pub pkt_type: Option<&'a str>,
    /// Emits a TDS `Pre-Login` (`0x12`) capability negotiation packet.
    pub is_prelogin: bool,
    /// Emits a TDS 7.4 `LOGIN7` (`0x10`) authentication packet.
    pub is_login: bool,
    /// Emits a TDS `SQLBatch` (`0x01`) query packet (default when bare).
    pub is_query: bool,
    /// Emits a TDS `Tabular Result` (`0x04`) success `DONE` (`0xFD`) response packet.
    pub is_ok: bool,
    /// Emits a TDS `Tabular Result` (`0x04`) `ERROR` (`0xAA`) + `DONE` (`0xFD`) packet.
    pub is_err: bool,
    /// Database username for `LOGIN7` (`sa` by default).
    pub user: Option<&'a str>,
    /// Target initial database name for `LOGIN7` (`master` by default).
    pub db: Option<&'a str>,
    /// UTF-16LE SQL batch text (`"SELECT 1"` by default) or SQL `ERROR` message text.
    pub sql: Option<&'a str>,
    /// SQL Server error number emitted inside `ERROR` token `0xAA` (defaults to `18456`).
    pub errcode: Option<u32>,
    /// TDS header Server Process ID (`SPID`, defaults to `0`).
    pub spid: Option<u16>,
    /// TDS header Packet ID (`PacketID`, defaults to `1`).
    pub pkt_id: Option<u8>,
}
