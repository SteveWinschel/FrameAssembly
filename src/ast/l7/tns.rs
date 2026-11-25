//! Oracle Transparent Network Substrate (TNS) Layer 7 Abstract Syntax Tree (AST) definitions.
//!
//! This module defines [`TnsSpec`], the zero-copy AST representation of an Oracle Transparent
//! Network Substrate (TNS) database session packet transmitted over TCP port 1521. On the wire,
//! every TNS frame starts with an 8-byte big-endian header (`length`, `packetChecksum = 0`,
//! `type`, `reserved = 0`, `headerChecksum = 0`), encapsulating `CONNECT` (`1`), `ACCEPT` (`2`),
//! `ACK` (`3`), `REFUSE` (`4`), `REDIRECT` (`5`), `DATA` (`6`), `NULL` (`7`), `ABORT` (`9`),
//! `RESEND` (`11`), or `MARKER` (`12`) payloads. Canonical `.frasm` syntax:
//! `tns [connect | accept | refuse | redirect | data | marker | msgtype <str>] [version <u16>] [service <str>] [sid <str>] [sql <str>] [flags <u16>] [errcode <u16>]`.

/// Oracle Transparent Network Substrate (TNS) protocol specification.
///
/// Syntax mapping: `tns [connect | accept | refuse | redirect | data | marker | msgtype <str>] [version <u16>] [service <str>] [sid <str>] [sql <str>] [flags <u16>] [errcode <u16>]`
#[doc(alias = "tns")]
#[doc(alias = "Oracle TNS")]
#[doc(alias = "1521")]
#[doc(alias = "connect")]
#[doc(alias = "accept")]
#[doc(alias = "refuse")]
#[doc(alias = "redirect")]
#[doc(alias = "data")]
#[doc(alias = "marker")]
#[doc(alias = "msgtype")]
#[doc(alias = "version")]
#[doc(alias = "service")]
#[doc(alias = "sid")]
#[doc(alias = "sql")]
#[doc(alias = "flags")]
#[doc(alias = "errcode")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TnsSpec<'a> {
    /// TNS packet type (`connect`, `accept`, `refuse`, `redirect`, `data`, `marker`, or `msgtype <str>`).
    pub msg_type: Option<&'a str>,
    /// 16-bit TNS protocol version in `CONNECT` and `ACCEPT` headers (`version <u16>`, default `314`).
    pub version: Option<u16>,
    /// Oracle `SERVICE_NAME` or redirect host parameter (`service <str>`, default `"ORCL"`).
    pub service: Option<&'a str>,
    /// Oracle System Identifier (`SID`) in `CONNECT` descriptors (`sid <str>`).
    pub sid: Option<&'a str>,
    /// SQL payload text encoded in `TNS DATA` frames (`sql <str>`).
    pub sql: Option<&'a str>,
    /// 16-bit `serviceOptions` (`CONNECT`/`ACCEPT`) or `dataFlags` (`DATA`) field (`flags <u16>`).
    pub flags: Option<u16>,
    /// Oracle error code embedded in `REFUSE` descriptors (`errcode <u16>`, default `12514`).
    pub errcode: Option<u16>,
}
