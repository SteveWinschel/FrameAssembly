//! The Syslog Protocol (RFC 5424 / RFC 3164 / RFC 6587 (TCP Transport)) Layer 7 AST definitions.
//!
//! This module defines the abstract syntax tree (AST) configuration parameters for synthesizing
//! The Syslog Protocol packets over UDP port 514 (default) or TCP port 514 (via TRANSPORT TCP). On the wire, the protocol uses a ASCII UTF-8 structured log record beginning with `<PRI>VERSION` header where `PRI = (Facility * 8) + Severity` (Facility 0..23, Severity 0..7), space-delimited ISO-8601 `TIMESTAMP`, `HOSTNAME`, `APP-NAME`, `PROCID`, `MSGID`, `STRUCTURED-DATA` (`-` or `[sd-id param="val"]`), and free-form UTF-8 `MSG` payload.
//! Every field in [`SyslogSpec`] is optional so authors can emit zero-configuration default
//! frames or override specific protocol header fields and attributes.
//!
//! Canonical `.fasm` syntax:
//! `a -> b SYSLOG [FACILITY <u8>] [SEVERITY <u8>] [PRI <u8>] [HOSTNAME <str>] [APP <str>] [PROCID <str>] [MSGID <str>] [MSG <str>] [TRANSPORT TCP]`

/// RFC 5424 The Syslog Protocol specification.
///
/// Syntax mapping: `SYSLOG [FACILITY <u8>] [SEVERITY <u8>] [PRI <u8>] [HOSTNAME <str>] [APP <str>] [PROCID <str>] [MSGID <str>] [MSG <str>] [TRANSPORT TCP]`
#[doc(alias = "SYSLOG")]
#[doc(alias = "RFC 5424")]
#[doc(alias = "RFC5424")]
#[doc(alias = "RFC 3164")]
#[doc(alias = "RFC3164")]
#[doc(alias = "RFC 6587")]
#[doc(alias = "FACILITY")]
#[doc(alias = "SEVERITY")]
#[doc(alias = "PRI")]
#[doc(alias = "HOSTNAME")]
#[doc(alias = "APP")]
#[doc(alias = "PROCID")]
#[doc(alias = "MSGID")]
#[doc(alias = "MSG")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SyslogSpec<'a> {
    /// Facility code (`FACILITY <0..=23>`).
    pub facility: Option<u8>,
    /// Severity code (`SEVERITY <0..=7>`).
    pub severity: Option<u8>,
    /// Priority value override (`PRI <u8>`).
    pub pri: Option<u8>,
    /// Hostname string (`HOSTNAME <str>`).
    pub hostname: Option<&'a str>,
    /// Application name string (`APP <str>`).
    pub app: Option<&'a str>,
    /// Process identifier string (`PROCID <str>`).
    pub procid: Option<&'a str>,
    /// Message identifier string (`MSGID <str>`).
    pub msgid: Option<&'a str>,
    /// Log message body (`MSG <str>`).
    pub msg: Option<&'a str>,
}
