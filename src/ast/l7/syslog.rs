//! The Syslog Protocol (RFC 5424 / RFC 3164 / RFC 6587 (TCP Transport)) Layer 7 AST definitions.
//!
//! This module defines the abstract syntax tree (AST) configuration parameters for synthesizing
//! The Syslog Protocol packets over UDP port 514 (default) or TCP port 514 (via TRANSPORT TCP). On the wire, the protocol uses a ASCII UTF-8 structured log record beginning with `<PRI>version` header where `PRI = (Facility * 8) + Severity` (Facility 0..23, Severity 0..7), space-delimited ISO-8601 `timestamp`, `hostname`, `app-NAME`, `procid`, `msgid`, `STRUCTURED-data` (`-` or `[sd-id param="val"]`), and free-form UTF-8 `msg` payload.
//! Every field in [`SyslogSpec`] is optional so authors can emit zero-configuration default
//! frames or override specific protocol header fields and attributes.
//!
//! Canonical `.fasm` syntax:
//! `a -> b syslog [facility <u8>] [severity <u8>] [pri <u8>] [hostname <str>] [app <str>] [procid <str>] [msgid <str>] [msg <str>] [transport tcp]`

/// RFC 5424 The Syslog Protocol specification.
///
/// Syntax mapping: `syslog [facility <u8>] [severity <u8>] [pri <u8>] [hostname <str>] [app <str>] [procid <str>] [msgid <str>] [msg <str>] [transport tcp]`
#[doc(alias = "syslog")]
#[doc(alias = "RFC 5424")]
#[doc(alias = "RFC5424")]
#[doc(alias = "RFC 3164")]
#[doc(alias = "RFC3164")]
#[doc(alias = "RFC 6587")]
#[doc(alias = "facility")]
#[doc(alias = "severity")]
#[doc(alias = "pri")]
#[doc(alias = "hostname")]
#[doc(alias = "app")]
#[doc(alias = "procid")]
#[doc(alias = "msgid")]
#[doc(alias = "msg")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SyslogSpec<'a> {
    /// Facility code (`facility <0..=23>`).
    pub facility: Option<u8>,
    /// Severity code (`severity <0..=7>`).
    pub severity: Option<u8>,
    /// Priority value override (`pri <u8>`).
    pub pri: Option<u8>,
    /// Hostname string (`hostname <str>`).
    pub hostname: Option<&'a str>,
    /// Application name string (`app <str>`).
    pub app: Option<&'a str>,
    /// Process identifier string (`procid <str>`).
    pub procid: Option<&'a str>,
    /// Message identifier string (`msgid <str>`).
    pub msgid: Option<&'a str>,
    /// Log message body (`msg <str>`).
    pub msg: Option<&'a str>,
}
