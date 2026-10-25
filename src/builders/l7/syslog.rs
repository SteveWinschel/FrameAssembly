//! The Syslog Protocol (RFC 5424 / RFC 3164 / RFC 6587 (TCP Transport)) Layer 7 wire packet builder.
//!
//! This module synthesizes deterministic on-the-wire The Syslog Protocol frames over UDP port 514 (default) or TCP port 514 (via TRANSPORT TCP).
//! The wire encoder constructs a ASCII UTF-8 structured log record beginning with `<PRI>VERSION` header where `PRI = (Facility * 8) + Severity` (Facility 0..23, Severity 0..7), space-delimited ISO-8601 `TIMESTAMP`, `HOSTNAME`, `APP-NAME`, `PROCID`, `MSGID`, `STRUCTURED-DATA` (`-` or `[sd-id param="val"]`), and free-form UTF-8 `MSG` payload. When optional fields in [`SyslogSpec`]
//! are omitted in the `.fasm` source, RFC-compliant default values are automatically populated.
//!
//! Canonical `.fasm` syntax:
//! `a -> b SYSLOG [FACILITY <u8>] [SEVERITY <u8>] [PRI <u8>] [HOSTNAME <str>] [APP <str>] [PROCID <str>] [MSG <str>] [TRANSPORT TCP]`

use crate::ast::*;
use crate::builders::WireContext;
use alloc::vec::Vec;

/// Builds an RFC 5424 Syslog packet payload.
/// Syntax mapping: `SYSLOG [FACILITY <u8>] [SEVERITY <u8>] [PRI <u8>] [HOSTNAME <str>] [APP <str>] [PROCID <str>] [MSG <str>] [TRANSPORT TCP]`
#[doc(alias = "SYSLOG")]
#[doc(alias = "RFC5424")]
#[doc(alias = "RFC3164")]
#[doc(alias = "FACILITY")]
#[doc(alias = "SEVERITY")]
pub fn build_syslog_payload(
    ctx: &WireContext,
    spec: &SyslogSpec,
    payload_bytes: &[u8],
) -> Vec<u8> {
    let pri = if let Some(p) = spec.pri {
        p
    } else {
        let facility = spec.facility.unwrap_or(1); // default 1: user-level
        let severity = spec.severity.unwrap_or(6); // default 6: informational
        (facility * 8) + severity
    };

    let hostname = spec.hostname.map(|s| s.to_string()).unwrap_or_else(|| ctx.src_ip.to_string());
    let app = spec.app.unwrap_or("app");
    let procid = spec.procid.unwrap_or("-");
    let msgid = spec.msgid.unwrap_or("-");
    let msg = spec.msg.unwrap_or("System notification");

    let formatted = format!("<{}>1 2026-10-23T00:00:00Z {} {} {} {} - {}", pri, hostname, app, procid, msgid, msg);
    let mut bytes = formatted.into_bytes();
    if !payload_bytes.is_empty() {
        bytes.extend_from_slice(payload_bytes);
    }
    bytes
}
