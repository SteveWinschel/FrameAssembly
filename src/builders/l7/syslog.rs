//! SYSLOG protocol wire builder.

use crate::ast::*;
use crate::builders::WireContext;
use alloc::vec::Vec;

/// Builds an RFC 5424 Syslog packet payload.
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
