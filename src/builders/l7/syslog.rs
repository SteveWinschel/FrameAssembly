//! The Syslog Protocol (RFC 5424 / RFC 3164 / RFC 6587 (TCP Transport)) Layer 7 wire packet builder.
//!
//! This module synthesizes deterministic on-the-wire Syslog frames over UDP port 514 (default),
//! TCP port 514 (`transport tcp`), or TCP port 6514 with RFC 6587 Section 3.4.1 octet-counting
//! framing (`<MSG-LEN> <SYSLOG-MSG>`). The wire encoder constructs an ASCII/UTF-8 structured log
//! record beginning with `<PRI>VERSION`, space-delimited ISO-8601 `TIMESTAMP`, `HOSTNAME`,
//! `APP-NAME`, `PROCID`, `MSGID`, `STRUCTURED-DATA` (`-`), and free-form `MSG`. When optional
//! fields in [`SyslogSpec`] are omitted in `.frasm`, RFC defaults are populated automatically.
//!
//! Canonical `.frasm` syntax:
//! `a -> b syslog [facility <u8>] [severity <u8>] [pri <u8>] [hostname <str>] [app <str>] [procid <str>] [msg <str>] [transport tcp]`

use crate::ast::*;
use crate::builders::WireContext;
use alloc::vec::Vec;

/// Builds an RFC 5424 Syslog packet payload, adding RFC 6587 octet-counting on TCP port 6514.
/// Syntax mapping: `syslog [facility <u8>] [severity <u8>] [pri <u8>] [hostname <str>] [app <str>] [procid <str>] [msg <str>] [transport tcp]`
#[doc(alias = "SYSLOG")]
#[doc(alias = "RFC5424")]
#[doc(alias = "RFC3164")]
#[doc(alias = "RFC6587")]
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
        ((u16::from(facility) * 8) + u16::from(severity)).min(191) as u8
    };

    let hostname = spec
        .hostname
        .map(|s| s.to_string())
        .unwrap_or_else(|| ctx.src_ip.to_string());
    let app = spec.app.unwrap_or("app");
    let procid = spec.procid.unwrap_or("-");
    let msgid = spec.msgid.unwrap_or("-");
    let msg = spec.msg.unwrap_or("System notification");

    let formatted = format!(
        "<{}>1 2026-10-23T00:00:00Z {} {} {} {} - {}",
        pri, hostname, app, procid, msgid, msg
    );
    let mut bytes = formatted.into_bytes();
    if !payload_bytes.is_empty() {
        bytes.extend_from_slice(payload_bytes);
    }

    let is_tcp_6514 = ctx.transport == Some(TransportProto::Tcp)
        && (ctx.dst_port == 6514 || ctx.src_port == 6514);
    if is_tcp_6514 {
        let prefix = format!("{} ", bytes.len());
        let mut framed = Vec::with_capacity(prefix.len() + bytes.len());
        framed.extend_from_slice(prefix.as_bytes());
        framed.extend_from_slice(&bytes);
        return framed;
    }

    bytes
}
