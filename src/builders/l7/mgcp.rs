//! Media Gateway Control Protocol (MGCP, RFC 3435) Layer 7 wire packet builder.
//!
//! This module implements [`build_mgcp_payload`], which synthesizes deterministic RFC 3435
//! Media Gateway Control Protocol (MGCP) text commands and status responses over UDP ports 2427
//! and 2727. Command messages emit `<Verb> <TransactionID> <EndpointID> MGCP 1.0\r\n` with
//! default connection parameters (`C:`, `I:`, `L:`, `M:`, `RM:`), while response messages emit
//! `<Status> <TransactionID> <Reason>\r\n`, optionally followed by a blank CRLF line and SDP
//! session description body.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write as _;

use crate::ast::*;
use crate::builders::WireContext;

/// Returns the canonical RFC 3435 reason phrase for a numeric MGCP response status code.
fn default_mgcp_reason(status: u16) -> &'static str {
    match status {
        100 => "Transaction Executing",
        200 => "OK",
        250 => "Connection was deleted",
        400 => "Transient error",
        500 => "Endpoint unknown",
        510 => "Protocol error",
        _ => "OK",
    }
}

/// Builds an RFC 3435 MGCP command or response payload.
///
/// Syntax mapping: `mgcp [crcx | mdcx | dlcx | rqnt | ntfy | auep | aucx | rsip | method <str>] [txid <u32>] [endpoint <str>] [status <u16>] [reason <str>] [callid <str>] [connid <str>] [localopts <str>] [mode <str>] [body <str>]`
#[doc(alias = "MGCP")]
#[doc(alias = "RFC3435")]
pub fn build_mgcp_payload(
    _ctx: &WireContext,
    spec: &MgcpSpec,
    payload_bytes: &[u8],
) -> Vec<u8> {
    let txid = spec.txid.unwrap_or(1);
    let mut out = String::new();
    let body_slice = spec.body.map(str::as_bytes).unwrap_or(&[]);
    let has_body = !body_slice.is_empty() || !payload_bytes.is_empty();

    if let Some(status) = spec.status {
        let reason = spec.reason.unwrap_or_else(|| default_mgcp_reason(status));
        let _ = write!(out, "{status} {txid} {reason}\r\n");
        if let Some(cid) = spec.call_id {
            let _ = write!(out, "C: {cid}\r\n");
        }
        if let Some(iid) = spec.conn_id {
            let _ = write!(out, "I: {iid}\r\n");
        }
        if let Some(lopts) = spec.local_opts {
            let _ = write!(out, "L: {lopts}\r\n");
        }
        if let Some(mode) = spec.mode {
            let _ = write!(out, "M: {mode}\r\n");
        }
        if has_body {
            out.push_str("\r\n");
        }
    } else {
        let verb = spec.method.unwrap_or("CRCX").to_ascii_uppercase();
        let endpoint = spec.endpoint.unwrap_or("aaln/1@gw1.example.com");
        let _ = write!(out, "{verb} {txid} {endpoint} MGCP 1.0\r\n");

        if let Some(cid) = spec.call_id {
            let _ = write!(out, "C: {cid}\r\n");
        } else if matches!(verb.as_str(), "CRCX" | "MDCX" | "DLCX" | "AUCX") {
            out.push_str("C: 1\r\n");
        }
        if let Some(iid) = spec.conn_id {
            let _ = write!(out, "I: {iid}\r\n");
        }
        if let Some(lopts) = spec.local_opts {
            let _ = write!(out, "L: {lopts}\r\n");
        } else if verb == "CRCX" {
            out.push_str("L: p:20, a:PCMU\r\n");
        }
        if let Some(mode) = spec.mode {
            let _ = write!(out, "M: {mode}\r\n");
        } else if verb == "CRCX" {
            out.push_str("M: sendrecv\r\n");
        }
        if verb == "RSIP"
            && spec.call_id.is_none()
            && spec.conn_id.is_none()
            && spec.local_opts.is_none()
            && spec.mode.is_none()
        {
            out.push_str("RM: graceful\r\n");
        }
        out.push_str("\r\n");
    }

    let mut bytes = out.into_bytes();
    if !body_slice.is_empty() {
        bytes.extend_from_slice(body_slice);
    }
    if !payload_bytes.is_empty() {
        bytes.extend_from_slice(payload_bytes);
    }
    bytes
}
