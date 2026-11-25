//! Network Configuration Protocol (`netconf`, RFC 6241 / RFC 6242) Layer 7 wire packet builder.
//!
//! This module synthesizes deterministic on-the-wire RFC 6241 and RFC 6242 Network Configuration
//! Protocol (`NETCONF`) XML framing payloads over TCP port `830`. It builds UTF-8 XML envelopes for
//! `<hello>` capability exchanges, `<rpc>` requests (`get-config`, `get`, `edit-config`, `lock`,
//! `unlock`, `close-session`, or custom operations), `<rpc-reply>` responses, and `<notification>`
//! events, framed with either RFC 6242 Section 4.3 `]]>]]>` end-of-message delimiters or Section
//! 4.2 chunked `\n#<len>\n...\n##\n` framing.
//!
//! Canonical `.frasm` syntax:
//! `a -> b netconf [hello | rpc | rpcreply | reply | notification | msgtype <str>] [msgid <str>] [sessionid <u32>] [operation <str>] [capability <str>] [chunked] [body <str>]`

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use crate::ast::*;
use crate::builders::WireContext;

/// Canonical NETCONF base 1.0 capability URN advertised in `<hello>` frames.
const DEFAULT_NETCONF_CAP: &str = "urn:ietf:params:netconf:base:1.0";

/// Formats an inner `<rpc>` operation XML element from `operation`.
fn build_rpc_operation_xml(operation: &str) -> String {
    let norm = operation.to_ascii_lowercase().replace(['_', '-'], "");
    match norm.as_str() {
        "getconfig" => String::from("<get-config><source><running/></source></get-config>"),
        "get" => String::from("<get/>"),
        "editconfig" => String::from("<edit-config><target><running/></target></edit-config>"),
        "lock" => String::from("<lock><target><running/></target></lock>"),
        "unlock" => String::from("<unlock><target><running/></target></unlock>"),
        "closesession" => String::from("<close-session/>"),
        _ => format!("<{operation}/>"),
    }
}

/// Builds an RFC 6241 / RFC 6242 NETCONF XML packet payload over TCP port `830`.
///
/// Syntax mapping: `netconf [hello | rpc | rpcreply | reply | notification | msgtype <str>] [msgid <str>] [sessionid <u32>] [operation <str>] [capability <str>] [chunked] [body <str>]`
#[doc(alias = "NETCONF")]
#[doc(alias = "RFC6241")]
#[doc(alias = "RFC6242")]
pub fn build_netconf_payload(
    _ctx: &WireContext,
    spec: &NetconfSpec,
    payload_bytes: &[u8],
) -> Vec<u8> {
    let mtype = spec
        .msg_type
        .unwrap_or("hello")
        .to_ascii_uppercase()
        .replace(['_', '-'], "");
    let msg_id = spec.msg_id.unwrap_or("101");

    let xml = match mtype.as_str() {
        "RPC" => {
            let inner = if let Some(b) = spec.body {
                String::from(b)
            } else {
                build_rpc_operation_xml(spec.operation.unwrap_or("get-config"))
            };
            format!(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<rpc message-id=\"{msg_id}\" xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">{inner}</rpc>"
            )
        }
        "RPCREPLY" | "REPLY" => {
            let inner = spec.body.unwrap_or("<ok/>");
            format!(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<rpc-reply message-id=\"{msg_id}\" xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">{inner}</rpc-reply>"
            )
        }
        "NOTIFICATION" => {
            let inner = spec
                .body
                .unwrap_or("<eventTime>2026-10-23T00:00:00Z</eventTime>");
            format!(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<notification xmlns=\"urn:ietf:params:xml:ns:netconf:notification:1.0\">{inner}</notification>"
            )
        }
        _ => {
            let cap = spec.capability.unwrap_or(DEFAULT_NETCONF_CAP);
            let sid_xml = if let Some(sid) = spec.session_id {
                format!("<session-id>{sid}</session-id>")
            } else {
                String::new()
            };
            let extra = spec.body.unwrap_or("");
            format!(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<hello xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\"><capabilities><capability>{cap}</capability></capabilities>{sid_xml}{extra}</hello>"
            )
        }
    };

    let mut pkt = if spec.chunked {
        let header = format!("\n#{}\n", xml.len());
        let mut out = Vec::with_capacity(header.len() + xml.len() + 4 + payload_bytes.len());
        out.extend_from_slice(header.as_bytes());
        out.extend_from_slice(xml.as_bytes());
        out.extend_from_slice(b"\n##\n");
        out
    } else {
        let mut out = Vec::with_capacity(xml.len() + 6 + payload_bytes.len());
        out.extend_from_slice(xml.as_bytes());
        out.extend_from_slice(b"]]>]]>");
        out
    };

    if !payload_bytes.is_empty() {
        pkt.extend_from_slice(payload_bytes);
    }
    pkt
}
