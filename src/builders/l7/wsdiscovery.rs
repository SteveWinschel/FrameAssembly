//! Web Services Dynamic Discovery (WS-Discovery OASIS 1.1 SOAP-over-UDP) Layer 7 wire packet builder.
//!
//! This module synthesizes deterministic OASIS WS-Discovery (`wsdiscovery`) SOAP 1.2 /
//! WS-Addressing discovery datagrams over UDP port 3702. When optional fields in
//! [`WsdiscoverySpec`] are omitted, bare `wsdiscovery` statements emit a valid `Probe` SOAP
//! envelope targeting WS-Discovery multicast `urn:docs-oasis-open-org:ws-dd:ns:discovery:2009:01`.
//! Explicit `msgtype` or shorthand actions synthesize `ProbeMatches`, `Hello`, `Bye`, `Resolve`,
//! and `ResolveMatches` XML envelopes with escaped text fields.
//!
//! Canonical `.frasm` syntax:
//! `a -> b wsdiscovery [probe | hello | msgtype <str>] [msgid <str>] [types <str>] [scopes <str>] [xaddrs <str>] [addr <str>]`

use crate::ast::*;
use crate::builders::WireContext;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

/// Default WS-Addressing `MessageID` URI emitted when `msgid` is omitted.
const DEFAULT_WSD_MSGID: &str = "urn:uuid:00000000-0000-0000-0000-000000000001";

/// Default WS-Addressing `EndpointReference/Address` URI emitted when `addr` is omitted.
const DEFAULT_WSD_ADDR: &str = "urn:uuid:00000000-0000-0000-0000-000000000002";

/// Default WS-Discovery device `Types` QName emitted when `types` is omitted.
const DEFAULT_WSD_TYPES: &str = "wsdp:Device";

/// Default WS-Discovery `XAddrs` URL emitted when `xaddrs` is omitted.
const DEFAULT_WSD_XADDRS: &str = "http://127.0.0.1:5357/ws";

/// Escapes special XML text characters (`&`, `<`, `>`).
fn escape_xml_text(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            other => out.push(other),
        }
    }
    out
}

/// Normalizes a WS-Discovery UUID/URI string, adding `urn:uuid:` when no URI scheme is present.
fn format_wsd_uri(val: &str) -> String {
    if val.contains(':') {
        escape_xml_text(val)
    } else {
        format!("urn:uuid:{}", escape_xml_text(val))
    }
}

/// Builds an OASIS WS-Discovery 1.1 SOAP-over-UDP XML payload.
///
/// Syntax mapping: `wsdiscovery [probe | hello | msgtype <str>] [msgid <str>] [types <str>] [scopes <str>] [xaddrs <str>] [addr <str>]`
#[doc(alias = "WSDISCOVERY")]
#[doc(alias = "WSD")]
#[doc(alias = "SOAP")]
#[doc(alias = "OASIS")]
pub fn build_wsdiscovery_payload(
    _ctx: &WireContext,
    spec: &WsdiscoverySpec,
    payload_bytes: &[u8],
) -> Vec<u8> {
    let raw_kind = spec.msg_type.unwrap_or("probe");
    let kind_norm = raw_kind.trim().to_ascii_uppercase().replace(['_', '-'], "");
    let action_name = match kind_norm.as_str() {
        "PROBEMATCHES" | "PROBEMATCH" => "ProbeMatches",
        "HELLO" => "Hello",
        "BYE" => "Bye",
        "RESOLVE" => "Resolve",
        "RESOLVEMATCHES" | "RESOLVEMATCH" => "ResolveMatches",
        _ => "Probe",
    };

    let msgid = spec
        .msgid
        .map(format_wsd_uri)
        .unwrap_or_else(|| String::from(DEFAULT_WSD_MSGID));
    let addr = spec
        .addr
        .map(format_wsd_uri)
        .unwrap_or_else(|| String::from(DEFAULT_WSD_ADDR));
    let types = escape_xml_text(spec.types.unwrap_or(DEFAULT_WSD_TYPES));
    let xaddrs = escape_xml_text(spec.xaddrs.unwrap_or(DEFAULT_WSD_XADDRS));

    let mut xml = format!(
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>\
<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\" \
xmlns:a=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\" \
xmlns:d=\"http://docs.oasis-open.org/ws-dd/ns/discovery/2009/01\" \
xmlns:wsdp=\"http://schemas.xmlsoap.org/ws/2006/02/devprof\">\
<s:Header>\
<a:Action>http://docs.oasis-open.org/ws-dd/ns/discovery/2009/01/{action_name}</a:Action>\
<a:MessageID>{msgid}</a:MessageID>\
<a:To>urn:docs-oasis-open-org:ws-dd:ns:discovery:2009:01</a:To>\
</s:Header><s:Body>"
    );

    match action_name {
        "ProbeMatches" => {
            xml.push_str(&format!(
                "<d:ProbeMatches><d:ProbeMatch><a:EndpointReference><a:Address>{addr}</a:Address></a:EndpointReference><d:Types>{types}</d:Types>"
            ));
            if let Some(sc) = spec.scopes {
                xml.push_str(&format!("<d:Scopes>{}</d:Scopes>", escape_xml_text(sc)));
            }
            xml.push_str(&format!(
                "<d:XAddrs>{xaddrs}</d:XAddrs><d:MetadataVersion>1</d:MetadataVersion></d:ProbeMatch></d:ProbeMatches>"
            ));
        }
        "Hello" => {
            xml.push_str(&format!(
                "<d:Hello><a:EndpointReference><a:Address>{addr}</a:Address></a:EndpointReference><d:Types>{types}</d:Types>"
            ));
            if let Some(sc) = spec.scopes {
                xml.push_str(&format!("<d:Scopes>{}</d:Scopes>", escape_xml_text(sc)));
            }
            xml.push_str(&format!(
                "<d:XAddrs>{xaddrs}</d:XAddrs><d:MetadataVersion>1</d:MetadataVersion></d:Hello>"
            ));
        }
        "Bye" => {
            xml.push_str(&format!(
                "<d:Bye><a:EndpointReference><a:Address>{addr}</a:Address></a:EndpointReference></d:Bye>"
            ));
        }
        "Resolve" => {
            xml.push_str(&format!(
                "<d:Resolve><a:EndpointReference><a:Address>{addr}</a:Address></a:EndpointReference></d:Resolve>"
            ));
        }
        "ResolveMatches" => {
            xml.push_str(&format!(
                "<d:ResolveMatches><d:ResolveMatch><a:EndpointReference><a:Address>{addr}</a:Address></a:EndpointReference>"
            ));
            if let Some(sc) = spec.scopes {
                xml.push_str(&format!("<d:Scopes>{}</d:Scopes>", escape_xml_text(sc)));
            }
            xml.push_str(&format!(
                "<d:XAddrs>{xaddrs}</d:XAddrs><d:MetadataVersion>1</d:MetadataVersion></d:ResolveMatch></d:ResolveMatches>"
            ));
        }
        _ => {
            xml.push_str(&format!("<d:Probe><d:Types>{types}</d:Types>"));
            if let Some(sc) = spec.scopes {
                xml.push_str(&format!("<d:Scopes>{}</d:Scopes>", escape_xml_text(sc)));
            }
            xml.push_str("</d:Probe>");
        }
    }

    xml.push_str("</s:Body></s:Envelope>");
    let mut bytes = xml.into_bytes();
    if !payload_bytes.is_empty() {
        bytes.extend_from_slice(payload_bytes);
    }
    bytes
}
