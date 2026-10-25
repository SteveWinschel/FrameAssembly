//! WHOIS Domain and IP Registry Query Protocol (RFC 3912) Layer 7 wire packet builder.
//!
//! This module synthesizes deterministic on-the-wire WHOIS Domain and IP Registry Query Protocol frames over TCP port 43.
//! The wire encoder constructs a Cleartext TCP query-response transaction on port 43 where the client transmits a CRLF-terminated domain name, Autonomous System Number (ASN), or IPv4/IPv6 CIDR prefix query (`<domain>\r\n`) and the RIR/TLD registry server returns human-readable key-value lines (`Domain Name:`, `Registrar:`, `Updated Date:`) before closing the connection. When optional fields in [`WhoisSpec`]
//! are omitted in the `.fasm` source, RFC-compliant default values are automatically populated.
//!
//! Canonical `.fasm` syntax:
//! `a -> b WHOIS [QUERY | RESPONSE] [DOMAIN <str>] [REGISTRAR <str>]`

use crate::ast::*;
use crate::builders::WireContext;
use alloc::vec::Vec;

/// Builds an RFC 3912 WHOIS query or response string.
/// Syntax mapping: `WHOIS [QUERY | RESPONSE] [DOMAIN <str>] [REGISTRAR <str>]`
#[doc(alias = "WHOIS")]
#[doc(alias = "RFC3912")]
#[doc(alias = "REGISTRAR")]
pub fn build_whois_payload(
    _ctx: &WireContext,
    spec: &WhoisSpec,
    payload_bytes: &[u8],
) -> Vec<u8> {
    let domain = spec.domain.unwrap_or("example.com");
    let formatted = if (spec.is_response || spec.registrar.is_some()) && !spec.is_query {
        let registrar = spec.registrar.unwrap_or("IANA");
        format!("Domain Name: {}\r\nRegistrar: {}\r\n", domain, registrar)
    } else {
        format!("{}\r\n", domain)
    };
    let mut bytes = formatted.into_bytes();
    if !payload_bytes.is_empty() {
        bytes.extend_from_slice(payload_bytes);
    }
    bytes
}
