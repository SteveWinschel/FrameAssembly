//! WHOIS Domain and IP Registry Query Protocol (RFC 3912) Layer 7 AST definitions.
//!
//! This module defines the abstract syntax tree (AST) configuration parameters for synthesizing
//! WHOIS Domain and IP Registry Query Protocol packets over TCP port 43. On the wire, the protocol uses a Cleartext TCP query-response transaction on port 43 where the client transmits a CRLF-terminated domain name, Autonomous System Number (ASN), or IPv4/IPv6 CIDR prefix query (`<domain>\r\n`) and the RIR/TLD registry server returns human-readable key-value lines (`Domain Name:`, `Registrar:`, `Updated Date:`) before closing the connection.
//! Every field in [`WhoisSpec`] is optional so authors can emit zero-configuration default
//! frames or override specific protocol header fields and attributes.
//!
//! Canonical `.fasm` syntax:
//! `a -> b whois [query | response] [domain <str>] [registrar <str>]`

/// RFC 3912 WHOIS Protocol specification.
///
/// Syntax mapping: `whois [query | response] [domain <str>] [registrar <str>]`
#[doc(alias = "whois")]
#[doc(alias = "RFC 3912")]
#[doc(alias = "RFC3912")]
#[doc(alias = "query")]
#[doc(alias = "response")]
#[doc(alias = "domain")]
#[doc(alias = "registrar")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct WhoisSpec<'a> {
    /// Query flag.
    pub is_query: bool,
    /// Response flag.
    pub is_response: bool,
    /// Domain query string.
    pub domain: Option<&'a str>,
    /// Registrar description string.
    pub registrar: Option<&'a str>,
}
