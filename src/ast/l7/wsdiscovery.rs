//! Web Services Dynamic Discovery (WS-Discovery OASIS 1.1 SOAP-over-UDP) Layer 7 AST definitions.
//!
//! This module defines the abstract syntax tree (AST) configuration parameters for synthesizing
//! OASIS WS-Discovery (`wsdiscovery`) SOAP 1.2 / WS-Addressing discovery datagrams over UDP port
//! 3702 (defaulting to IPv4 multicast `239.255.255.250` or IPv6 multicast `ff02::c` when sending
//! to unspecified or multicast targets). On the wire, the protocol carries a compact UTF-8 XML
//! SOAP envelope containing `Probe`, `ProbeMatches`, `Hello`, `Bye`, `Resolve`, or
//! `ResolveMatches` actions. Every field in [`WsdiscoverySpec`] is optional so authors can emit
//! zero-configuration default discovery frames or customize XML discovery metadata.
//!
//! Canonical `.frasm` syntax:
//! `a -> b wsdiscovery [probe | hello | msgtype <str>] [msgid <str>] [types <str>] [scopes <str>] [xaddrs <str>] [addr <str>]`

/// OASIS WS-Discovery 1.1 SOAP-over-UDP specification.
///
/// Syntax mapping: `wsdiscovery [probe | hello | msgtype <str>] [msgid <str>] [types <str>] [scopes <str>] [xaddrs <str>] [addr <str>]`
#[doc(alias = "wsdiscovery")]
#[doc(alias = "WSD")]
#[doc(alias = "SOAP")]
#[doc(alias = "OASIS")]
#[doc(alias = "probe")]
#[doc(alias = "hello")]
#[doc(alias = "msgtype")]
#[doc(alias = "msgid")]
#[doc(alias = "types")]
#[doc(alias = "scopes")]
#[doc(alias = "xaddrs")]
#[doc(alias = "addr")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct WsdiscoverySpec<'a> {
    /// WS-Discovery SOAP action kind (`probe`, `hello`, or `msgtype <str>`: `"probe"`, `"probematches"`, `"hello"`, `"bye"`, `"resolve"`, `"resolvematches"`).
    pub msg_type: Option<&'a str>,
    /// WS-Addressing `MessageID` string (`msgid <str>`).
    pub msgid: Option<&'a str>,
    /// WS-Discovery `Types` QName list (`types <str>`, default `"wsdp:Device"`).
    pub types: Option<&'a str>,
    /// Optional WS-Discovery `Scopes` URI list (`scopes <str>`).
    pub scopes: Option<&'a str>,
    /// WS-Discovery `XAddrs` transport URL list (`xaddrs <str>`).
    pub xaddrs: Option<&'a str>,
    /// WS-Addressing `EndpointReference/Address` URI (`addr <str>`).
    pub addr: Option<&'a str>,
}
