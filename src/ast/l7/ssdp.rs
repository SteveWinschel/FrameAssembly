//! Simple Service Discovery Protocol (SSDP / UPnP) (UPnP Device Architecture 1.1 / 2.0 (HTTPU over UDP Multicast)) Layer 7 AST definitions.
//!
//! This module defines the abstract syntax tree (AST) configuration parameters for synthesizing
//! Simple Service Discovery Protocol (SSDP / UPnP) packets over UDP port 1900 (IPv4 multicast 239.255.255.250 / IPv6 ff02::c or ff05::c). On the wire, the protocol uses a HTTP-over-UDP (HTTPU) multicast datagram beginning with `M-SEARCH * http/1.1\r\n` active discovery request or `notify * http/1.1\r\n` presence advertisement, carrying `host:`, `man:` (`"ssdp:discover"`), `mx:` delay seconds, `st:` Search Target, `nt:` Notification Type, `nts:` (`ssdp:alive`, `ssdp:byebye`, `ssdp:update`), `usn:` Unique Service Name, and `location:` XML device descriptor URL.
//! Every field in [`SsdpSpec`] is optional so authors can emit zero-configuration default
//! frames or override specific protocol header fields and attributes.
//!
//! Canonical `.fasm` syntax:
//! `a -> b ssdp [msearch | notify] [hosthdr <str>] [man <str>] [mx <u8>] [st <str>] [nt <str>] [nts <str>] [usn <str>] [location <str>]`

/// Simple Service Discovery Protocol specification.
///
/// Syntax mapping: `ssdp [msearch | notify] [hosthdr <str>] [man <str>] [mx <u8>] [st <str>] [nt <str>] [nts <str>] [usn <str>] [location <str>]`
#[doc(alias = "ssdp")]
#[doc(alias = "UPNP")]
#[doc(alias = "DLNA")]
#[doc(alias = "msearch")]
#[doc(alias = "notify")]
#[doc(alias = "hosthdr")]
#[doc(alias = "man")]
#[doc(alias = "mx")]
#[doc(alias = "st")]
#[doc(alias = "nt")]
#[doc(alias = "nts")]
#[doc(alias = "usn")]
#[doc(alias = "location")]
#[doc(alias = "1900")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SsdpSpec<'a> {
    /// M-SEARCH discovery flag.
    pub is_msearch: bool,
    /// NOTIFY advertisement flag.
    pub is_notify: bool,
    /// Host header string.
    pub host_hdr: Option<&'a str>,
    /// MAN header string.
    pub man: Option<&'a str>,
    /// Maximum wait time in seconds (MX).
    pub mx: Option<u8>,
    /// Search Target (ST) string.
    pub st: Option<&'a str>,
    /// Notification Type (NT) string.
    pub nt: Option<&'a str>,
    /// Notification Sub-Type (NTS) string.
    pub nts: Option<&'a str>,
    /// Unique Service Name (USN) string.
    pub usn: Option<&'a str>,
    /// Location URL string.
    pub location: Option<&'a str>,
}
