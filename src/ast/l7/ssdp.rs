//! Simple Service Discovery Protocol (SSDP / UPnP) (UPnP Device Architecture 1.1 / 2.0 (HTTPU over UDP Multicast)) Layer 7 AST definitions.
//!
//! This module defines the abstract syntax tree (AST) configuration parameters for synthesizing
//! Simple Service Discovery Protocol (SSDP / UPnP) packets over UDP port 1900 (IPv4 multicast 239.255.255.250 / IPv6 ff02::c or ff05::c). On the wire, the protocol uses a HTTP-over-UDP (HTTPU) multicast datagram beginning with `M-SEARCH * HTTP/1.1\r\n` active discovery request or `NOTIFY * HTTP/1.1\r\n` presence advertisement, carrying `HOST:`, `MAN:` (`"ssdp:discover"`), `MX:` delay seconds, `ST:` Search Target, `NT:` Notification Type, `NTS:` (`ssdp:alive`, `ssdp:byebye`, `ssdp:update`), `USN:` Unique Service Name, and `LOCATION:` XML device descriptor URL.
//! Every field in [`SsdpSpec`] is optional so authors can emit zero-configuration default
//! frames or override specific protocol header fields and attributes.
//!
//! Canonical `.fasm` syntax:
//! `a -> b SSDP [MSEARCH | NOTIFY] [HOST_HDR <str>] [MAN <str>] [MX <u8>] [ST <str>] [NT <str>] [NTS <str>] [USN <str>] [LOCATION <str>]`

/// Simple Service Discovery Protocol specification.
///
/// Syntax mapping: `SSDP [MSEARCH | NOTIFY] [HOST_HDR <str>] [MAN <str>] [MX <u8>] [ST <str>] [NT <str>] [NTS <str>] [USN <str>] [LOCATION <str>]`
#[doc(alias = "SSDP")]
#[doc(alias = "UPNP")]
#[doc(alias = "DLNA")]
#[doc(alias = "MSEARCH")]
#[doc(alias = "NOTIFY")]
#[doc(alias = "HOST_HDR")]
#[doc(alias = "MAN")]
#[doc(alias = "MX")]
#[doc(alias = "ST")]
#[doc(alias = "NT")]
#[doc(alias = "NTS")]
#[doc(alias = "USN")]
#[doc(alias = "LOCATION")]
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
