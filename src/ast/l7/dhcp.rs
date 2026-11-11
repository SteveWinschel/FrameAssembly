//! Dynamic Host Configuration Protocol (DHCPv4 / DHCPv6) (RFC 2131 / RFC 2132 / RFC 8415) Layer 7 AST definitions.
//!
//! This module defines the abstract syntax tree (AST) configuration parameters for synthesizing
//! Dynamic Host Configuration Protocol (DHCPv4 / DHCPv6) packets over UDP ports 67/68 (DHCPv4) and UDP ports 546/547 (DHCPv6). On the wire, the protocol uses a 236-byte BOOTP fixed header (op, htype, hlen, hops, 32-bit xid, secs, flags, ciaddr, yiaddr, siaddr, giaddr, 16-byte chaddr, 64-byte sname, 128-byte file), 4-byte RFC 1497 magic cookie 0x63825363, and TLV DHCP options (Option 53 Message Type, Option 1 Subnet Mask, Option 3 Router, Option 6 DNS, Option 12 Hostname, Option 51 Lease Time, 0xFF End), or 4-byte DHCPv6 msg-type + 24-bit transaction-id header.
//! Every field in [`DhcpSpec`] is optional so authors can emit zero-configuration default
//! frames or override specific protocol header fields and attributes.
//!
//! Canonical `.fasm` syntax:
//! `a -> b dhcp [discover | offer | request | ack | release | solicit | advertise | reply] [xid <u32>] [ciaddr <ip>] [yiaddr <ip>] [siaddr <ip>] [chaddr <mac>] [hostname <str>] [dnsserver <ip>] [router <ip>] [subnetmask <ip>] [leasetime <u32>]`

use core::net::IpAddr;
/// Dynamic Host Configuration Protocol (v4 / v6) specification.
///
/// Syntax mapping: `dhcp [discover | offer | request | ack | release | solicit | advertise | reply] [xid <u32>] [ciaddr <ip>] [yiaddr <ip>] [siaddr <ip>] [chaddr <mac>] [hostname <str>] [dnsserver <ip>] [router <ip>] [subnetmask <ip>] [leasetime <u32>]`
#[doc(alias = "dhcp")]
#[doc(alias = "DHCPV4")]
#[doc(alias = "DHCPV6")]
#[doc(alias = "RFC 2131")]
#[doc(alias = "RFC2131")]
#[doc(alias = "RFC 8415")]
#[doc(alias = "RFC8415")]
#[doc(alias = "BOOTP")]
#[doc(alias = "discover")]
#[doc(alias = "offer")]
#[doc(alias = "request")]
#[doc(alias = "ack")]
#[doc(alias = "release")]
#[doc(alias = "solicit")]
#[doc(alias = "advertise")]
#[doc(alias = "reply")]
#[doc(alias = "xid")]
#[doc(alias = "ciaddr")]
#[doc(alias = "yiaddr")]
#[doc(alias = "siaddr")]
#[doc(alias = "chaddr")]
#[doc(alias = "hostname")]
#[doc(alias = "dnsserver")]
#[doc(alias = "router")]
#[doc(alias = "subnetmask")]
#[doc(alias = "leasetime")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DhcpSpec<'a> {
    /// DHCPDISCOVER flag.
    pub is_discover: bool,
    /// DHCPv6 Solicit flag.
    pub is_solicit: bool,
    /// DHCPOFFER flag.
    pub is_offer: bool,
    /// DHCPv6 Advertise flag.
    pub is_advertise: bool,
    /// DHCPREQUEST flag.
    pub is_request: bool,
    /// DHCPACK flag.
    pub is_ack: bool,
    /// DHCPv6 Reply flag.
    pub is_reply: bool,
    /// DHCPRELEASE flag.
    pub is_release: bool,
    /// Transaction ID.
    pub xid: Option<u32>,
    /// Client IP address (ciaddr).
    pub ciaddr: Option<IpAddr>,
    /// 'Your' (client) IP address (yiaddr).
    pub yiaddr: Option<IpAddr>,
    /// Next server IP address (siaddr).
    pub siaddr: Option<IpAddr>,
    /// Client hardware address override.
    pub chaddr: Option<[u8; 6]>,
    /// Host name option.
    pub hostname: Option<&'a str>,
    /// DNS server option IP.
    pub dns_server: Option<IpAddr>,
    /// Router default gateway option IP.
    pub router: Option<IpAddr>,
    /// Subnet mask option IP.
    pub subnet_mask: Option<IpAddr>,
    /// IP address lease time in seconds.
    pub lease_time: Option<u32>,
}
