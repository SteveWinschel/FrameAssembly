//! DHCP protocol AST definitions.

use core::net::IpAddr;
/// Dynamic Host Configuration Protocol (v4 / v6) specification.
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
