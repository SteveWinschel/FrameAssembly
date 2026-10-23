//! RADIUS protocol AST definitions.

use core::net::IpAddr;
/// RFC 2865 RADIUS authentication & accounting specification.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RadiusSpec<'a> {
    /// Packet code (e.g. ACCESS_REQUEST, ACCESS_ACCEPT).
    pub code: Option<&'a str>,
    /// Identifier byte.
    pub id: Option<u8>,
    /// User name attribute string.
    pub user: Option<&'a str>,
    /// NAS IP address.
    pub nas_ip: Option<IpAddr>,
    /// Service Type numeric code.
    pub service_type: Option<u32>,
    /// Framed IP address.
    pub framed_ip: Option<IpAddr>,
}
