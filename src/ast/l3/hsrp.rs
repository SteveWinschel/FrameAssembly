//! Hot Standby Router Protocol (HSRP) AST definitions.

use core::net::IpAddr;

/// Cisco Hot Standby Router Protocol (RFC 2281) specification.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct HsrpSpec<'a> {
    /// Standby Group number.
    pub group: Option<u8>,
    /// Priority.
    pub priority: Option<u8>,
    /// State.
    pub state: Option<u8>,
    /// Authentication string.
    pub auth: Option<&'a str>,
    /// Virtual IP address.
    pub vip: Option<IpAddr>,
    /// Hello time in seconds.
    pub hellotime: Option<u8>,
    /// Hold time in seconds.
    pub holdtime: Option<u8>,
}
