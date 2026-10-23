//! Virtual Router Redundancy Protocol (VRRP) AST definitions.

use core::marker::PhantomData;
use core::net::IpAddr;

/// Virtual Router Redundancy Protocol (RFC 5798) specification.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct VrrpSpec<'a> {
    /// Virtual Router Identifier (1..=255).
    pub vrid: Option<u8>,
    /// Router Priority (1..=254).
    pub priority: Option<u8>,
    /// Advertisement Interval in centiseconds.
    pub adv_int: Option<u16>,
    /// Virtual IP address.
    pub vip: Option<IpAddr>,
    /// VRRP version (2 or 3).
    pub version: Option<u8>,
    /// Optional phantom reference.
    pub _marker: PhantomData<&'a ()>,
}
