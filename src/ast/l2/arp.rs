//! Address Resolution Protocol (ARP) AST definitions.

use core::marker::PhantomData;
use core::net::IpAddr;

/// ARP operation code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArpOpcode {
    /// ARP Request (1)
    Request,
    /// ARP Reply (2)
    Reply,
}

/// Address Resolution Protocol (RFC 826) specification.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ArpSpec<'a> {
    /// Operation code (Request or Reply).
    pub opcode: Option<ArpOpcode>,
    /// Gratuitous ARP flag.
    pub is_gratuitous: bool,
    /// Sender Hardware Address override.
    pub sha: Option<[u8; 6]>,
    /// Sender Protocol Address override.
    pub spa: Option<IpAddr>,
    /// Target Hardware Address override.
    pub tha: Option<[u8; 6]>,
    /// Target Protocol Address override.
    pub tpa: Option<IpAddr>,
    /// Optional phantom reference.
    pub _marker: PhantomData<&'a ()>,
}
