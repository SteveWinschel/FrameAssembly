//! Internet Control Message Protocol (ICMP / ICMPv6) AST definitions.

use core::marker::PhantomData;
use core::net::IpAddr;

/// ICMP message type classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IcmpTypeChoice {
    /// Echo Request
    EchoRequest,
    /// Echo Reply
    EchoReply,
    /// Destination Unreachable
    DestUnreach,
    /// Time Exceeded
    TimeExceeded,
    /// Redirect
    Redirect,
}

/// Internet Control Message Protocol (RFC 792 / RFC 4443) specification.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct IcmpSpec<'a> {
    /// Message type selection.
    pub type_choice: Option<IcmpTypeChoice>,
    /// Explicit numeric ICMP Type.
    pub icmp_type: Option<u8>,
    /// Explicit numeric ICMP Code.
    pub icmp_code: Option<u8>,
    /// Identifier.
    pub id: Option<u16>,
    /// Sequence Number.
    pub seq: Option<u16>,
    /// Gateway IP address (for Redirect).
    pub gateway: Option<IpAddr>,
    /// Optional phantom reference.
    pub _marker: PhantomData<&'a ()>,
}
