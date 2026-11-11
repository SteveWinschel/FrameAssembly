//! Address Resolution Protocol (ARP, RFC 826 / RFC 5227) AST definitions.
//!
//! Defines the wire-level configuration parameters for IPv4-to-Ethernet address resolution
//! over EtherType `0x0806`. The 28-byte ARP payload consists of Hardware Type (`HTYPE = 0x0001`
//! for Ethernet), Protocol Type (`PTYPE = 0x0800` for IPv4), Hardware Address Length (`HLEN = 6`),
//! Protocol Address Length (`PLEN = 4`), 16-bit Operation Code (`OPER = 1` Request, `2` Reply),
//! 48-bit Sender Hardware Address (`sha`), 32-bit Sender Protocol Address (`spa`), 48-bit Target
//! Hardware Address (`tha`), and 32-bit Target Protocol Address (`tpa`).
//!
//! Canonical `.fasm` syntax:
//! `a -> b arp [request | reply] [gratuitous] [sendermac <mac>] [senderip <ip>] [targetmac <mac>] [targetip <ip>]`

use core::marker::PhantomData;
use core::net::IpAddr;

/// ARP 16-bit operation code (`OPER` field at byte offset 6..8 of the ARP header per RFC 826).
#[doc(alias = "OPER")]
#[doc(alias = "RFC826")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArpOpcode {
    /// ARP Request (`OPER = 1`, broadcast query resolving target protocol address).
    Request,
    /// ARP Reply (`OPER = 2`, unicast or gratuitous response providing hardware address).
    Reply,
}

/// Address Resolution Protocol (RFC 826 / RFC 5227) frame specification.
///
/// Syntax mapping: `arp [request | reply] [gratuitous] [sendermac <mac>] [senderip <ip>] [targetmac <mac>] [targetip <ip>]`
#[doc(alias = "arp")]
#[doc(alias = "RFC 826")]
#[doc(alias = "RFC 5227")]
#[doc(alias = "0x0806")]
#[doc(alias = "request")]
#[doc(alias = "reply")]
#[doc(alias = "gratuitous")]
#[doc(alias = "sendermac")]
#[doc(alias = "senderip")]
#[doc(alias = "targetmac")]
#[doc(alias = "targetip")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ArpSpec<'a> {
    /// Operation code (`request` = 1 or `reply` = 2).
    pub opcode: Option<ArpOpcode>,
    /// Gratuitous ARP announcement flag (`gratuitous`, sets `TPA = SPA` and `THA = 00:00:00:00:00:00`).
    pub is_gratuitous: bool,
    /// Sender 48-bit Hardware Address override (`sendermac <mac>`).
    pub sha: Option<[u8; 6]>,
    /// Sender 32-bit Protocol Address override (`senderip <ipv4>`).
    pub spa: Option<IpAddr>,
    /// Target 48-bit Hardware Address override (`targetmac <mac>`).
    pub tha: Option<[u8; 6]>,
    /// Target 32-bit Protocol Address override (`targetip <ipv4>`).
    pub tpa: Option<IpAddr>,
    /// Optional lifetime marker for zero-copy AST borrowing.
    pub _marker: PhantomData<&'a ()>,
}
