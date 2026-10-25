//! Address Resolution Protocol (ARP, RFC 826 / RFC 5227) AST definitions.
//!
//! Defines the wire-level configuration parameters for IPv4-to-Ethernet address resolution
//! over EtherType `0x0806`. The 28-byte ARP payload consists of Hardware Type (`HTYPE = 0x0001`
//! for Ethernet), Protocol Type (`PTYPE = 0x0800` for IPv4), Hardware Address Length (`HLEN = 6`),
//! Protocol Address Length (`PLEN = 4`), 16-bit Operation Code (`OPER = 1` Request, `2` Reply),
//! 48-bit Sender Hardware Address (`SHA`), 32-bit Sender Protocol Address (`SPA`), 48-bit Target
//! Hardware Address (`THA`), and 32-bit Target Protocol Address (`TPA`).
//!
//! Canonical `.fasm` syntax:
//! `a -> b ARP [REQUEST | REPLY] [GRATUITOUS] [SENDERMAC <mac>] [SENDERIP <ip>] [TARGETMAC <mac>] [TARGETIP <ip>]`

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
/// Syntax mapping: `ARP [REQUEST | REPLY] [GRATUITOUS] [SENDERMAC <mac>] [SENDERIP <ip>] [TARGETMAC <mac>] [TARGETIP <ip>]`
#[doc(alias = "ARP")]
#[doc(alias = "RFC 826")]
#[doc(alias = "RFC 5227")]
#[doc(alias = "0x0806")]
#[doc(alias = "REQUEST")]
#[doc(alias = "REPLY")]
#[doc(alias = "GRATUITOUS")]
#[doc(alias = "SENDERMAC")]
#[doc(alias = "SENDERIP")]
#[doc(alias = "TARGETMAC")]
#[doc(alias = "TARGETIP")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ArpSpec<'a> {
    /// Operation code (`REQUEST` = 1 or `REPLY` = 2).
    pub opcode: Option<ArpOpcode>,
    /// Gratuitous ARP announcement flag (`GRATUITOUS`, sets `TPA = SPA` and `THA = 00:00:00:00:00:00`).
    pub is_gratuitous: bool,
    /// Sender 48-bit Hardware Address override (`SENDERMAC <mac>`).
    pub sha: Option<[u8; 6]>,
    /// Sender 32-bit Protocol Address override (`SENDERIP <ipv4>`).
    pub spa: Option<IpAddr>,
    /// Target 48-bit Hardware Address override (`TARGETMAC <mac>`).
    pub tha: Option<[u8; 6]>,
    /// Target 32-bit Protocol Address override (`TARGETIP <ipv4>`).
    pub tpa: Option<IpAddr>,
    /// Optional lifetime marker for zero-copy AST borrowing.
    pub _marker: PhantomData<&'a ()>,
}
