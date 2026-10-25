//! IPv6 Multicast Listener Discovery (MLD, RFC 2710 / MLDv2 RFC 3810) AST definitions.
//!
//! Defines IPv6 multicast group management signaling carried as ICMPv6 sub-messages over IPv6 Next
//! Header `58` (`0x3A`). The 24-byte MLDv1 (RFC 2710) packet format comprises an 8-bit ICMPv6 `Type`
//! (`130` Multicast Listener `QUERY`, `131` Multicast Listener `REPORT`, `132` Multicast Listener
//! `DONE`), an 8-bit `Code` (`0`), a 16-bit ICMPv6 ones'-complement `Checksum` (verified against the
//! 40-byte IPv6 pseudo-header), a 16-bit `Maximum Response Delay` in milliseconds (`MAX_RESP_DELAY`),
//! a 16-bit `Reserved` field, and a 128-bit IPv6 `Multicast Address` (`MULTICAST_ADDR`).
//!
//! Canonical `.fasm` syntax:
//! `a -> b MLD [QUERY | REPORT | DONE] [MULTICAST_ADDR <ipv6>] [MAX_RESP_DELAY <u16>]`

use core::marker::PhantomData;
use core::net::IpAddr;

/// RFC 2710 / RFC 3810 MLD ICMPv6 message type code.
#[doc(alias = "MldMessageType")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MldType {
    /// Multicast Listener Query (`QUERY`, ICMPv6 Type `130`, default group `ff02::1`).
    Query,
    /// Multicast Listener Report (`REPORT`, ICMPv6 Type `131`, default group `ff02::1`).
    Report,
    /// Multicast Listener Done (`DONE`, ICMPv6 Type `132`, default group `ff02::2`).
    Done,
}

/// Multicast Listener Discovery (RFC 2710 / RFC 3810) specification for IPv6 over ICMPv6 (`58`).
///
/// Syntax mapping: `MLD [QUERY | REPORT | DONE] [MULTICAST_ADDR <ipv6>] [MAX_RESP_DELAY <u16>]`
#[doc(alias = "MLD")]
#[doc(alias = "MLDv2")]
#[doc(alias = "RFC 2710")]
#[doc(alias = "RFC2710")]
#[doc(alias = "RFC 3810")]
#[doc(alias = "RFC3810")]
#[doc(alias = "QUERY")]
#[doc(alias = "REPORT")]
#[doc(alias = "DONE")]
#[doc(alias = "MULTICAST_ADDR")]
#[doc(alias = "MAX_RESP_DELAY")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MldSpec<'a> {
    /// MLD message type (`QUERY`, `REPORT`, or `DONE`; default `REPORT`).
    pub mld_type: Option<MldType>,
    /// 128-bit IPv6 Multicast group address (`MULTICAST_ADDR <ipv6>`).
    pub multicast_addr: Option<IpAddr>,
    /// 16-bit Maximum Response Delay in milliseconds (`MAX_RESP_DELAY <u16>`, default `0`).
    pub max_resp_delay: Option<u16>,
    /// Optional lifetime phantom marker for AST uniformity.
    pub _marker: PhantomData<&'a ()>,
}
