//! IPv6 Multicast Listener Discovery (MLD, RFC 2710 / MLDv2 RFC 3810) AST definitions.
//!
//! Defines IPv6 multicast group management signaling carried as ICMPv6 sub-messages over IPv6 Next
//! Header `58` (`0x3A`). The 24-byte MLDv1 (RFC 2710) packet format comprises an 8-bit ICMPv6 `Type`
//! (`130` Multicast Listener `query`, `131` Multicast Listener `report`, `132` Multicast Listener
//! `done`), an 8-bit `Code` (`0`), a 16-bit ICMPv6 ones'-complement `Checksum` (verified against the
//! 40-byte IPv6 pseudo-header), a 16-bit `Maximum Response Delay` in milliseconds (`maxrespdelay`),
//! a 16-bit `Reserved` field, and a 128-bit IPv6 `Multicast Address` (`multicastaddr`).
//!
//! Canonical `.frasm` syntax:
//! `a -> b mld [query | report | done] [multicastaddr <ipv6>] [maxrespdelay <u16>]`

use core::marker::PhantomData;
use core::net::IpAddr;

/// RFC 2710 / RFC 3810 MLD ICMPv6 message type code.
#[doc(alias = "MldMessageType")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MldType {
    /// Multicast Listener Query (`query`, ICMPv6 Type `130`, default group `ff02::1`).
    Query,
    /// Multicast Listener Report (`report`, ICMPv6 Type `131`, default group `ff02::1`).
    Report,
    /// Multicast Listener Done (`done`, ICMPv6 Type `132`, default group `ff02::2`).
    Done,
}

/// Multicast Listener Discovery (RFC 2710 / RFC 3810) specification for IPv6 over ICMPv6 (`58`).
///
/// Syntax mapping: `mld [query | report | done] [multicastaddr <ipv6>] [maxrespdelay <u16>]`
#[doc(alias = "mld")]
#[doc(alias = "MLDv2")]
#[doc(alias = "RFC 2710")]
#[doc(alias = "RFC2710")]
#[doc(alias = "RFC 3810")]
#[doc(alias = "RFC3810")]
#[doc(alias = "query")]
#[doc(alias = "report")]
#[doc(alias = "done")]
#[doc(alias = "multicastaddr")]
#[doc(alias = "maxrespdelay")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MldSpec<'a> {
    /// MLD message type (`query`, `report`, or `done`; default `report`).
    pub mld_type: Option<MldType>,
    /// 128-bit IPv6 Multicast group address (`multicastaddr <ipv6>`).
    pub multicast_addr: Option<IpAddr>,
    /// 16-bit Maximum Response Delay in milliseconds (`maxrespdelay <u16>`, default `0`).
    pub max_resp_delay: Option<u16>,
    /// Optional lifetime phantom marker for AST uniformity.
    pub _marker: PhantomData<&'a ()>,
}
