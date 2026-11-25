//! GPRS Tunneling Protocol Control Plane v2 (`gtpc`, 3GPP TS 29.274) Layer 7 AST definitions.
//!
//! This module defines [`GtpcSpec`], the zero-copy abstract syntax tree (AST) representation for
//! synthesizing 3GPP TS 29.274 GTPv2-C signaling packets over UDP port `2123`. It models the
//! 8-byte (no TEID, `T=0` for `Echo Request`/`Echo Response`) and 12-byte (`T=1` with 32-bit
//! Tunnel Endpoint Identifier) GTPv2-C headers alongside core EPC/5G control Information Elements
//! (`IMSI`, `Cause`, `Recovery`, `APN`, `PDN Address Allocation`, and `RAT Type`). Every field in
//! [`GtpcSpec`] is optional so bare `gtpc` emits a valid GTPv2-C Echo Request with a Recovery IE.
//!
//! Canonical `.frasm` syntax:
//! `a -> b gtpc [echorequest | echoreply | echoresponse | createsessionrequest | createsessionresponse | modifybearerrequest | modifybearerresponse | deletesessionrequest | deletesessionresponse | msgtype <str>] [teid <u32>] [seqnum <u32>] [cause <u8>] [imsi <str>] [apn <str>] [rat <u8>] [recovery <u8>] [addr <ip>]`

use core::net::IpAddr;

/// 3GPP TS 29.274 GTPv2-C Control Plane (`gtpc`) specification.
///
/// Syntax mapping: `gtpc [echorequest | echoreply | echoresponse | createsessionrequest | createsessionresponse | modifybearerrequest | modifybearerresponse | deletesessionrequest | deletesessionresponse | msgtype <str>] [teid <u32>] [seqnum <u32>] [cause <u8>] [imsi <str>] [apn <str>] [rat <u8>] [recovery <u8>] [addr <ip>]`
#[doc(alias = "gtpc")]
#[doc(alias = "GTPv2")]
#[doc(alias = "GTPv2-C")]
#[doc(alias = "TS 29.274")]
#[doc(alias = "2123")]
#[doc(alias = "echorequest")]
#[doc(alias = "echoresponse")]
#[doc(alias = "createsessionrequest")]
#[doc(alias = "createsessionresponse")]
#[doc(alias = "modifybearerrequest")]
#[doc(alias = "modifybearerresponse")]
#[doc(alias = "deletesessionrequest")]
#[doc(alias = "deletesessionresponse")]
#[doc(alias = "msgtype")]
#[doc(alias = "teid")]
#[doc(alias = "seqnum")]
#[doc(alias = "cause")]
#[doc(alias = "imsi")]
#[doc(alias = "apn")]
#[doc(alias = "rat")]
#[doc(alias = "recovery")]
#[doc(alias = "addr")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct GtpcSpec<'a> {
    /// GTPv2-C message type name or numeric code (`"echorequest"`, `"echoresponse"`, `"createsessionrequest"`, `"createsessionresponse"`, `"modifybearerrequest"`, `"modifybearerresponse"`, `"deletesessionrequest"`, `"deletesessionresponse"`).
    pub msg_type: Option<&'a str>,
    /// 32-bit Tunnel Endpoint Identifier included when `T=1` (`teid <u32>`).
    pub teid: Option<u32>,
    /// 24-bit GTPv2-C sequence number (`seqnum <u32>`; default `1`).
    pub seq_num: Option<u32>,
    /// 8-bit GTPv2 Cause IE Type `2` value (`cause <u8>`, e.g., `16` for Request accepted).
    pub cause: Option<u8>,
    /// Subscriber IMSI digit string encoded into TBCD IMSI IE Type `1` (`imsi <str>`).
    pub imsi: Option<&'a str>,
    /// Access Point Name encoded as DNS labels in APN IE Type `71` (`apn <str>`).
    pub apn: Option<&'a str>,
    /// 8-bit Radio Access Technology code in RAT Type IE Type `82` (`rat <u8>`, e.g., `6` EUTRAN).
    pub rat: Option<u8>,
    /// 8-bit Restart Counter in Recovery IE Type `3` (`recovery <u8>`; default `1` on Echo).
    pub recovery: Option<u8>,
    /// Assigned PDN IPv4 or IPv6 address in PAA IE Type `79` (`addr <ip>`).
    pub addr: Option<IpAddr>,
}
