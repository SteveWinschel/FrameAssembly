//! Packet Forwarding Control Protocol (`pfcp`, 3GPP TS 29.244) Layer 7 AST definitions.
//!
//! This module defines [`PfcpSpec`], the zero-copy abstract syntax tree (AST) representation for
//! synthesizing 3GPP TS 29.244 PFCP N4/Sx/Sxa/Sxb/Sxc control-plane packets over UDP port `8805`.
//! It supports both Node-related messages without a Session Endpoint Identifier (`S=0` 8-byte
//! header: `Heartbeat Request`/`Response` and `Association Setup Request`/`Response`) and
//! Session-related messages with a 64-bit SEID (`S=1` 16-byte header: `Session Establishment`,
//! `Session Modification`, and `Session Deletion` Request/Response), along with `Node ID` (Type `60`),
//! `Cause` (Type `19`), and `Recovery Time Stamp` (Type `96`) Information Elements.
//!
//! Canonical `.frasm` syntax:
//! `a -> b pfcp [heartbeatrequest | heartbeatresponse | associationsetuprequest | associationsetupresponse | sessionestablishmentrequest | sessionestablishmentresponse | sessionmodificationrequest | sessionmodificationresponse | sessiondeletionrequest | sessiondeletionresponse | msgtype <str>] [seid <u64>] [seqnum <u32>] [cause <u8>] [nodeid <ip|str>] [recovery <u32>]`

/// 3GPP TS 29.244 Packet Forwarding Control Protocol (`pfcp`) specification.
///
/// Syntax mapping: `pfcp [heartbeatrequest | heartbeatresponse | associationsetuprequest | associationsetupresponse | sessionestablishmentrequest | sessionestablishmentresponse | sessionmodificationrequest | sessionmodificationresponse | sessiondeletionrequest | sessiondeletionresponse | msgtype <str>] [seid <u64>] [seqnum <u32>] [cause <u8>] [nodeid <ip|str>] [recovery <u32>]`
#[doc(alias = "pfcp")]
#[doc(alias = "TS 29.244")]
#[doc(alias = "N4")]
#[doc(alias = "8805")]
#[doc(alias = "heartbeatrequest")]
#[doc(alias = "heartbeatresponse")]
#[doc(alias = "associationsetuprequest")]
#[doc(alias = "associationsetupresponse")]
#[doc(alias = "sessionestablishmentrequest")]
#[doc(alias = "sessionestablishmentresponse")]
#[doc(alias = "sessionmodificationrequest")]
#[doc(alias = "sessionmodificationresponse")]
#[doc(alias = "sessiondeletionrequest")]
#[doc(alias = "sessiondeletionresponse")]
#[doc(alias = "msgtype")]
#[doc(alias = "seid")]
#[doc(alias = "seqnum")]
#[doc(alias = "cause")]
#[doc(alias = "nodeid")]
#[doc(alias = "recovery")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PfcpSpec<'a> {
    /// PFCP message type name or numeric code (`"heartbeatrequest"`, `"heartbeatresponse"`, `"associationsetuprequest"`, `"associationsetupresponse"`, `"sessionestablishmentrequest"`, `"sessionestablishmentresponse"`, `"sessionmodificationrequest"`, `"sessionmodificationresponse"`, `"sessiondeletionrequest"`, `"sessiondeletionresponse"`).
    pub msg_type: Option<&'a str>,
    /// 64-bit Session Endpoint Identifier present when `S=1` (`seid <u64>`).
    pub seid: Option<u64>,
    /// 24-bit PFCP sequence number (`seqnum <u32>`; default `1`).
    pub seq_num: Option<u32>,
    /// 8-bit PFCP Cause IE Type `19` code (`cause <u8>`, e.g., `1` for Request accepted).
    pub cause: Option<u8>,
    /// PFCP Node ID IE Type `60` IPv4, IPv6, or FQDN string (`nodeid <ip|str>`).
    pub node_id: Option<&'a str>,
    /// 32-bit NTP Recovery Time Stamp in IE Type `96` (`recovery <u32>`; default `0x11223344`).
    pub recovery: Option<u32>,
}
