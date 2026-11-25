//! ITU-T H.323 / H.225.0 Call Signaling and RAS Layer 7 AST definitions.
//!
//! This module defines [`H323Spec`], the zero-copy Abstract Syntax Tree (AST) specification for
//! synthesizing ITU-T H.323 multimedia signaling frames across both TCP port 1720 (H.225.0 Call
//! Signaling over RFC 1006 TPKT + ITU-T Q.931 + X.691 Aligned PER `H323-UserInformation`
//! inside the User-User Information Element `0x7E`) and UDP port 1719 (H.225.0 Registration,
//! Admission, and Status `RasMessage` PDUs encoded in Aligned PER when `transport udp` or a RAS
//! keyword such as `grq`, `gcf`, `rrq`, `rcf`, `drq`, or `dcf` is specified).
//!
//! Canonical `.frasm` syntax:
//! `a -> b h323 [setup | callproceeding | alerting | connect | releasecomplete | grq | gcf | rrq | rcf | drq | dcf | msgtype <str>] [callref <u16>] [callingparty <str>] [calledparty <str>] [cause <u8>] [seqnum <u16>] [rasaddr <ip> [<u16>]] [transport udp]`

use core::net::IpAddr;

/// ITU-T H.323 / H.225.0 Call Signaling and RAS protocol specification.
///
/// Syntax mapping: `h323 [setup | callproceeding | alerting | connect | releasecomplete | grq | gcf | rrq | rcf | drq | dcf | msgtype <str>] [callref <u16>] [callingparty <str>] [calledparty <str>] [cause <u8>] [seqnum <u16>] [rasaddr <ip> [<u16>]] [transport udp]`
#[doc(alias = "h323")]
#[doc(alias = "H.323")]
#[doc(alias = "H.225.0")]
#[doc(alias = "Q.931")]
#[doc(alias = "TPKT")]
#[doc(alias = "RAS")]
#[doc(alias = "1720")]
#[doc(alias = "1719")]
#[doc(alias = "setup")]
#[doc(alias = "callproceeding")]
#[doc(alias = "alerting")]
#[doc(alias = "connect")]
#[doc(alias = "releasecomplete")]
#[doc(alias = "callref")]
#[doc(alias = "callingparty")]
#[doc(alias = "calledparty")]
#[doc(alias = "cause")]
#[doc(alias = "grq")]
#[doc(alias = "gcf")]
#[doc(alias = "rrq")]
#[doc(alias = "rcf")]
#[doc(alias = "drq")]
#[doc(alias = "dcf")]
#[doc(alias = "seqnum")]
#[doc(alias = "rasaddr")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct H323Spec<'a> {
    /// Call Signaling (`setup`, `callproceeding`, `alerting`, `connect`, `releasecomplete`, `information`) or RAS (`grq`, `gcf`, `rrq`, `rcf`, `drq`, `dcf`) message type.
    pub msg_type: Option<&'a str>,
    /// Q.931 16-bit Call Reference Value (`callref <u16>`, also used in RAS `DRQ`).
    pub call_ref: Option<u16>,
    /// Q.931 Calling Party Number IE (`0x6C`) digit string (`callingparty <str>`).
    pub calling_party: Option<&'a str>,
    /// Q.931 Called Party Number IE (`0x70`) digit string (`calledparty <str>`).
    pub called_party: Option<&'a str>,
    /// Q.931 Cause IE (`0x08`) numeric cause value (`cause <u8>`, e.g., `16` Normal call clearing).
    pub cause: Option<u8>,
    /// H.225.0 RAS `requestSeqNum` (`1..=65535`, `seqnum <u16>`).
    pub seq_num: Option<u16>,
    /// H.225.0 RAS `TransportAddress` IPv4 endpoint address (`rasaddr <ip> [<u16>]`).
    pub ras_addr: Option<IpAddr>,
    /// Optional H.225.0 RAS `TransportAddress` UDP/TCP port (`rasaddr <ip> [<u16>]`).
    pub ras_port: Option<u16>,
}
