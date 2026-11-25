//! Real-time Transport Control Protocol (RTCP, RFC 3550) Layer 7 AST definitions.
//!
//! This module defines [`RtcpSpec`], the zero-copy AST representation of an RFC 3550 Real-time
//! Transport Control Protocol (RTCP) feedback datagram transmitted over UDP port 5005. On the
//! wire, every RTCP packet begins with a 4-byte big-endian header (`V=2`, `P=0`, `RC/SC` count,
//! `PT` packet type `200..=204`, and `length` in 32-bit words minus one), encoding Sender Reports
//! (`sr`, `200`), Receiver Reports (`rr`, `201`), Source Descriptions (`sdes`, `202`), Goodbye
//! (`bye`, `203`), or Application-Defined (`app`, `204`) packets. Canonical `.frasm` syntax:
//! `rtcp [sr | rr | sdes | bye | app | pt <u8>] [ssrc <u32>] [timestamp <u32>] [packets <u32>] [octets <u32>] [fraction <u8>] [lost <u32>] [jitter <u32>] [seqnum <u32>] [cname <str>] [reason <str>]`.

/// RFC 3550 Real-time Transport Control Protocol (RTCP) specification.
///
/// Syntax mapping: `rtcp [sr | rr | sdes | bye | app | pt <u8>] [ssrc <u32>] [timestamp <u32>] [packets <u32>] [octets <u32>] [fraction <u8>] [lost <u32>] [jitter <u32>] [seqnum <u32>] [cname <str>] [reason <str>]`
#[doc(alias = "rtcp")]
#[doc(alias = "RFC 3550")]
#[doc(alias = "RFC3550")]
#[doc(alias = "5005")]
#[doc(alias = "sr")]
#[doc(alias = "rr")]
#[doc(alias = "sdes")]
#[doc(alias = "bye")]
#[doc(alias = "app")]
#[doc(alias = "pt")]
#[doc(alias = "ssrc")]
#[doc(alias = "timestamp")]
#[doc(alias = "packets")]
#[doc(alias = "octets")]
#[doc(alias = "fraction")]
#[doc(alias = "lost")]
#[doc(alias = "jitter")]
#[doc(alias = "seqnum")]
#[doc(alias = "cname")]
#[doc(alias = "reason")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RtcpSpec<'a> {
    /// RTCP packet type (`200` SR, `201` RR, `202` SDES, `203` BYE, `204` APP; `pt <u8>`).
    pub pt: Option<u8>,
    /// 32-bit Synchronization Source identifier of the RTCP sender (`ssrc <u32>`, default `0x12345678`).
    pub ssrc: Option<u32>,
    /// 32-bit RTP media timestamp in Sender Reports (`timestamp <u32>`, default `160`).
    pub timestamp: Option<u32>,
    /// 32-bit sender's packet count in Sender Reports (`packets <u32>`, default `10`).
    pub packets: Option<u32>,
    /// 32-bit sender's octet count in Sender Reports (`octets <u32>`, default `1600`).
    pub octets: Option<u32>,
    /// 8-bit fraction of RTP packets lost since last report (`fraction <u8>`, default `0`).
    pub fraction: Option<u8>,
    /// 24-bit cumulative number of packets lost (`lost <u32>`, `0..=16777215`, default `0`).
    pub lost: Option<u32>,
    /// 32-bit statistical variance estimate of interarrival jitter (`jitter <u32>`, default `0`).
    pub jitter: Option<u32>,
    /// 32-bit extended highest sequence number received (`seqnum <u32>`, default `1`).
    pub seq_num: Option<u32>,
    /// SDES `CNAME` string (default `"user@frameassembly.local"`) or 4-byte `APP` name (`cname <str>`).
    pub cname: Option<&'a str>,
    /// Optional reason-for-leaving string for `BYE` packets (`reason <str>`).
    pub reason: Option<&'a str>,
}
