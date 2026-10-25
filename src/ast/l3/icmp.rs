//! Internet Control Message Protocol (ICMPv4 RFC 792 / ICMPv6 RFC 4443) AST definitions.
//!
//! Defines network-layer diagnostic, reachability, and error-reporting control messages carried
//! over IP protocol `1` (ICMPv4, RFC 792) and IPv6 Next Header `58` (ICMPv6, RFC 4443). The 8-byte
//! base header consists of an 8-bit `Type` (`TYPE` or symbolic keyword `ECHO_REQUEST`, `ECHO_REPLY`,
//! `DEST_UNREACH`, `TIME_EXCEEDED`, `REDIRECT`), an 8-bit `Code` (`CODE`), a 16-bit ones'-complement
//! `Checksum` (computed over the ICMPv6 pseudo-header when running over IPv6), and a 32-bit header
//! rest field containing `Identifier` (`ID`) and `Sequence Number` (`SEQ`) for Echo messages or a
//! 32-bit `Gateway Internet Address` (`GATEWAY`) for IPv4 Redirect messages.
//!
//! Canonical `.fasm` syntax:
//! `a -> b ICMP [ECHO_REQUEST | ECHO_REPLY | DEST_UNREACH | TIME_EXCEEDED | REDIRECT] [TYPE <u8>] [CODE <u8>] [ID <u16>] [SEQ <u16>] [GATEWAY <ipv4>]`

use core::marker::PhantomData;
use core::net::IpAddr;

/// Symbolic ICMPv4 (RFC 792) and ICMPv6 (RFC 4443) message type classification.
#[doc(alias = "IcmpType")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IcmpTypeChoice {
    /// Echo Request (`ECHO_REQUEST`: ICMPv4 Type `8` / ICMPv6 Type `128`, Code `0`).
    EchoRequest,
    /// Echo Reply (`ECHO_REPLY`: ICMPv4 Type `0` / ICMPv6 Type `129`, Code `0`).
    EchoReply,
    /// Destination Unreachable (`DEST_UNREACH`: ICMPv4 Type `3` / ICMPv6 Type `1`).
    DestUnreach,
    /// Time Exceeded (`TIME_EXCEEDED`: ICMPv4 Type `11` / ICMPv6 Type `3`).
    TimeExceeded,
    /// Redirect Message (`REDIRECT`: ICMPv4 Type `5` / ICMPv6 Type `137`).
    Redirect,
}

/// Internet Control Message Protocol (RFC 792 / RFC 4443) specification over IP protocol `1` / `58`.
///
/// Syntax mapping: `ICMP [ECHO_REQUEST | ECHO_REPLY | DEST_UNREACH | TIME_EXCEEDED | REDIRECT] [TYPE <u8>] [CODE <u8>] [ID <u16>] [SEQ <u16>] [GATEWAY <ipv4>]`
#[doc(alias = "ICMP")]
#[doc(alias = "ICMPv6")]
#[doc(alias = "RFC 792")]
#[doc(alias = "RFC792")]
#[doc(alias = "RFC 4443")]
#[doc(alias = "RFC4443")]
#[doc(alias = "ECHO_REQUEST")]
#[doc(alias = "ECHO_REPLY")]
#[doc(alias = "DEST_UNREACH")]
#[doc(alias = "TIME_EXCEEDED")]
#[doc(alias = "REDIRECT")]
#[doc(alias = "GATEWAY")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct IcmpSpec<'a> {
    /// Symbolic ICMP message type selection (`ECHO_REQUEST`, `ECHO_REPLY`, `DEST_UNREACH`, `TIME_EXCEEDED`, `REDIRECT`).
    pub type_choice: Option<IcmpTypeChoice>,
    /// Explicit numeric 8-bit ICMP Type override (`TYPE <u8>`).
    pub icmp_type: Option<u8>,
    /// Explicit numeric 8-bit ICMP Code override (`CODE <u8>`, default `0`).
    pub icmp_code: Option<u8>,
    /// 16-bit Echo Request/Reply Identifier (`ID <u16>`, default `0x1234`).
    pub id: Option<u16>,
    /// 16-bit Echo Request/Reply Sequence Number (`SEQ <u16>`, default `1`).
    pub seq: Option<u16>,
    /// 32-bit Redirect Gateway IPv4 address (`GATEWAY <ipv4>`).
    pub gateway: Option<IpAddr>,
    /// Optional lifetime phantom marker for AST uniformity.
    pub _marker: PhantomData<&'a ()>,
}
