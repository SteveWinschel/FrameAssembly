//! Label Distribution Protocol (LDP, RFC 5036) AST definitions.
//!
//! Defines [`LdpSpec`] and [`LdpType`] for RFC 5036 MPLS Label Distribution Protocol messages
//! carried over TCP port `646` (session initialization, keepalive, notification, and FEC-to-label
//! mapping/request/withdraw/release) or UDP port `646` (`transport udp` link and targeted Hello
//! discovery). Supports `lsrid`, `labelspace`, `msgid`, `holdtime`, 20-bit MPLS `label`, FEC
//! `prefix`, and Notification `status`.
//!
//! Canonical `.frasm` syntax:
//! `a -> b ldp [hello | init | keepalive | notification | labelmapping | labelrequest | labelwithdraw | labelrelease] [lsrid <ipv4>] [labelspace <u16>] [msgid <u32>] [holdtime <u16>] [label <u32>] [prefix "<cidr>"] [status <u32>]`

use core::net::IpAddr;

/// RFC 5036 LDP message type code.
#[doc(alias = "LdpMessageType")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LdpType {
    /// Type `0x0100` (`hello`): Link or Targeted Hello neighbor discovery.
    Hello,
    /// Type `0x0200` (`init`): Session Initialization capability and parameter negotiation.
    Init,
    /// Type `0x0201` (`keepalive`): Session KeepAlive heartbeat (default over TCP).
    Keepalive,
    /// Type `0x0001` (`notification`): Error or advisory status notification.
    Notification,
    /// Type `0x0400` (`labelmapping`): FEC-to-Label binding advertisement.
    LabelMapping,
    /// Type `0x0401` (`labelrequest`): Downstream-on-demand FEC label request.
    LabelRequest,
    /// Type `0x0402` (`labelwithdraw`): Previously advertised FEC label withdrawal.
    LabelWithdraw,
    /// Type `0x0403` (`labelrelease`): Label release acknowledgment to peer.
    LabelRelease,
}

/// Label Distribution Protocol (LDP, RFC 5036) specification over TCP/UDP port `646`.
///
/// Syntax mapping: `ldp [hello | init | keepalive | notification | labelmapping | labelrequest | labelwithdraw | labelrelease] [lsrid <ipv4>] [labelspace <u16>] [msgid <u32>] [holdtime <u16>] [label <u32>] [prefix "<cidr>"] [status <u32>]`
#[doc(alias = "ldp")]
#[doc(alias = "RFC 5036")]
#[doc(alias = "RFC5036")]
#[doc(alias = "646")]
#[doc(alias = "hello")]
#[doc(alias = "init")]
#[doc(alias = "keepalive")]
#[doc(alias = "notification")]
#[doc(alias = "labelmapping")]
#[doc(alias = "labelrequest")]
#[doc(alias = "labelwithdraw")]
#[doc(alias = "labelrelease")]
#[doc(alias = "lsrid")]
#[doc(alias = "labelspace")]
#[doc(alias = "msgid")]
#[doc(alias = "holdtime")]
#[doc(alias = "label")]
#[doc(alias = "prefix")]
#[doc(alias = "status")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LdpSpec<'a> {
    /// LDP message type (`keepalive` default over TCP, `hello` default over `transport udp`).
    pub msg_type: Option<LdpType>,
    /// 32-bit LSR ID in the 6-byte LDP Identifier (`lsrid <ipv4>`, defaults to `ctx.src_ip` or `10.0.0.1`).
    pub lsr_id: Option<IpAddr>,
    /// 16-bit Label Space ID in the 6-byte LDP Identifier (`labelspace <u16>`, default `0`).
    pub label_space: Option<u16>,
    /// 32-bit LDP Message ID (`msgid <u32>`, default `1`).
    pub msg_id: Option<u32>,
    /// 16-bit Hello Hold Time or Session KeepAlive Time (`holdtime <u16>`, default `15` / `45`).
    pub holdtime: Option<u16>,
    /// 20-bit MPLS Generic Label (`label <u32>`, default `16`).
    pub label: Option<u32>,
    /// FEC address prefix CIDR string (`prefix "<cidr>"`, default `"10.0.0.0/24"` / `"2001:db8::/32"`).
    pub prefix: Option<&'a str>,
    /// 32-bit Notification Status Code (`status <u32>`, default `0`).
    pub status: Option<u32>,
}
