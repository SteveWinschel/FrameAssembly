//! Layer 2 Tunneling Protocol (L2TPv2 RFC 2661 / L2TPv3 RFC 3931) AST definitions.
//!
//! Defines both L2TPv2 control and PPP data tunneling over UDP port `1701` (RFC 2661) and L2TPv3
//! pseudowire control and session frames encapsulated directly over IP protocol `115` or UDP port
//! `1701` (RFC 3931). Control messages carry reliable `ns`/`nr` sequencing and Attribute-Value Pairs
//! (such as `Message Type` for `sccrq`, `sccrp`, `scccn`, `stopccn`, and `hello`), whereas data
//! messages (`data`) carry PPP or Ethernet pseudowire payloads keyed by `tunnelid` and `sessionid`.
//!
//! Canonical `.frasm` syntax:
//! `a -> b l2tp [v2 | v3 | version <2|3>] [hello | sccrq | sccrp | scccn | stopccn | data | msgtype <str|u16>] [tunnelid <u32>] [sessionid <u32>] [ns <u16>] [nr <u16>] [flags <u16>] [transport udp]`

/// Layer 2 Tunneling Protocol (L2TPv2 RFC 2661 / L2TPv3 RFC 3931) specification over UDP `1701` or IP `115`.
///
/// Syntax mapping: `l2tp [v2 | v3 | version <2|3>] [hello | sccrq | sccrp | scccn | stopccn | data | msgtype <str|u16>] [tunnelid <u32>] [sessionid <u32>] [ns <u16>] [nr <u16>] [flags <u16>] [transport udp]`
#[doc(alias = "l2tp")]
#[doc(alias = "L2TPv2")]
#[doc(alias = "L2TPv3")]
#[doc(alias = "RFC 2661")]
#[doc(alias = "RFC 3931")]
#[doc(alias = "1701")]
#[doc(alias = "115")]
#[doc(alias = "tunnelid")]
#[doc(alias = "sessionid")]
#[doc(alias = "sccrq")]
#[doc(alias = "hello")]
#[doc(alias = "data")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct L2tpSpec<'a> {
    /// L2TP protocol version (`2` for UDP `1701` RFC 2661, `3` for IP `115` / UDP `1701` RFC 3931; default `2`).
    pub version: Option<u8>,
    /// Selects an L2TP data-plane tunnel frame (`data`) instead of a control-plane message.
    pub is_data: bool,
    /// Control Message Type AVP selector (`"hello"`, `"sccrq"`, `"sccrp"`, `"scccn"`, `"stopccn"`, or numeric code; default `"hello"`).
    pub msg_type: Option<&'a str>,
    /// 16-bit L2TPv2 Tunnel ID or 32-bit L2TPv3 Control Connection ID (`tunnelid <u32>`, default `1`).
    pub tunnel_id: Option<u32>,
    /// 16-bit L2TPv2 Session ID or 32-bit L2TPv3 Session ID (`sessionid <u32>`, default `0` for control, `1` for data).
    pub session_id: Option<u32>,
    /// 16-bit control sequence number for this packet (`ns <u16>`, default `0`).
    pub ns: Option<u16>,
    /// 16-bit expected next control sequence number (`nr <u16>`, default `0`).
    pub nr: Option<u16>,
    /// Raw 16-bit L2TP header flags word override (`flags <u16>`).
    pub flags: Option<u16>,
}
