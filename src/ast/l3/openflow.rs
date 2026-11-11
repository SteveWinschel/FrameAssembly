//! OpenFlow Switch Protocol (ONF OpenFlow v1.0–v1.5) AST definitions.
//!
//! Defines Software-Defined Networking (SDN) Southbound control channel messages exchanged between an
//! OpenFlow controller and an OpenFlow-enabled switch over TCP port `6653` (IANA standard) or `6633`.
//! Every OpenFlow message starts with an 8-byte `ofp_header` comprising an 8-bit `version` (`version`,
//! default `4` for OpenFlow 1.3), an 8-bit `type` code (`hello` `0`, `echoreq` `2`, `echoreply` `3`,
//! `featuresreq` `5`, `featuresreply` `6`, `packetin` `10`, `packetout` `13`, `flowmod` `14`), a
//! 16-bit total message `length`, and a 32-bit transaction identifier `xid` (`xid`), optionally
//! accompanied by Datapath ID (`dpid`), flow `tableid`, and flow rule `priority` attributes.
//!
//! Canonical `.fasm` syntax:
//! `a -> b openflow [hello | echoreq | echoreply | featuresreq | featuresreply | packetin | packetout | flowmod] [version <u8>] [xid <u32>] [dpid <u64>] [tableid <u8>] [priority <u16>]`

use core::marker::PhantomData;

/// ONF OpenFlow Switch Protocol `ofp_type` message classification.
#[doc(alias = "OfpType")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenflowType {
    /// `OFPT_HELLO` (`0`): Symmetric connection startup version negotiation message.
    Hello,
    /// `OFPT_ECHO_REQUEST` (`2`): Symmetric control channel liveness probe request.
    EchoReq,
    /// `OFPT_ECHO_REPLY` (`3`): Symmetric control channel liveness probe response.
    EchoReply,
    /// `OFPT_FEATURES_REQUEST` (`5`): Controller request querying switch datapath capabilities (`dpid`).
    FeaturesReq,
    /// `OFPT_FEATURES_REPLY` (`6`): Switch response advertising `datapath_id` and supported tables/ports.
    FeaturesReply,
    /// `OFPT_PACKET_IN` (`10`): Asynchronous switch-to-controller punt of a table-miss or controller-action packet.
    PacketIn,
    /// `OFPT_FLOW_MOD` (`14`): Controller-to-switch command installing, modifying, or deleting a flow table entry.
    FlowMod,
    /// `OFPT_PACKET_OUT` (`13`): Controller-to-switch command injecting a raw frame out a switch port.
    PacketOut,
}

/// OpenFlow Switch Protocol (ONF v1.3+) specification over TCP port `6653`.
///
/// Syntax mapping: `openflow [hello | echoreq | echoreply | featuresreq | featuresreply | packetin | packetout | flowmod] [version <u8>] [xid <u32>] [dpid <u64>] [tableid <u8>] [priority <u16>]`
#[doc(alias = "openflow")]
#[doc(alias = "OpenFlow")]
#[doc(alias = "SDN")]
#[doc(alias = "6653")]
#[doc(alias = "ofp_header")]
#[doc(alias = "hello")]
#[doc(alias = "echoreq")]
#[doc(alias = "echoreply")]
#[doc(alias = "featuresreq")]
#[doc(alias = "featuresreply")]
#[doc(alias = "packetin")]
#[doc(alias = "packetout")]
#[doc(alias = "flowmod")]
#[doc(alias = "version")]
#[doc(alias = "xid")]
#[doc(alias = "dpid")]
#[doc(alias = "tableid")]
#[doc(alias = "priority")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct OpenflowSpec<'a> {
    /// OpenFlow wire protocol version (`version <u8>`, e.g. `1` = OF 1.0, `4` = OF 1.3, `5` = OF 1.4; default `4`).
    pub version: Option<u8>,
    /// OpenFlow message type (`hello`, `echoreq`, `echoreply`, `featuresreq`, `featuresreply`, `packetin`, `flowmod`, `packetout`; default `hello`).
    pub of_type: Option<OpenflowType>,
    /// 32-bit Transaction ID correlating requests and replies (`xid <u32>`, default `1`).
    pub xid: Option<u32>,
    /// 64-bit switch Datapath Identifier (`dpid <u64>`).
    pub dpid: Option<u64>,
    /// 8-bit pipeline Flow Table Identifier (`tableid <u8>`).
    pub table_id: Option<u8>,
    /// 16-bit flow entry matching Priority (`priority <u16>`).
    pub priority: Option<u16>,
    /// Optional lifetime phantom marker for AST uniformity.
    pub _marker: PhantomData<&'a ()>,
}
