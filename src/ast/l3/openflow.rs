//! OpenFlow Switch Protocol AST definitions.

use core::marker::PhantomData;

/// OpenFlow message type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenflowType {
    /// OFPT_HELLO (0)
    Hello,
    /// OFPT_ECHO_REQUEST (2)
    EchoReq,
    /// OFPT_ECHO_REPLY (3)
    EchoReply,
    /// OFPT_FEATURES_REQUEST (5)
    FeaturesReq,
    /// OFPT_FEATURES_REPLY (6)
    FeaturesReply,
    /// OFPT_PACKET_IN (10)
    PacketIn,
    /// OFPT_FLOW_MOD (14)
    FlowMod,
    /// OFPT_PACKET_OUT (13)
    PacketOut,
}

/// OpenFlow switch specification.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct OpenflowSpec<'a> {
    /// OpenFlow Version (e.g. 4 for OF 1.3).
    pub version: Option<u8>,
    /// Message type.
    pub of_type: Option<OpenflowType>,
    /// Transaction ID.
    pub xid: Option<u32>,
    /// Datapath ID.
    pub dpid: Option<u64>,
    /// Table ID.
    pub table_id: Option<u8>,
    /// Priority.
    pub priority: Option<u16>,
    /// Optional phantom reference.
    pub _marker: PhantomData<&'a ()>,
}
