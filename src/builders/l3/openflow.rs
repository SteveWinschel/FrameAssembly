//! OPENFLOW Layer 3 protocol wire builder.

use crate::ast::*;
use alloc::vec::Vec;

/// Builds an OpenFlow OFPT_HELLO payload over TCP 6653.
pub fn build_openflow_payload(spec: &OpenflowSpec, payload: &[u8]) -> (Vec<u8>, u16) {
    let version = spec.version.unwrap_or(4); // OF 1.3
    let of_type = match spec.of_type.unwrap_or(OpenflowType::Hello) {
        OpenflowType::Hello => 0,
        OpenflowType::EchoReq => 2,
        OpenflowType::EchoReply => 3,
        OpenflowType::FeaturesReq => 5,
        OpenflowType::FeaturesReply => 6,
        OpenflowType::PacketIn => 10,
        OpenflowType::FlowMod => 14,
        OpenflowType::PacketOut => 13,
    };
    let total_len = (8 + payload.len()) as u16;

    let mut of = Vec::with_capacity(8 + payload.len());
    of.push(version);
    of.push(of_type);
    of.extend_from_slice(&total_len.to_be_bytes());
    of.extend_from_slice(&spec.xid.unwrap_or(1).to_be_bytes());
    of.extend_from_slice(payload);

    (of, 6653)
}
