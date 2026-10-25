//! OpenFlow Switch Protocol (ONF OpenFlow v1.0–v1.5) Layer 3 wire builder.
//!
//! Serializes an [`OpenflowSpec`] into an 8-byte `ofp_header` (plus optional message body octets)
//! carried over TCP destination port `6653`. The header writes the 8-bit `version` (`VERSION`,
//! default `4` for OpenFlow 1.3), 8-bit `type` (`0` `HELLO`, `2` `ECHO_REQ`, `3` `ECHO_REPLY`,
//! `5` `FEATURES_REQ`, `6` `FEATURES_REPLY`, `10` `PACKET_IN`, `13` `PACKET_OUT`, `14` `FLOW_MOD`),
//! 16-bit big-endian total `length` (`8 + payload.len()`), and 32-bit big-endian transaction ID (`XID`).
//!
//! Canonical `.fasm` syntax:
//! `a -> b OPENFLOW [HELLO | ECHO_REQ | ECHO_REPLY | FEATURES_REQ | FEATURES_REPLY | PACKET_IN | PACKET_OUT | FLOW_MOD] [VERSION <u8>] [XID <u32>] [DPID <u64>] [TABLE_ID <u8>] [PRIORITY <u16>]`

use crate::ast::*;
use alloc::vec::Vec;

/// Builds an ONF OpenFlow protocol payload and returns `(bytes, 6653)` for TCP encapsulation.
pub fn build_openflow_payload(spec: &OpenflowSpec, payload: &[u8]) -> (Vec<u8>, u16) {
    let version = spec.version.unwrap_or(4); // OF 1.3
    let resolved_type = spec.of_type.unwrap_or(if spec.dpid.is_some() {
        OpenflowType::FeaturesReply
    } else if spec.table_id.is_some() || spec.priority.is_some() {
        OpenflowType::FlowMod
    } else {
        OpenflowType::Hello
    });
    let of_type = match resolved_type {
        OpenflowType::Hello => 0,
        OpenflowType::EchoReq => 2,
        OpenflowType::EchoReply => 3,
        OpenflowType::FeaturesReq => 5,
        OpenflowType::FeaturesReply => 6,
        OpenflowType::PacketIn => 10,
        OpenflowType::FlowMod => 14,
        OpenflowType::PacketOut => 13,
    };

    let mut body = Vec::new();
    if payload.is_empty() {
        match resolved_type {
            OpenflowType::FeaturesReply => {
                // OpenFlow 1.3 ofp_switch_features (24-byte body after 8-byte ofp_header)
                let dpid = spec.dpid.unwrap_or(0x0000_0000_0000_0001);
                body.extend_from_slice(&dpid.to_be_bytes());
                body.extend_from_slice(&256_u32.to_be_bytes()); // n_buffers
                body.push(spec.table_id.unwrap_or(254)); // n_tables
                body.push(0); // auxiliary_id
                body.extend_from_slice(&[0, 0]); // pad
                body.extend_from_slice(&0x0000_004f_u32.to_be_bytes()); // capabilities
                body.extend_from_slice(&(spec.priority.unwrap_or(0) as u32).to_be_bytes()); // reserved
            }
            OpenflowType::FlowMod => {
                // OpenFlow 1.3 ofp_flow_mod (48-byte body after 8-byte ofp_header)
                let cookie = spec.dpid.unwrap_or(0);
                body.extend_from_slice(&cookie.to_be_bytes()); // cookie
                body.extend_from_slice(&0_u64.to_be_bytes()); // cookie_mask
                body.push(spec.table_id.unwrap_or(0)); // table_id
                body.push(0); // command: OFPFC_ADD
                body.extend_from_slice(&0_u16.to_be_bytes()); // idle_timeout
                body.extend_from_slice(&0_u16.to_be_bytes()); // hard_timeout
                body.extend_from_slice(&spec.priority.unwrap_or(100).to_be_bytes()); // priority
                body.extend_from_slice(&0xFFFF_FFFF_u32.to_be_bytes()); // buffer_id: OFP_NO_BUFFER
                body.extend_from_slice(&0xFFFF_FFFF_u32.to_be_bytes()); // out_port: OFPP_ANY
                body.extend_from_slice(&0xFFFF_FFFF_u32.to_be_bytes()); // out_group: OFPG_ANY
                body.extend_from_slice(&0_u16.to_be_bytes()); // flags
                body.extend_from_slice(&[0, 0]); // pad
                // ofp_match: OFPMT_OXM (1), length 4, 4 bytes pad
                body.extend_from_slice(&1_u16.to_be_bytes());
                body.extend_from_slice(&4_u16.to_be_bytes());
                body.extend_from_slice(&[0, 0, 0, 0]);
            }
            _ => {
                if let Some(dpid) = spec.dpid {
                    body.extend_from_slice(&dpid.to_be_bytes());
                }
                if let Some(table_id) = spec.table_id {
                    body.push(table_id);
                }
                if let Some(priority) = spec.priority {
                    body.extend_from_slice(&priority.to_be_bytes());
                }
            }
        }
    } else {
        body.extend_from_slice(payload);
    }

    let total_len = (8 + body.len()) as u16;
    let mut of = Vec::with_capacity(total_len as usize);
    of.push(version);
    of.push(of_type);
    of.extend_from_slice(&total_len.to_be_bytes());
    of.extend_from_slice(&spec.xid.unwrap_or(1).to_be_bytes());
    of.extend_from_slice(&body);

    (of, 6653)
}

