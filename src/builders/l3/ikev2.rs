//! IKEV2 Layer 3 protocol wire builder.

use crate::ast::*;
use alloc::vec::Vec;

/// Builds an RFC 7296 IKEv2 payload over UDP 500.
pub fn build_ikev2_payload(spec: &Ikev2Spec, payload: &[u8]) -> (Vec<u8>, u16) {
    let init_spi = spec.initiator_spi.unwrap_or(0x0102_0304_0506_0708);
    let resp_spi = spec.responder_spi.unwrap_or(0);
    let exchange = match spec.exchange.unwrap_or(IkeExchange::SaInit) {
        IkeExchange::SaInit => 34,
        IkeExchange::Auth => 35,
        IkeExchange::CreateChildSa => 36,
        IkeExchange::Informational => 37,
    };
    let flags = spec.flags.unwrap_or(0x08); // Initiator
    let msgid = spec.msgid.unwrap_or(0);
    let total_len = (28 + payload.len()) as u32;

    let mut ike = Vec::with_capacity(28 + payload.len());
    ike.extend_from_slice(&init_spi.to_be_bytes());
    ike.extend_from_slice(&resp_spi.to_be_bytes());
    ike.push(spec.next_payload.unwrap_or(0));
    ike.push(0x20); // Version 2.0
    ike.push(exchange);
    ike.push(flags);
    ike.extend_from_slice(&msgid.to_be_bytes());
    ike.extend_from_slice(&total_len.to_be_bytes());
    ike.extend_from_slice(payload);

    (ike, 500)
}
