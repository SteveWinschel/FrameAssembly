//! WIREGUARD Layer 3 protocol wire builder.

use crate::ast::*;
use alloc::vec::Vec;

/// Builds a WireGuard packet payload over UDP 51820.
pub fn build_wireguard_payload(spec: &WireguardSpec, payload: &[u8]) -> (Vec<u8>, u16) {
    let msg_type = spec.msg_type.unwrap_or(WireguardType::Initiation);
    let mut wg = Vec::new();

    match msg_type {
        WireguardType::Initiation => {
            wg.reserve(148);
            wg.push(1); // Type 1: Handshake Initiation
            wg.extend_from_slice(&[0, 0, 0]); // Reserved
            let sender = spec.sender.unwrap_or(1);
            wg.extend_from_slice(&sender.to_le_bytes());
            wg.extend_from_slice(&[0u8; 32]); // Ephemeral key
            wg.extend_from_slice(&[0u8; 48]); // Encrypted static
            wg.extend_from_slice(&[0u8; 28]); // Encrypted timestamp
            wg.extend_from_slice(&[0u8; 16]); // MAC1
            wg.extend_from_slice(&[0u8; 16]); // MAC2
        }
        WireguardType::Response => {
            wg.reserve(92);
            wg.push(2);
            wg.extend_from_slice(&[0, 0, 0]);
            wg.extend_from_slice(&spec.sender.unwrap_or(1).to_le_bytes());
            wg.extend_from_slice(&spec.receiver.unwrap_or(2).to_le_bytes());
            wg.extend_from_slice(&[0u8; 32]); // Ephemeral
            wg.extend_from_slice(&[0u8; 16]); // Empty
            wg.extend_from_slice(&[0u8; 16]); // MAC1
            wg.extend_from_slice(&[0u8; 16]); // MAC2
        }
        WireguardType::Cookie => {
            wg.reserve(64);
            wg.push(3);
            wg.extend_from_slice(&[0, 0, 0]);
            wg.extend_from_slice(&spec.receiver.unwrap_or(1).to_le_bytes());
            wg.extend_from_slice(&[0u8; 24]); // Nonce
            wg.extend_from_slice(&[0u8; 32]); // Cookie
        }
        WireguardType::Data => {
            wg.reserve(32 + payload.len());
            wg.push(4);
            wg.extend_from_slice(&[0, 0, 0]);
            wg.extend_from_slice(&spec.receiver.unwrap_or(1).to_le_bytes());
            wg.extend_from_slice(&spec.counter.unwrap_or(0).to_le_bytes());
            wg.extend_from_slice(payload);
        }
    }

    (wg, 51820)
}
