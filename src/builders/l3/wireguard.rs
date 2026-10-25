//! WireGuard Next-Generation Secure Network Tunnel (`Noise_IKpsk2`) Layer 3 wire builder.
//!
//! Serializes a [`WireguardSpec`] into a WireGuard protocol packet carried over UDP destination
//! port `51820`. All integer fields in WireGuard headers are encoded in little-endian byte order:
//! - `INITIATION` (`Type = 1`, 148 bytes): 3-byte zeroed Reserved, 32-bit LE `sender_index` (`SENDER`),
//!   32-byte unencrypted ephemeral Curve25519 public key, 48-byte encrypted static key, 28-byte
//!   encrypted TAI64N timestamp, 16-byte `mac1`, and 16-byte `mac2`.
//! - `RESPONSE` (`Type = 2`, 92 bytes): 32-bit LE `sender_index`, 32-bit LE `receiver_index` (`RECEIVER`),
//!   32-byte ephemeral key, 16-byte encrypted empty payload, and two 16-byte MAC tags.
//! - `COOKIE` (`Type = 3`, 64 bytes): 32-bit LE `receiver_index`, 24-byte nonce, and 32-byte cookie.
//! - `DATA` (`Type = 4`, `16 + payload` bytes): 32-bit LE `receiver_index` and 64-bit LE `counter` (`COUNTER`).
//!
//! Canonical `.fasm` syntax:
//! `a -> b WIREGUARD [TYPE <INITIATION|RESPONSE|COOKIE|DATA> | INITIATION | COOKIE | DATA] [SENDER <u32>] [RECEIVER <u32>] [COUNTER <u64>] [PAYLOAD "<str>" | HEXPAYLOAD "<hex>"]`

use crate::ast::*;
use alloc::vec::Vec;

/// Builds a WireGuard packet payload and returns `(bytes, 51820)` for UDP encapsulation.
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
            if payload.len() < 16 {
                // Append 16-byte Poly1305 AEAD authentication tag so Type 4 packets are >= 32 bytes
                wg.extend_from_slice(&[0u8; 16]);
            }
        }
    }

    (wg, 51820)
}

