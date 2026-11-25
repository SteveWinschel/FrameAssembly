//! WireGuard Next-Generation Secure Network Tunnel (`Noise_IKpsk2`) Layer 3 wire builder.
//!
//! Serializes a [`WireguardSpec`] into a WireGuard protocol packet carried over UDP destination
//! port `51820`. All integer fields in WireGuard headers are encoded in little-endian byte order:
//! - `initiation` (`Type = 1`, 148 bytes): 3-byte zeroed Reserved, 32-bit LE `sender_index` (`sender`),
//!   32-byte unencrypted ephemeral Curve25519 public key, 48-byte encrypted static key, 28-byte
//!   encrypted TAI64N timestamp, 16-byte `mac1`, and 16-byte `mac2`.
//! - `response` (`Type = 2`, 92 bytes): 32-bit LE `sender_index`, 32-bit LE `receiver_index` (`receiver`),
//!   32-byte ephemeral key, 16-byte encrypted empty payload, and two 16-byte MAC tags.
//! - `cookie` (`Type = 3`, 64 bytes): 32-bit LE `receiver_index`, 24-byte nonce, and 32-byte cookie.
//! - `data` (`Type = 4`, `16 + payload` bytes): 32-bit LE `receiver_index` and 64-bit LE `counter` (`counter`).
//!
//! Canonical `.frasm` syntax:
//! `a -> b wireguard [type <initiation|response|cookie|data> | initiation | cookie | data] [sender <u32>] [receiver <u32>] [counter <u64>] [payload "<str>" | hexpayload "<hex>"]`

use crate::ast::*;
use alloc::vec::Vec;

/// Generates a deterministic non-zero byte sequence of length `N` seeded by `seed`.
fn deterministic_non_zero<const N: usize>(seed: u8) -> [u8; N] {
    let mut out = [0u8; N];
    let mut i = 0usize;
    while i < N {
        out[i] = seed.wrapping_add((i as u8).wrapping_mul(17)) | 1;
        i += 1;
    }
    out
}

/// Generates a deterministic valid clamped Curve25519 public key for WireGuard handshakes.
fn deterministic_curve25519_key(seed: u8) -> [u8; 32] {
    let mut key = deterministic_non_zero::<32>(seed);
    key[0] &= 0xF8;
    key[31] = (key[31] & 0x7F) | 0x40;
    key
}

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
            wg.extend_from_slice(&deterministic_curve25519_key(0x21)); // 32B Ephemeral key
            wg.extend_from_slice(&deterministic_non_zero::<48>(0x43)); // 48B Encrypted static
            wg.extend_from_slice(&deterministic_non_zero::<28>(0x65)); // 28B Encrypted timestamp
            wg.extend_from_slice(&deterministic_non_zero::<16>(0x87)); // 16B MAC1
            wg.extend_from_slice(&[0u8; 16]); // 16B MAC2 (zero when no cookie active)
        }
        WireguardType::Response => {
            wg.reserve(92);
            wg.push(2);
            wg.extend_from_slice(&[0, 0, 0]);
            wg.extend_from_slice(&spec.sender.unwrap_or(1).to_le_bytes());
            wg.extend_from_slice(&spec.receiver.unwrap_or(2).to_le_bytes());
            wg.extend_from_slice(&deterministic_curve25519_key(0x31)); // 32B Ephemeral key
            wg.extend_from_slice(&deterministic_non_zero::<16>(0x53)); // 16B Encrypted empty AEAD
            wg.extend_from_slice(&deterministic_non_zero::<16>(0x75)); // 16B MAC1
            wg.extend_from_slice(&[0u8; 16]); // 16B MAC2
        }
        WireguardType::Cookie => {
            wg.reserve(64);
            wg.push(3);
            wg.extend_from_slice(&[0, 0, 0]);
            wg.extend_from_slice(&spec.receiver.unwrap_or(1).to_le_bytes());
            wg.extend_from_slice(&deterministic_non_zero::<24>(0x91)); // 24B XChaCha20 nonce
            wg.extend_from_slice(&deterministic_non_zero::<32>(0xA3)); // 32B Encrypted cookie
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

