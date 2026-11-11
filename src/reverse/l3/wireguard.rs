//! WireGuard Noise_IK Cryptographic VPN Tunnel Layer 3 PCAP-to-`.fasm` decompiler.
//!
//! This module implements the fuzz-safe PCAP and PCAPNG decompiler for `wireguard` VPN packets
//! carried over UDP port `51820`. It validates the 4-byte message type (`1..=4`) and zeroed
//! reserved bytes, and decodes handshake `initiation` (`sender`), handshake `response` (`sender`,
//! `receiver`), `cookie` reply (`receiver`), and transport `data` (`receiver`, `counter`) messages
//! into canonical `.fasm` statements.

use alloc::string::String;
use alloc::vec::Vec;

use crate::ast::Protocol;
use crate::reverse::{ProtocolDissection, le_u32, push_if, sd};

/// Decompiles a `wireguard` UDP payload (port `51820`) into a [`ProtocolDissection`].
pub(crate) fn dissect_wireguard(b: &[u8]) -> Option<ProtocolDissection> {
    if b.len() < 16 || !matches!(b[0], 1..=4) || b[1..4] != [0, 0, 0] {
        return None;
    }
    let mut t = String::from("wireguard");
    let res = match b[0] {
        1 if b.len() >= 148 => {
            t.push_str(" initiation");
            push_if(&mut t, "sender", le_u32(b, 4), 1);
            b[148..].to_vec()
        }
        2 if b.len() >= 92 => {
            t.push_str(" response");
            push_if(&mut t, "sender", le_u32(b, 4), 1);
            push_if(&mut t, "receiver", le_u32(b, 8), 2);
            b[92..].to_vec()
        }
        3 if b.len() >= 64 => {
            t.push_str(" cookie");
            push_if(&mut t, "receiver", le_u32(b, 4), 1);
            b[64..].to_vec()
        }
        4 => {
            t.push_str(" data");
            let mut ctr = [0u8; 8];
            ctr.copy_from_slice(&b[8..16]);
            push_if(&mut t, "receiver", le_u32(b, 4), 1);
            push_if(&mut t, "counter", u64::from_le_bytes(ctr), 0);
            if b[16..] == [0u8; 16] {
                Vec::new()
            } else {
                b[16..].to_vec()
            }
        }
        _ => return None,
    };
    Some(sd(Protocol::Wireguard, t, res))
}
