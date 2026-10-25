//! WireGuard Next-Generation Secure Network Tunnel (`Noise_IKpsk2`) AST definitions.
//!
//! Defines the modern cryptographic VPN protocol designed by Jason A. Donenfeld and carried over
//! UDP port `51820`. WireGuard combines the `Noise_IKpsk2` handshake framework (Curve25519 ECDH,
//! BLAKE2s hashing, HKDF, and ChaCha20-Poly1305 AEAD) with four fixed-layout little-endian message
//! types: Type `1` Handshake `INITIATION` (`148` bytes, carrying `sender_index`, 32B ephemeral key,
//! 48B encrypted static key, 28B encrypted TAI64N timestamp, and two 16B BLAKE2s MACs), Type `2`
//! Handshake `RESPONSE` (`92` bytes, carrying `sender_index` and `receiver_index`), Type `3` `COOKIE`
//! Reply (`64` bytes, carrying `receiver_index`, 24B XChaCha20-Poly1305 nonce, and 32B encrypted cookie
//! for DoS mitigation), and Type `4` Transport `DATA` (`16`B header with `receiver_index` and 64-bit `counter`).
//!
//! Canonical `.fasm` syntax:
//! `a -> b WIREGUARD [TYPE <INITIATION|RESPONSE|COOKIE|DATA> | INITIATION | COOKIE | DATA] [SENDER <u32>] [RECEIVER <u32>] [COUNTER <u64>] [PAYLOAD "<str>" | HEXPAYLOAD "<hex>"]`

use core::marker::PhantomData;

/// WireGuard protocol message type (`1..=4`).
#[doc(alias = "WgMessageType")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireguardType {
    /// Type `1` (`INITIATION`): 148-byte `Noise_IKpsk2` Handshake Initiation message.
    Initiation,
    /// Type `2` (`RESPONSE`): 92-byte `Noise_IKpsk2` Handshake Response message.
    Response,
    /// Type `3` (`COOKIE`): 64-byte Cookie Reply message mitigating stateless CPU-exhaustion DoS attacks.
    Cookie,
    /// Type `4` (`DATA`): ChaCha20-Poly1305 authenticated transport data frame with a 64-bit anti-replay counter.
    Data,
}

/// WireGuard cryptographic VPN tunnel specification over UDP port `51820`.
///
/// Syntax mapping: `WIREGUARD [TYPE <INITIATION|RESPONSE|COOKIE|DATA> | INITIATION | COOKIE | DATA] [SENDER <u32>] [RECEIVER <u32>] [COUNTER <u64>]`
#[doc(alias = "WIREGUARD")]
#[doc(alias = "WireGuard")]
#[doc(alias = "Noise_IK")]
#[doc(alias = "RFC 8439")]
#[doc(alias = "51820")]
#[doc(alias = "ChaCha20Poly1305")]
#[doc(alias = "INITIATION")]
#[doc(alias = "RESPONSE")]
#[doc(alias = "COOKIE")]
#[doc(alias = "DATA")]
#[doc(alias = "SENDER")]
#[doc(alias = "RECEIVER")]
#[doc(alias = "COUNTER")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct WireguardSpec<'a> {
    /// WireGuard packet type (`INITIATION` `1`, `RESPONSE` `2`, `COOKIE` `3`, or `DATA` `4`; default `INITIATION`).
    pub msg_type: Option<WireguardType>,
    /// 32-bit little-endian Sender session index (`SENDER <u32>`, default `1`).
    pub sender: Option<u32>,
    /// 32-bit little-endian Receiver session index (`RECEIVER <u32>`, default `1` or `2`).
    pub receiver: Option<u32>,
    /// 64-bit little-endian ChaCha20-Poly1305 nonce / anti-replay packet counter for `DATA` frames (`COUNTER <u64>`, default `0`).
    pub counter: Option<u64>,
    /// Optional lifetime phantom marker for AST uniformity.
    pub _marker: PhantomData<&'a ()>,
}
