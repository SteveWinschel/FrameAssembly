//! IPsec security suite (RFC 4303 ESP & RFC 4302 AH) Layer 3 PCAP-to-`.fasm` decompiler facade.
//!
//! This module provides the `ipsec` Layer 3 decompiler entry point ([`dissect_ipsec`]) for the
//! FrameAssembly PCAP and PCAPNG decompiler, delegating IP protocol `50` (`0x32`) Encapsulating
//! Security Payload frames to [`super::esp::dissect_esp`] while maintaining one-to-one structural
//! symmetry with `src/ast/l3/ipsec.rs`, `src/parser/l3/ipsec.rs`, and `src/builders/l3/ipsec.rs`.
//! Encrypted ciphertext payloads are never decrypted, preserving unencrypted header parameters and
//! residual payload bytes for lossless round-trip compilation.

use crate::reverse::ProtocolDissection;

/// Decompiles an RFC 4303 `ipsec` / `esp` packet (`ip_proto == 50`) into a [`ProtocolDissection`].
pub(crate) fn dissect_ipsec(b: &[u8]) -> ProtocolDissection {
    super::esp::dissect_esp(b)
}
