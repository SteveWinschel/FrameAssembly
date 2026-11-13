//! IPsec Encapsulating Security Payload (ESP, RFC 4303) Layer 3 PCAP-to-`.frasm` decompiler.
//!
//! This module implements the fuzz-safe PCAP and PCAPNG decompiler for RFC 4303 IPsec
//! Encapsulating Security Payload (`esp`) packets carried directly over IPv4 or IPv6 with protocol
//! / Next Header number `50` (`0x32`). It decodes the 32-bit Security Parameters Index (`spi`),
//! Sequence Number (`seq`), 8-byte Initialization Vector (`iv`), ESP trailer Next Header
//! (`nextheader`), 12-byte Integrity Check Value (`icv`), and ciphertext body into canonical
//! `.frasm` tokens.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write as _;

use crate::ast::Protocol;
use crate::reverse::{ProtocolDissection, be_u32, bytes_to_hex_lower, push_hex, push_if, sd};

/// Decompiles an RFC 4303 `esp` / `ipsec` packet (`ip_proto == 50`) into a [`ProtocolDissection`].
pub(crate) fn dissect_esp(b: &[u8]) -> ProtocolDissection {
    if b.len() < 8 {
        return sd(Protocol::Esp, String::from("esp"), b.to_vec());
    }
    let (spi, seq, mut t, mut res) = (be_u32(b, 0), be_u32(b, 4), String::from("esp"), Vec::new());
    push_hex(&mut t, "spi", u64::from(spi), 0x1000, 1);
    push_if(&mut t, "seq", seq, 1);
    let rest = &b[8..];
    if rest.len() >= 22 && rest[rest.len() - 14] == 0 {
        let (iv, cipher, nh, icv) = (
            &rest[..8],
            &rest[8..rest.len() - 14],
            rest[rest.len() - 13],
            &rest[rest.len() - 12..],
        );
        if iv != [0u8; 8] {
            let _ = write!(t, " iv \"{}\"", bytes_to_hex_lower(iv));
        }
        push_if(&mut t, "nextheader", nh, 59);
        if icv != [0u8; 12] {
            let _ = write!(t, " icv \"{}\"", bytes_to_hex_lower(icv));
        }
        if cipher != [0xAA; 16] {
            res.extend_from_slice(cipher);
        }
    } else {
        res.extend_from_slice(rest);
    }
    sd(Protocol::Esp, t, res)
}
