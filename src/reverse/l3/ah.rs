//! IPsec Authentication Header (AH, RFC 4302) Layer 3 PCAP-to-`.fasm` decompiler.
//!
//! This module implements the fuzz-safe PCAP and PCAPNG decompiler for RFC 4302 IPsec
//! Authentication Header (`AH`) packets carried directly over IPv4 or IPv6 with protocol / Next
//! Header number `51` (`0x33`). It extracts the Next Header (`next_header`), 32-bit Security
//! Parameters Index (`spi`), anti-replay Sequence Number (`seq`), variable-length Integrity Check
//! Value (`icv`), and any encapsulated inner payload bytes into canonical `.fasm` tokens.

use alloc::string::String;
use core::fmt::Write as _;

use crate::ast::Protocol;
use crate::reverse::{ProtocolDissection, be_u32, bytes_to_hex_lower, push_hex, push_if, sd};

/// Decompiles an RFC 4302 `AH` packet (`ip_proto == 51`) into a [`ProtocolDissection`].
pub(crate) fn dissect_ah(b: &[u8]) -> ProtocolDissection {
    let ah_len = ((b.get(1).copied().unwrap_or(4) as usize) + 2) * 4;
    if b.len() < 12 || b.len() < ah_len {
        return sd(Protocol::Ah, String::from("ah"), b.to_vec());
    }
    let mut t = String::from("ah");
    push_if(&mut t, "next_header", b[0], 59);
    push_hex(&mut t, "spi", u64::from(be_u32(b, 4)), 0x2000, 1);
    push_if(&mut t, "seq", be_u32(b, 8), 1);
    let icv = &b[12..ah_len];
    if icv != [0u8; 12] {
        let _ = write!(t, " icv \"{}\"", bytes_to_hex_lower(icv));
    }
    sd(Protocol::Ah, t, b[ah_len..].to_vec())
}
