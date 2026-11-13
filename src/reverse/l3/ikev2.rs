//! Internet Key Exchange v2 (IKEv2, RFC 7296) Layer 3 PCAP-to-`.frasm` decompiler.
//!
//! This module implements the fuzz-safe PCAP and PCAPNG decompiler for RFC 7296 Internet Key
//! Exchange v2 (`ikev2`) control messages carried over UDP ports `500` and `4500`. It validates
//! the 28-byte IKEv2 header and version byte (`0x20`) and extracts exchange subtype (`sainit`,
//! `createchildsa`, `informational`), 64-bit `initiatorspi` and `responderspi`,
//! `nextpayload`, `flags`, and `msgid` into canonical `.frasm` tokens.

use alloc::string::String;

use crate::ast::Protocol;
use crate::reverse::{ProtocolDissection, be_u32, be_u64, push_hex, push_if, sd};

/// Decompiles an RFC 7296 `ikev2` UDP payload (ports `500` and `4500`) into a [`ProtocolDissection`].
pub(crate) fn dissect_ikev2(b: &[u8]) -> Option<ProtocolDissection> {
    if b.len() < 28 || b[17] != 0x20 {
        return None;
    }
    let (ispi, rspi, np, et, fl, mid) = (
        be_u64(b, 0),
        be_u64(b, 8),
        b[16],
        b[18],
        b[19],
        be_u32(b, 20),
    );
    let mut t = String::from("ikev2");
    match et {
        36 => t.push_str(" createchildsa"),
        37 => t.push_str(" informational"),
        _ => t.push_str(" sainit"),
    }
    push_hex(&mut t, "initiatorspi", ispi, 0x0102_0304_0506_0708, 16);
    push_hex(&mut t, "responderspi", rspi, 0, 16);
    push_if(&mut t, "nextpayload", np, 0);
    push_hex(&mut t, "flags", u64::from(fl), 0x08, 2);
    push_if(&mut t, "msgid", mid, 0);
    Some(sd(Protocol::Ikev2, t, b[28..].to_vec()))
}
