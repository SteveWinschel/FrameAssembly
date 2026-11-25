//! Internet Key Exchange v2 (IKEv2, RFC 7296) Layer 3 PCAP-to-`.frasm` decompiler.
//!
//! This module implements the fuzz-safe PCAP and PCAPNG decompiler for RFC 7296 Internet Key
//! Exchange v2 (`ikev2`) control messages carried over UDP ports `500` and `4500`. It validates
//! the 28-byte IKEv2 header and version byte (`0x20`), extracts exchange subtype (`sainit`,
//! `auth`, `createchildsa`, `informational`), 64-bit `initiatorspi` and `responderspi`,
//! `nextpayload`, `flags`, and `msgid`, and elides default `SAi1+KEi+Ni` / `SAr1+KEr+Nr` / `SK`
//! payloads into canonical `.frasm` tokens.

use alloc::string::String;
use alloc::vec::Vec;

use crate::ast::{IkeExchange, Protocol};
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
    let (kw, ex_enum) = match et {
        35 => (" auth", IkeExchange::Auth),
        36 => (" createchildsa", IkeExchange::CreateChildSa),
        37 => (" informational", IkeExchange::Informational),
        _ => (" sainit", IkeExchange::SaInit),
    };
    let mut t = String::from("ikev2");
    t.push_str(kw);
    push_hex(&mut t, "initiatorspi", ispi, 0x0102_0304_0506_0708, 16);
    push_hex(&mut t, "responderspi", rspi, 0, 16);
    let (def_np, def_body) =
        crate::builders::l3::ikev2::default_ikev2_payload(ex_enum, (fl & 0x20) != 0);
    let body = &b[28..];
    let is_default_body = np == def_np && body == def_body.as_slice();
    if !is_default_body {
        push_if(&mut t, "nextpayload", np, 0);
    }
    push_hex(&mut t, "flags", u64::from(fl), 0x08, 2);
    push_if(&mut t, "msgid", mid, 0);
    let res = if is_default_body {
        Vec::new()
    } else {
        body.to_vec()
    };
    Some(sd(Protocol::Ikev2, t, res))
}
