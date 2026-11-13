//! Generic Routing Encapsulation (GRE, RFC 2784 / RFC 2890) Layer 3 PCAP-to-`.frasm` decompiler.
//!
//! This module implements the fuzz-safe PCAP and PCAPNG decompiler for RFC 2784 and RFC 2890
//! Generic Routing Encapsulation (`gre`) tunnel packets carried directly over IPv4 or IPv6 with
//! protocol / Next Header number `47` (`0x2F`). It inspects the GRE flag bits (`C`, `K`, `S`),
//! extracts the encapsulated EtherType (`greproto`), optional `checksum`, 32-bit `grekey`, and
//! 32-bit `greseq`, and strips the default synthesized inner payload when unchanged.

use alloc::string::String;
use core::fmt::Write as _;

use crate::ast::Protocol;
use crate::reverse::{ProtocolDissection, be_u16, be_u32, push_hex, sd};

/// Decompiles an RFC 2784 / RFC 2890 `gre` header (`ip_proto == 47`) into a [`ProtocolDissection`].
pub(crate) fn dissect_gre(b: &[u8]) -> ProtocolDissection {
    if b.len() < 4 {
        return sd(Protocol::Gre, String::from("gre"), b.to_vec());
    }
    let (flags, proto, mut pos, mut t) = (be_u16(b, 0), be_u16(b, 2), 4usize, String::from("gre"));
    push_hex(&mut t, "greproto", u64::from(proto), 0x0800, 4);
    if (flags & 0x8000) != 0 && pos + 4 <= b.len() {
        t.push_str(" checksum");
        pos += 4;
    }
    if (flags & 0x2000) != 0 && pos + 4 <= b.len() {
        let _ = write!(t, " grekey {}", be_u32(b, pos));
        pos += 4;
    }
    if (flags & 0x1000) != 0 && pos + 4 <= b.len() {
        let _ = write!(t, " greseq {}", be_u32(b, pos));
        pos += 4;
    }
    let rem = if &b[pos..] == b"FrameAssembly GRE Inner Packet" {
        &[][..]
    } else {
        &b[pos..]
    };
    sd(Protocol::Gre, t, rem.to_vec())
}
