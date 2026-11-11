//! Bidirectional Forwarding Detection (BFD, RFC 5880) Layer 3 PCAP-to-`.fasm` decompiler.
//!
//! This module implements the fuzz-safe PCAP and PCAPNG decompiler for RFC 5880 / RFC 5881
//! Bidirectional Forwarding Detection (`bfd`) control packets carried over UDP ports `3784`
//! (single-hop) and `4784` (multi-hop). It validates the 24-byte BFD v1 control header and decodes
//! session `state`, diagnostic code (`diag`), detection multiplier (`mult`), `mydisc`,
//! `yourdisc`, `mintx`, and `minrx` timer intervals into canonical `.fasm` tokens.

use alloc::string::String;

use crate::ast::Protocol;
use crate::reverse::{ProtocolDissection, be_u32, push_if, sd};

/// Decompiles an RFC 5880 `bfd` UDP payload (ports `3784` / `4784`) into a [`ProtocolDissection`].
pub(crate) fn dissect_bfd(b: &[u8]) -> Option<ProtocolDissection> {
    if b.len() < 24 || (b[0] >> 5) != 1 {
        return None;
    }
    let mut t = String::from("bfd");
    push_if(&mut t, "state", (b[1] >> 6) & 0x03, 3);
    push_if(&mut t, "diag", b[0] & 0x1F, 0);
    push_if(&mut t, "mult", b[2], 3);
    push_if(&mut t, "mydisc", be_u32(b, 4), 1);
    push_if(&mut t, "yourdisc", be_u32(b, 8), 0);
    push_if(&mut t, "mintx", be_u32(b, 12), 1_000_000);
    push_if(&mut t, "minrx", be_u32(b, 16), 1_000_000);
    Some(sd(Protocol::Bfd, t, b[24..].to_vec()))
}
