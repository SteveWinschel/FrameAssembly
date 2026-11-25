//! Network Service Header (NSH, RFC 8300) Layer 2 PCAP-to-`.frasm` decompiler.
//!
//! This module implements the fuzz-safe PCAP and PCAPNG decompiler for RFC 8300 Network Service
//! Header (`nsh`, EtherType `0x894F`) frames in FrameAssembly. It validates the 4-byte Base
//! Header and 4-byte Service Path Header, extracts `version`, `oam`, `ttl`, `mdtype`,
//! `nextproto`, `spi`, `si`, and fixed (`MD Type 1`) or variable (`MD Type 2`) `context`
//! metadata bytes, and elides FrameAssembly's default inner Ethernet, IPv4, IPv6, or MPLS stub
//! payloads for clean roundtrip decompilation.

use alloc::string::String;
use core::fmt::Write as _;

use crate::ast::Protocol;
use crate::reverse::{ProtocolDissection, bytes_to_hex_lower, push_if, sd};

/// Decompiles an RFC 8300 `nsh` Ethernet payload (`0x894F`) into a [`ProtocolDissection`].
pub(crate) fn dissect_nsh(b: &[u8]) -> Option<ProtocolDissection> {
    if b.len() < 8 {
        return None;
    }
    let b0 = b[0];
    let b1 = b[1];
    let ver = (b0 >> 6) & 0x03;
    let oam = (b0 & 0x20) != 0;
    let ttl = ((b0 & 0x0F) << 2) | ((b1 >> 6) & 0x03);
    let len_words = (b1 & 0x3F) as usize;
    let md_type = b[2] & 0x0F;
    let next_proto = b[3];

    let hdr_len = len_words.checked_mul(4)?;
    if hdr_len < 8 || hdr_len > b.len() {
        return None;
    }
    if md_type == 1 && hdr_len != 24 {
        return None;
    }

    let sph = u32::from_be_bytes([b[4], b[5], b[6], b[7]]);
    let spi = sph >> 8;
    let si = (sph & 0xFF) as u8;

    let mut t = String::from("nsh");
    push_if(&mut t, "version", ver, 0);
    if oam {
        t.push_str(" oam");
    }
    push_if(&mut t, "ttl", ttl, 63);
    push_if(&mut t, "mdtype", md_type, 1);
    push_if(&mut t, "nextproto", next_proto, 0x03);
    push_if(&mut t, "spi", spi, 1);
    push_if(&mut t, "si", si, 255);

    let ctx_slice = b.get(8..hdr_len)?;
    if md_type == 1 {
        if ctx_slice.iter().any(|&x| x != 0) {
            let _ = write!(t, " context \"{}\"", bytes_to_hex_lower(ctx_slice));
        }
    } else if !ctx_slice.is_empty() {
        let _ = write!(t, " context \"{}\"", bytes_to_hex_lower(ctx_slice));
    }

    let inner = b.get(hdr_len..)?;
    let is_default_inner = match next_proto {
        0x03 => crate::reverse::l3::is_default_overlay_inner(inner),
        0x01 => {
            inner
                == crate::builders::l3::gre::default_gre_inner_packet(0x0800).as_slice()
        }
        0x02 => {
            inner
                == crate::builders::l3::gre::default_gre_inner_packet(0x86DD).as_slice()
        }
        0x05 => {
            inner.strip_prefix(&[0x00, 0x01, 0x01, 0x40]).is_some_and(|rest| {
                rest == crate::builders::l3::gre::default_gre_inner_packet(0x0800).as_slice()
            })
        }
        _ => inner == b"FrameAssembly NSH Data",
    };
    let rem = if is_default_inner {
        alloc::vec::Vec::new()
    } else {
        inner.to_vec()
    };

    Some(sd(Protocol::Nsh, t, rem))
}
