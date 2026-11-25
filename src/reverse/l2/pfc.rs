//! IEEE 802.1Qbb Priority-based Flow Control (`pfc`, EtherType `0x8808`) Layer 2 decompiler.
//!
//! This module implements the fuzz-safe PCAP and PCAPNG decompiler for IEEE 802.1Qbb / IEEE
//! 802.3bd MAC Control Priority Flow Control (`pfc`, EtherType `0x8808`, OpCode `0x0101`) frames.
//! It extracts the 16-bit Class Enable Vector (`enable`), detects uniform pause durations
//! (`quanta`) across enabled classes, emits per-priority timers (`q0`..`q7`) when asymmetric, and
//! cleanly strips the 26 trailing reserved zero bytes of the canonical 46-byte MAC Control SDU.

use alloc::string::String;
use core::fmt::Write as _;

use crate::ast::Protocol;
use crate::reverse::l7::checked_be_u16;
use crate::reverse::{ProtocolDissection, push_hex, push_if, sd};

/// Decompiles an IEEE 802.1Qbb `pfc` frame (`EtherType = 0x8808`, `OpCode = 0x0101`).
pub(crate) fn dissect_pfc(b: &[u8]) -> ProtocolDissection {
    if b.len() < 20 || checked_be_u16(b, 0) != Some(0x0101) {
        return sd(Protocol::Pfc, String::from("pfc"), b.to_vec());
    }

    let enable = checked_be_u16(b, 2).unwrap_or(0x00FF);
    let mut timers = [0u16; 8];
    for (idx, slot) in timers.iter_mut().enumerate() {
        *slot = checked_be_u16(b, 4 + idx * 2).unwrap_or(0);
    }

    let mut t = String::from("pfc");
    if enable == 0x00FF && timers.iter().all(|&q| q == timers[0]) {
        push_if(&mut t, "quanta", timers[0], 0xFFFF);
    } else {
        push_hex(&mut t, "enable", u64::from(enable), 0x00FF, 4);
        let mut enabled_count = 0usize;
        let mut uniform_q: Option<u16> = None;
        let mut uniform_ok = true;
        for (idx, &q) in timers.iter().enumerate() {
            if (enable & (1_u16 << idx)) != 0 {
                enabled_count += 1;
                match uniform_q {
                    None => uniform_q = Some(q),
                    Some(prev) if prev != q => uniform_ok = false,
                    _ => {}
                }
            } else if q != 0 {
                uniform_ok = false;
            }
        }
        if let Some(uq) = uniform_q
            && enabled_count >= 2
            && uniform_ok
            && uq != 0xFFFF
        {
            let _ = write!(t, " quanta {uq}");
        } else {
            for (idx, &q) in timers.iter().enumerate() {
                let expected = if (enable & (1_u16 << idx)) != 0 {
                    0xFFFF
                } else {
                    0
                };
                if q != expected {
                    let _ = write!(t, " q{idx} {q}");
                }
            }
        }
    }

    let residual = if b.len() >= 46 && b.get(20..46).is_some_and(|z| z.iter().all(|&x| x == 0)) {
        b.get(46..).unwrap_or(&[]).to_vec()
    } else {
        b.get(20..).unwrap_or(&[]).to_vec()
    };

    sd(Protocol::Pfc, t, residual)
}
