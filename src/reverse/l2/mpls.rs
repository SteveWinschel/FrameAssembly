//! Multiprotocol Label Switching (MPLS, RFC 3032) Layer 2 shim header and standalone decompiler.
//!
//! This module implements RFC 3032 MPLS label stack shim peeling ([`peel_mpls`]) and standalone
//! `mpls` frame decompilation ([`dissect_mpls`]) for FrameAssembly's PCAP and PCAPNG reverse
//! decompiler (`EtherType 0x8847` unicast and `0x8848` multicast). It extracts the 20-bit label
//! (`mpls`), 3-bit traffic class / experimental bits (`exp`), 1-bit bottom-of-stack indicator
//! (`bos`), and 8-bit time-to-live (`mplsttl`) while inferring inner L2/L3 protocol framing.

use alloc::format;
use alloc::vec::Vec;

use crate::ast::{L2Modifiers, MplsSpec, Protocol};
use crate::reverse::{ProtocolDissection, be_u32, push_if, sd};

/// Peels an RFC 3032 MPLS shim header (`0x8847` or `0x8848`) from `b` at `*off`, updating `*l2`
/// and inferring the inner protocol EtherType in `*et`.
pub(crate) fn peel_mpls(
    b: &[u8],
    dst_mac: [u8; 6],
    et: &mut u16,
    off: &mut usize,
    l2: &mut L2Modifiers,
) {
    if matches!(*et, 0x8847 | 0x8848) && *off + 4 <= b.len() {
        let shim = be_u32(b, *off);
        let (exp, bos, mttl) = (
            ((shim >> 9) & 0x07) as u8,
            ((shim >> 8) & 0x01) as u8,
            (shim & 0xFF) as u8,
        );
        l2.mpls = Some(MplsSpec {
            label: shim >> 12,
            exp: (exp != 0).then_some(exp),
            bos: (bos != 1).then_some(bos),
            ttl: (mttl != 64).then_some(mttl),
        });
        *off += 4;
        if *off + 28 <= b.len()
            && b[*off..*off + 6] == [0x00, 0x01, 0x08, 0x00, 0x06, 0x04]
            && matches!(b[*off + 6..*off + 8], [0x00, 0x01 | 0x02])
        {
            *et = 0x0806;
        } else if dst_mac == [0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e] && *off + 2 <= b.len() {
            *et = 0x88CC;
        } else if *off + 38 <= b.len() && b[*off..*off + 3] == [0x42, 0x42, 0x03] {
            *et = (b.len() - *off) as u16;
        } else if *off + 110 <= b.len() && b[*off..*off + 2] == [0x01, 0x01] {
            *et = 0x8809;
        } else if dst_mac == [0x01, 0x80, 0xc2, 0x00, 0x00, 0x03] && *off + 4 <= b.len() {
            *et = 0x888E;
        } else if let Some(&nib) = b.get(*off) {
            match nib >> 4 {
                4 if *off + 20 <= b.len() && (nib & 0x0f) >= 5 => *et = 0x0800,
                6 if *off + 40 <= b.len() => *et = 0x86DD,
                _ => {}
            }
        }
    }
}

/// Formats a standalone `mpls` [`ProtocolDissection`] from an [`MplsSpec`] and residual payload.
pub(crate) fn dissect_mpls(m: &MplsSpec, res: Vec<u8>) -> ProtocolDissection {
    let mut t = format!("mpls {}", m.label);
    push_if(&mut t, "exp", m.exp.unwrap_or(0), 0);
    push_if(&mut t, "bos", m.bos.unwrap_or(1), 1);
    push_if(&mut t, "mplsttl", m.ttl.unwrap_or(64), 64);
    sd(Protocol::Mpls, t, res)
}
