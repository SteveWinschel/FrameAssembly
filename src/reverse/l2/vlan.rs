//! IEEE 802.1Q Virtual LAN (VLAN) tag peeler and standalone Layer 2 decompiler.
//!
//! This module implements outer IEEE 802.1Q (`0x8100`) and IEEE 802.1ad (`0x88A8` / `0x9100`) tag
//! peeling ([`peel_vlan_or_qinq`]) as well as standalone `vlan` frame decompilation
//! ([`dissect_vlan`]) for FrameAssembly's PCAP and PCAPNG reverse decompiler. It extracts the
//! 12-bit VLAN Identifier (`vlan`), 3-bit Priority Code Point (`pcp`), and 1-bit Drop Eligible
//! Indicator (`dei`) from the Tag Control Information (TCI) word.

use alloc::format;
use alloc::vec::Vec;

use crate::ast::{L2Modifiers, Protocol, QinqSpec, VlanSpec};
use crate::reverse::{ProtocolDissection, be_u16, push_if, sd};

/// Peels outer IEEE 802.1ad `QINQ` or single 802.1Q `VLAN` tags from `b` at `*off`, updating `*et`
/// and `*l2`, and returning `(qinq_pcp, qinq_dei)`.
pub(crate) fn peel_vlan_or_qinq(
    b: &[u8],
    et: &mut u16,
    off: &mut usize,
    l2: &mut L2Modifiers,
) -> (u8, u8) {
    let (mut qp, mut qd) = (0u8, 0u8);
    if matches!(*et, 0x88A8 | 0x8100 | 0x9100) && *off + 4 <= b.len() {
        let (tci1, et1) = (be_u16(b, *off), be_u16(b, *off + 2));
        let (pcp, dei) = (((tci1 >> 13) & 0x07) as u8, ((tci1 >> 12) & 0x01) as u8);
        if et1 == 0x8100 && *off + 8 <= b.len() {
            let tci2 = be_u16(b, *off + 4);
            *et = be_u16(b, *off + 6);
            *off += 8;
            (qp, qd) = (pcp, dei);
            l2.qinq = Some(QinqSpec {
                outer_vid: tci1 & 0x0FFF,
                inner_vid: Some(tci2 & 0x0FFF),
            });
            if qp != 0 || qd != 0 {
                l2.vlan = Some(VlanSpec {
                    vid: 1,
                    pcp: (qp != 0).then_some(qp),
                    dei: (qd != 0).then_some(qd),
                });
            }
        } else if *et == 0x88A8 {
            *off += 4;
            *et = et1;
            (qp, qd) = (pcp, dei);
            l2.qinq = Some(QinqSpec {
                outer_vid: tci1 & 0x0FFF,
                inner_vid: None,
            });
            if qp != 0 || qd != 0 {
                l2.vlan = Some(VlanSpec {
                    vid: 1,
                    pcp: (qp != 0).then_some(qp),
                    dei: (qd != 0).then_some(qd),
                });
            }
        } else {
            *off += 4;
            *et = et1;
            l2.vlan = Some(VlanSpec {
                vid: tci1 & 0x0FFF,
                pcp: (pcp != 0).then_some(pcp),
                dei: (dei != 0).then_some(dei),
            });
        }
    }
    (qp, qd)
}

/// Formats a standalone `vlan` [`ProtocolDissection`] from an optional [`VlanSpec`] and residual payload.
pub(crate) fn dissect_vlan(v: Option<&VlanSpec>, res: Vec<u8>) -> ProtocolDissection {
    let mut t = format!("vlan {}", v.map_or(1, |s| s.vid));
    if let Some(s) = v {
        push_if(&mut t, "pcp", s.pcp.unwrap_or(0), 0);
        push_if(&mut t, "dei", s.dei.unwrap_or(0), 0);
    }
    sd(Protocol::Vlan, t, res)
}
