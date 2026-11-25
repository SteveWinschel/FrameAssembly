//! IEEE 802.1Q Virtual LAN (VLAN) tag peeler and standalone Layer 2 decompiler.
//!
//! This module implements multi-tag IEEE 802.1Q (`0x8100` / `0x9100`) and IEEE 802.1ad (`0x88A8`)
//! tag stack peeling ([`peel_vlan_or_qinq`]) as well as standalone `vlan` frame decompilation
//! ([`dissect_vlan`]) for FrameAssembly's PCAP and PCAPNG reverse decompiler. It extracts stacked
//! 12-bit VLAN Identifiers (`vlan` / `qinq` + `innervlan`), preserving `vlan 0`, 3-bit Priority
//! Code Point (`pcp`), and 1-bit Drop Eligible Indicator (`dei`) fields from each TCI word.

use alloc::format;
use alloc::vec::Vec;

use crate::ast::{L2Modifiers, Protocol, QinqSpec, VlanSpec};
use crate::reverse::{ProtocolDissection, be_u16, push_if, sd};

/// Peels one or more stacked IEEE 802.1ad `qinq` or 802.1Q `vlan` tags from `b` at `*off`,
/// updating `*et` and `*l2`, preserving `vlan 0`, and returning `(qinq_pcp, qinq_dei)`.
pub(crate) fn peel_vlan_or_qinq(
    b: &[u8],
    et: &mut u16,
    off: &mut usize,
    l2: &mut L2Modifiers,
) -> (u8, u8) {
    let mut tags: Vec<(u16, u16, u8, u8)> = Vec::new();
    while matches!(*et, 0x88A8 | 0x8100 | 0x9100) && *off + 4 <= b.len() && tags.len() < 16 {
        let tpid = *et;
        let (tci, next_et) = (be_u16(b, *off), be_u16(b, *off + 2));
        let pcp = ((tci >> 13) & 0x07) as u8;
        let dei = ((tci >> 12) & 0x01) as u8;
        let vid = tci & 0x0FFF;
        tags.push((tpid, vid, pcp, dei));
        *et = next_et;
        *off += 4;
    }

    match tags.len() {
        0 => (0, 0),
        1 => {
            let (tpid, vid, pcp, dei) = tags[0];
            if tpid == 0x88A8 {
                l2.qinq = Some(QinqSpec {
                    outer_vid: vid,
                    inner_vid: None,
                    pcp: (pcp != 0).then_some(pcp),
                    dei: (dei != 0).then_some(dei),
                });
                (pcp, dei)
            } else {
                l2.vlan = Some(VlanSpec {
                    vid,
                    pcp: (pcp != 0).then_some(pcp),
                    dei: (dei != 0).then_some(dei),
                });
                (0, 0)
            }
        }
        _ => {
            let (_, outer_vid, qp, qd) = tags[0];
            let (_, inner_vid, _, _) = tags[tags.len() - 1];
            l2.qinq = Some(QinqSpec {
                outer_vid,
                inner_vid: Some(inner_vid),
                pcp: (qp != 0).then_some(qp),
                dei: (qd != 0).then_some(qd),
            });
            (qp, qd)
        }
    }
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
