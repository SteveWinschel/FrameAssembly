//! Multiprotocol Label Switching (MPLS, RFC 3032) Layer 2 shim header and standalone decompiler.
//!
//! This module implements RFC 3032 multi-label MPLS stack shim peeling ([`peel_mpls`]) including
//! RFC 4448 EoMPLS PWE3 control-word unwrapping and standalone `mpls` / multi-label stack
//! decompilation ([`dissect_mpls`], [`dissect_mpls_stack`]) for FrameAssembly's PCAP and PCAPNG
//! reverse decompiler (`EtherType 0x8847` unicast and `0x8848` multicast). It extracts each
//! 20-bit label (`mpls`), 3-bit experimental field (`exp`), bottom-of-stack bit (`bos`), and
//! 8-bit TTL (`mplsttl`).

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write as _;

use crate::ast::{L2Modifiers, MplsSpec, Protocol};
use crate::reverse::{ProtocolDissection, be_u16, be_u32, push_if, sd};

/// Peels one or more RFC 3032 MPLS shim headers (`0x8847` or `0x8848`, looping while `bos == 0`)
/// and optional RFC 4448 EoMPLS PWE3 control words from `b` at `*off`, updating `*l2` and `*et`.
pub(crate) fn peel_mpls(
    b: &[u8],
    dst_mac: [u8; 6],
    et: &mut u16,
    off: &mut usize,
    l2: &mut L2Modifiers,
) {
    if !matches!(*et, 0x8847 | 0x8848) || *off + 4 > b.len() {
        return;
    }
    let mut stack = Vec::new();
    while *off + 4 <= b.len() && stack.len() < 16 {
        let shim = be_u32(b, *off);
        let (label, exp, bos, mttl) = (
            shim >> 12,
            ((shim >> 9) & 0x07) as u8,
            ((shim >> 8) & 0x01) as u8,
            (shim & 0xFF) as u8,
        );
        stack.push(MplsSpec {
            label,
            exp: (exp != 0).then_some(exp),
            bos: Some(bos),
            ttl: (mttl != 64).then_some(mttl),
        });
        *off += 4;
        if bos == 1 {
            break;
        }
    }
    let total = stack.len();
    for (idx, entry) in stack.iter_mut().enumerate() {
        let expected_bos = u8::from(idx + 1 == total);
        if entry.bos == Some(expected_bos) {
            entry.bos = None;
        }
    }
    l2.mpls = stack.first().cloned();
    l2.mpls_stack = stack;

    // Optional RFC 4448 EoMPLS 4-byte zero control word + 14-byte inner Ethernet header.
    if *off + 18 <= b.len() && b[*off..*off + 4] == [0x00, 0x00, 0x00, 0x00] {
        let inner_et = be_u16(b, *off + 16);
        let rem = b.len() - (*off + 18);
        let cw_body = &b[*off + 18..];
        let valid_cw = match inner_et {
            0x0800 => {
                rem >= 20
                    && (cw_body[0] >> 4) == 4
                    && usize::from(cw_body[0] & 0x0F) * 4 >= 20
                    && usize::from(be_u16(cw_body, 2)) <= rem
            }
            0x86DD => {
                rem >= 40
                    && (cw_body[0] >> 4) == 6
                    && 40usize.saturating_add(usize::from(be_u16(cw_body, 4))) <= rem
            }
            0x0806 => {
                rem >= 28
                    && cw_body[0..6] == [0x00, 0x01, 0x08, 0x00, 0x06, 0x04]
                    && matches!(cw_body[6..8], [0x00, 0x01 | 0x02])
            }
            0x88CC => rem >= 2,
            0x8809 => rem >= 110 && cw_body[0..2] == [0x01, 0x01],
            0x888E => rem >= 4,
            0..=1500 => {
                usize::from(inner_et) >= 3
                    && usize::from(inner_et) <= rem
                    && matches!(cw_body.get(0..3), Some([0x42, 0x42, 0x03] | [0xAA, 0xAA, 0x03]))
            }
            _ => false,
        };
        if valid_cw {
            *off += 18;
            *et = inner_et;
            return;
        }
    }

    let rem = b.len() - *off;
    let body = &b[*off..];
    if rem >= 28
        && body[0..6] == [0x00, 0x01, 0x08, 0x00, 0x06, 0x04]
        && matches!(body[6..8], [0x00, 0x01 | 0x02])
    {
        *et = 0x0806;
    } else if dst_mac == [0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e] && rem >= 2 {
        *et = 0x88CC;
    } else if (3..=1500).contains(&rem) && body[0..3] == [0x42, 0x42, 0x03] {
        *et = rem as u16;
    } else if rem >= 110 && body[0..2] == [0x01, 0x01] {
        *et = 0x8809;
    } else if dst_mac == [0x01, 0x80, 0xc2, 0x00, 0x00, 0x03] && rem >= 4 {
        *et = 0x888E;
    } else if let Some(&nib) = body.first() {
        match nib >> 4 {
            4 if rem >= 20 && usize::from(nib & 0x0f) * 4 >= 20 => {
                let total_len = usize::from(be_u16(body, 2));
                let ihl = usize::from(nib & 0x0f) * 4;
                if total_len >= ihl && total_len <= rem {
                    *et = 0x0800;
                }
            }
            6 if rem >= 40 => {
                let plen = usize::from(be_u16(body, 4));
                if 40usize.saturating_add(plen) <= rem && body[7] > 0 {
                    *et = 0x86DD;
                }
            }
            _ => {}
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

/// Formats a standalone single- or multi-label `mpls` [`ProtocolDissection`] from `stack` and
/// residual payload, eliding default `bos` flags (`0` on inner stack entries, `1` at bottom).
pub(crate) fn dissect_mpls_stack(stack: &[MplsSpec], res: Vec<u8>) -> ProtocolDissection {
    if stack.is_empty() {
        return dissect_mpls(&MplsSpec::default(), res);
    }
    let mut t = String::new();
    for (idx, m) in stack.iter().enumerate() {
        if idx > 0 {
            t.push(' ');
        }
        let _ = write!(t, "mpls {}", m.label);
        push_if(&mut t, "exp", m.exp.unwrap_or(0), 0);
        let default_bos = u8::from(idx + 1 == stack.len());
        push_if(&mut t, "bos", m.bos.unwrap_or(default_bos), default_bos);
        push_if(&mut t, "mplsttl", m.ttl.unwrap_or(64), 64);
    }
    sd(Protocol::Mpls, t, res)
}
