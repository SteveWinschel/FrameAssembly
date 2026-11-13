//! IEEE 802.1ad Provider Bridge (QinQ) Layer 2 standalone frame decompiler.
//!
//! This module implements standalone IEEE 802.1ad double-tagged (`qinq`, outer EtherType `0x88A8`
//! or `0x9100` with inner `0x8100`) frame decompilation ([`dissect_qinq`]) for FrameAssembly's
//! PCAP and PCAPNG reverse decompiler. It formats the outer service VLAN identifier (`qinq`),
//! optional inner customer VLAN identifier (`innervlan`), Priority Code Point (`pcp`), and Drop
//! Eligible Indicator (`dei`) into canonical `.frasm` tokens.

use alloc::format;
use alloc::vec::Vec;
use core::fmt::Write as _;

use crate::ast::{Protocol, QinqSpec};
use crate::reverse::{ProtocolDissection, push_if, sd};

/// Formats a standalone `qinq` [`ProtocolDissection`] from a [`QinqSpec`], outer priority/DEI
/// fields (`qp`, `qd`), and residual L2 payload bytes.
pub(crate) fn dissect_qinq(q: &QinqSpec, qp: u8, qd: u8, res: Vec<u8>) -> ProtocolDissection {
    let mut t = format!("qinq {}", q.outer_vid);
    if let Some(iv) = q.inner_vid {
        let _ = write!(t, " innervlan {iv}");
    }
    push_if(&mut t, "pcp", qp, 0);
    push_if(&mut t, "dei", qd, 0);
    sd(Protocol::Qinq, t, res)
}
