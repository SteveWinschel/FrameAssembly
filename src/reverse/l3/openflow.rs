//! OpenFlow Software-Defined Networking (SDN, ONF OpenFlow v1.0–v1.5) Layer 3 PCAP-to-`.frasm` decompiler.
//!
//! This module implements the fuzz-safe PCAP and PCAPNG decompiler for ONF `openflow` control-plane
//! messages carried over TCP ports `6653` and `6633`. It validates the 8-byte OpenFlow header and
//! protocol `version` (`1..=6`), and decodes `hello`, `echoreq`, `echoreply`, `featuresreq`,
//! `featuresreply` (`dpid`, `tableid`, `priority`), `packetin`, `packetout`, and `flowmod`
//! (`dpid`, `tableid`, `priority`), plus transaction identifier `xid`.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write as _;

use crate::ast::Protocol;
use crate::reverse::{ProtocolDissection, be_u16, be_u32, be_u64, push_hex, push_if, sd};

/// Decompiles an `openflow` SDN message over TCP port `6653` / `6633` into a [`ProtocolDissection`].
pub(crate) fn dissect_openflow(b: &[u8]) -> Option<ProtocolDissection> {
    if b.len() < 8 || !matches!(b[0], 1..=6) {
        return None;
    }
    let (body, mut t, mut res) = (&b[8..], String::from("openflow"), Vec::new());
    push_if(&mut t, "version", b[0], 4);
    match b[1] {
        0 | 2 | 3 | 5 | 13 => {
            t.push_str(match b[1] {
                0 => " hello",
                2 => " echoreq",
                3 => " echoreply",
                5 => " featuresreq",
                _ => " packetout",
            });
            res.extend_from_slice(body);
        }
        6 if body.len() >= 24 => {
            t.push_str(" featuresreply");
            push_hex(&mut t, "dpid", be_u64(body, 0), 1, 1);
            push_if(&mut t, "tableid", body[12], 254);
            push_if(&mut t, "priority", be_u32(body, 20) as u16, 0);
            res.extend_from_slice(&body[24..]);
        }
        10 => {
            t.push_str(" packetin");
            if body.len() == 1 {
                let _ = write!(t, " tableid {}", body[0]);
            } else {
                res.extend_from_slice(body);
            }
        }
        14 if body.len() >= 48 => {
            t.push_str(" flowmod");
            push_hex(&mut t, "dpid", be_u64(body, 0), 0, 1);
            push_if(&mut t, "tableid", body[16], 0);
            push_if(&mut t, "priority", be_u16(body, 22), 100);
            res.extend_from_slice(&body[48..]);
        }
        _ => return None,
    }
    push_if(&mut t, "xid", be_u32(b, 4), 1);
    Some(sd(Protocol::Openflow, t, res))
}
