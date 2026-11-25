//! Encapsulated Remote Switch Port Analyzer (ERSPAN Type II & III) Layer 3 PCAP-to-`.frasm` decompiler.
//!
//! This module implements the fuzz-safe PCAP and PCAPNG decompiler for Cisco ERSPAN frames
//! carried inside GRE (IP protocol `47`) with GRE EtherType `0x88BE` (Type II, `v2`) or
//! `0x22EB` (Type III, `v3`). It parses the GRE Sequence Number (`greseq`) and ERSPAN `sessionid`,
//! `vid`, `cos`, `index`, `timestamp`, and `direction`, while eliding the default 42-byte overlay
//! inner Ethernet frame.

use alloc::string::String;

use crate::ast::Protocol;
use crate::reverse::{ProtocolDissection, be_u16, be_u32, push_if, sd};

use super::is_default_overlay_inner;

/// Decompiles a GRE-encapsulated Cisco `erspan` Type II (`0x88BE`) or Type III (`0x22EB`) packet.
pub(crate) fn dissect_erspan(b: &[u8]) -> Option<ProtocolDissection> {
    if b.len() < 4 {
        return None;
    }
    let flags = be_u16(b, 0);
    let proto = be_u16(b, 2);
    if proto != 0x88BE && proto != 0x22EB {
        return None;
    }
    if proto == 0x88BE && (flags & 0x1000) == 0 {
        return None;
    }

    let mut pos = 4usize;
    if (flags & 0x8000) != 0 {
        pos = pos.checked_add(4)?;
    }
    if (flags & 0x2000) != 0 {
        pos = pos.checked_add(4)?;
    }
    let gre_seq = if (flags & 0x1000) != 0 {
        if pos.checked_add(4)? > b.len() {
            return None;
        }
        let s = be_u32(b, pos);
        pos += 4;
        s
    } else {
        1
    };

    let mut t = String::from("erspan");
    let inner_off = if proto == 0x22EB {
        if pos.checked_add(12)? > b.len() {
            return None;
        }
        let w0 = be_u16(b, pos);
        let w1 = be_u16(b, pos + 2);
        let ts = be_u32(b, pos + 4);
        let w3 = be_u16(b, pos + 10);
        let vid = w0 & 0x0FFF;
        let cos = ((w1 >> 13) & 0x07) as u8;
        let sid = w1 & 0x03FF;
        let dir = ((w3 >> 3) & 1) as u8;
        let has_opt = (w3 & 1) != 0;
        let hdr_len = if has_opt && pos + 20 <= b.len() { 20 } else { 12 };
        t.push_str(" v3");
        push_if(&mut t, "sessionid", sid, 1);
        push_if(&mut t, "vid", vid, 0);
        push_if(&mut t, "cos", cos, 0);
        push_if(&mut t, "greseq", gre_seq, 1);
        push_if(&mut t, "timestamp", ts, 0);
        push_if(&mut t, "direction", dir, 0);
        pos + hdr_len
    } else {
        if pos.checked_add(8)? > b.len() {
            return None;
        }
        let w0 = be_u16(b, pos);
        let w1 = be_u16(b, pos + 2);
        let index = be_u32(b, pos + 4) & 0x000F_FFFF;
        let vid = w0 & 0x0FFF;
        let cos = ((w1 >> 13) & 0x07) as u8;
        let sid = w1 & 0x03FF;
        push_if(&mut t, "sessionid", sid, 1);
        push_if(&mut t, "vid", vid, 0);
        push_if(&mut t, "cos", cos, 0);
        push_if(&mut t, "greseq", gre_seq, 1);
        push_if(&mut t, "index", index, 0);
        pos + 8
    };

    let inner = b.get(inner_off..).unwrap_or(&[]);
    let rem = if is_default_overlay_inner(inner) {
        &[][..]
    } else {
        inner
    };
    Some(sd(Protocol::Erspan, t, rem.to_vec()))
}
