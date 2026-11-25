//! GPRS Tunneling Protocol User Plane (GTPv1-U, 3GPP TS 29.281) Layer 3 PCAP-to-`.frasm` decompiler.
//!
//! This module implements the fuzz-safe PCAP and PCAPNG decompiler for 3GPP TS 29.281 GTPv1-U
//! packets carried over UDP port `2152`. It validates the 8-byte GTPv1 header (`Version == 1`,
//! `PT == 1`, `Length`), parses optional 4-byte `seqnum`/`npdu`/`Next Extension Header` fields
//! and bounded 5G PDU Session Container (`0x85`) `qfi` extension headers, decodes `gpdu`,
//! `echorequest`, `echoreply`, `errorindication`, and `endmarker` messages, and elides default
//! inner payloads and IEs cleanly.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write as _;
use core::net::IpAddr;

use crate::ast::Protocol;
use crate::reverse::{ProtocolDissection, be_u16, be_u32, ipv4_at, ipv6_at, push_hex, push_if, sd};

/// Checks if `body` equals the default `errorindication` IE sequence for `src_ip`.
fn is_default_gtpu_errind(body: &[u8], src_ip: Option<IpAddr>) -> bool {
    if body.len() < 8 || body[0..5] != [16, 0, 0, 0, 1] || body[5] != 133 {
        return false;
    }
    let alen = be_u16(body, 6) as usize;
    if 8 + alen != body.len() {
        return false;
    }
    match (alen, src_ip) {
        (4, Some(IpAddr::V4(v4))) => ipv4_at(body, 8) == v4,
        (16, Some(IpAddr::V6(v6))) => ipv6_at(body, 8) == v6,
        _ => false,
    }
}

/// Decompiles a 3GPP TS 29.281 `gtpu` UDP payload (port `2152`) into a [`ProtocolDissection`].
pub(crate) fn dissect_gtpu(b: &[u8], src_ip: Option<IpAddr>) -> Option<ProtocolDissection> {
    if b.len() < 8 || (b[0] >> 5) != 1 || (b[0] & 0x10) == 0 {
        return None;
    }
    let flags = b[0];
    let mtype = b[1];
    let gtp_len = be_u16(b, 2) as usize;
    let teid = be_u32(b, 4);
    let end = 8usize.checked_add(gtp_len)?;
    if end > b.len() {
        return None;
    }

    let mut pos = 8usize;
    let mut seq_opt: Option<u16> = None;
    let mut npdu_opt: Option<u8> = None;
    let mut qfi_opt: Option<u8> = None;

    if (flags & 0x07) != 0 {
        if pos + 4 > end {
            return None;
        }
        if (flags & 0x02) != 0 {
            seq_opt = Some(be_u16(b, pos));
        }
        if (flags & 0x01) != 0 {
            npdu_opt = Some(b[pos + 2]);
        }
        let mut next_ext = b[pos + 3];
        pos += 4;
        let mut ext_count = 0usize;
        while (flags & 0x04) != 0 && next_ext != 0 && ext_count < 16 {
            ext_count += 1;
            if pos >= end {
                return None;
            }
            let ext_words = usize::from(b[pos]);
            if ext_words == 0 {
                return None;
            }
            let ext_bytes = ext_words.saturating_mul(4);
            let ext_end = pos.checked_add(ext_bytes)?;
            if ext_end > end {
                return None;
            }
            if next_ext == 0x85 && ext_bytes >= 4 && qfi_opt.is_none() {
                qfi_opt = Some(b[pos + 2] & 0x3F);
            }
            next_ext = b[ext_end - 1];
            pos = ext_end;
        }
    }

    let mut t = String::from("gtpu");
    let def_teid = match mtype {
        1 => {
            t.push_str(" echorequest");
            0_u32
        }
        2 => {
            t.push_str(" echoreply");
            0_u32
        }
        26 => {
            t.push_str(" errorindication");
            0_u32
        }
        254 => {
            t.push_str(" endmarker");
            1_u32
        }
        255 => 1_u32,
        _ => return None,
    };

    push_hex(&mut t, "teid", u64::from(teid), u64::from(def_teid), 1);

    let mut expected_flags = if matches!(mtype, 1 | 2) {
        0x32_u8
    } else {
        0x30_u8
    };
    if qfi_opt.is_some() {
        expected_flags |= 0x04;
    }
    if seq_opt.is_some() {
        expected_flags |= 0x02;
    }
    if npdu_opt.is_some() {
        expected_flags |= 0x01;
    }
    push_hex(
        &mut t,
        "flags",
        u64::from(flags),
        u64::from(expected_flags),
        2,
    );

    if let Some(seq) = seq_opt {
        let def_seq = if matches!(mtype, 1 | 2) { 1_u16 } else { 0_u16 };
        push_if(&mut t, "seqnum", seq, def_seq);
    }
    if let Some(npdu) = npdu_opt {
        let _ = write!(t, " npdu {npdu}");
    }
    if let Some(qfi) = qfi_opt {
        let _ = write!(t, " qfi {qfi}");
    }

    let body = &b[pos..end];
    let is_def_body = match mtype {
        255 => body == crate::builders::l3::gre::default_gre_inner_packet(0x0800).as_slice(),
        2 => body == [14, 0],
        26 => is_default_gtpu_errind(body, src_ip),
        1 | 254 => body.is_empty(),
        _ => false,
    };

    let mut res = Vec::new();
    if !is_def_body {
        res.extend_from_slice(body);
    }
    res.extend_from_slice(&b[end..]);
    Some(sd(Protocol::Gtpu, t, res))
}
