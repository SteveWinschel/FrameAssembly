//! NetBIOS Name Service (`nbns`, RFC 1001 / RFC 1002) Layer 7 PCAP-to-`.frasm` decompiler.
//!
//! This module implements the fuzz-safe reverse dissector for RFC 1001 and RFC 1002 NetBIOS Name
//! Service (`nbns`) datagrams over UDP port `137`. It validates NBNS header flags and section
//! counts, decodes RFC 1001 §14.1 32-byte first-level encoded NetBIOS names with 1-byte suffix
//! types (`nbtype`) and optional scope labels (`scope`), and dissects `NB` (`0x0020`) and `NBSTAT`
//! (`0x0021`) resource records for queries, responses, registrations, releases, and refreshes.

use alloc::string::{String, ToString};
use core::fmt::Write as _;

use crate::ast::Protocol;
use crate::reverse::{ProtocolDissection, be_u16, be_u32, ipv4_at, push_if};

use super::dns::decode_dns_name;
use super::{is_printable_ascii_str, push_str_if};

/// Decodes a 32-byte first-level encoded NetBIOS name (+ optional scope labels) at `start_off`.
fn decode_nbns_name(msg: &[u8], start_off: usize) -> Option<(String, u8, String, usize)> {
    let first = *msg.get(start_off)?;
    if (first & 0xC0) == 0xC0 {
        let ptr_lo = usize::from(*msg.get(start_off + 1)?);
        let ptr = ((usize::from(first & 0x3F)) << 8) | ptr_lo;
        if ptr >= start_off {
            return None;
        }
        let (name, nb_type, scope, _) = decode_nbns_name(msg, ptr)?;
        return Some((name, nb_type, scope, start_off + 2));
    }
    if first != 0x20 {
        return None;
    }
    let enc = msg.get(start_off + 1..start_off + 33)?;
    let mut raw16 = [0u8; 16];
    for (i, pair) in enc.as_chunks::<2>().0.iter().enumerate() {
        if !(b'A'..=b'P').contains(&pair[0]) || !(b'A'..=b'P').contains(&pair[1]) {
            return None;
        }
        raw16[i] = ((pair[0] - b'A') << 4) | (pair[1] - b'A');
    }
    let nb_type = raw16[15];
    let name = if raw16[0] == b'*' && raw16[1..15].iter().all(|&b| b == 0) {
        String::from("*")
    } else {
        let mut end = 15usize;
        while end > 0 && raw16[end - 1] == b' ' {
            end -= 1;
        }
        is_printable_ascii_str(&raw16[..end])?.to_string()
    };

    let scope_off = start_off + 33;
    let (scope, end_off) = if msg.get(scope_off) == Some(&0x00) {
        (String::new(), scope_off + 1)
    } else {
        decode_dns_name(msg, scope_off)?
    };
    Some((name, nb_type, scope, end_off))
}

/// Dissects an RFC 1001 / RFC 1002 `nbns` datagram over UDP port `137`.
pub(crate) fn dissect_nbns(payload: &[u8]) -> Option<ProtocolDissection> {
    if payload.len() < 12 {
        return None;
    }
    let (txid, flags, qdcount, ancount, nscount, arcount) = (
        be_u16(payload, 0),
        be_u16(payload, 2),
        be_u16(payload, 4),
        be_u16(payload, 6),
        be_u16(payload, 8),
        be_u16(payload, 10),
    );
    if qdcount > 1 || ancount > 1 || nscount != 0 || arcount > 1 || (qdcount == 0 && ancount == 0) {
        return None;
    }

    let is_response = (flags & 0x8000) != 0;
    let opcode = ((flags >> 11) & 0x0F) as u8;
    let rcode = (flags & 0x000F) as u8;
    let default_flags: u16 = match (opcode, is_response) {
        (0, false) => 0x0110,
        (0, true) => 0x8580,
        (5, false) => 0x2910,
        (5, true) => 0xAD80,
        (6, false) => 0x3010,
        (6, true) => 0xB400,
        (8, false) => 0x4010,
        (8, true) => 0xC400,
        (op, r) => (if r { 0x8400 } else { 0x0110 }) | ((u16::from(op) & 0x0F) << 11),
    };

    let mut offset = 12usize;
    let mut qname = String::from("WORKSTATION");
    let mut nb_type = 0u8;
    let mut scope = String::new();
    let mut qtype = 0x0020u16;

    if qdcount == 1 {
        let (n, nt, sc, after_name) = decode_nbns_name(payload, offset)?;
        qname = n;
        nb_type = nt;
        scope = sc;
        if payload.len() < after_name.checked_add(4)? || be_u16(payload, after_name + 2) != 1 {
            return None;
        }
        qtype = be_u16(payload, after_name);
        offset = after_name + 4;
    }

    let mut rdata_ip: Option<String> = None;
    let mut ans_ttl: Option<u32> = None;
    let mut is_group = false;

    for rr_is_ans in [true, false] {
        let count = if rr_is_ans { ancount } else { arcount };
        if count == 0 {
            continue;
        }
        let (n, nt, sc, after_name) = decode_nbns_name(payload, offset)?;
        if qdcount == 0 && rr_is_ans {
            qname = n;
            nb_type = nt;
            scope = sc;
        }
        let rdata_start = after_name.checked_add(10)?;
        if payload.len() < rdata_start || be_u16(payload, after_name + 2) != 1 {
            return None;
        }
        let rr_type = be_u16(payload, after_name);
        if qdcount == 0 && rr_is_ans {
            qtype = rr_type;
        } else if rr_type != qtype {
            return None;
        }
        ans_ttl = Some(be_u32(payload, after_name + 4));
        let rdlen = usize::from(be_u16(payload, after_name + 8));
        let rdata_end = rdata_start.checked_add(rdlen)?;
        let rdata = payload.get(rdata_start..rdata_end)?;
        if rr_type == 0x0020 && rdlen == 6 {
            let nb_flags = be_u16(rdata, 0);
            is_group = (nb_flags & 0x8000) != 0;
            rdata_ip = Some(ipv4_at(rdata, 2).to_string());
        } else if rr_type == 0x0021 && rdlen == 65 && rdata.first() == Some(&1) {
            let stat_flags = be_u16(rdata, 17);
            is_group = (stat_flags & 0x8000) != 0;
        } else {
            return None;
        }
        offset = rdata_end;
    }

    let residual_payload = payload.get(offset..)?.to_vec();
    let mut tokens = String::from("nbns");
    match opcode {
        0 => {}
        5 => tokens.push_str(" register"),
        6 => tokens.push_str(" release"),
        8 => tokens.push_str(" refresh"),
        other => {
            let _ = write!(tokens, " opcode {other}");
        }
    }
    if is_response {
        tokens.push_str(" response");
    }
    if txid != 0x1337 {
        let _ = write!(tokens, " txid 0x{txid:04x}");
    }
    push_str_if(&mut tokens, "qname", &qname, "WORKSTATION");
    if nb_type != 0 {
        let _ = write!(tokens, " nbtype 0x{nb_type:02x}");
    }
    let qtype_name = match qtype {
        0x0020 => String::from("nb"),
        0x0021 => String::from("nbstat"),
        other => other.to_string(),
    };
    push_str_if(&mut tokens, "qtype", &qtype_name, "nb");
    push_str_if(&mut tokens, "scope", &scope, "");
    if let Some(ip) = rdata_ip.as_deref()
        && ip != "10.0.0.10"
    {
        push_str_if(&mut tokens, "rdata", ip, "");
    }
    push_if(&mut tokens, "rcode", rcode, 0);
    if let Some(ttl) = ans_ttl {
        push_if(&mut tokens, "ansttl", ttl, 300);
    }
    if (flags & 0xFFF0) != (default_flags & 0xFFF0) {
        let _ = write!(tokens, " flags 0x{flags:04x}");
    }
    if is_group {
        tokens.push_str(" group");
    }

    Some(ProtocolDissection {
        protocol: Protocol::Nbns,
        tokens,
        residual_payload,
        explicit_transport: None,
    })
}
