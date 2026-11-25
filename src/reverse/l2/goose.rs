//! IEC 61850-8-1 GOOSE (`goose`, EtherType `0x88B8`) Layer 2 PCAP-to-`.frasm` decompiler.
//!
//! This module implements the fuzz-safe ASN.1 BER PCAP and PCAPNG decompiler for IEC 61850-8-1
//! Generic Object Oriented Substation Event (`goose`, EtherType `0x88B8`) frames in FrameAssembly.
//! It validates the 8-byte GOOSE transport header (`APPID`, `Length`, `Reserved1`, `Reserved2`)
//! and iteratively decodes `[APPLICATION 1]` (`0x61`) `goosePdu` fields (`gocbref`,
//! `timetolive`, `datset`, `goid`, `stnum`, `sqnum`, `simulation`, `confrev`, `ndscom`,
//! `numdatsetentries`) while restoring OctetString or residual `allData` payloads.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write as _;

use crate::ast::Protocol;
use crate::reverse::l7::quote_raw_str;
use crate::reverse::{ProtocolDissection, push_hex, push_if, sd};

/// Parses a single ASN.1 BER definite-length TLV `(tag, value, rest)` without panicking.
fn parse_ber_tlv(input: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    if input.len() < 2 {
        return None;
    }
    let tag = input[0];
    let b1 = input[1];
    let (len, hdr_len) = if (b1 & 0x80) == 0 {
        (usize::from(b1), 2usize)
    } else {
        let num_octets = usize::from(b1 & 0x7F);
        if num_octets == 0 || num_octets > 4 || input.len() < 2 + num_octets {
            return None;
        }
        let mut l = 0usize;
        for &byte in input.get(2..2 + num_octets)? {
            l = (l << 8) | usize::from(byte);
        }
        (l, 2 + num_octets)
    };
    let end = hdr_len.checked_add(len)?;
    let val = input.get(hdr_len..end)?;
    let rest = input.get(end..)?;
    Some((tag, val, rest))
}

/// Parses an ASN.1 BER unsigned integer up to 4 bytes into a `u32`.
fn parse_ber_u32(bytes: &[u8]) -> Option<u32> {
    if bytes.is_empty() || bytes.len() > 5 || (bytes[0] & 0x80) != 0 {
        return None;
    }
    let trimmed = if bytes.len() > 1 && bytes[0] == 0 {
        &bytes[1..]
    } else {
        bytes
    };
    if trimmed.len() > 4 {
        return None;
    }
    let mut val = 0u32;
    for &b in trimmed {
        val = (val << 8) | u32::from(b);
    }
    Some(val)
}

/// Decompiles an IEC 61850-8-1 `goose` Ethernet payload (`0x88B8`) into a [`ProtocolDissection`].
pub(crate) fn dissect_goose(b: &[u8]) -> Option<ProtocolDissection> {
    if b.len() < 12 {
        return None;
    }
    let appid = u16::from_be_bytes([b[0], b[1]]);
    let declared_len = usize::from(u16::from_be_bytes([b[2], b[3]]));
    let res1 = u16::from_be_bytes([b[4], b[5]]);
    if declared_len < 10 || declared_len > b.len() {
        return None;
    }
    let apdu_slice = b.get(8..declared_len)?;
    let (pdu_tag, mut cursor, trailing) = parse_ber_tlv(apdu_slice)?;
    if pdu_tag != 0x61 || !trailing.is_empty() {
        return None;
    }

    let mut gocb_ref: Option<&str> = None;
    let mut ttl_ms: Option<u32> = None;
    let mut dat_set: Option<&str> = None;
    let mut go_id: Option<&str> = None;
    let mut st_num: Option<u32> = None;
    let mut sq_num: Option<u32> = None;
    let mut sim_ber = false;
    let mut conf_rev: Option<u32> = None;
    let mut nds_com = false;
    let mut num_entries: Option<u32> = None;
    let mut all_data: Option<&[u8]> = None;

    while !cursor.is_empty() {
        let (tag, val, next) = parse_ber_tlv(cursor)?;
        cursor = next;
        match tag {
            0x80 => gocb_ref = Some(core::str::from_utf8(val).ok()?),
            0x81 => ttl_ms = Some(parse_ber_u32(val)?),
            0x82 => dat_set = Some(core::str::from_utf8(val).ok()?),
            0x83 => go_id = Some(core::str::from_utf8(val).ok()?),
            0x84 => {} // UTC Timestamp
            0x85 => st_num = Some(parse_ber_u32(val)?),
            0x86 => sq_num = Some(parse_ber_u32(val)?),
            0x87 => sim_ber = val.first().is_some_and(|&x| x != 0),
            0x88 => conf_rev = Some(parse_ber_u32(val)?),
            0x89 => nds_com = val.first().is_some_and(|&x| x != 0),
            0x8A => num_entries = Some(parse_ber_u32(val)?),
            0xAB => all_data = Some(val),
            _ => {}
        }
    }

    let sim = sim_ber || (res1 & 0x8000) != 0;
    let mut residual = Vec::new();
    let entries_val = num_entries.unwrap_or(2);
    if let Some(ad) = all_data {
        if ad == [0x83, 0x01, 0x00, 0x84, 0x02, 0x03, 0x00] && entries_val == 2 {
            // Standard default empty-payload 2-entry allData
        } else if let Some((first_tag, first_val, rest)) = parse_ber_tlv(ad) {
            if first_tag == 0x89
                && !first_val.is_empty()
                && rest.as_chunks::<3>().0.iter().all(|&c| c == [0x83, 0x01, 0x00])
                && rest.len() % 3 == 0
            {
                residual = first_val.to_vec();
            } else if !(ad.as_chunks::<3>().0.iter().all(|&c| c == [0x83, 0x01, 0x00])
                && ad.len() == (entries_val as usize) * 3)
            {
                residual = ad.to_vec();
            }
        }
    }

    let mut t = String::from("goose");
    push_hex(&mut t, "appid", u64::from(appid), 0x1000, 4);
    if let Some(g) = gocb_ref
        && g != "IED1/LLN0$GO$gcb01"
    {
        let _ = write!(t, " gocbref \"{}\"", quote_raw_str(g));
    }
    if let Some(ms) = ttl_ms {
        push_if(&mut t, "timetolive", ms, 2000);
    }
    if let Some(ds) = dat_set
        && ds != "IED1/LLN0$ds01"
    {
        let _ = write!(t, " datset \"{}\"", quote_raw_str(ds));
    }
    if let Some(id) = go_id
        && id != "gcb01"
    {
        let _ = write!(t, " goid \"{}\"", quote_raw_str(id));
    }
    if let Some(st) = st_num {
        push_if(&mut t, "stnum", st, 1);
    }
    if let Some(sq) = sq_num {
        push_if(&mut t, "sqnum", sq, 0);
    }
    if sim {
        t.push_str(" simulation");
    }
    if let Some(cr) = conf_rev {
        push_if(&mut t, "confrev", cr, 1);
    }
    if nds_com {
        t.push_str(" ndscom");
    }
    let def_entries = if residual.is_empty() { 2 } else { 1 };
    if let Some(ne) = num_entries {
        push_if(&mut t, "numdatsetentries", ne, def_entries);
    }

    Some(sd(Protocol::Goose, t, residual))
}
