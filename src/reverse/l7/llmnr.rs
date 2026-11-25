//! Link-Local Multicast Name Resolution (`llmnr`, RFC 4795) Layer 7 PCAP-to-`.frasm` decompiler.
//!
//! This module implements the fuzz-safe reverse dissector for RFC 4795 Link-Local Multicast Name
//! Resolution (`llmnr`) packets carried over UDP or TCP port `5355` (validating the optional
//! 2-byte TCP length prefix). It reuses cycle-safe DNS domain name decoding from [`super::dns`],
//! decodes `query`/`response`, `txid`, `qname`, `qtype`, single or repeated `rdata`, `rcode`,
//! `ansttl` (`30` default), and RFC 4795 header `flags` (`C`/`TC`/`T`), and preserves transport
//! overrides (`transport tcp`).

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt::Write as _;

use crate::ast::{Protocol, TransportProto};
use crate::reverse::{ProtocolDissection, be_u16, be_u32, ipv4_at, ipv6_at, push_if};

use super::dns::decode_dns_name;
use super::{is_printable_ascii_str, push_str_if};

/// Decodes one LLMNR answer RR RDATA slice (`qtype`) into its canonical string representation.
fn decode_llmnr_rdata(
    msg: &[u8],
    qtype: u16,
    rdata_start: usize,
    rdata_end: usize,
) -> Option<String> {
    let rdata_bytes = msg.get(rdata_start..rdata_end)?;
    match qtype {
        1 if rdata_bytes.len() == 4 => Some(ipv4_at(rdata_bytes, 0).to_string()),
        28 if rdata_bytes.len() == 16 => Some(ipv6_at(rdata_bytes, 0).to_string()),
        2 | 5 | 12 => {
            let (target, end_pos) = decode_dns_name(msg, rdata_start)?;
            (end_pos == rdata_end).then_some(target)
        }
        16 if !rdata_bytes.is_empty() => {
            let len = usize::from(*rdata_bytes.first()?);
            if len + 1 != rdata_bytes.len() {
                return None;
            }
            is_printable_ascii_str(rdata_bytes.get(1..)?).map(ToString::to_string)
        }
        _ if !matches!(qtype, 1 | 2 | 5 | 12 | 16 | 28) => {
            is_printable_ascii_str(rdata_bytes).map(ToString::to_string)
        }
        _ => None,
    }
}

/// Dissects an RFC 4795 `llmnr` query or response over UDP or TCP port `5355`.
pub(crate) fn dissect_llmnr(payload: &[u8], is_tcp: bool) -> Option<ProtocolDissection> {
    let msg = if is_tcp {
        if payload.len() < 14 {
            return None;
        }
        let msg_len = usize::from(be_u16(payload, 0));
        let end = 2usize.checked_add(msg_len)?;
        if msg_len < 12 || end != payload.len() {
            return None;
        }
        payload.get(2..end)?
    } else {
        (payload.len() >= 12).then_some(payload)?
    };

    let (txid, flags, qdcount, ancount, nscount, arcount) = (
        be_u16(msg, 0),
        be_u16(msg, 2),
        be_u16(msg, 4),
        be_u16(msg, 6),
        be_u16(msg, 8),
        be_u16(msg, 10),
    );
    if qdcount != 1 || nscount != 0 || arcount != 0 {
        return None;
    }

    let is_response = (flags & 0x8000) != 0;
    let rcode = (flags & 0x000F) as u8;
    let base_flags = flags & 0xFFF0;

    let (qname, pos_after_qname) = decode_dns_name(msg, 12)?;
    let after_q = pos_after_qname.checked_add(4)?;
    if after_q > msg.len() || be_u16(msg, pos_after_qname + 2) != 1 {
        return None;
    }
    let qtype = be_u16(msg, pos_after_qname);
    let mut offset = after_q;

    let mut ans_ttl: Option<u32> = None;
    let mut rdata_list: Vec<String> = Vec::new();
    let mut residual_payload = Vec::new();

    for _ in 0..ancount {
        let (_ans_name, pos_after_ans) = decode_dns_name(msg, offset)?;
        let rdata_start = pos_after_ans.checked_add(10)?;
        if rdata_start > msg.len()
            || be_u16(msg, pos_after_ans) != qtype
            || be_u16(msg, pos_after_ans + 2) != 1
        {
            return None;
        }
        let ttl = be_u32(msg, pos_after_ans + 4);
        if let Some(prev) = ans_ttl
            && prev != ttl
        {
            return None;
        }
        ans_ttl = Some(ttl);
        let rdlen = usize::from(be_u16(msg, pos_after_ans + 8));
        let rdata_end = rdata_start.checked_add(rdlen)?;
        if rdata_end > msg.len() {
            return None;
        }
        if let Some(decoded) = decode_llmnr_rdata(msg, qtype, rdata_start, rdata_end) {
            rdata_list.push(decoded);
        } else if ancount == 1 && is_response && rdata_end == msg.len() {
            residual_payload = msg.get(rdata_start..rdata_end)?.to_vec();
        } else {
            return None;
        }
        offset = rdata_end;
    }

    if offset < msg.len() {
        if ancount == 0 {
            residual_payload = msg.get(offset..)?.to_vec();
        } else {
            return None;
        }
    }

    let emit_response = is_response && ancount > 0;
    let mut tokens = format!(
        "llmnr {}",
        if emit_response { "response" } else { "query" }
    );
    if txid != 0x1234 {
        let _ = write!(tokens, " txid 0x{txid:04x}");
    }
    push_str_if(&mut tokens, "qname", &qname, "fileserver");
    let qtype_name = match qtype {
        1 => String::from("a"),
        2 => String::from("ns"),
        5 => String::from("cname"),
        12 => String::from("ptr"),
        16 => String::from("txt"),
        28 => String::from("aaaa"),
        255 => String::from("any"),
        other => other.to_string(),
    };
    push_str_if(&mut tokens, "qtype", &qtype_name, "a");

    let is_default_rdata = |rd: &str| match qtype {
        1 => rd == "10.0.0.10",
        28 => rd == "2001:db8::1",
        2 | 5 | 12 => rd == "fileserver.local",
        16 => rd == "llmnr=true",
        _ => false,
    };
    if rdata_list.len() == 1 {
        let rd = &rdata_list[0];
        if !(emit_response && is_default_rdata(rd)) {
            push_str_if(&mut tokens, "rdata", rd, "");
        }
    } else {
        for rd in &rdata_list {
            push_str_if(&mut tokens, "rdata", rd, "");
        }
    }

    push_if(&mut tokens, "rcode", rcode, 0);
    if let Some(ttl) = ans_ttl {
        push_if(&mut tokens, "ansttl", ttl, 30);
    }
    let expected_flags = if emit_response { 0x8000u16 } else { 0x0000u16 };
    if base_flags != expected_flags || (is_response && !emit_response) {
        let _ = write!(tokens, " flags 0x{flags:04x}");
    }

    Some(ProtocolDissection {
        protocol: Protocol::Llmnr,
        tokens,
        residual_payload,
        explicit_transport: is_tcp.then_some(TransportProto::Tcp),
    })
}
