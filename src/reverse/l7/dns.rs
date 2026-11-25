//! Domain Name System (`dns`, RFC 1035 / RFC 3596 / RFC 6891) Layer 7 PCAP-to-`.frasm` decompiler.
//!
//! This module implements the fuzz-safe reverse dissector for RFC 1035 and RFC 6891 Domain Name
//! System (`dns`) queries and responses carried over UDP, TCP, or SCTP port `53` (safely
//! validating the 2-byte RFC 1035 §4.2.2 TCP length prefix). It enforces a visited-offset bitset
//! alongside `MAX_DNS_JUMPS = 16` against compression cycles, and decodes `txid`, `qname`, `qtype`,
//! binary `SOA`/`SRV` and multi-RR `rdata`, `rcode`, `ansttl`, `edns0`, `udpsize`, and `dobit`.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt::Write as _;

use crate::ast::{Protocol, TransportProto};
use crate::reverse::{ProtocolDissection, be_u16, be_u32, ipv4_at, ipv6_at, push_if};

use super::{is_printable_ascii_str, push_str_if};

/// Maximum number of RFC 1035 §4.1.4 DNS label compression pointer jumps allowed.
const MAX_DNS_JUMPS: usize = 16;

/// Default RFC 1035 §3.3.13 SOA RDATA string synthesized when `rdata` is omitted.
const DEFAULT_SOA_RDATA: &str =
    "ns1.example.com hostmaster.example.com 2026010101 7200 900 1209600 300";

/// Default RFC 2782 SRV RDATA string synthesized when `rdata` is omitted.
const DEFAULT_SRV_RDATA: &str = "10 5 443 srv.example.com";

/// Dissects an RFC 1035 `dns` query or response message over UDP, TCP, or SCTP port `53`.
pub(crate) fn dissect_dns(payload: &[u8], is_tcp: bool) -> Option<ProtocolDissection> {
    dissect_dns_or_mdns(payload, is_tcp, false)
}

/// Records `offset` in the visited-offset bitset (`0..8192`) or overflow vec, returning `false` on cycles.
fn mark_dns_offset(
    visited_lo: &mut [u64; 128],
    visited_hi: &mut Vec<usize>,
    offset: usize,
) -> bool {
    if offset < 8192 {
        let word = offset >> 6;
        let mask = 1u64 << (offset & 63);
        if (visited_lo[word] & mask) != 0 {
            return false;
        }
        visited_lo[word] |= mask;
        true
    } else {
        if visited_hi.contains(&offset) || visited_hi.len() >= 256 {
            return false;
        }
        visited_hi.push(offset);
        true
    }
}

/// Decodes a DNS domain name starting at `start_offset` in `msg`, enforcing [`MAX_DNS_JUMPS`] and
/// a visited-offset bitset against forward and backward (`ptr < pos`) compression cycles.
pub(crate) fn decode_dns_name(msg: &[u8], start_offset: usize) -> Option<(String, usize)> {
    if start_offset >= msg.len() {
        return None;
    }
    let (mut labels, mut pos, mut end_offset, mut jumps) = (Vec::new(), start_offset, None, 0usize);
    let mut visited_lo = [0u64; 128];
    let mut visited_hi = Vec::new();

    loop {
        if !mark_dns_offset(&mut visited_lo, &mut visited_hi, pos) || labels.len() >= 128 {
            return None;
        }
        let &len_byte = msg.get(pos)?;
        if len_byte == 0 {
            end_offset.get_or_insert(pos + 1);
            break;
        }
        if (len_byte & 0xC0) == 0xC0 {
            let &lo = msg.get(pos + 1)?;
            if jumps >= MAX_DNS_JUMPS {
                return None;
            }
            jumps += 1;
            end_offset.get_or_insert(pos + 2);
            let ptr = (((len_byte & 0x3F) as usize) << 8) | (lo as usize);
            if ptr >= msg.len() || ptr == pos {
                return None;
            }
            pos = ptr;
            continue;
        }
        if (len_byte & 0xC0) != 0 {
            return None;
        }
        let label_len = len_byte as usize;
        let label_start = pos.checked_add(1)?;
        let label_end = label_start.checked_add(label_len)?;
        labels.push(core::str::from_utf8(msg.get(label_start..label_end)?).ok()?);
        pos = label_end;
    }

    Some((labels.join("."), end_offset?))
}

/// Decodes RFC 1035 `<character-string>` TXT RDATA chunks into a single printable ASCII string
/// when the wire chunks match deterministic 255-byte segmentation.
fn decode_txt_rdata(rdata_bytes: &[u8]) -> Option<String> {
    if rdata_bytes == [0] {
        return Some(String::new());
    }
    let mut pos = 0usize;
    let mut out = String::new();
    while pos < rdata_bytes.len() {
        let len = usize::from(*rdata_bytes.get(pos)?);
        let end = pos.checked_add(1)?.checked_add(len)?;
        if end > rdata_bytes.len() {
            return None;
        }
        if end < rdata_bytes.len() && len != 255 {
            return None;
        }
        let s = is_printable_ascii_str(&rdata_bytes[pos + 1..end])?;
        out.push_str(s);
        pos = end;
    }
    (!out.is_empty()).then_some(out)
}

/// Decodes one DNS answer RR RDATA slice (`qtype`) into canonical `.frasm` `rdata` string form.
fn decode_rr_rdata(
    msg: &[u8],
    qtype: u16,
    rdata_start: usize,
    rdata_end: usize,
) -> Option<String> {
    let rdata_bytes = msg.get(rdata_start..rdata_end)?;
    let rdlen = rdata_bytes.len();
    match qtype {
        1 if rdlen == 4 => Some(ipv4_at(rdata_bytes, 0).to_string()),
        28 if rdlen == 16 => Some(ipv6_at(rdata_bytes, 0).to_string()),
        2 | 5 | 12 => {
            let (target, end_pos) = decode_dns_name(msg, rdata_start)?;
            (end_pos == rdata_end).then_some(target)
        }
        6 => {
            let (mname, p1) = decode_dns_name(msg, rdata_start)?;
            let (rname, p2) = decode_dns_name(msg, p1)?;
            if p2.checked_add(20)? != rdata_end {
                return None;
            }
            let (serial, refresh, retry, expire, minimum) = (
                be_u32(msg, p2),
                be_u32(msg, p2 + 4),
                be_u32(msg, p2 + 8),
                be_u32(msg, p2 + 12),
                be_u32(msg, p2 + 16),
            );
            Some(format!(
                "{mname} {rname} {serial} {refresh} {retry} {expire} {minimum}"
            ))
        }
        15 if rdlen >= 3 => {
            let pref = be_u16(msg, rdata_start);
            let (exch, end_pos) = decode_dns_name(msg, rdata_start + 2)?;
            if end_pos != rdata_end {
                return None;
            }
            Some(if pref == 10 {
                exch
            } else {
                format!("{pref} {exch}")
            })
        }
        16 if !rdata_bytes.is_empty() => decode_txt_rdata(rdata_bytes),
        33 if rdlen >= 7 => {
            let priority = be_u16(msg, rdata_start);
            let weight = be_u16(msg, rdata_start + 2);
            let port = be_u16(msg, rdata_start + 4);
            let (target, end_pos) = decode_dns_name(msg, rdata_start + 6)?;
            if end_pos != rdata_end {
                return None;
            }
            Some(format!("{priority} {weight} {port} {target}"))
        }
        _ if !matches!(qtype, 1 | 2 | 5 | 6 | 12 | 15 | 16 | 28 | 33) => {
            is_printable_ascii_str(rdata_bytes).map(ToString::to_string)
        }
        _ => None,
    }
}

/// Returns `true` when `rdata` equals the synthesized zero-keyword response default for `qtype`.
fn is_default_response_rdata(qtype: u16, rdata: &str) -> bool {
    match qtype {
        1 => rdata == "93.184.216.34",
        28 => rdata == "2001:db8::1",
        2 | 5 | 12 => rdata == "ns1.example.com",
        6 => rdata == DEFAULT_SOA_RDATA,
        15 => rdata == "mail.example.com",
        16 => rdata == "v=spf1 -all",
        33 => rdata == DEFAULT_SRV_RDATA,
        _ => false,
    }
}

/// Dissects a `dns` (port `53`, UDP/TCP/SCTP) or `mdns` (UDP port `5353`) message.
pub(crate) fn dissect_dns_or_mdns(
    payload: &[u8],
    is_tcp: bool,
    is_mdns: bool,
) -> Option<ProtocolDissection> {
    let msg = if is_tcp {
        if payload.len() < 14 {
            return None;
        }
        let dns_len = be_u16(payload, 0) as usize;
        let end = 2usize.checked_add(dns_len)?;
        if dns_len < 12 || end != payload.len() {
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
    if qdcount != 1 || nscount != 0 || arcount > 1 {
        return None;
    }

    let is_response = (flags & 0x8000) != 0;
    let mut rcode = (flags & 0x000F) as u8;

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
        let rdlen = be_u16(msg, pos_after_ans + 8) as usize;
        let rdata_end = rdata_start.checked_add(rdlen)?;
        if rdata_end > msg.len() {
            return None;
        }
        if let Some(decoded) = decode_rr_rdata(msg, qtype, rdata_start, rdata_end) {
            rdata_list.push(decoded);
        } else if ancount == 1 && arcount == 0 && is_response && rdata_end == msg.len() {
            residual_payload = msg[rdata_start..rdata_end].to_vec();
        } else {
            return None;
        }
        offset = rdata_end;
    }

    let mut edns_opt: Option<(u16, bool)> = None;
    if arcount == 1 {
        let opt_end = offset.checked_add(11)?;
        if opt_end > msg.len()
            || msg[offset] != 0x00
            || be_u16(msg, offset + 1) != 41
            || msg[offset + 6] != 0x00
            || (msg[offset + 7] & 0x7F) != 0x00
            || msg[offset + 8] != 0x00
            || be_u16(msg, offset + 9) != 0
        {
            return None;
        }
        let udp_size = be_u16(msg, offset + 3);
        let ext_rcode = msg[offset + 5];
        if ext_rcode >= 16 {
            return None;
        }
        rcode |= ext_rcode << 4;
        let do_bit = (msg[offset + 7] & 0x80) != 0;
        edns_opt = Some((udp_size, do_bit));
        offset = opt_end;
    }

    if offset < msg.len() {
        if ancount == 0 {
            residual_payload = msg[offset..].to_vec();
        } else {
            return None;
        }
    }

    let mut tokens = format!(
        "{} {}",
        if is_mdns { "mdns" } else { "dns" },
        if is_response { "response" } else { "query" }
    );
    let default_txid = if is_mdns { 0x0000 } else { 0x1234 };
    if txid != default_txid {
        let _ = write!(tokens, " txid 0x{txid:04x}");
    }
    push_str_if(&mut tokens, "qname", &qname, "example.com");
    let qtype_name = match qtype {
        1 => String::from("a"),
        2 => String::from("ns"),
        5 => String::from("cname"),
        6 => String::from("soa"),
        12 => String::from("ptr"),
        15 => String::from("mx"),
        16 => String::from("txt"),
        28 => String::from("aaaa"),
        33 => String::from("srv"),
        252 => String::from("axfr"),
        255 => String::from("any"),
        other => other.to_string(),
    };
    push_str_if(&mut tokens, "qtype", &qtype_name, "a");

    if rdata_list.len() == 1 {
        let rdata = &rdata_list[0];
        if !(is_response && is_default_response_rdata(qtype, rdata)) {
            if rdata.is_empty() {
                tokens.push_str(" rdata \"\"");
            } else {
                push_str_if(&mut tokens, "rdata", rdata, "");
            }
        }
    } else {
        for rdata in &rdata_list {
            if rdata.is_empty() {
                tokens.push_str(" rdata \"\"");
            } else {
                push_str_if(&mut tokens, "rdata", rdata, "");
            }
        }
    }

    push_if(&mut tokens, "rcode", rcode, 0);
    if let Some(ttl) = ans_ttl {
        push_if(&mut tokens, "ansttl", ttl, 300);
    }
    if let Some((udp_size, do_bit)) = edns_opt {
        if udp_size == 4096 && !do_bit {
            tokens.push_str(" edns0");
        } else {
            if udp_size != 4096 {
                let _ = write!(tokens, " udpsize {udp_size}");
            }
            if do_bit {
                tokens.push_str(" dobit");
            }
        }
    }

    Some(ProtocolDissection {
        protocol: if is_mdns {
            Protocol::Mdns
        } else {
            Protocol::Dns
        },
        tokens,
        residual_payload,
        explicit_transport: (is_tcp && !is_mdns).then_some(TransportProto::Tcp),
    })
}
