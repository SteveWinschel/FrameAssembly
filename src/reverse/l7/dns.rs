//! Domain Name System (`dns`, RFC 1035) Layer 7 PCAP-to-`.fasm` decompiler.
//!
//! This module implements the fuzz-safe reverse dissector for RFC 1035 Domain Name System (`dns`)
//! queries and responses carried over UDP or TCP port `53` (including the 2-byte TCP length prefix
//! per RFC 1035 §4.2.2). It enforces a strict pointer-compression jump ceiling (`MAX_DNS_JUMPS`)
//! to prevent infinite loops on malformed packets and decodes `txid`, `qname`, `qtype`, `rdata`,
//! `rcode`, and `ansttl` into canonical `.fasm` modifiers.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt::Write as _;

use crate::ast::{Protocol, TransportProto};
use crate::reverse::{ProtocolDissection, be_u16, be_u32, ipv4_at, ipv6_at, push_if};

use super::{is_printable_ascii_str, push_str_if};

/// Maximum number of RFC 1035 §4.1.4 DNS label compression pointer jumps allowed.
const MAX_DNS_JUMPS: usize = 16;

/// Dissects an RFC 1035 `dns` query or response message over UDP or TCP port `53`.
pub(crate) fn dissect_dns(payload: &[u8], is_tcp: bool) -> Option<ProtocolDissection> {
    dissect_dns_or_mdns(payload, is_tcp, false)
}

/// Decodes a DNS domain name starting at `start_offset` in `msg`, enforcing [`MAX_DNS_JUMPS`].
pub(crate) fn decode_dns_name(msg: &[u8], start_offset: usize) -> Option<(String, usize)> {
    if start_offset >= msg.len() {
        return None;
    }
    let (mut labels, mut pos, mut end_offset, mut jumps) = (Vec::new(), start_offset, None, 0usize);

    loop {
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
        pos += 1;
        labels.push(core::str::from_utf8(msg.get(pos..pos + label_len)?).ok()?);
        pos += label_len;
    }

    Some((labels.join("."), end_offset?))
}

/// Dissects a `dns` (port `53`, UDP or TCP) or `mdns` (UDP port `5353`) message.
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
        payload
            .get(2..2 + dns_len)
            .filter(|s| s.len() >= 12 && 2 + dns_len == payload.len())?
    } else {
        (payload.len() >= 12).then_some(payload)?
    };

    let (txid, flags, qdcount, ancount) = (
        be_u16(msg, 0),
        be_u16(msg, 2),
        be_u16(msg, 4),
        be_u16(msg, 6),
    );
    if qdcount != 1 || be_u16(msg, 8) != 0 || be_u16(msg, 10) != 0 || ancount > 1 {
        return None;
    }

    let is_response = (flags & 0x8000) != 0;
    let rcode = (flags & 0x000F) as u8;

    let (qname, pos_after_qname) = decode_dns_name(msg, 12)?;
    if pos_after_qname + 4 > msg.len() || be_u16(msg, pos_after_qname + 2) != 1 {
        return None;
    }
    let qtype = be_u16(msg, pos_after_qname);
    let offset = pos_after_qname + 4;

    let (mut ans_ttl, mut rdata_str, mut residual_payload) = (None, None, Vec::new());

    if ancount == 1 {
        let (_ans_name, pos_after_ans) = decode_dns_name(msg, offset)?;
        if pos_after_ans + 10 > msg.len()
            || be_u16(msg, pos_after_ans) != qtype
            || be_u16(msg, pos_after_ans + 2) != 1
        {
            return None;
        }
        ans_ttl = Some(be_u32(msg, pos_after_ans + 4));
        let rdlen = be_u16(msg, pos_after_ans + 8) as usize;
        let rdata_start = pos_after_ans + 10;
        if rdata_start + rdlen != msg.len() {
            return None;
        }
        let rdata_bytes = &msg[rdata_start..rdata_start + rdlen];

        if qtype == 1 && rdata_bytes.len() == 4 {
            rdata_str = Some(ipv4_at(rdata_bytes, 0).to_string());
        } else if qtype == 28 && rdata_bytes.len() == 16 {
            rdata_str = Some(ipv6_at(rdata_bytes, 0).to_string());
        } else if matches!(qtype, 2 | 5 | 12) {
            let (target_domain, end_pos) = decode_dns_name(msg, rdata_start)?;
            if end_pos == rdata_start + rdlen {
                rdata_str = Some(target_domain);
            } else {
                residual_payload = rdata_bytes.to_vec();
            }
        } else if let Some(s) = is_printable_ascii_str(rdata_bytes) {
            rdata_str = Some(s.to_string());
        } else if is_response {
            residual_payload = rdata_bytes.to_vec();
        } else {
            return None;
        }
    } else if offset < msg.len() {
        residual_payload = msg[offset..].to_vec();
    }

    let mut tokens = format!(
        "{} {}",
        if is_mdns { "mdns" } else { "dns" },
        if is_response { "response" } else { "query" }
    );
    if txid != 0x1234 {
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
    if let Some(rdata) = rdata_str
        && !(is_response && qtype == 1 && rdata == "93.184.216.34")
    {
        push_str_if(&mut tokens, "rdata", &rdata, "");
    }
    push_if(&mut tokens, "rcode", rcode, 0);
    if let Some(ttl) = ans_ttl {
        push_if(&mut tokens, "ansttl", ttl, 300);
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
