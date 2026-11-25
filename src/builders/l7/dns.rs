//! Domain Name System (DNS) (RFC 1035 / RFC 3596 / RFC 6891) Layer 7 wire packet builder.
//!
//! This module synthesizes deterministic on-the-wire Domain Name System (DNS) frames over UDP/TCP port 53.
//! The wire encoder constructs a 12-byte fixed DNS header (16-bit Transaction ID, 16-bit Flags QR/Opcode/AA/TC/RD/RA/Z/RCODE, 16-bit QDCOUNT, 16-bit ANCOUNT, 16-bit NSCOUNT, 16-bit ARCOUNT) followed by length-prefixed QNAME labels, 16-bit QTYPE, 16-bit QCLASS, and resource record RDATA sections. When optional fields in [`DnsSpec`]
//! are omitted in the `.frasm` source, RFC-compliant default values are automatically populated.
//!
//! Canonical `.frasm` syntax:
//! `a -> b dns [query | response] [txid <u16>] [qname <str>] [qtype <str>] [rdata <str>] [rcode <u8>] [ansttl <u32>] [transport tcp]`

use crate::ast::*;
use crate::builders::WireContext;
use alloc::vec::Vec;
use core::net::IpAddr;

/// Encodes a domain name string into DNS wire format labels (RFC 1035 §3.1).
///
/// For example, `"example.com"` is encoded as `[7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0]`.
pub fn encode_dns_name(domain: &str) -> Vec<u8> {
    let mut encoded = Vec::new();
    let trimmed = domain.trim_matches('.');
    if trimmed.is_empty() {
        encoded.push(0);
        return encoded;
    }
    for label in trimmed.split('.') {
        let len = label.len().min(63) as u8;
        encoded.push(len);
        encoded.extend_from_slice(&label.as_bytes()[..usize::from(len)]);
    }
    encoded.push(0);
    encoded
}

/// Parses a DNS QTYPE string (e.g. `"a"`, `"aaaa"`, `"cname"`, `"A"`) into its 16-bit numeric identifier.
pub fn parse_dns_qtype(qtype: &str) -> u16 {
    let norm = qtype.trim().to_ascii_uppercase().replace(['_', '-'], "");
    match norm.as_str() {
        "A" => 1,
        "NS" => 2,
        "CNAME" => 5,
        "SOA" => 6,
        "PTR" => 12,
        "MX" => 15,
        "TXT" => 16,
        "AAAA" => 28,
        "SRV" => 33,
        "AXFR" => 252,
        "ANY" => 255,
        _ => qtype.trim().parse::<u16>().unwrap_or(1),
    }
}

/// Encodes an RFC 1035 `<character-string>` TXT RDATA payload into 1-byte length-prefixed chunks (`<= 255` bytes each).
fn encode_txt_rdata(txt: &str) -> Vec<u8> {
    let raw = txt.as_bytes();
    if raw.is_empty() {
        return alloc::vec![0];
    }
    let mut out = Vec::with_capacity(raw.len() + (raw.len() / 255) + 1);
    for chunk in raw.chunks(255) {
        out.push(chunk.len() as u8);
        out.extend_from_slice(chunk);
    }
    out
}

/// Encodes an RFC 1035 MX RDATA payload (`16-bit preference` + DNS wire-format `exchange` domain name).
fn encode_mx_rdata(rdata_str: &str) -> Vec<u8> {
    let (pref, exchange) = if let Some((pref_s, exch_s)) = rdata_str.split_once(' ')
        && let Ok(p) = pref_s.trim().parse::<u16>()
        && !exch_s.trim().is_empty()
    {
        (p, exch_s.trim())
    } else {
        (10u16, rdata_str.trim())
    };
    let mut out = Vec::new();
    out.extend_from_slice(&pref.to_be_bytes());
    out.extend_from_slice(&encode_dns_name(exchange));
    out
}

/// Encodes an RFC 1035 §3.3.13 SOA RDATA payload (`MNAME`, `RNAME`, `SERIAL`, `REFRESH`, `RETRY`, `EXPIRE`, `MINIMUM`).
fn encode_soa_rdata(rdata_str: &str) -> Vec<u8> {
    let mut parts = rdata_str.split_whitespace();
    let mname = parts
        .next()
        .filter(|s| !s.is_empty())
        .unwrap_or("ns1.example.com");
    let rname_raw = parts
        .next()
        .filter(|s| !s.is_empty())
        .unwrap_or("hostmaster.example.com");
    let rname = rname_raw.replacen('@', ".", 1);
    let serial = parts
        .next()
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(2_026_010_101);
    let refresh = parts
        .next()
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(7200);
    let retry = parts
        .next()
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(900);
    let expire = parts
        .next()
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(1_209_600);
    let minimum = parts
        .next()
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(300);

    let mut out = encode_dns_name(mname);
    out.extend_from_slice(&encode_dns_name(&rname));
    out.extend_from_slice(&serial.to_be_bytes());
    out.extend_from_slice(&refresh.to_be_bytes());
    out.extend_from_slice(&retry.to_be_bytes());
    out.extend_from_slice(&expire.to_be_bytes());
    out.extend_from_slice(&minimum.to_be_bytes());
    out
}

/// Encodes an RFC 2782 SRV RDATA payload (`Priority`, `Weight`, `Port`, and wire-format `Target`).
fn encode_srv_rdata(rdata_str: &str) -> Vec<u8> {
    let mut parts = rdata_str.split_whitespace();
    let first = parts.next();
    let (priority, weight, port, target) = if let Some(p0) = first
        && let Ok(prio) = p0.parse::<u16>()
        && let Some(p1) = parts.next()
        && let Ok(wt) = p1.parse::<u16>()
        && let Some(p2) = parts.next()
        && let Ok(pt) = p2.parse::<u16>()
    {
        let tgt = parts
            .next()
            .filter(|s| !s.is_empty())
            .unwrap_or("srv.example.com");
        (prio, wt, pt, tgt)
    } else if let Some(target_only) = first.filter(|s| !s.is_empty()) {
        (10u16, 5u16, 443u16, target_only)
    } else {
        (10u16, 5u16, 443u16, "srv.example.com")
    };

    let mut out = Vec::with_capacity(8 + target.len());
    out.extend_from_slice(&priority.to_be_bytes());
    out.extend_from_slice(&weight.to_be_bytes());
    out.extend_from_slice(&port.to_be_bytes());
    out.extend_from_slice(&encode_dns_name(target));
    out
}

/// Encodes one DNS resource record RDATA payload matching `qtype`.
fn encode_dns_rr_rdata(qtype: u16, rdata_opt: Option<&str>, payload_bytes: &[u8]) -> Vec<u8> {
    if let Some(rdata_str) = rdata_opt {
        match qtype {
            1 => {
                if let Ok(IpAddr::V4(v4)) = rdata_str.parse::<IpAddr>() {
                    v4.octets().to_vec()
                } else {
                    [93, 184, 216, 34].to_vec()
                }
            }
            28 => {
                if let Ok(IpAddr::V6(v6)) = rdata_str.parse::<IpAddr>() {
                    v6.octets().to_vec()
                } else {
                    alloc::vec![0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
                }
            }
            2 | 5 | 12 => encode_dns_name(rdata_str),
            6 => encode_soa_rdata(rdata_str),
            15 => encode_mx_rdata(rdata_str),
            16 => encode_txt_rdata(rdata_str),
            33 => encode_srv_rdata(rdata_str),
            _ => rdata_str.as_bytes().to_vec(),
        }
    } else if !payload_bytes.is_empty() {
        payload_bytes.to_vec()
    } else {
        match qtype {
            1 => [93, 184, 216, 34].to_vec(),
            28 => alloc::vec![0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            2 | 5 | 12 => encode_dns_name("ns1.example.com"),
            6 => encode_soa_rdata(
                "ns1.example.com hostmaster.example.com 2026010101 7200 900 1209600 300",
            ),
            15 => encode_mx_rdata("10 mail.example.com"),
            16 => encode_txt_rdata("v=spf1 -all"),
            33 => encode_srv_rdata("10 5 443 srv.example.com"),
            _ => [93, 184, 216, 34].to_vec(),
        }
    }
}

/// Builds an RFC 1035 DNS message payload for UDP or TCP transmission.
///
/// When `is_tcp` is true, a 2-byte big-endian message length prefix is prepended (RFC 1035 §4.2.2).
/// Syntax mapping: `dns [query | response] [txid <u16>] [qname <str>] [qtype <str>] [rdata <str>] [rcode <u8>] [ansttl <u32>] [transport tcp]`
#[doc(alias = "DNS")]
#[doc(alias = "RFC1035")]
#[doc(alias = "RFC3596")]
#[doc(alias = "QNAME")]
#[doc(alias = "QTYPE")]
#[doc(alias = "RDATA")]
pub fn build_dns_payload(
    ctx: &WireContext,
    spec: &DnsSpec,
    payload_bytes: &[u8],
    is_tcp: bool,
) -> Vec<u8> {
    build_dns_or_mdns_payload(ctx, spec, payload_bytes, is_tcp, false)
}

/// Shared RFC 1035 DNS and RFC 6762 mDNS wire message encoder.
pub(crate) fn build_dns_or_mdns_payload(
    _ctx: &WireContext,
    spec: &DnsSpec,
    payload_bytes: &[u8],
    is_tcp: bool,
    is_mdns: bool,
) -> Vec<u8> {
    let txid = spec.txid.unwrap_or(if is_mdns { 0x0000 } else { 0x1234 });
    let is_resp = spec.is_response && !spec.is_query;
    let mut flags: u16 = match (is_mdns, is_resp) {
        (false, true) => 0x8180,  // DNS Response: QR=1, RD=1, RA=1
        (false, false) => 0x0100, // DNS Query: QR=0, RD=1
        (true, true) => 0x8400,   // mDNS Response (RFC 6762): QR=1, AA=1
        (true, false) => 0x0000,  // mDNS Query (RFC 6762): QR=0, RD=0
    };
    if let Some(rcode) = spec.rcode {
        flags = (flags & 0xFFF0) | (rcode as u16 & 0x000F);
    }

    let qdcount = 1u16;
    let mut answer_items: Vec<Option<&str>> = Vec::new();
    if !spec.rdata_list.is_empty() {
        for r in &spec.rdata_list {
            answer_items.push(Some(*r));
        }
    } else if let Some(r) = spec.rdata {
        answer_items.push(Some(r));
    } else if is_resp {
        answer_items.push(None);
    }
    let has_answer = !answer_items.is_empty();
    let ancount = answer_items.len().min(usize::from(u16::MAX)) as u16;
    let nscount = 0u16;
    let has_edns0 = spec.edns0 || spec.udp_size.is_some() || spec.do_bit;
    let arcount = if has_edns0 { 1u16 } else { 0u16 };

    let mut dns_msg = Vec::new();
    dns_msg.extend_from_slice(&txid.to_be_bytes());
    dns_msg.extend_from_slice(&flags.to_be_bytes());
    dns_msg.extend_from_slice(&qdcount.to_be_bytes());
    dns_msg.extend_from_slice(&ancount.to_be_bytes());
    dns_msg.extend_from_slice(&nscount.to_be_bytes());
    dns_msg.extend_from_slice(&arcount.to_be_bytes());

    // Question section
    let qname = spec.qname.unwrap_or("example.com");
    let encoded_qname = encode_dns_name(qname);
    dns_msg.extend_from_slice(&encoded_qname);

    let qtype = spec.qtype.map(parse_dns_qtype).unwrap_or(1);
    dns_msg.extend_from_slice(&qtype.to_be_bytes());
    dns_msg.extend_from_slice(&1u16.to_be_bytes()); // QCLASS IN (1)

    // Answer section (supports 1 or more RRs via ANCOUNT)
    if has_answer {
        let ttl = spec.ans_ttl.unwrap_or(300);
        for rdata_opt in answer_items.iter().take(usize::from(ancount)) {
            // Name compression pointer back to QNAME at byte offset 12
            dns_msg.extend_from_slice(&0xC00Cu16.to_be_bytes());
            dns_msg.extend_from_slice(&qtype.to_be_bytes());
            dns_msg.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN (1)
            dns_msg.extend_from_slice(&ttl.to_be_bytes());

            let rdata_bytes = encode_dns_rr_rdata(qtype, *rdata_opt, payload_bytes);
            dns_msg.extend_from_slice(&(rdata_bytes.len() as u16).to_be_bytes());
            dns_msg.extend_from_slice(&rdata_bytes);
        }
    }

    // Additional section: RFC 6891 EDNS0 OPT RR (Type 41) when edns0/udpsize/dobit is active
    if has_edns0 {
        let udp_size = spec.udp_size.unwrap_or(4096);
        let ext_rcode = spec.rcode.map_or(0u8, |r| r >> 4);
        let edns_flags_hi = if spec.do_bit { 0x80u8 } else { 0x00u8 };
        dns_msg.push(0x00); // NAME: root domain (.)
        dns_msg.extend_from_slice(&41u16.to_be_bytes()); // TYPE: OPT (41)
        dns_msg.extend_from_slice(&udp_size.to_be_bytes()); // CLASS: requestor UDP payload size
        dns_msg.extend_from_slice(&[ext_rcode, 0x00, edns_flags_hi, 0x00]); // extended RCODE / EDNS version / DO flag
        dns_msg.extend_from_slice(&0u16.to_be_bytes()); // RDLEN: 0
    }

    if !has_answer && !payload_bytes.is_empty() {
        dns_msg.extend_from_slice(payload_bytes);
    }

    if is_tcp {
        let mut tcp_frame = Vec::with_capacity(dns_msg.len() + 2);
        tcp_frame.extend_from_slice(&(dns_msg.len() as u16).to_be_bytes());
        tcp_frame.extend_from_slice(&dns_msg);
        tcp_frame
    } else {
        dns_msg
    }
}
