//! Domain Name System (DNS) (RFC 1035 / RFC 3596 / RFC 6891) Layer 7 wire packet builder.
//!
//! This module synthesizes deterministic on-the-wire Domain Name System (DNS) frames over UDP/TCP port 53.
//! The wire encoder constructs a 12-byte fixed DNS header (16-bit Transaction ID, 16-bit Flags QR/Opcode/AA/TC/RD/RA/Z/RCODE, 16-bit QDCOUNT, 16-bit ANCOUNT, 16-bit NSCOUNT, 16-bit ARCOUNT) followed by length-prefixed QNAME labels, 16-bit QTYPE, 16-bit QCLASS, and resource record RDATA sections. When optional fields in [`DnsSpec`]
//! are omitted in the `.fasm` source, RFC-compliant default values are automatically populated.
//!
//! Canonical `.fasm` syntax:
//! `a -> b DNS [QUERY | RESPONSE] [TXID <u16>] [QNAME <str>] [QTYPE <str>] [RDATA <str>] [RCODE <u8>] [ANS_TTL <u32>] [TRANSPORT TCP]`

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
        encoded.extend_from_slice(label.as_bytes());
    }
    encoded.push(0);
    encoded
}

/// Parses a DNS QTYPE string (e.g. `"A"`, `"AAAA"`, `"CNAME"`) into its 16-bit numeric identifier.
pub fn parse_dns_qtype(qtype: &str) -> u16 {
    match qtype.to_ascii_uppercase().as_str() {
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
        _ => qtype.parse::<u16>().unwrap_or(1),
    }
}

/// Builds an RFC 1035 DNS message payload for UDP or TCP transmission.
///
/// When `is_tcp` is true, a 2-byte big-endian message length prefix is prepended (RFC 1035 §4.2.2).
/// Syntax mapping: `DNS [QUERY | RESPONSE] [TXID <u16>] [QNAME <str>] [QTYPE <str>] [RDATA <str>] [RCODE <u8>] [ANS_TTL <u32>] [TRANSPORT TCP]`
#[doc(alias = "DNS")]
#[doc(alias = "RFC1035")]
#[doc(alias = "RFC3596")]
#[doc(alias = "QNAME")]
#[doc(alias = "QTYPE")]
#[doc(alias = "RDATA")]
pub fn build_dns_payload(
    _ctx: &WireContext,
    spec: &DnsSpec,
    payload_bytes: &[u8],
    is_tcp: bool,
) -> Vec<u8> {
    let txid = spec.txid.unwrap_or(0x1234);
    let is_resp = spec.is_response && !spec.is_query;
    let mut flags: u16 = if is_resp {
        0x8180 // Response, Recursion Desired, Recursion Available, No Error
    } else {
        0x0100 // Standard Query, Recursion Desired
    };
    if let Some(rcode) = spec.rcode {
        flags = (flags & 0xFFF0) | (rcode as u16 & 0x000F);
    }

    let qdcount = 1u16;
    let has_answer = is_resp || spec.rdata.is_some();
    let ancount = if has_answer { 1u16 } else { 0u16 };
    let nscount = 0u16;
    let arcount = 0u16;

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

    // Answer section (if present)
    if has_answer {
        // Name compression pointer back to QNAME at byte offset 12
        dns_msg.extend_from_slice(&0xC00Cu16.to_be_bytes());
        dns_msg.extend_from_slice(&qtype.to_be_bytes());
        dns_msg.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN (1)
        let ttl = spec.ans_ttl.unwrap_or(300);
        dns_msg.extend_from_slice(&ttl.to_be_bytes());

        let rdata_bytes = if let Some(rdata_str) = spec.rdata {
            if qtype == 1 {
                // A Record (IPv4)
                if let Ok(IpAddr::V4(v4)) = rdata_str.parse::<IpAddr>() {
                    v4.octets().to_vec()
                } else {
                    [93, 184, 216, 34].to_vec()
                }
            } else if qtype == 28 {
                // AAAA Record (IPv6)
                if let Ok(IpAddr::V6(v6)) = rdata_str.parse::<IpAddr>() {
                    v6.octets().to_vec()
                } else {
                    alloc::vec![0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
                }
            } else if qtype == 5 || qtype == 2 || qtype == 12 {
                // CNAME, NS, PTR: domain name
                encode_dns_name(rdata_str)
            } else {
                rdata_str.as_bytes().to_vec()
            }
        } else if !payload_bytes.is_empty() {
            payload_bytes.to_vec()
        } else {
            [93, 184, 216, 34].to_vec() // Default 93.184.216.34 (example.com)
        };

        dns_msg.extend_from_slice(&(rdata_bytes.len() as u16).to_be_bytes());
        dns_msg.extend_from_slice(&rdata_bytes);
    } else if !payload_bytes.is_empty() {
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
