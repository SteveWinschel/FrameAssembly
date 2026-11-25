//! NetBIOS Name Service (`nbns`, RFC 1001 / RFC 1002) Layer 7 wire packet builder.
//!
//! This module implements [`build_nbns_payload`], which synthesizes RFC 1001 and RFC 1002 NetBIOS
//! Name Service (`nbns`) datagrams over UDP port 137. It encodes the 12-byte NBNS header
//! (`NAME_TRN_ID`, `R`/`OPCODE`/`NM_FLAGS`/`RCODE`, section counts), RFC 1001 §14.1 32-byte
//! first-level encoded NetBIOS names with 1-byte suffix type and optional scope labels, and `NB`
//! (`0x0020`) or `NBSTAT` (`0x0021`) resource records for queries, responses, registrations,
//! releases, and refreshes.

use super::dns::encode_dns_name;
use crate::ast::NbnsSpec;
use crate::builders::WireContext;
use alloc::vec::Vec;
use core::net::{IpAddr, Ipv4Addr};

/// Encodes a NetBIOS name and 1-byte suffix (`nb_type`) using RFC 1001 §14.1 first-level encoding.
fn encode_nbns_name(name: &str, nb_type: u8, scope: Option<&str>) -> Vec<u8> {
    let mut raw16 = [b' '; 16];
    let trimmed = name.trim();
    if trimmed == "*" {
        raw16.fill(0);
        raw16[0] = b'*';
    } else {
        for (i, b) in trimmed.as_bytes().iter().take(15).enumerate() {
            raw16[i] = b.to_ascii_uppercase();
        }
    }
    raw16[15] = nb_type;

    let mut out = Vec::with_capacity(34);
    out.push(0x20); // 32 encoded octets
    for &b in &raw16 {
        out.push(b'A' + (b >> 4));
        out.push(b'A' + (b & 0x0F));
    }
    if let Some(sc) = scope.filter(|s| !s.trim_matches('.').is_empty()) {
        out.extend_from_slice(&encode_dns_name(sc));
    } else {
        out.push(0x00);
    }
    out
}

/// Parses an NBNS `opcode` keyword or numeric code into `(opcode_nibble, is_reg_like)`.
fn parse_nbns_opcode(raw: &str) -> u8 {
    let norm = raw.trim().to_ascii_lowercase().replace(['_', '-'], "");
    match norm.as_str() {
        "query" => 0,
        "register" | "registration" => 5,
        "release" => 6,
        "wack" => 7,
        "refresh" => 8,
        _ => raw.trim().parse::<u8>().unwrap_or(0) & 0x0F,
    }
}

/// Parses an NBNS `qtype` keyword or numeric code into `0x0020` (`NB`) or `0x0021` (`NBSTAT`).
fn parse_nbns_qtype(raw: &str) -> u16 {
    let norm = raw.trim().to_ascii_lowercase().replace(['_', '-'], "");
    match norm.as_str() {
        "nb" => 0x0020,
        "nbstat" => 0x0021,
        _ => raw.trim().parse::<u16>().unwrap_or(0x0020),
    }
}

/// Parses an IPv4 address string for an `NB` Resource Record, defaulting to `10.0.0.10`.
fn parse_nb_ipv4(rdata: Option<&str>) -> [u8; 4] {
    if let Some(s) = rdata
        && let Ok(IpAddr::V4(v4)) = s.trim().parse::<IpAddr>()
    {
        return v4.octets();
    }
    Ipv4Addr::new(10, 0, 0, 10).octets()
}

/// Builds an RFC 1001 / RFC 1002 NetBIOS Name Service (`nbns`) UDP port 137 payload.
pub fn build_nbns_payload(
    _ctx: &WireContext,
    spec: &NbnsSpec,
    payload_bytes: &[u8],
) -> Vec<u8> {
    let txid = spec.txid.unwrap_or(0x1337);
    let opcode = spec.opcode.map(parse_nbns_opcode).unwrap_or(0);
    let is_resp = spec.is_response || (spec.opcode.is_none() && spec.rdata.is_some());

    let default_flags: u16 = match (opcode, is_resp) {
        (0, false) => 0x0110, // Query Request (RD=1, B=1)
        (0, true) => 0x8580,  // Query Response (R=1, AA=1, RD=1, RA=1)
        (5, false) => 0x2910, // Registration Request (OP=5, RD=1, B=1)
        (5, true) => 0xAD80,  // Registration Response
        (6, false) => 0x3010, // Release Request (OP=6, B=1)
        (6, true) => 0xB400,  // Release Response
        (8, false) => 0x4010, // Refresh Request (OP=8, B=1)
        (8, true) => 0xC400,  // Refresh Response
        (op, r) => {
            (if r { 0x8400 } else { 0x0110 }) | ((u16::from(op) & 0x0F) << 11)
        }
    };
    let mut flags = spec.flags.unwrap_or(default_flags);
    if let Some(rcode) = spec.rcode {
        flags = (flags & 0xFFF0) | (u16::from(rcode) & 0x000F);
    }

    let qtype = spec.qtype.map(parse_nbns_qtype).unwrap_or(0x0020);
    let nb_name = spec.qname.unwrap_or("WORKSTATION");
    let nb_type = spec.nb_type.unwrap_or(0x00);
    let encoded_name = encode_nbns_name(nb_name, nb_type, spec.scope);
    let ttl = spec.ans_ttl.unwrap_or(300);
    let nb_flags: u16 = if spec.is_group { 0x8000 } else { 0x0000 };
    let ip4 = parse_nb_ipv4(spec.rdata);

    let has_additional_rr = !is_resp && matches!(opcode, 5 | 6 | 8);
    let (qdcount, ancount, arcount): (u16, u16, u16) = if is_resp {
        (0, 1, 0)
    } else if has_additional_rr {
        (1, 0, 1)
    } else {
        (1, 0, 0)
    };

    let mut pkt = Vec::with_capacity(64);
    pkt.extend_from_slice(&txid.to_be_bytes());
    pkt.extend_from_slice(&flags.to_be_bytes());
    pkt.extend_from_slice(&qdcount.to_be_bytes());
    pkt.extend_from_slice(&ancount.to_be_bytes());
    pkt.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    pkt.extend_from_slice(&arcount.to_be_bytes());

    if qdcount == 1 {
        pkt.extend_from_slice(&encoded_name);
        pkt.extend_from_slice(&qtype.to_be_bytes());
        pkt.extend_from_slice(&1u16.to_be_bytes()); // QCLASS IN (1)
    }

    if ancount == 1 || arcount == 1 {
        if ancount == 1 {
            pkt.extend_from_slice(&encoded_name);
        } else {
            pkt.extend_from_slice(&0xC00Cu16.to_be_bytes()); // Pointer to offset 12 Question Name
        }
        pkt.extend_from_slice(&qtype.to_be_bytes());
        pkt.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN (1)
        pkt.extend_from_slice(&ttl.to_be_bytes());
        if qtype == 0x0021 && ancount == 1 {
            // NBSTAT Node Status RDATA (1 byte count + 18 byte name entry + 46 byte statistics)
            pkt.extend_from_slice(&65u16.to_be_bytes());
            pkt.push(1); // NUMBER_OF_NAMES
            let mut entry = [b' '; 18];
            for (i, b) in nb_name.trim().as_bytes().iter().take(15).enumerate() {
                entry[i] = b.to_ascii_uppercase();
            }
            entry[15] = nb_type;
            let stat_flags: u16 = if spec.is_group { 0x8400 } else { 0x0400 };
            entry[16..18].copy_from_slice(&stat_flags.to_be_bytes());
            pkt.extend_from_slice(&entry);
            pkt.extend_from_slice(&[0u8; 46]); // Statistics
        } else {
            // NB RDATA (6 bytes: NB_FLAGS + NB_ADDRESS)
            pkt.extend_from_slice(&6u16.to_be_bytes());
            pkt.extend_from_slice(&nb_flags.to_be_bytes());
            pkt.extend_from_slice(&ip4);
        }
    }

    if !payload_bytes.is_empty() {
        pkt.extend_from_slice(payload_bytes);
    }
    pkt
}
