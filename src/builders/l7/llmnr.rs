//! Link-Local Multicast Name Resolution (`llmnr`, RFC 4795) Layer 7 wire packet builder.
//!
//! This module implements [`build_llmnr_payload`], which synthesizes RFC 4795 Link-Local
//! Multicast Name Resolution (`llmnr`) frames over UDP or TCP port 5355. It constructs the 12-byte
//! LLMNR header (`ID`, `QR`/`OPCODE`/`C`/`TC`/`T`/`Z`/`RCODE` flags, `QDCOUNT`, `ANCOUNT`,
//! `NSCOUNT`, `ARCOUNT`), length-prefixed question `QNAME`/`QTYPE`/`QCLASS` records, and answer
//! resource records (`A`, `AAAA`, `NS`, `CNAME`, `PTR`, `TXT`) with optional 2-byte TCP framing.

use super::dns::{encode_dns_name, parse_dns_qtype};
use crate::ast::LlmnrSpec;
use crate::builders::WireContext;
use alloc::vec::Vec;
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Encodes one LLMNR answer resource record RDATA payload matching `qtype`.
fn encode_llmnr_rdata(qtype: u16, rdata_opt: Option<&str>, payload_bytes: &[u8]) -> Vec<u8> {
    if let Some(rdata_str) = rdata_opt {
        match qtype {
            1 => {
                if let Ok(IpAddr::V4(v4)) = rdata_str.parse::<IpAddr>() {
                    v4.octets().to_vec()
                } else {
                    [10, 0, 0, 10].to_vec()
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
            16 => {
                let raw = rdata_str.as_bytes();
                let len = raw.len().min(255);
                let mut out = Vec::with_capacity(1 + len);
                out.push(len as u8);
                out.extend_from_slice(&raw[..len]);
                out
            }
            _ => rdata_str.as_bytes().to_vec(),
        }
    } else if !payload_bytes.is_empty() {
        payload_bytes.to_vec()
    } else {
        match qtype {
            1 => [10, 0, 0, 10].to_vec(),
            28 => alloc::vec![0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            2 | 5 | 12 => encode_dns_name("fileserver.local"),
            16 => {
                let mut out = alloc::vec![10];
                out.extend_from_slice(b"llmnr=true");
                out
            }
            _ => [10, 0, 0, 10].to_vec(),
        }
    }
}

/// Builds an RFC 4795 LLMNR wire payload and returns `(payload, optional_multicast_ip, 5355)`.
pub fn build_llmnr_payload(
    ctx: &WireContext,
    spec: &LlmnrSpec,
    payload_bytes: &[u8],
    is_tcp: bool,
) -> (Vec<u8>, Option<IpAddr>, u16) {
    let txid = spec.txid.unwrap_or(0x1234);
    let is_resp = (spec.is_response || !spec.rdata_list.is_empty() || spec.rdata.is_some())
        && !spec.is_query;
    let mut flags = spec.flags.unwrap_or(if is_resp { 0x8000 } else { 0x0000 });
    if let Some(rcode) = spec.rcode {
        flags = (flags & 0xFFF0) | (u16::from(rcode) & 0x000F);
    }

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

    let mut msg = Vec::new();
    msg.extend_from_slice(&txid.to_be_bytes());
    msg.extend_from_slice(&flags.to_be_bytes());
    msg.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    msg.extend_from_slice(&ancount.to_be_bytes()); // ANCOUNT
    msg.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    msg.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT

    let qname = spec.qname.unwrap_or("fileserver");
    msg.extend_from_slice(&encode_dns_name(qname));
    let qtype = spec.qtype.map(parse_dns_qtype).unwrap_or(1);
    msg.extend_from_slice(&qtype.to_be_bytes());
    msg.extend_from_slice(&1u16.to_be_bytes()); // QCLASS IN (1)

    if has_answer {
        let ttl = spec.ans_ttl.unwrap_or(30);
        for rdata_opt in answer_items.iter().take(usize::from(ancount)) {
            msg.extend_from_slice(&0xC00Cu16.to_be_bytes()); // Pointer to offset 12 QNAME
            msg.extend_from_slice(&qtype.to_be_bytes());
            msg.extend_from_slice(&1u16.to_be_bytes());
            msg.extend_from_slice(&ttl.to_be_bytes());
            let rdata = encode_llmnr_rdata(qtype, *rdata_opt, payload_bytes);
            msg.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
            msg.extend_from_slice(&rdata);
        }
    } else if !payload_bytes.is_empty() {
        msg.extend_from_slice(payload_bytes);
    }

    let final_payload = if is_tcp {
        let mut framed = Vec::with_capacity(2 + msg.len());
        framed.extend_from_slice(&(u16::try_from(msg.len()).unwrap_or(u16::MAX)).to_be_bytes());
        framed.extend_from_slice(&msg);
        framed
    } else {
        msg
    };

    let target_ip = if !is_tcp && !is_resp {
        Some(if ctx.src_ip.is_ipv6() {
            IpAddr::V6(Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 1, 3))
        } else {
            IpAddr::V4(Ipv4Addr::new(224, 0, 0, 252))
        })
    } else {
        None
    };
    (final_payload, target_ip, 5355)
}
