//! Two-Way Active Measurement Protocol (`twamp`, RFC 5357) Layer 7 wire packet builder.
//!
//! This module synthesizes deterministic on-the-wire RFC 5357 Two-Way Active Measurement Protocol
//! packets across both UDP port `862` (`TWAMP-Test` unauthenticated Session-Sender and
//! Session-Reflector measurement packets) and TCP port `862` (`TWAMP-Control` session signaling:
//! `Server-Greeting`, `Set-Up-Response`, `Server-Start`, `Request-TW-Session`, `Accept-Session`,
//! `Start-Sessions`, `Start-Ack`, and `Stop-Sessions`). When optional fields in [`TwampSpec`] are
//! omitted, compliant RFC 5357 defaults are automatically populated.
//!
//! Canonical `.frasm` syntax:
//! `a -> b twamp [sender | reflector | greeting | setupresponse | serverstart | requestsession | acceptsession | startsessions | startack | stopsessions | msgtype <str>] [seqnum <u32>] [timestamp <u64>] [errorestimate <u16>] [senderttl <u8>] [mode <u32>] [count <u32>] [status <u8>] [port <u16>] [padding <u16>] [transport tcp]`

use alloc::vec::Vec;
use core::net::IpAddr;

use crate::ast::*;
use crate::builders::WireContext;

/// Encodes an `IpAddr` into the 16-byte TWAMP-Control address field (IPv4 in first 4 bytes + 12 zero bytes, or 16-byte IPv6).
fn push_twamp_addr(out: &mut Vec<u8>, ip: IpAddr) {
    match ip {
        IpAddr::V4(v4) => {
            out.extend_from_slice(&v4.octets());
            out.extend_from_slice(&[0u8; 12]);
        }
        IpAddr::V6(v6) => {
            out.extend_from_slice(&v6.octets());
        }
    }
}

/// Builds a TWAMP-Control message payload for TCP port `862`.
fn build_twamp_control_payload(ctx: &WireContext, spec: &TwampSpec, mtype: &str) -> Vec<u8> {
    let mode = spec.mode.unwrap_or(1);
    let status = spec.status.unwrap_or(0);
    let ts = spec.timestamp.unwrap_or(0);
    let port = spec.port.unwrap_or(862);
    let padding = u32::from(spec.padding.unwrap_or(27));

    match mtype {
        "SETUPRESPONSE" => {
            let mut pkt = Vec::with_capacity(164);
            pkt.extend_from_slice(&mode.to_be_bytes());
            pkt.resize(164, 0);
            pkt
        }
        "SERVERSTART" => {
            let mut pkt = Vec::with_capacity(48);
            pkt.extend_from_slice(&[0u8; 15]);
            pkt.push(status);
            pkt.extend_from_slice(&[0u8; 16]); // Server-IV
            pkt.extend_from_slice(&ts.to_be_bytes());
            pkt.extend_from_slice(&[0u8; 8]); // MBZ
            pkt
        }
        "REQUESTSESSION" => {
            let ipvn = if ctx.src_ip.is_ipv6() || ctx.dst_ip.is_ipv6() {
                0x60u8
            } else {
                0x40u8
            };
            let mut pkt = Vec::with_capacity(112);
            pkt.push(5); // Command: Request-TW-Session (5)
            pkt.push(ipvn);
            pkt.extend_from_slice(&[0u8; 2]); // Conf-Sender, Conf-Receiver
            pkt.extend_from_slice(&0u32.to_be_bytes()); // Number of Schedule Slots
            pkt.extend_from_slice(&0u32.to_be_bytes()); // Number of Packets
            pkt.extend_from_slice(&ctx.src_port.to_be_bytes()); // Sender Port
            pkt.extend_from_slice(&port.to_be_bytes()); // Receiver Port
            push_twamp_addr(&mut pkt, ctx.src_ip);
            push_twamp_addr(&mut pkt, ctx.dst_ip);
            pkt.extend_from_slice(&[0u8; 16]); // SID
            pkt.extend_from_slice(&padding.to_be_bytes());
            pkt.extend_from_slice(&ts.to_be_bytes()); // Start Time
            pkt.extend_from_slice(&0u64.to_be_bytes()); // Timeout
            pkt.extend_from_slice(&0u32.to_be_bytes()); // Type-P Descriptor
            pkt.extend_from_slice(&[0u8; 8]); // MBZ
            pkt.extend_from_slice(&[0u8; 16]); // HMAC
            pkt
        }
        "ACCEPTSESSION" => {
            let mut pkt = Vec::with_capacity(48);
            pkt.push(status);
            pkt.push(0); // MBZ
            pkt.extend_from_slice(&port.to_be_bytes());
            pkt.extend_from_slice(&[0u8; 16]); // SID
            pkt.extend_from_slice(&[0u8; 12]); // MBZ
            pkt.extend_from_slice(&[0u8; 16]); // HMAC
            pkt
        }
        "STARTSESSIONS" => {
            let mut pkt = Vec::with_capacity(32);
            pkt.push(2); // Command: Start-Sessions (2)
            pkt.resize(32, 0);
            pkt
        }
        "STARTACK" => {
            let mut pkt = Vec::with_capacity(32);
            pkt.push(status);
            pkt.resize(32, 0);
            pkt
        }
        "STOPSESSIONS" => {
            let count = spec.count.unwrap_or(1);
            let mut pkt = Vec::with_capacity(32);
            pkt.push(3); // Command: Stop-Sessions (3)
            pkt.push(status);
            pkt.extend_from_slice(&[0u8; 2]); // MBZ
            pkt.extend_from_slice(&count.to_be_bytes());
            pkt.resize(32, 0);
            pkt
        }
        _ => {
            // Server-Greeting (64 bytes, default on TCP)
            let count = spec.count.unwrap_or(1024);
            let mut pkt = Vec::with_capacity(64);
            pkt.extend_from_slice(&[0u8; 12]); // Unused
            pkt.extend_from_slice(&mode.to_be_bytes());
            pkt.extend_from_slice(&[0u8; 16]); // Challenge
            pkt.extend_from_slice(&[0u8; 16]); // Salt
            pkt.extend_from_slice(&count.to_be_bytes());
            pkt.extend_from_slice(&[0u8; 12]); // MBZ
            pkt
        }
    }
}

/// Builds an RFC 5357 TWAMP-Test (UDP `862`) or TWAMP-Control (TCP `862`) packet payload.
///
/// Syntax mapping: `twamp [sender | reflector | greeting | setupresponse | serverstart | requestsession | acceptsession | startsessions | startack | stopsessions | msgtype <str>] [seqnum <u32>] [timestamp <u64>] [errorestimate <u16>] [senderttl <u8>] [mode <u32>] [count <u32>] [status <u8>] [port <u16>] [padding <u16>] [transport tcp]`
#[doc(alias = "TWAMP")]
#[doc(alias = "RFC5357")]
pub fn build_twamp_payload(
    ctx: &WireContext,
    spec: &TwampSpec,
    payload_bytes: &[u8],
) -> Vec<u8> {
    let is_tcp = ctx.transport == Some(TransportProto::Tcp);
    let default_type = if is_tcp { "greeting" } else { "sender" };
    let mtype = spec
        .msg_type
        .unwrap_or(default_type)
        .to_ascii_uppercase()
        .replace(['_', '-'], "");

    if is_tcp {
        let mut pkt = build_twamp_control_payload(ctx, spec, mtype.as_str());
        if !payload_bytes.is_empty() {
            pkt.extend_from_slice(payload_bytes);
        }
        return pkt;
    }

    let seq = spec.seq_num.unwrap_or(1);
    let ts = spec.timestamp.unwrap_or(0);
    let err_est = spec.error_estimate.unwrap_or(0x8001);

    if mtype == "REFLECTOR" {
        let sender_ttl = spec.sender_ttl.unwrap_or(255);
        let mut pkt = Vec::with_capacity(41 + payload_bytes.len());
        pkt.extend_from_slice(&seq.to_be_bytes());
        pkt.extend_from_slice(&ts.to_be_bytes());
        pkt.extend_from_slice(&err_est.to_be_bytes());
        pkt.extend_from_slice(&[0u8; 2]); // MBZ
        pkt.extend_from_slice(&ts.to_be_bytes()); // Receive Timestamp
        pkt.extend_from_slice(&seq.to_be_bytes()); // Sender Sequence Number
        pkt.extend_from_slice(&ts.to_be_bytes()); // Sender Timestamp
        pkt.extend_from_slice(&err_est.to_be_bytes()); // Sender Error Estimate
        pkt.extend_from_slice(&[0u8; 2]); // MBZ
        pkt.push(sender_ttl);
        if !payload_bytes.is_empty() {
            pkt.extend_from_slice(payload_bytes);
        } else if let Some(pad) = spec.padding
            && pad > 0
        {
            pkt.resize(pkt.len() + usize::from(pad), 0);
        }
        return pkt;
    }

    // TWAMP-Test Session-Sender (14-byte header + padding or payload)
    let mut pkt = Vec::with_capacity(14 + payload_bytes.len().max(27));
    pkt.extend_from_slice(&seq.to_be_bytes());
    pkt.extend_from_slice(&ts.to_be_bytes());
    pkt.extend_from_slice(&err_est.to_be_bytes());
    if !payload_bytes.is_empty() {
        pkt.extend_from_slice(payload_bytes);
        if let Some(pad) = spec.padding
            && pad > 0
        {
            pkt.resize(pkt.len() + usize::from(pad), 0);
        }
    } else {
        let pad_len = usize::from(spec.padding.unwrap_or(27));
        pkt.resize(pkt.len() + pad_len, 0);
    }
    pkt
}
