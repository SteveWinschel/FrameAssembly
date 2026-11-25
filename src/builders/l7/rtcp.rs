//! Real-time Transport Control Protocol (RTCP, RFC 3550) Layer 7 wire payload builder.
//!
//! This module implements [`build_rtcp_payload`], which serializes a [`RtcpSpec`] AST
//! specification into an RFC 3550 Real-time Transport Control Protocol (RTCP) packet over UDP
//! port 5005. It builds 32-bit-word-aligned RTCP packets for Sender Reports (`sr`, `PT = 200`),
//! Receiver Reports (`rr`, `PT = 201`), Source Descriptions (`sdes`, `PT = 202` with `CNAME` item),
//! Goodbye (`bye`, `PT = 203` with optional reason), and Application-Defined (`app`, `PT = 204`)
//! feedback frames with automatic word-length headers.

use crate::ast::*;
use crate::builders::WireContext;
use alloc::vec::Vec;

/// Encodes a 24-byte RFC 3550 §6.4.1 Reception Report Block for `SR` (`RC=1`) or `RR` (`RC=1`).
fn push_report_block(buf: &mut Vec<u8>, spec: &RtcpSpec) {
    buf.extend_from_slice(&0x8765_4321u32.to_be_bytes()); // SSRC_1
    buf.push(spec.fraction.unwrap_or(0)); // fraction lost
    let lost = spec.lost.unwrap_or(0) & 0x00FF_FFFF;
    buf.push((lost >> 16) as u8);
    buf.push((lost >> 8) as u8);
    buf.push(lost as u8);
    buf.extend_from_slice(&spec.seq_num.unwrap_or(1).to_be_bytes()); // extended highest seqnum
    buf.extend_from_slice(&spec.jitter.unwrap_or(0).to_be_bytes()); // interarrival jitter
    buf.extend_from_slice(&0u32.to_be_bytes()); // LSR
    buf.extend_from_slice(&0u32.to_be_bytes()); // DLSR
}

/// Builds an RFC 3550 RTCP media control and quality feedback payload.
pub fn build_rtcp_payload(
    _ctx: &WireContext,
    spec: &RtcpSpec,
    payload_bytes: &[u8],
) -> Vec<u8> {
    let has_rr_fields = spec.fraction.is_some()
        || spec.lost.is_some()
        || spec.jitter.is_some()
        || spec.seq_num.is_some();
    let pt = spec.pt.unwrap_or(if spec.reason.is_some() {
        203
    } else if spec.cname.is_some() {
        202
    } else if has_rr_fields {
        201
    } else {
        200
    });
    let ssrc = spec.ssrc.unwrap_or(0x1234_5678);
    let mut pkt = Vec::new();

    match pt {
        200 => {
            // Sender Report (SR)
            let rc = u8::from(has_rr_fields);
            let len_words: u16 = if rc == 0 { 6 } else { 12 };
            pkt.push(0x80 | rc);
            pkt.push(200);
            pkt.extend_from_slice(&len_words.to_be_bytes());
            pkt.extend_from_slice(&ssrc.to_be_bytes());
            pkt.extend_from_slice(&0u64.to_be_bytes()); // NTP timestamp MSW/LSW
            pkt.extend_from_slice(&spec.timestamp.unwrap_or(160).to_be_bytes());
            pkt.extend_from_slice(&spec.packets.unwrap_or(10).to_be_bytes());
            pkt.extend_from_slice(&spec.octets.unwrap_or(1600).to_be_bytes());
            if rc == 1 {
                push_report_block(&mut pkt, spec);
            }
        }
        201 => {
            // Receiver Report (RR, RC=1)
            pkt.push(0x81);
            pkt.push(201);
            pkt.extend_from_slice(&7u16.to_be_bytes());
            pkt.extend_from_slice(&ssrc.to_be_bytes());
            push_report_block(&mut pkt, spec);
        }
        202 => {
            // Source Description (SDES, SC=1, CNAME=1)
            let cname = spec.cname.unwrap_or("user@frameassembly.local").as_bytes();
            let item_len = cname.len().min(255);
            pkt.push(0x81);
            pkt.push(202);
            pkt.extend_from_slice(&0u16.to_be_bytes()); // placeholder
            pkt.extend_from_slice(&ssrc.to_be_bytes());
            pkt.push(0x01); // CNAME item type
            pkt.push(item_len as u8);
            pkt.extend_from_slice(&cname[..item_len]);
            pkt.push(0x00); // END item
            while !pkt.len().is_multiple_of(4) {
                pkt.push(0x00);
            }
            let len_words = ((pkt.len() / 4) - 1) as u16;
            pkt[2..4].copy_from_slice(&len_words.to_be_bytes());
        }
        203 => {
            // Goodbye (BYE, SC=1)
            pkt.push(0x81);
            pkt.push(203);
            pkt.extend_from_slice(&0u16.to_be_bytes());
            pkt.extend_from_slice(&ssrc.to_be_bytes());
            if let Some(reason) = spec.reason {
                let rbytes = reason.as_bytes();
                let rlen = rbytes.len().min(255);
                pkt.push(rlen as u8);
                pkt.extend_from_slice(&rbytes[..rlen]);
                while !pkt.len().is_multiple_of(4) {
                    pkt.push(0x00);
                }
            }
            let len_words = ((pkt.len() / 4) - 1) as u16;
            pkt[2..4].copy_from_slice(&len_words.to_be_bytes());
        }
        204 => {
            // Application-Defined (APP)
            pkt.push(0x80);
            pkt.push(204);
            pkt.extend_from_slice(&2u16.to_be_bytes());
            pkt.extend_from_slice(&ssrc.to_be_bytes());
            let mut name = [b' '; 4];
            let raw_name = spec.cname.unwrap_or("FRAM").as_bytes();
            let copy_len = raw_name.len().min(4);
            name[..copy_len].copy_from_slice(&raw_name[..copy_len]);
            pkt.extend_from_slice(&name);
        }
        _ => {
            pkt.push(0x80);
            pkt.push(pt);
            pkt.extend_from_slice(&1u16.to_be_bytes());
            pkt.extend_from_slice(&ssrc.to_be_bytes());
        }
    }

    if !payload_bytes.is_empty() {
        pkt.extend_from_slice(payload_bytes);
    }
    pkt
}
