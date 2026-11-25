//! GPRS Tunneling Protocol User Plane (GTPv1-U, 3GPP TS 29.281) Layer 3 wire builder.
//!
//! Serializes a [`GtpuSpec`] into a 3GPP TS 29.281 GTPv1-U packet carried over UDP destination
//! port `2152`. Emits the 8-byte mandatory GTPv1 header (`Flags`, `Message Type`, 16-bit `Length`,
//! and 32-bit `teid`), optional 4-byte `seqnum`/`npdu`/`Next Extension Header` fields when
//! `E`/`S`/`PN` flags are set, and a 4-byte 5G PDU Session Container (`0x85`) when `qfi` is
//! supplied. Synthesizes inner IPv4+ICMPv4 payloads for `gpdu`, `Recovery` IEs for `echoreply`,
//! and `TEID Data I` + `Peer Address` IEs for `errorindication`.
//!
//! Canonical `.frasm` syntax:
//! `a -> b gtpu [gpdu | echorequest | echoreply | errorindication | endmarker] [teid <u32>] [flags <u8>] [seqnum <u16>] [npdu <u8>] [qfi <0..63>]`

use crate::ast::*;
use crate::builders::WireContext;
use alloc::vec::Vec;
use core::net::IpAddr;

/// Builds a 3GPP TS 29.281 GTPv1-U payload and returns `(bytes, 2152)` for UDP encapsulation.
pub fn build_gtpu_payload(ctx: &WireContext, spec: &GtpuSpec, payload: &[u8]) -> (Vec<u8>, u16) {
    let msg_type = spec.msg_type.unwrap_or(GtpuType::Gpdu);
    let type_code = match msg_type {
        GtpuType::EchoRequest => 1_u8,
        GtpuType::EchoReply => 2_u8,
        GtpuType::ErrorIndication => 26_u8,
        GtpuType::EndMarker => 254_u8,
        GtpuType::Gpdu => 255_u8,
    };

    let teid = spec.teid.unwrap_or(match msg_type {
        GtpuType::EchoRequest | GtpuType::EchoReply | GtpuType::ErrorIndication => 0,
        GtpuType::EndMarker | GtpuType::Gpdu => 1,
    });

    let mut flags = spec
        .flags
        .map_or(0x30_u8, |f| if (f & 0xE0) != 0 { f } else { 0x30 | f });
    if spec.qfi.is_some() {
        flags |= 0x04; // E bit
    }
    if spec.seqnum.is_some() || matches!(msg_type, GtpuType::EchoRequest | GtpuType::EchoReply) {
        flags |= 0x02; // S bit
    }
    if spec.npdu.is_some() {
        flags |= 0x01; // PN bit
    }

    let mut body = Vec::with_capacity(48 + payload.len());
    if (flags & 0x07) != 0 {
        let seq = spec.seqnum.unwrap_or(if (flags & 0x02) != 0 { 1 } else { 0 });
        let npdu = spec.npdu.unwrap_or(0);
        let has_ext = (flags & 0x04) != 0;
        let next_ext = if has_ext { 0x85_u8 } else { 0x00_u8 };
        body.extend_from_slice(&seq.to_be_bytes());
        body.push(npdu);
        body.push(next_ext);
        if has_ext {
            // 3GPP TS 38.415 PDU Session Container (Type 0x85): len=1 (4 bytes), UL Info, QFI, Next=0
            let qfi = spec.qfi.unwrap_or(1) & 0x3F;
            body.extend_from_slice(&[0x01, 0x10, qfi, 0x00]);
        }
    }

    if payload.is_empty() {
        match msg_type {
            GtpuType::Gpdu => {
                body.extend_from_slice(&super::gre::default_gre_inner_packet(0x0800));
            }
            GtpuType::EchoReply => {
                // Recovery IE (Type 14, Restart Counter = 0)
                body.extend_from_slice(&[14, 0]);
            }
            GtpuType::ErrorIndication => {
                // IE 16: Tunnel Endpoint Identifier Data I (5 bytes)
                body.push(16);
                body.extend_from_slice(&1_u32.to_be_bytes());
                // IE 133: GTP-U Peer Address (TLV)
                body.push(133);
                match ctx.src_ip {
                    IpAddr::V4(v4) => {
                        body.extend_from_slice(&4_u16.to_be_bytes());
                        body.extend_from_slice(&v4.octets());
                    }
                    IpAddr::V6(v6) => {
                        body.extend_from_slice(&16_u16.to_be_bytes());
                        body.extend_from_slice(&v6.octets());
                    }
                }
            }
            GtpuType::EchoRequest | GtpuType::EndMarker => {}
        }
    } else {
        body.extend_from_slice(payload);
    }

    let gtp_len = u16::try_from(body.len()).unwrap_or(u16::MAX);
    let mut gtpu = Vec::with_capacity(8 + body.len());
    gtpu.push(flags);
    gtpu.push(type_code);
    gtpu.extend_from_slice(&gtp_len.to_be_bytes());
    gtpu.extend_from_slice(&teid.to_be_bytes());
    gtpu.extend_from_slice(&body);

    (gtpu, 2152)
}
