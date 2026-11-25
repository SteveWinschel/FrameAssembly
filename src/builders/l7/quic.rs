//! QUIC UDP-Based Multiplexed and Secure Transport (RFC 9000 (QUIC Transport) / RFC 9001 (QUIC-TLS) / RFC 9114 (HTTP/3)) Layer 7 wire packet builder.
//!
//! This module synthesizes deterministic on-the-wire QUIC UDP-Based Multiplexed and Secure Transport frames over UDP port 443.
//! The wire encoder constructs a RFC 9000 Long Header (`Header Form = 1`, `Fixed Bit = 1`, 2-bit Long Packet Type: `0x0` Initial with TLS 1.3 `ClientHello` `CRYPTO` + `PADDING` to >= 1200 bytes, `0x1` 0-RTT, `0x2` Handshake, `0x3` Retry; 32-bit Version e.g. `0x00000001` v1 or `0x6b3343cf` v2; `0..=20`-byte DCID/SCID; variable-length Token; Length; 1..=4-byte Packet Number) or 1-RTT Short Header (`Header Form = 0`, `Fixed Bit = 1`, DCID, Packet Number). When optional fields in [`QuicSpec`]
//! are omitted in the `.frasm` source, RFC-compliant default values are automatically populated.
//!
//! Canonical `.frasm` syntax:
//! `a -> b quic [initial | zerortt | handshake | retry | short] [version <u32>] [dcid <u64|hex>] [scid <u64|hex>] [token <str>] [pktnum <u32>]`

use crate::ast::*;
use crate::builders::WireContext;
use alloc::vec::Vec;

/// Appends an RFC 9000 §16 variable-length integer using the minimal 1-, 2-, or 4-byte encoding.
fn push_quic_varint_min(buf: &mut Vec<u8>, val: usize) {
    if val < 64 {
        buf.push(val as u8);
    } else if val < 16384 {
        buf.extend_from_slice(&(0x4000u16 | (val as u16)).to_be_bytes());
    } else {
        let clamped = (val as u32) & 0x3FFF_FFFF;
        buf.extend_from_slice(&(0x8000_0000u32 | clamped).to_be_bytes());
    }
}

/// Resolves a QUIC Connection ID (`0..=20` bytes) preferring explicit hex bytes over `u64` shorthand.
fn resolve_cid_bytes(bytes_opt: Option<&[u8]>, int_opt: Option<u64>, default_val: u32) -> Vec<u8> {
    if let Some(raw) = bytes_opt {
        return raw[..raw.len().min(20)].to_vec();
    }
    let val = int_opt.unwrap_or(u64::from(default_val));
    if val > u64::from(u32::MAX) {
        val.to_be_bytes().to_vec()
    } else {
        (val as u32).to_be_bytes().to_vec()
    }
}

/// Encodes an unprotected QUIC Packet Number in minimal 1..=4 big-endian bytes.
fn encode_pkt_num(pn: u32) -> ([u8; 4], usize) {
    if pn <= 0xFF {
        ([pn as u8, 0, 0, 0], 1)
    } else if pn <= 0xFFFF {
        let be = (pn as u16).to_be_bytes();
        ([be[0], be[1], 0, 0], 2)
    } else if pn <= 0x00FF_FFFF {
        ([(pn >> 16) as u8, (pn >> 8) as u8, pn as u8, 0], 3)
    } else {
        (pn.to_be_bytes(), 4)
    }
}

/// Builds a default RFC 9000 QUIC `Initial` payload containing a `CRYPTO` frame with a TLS 1.3 `ClientHello`.
fn build_initial_crypto_frame(scid: &[u8]) -> Vec<u8> {
    let mut tp = Vec::with_capacity(8 + scid.len());
    tp.extend_from_slice(&[0x01, 0x02, 0x67, 0x10]); // max_idle_timeout = 10000 ms
    tp.push(0x0f); // initial_source_connection_id
    tp.push(scid.len() as u8);
    tp.extend_from_slice(scid);

    let mut tp_ext = Vec::with_capacity(4 + tp.len());
    tp_ext.extend_from_slice(&0x0039u16.to_be_bytes()); // quic_transport_parameters
    tp_ext.extend_from_slice(&(tp.len() as u16).to_be_bytes());
    tp_ext.extend_from_slice(&tp);

    let tls_ch = super::tls::build_tls_client_hello_handshake(None, Some("h3"), 0x1301, &tp_ext);
    let mut crypto = Vec::with_capacity(6 + tls_ch.len());
    crypto.push(0x06); // CRYPTO frame
    crypto.push(0x00); // Offset = 0
    push_quic_varint_min(&mut crypto, tls_ch.len());
    crypto.extend_from_slice(&tls_ch);
    crypto
}

/// Builds an RFC 9000 QUIC packet payload.
/// Syntax mapping: `quic [initial | zerortt | handshake | retry | short] [version <u32>] [dcid <u64|hex>] [scid <u64|hex>] [token <str>] [pktnum <u32>]`
#[doc(alias = "QUIC")]
#[doc(alias = "HTTP3")]
#[doc(alias = "RFC9000")]
#[doc(alias = "DCID")]
#[doc(alias = "SCID")]
pub fn build_quic_payload(
    _ctx: &WireContext,
    spec: &QuicSpec,
    payload_bytes: &[u8],
) -> Vec<u8> {
    let mut pkt = Vec::new();
    let dcid = resolve_cid_bytes(spec.dcid_bytes.as_deref(), spec.dcid, 0x0102_0304);
    let (pn_bytes, pn_len) = encode_pkt_num(spec.pkt_num.unwrap_or(1));
    let pn_len_bits = (pn_len as u8) - 1;

    if spec.is_short
        && !spec.is_initial
        && !spec.is_zero_rtt
        && !spec.is_handshake
        && !spec.is_retry
    {
        // 1-RTT Short Header (Header Form = 0, Fixed Bit = 1 -> 0x40)
        pkt.push(0x40 | pn_len_bits);
        pkt.extend_from_slice(&dcid);
        pkt.extend_from_slice(&pn_bytes[..pn_len]);
        pkt.extend_from_slice(payload_bytes);
        return pkt;
    }

    let hdr_type: u8 = if spec.is_initial {
        0
    } else if spec.is_zero_rtt {
        1
    } else if spec.is_handshake {
        2
    } else if spec.is_retry {
        3
    } else {
        0
    };

    // Long Header: Header Form = 1 (0x80) | Fixed Bit = 1 (0x40) | Type (bits 4..5) | PN Len
    let first_byte = if hdr_type == 3 {
        0xC0 | ((hdr_type & 0x03) << 4)
    } else {
        0xC0 | ((hdr_type & 0x03) << 4) | pn_len_bits
    };
    pkt.push(first_byte);
    let version = spec.version.unwrap_or(0x0000_0001);
    pkt.extend_from_slice(&version.to_be_bytes());

    pkt.push(dcid.len() as u8);
    pkt.extend_from_slice(&dcid);

    let scid = resolve_cid_bytes(spec.scid_bytes.as_deref(), spec.scid, 0x0506_0708);
    pkt.push(scid.len() as u8);
    pkt.extend_from_slice(&scid);

    if hdr_type == 3 {
        // Retry packet: Retry Token + payload / 16-byte Retry Integrity Tag
        if let Some(tok) = spec.token {
            pkt.extend_from_slice(tok.as_bytes());
        }
        if !payload_bytes.is_empty() {
            pkt.extend_from_slice(payload_bytes);
        } else {
            pkt.extend_from_slice(&[0u8; 16]);
        }
        return pkt;
    }

    if hdr_type == 0 {
        // Initial packet includes RFC 9000 varint Token Length + Token
        if let Some(tok) = spec.token {
            push_quic_varint_min(&mut pkt, tok.len());
            pkt.extend_from_slice(tok.as_bytes());
        } else {
            pkt.push(0);
        }
    }

    let initial_body: Option<Vec<u8>> = if hdr_type == 0 && payload_bytes.is_empty() {
        let mut frames = build_initial_crypto_frame(&scid);
        let min_body_len = 1200usize.saturating_sub(pkt.len() + 2 + pn_len);
        if frames.len() < min_body_len && pn_len + min_body_len <= 0x3FFF {
            frames.resize(min_body_len, 0x00); // RFC 9000 §14.1 PADDING frames to >= 1200 bytes
        }
        Some(frames)
    } else {
        None
    };
    let body: &[u8] = initial_body.as_deref().unwrap_or(payload_bytes);

    // RFC 9000 §16 2-byte variable-length integer (prefix bits 01 -> 0x4000, or 4-byte when > 16383)
    let inner_len = pn_len + body.len();
    if inner_len <= 0x3FFF {
        let varint_len = 0x4000u16 | (inner_len as u16);
        pkt.extend_from_slice(&varint_len.to_be_bytes());
    } else {
        let varint_len = 0x8000_0000u32 | ((inner_len as u32) & 0x3FFF_FFFF);
        pkt.extend_from_slice(&varint_len.to_be_bytes());
    }
    pkt.extend_from_slice(&pn_bytes[..pn_len]);
    pkt.extend_from_slice(body);
    pkt
}
