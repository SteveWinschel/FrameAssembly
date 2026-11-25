//! Transport Layer Security (TLS 1.2 / TLS 1.3) (RFC 8446 (TLS 1.3) / RFC 5246 (TLS 1.2) / RFC 6066 (SNI) / RFC 7301 (ALPN)) Layer 7 wire packet builder.
//!
//! This module synthesizes deterministic on-the-wire Transport Layer Security (TLS 1.2 / TLS 1.3) frames over TCP port 443.
//! The wire encoder constructs a 5-byte TLS Record Layer header (8-bit ContentType: `21` Alert, `22` Handshake, `23` ApplicationData; 16-bit Legacy Record Version e.g. `0x0303`; 16-bit Length) encapsulating a 4-byte Handshake header (8-bit HandshakeType: `1` ClientHello, `2` ServerHello, `11` Certificate, `20` Finished; 24-bit Length), 32-byte Random nonce, CipherSuite list (`0x1301` TLS_AES_128_GCM_SHA256, `0x1302` TLS_AES_256_GCM_SHA384), and SNI (`0x0000`) / ALPN (`0x0010`) extensions. When optional fields in [`TlsSpec`]
//! are omitted in the `.frasm` source, RFC-compliant default values are automatically populated.
//!
//! Canonical `.frasm` syntax:
//! `a -> b tls [clienthello | serverhello | certificate | finished | appdata | alert] [recordversion <u16>] [handshakeversion <u16>] [sni <str>] [ciphersuite <u16>] [alpn <str>]`

use crate::ast::*;
use crate::builders::WireContext;
use alloc::vec::Vec;

/// Returns `true` when `cs` is an RFC 8446 TLS 1.3 cipher suite (`0x1301..=0x1305`).
const fn is_tls13_ciphersuite(cs: u16) -> bool {
    matches!(cs, 0x1301..=0x1305)
}

/// Appends SNI (`0x0000`), ALPN (`0x0010`), mandatory TLS 1.3 extensions, and optional `0xFFFF` payload carrier.
fn build_tls_extensions(
    hs_type: u8,
    is_tls13: bool,
    sni: Option<&str>,
    alpn: Option<&str>,
    extra_exts: &[u8],
    payload_bytes: &[u8],
) -> Vec<u8> {
    let mut exts = Vec::new();
    if let Some(sni_name) = sni {
        let raw = sni_name.as_bytes();
        let sni_bytes = &raw[..raw.len().min(usize::from(u16::MAX) - 5)];
        exts.extend_from_slice(&0u16.to_be_bytes()); // Extension Type 0: server_name
        let ext_len = (sni_bytes.len() + 5) as u16;
        exts.extend_from_slice(&ext_len.to_be_bytes());
        let list_len = (sni_bytes.len() + 3) as u16;
        exts.extend_from_slice(&list_len.to_be_bytes());
        exts.push(0); // HostName Type 0
        exts.extend_from_slice(&(sni_bytes.len() as u16).to_be_bytes());
        exts.extend_from_slice(sni_bytes);
    }
    if let Some(alpn_proto) = alpn {
        let raw = alpn_proto.as_bytes();
        let alpn_bytes = &raw[..raw.len().min(255)];
        exts.extend_from_slice(&0x0010u16.to_be_bytes()); // Extension Type 16: application_layer_protocol_negotiation
        let ext_len = (alpn_bytes.len() + 3) as u16;
        exts.extend_from_slice(&ext_len.to_be_bytes());
        let list_len = (alpn_bytes.len() + 1) as u16;
        exts.extend_from_slice(&list_len.to_be_bytes());
        exts.push(alpn_bytes.len() as u8);
        exts.extend_from_slice(alpn_bytes);
    }
    if is_tls13 {
        if hs_type == 1 {
            // supported_versions (0x002b): offers TLS 1.3 (0x0304) and TLS 1.2 (0x0303)
            exts.extend_from_slice(&[0x00, 0x2b, 0x00, 0x05, 0x04, 0x03, 0x04, 0x03, 0x03]);
            // supported_groups (0x000a): x25519 (0x001d), secp256r1 (0x0017)
            exts.extend_from_slice(&[0x00, 0x0a, 0x00, 0x06, 0x00, 0x04, 0x00, 0x1d, 0x00, 0x17]);
            // signature_algorithms (0x000d): ecdsa_secp256r1_sha256, rsa_pss_rsae_sha256, rsa_pkcs1_sha256
            exts.extend_from_slice(&[
                0x00, 0x0d, 0x00, 0x08, 0x00, 0x06, 0x04, 0x03, 0x08, 0x04, 0x04, 0x01,
            ]);
            // key_share (0x0033): client_shares x25519 (0x001d), 32-byte key_exchange
            exts.extend_from_slice(&[
                0x00, 0x33, 0x00, 0x26, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20,
            ]);
            exts.extend_from_slice(&[0x42; 32]);
        } else if hs_type == 2 {
            // supported_versions (0x002b): ServerHello selected_version = TLS 1.3 (0x0304)
            exts.extend_from_slice(&[0x00, 0x2b, 0x00, 0x02, 0x03, 0x04]);
            // key_share (0x0033): server_share x25519 (0x001d), 32-byte key_exchange
            exts.extend_from_slice(&[0x00, 0x33, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20]);
            exts.extend_from_slice(&[0x43; 32]);
        }
    }
    if !extra_exts.is_empty() {
        exts.extend_from_slice(extra_exts);
    }
    if (hs_type == 1 || hs_type == 2) && !payload_bytes.is_empty() {
        let max_ext = usize::from(u16::MAX).saturating_sub(exts.len().saturating_add(64));
        let p_slice = &payload_bytes[..payload_bytes.len().min(max_ext)];
        exts.extend_from_slice(&0xFFFFu16.to_be_bytes()); // Private-use Extension Type 0xFFFF
        exts.extend_from_slice(&(p_slice.len() as u16).to_be_bytes());
        exts.extend_from_slice(p_slice);
    }
    exts
}

/// Builds a bare TLS 1.3 Handshake `ClientHello` message (`0x01 || uint24 len || body`) for QUIC `CRYPTO` frames.
pub(crate) fn build_tls_client_hello_handshake(
    sni: Option<&str>,
    alpn: Option<&str>,
    cs: u16,
    extra_exts: &[u8],
) -> Vec<u8> {
    let exts = build_tls_extensions(1, true, sni, alpn, extra_exts, &[]);
    let mut hs_body = Vec::with_capacity(64 + exts.len());
    hs_body.extend_from_slice(&0x0303u16.to_be_bytes()); // legacy_version = TLS 1.2
    hs_body.extend_from_slice(&[0x11; 32]); // Client Random
    hs_body.push(0); // Session ID length: 0
    let fallback_cs: u16 = if cs == 0x1302 { 0x1301 } else { 0x1302 };
    hs_body.extend_from_slice(&4u16.to_be_bytes());
    hs_body.extend_from_slice(&cs.to_be_bytes());
    hs_body.extend_from_slice(&fallback_cs.to_be_bytes());
    hs_body.push(1); // Compression Methods length
    hs_body.push(0); // null
    hs_body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
    hs_body.extend_from_slice(&exts);

    let hs_len = hs_body.len() as u32;
    let mut hs = Vec::with_capacity(4 + hs_body.len());
    hs.push(1); // HandshakeType::ClientHello
    hs.push((hs_len >> 16) as u8);
    hs.push((hs_len >> 8) as u8);
    hs.push(hs_len as u8);
    hs.extend_from_slice(&hs_body);
    hs
}

/// Builds an RFC 8446 TLS 1.3 handshake record payload.
/// Syntax mapping: `tls [clienthello | serverhello | certificate | finished | appdata | alert] [recordversion <u16>] [handshakeversion <u16>] [sni <str>] [ciphersuite <u16>] [alpn <str>]`
#[doc(alias = "TLS")]
#[doc(alias = "TLS13")]
#[doc(alias = "RFC8446")]
#[doc(alias = "SNI")]
#[doc(alias = "ALPN")]
#[doc(alias = "CIPHERSUITE")]
pub fn build_tls_payload(
    _ctx: &WireContext,
    spec: &TlsSpec,
    payload_bytes: &[u8],
) -> Vec<u8> {
    let rec_version = spec.record_version.unwrap_or(0x0303); // TLS 1.2 compatibility layer
    let hs_version = spec
        .handshake_version
        .or(spec.record_version)
        .unwrap_or(0x0303);
    let cs = spec.ciphersuite.unwrap_or(0x1301); // TLS_AES_128_GCM_SHA256
    let is_tls13 = is_tls13_ciphersuite(cs)
        || spec.handshake_version == Some(0x0304)
        || spec.record_version == Some(0x0304);

    if spec.is_alert {
        let body: &[u8] = if !payload_bytes.is_empty() {
            payload_bytes
        } else {
            &[2, 40] // Level 2 (Fatal), Description 40 (handshake_failure)
        };
        let mut rec = Vec::with_capacity(5 + body.len());
        rec.push(21); // ContentType: Alert (21)
        rec.extend_from_slice(&rec_version.to_be_bytes());
        rec.extend_from_slice(&(body.len() as u16).to_be_bytes());
        rec.extend_from_slice(body);
        return rec;
    }

    if spec.is_app_data {
        let body: &[u8] = if !payload_bytes.is_empty() {
            payload_bytes
        } else {
            b"\x00\x01\x02\x03\x04\x05\x06\x07"
        };
        let mut rec = Vec::with_capacity(5 + body.len());
        rec.push(23); // ContentType: ApplicationData (23)
        rec.extend_from_slice(&rec_version.to_be_bytes());
        rec.extend_from_slice(&(body.len() as u16).to_be_bytes());
        rec.extend_from_slice(body);
        return rec;
    }

    let hs_type: u8 = if spec.is_client_hello {
        1 // ClientHello
    } else if spec.is_server_hello {
        2 // ServerHello
    } else if spec.is_certificate {
        11 // Certificate
    } else if spec.is_finished {
        20 // Finished
    } else {
        1 // ClientHello (default)
    };

    let exts = build_tls_extensions(hs_type, is_tls13, spec.sni, spec.alpn, &[], payload_bytes);

    let mut hs_body = Vec::new();
    if hs_type == 2 {
        // ServerHello Handshake (RFC 8446 §4.1.3 sets legacy_version = 0x0303 for TLS 1.3)
        let sh_ver = if is_tls13 && spec.handshake_version.is_none() {
            0x0303
        } else {
            hs_version
        };
        hs_body.extend_from_slice(&sh_ver.to_be_bytes());
        hs_body.extend_from_slice(&[0xaa; 32]); // Server Random
        hs_body.push(0); // Session ID length: 0
        hs_body.extend_from_slice(&cs.to_be_bytes());
        hs_body.push(0); // Compression Method 0 (null)
        hs_body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        hs_body.extend_from_slice(&exts);
    } else if hs_type == 11 {
        // Certificate Handshake
        if !payload_bytes.is_empty() {
            hs_body.extend_from_slice(payload_bytes);
        } else {
            hs_body.extend_from_slice(&[0x00, 0x00, 0x00]); // Empty certificate_list
        }
    } else if hs_type == 20 {
        // Finished Handshake
        if !payload_bytes.is_empty() {
            hs_body.extend_from_slice(payload_bytes);
        } else {
            hs_body.extend_from_slice(&[0xdd; 32]); // 32-byte verify_data
        }
    } else {
        // ClientHello Handshake (hs_type == 1)
        let ch_ver = if is_tls13 && spec.handshake_version.is_none() {
            0x0303
        } else {
            hs_version
        };
        hs_body.extend_from_slice(&ch_ver.to_be_bytes());
        hs_body.extend_from_slice(&[0x11; 32]); // Client Random
        hs_body.push(0); // Session ID length: 0

        if is_tls13 {
            let fallback_cs: u16 = if cs == 0x1302 { 0x1301 } else { 0x1302 };
            hs_body.extend_from_slice(&4u16.to_be_bytes());
            hs_body.extend_from_slice(&cs.to_be_bytes());
            hs_body.extend_from_slice(&fallback_cs.to_be_bytes());
        } else {
            hs_body.extend_from_slice(&2u16.to_be_bytes());
            hs_body.extend_from_slice(&cs.to_be_bytes());
        }

        // Compression Methods
        hs_body.push(1); // 1 method
        hs_body.push(0); // null

        hs_body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        hs_body.extend_from_slice(&exts);
    }

    let hs_len = hs_body.len() as u32;
    let mut hs = alloc::vec![
        hs_type,
        (hs_len >> 16) as u8,
        (hs_len >> 8) as u8,
        hs_len as u8,
    ];
    hs.extend_from_slice(&hs_body);

    let rec_len = hs.len().min(usize::from(u16::MAX)) as u16;
    let mut rec = Vec::with_capacity(5 + hs.len());
    rec.push(22); // ContentType: Handshake (22)
    rec.extend_from_slice(&rec_version.to_be_bytes());
    rec.extend_from_slice(&rec_len.to_be_bytes());
    rec.extend_from_slice(&hs);
    rec
}
