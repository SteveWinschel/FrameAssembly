//! Transport Layer Security (TLS 1.2 / TLS 1.3) (RFC 8446 (TLS 1.3) / RFC 5246 (TLS 1.2) / RFC 6066 (SNI) / RFC 7301 (ALPN)) Layer 7 wire packet builder.
//!
//! This module synthesizes deterministic on-the-wire Transport Layer Security (TLS 1.2 / TLS 1.3) frames over TCP port 443.
//! The wire encoder constructs a 5-byte TLS Record Layer header (8-bit ContentType: `21` Alert, `22` Handshake, `23` ApplicationData; 16-bit Legacy Record Version e.g. `0x0303`; 16-bit Length) encapsulating a 4-byte Handshake header (8-bit HandshakeType: `1` ClientHello, `2` ServerHello, `11` Certificate, `20` Finished; 24-bit Length), 32-byte Random nonce, CipherSuite list (`0x1301` TLS_AES_128_GCM_SHA256, `0x1302` TLS_AES_256_GCM_SHA384), and SNI (`0x0000`) / ALPN (`0x0010`) extensions. When optional fields in [`TlsSpec`]
//! are omitted in the `.fasm` source, RFC-compliant default values are automatically populated.
//!
//! Canonical `.fasm` syntax:
//! `a -> b TLS [CLIENT_HELLO | SERVER_HELLO | CERTIFICATE | FINISHED | APP_DATA | ALERT] [RECORD_VERSION <u16>] [HANDSHAKE_VERSION <u16>] [SNI <str>] [CIPHERSUITE <u16>] [ALPN <str>]`

use crate::ast::*;
use crate::builders::WireContext;
use alloc::vec::Vec;

/// Builds an RFC 8446 TLS 1.3 handshake record payload.
/// Syntax mapping: `TLS [CLIENT_HELLO | SERVER_HELLO | CERTIFICATE | FINISHED | APP_DATA | ALERT] [RECORD_VERSION <u16>] [HANDSHAKE_VERSION <u16>] [SNI <str>] [CIPHERSUITE <u16>] [ALPN <str>]`
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

    // Build shared TLS Extensions (RFC 6066 SNI 0x0000 and RFC 7301 ALPN 0x0010)
    let mut exts = Vec::new();
    if let Some(sni) = spec.sni {
        let sni_bytes = sni.as_bytes();
        exts.extend_from_slice(&0u16.to_be_bytes()); // Extension Type 0: server_name
        let ext_len = (sni_bytes.len() + 5) as u16;
        exts.extend_from_slice(&ext_len.to_be_bytes());
        let list_len = (sni_bytes.len() + 3) as u16;
        exts.extend_from_slice(&list_len.to_be_bytes());
        exts.push(0); // HostName Type 0
        exts.extend_from_slice(&(sni_bytes.len() as u16).to_be_bytes());
        exts.extend_from_slice(sni_bytes);
    }
    if let Some(alpn) = spec.alpn {
        let alpn_bytes = alpn.as_bytes();
        exts.extend_from_slice(&0x0010u16.to_be_bytes()); // Extension Type 16: application_layer_protocol_negotiation
        let ext_len = (alpn_bytes.len() + 3) as u16;
        exts.extend_from_slice(&ext_len.to_be_bytes());
        let list_len = (alpn_bytes.len() + 1) as u16;
        exts.extend_from_slice(&list_len.to_be_bytes());
        exts.push(alpn_bytes.len() as u8);
        exts.extend_from_slice(alpn_bytes);
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

    let mut hs_body = Vec::new();
    if hs_type == 2 {
        // ServerHello Handshake
        hs_body.extend_from_slice(&hs_version.to_be_bytes());
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
        hs_body.extend_from_slice(&hs_version.to_be_bytes());
        hs_body.extend_from_slice(&[0x11; 32]); // Client Random
        hs_body.push(0); // Session ID length: 0

        // Cipher Suites (4 bytes: primary + fallback)
        hs_body.extend_from_slice(&4u16.to_be_bytes());
        hs_body.extend_from_slice(&cs.to_be_bytes());
        hs_body.extend_from_slice(&0x1302u16.to_be_bytes()); // TLS_AES_256_GCM_SHA384

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

    if (hs_type == 1 || hs_type == 2) && !payload_bytes.is_empty() {
        hs.extend_from_slice(payload_bytes);
    }

    let rec_len = hs.len() as u16;
    let mut rec = Vec::with_capacity(5 + hs.len());
    rec.push(22); // ContentType: Handshake (22)
    rec.extend_from_slice(&rec_version.to_be_bytes());
    rec.extend_from_slice(&rec_len.to_be_bytes());
    rec.extend_from_slice(&hs);
    rec
}
