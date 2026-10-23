//! TLS protocol wire builder.

use crate::ast::*;
use crate::builders::WireContext;
use alloc::vec::Vec;

/// Builds an RFC 8446 TLS 1.3 handshake record payload.
pub fn build_tls_payload(
    _ctx: &WireContext,
    spec: &TlsSpec,
    payload_bytes: &[u8],
) -> Vec<u8> {
    let rec_version = spec.record_version.unwrap_or(0x0303); // TLS 1.2 compatibility layer

    if spec.is_server_hello {
        // ServerHello Handshake
        let mut hs_body = Vec::new();
        hs_body.extend_from_slice(&0x0303u16.to_be_bytes()); // Server version
        hs_body.extend_from_slice(&[0xaa; 32]); // Server Random
        hs_body.push(0); // Session ID length: 0
        hs_body.extend_from_slice(&0x1301u16.to_be_bytes()); // TLS_AES_128_GCM_SHA256
        hs_body.push(0); // Compression Method 0 (null)
        hs_body.extend_from_slice(&0u16.to_be_bytes()); // Extensions length: 0

        let hs_len = hs_body.len() as u32;
        let mut hs = alloc::vec![
            2, // Handshake Type 2: ServerHello
            (hs_len >> 16) as u8,
            (hs_len >> 8) as u8,
            hs_len as u8,
        ];
        hs.extend_from_slice(&hs_body);

        let rec_len = hs.len() as u16;
        let mut rec = Vec::new();
        rec.push(22); // ContentType: Handshake (22)
        rec.extend_from_slice(&rec_version.to_be_bytes());
        rec.extend_from_slice(&rec_len.to_be_bytes());
        rec.extend_from_slice(&hs);
        return rec;
    }

    // Default: ClientHello Handshake
    let mut hs_body = Vec::new();
    hs_body.extend_from_slice(&0x0303u16.to_be_bytes()); // Client version TLS 1.2
    hs_body.extend_from_slice(&[0x11; 32]); // Client Random
    hs_body.push(0); // Session ID length: 0

    // Cipher Suites (length 2 + suites)
    hs_body.extend_from_slice(&4u16.to_be_bytes()); // 4 bytes
    hs_body.extend_from_slice(&0x1301u16.to_be_bytes()); // TLS_AES_128_GCM_SHA256
    hs_body.extend_from_slice(&0x1302u16.to_be_bytes()); // TLS_AES_256_GCM_SHA384

    // Compression Methods
    hs_body.push(1); // 1 method
    hs_body.push(0); // null

    // Extensions
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

    hs_body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
    hs_body.extend_from_slice(&exts);

    let hs_len = hs_body.len() as u32;
    let mut hs = alloc::vec![
        1, // Handshake Type 1: ClientHello
        (hs_len >> 16) as u8,
        (hs_len >> 8) as u8,
        hs_len as u8,
    ];
    hs.extend_from_slice(&hs_body);

    if !payload_bytes.is_empty() {
        hs.extend_from_slice(payload_bytes);
    }

    let rec_len = hs.len() as u16;
    let mut rec = Vec::new();
    rec.push(22); // ContentType: Handshake (22)
    rec.extend_from_slice(&rec_version.to_be_bytes());
    rec.extend_from_slice(&rec_len.to_be_bytes());
    rec.extend_from_slice(&hs);
    rec
}
