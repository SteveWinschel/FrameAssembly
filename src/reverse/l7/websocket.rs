//! WebSocket (`websocket`, RFC 6455) Layer 7 framing PCAP-to-`.frasm` decompiler.
//!
//! This module implements the fuzz-safe reverse dissector for RFC 6455 `websocket` data and
//! control frames carried over TCP or SCTP ports `80`, `443`, `8080`, and `8443`. It validates
//! reserved header bits (`RSV1..RSV3 == 0`), decodes opcodes (`text`, `binary`, `close`, `ping`,
//! `pong`), `finbit`, extended 16-bit and 64-bit lengths, 32-bit client masking keys (`maskkey`),
//! unmasked server-originated replies, and empty zero-byte `payload ""` frames cleanly.

use alloc::format;
use alloc::vec::Vec;
use core::fmt::Write as _;

use crate::ast::Protocol;
use crate::reverse::{ProtocolDissection, sd};

use super::checked_be_u16;

/// Returns `true` when `(src_port, dst_port)` identifies a server-originated WebSocket flow.
fn is_websocket_server_src(src_port: u16, dst_port: u16) -> bool {
    let ws_port = |p: u16| matches!(p, 80 | 443 | 8080 | 8443);
    (ws_port(src_port) && !ws_port(dst_port)) || (src_port < 1024 && dst_port >= 1024)
}

/// Dissects an RFC 6455 WebSocket binary, text, or control frame.
pub(crate) fn dissect_websocket(
    payload: &[u8],
    src_port: u16,
    dst_port: u16,
) -> Option<ProtocolDissection> {
    let b0 = *payload.first()?;
    let b1 = *payload.get(1)?;
    if (b0 & 0x70) != 0 {
        return None;
    }
    let fin_bit = (b0 >> 7) & 0x01;
    let opcode_tok = match b0 & 0x0F {
        1 => "text",
        2 => "binary",
        8 => "close",
        9 => "ping",
        10 => "pong",
        _ => return None,
    };

    let masked = (b1 & 0x80) != 0;
    let server_src = is_websocket_server_src(src_port, dst_port);
    if !masked && !server_src {
        return None;
    }
    let len7 = (b1 & 0x7F) as usize;
    let (content_len, mut offset) = if len7 <= 125 {
        (len7, 2usize)
    } else if len7 == 126 {
        (checked_be_u16(payload, 2)? as usize, 4usize)
    } else {
        let len64 = u64::from_be_bytes(payload.get(2..10)?.try_into().ok()?);
        (usize::try_from(len64).ok()?, 10usize)
    };

    let mut mask_key = 0x1234_5678u32;
    let mut mask_bytes = [0u8; 4];
    if masked {
        mask_bytes.copy_from_slice(payload.get(offset..offset.checked_add(4)?)?);
        mask_key = u32::from_be_bytes(mask_bytes);
        offset = offset.checked_add(4)?;
    }
    if offset.checked_add(content_len)? != payload.len() {
        return None;
    }

    let raw_data = payload.get(offset..offset + content_len)?;
    let unmasked: Vec<u8> = if masked {
        raw_data
            .iter()
            .enumerate()
            .map(|(i, &b)| b ^ mask_bytes[i % 4])
            .collect()
    } else {
        raw_data.to_vec()
    };

    let mut tokens = format!("websocket {opcode_tok}");
    if fin_bit != 1 {
        let _ = write!(tokens, " finbit {fin_bit}");
    }
    if masked && (server_src || mask_key != 0x1234_5678) {
        let _ = write!(tokens, " maskkey 0x{mask_key:08x}");
    }
    let default_payload: &[u8] = if opcode_tok == "close" {
        &[0x03, 0xE8]
    } else {
        b"ping"
    };
    let residual = if unmasked.is_empty() {
        tokens.push_str(" payload \"\"");
        Vec::new()
    } else if unmasked == default_payload {
        Vec::new()
    } else {
        unmasked
    };
    Some(sd(Protocol::Websocket, tokens, residual))
}
