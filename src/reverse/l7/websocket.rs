//! WebSocket (`WEBSOCKET`, RFC 6455) Layer 7 framing PCAP-to-`.fasm` decompiler.
//!
//! This module implements the fuzz-safe reverse dissector for RFC 6455 `WEBSOCKET` data and
//! control frames carried over TCP ports `80`, `443`, `8080`, and `8443`. It validates reserved
//! header bits (`RSV1..RSV3 == 0`), decodes opcodes (`text`, `binary`, `close`, `ping`, `pong`),
//! `fin_bit`, extended 16-bit and 64-bit big-endian payload lengths, and 32-bit client masking
//! keys (`mask_key`), unmasking payload bytes so the forward compiler reproduces identical wire
//! frames.

use alloc::format;
use alloc::vec::Vec;
use core::fmt::Write as _;

use crate::ast::Protocol;
use crate::reverse::{ProtocolDissection, sd};

use super::checked_be_u16;

/// Dissects an RFC 6455 WebSocket binary, text, or control frame.
pub(crate) fn dissect_websocket(payload: &[u8]) -> Option<ProtocolDissection> {
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
    let len7 = (b1 & 0x7F) as usize;
    let (content_len, mut offset) = if len7 <= 125 {
        (len7, 2usize)
    } else if len7 == 126 {
        (checked_be_u16(payload, 2)? as usize, 4usize)
    } else {
        let len64 = u64::from_be_bytes(payload.get(2..10)?.try_into().ok()?);
        (usize::try_from(len64).ok()?, 10usize)
    };

    let mut mask_key = 0x12345678u32;
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
        let _ = write!(tokens, " fin_bit {fin_bit}");
    }
    if masked && mask_key != 0x12345678 {
        let _ = write!(tokens, " mask_key 0x{mask_key:08x}");
    }
    let residual = if unmasked == b"ping" {
        Vec::new()
    } else {
        unmasked
    };
    Some(sd(Protocol::Websocket, tokens, residual))
}
