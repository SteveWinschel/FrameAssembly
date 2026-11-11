//! Real-time Transport Protocol (`rtp`, RFC 3550) Layer 7 media stream PCAP-to-`.fasm` decompiler.
//!
//! This module implements the fuzz-safe reverse dissector for RFC 3550 `rtp` 12-byte fixed headers
//! (`V=2`, `P=0`, `X=0`, `CC=0`) and audio or video media payloads carried over UDP ports `5004`,
//! `50004`, `10000`, `10002`, and `60000`. It decodes the 7-bit payload type (`pt`), 16-bit
//! sequence number (`seq`), 32-bit media `timestamp`, 32-bit synchronization source (`ssrc`), and
//! `marker` bit while eliding default 160-byte G.711 PCMU silence and preserving custom audio
//! frames losslessly in `residual_payload`.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write as _;

use crate::ast::Protocol;
use crate::reverse::{ProtocolDissection, sd};

use super::{checked_be_u16, checked_be_u32};

/// Dissects an RFC 3550 RTP media frame on UDP port `5004`.
pub(crate) fn dissect_rtp(payload: &[u8]) -> Option<ProtocolDissection> {
    if payload.len() < 12 || payload[0] != 0x80 {
        return None;
    }
    let marker = (payload[1] >> 7) & 0x01;
    let pt = payload[1] & 0x7F;
    let seq = checked_be_u16(payload, 2)?;
    let timestamp = checked_be_u32(payload, 4)?;
    let ssrc = checked_be_u32(payload, 8)?;
    let audio = payload.get(12..)?;

    let mut tokens = String::from("rtp");
    if pt != 0 {
        let _ = write!(tokens, " pt {pt}");
    }
    if seq != 1 {
        let _ = write!(tokens, " seq {seq}");
    }
    if timestamp != 160 {
        let _ = write!(tokens, " timestamp {timestamp}");
    }
    if ssrc != 0x12345678 {
        let _ = write!(tokens, " ssrc 0x{ssrc:08x}");
    }
    if marker != 0 {
        let _ = write!(tokens, " marker {marker}");
    }

    let residual = if audio == [0u8; 160] {
        Vec::new()
    } else {
        audio.to_vec()
    };
    Some(sd(Protocol::Rtp, tokens, residual))
}
