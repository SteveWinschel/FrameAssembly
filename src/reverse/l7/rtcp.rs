//! Real-time Transport Control Protocol (`rtcp`, RFC 3550) Layer 7 PCAP-to-`.frasm` decompiler.
//!
//! This module implements the fuzz-safe reverse dissector for RFC 3550 `rtcp` media feedback
//! datagrams carried over UDP ports `5005`, `50005`, `10001`, `10003`, and `60001` (or SCTP).
//! It validates the 4-byte common RTCP header (`V=2`, `P=0`, `RC/SC`, `PT = 200..=204`, and
//! 32-bit word length), decodes Sender Reports (`sr`), Receiver Reports (`rr`), Source
//! Descriptions (`sdes` `CNAME`), Goodbye (`bye`), and Application-Defined (`app`) packets,
//! elides default counters, and preserves trailing payload bytes.

use alloc::string::String;
use core::fmt::Write as _;

use crate::ast::Protocol;
use crate::reverse::{ProtocolDissection, sd};

use super::{checked_be_u16, checked_be_u32, is_valid_raw_string_body, push_str_mod};

/// Decodes a 24-byte Reception Report Block starting at `off` in `payload`.
fn dissect_report_block(payload: &[u8], off: usize, tokens: &mut String, force_seq_if_default: bool) -> Option<()> {
    if checked_be_u32(payload, off)? != 0x8765_4321
        || checked_be_u32(payload, off + 16)? != 0
        || checked_be_u32(payload, off + 20)? != 0
    {
        return None;
    }
    let fraction = *payload.get(off + 4)?;
    let lost = (u32::from(*payload.get(off + 5)?) << 16)
        | (u32::from(*payload.get(off + 6)?) << 8)
        | u32::from(*payload.get(off + 7)?);
    let seqnum = checked_be_u32(payload, off + 8)?;
    let jitter = checked_be_u32(payload, off + 12)?;

    if fraction != 0 {
        let _ = write!(tokens, " fraction {fraction}");
    }
    if lost != 0 {
        let _ = write!(tokens, " lost {lost}");
    }
    if seqnum != 1 || (force_seq_if_default && fraction == 0 && lost == 0 && jitter == 0) {
        let _ = write!(tokens, " seqnum {seqnum}");
    }
    if jitter != 0 {
        let _ = write!(tokens, " jitter {jitter}");
    }
    Some(())
}

/// Dissects an RFC 3550 RTCP media control packet on UDP port `5005`.
pub(crate) fn dissect_rtcp(payload: &[u8]) -> Option<ProtocolDissection> {
    if payload.len() < 8 || (payload[0] & 0xE0) != 0x80 {
        return None;
    }
    let rc = payload[0] & 0x1F;
    let pt = payload[1];
    let words = checked_be_u16(payload, 2)? as usize;
    let word_len = words.checked_add(1)?.checked_mul(4)?;
    if word_len > payload.len() {
        return None;
    }
    let ssrc = checked_be_u32(payload, 4)?;
    let mut tokens = String::from("rtcp");

    match pt {
        200 => {
            if !((rc == 0 && word_len == 28) || (rc == 1 && word_len == 52)) {
                return None;
            }
            if checked_be_u32(payload, 8)? != 0 || checked_be_u32(payload, 12)? != 0 {
                return None;
            }
            let ts = checked_be_u32(payload, 16)?;
            let packets = checked_be_u32(payload, 20)?;
            let octets = checked_be_u32(payload, 24)?;
            if rc == 1 {
                tokens.push_str(" sr");
            }
            if ssrc != 0x1234_5678 {
                let _ = write!(tokens, " ssrc 0x{ssrc:08x}");
            }
            if ts != 160 {
                let _ = write!(tokens, " timestamp {ts}");
            }
            if packets != 10 {
                let _ = write!(tokens, " packets {packets}");
            }
            if octets != 1600 {
                let _ = write!(tokens, " octets {octets}");
            }
            if rc == 1 {
                dissect_report_block(payload, 28, &mut tokens, true)?;
            }
        }
        201 => {
            if rc != 1 || word_len != 32 {
                return None;
            }
            tokens.push_str(" rr");
            if ssrc != 0x1234_5678 {
                let _ = write!(tokens, " ssrc 0x{ssrc:08x}");
            }
            dissect_report_block(payload, 8, &mut tokens, false)?;
        }
        202 => {
            if rc != 1 || word_len < 12 || payload.get(8) != Some(&0x01) {
                return None;
            }
            let clen = *payload.get(9)? as usize;
            let cend = 10usize.checked_add(clen)?;
            if cend >= word_len {
                return None;
            }
            let cname = core::str::from_utf8(payload.get(10..cend)?).ok()?;
            if !is_valid_raw_string_body(cname) {
                return None;
            }
            if payload.get(cend..word_len)?.iter().any(|&b| b != 0) {
                return None;
            }
            tokens.push_str(" sdes");
            if ssrc != 0x1234_5678 {
                let _ = write!(tokens, " ssrc 0x{ssrc:08x}");
            }
            if cname != "user@frameassembly.local" {
                push_str_mod(&mut tokens, "cname", cname);
            }
        }
        203 => {
            if rc != 1 || word_len < 8 {
                return None;
            }
            tokens.push_str(" bye");
            if ssrc != 0x1234_5678 {
                let _ = write!(tokens, " ssrc 0x{ssrc:08x}");
            }
            if word_len > 8 {
                let rlen = *payload.get(8)? as usize;
                let rend = 9usize.checked_add(rlen)?;
                if rend > word_len || payload.get(rend..word_len)?.iter().any(|&b| b != 0) {
                    return None;
                }
                let reason = core::str::from_utf8(payload.get(9..rend)?).ok()?;
                if !is_valid_raw_string_body(reason) {
                    return None;
                }
                push_str_mod(&mut tokens, "reason", reason);
            }
        }
        204 => {
            if rc != 0 || word_len != 12 {
                return None;
            }
            let name_bytes = payload.get(8..12)?;
            let name = core::str::from_utf8(name_bytes).ok()?;
            if !is_valid_raw_string_body(name) {
                return None;
            }
            tokens.push_str(" app");
            if ssrc != 0x1234_5678 {
                let _ = write!(tokens, " ssrc 0x{ssrc:08x}");
            }
            if name != "FRAM" {
                push_str_mod(&mut tokens, "cname", name);
            }
        }
        _ => return None,
    }

    let residual = payload.get(word_len..)?.to_vec();
    Some(sd(Protocol::Rtcp, tokens, residual))
}
