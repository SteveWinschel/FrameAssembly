//! Trivial File Transfer Protocol (`tftp`, RFC 1350) Layer 7 PCAP-to-`.frasm` decompiler.
//!
//! This module implements the fuzz-safe reverse dissector for RFC 1350 `tftp` datagrams carried
//! over UDP port `69` and ephemeral data-transfer port pairs. It validates 16-bit big-endian
//! opcodes and NUL-terminated ASCII fields to decode Read Requests (`rrq`), Write Requests
//! (`wrq`), Data blocks (`data`), Acknowledgments (`ack`), and Error messages (`error`),
//! extracting `filename`, `mode`, `block`, `errcode`, and `errmsg` modifiers while preserving data
//! block payloads via residual bytes.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write as _;

use crate::ast::Protocol;
use crate::reverse::{ProtocolDissection, sd};

use super::{checked_be_u16, push_str_mod};

/// Dissects an RFC 1350 TFTP packet on UDP port `69`.
pub(crate) fn dissect_tftp(payload: &[u8]) -> Option<ProtocolDissection> {
    if payload.len() < 4 {
        return None;
    }
    let opcode = checked_be_u16(payload, 0)?;
    let rest = payload.get(2..)?;

    match opcode {
        1 | 2 => {
            let nul1 = rest.iter().position(|&b| b == 0)?;
            let filename = core::str::from_utf8(rest.get(..nul1)?).ok()?;
            let after_fn = rest.get(nul1 + 1..)?;
            let nul2 = after_fn.iter().position(|&b| b == 0)?;
            let mode = core::str::from_utf8(after_fn.get(..nul2)?).ok()?;
            let trailing = after_fn.get(nul2 + 1..)?;

            let mut tokens = String::from(if opcode == 1 { "tftp rrq" } else { "tftp wrq" });
            if filename != "boot.bin" {
                push_str_mod(&mut tokens, "filename", filename);
            }
            if mode != "octet" {
                push_str_mod(&mut tokens, "mode", mode);
            }
            Some(sd(Protocol::Tftp, tokens, trailing.to_vec()))
        }
        3 | 4 => {
            if opcode == 4 && rest.len() != 2 {
                return None;
            }
            let block = checked_be_u16(rest, 0)?;
            let mut tokens = String::from(if opcode == 3 { "tftp data" } else { "tftp ack" });
            if block != 1 {
                let _ = write!(tokens, " block {block}");
            }
            Some(sd(Protocol::Tftp, tokens, rest.get(2..)?.to_vec()))
        }
        5 => {
            let errcode = checked_be_u16(rest, 0)?;
            let msg_part = rest.get(2..)?;
            let nul = msg_part.iter().position(|&b| b == 0)?;
            if nul + 1 != msg_part.len() {
                return None;
            }
            let errmsg = core::str::from_utf8(msg_part.get(..nul)?).ok()?;
            let mut tokens = String::from("tftp error");
            if errcode != 1 {
                let _ = write!(tokens, " errcode {errcode}");
            }
            if errmsg != "File not found" {
                push_str_mod(&mut tokens, "errmsg", errmsg);
            }
            Some(sd(Protocol::Tftp, tokens, Vec::new()))
        }
        _ => None,
    }
}
