//! gRPC Remote Procedure Call (`grpc`) Layer 7 PCAP-to-`.fasm` decompiler.
//!
//! This module implements the fuzz-safe reverse dissector for length-prefixed `grpc` frames (1-byte
//! compression flag `0x00` or `0x01` followed by a 4-byte big-endian message length) carried over
//! TCP ports `50051`, `50001`, `2379`, `9339`, `9559`, `7233`, and `8001`. It validates exact wire
//! framing bounds, extracts gRPC service names (`service`), RPC method names (`method`), and
//! trailing status codes (`grpcstatus`), and preserves remaining Protobuf or message bytes via
//! residual payload.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write as _;

use crate::ast::Protocol;
use crate::reverse::{ProtocolDissection, sd};

use super::{checked_be_u32, find_subslice, is_valid_raw_string_body, push_str_mod};

/// Dissects a length-prefixed gRPC message payload on TCP port `50051`.
pub(crate) fn dissect_grpc(payload: &[u8]) -> Option<ProtocolDissection> {
    if *payload.first()? > 1 {
        return None;
    }
    let msg_len = checked_be_u32(payload, 1)? as usize;
    if 5usize.checked_add(msg_len)? != payload.len() {
        return None;
    }

    let data = payload.get(5..5 + msg_len)?;
    let mut tokens = String::from("grpc");
    if data.is_empty() {
        return Some(sd(Protocol::Grpc, tokens, Vec::new()));
    }

    let status_split = data
        .strip_prefix(b"grpc-status:")
        .map(|rest| (&b""[..], rest))
        .or_else(|| {
            let pos = find_subslice(data, b" grpc-status:")?;
            Some((data.get(..pos)?, data.get(pos + 13..)?))
        });
    if let Some((prefix, after_marker)) = status_split {
        let dlen = after_marker
            .iter()
            .take_while(|b| b.is_ascii_digit())
            .count();
        if dlen > 0 {
            let status: u32 = core::str::from_utf8(after_marker.get(..dlen)?)
                .ok()?
                .parse()
                .ok()?;
            if let Ok(prefix_str) = core::str::from_utf8(prefix) {
                if let Some((svc, mth)) = prefix_str.split_once('/') {
                    if !svc.is_empty() {
                        push_str_mod(&mut tokens, "service", svc);
                    }
                    if !mth.is_empty() {
                        push_str_mod(&mut tokens, "method", mth);
                    }
                } else if !prefix_str.is_empty() {
                    push_str_mod(&mut tokens, "method", prefix_str);
                }
            }
            let _ = write!(tokens, " grpcstatus {status}");
            return Some(sd(
                Protocol::Grpc,
                tokens,
                after_marker.get(dlen..)?.to_vec(),
            ));
        }
    }

    if let Some(slash_pos) = data.iter().position(|&b| b == b'/') {
        let svc_bytes = data.get(..slash_pos)?;
        let after_slash = data.get(slash_pos + 1..)?;
        if let Ok(svc_str) = core::str::from_utf8(svc_bytes)
            && !svc_str.is_empty()
            && is_valid_raw_string_body(svc_str)
        {
            push_str_mod(&mut tokens, "service", svc_str);
            let mth_len = after_slash
                .iter()
                .take_while(|&&b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'))
                .count();
            let residual = if mth_len > 0 {
                let mth_str = core::str::from_utf8(after_slash.get(..mth_len)?).ok()?;
                push_str_mod(&mut tokens, "method", mth_str);
                after_slash.get(mth_len..)?.to_vec()
            } else {
                after_slash.to_vec()
            };
            return Some(sd(Protocol::Grpc, tokens, residual));
        }
    }

    Some(sd(Protocol::Grpc, tokens, data.to_vec()))
}
