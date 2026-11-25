//! gRPC Remote Procedure Call (`grpc`, gRPC over HTTP/2) Layer 7 PCAP-to-`.frasm` decompiler.
//!
//! This module implements the fuzz-safe reverse dissector for RFC 9113 HTTP/2-wrapped `grpc`
//! RPC calls carried over TCP/SCTP ports `50051`, `50001`, `2379`, `9339`, `9559`, `7233`,
//! `8001`, or HTTP/2 web ports when `content-type: application/grpc` is present. It decodes
//! HPACK `:method`, `:path` (`/service/method`), `:status`, and trailing `grpc-status` headers
//! along with the 5-byte length-prefixed message frame into canonical `.frasm` tokens.

use alloc::string::String;
use core::fmt::Write as _;

use crate::ast::Protocol;
use crate::reverse::{ProtocolDissection, sd};

use super::http2::decode_hpack_headers;
use super::{checked_be_u32, is_valid_raw_string_body, push_str_mod};

/// Returns `true` when `(src_port, dst_port)` identifies a server-originated gRPC HTTP/2 flow.
fn is_grpc_server_src(src_port: u16, dst_port: u16) -> bool {
    let grpc_port = |p: u16| matches!(p, 50051 | 443 | 80 | 8080 | 8443);
    (grpc_port(src_port) && !grpc_port(dst_port)) || (src_port < 1024 && dst_port >= 1024)
}

/// Parsed RFC 9113 HTTP/2 frame header tuple `(type, flags, stream_id, body, rest)`.
type H2Frame<'a> = (u8, u8, u32, &'a [u8], &'a [u8]);

/// Parses one 9-byte RFC 9113 HTTP/2 frame header and returns `(type, flags, stream_id, body, rest)`.
fn parse_h2_frame(buf: &[u8]) -> Option<H2Frame<'_>> {
    if buf.len() < 9 {
        return None;
    }
    let len = ((buf[0] as usize) << 16) | ((buf[1] as usize) << 8) | (buf[2] as usize);
    let end = 9usize.checked_add(len)?;
    let body = buf.get(9..end)?;
    let rest = buf.get(end..)?;
    let ftype = buf[3];
    let flags = buf[4];
    let stream_id = checked_be_u32(buf, 5)? & 0x7FFF_FFFF;
    Some((ftype, flags, stream_id, body, rest))
}

/// Checks whether `payload` begins with an HTTP/2 `HEADERS` frame advertising `application/grpc`.
pub(crate) fn is_http2_grpc_signature(payload: &[u8]) -> bool {
    let Some((ftype, _flags, _stream_id, body, rest)) = parse_h2_frame(payload) else {
        return false;
    };
    if ftype != 1 || rest.len() < 9 {
        return false;
    }
    decode_hpack_headers(body).is_some_and(|pairs| {
        pairs.iter().any(|(k, v)| {
            k.eq_ignore_ascii_case("content-type") && v.starts_with("application/grpc")
        })
    })
}

/// Dissects an RFC 9113 HTTP/2-wrapped gRPC request or response frame sequence.
pub(crate) fn dissect_grpc(
    payload: &[u8],
    src_port: u16,
    dst_port: u16,
    on_grpc_port: bool,
) -> Option<ProtocolDissection> {
    let (f1_type, f1_flags, stream1, h1_body, rest1) = parse_h2_frame(payload)?;
    if f1_type != 1 || f1_flags != 0x04 || stream1 != 1 {
        return None;
    }
    let h1_pairs = decode_hpack_headers(h1_body)?;
    let has_grpc_ct = h1_pairs.iter().any(|(k, v)| {
        k.eq_ignore_ascii_case("content-type") && v.starts_with("application/grpc")
    });
    if !has_grpc_ct && !on_grpc_port {
        return None;
    }

    let (f2_type, f2_flags, stream2, data_body, rest2) = parse_h2_frame(rest1)?;
    if f2_type != 0 || stream2 != stream1 {
        return None;
    }
    if *data_body.first()? != 0 {
        return None;
    }
    let msg_len = checked_be_u32(data_body, 1)? as usize;
    if 5usize.checked_add(msg_len)? != data_body.len() {
        return None;
    }
    let msg_bytes = data_body.get(5..)?;

    let grpc_status = if rest2.is_empty() {
        if f2_flags != 0x01 {
            return None;
        }
        None
    } else {
        if f2_flags != 0x00 {
            return None;
        }
        let (f3_type, f3_flags, stream3, h3_body, rest3) = parse_h2_frame(rest2)?;
        if f3_type != 1 || f3_flags != 0x05 || stream3 != stream1 || !rest3.is_empty() {
            return None;
        }
        let h3_pairs = decode_hpack_headers(h3_body)?;
        let status_val = h3_pairs
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("grpc-status"))
            .map(|(_, v)| v.as_str())?;
        if h3_pairs.len() != 1 {
            return None;
        }
        Some(status_val.parse::<u32>().ok()?)
    };

    let mut tokens = String::from("grpc");
    let server_src = is_grpc_server_src(src_port, dst_port);
    let path_opt = h1_pairs
        .iter()
        .find(|(k, _)| k == ":path")
        .map(|(_, v)| v.as_str());
    let status_opt = h1_pairs
        .iter()
        .find(|(k, _)| k == ":status")
        .map(|(_, v)| v.as_str());

    if status_opt == Some("200") && path_opt.is_none() {
        if !server_src || !has_grpc_ct {
            return None;
        }
    } else {
        let method_hdr = h1_pairs
            .iter()
            .find(|(k, _)| k == ":method")
            .map(|(_, v)| v.as_str());
        if method_hdr != Some("POST") {
            return None;
        }
        let path = path_opt?.strip_prefix('/')?;
        let (svc, mth) = path.split_once('/')?;
        if svc.is_empty()
            || mth.is_empty()
            || !is_valid_raw_string_body(svc)
            || !is_valid_raw_string_body(mth)
        {
            return None;
        }
        let keep_explicit = server_src || svc != "grpc.Service";
        let keep_method = server_src || mth != "Call";
        if keep_explicit {
            push_str_mod(&mut tokens, "service", svc);
        }
        if keep_method {
            push_str_mod(&mut tokens, "method", mth);
        }
    }

    if let Some(status) = grpc_status {
        let _ = write!(tokens, " grpcstatus {status}");
    }

    Some(sd(Protocol::Grpc, tokens, msg_bytes.to_vec()))
}
