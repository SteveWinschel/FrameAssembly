//! HTTP/2 (`http2`, RFC 9113 / RFC 7541) Layer 7 binary framing PCAP-to-`.frasm` decompiler.
//!
//! This module implements the fuzz-safe reverse dissector for RFC 9113 HTTP/2 connection preface
//! strings (`PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n`) and 9-byte binary frame headers carried over TCP
//! or SCTP ports `80`, `443`, `8080`, and `8443`. It validates the 24-bit payload length against
//! the enclosing transport segment, decodes canonical frame types (`preface`, `data`, `headers`,
//! `settings`, `ping`, `goaway`, `windowupdate`), 31-bit stream identifiers (`streamid`), and
//! RFC 7541 HPACK header blocks for shared use by HTTP/2 and gRPC reverse dissection.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt::Write as _;
use core::net::IpAddr;

use crate::ast::Protocol;
use crate::reverse::{ProtocolDissection, sd};

use super::checked_be_u32;

/// HTTP/2 client connection preface string (RFC 9113 §3.4).
pub(crate) const H2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// RFC 7541 Appendix A static HPACK header table (`index 1..=61`).
const HPACK_STATIC: [(&str, &str); 61] = [
    (":authority", ""),
    (":method", "GET"),
    (":method", "POST"),
    (":path", "/"),
    (":path", "/index.html"),
    (":scheme", "http"),
    (":scheme", "https"),
    (":status", "200"),
    (":status", "204"),
    (":status", "206"),
    (":status", "304"),
    (":status", "400"),
    (":status", "404"),
    (":status", "500"),
    ("accept-charset", ""),
    ("accept-encoding", "gzip, deflate"),
    ("accept-language", ""),
    ("accept-ranges", ""),
    ("accept", ""),
    ("access-control-allow-origin", ""),
    ("age", ""),
    ("allow", ""),
    ("authorization", ""),
    ("cache-control", ""),
    ("content-disposition", ""),
    ("content-encoding", ""),
    ("content-language", ""),
    ("content-length", ""),
    ("content-location", ""),
    ("content-range", ""),
    ("content-type", ""),
    ("cookie", ""),
    ("date", ""),
    ("etag", ""),
    ("expect", ""),
    ("expires", ""),
    ("from", ""),
    ("host", ""),
    ("if-match", ""),
    ("if-modified-since", ""),
    ("if-none-match", ""),
    ("if-range", ""),
    ("if-unmodified-since", ""),
    ("last-modified", ""),
    ("link", ""),
    ("location", ""),
    ("max-forwards", ""),
    ("proxy-authenticate", ""),
    ("proxy-authorization", ""),
    ("range", ""),
    ("referer", ""),
    ("refresh", ""),
    ("retry-after", ""),
    ("server", ""),
    ("set-cookie", ""),
    ("strict-transport-security", ""),
    ("transfer-encoding", ""),
    ("user-agent", ""),
    ("vary", ""),
    ("via", ""),
    ("www-authenticate", ""),
];

/// Returns `true` when `(src_port, dst_port)` identifies a server-originated HTTP/2 flow.
fn is_http2_server_src(src_port: u16, dst_port: u16) -> bool {
    let web_port = |p: u16| matches!(p, 80 | 443 | 8080 | 8443);
    (web_port(src_port) && !web_port(dst_port)) || (src_port < 1024 && dst_port >= 1024)
}

/// Decodes an RFC 7541 §5.1 variable-length HPACK integer with overflow bounds checks.
fn decode_hpack_int(buf: &[u8], pos: &mut usize, prefix_bits: u8) -> Option<usize> {
    let first = *buf.get(*pos)?;
    *pos += 1;
    let max_prefix = (1usize << prefix_bits) - 1;
    let val = (first as usize) & max_prefix;
    if val < max_prefix {
        return Some(val);
    }
    let mut result = max_prefix;
    let mut shift = 0u32;
    loop {
        let b = *buf.get(*pos)?;
        *pos += 1;
        if shift >= 28 {
            return None;
        }
        result = result.checked_add(((b & 0x7F) as usize) << shift)?;
        if (b & 0x80) == 0 {
            return Some(result);
        }
        shift += 7;
    }
}

/// Decodes an uncompressed (`H = 0`) RFC 7541 §5.2 HPACK string literal.
fn decode_hpack_str(buf: &[u8], pos: &mut usize) -> Option<String> {
    let first = *buf.get(*pos)?;
    if (first & 0x80) != 0 {
        return None;
    }
    let len = decode_hpack_int(buf, pos, 7)?;
    let end = pos.checked_add(len)?;
    let raw = buf.get(*pos..end)?;
    *pos = end;
    core::str::from_utf8(raw).ok().map(ToString::to_string)
}

/// Looks up an HPACK header entry in the RFC 7541 static table and dynamic table.
fn lookup_hpack_entry(dynamic: &[(String, String)], idx: usize) -> Option<(&str, &str)> {
    if idx == 0 {
        return None;
    }
    if idx <= HPACK_STATIC.len() {
        return Some(HPACK_STATIC[idx - 1]);
    }
    let dyn_idx = idx - HPACK_STATIC.len() - 1;
    dynamic
        .get(dyn_idx)
        .map(|(n, v)| (n.as_str(), v.as_str()))
}

/// Decodes an RFC 7541 HPACK header block (`H = 0`) into `(name, value)` pairs.
pub(crate) fn decode_hpack_headers(block: &[u8]) -> Option<Vec<(String, String)>> {
    let mut pos = 0usize;
    let mut dynamic: Vec<(String, String)> = Vec::new();
    let mut headers: Vec<(String, String)> = Vec::new();

    while pos < block.len() {
        let b = block[pos];
        if (b & 0x80) != 0 {
            let idx = decode_hpack_int(block, &mut pos, 7)?;
            let (name, val) = lookup_hpack_entry(&dynamic, idx)?;
            headers.push((name.to_string(), val.to_string()));
        } else if (b & 0xC0) == 0x40 {
            let idx = decode_hpack_int(block, &mut pos, 6)?;
            let name = if idx == 0 {
                decode_hpack_str(block, &mut pos)?
            } else {
                lookup_hpack_entry(&dynamic, idx)?.0.to_string()
            };
            let val = decode_hpack_str(block, &mut pos)?;
            headers.push((name.clone(), val.clone()));
            if dynamic.len() < 128 {
                dynamic.insert(0, (name, val));
            }
        } else if (b & 0xE0) == 0x20 {
            let new_max = decode_hpack_int(block, &mut pos, 5)?;
            if new_max > 65536 {
                return None;
            }
            if new_max == 0 {
                dynamic.clear();
            }
        } else {
            let prefix_bits = if (b & 0xF0) == 0x00 || (b & 0xF0) == 0x10 {
                4
            } else {
                return None;
            };
            let idx = decode_hpack_int(block, &mut pos, prefix_bits)?;
            let name = if idx == 0 {
                decode_hpack_str(block, &mut pos)?
            } else {
                lookup_hpack_entry(&dynamic, idx)?.0.to_string()
            };
            let val = decode_hpack_str(block, &mut pos)?;
            headers.push((name, val));
        }
    }

    (!headers.is_empty()).then_some(headers)
}

/// Checks whether decoded HPACK header pairs match the forward builder default `HEADERS` block.
fn is_default_h2_headers(
    pairs: &[(String, String)],
    src_port: u16,
    dst_port: u16,
    dst_ip: Option<IpAddr>,
) -> bool {
    if is_http2_server_src(src_port, dst_port) {
        return pairs.len() == 1 && pairs[0].0 == ":status" && pairs[0].1 == "200";
    }
    let Some(ip) = dst_ip else {
        return false;
    };
    let is_tls = dst_port == 443 || dst_port == 8443;
    let scheme = if is_tls { "https" } else { "http" };
    let authority = crate::builders::l7::http2::format_authority(ip, dst_port, is_tls);
    pairs.len() == 4
        && pairs[0] == (":method".to_string(), "GET".to_string())
        && pairs[1] == (":path".to_string(), "/".to_string())
        && pairs[2] == (":scheme".to_string(), scheme.to_string())
        && pairs[3].0 == ":authority"
        && pairs[3].1 == authority
}

/// Converts decoded HPACK header pairs into textual `key: val` lines when lossless re-encoding matches `raw_body`.
fn hpack_pairs_to_text_lines(pairs: &[(String, String)], raw_body: &[u8]) -> Option<Vec<u8>> {
    let refs: Vec<(&str, &str)> = pairs.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    if crate::builders::l7::http2::encode_hpack_headers(&refs) != raw_body {
        return None;
    }
    let mut lines = Vec::with_capacity(pairs.len());
    for (k, v) in pairs {
        let search_start = usize::from(k.starts_with(':'));
        if k.len() <= search_start
            || !k[search_start..]
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
            || v.trim() != v
            || v.contains(['\r', '\n'])
        {
            return None;
        }
        lines.push(format!("{k}: {v}"));
    }
    Some(lines.join("\n").into_bytes())
}

/// Dissects an RFC 9113 HTTP/2 connection preface or 9-byte frame header.
pub(crate) fn dissect_http2(
    payload: &[u8],
    src_port: u16,
    dst_port: u16,
    dst_ip: Option<IpAddr>,
) -> Option<ProtocolDissection> {
    if let Some(rest) = payload.strip_prefix(H2_PREFACE) {
        return Some(sd(
            Protocol::Http2,
            "http2 preface".to_string(),
            rest.to_vec(),
        ));
    }
    if payload.len() < 9 {
        return None;
    }
    let len = ((payload[0] as usize) << 16) | ((payload[1] as usize) << 8) | (payload[2] as usize);
    if 9usize.checked_add(len)? != payload.len() {
        return None;
    }
    let ftype = payload[3];
    let flags = payload[4];
    let (type_kw, default_stream, expected_flags) = match ftype {
        0 => ("data", 1u32, 0x01u8),
        1 => ("headers", 1u32, 0x05u8),
        4 => ("settings", 0u32, 0x00u8),
        6 => ("ping", 0u32, 0x00u8),
        7 => ("goaway", 0u32, 0x00u8),
        8 => ("windowupdate", 0u32, 0x00u8),
        _ => return None,
    };
    if flags != expected_flags {
        return None;
    }

    let stream_id = checked_be_u32(payload, 5)? & 0x7FFF_FFFF;
    let mut tokens = format!("http2 {type_kw}");
    if stream_id != default_stream {
        let _ = write!(tokens, " streamid {stream_id}");
    }
    let body = payload.get(9..)?;
    let residual = if type_kw == "headers" {
        if let Some(pairs) = decode_hpack_headers(body) {
            if is_default_h2_headers(&pairs, src_port, dst_port, dst_ip) {
                Vec::new()
            } else if let Some(text) = hpack_pairs_to_text_lines(&pairs, body) {
                text
            } else {
                body.to_vec()
            }
        } else {
            body.to_vec()
        }
    } else if (matches!(type_kw, "ping" | "goaway") && body == [0u8; 8])
        || (type_kw == "windowupdate" && body == [0, 0, 0, 1])
    {
        Vec::new()
    } else {
        body.to_vec()
    };
    Some(sd(Protocol::Http2, tokens, residual))
}
