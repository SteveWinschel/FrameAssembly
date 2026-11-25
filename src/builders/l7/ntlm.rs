//! NT LAN Manager Authentication over HTTP (`ntlm`, MS-NLMP / RFC 4559) Layer 7 wire builder.
//!
//! This module implements [`build_ntlm_payload`], which synthesizes HTTP/1.1 messages carrying
//! Base64-encoded Microsoft `NTLMSSP\0` authentication tokens over TCP port 80. It includes a
//! self-contained `alloc`-only RFC 4648 Base64 encoder and synthesizes MS-NLMP Type 1
//! `NEGOTIATE_MESSAGE` (`Authorization: NTLM`), Type 2 `CHALLENGE_MESSAGE` (`HTTP/1.1 401
//! Unauthorized` + `WWW-Authenticate: NTLM` with UTF-16LE `TargetName` and `AV_PAIR` `TargetInfo`),
//! and Type 3 `AUTHENTICATE_MESSAGE` (`Authorization: NTLM` with UTF-16LE domain, user, and
//! workstation buffers).

use crate::ast::NtlmSpec;
use crate::builders::WireContext;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

/// RFC 4648 Base64 encoding alphabet.
const B64_ALPHA: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Default 8-byte Type 2 Server Challenge nonce used when `nonce` is omitted.
const DEFAULT_NTLM_NONCE: [u8; 8] = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];

/// Default Type 1 `NegotiateFlags` (56-bit, 128-bit, ExtSec, AlwaysSign, NTLM, RequestTarget, OEM, Unicode).
const DEFAULT_FLAGS_T1: u32 = 0xa008_8207;

/// Default Type 2 `NegotiateFlags` (56-bit, 128-bit, TargetInfo, ExtSec, TargetTypeDomain, AlwaysSign, NTLM, RequestTarget, Unicode).
const DEFAULT_FLAGS_T2: u32 = 0xa089_8205;

/// Default Type 3 `NegotiateFlags` (56-bit, 128-bit, ExtSec, AlwaysSign, NTLM, Unicode).
const DEFAULT_FLAGS_T3: u32 = 0xa008_8201;

/// Encodes `input` as a standard RFC 4648 Base64 ASCII string without `std` dependencies.
fn encode_base64(input: &[u8]) -> String {
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0];
        let b1 = *chunk.get(1).unwrap_or(&0);
        let b2 = *chunk.get(2).unwrap_or(&0);
        out.push(B64_ALPHA[(b0 >> 2) as usize] as char);
        out.push(B64_ALPHA[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize] as char);
        if chunk.len() > 1 {
            out.push(B64_ALPHA[(((b1 & 0x0f) << 2) | (b2 >> 6)) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(B64_ALPHA[(b2 & 0x3f) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

/// Encodes a UTF-8 string slice as little-endian UTF-16 code units.
fn encode_utf16le(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

/// Appends an MS-NLMP 8-byte `(Len, MaxLen, BufferOffset)` security buffer descriptor.
fn push_sec_buf(buf: &mut Vec<u8>, len: usize, offset: usize) {
    let len16 = u16::try_from(len).unwrap_or(u16::MAX);
    let off32 = u32::try_from(offset).unwrap_or(0);
    buf.extend_from_slice(&len16.to_le_bytes());
    buf.extend_from_slice(&len16.to_le_bytes());
    buf.extend_from_slice(&off32.to_le_bytes());
}

/// Parses an 8-byte server challenge nonce from a hex string or integer string.
fn parse_ntlm_nonce(raw: &str) -> [u8; 8] {
    let trimmed = raw
        .trim()
        .strip_prefix("0x")
        .or_else(|| raw.trim().strip_prefix("0X"))
        .unwrap_or(raw.trim());
    if trimmed.len() == 16 && trimmed.bytes().all(|b| b.is_ascii_hexdigit()) {
        let mut out = [0u8; 8];
        let b = trimmed.as_bytes();
        let mut ok = true;
        for (i, slot) in out.iter_mut().enumerate() {
            if let Ok(pair) = core::str::from_utf8(&b[i * 2..i * 2 + 2])
                && let Ok(val) = u8::from_str_radix(pair, 16)
            {
                *slot = val;
            } else {
                ok = false;
                break;
            }
        }
        if ok {
            return out;
        }
    }
    if let Ok(val) = u64::from_str_radix(trimmed, 16) {
        return val.to_be_bytes();
    }
    if let Ok(val) = raw.trim().parse::<u64>() {
        return val.to_be_bytes();
    }
    DEFAULT_NTLM_NONCE
}

/// Formats an HTTP `Host` header value from `host_hdr` or destination socket context.
fn format_ntlm_http_host(ctx: &WireContext, host_hdr: Option<&str>) -> String {
    if let Some(h) = host_hdr {
        if !h.starts_with('[') && h.parse::<core::net::Ipv6Addr>().is_ok() {
            return format!("[{h}]");
        }
        return h.to_string();
    }
    let base = match ctx.dst_ip {
        core::net::IpAddr::V4(v4) => v4.to_string(),
        core::net::IpAddr::V6(v6) => format!("[{v6}]"),
    };
    if ctx.dst_port != 80 && ctx.dst_port != 0 {
        format!("{base}:{}", ctx.dst_port)
    } else {
        base
    }
}

/// Builds an HTTP-encapsulated MS-NLMP (`ntlm`) authentication request or challenge response.
pub fn build_ntlm_payload(
    ctx: &WireContext,
    spec: &NtlmSpec,
    payload_bytes: &[u8],
) -> Vec<u8> {
    let stage: u32 = if let Some(mt) = spec.msg_type {
        let norm = mt.trim().to_ascii_lowercase().replace(['_', '-'], "");
        match norm.as_str() {
            "negotiate" | "type1" | "1" => 1,
            "challenge" | "type2" | "2" => 2,
            "authenticate" | "auth" | "type3" | "3" => 3,
            _ => 1,
        }
    } else if spec.status.is_some() || spec.nonce.is_some() {
        2
    } else if spec.user.is_some() {
        3
    } else {
        1
    };

    let mut ntlm = Vec::new();
    ntlm.extend_from_slice(b"NTLMSSP\0");
    ntlm.extend_from_slice(&stage.to_le_bytes());

    match stage {
        2 => {
            // MS-NLMP Type 2: CHALLENGE_MESSAGE
            let target_name = encode_utf16le(spec.domain.unwrap_or("CORP"));
            let nb_computer = encode_utf16le(spec.workstation.unwrap_or("DC01"));
            let mut target_info = Vec::new();
            target_info.extend_from_slice(&2u16.to_le_bytes()); // MsvAvNbDomainName
            target_info.extend_from_slice(&(target_name.len() as u16).to_le_bytes());
            target_info.extend_from_slice(&target_name);
            target_info.extend_from_slice(&1u16.to_le_bytes()); // MsvAvNbComputerName
            target_info.extend_from_slice(&(nb_computer.len() as u16).to_le_bytes());
            target_info.extend_from_slice(&nb_computer);
            target_info.extend_from_slice(&[0, 0, 0, 0]); // MsvAvEOL

            let flags = spec.flags.unwrap_or(DEFAULT_FLAGS_T2);
            let has_ver = (flags & 0x0200_0000) != 0;
            let base_off = if has_ver { 56 } else { 48 };
            let tname_off = if target_name.is_empty() { 0 } else { base_off };
            let tinfo_off = base_off + target_name.len();
            let nonce = spec.nonce.map(parse_ntlm_nonce).unwrap_or(DEFAULT_NTLM_NONCE);

            push_sec_buf(&mut ntlm, target_name.len(), tname_off);
            ntlm.extend_from_slice(&flags.to_le_bytes());
            ntlm.extend_from_slice(&nonce);
            ntlm.extend_from_slice(&[0u8; 8]); // Reserved
            push_sec_buf(&mut ntlm, target_info.len(), tinfo_off);
            if has_ver {
                ntlm.extend_from_slice(&[0x0a, 0x00, 0x61, 0x4a, 0x00, 0x00, 0x00, 0x0f]);
            }
            ntlm.extend_from_slice(&target_name);
            ntlm.extend_from_slice(&target_info);
        }
        3 => {
            // MS-NLMP Type 3: AUTHENTICATE_MESSAGE
            let domain = encode_utf16le(spec.domain.unwrap_or("CORP"));
            let user = encode_utf16le(spec.user.unwrap_or("alice"));
            let workstation = encode_utf16le(spec.workstation.unwrap_or("WS01"));
            let lm_resp = [0u8; 24];
            let nt_resp = [0xaa_u8; 24];
            let flags = spec.flags.unwrap_or(DEFAULT_FLAGS_T3);
            let has_ver = (flags & 0x0200_0000) != 0;
            let base_off = if has_ver { 72 } else { 64 };

            let dom_off = base_off;
            let usr_off = dom_off + domain.len();
            let wks_off = usr_off + user.len();
            let lm_off = wks_off + workstation.len();
            let nt_off = lm_off + lm_resp.len();
            let end_off = nt_off + nt_resp.len();

            push_sec_buf(&mut ntlm, lm_resp.len(), lm_off);
            push_sec_buf(&mut ntlm, nt_resp.len(), nt_off);
            push_sec_buf(&mut ntlm, domain.len(), dom_off);
            push_sec_buf(&mut ntlm, user.len(), usr_off);
            push_sec_buf(&mut ntlm, workstation.len(), wks_off);
            push_sec_buf(&mut ntlm, 0, end_off); // EncryptedRandomSessionKey
            ntlm.extend_from_slice(&flags.to_le_bytes());
            if has_ver {
                ntlm.extend_from_slice(&[0x0a, 0x00, 0x61, 0x4a, 0x00, 0x00, 0x00, 0x0f]);
            }
            ntlm.extend_from_slice(&domain);
            ntlm.extend_from_slice(&user);
            ntlm.extend_from_slice(&workstation);
            ntlm.extend_from_slice(&lm_resp);
            ntlm.extend_from_slice(&nt_resp);
        }
        _ => {
            // MS-NLMP Type 1: NEGOTIATE_MESSAGE
            let dom = spec.domain.unwrap_or("").as_bytes();
            let wks = spec.workstation.unwrap_or("").as_bytes();
            let mut flags = spec.flags.unwrap_or(DEFAULT_FLAGS_T1);
            if spec.flags.is_none() {
                if !dom.is_empty() {
                    flags |= 0x0000_1000; // NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED
                }
                if !wks.is_empty() {
                    flags |= 0x0000_2000; // NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED
                }
            }
            let has_ver = (flags & 0x0200_0000) != 0;
            let base_off = if has_ver { 40 } else { 32 };
            let dom_off = if dom.is_empty() { 0 } else { base_off };
            let wks_off = if wks.is_empty() { 0 } else { base_off + dom.len() };

            ntlm.extend_from_slice(&flags.to_le_bytes());
            push_sec_buf(&mut ntlm, dom.len(), dom_off);
            push_sec_buf(&mut ntlm, wks.len(), wks_off);
            if has_ver {
                ntlm.extend_from_slice(&[0x0a, 0x00, 0x61, 0x4a, 0x00, 0x00, 0x00, 0x0f]);
            }
            ntlm.extend_from_slice(dom);
            ntlm.extend_from_slice(wks);
        }
    }

    let b64 = encode_base64(&ntlm);
    let mut http = String::new();
    if stage == 2 {
        let status = spec.status.unwrap_or(401);
        let reason = match status {
            401 => "Unauthorized",
            407 => "Proxy Authentication Required",
            200 => "OK",
            _ => "Unauthorized",
        };
        http.push_str(&format!(
            "HTTP/1.1 {status} {reason}\r\nWWW-Authenticate: NTLM {b64}\r\n"
        ));
    } else {
        let method = spec.method.unwrap_or("GET");
        let uri = spec.uri.unwrap_or("/");
        let host = format_ntlm_http_host(ctx, spec.host_hdr);
        http.push_str(&format!(
            "{method} {uri} HTTP/1.1\r\nHost: {host}\r\nAuthorization: NTLM {b64}\r\n"
        ));
        let method_upper = method.to_ascii_uppercase();
        if !payload_bytes.is_empty() || !matches!(method_upper.as_str(), "GET" | "HEAD" | "DELETE") {
            http.push_str(&format!("Content-Length: {}\r\n", payload_bytes.len()));
        }
    }
    if stage == 2 && !payload_bytes.is_empty() {
        http.push_str(&format!("Content-Length: {}\r\n", payload_bytes.len()));
    }
    http.push_str("\r\n");

    let mut out = http.into_bytes();
    out.extend_from_slice(payload_bytes);
    out
}
