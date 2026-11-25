//! NT LAN Manager Authentication over HTTP (`ntlm`, MS-NLMP / RFC 4559) Layer 7 PCAP-to-`.frasm` decompiler.
//!
//! This module implements the fuzz-safe reverse dissector for HTTP-carried `ntlm` authentication
//! exchanges (`Authorization: NTLM <base64>` and `WWW-Authenticate: NTLM <base64>`) over TCP port
//! `80` and custom HTTP ports. It decodes RFC 4648 Base64 `NTLMSSP\0` Type 1 `negotiate`, Type 2
//! `challenge` (including `ServerChallenge` nonces and `AV_PAIR` `TargetInfo` attributes), and
//! Type 3 `authenticate` (UTF-16LE `domain`, `user`, `workstation`) payloads into canonical `.frasm`
//! tokens while preserving residual HTTP bodies.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write as _;

use crate::ast::Protocol;
use crate::reverse::{ProtocolDissection, bytes_to_hex_lower, sd};

use super::{find_subslice, push_str_mod, split_crlf_headers};

/// Default Type 1 `NegotiateFlags` elided when matched.
const DEFAULT_FLAGS_T1: u32 = 0xa008_8207;

/// Default Type 2 `NegotiateFlags` elided when matched.
const DEFAULT_FLAGS_T2: u32 = 0xa089_8205;

/// Default Type 3 `NegotiateFlags` elided when matched.
const DEFAULT_FLAGS_T3: u32 = 0xa008_8201;

/// Default 8-byte Type 2 Server Challenge nonce elided when matched.
const DEFAULT_NTLM_NONCE: [u8; 8] = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];

/// Reads a checked little-endian `u16` at `off` from `buf`.
fn le_u16(buf: &[u8], off: usize) -> Option<u16> {
    let b = buf.get(off..off.checked_add(2)?)?;
    Some(u16::from_le_bytes([b[0], b[1]]))
}

/// Reads a checked little-endian `u32` at `off` from `buf`.
fn le_u32(buf: &[u8], off: usize) -> Option<u32> {
    let b = buf.get(off..off.checked_add(4)?)?;
    Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

/// Maps one Base64 ASCII character to its 6-bit value.
fn b64_val(b: u8) -> Option<u8> {
    match b {
        b'A'..=b'Z' => Some(b - b'A'),
        b'a'..=b'z' => Some(b - b'a' + 26),
        b'0'..=b'9' => Some(b - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

/// Decodes a padded RFC 4648 Base64 ASCII string into raw octets without `std` dependencies.
fn decode_base64(input: &str) -> Option<Vec<u8>> {
    let bytes = input.trim().as_bytes();
    if bytes.is_empty() || !bytes.len().is_multiple_of(4) {
        return None;
    }
    let mut out = Vec::with_capacity((bytes.len() / 4) * 3);
    for (idx, quad) in bytes.as_chunks::<4>().0.iter().enumerate() {
        let is_last = (idx + 1) * 4 == bytes.len();
        let a = b64_val(quad[0])?;
        let b = b64_val(quad[1])?;
        let pad2 = quad[2] == b'=';
        let pad3 = quad[3] == b'=';
        if (pad2 && !pad3) || ((pad2 || pad3) && !is_last) {
            return None;
        }
        let c = if pad2 { 0 } else { b64_val(quad[2])? };
        let d = if pad3 { 0 } else { b64_val(quad[3])? };
        out.push((a << 2) | (b >> 4));
        if !pad2 {
            out.push((b << 4) | (c >> 2));
        }
        if !pad3 {
            out.push((c << 6) | d);
        }
    }
    Some(out)
}

/// Reads an MS-NLMP 8-byte security buffer slice from `ntlm` at descriptor offset `desc_off`.
fn read_sec_buf(ntlm: &[u8], desc_off: usize) -> Option<&[u8]> {
    let len = usize::from(le_u16(ntlm, desc_off)?);
    let offset = le_u32(ntlm, desc_off + 4)? as usize;
    if len == 0 {
        return Some(&[]);
    }
    ntlm.get(offset..offset.checked_add(len)?)
}

/// Decodes a UTF-16LE byte slice into a printable `String`.
fn decode_utf16le_printable(bytes: &[u8]) -> Option<String> {
    if !bytes.len().is_multiple_of(2) {
        return None;
    }
    let mut units = Vec::with_capacity(bytes.len() / 2);
    for &pair in bytes.as_chunks::<2>().0 {
        units.push(u16::from_le_bytes(pair));
    }
    let s = String::from_utf16(&units).ok()?;
    (!s.chars().any(char::is_control)).then_some(s)
}

/// Extracts `MsvAvNbDomainName` (`2`) and `MsvAvNbComputerName` (`1`) strings from `TargetInfo`.
fn parse_target_info(mut bytes: &[u8]) -> (Option<String>, Option<String>) {
    let (mut domain, mut computer) = (None, None);
    while bytes.len() >= 4 {
        let av_id = u16::from_le_bytes([bytes[0], bytes[1]]);
        let av_len = usize::from(u16::from_le_bytes([bytes[2], bytes[3]]));
        if av_id == 0 {
            break;
        }
        let Some(val) = bytes.get(4..4usize.saturating_add(av_len)) else {
            break;
        };
        if av_id == 2 && domain.is_none() {
            domain = decode_utf16le_printable(val);
        } else if av_id == 1 && computer.is_none() {
            computer = decode_utf16le_printable(val);
        }
        bytes = bytes.get(4 + av_len..).unwrap_or(&[]);
    }
    (domain, computer)
}

/// Checks whether `payload` carries an HTTP `Authorization: NTLM` or `WWW-Authenticate: NTLM` header.
pub(crate) fn is_ntlm_http_signature(payload: &[u8]) -> bool {
    find_subslice(payload, b": NTLM ").is_some()
        || find_subslice(payload, b": ntlm ").is_some()
}

/// Dissects an HTTP-wrapped MS-NLMP (`ntlm`) authentication request or challenge response.
pub(crate) fn dissect_ntlm(payload: &[u8]) -> Option<ProtocolDissection> {
    let (hdr_str, body_bytes) = split_crlf_headers(payload)?;
    let mut lines = hdr_str.split("\r\n");
    let first_line = lines.next()?;

    let mut is_resp = false;
    let mut status: Option<u16> = None;
    let mut method: Option<&str> = None;
    let mut uri: Option<&str> = None;
    let mut host_hdr: Option<&str> = None;
    let mut ntlm_b64: Option<&str> = None;

    if let Some(after_http) = first_line.strip_prefix("HTTP/") {
        let (_ver, rest) = after_http.split_once(' ')?;
        let (st_str, _) = rest.split_once(' ').unwrap_or((rest, ""));
        status = Some(st_str.parse().ok()?);
        is_resp = true;
    } else {
        let (m, rest) = first_line.split_once(' ')?;
        let (u, ver) = rest.split_once(' ')?;
        if !ver.starts_with("HTTP/") {
            return None;
        }
        method = Some(m);
        uri = Some(u);
    }

    for hline in lines {
        let Some((k, v)) = hline.split_once(':') else {
            continue;
        };
        let v_trimmed = v.trim();
        if !is_resp && k.eq_ignore_ascii_case("Host") && host_hdr.is_none() {
            host_hdr = Some(v_trimmed);
        } else if (k.eq_ignore_ascii_case("Authorization")
            || k.eq_ignore_ascii_case("WWW-Authenticate")
            || k.eq_ignore_ascii_case("Proxy-Authenticate"))
            && let Some(b64) = v_trimmed
                .strip_prefix("NTLM ")
                .or_else(|| v_trimmed.strip_prefix("ntlm "))
        {
            ntlm_b64 = Some(b64.trim());
        }
    }

    let ntlm_bytes = decode_base64(ntlm_b64?)?;
    if ntlm_bytes.get(0..8) != Some(&b"NTLMSSP\0"[..]) {
        return None;
    }
    let msg_type = le_u32(&ntlm_bytes, 8)?;
    let mut tokens = String::from("ntlm");

    match msg_type {
        1 => {
            if ntlm_bytes.len() < 32 {
                return None;
            }
            let flags = le_u32(&ntlm_bytes, 12)?;
            let dom_b = read_sec_buf(&ntlm_bytes, 16)?;
            let wks_b = read_sec_buf(&ntlm_bytes, 24)?;
            let dom = core::str::from_utf8(dom_b)
                .ok()
                .filter(|s| !s.is_empty() && !s.chars().any(char::is_control));
            let wks = core::str::from_utf8(wks_b)
                .ok()
                .filter(|s| !s.is_empty() && !s.chars().any(char::is_control));
            let mut expected_flags = DEFAULT_FLAGS_T1;
            if dom.is_some() {
                expected_flags |= 0x0000_1000;
            }
            if wks.is_some() {
                expected_flags |= 0x0000_2000;
            }
            if let Some(d) = dom {
                push_str_mod(&mut tokens, "domain", d);
            }
            if let Some(w) = wks {
                push_str_mod(&mut tokens, "workstation", w);
            }
            if flags != expected_flags {
                let _ = write!(tokens, " flags 0x{flags:08x}");
            }
        }
        2 => {
            if ntlm_bytes.len() < 48 {
                return None;
            }
            tokens.push_str(" challenge");
            let tname_b = read_sec_buf(&ntlm_bytes, 12)?;
            let flags = le_u32(&ntlm_bytes, 20)?;
            let nonce = ntlm_bytes.get(24..32)?;
            let tinfo_b = read_sec_buf(&ntlm_bytes, 40)?;
            let (av_dom, av_comp) = parse_target_info(tinfo_b);
            let dom = decode_utf16le_printable(tname_b).or(av_dom);

            if let Some(d) = dom.as_deref()
                && d != "CORP"
            {
                push_str_mod(&mut tokens, "domain", d);
            }
            if let Some(w) = av_comp.as_deref()
                && w != "DC01"
            {
                push_str_mod(&mut tokens, "workstation", w);
            }
            if nonce != DEFAULT_NTLM_NONCE {
                push_str_mod(&mut tokens, "nonce", &bytes_to_hex_lower(nonce));
            }
            if flags != DEFAULT_FLAGS_T2 {
                let _ = write!(tokens, " flags 0x{flags:08x}");
            }
            if let Some(st) = status
                && st != 401
            {
                let _ = write!(tokens, " status {st}");
            }
        }
        3 => {
            if ntlm_bytes.len() < 64 {
                return None;
            }
            tokens.push_str(" authenticate");
            let dom_b = read_sec_buf(&ntlm_bytes, 28)?;
            let usr_b = read_sec_buf(&ntlm_bytes, 36)?;
            let wks_b = read_sec_buf(&ntlm_bytes, 44)?;
            let flags = le_u32(&ntlm_bytes, 60)?;

            let dom = decode_utf16le_printable(dom_b);
            let usr = decode_utf16le_printable(usr_b);
            let wks = decode_utf16le_printable(wks_b);

            if let Some(d) = dom.as_deref()
                && d != "CORP"
            {
                push_str_mod(&mut tokens, "domain", d);
            }
            if let Some(u) = usr.as_deref()
                && u != "alice"
            {
                push_str_mod(&mut tokens, "user", u);
            }
            if let Some(w) = wks.as_deref()
                && w != "WS01"
            {
                push_str_mod(&mut tokens, "workstation", w);
            }
            if flags != DEFAULT_FLAGS_T3 {
                let _ = write!(tokens, " flags 0x{flags:08x}");
            }
        }
        _ => return None,
    }

    if !is_resp {
        if let Some(m) = method
            && m != "GET"
        {
            push_str_mod(&mut tokens, "method", m);
        }
        if let Some(u) = uri
            && u != "/"
        {
            push_str_mod(&mut tokens, "uri", u);
        }
        if let Some(h) = host_hdr {
            push_str_mod(&mut tokens, "hosthdr", h);
        }
    }

    Some(sd(Protocol::Ntlm, tokens, body_bytes.to_vec()))
}
