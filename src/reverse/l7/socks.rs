//! SOCKS Version 5 Proxy Protocol (`socks`, RFC 1928 / RFC 1929) Layer 7 PCAP-to-`.frasm` decompiler.
//!
//! This module implements the fuzz-safe reverse dissector for SOCKS5 proxy handshakes, RFC 1929
//! username/password subnegotiations, and `CONNECT` / `BIND` / `UDP ASSOCIATE` command requests
//! and replies carried over TCP or SCTP port `1080`. It validates address-type framing (`IPv4`,
//! domain name length, `IPv6`), elides default client/server greetings and endpoints, and preserves
//! any trailing bytes cleanly in `residual_payload`.

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt::Write as _;

use crate::ast::{Protocol, TransportProto};
use crate::reverse::{ipv4_at, ipv6_at, ProtocolDissection, sd};

use super::{checked_be_u16, is_valid_raw_string_body, push_str_mod};

/// Returns `true` when `(src_port, dst_port)` identifies a SOCKS5 proxy server endpoint.
fn is_socks_server_src(src_port: u16, dst_port: u16) -> bool {
    (src_port == 1080 && dst_port != 1080) || (src_port < 1024 && dst_port >= 1024)
}

/// Decodes a SOCKS5 `ATYP` + address + 16-bit port starting at `offset`, returning `(addr, port, end)`.
fn decode_socks_endpoint(payload: &[u8], offset: usize) -> Option<(String, u16, usize)> {
    let atyp = *payload.get(offset)?;
    let (addr, port_off) = match atyp {
        0x01 => {
            let end = offset.checked_add(5)?;
            if end > payload.len() {
                return None;
            }
            (ipv4_at(payload, offset + 1).to_string(), end)
        }
        0x03 => {
            let dlen = usize::from(*payload.get(offset + 1)?);
            let start = offset.checked_add(2)?;
            let end = start.checked_add(dlen)?;
            let dom_bytes = payload.get(start..end)?;
            let dom = core::str::from_utf8(dom_bytes).ok()?;
            if !is_valid_raw_string_body(dom) {
                return None;
            }
            (dom.to_string(), end)
        }
        0x04 => {
            let end = offset.checked_add(17)?;
            if end > payload.len() {
                return None;
            }
            (ipv6_at(payload, offset + 1).to_string(), end)
        }
        _ => return None,
    };
    let port = checked_be_u16(payload, port_off)?;
    let pdu_end = port_off.checked_add(2)?;
    Some((addr, port, pdu_end))
}

/// Dissects a SOCKS5 (`socks`, TCP/SCTP port `1080`) greeting, auth message, or command PDU.
pub(crate) fn dissect_socks(
    transport: TransportProto,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Option<ProtocolDissection> {
    if !matches!(transport, TransportProto::Tcp | TransportProto::Sctp)
        || (src_port != 1080 && dst_port != 1080)
        || payload.len() < 2
    {
        return None;
    }

    let server_src = is_socks_server_src(src_port, dst_port);
    let ver = payload[0];

    // 1. RFC 1929 Username/Password subnegotiation (VER = 0x01)
    if ver == 0x01 {
        if payload.len() == 2 && server_src {
            let status = payload[1];
            let mut tokens = String::from("socks version 1 reply");
            if status != 0 {
                let _ = write!(tokens, " status {status}");
            }
            return Some(sd(Protocol::Socks, tokens, Vec::new()));
        }
        let ulen = usize::from(*payload.get(1)?);
        let u_end = 2usize.checked_add(ulen)?;
        let user = core::str::from_utf8(payload.get(2..u_end)?).ok()?;
        let plen = usize::from(*payload.get(u_end)?);
        let p_start = u_end.checked_add(1)?;
        let p_end = p_start.checked_add(plen)?;
        let pass = core::str::from_utf8(payload.get(p_start..p_end)?).ok()?;
        if !is_valid_raw_string_body(user) || !is_valid_raw_string_body(pass) {
            return None;
        }
        let mut tokens = String::from("socks");
        if user != "user" || pass.is_empty() {
            push_str_mod(&mut tokens, "user", user);
        }
        if !pass.is_empty() {
            push_str_mod(&mut tokens, "password", pass);
        }
        let residual = payload.get(p_end..)?.to_vec();
        return Some(sd(Protocol::Socks, tokens, residual));
    }

    if ver != 0x05 {
        return None;
    }

    // 2. SOCKS5 Command Request / Reply (VER=5, CMD/REP, RSV=0, ATYP in {1,3,4})
    if payload.len() >= 7
        && payload[2] == 0x00
        && matches!(payload[3], 0x01 | 0x03 | 0x04)
        && let Some((addr, port, pdu_end)) = decode_socks_endpoint(payload, 3)
    {
        let code = payload[1];
        let mut tokens = String::from("socks");
        if server_src || code == 0 || code > 3 {
            tokens.push_str(" reply");
            if code != 0 {
                let _ = write!(tokens, " status {code}");
            }
            if addr != "0.0.0.0" {
                push_str_mod(&mut tokens, "addr", &addr);
            }
            if port != 0 {
                let _ = write!(tokens, " targetport {port}");
            }
        } else {
            let cmd_kw = match code {
                1 => "connect",
                2 => "bind",
                3 => "udpassociate",
                _ => return None,
            };
            let _ = write!(tokens, " {cmd_kw}");
            if addr != "93.184.216.34" {
                push_str_mod(&mut tokens, "addr", &addr);
            }
            if port != 80 {
                let _ = write!(tokens, " targetport {port}");
            }
        }
        let residual = payload.get(pdu_end..)?.to_vec();
        return Some(sd(Protocol::Socks, tokens, residual));
    }

    // 3. Server Method Selection Reply (2 bytes: [0x05, method])
    if payload.len() == 2 {
        let m = payload[1];
        let mut tokens = String::from("socks");
        if server_src {
            if m != 0 {
                let _ = write!(tokens, " method {m}");
            }
        } else {
            let _ = write!(tokens, " reply method {m}");
        }
        return Some(sd(Protocol::Socks, tokens, Vec::new()));
    }

    // 4. Client Method Selection Greeting ([0x05, nmethods, methods...])
    let nmethods = usize::from(payload[1]);
    let end = 2usize.checked_add(nmethods)?;
    if nmethods == 0 || end > payload.len() {
        return None;
    }
    let methods = payload.get(2..end)?;
    let mut tokens = String::from("socks");
    if server_src {
        tokens.push_str(" greeting");
    }
    if !(methods.len() == 1 && methods[0] == 0x00) {
        if methods.len() == 1 {
            let _ = write!(tokens, " method {}", methods[0]);
        } else {
            let mut list = String::new();
            for (idx, m) in methods.iter().enumerate() {
                if idx > 0 {
                    list.push(',');
                }
                let _ = write!(list, "{m}");
            }
            let _ = write!(tokens, " method \"{list}\"");
        }
    }
    let residual = payload.get(end..)?.to_vec();
    Some(sd(Protocol::Socks, tokens, residual))
}
