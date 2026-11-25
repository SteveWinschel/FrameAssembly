//! SOCKS Version 5 Proxy Protocol (RFC 1928 / RFC 1929 Username-Password Authentication) Layer 7 wire packet builder.
//!
//! This module synthesizes deterministic on-the-wire SOCKS5 proxy control frames over TCP port
//! 1080. The wire encoder supports RFC 1928 client method-selection greetings
//! (`0x05 <nmethods> <methods...>`), server method-selection replies (`0x05 <method>`), RFC 1929 username/password
//! subnegotiation requests and replies (`0x01`), and SOCKS5 `CONNECT` (`0x01`), `BIND` (`0x02`),
//! and `UDP ASSOCIATE` (`0x03`) requests and replies carrying IPv4, domain name, or IPv6 endpoints.
//!
//! Canonical `.frasm` syntax:
//! `a -> b socks [greeting | reply] [connect | bind | udpassociate | cmd <str>] [version <u8>] [method <str>] [status <u8>] [addr <str>] [targetport <u16>] [user <str>] [password <str>]`

use crate::ast::*;
use crate::builders::WireContext;
use alloc::vec::Vec;
use core::net::{Ipv4Addr, Ipv6Addr};

/// Returns `true` when the resolved source port identifies a SOCKS5 proxy server endpoint.
fn is_socks_server_src(ctx: &WireContext) -> bool {
    (ctx.src_port == 1080 && ctx.dst_port != 1080)
        || (ctx.src_port < 1024 && ctx.dst_port >= 1024)
}

/// Parses a single SOCKS5 authentication method name or numeric identifier.
fn parse_single_method(s: &str) -> u8 {
    let norm = s.trim().to_ascii_uppercase().replace(['_', '-'], "");
    match norm.as_str() {
        "NOAUTH" | "NONE" => 0x00,
        "GSSAPI" => 0x01,
        "USERPASS" | "PASSWORD" => 0x02,
        "NOACCEPTABLE" => 0xFF,
        _ => {
            let trimmed = s.trim();
            if let Some(hex) = trimmed.strip_prefix("0x").or_else(|| trimmed.strip_prefix("0X")) {
                u8::from_str_radix(hex, 16).unwrap_or(0)
            } else {
                trimmed.parse::<u8>().unwrap_or(0)
            }
        }
    }
}

/// Parses a comma- or whitespace-separated SOCKS5 authentication method list.
fn parse_method_list(method_opt: Option<&str>) -> Vec<u8> {
    let Some(raw) = method_opt else {
        return alloc::vec![0x00];
    };
    let mut methods = Vec::new();
    for part in raw.split([',', ' ']).filter(|p| !p.is_empty()) {
        if methods.len() >= 255 {
            break;
        }
        methods.push(parse_single_method(part));
    }
    if methods.is_empty() {
        methods.push(0x00);
    }
    methods
}

/// Parses a SOCKS5 command verb (`CONNECT`, `BIND`, `UDP ASSOCIATE`) or numeric opcode.
fn parse_socks_cmd(cmd: &str) -> u8 {
    let norm = cmd.trim().to_ascii_uppercase().replace(['_', '-'], "");
    match norm.as_str() {
        "CONNECT" => 0x01,
        "BIND" => 0x02,
        "UDPASSOCIATE" => 0x03,
        _ => {
            let trimmed = cmd.trim();
            if let Some(hex) = trimmed.strip_prefix("0x").or_else(|| trimmed.strip_prefix("0X")) {
                u8::from_str_radix(hex, 16).unwrap_or(1)
            } else {
                trimmed.parse::<u8>().unwrap_or(1)
            }
        }
    }
}

/// Appends SOCKS5 `ATYP` and `ADDR` wire octets for an IPv4, IPv6, or domain name string.
fn append_socks_addr(pkt: &mut Vec<u8>, addr: &str) {
    if let Ok(v4) = addr.parse::<Ipv4Addr>() {
        pkt.push(0x01);
        pkt.extend_from_slice(&v4.octets());
    } else if let Ok(v6) = addr.parse::<Ipv6Addr>() {
        pkt.push(0x04);
        pkt.extend_from_slice(&v6.octets());
    } else {
        let raw = addr.as_bytes();
        let len = raw.len().min(255);
        pkt.push(0x03);
        pkt.push(len as u8);
        pkt.extend_from_slice(&raw[..len]);
    }
}

/// Builds an RFC 1928 / RFC 1929 SOCKS5 proxy control payload.
///
/// Syntax mapping: `socks [greeting | reply] [connect | bind | udpassociate | cmd <str>] [version <u8>] [method <str>] [status <u8>] [addr <str>] [targetport <u16>] [user <str>] [password <str>]`
#[doc(alias = "SOCKS")]
#[doc(alias = "SOCKS5")]
#[doc(alias = "RFC1928")]
#[doc(alias = "RFC1929")]
pub fn build_socks_payload(
    ctx: &WireContext,
    spec: &SocksSpec,
    payload_bytes: &[u8],
) -> Vec<u8> {
    let mut pkt = Vec::new();
    let server_src = is_socks_server_src(ctx);

    if spec.user.is_some() || spec.password.is_some() {
        let ver = spec.version.unwrap_or(1);
        let user_bytes = spec.user.unwrap_or("user").as_bytes();
        let ulen = user_bytes.len().min(255);
        let pass_bytes = spec.password.unwrap_or("").as_bytes();
        let plen = pass_bytes.len().min(255);
        pkt.push(ver);
        pkt.push(ulen as u8);
        pkt.extend_from_slice(&user_bytes[..ulen]);
        pkt.push(plen as u8);
        pkt.extend_from_slice(&pass_bytes[..plen]);
    } else if spec.version == Some(1) && (spec.is_reply || spec.status.is_some()) {
        pkt.push(1);
        pkt.push(spec.status.unwrap_or(0));
    } else if spec.cmd.is_some()
        || spec.addr.is_some()
        || spec.target_port.is_some()
        || (spec.is_reply && spec.method.is_none())
        || (spec.status.is_some() && !spec.is_greeting)
    {
        let ver = spec.version.unwrap_or(5);
        let is_rep =
            spec.is_reply || spec.status.is_some() || (server_src && spec.cmd.is_none());
        let code = if is_rep {
            spec.status.unwrap_or(0)
        } else {
            parse_socks_cmd(spec.cmd.unwrap_or("connect"))
        };
        let default_addr = if is_rep { "0.0.0.0" } else { "93.184.216.34" };
        let addr = spec.addr.unwrap_or(default_addr);
        let port = spec.target_port.unwrap_or(if is_rep { 0 } else { 80 });
        pkt.push(ver);
        pkt.push(code);
        pkt.push(0x00);
        append_socks_addr(&mut pkt, addr);
        pkt.extend_from_slice(&port.to_be_bytes());
    } else if !spec.is_greeting && (server_src || (spec.is_reply && spec.method.is_some())) {
        let ver = spec.version.unwrap_or(5);
        let method = parse_single_method(spec.method.unwrap_or("0"));
        pkt.push(ver);
        pkt.push(method);
    } else {
        let ver = spec.version.unwrap_or(5);
        let methods = parse_method_list(spec.method);
        pkt.push(ver);
        pkt.push(methods.len() as u8);
        pkt.extend_from_slice(&methods);
    }

    if !payload_bytes.is_empty() {
        pkt.extend_from_slice(payload_bytes);
    }
    pkt
}
