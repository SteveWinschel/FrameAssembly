//! Layer 7 application, network management, telemetry, web, security, VoIP, storage, database,
//! message broker, and industrial OT protocol PCAP-to-`.fasm` decompilers.
//!
//! This module organizes all 50 Layer 7 protocol dissectors into 1-to-1 per-protocol files
//! mirroring `src/ast/l7/`, `src/parser/l7/`, and `src/builders/l7/`. The top-level [`dissect_l7`]
//! dispatcher routes TCP and UDP application payloads across three domain tiers:
//! 1. **Infrastructure, Network Management & Telemetry**: `snmp1`, `snmp2`, `snmp3`, `dns`,
//!    `mdns`, `dhcp`, `ntp`, `ptp`, `radius`, `tacacs`, `syslog`, `netflow`, `ipfix`, `sflow`.
//! 2. **Web, Cloud-Native, Security, Remote Access & VoIP**: `http`, `http2`, `grpc`, `websocket`,
//!    `tls`, `quic`, `tftp`, `ftp`, `ssh`, `telnet`, `whois`, `sip`, `rtp`, `rtsp`, `stun`, `ssdp`.
//! 3. **Mail, Auth, Directory, Storage, Databases, Messaging & Industrial OT**: `smtp`, `imap`,
//!    `pop3`, `kerberos`, `ldap`, `smb`, `nfs`, `redis`, `memcached`, `mysql`, `postgres`, `mqtt`,
//!    `coap`, `amqp`, `modbus`, `bacnet`, `dnp3`, `s7comm`, `ethernetip`, `opcua`.

pub(crate) mod amqp;
pub(crate) mod bacnet;
pub(crate) mod coap;
pub(crate) mod dhcp;
pub(crate) mod dnp3;
pub(crate) mod dns;
pub(crate) mod ethernetip;
pub(crate) mod ftp;
pub(crate) mod grpc;
pub(crate) mod http;
pub(crate) mod http2;
pub(crate) mod imap;
pub(crate) mod ipfix;
pub(crate) mod kerberos;
pub(crate) mod ldap;
pub(crate) mod mdns;
pub(crate) mod memcached;
pub(crate) mod modbus;
pub(crate) mod mqtt;
pub(crate) mod mysql;
pub(crate) mod netflow;
pub(crate) mod nfs;
pub(crate) mod ntp;
pub(crate) mod opcua;
pub(crate) mod pop3;
pub(crate) mod postgres;
pub(crate) mod ptp;
pub(crate) mod quic;
pub(crate) mod radius;
pub(crate) mod redis;
pub(crate) mod rtp;
pub(crate) mod rtsp;
pub(crate) mod s7comm;
pub(crate) mod sflow;
pub(crate) mod sip;
pub(crate) mod smb;
pub(crate) mod smtp;
pub(crate) mod snmp1;
pub(crate) mod snmp2;
pub(crate) mod snmp3;
pub(crate) mod ssh;
pub(crate) mod ssdp;
pub(crate) mod stun;
pub(crate) mod syslog;
pub(crate) mod tacacs;
pub(crate) mod telnet;
pub(crate) mod tftp;
pub(crate) mod tls;
pub(crate) mod websocket;
pub(crate) mod whois;

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt::Write as _;
use core::net::{IpAddr, Ipv4Addr};

use crate::ast::{Protocol, TransportProto};
use crate::reverse::{ProtocolDissection, escape_fasm_string, push_if};

/// Dispatches a TCP or UDP application-layer payload across all 50 Layer 7 protocol dissectors.
pub(crate) fn dissect_l7(
    transport: TransportProto,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
    is_ipv6: bool,
    dst_ip: Option<IpAddr>,
) -> Option<ProtocolDissection> {
    let _ = dst_ip;
    if payload.is_empty() {
        return None;
    }
    let is_tcp = matches!(transport, TransportProto::Tcp);
    dissect_infra(payload, src_port, dst_port, is_tcp, is_ipv6)
        .or_else(|| dissect_web(payload, src_port, dst_port, is_tcp))
        .or_else(|| dissect_data_ot(transport, src_port, dst_port, payload))
}

/// Invokes `f` if `sp` or `dp` matches any port in `ports`.
fn on_ports(
    sp: u16,
    dp: u16,
    ports: &[u16],
    f: impl FnOnce() -> Option<ProtocolDissection>,
) -> Option<ProtocolDissection> {
    ports.iter().any(|&p| sp == p || dp == p).then(f).flatten()
}

/// Dispatches Layer 7 infrastructure, SNMP, AAA, time, and flow telemetry protocols.
fn dissect_infra(
    payload: &[u8],
    sp: u16,
    dp: u16,
    is_tcp: bool,
    is_ipv6: bool,
) -> Option<ProtocolDissection> {
    if is_tcp {
        return on_ports(sp, dp, &[53], || dns::dissect_dns(payload, true))
            .or_else(|| on_ports(sp, dp, &[49], || tacacs::dissect_tacacs(payload)))
            .or_else(|| {
                on_ports(sp, dp, &[514, 1514, 6514], || {
                    syslog::dissect_syslog(payload, true)
                })
            });
    }
    netflow::dissect_netflow(payload, sp, dp)
        .or_else(|| ipfix::dissect_ipfix(payload, sp, dp))
        .or_else(|| sflow::dissect_sflow(payload, sp, dp))
        .or_else(|| {
            on_ports(sp, dp, &[161, 162, 10161, 10162], || {
                snmp3::dissect_snmp3(payload)
                    .or_else(|| snmp2::dissect_snmp2(payload))
                    .or_else(|| snmp1::dissect_snmp1(payload, is_ipv6))
            })
        })
        .or_else(|| on_ports(sp, dp, &[53], || dns::dissect_dns(payload, false)))
        .or_else(|| on_ports(sp, dp, &[5353], || mdns::dissect_mdns(payload)))
        .or_else(|| {
            on_ports(sp, dp, &[67, 68, 546, 547], || {
                dhcp::dissect_dhcp(payload, is_ipv6)
            })
        })
        .or_else(|| on_ports(sp, dp, &[123], || ntp::dissect_ntp(payload)))
        .or_else(|| on_ports(sp, dp, &[319, 320], || ptp::dissect_ptp(payload)))
        .or_else(|| {
            on_ports(sp, dp, &[1812, 1813, 1645, 1646], || {
                radius::dissect_radius(payload)
            })
        })
        .or_else(|| {
            on_ports(sp, dp, &[514, 1514, 6514], || {
                syslog::dissect_syslog(payload, false)
            })
        })
}

/// Predicate-guarded Layer 7 payload dissector rule (`(condition, dissector_fn)`).
type DissectRule = (bool, fn(&[u8]) -> Option<ProtocolDissection>);

/// Dispatches Layer 7 web, cloud-native, security, remote access, and VoIP protocols.
fn dissect_web(
    payload: &[u8],
    src_port: u16,
    dst_port: u16,
    is_tcp: bool,
) -> Option<ProtocolDissection> {
    let any_port = |ps: &[u16]| ps.contains(&src_port) || ps.contains(&dst_port);
    let p80 = any_port(&[80, 8080, 8000]);
    let p443 = any_port(&[443, 8443, 6443]);
    let p_sip = any_port(&[5060, 5061]);
    let p_grpc = any_port(&[50051, 50001, 2379, 9339, 9559, 7233, 8001]);
    let is_h2 = payload.starts_with(http2::H2_PREFACE);
    let is_http = http::is_http_signature(payload);
    let is_sip = sip::is_sip_signature(payload);
    let is_tls = tls::is_tls_signature(payload);

    if is_tcp {
        let rules: &[DissectRule] = &[
            (p80 && is_h2, http2::dissect_http2),
            (p80 && is_http, http::dissect_http),
            (p80, http2::dissect_http2),
            (p80, websocket::dissect_websocket),
            (p80, http::dissect_http),
            (p443 && is_h2, http2::dissect_http2),
            (p443 && is_tls, tls::dissect_tls),
            (p443, http2::dissect_http2),
            (p443, websocket::dissect_websocket),
            (p443 && is_http, http::dissect_http),
            (p_grpc, grpc::dissect_grpc),
            (any_port(&[21, 2121]), ftp::dissect_ftp),
            (any_port(&[22, 2222, 830]), ssh::dissect_ssh),
            (any_port(&[23, 2323, 2001, 4000]), telnet::dissect_telnet),
            (any_port(&[43]), whois::dissect_whois),
            (any_port(&[554, 8554]), rtsp::dissect_rtsp),
            (p_sip, |b| sip::dissect_sip(b, true)),
            (is_h2, http2::dissect_http2),
            (is_tls, tls::dissect_tls),
            (
                payload.starts_with(b"SSH-2.0-") || payload.starts_with(b"SSH-1.99-"),
                ssh::dissect_ssh,
            ),
            (rtsp::is_rtsp_signature(payload), rtsp::dissect_rtsp),
            (is_sip, |b| sip::dissect_sip(b, true)),
            (is_http, http::dissect_http),
            (
                payload.starts_with(b"Domain Name: ")
                    && find_subslice(payload, b"\r\nRegistrar: ").is_some(),
                whois::dissect_whois,
            ),
        ];
        for &(cond, func) in rules {
            if cond && let Some(d) = func(payload) {
                return Some(d);
            }
        }
    } else {
        let p_quic = p443
            || any_port(&[4433, 853, 179])
            || (any_port(&[5684])
                && ((payload[0] & 0x80) != 0 || payload.get(6..11) == Some(b"COAP_")));
        let p_rtp = any_port(&[5004, 50004, 10000, 10002, 60000]);
        let rules: &[DissectRule] = &[
            (p_quic, quic::dissect_quic),
            (
                any_port(&[69]) || (any_port(&[50100]) && any_port(&[54120])),
                tftp::dissect_tftp,
            ),
            (p_sip, |b| sip::dissect_sip(b, false)),
            (p_rtp, rtp::dissect_rtp),
            (any_port(&[3478, 19302]), stun::dissect_stun),
            (any_port(&[1900]), ssdp::dissect_ssdp),
            (
                payload.starts_with(b"M-SEARCH * HTTP/1.1\r\n")
                    || payload.starts_with(b"NOTIFY * HTTP/1.1\r\n"),
                ssdp::dissect_ssdp,
            ),
            (is_sip, |b| sip::dissect_sip(b, false)),
            (
                payload.len() >= 20 && payload.get(4..8) == Some(&[0x21, 0x12, 0xA4, 0x42]),
                stun::dissect_stun,
            ),
        ];
        for &(cond, func) in rules {
            if cond && let Some(d) = func(payload) {
                return Some(d);
            }
        }
    }

    None
}

/// Dispatches Layer 7 mail, directory, storage, database, cache, messaging, and OT protocols.
fn dissect_data_ot(
    transport: TransportProto,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Option<ProtocolDissection> {
    let any_port = |ps: &[u16]| ps.contains(&src_port) || ps.contains(&dst_port);

    // 1. Port-prioritized dispatch across the 20 Data/OT protocols.
    if any_port(&[25, 465, 587, 2525])
        && let Some(d) = smtp::dissect_smtp(transport, src_port, dst_port, payload)
    {
        return Some(d);
    }
    if any_port(&[143, 993])
        && let Some(d) = imap::dissect_imap(transport, src_port, dst_port, payload)
    {
        return Some(d);
    }
    if any_port(&[110, 995])
        && let Some(d) = pop3::dissect_pop3(transport, src_port, dst_port, payload)
    {
        return Some(d);
    }
    if any_port(&[445, 139])
        && let Some(d) = smb::dissect_smb(transport, src_port, dst_port, payload)
    {
        return Some(d);
    }
    if any_port(&[6379, 26379])
        && let Some(d) = redis::dissect_redis(transport, src_port, dst_port, payload)
    {
        return Some(d);
    }
    if any_port(&[3306])
        && let Some(d) = mysql::dissect_mysql(transport, src_port, dst_port, payload)
    {
        return Some(d);
    }
    if any_port(&[5432, 6432, 9999])
        && let Some(d) = postgres::dissect_postgres(transport, src_port, dst_port, payload)
    {
        return Some(d);
    }
    if any_port(&[88])
        && let Some(d) = kerberos::dissect_kerberos(transport, src_port, dst_port, payload)
    {
        return Some(d);
    }
    if any_port(&[389, 636, 3268])
        && let Some(d) = ldap::dissect_ldap(transport, src_port, dst_port, payload)
    {
        return Some(d);
    }
    if any_port(&[2049])
        && let Some(d) = nfs::dissect_nfs(transport, src_port, dst_port, payload)
    {
        return Some(d);
    }
    if any_port(&[11211, 11212])
        && let Some(d) = memcached::dissect_memcached(transport, src_port, dst_port, payload)
    {
        return Some(d);
    }
    if any_port(&[1883, 8883])
        && let Some(d) = mqtt::dissect_mqtt(transport, src_port, dst_port, payload)
    {
        return Some(d);
    }
    if any_port(&[5672, 5671])
        && let Some(d) = amqp::dissect_amqp(transport, src_port, dst_port, payload)
    {
        return Some(d);
    }
    if any_port(&[102])
        && let Some(d) = s7comm::dissect_s7comm(transport, src_port, dst_port, payload)
    {
        return Some(d);
    }
    if any_port(&[4840])
        && let Some(d) = opcua::dissect_opcua(transport, src_port, dst_port, payload)
    {
        return Some(d);
    }
    if any_port(&[5683, 5684])
        && let Some(d) = coap::dissect_coap(transport, src_port, dst_port, payload)
    {
        return Some(d);
    }
    if any_port(&[47808])
        && let Some(d) = bacnet::dissect_bacnet(transport, src_port, dst_port, payload)
    {
        return Some(d);
    }
    if any_port(&[502])
        && let Some(d) = modbus::dissect_modbus(transport, src_port, dst_port, payload)
    {
        return Some(d);
    }
    if any_port(&[20000])
        && let Some(d) = dnp3::dissect_dnp3(transport, src_port, dst_port, payload)
    {
        return Some(d);
    }
    if any_port(&[44818, 2222])
        && let Some(d) = ethernetip::dissect_ethernetip(transport, src_port, dst_port, payload)
    {
        return Some(d);
    }

    // 2. Signature-based fallback for custom-port flows across Data/OT dissectors.
    smb::dissect_smb(transport, src_port, dst_port, payload)
        .or_else(|| postgres::dissect_postgres(transport, src_port, dst_port, payload))
        .or_else(|| s7comm::dissect_s7comm(transport, src_port, dst_port, payload))
        .or_else(|| opcua::dissect_opcua(transport, src_port, dst_port, payload))
        .or_else(|| amqp::dissect_amqp(transport, src_port, dst_port, payload))
        .or_else(|| mqtt::dissect_mqtt(transport, src_port, dst_port, payload))
        .or_else(|| bacnet::dissect_bacnet(transport, src_port, dst_port, payload))
        .or_else(|| dnp3::dissect_dnp3(transport, src_port, dst_port, payload))
        .or_else(|| ethernetip::dissect_ethernetip(transport, src_port, dst_port, payload))
        .or_else(|| nfs::dissect_nfs(transport, src_port, dst_port, payload))
        .or_else(|| kerberos::dissect_kerberos(transport, src_port, dst_port, payload))
        .or_else(|| memcached::dissect_memcached(transport, src_port, dst_port, payload))
}

/// Checks whether a byte slice is valid printable ASCII suitable for a `.fasm` string literal.
pub(crate) fn is_printable_ascii_str(bytes: &[u8]) -> Option<&str> {
    let s = core::str::from_utf8(bytes).ok()?;
    s.bytes().all(|b| (0x20..=0x7E).contains(&b)).then_some(s)
}

/// Formats `s` for `parse_raw_string_lit`, escaping only when raw syntax would mis-tokenize.
pub(crate) fn quote_raw_str(s: &str) -> String {
    let mut it = s.chars();
    while let Some(c) = it.next() {
        if matches!(c, '\0' | '\r' | '\n' | '"')
            || (c == '\\' && it.next().is_none_or(|n| matches!(n, '\0' | '\r' | '\n')))
        {
            return escape_fasm_string(s);
        }
    }
    s.to_string()
}

/// Appends ` <kw> "<quoted>"` to `out` when `val != default`.
pub(crate) fn push_str_if(out: &mut String, kw: &str, val: &str, default: &str) {
    if val != default {
        let _ = write!(out, " {kw} \"{}\"", quote_raw_str(val));
    }
}

/// Appends ` <kw> <v>` to `out` when `val` is `Some(v)`.
pub(crate) fn push_opt<T: core::fmt::Display>(out: &mut String, kw: &str, val: Option<T>) {
    if let Some(v) = val {
        let _ = write!(out, " {kw} {v}");
    }
}

/// Constructs a [`ProtocolDissection`] with default L4 transport.
pub(crate) fn ok_dissect(
    protocol: Protocol,
    tokens: String,
    residual_payload: Vec<u8>,
) -> Option<ProtocolDissection> {
    Some(ProtocolDissection {
        protocol,
        tokens,
        residual_payload,
        explicit_transport: None,
    })
}

/// Appends common NetFlow/IPFIX flow record fields (`srcip`, `dstip`, `proto`, `packets`, `octets`).
pub(crate) fn append_flow_record_tokens(
    tokens: &mut String,
    flow_src: Ipv4Addr,
    flow_dst: Ipv4Addr,
    proto: u8,
    packets: u32,
    octets: u32,
) {
    let _ = write!(tokens, " srcip {flow_src} dstip {flow_dst}");
    push_if(tokens, "proto", proto, 6);
    push_if(tokens, "packets", packets, 1);
    push_if(tokens, "octets", octets, 64);
}

/// Reads a checked big-endian `u16` at `offset` from `buf`.
pub(crate) fn checked_be_u16(buf: &[u8], offset: usize) -> Option<u16> {
    let b = buf.get(offset..offset.checked_add(2)?)?;
    Some(u16::from_be_bytes([b[0], b[1]]))
}

/// Reads a checked big-endian `u32` at `offset` from `buf`.
pub(crate) fn checked_be_u32(buf: &[u8], offset: usize) -> Option<u32> {
    let b = buf.get(offset..offset.checked_add(4)?)?;
    Some(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
}

/// Checks whether a string slice can be placed inside `"..."` in `.fasm` source and round-tripped
/// verbatim through `Token::StringLit` and `parse_raw_string_lit`.
pub(crate) fn is_valid_raw_string_body(s: &str) -> bool {
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if b < 0x20 || b == 0x7f || b == b'"' {
            return false;
        }
        if b == b'\\' {
            if bytes.get(i + 1).is_none_or(|&n| n < 0x20 || n == 0x7f) {
                return false;
            }
            i += 2;
            continue;
        }
        i += 1;
    }
    true
}

/// Formats a string value as a quoted `.fasm` string literal (`"..."`), preserving existing valid
/// escape sequences for `parse_raw_string_lit` and escaping raw quotes or control characters.
pub(crate) fn quote_web_str(s: &str) -> String {
    if is_valid_raw_string_body(s) {
        format!("\"{s}\"")
    } else {
        format!("\"{}\"", escape_fasm_string(s))
    }
}

/// Appends `" <key> \"<val>\""` to `tokens`.
pub(crate) fn push_str_mod(tokens: &mut String, key: &str, val: &str) {
    let _ = write!(tokens, " {key} {}", quote_web_str(val));
}

/// Appends `<key> "<str>"` if `body_bytes` is valid raw UTF-8, or returns `body_bytes` as residual payload.
pub(crate) fn attach_text_body(tokens: &mut String, key: &str, body_bytes: &[u8]) -> Vec<u8> {
    if body_bytes.is_empty() {
        return Vec::new();
    }
    if let Ok(s) = core::str::from_utf8(body_bytes)
        && is_valid_raw_string_body(s)
    {
        push_str_mod(tokens, key, s);
        Vec::new()
    } else {
        body_bytes.to_vec()
    }
}

/// Searches for the first occurrence of `needle` inside `haystack`.
pub(crate) fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Splits a CRLF-delimited header block (`\r\n\r\n`) into its UTF-8 header text and trailing body.
pub(crate) fn split_crlf_headers(payload: &[u8]) -> Option<(&str, &[u8])> {
    let hdr_end = find_subslice(payload, b"\r\n\r\n")?;
    Some((
        core::str::from_utf8(payload.get(..hdr_end)?).ok()?,
        payload.get(hdr_end + 4..)?,
    ))
}

/// Extracts the first CRLF-terminated line from `payload` as a UTF-8 string slice.
pub(crate) fn first_crlf_line(payload: &[u8]) -> Option<&str> {
    let crlf = find_subslice(payload, b"\r\n")?;
    core::str::from_utf8(payload.get(..crlf)?).ok()
}
