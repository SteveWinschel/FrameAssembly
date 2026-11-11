//! WebAssembly bindings, PCAP/PCAPNG-to-`.fasm` decompiler, frame inspector, and UTF-16 IDE
//! diagnostics for the FrameAssembly (`.fasm` v2.0.0) network packet synthesis compiler.
//!
//! This crate exposes `validate_fasm` (`validateFasm`), `inspect_fasm`,
//! `compile_fasm_to_pcapng` (`compileFasm`), and `reverse_pcap` (`reversePcap`) to browser
//! environments, VS Code Desktop and Web extensions, Node.js test harnesses, and web-based code
//! editors (Monaco, CodeMirror, VS Code Web) via `wasm-bindgen`. It compiles strict-lowercase
//! `.fasm` specifications across all 81 native Layer 2 through Layer 7 protocols into
//! deterministic nanosecond-resolution PCAPNG byte arrays (`Uint8Array`), decompiles binary
//! `.pcap` and `.pcapng` packet captures back into canonical lowercase `.fasm` code in memory via
//! `frameassembly::reverse::reverse_pcap_bytes`, summarizes Ethernet/VLAN/QinQ/MPLS/ARP/IPv4/IPv6
//! and Layer 4/Layer 7 frames, and maps compiler diagnostic byte spans into zero-based UTF-16
//! line and column coordinates.

use std::fmt::Write;
use std::net::{Ipv4Addr, Ipv6Addr};

use frameassembly::backend::compile_program;
use frameassembly::parser::parse_program;
use frameassembly::reverse::reverse_pcap_bytes;
use miette::Diagnostic;
use serde::Serialize;
use wasm_bindgen::prelude::*;

/// Custom TypeScript interface definitions appended to the generated `.d.ts` bindings.
#[wasm_bindgen(typescript_custom_section)]
const TS_APPEND_CONTENT: &'static str = r#"
export interface IdeDiagnostic {
    start_line: number;
    start_col: number;
    end_line: number;
    end_col: number;
    message: string;
    help?: string;
}

export interface PacketPreview {
    index: number;
    timestamp_ms: number;
    length: number;
    hex: string;
    source_dest: string;
    protocol: string;
    summary: string;
}

export interface ReversePcapResult {
    success: boolean;
    fasm: string;
    packetCount: number;
    hostCount: number;
}

export type ReverseJsResult = ReversePcapResult;

export interface ReversePcapError {
    success: boolean;
    error: string;
    message: string;
}
"#;

/// Zero-based UTF-16 source range diagnostic and remediation hint for browser and IDE code editors.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct IdeDiagnostic {
    /// Zero-based starting line index.
    pub start_line: u32,
    /// Zero-based starting UTF-16 column offset.
    pub start_col: u32,
    /// Zero-based ending line index.
    pub end_line: u32,
    /// Zero-based ending UTF-16 column offset.
    pub end_col: u32,
    /// Primary diagnostic error message.
    pub message: String,
    /// Optional plain-English remediation hint (including v2.0.0 lowercase keyword quick-fix hints).
    pub help: Option<String>,
}

/// Summary metadata, protocol dissection, and hexadecimal wire dump for a synthesized Ethernet frame.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PacketPreview {
    /// One-based frame sequence index in the capture.
    pub index: usize,
    /// Relative frame timestamp in milliseconds from the first frame.
    pub timestamp_ms: f64,
    /// Total Ethernet frame length in bytes.
    pub length: usize,
    /// Space-delimited lowercase hexadecimal representation of the frame bytes.
    pub hex: String,
    /// Formatted `source -> destination` IPv4, IPv6, or MAC endpoint pair.
    pub source_dest: String,
    /// Dissected highest-layer protocol label (e.g. `DNS`, `SNMP`, `MODBUS`, `TCP`, `ARP`, `LLDP`).
    pub protocol: String,
    /// Human-readable Ethernet/VLAN/QinQ/MPLS/L3/L4/L7 frame summary string.
    pub summary: String,
}

/// Decompilation summary and canonical `.fasm` code returned by [`reverse_pcap`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReversePcapResult {
    /// Indicates that the binary capture was decompiled into `.fasm` code (`true`).
    pub success: bool,
    /// Generated canonical lowercase `.fasm` source code.
    pub fasm: String,
    /// Total number of packets reversed from the capture.
    pub packet_count: usize,
    /// Total number of `host1`, `host2`, ... definitions emitted in the `.fasm` program.
    pub host_count: usize,
}

/// Type alias for [`ReversePcapResult`] returned to JavaScript callers by [`reverse_pcap`].
pub type ReverseJsResult = ReversePcapResult;

/// Structured error payload returned when binary `.pcap` or `.pcapng` decompilation fails.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReversePcapError {
    /// Indicates that decompilation failed (`false`).
    pub success: bool,
    /// Human-readable decompilation error description.
    pub error: String,
    /// Standard JavaScript `Error`-compatible message string.
    pub message: String,
}

/// Converts a UTF-8 byte offset within `source` into a zero-based `(line, utf16_col)` pair
/// suitable for Monaco Editor, CodeMirror 6, and VS Code diagnostics.
pub fn byte_offset_to_utf16_line_col(source: &str, byte_offset: usize) -> (u32, u32) {
    let clamped = byte_offset.min(source.len());
    let safe_end = (0..=clamped)
        .rev()
        .find(|&i| source.is_char_boundary(i))
        .unwrap_or(0);

    let prefix = &source[..safe_end];
    let line = prefix.bytes().filter(|&b| b == b'\n').count() as u32;
    let col = match prefix.rfind('\n') {
        Some(nl) => prefix[nl + 1..].encode_utf16().count() as u32,
        None => prefix.encode_utf16().count() as u32,
    };
    (line, col)
}

/// Converts a UTF-8 byte offset within `source` into a zero-based `(line, utf16_col)` pair.
fn byte_to_utf16_pos(source: &str, byte_offset: usize) -> (u32, u32) {
    byte_offset_to_utf16_line_col(source, byte_offset)
}

/// Scans `source` outside `//` line comments and `"..."` string literals, yielding
/// `(token_str, start_byte, end_byte)` for each identifier or keyword run.
fn scan_code_words(source: &str) -> Vec<(&str, usize, usize)> {
    let bytes = source.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;

    while i < bytes.len() {
        let b = bytes[i];
        if b == b'/' && i + 1 < bytes.len() && bytes[i + 1] == b'/' {
            i += 2;
            while i < bytes.len() && bytes[i] != b'\n' {
                i += 1;
            }
        } else if b == b'"' {
            i += 1;
            while i < bytes.len() {
                if bytes[i] == b'\\' {
                    i = (i + 2).min(bytes.len());
                } else if bytes[i] == b'"' {
                    i += 1;
                    break;
                } else {
                    i += 1;
                }
            }
        } else if b.is_ascii_alphanumeric() || b == b'_' {
            let start = i;
            i += 1;
            while i < bytes.len()
                && (bytes[i].is_ascii_alphanumeric()
                    || bytes[i] == b'_'
                    || (bytes[i] == b'-'
                        && i + 1 < bytes.len()
                        && (bytes[i + 1].is_ascii_alphanumeric() || bytes[i + 1] == b'_')))
            {
                i += 1;
            }
            if let Some(slice) = source.get(start..i) {
                out.push((slice, start, i));
            }
        } else {
            i += 1;
        }
    }

    out
}

/// Extracts the first single-quoted token `'...'` from a backend error message, if present.
fn extract_single_quoted_subject(err_msg: &str) -> Option<&str> {
    let start = err_msg.find('\'')? + 1;
    let rest = err_msg.get(start..)?;
    let end = rest.find('\'')?;
    let token = &rest[..end];
    if token.is_empty() { None } else { Some(token) }
}

/// Locates the most accurate UTF-8 `(start_byte, end_byte)` span in `source` for a backend
/// compilation error, preferring the offending statement/identifier token inside code or falling
/// back to the `compile` block keyword span instead of `(0, 0)`.
fn find_backend_error_span(source: &str, err_msg: &str) -> (usize, usize) {
    let words = scan_code_words(source);
    let compile_span = words
        .iter()
        .rev()
        .find(|(w, _, _)| w.eq_ignore_ascii_case("compile"))
        .map(|&(_, s, e)| (s, e));

    if let Some(subject) = extract_single_quoted_subject(err_msg) {
        if let Some(&(_, s, e)) = words
            .iter()
            .rev()
            .find(|(w, s, _)| *w == subject && compile_span.is_none_or(|(cs, _)| *s >= cs))
            .or_else(|| words.iter().rev().find(|(w, _, _)| *w == subject))
        {
            return (s, e);
        }
    }

    if err_msg.contains("SNMPv1")
        && let Some(&(_, s, e)) = words.iter().find(|(w, _, _)| *w == "snmp1")
    {
        return (s, e);
    }

    if err_msg.contains("SNMPv3")
        && let Some(&(_, s, e)) = words.iter().find(|(w, _, _)| *w == "snmp3")
    {
        return (s, e);
    }

    if let Some(span) = compile_span {
        return span;
    }

    if let Some(&(_, s, e)) = words.first() {
        return (s, e);
    }

    (0, source.len().min(1))
}

/// Validates `.fasm` source and returns typed [`IdeDiagnostic`] entries without invoking JS bindings.
pub fn validate_fasm_to_diagnostics(source: &str) -> Vec<IdeDiagnostic> {
    let mut diagnostics = Vec::new();

    match parse_program(source) {
        Ok(program) => {
            if let Err(err) = compile_program(&program) {
                let (start_byte, end_byte) = find_backend_error_span(source, &err);
                let (start_line, start_col) = byte_to_utf16_pos(source, start_byte);
                let (end_line, end_col) =
                    byte_to_utf16_pos(source, end_byte.max(start_byte.saturating_add(1)));
                diagnostics.push(IdeDiagnostic {
                    start_line,
                    start_col,
                    end_line,
                    end_col,
                    message: err,
                    help: None,
                });
            }
        }
        Err(err) => push_diagnostic(source, &err, &mut diagnostics),
    }

    diagnostics
}

/// Validates `.fasm` source and returns UTF-16 line/column diagnostics for Monaco, CodeMirror, and VS Code.
#[wasm_bindgen(unchecked_return_type = "IdeDiagnostic[]")]
pub fn validate_fasm(source: &str) -> Result<JsValue, JsError> {
    let diagnostics = validate_fasm_to_diagnostics(source);
    Ok(serde_wasm_bindgen::to_value(&diagnostics)?)
}

/// Validates `.fasm` source and returns UTF-16 line/column diagnostics (`validateFasm` alias).
#[wasm_bindgen(js_name = validateFasm, unchecked_return_type = "IdeDiagnostic[]")]
pub fn validate_fasm_js(source: &str) -> Result<JsValue, JsError> {
    validate_fasm(source)
}

/// Maps well-known TCP/UDP port numbers to concise L7 protocol display labels for packet ladder previews.
fn port_to_l7_name(port: u16, is_tcp: bool) -> Option<&'static str> {
    match (port, is_tcp) {
        (21, true) => Some("FTP"),
        (22, true) => Some("SSH"),
        (23, true) => Some("TELNET"),
        (25 | 587, true) => Some("SMTP"),
        (43, true) => Some("WHOIS"),
        (49, true) => Some("TACACS"),
        (53, _) => Some("DNS"),
        (67 | 68 | 546 | 547, false) => Some("DHCP"),
        (69, false) => Some("TFTP"),
        (80, true) => Some("HTTP"),
        (88, _) => Some("KERBEROS"),
        (102, true) => Some("S7COMM"),
        (110, true) => Some("POP3"),
        (123, false) => Some("NTP"),
        (143, true) => Some("IMAP"),
        (161 | 162, false) => Some("SNMP"),
        (179, true) => Some("BGP"),
        (319 | 320, false) => Some("PTP"),
        (389, _) => Some("LDAP"),
        (443, true) => Some("TLS"),
        (443, false) => Some("QUIC"),
        (445, true) => Some("SMB"),
        (500 | 4500, false) => Some("IKEV2"),
        (502, _) => Some("MODBUS"),
        (514, _) => Some("SYSLOG"),
        (520 | 521, false) => Some("RIP"),
        (554, true) => Some("RTSP"),
        (1812 | 1813, false) => Some("RADIUS"),
        (1883, true) => Some("MQTT"),
        (1900, false) => Some("SSDP"),
        (1985, false) => Some("HSRP"),
        (2049, _) => Some("NFS"),
        (2055, false) => Some("NETFLOW"),
        (3306, true) => Some("MYSQL"),
        (3478, false) => Some("STUN"),
        (3784, false) => Some("BFD"),
        (4739, false) => Some("IPFIX"),
        (4789, false) => Some("VXLAN"),
        (4840, true) => Some("OPCUA"),
        (5004, false) => Some("RTP"),
        (5060, _) => Some("SIP"),
        (5353, false) => Some("MDNS"),
        (5432, true) => Some("POSTGRES"),
        (5672, true) => Some("AMQP"),
        (5683, false) => Some("COAP"),
        (6081, false) => Some("GENEVE"),
        (6343, false) => Some("SFLOW"),
        (6379, true) => Some("REDIS"),
        (6653, true) => Some("OPENFLOW"),
        (11211, _) => Some("MEMCACHED"),
        (20000, _) => Some("DNP3"),
        (44818, _) => Some("ETHERNETIP"),
        (47808, false) => Some("BACNET"),
        (50051, true) => Some("GRPC"),
        (51820, false) => Some("WIREGUARD"),
        _ => None,
    }
}

/// Formats a 6-byte Ethernet MAC address slice as `xx:xx:xx:xx:xx:xx`.
fn format_mac(b: &[u8]) -> String {
    if b.len() < 6 {
        return "00:00:00:00:00:00".to_string();
    }
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        b[0], b[1], b[2], b[3], b[4], b[5]
    )
}

/// Dissects a raw Ethernet frame into `(source_dest, protocol, summary)` strings.
fn summarize_frame(data: &[u8]) -> (String, String, String) {
    if data.len() < 14 {
        return (
            "unknown -> unknown".to_string(),
            "RAW".to_string(),
            format!("{} bytes", data.len()),
        );
    }

    let dst_mac = format_mac(&data[0..6]);
    let src_mac = format_mac(&data[6..12]);
    let mut etype = u16::from_be_bytes([data[12], data[13]]);
    let mut offset = 14usize;
    let mut l2_tags = Vec::new();

    while (etype == 0x8100 || etype == 0x88A8 || etype == 0x9100) && offset + 4 <= data.len() {
        let tci = u16::from_be_bytes([data[offset], data[offset + 1]]);
        let vid = tci & 0x0FFF;
        let pcp = (tci >> 13) & 0x07;
        if etype == 0x88A8 || etype == 0x9100 {
            l2_tags.push(format!("SVLAN={vid}"));
        } else if l2_tags.iter().any(|t: &String| t.starts_with("SVLAN=")) {
            l2_tags.push(format!("CVLAN={vid}"));
        } else if pcp > 0 {
            l2_tags.push(format!("VLAN={vid}(PCP={pcp})"));
        } else {
            l2_tags.push(format!("VLAN={vid}"));
        }
        etype = u16::from_be_bytes([data[offset + 2], data[offset + 3]]);
        offset += 4;
    }

    if (etype == 0x8847 || etype == 0x8848) && offset + 4 <= data.len() {
        while offset + 4 <= data.len() {
            let entry = u32::from_be_bytes([
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            ]);
            let label = entry >> 12;
            let bos = (entry >> 8) & 1;
            l2_tags.push(format!("MPLS={label}"));
            offset += 4;
            if bos == 1 {
                break;
            }
        }
        if offset < data.len() {
            let first_nibble = data[offset] >> 4;
            if first_nibble == 4 {
                etype = 0x0800;
            } else if first_nibble == 6 {
                etype = 0x86DD;
            }
        }
    }

    let tag_prefix = if l2_tags.is_empty() {
        String::new()
    } else {
        format!("[{}] ", l2_tags.join(" "))
    };

    match etype {
        0x0806 if offset + 28 <= data.len() => {
            let oper = u16::from_be_bytes([data[offset + 6], data[offset + 7]]);
            let spa = Ipv4Addr::new(
                data[offset + 14],
                data[offset + 15],
                data[offset + 16],
                data[offset + 17],
            );
            let tpa = Ipv4Addr::new(
                data[offset + 24],
                data[offset + 25],
                data[offset + 26],
                data[offset + 27],
            );
            let detail = if oper == 1 {
                format!("{tag_prefix}Who has {tpa}? Tell {spa}")
            } else {
                format!("{tag_prefix}{spa} is at {src_mac}")
            };
            (format!("{spa} -> {tpa}"), "ARP".to_string(), detail)
        }
        0x0800 if offset + 20 <= data.len() => {
            let ihl = ((data[offset] & 0x0F) as usize) * 4;
            let proto = data[offset + 9];
            let src_ip = Ipv4Addr::new(
                data[offset + 12],
                data[offset + 13],
                data[offset + 14],
                data[offset + 15],
            );
            let dst_ip = Ipv4Addr::new(
                data[offset + 16],
                data[offset + 17],
                data[offset + 18],
                data[offset + 19],
            );
            let l4_slice = if offset + ihl <= data.len() {
                &data[offset + ihl..]
            } else {
                &[]
            };
            let (p_label, summary) = summarize_l4(proto, l4_slice, &tag_prefix);
            (format!("{src_ip} -> {dst_ip}"), p_label, summary)
        }
        0x86DD if offset + 40 <= data.len() => {
            let mut next_hdr = data[offset + 6];
            let mut src_bytes = [0u8; 16];
            src_bytes.copy_from_slice(&data[offset + 8..offset + 24]);
            let mut dst_bytes = [0u8; 16];
            dst_bytes.copy_from_slice(&data[offset + 24..offset + 40]);
            let src_ip = Ipv6Addr::from(src_bytes);
            let dst_ip = Ipv6Addr::from(dst_bytes);
            let mut l4_offset = offset + 40;
            if next_hdr == 0 && l4_offset + 8 <= data.len() {
                next_hdr = data[l4_offset];
                let ext_len = (data[l4_offset + 1] as usize + 1) * 8;
                if l4_offset + ext_len <= data.len() {
                    l4_offset += ext_len;
                }
            }
            let l4_slice = if l4_offset <= data.len() {
                &data[l4_offset..]
            } else {
                &[]
            };
            let (p_label, summary) = summarize_l4(next_hdr, l4_slice, &tag_prefix);
            (format!("{src_ip} -> {dst_ip}"), p_label, summary)
        }
        0x88CC => (
            format!("{src_mac} -> {dst_mac}"),
            "LLDP".to_string(),
            format!("{tag_prefix}Link Layer Discovery Protocol frame"),
        ),
        0x8809 => (
            format!("{src_mac} -> {dst_mac}"),
            "LACP".to_string(),
            format!("{tag_prefix}Link Aggregation Control Protocol PDU"),
        ),
        0x888E => (
            format!("{src_mac} -> {dst_mac}"),
            "EAPOL".to_string(),
            format!("{tag_prefix}IEEE 802.1X EAP over LAN frame"),
        ),
        _ => {
            let proto = if dst_mac == "01:80:c2:00:00:00" {
                "STP"
            } else if l2_tags.iter().any(|t| t.starts_with("SVLAN=")) {
                "QINQ"
            } else if l2_tags.iter().any(|t| t.starts_with("VLAN=")) {
                "VLAN"
            } else if l2_tags.iter().any(|t| t.starts_with("MPLS=")) {
                "MPLS"
            } else {
                "L2"
            };
            (
                format!("{src_mac} -> {dst_mac}"),
                proto.to_string(),
                format!("{tag_prefix}EtherType 0x{etype:04x}"),
            )
        }
    }
}

/// Dissects the Layer 4 / Layer 3-control header inside an IPv4 or IPv6 packet.
fn summarize_l4(proto: u8, l4: &[u8], tag_prefix: &str) -> (String, String) {
    match proto {
        6 if l4.len() >= 20 => {
            let sport = u16::from_be_bytes([l4[0], l4[1]]);
            let dport = u16::from_be_bytes([l4[2], l4[3]]);
            let seq = u32::from_be_bytes([l4[4], l4[5], l4[6], l4[7]]);
            let ack = u32::from_be_bytes([l4[8], l4[9], l4[10], l4[11]]);
            let hdr_len = ((l4[12] >> 4) as usize) * 4;
            let flags = l4[13];
            let payload_len = l4.len().saturating_sub(hdr_len);
            let payload = if hdr_len <= l4.len() {
                &l4[hdr_len..]
            } else {
                &[]
            };

            let mut flag_names = Vec::new();
            for (bit, name) in [
                (0x02, "SYN"),
                (0x10, "ACK"),
                (0x08, "PSH"),
                (0x04, "RST"),
                (0x01, "FIN"),
                (0x20, "URG"),
                (0x40, "ECE"),
                (0x80, "CWR"),
            ] {
                if flags & bit != 0 {
                    flag_names.push(name);
                }
            }
            let flags_str = if flag_names.is_empty() {
                "NONE".to_string()
            } else {
                flag_names.join(" ")
            };

            let l7_proto = if payload_len > 0 {
                if payload.starts_with(b"PRI * HTTP/2.0") {
                    Some("HTTP2")
                } else {
                    port_to_l7_name(dport, true).or_else(|| port_to_l7_name(sport, true))
                }
            } else {
                None
            };
            let label = l7_proto.unwrap_or("TCP").to_string();
            let ack_part = if flags & 0x10 != 0 {
                format!(" ack={ack}")
            } else {
                String::new()
            };
            (
                label,
                format!(
                    "{tag_prefix}{sport} -> {dport} [{flags_str}] seq={seq}{ack_part} len={payload_len}"
                ),
            )
        }
        17 if l4.len() >= 8 => {
            let sport = u16::from_be_bytes([l4[0], l4[1]]);
            let dport = u16::from_be_bytes([l4[2], l4[3]]);
            let payload_len = l4.len().saturating_sub(8);
            let l7_proto = port_to_l7_name(dport, false).or_else(|| port_to_l7_name(sport, false));
            let label = l7_proto.unwrap_or("UDP").to_string();
            (
                label,
                format!("{tag_prefix}{sport} -> {dport} len={payload_len}"),
            )
        }
        1 if l4.len() >= 4 => {
            let icmp_type = l4[0];
            let icmp_code = l4[1];
            let desc = match icmp_type {
                8 => "Echo Request",
                0 => "Echo Reply",
                3 => "Destination Unreachable",
                5 => "Redirect",
                11 => "Time Exceeded",
                _ => "Control Message",
            };
            (
                "ICMP".to_string(),
                format!("{tag_prefix}{desc} (type={icmp_type} code={icmp_code})"),
            )
        }
        58 if l4.len() >= 4 => {
            let icmp6_type = l4[0];
            let (label, desc) = match icmp6_type {
                128 => ("ICMPv6", "Echo Request"),
                129 => ("ICMPv6", "Echo Reply"),
                130..=132 | 143 => ("MLD", "Multicast Listener Discovery"),
                133..=137 => ("NDP", "Neighbor Discovery Protocol"),
                _ => ("ICMPv6", "Control Message"),
            };
            (
                label.to_string(),
                format!("{tag_prefix}{desc} (type={icmp6_type})"),
            )
        }
        2 => (
            "IGMP".to_string(),
            format!("{tag_prefix}Multicast Membership Message"),
        ),
        47 => ("GRE".to_string(), format!("{tag_prefix}GRE Tunnel Packet")),
        50 => (
            "ESP".to_string(),
            format!("{tag_prefix}IPsec Encapsulating Security Payload"),
        ),
        51 => (
            "AH".to_string(),
            format!("{tag_prefix}IPsec Authentication Header"),
        ),
        89 => (
            "OSPF".to_string(),
            format!("{tag_prefix}Open Shortest Path First"),
        ),
        103 => (
            "PIM".to_string(),
            format!("{tag_prefix}Protocol Independent Multicast"),
        ),
        112 => (
            "VRRP".to_string(),
            format!("{tag_prefix}Virtual Router Redundancy Protocol"),
        ),
        132 if l4.len() >= 12 => {
            let sport = u16::from_be_bytes([l4[0], l4[1]]);
            let dport = u16::from_be_bytes([l4[2], l4[3]]);
            (
                "SCTP".to_string(),
                format!("{tag_prefix}{sport} -> {dport}"),
            )
        }
        other => (
            format!("IP({other})"),
            format!("{tag_prefix}Protocol {other} ({} bytes)", l4.len()),
        ),
    }
}

/// Compiles `.fasm` source into typed [`PacketPreview`] entries without invoking JS bindings.
///
/// # Errors
/// Returns a human-readable compilation error string if parsing or wire synthesis fails.
pub fn inspect_fasm_to_previews(source: &str) -> Result<Vec<PacketPreview>, String> {
    let program = parse_program(source).map_err(|e| e.to_string())?;
    let packets = compile_program(&program)?;
    let base_ns = packets.first().map_or(0, |(_, ts)| *ts);

    let previews = packets
        .iter()
        .enumerate()
        .map(|(idx, (bytes, ts_ns))| {
            let mut hex = String::with_capacity(bytes.len().saturating_mul(3));
            for (i, b) in bytes.iter().enumerate() {
                if i > 0 {
                    hex.push(' ');
                }
                let _ = write!(hex, "{b:02x}");
            }
            let (source_dest, protocol, summary) = summarize_frame(bytes);
            PacketPreview {
                index: idx + 1,
                timestamp_ms: ts_ns.saturating_sub(base_ns) as f64 / 1_000_000.0,
                length: bytes.len(),
                hex,
                source_dest,
                protocol,
                summary,
            }
        })
        .collect();

    Ok(previews)
}

/// Returns decoded frame metadata, endpoint/protocol summaries, and hex strings for packet ladder inspectors.
#[wasm_bindgen(unchecked_return_type = "PacketPreview[]")]
pub fn inspect_fasm(source: &str) -> Result<JsValue, JsError> {
    let previews = inspect_fasm_to_previews(source).map_err(|e| JsError::new(&e))?;
    Ok(serde_wasm_bindgen::to_value(&previews)?)
}

/// Compiles `.fasm` source into a standards-compliant PCAPNG byte array (JS `Uint8Array`).
#[wasm_bindgen]
pub fn compile_fasm_to_pcapng(source: &str) -> Result<Vec<u8>, JsError> {
    let program = parse_program(source).map_err(|e| JsError::new(&e.to_string()))?;
    let packets = compile_program(&program).map_err(|e| JsError::new(&e.to_string()))?;
    Ok(packets_to_pcapng(&packets))
}

/// Compiles `.fasm` source into a standards-compliant PCAPNG byte array (`compileFasm` alias).
#[wasm_bindgen(js_name = compileFasm)]
pub fn compile_fasm(source: &str) -> Result<Vec<u8>, JsError> {
    compile_fasm_to_pcapng(source)
}

/// Decompiles an in-memory `.pcap` or `.pcapng` byte slice into a typed [`ReversePcapResult`]
/// or [`ReversePcapError`] without invoking JavaScript heap bindings.
///
/// # Errors
/// Returns [`ReversePcapError`] if `pcap_bytes` is not a valid `.pcap` or `.pcapng` capture.
pub fn reverse_pcap_to_result(pcap_bytes: &[u8]) -> Result<ReversePcapResult, ReversePcapError> {
    match reverse_pcap_bytes(pcap_bytes) {
        Ok(out) => Ok(ReversePcapResult {
            success: true,
            fasm: out.fasm,
            packet_count: out.packet_count,
            host_count: out.host_count,
        }),
        Err(err) => {
            let message = err.to_string();
            Err(ReversePcapError {
                success: false,
                error: message.clone(),
                message,
            })
        }
    }
}

/// Decompiles an in-memory `.pcap` or `.pcapng` capture (`Uint8Array`) into canonical `.fasm`
/// source code and summary counts (`{ success: true, fasm, packetCount, hostCount }`).
///
/// # Errors
/// Returns a structured `JsValue` error object (`{ success: false, error, message }`) if
/// `pcap_bytes` is not a valid `.pcap` or `.pcapng` capture.
#[wasm_bindgen(unchecked_return_type = "ReversePcapResult")]
pub fn reverse_pcap(pcap_bytes: &[u8]) -> Result<JsValue, JsValue> {
    match reverse_pcap_to_result(pcap_bytes) {
        Ok(result) => serde_wasm_bindgen::to_value(&result)
            .map_err(|e| JsValue::from_str(&e.to_string())),
        Err(err) => {
            let fallback = err.message.clone();
            Err(serde_wasm_bindgen::to_value(&err)
                .unwrap_or_else(|_| JsValue::from_str(&fallback)))
        }
    }
}

/// Decompiles an in-memory `.pcap` or `.pcapng` capture (`reversePcap` camelCase alias).
///
/// # Errors
/// Returns a structured `JsValue` error object (`{ success: false, error, message }`) if
/// `pcap_bytes` is not a valid `.pcap` or `.pcapng` capture.
#[wasm_bindgen(js_name = reversePcap, unchecked_return_type = "ReversePcapResult")]
pub fn reverse_pcap_js(pcap_bytes: &[u8]) -> Result<JsValue, JsValue> {
    reverse_pcap(pcap_bytes)
}

/// Serializes `(frame_bytes, timestamp_ns)` tuples into an in-memory PCAPNG byte vector
/// with nanosecond timestamp resolution (`IfTsResol = 9`).
pub fn packets_to_pcapng(packets: &[(Vec<u8>, u64)]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(60 + packets.len() * 96);

    // Section Header Block (28 bytes)
    buf.extend_from_slice(&0x0A0D_0D0Au32.to_le_bytes());
    buf.extend_from_slice(&28u32.to_le_bytes());
    buf.extend_from_slice(&0x1A2B_3C4Du32.to_le_bytes());
    buf.extend_from_slice(&1u16.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&(-1i64).to_le_bytes());
    buf.extend_from_slice(&28u32.to_le_bytes());

    // Interface Description Block (32 bytes, Ethernet + snaplen 65535 + nanosecond resolution)
    buf.extend_from_slice(&1u32.to_le_bytes());
    buf.extend_from_slice(&32u32.to_le_bytes());
    buf.extend_from_slice(&1u16.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&65_535u32.to_le_bytes());
    buf.extend_from_slice(&9u16.to_le_bytes());
    buf.extend_from_slice(&1u16.to_le_bytes());
    buf.extend_from_slice(&[9, 0, 0, 0]);
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&32u32.to_le_bytes());

    // Enhanced Packet Blocks
    for (frame, ts_ns) in packets {
        let orig_len = frame.len() as u32;
        let padded_len = (frame.len() + 3) & !3;
        let block_len = (32 + padded_len) as u32;

        buf.extend_from_slice(&6u32.to_le_bytes());
        buf.extend_from_slice(&block_len.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.extend_from_slice(&((ts_ns >> 32) as u32).to_le_bytes());
        buf.extend_from_slice(&(*ts_ns as u32).to_le_bytes());
        buf.extend_from_slice(&orig_len.to_le_bytes());
        buf.extend_from_slice(&orig_len.to_le_bytes());
        buf.extend_from_slice(frame);
        buf.resize(buf.len() + (padded_len - frame.len()), 0);
        buf.extend_from_slice(&block_len.to_le_bytes());
    }

    buf
}

/// Extracts span coordinates and remediation hints from a `miette::Diagnostic` and appends an [`IdeDiagnostic`].
fn push_diagnostic(source: &str, err: &dyn Diagnostic, out: &mut Vec<IdeDiagnostic>) {
    let message = err.to_string();
    let help = err.help().map(|h| h.to_string());

    if let Some(mut labels) = err.labels()
        && let Some(span) = labels.next()
    {
        let (start_line, start_col) = byte_to_utf16_pos(source, span.offset());
        let (end_line, end_col) = byte_to_utf16_pos(source, span.offset() + span.len().max(1));
        out.push(IdeDiagnostic {
            start_line,
            start_col,
            end_line,
            end_col,
            message,
            help,
        });
    } else {
        let (start_byte, end_byte) = find_backend_error_span(source, &message);
        let (start_line, start_col) = byte_to_utf16_pos(source, start_byte);
        let (end_line, end_col) =
            byte_to_utf16_pos(source, end_byte.max(start_byte.saturating_add(1)));
        out.push(IdeDiagnostic {
            start_line,
            start_col,
            end_line,
            end_col,
            message,
            help,
        });
    }
}

/// Unit tests for UTF-16 span mapping, diagnostics, packet previews, PCAPNG serialization, and decompilation.
#[cfg(test)]
mod tests {
    use super::*;

    /// Verifies that `byte_offset_to_utf16_line_col` maps multi-byte UTF-8 and astral-plane
    /// surrogate pairs to zero-based UTF-16 line and column indices and clamps mid-character offsets.
    #[test]
    fn test_utf16_line_col_handles_multibyte_utf8_and_surrogate_pairs() {
        let src = "host host1 { ip 10.0.0.1 }\n// 🔥\ncompile { host1 -> host1 icmp }";
        assert_eq!(byte_offset_to_utf16_line_col(src, 0), (0, 0));
        let line2_start = src.find("//").unwrap_or(0);
        assert_eq!(byte_offset_to_utf16_line_col(src, line2_start + 7), (1, 5));
        assert_eq!(byte_offset_to_utf16_line_col(src, line2_start + 5), (1, 3));
        assert_eq!(
            byte_offset_to_utf16_line_col(src, src.len() + 100),
            byte_offset_to_utf16_line_col(src, src.len())
        );
    }

    /// Verifies in-memory `.fasm` -> PCAPNG compilation, enriched `PacketPreview` summaries, and `reverse_pcap_to_result`.
    #[test]
    fn test_packets_to_pcapng_preview_and_reverse_pcap_roundtrip_in_memory() {
        let src = "host host1 { ip 192.0.2.10 mac 00:11:22:33:44:55 }\n\
                   host host2 { ip 192.0.2.20 mac 00:aa:bb:cc:dd:ee }\n\
                   compile {\n\
                       host1 -> host2 vlan 100 dns query txid 0x1a2b qname \"example.com\" qtype \"a\"\n\
                   }";
        assert!(validate_fasm_to_diagnostics(src).is_empty());

        let previews = inspect_fasm_to_previews(src).expect("inspect valid .fasm");
        assert_eq!(previews.len(), 1);
        assert_eq!(previews[0].index, 1);
        assert_eq!(previews[0].source_dest, "192.0.2.10 -> 192.0.2.20");
        assert_eq!(previews[0].protocol, "DNS");
        assert!(previews[0].summary.contains("[VLAN=100]"));
        assert!(!previews[0].hex.is_empty());

        let program = parse_program(src).expect("parse valid .fasm");
        let packets = compile_program(&program).expect("compile packets");
        let pcapng_bytes = packets_to_pcapng(&packets);

        let rev = reverse_pcap_to_result(&pcapng_bytes).expect("reverse pcapng bytes");
        assert!(rev.success);
        assert_eq!(rev.packet_count, 1);
        assert_eq!(rev.host_count, 2);
        assert!(rev.fasm.contains("host1"));
        assert!(rev.fasm.contains("host2"));
        assert!(rev.fasm.contains("dns"));
    }

    /// Verifies that backend errors highlight the offending statement or `compile` block instead of `(0, 0)`,
    /// and that v2.0.0 lowercase keyword hints are preserved in `IdeDiagnostic.help`.
    #[test]
    fn test_validate_fasm_backend_span_and_lowercase_help_hints() {
        // 1. General backend error fallback locates the `compile` keyword (ignoring `compile` in comments)
        let comment_and_compile = "// compile comment on line 0\n\
                                   host host1 { ip 10.0.0.1 }\n\
                                   compile {\n\
                                       host1 -> host1 icmp\n\
                                   }";
        let (s_byte, e_byte) = find_backend_error_span(comment_and_compile, "generic backend failure");
        assert_eq!(&comment_and_compile[s_byte..e_byte], "compile");
        assert_eq!(byte_offset_to_utf16_line_col(comment_and_compile, s_byte), (2, 0));

        // 2. Real backend error (`SNMPv3` privacy without authentication) highlights the non-(0,0) statement
        let bad_backend = "host host1 { ip 10.0.0.1 }\n\
                           host host2 { ip 10.0.0.2 }\n\
                           compile {\n\
                               host1 -> host2 snmp3 trap user \"ops\" priv aes \"PrivPass123!\"\n\
                           }";
        let diags = validate_fasm_to_diagnostics(bad_backend);
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0].start_line, 3);
        assert!(diags[0].start_col > 0);

        // 3. Uppercase / snake_case keyword error preserves self-healing `replace '...' with '...'` help
        let bad_kw = "host host1 { ip 10.0.0.1 }\n\
                      compile {\n\
                          host1 -> host1 icmp echo_request\n\
                      }";
        let kw_diags = validate_fasm_to_diagnostics(bad_kw);
        assert_eq!(kw_diags.len(), 1);
        let help = kw_diags[0].help.as_deref().unwrap_or("");
        assert!(
            help.contains("replace 'echo_request' with 'echorequest'"),
            "expected v2.0.0 lowercase help hint, got: {help}"
        );
    }

    /// Verifies that corrupt or empty capture inputs return a structured [`ReversePcapError`] without panicking.
    #[test]
    fn test_reverse_pcap_rejects_corrupt_bytes_without_panicking() {
        for bad in [&b""[..], &b"xyz"[..], &b"not a pcap capture"[..]] {
            let err = reverse_pcap_to_result(bad).expect_err("must reject invalid capture bytes");
            assert!(!err.success);
            assert!(!err.error.is_empty());
            assert_eq!(err.error, err.message);
        }
    }
}
