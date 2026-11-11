//! Native PCAP and PCAPNG to `.fasm` reverse decompiler for FrameAssembly.
//!
//! This module implements the five-stage decompilation pipeline that translates binary `.pcap` and
//! `.pcapng` packet captures back into canonical, lowercase `.fasm` network traffic specifications:
//!
//! 1. **Container Normalization (`container`)**: Streams legacy PCAP (microsecond and nanosecond
//!    magic numbers) and PCAPNG (`SectionHeaderBlock`, `InterfaceDescriptionBlock`,
//!    `EnhancedPacketBlock`, `SimplePacketBlock`, `PacketBlock`), scales `IfTsResol` timestamps to
//!    nanoseconds, normalizes link-layer types (`ETHERNET`, `RAW`, `IPV4`, `IPV6`, `LINUX_SLL`,
//!    `LINUX_SLL2`, `NULL`, `LOOP`) into Ethernet II frames, and strips 60/64-byte Ethernet zero
//!    padding and 4-byte FCS trailers.
//! 2. **Layer 2–7 Modular Protocol Dissection (`l2`, `l3`, `l4`, `l7`)**: Decodes all 81 native
//!    protocols across Layer 2 through Layer 7 into strongly-typed modifier structures and
//!    canonical `.fasm` token strings.
//! 3. **Deterministic Topology Discovery (`topology`)**: Infers sequential `host1`, `host2`, ...
//!    declarations, tracks dominant unicast MAC addresses, pairs broadcast/multicast traffic, and
//!    locks directional arrows (`->` vs `<-`) per endpoint pair.
//! 4. **Per-Packet Self-Check Oracle (`oracle`)**: Compiles each candidate `.fasm` statement in
//!    isolation via FrameAssembly's own forward compiler and preserves clean, readable high-level
//!    `.fasm` statements (or steps down to raw L4/L2 if a candidate statement fails to compile).
//! 5. **Shadow-State Elision & Emission (`shadow_emit`)**: Mirrors the forward compiler's 4-tuple
//!    TCP sequence/acknowledgment state machine and bidirectional port inheritance to elide
//!    redundant defaults and emit canonical `host` and `compile` blocks.

pub(crate) mod container;
pub(crate) mod l2;
pub(crate) mod l3;
pub(crate) mod l4;
pub(crate) mod l7;
pub(crate) mod oracle;
pub(crate) mod shadow_emit;
pub(crate) mod topology;

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write as _;
use core::net::IpAddr;

use crate::ast::{L2Modifiers, L3Modifiers, L4Modifiers, Protocol, TransportProto};
use crate::error::CompilerError;

/// Summary statistics and `.fasm` source code returned by the decompiler.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReverseOutput {
    /// Generated canonical lowercase `.fasm` code.
    pub fasm: String,
    /// Total number of packets reversed.
    pub packet_count: usize,
    /// Total number of `hostN` definitions emitted.
    pub host_count: usize,
}

/// Result returned by a protocol dissector.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtocolDissection {
    /// Identified FrameAssembly [`Protocol`].
    pub protocol: Protocol,
    /// Canonical lowercase `.fasm` protocol keyword and protocol-specific modifiers
    /// (e.g., `"dns query txid 0x1a2b qname \"example.com\" qtype \"a\""`).
    /// Does NOT include caller/callee arrows, L2/L3/L4 universal modifiers, `payload`/`hexpayload`, or `wait`.
    pub tokens: String,
    /// Residual application payload bytes to attach as `payload "..."` or `hexpayload "..."`.
    pub residual_payload: Vec<u8>,
    /// Optional explicit `transport tcp` or `transport udp` modifier if non-default for this protocol.
    pub explicit_transport: Option<TransportProto>,
}

/// Normalized, dissected packet representation across L2–L7.
#[derive(Debug, Clone)]
pub(crate) struct DissectedPacket {
    /// Capture timestamp in nanoseconds.
    pub timestamp_ns: u64,
    /// Normalized Ethernet II frame bytes (with Ethernet zero-padding and 4B FCS stripped).
    pub raw_eth_frame: Vec<u8>,
    /// Whether the original capture linktype was L3-only (`RAW`/`IPV4`/`IPV6`/`NULL`/`LOOP`).
    pub is_l3_only: bool,
    /// Outer source MAC address.
    pub src_mac: [u8; 6],
    /// Outer destination MAC address.
    pub dst_mac: [u8; 6],
    /// Parsed L2 modifiers (`vlan`, `qinq`, `mpls`, `ethertype`, `src_mac`, `dst_mac`).
    pub l2: L2Modifiers,
    /// Inner EtherType (or IEEE 802.3 length <= 1500) following any VLAN/QinQ/MPLS tags.
    pub inner_ethertype: u16,
    /// Source IP address if an IPv4/IPv6 header (or ARP) is present.
    pub src_ip: Option<IpAddr>,
    /// Destination IP address if an IPv4/IPv6 header (or ARP) is present.
    pub dst_ip: Option<IpAddr>,
    /// Whether `src_ip`/`dst_ip` came from an actual IPv4/IPv6 L3 header (`true`) vs pure L2/ARP (`false`).
    pub has_ip_header: bool,
    /// IP protocol / Next Header number if `has_ip_header` is `true`.
    pub ip_proto: Option<u8>,
    /// Parsed L3 modifiers (`ttl`, `dscp`, `ecn`, `flowlabel`, `ipid`, `df`, `mf`, `frag_offset`).
    pub l3: L3Modifiers,
    /// Parsed L4 modifiers (`src_port`, `dst_port`, `transport`, `tcp_flags`, `urgent`, `tcp_options`, `sctp_params`).
    pub l4: L4Modifiers,
    /// TCP sequence number if TCP.
    pub seq: Option<u32>,
    /// TCP acknowledgment number if TCP.
    pub ack_num: Option<u32>,
    /// TCP window size if TCP.
    pub win: Option<u16>,
    /// Raw L4 payload bytes (after TCP/UDP/SCTP header), or L3 payload bytes, or L2 payload bytes.
    pub l4_payload: Vec<u8>,
    /// Raw L2 payload bytes (immediately after Ethernet/VLAN/QinQ/MPLS header).
    pub l2_payload: Vec<u8>,
    /// High-level protocol dissection result.
    pub dissection: ProtocolDissection,
}

/// Decompiles a binary `.pcap` or `.pcapng` capture stream into canonical `.fasm` code.
///
/// # Errors
/// Returns [`CompilerError::BackendError`] if the stream is not a valid `.pcap` or `.pcapng`
/// capture or if an I/O or container framing error occurs.
pub fn reverse_pcap_reader<R: std::io::Read>(reader: R) -> Result<ReverseOutput, CompilerError> {
    let frames = container::read_capture_frames(reader).map_err(CompilerError::BackendError)?;
    let packets: Vec<DissectedPacket> = frames.into_iter().map(l2::dissect_packet).collect();
    let topo = topology::build_topology(&packets);
    Ok(shadow_emit::emit_fasm_program(&packets, &topo))
}

/// Decompiles an in-memory `.pcap` or `.pcapng` byte slice into canonical `.fasm` code.
///
/// # Errors
/// Returns [`CompilerError::BackendError`] if `bytes` is not a valid `.pcap` or `.pcapng` capture.
pub fn reverse_pcap_bytes(bytes: &[u8]) -> Result<ReverseOutput, CompilerError> {
    reverse_pcap_reader(std::io::Cursor::new(bytes))
}

/// Decompiles a `.pcap` or `.pcapng` file on disk into canonical `.fasm` code.
///
/// # Errors
/// Returns [`CompilerError::BackendError`] if the file cannot be opened or is not a valid capture.
pub fn reverse_pcap_file(path: impl AsRef<std::path::Path>) -> Result<ReverseOutput, CompilerError> {
    let path_ref = path.as_ref();
    let file = std::fs::File::open(path_ref).map_err(|e| {
        CompilerError::BackendError(alloc::format!(
            "Failed to open capture file '{}': {}",
            path_ref.display(),
            e
        ))
    })?;
    let reader = std::io::BufReader::new(file);
    reverse_pcap_reader(reader)
}

/// Formats a 6-byte MAC address as lowercase colon-separated hexadecimal (`aa:bb:cc:dd:ee:ff`).
pub(crate) fn format_mac_lower(mac: [u8; 6]) -> String {
    alloc::format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0],
        mac[1],
        mac[2],
        mac[3],
        mac[4],
        mac[5]
    )
}

/// Escapes a UTF-8 string for inclusion inside a `.fasm` double-quoted string literal.
pub(crate) fn escape_fasm_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\r' => out.push_str("\\r"),
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 || (c as u32) == 0x7f => {
                let _ = write!(out, "\\x{:02x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out
}

/// Encodes a byte slice as a lowercase contiguous hexadecimal string.
pub(crate) fn bytes_to_hex_lower(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        let _ = write!(out, "{:02x}", b);
    }
    out
}

/// Formats residual payload bytes as `payload "..."` when printable ASCII/UTF-8 or `hexpayload "..."` otherwise.
///
/// Returns an empty string when `bytes` is empty.
pub(crate) fn format_payload_modifier(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return String::new();
    }
    if bytes
        .iter()
        .all(|&b| (0x20..=0x7e).contains(&b) || b == b'\r' || b == b'\n' || b == b'\t')
        && let Ok(s) = core::str::from_utf8(bytes)
    {
        return alloc::format!("payload \"{}\"", escape_fasm_string(s));
    }
    alloc::format!("hexpayload \"{}\"", bytes_to_hex_lower(bytes))
}

/// Reads a big-endian `u16` from `b` at `off`.
pub(crate) fn be_u16(b: &[u8], off: usize) -> u16 {
    u16::from_be_bytes([b[off], b[off + 1]])
}

/// Reads a big-endian `u32` from `b` at `off`.
pub(crate) fn be_u32(b: &[u8], off: usize) -> u32 {
    u32::from_be_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}

/// Reads a big-endian `u64` from `b` at `off`.
pub(crate) fn be_u64(b: &[u8], off: usize) -> u64 {
    let mut arr = [0u8; 8];
    arr.copy_from_slice(&b[off..off + 8]);
    u64::from_be_bytes(arr)
}

/// Reads a little-endian `u32` from `b` at `off`.
pub(crate) fn le_u32(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}

/// Reads a 6-byte MAC address from `b` at `off`.
pub(crate) fn mac_at(b: &[u8], off: usize) -> [u8; 6] {
    [
        b[off],
        b[off + 1],
        b[off + 2],
        b[off + 3],
        b[off + 4],
        b[off + 5],
    ]
}

/// Reads an `Ipv4Addr` from `b` at `off`.
pub(crate) fn ipv4_at(b: &[u8], off: usize) -> core::net::Ipv4Addr {
    core::net::Ipv4Addr::new(b[off], b[off + 1], b[off + 2], b[off + 3])
}

/// Reads an `Ipv6Addr` from `b` at `off`.
pub(crate) fn ipv6_at(b: &[u8], off: usize) -> core::net::Ipv6Addr {
    let mut arr = [0u8; 16];
    arr.copy_from_slice(&b[off..off + 16]);
    core::net::Ipv6Addr::from(arr)
}

/// Appends ` <kw> <val>` onto `out` when `val != default`.
pub(crate) fn push_if<T: PartialEq + core::fmt::Display>(
    out: &mut String,
    kw: &str,
    val: T,
    default: T,
) {
    if val != default {
        let _ = write!(out, " {kw} {val}");
    }
}

/// Appends ` <kw> 0x<val>` with `width` hex digits onto `out` when `val != default`.
pub(crate) fn push_hex(out: &mut String, kw: &str, val: u64, default: u64, width: usize) {
    if val != default {
        let _ = write!(out, " {kw} 0x{val:0width$x}");
    }
}

/// Appends ` <kw> "<val>"` onto `out` when `val != default`.
#[allow(dead_code)]
pub(crate) fn push_str_if(out: &mut String, kw: &str, val: &str, default: &str) {
    if val != default {
        let needs_escape = {
            let mut it = val.chars();
            let mut esc = false;
            while let Some(c) = it.next() {
                if matches!(c, '\0' | '\r' | '\n' | '"')
                    || (c == '\\' && it.next().is_none_or(|n| matches!(n, '\0' | '\r' | '\n')))
                {
                    esc = true;
                    break;
                }
            }
            esc
        };
        if needs_escape {
            let _ = write!(out, " {kw} \"{}\"", escape_fasm_string(val));
        } else {
            let _ = write!(out, " {kw} \"{val}\"");
        }
    }
}

/// Appends ` <kw> <ip>` onto `out` when `ip != default`.
#[allow(dead_code)]
pub(crate) fn push_ip_if<T: PartialEq + core::fmt::Display>(
    out: &mut String,
    kw: &str,
    ip: T,
    default: T,
) {
    if ip != default {
        let _ = write!(out, " {kw} {ip}");
    }
}

/// Appends ` <kw> <mac>` onto `out` when `mac != default`.
pub(crate) fn push_mac_if(out: &mut String, kw: &str, mac: [u8; 6], default: [u8; 6]) {
    if mac != default {
        let _ = write!(out, " {kw} {}", format_mac_lower(mac));
    }
}

/// Extracts `Ipv4Addr` from `src_ip` or returns `fallback`.
pub(crate) fn src_v4_or(
    src_ip: Option<IpAddr>,
    fallback: core::net::Ipv4Addr,
) -> core::net::Ipv4Addr {
    match src_ip {
        Some(IpAddr::V4(v4)) => v4,
        _ => fallback,
    }
}

/// Constructs a [`ProtocolDissection`] with no explicit L4 transport override.
pub(crate) fn sd(
    protocol: Protocol,
    tokens: String,
    residual_payload: Vec<u8>,
) -> ProtocolDissection {
    ProtocolDissection {
        protocol,
        tokens,
        residual_payload,
        explicit_transport: None,
    }
}

/// Constructs a [`ProtocolDissection`] with an explicit L4 transport override.
#[allow(dead_code)]
pub(crate) fn sd_tp(
    protocol: Protocol,
    tokens: String,
    residual_payload: Vec<u8>,
    explicit_transport: impl Into<Option<TransportProto>>,
) -> ProtocolDissection {
    ProtocolDissection {
        protocol,
        tokens,
        residual_payload,
        explicit_transport: explicit_transport.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::compile_program;
    use crate::parser::parse_program;
    use pcap_file::pcapng::PcapNgWriter;
    use pcap_file::pcapng::blocks::Block;
    use pcap_file::pcapng::blocks::enhanced_packet::EnhancedPacketBlock;
    use pcap_file::pcapng::blocks::interface_description::{
        InterfaceDescriptionBlock, InterfaceDescriptionOption,
    };
    use std::borrow::Cow;
    use std::time::Duration;

    /// Serializes `(frame_bytes, timestamp_ns)` pairs into an in-memory PCAPNG buffer.
    fn frames_to_pcapng(frames: &[(Vec<u8>, u64)]) -> Vec<u8> {
        let mut buf = Vec::new();
        let Ok(mut writer) = PcapNgWriter::new(&mut buf) else {
            panic!("create PcapNgWriter");
        };
        let idb = InterfaceDescriptionBlock {
            linktype: pcap_file::DataLink::ETHERNET,
            snaplen: 65535,
            options: alloc::vec![InterfaceDescriptionOption::IfTsResol(9)],
        };
        assert!(
            writer
                .write_block(&Block::InterfaceDescription(idb))
                .is_ok()
        );
        for (data, ts) in frames {
            let epb = EnhancedPacketBlock {
                interface_id: 0,
                timestamp: Duration::from_nanos(*ts),
                original_len: data.len() as u32,
                data: Cow::Borrowed(data),
                options: Vec::new(),
            };
            assert!(writer.write_block(&Block::EnhancedPacket(epb)).is_ok());
        }
        buf
    }

    /// Recursively collects `.fasm` files under `dir`.
    fn collect_fasm_files(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
        if let Ok(entries) = std::fs::read_dir(dir) {
            let mut paths: Vec<_> = entries.filter_map(|e| e.ok().map(|e| e.path())).collect();
            paths.sort();
            for p in paths {
                if p.is_dir() {
                    collect_fasm_files(&p, out);
                } else if p.extension().and_then(|s| s.to_str()) == Some("fasm") {
                    out.push(p);
                }
            }
        }
    }

    /// Verifies round-trip PCAPNG decompilation and recompilation across all `examples/{l2,l3,l4}` corpus files.
    #[test]
    fn test_l2_l3_l4_corpus_roundtrip_oracle() {
        let mut files = Vec::new();
        for sub in ["examples/l2", "examples/l3", "examples/l4"] {
            collect_fasm_files(std::path::Path::new(sub), &mut files);
        }
        assert!(!files.is_empty(), "expected L2/L3/L4 corpus files");

        for path in &files {
            let Ok(src) = std::fs::read_to_string(path) else {
                panic!("read corpus file");
            };
            let Ok(prog) = parse_program(&src) else {
                panic!("parse original corpus file");
            };
            let Ok(orig_frames) = compile_program(&prog) else {
                panic!("compile original corpus file");
            };
            let pcap_bytes = frames_to_pcapng(&orig_frames);

            let out = reverse_pcap_bytes(&pcap_bytes)
                .unwrap_or_else(|e| panic!("reverse failed on {}: {e}", path.display()));
            assert!(
                !out.fasm.contains("// ["),
                "unexpected fallback comment in {}:\n{}",
                path.display(),
                out.fasm
            );
            let reprog = parse_program(&out.fasm).unwrap_or_else(|e| {
                panic!(
                    "re-parse failed on {}: {e}\n--- FASM ---\n{}",
                    path.display(),
                    out.fasm
                )
            });
            let reframes = compile_program(&reprog)
                .unwrap_or_else(|e| panic!("re-compile failed on {}: {e}", path.display()));
            assert_eq!(
                orig_frames.len(),
                reframes.len(),
                "frame count mismatch on {}",
                path.display()
            );
            let orig_base = orig_frames.first().map_or(0, |(_, ts)| *ts);
            let re_base = reframes.first().map_or(0, |(_, ts)| *ts);
            for (idx, ((_orig_b, orig_ts), (_re_b, re_ts))) in
                orig_frames.iter().zip(reframes.iter()).enumerate()
            {
                assert_eq!(
                    orig_ts.saturating_sub(orig_base),
                    re_ts.saturating_sub(re_base),
                    "relative timestamp mismatch on {} frame #{}",
                    path.display(),
                    idx + 1
                );
            }
        }
    }

    /// Verifies v2.0.0 strict-lowercase PCAPNG decompilation (`host1`/`host2`, zero `loop`,
    /// lowercase enum strings, SCTP `shutdownack`, and exact wire-literal case preservation).
    #[test]
    fn test_v2_strict_lowercase_reverse_roundtrip() {
        let src = r#"
host client { ip 10.10.0.1 mac 02:00:00:00:00:01 }
host server { ip 10.10.0.2 mac 02:00:00:00:00:02 }

flow v2_check(a, b) {
    a -> b qinq 100 innervlan 200 payload "QinQ-Body"
    a -> b tcp dstport 443 syn mss 1460 sackperm
    a -> b sctp srcport 2905 dstport 2905 vtag 0x12345678 shutdownack
    b -> a dns response txid 0x1122 qname "Api.Example.COM" qtype "aaaa" rdata 2001:db8::1 ansttl 60
    a -> b http get uri "/v2/HealthCheck" hosthdr "Api.Example.COM"
    a -> b modbus readcoils count 4
    b -> a s7comm rosctr "ackdata" setupcomm
    a -> b opcua msgtype "opn" chunktype "c"
    a -> b smb command "logoff" sessionid 0x42
}

compile {
    v2_check(client, server)
}
"#;
        let prog = parse_program(src).unwrap_or_else(|e| panic!("parse v2 fixture failed: {e}"));
        let orig_frames =
            compile_program(&prog).unwrap_or_else(|e| panic!("compile v2 fixture failed: {e}"));
        let pcap_bytes = frames_to_pcapng(&orig_frames);

        let out = reverse_pcap_bytes(&pcap_bytes)
            .unwrap_or_else(|e| panic!("reverse_pcap_bytes failed: {e}"));
        assert!(out.fasm.contains("host host1"), "expected host1:\n{}", out.fasm);
        assert!(out.fasm.contains("host host2"), "expected host2:\n{}", out.fasm);
        assert!(!out.fasm.contains("host_1"), "unexpected host_1:\n{}", out.fasm);
        assert!(!out.fasm.contains("loop "), "unexpected loop block:\n{}", out.fasm);
        assert!(!out.fasm.contains("// ["), "unexpected fallback comment:\n{}", out.fasm);
        assert!(out.fasm.contains("innervlan 200"), "expected innervlan:\n{}", out.fasm);
        assert!(out.fasm.contains("sackperm"), "expected sackperm:\n{}", out.fasm);
        assert!(out.fasm.contains("shutdownack"), "expected shutdownack:\n{}", out.fasm);
        assert!(out.fasm.contains("qtype \"aaaa\""), "expected lowercase qtype:\n{}", out.fasm);
        assert!(out.fasm.contains("Api.Example.COM"), "expected preserved domain case:\n{}", out.fasm);
        assert!(out.fasm.contains("/v2/HealthCheck"), "expected preserved URI case:\n{}", out.fasm);
        assert!(out.fasm.contains("rosctr \"ackdata\""), "expected lowercase rosctr:\n{}", out.fasm);
        assert!(out.fasm.contains("chunktype \"c\""), "expected lowercase chunktype:\n{}", out.fasm);
        assert!(out.fasm.contains("command \"logoff\""), "expected lowercase smb command:\n{}", out.fasm);

        let reprog =
            parse_program(&out.fasm).unwrap_or_else(|e| panic!("re-parse failed: {e}\n{}", out.fasm));
        let reframes =
            compile_program(&reprog).unwrap_or_else(|e| panic!("re-compile failed: {e}"));
        assert_eq!(orig_frames.len(), reframes.len());
        for (idx, ((orig_b, _), (re_b, _))) in orig_frames.iter().zip(reframes.iter()).enumerate() {
            assert_eq!(orig_b, re_b, "wire frame mismatch on packet #{}", idx + 1);
        }
    }

    /// Verifies that all 50 Layer 7 protocols reverse-decompile to their native v2.0.0 lowercase
    /// protocol keywords without silently stepping down to `tcp`/`udp` + `hexpayload` in the oracle.
    #[test]
    fn test_all_50_l7_protocols_reverse_without_fallback() {
        let l7_protos = [
            "snmp1", "snmp2", "snmp3", "dns", "mdns", "dhcp", "ntp", "ptp", "radius", "tacacs",
            "syslog", "netflow", "ipfix", "sflow", "tftp", "ftp", "ssh", "telnet", "http", "http2",
            "grpc", "websocket", "tls", "quic", "stun", "sip", "rtp", "rtsp", "smtp", "imap",
            "pop3", "kerberos", "ldap", "smb", "nfs", "redis", "memcached", "mysql", "postgres",
            "mqtt", "coap", "amqp", "ssdp", "whois", "modbus", "bacnet", "dnp3", "s7comm",
            "ethernetip", "opcua",
        ];
        assert_eq!(l7_protos.len(), 50);

        let mut fallbacks = Vec::new();
        for proto in l7_protos {
            let src = alloc::format!(
                "host c {{ ip 10.20.0.1 mac 02:00:00:00:01:01 }}\n\
                 host s {{ ip 10.20.0.2 mac 02:00:00:00:01:02 }}\n\
                 flow f(a, b) {{ a -> b {proto} }}\n\
                 compile {{ f(c, s) }}\n"
            );
            let prog = parse_program(&src)
                .unwrap_or_else(|e| panic!("parse failed for {proto}: {e}"));
            let orig_frames = compile_program(&prog)
                .unwrap_or_else(|e| panic!("compile failed for {proto}: {e}"));
            let pcap_bytes = frames_to_pcapng(&orig_frames);
            let out = reverse_pcap_bytes(&pcap_bytes)
                .unwrap_or_else(|e| panic!("reverse failed for {proto}: {e}"));

            let needle = alloc::format!(" {proto}");
            if !out.fasm.contains(&needle) || out.fasm.contains("hexpayload") {
                fallbacks.push((proto, out.fasm.clone()));
                continue;
            }

            let reprog = parse_program(&out.fasm)
                .unwrap_or_else(|e| panic!("re-parse failed for {proto}: {e}\n{}", out.fasm));
            let reframes = compile_program(&reprog)
                .unwrap_or_else(|e| panic!("re-compile failed for {proto}: {e}"));
            assert_eq!(orig_frames[0].0, reframes[0].0, "wire mismatch for {proto}");
        }
        assert!(
            fallbacks.is_empty(),
            "L7 protocols fell back ({} total): {:?}",
            fallbacks.len(),
            fallbacks.iter().map(|(p, _)| *p).collect::<Vec<_>>()
        );
    }
}
