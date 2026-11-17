//! Native PCAP and PCAPNG to `.frasm` reverse decompiler for FrameAssembly.
//!
//! This module implements the five-stage decompilation pipeline that translates binary `.pcap` and
//! `.pcapng` packet captures back into canonical, lowercase `.frasm` network traffic specifications:
//!
//! 1. **Container Normalization (`container`)**: Streams legacy PCAP (microsecond and nanosecond
//!    magic numbers) and PCAPNG (`SectionHeaderBlock`, `InterfaceDescriptionBlock`,
//!    `EnhancedPacketBlock`, `SimplePacketBlock`, `PacketBlock`), scales `IfTsResol` timestamps to
//!    nanoseconds, normalizes link-layer types (`ETHERNET`, `RAW`, `IPV4`, `IPV6`, `LINUX_SLL`,
//!    `LINUX_SLL2`, `NULL`, `LOOP`) into Ethernet II frames, and strips 60/64-byte Ethernet zero
//!    padding and 4-byte FCS trailers.
//! 2. **Layer 2–7 Modular Protocol Dissection (`l2`, `l3`, `l4`, `l7`)**: Decodes all 81 native
//!    protocols across Layer 2 through Layer 7 into strongly-typed modifier structures and
//!    canonical `.frasm` token strings.
//! 3. **Deterministic Topology Discovery (`topology`)**: Infers sequential `host1`, `host2`, ...
//!    declarations, tracks dominant unicast MAC addresses, pairs broadcast/multicast traffic, and
//!    locks directional arrows (`->` vs `<-`) per endpoint pair.
//! 4. **Per-Packet Self-Check Oracle (`oracle`)**: Compiles each candidate `.frasm` statement in
//!    isolation via FrameAssembly's own forward compiler and preserves clean, readable high-level
//!    `.frasm` statements (or steps down to raw L4/L2 if a candidate statement fails to compile).
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

/// Summary statistics and `.frasm` source code returned by the decompiler.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReverseOutput {
    /// Generated canonical lowercase `.frasm` code.
    pub fasm: String,
    /// Total number of packets reversed.
    pub packet_count: usize,
    /// Total number of `hostN` definitions emitted.
    pub host_count: usize,
    /// Non-fatal container warnings (e.g., skipped non-Ethernet interfaces or salvaged truncated EOF).
    pub warnings: Vec<String>,
}

/// Normalized Ethernet II packet and nanosecond timestamp extracted for `frameassembly show`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShowCapturePacket {
    /// Capture timestamp in nanoseconds since the Unix epoch.
    pub timestamp_ns: u64,
    /// Normalized Ethernet II frame bytes with trailing zero-padding and 4-byte FCS stripped.
    pub raw_eth_frame: Vec<u8>,
}

/// Result returned by a protocol dissector.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtocolDissection {
    /// Identified FrameAssembly [`Protocol`].
    pub protocol: Protocol,
    /// Canonical lowercase `.frasm` protocol keyword and protocol-specific modifiers
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

/// Decompiles a binary `.pcap` or `.pcapng` capture stream into canonical `.frasm` code.
///
/// # Errors
/// Returns [`CompilerError::BackendError`] if the stream is not a valid `.pcap` or `.pcapng`
/// capture or if an I/O or container framing error occurs.
pub fn reverse_pcap_reader<R: std::io::Read>(reader: R) -> Result<ReverseOutput, CompilerError> {
    let read_res = container::read_capture_frames_with_warnings(reader)
        .map_err(CompilerError::BackendError)?;
    let packets: Vec<DissectedPacket> =
        read_res.frames.into_iter().map(l2::dissect_packet).collect();
    let topo = topology::build_topology(&packets);
    let mut out = shadow_emit::emit_fasm_program(&packets, &topo);
    out.warnings = read_res.warnings;
    Ok(out)
}

/// Reads an in-memory `.pcap` or `.pcapng` byte slice into normalized Ethernet II frames and
/// non-fatal container warnings for `frameassembly show`.
///
/// # Errors
/// Returns an error string if `bytes` is not a valid `.pcap` or `.pcapng` capture.
pub fn read_capture_bytes_for_show(
    bytes: &[u8],
) -> Result<(Vec<ShowCapturePacket>, Vec<String>), String> {
    let res = container::read_capture_frames_with_warnings(std::io::Cursor::new(bytes))?;
    let packets = res
        .frames
        .into_iter()
        .map(|f| ShowCapturePacket {
            timestamp_ns: f.timestamp_ns,
            raw_eth_frame: f.eth_bytes,
        })
        .collect();
    Ok((packets, res.warnings))
}

/// Reads a `.pcap` or `.pcapng` file on disk into normalized Ethernet II frames and non-fatal
/// container warnings for `frameassembly show`.
///
/// # Errors
/// Returns an error string if `path` cannot be opened or is not a valid `.pcap` or `.pcapng` capture.
pub fn read_capture_for_show(
    path: &str,
) -> Result<(Vec<ShowCapturePacket>, Vec<String>), String> {
    let file = std::fs::File::open(path)
        .map_err(|e| alloc::format!("Failed to open capture file '{path}': {e}"))?;
    let res = container::read_capture_frames_with_warnings(std::io::BufReader::new(file))?;
    let packets = res
        .frames
        .into_iter()
        .map(|f| ShowCapturePacket {
            timestamp_ns: f.timestamp_ns,
            raw_eth_frame: f.eth_bytes,
        })
        .collect();
    Ok((packets, res.warnings))
}

/// Decompiles an in-memory `.pcap` or `.pcapng` byte slice into canonical `.frasm` code.
///
/// # Errors
/// Returns [`CompilerError::BackendError`] if `bytes` is not a valid `.pcap` or `.pcapng` capture.
pub fn reverse_pcap_bytes(bytes: &[u8]) -> Result<ReverseOutput, CompilerError> {
    reverse_pcap_reader(std::io::Cursor::new(bytes))
}

/// Decompiles a `.pcap` or `.pcapng` file on disk into canonical `.frasm` code.
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

/// Escapes a UTF-8 string for inclusion inside a `.frasm` double-quoted string literal.
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

/// Returns `true` if `"<s>"` tokenizes cleanly as a single `Token::StringLit` whose raw body
/// (parsed by `parse_raw_string_lit`) equals `s` verbatim without escape Expansion.
pub(crate) fn is_valid_raw_string_body(s: &str) -> bool {
    let mut it = s.chars();
    while let Some(c) = it.next() {
        if (c as u32) < 0x20 || (c as u32) == 0x7f || c == '"' {
            return false;
        }
        if c == '\\' {
            match it.next() {
                Some(n) if (n as u32) >= 0x20 && (n as u32) != 0x7f => {}
                _ => return false,
            }
        }
    }
    true
}

/// Appends ` <kw> "<val>"` onto `out` when `val != default`.
#[allow(dead_code)]
pub(crate) fn push_str_if(out: &mut String, kw: &str, val: &str, default: &str) {
    if val != default {
        if is_valid_raw_string_body(val) {
            let _ = write!(out, " {kw} \"{val}\"");
        } else {
            let _ = write!(out, " {kw} \"{}\"", escape_fasm_string(val));
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

    /// MAC-only host pair used by the pure Layer 2 roundtrip fixtures.
    const MAC_HOSTS: &str = "host a { mac 02:00:00:00:00:01 }\nhost b { mac 02:00:00:00:00:02 }\n";

    /// IPv4 host pair (with explicit MACs) used by the IPv4 L2/L3/L4 roundtrip fixtures.
    const V4_HOSTS: &str = "host a { ip 10.0.0.1 mac 02:00:00:00:00:01 }\n\
                            host b { ip 10.0.0.2 mac 02:00:00:00:00:02 }\n";

    /// IPv6 host pair (with explicit MACs) used by the IPv6-only `ndp` and `mld` fixtures.
    const V6_HOSTS: &str = "host a { ip 2001:db8::1 mac 02:00:00:00:00:01 }\n\
                            host b { ip 2001:db8::2 mac 02:00:00:00:00:02 }\n";

    /// Inline L2/L3/L4 roundtrip fixtures as `(protocol, host_block, flow_body)` triples.
    ///
    /// Every one of the 31 L2 (8), L3 (20), and L4 (3) protocols appears exactly once. Each
    /// `flow_body` holds minimal v3.0.0 strict-lowercase statements for a `flow f(x, y)` whose
    /// second statement carries a `wait` so relative timestamps are exercised by the oracle.
    const L2_L3_L4_FIXTURES: [(&str, &str, &str); 31] = [
        ("arp", V4_HOSTS, "x -> y arp\n    y -> x arp wait 5ms"),
        ("vlan", MAC_HOSTS, "x -> y vlan 100\n    y -> x vlan 100 wait 5ms"),
        ("qinq", MAC_HOSTS, "x -> y qinq 100 innervlan 200 payload \"QinQ-Body\"\n    y -> x qinq wait 5ms"),
        ("lldp", MAC_HOSTS, "x -> y lldp\n    y -> x lldp wait 30s"),
        ("stp", MAC_HOSTS, "x -> y stp\n    x -> y stp wait 2s"),
        ("lacp", MAC_HOSTS, "x -> y lacp\n    y -> x lacp wait 1s"),
        ("eapol", MAC_HOSTS, "x -> y eapol\n    y -> x eapol wait 10ms"),
        ("mpls", MAC_HOSTS, "x -> y mpls\n    y -> x mpls wait 1ms"),
        ("icmp", V4_HOSTS, "x -> y icmp\n    y -> x icmp wait 2ms"),
        ("ndp", V6_HOSTS, "x -> y ndp\n    y -> x ndp wait 2ms"),
        ("igmp", V4_HOSTS, "x -> y igmp\n    x -> y igmp wait 1s"),
        ("mld", V6_HOSTS, "x -> y mld\n    x -> y mld wait 1s"),
        ("gre", V4_HOSTS, "x -> y gre\n    y -> x gre wait 1ms"),
        ("vxlan", V4_HOSTS, "x -> y vxlan\n    y -> x vxlan wait 1ms"),
        ("geneve", V4_HOSTS, "x -> y geneve\n    y -> x geneve wait 1ms"),
        ("ipsec", V4_HOSTS, "x -> y ipsec\n    y -> x ipsec wait 1ms"),
        ("esp", V4_HOSTS, "x -> y esp\n    y -> x esp wait 1ms"),
        ("ah", V4_HOSTS, "x -> y ah\n    y -> x ah wait 1ms"),
        ("ikev2", V4_HOSTS, "x -> y ikev2\n    y -> x ikev2 wait 20ms"),
        ("wireguard", V4_HOSTS, "x -> y wireguard\n    y -> x wireguard wait 20ms"),
        ("ospf", V4_HOSTS, "x -> y ospf\n    y -> x ospf wait 10s"),
        ("bgp", V4_HOSTS, "x -> y bgp\n    y -> x bgp wait 50ms"),
        ("rip", V4_HOSTS, "x -> y rip\n    y -> x rip wait 30s"),
        ("vrrp", V4_HOSTS, "x -> y vrrp\n    y -> x vrrp wait 1s"),
        ("hsrp", V4_HOSTS, "x -> y hsrp\n    y -> x hsrp wait 3s"),
        ("pim", V4_HOSTS, "x -> y pim\n    y -> x pim wait 30s"),
        ("bfd", V4_HOSTS, "x -> y bfd\n    y -> x bfd wait 300ms"),
        ("openflow", V4_HOSTS, "x -> y openflow\n    y -> x openflow wait 5ms"),
        ("tcp", V4_HOSTS, "x -> y tcp dstport 443 syn mss 1460 sackperm\n    y -> x tcp syn ack wait 1ms\n    x -> y tcp ack wait 1ms"),
        ("udp", V4_HOSTS, "x -> y udp dstport 5000 payload \"ping\"\n    y -> x udp payload \"pong\" wait 2ms"),
        ("sctp", V4_HOSTS, "x -> y sctp srcport 2905 dstport 2905 vtag 0x12345678\n    y -> x sctp shutdownack wait 3ms"),
    ];

    /// Runs one inline fixture through the roundtrip oracle (parse -> compile -> PCAPNG ->
    /// `reverse_pcap_bytes` -> re-parse -> re-compile), returning a protocol-tagged error message
    /// on fallback comments, frame-count drift, or relative-timestamp drift.
    fn roundtrip_fixture(proto: &str, hosts: &str, body: &str) -> Result<(), String> {
        let src = alloc::format!("{hosts}flow f(x, y) {{\n    {body}\n}}\ncompile {{ f(a, b) }}\n");
        let prog = parse_program(&src).map_err(|e| alloc::format!("{proto}: parse original failed: {e}"))?;
        let orig_frames = compile_program(&prog)
            .map_err(|e| alloc::format!("{proto}: compile original failed: {e}"))?;
        let pcap_bytes = frames_to_pcapng(&orig_frames);

        let out = reverse_pcap_bytes(&pcap_bytes)
            .map_err(|e| alloc::format!("{proto}: reverse failed: {e}"))?;
        if out.fasm.contains("// [") {
            return Err(alloc::format!("{proto}: unexpected fallback comment:\n{}", out.fasm));
        }
        let reprog = parse_program(&out.fasm).map_err(|e| {
            alloc::format!("{proto}: re-parse failed: {e}\n--- FRASM ---\n{}", out.fasm)
        })?;
        let reframes = compile_program(&reprog)
            .map_err(|e| alloc::format!("{proto}: re-compile failed: {e}"))?;
        if orig_frames.len() != reframes.len() {
            return Err(alloc::format!(
                "{proto}: frame count mismatch ({} vs {})",
                orig_frames.len(),
                reframes.len()
            ));
        }
        let orig_base = orig_frames.first().map_or(0, |(_, ts)| *ts);
        let re_base = reframes.first().map_or(0, |(_, ts)| *ts);
        for (idx, ((_, orig_ts), (_, re_ts))) in orig_frames.iter().zip(reframes.iter()).enumerate() {
            let (o, r) = (orig_ts.saturating_sub(orig_base), re_ts.saturating_sub(re_base));
            if o != r {
                return Err(alloc::format!(
                    "{proto}: relative timestamp mismatch on frame #{} ({o} vs {r})",
                    idx + 1
                ));
            }
        }
        Ok(())
    }

    /// Verifies round-trip PCAPNG decompilation and recompilation across inline fixtures covering
    /// all 31 L2/L3/L4 protocols, reporting every failing protocol by name.
    #[test]
    fn test_l2_l3_l4_inline_roundtrip_oracle() {
        let failures: Vec<String> = L2_L3_L4_FIXTURES
            .iter()
            .filter_map(|(proto, hosts, body)| roundtrip_fixture(proto, hosts, body).err())
            .collect();
        assert!(
            failures.is_empty(),
            "L2/L3/L4 roundtrip oracle failed for {} protocol(s):\n{}",
            failures.len(),
            failures.join("\n")
        );
    }

    /// Verifies v3.0.0 strict-lowercase PCAPNG decompilation (`host1`/`host2`, zero `loop`,
    /// lowercase enum strings, SCTP `shutdownack`, and exact wire-literal case preservation).
    #[test]
    fn test_v2_strict_lowercase_reverse_roundtrip() {
        let src = r#"
host client { ip 10.10.0.1 mac 00:00:00:00:00:01 }
host server { ip 10.10.0.2 mac 00:00:00:00:00:02 }

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

    /// Verifies that all 50 Layer 7 protocols reverse-decompile to their native v3.0.0 lowercase
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
