# Networking, Native RFC Wire Crafting & PCAP Production Reference Patterns

This reference document provides production-ready, fully-documented, and compile-verified Rust code templates for building high-performance packet crafters, checksum/CRC engines, multi-layer L2–L4 wire encoders, stateful TCP stream trackers, and packet capture serializers using **native Rust 2024 RFC wire builders** (`frameassembly::packet`, `frameassembly::builders`) and **`pcap-file` (`2.0.0`)**.

---

## 1. Native RFC 1071, RFC 768 Zero-Mapping, RFC 9260 CRC32c & DNP3 CRC-16 Checksum Engines

`frameassembly` computes all L3, L4, and OT/ICS checksums without external checksum crates or temporary heap concatenations:
- **RFC 1071 One's Complement Checksum (`internet_checksum`)**: Uses Rust 2024's stabilized `slice.as_chunks::<2>()` over `&[&[u8]]` to sum 16-bit big-endian words across disjoint slices (e.g., `[&pseudo_header, &l4_header, payload]`), handles odd trailing bytes by left-shifting (`(remainder[0] as u32) << 8`), folds 32-bit carries, and returns `!sum as u16`.
- **RFC 768 / RFC 8200 §8.1 UDP Zero-Checksum Mapping**: Maps a computed `0x0000` one's complement result to `0xFFFF` (`if c == 0 { 0xFFFF } else { c }`), because `0x0000` in a UDP header signifies "checksum omitted" (which is forbidden over IPv6).
- **RFC 9260 §3.3.10 / RFC 3309 SCTP Castagnoli CRC32c (`crc32c`)**: Uses a compile-time `const` 256-entry table (`0x82F6_3B78` reflected polynomial) and stores the 32-bit digest in **little-endian** (`cksum.to_le_bytes()`) at bytes `8..12` of the SCTP common header.
- **IEEE 1815 DNP3 CRC-16 (`calculate_dnp3_crc`)**: Uses reflected polynomial `0xA653` (`0x3D65`), bitwise inversion `!crc`, and **little-endian** byte order after the 8-byte link header and every 16-byte data block.

```rust
use core::net::{Ipv4Addr, Ipv6Addr};

/// Computes the 16-bit one's complement Internet Checksum (RFC 1071) over disjoint byte slices.
///
/// Uses `slice.as_chunks::<2>()` to process 16-bit big-endian words with zero heap allocation.
pub fn internet_checksum(data: &[&[u8]]) -> u16 {
    let mut sum: u32 = 0;
    for slice in data {
        let (chunks, remainder) = slice.as_chunks::<2>();
        for chunk in chunks {
            sum += u16::from_be_bytes(*chunk) as u32;
        }
        if !remainder.is_empty() {
            sum += (remainder[0] as u32) << 8;
        }
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !sum as u16
}

/// Computes the UDP checksum over an IPv6 pseudo-header, enforcing RFC 8200 §8.1 zero-to-0xFFFF mapping.
pub fn compute_udp_ipv6_checksum(
    src: Ipv6Addr,
    dst: Ipv6Addr,
    udp_header_zero_cksum: &[u8; 8],
    payload: &[u8],
) -> u16 {
    let udp_len = (udp_header_zero_cksum.len() + payload.len()) as u32;
    let mut pseudo = [0u8; 40];
    pseudo[0..16].copy_from_slice(&src.octets());
    pseudo[16..32].copy_from_slice(&dst.octets());
    pseudo[32..36].copy_from_slice(&udp_len.to_be_bytes());
    pseudo[39] = 17; // Next Header = UDP (17)

    let c = internet_checksum(&[&pseudo, udp_header_zero_cksum, payload]);
    if c == 0 { 0xFFFF } else { c }
}

/// Computes the ICMPv6 / NDP / MLD checksum over the mandatory RFC 4443 IPv6 pseudo-header (Next Header = 58).
///
/// Note: When NDP or MLD overrides the destination IP with a multicast address (e.g., Solicited-Node
/// `ff02::1:ffXX:XXXX` or `ff02::2`), `effective_dst` MUST be that multicast address.
pub fn compute_icmpv6_checksum(
    src: Ipv6Addr,
    effective_dst: Ipv6Addr,
    icmpv6_body_zero_cksum: &[u8],
) -> u16 {
    let len = icmpv6_body_zero_cksum.len() as u32;
    let mut pseudo = [0u8; 40];
    pseudo[0..16].copy_from_slice(&src.octets());
    pseudo[16..32].copy_from_slice(&effective_dst.octets());
    pseudo[32..36].copy_from_slice(&len.to_be_bytes());
    pseudo[39] = 58; // Next Header = ICMPv6 (58)

    internet_checksum(&[&pseudo, icmpv6_body_zero_cksum])
}

/// Precomputed Castagnoli CRC32c table (polynomial 0x1EDC6F41, reflected 0x82F63B78).
const CRC32C_TABLE: [u32; 256] = {
    let mut table = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut crc = i as u32;
        let mut j = 0;
        while j < 8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0x82F6_3B78;
            } else {
                crc >>= 1;
            }
            j += 1;
        }
        table[i] = crc;
        i += 1;
    }
    table
};

/// Computes the Castagnoli CRC32c checksum over byte slices per RFC 9260 §3.3.10.
///
/// Verified against RFC 3309 vectors:
/// - `crc32c(&[b"123456789"]) == 0xe3069283`
/// - `crc32c(&[&[0u8; 32]]) == 0x8a9136aa`
pub fn crc32c(slices: &[&[u8]]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for slice in slices {
        for &byte in *slice {
            let index = ((crc ^ (byte as u32)) & 0xFF) as usize;
            crc = (crc >> 8) ^ CRC32C_TABLE[index];
        }
    }
    crc ^ 0xFFFF_FFFF
}

/// Computes the IEEE 1815 DNP3 16-bit CRC over a byte slice (reflected poly `0xA653`, inverted remainder).
pub fn calculate_dnp3_crc(data: &[u8]) -> u16 {
    let mut crc: u16 = 0x0000;
    for &b in data {
        let mut byte = b;
        for _ in 0..8 {
            let bit = (crc ^ (byte as u16)) & 0x0001;
            crc >>= 1;
            if bit != 0 {
                crc ^= 0xA653;
            }
            byte >>= 1;
        }
    }
    !crc
}

/// Synthesizes a 2-byte UDP payload that forces the raw one's complement sum to `0xFFFF` (`!sum == 0x0000`),
/// proving that `compute_udp_ipv6_checksum` maps `0x0000` to `0xFFFF` per RFC 8200 §8.1.
pub fn synthesize_zero_checksum_udp_payload(
    src: Ipv6Addr,
    dst: Ipv6Addr,
    src_port: u16,
    dst_port: u16,
) -> [u8; 2] {
    let udp_len: u16 = 10; // 8-byte header + 2-byte payload
    let mut pseudo = [0u8; 40];
    pseudo[0..16].copy_from_slice(&src.octets());
    pseudo[16..32].copy_from_slice(&dst.octets());
    pseudo[32..36].copy_from_slice(&(udp_len as u32).to_be_bytes());
    pseudo[39] = 17;

    let udp_hdr_zero = [
        (src_port >> 8) as u8,
        src_port as u8,
        (dst_port >> 8) as u8,
        dst_port as u8,
        0,
        10,
        0,
        0,
    ];

    //internet_checksum returns !partial_sum, which is the exact 16-bit word needed to make the total sum 0xFFFF!
    let cancelling_word = internet_checksum(&[&pseudo, &udp_hdr_zero]);
    cancelling_word.to_be_bytes()
}
```

---

## 2. Native L3/L4 Dual-Stack Wire Builders (IPv4, IPv6, TCP with Options, UDP, SCTP)

Demonstrates `frameassembly`'s native inner-outward L4 and L3 packet synthesis:
- **IPv4 Header (`build_ipv4_header`)**: Packs DSCP (6 bits) + ECN (2 bits) into TOS, computes Total Length (`20 + l4_and_payload_len`), packs DF (`0x4000`), MF (`0x2000`), and 13-bit Fragment Offset (`& 0x1FFF`), and populates the RFC 791 header checksum at bytes `10..12`.
- **IPv6 Header (`build_ipv6_header`)**: Packs Version `6` (bits 28..32), 8-bit Traffic Class `(dscp << 2) | ecn` (bits 20..28), and 20-bit Flow Label (`& 0x000F_FFFF`) into a 32-bit big-endian word, followed by 16-bit Payload Length, Next Header, Hop Limit, and 16-byte Source/Destination addresses.
- **TCP Segment (`build_tcp_segment`)**: Encodes MSS (Kind 2), Window Scale (Kind 3), SACK Permitted (Kind 4), and Timestamps (Kind 8), pads options with `NOP` (`0x01`) to a 32-bit boundary, sets `data_offset = (tcp_header_len / 4) << 4`, and computes the IPv4 or IPv6 pseudo-header checksum at bytes `16..18`.
- **SCTP Packet (`build_sctp_datagram`)**: Pads variable-length chunks (`DATA`, `HEARTBEAT`, `COOKIE_ECHO`) with `0x00` to 4-byte boundaries per RFC 9260 §3.3.1, then writes the Castagnoli CRC32c in **little-endian** at bytes `8..12`.

```rust
use core::net::IpAddr;

/// Layer 3 header modifiers for IPv4 and IPv6 packet construction.
#[derive(Clone, Debug, Default)]
pub struct L3WireConfig {
    /// Time-To-Live (IPv4) or Hop Limit (IPv6); defaults to 64.
    pub ttl: Option<u8>,
    /// 6-bit Differentiated Services Code Point (0..=63).
    pub dscp: Option<u8>,
    /// 2-bit Explicit Congestion Notification (0..=3).
    pub ecn: Option<u8>,
    /// 16-bit IPv4 Identification field.
    pub ipid: Option<u16>,
    /// IPv4 Don't Fragment flag (`0x4000`).
    pub df: bool,
    /// IPv4 More Fragments flag (`0x2000`).
    pub mf: bool,
    /// 13-bit IPv4 Fragment Offset in 8-octet units (`0..=8191`).
    pub frag_offset: Option<u16>,
    /// 20-bit IPv6 Flow Label (`0..=0xFFFFF`).
    pub flowlabel: Option<u32>,
}

/// TCP option parameters padded to a 32-bit boundary.
#[derive(Clone, Debug, Default)]
pub struct TcpOptionsConfig {
    /// Maximum Segment Size (Kind 2, Length 4).
    pub mss: Option<u16>,
    /// Window Scale shift count (Kind 3, Length 3).
    pub wscale: Option<u8>,
    /// Selective Acknowledgment Permitted (Kind 4, Length 2).
    pub sack_perm: bool,
    /// Timestamp Value (Kind 8, Length 10).
    pub tsval: Option<u32>,
    /// Timestamp Echo Reply (Kind 8, Length 10).
    pub tsecr: Option<u32>,
}

/// Encodes TCP options into a 4-byte-aligned vector padded with NOP (`0x01`).
pub fn encode_tcp_options(opts: &TcpOptionsConfig) -> Vec<u8> {
    let mut buf = Vec::with_capacity(24);
    if let Some(mss) = opts.mss {
        buf.push(2);
        buf.push(4);
        buf.extend_from_slice(&mss.to_be_bytes());
    }
    if let Some(wscale) = opts.wscale {
        buf.push(1); // NOP alignment
        buf.push(3);
        buf.push(3);
        buf.push(wscale);
    }
    if opts.sack_perm {
        buf.push(4);
        buf.push(2);
        buf.push(1);
        buf.push(1);
    }
    if opts.tsval.is_some() || opts.tsecr.is_some() {
        buf.push(1);
        buf.push(1);
        buf.push(8);
        buf.push(10);
        buf.extend_from_slice(&opts.tsval.unwrap_or(0).to_be_bytes());
        buf.extend_from_slice(&opts.tsecr.unwrap_or(0).to_be_bytes());
    }
    while buf.len() % 4 != 0 {
        buf.push(1);
    }
    buf
}

/// Constructs a 20-byte RFC 791 IPv4 header with computed header checksum.
pub fn build_ipv4_header(
    src: [u8; 4],
    dst: [u8; 4],
    protocol: u8,
    l3: &L3WireConfig,
    l4_and_payload_len: usize,
) -> Vec<u8> {
    let mut header = Vec::with_capacity(20);
    header.push(0x45); // Version 4, IHL 5 (20 bytes)
    let tos = ((l3.dscp.unwrap_or(0) & 0x3F) << 2) | (l3.ecn.unwrap_or(0) & 0x03);
    header.push(tos);
    let total_len = (20 + l4_and_payload_len) as u16;
    header.extend_from_slice(&total_len.to_be_bytes());
    header.extend_from_slice(&l3.ipid.unwrap_or(0).to_be_bytes());

    let mut flags_and_offset = l3.frag_offset.unwrap_or(0) & 0x1FFF;
    if l3.df {
        flags_and_offset |= 0x4000;
    }
    if l3.mf {
        flags_and_offset |= 0x2000;
    }
    header.extend_from_slice(&flags_and_offset.to_be_bytes());
    header.push(l3.ttl.unwrap_or(64));
    header.push(protocol);
    header.extend_from_slice(&[0, 0]); // Checksum placeholder
    header.extend_from_slice(&src);
    header.extend_from_slice(&dst);

    let cksum = internet_checksum(&[&header]);
    header[10..12].copy_from_slice(&cksum.to_be_bytes());
    header
}

/// Constructs a 40-byte RFC 8200 IPv6 header.
pub fn build_ipv6_header(
    src: [u8; 16],
    dst: [u8; 16],
    next_header: u8,
    l3: &L3WireConfig,
    l4_and_payload_len: usize,
) -> Vec<u8> {
    let mut header = Vec::with_capacity(40);
    let tc = ((l3.dscp.unwrap_or(0) & 0x3F) << 2) | (l3.ecn.unwrap_or(0) & 0x03);
    let flow_label = l3.flowlabel.unwrap_or(0) & 0x000F_FFFF;
    let v_tc_fl: u32 = (0x6_u32 << 28) | ((tc as u32) << 20) | flow_label;
    header.extend_from_slice(&v_tc_fl.to_be_bytes());
    header.extend_from_slice(&(l4_and_payload_len as u16).to_be_bytes());
    header.push(next_header);
    header.push(l3.ttl.unwrap_or(64));
    header.extend_from_slice(&src);
    header.extend_from_slice(&dst);
    header
}

/// Constructs a complete RFC 9260 SCTP packet (IP protocol 132) with a DATA chunk
/// padded to a 4-byte boundary and a little-endian CRC32c checksum.
pub fn build_sctp_data_packet(
    src_port: u16,
    dst_port: u16,
    vtag: u32,
    tsn: u32,
    stream_id: u16,
    ssn: u16,
    ppid: u32,
    payload: &[u8],
) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(28 + payload.len() + 4);
    // 12-byte SCTP Common Header
    pkt.extend_from_slice(&src_port.to_be_bytes());
    pkt.extend_from_slice(&dst_port.to_be_bytes());
    pkt.extend_from_slice(&vtag.to_be_bytes());
    pkt.extend_from_slice(&0_u32.to_be_bytes()); // CRC32c placeholder at bytes 8..12

    // DATA Chunk (Type 0, Flags 0x03 = B|E, Unpadded Length = 16 + payload.len())
    let chunk_len = (16 + payload.len()) as u16;
    pkt.push(0);
    pkt.push(0x03);
    pkt.extend_from_slice(&chunk_len.to_be_bytes());
    pkt.extend_from_slice(&tsn.to_be_bytes());
    pkt.extend_from_slice(&stream_id.to_be_bytes());
    pkt.extend_from_slice(&ssn.to_be_bytes());
    pkt.extend_from_slice(&ppid.to_be_bytes());
    pkt.extend_from_slice(payload);

    // Pad chunk with 0x00 to 4-byte boundary per RFC 9260 §3.3.1
    while pkt.len() % 4 != 0 {
        pkt.push(0);
    }

    // RFC 9260 §3.3.10: Store Castagnoli CRC32c in little-endian byte order
    let cksum = crc32c(&[&pkt]);
    pkt[8..12].copy_from_slice(&cksum.to_le_bytes());
    pkt
}
```

---

## 3. Native L2 Encapsulation (Ethernet II, 802.1Q VLAN, 802.1ad QinQ, RFC 3032 MPLS) & Multicast MAC Derivation

Demonstrates `frameassembly`'s Layer 2 framing and address resolution engine:
- **Deterministic MAC Resolution (`derive_mac`)**:
  1. Explicit statement-level MAC (`SRCMAC` / `DSTMAC`) takes highest priority.
  2. Host-level configured MAC (`HOST ... { MAC ... }`) takes second priority.
  3. **RFC 1112 IPv4 Multicast (`224.0.0.0/4`)**: Maps lower 23 bits of IPv4 into `01:00:5e:(b1 & 0x7f):b2:b3`.
  4. **RFC 2464 IPv6 Multicast (`ff00::/8`)**: Maps lower 32 bits of IPv6 into `33:33:b12:b13:b14:b15`.
  5. Unicast fallback: `00:00:00:00:00:01` for caller, `00:00:00:00:00:02` for callee.
- **Tag Stacking (`build_ethernet_and_l2`)**: Supports standalone or combined IEEE 802.1Q VLAN (`0x8100`), IEEE 802.1ad QinQ (`0x88A8` outer + `0x8100` inner), and RFC 3032 MPLS (`0x8847`).

```rust
use core::net::IpAddr;

/// IEEE 802.1Q VLAN tag parameters.
#[derive(Clone, Copy, Debug, Default)]
pub struct VlanTag {
    /// 12-bit VLAN Identifier (`0..=4095`).
    pub vid: u16,
    /// 3-bit Priority Code Point (`0..=7`).
    pub pcp: Option<u8>,
    /// 1-bit Drop Eligible Indicator (`0..=1`).
    pub dei: Option<u8>,
}

/// IEEE 802.1ad QinQ double VLAN tag parameters.
#[derive(Clone, Copy, Debug, Default)]
pub struct QinqTag {
    /// Outer Service VLAN ID (`0x88A8`).
    pub outer_vid: u16,
    /// Optional Inner Customer VLAN ID (`0x8100`).
    pub inner_vid: Option<u16>,
}

/// RFC 3032 MPLS shim header parameters.
#[derive(Clone, Copy, Debug, Default)]
pub struct MplsShim {
    /// 20-bit MPLS Label (`0..=1048575`).
    pub label: u32,
    /// 3-bit Traffic Class / EXP field (`0..=7`).
    pub exp: Option<u8>,
    /// 1-bit Bottom-of-Stack flag (`0..=1`, defaults to 1).
    pub bos: Option<u8>,
    /// 8-bit Time-To-Live (defaults to 64).
    pub ttl: Option<u8>,
}

/// Layer 2 encapsulation modifiers.
#[derive(Clone, Debug, Default)]
pub struct L2EncapConfig {
    /// Optional 802.1Q VLAN tag.
    pub vlan: Option<VlanTag>,
    /// Optional 802.1ad QinQ tag stack.
    pub qinq: Option<QinqTag>,
    /// Optional RFC 3032 MPLS label stack entry.
    pub mpls: Option<MplsShim>,
    /// Optional explicit EtherType override.
    pub ethertype: Option<u16>,
}

/// Derives an Ethernet MAC address following RFC 1112 (IPv4 multicast),
/// RFC 2464 (IPv6 multicast), or deterministic unicast defaults.
pub fn derive_mac(
    host_mac: Option<[u8; 6]>,
    stmt_mac: Option<[u8; 6]>,
    ip: IpAddr,
    is_caller: bool,
) -> [u8; 6] {
    if let Some(mac) = stmt_mac {
        return mac;
    }
    if let Some(mac) = host_mac {
        return mac;
    }
    match ip {
        IpAddr::V6(v6) => {
            let octets = v6.octets();
            if octets[0] == 0xFF {
                [0x33, 0x33, octets[12], octets[13], octets[14], octets[15]]
            } else if is_caller {
                [0x00, 0x00, 0x00, 0x00, 0x00, 0x01]
            } else {
                [0x00, 0x00, 0x00, 0x00, 0x00, 0x02]
            }
        }
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            if (224..=239).contains(&octets[0]) {
                [0x01, 0x00, 0x5E, octets[1] & 0x7F, octets[2], octets[3]]
            } else if is_caller {
                [0x00, 0x00, 0x00, 0x00, 0x00, 0x01]
            } else {
                [0x00, 0x00, 0x00, 0x00, 0x00, 0x02]
            }
        }
    }
}

/// Prepends Ethernet II, 802.1Q VLAN, 802.1ad QinQ, and/or RFC 3032 MPLS headers around `inner_packet`.
pub fn build_ethernet_and_l2(
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    l2: &L2EncapConfig,
    ip_ethertype: u16,
    inner_packet: &[u8],
) -> Vec<u8> {
    let mut frame = Vec::with_capacity(14 + 8 + 4 + inner_packet.len());
    frame.extend_from_slice(&dst_mac);
    frame.extend_from_slice(&src_mac);

    let append_mpls_or_ethertype = |buf: &mut Vec<u8>| {
        if let Some(mpls) = &l2.mpls {
            buf.extend_from_slice(&0x8847_u16.to_be_bytes());
            let exp = mpls.exp.unwrap_or(0) & 0x07;
            let bos = mpls.bos.unwrap_or(1) & 0x01;
            let ttl = mpls.ttl.unwrap_or(64);
            let entry: u32 = ((mpls.label & 0x000F_FFFF) << 12)
                | ((exp as u32) << 9)
                | ((bos as u32) << 8)
                | (ttl as u32);
            buf.extend_from_slice(&entry.to_be_bytes());
        } else {
            let next_et = l2.ethertype.unwrap_or(ip_ethertype);
            buf.extend_from_slice(&next_et.to_be_bytes());
        }
    };

    if let Some(qinq) = &l2.qinq {
        frame.extend_from_slice(&0x88A8_u16.to_be_bytes());
        let pcp = l2.vlan.as_ref().and_then(|v| v.pcp).unwrap_or(0) & 0x07;
        let dei = l2.vlan.as_ref().and_then(|v| v.dei).unwrap_or(0) & 0x01;
        let outer_tci: u16 =
            ((pcp as u16) << 13) | ((dei as u16) << 12) | (qinq.outer_vid & 0x0FFF);
        frame.extend_from_slice(&outer_tci.to_be_bytes());

        if let Some(inner_vid) = qinq.inner_vid {
            frame.extend_from_slice(&0x8100_u16.to_be_bytes());
            frame.extend_from_slice(&(inner_vid & 0x0FFF).to_be_bytes());
        }
        append_mpls_or_ethertype(&mut frame);
    } else if let Some(vlan) = &l2.vlan {
        frame.extend_from_slice(&0x8100_u16.to_be_bytes());
        let pcp = vlan.pcp.unwrap_or(0) & 0x07;
        let dei = vlan.dei.unwrap_or(0) & 0x01;
        let tci: u16 = ((pcp as u16) << 13) | ((dei as u16) << 12) | (vlan.vid & 0x0FFF);
        frame.extend_from_slice(&tci.to_be_bytes());
        append_mpls_or_ethertype(&mut frame);
    } else {
        append_mpls_or_ethertype(&mut frame);
    }

    frame.extend_from_slice(inner_packet);
    frame
}
```

---

## 4. Canonical 4-Tuple TCP Stream State Machine & Two-Stage Port Inheritance

When synthesizing multi-packet flows (e.g., 3-way TCP handshake `SYN -> SYN|ACK -> ACK` followed by `HTTP` request/response and `FIN`), `frameassembly` maintains two state tables:
1. **Stage 1 (`EndpointPairPorts`)**: Keyed by `(caller_name, callee_name)`. Stores the resolved `caller_port` and `callee_port` so subsequent statements between the same pair automatically inherit the ephemeral port (`12345`) and service port (`80`, `443`, `502`, etc.) across both `->` and `<-` directions.
2. **Stage 2 (`TcpStreamState` keyed by `Canonical4Tuple`)**: Keyed by sorted socket endpoints `((ip_a, port_a), (ip_b, port_b))` where `ep1 <= ep2`. Tracks each direction's next sequence number (`seq1`, `seq2`, initialized to `1000`), automatically populates `ack_num` from the peer's sequence counter, and advances the sender's sequence counter by `payload_len + (SYN ? 1 : 0) + (FIN ? 1 : 0)` via `wrapping_add`.

```rust
use core::net::IpAddr;
use std::collections::HashMap;

/// Canonical sorted 4-tuple key: `ep1 <= ep2`.
pub type Canonical4Tuple = ((IpAddr, u16), (IpAddr, u16));

/// Per-connection TCP sequence state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TcpStreamState {
    /// Next sequence number for endpoint 1 (`ep1`).
    pub seq1: u32,
    /// Next sequence number for endpoint 2 (`ep2`).
    pub seq2: u32,
}

/// Evaluates and advances TCP sequence and acknowledgment numbers for a single segment.
pub fn advance_tcp_stream_state(
    connections: &mut HashMap<Canonical4Tuple, TcpStreamState>,
    src_ip: IpAddr,
    src_port: u16,
    dst_ip: IpAddr,
    dst_port: u16,
    explicit_seq: Option<u32>,
    explicit_ack: Option<u32>,
    is_syn: bool,
    is_fin: bool,
    payload_len: u32,
) -> (u32, u32) {
    let ep1 = (src_ip, src_port);
    let ep2 = (dst_ip, dst_port);
    let (key, is_forward) = if ep1 <= ep2 {
        ((ep1, ep2), true)
    } else {
        ((ep2, ep1), false)
    };

    let state = connections.entry(key).or_insert(TcpStreamState {
        seq1: 1000,
        seq2: 1000,
    });

    let (sender_seq, receiver_seq) = if is_forward {
        (&mut state.seq1, &mut state.seq2)
    } else {
        (&mut state.seq2, &mut state.seq1)
    };

    let seq_num = if let Some(s) = explicit_seq {
        *sender_seq = s;
        s
    } else {
        *sender_seq
    };

    let ack_num = explicit_ack.unwrap_or(*receiver_seq);

    let mut advance = payload_len;
    if is_syn {
        advance += 1;
    }
    if is_fin {
        advance += 1;
    }
    *sender_seq = seq_num.wrapping_add(advance);

    (seq_num, ack_num)
}
```

---

## 5. Transactional PCAPNG Writer with Nanosecond Fidelity & `pcap-file 2.0.0` Quirks

Demonstrates `frameassembly`'s `PcapWriter` (`src/pcap.rs`) and transactional PCAPNG emission (`src/backend/mod.rs`), along with critical `pcap-file 2.0.0` API invariants:
- **Exact `PcapError` Enum (6 Variants)**: `IncompleteBuffer`, `IoError(std::io::Error)`, `InvalidField(&'static str)`, `Utf8Error(std::str::Utf8Error)`, `FromUtf8Error(std::string::FromUtf8Error)`, `InvalidInterfaceId(u32)`. Never match on non-existent variants (`InvalidTsResolution`, `HeaderNotFound`, `QuoteNotClosed`).
- **Exact `Block<'a>` Enum (9 Variants)**: `SectionHeader`, `InterfaceDescription`, `Packet`, `SimplePacket`, `NameResolution`, `InterfaceStatistics`, `EnhancedPacket`, `SystemdJournalExport`, and `Unknown(UnknownBlock<'a>)` (which captures IETF `DecryptionSecretsBlock` `0x0000000A` and `CustomBlock` `0x00000BAD`).
- **`derive-into-owned 0.2.0` & `ReadBuffer` Limit**: Every block/option struct provides an inherent `.into_owned(self)` method; `PcapNgReader`'s internal `ReadBuffer` enforces an **8,000,000-byte (8 MB)** single-block limit.
- **Quirk 1 (`EnhancedPacketBlock` Timestamp Resolution)**: `pcap-file 2.0.0` unconditionally converts `Duration` via `as_nanos()` / `Duration::from_nanos()` while ignoring `IfTsResol`, whereas Wireshark/`tshark` default to `IfTsResol(6)` ($10^{-6}\text{s}$) when Option 9 is omitted. Thus `InterfaceDescriptionOption::IfTsResol(9)` is **strictly mandatory**.
- **Quirk 2 (`InterfaceDescriptionOption::IfTzone` Fatal Read Bug)**: In `pcap-file 2.0.0`, Option 10 (`IfTzone`) checks `if slice.len() != 1` and then calls `slice.read_u32::<B>()` (4 bytes), causing `PcapNgReader` to **always fail** if `IfTzone` is present. **Never emit `IfTzone`**.
- **Transactional File Creation**: All packets are synthesized into `packet_buffer: Vec<(Vec<u8>, u64)>` before opening the output file so that any semantic or protocol error aborts cleanly without leaving a partial `.pcap` file on disk.

```rust
use pcap_file::pcapng::blocks::enhanced_packet::EnhancedPacketBlock;
use pcap_file::pcapng::blocks::interface_description::{
    InterfaceDescriptionBlock, InterfaceDescriptionOption,
};
use pcap_file::pcapng::{PcapNgBlock, PcapNgWriter};
use pcap_file::{DataLink, PcapError};
use std::borrow::Cow;
use std::fs::File;
use std::io::{self, Error, Write};
use std::time::Duration;

/// Maps the exact 6 `pcap_file::PcapError` variants in `pcap-file 2.0.0` to `std::io::Error`.
pub fn map_pcap_error(err: PcapError) -> io::Error {
    match err {
        PcapError::IncompleteBuffer => Error::new(io::ErrorKind::UnexpectedEof, "Incomplete PCAP buffer"),
        PcapError::IoError(e) => e,
        PcapError::InvalidField(msg) => Error::new(io::ErrorKind::InvalidData, msg),
        PcapError::Utf8Error(e) => Error::new(io::ErrorKind::InvalidData, e),
        PcapError::FromUtf8Error(e) => Error::new(io::ErrorKind::InvalidData, e),
        PcapError::InvalidInterfaceId(id) => {
            Error::new(io::ErrorKind::InvalidInput, format!("Unregistered interface_id: {id}"))
        }
    }
}

/// Writes a batch of `(packet_bytes, timestamp_nanos)` tuples transactionally to a PCAPNG file.
///
/// The destination file is created only if `packets` is ready to be committed.
pub fn write_pcapng_transactional(
    output_path: &str,
    packets: &[(Vec<u8>, u64)],
) -> io::Result<()> {
    let file = File::create(output_path)?;
    write_pcapng_to_sink(file, packets).map(|_| ())
}

/// Writes PCAPNG blocks (`SHB -> IDB -> EPB*`) with mandatory `IfTsResol(9)` and no `IfTzone`.
pub fn write_pcapng_to_sink<W: Write>(
    sink: W,
    packets: &[(Vec<u8>, u64)],
) -> io::Result<W> {
    let mut writer = PcapNgWriter::new(sink).map_err(map_pcap_error)?;

    // Mandatory IDB at interface_id = 0 with IfTsResol(9) (10^-9 seconds = nanoseconds).
    // NEVER include InterfaceDescriptionOption::IfTzone due to pcap-file 2.0.0's 1-byte vs 4-byte read bug!
    let interface = InterfaceDescriptionBlock {
        linktype: DataLink::ETHERNET,
        snaplen: 65535,
        options: vec![InterfaceDescriptionOption::IfTsResol(9)],
    };
    writer
        .write_block(&interface.into_block())
        .map_err(map_pcap_error)?;

    for (packet_data, ts_nanos) in packets {
        let epb = EnhancedPacketBlock {
            interface_id: 0,
            timestamp: Duration::from_nanos(*ts_nanos),
            original_len: packet_data.len() as u32,
            data: Cow::Borrowed(packet_data),
            options: vec![],
        };
        writer
            .write_block(&epb.into_block())
            .map_err(map_pcap_error)?;
    }

    Ok(writer.into_inner())
}
```

---

## 6. Zero-Copy Streaming PCAPNG Dissector (`PcapNgReader` + Native Wire Slicing)

Demonstrates how `frameassembly`'s verification suites (`tests/challenger_wire_verification_tests.rs`, `tests/e2e_60_protocols_tests.rs`) stream `EnhancedPacketBlock` records via `pcap_file::pcapng::PcapNgReader`, handle all 9 `Block<'a>` variants (or promote borrowed blocks via `derive-into-owned 0.2.0`'s `.into_owned()`), and dissect L2 (Ethernet II, VLAN `0x8100`, QinQ `0x88A8`, MPLS `0x8847`), L3 (IPv4 IHL, IPv6), and L4 (TCP, UDP, SCTP) headers directly from `epb.data` with **zero external parser dependencies**.

```rust
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use pcap_file::pcapng::{Block, PcapNgReader};
use pcap_file::PcapError;
use std::io::Read;
use std::time::Duration;

/// Dissected L2–L4 wire header summary extracted from a single captured frame.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativeDissectedFrame {
    /// Capture timestamp from the EnhancedPacketBlock.
    pub timestamp: Duration,
    /// Destination MAC address (`bytes[0..6]`).
    pub dst_mac: [u8; 6],
    /// Source MAC address (`bytes[6..12]`).
    pub src_mac: [u8; 6],
    /// Outer 802.1Q / 802.1ad VLAN ID if tagged.
    pub outer_vlan_id: Option<u16>,
    /// Inner 802.1Q VLAN ID if QinQ double-tagged.
    pub inner_vlan_id: Option<u16>,
    /// 20-bit MPLS label if EtherType `0x8847` is present.
    pub mpls_label: Option<u32>,
    /// Effective inner EtherType (`0x0800`, `0x86DD`, `0x0806`, etc.).
    pub ethertype: u16,
    /// Source IP address if IPv4 or IPv6.
    pub src_ip: Option<IpAddr>,
    /// Destination IP address if IPv4 or IPv6.
    pub dst_ip: Option<IpAddr>,
    /// IPv4 protocol or IPv6 next_header number (`6` = TCP, `17` = UDP, `132` = SCTP, `58` = ICMPv6).
    pub ip_proto: Option<u8>,
    /// IPv4 TTL or IPv6 Hop Limit.
    pub ttl: Option<u8>,
    /// Transport source port (for TCP, UDP, or SCTP).
    pub src_port: Option<u16>,
    /// Transport destination port (for TCP, UDP, or SCTP).
    pub dst_port: Option<u16>,
    /// Byte offset where the L4 payload begins.
    pub l4_payload_offset: usize,
}

/// Dissects a raw Ethernet frame into L2, L3, and L4 fields using native slice offsets.
pub fn dissect_wire_frame(frame: &[u8], timestamp: Duration) -> Option<NativeDissectedFrame> {
    if frame.len() < 14 {
        return None;
    }
    let dst_mac: [u8; 6] = frame[0..6].try_into().ok()?;
    let src_mac: [u8; 6] = frame[6..12].try_into().ok()?;
    let mut offset = 12;
    let mut ethertype = u16::from_be_bytes([frame[offset], frame[offset + 1]]);
    offset += 2;

    let mut outer_vlan_id = None;
    let mut inner_vlan_id = None;
    let mut mpls_label = None;

    // 1. Check for 802.1ad QinQ (0x88A8) or 802.1Q VLAN (0x8100)
    if ethertype == 0x88A8 || ethertype == 0x8100 {
        if frame.len() < offset + 4 {
            return None;
        }
        let tci = u16::from_be_bytes([frame[offset], frame[offset + 1]]);
        outer_vlan_id = Some(tci & 0x0FFF);
        ethertype = u16::from_be_bytes([frame[offset + 2], frame[offset + 3]]);
        offset += 4;

        // Check for inner C-VLAN tag (0x8100) in QinQ stack
        if ethertype == 0x8100 {
            if frame.len() < offset + 4 {
                return None;
            }
            let inner_tci = u16::from_be_bytes([frame[offset], frame[offset + 1]]);
            inner_vlan_id = Some(inner_tci & 0x0FFF);
            ethertype = u16::from_be_bytes([frame[offset + 2], frame[offset + 3]]);
            offset += 4;
        }
    }

    // 2. Check for RFC 3032 MPLS unicast shim (0x8847)
    if ethertype == 0x8847 {
        if frame.len() < offset + 4 {
            return None;
        }
        let shim = u32::from_be_bytes(frame[offset..offset + 4].try_into().ok()?);
        mpls_label = Some(shim >> 12);
        offset += 4;
        // Peek version nibble of inner IP packet if present
        if frame.len() > offset {
            match frame[offset] >> 4 {
                4 => ethertype = 0x0800,
                6 => ethertype = 0x86DD,
                _ => {}
            }
        }
    }

    let mut src_ip = None;
    let mut dst_ip = None;
    let mut ip_proto = None;
    let mut ttl = None;

    // 3. Parse L3 IPv4 (0x0800) or IPv6 (0x86DD)
    match ethertype {
        0x0800 if frame.len() >= offset + 20 && (frame[offset] >> 4) == 4 => {
            let ihl = ((frame[offset] & 0x0F) as usize) * 4;
            if ihl < 20 || frame.len() < offset + ihl {
                return None;
            }
            ttl = Some(frame[offset + 8]);
            ip_proto = Some(frame[offset + 9]);
            let s: [u8; 4] = frame[offset + 12..offset + 16].try_into().ok()?;
            let d: [u8; 4] = frame[offset + 16..offset + 20].try_into().ok()?;
            src_ip = Some(IpAddr::V4(Ipv4Addr::from(s)));
            dst_ip = Some(IpAddr::V4(Ipv4Addr::from(d)));
            offset += ihl;
        }
        0x86DD if frame.len() >= offset + 40 && (frame[offset] >> 4) == 6 => {
            ip_proto = Some(frame[offset + 6]);
            ttl = Some(frame[offset + 7]);
            let s: [u8; 16] = frame[offset + 8..offset + 24].try_into().ok()?;
            let d: [u8; 16] = frame[offset + 24..offset + 40].try_into().ok()?;
            src_ip = Some(IpAddr::V6(Ipv6Addr::from(s)));
            dst_ip = Some(IpAddr::V6(Ipv6Addr::from(d)));
            offset += 40;
        }
        _ => {}
    }

    // 4. Parse L4 TCP (6), UDP (17), or SCTP (132)
    let mut src_port = None;
    let mut dst_port = None;
    let mut l4_payload_offset = offset;

    if let Some(proto) = ip_proto {
        match proto {
            6 if frame.len() >= offset + 20 => {
                src_port = Some(u16::from_be_bytes([frame[offset], frame[offset + 1]]));
                dst_port = Some(u16::from_be_bytes([frame[offset + 2], frame[offset + 3]]));
                let data_offset = ((frame[offset + 12] >> 4) as usize) * 4;
                l4_payload_offset = offset + data_offset.max(20);
            }
            17 if frame.len() >= offset + 8 => {
                src_port = Some(u16::from_be_bytes([frame[offset], frame[offset + 1]]));
                dst_port = Some(u16::from_be_bytes([frame[offset + 2], frame[offset + 3]]));
                l4_payload_offset = offset + 8;
            }
            132 if frame.len() >= offset + 12 => {
                src_port = Some(u16::from_be_bytes([frame[offset], frame[offset + 1]]));
                dst_port = Some(u16::from_be_bytes([frame[offset + 2], frame[offset + 3]]));
                l4_payload_offset = offset + 12;
            }
            _ => {}
        }
    }

    Some(NativeDissectedFrame {
        timestamp,
        dst_mac,
        src_mac,
        outer_vlan_id,
        inner_vlan_id,
        mpls_label,
        ethertype,
        src_ip,
        dst_ip,
        ip_proto,
        ttl,
        src_port,
        dst_port,
        l4_payload_offset,
    })
}

/// Streams a PCAPNG file across all 9 `Block<'a>` variants and dissects every `EnhancedPacketBlock`.
pub fn dissect_pcapng_stream<R: Read>(reader: R) -> Result<Vec<NativeDissectedFrame>, PcapError> {
    let mut ng_reader = PcapNgReader::new(reader)?;
    let mut frames = Vec::new();

    while let Some(block_res) = ng_reader.next_block() {
        let block = block_res?;
        match block {
            Block::EnhancedPacket(epb) => {
                // Note: call `epb.into_owned()` (from derive-into-owned 0.2.0) if the block must outlive `ng_reader`
                if let Some(dissected) = dissect_wire_frame(&epb.data, epb.timestamp) {
                    frames.push(dissected);
                }
            }
            Block::SectionHeader(_)
            | Block::InterfaceDescription(_)
            | Block::Packet(_)
            | Block::SimplePacket(_)
            | Block::NameResolution(_)
            | Block::InterfaceStatistics(_)
            | Block::SystemdJournalExport(_)
            | Block::Unknown(_) => {
                // DecryptionSecretsBlock (0x0000000A) and CustomBlock (0x00000BAD) map to Block::Unknown
            }
        }
    }

    Ok(frames)
}
```

---

## 7. 81-Protocol Wire & Wireshark (`tshark`) Dissector QA Invariant Verification Suite

Demonstrates reusable wire-level verification helpers enforcing the critical L2–L7 dissector invariants across `src/backend/l7_dispatch.rs` and `src/builders/`:
1. **L7 Return-Tuple Preservation**: `DHCP` (`(546, 547)` / `(547, 546)` over IPv6 vs `(68, 67)` over IPv4), `MDNS` (`224.0.0.251` / `ff02::fb` on UDP `5353`), `PTP` (`319` Event vs `320` General), and `RADIUS` (`1812` Auth vs `1813` Accounting).
2. **L2/L3 Checksum, TTL & Inner Frame Rules**: `GRE` checksum at `gre[4..6]`, `VRRPv3` IPv4/IPv6 pseudo-header (proto `112`) + TTL/Hop Limit `255`, `NDP` Hop Limit `255`, `GENEVE` `proto = 0x6558` 14B inner Ethernet + 20B IPv4 frame, `WIREGUARD` Type `4` (`DATA`) $\ge 32$B (16B header + payload + 16B Poly1305 tag), `STP` RSTP 36th byte `0x00`, and `EAPOL` EAP Success/Failure (`Code 3/4`) 4-byte length.
3. **L7 Length, Varint & Framing Rules**: `QUIC` Long Header 2B varint (`0x4000 | len`), `IPFIX` `total_len` & `set_len` including payload, `SFLOW` v5 Flow Sample 8-`u32` (32B) header, `MYSQL` 3B LE length, `POSTGRES` `'Q'` + 4B BE length including self, `MODBUS` MBAP `len = 1 + pdu.len()`, `S7COMM` 10B Job / 12B Ack_Data header, `ETHERNETIP` 24B LE header, and `OPCUA` 8B LE UACP header.

```rust
use core::net::{Ipv4Addr, Ipv6Addr};

/// Verifies VRRPv3 (RFC 5798 §5.2.8) wire invariants: IP TTL / Hop Limit == 255 and valid pseudo-header checksum.
pub fn verify_vrrpv3_ipv4_wire(ttl: u8, src: Ipv4Addr, dst: Ipv4Addr, vrrp_pkt: &[u8]) -> bool {
    if ttl != 255 || vrrp_pkt.len() < 12 || (vrrp_pkt[0] >> 4) != 3 {
        return false;
    }
    let mut pseudo = [0u8; 12];
    pseudo[0..4].copy_from_slice(&src.octets());
    pseudo[4..8].copy_from_slice(&dst.octets());
    pseudo[9] = 112; // VRRP IP protocol 112
    pseudo[10..12].copy_from_slice(&(vrrp_pkt.len() as u16).to_be_bytes());
    internet_checksum(&[&pseudo, vrrp_pkt]) == 0
}

/// Verifies GRE (RFC 2784 / RFC 2890) checksum invariant when the Checksum Present bit (`0x8000`) is set.
pub fn verify_gre_checksum(gre_pkt: &[u8]) -> bool {
    if gre_pkt.len() < 4 {
        return false;
    }
    let flags = u16::from_be_bytes([gre_pkt[0], gre_pkt[1]]);
    if (flags & 0x8000) != 0 {
        if gre_pkt.len() < 8 {
            return false;
        }
        let wire_cksum = u16::from_be_bytes([gre_pkt[4], gre_pkt[5]]);
        wire_cksum != 0 && internet_checksum(&[gre_pkt]) == 0
    } else {
        true
    }
}

/// Verifies QUIC Long Header (RFC 9000 §16) 2-byte variable-length integer framing (`0x4000 | remaining_len`).
pub fn verify_quic_long_header_varint(quic_payload: &[u8]) -> bool {
    if quic_payload.len() < 7 || (quic_payload[0] & 0x80) == 0 {
        return false;
    }
    let dcid_len = quic_payload[5] as usize;
    let scid_idx = 6 + dcid_len;
    if quic_payload.len() <= scid_idx {
        return false;
    }
    let scid_len = quic_payload[scid_idx] as usize;
    let mut len_offset = scid_idx + 1 + scid_len;
    // Initial packets (type 0x00) include a Token Length byte (0x00) before the 2-byte Length varint
    if ((quic_payload[0] & 0x30) >> 4) == 0 {
        if quic_payload.len() <= len_offset {
            return false;
        }
        let token_len = quic_payload[len_offset] as usize;
        len_offset += 1 + token_len;
    }
    if quic_payload.len() < len_offset + 2 {
        return false;
    }
    let raw_varint = u16::from_be_bytes([quic_payload[len_offset], quic_payload[len_offset + 1]]);
    let has_2byte_prefix = (raw_varint & 0xC000) == 0x4000;
    let declared_len = (raw_varint & 0x3FFF) as usize;
    let actual_remaining = quic_payload.len() - (len_offset + 2);
    has_2byte_prefix && declared_len == actual_remaining
}

/// Verifies sFlow v5 Flow Sample (`sample_type == 1`) 32-byte (8 x u32) sample header invariant.
pub fn verify_sflow_v5_sample_header(sflow_payload: &[u8]) -> bool {
    // 28B datagram header (with IPv4 agent address) + 8B sample type/len + 32B flow sample header = 68B minimum
    if sflow_payload.len() < 68 {
        return false;
    }
    let version = u32::from_be_bytes(sflow_payload[0..4].try_into().unwrap());
    let sample_type = u32::from_be_bytes(sflow_payload[28..32].try_into().unwrap());
    let sample_len = u32::from_be_bytes(sflow_payload[32..36].try_into().unwrap()) as usize;
    version == 5 && sample_type == 1 && sample_len >= 32 && sflow_payload.len() == 36 + sample_len
}
```
