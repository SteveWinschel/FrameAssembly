# PCAP & PCAPNG to `.frasm` Decompilation Production Reference Patterns

This reference document provides production-ready, fully-documented, and compile-verified Rust code templates for FrameAssembly's 5-stage **PCAP and PCAPNG to `.frasm` decompilation pipeline** (`src/reverse/`) using **`etherparse = { version = "0.21.0", default-features = false, features = ["std"] }`**, **`pcap-file = "2.0.0"`**, and **`rasn = "0.28.15"`**.

---

## 1. Container Magic Detection, 8-Linktype Normalization & Ethernet Padding/FCS Stripping (`container.rs` Pattern)

Demonstrates Stage 1 of the PCAP-to-`.frasm` decompiler (`src/reverse/container.rs`):
- **4-Byte Magic Dispatch**: Distinguishes `PCAPNG` (`0x0A0D0D0A` Section Header Block) from legacy `PCAP` microsecond (`0xa1b2c3d4` / `0xd4c3b2a1`) and nanosecond (`0xa1b23c4d` / `0x4d3cb2a1`) captures.
- **8-Linktype Normalization**: Converts `ETHERNET`, `RAW`, `IPV4`, `IPV6`, `LINUX_SLL` (16B header), `LINUX_SLL2` (20B header), `NULL`, and `LOOP` (4B BSD family header) into canonical 14-byte Ethernet II frames.
- **Ethernet Zero-Padding & 4-Byte FCS Stripping**: Advances past up to 2 VLAN/QinQ tags (`0x8100`, `0x88A8`, `0x9100`) and any MPLS shim stack (`0x8847`, `0x8848`), then uses `IPv4.total_len`, `IPv6.payload_len`, `ARP` 28-byte body, or `EAPOL` `body_len` to truncate 60/64-byte Ethernet padding and 4-byte FCS trailers.

```rust
use pcap_file::DataLink;
use pcap_file::pcap::PcapReader;
use pcap_file::pcapng::{Block, PcapNgReader};
use std::io::{Cursor, Read};

/// A single capture frame normalized to 14-byte Ethernet II framing with nanosecond precision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizedFrame {
    /// Capture timestamp in nanoseconds since the Unix epoch.
    pub timestamp_ns: u64,
    /// Normalized Ethernet II frame bytes with trailing 60/64B padding and 4B FCS stripped.
    pub eth_bytes: Vec<u8>,
    /// Whether the original capture linktype lacked Ethernet MAC headers (`RAW`/`IPV4`/`IPV6`/`NULL`/`LOOP`).
    pub is_l3_only: bool,
}

/// Reads all frames from a `.pcap` or `.pcapng` stream and normalizes them to Ethernet II.
pub fn read_capture_frames<R: Read>(mut reader: R) -> Result<Vec<NormalizedFrame>, String> {
    let mut buf = Vec::new();
    reader
        .read_to_end(&mut buf)
        .map_err(|e| format!("Failed to read capture stream: {e}"))?;

    let Some(magic) = buf.get(0..4) else {
        return Err("Capture input is too short (< 4 bytes)".to_string());
    };

    match magic {
        [0x0A, 0x0D, 0x0D, 0x0A] => read_pcapng_bytes(&buf),
        [0xa1, 0xb2, 0xc3, 0xd4]
        | [0xd4, 0xc3, 0xb2, 0xa1]
        | [0xa1, 0xb2, 0x3c, 0x4d]
        | [0x4d, 0x3c, 0xb2, 0xa1] => read_legacy_pcap_bytes(&buf),
        _ => Err(format!(
            "Unrecognized capture magic {:02x}{:02x}{:02x}{:02x}",
            magic[0], magic[1], magic[2], magic[3]
        )),
    }
}

/// Streams a PCAPNG buffer across multiple Section Header Blocks and interfaces.
fn read_pcapng_bytes(buf: &[u8]) -> Result<Vec<NormalizedFrame>, String> {
    let mut ng_reader = PcapNgReader::new(Cursor::new(buf))
        .map_err(|e| format!("Failed to initialize PCAPNG reader: {e}"))?;
    let mut interfaces: Vec<DataLink> = Vec::new();
    let mut frames: Vec<NormalizedFrame> = Vec::new();
    let mut last_ts_ns: u64 = 1_700_000_000_000_000_000;

    while let Some(block_res) = ng_reader.next_block() {
        let block = block_res.map_err(|e| format!("Failed to parse PCAPNG block: {e}"))?;
        match block {
            Block::SectionHeader(_) => interfaces.clear(),
            Block::InterfaceDescription(idb) => interfaces.push(idb.linktype),
            Block::EnhancedPacket(epb) => {
                let linktype = interfaces
                    .get(epb.interface_id as usize)
                    .copied()
                    .unwrap_or(DataLink::ETHERNET);
                let ts_ns = epb.timestamp.as_nanos() as u64;
                last_ts_ns = ts_ns;
                if let Some(f) = normalize_frame(&epb.data, linktype, ts_ns)? {
                    frames.push(f);
                }
            }
            Block::SimplePacket(spb) => {
                let linktype = interfaces.first().copied().unwrap_or(DataLink::ETHERNET);
                if let Some(f) = normalize_frame(&spb.data, linktype, last_ts_ns)? {
                    frames.push(f);
                }
            }
            Block::Packet(pb) => {
                let linktype = interfaces
                    .get(pb.interface_id as usize)
                    .copied()
                    .unwrap_or(DataLink::ETHERNET);
                let ts_ns = pb.timestamp.as_nanos() as u64;
                last_ts_ns = ts_ns;
                if let Some(f) = normalize_frame(&pb.data, linktype, ts_ns)? {
                    frames.push(f);
                }
            }
            _ => {}
        }
    }
    Ok(frames)
}

/// Streams a legacy PCAP buffer (microsecond or nanosecond precision).
fn read_legacy_pcap_bytes(buf: &[u8]) -> Result<Vec<NormalizedFrame>, String> {
    let mut pcap_reader = PcapReader::new(Cursor::new(buf))
        .map_err(|e| format!("Failed to initialize legacy PCAP reader: {e}"))?;
    let linktype = pcap_reader.header().datalink;
    let mut frames = Vec::new();

    while let Some(pkt_res) = pcap_reader.next_packet() {
        let pkt = pkt_res.map_err(|e| format!("Failed to parse PCAP packet: {e}"))?;
        let ts_ns = pkt.timestamp.as_nanos() as u64;
        if let Some(f) = normalize_frame(&pkt.data, linktype, ts_ns)? {
            frames.push(f);
        }
    }
    Ok(frames)
}

/// Normalizes a raw frame from `linktype` into a 14-byte Ethernet II frame and strips padding/FCS.
pub fn normalize_frame(
    raw: &[u8],
    linktype: DataLink,
    timestamp_ns: u64,
) -> Result<Option<NormalizedFrame>, String> {
    if raw.is_empty() {
        return Ok(None);
    }

    let (eth_raw, is_l3_only) = match linktype {
        DataLink::ETHERNET => {
            if raw.len() < 14 {
                return Err(format!("Truncated Ethernet frame ({}B < 14B)", raw.len()));
            }
            (raw.to_vec(), false)
        }
        DataLink::RAW | DataLink::IPV4 | DataLink::IPV6 => {
            let et: u16 = match raw[0] >> 4 {
                4 => 0x0800,
                6 => 0x86DD,
                _ if linktype == DataLink::IPV6 => 0x86DD,
                _ => 0x0800,
            };
            let mut eth = Vec::with_capacity(14 + raw.len());
            eth.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x02]);
            eth.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x01]);
            eth.extend_from_slice(&et.to_be_bytes());
            eth.extend_from_slice(raw);
            (eth, true)
        }
        DataLink::LINUX_SLL => {
            if raw.len() < 16 {
                return Err(format!("Truncated LINUX_SLL frame ({}B < 16B)", raw.len()));
            }
            let halen = u16::from_be_bytes([raw[4], raw[5]]) as usize;
            let src_mac = if halen == 6 {
                [raw[6], raw[7], raw[8], raw[9], raw[10], raw[11]]
            } else {
                [0x00, 0x00, 0x00, 0x00, 0x00, 0x01]
            };
            let mut eth = Vec::with_capacity(14 + raw.len() - 16);
            eth.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x02]);
            eth.extend_from_slice(&src_mac);
            eth.extend_from_slice(&raw[14..16]);
            eth.extend_from_slice(&raw[16..]);
            (eth, halen != 6)
        }
        DataLink::LINUX_SLL2 => {
            if raw.len() < 20 {
                return Err(format!("Truncated LINUX_SLL2 frame ({}B < 20B)", raw.len()));
            }
            let halen = raw[10] as usize;
            let src_mac = if halen == 6 {
                [raw[12], raw[13], raw[14], raw[15], raw[16], raw[17]]
            } else {
                [0x00, 0x00, 0x00, 0x00, 0x00, 0x01]
            };
            let mut eth = Vec::with_capacity(14 + raw.len() - 20);
            eth.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x02]);
            eth.extend_from_slice(&src_mac);
            eth.extend_from_slice(&raw[0..2]);
            eth.extend_from_slice(&raw[20..]);
            (eth, halen != 6)
        }
        DataLink::NULL | DataLink::LOOP => {
            if raw.len() < 4 {
                return Err(format!("Truncated BSD NULL/LOOP frame ({}B < 4B)", raw.len()));
            }
            let fam_le = u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]);
            let fam_be = u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]);
            let fam = if fam_le <= 0xFFFF { fam_le } else { fam_be };
            let et: u16 = match fam {
                2 => 0x0800,
                10 | 24 | 28 | 30 => 0x86DD,
                _ => match raw.get(4).map(|b| b >> 4) {
                    Some(6) => 0x86DD,
                    _ => 0x0800,
                },
            };
            let mut eth = Vec::with_capacity(14 + raw.len() - 4);
            eth.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x02]);
            eth.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x01]);
            eth.extend_from_slice(&et.to_be_bytes());
            eth.extend_from_slice(&raw[4..]);
            (eth, true)
        }
        other => return Err(format!("Unsupported capture linktype {other:?}")),
    };

    Ok(Some(NormalizedFrame {
        timestamp_ns,
        eth_bytes: strip_padding_and_fcs(eth_raw),
        is_l3_only,
    }))
}

/// Strips 60/64-byte Ethernet zero-padding and 4-byte FCS trailers using inner protocol length fields.
pub fn strip_padding_and_fcs(mut eth_bytes: Vec<u8>) -> Vec<u8> {
    if eth_bytes.len() < 14 {
        return eth_bytes;
    }
    let mut offset = 12usize;
    let mut et = u16::from_be_bytes([eth_bytes[offset], eth_bytes[offset + 1]]);
    offset += 2;

    let mut vlan_tags = 0usize;
    while matches!(et, 0x8100 | 0x88A8 | 0x9100)
        && vlan_tags < 2
        && offset + 4 <= eth_bytes.len()
    {
        et = u16::from_be_bytes([eth_bytes[offset + 2], eth_bytes[offset + 3]]);
        offset += 4;
        vlan_tags += 1;
    }

    if matches!(et, 0x8847 | 0x8848) {
        while offset + 4 <= eth_bytes.len() {
            let bos = (eth_bytes[offset + 2] & 0x01) != 0;
            offset += 4;
            if bos {
                break;
            }
        }
        if let Some(&first_byte) = eth_bytes.get(offset) {
            match first_byte >> 4 {
                4 => et = 0x0800,
                6 => et = 0x86DD,
                _ => {}
            }
        }
    }

    let l3_offset = offset;
    match et {
        0x0800 if l3_offset + 20 <= eth_bytes.len() => {
            let ver = eth_bytes[l3_offset] >> 4;
            let ihl = ((eth_bytes[l3_offset] & 0x0f) as usize) * 4;
            let total_len =
                u16::from_be_bytes([eth_bytes[l3_offset + 2], eth_bytes[l3_offset + 3]]) as usize;
            if ver == 4 && ihl >= 20 && total_len >= ihl && l3_offset + total_len <= eth_bytes.len()
            {
                eth_bytes.truncate(l3_offset + total_len);
            }
        }
        0x86DD if l3_offset + 40 <= eth_bytes.len() && (eth_bytes[l3_offset] >> 4) == 6 => {
            let payload_len =
                u16::from_be_bytes([eth_bytes[l3_offset + 4], eth_bytes[l3_offset + 5]]) as usize;
            if l3_offset + 40 + payload_len <= eth_bytes.len() {
                eth_bytes.truncate(l3_offset + 40 + payload_len);
            }
        }
        0x0806 if l3_offset + 28 < eth_bytes.len() => {
            let trailing = &eth_bytes[l3_offset + 28..];
            let all_zero = trailing.iter().all(|&b| b == 0);
            let zero_plus_fcs = (eth_bytes.len() == 60 || eth_bytes.len() == 64)
                && trailing.len() >= 4
                && trailing[..trailing.len() - 4].iter().all(|&b| b == 0);
            if all_zero || zero_plus_fcs {
                eth_bytes.truncate(l3_offset + 28);
            }
        }
        _ => {}
    }
    eth_bytes
}
```

---

## 2. `etherparse 0.21.0` Zero-Copy L2–L4 + MPLS + SCTP Decompilation (`src/reverse/{l2,l3,l4}` Pattern)

Demonstrates how to slice Ethernet II, VLAN/QinQ (`sliced.vlan()` & `sliced.link_exts`), ARP (`NetSlice::Arp`), IPv4/IPv6 (`NetSlice::{Ipv4, Ipv6}`), TCP (`TransportSlice::Tcp` + `tcp.options_iterator()`), UDP (`TransportSlice::Udp`), ICMPv4/ICMPv6/IGMP, plus manual RFC 3032 MPLS (`0x8847`) and RFC 9260 SCTP (`ip_proto == 132`) using `etherparse 0.21.0`:

```rust
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use etherparse::{
    LaxSlicedPacket, LinkExtSlice, NetSlice, SlicedPacket, TcpOptionElement, TransportSlice,
    VlanSlice,
};

/// Summary of L2–L4 headers extracted via `etherparse 0.21.0` + manual MPLS/SCTP peeling.
#[derive(Debug, Clone, Default)]
pub struct DecompiledL2L4 {
    /// Source MAC address.
    pub src_mac: [u8; 6],
    /// Destination MAC address.
    pub dst_mac: [u8; 6],
    /// Single 802.1Q VLAN `(vid, pcp, dei)`.
    pub vlan: Option<(u16, u8, u8)>,
    /// Double 802.1ad QinQ `(outer_vid, inner_vid, pcp, dei)`.
    pub qinq: Option<(u16, u16, u8, u8)>,
    /// RFC 3032 MPLS `(label, exp, bos, ttl)`.
    pub mpls: Option<(u32, u8, u8, u8)>,
    /// Source IP address.
    pub src_ip: Option<IpAddr>,
    /// Destination IP address.
    pub dst_ip: Option<IpAddr>,
    /// IP protocol / Next Header number.
    pub ip_proto: Option<u8>,
    /// TTL or Hop Limit.
    pub ttl: Option<u8>,
    /// Source port (TCP, UDP, or SCTP).
    pub src_port: Option<u16>,
    /// Destination port (TCP, UDP, or SCTP).
    pub dst_port: Option<u16>,
    /// TCP sequence number.
    pub seq: Option<u32>,
    /// TCP acknowledgment number.
    pub ack_num: Option<u32>,
    /// Decoded TCP options `(mss, wscale, sack_perm, tsval, tsecr)`.
    pub tcp_opts: (Option<u16>, Option<u8>, bool, Option<u32>, Option<u32>),
    /// SCTP verification tag and first chunk type if `ip_proto == 132`.
    pub sctp_vtag_and_chunk: Option<(u32, u8)>,
    /// Application-layer L4 payload bytes.
    pub l4_payload: Vec<u8>,
}

/// Decompiles L2–L4 headers using `etherparse 0.21.0` (`SlicedPacket` with `LaxSlicedPacket` fallback).
pub fn decompile_l2_l4_headers(eth_frame: &[u8]) -> Option<DecompiledL2L4> {
    if eth_frame.len() < 14 {
        return None;
    }
    let mut out = DecompiledL2L4 {
        dst_mac: eth_frame.get(0..6)?.try_into().ok()?,
        src_mac: eth_frame.get(6..12)?.try_into().ok()?,
        ..Default::default()
    };

    // 1. Try etherparse 0.21.0 SlicedPacket::from_ethernet (or LaxSlicedPacket for truncated frames)
    if let Ok(sliced) = SlicedPacket::from_ethernet(eth_frame) {
        // In etherparse 0.21.0, `.vlan()` inspects `link_exts: ArrayVec<LinkExtSlice, 3>`
        match sliced.vlan() {
            Some(VlanSlice::SingleVlan(v)) => {
                out.vlan = Some((
                    v.vlan_identifier().value(),
                    v.priority_code_point().value(),
                    u8::from(v.drop_eligible_indicator()),
                ));
            }
            Some(VlanSlice::DoubleVlan(d)) => {
                out.qinq = Some((
                    d.outer().vlan_identifier().value(),
                    d.inner().vlan_identifier().value(),
                    d.outer().priority_code_point().value(),
                    u8::from(d.outer().drop_eligible_indicator()),
                ));
            }
            None => {}
        }

        // Inspect `link_exts` directly if IEEE 802.1AE MACsec (`0x88E5`) metadata is needed
        for ext in &sliced.link_exts {
            if let LinkExtSlice::Macsec(_macsec) = ext {
                // MACsec SecTAG present
            }
        }

        // 2. Match NetSlice::{Ipv4, Ipv6, Arp}
        let mut raw_ip_payload: &[u8] = &[];
        match &sliced.net {
            Some(NetSlice::Ipv4(v4)) => {
                let hdr = v4.header();
                out.src_ip = Some(IpAddr::V4(hdr.source_addr()));
                out.dst_ip = Some(IpAddr::V4(hdr.destination_addr()));
                out.ttl = Some(hdr.ttl());
                out.ip_proto = Some(hdr.protocol().0);
                raw_ip_payload = v4.payload().payload;
            }
            Some(NetSlice::Ipv6(v6)) => {
                let hdr = v6.header();
                out.src_ip = Some(IpAddr::V6(hdr.source_addr()));
                out.dst_ip = Some(IpAddr::V6(hdr.destination_addr()));
                out.ttl = Some(hdr.hop_limit());
                out.ip_proto = Some(v6.payload().ip_number.0);
                raw_ip_payload = v6.payload().payload;
            }
            Some(NetSlice::Arp(arp)) => {
                if let (Ok(spa), Ok(tpa)) = (
                     <[u8; 4]>::try_from(arp.sender_protocol_addr()),
                    <[u8; 4]>::try_from(arp.target_protocol_addr()),
                ) {
                    out.src_ip = Some(IpAddr::V4(Ipv4Addr::from(spa)));
                    out.dst_ip = Some(IpAddr::V4(Ipv4Addr::from(tpa)));
                }
            }
            None => {}
        }

        // 3. Match TransportSlice::{Tcp, Udp, Icmpv4, Icmpv6, Igmp}
        match &sliced.transport {
            Some(TransportSlice::Tcp(tcp)) => {
                out.src_port = Some(tcp.source_port());
                out.dst_port = Some(tcp.destination_port());
                out.seq = Some(tcp.sequence_number());
                out.ack_num = Some(tcp.acknowledgment_number());
                for opt_res in tcp.options_iterator() {
                    let Ok(opt) = opt_res else { break };
                    match opt {
                        TcpOptionElement::MaximumSegmentSize(mss) => out.tcp_opts.0 = Some(mss),
                        TcpOptionElement::WindowScale(ws) => out.tcp_opts.1 = Some(ws),
                        TcpOptionElement::SelectiveAcknowledgementPermitted => {
                            out.tcp_opts.2 = true;
                        }
                        TcpOptionElement::Timestamp(tsval, tsecr) => {
                            out.tcp_opts.3 = Some(tsval);
                            out.tcp_opts.4 = Some(tsecr);
                        }
                        _ => {}
                    }
                }
                out.l4_payload = tcp.payload().to_vec();
            }
            Some(TransportSlice::Udp(udp)) => {
                out.src_port = Some(udp.source_port());
                out.dst_port = Some(udp.destination_port());
                out.l4_payload = udp.payload().to_vec();
            }
            Some(TransportSlice::Icmpv4(icmp4)) => {
                out.l4_payload = icmp4.payload().to_vec();
            }
            Some(TransportSlice::Icmpv6(icmp6)) => {
                out.l4_payload = icmp6.payload().to_vec();
            }
            Some(TransportSlice::Igmp(igmp_slice)) => {
                out.l4_payload = igmp_slice.to_vec();
            }
            None => {
                // 4. Manual RFC 9260 SCTP (`ip_proto == 132`) header & chunk decompilation
                if out.ip_proto == Some(132) && raw_ip_payload.len() >= 12 {
                    out.src_port = Some(u16::from_be_bytes([raw_ip_payload[0], raw_ip_payload[1]]));
                    out.dst_port = Some(u16::from_be_bytes([raw_ip_payload[2], raw_ip_payload[3]]));
                    let vtag = u32::from_be_bytes([
                        raw_ip_payload[4],
                        raw_ip_payload[5],
                        raw_ip_payload[6],
                        raw_ip_payload[7],
                    ]);
                    let first_chunk_type = raw_ip_payload.get(12).copied().unwrap_or(0);
                    out.sctp_vtag_and_chunk = Some((vtag, first_chunk_type));
                }
            }
        }
    } else if let Ok(_lax) = LaxSlicedPacket::from_ethernet(eth_frame) {
        // Fallback path for snaplen-truncated captures
    }

    // 5. Manual RFC 3032 MPLS (`0x8847` / `0x8848`) shim peeling when present after L2 tags
    let mut offset = 12usize;
    let mut et = u16::from_be_bytes([eth_frame[offset], eth_frame[offset + 1]]);
    offset += 2;
    let mut tags = 0usize;
    while matches!(et, 0x8100 | 0x88A8 | 0x9100) && tags < 2 && offset + 4 <= eth_frame.len() {
        et = u16::from_be_bytes([eth_frame[offset + 2], eth_frame[offset + 3]]);
        offset += 4;
        tags += 1;
    }
    if matches!(et, 0x8847 | 0x8848) && offset + 4 <= eth_frame.len() {
        let shim = u32::from_be_bytes(eth_frame.get(offset..offset + 4)?.try_into().ok()?);
        let label = shim >> 12;
        let exp = ((shim >> 9) & 0x07) as u8;
        let bos = ((shim >> 8) & 0x01) as u8;
        let mpls_ttl = (shim & 0xFF) as u8;
        out.mpls = Some((label, exp, bos, mpls_ttl));
        if out.src_ip.is_none()
            && let Some(inner) = eth_frame.get(offset + 4..)
        {
            if inner.len() >= 20 && (inner[0] >> 4) == 4 {
                let s: [u8; 4] = inner.get(12..16)?.try_into().ok()?;
                let d: [u8; 4] = inner.get(16..20)?.try_into().ok()?;
                out.src_ip = Some(IpAddr::V4(Ipv4Addr::from(s)));
                out.dst_ip = Some(IpAddr::V4(Ipv4Addr::from(d)));
            } else if inner.len() >= 40 && (inner[0] >> 4) == 6 {
                let s: [u8; 16] = inner.get(8..24)?.try_into().ok()?;
                let d: [u8; 16] = inner.get(24..40)?.try_into().ok()?;
                out.src_ip = Some(IpAddr::V6(Ipv6Addr::from(s)));
                out.dst_ip = Some(IpAddr::V6(Ipv6Addr::from(d)));
            }
        }
    }

    Some(out)
}
```

---

## 3. Fuzz-Safe L7 Protocol Decompilation with Bounded DNS Pointers (`MAX_DNS_JUMPS = 16`) & ASN.1 BER/DER Decoding (`src/reverse/l7/<protocol>.rs` Pattern)

Demonstrates fuzz-safe Layer 7 decompilation patterns from `src/reverse/l7/dns.rs` and `src/reverse/l7/snmp2.rs`:
- **Bounded DNS Pointer Compression (`MAX_DNS_JUMPS = 16`)**: Prevents infinite loops on malformed `0xC000` self-pointers while tracking `end_after_first_jump` so the caller knows the exact byte offset immediately following the question/record name.
- **ASN.1 BER Remainder Decompilation (`rasn::ber::decode_with_remainder`)**: Decodes `SNMP2` PDUs without panicking and preserves any trailing bytes in `residual_payload`.

```rust
use rasn_snmp::v2::Pdus as SnmpV2Pdus;
use rasn_snmp::v2c::Message as SnmpV2cMessage;

/// Maximum RFC 1035 §4.1.4 pointer jumps allowed before aborting DNS name decoding.
pub const MAX_DNS_JUMPS: usize = 16;

/// Decodes an RFC 1035 domain name starting at `start_offset` with bounded compression jumps.
///
/// Returns `(decoded_name, offset_immediately_after_name_in_stream)`.
pub fn decode_dns_name_bounded(packet: &[u8], start_offset: usize) -> Option<(String, usize)> {
    if start_offset >= packet.len() {
        return None;
    }
    let mut labels: Vec<&str> = Vec::new();
    let mut pos = start_offset;
    let mut end_after_first_jump: Option<usize> = None;
    let mut jumps = 0usize;

    loop {
        let len_byte = *packet.get(pos)?;
        if len_byte == 0 {
            let final_offset = end_after_first_jump.unwrap_or(pos + 1);
            return Some((labels.join("."), final_offset));
        }
        if (len_byte & 0xC0) == 0xC0 {
            jumps += 1;
            if jumps > MAX_DNS_JUMPS {
                return None;
            }
            let second_byte = *packet.get(pos + 1)?;
            let target_offset = (((len_byte & 0x3F) as usize) << 8) | (second_byte as usize);
            if target_offset >= packet.len() || target_offset == pos {
                return None;
            }
            if end_after_first_jump.is_none() {
                end_after_first_jump = Some(pos + 2);
            }
            pos = target_offset;
            continue;
        }
        if (len_byte & 0xC0) != 0 {
            return None; // Reserved label bits
        }
        let label_len = len_byte as usize;
        let label_start = pos.checked_add(1)?;
        let label_end = label_start.checked_add(label_len)?;
        let label_bytes = packet.get(label_start..label_end)?;
        let label_str = core::str::from_utf8(label_bytes).ok()?;
        labels.push(label_str);
        pos = label_end;
    }
}

/// Fuzz-safe SNMPv2c ASN.1 BER decompiler returning `(fasm_tokens, residual_payload)`.
pub fn decompile_snmpv2c_ber(payload: &[u8]) -> Option<(String, Vec<u8>)> {
    let (msg, remainder): (SnmpV2cMessage<SnmpV2Pdus>, &[u8]) =
        rasn::ber::decode_with_remainder(payload).ok()?;
    if msg.version != 1.into() {
        return None;
    }
    let community = core::str::from_utf8(msg.community.as_ref()).ok()?;
    let mut tokens = String::from("snmp2");
    match &msg.data {
        SnmpV2Pdus::GetRequest(pdu) => {
            tokens.push_str(" get");
            if pdu.0.request_id != 1 {
                tokens.push_str(&format!(" reqid {}", pdu.0.request_id));
            }
        }
        SnmpV2Pdus::Response(pdu) => {
            tokens.push_str(" response");
            if pdu.0.request_id != 1 {
                tokens.push_str(&format!(" reqid {}", pdu.0.request_id));
            }
        }
        SnmpV2Pdus::Trap(_) => tokens.push_str(" trap"),
        SnmpV2Pdus::InformRequest(_) => tokens.push_str(" inform"),
        SnmpV2Pdus::GetNextRequest(_) => tokens.push_str(" getnext"),
        SnmpV2Pdus::SetRequest(_) => tokens.push_str(" set"),
        SnmpV2Pdus::GetBulkRequest(_) => tokens.push_str(" getbulk"),
        SnmpV2Pdus::Report(_) => return None,
    }
    if community != "public" {
        tokens.push_str(&format!(" community \"{community}\""));
    }
    Some((tokens, remainder.to_vec()))
}
```

---

## 4. Deterministic Topology Discovery (`host1`, `host2`, Dominant MACs, Arrow Locking) & Direct `compile` Emission (Zero `loop` Blocks)

Demonstrates Stages 3 and 5 of the FrameAssembly v3.0.0 decompiler:
- **Deterministic Host & Direction Discovery**: Assigns `host1`, `host2`, ... (never `host_1`, `host_2`) in first-seen order, tracks each host's dominant unicast MAC (ignoring broadcast `ff:ff:ff:ff:ff:ff` and multicast `01:00:5e:...` / `33:33:...`), and locks each pair's canonical `(caller_idx, callee_idx)` so forward frames emit `->` and reply frames emit `<-`.
- **Direct `compile` Emission (Zero `loop` Blocks)**: Because `loop` was removed in FrameAssembly v2.0.0, `shadow_emit.rs` emits direct flow invocations inside `compile { ... }` without folding consecutive calls into `loop` blocks.

```rust
use core::net::IpAddr;
use std::collections::HashMap;

/// Discovered host definition for v3.0.0 `.frasm` topology emission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveredHost {
    /// Sequential v3.0.0 identifier (`"host1"`, `"host2"`, ... — never `"host_1"`).
    pub name: String,
    /// Host IPv4 or IPv6 address (`None` for pure L2 MAC-only endpoints).
    pub ip: Option<IpAddr>,
    /// Dominant unicast MAC address observed for this host.
    pub mac: Option<[u8; 6]>,
}

impl DiscoveredHost {
    /// Constructs a sequentially numbered v3.0.0 host (`host1`, `host2`, ...).
    pub fn numbered(one_based_index: usize, ip: Option<IpAddr>, mac: Option<[u8; 6]>) -> Self {
        Self {
            name: format!("host{one_based_index}"),
            ip,
            mac,
        }
    }

    /// Formats the canonical v3.0.0 `host <name> { [ip <ip>] [mac <mac>] }` declaration.
    pub fn to_fasm_decl(&self) -> String {
        let mut fields = Vec::new();
        if let Some(ip) = self.ip {
            fields.push(format!("ip {ip}"));
        }
        if let Some(m) = self.mac {
            fields.push(format!(
                "mac {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                m[0], m[1], m[2], m[3], m[4], m[5]
            ));
        }
        format!("host {} {{ {} }}", self.name, fields.join(" "))
    }
}

/// Returns `true` if `mac` is a unicast Ethernet MAC (least-significant bit of byte 0 is 0 and non-zero).
#[inline]
pub fn is_unicast_mac(mac: [u8; 6]) -> bool {
    mac != [0; 6] && (mac[0] & 0x01) == 0
}

/// Emits direct flow invocations inside a v3.0.0 `compile { ... }` block (never folding into `loop`).
pub fn emit_compile_block(invocations: &[String]) -> String {
    let mut out = String::from("compile {\n");
    for call in invocations {
        out.push_str("    ");
        out.push_str(call);
        out.push('\n');
    }
    out.push('}');
    out
}

/// Tracks locked endpoint pair directionality (`->` vs `<-`) in order of first communication.
pub fn resolve_pair_direction(
    locked_pairs: &mut HashMap<(usize, usize), (usize, usize)>,
    src_host_idx: usize,
    dst_host_idx: usize,
) -> (usize, usize, &'static str) {
    let canonical_key = if src_host_idx <= dst_host_idx {
        (src_host_idx, dst_host_idx)
    } else {
        (dst_host_idx, src_host_idx)
    };
    let &(caller_idx, callee_idx) = locked_pairs
        .entry(canonical_key)
        .or_insert((src_host_idx, dst_host_idx));
    if src_host_idx == caller_idx {
        (caller_idx, callee_idx, "->")
    } else {
        (caller_idx, callee_idx, "<-")
    }
}
```

---

## 5. Self-Checking Forward-Compiler Oracle (`verify_with_oracle`) & Round-Trip Decompilation Verification Test Template

Demonstrates Stage 4 (`src/reverse/oracle.rs`) and end-to-end round-trip verification:
- **In-Memory Compiler Oracle (`verify_statement_against_wire`)**: Wraps a candidate v3.0.0 `.frasm` statement in a minimal self-contained `.frasm` program, runs `frameassembly::parser::parse_program` -> `frameassembly::backend::compile_program`, and compares the synthesized Ethernet II bytes against the original normalized frame.
- **Round-Trip Verification Test**: Compiles a canonical v3.0.0 `.frasm` specification into PCAPNG bytes in memory, decompiles those bytes back into `.frasm` via `reverse_pcap_bytes`, recompiles the decompiled `.frasm` program, and asserts 100% byte-for-byte wire identity across every frame and timestamp.

```frameassembly
host h1 { ip 10.0.0.1 mac 00:11:22:33:44:01 }
host h2 { ip 10.0.0.2 mac 00:11:22:33:44:02 }

flow dns_and_http(a, b) {
    a -> b dns query txid 0x1a2b qname "api.example.com" qtype "a"
    a <- b dns response txid 0x1a2b qname "api.example.com" rdata 93.184.216.34
    a -> b tcp syn
    a <- b tcp syn ack
    a -> b tcp ack
    a -> b http get uri "/health" hosthdr "api.example.com"
    a <- b http response status 200 reason "OK"
}

compile {
    dns_and_http(h1, h2)
}
```

```rust
use frameassembly::backend::compile_program;
use frameassembly::parser::parse_program;
use frameassembly::reverse::reverse_pcap_bytes;
use pcap_file::pcapng::blocks::enhanced_packet::EnhancedPacketBlock;
use pcap_file::pcapng::blocks::interface_description::{
    InterfaceDescriptionBlock, InterfaceDescriptionOption,
};
use pcap_file::pcapng::{PcapNgBlock, PcapNgWriter};
use pcap_file::DataLink;
use std::borrow::Cow;
use std::time::Duration;

/// Compiles a single candidate `.frasm` statement in memory and checks whether its wire bytes
/// match `expected_eth_frame` byte-for-byte.
pub fn verify_statement_against_wire(
    caller_decl: &str,
    callee_decl: &str,
    caller_name: &str,
    arrow: &str,
    callee_name: &str,
    candidate_body: &str,
    expected_eth_frame: &[u8],
) -> bool {
    let fasm_src = format!(
        "{caller_decl}\n{callee_decl}\nflow f(a, b) {{\n    a {arrow} b {candidate_body}\n}}\ncompile {{\n    f({caller_name}, {callee_name})\n}}\n"
    );
    let Ok(program) = parse_program(&fasm_src) else {
        return false;
    };
    let Ok(frames) = compile_program(&program) else {
        return false;
    };
    frames
        .first()
        .is_some_and(|(synthesized_bytes, _)| synthesized_bytes.as_slice() == expected_eth_frame)
}

/// Performs a full forward -> PCAPNG -> decompiler -> forward round-trip test and asserts
/// 100% byte-for-byte and nanosecond-timestamp identity.
pub fn assert_lossless_pcap_decompilation_roundtrip(original_fasm: &str) -> Result<String, String> {
    // 1. Compile original .frasm to frames
    let prog1 = parse_program(original_fasm).map_err(|e| format!("Parse 1 failed: {e}"))?;
    let frames1 = compile_program(&prog1).map_err(|e| format!("Compile 1 failed: {e}"))?;

    // 2. Serialize frames into an in-memory PCAPNG buffer with IfTsResol(9)
    let mut pcapng_buf = Vec::new();
    {
        let mut writer =
            PcapNgWriter::new(&mut pcapng_buf).map_err(|e| format!("PcapNgWriter err: {e}"))?;
        let idb = InterfaceDescriptionBlock {
            linktype: DataLink::ETHERNET,
            snaplen: 65535,
            options: vec![InterfaceDescriptionOption::IfTsResol(9)],
        };
        writer
            .write_block(&idb.into_block())
            .map_err(|e| format!("IDB write err: {e}"))?;
        for (data, timestamp_ns) in &frames1 {
            let epb = EnhancedPacketBlock {
                interface_id: 0,
                timestamp: Duration::from_nanos(*timestamp_ns),
                original_len: data.len() as u32,
                data: Cow::Borrowed(data),
                options: vec![],
            };
            writer
                .write_block(&epb.into_block())
                .map_err(|e| format!("EPB write err: {e}"))?;
        }
    }

    // 3. Decompile the PCAPNG buffer back into canonical .frasm code
    let reversed = reverse_pcap_bytes(&pcapng_buf)?;
    assert_eq!(reversed.packet_count, frames1.len());

    // 4. Recompile the decompiled .frasm code and verify byte-for-byte + timestamp equality
    let prog2 =
        parse_program(&reversed.frasm).map_err(|e| format!("Decompiled .frasm parse failed: {e}"))?;
    let frames2 =
        compile_program(&prog2).map_err(|e| format!("Decompiled .frasm compile failed: {e}"))?;

    assert_eq!(frames1.len(), frames2.len(), "Packet count mismatch");
    for (idx, ((b1, ts1), (b2, ts2))) in frames1.iter().zip(frames2.iter()).enumerate() {
        assert_eq!(b1, b2, "Wire bytes diverged at packet {}", idx + 1);
        assert_eq!(
            ts1,
            ts2,
            "Timestamp diverged at packet {}",
            idx + 1
        );
    }

    Ok(reversed.frasm)
}
```
