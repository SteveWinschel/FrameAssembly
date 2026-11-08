//! Binary PCAP and PCAPNG container reader, linktype normalizer, and Ethernet padding/FCS stripper.
//!
//! This module implements Stage 1 of the FrameAssembly reverse decompiler (`frameassembly reverse`).
//! It inspects the leading 4-byte container magic number of any `std::io::Read` stream to dispatch
//! between Next-Generation Packet Capture (`PCAPNG`, Section Header Block `0x0A0D0D0A`) and legacy
//! `PCAP` (both microsecond `0xa1b2c3d4`/`0xd4c3b2a1` and nanosecond `0xa1b23c4d`/`0x4d3cb2a1`
//! magic variants). PCAPNG `InterfaceDescriptionBlock` `IfTsResol` (decimal $10^{-x}$ and binary
//! $2^{-x}$) and `IfTsOffset` options are scaled to nanosecond precision. Non-Ethernet link-layer
//! encapsulations (`RAW`, `IPV4`, `IPV6`, `LINUX_SLL`, `LINUX_SLL2`, `NULL`, and `LOOP`) are
//! normalized into canonical 14-byte Ethernet II frames, and 60/64-byte Ethernet zero padding and
//! 4-byte Frame Check Sequence (FCS) trailers are stripped using exact Layer 2 and Layer 3 header
//! length fields (`IPv4`, `IPv6`, `ARP`, `EAPOL`, `LLDP`, and IEEE 802.3 LLC length).

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use pcap_file::DataLink;
use pcap_file::pcap::PcapReader;
use pcap_file::pcapng::blocks::interface_description::InterfaceDescriptionOption;
use pcap_file::pcapng::{Block, PcapNgReader};

/// Per-interface metadata recorded from a PCAPNG `InterfaceDescriptionBlock`.
#[derive(Debug, Clone, Copy)]
struct InterfaceMeta {
    /// Link-layer encapsulation type for the interface.
    linktype: DataLink,
    /// Optional raw `if_tsresol` byte (bit 7 = binary $2^{-x}$ vs decimal $10^{-x}$, bits 0..6 = exponent).
    ts_resol: Option<u8>,
    /// Optional `if_tsoffset` seconds added to every packet timestamp on this interface.
    ts_offset_secs: u64,
}

impl Default for InterfaceMeta {
    fn default() -> Self {
        Self {
            linktype: DataLink::ETHERNET,
            ts_resol: None,
            ts_offset_secs: 0,
        }
    }
}

/// A single capture frame normalized to Ethernet II framing with nanosecond timestamp precision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NormalizedFrame {
    /// Capture timestamp in nanoseconds since the Unix epoch.
    pub timestamp_ns: u64,
    /// Normalized Ethernet II frame bytes with trailing zero-padding and 4-byte FCS stripped.
    pub eth_bytes: Vec<u8>,
    /// Whether the original capture linktype lacked Ethernet MAC headers (`RAW`/`IPV4`/`IPV6`/`NULL`/`LOOP`).
    pub is_l3_only: bool,
}

/// Reads all frames from a `.pcap` or `.pcapng` capture stream and normalizes them to Ethernet II.
///
/// # Errors
/// Returns a descriptive error string if the stream is shorter than 4 bytes, does not start with
/// a recognized PCAP or PCAPNG magic number, or contains corrupt container blocks.
pub(crate) fn read_capture_frames<R: std::io::Read>(
    mut reader: R,
) -> Result<Vec<NormalizedFrame>, String> {
    let mut buf = Vec::new();
    reader
        .read_to_end(&mut buf)
        .map_err(|e| alloc::format!("Failed to read capture stream: {}", e))?;

    if buf.len() < 4 {
        return Err(
            "Capture input is too short (< 4 bytes) to contain a PCAP or PCAPNG header".to_string(),
        );
    }

    let magic = [buf[0], buf[1], buf[2], buf[3]];
    match magic {
        [0x0A, 0x0D, 0x0D, 0x0A] => read_pcapng_bytes(&buf),
        [0xa1, 0xb2, 0xc3, 0xd4]
        | [0xd4, 0xc3, 0xb2, 0xa1]
        | [0xa1, 0xb2, 0x3c, 0x4d]
        | [0x4d, 0x3c, 0xb2, 0xa1] => read_legacy_pcap_bytes(&buf),
        _ => Err(alloc::format!(
            "Unrecognized capture magic bytes {:02x}{:02x}{:02x}{:02x} (expected PCAPNG 0a0d0d0a or legacy PCAP a1b2c3d4/a1b23c4d)",
            magic[0],
            magic[1],
            magic[2],
            magic[3]
        )),
    }
}

/// Scales raw 64-bit PCAPNG timestamp ticks to nanoseconds using the interface's `IfTsResol` and `IfTsOffset`.
fn scale_pcapng_ts_to_ns(raw_ticks: u64, meta: InterfaceMeta) -> u64 {
    let scaled_ns = match meta.ts_resol {
        Some(resol) => {
            let is_binary = (resol & 0x80) != 0;
            let exp = u32::from(resol & 0x7f);
            if !is_binary {
                if exp == 9 {
                    raw_ticks
                } else if exp < 9 {
                    let factor = 10u128.pow(9 - exp);
                    u128::from(raw_ticks)
                        .saturating_mul(factor)
                        .min(u128::from(u64::MAX)) as u64
                } else {
                    let divisor = 10u128.pow((exp - 9).min(18));
                    (u128::from(raw_ticks) / divisor) as u64
                }
            } else {
                let shift = exp.min(64);
                let prod = u128::from(raw_ticks).saturating_mul(1_000_000_000u128);
                let half = if shift > 0 { 1u128 << (shift - 1) } else { 0 };
                let rounded = prod.saturating_add(half);
                let shifted = if shift == 64 {
                    rounded >> 64
                } else {
                    rounded >> shift
                };
                shifted.min(u128::from(u64::MAX)) as u64
            }
        }
        None => {
            // Standard PCAPNG defaults `if_tsresol` to 6 (10^-6 s = microseconds) when omitted;
            // only raw nanosecond Unix-epoch ticks (>= 5*10^17) written without `IfTsResol(9)`
            // are already in nanoseconds.
            if raw_ticks < 500_000_000_000_000_000 {
                raw_ticks.saturating_mul(1_000)
            } else {
                raw_ticks
            }
        }
    };
    scaled_ns.saturating_add(meta.ts_offset_secs.saturating_mul(1_000_000_000))
}

/// Parses a PCAPNG byte buffer across one or more Section Header Blocks and interfaces.
fn read_pcapng_bytes(buf: &[u8]) -> Result<Vec<NormalizedFrame>, String> {
    let mut ng_reader = PcapNgReader::new(std::io::Cursor::new(buf))
        .map_err(|e| alloc::format!("Failed to initialize PCAPNG reader: {}", e))?;

    let mut interfaces: Vec<InterfaceMeta> = Vec::new();
    let mut frames: Vec<NormalizedFrame> = Vec::new();
    let mut last_timestamp_ns: u64 = 1_700_000_000_000_000_000;

    while let Some(block_res) = ng_reader.next_block() {
        let block = block_res.map_err(|e| alloc::format!("Failed to parse PCAPNG block: {}", e))?;
        match block {
            Block::SectionHeader(_) => {
                interfaces.clear();
            }
            Block::InterfaceDescription(idb) => {
                let mut ts_resol = None;
                let mut ts_offset_secs = 0u64;
                for opt in &idb.options {
                    match *opt {
                        InterfaceDescriptionOption::IfTsResol(r) => ts_resol = Some(r),
                        InterfaceDescriptionOption::IfTsOffset(off) => {
                            ts_offset_secs = off;
                        }
                        _ => {}
                    }
                }
                interfaces.push(InterfaceMeta {
                    linktype: idb.linktype,
                    ts_resol,
                    ts_offset_secs,
                });
            }
            Block::EnhancedPacket(epb) => {
                let meta = interfaces
                    .get(epb.interface_id as usize)
                    .copied()
                    .unwrap_or_default();
                let raw_ticks = epb.timestamp.as_nanos() as u64;
                let ts_ns = scale_pcapng_ts_to_ns(raw_ticks, meta);
                last_timestamp_ns = ts_ns;
                if let Some(frame) = normalize_frame(&epb.data, meta.linktype, ts_ns)? {
                    frames.push(frame);
                }
            }
            Block::SimplePacket(spb) => {
                let meta = interfaces.first().copied().unwrap_or_default();
                let ts_ns = last_timestamp_ns;
                if let Some(frame) = normalize_frame(&spb.data, meta.linktype, ts_ns)? {
                    frames.push(frame);
                }
            }
            Block::Packet(pb) => {
                let meta = interfaces
                    .get(pb.interface_id as usize)
                    .copied()
                    .unwrap_or_default();
                let ts_ns = scale_pcapng_ts_to_ns(pb.timestamp, meta);
                last_timestamp_ns = ts_ns;
                if let Some(frame) = normalize_frame(&pb.data, meta.linktype, ts_ns)? {
                    frames.push(frame);
                }
            }
            _ => {}
        }
    }

    Ok(frames)
}

/// Parses a legacy PCAP byte buffer (microsecond or nanosecond precision).
fn read_legacy_pcap_bytes(buf: &[u8]) -> Result<Vec<NormalizedFrame>, String> {
    let mut pcap_reader = PcapReader::new(std::io::Cursor::new(buf))
        .map_err(|e| alloc::format!("Failed to initialize legacy PCAP reader: {}", e))?;
    let linktype = pcap_reader.header().datalink;
    let mut frames = Vec::new();

    while let Some(pkt_res) = pcap_reader.next_packet() {
        let pkt = pkt_res.map_err(|e| alloc::format!("Failed to parse PCAP packet: {}", e))?;
        let ts_ns = pkt.timestamp.as_nanos() as u64;
        if let Some(frame) = normalize_frame(&pkt.data, linktype, ts_ns)? {
            frames.push(frame);
        }
    }

    Ok(frames)
}

/// Normalizes a single raw frame from `linktype` into a 14-byte Ethernet II frame and strips padding.
fn normalize_frame(
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
                return Err(alloc::format!(
                    "Truncated Ethernet frame of {} bytes (< 14 bytes)",
                    raw.len()
                ));
            }
            (raw.to_vec(), false)
        }
        DataLink::RAW | DataLink::IPV4 | DataLink::IPV6 => {
            let version = raw[0] >> 4;
            let ethertype: u16 = match version {
                4 => 0x0800,
                6 => 0x86DD,
                _ if linktype == DataLink::IPV6 => 0x86DD,
                _ => 0x0800,
            };
            let mut eth = Vec::with_capacity(14 + raw.len());
            eth.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x02]);
            eth.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x01]);
            eth.extend_from_slice(&ethertype.to_be_bytes());
            eth.extend_from_slice(raw);
            (eth, true)
        }
        DataLink::LINUX_SLL => {
            if raw.len() < 16 {
                return Err(alloc::format!(
                    "Truncated LINUX_SLL frame of {} bytes (< 16 bytes)",
                    raw.len()
                ));
            }
            let halen = u16::from_be_bytes([raw[4], raw[5]]) as usize;
            let src_mac = if halen == 6 {
                [raw[6], raw[7], raw[8], raw[9], raw[10], raw[11]]
            } else {
                [0x00, 0x00, 0x00, 0x00, 0x00, 0x01]
            };
            let dst_mac = [0x00, 0x00, 0x00, 0x00, 0x00, 0x02];
            let mut eth = Vec::with_capacity(14 + raw.len() - 16);
            eth.extend_from_slice(&dst_mac);
            eth.extend_from_slice(&src_mac);
            eth.extend_from_slice(&raw[14..16]);
            eth.extend_from_slice(&raw[16..]);
            (eth, halen != 6)
        }
        DataLink::LINUX_SLL2 => {
            if raw.len() < 20 {
                return Err(alloc::format!(
                    "Truncated LINUX_SLL2 frame of {} bytes (< 20 bytes)",
                    raw.len()
                ));
            }
            let halen = raw[10] as usize;
            let src_mac = if halen == 6 {
                [raw[12], raw[13], raw[14], raw[15], raw[16], raw[17]]
            } else {
                [0x00, 0x00, 0x00, 0x00, 0x00, 0x01]
            };
            let dst_mac = [0x00, 0x00, 0x00, 0x00, 0x00, 0x02];
            let mut eth = Vec::with_capacity(14 + raw.len() - 20);
            eth.extend_from_slice(&dst_mac);
            eth.extend_from_slice(&src_mac);
            eth.extend_from_slice(&raw[0..2]);
            eth.extend_from_slice(&raw[20..]);
            (eth, halen != 6)
        }
        DataLink::NULL | DataLink::LOOP => {
            if raw.len() < 4 {
                return Err(alloc::format!(
                    "Truncated BSD NULL/LOOP frame of {} bytes (< 4 bytes)",
                    raw.len()
                ));
            }
            let fam_le = u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]);
            let fam_be = u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]);
            let fam = if fam_le <= 0xFFFF { fam_le } else { fam_be };
            let ethertype: u16 = match fam {
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
            eth.extend_from_slice(&ethertype.to_be_bytes());
            eth.extend_from_slice(&raw[4..]);
            (eth, true)
        }
        other => {
            return Err(alloc::format!(
                "Unsupported capture linktype {:?} (supported: ETHERNET, RAW, IPV4, IPV6, LINUX_SLL, LINUX_SLL2, NULL, LOOP)",
                other
            ));
        }
    };

    let eth_bytes = strip_padding_and_fcs(eth_raw);
    Ok(Some(NormalizedFrame {
        timestamp_ns,
        eth_bytes,
        is_l3_only,
    }))
}

/// Checks whether `trailing` consists of Ethernet zero-padding or zero-padding plus a 4-byte FCS
/// trailer on a minimum-size (60 or 64 byte) Ethernet frame.
fn is_zero_padding_or_fcs(trailing: &[u8], total_frame_len: usize) -> bool {
    let all_zero = trailing.iter().all(|&b| b == 0);
    let zero_plus_fcs = (total_frame_len == 60 || total_frame_len == 64)
        && trailing.len() >= 4
        && trailing[..trailing.len() - 4].iter().all(|&b| b == 0);
    all_zero || zero_plus_fcs
}

/// Strips 60/64-byte Ethernet zero-padding and 4-byte FCS trailers using inner protocol length fields.
pub(crate) fn strip_padding_and_fcs(mut eth_bytes: Vec<u8>) -> Vec<u8> {
    if eth_bytes.len() < 14 {
        return eth_bytes;
    }

    let mut offset = 12usize;
    let mut et = u16::from_be_bytes([eth_bytes[offset], eth_bytes[offset + 1]]);
    offset += 2;

    // Advance past up to 2 IEEE 802.1Q / 802.1ad VLAN tags
    let mut vlan_tags = 0usize;
    while matches!(et, 0x8100 | 0x88A8 | 0x9100) && vlan_tags < 2 && offset + 4 <= eth_bytes.len() {
        et = u16::from_be_bytes([eth_bytes[offset + 2], eth_bytes[offset + 3]]);
        offset += 4;
        vlan_tags += 1;
    }

    // Advance past any MPLS shim stack (0x8847 unicast or 0x8848 multicast)
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
        0x0800 => {
            if l3_offset + 20 <= eth_bytes.len() {
                let ver = eth_bytes[l3_offset] >> 4;
                let ihl = ((eth_bytes[l3_offset] & 0x0f) as usize) * 4;
                let total_len =
                    u16::from_be_bytes([eth_bytes[l3_offset + 2], eth_bytes[l3_offset + 3]])
                        as usize;
                // Ignore TSO `total_len == 0`
                if ver == 4
                    && ihl >= 20
                    && total_len > 0
                    && total_len >= ihl
                    && l3_offset + total_len <= eth_bytes.len()
                {
                    eth_bytes.truncate(l3_offset + total_len);
                }
            }
        }
        0x86DD => {
            if l3_offset + 40 <= eth_bytes.len() && (eth_bytes[l3_offset] >> 4) == 6 {
                let payload_len =
                    u16::from_be_bytes([eth_bytes[l3_offset + 4], eth_bytes[l3_offset + 5]])
                        as usize;
                let next_hdr = eth_bytes[l3_offset + 6];
                if (payload_len > 0 || next_hdr != 0)
                    && l3_offset + 40 + payload_len <= eth_bytes.len()
                {
                    eth_bytes.truncate(l3_offset + 40 + payload_len);
                }
            }
        }
        0x0806 => {
            if l3_offset + 28 < eth_bytes.len() {
                let htype = u16::from_be_bytes([eth_bytes[l3_offset], eth_bytes[l3_offset + 1]]);
                let ptype =
                    u16::from_be_bytes([eth_bytes[l3_offset + 2], eth_bytes[l3_offset + 3]]);
                let hlen = eth_bytes[l3_offset + 4];
                let plen = eth_bytes[l3_offset + 5];
                if htype == 1
                    && ptype == 0x0800
                    && hlen == 6
                    && plen == 4
                    && is_zero_padding_or_fcs(&eth_bytes[l3_offset + 28..], eth_bytes.len())
                {
                    eth_bytes.truncate(l3_offset + 28);
                }
            }
        }
        0x888E => {
            if l3_offset + 4 <= eth_bytes.len() {
                let body_len =
                    u16::from_be_bytes([eth_bytes[l3_offset + 2], eth_bytes[l3_offset + 3]])
                        as usize;
                let end = l3_offset + 4 + body_len;
                if end < eth_bytes.len()
                    && is_zero_padding_or_fcs(&eth_bytes[end..], eth_bytes.len())
                {
                    eth_bytes.truncate(end);
                }
            }
        }
        0x88CC => {
            let mut pos = l3_offset;
            while pos + 2 <= eth_bytes.len() {
                let tlv_hdr = u16::from_be_bytes([eth_bytes[pos], eth_bytes[pos + 1]]);
                let tlv_type = tlv_hdr >> 9;
                let tlv_len = (tlv_hdr & 0x01FF) as usize;
                pos += 2;
                if tlv_type == 0 && tlv_len == 0 {
                    if pos < eth_bytes.len()
                        && is_zero_padding_or_fcs(&eth_bytes[pos..], eth_bytes.len())
                    {
                        eth_bytes.truncate(pos);
                    }
                    break;
                }
                if pos + tlv_len > eth_bytes.len() {
                    break;
                }
                pos += tlv_len;
            }
        }
        len if (1..=1500).contains(&len) => {
            let body_len = len as usize;
            if l3_offset + body_len <= eth_bytes.len() {
                eth_bytes.truncate(l3_offset + body_len);
            }
        }
        _ => {}
    }

    eth_bytes
}
