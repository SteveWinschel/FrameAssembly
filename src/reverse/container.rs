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

use alloc::borrow::Cow;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use pcap_file::DataLink;
use pcap_file::pcap::PcapReader;
use pcap_file::pcapng::blocks::enhanced_packet::EnhancedPacketOption;
use pcap_file::pcapng::blocks::interface_description::InterfaceDescriptionOption;
use pcap_file::pcapng::blocks::packet::PacketOption;
use pcap_file::pcapng::{Block, PcapNgReader};

/// Maximum capture byte size accepted from any capture file or stream (`256 MiB`).
pub(crate) const MAX_CAPTURE_BYTES: u64 = 256 * 1024 * 1024;

/// Maximum snapshot or packet capture length accepted per record (`256 KiB`).
pub(crate) const MAX_SNAPLEN: u32 = 262_144;

/// Maximum number of normalized packet frames processed per capture (`100_000`).
pub(crate) const MAX_REVERSE_FRAMES: usize = 100_000;

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
    /// Returns the default Ethernet II interface metadata with microsecond-fallback resolution.
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
    /// Whether the frame carried a valid trailing 4-byte IEEE 802.3 CRC-32 FCS (`fcs`).
    pub fcs: bool,
    /// Whether the frame carried an inverted trailing 4-byte IEEE 802.3 CRC-32 FCS (`badfcs`).
    pub bad_fcs: bool,
    /// Optional per-packet comment extracted from PCAPNG block options.
    pub comment: Option<String>,
}

/// Normalized container capture result pairing extracted frames with non-fatal container warnings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CaptureReadResult {
    /// Normalized Ethernet II frames extracted from the capture.
    pub frames: Vec<NormalizedFrame>,
    /// Non-fatal container warnings (e.g., skipped non-Ethernet interfaces or salvaged truncated EOF).
    pub warnings: Vec<String>,
}

/// Returns `true` when `linktype` is one of the 8 link-layer encapsulations normalized by FrameAssembly.
fn is_supported_linktype(linktype: DataLink) -> bool {
    matches!(
        linktype,
        DataLink::ETHERNET
            | DataLink::RAW
            | DataLink::IPV4
            | DataLink::IPV6
            | DataLink::LINUX_SLL
            | DataLink::LINUX_SLL2
            | DataLink::NULL
            | DataLink::LOOP
    )
}

/// Reads at most `max_bytes` from `reader`, failing cleanly if the stream exceeds `max_bytes`.
pub(crate) fn read_bounded_capture<R: std::io::Read>(
    reader: R,
    max_bytes: u64,
) -> Result<Vec<u8>, String> {
    use std::io::Read as _;
    let limit = max_bytes.saturating_add(1);
    let mut buf = Vec::new();
    reader
        .take(limit)
        .read_to_end(&mut buf)
        .map_err(|e| alloc::format!("Failed to read capture stream: {}", e))?;
    if (buf.len() as u64) > max_bytes {
        return Err(alloc::format!(
            "Capture stream exceeds maximum supported size of {} bytes",
            max_bytes
        ));
    }
    Ok(buf)
}

/// Concatenates non-empty PCAPNG comment option values into a single optional string.
fn join_non_empty_comments<'a>(comments: impl Iterator<Item = &'a str>) -> Option<String> {
    let mut joined = String::new();
    for comment in comments {
        if comment.is_empty() {
            continue;
        }
        if !joined.is_empty() {
            joined.push('\n');
        }
        joined.push_str(comment);
    }
    (!joined.is_empty()).then_some(joined)
}

/// Reads all frames and non-fatal warnings from a `.pcap` or `.pcapng` capture stream and normalizes them to Ethernet II.
///
/// # Errors
/// Returns a descriptive error string if the stream exceeds [`MAX_CAPTURE_BYTES`], exceeds [`MAX_SNAPLEN`] or
/// [`MAX_REVERSE_FRAMES`], is shorter than 4 bytes, does not start with a recognized PCAP or PCAPNG magic
/// number, or contains no supported/valid frames.
pub(crate) fn read_capture_frames_with_warnings<R: std::io::Read>(
    reader: R,
) -> Result<CaptureReadResult, String> {
    let buf = read_bounded_capture(reader, MAX_CAPTURE_BYTES)?;

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

/// Reads all frames from a `.pcap` or `.pcapng` capture stream and normalizes them to Ethernet II.
///
/// # Errors
/// Returns a descriptive error string if the stream exceeds [`MAX_CAPTURE_BYTES`], exceeds [`MAX_SNAPLEN`] or
/// [`MAX_REVERSE_FRAMES`], is shorter than 4 bytes, does not start with a recognized PCAP or PCAPNG magic
/// number, or contains corrupt container blocks.
#[allow(dead_code)]
pub(crate) fn read_capture_frames<R: std::io::Read>(
    reader: R,
) -> Result<Vec<NormalizedFrame>, String> {
    read_capture_frames_with_warnings(reader).map(|r| r.frames)
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

/// Pre-validates PCAPNG block snapshot/captured lengths against [`MAX_SNAPLEN`] and sanitizes
/// `InterfaceDescriptionBlock` options so `pcap-file`'s `PcapNgReader` does not reject standard
/// 4-byte `if_tzone` (`opt_code == 10`) options or panic on oversized `captured_len` arithmetic.
fn sanitize_pcapng_idb_options(buf: &[u8]) -> Result<Cow<'_, [u8]>, String> {
    let mut pos = 0usize;
    let mut is_be = false;
    let mut owned: Option<Vec<u8>> = None;

    while let Some(hdr) = buf.get(pos..pos.saturating_add(12)) {
        if hdr.len() < 12 {
            break;
        }
        let shb_candidate = [hdr[0], hdr[1], hdr[2], hdr[3]] == [0x0A, 0x0D, 0x0D, 0x0A];
        if shb_candidate {
            let bom = [hdr[8], hdr[9], hdr[10], hdr[11]];
            if bom == [0x1A, 0x2B, 0x3C, 0x4D] {
                is_be = true;
            } else if bom == [0x4D, 0x3C, 0x2B, 0x1A] {
                is_be = false;
            }
        }
        let read_u32 = |s: &[u8], o: usize, be: bool| -> u32 {
            let arr = [s[o], s[o + 1], s[o + 2], s[o + 3]];
            if be {
                u32::from_be_bytes(arr)
            } else {
                u32::from_le_bytes(arr)
            }
        };
        let read_u16 = |s: &[u8], o: usize, be: bool| -> u16 {
            let arr = [s[o], s[o + 1]];
            if be {
                u16::from_be_bytes(arr)
            } else {
                u16::from_le_bytes(arr)
            }
        };

        let block_type = read_u32(buf, pos, is_be);
        let total_len = read_u32(buf, pos + 4, is_be) as usize;
        if total_len < 12 {
            break;
        }

        // Guard IDB snaplen and packet block captured lengths before `pcap-file` parses or wraps `captured_len + pad`.
        if block_type == 1 && pos.saturating_add(16) <= buf.len() {
            let snaplen = read_u32(buf, pos + 12, is_be);
            if snaplen > MAX_SNAPLEN {
                return Err(alloc::format!(
                    "PCAPNG interface snaplen {} exceeds maximum allowed {} bytes",
                    snaplen,
                    MAX_SNAPLEN
                ));
            }
        } else if matches!(block_type, 2 | 6) && pos.saturating_add(24) <= buf.len() {
            let captured_len = read_u32(buf, pos + 20, is_be);
            if captured_len > MAX_SNAPLEN {
                return Err(alloc::format!(
                    "PCAPNG packet captured length {} exceeds maximum allowed {} bytes",
                    captured_len,
                    MAX_SNAPLEN
                ));
            }
        } else if block_type == 3 && total_len >= 16 && (total_len - 16) > MAX_SNAPLEN as usize {
            return Err(alloc::format!(
                "PCAPNG simple packet length {} exceeds maximum allowed {} bytes",
                total_len - 16,
                MAX_SNAPLEN
            ));
        }

        let Some(block_end) = pos.checked_add(total_len) else {
            break;
        };
        if block_end > buf.len() {
            break;
        }

        // Interface Description Block (`0x00000001`): 8B header + 8B fixed body + options + 4B trailer
        if block_type == 1 && total_len >= 20 {
            let mut opt_pos = pos + 16;
            let opts_end = block_end - 4;
            while opt_pos.saturating_add(4) <= opts_end {
                let opt_code = read_u16(buf, opt_pos, is_be);
                let opt_len = read_u16(buf, opt_pos + 2, is_be) as usize;
                if opt_code == 0 && opt_len == 0 {
                    break;
                }
                if opt_code == 10 && opt_len != 1 {
                    let vec = owned.get_or_insert_with(|| buf.to_vec());
                    let repl = if is_be {
                        0x7FFFu16.to_be_bytes()
                    } else {
                        0x7FFFu16.to_le_bytes()
                    };
                    vec[opt_pos..opt_pos + 2].copy_from_slice(&repl);
                }
                let padded = (opt_len + 3) & !3;
                let Some(next_opt) = opt_pos.checked_add(4).and_then(|v| v.checked_add(padded))
                else {
                    break;
                };
                if next_opt > opts_end {
                    break;
                }
                opt_pos = next_opt;
            }
        }

        pos = block_end;
    }

    Ok(match owned {
        Some(v) => Cow::Owned(v),
        None => Cow::Borrowed(buf),
    })
}

/// Parses a PCAPNG byte buffer across one or more Section Header Blocks and interfaces.
fn read_pcapng_bytes(buf: &[u8]) -> Result<CaptureReadResult, String> {
    let clean_buf = sanitize_pcapng_idb_options(buf)?;
    let mut ng_reader = PcapNgReader::new(std::io::Cursor::new(clean_buf.as_ref()))
        .map_err(|e| alloc::format!("Failed to initialize PCAPNG reader: {}", e))?;

    let mut interfaces: Vec<InterfaceMeta> = Vec::new();
    let mut skipped_per_iface: Vec<usize> = Vec::new();
    let mut frames: Vec<NormalizedFrame> = Vec::new();
    let mut warnings: Vec<String> = Vec::new();
    let mut last_timestamp_ns: u64 = 1_700_000_000_000_000_000;

    while let Some(block_res) = ng_reader.next_block() {
        let block = match block_res {
            Ok(b) => b,
            Err(e) => {
                if !frames.is_empty() {
                    warnings.push(alloc::format!(
                        "Capture ended with a truncated trailing PCAPNG block ({}); salvaged {} preceding packet(s)",
                        e,
                        frames.len()
                    ));
                    break;
                }
                return Err(alloc::format!("Failed to parse PCAPNG block: {}", e));
            }
        };
        match block {
            Block::SectionHeader(_) => {
                for (idx, &count) in skipped_per_iface.iter().enumerate() {
                    if count > 0
                        && let Some(meta) = interfaces.get(idx)
                    {
                        warnings.push(alloc::format!(
                            "Skipped {} packet(s) on unsupported PCAPNG interface #{} ({:?})",
                            count,
                            idx,
                            meta.linktype
                        ));
                    }
                }
                interfaces.clear();
                skipped_per_iface.clear();
            }
            Block::InterfaceDescription(idb) => {
                if idb.snaplen > MAX_SNAPLEN {
                    return Err(alloc::format!(
                        "PCAPNG interface snaplen {} exceeds maximum allowed {} bytes",
                        idb.snaplen,
                        MAX_SNAPLEN
                    ));
                }
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
                skipped_per_iface.push(0);
            }
            Block::EnhancedPacket(epb) => {
                if epb.data.len() > MAX_SNAPLEN as usize {
                    return Err(alloc::format!(
                        "PCAPNG packet length {} exceeds maximum allowed {} bytes",
                        epb.data.len(),
                        MAX_SNAPLEN
                    ));
                }
                let iface_idx = epb.interface_id as usize;
                let meta = interfaces.get(iface_idx).copied().unwrap_or_default();
                let raw_ticks = epb.timestamp.as_nanos() as u64;
                let ts_ns = scale_pcapng_ts_to_ns(raw_ticks, meta);
                last_timestamp_ns = ts_ns;
                if !is_supported_linktype(meta.linktype) {
                    if let Some(slot) = skipped_per_iface.get_mut(iface_idx) {
                        *slot += 1;
                    }
                    continue;
                }
                let comment = join_non_empty_comments(epb.options.iter().filter_map(|opt| {
                    match opt {
                        EnhancedPacketOption::Comment(c) => Some(c.as_ref()),
                        _ => None,
                    }
                }));
                if let Some(mut frame) = normalize_frame(&epb.data, meta.linktype, ts_ns)? {
                    if frames.len() >= MAX_REVERSE_FRAMES {
                        return Err(alloc::format!(
                            "Capture exceeds maximum supported limit of {} frames",
                            MAX_REVERSE_FRAMES
                        ));
                    }
                    frame.comment = comment;
                    frames.push(frame);
                }
            }
            Block::SimplePacket(spb) => {
                if spb.data.len() > MAX_SNAPLEN as usize {
                    return Err(alloc::format!(
                        "PCAPNG simple packet length {} exceeds maximum allowed {} bytes",
                        spb.data.len(),
                        MAX_SNAPLEN
                    ));
                }
                let meta = interfaces.first().copied().unwrap_or_default();
                let ts_ns = last_timestamp_ns;
                if !is_supported_linktype(meta.linktype) {
                    if let Some(slot) = skipped_per_iface.first_mut() {
                        *slot += 1;
                    }
                    continue;
                }
                if let Some(frame) = normalize_frame(&spb.data, meta.linktype, ts_ns)? {
                    if frames.len() >= MAX_REVERSE_FRAMES {
                        return Err(alloc::format!(
                            "Capture exceeds maximum supported limit of {} frames",
                            MAX_REVERSE_FRAMES
                        ));
                    }
                    frames.push(frame);
                }
            }
            Block::Packet(pb) => {
                if pb.data.len() > MAX_SNAPLEN as usize {
                    return Err(alloc::format!(
                        "PCAPNG packet length {} exceeds maximum allowed {} bytes",
                        pb.data.len(),
                        MAX_SNAPLEN
                    ));
                }
                let iface_idx = pb.interface_id as usize;
                let meta = interfaces.get(iface_idx).copied().unwrap_or_default();
                let ts_ns = scale_pcapng_ts_to_ns(pb.timestamp, meta);
                last_timestamp_ns = ts_ns;
                if !is_supported_linktype(meta.linktype) {
                    if let Some(slot) = skipped_per_iface.get_mut(iface_idx) {
                        *slot += 1;
                    }
                    continue;
                }
                let comment = join_non_empty_comments(pb.options.iter().filter_map(|opt| {
                    match opt {
                        PacketOption::Comment(c) => Some(c.as_ref()),
                        _ => None,
                    }
                }));
                if let Some(mut frame) = normalize_frame(&pb.data, meta.linktype, ts_ns)? {
                    if frames.len() >= MAX_REVERSE_FRAMES {
                        return Err(alloc::format!(
                            "Capture exceeds maximum supported limit of {} frames",
                            MAX_REVERSE_FRAMES
                        ));
                    }
                    frame.comment = comment;
                    frames.push(frame);
                }
            }
            _ => {}
        }
    }

    if !interfaces.is_empty() && !interfaces.iter().any(|m| is_supported_linktype(m.linktype)) {
        let first_lt = interfaces[0].linktype;
        return Err(alloc::format!(
            "Unsupported capture linktype {:?} (supported: ETHERNET, RAW, IPV4, IPV6, LINUX_SLL, LINUX_SLL2, NULL, LOOP)",
            first_lt
        ));
    }

    for (idx, &count) in skipped_per_iface.iter().enumerate() {
        if count > 0
            && let Some(meta) = interfaces.get(idx)
        {
            warnings.push(alloc::format!(
                "Skipped {} packet(s) on unsupported PCAPNG interface #{} ({:?})",
                count,
                idx,
                meta.linktype
            ));
        }
    }

    Ok(CaptureReadResult { frames, warnings })
}

/// Validates classic `.pcap` `snaplen`/`incl_len` bounds against [`MAX_SNAPLEN`] and widens a
/// classic `.pcap` global header `snaplen` (`bytes 16..20`) when bounded records carry `orig_len > snaplen`
/// (such as `tcpdump -s 96` captures rejected by `pcap-file`'s header check).
fn widen_legacy_pcap_snaplen(buf: &[u8]) -> Result<Cow<'_, [u8]>, String> {
    if buf.len() < 24 {
        return Ok(Cow::Borrowed(buf));
    }
    let is_be = matches!(buf[0], 0xa1);
    let read_u32 = |o: usize| -> u32 {
        let arr = [buf[o], buf[o + 1], buf[o + 2], buf[o + 3]];
        if is_be {
            u32::from_be_bytes(arr)
        } else {
            u32::from_le_bytes(arr)
        }
    };
    let hdr_snaplen = read_u32(16);
    if hdr_snaplen > MAX_SNAPLEN {
        return Err(alloc::format!(
            "PCAP header snaplen {} exceeds maximum allowed {} bytes",
            hdr_snaplen,
            MAX_SNAPLEN
        ));
    }
    let mut max_needed = hdr_snaplen;
    let mut pos = 24usize;
    while pos.saturating_add(16) <= buf.len() {
        let incl_len = read_u32(pos + 8);
        if incl_len > MAX_SNAPLEN {
            return Err(alloc::format!(
                "PCAP packet captured length {} exceeds maximum allowed {} bytes",
                incl_len,
                MAX_SNAPLEN
            ));
        }
        let orig_len = read_u32(pos + 12);
        max_needed = max_needed.max(incl_len).max(orig_len.min(MAX_SNAPLEN));
        let Some(next_pos) = pos.checked_add(16).and_then(|v| v.checked_add(incl_len as usize))
        else {
            break;
        };
        if next_pos > buf.len() {
            break;
        }
        pos = next_pos;
    }
    if max_needed > hdr_snaplen {
        let mut copy = buf.to_vec();
        let bytes = if is_be {
            max_needed.to_be_bytes()
        } else {
            max_needed.to_le_bytes()
        };
        copy[16..20].copy_from_slice(&bytes);
        Ok(Cow::Owned(copy))
    } else {
        Ok(Cow::Borrowed(buf))
    }
}

/// Parses a legacy PCAP byte buffer (microsecond or nanosecond precision).
fn read_legacy_pcap_bytes(buf: &[u8]) -> Result<CaptureReadResult, String> {
    let clean_buf = widen_legacy_pcap_snaplen(buf)?;
    let mut pcap_reader = PcapReader::new(std::io::Cursor::new(clean_buf.as_ref()))
        .map_err(|e| alloc::format!("Failed to initialize legacy PCAP reader: {}", e))?;
    let linktype = pcap_reader.header().datalink;
    if !is_supported_linktype(linktype) {
        return Err(alloc::format!(
            "Unsupported capture linktype {:?} (supported: ETHERNET, RAW, IPV4, IPV6, LINUX_SLL, LINUX_SLL2, NULL, LOOP)",
            linktype
        ));
    }
    let mut frames = Vec::new();
    let mut warnings = Vec::new();

    while let Some(pkt_res) = pcap_reader.next_packet() {
        let pkt = match pkt_res {
            Ok(p) => p,
            Err(e) => {
                if !frames.is_empty() {
                    warnings.push(alloc::format!(
                        "Capture ended with a truncated trailing PCAP record ({}); salvaged {} preceding packet(s)",
                        e,
                        frames.len()
                    ));
                    break;
                }
                return Err(alloc::format!("Failed to parse PCAP packet: {}", e));
            }
        };
        if pkt.data.len() > MAX_SNAPLEN as usize {
            return Err(alloc::format!(
                "PCAP packet length {} exceeds maximum allowed {} bytes",
                pkt.data.len(),
                MAX_SNAPLEN
            ));
        }
        let ts_ns = pkt.timestamp.as_nanos() as u64;
        if let Some(frame) = normalize_frame(&pkt.data, linktype, ts_ns)? {
            if frames.len() >= MAX_REVERSE_FRAMES {
                return Err(alloc::format!(
                    "Capture exceeds maximum supported limit of {} frames",
                    MAX_REVERSE_FRAMES
                ));
            }
            frames.push(frame);
        }
    }

    Ok(CaptureReadResult { frames, warnings })
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
            let ethertype: u16 = match linktype {
                DataLink::IPV4 => 0x0800,
                DataLink::IPV6 => 0x86DD,
                _ => match raw[0] >> 4 {
                    6 => 0x86DD,
                    _ => 0x0800,
                },
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
            let pkt_type = u16::from_be_bytes([raw[0], raw[1]]);
            let halen = u16::from_be_bytes([raw[4], raw[5]]) as usize;
            let src_mac = if halen == 6 {
                [raw[6], raw[7], raw[8], raw[9], raw[10], raw[11]]
            } else {
                [0x00, 0x00, 0x00, 0x00, 0x00, 0x01]
            };
            let dst_mac = if pkt_type == 1 {
                [0xff, 0xff, 0xff, 0xff, 0xff, 0xff]
            } else {
                [0x00, 0x00, 0x00, 0x00, 0x00, 0x02]
            };
            let proto = u16::from_be_bytes([raw[14], raw[15]]);
            let payload_len = raw.len() - 16;
            let et_bytes = if matches!(proto, 0x0001 | 0x0004) && (1..=1500).contains(&payload_len) {
                (payload_len as u16).to_be_bytes()
            } else {
                [raw[14], raw[15]]
            };
            let mut eth = Vec::with_capacity(14 + payload_len);
            eth.extend_from_slice(&dst_mac);
            eth.extend_from_slice(&src_mac);
            eth.extend_from_slice(&et_bytes);
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
            // Tcpdump LINKTYPE_LINUX_SLL2 stores `packet_type` (0..=4) at byte 10 and `halen` at byte 11;
            // keep a narrow fallback for legacy test vectors that stored `halen == 6` at byte 10 with byte 11 == 0.
            let real_sll2 = raw[11] > 0;
            let halen = if real_sll2 {
                raw[11] as usize
            } else if raw[10] == 6 {
                6
            } else {
                0
            };
            let src_mac = if halen == 6 {
                [raw[12], raw[13], raw[14], raw[15], raw[16], raw[17]]
            } else {
                [0x00, 0x00, 0x00, 0x00, 0x00, 0x01]
            };
            let dst_mac = if real_sll2 && raw[10] == 1 {
                [0xff, 0xff, 0xff, 0xff, 0xff, 0xff]
            } else {
                [0x00, 0x00, 0x00, 0x00, 0x00, 0x02]
            };
            let proto = u16::from_be_bytes([raw[0], raw[1]]);
            let payload_len = raw.len() - 20;
            let et_bytes = if matches!(proto, 0x0001 | 0x0004) && (1..=1500).contains(&payload_len) {
                (payload_len as u16).to_be_bytes()
            } else {
                [raw[0], raw[1]]
            };
            let mut eth = Vec::with_capacity(14 + payload_len);
            eth.extend_from_slice(&dst_mac);
            eth.extend_from_slice(&src_mac);
            eth.extend_from_slice(&et_bytes);
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
            let fam = if linktype == DataLink::LOOP {
                if fam_be <= 0xFFFF { fam_be } else { fam_le }
            } else if fam_le <= 0xFFFF {
                fam_le
            } else {
                fam_be
            };
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

    let (eth_bytes, fcs, bad_fcs) = strip_padding_and_fcs_with_fcs(eth_raw, !is_l3_only);
    Ok(Some(NormalizedFrame {
        timestamp_ns,
        eth_bytes,
        is_l3_only,
        fcs,
        bad_fcs,
        comment: None,
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

/// Classifies a 4-byte trailing slice as a valid IEEE 802.3 CRC-32 (`fcs`) or bitwise-inverted (`badfcs`).
fn classify_4b_fcs(body: &[u8], trailer: &[u8]) -> (bool, bool) {
    if trailer.len() != 4 {
        return (false, false);
    }
    let wire = u32::from_le_bytes([trailer[0], trailer[1], trailer[2], trailer[3]]);
    let crc = crate::packet::ieee8023_crc32(body);
    if wire == crc {
        (true, false)
    } else if wire == (crc ^ 0xFFFF_FFFF) {
        (false, true)
    } else {
        (false, false)
    }
}

/// Returns `true` when `eth_bytes[end..]` is an exact 4-byte valid or bitwise-inverted IEEE 802.3 FCS.
fn is_exact_4b_fcs(eth_bytes: &[u8], end: usize) -> bool {
    eth_bytes.len() == end.saturating_add(4)
        && !matches!(
            classify_4b_fcs(&eth_bytes[..end], &eth_bytes[end..]),
            (false, false)
        )
}

/// Strips 60/64-byte Ethernet zero-padding and 4-byte FCS trailers using inner protocol length fields.
#[allow(dead_code)]
pub(crate) fn strip_padding_and_fcs(eth_bytes: Vec<u8>) -> Vec<u8> {
    strip_padding_and_fcs_with_fcs(eth_bytes, false).0
}

/// Strips Ethernet zero-padding and 4-byte FCS trailers while optionally classifying IEEE 802.3 CRC-32 status.
fn strip_padding_and_fcs_with_fcs(
    mut eth_bytes: Vec<u8>,
    detect_fcs: bool,
) -> (Vec<u8>, bool, bool) {
    if eth_bytes.len() < 14 {
        return (eth_bytes, false, false);
    }

    let mut offset = 12usize;
    let mut et = u16::from_be_bytes([eth_bytes[offset], eth_bytes[offset + 1]]);
    offset += 2;

    // Advance past up to 16 stacked IEEE 802.1Q / 802.1ad VLAN tags (matching `l2/vlan.rs`).
    let mut vlan_tags = 0usize;
    while matches!(et, 0x8100 | 0x88A8 | 0x9100) && vlan_tags < 16 && offset + 4 <= eth_bytes.len() {
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
                _ => {
                    // Check for RFC 4448 EoMPLS 4-byte zero control word + 14-byte Ethernet header.
                    if let Some(cw_end) = offset.checked_add(18)
                        && cw_end <= eth_bytes.len()
                        && eth_bytes[offset..offset + 4] == [0x00, 0x00, 0x00, 0x00]
                    {
                        let inner_et =
                            u16::from_be_bytes([eth_bytes[offset + 16], eth_bytes[offset + 17]]);
                        if matches!(
                            inner_et,
                            0x0800 | 0x86DD | 0x0806 | 0x888E | 0x88CC | 0x8809 | 1..=1500
                        ) {
                            et = inner_et;
                            offset = cw_end;
                        }
                    }
                }
            }
        }
    }

    let l3_offset = offset;
    let mut protocol_len_known = false;
    let mut target_len: Option<usize> = None;

    match et {
        0x0800 => {
            if let Some(hdr_end) = l3_offset.checked_add(20)
                && hdr_end <= eth_bytes.len()
            {
                let ver = eth_bytes[l3_offset] >> 4;
                let ihl = ((eth_bytes[l3_offset] & 0x0f) as usize) * 4;
                let total_len =
                    u16::from_be_bytes([eth_bytes[l3_offset + 2], eth_bytes[l3_offset + 3]])
                        as usize;
                // Ignore TSO `total_len == 0`
                if ver == 4
                    && ihl >= 20
                    && total_len >= ihl
                    && let Some(end) = l3_offset.checked_add(total_len)
                    && end <= eth_bytes.len()
                {
                    protocol_len_known = true;
                    if end < eth_bytes.len() {
                        target_len = Some(end);
                    }
                }
            }
        }
        0x86DD => {
            if let Some(hdr_end) = l3_offset.checked_add(40)
                && hdr_end <= eth_bytes.len()
                && (eth_bytes[l3_offset] >> 4) == 6
            {
                let payload_len =
                    u16::from_be_bytes([eth_bytes[l3_offset + 4], eth_bytes[l3_offset + 5]])
                        as usize;
                let next_hdr = eth_bytes[l3_offset + 6];
                if (payload_len > 0 || next_hdr != 0)
                    && let Some(end) = hdr_end.checked_add(payload_len)
                    && end <= eth_bytes.len()
                {
                    protocol_len_known = true;
                    if end < eth_bytes.len() {
                        target_len = Some(end);
                    }
                }
            }
        }
        0x0806 => {
            if let Some(end) = l3_offset.checked_add(28)
                && end <= eth_bytes.len()
            {
                let htype = u16::from_be_bytes([eth_bytes[l3_offset], eth_bytes[l3_offset + 1]]);
                let ptype =
                    u16::from_be_bytes([eth_bytes[l3_offset + 2], eth_bytes[l3_offset + 3]]);
                let hlen = eth_bytes[l3_offset + 4];
                let plen = eth_bytes[l3_offset + 5];
                if htype == 1 && ptype == 0x0800 && hlen == 6 && plen == 4 {
                    protocol_len_known = true;
                    if end < eth_bytes.len()
                        && (is_zero_padding_or_fcs(&eth_bytes[end..], eth_bytes.len())
                            || (detect_fcs && is_exact_4b_fcs(&eth_bytes, end)))
                    {
                        target_len = Some(end);
                    }
                }
            }
        }
        0x888E => {
            if let Some(hdr_end) = l3_offset.checked_add(4)
                && hdr_end <= eth_bytes.len()
            {
                let body_len =
                    u16::from_be_bytes([eth_bytes[l3_offset + 2], eth_bytes[l3_offset + 3]])
                        as usize;
                if let Some(end) = hdr_end.checked_add(body_len)
                    && end <= eth_bytes.len()
                {
                    protocol_len_known = true;
                    if end < eth_bytes.len()
                        && (is_zero_padding_or_fcs(&eth_bytes[end..], eth_bytes.len())
                            || (detect_fcs && is_exact_4b_fcs(&eth_bytes, end)))
                    {
                        target_len = Some(end);
                    }
                }
            }
        }
        0x8809 => {
            if let Some(end) = l3_offset.checked_add(110)
                && end <= eth_bytes.len()
                && eth_bytes[l3_offset..].starts_with(&[0x01, 0x01])
            {
                protocol_len_known = true;
                if end < eth_bytes.len()
                    && (is_zero_padding_or_fcs(&eth_bytes[end..], eth_bytes.len())
                        || (detect_fcs && is_exact_4b_fcs(&eth_bytes, end)))
                {
                    target_len = Some(end);
                }
            }
        }
        0x88CC => {
            let mut pos = l3_offset;
            while let Some(next_hdr) = pos.checked_add(2)
                && next_hdr <= eth_bytes.len()
            {
                let tlv_hdr = u16::from_be_bytes([eth_bytes[pos], eth_bytes[pos + 1]]);
                let tlv_type = tlv_hdr >> 9;
                let tlv_len = (tlv_hdr & 0x01FF) as usize;
                pos = next_hdr;
                if tlv_type == 0 && tlv_len == 0 {
                    protocol_len_known = true;
                    if pos < eth_bytes.len()
                        && (is_zero_padding_or_fcs(&eth_bytes[pos..], eth_bytes.len())
                            || (detect_fcs && is_exact_4b_fcs(&eth_bytes, pos)))
                    {
                        target_len = Some(pos);
                    }
                    break;
                }
                let Some(next_pos) = pos.checked_add(tlv_len) else {
                    break;
                };
                if next_pos > eth_bytes.len() {
                    break;
                }
                pos = next_pos;
            }
        }
        len if (1..=1500).contains(&len) => {
            if let Some(end) = l3_offset.checked_add(len as usize)
                && end <= eth_bytes.len()
            {
                protocol_len_known = true;
                if end < eth_bytes.len() {
                    target_len = Some(end);
                }
            }
        }
        _ => {}
    }

    let mut fcs = false;
    let mut bad_fcs = false;
    let orig_len = eth_bytes.len();
    if let Some(end) = target_len {
        if detect_fcs {
            if orig_len == end.saturating_add(4) {
                (fcs, bad_fcs) = classify_4b_fcs(&eth_bytes[..end], &eth_bytes[end..]);
            } else if orig_len == 64 && end < 60 && eth_bytes[end..60].iter().all(|&b| b == 0) {
                (fcs, bad_fcs) = classify_4b_fcs(&eth_bytes[..60], &eth_bytes[60..64]);
            }
        }
        eth_bytes.truncate(end);
    } else if detect_fcs && !protocol_len_known && orig_len >= 18 {
        let body_end = orig_len - 4;
        let (is_good, is_bad) = classify_4b_fcs(&eth_bytes[..body_end], &eth_bytes[body_end..]);
        if is_good || is_bad {
            fcs = is_good;
            bad_fcs = is_bad;
            eth_bytes.truncate(body_end);
        }
    }

    (eth_bytes, fcs, bad_fcs)
}
