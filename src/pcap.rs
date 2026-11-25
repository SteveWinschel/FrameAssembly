//! Classic libpcap (`.pcap`) and PCAP Next Generation (`PCAPNG`, `.pcapng`) serialization engine.
//!
//! This module emits standards-compliant `.pcap` and `.pcapng` network capture files over
//! Ethernet (`LINKTYPE_ETHERNET`, 262,144-byte snapshot length). Output paths ending with `.pcap`
//! (case-insensitive) emit classic libpcap captures via [`serialize_classic_pcap`] (automatically
//! selecting nanosecond resolution when any frame timestamp contains sub-microsecond precision, or
//! microsecond resolution otherwise), while `.pcapng` and other extensions emit `PCAPNG` captures
//! with `IfTsResol(9)` nanosecond resolution via [`serialize_pcapng`], [`serialize_pcapng_with_metadata`],
//! and [`PcapWriter`].

use pcap_file::pcap::{PcapHeader, PcapPacket, PcapWriter as ClassicPcapWriter};
use pcap_file::pcapng::PcapNgBlock;
use pcap_file::pcapng::PcapNgWriter;
use pcap_file::pcapng::blocks::enhanced_packet::{EnhancedPacketBlock, EnhancedPacketOption};
use pcap_file::pcapng::blocks::interface_description::{
    InterfaceDescriptionBlock, InterfaceDescriptionOption,
};
use pcap_file::pcapng::blocks::name_resolution::{
    Ipv4Record, Ipv6Record, NameResolutionBlock, Record,
};
use pcap_file::{DataLink, TsResolution};
use std::borrow::Cow;
use std::fs::File;
use std::io::{self, Error};
use std::net::IpAddr;
use std::time::Duration;

/// Default capture snapshot length (256 KiB, matching modern Wireshark/dumpcap defaults).
const DEFAULT_SNAPLEN: u32 = 262_144;

/// Serializes `(frame_bytes, timestamp_ns)` items into an in-memory classic libpcap (`.pcap`) buffer.
fn serialize_classic_pcap_slice<'a, I>(frames: I, count: usize, payload_hint: usize) -> Result<Vec<u8>, String>
where
    I: Iterator<Item = (&'a [u8], u64)> + Clone,
{
    let ts_resolution = if frames.clone().any(|(_, ts)| ts % 1_000 != 0) {
        TsResolution::NanoSecond
    } else {
        TsResolution::MicroSecond
    };
    let header = PcapHeader {
        datalink: DataLink::ETHERNET,
        snaplen: DEFAULT_SNAPLEN,
        ts_resolution,
        ..PcapHeader::default()
    };
    let mut buf = Vec::with_capacity(24 + count * 16 + payload_hint);
    let mut writer = ClassicPcapWriter::with_header(&mut buf, header)
        .map_err(|e| alloc::format!("Failed to initialize classic PCAP writer: {}", e))?;

    for (packet_data, ts_nanos_total) in frames {
        let orig_len = u32::try_from(packet_data.len())
            .map_err(|_| "Frame exceeds maximum 32-bit PCAP packet length".to_string())?;
        let pkt = PcapPacket {
            timestamp: Duration::from_nanos(ts_nanos_total),
            orig_len,
            data: Cow::Borrowed(packet_data),
        };
        writer
            .write_packet(&pkt)
            .map_err(|e| alloc::format!("Failed to write classic PCAP packet: {}", e))?;
    }
    Ok(buf)
}

/// Serializes `(frame_bytes, timestamp_ns)` tuples into an in-memory classic libpcap (`.pcap`) buffer.
///
/// Uses `TsResolution::NanoSecond` if any frame timestamp is not an exact multiple of `1,000 ns`,
/// or `TsResolution::MicroSecond` otherwise, with `DataLink::ETHERNET` and `snaplen = 262144`.
///
/// # Examples
/// ```
/// use frameassembly::pcap::serialize_classic_pcap;
///
/// let bytes = serialize_classic_pcap(&[(vec![0u8; 60], 0)]).unwrap();
/// assert!(bytes.len() >= 24 + 16 + 60);
/// ```
///
/// # Errors
/// Returns a descriptive `String` error if header or packet serialization fails.
pub fn serialize_classic_pcap(frames: &[(Vec<u8>, u64)]) -> Result<Vec<u8>, String> {
    let payload_hint: usize = frames.iter().map(|(f, _)| f.len()).sum();
    serialize_classic_pcap_slice(
        frames.iter().map(|(f, ts)| (f.as_slice(), *ts)),
        frames.len(),
        payload_hint,
    )
}

/// Serializes frame slices with optional packet comments and host NRB records into `PCAPNG`.
fn serialize_pcapng_iter<'a, I>(
    frames: I,
    count: usize,
    payload_hint: usize,
    hosts: &[(String, IpAddr)],
) -> Result<Vec<u8>, String>
where
    I: Iterator<Item = (&'a [u8], u64, Option<&'a str>)>,
{
    let mut buf = Vec::with_capacity(128 + count * 32 + payload_hint);
    let mut writer = PcapNgWriter::new(&mut buf)
        .map_err(|e| alloc::format!("Failed to initialize PCAPNG writer: {}", e))?;

    let interface = InterfaceDescriptionBlock {
        linktype: DataLink::ETHERNET,
        snaplen: DEFAULT_SNAPLEN,
        options: vec![InterfaceDescriptionOption::IfTsResol(9)],
    };
    writer
        .write_block(&interface.into_block())
        .map_err(|e| alloc::format!("Failed to write PCAPNG interface block: {}", e))?;

    if !hosts.is_empty() {
        let mut records = Vec::with_capacity(hosts.len());
        for (name, ip) in hosts {
            if name.is_empty() {
                continue;
            }
            let record = match ip {
                IpAddr::V4(v4) => Record::Ipv4(Ipv4Record {
                    ip_addr: Cow::Owned(v4.octets().to_vec()),
                    names: vec![Cow::Borrowed(name.as_str())],
                }),
                IpAddr::V6(v6) => Record::Ipv6(Ipv6Record {
                    ip_addr: Cow::Owned(v6.octets().to_vec()),
                    names: vec![Cow::Borrowed(name.as_str())],
                }),
            };
            records.push(record);
        }
        if !records.is_empty() {
            let nrb = NameResolutionBlock {
                records,
                options: vec![],
            };
            writer
                .write_block(&nrb.into_block())
                .map_err(|e| alloc::format!("Failed to write PCAPNG name resolution block: {}", e))?;
        }
    }

    for (packet_data, ts_nanos_total, comment) in frames {
        let original_len = u32::try_from(packet_data.len())
            .map_err(|_| "Frame exceeds maximum 32-bit PCAPNG packet length".to_string())?;
        let options = match comment {
            Some(c) if !c.is_empty() => vec![EnhancedPacketOption::Comment(Cow::Borrowed(c))],
            _ => vec![],
        };
        let epb = EnhancedPacketBlock {
            interface_id: 0,
            timestamp: Duration::from_nanos(ts_nanos_total),
            original_len,
            data: Cow::Borrowed(packet_data),
            options,
        };
        writer
            .write_block(&epb.into_block())
            .map_err(|e| alloc::format!("Failed to write PCAPNG packet block: {}", e))?;
    }
    Ok(buf)
}

/// Serializes `(frame_bytes, timestamp_ns)` tuples into an in-memory `PCAPNG` (`.pcapng`) buffer.
///
/// Emits a `SectionHeaderBlock`, an Ethernet `InterfaceDescriptionBlock` (`snaplen = 262144`,
/// `IfTsResol(9)` nanosecond resolution), and one `EnhancedPacketBlock` per frame.
///
/// # Examples
/// ```
/// use frameassembly::pcap::serialize_pcapng;
///
/// let bytes = serialize_pcapng(&[(vec![0u8; 60], 0)]).unwrap();
/// assert_eq!(&bytes[0..4], &[0x0A, 0x0D, 0x0D, 0x0A]);
/// ```
///
/// # Errors
/// Returns a descriptive `String` error if block serialization fails.
pub fn serialize_pcapng(frames: &[(Vec<u8>, u64)]) -> Result<Vec<u8>, String> {
    let payload_hint: usize = frames.iter().map(|(f, _)| f.len()).sum();
    serialize_pcapng_iter(
        frames.iter().map(|(f, ts)| (f.as_slice(), *ts, None)),
        frames.len(),
        payload_hint,
        &[],
    )
}

/// Serializes `(frame_bytes, timestamp_ns, comment)` tuples into an in-memory `PCAPNG` buffer,
/// emitting a `NameResolutionBlock` for declared host IP mappings and per-packet `Comment` options.
///
/// # Errors
/// Returns a descriptive `String` error if block serialization fails.
pub fn serialize_pcapng_with_metadata(
    frames: &[(Vec<u8>, u64, Option<String>)],
    hosts: &[(String, IpAddr)],
) -> Result<Vec<u8>, String> {
    let payload_hint: usize = frames.iter().map(|(f, _, _)| f.len()).sum();
    serialize_pcapng_iter(
        frames
            .iter()
            .map(|(f, ts, c)| (f.as_slice(), *ts, c.as_deref())),
        frames.len(),
        payload_hint,
        hosts,
    )
}

/// Writes `(frame_bytes, timestamp_ns)` tuples to `path`, selecting classic libpcap (`.pcap`) when
/// `path` ends with `.pcap` (case-insensitive) and `PCAPNG` otherwise.
///
/// # Errors
/// Returns a descriptive `String` error if serialization or file writing fails.
pub fn write_capture_file(frames: &[(Vec<u8>, u64)], path: &str) -> Result<(), String> {
    let is_classic_pcap =
        path.len() >= 5 && path.as_bytes()[path.len() - 5..].eq_ignore_ascii_case(b".pcap");
    let bytes = if is_classic_pcap {
        serialize_classic_pcap(frames)?
    } else {
        serialize_pcapng(frames)?
    };
    std::fs::write(path, &bytes)
        .map_err(|e| alloc::format!("Failed to write capture file '{}': {}", path, e))
}

/// Writes `(frame_bytes, timestamp_ns, comment)` tuples and host IP mappings to `path`, selecting
/// classic libpcap (`.pcap`) when `path` ends with `.pcap` (case-insensitive) and metadata-rich
/// `PCAPNG` otherwise.
///
/// # Errors
/// Returns a descriptive `String` error if serialization or file writing fails.
pub fn write_capture_file_with_metadata(
    frames: &[(Vec<u8>, u64, Option<String>)],
    hosts: &[(String, IpAddr)],
    path: &str,
) -> Result<(), String> {
    let is_classic_pcap =
        path.len() >= 5 && path.as_bytes()[path.len() - 5..].eq_ignore_ascii_case(b".pcap");
    let bytes = if is_classic_pcap {
        let payload_hint: usize = frames.iter().map(|(f, _, _)| f.len()).sum();
        serialize_classic_pcap_slice(
            frames.iter().map(|(f, ts, _)| (f.as_slice(), *ts)),
            frames.len(),
            payload_hint,
        )?
    } else {
        serialize_pcapng_with_metadata(frames, hosts)?
    };
    std::fs::write(path, &bytes)
        .map_err(|e| alloc::format!("Failed to write capture file '{}': {}", path, e))
}

/// A streaming writer wrapper for generating `PCAPNG` format files.
///
/// This struct uses `pcap_file` to write standard `PCAPNG` network capture files with an
/// initialized Ethernet interface block and `IfTsResol(9)` nanosecond resolution.
///
/// # Examples
/// ```no_run
/// use frameassembly::pcap::PcapWriter;
///
/// let writer = PcapWriter::create("test.pcapng").unwrap();
/// ```
pub struct PcapWriter {
    /// The underlying pcap-file writer.
    writer: PcapNgWriter<File>,
}

impl PcapWriter {
    /// Creates a new `PcapWriter` at the specified file path.
    ///
    /// This initializes the file and writes the necessary `PCAPNG` interface description block
    /// with nanosecond timestamp resolution.
    ///
    /// # Examples
    /// ```no_run
    /// use frameassembly::pcap::PcapWriter;
    ///
    /// let writer = PcapWriter::create("output.pcapng").unwrap();
    /// ```
    ///
    /// # Errors
    /// Returns an `io::Error` if:
    /// * The file cannot be created.
    /// * The initial `PCAPNG` interface block cannot be written.
    pub fn create(path: &str) -> io::Result<Self> {
        let file = File::create(path)?;
        let mut writer = PcapNgWriter::new(file)
            .map_err(|e| Error::other(alloc::format!("Failed to create PCAP writer: {}", e)))?;

        let interface = InterfaceDescriptionBlock {
            linktype: DataLink::ETHERNET,
            snaplen: DEFAULT_SNAPLEN,
            options: vec![InterfaceDescriptionOption::IfTsResol(9)],
        };
        writer.write_block(&interface.into_block()).map_err(|e| {
            Error::other(alloc::format!(
                "Failed to write PCAP interface block: {}",
                e
            ))
        })?;

        Ok(Self { writer })
    }

    /// Writes a single network packet to the `PCAPNG` file.
    ///
    /// # Examples
    /// ```no_run
    /// use frameassembly::pcap::PcapWriter;
    ///
    /// let mut writer = PcapWriter::create("output.pcapng").unwrap();
    /// writer.write_packet(&[0u8; 64], 1_000_000_000).unwrap();
    /// ```
    ///
    /// # Errors
    /// Returns an `io::Error` if the packet length exceeds 32-bit PCAPNG bounds or the packet
    /// block cannot be written to the file.
    pub fn write_packet(&mut self, packet_data: &[u8], ts_nanos_total: u64) -> io::Result<()> {
        let length = u32::try_from(packet_data.len()).map_err(|_| {
            Error::new(
                io::ErrorKind::InvalidInput,
                "Frame exceeds maximum 32-bit PCAPNG packet length",
            )
        })?;

        let epb = EnhancedPacketBlock {
            interface_id: 0,
            timestamp: Duration::from_nanos(ts_nanos_total),
            original_len: length,
            data: Cow::Borrowed(packet_data),
            options: vec![],
        };
        self.writer.write_block(&epb.into_block()).map_err(|e| {
            Error::other(alloc::format!("Failed to write PCAP packet block: {}", e))
        })?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::net::Ipv4Addr;

    #[test]
    fn test_serialize_classic_pcap_usec_and_nsec_magic() {
        let usec = serialize_classic_pcap(&[(vec![0u8; 60], 1_000_000)]).unwrap();
        assert!(matches!(
            &usec[0..4],
            [0xd4, 0xc3, 0xb2, 0xa1] | [0xa1, 0xb2, 0xc3, 0xd4]
        ));

        let nsec = serialize_classic_pcap(&[(vec![0u8; 60], 1_500)]).unwrap();
        assert!(matches!(
            &nsec[0..4],
            [0x4d, 0x3c, 0xb2, 0xa1] | [0xa1, 0xb2, 0x3c, 0x4d]
        ));
    }

    #[test]
    fn test_serialize_pcapng_shb_magic_and_metadata_blocks() {
        let ng = serialize_pcapng(&[(vec![0u8; 60], 0)]).unwrap();
        assert_eq!(&ng[0..4], &[0x0A, 0x0D, 0x0D, 0x0A]);

        let frames = vec![(vec![0u8; 60], 1_000, Some("SYN probe".to_string()))];
        let hosts = vec![("cli".to_string(), IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)))];
        let meta = serialize_pcapng_with_metadata(&frames, &hosts).unwrap();
        assert_eq!(&meta[0..4], &[0x0A, 0x0D, 0x0D, 0x0A]);
        assert!(meta.windows(3).any(|w| w == b"cli"));
        assert!(meta.windows(9).any(|w| w == b"SYN probe"));
    }
}
