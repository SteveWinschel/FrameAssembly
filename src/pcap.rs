//! Classic libpcap (`.pcap`) and PCAP Next Generation (`PCAPNG`, `.pcapng`) serialization engine.
//!
//! This module emits standards-compliant `.pcap` and `.pcapng` network capture files over
//! Ethernet (`LINKTYPE_ETHERNET`, 65,535-byte snapshot length). Output paths ending with `.pcap`
//! (case-insensitive) emit classic libpcap captures via [`serialize_classic_pcap`] (automatically
//! selecting nanosecond resolution when any frame timestamp contains sub-microsecond precision, or
//! microsecond resolution otherwise), while `.pcapng` and other extensions emit `PCAPNG` captures
//! with `IfTsResol(9)` nanosecond resolution via [`serialize_pcapng`] and [`PcapWriter`].

use pcap_file::pcap::{PcapHeader, PcapPacket, PcapWriter as ClassicPcapWriter};
use pcap_file::pcapng::PcapNgBlock;
use pcap_file::pcapng::PcapNgWriter;
use pcap_file::pcapng::blocks::enhanced_packet::EnhancedPacketBlock;
use pcap_file::pcapng::blocks::interface_description::{
    InterfaceDescriptionBlock, InterfaceDescriptionOption,
};
use pcap_file::{DataLink, TsResolution};
use std::borrow::Cow;
use std::fs::File;
use std::io::{self, Error};
use std::time::Duration;

/// Serializes `(frame_bytes, timestamp_ns)` tuples into an in-memory classic libpcap (`.pcap`) buffer.
///
/// Uses `TsResolution::NanoSecond` if any frame timestamp is not an exact multiple of `1,000 ns`,
/// or `TsResolution::MicroSecond` otherwise, with `DataLink::ETHERNET` and `snaplen = 65535`.
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
    let ts_resolution = if frames.iter().any(|(_, ts)| ts % 1_000 != 0) {
        TsResolution::NanoSecond
    } else {
        TsResolution::MicroSecond
    };
    let header = PcapHeader {
        datalink: DataLink::ETHERNET,
        snaplen: 65535,
        ts_resolution,
        ..PcapHeader::default()
    };
    let total_payload: usize = frames.iter().map(|(f, _)| 16 + f.len()).sum();
    let mut buf = Vec::with_capacity(24 + total_payload);
    let mut writer = ClassicPcapWriter::with_header(&mut buf, header)
        .map_err(|e| alloc::format!("Failed to initialize classic PCAP writer: {}", e))?;

    for (packet_data, ts_nanos_total) in frames {
        let orig_len = u32::try_from(packet_data.len())
            .map_err(|_| "Frame exceeds maximum 32-bit PCAP packet length".to_string())?;
        let pkt = PcapPacket {
            timestamp: Duration::from_nanos(*ts_nanos_total),
            orig_len,
            data: Cow::Borrowed(packet_data.as_slice()),
        };
        writer
            .write_packet(&pkt)
            .map_err(|e| alloc::format!("Failed to write classic PCAP packet: {}", e))?;
    }
    Ok(buf)
}

/// Serializes `(frame_bytes, timestamp_ns)` tuples into an in-memory `PCAPNG` (`.pcapng`) buffer.
///
/// Emits a `SectionHeaderBlock`, an Ethernet `InterfaceDescriptionBlock` (`snaplen = 65535`,
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
    let total_payload: usize = frames.iter().map(|(f, _)| 32 + f.len()).sum();
    let mut buf = Vec::with_capacity(128 + total_payload);
    let mut writer = PcapNgWriter::new(&mut buf)
        .map_err(|e| alloc::format!("Failed to initialize PCAPNG writer: {}", e))?;

    let interface = InterfaceDescriptionBlock {
        linktype: DataLink::ETHERNET,
        snaplen: 65535,
        options: vec![InterfaceDescriptionOption::IfTsResol(9)],
    };
    writer
        .write_block(&interface.into_block())
        .map_err(|e| alloc::format!("Failed to write PCAPNG interface block: {}", e))?;

    for (packet_data, ts_nanos_total) in frames {
        let original_len = u32::try_from(packet_data.len())
            .map_err(|_| "Frame exceeds maximum 32-bit PCAPNG packet length".to_string())?;
        let epb = EnhancedPacketBlock {
            interface_id: 0,
            timestamp: Duration::from_nanos(*ts_nanos_total),
            original_len,
            data: Cow::Borrowed(packet_data.as_slice()),
            options: vec![],
        };
        writer
            .write_block(&epb.into_block())
            .map_err(|e| alloc::format!("Failed to write PCAPNG packet block: {}", e))?;
    }
    Ok(buf)
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
            snaplen: 65535,
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
    /// Returns an `io::Error` if the packet block cannot be written to the file.
    pub fn write_packet(&mut self, packet_data: &[u8], ts_nanos_total: u64) -> io::Result<()> {
        let length = packet_data.len() as u32;

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
    fn test_serialize_pcapng_shb_magic() {
        let ng = serialize_pcapng(&[(vec![0u8; 60], 0)]).unwrap();
        assert_eq!(&ng[0..4], &[0x0A, 0x0D, 0x0D, 0x0A]);
    }
}
