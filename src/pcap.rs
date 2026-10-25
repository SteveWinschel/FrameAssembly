//! PCAP Next Generation (`PCAPNG`) file writer and packet block serialization engine.
//!
//! This module wraps `pcap_file::pcapng::PcapNgWriter` via [`PcapWriter`] to emit standards-compliant
//! `.pcap` and `.pcapng` network capture files. It automatically initializes an Ethernet (`LINKTYPE_ETHERNET`)
//! `InterfaceDescriptionBlock` configured with a 65,535-byte snapshot length and `IfTsResol(9)`
//! nanosecond timestamp resolution (`10^-9` seconds), writing each synthesized frame as an
//! `EnhancedPacketBlock`.

use pcap_file::pcapng::PcapNgBlock;
use pcap_file::pcapng::PcapNgWriter;
use pcap_file::pcapng::blocks::enhanced_packet::EnhancedPacketBlock;
use pcap_file::pcapng::blocks::interface_description::{
    InterfaceDescriptionBlock, InterfaceDescriptionOption,
};
use std::borrow::Cow;
use std::fs::File;
use std::io::{self, Error};

/// A writer wrapper for generating `PCAPNG` format files.
///
/// This struct uses `pcap_file` to write standard network capture files with an
/// initialized Ethernet interface block.
///
/// # Examples
/// ```no_run
/// use frameassembly::pcap::PcapWriter;
///
/// let writer = PcapWriter::create("test.pcap").unwrap();
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
    /// let writer = PcapWriter::create("output.pcap").unwrap();
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
            linktype: pcap_file::DataLink::ETHERNET,
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
    /// let mut writer = PcapWriter::create("output.pcap").unwrap();
    /// writer.write_packet(&[0u8; 64], 1_000_000_000).unwrap();
    /// ```
    ///
    /// # Errors
    /// Returns an `io::Error` if the packet block cannot be written to the file.
    pub fn write_packet(&mut self, packet_data: &[u8], ts_nanos_total: u64) -> io::Result<()> {
        let length = packet_data.len() as u32;

        let epb = EnhancedPacketBlock {
            interface_id: 0,
            timestamp: std::time::Duration::from_nanos(ts_nanos_total),
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
