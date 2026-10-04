use pcap_file::pcapng::PcapNgBlock;
use pcap_file::pcapng::PcapNgWriter;
use pcap_file::pcapng::blocks::enhanced_packet::EnhancedPacketBlock;
use pcap_file::pcapng::blocks::interface_description::{
    InterfaceDescriptionBlock, InterfaceDescriptionOption,
};
use std::borrow::Cow;
use std::fs::File;
use std::io::{self, Error};

pub struct PcapWriter {
    writer: PcapNgWriter<File>,
}

impl PcapWriter {
    pub fn create(path: &str) -> io::Result<Self> {
        let file = File::create(path)?;
        let mut writer = PcapNgWriter::new(file).map_err(|e| {
            Error::other(alloc::format!("Failed to create PCAP writer: {}", e))
        })?;

        let interface = InterfaceDescriptionBlock {
            linktype: pcap_file::DataLink::ETHERNET,
            snaplen: 65535,
            options: vec![InterfaceDescriptionOption::IfTsResol(9)],
        };
        writer.write_block(&interface.into_block()).map_err(|e| {
            Error::other(alloc::format!("Failed to write PCAP interface block: {}", e))
        })?;

        Ok(Self { writer })
    }

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
