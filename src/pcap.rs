use std::fs::File;
use std::io::{self, Write};

/// A simple zero-dependency PCAP writer.
pub struct PcapWriter {
    file: File,
}

impl PcapWriter {
    /// Creates a new PCAP file and writes the global header.
    pub fn create(path: &str) -> io::Result<Self> {
        let mut file = File::create(path)?;
        
        // PCAP Global Header (24 bytes)
        // Magic Number: a1b2c3d4 (microsecond resolution)
        // Version Major: 2, Version Minor: 4
        // Thiszone: 0, Sigfigs: 0
        // Snaplen: 65535
        // Network: 1 (Ethernet)
        let global_header: [u8; 24] = [
            0xd4, 0xc3, 0xb2, 0xa1, 
            0x02, 0x00, 0x04, 0x00, 
            0x00, 0x00, 0x00, 0x00, 
            0x00, 0x00, 0x00, 0x00, 
            0xff, 0xff, 0x00, 0x00, 
            0x01, 0x00, 0x00, 0x00, 
        ];
        
        file.write_all(&global_header)?;
        Ok(Self { file })
    }

    /// Writes a single packet record to the PCAP file.
    pub fn write_packet(&mut self, packet_data: &[u8], ts_usec_total: u64) -> io::Result<()> {
        let ts_sec = (ts_usec_total / 1_000_000) as u32;
        let ts_usec = (ts_usec_total % 1_000_000) as u32;
        let length = packet_data.len() as u32;

        // PCAP Record Header (16 bytes)
        self.file.write_all(&ts_sec.to_le_bytes())?;
        self.file.write_all(&ts_usec.to_le_bytes())?;
        self.file.write_all(&length.to_le_bytes())?; // incl_len
        self.file.write_all(&length.to_le_bytes())?; // orig_len
        
        // Packet Data
        self.file.write_all(packet_data)?;
        
        Ok(())
    }
}
