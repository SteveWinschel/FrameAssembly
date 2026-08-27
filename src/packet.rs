use alloc::vec::Vec;
use core::net::IpAddr;

/// A simple packet builder for the FrameAssembly prototype.
/// Hardcodes MAC addresses and uses dummy values where acceptable for a zero-dependency prototype.

const DUMMY_MAC_SRC: [u8; 6] = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
const DUMMY_MAC_DST: [u8; 6] = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];

/// Build a raw TCP/IPv4/Ethernet frame.
pub fn build_tcp_packet(
    src_ip: IpAddr,
    src_port: u16,
    dst_ip: IpAddr,
    dst_port: u16,
    syn: bool,
    ack: bool,
    seq: Option<u32>,
    win: Option<u16>,
    payload: Option<&[u8]>,
    reverse_macs: bool,
) -> Vec<u8> {
    let mut packet = Vec::new();

    // --- Ethernet Header (14 bytes) ---
    if reverse_macs {
        packet.extend_from_slice(&DUMMY_MAC_SRC); // Destination MAC
        packet.extend_from_slice(&DUMMY_MAC_DST); // Source MAC
    } else {
        packet.extend_from_slice(&DUMMY_MAC_DST); // Destination MAC
        packet.extend_from_slice(&DUMMY_MAC_SRC); // Source MAC
    }
    packet.extend_from_slice(&[0x08, 0x00]);  // EtherType (IPv4)

    // Ensure we only handle IPv4 for this prototype
    let (src_v4, dst_v4) = match (src_ip, dst_ip) {
        (IpAddr::V4(s), IpAddr::V4(d)) => (s.octets(), d.octets()),
        _ => panic!("Only IPv4 is supported in this prototype"),
    };

    let payload_bytes = payload.unwrap_or(&[]);
    let payload_len = payload_bytes.len() as u16;

    // --- IPv4 Header (20 bytes) ---
    let ip_header_len = 20;
    let tcp_header_len = 20;
    let total_len = ip_header_len + tcp_header_len + payload_len;

    packet.push(0x45); // Version (4) + IHL (5 words)
    packet.push(0x00); // DSCP + ECN
    packet.extend_from_slice(&total_len.to_be_bytes()); // Total Length
    packet.extend_from_slice(&[0x00, 0x00]); // Identification
    packet.extend_from_slice(&[0x40, 0x00]); // Flags + Fragment Offset (Don't fragment)
    packet.push(64); // TTL
    packet.push(6);  // Protocol (TCP)
    packet.extend_from_slice(&[0x00, 0x00]); // Header Checksum (dummy)
    packet.extend_from_slice(&src_v4); // Source IP
    packet.extend_from_slice(&dst_v4); // Destination IP

    // Calculate and update IP checksum
    let ip_checksum = calculate_checksum(&packet[14..34]);
    packet[24..26].copy_from_slice(&ip_checksum.to_be_bytes());

    // --- TCP Header (20 bytes) ---
    packet.extend_from_slice(&src_port.to_be_bytes()); // Source Port
    packet.extend_from_slice(&dst_port.to_be_bytes()); // Destination Port
    
    let seq_num = seq.unwrap_or(0);
    packet.extend_from_slice(&seq_num.to_be_bytes()); // Sequence Number
    packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // Acknowledgment Number
    
    // Data Offset (5 words = 20 bytes) + Flags
    let data_offset = 0x50; // 5 << 4
    let mut flags = 0u8;
    if syn { flags |= 0x02; }
    if ack { flags |= 0x10; }
    
    packet.push(data_offset);
    packet.push(flags);
    
    let window_size = win.unwrap_or(64240);
    packet.extend_from_slice(&window_size.to_be_bytes()); // Window Size
    packet.extend_from_slice(&[0x00, 0x00]); // Checksum (dummy)
    packet.extend_from_slice(&[0x00, 0x00]); // Urgent Pointer

    // --- Payload ---
    packet.extend_from_slice(payload_bytes);

    // Calculate and update TCP Checksum
    let mut tcp_checksum_data = Vec::new();
    tcp_checksum_data.extend_from_slice(&src_v4);
    tcp_checksum_data.extend_from_slice(&dst_v4);
    tcp_checksum_data.push(0); // Reserved
    tcp_checksum_data.push(6); // Protocol TCP
    let tcp_len = tcp_header_len + payload_len;
    tcp_checksum_data.extend_from_slice(&tcp_len.to_be_bytes());
    tcp_checksum_data.extend_from_slice(&packet[34..]); // TCP Header + Payload
    
    let tcp_checksum = calculate_checksum(&tcp_checksum_data);
    packet[50..52].copy_from_slice(&tcp_checksum.to_be_bytes());

    packet
}

/// Calculates the RFC-1071 Internet Checksum
fn calculate_checksum(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut chunks = data.chunks_exact(2);
    
    // Sum all 16-bit words
    for chunk in chunks.by_ref() {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    
    // If there is an odd byte left over, pad it with a zero
    if let Some(&b) = chunks.remainder().first() {
        sum += u16::from_be_bytes([b, 0]) as u32;
    }
    
    // Fold 32-bit sum into 16 bits
    while (sum >> 16) > 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    
    // One's complement (bitwise NOT)
    !(sum as u16)
}
