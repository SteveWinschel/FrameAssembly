use alloc::string::ToString;
use alloc::vec::Vec;
use core::net::IpAddr;
use etherparse::{Ethernet2Header, Ipv4Header, TcpHeader, UdpHeader, EtherType, IpNumber};

use crate::error::CompilerError;

#[allow(clippy::too_many_arguments)]
pub fn build_tcp_packet(
    src_ip: IpAddr,
    src_port: u16,
    dst_ip: IpAddr,
    dst_port: u16,
    syn: bool,
    ack: bool,
    seq: Option<u32>,
    ack_num: Option<u32>,
    win: Option<u16>,
    payload: Option<&[u8]>,
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
) -> Result<Vec<u8>, CompilerError> {
    let payload_bytes = payload.unwrap_or(&[]);

    let (src_v4, dst_v4) = match (src_ip, dst_ip) {
        (IpAddr::V4(s), IpAddr::V4(d)) => (s.octets(), d.octets()),
        _ => {
            return Err(CompilerError::BackendError(
                "Only IPv4 is supported".to_string(),
            ));
        }
    };

    let mut tcp_header = TcpHeader::new(src_port, dst_port, seq.unwrap_or(0), win.unwrap_or(64240));
    tcp_header.syn = syn;
    tcp_header.ack = ack;
    tcp_header.acknowledgment_number = ack_num.unwrap_or(0);

    let ip_header = Ipv4Header::new(
        tcp_header.header_len() as u16 + payload_bytes.len() as u16,
        64,
        IpNumber::TCP,
        src_v4,
        dst_v4,
    ).map_err(|e| CompilerError::BackendError(alloc::format!("Failed to create IP header: {}", e)))?;

    tcp_header.checksum = tcp_header.calc_checksum_ipv4(&ip_header, payload_bytes)
        .map_err(|e| CompilerError::BackendError(alloc::format!("Failed to calculate TCP checksum: {}", e)))?;

    let eth_header = Ethernet2Header {
        source: src_mac,
        destination: dst_mac,
        ether_type: EtherType::IPV4,
    };

    let mut result = Vec::with_capacity(
        eth_header.header_len() + ip_header.header_len() + tcp_header.header_len() + payload_bytes.len()
    );

    eth_header.write(&mut result).map_err(|e| {
        CompilerError::BackendError(alloc::format!("Failed to write ETH header: {}", e))
    })?;
    ip_header.write(&mut result).map_err(|e| {
        CompilerError::BackendError(alloc::format!("Failed to write IP header: {}", e))
    })?;
    tcp_header.write(&mut result).map_err(|e| {
        CompilerError::BackendError(alloc::format!("Failed to write TCP header: {}", e))
    })?;
    result.extend_from_slice(payload_bytes);

    Ok(result)
}

pub fn build_udp_packet(
    src_ip: IpAddr,
    src_port: u16,
    dst_ip: IpAddr,
    dst_port: u16,
    payload: Option<&[u8]>,
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
) -> Result<Vec<u8>, CompilerError> {
    let payload_bytes = payload.unwrap_or(&[]);

    let (src_v4, dst_v4) = match (src_ip, dst_ip) {
        (IpAddr::V4(s), IpAddr::V4(d)) => (s.octets(), d.octets()),
        _ => {
            return Err(CompilerError::BackendError(
                "Only IPv4 is supported".to_string(),
            ));
        }
    };

    let mut udp_header = UdpHeader::without_ipv4_checksum(src_port, dst_port, payload_bytes.len())
        .map_err(|e| CompilerError::BackendError(alloc::format!("Failed to create UDP header: {}", e)))?;

    let ip_header = Ipv4Header::new(
        udp_header.header_len() as u16 + payload_bytes.len() as u16,
        64,
        IpNumber::UDP,
        src_v4,
        dst_v4,
    ).map_err(|e| CompilerError::BackendError(alloc::format!("Failed to create IP header: {}", e)))?;

    udp_header.checksum = udp_header.calc_checksum_ipv4(&ip_header, payload_bytes)
        .map_err(|e| CompilerError::BackendError(alloc::format!("Failed to calculate UDP checksum: {}", e)))?;

    let eth_header = Ethernet2Header {
        source: src_mac,
        destination: dst_mac,
        ether_type: EtherType::IPV4,
    };

    let mut result = Vec::with_capacity(
        eth_header.header_len() + ip_header.header_len() + udp_header.header_len() + payload_bytes.len()
    );

    eth_header.write(&mut result).map_err(|e| {
        CompilerError::BackendError(alloc::format!("Failed to write ETH header: {}", e))
    })?;
    ip_header.write(&mut result).map_err(|e| {
        CompilerError::BackendError(alloc::format!("Failed to write IP header: {}", e))
    })?;
    udp_header.write(&mut result).map_err(|e| {
        CompilerError::BackendError(alloc::format!("Failed to write UDP header: {}", e))
    })?;
    result.extend_from_slice(payload_bytes);

    Ok(result)
}
