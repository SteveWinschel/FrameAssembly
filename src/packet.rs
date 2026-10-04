use alloc::string::ToString;
use alloc::vec::Vec;
use core::net::IpAddr;
use etherparse::{PacketBuilder, TcpHeader};

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

    let builder = PacketBuilder::ethernet2(src_mac, dst_mac)
        .ipv4(src_v4, dst_v4, 64)
        .tcp_header(tcp_header);

    let mut result = Vec::with_capacity(builder.size(payload_bytes.len()));
    builder.write(&mut result, payload_bytes).map_err(|e| {
        CompilerError::BackendError(alloc::format!("Failed to write TCP packet: {}", e))
    })?;

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

    let builder = PacketBuilder::ethernet2(src_mac, dst_mac)
        .ipv4(src_v4, dst_v4, 64)
        .udp(src_port, dst_port);

    let mut result = Vec::with_capacity(builder.size(payload_bytes.len()));
    builder.write(&mut result, payload_bytes).map_err(|e| {
        CompilerError::BackendError(alloc::format!("Failed to write UDP packet: {}", e))
    })?;

    Ok(result)
}
