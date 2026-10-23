//! Stream Control Transmission Protocol (SCTP) wire builder and CRC32c engine.

use crate::ast::*;
use crate::builders::WireContext;
use crate::error::CompilerError;
use alloc::vec::Vec;

/// Precomputed Castagnoli CRC32c table (polynomial 0x1EDC6F41, reflected 0x82F63B78).
const CRC32C_TABLE: [u32; 256] = {
    let mut table = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut crc = i as u32;
        let mut j = 0;
        while j < 8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0x82F6_3B78;
            } else {
                crc >>= 1;
            }
            j += 1;
        }
        table[i] = crc;
        i += 1;
    }
    table
};

/// Computes the Castagnoli CRC32c checksum over byte slices per RFC 9260 §3.3.10.
///
/// # Examples
/// ```
/// use frameassembly::builders::transport::crc32c;
/// let cksum = crc32c(&[b"123456789"]);
/// assert_eq!(cksum, 0xe3069283);
/// ```
pub fn crc32c(slices: &[&[u8]]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for slice in slices {
        for &byte in *slice {
            let index = ((crc ^ (byte as u32)) & 0xFF) as usize;
            crc = (crc >> 8) ^ CRC32C_TABLE[index];
        }
    }
    crc ^ 0xFFFF_FFFF
}

/// Builds an RFC 9260 SCTP packet payload over IP proto 132.
///
/// Returns the complete SCTP datagram bytes and the IP protocol number (132).
///
/// # Errors
/// Returns `CompilerError::BackendError` if serialization fails.
pub fn build_sctp_payload(
    ctx: &WireContext,
    params: &SctpParams,
    payload: &[u8],
) -> Result<(Vec<u8>, u8), CompilerError> {
    let src_port = ctx.src_port;
    let dst_port = ctx.dst_port;
    let vtag = params.vtag.unwrap_or(0);

    // 12-byte SCTP Common Header
    let mut sctp_packet = Vec::with_capacity(64 + payload.len());
    sctp_packet.extend_from_slice(&src_port.to_be_bytes());
    sctp_packet.extend_from_slice(&dst_port.to_be_bytes());
    sctp_packet.extend_from_slice(&vtag.to_be_bytes());
    sctp_packet.extend_from_slice(&0_u32.to_be_bytes()); // Checksum placeholder

    // Build Chunk
    let chunk_type = params.chunk.as_deref().unwrap_or("INIT");
    match chunk_type.to_ascii_uppercase().as_str() {
        "DATA" => {
            let stream = params.stream.unwrap_or(0);
            let ssn = params.ssn.unwrap_or(0);
            let ppid = params.ppid.unwrap_or(0);
            let chunk_len = (16 + payload.len()) as u16;

            sctp_packet.push(0); // Type 0: DATA
            sctp_packet.push(0x03); // Flags: U=0, B=1, E=1
            sctp_packet.extend_from_slice(&chunk_len.to_be_bytes());
            sctp_packet.extend_from_slice(&1000_u32.to_be_bytes()); // TSN
            sctp_packet.extend_from_slice(&stream.to_be_bytes());
            sctp_packet.extend_from_slice(&ssn.to_be_bytes());
            sctp_packet.extend_from_slice(&ppid.to_be_bytes());
            sctp_packet.extend_from_slice(payload);

            // Pad chunk to 4-byte boundary per RFC 9260 §3.3.1
            while sctp_packet.len() % 4 != 0 {
                sctp_packet.push(0);
            }
        }
        "INIT_ACK" => {
            sctp_packet.push(2); // Type 2: INIT_ACK
            sctp_packet.push(0);
            sctp_packet.extend_from_slice(&20_u16.to_be_bytes());
            sctp_packet.extend_from_slice(&0x1234_5678_u32.to_be_bytes()); // Initiate Tag
            sctp_packet.extend_from_slice(&100_000_u32.to_be_bytes()); // a_rwnd
            sctp_packet.extend_from_slice(&10_u16.to_be_bytes()); // Outbound Streams
            sctp_packet.extend_from_slice(&10_u16.to_be_bytes()); // Inbound Streams
            sctp_packet.extend_from_slice(&1000_u32.to_be_bytes()); // Initial TSN
        }
        "SACK" => {
            sctp_packet.push(3); // Type 3: SACK
            sctp_packet.push(0);
            sctp_packet.extend_from_slice(&16_u16.to_be_bytes());
            sctp_packet.extend_from_slice(&1000_u32.to_be_bytes()); // Cumulative TSN Ack
            sctp_packet.extend_from_slice(&100_000_u32.to_be_bytes()); // a_rwnd
            sctp_packet.extend_from_slice(&0_u16.to_be_bytes()); // Number of Gap Ack Blocks
            sctp_packet.extend_from_slice(&0_u16.to_be_bytes()); // Number of Duplicate TSNs
        }
        "HEARTBEAT" => {
            let chunk_len = (4 + payload.len()) as u16;
            sctp_packet.push(4); // Type 4: HEARTBEAT
            sctp_packet.push(0);
            sctp_packet.extend_from_slice(&chunk_len.to_be_bytes());
            sctp_packet.extend_from_slice(payload);
            while sctp_packet.len() % 4 != 0 {
                sctp_packet.push(0);
            }
        }
        "HEARTBEAT_ACK" => {
            let chunk_len = (4 + payload.len()) as u16;
            sctp_packet.push(5);
            sctp_packet.push(0);
            sctp_packet.extend_from_slice(&chunk_len.to_be_bytes());
            sctp_packet.extend_from_slice(payload);
            while sctp_packet.len() % 4 != 0 {
                sctp_packet.push(0);
            }
        }
        "ABORT" => {
            sctp_packet.push(6);
            sctp_packet.push(0);
            sctp_packet.extend_from_slice(&4_u16.to_be_bytes());
        }
        "SHUTDOWN" => {
            sctp_packet.push(7);
            sctp_packet.push(0);
            sctp_packet.extend_from_slice(&8_u16.to_be_bytes());
            sctp_packet.extend_from_slice(&1000_u32.to_be_bytes()); // Cumulative TSN Ack
        }
        "COOKIE_ECHO" => {
            let chunk_len = (4 + payload.len()) as u16;
            sctp_packet.push(10);
            sctp_packet.push(0);
            sctp_packet.extend_from_slice(&chunk_len.to_be_bytes());
            sctp_packet.extend_from_slice(payload);
            while sctp_packet.len() % 4 != 0 {
                sctp_packet.push(0);
            }
        }
        "COOKIE_ACK" => {
            sctp_packet.push(11);
            sctp_packet.push(0);
            sctp_packet.extend_from_slice(&4_u16.to_be_bytes());
        }
        _ => {
            // Default: INIT Chunk (Type 1)
            sctp_packet.push(1); // Type 1: INIT
            sctp_packet.push(0); // Flags
            sctp_packet.extend_from_slice(&20_u16.to_be_bytes()); // Length 20
            sctp_packet.extend_from_slice(&0x1234_5678_u32.to_be_bytes()); // Initiate Tag
            sctp_packet.extend_from_slice(&100_000_u32.to_be_bytes()); // a_rwnd
            sctp_packet.extend_from_slice(&10_u16.to_be_bytes()); // Outbound Streams
            sctp_packet.extend_from_slice(&10_u16.to_be_bytes()); // Inbound Streams
            sctp_packet.extend_from_slice(&1000_u32.to_be_bytes()); // Initial TSN
        }
    }

    // Calculate CRC32c over entire packet with checksum field set to 0
    let cksum = crc32c(&[&sctp_packet]);
    // RFC 9260 §3.3.10: CRC32c is stored in little-endian byte order
    sctp_packet[8..12].copy_from_slice(&cksum.to_le_bytes());

    Ok((sctp_packet, 132))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crc32c_rfc_vectors() {
        assert_eq!(crc32c(&[b"123456789"]), 0xe3069283);
        assert_eq!(crc32c(&[&[0u8; 32]]), 0x8a9136aa);
    }

    #[test]
    fn test_sctp_init_chunk_layout() {
        let l2 = L2Modifiers::default();
        let l3 = L3Modifiers::default();
        let l4 = L4Modifiers::default();
        let ctx = WireContext {
            src_ip: "10.0.0.1".parse().unwrap(),
            dst_ip: "10.0.0.2".parse().unwrap(),
            src_mac: [0; 6],
            dst_mac: [0; 6],
            transport: None,
            src_port: 2905,
            dst_port: 2905,
            seq: None,
            ack: None,
            l2: &l2,
            l3: &l3,
            l4: &l4,
        };
        let (pkt, proto) = build_sctp_payload(&ctx, &SctpParams::default(), &[]).unwrap();
        assert_eq!(proto, 132);
        assert_eq!(&pkt[0..2], &2905_u16.to_be_bytes());
        assert_eq!(&pkt[2..4], &2905_u16.to_be_bytes());
        assert_eq!(pkt[12], 1); // INIT chunk type
    }
}

