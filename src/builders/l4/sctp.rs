//! Stream Control Transmission Protocol (SCTP, RFC 9260 / RFC 4960) wire builder and CRC32c engine.
//!
//! Synthesizes RFC 9260 SCTP packets over IP Protocol `132` (`0x84`). Constructs the 12-byte
//! SCTP Common Header (16-bit Source Port, 16-bit Destination Port, 32-bit Verification Tag
//! `vtag`, and 32-bit little-endian Castagnoli CRC32c checksum) followed by 32-bit padded
//! control or data chunks (`data`, `init`, `initack`, `sack`, `heartbeat`, `heartbeatack`,
//! `abort`, `shutdown`, `shutdownack`, `cookieecho`, `cookieack`).
//!
//! Canonical `.frasm` syntax:
//! `a -> b sctp [chunk <type>] [vtag <u32>] [stream <u16>] [ssn <u16>] [ppid <u32>] [srcport <u16>] [dstport <u16>]`

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
    let chunk_type = params
        .chunk
        .as_deref()
        .unwrap_or("init")
        .to_ascii_uppercase()
        .replace(['_', '-'], "");
    match chunk_type.as_str() {
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
        "INITACK" => {
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
        "HEARTBEATACK" => {
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
        "SHUTDOWNACK" => {
            sctp_packet.push(8); // Type 8: SHUTDOWN_ACK (RFC 9260 §3.3.9)
            sctp_packet.push(0);
            sctp_packet.extend_from_slice(&4_u16.to_be_bytes());
        }
        "COOKIEECHO" => {
            let chunk_len = (4 + payload.len()) as u16;
            sctp_packet.push(10);
            sctp_packet.push(0);
            sctp_packet.extend_from_slice(&chunk_len.to_be_bytes());
            sctp_packet.extend_from_slice(payload);
            while sctp_packet.len() % 4 != 0 {
                sctp_packet.push(0);
            }
        }
        "COOKIEACK" => {
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

    #[test]
    fn test_sctp_shutdownack_and_normalized_chunks() {
        let l2 = L2Modifiers::default();
        let l3 = L3Modifiers::default();
        let l4 = L4Modifiers::default();
        let ctx = WireContext {
            src_ip: "10.0.0.1".parse().unwrap(),
            dst_ip: "10.0.0.2".parse().unwrap(),
            src_mac: [0; 6],
            dst_mac: [0; 6],
            transport: None,
            src_port: 38412,
            dst_port: 38412,
            seq: None,
            ack: None,
            l2: &l2,
            l3: &l3,
            l4: &l4,
        };
        let p_v2 = SctpParams {
            chunk: Some(alloc::string::String::from("shutdownack")),
            ..SctpParams::default()
        };
        let p_legacy = SctpParams {
            chunk: Some(alloc::string::String::from("SHUTDOWN_ACK")),
            ..SctpParams::default()
        };
        let (pkt_v2, _) = build_sctp_payload(&ctx, &p_v2, &[]).unwrap();
        let (pkt_legacy, _) = build_sctp_payload(&ctx, &p_legacy, &[]).unwrap();
        assert_eq!(pkt_v2, pkt_legacy);
        assert_eq!(&pkt_v2[12..16], &[8, 0, 0, 4]);

        for (lower, upper, expected_type) in [
            ("initack", "INIT_ACK", 2u8),
            ("heartbeatack", "HEARTBEAT_ACK", 5u8),
            ("cookieecho", "COOKIE_ECHO", 10u8),
            ("cookieack", "COOKIE_ACK", 11u8),
        ] {
            let a = SctpParams {
                chunk: Some(alloc::string::String::from(lower)),
                ..SctpParams::default()
            };
            let b = SctpParams {
                chunk: Some(alloc::string::String::from(upper)),
                ..SctpParams::default()
            };
            let (pa, _) = build_sctp_payload(&ctx, &a, &[]).unwrap();
            let (pb, _) = build_sctp_payload(&ctx, &b, &[]).unwrap();
            assert_eq!(pa, pb);
            assert_eq!(pa[12], expected_type);
        }
    }
}

