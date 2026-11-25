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

/// Encodes a checked 16-bit SCTP chunk/TLV length or returns a descriptive [`CompilerError`].
fn checked_sctp_u16(len: usize, context: &str) -> Result<u16, CompilerError> {
    u16::try_from(len).map_err(|_| {
        CompilerError::BackendError(alloc::format!(
            "SCTP {context} length ({len} bytes) exceeds 65,535-byte chunk limit"
        ))
    })
}

/// Appends zero-byte padding so `buf.len()` sits on a 4-byte RFC 9260 chunk/parameter boundary.
fn pad_sctp_4(buf: &mut Vec<u8>) {
    while !buf.len().is_multiple_of(4) {
        buf.push(0);
    }
}

/// Builds an RFC 9260 SCTP packet carrying an arbitrary Layer 7 payload inside a `DATA` chunk.
///
/// Encodes the 12-byte SCTP common header, a `DATA` chunk (`Type = 0`, `B|E = 0x03`) with the
/// supplied `tsn`, `stream`, `ssn`, and `ppid`, pads the chunk to a 4-byte boundary, and stores
/// the little-endian Castagnoli CRC32c (or bitwise-inverted CRC32c when `bad_checksum` is true).
///
/// # Errors
/// Returns `CompilerError::BackendError` if IP versions do not match or chunk length exceeds 65,535 bytes.
#[allow(clippy::too_many_arguments)]
pub fn build_sctp_l7_packet(
    src_ip: core::net::IpAddr,
    dst_ip: core::net::IpAddr,
    src_port: u16,
    dst_port: u16,
    vtag: u32,
    tsn: u32,
    stream: u16,
    ssn: u16,
    ppid: u32,
    payload: &[u8],
    bad_checksum: bool,
) -> Result<Vec<u8>, CompilerError> {
    if src_ip.is_ipv4() != dst_ip.is_ipv4() {
        return Err(CompilerError::BackendError(
            alloc::string::String::from("Source and Destination IP versions must match"),
        ));
    }
    let chunk_len = checked_sctp_u16(16usize.saturating_add(payload.len()), "DATA chunk")?;

    let mut sctp_packet = Vec::with_capacity(28 + payload.len() + 4);
    sctp_packet.extend_from_slice(&src_port.to_be_bytes());
    sctp_packet.extend_from_slice(&dst_port.to_be_bytes());
    sctp_packet.extend_from_slice(&vtag.to_be_bytes());
    sctp_packet.extend_from_slice(&0_u32.to_be_bytes());

    sctp_packet.push(0); // Type 0: DATA
    sctp_packet.push(0x03); // Flags: B=1, E=1
    sctp_packet.extend_from_slice(&chunk_len.to_be_bytes());
    sctp_packet.extend_from_slice(&tsn.to_be_bytes());
    sctp_packet.extend_from_slice(&stream.to_be_bytes());
    sctp_packet.extend_from_slice(&ssn.to_be_bytes());
    sctp_packet.extend_from_slice(&ppid.to_be_bytes());
    sctp_packet.extend_from_slice(payload);
    pad_sctp_4(&mut sctp_packet);

    let cksum = crc32c(&[&sctp_packet]);
    let wire_crc = if bad_checksum { cksum ^ 0xFFFF_FFFF } else { cksum };
    sctp_packet[8..12].copy_from_slice(&wire_crc.to_le_bytes());

    Ok(sctp_packet)
}

/// Builds an RFC 9260 SCTP packet payload over IP proto 132.
///
/// Returns the complete SCTP datagram bytes and the IP protocol number (132).
///
/// # Errors
/// Returns `CompilerError::BackendError` if serialization fails or an unknown chunk type is given.
pub fn build_sctp_payload(
    ctx: &WireContext,
    params: &SctpParams,
    payload: &[u8],
) -> Result<(Vec<u8>, u8), CompilerError> {
    let src_port = ctx.src_port;
    let dst_port = ctx.dst_port;
    let vtag = params.vtag.unwrap_or(0);
    let tsn = ctx.seq.unwrap_or(1000);

    // 12-byte SCTP Common Header
    let mut sctp_packet = Vec::with_capacity(64 + payload.len());
    sctp_packet.extend_from_slice(&src_port.to_be_bytes());
    sctp_packet.extend_from_slice(&dst_port.to_be_bytes());
    sctp_packet.extend_from_slice(&vtag.to_be_bytes());
    sctp_packet.extend_from_slice(&0_u32.to_be_bytes()); // Checksum placeholder

    // Build Chunk
    let raw_chunk = params.chunk.as_deref().unwrap_or("init");
    let chunk_type = raw_chunk.to_ascii_uppercase().replace(['_', '-'], "");
    match chunk_type.as_str() {
        "DATA" => {
            let stream = params.stream.unwrap_or(0);
            let ssn = params.ssn.unwrap_or(0);
            let ppid = params.ppid.unwrap_or(0);
            let chunk_len = checked_sctp_u16(16usize.saturating_add(payload.len()), "DATA chunk")?;

            sctp_packet.push(0); // Type 0: DATA
            sctp_packet.push(0x03); // Flags: U=0, B=1, E=1
            sctp_packet.extend_from_slice(&chunk_len.to_be_bytes());
            sctp_packet.extend_from_slice(&tsn.to_be_bytes()); // TSN
            sctp_packet.extend_from_slice(&stream.to_be_bytes());
            sctp_packet.extend_from_slice(&ssn.to_be_bytes());
            sctp_packet.extend_from_slice(&ppid.to_be_bytes());
            sctp_packet.extend_from_slice(payload);
            pad_sctp_4(&mut sctp_packet);
        }
        "INIT" => {
            sctp_packet.push(1); // Type 1: INIT
            sctp_packet.push(0); // Flags
            sctp_packet.extend_from_slice(&20_u16.to_be_bytes()); // Length 20
            sctp_packet.extend_from_slice(&0x1234_5678_u32.to_be_bytes()); // Initiate Tag
            sctp_packet.extend_from_slice(&100_000_u32.to_be_bytes()); // a_rwnd
            sctp_packet.extend_from_slice(&10_u16.to_be_bytes()); // Outbound Streams
            sctp_packet.extend_from_slice(&10_u16.to_be_bytes()); // Inbound Streams
            sctp_packet.extend_from_slice(&tsn.to_be_bytes()); // Initial TSN
        }
        "INITACK" => {
            // RFC 9260 §3.3.3 INIT_ACK + mandatory State Cookie Parameter (Type 7)
            let cookie: &[u8] = if payload.is_empty() {
                b"FACOOKIE"
            } else {
                payload
            };
            let param_len = checked_sctp_u16(4usize.saturating_add(cookie.len()), "State Cookie")?;
            let chunk_len = checked_sctp_u16(20usize.saturating_add(usize::from(param_len)), "INIT_ACK")?;
            sctp_packet.push(2); // Type 2: INIT_ACK
            sctp_packet.push(0);
            sctp_packet.extend_from_slice(&chunk_len.to_be_bytes());
            sctp_packet.extend_from_slice(&0x1234_5678_u32.to_be_bytes()); // Initiate Tag
            sctp_packet.extend_from_slice(&100_000_u32.to_be_bytes()); // a_rwnd
            sctp_packet.extend_from_slice(&10_u16.to_be_bytes()); // Outbound Streams
            sctp_packet.extend_from_slice(&10_u16.to_be_bytes()); // Inbound Streams
            sctp_packet.extend_from_slice(&tsn.to_be_bytes()); // Initial TSN
            sctp_packet.extend_from_slice(&7_u16.to_be_bytes()); // Parameter Type 7: State Cookie
            sctp_packet.extend_from_slice(&param_len.to_be_bytes());
            sctp_packet.extend_from_slice(cookie);
            pad_sctp_4(&mut sctp_packet);
        }
        "SACK" => {
            sctp_packet.push(3); // Type 3: SACK
            sctp_packet.push(0);
            sctp_packet.extend_from_slice(&16_u16.to_be_bytes());
            sctp_packet.extend_from_slice(&tsn.to_be_bytes()); // Cumulative TSN Ack
            sctp_packet.extend_from_slice(&100_000_u32.to_be_bytes()); // a_rwnd
            sctp_packet.extend_from_slice(&0_u16.to_be_bytes()); // Number of Gap Ack Blocks
            sctp_packet.extend_from_slice(&0_u16.to_be_bytes()); // Number of Duplicate TSNs
        }
        "HEARTBEAT" => {
            // RFC 9260 §3.3.5 HEARTBEAT with Parameter Type 1: Heartbeat Info TLV
            let info: &[u8] = if payload.is_empty() {
                &[0_u8; 4]
            } else {
                payload
            };
            let param_len = checked_sctp_u16(4usize.saturating_add(info.len()), "Heartbeat Info")?;
            let chunk_len = checked_sctp_u16(4usize.saturating_add(usize::from(param_len)), "HEARTBEAT")?;
            sctp_packet.push(4); // Type 4: HEARTBEAT
            sctp_packet.push(0);
            sctp_packet.extend_from_slice(&chunk_len.to_be_bytes());
            sctp_packet.extend_from_slice(&1_u16.to_be_bytes()); // Parameter Type 1: Heartbeat Info
            sctp_packet.extend_from_slice(&param_len.to_be_bytes());
            sctp_packet.extend_from_slice(info);
            pad_sctp_4(&mut sctp_packet);
        }
        "HEARTBEATACK" => {
            let chunk_len = checked_sctp_u16(4usize.saturating_add(payload.len()), "HEARTBEAT_ACK")?;
            sctp_packet.push(5);
            sctp_packet.push(0);
            sctp_packet.extend_from_slice(&chunk_len.to_be_bytes());
            sctp_packet.extend_from_slice(payload);
            pad_sctp_4(&mut sctp_packet);
        }
        "ABORT" => {
            if payload.is_empty() {
                sctp_packet.push(6);
                sctp_packet.push(0);
                sctp_packet.extend_from_slice(&4_u16.to_be_bytes());
            } else {
                let cause_len = checked_sctp_u16(4usize.saturating_add(payload.len()), "ABORT Error Cause")?;
                let chunk_len = checked_sctp_u16(4usize.saturating_add(usize::from(cause_len)), "ABORT")?;
                sctp_packet.push(6);
                sctp_packet.push(0);
                sctp_packet.extend_from_slice(&chunk_len.to_be_bytes());
                sctp_packet.extend_from_slice(&12_u16.to_be_bytes()); // Cause Code 12: User-Initiated Abort
                sctp_packet.extend_from_slice(&cause_len.to_be_bytes());
                sctp_packet.extend_from_slice(payload);
                pad_sctp_4(&mut sctp_packet);
            }
        }
        "SHUTDOWN" => {
            sctp_packet.push(7);
            sctp_packet.push(0);
            sctp_packet.extend_from_slice(&8_u16.to_be_bytes());
            sctp_packet.extend_from_slice(&tsn.to_be_bytes()); // Cumulative TSN Ack
        }
        "SHUTDOWNACK" => {
            sctp_packet.push(8); // Type 8: SHUTDOWN_ACK (RFC 9260 §3.3.9)
            sctp_packet.push(0);
            sctp_packet.extend_from_slice(&4_u16.to_be_bytes());
        }
        "COOKIEECHO" => {
            let chunk_len = checked_sctp_u16(4usize.saturating_add(payload.len()), "COOKIE_ECHO")?;
            sctp_packet.push(10);
            sctp_packet.push(0);
            sctp_packet.extend_from_slice(&chunk_len.to_be_bytes());
            sctp_packet.extend_from_slice(payload);
            pad_sctp_4(&mut sctp_packet);
        }
        "COOKIEACK" => {
            sctp_packet.push(11);
            sctp_packet.push(0);
            sctp_packet.extend_from_slice(&4_u16.to_be_bytes());
        }
        "SHUTDOWNCOMPLETE" => {
            sctp_packet.push(14); // Type 14: SHUTDOWN_COMPLETE (RFC 9260 §3.3.13)
            sctp_packet.push(0);
            sctp_packet.extend_from_slice(&4_u16.to_be_bytes());
        }
        _ => {
            return Err(CompilerError::BackendError(alloc::format!(
                "Unknown SCTP chunk type '{}'",
                raw_chunk
            )));
        }
    }

    // Calculate CRC32c over entire packet with checksum field set to 0
    let cksum = crc32c(&[&sctp_packet]);
    let wire_crc = if ctx.l4.bad_checksum {
        cksum ^ 0xFFFF_FFFF
    } else {
        cksum
    };
    // RFC 9260 §3.3.10: CRC32c is stored in little-endian byte order
    sctp_packet[8..12].copy_from_slice(&wire_crc.to_le_bytes());

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

    #[test]
    fn test_sctp_v33_tsn_tlv_shutdowncomplete_and_l7_carrier() {
        let l2 = L2Modifiers::default();
        let l3 = L3Modifiers::default();
        let l4 = L4Modifiers {
            bad_checksum: true,
            ..L4Modifiers::default()
        };
        let ctx = WireContext {
            src_ip: "10.0.0.1".parse().unwrap(),
            dst_ip: "10.0.0.2".parse().unwrap(),
            src_mac: [0; 6],
            dst_mac: [0; 6],
            transport: None,
            src_port: 2905,
            dst_port: 2905,
            seq: Some(4242),
            ack: None,
            l2: &l2,
            l3: &l3,
            l4: &l4,
        };
        let data_p = SctpParams {
            chunk: Some(alloc::string::String::from("data")),
            vtag: Some(0x1122_3344),
            stream: Some(1),
            ssn: Some(2),
            ppid: Some(60),
        };
        let (pkt, _) = build_sctp_payload(&ctx, &data_p, b"sig").unwrap();
        assert_eq!(&pkt[16..20], &4242_u32.to_be_bytes());

        let sc_p = SctpParams {
            chunk: Some(alloc::string::String::from("shutdowncomplete")),
            ..SctpParams::default()
        };
        let (sc_pkt, _) = build_sctp_payload(&ctx, &sc_p, &[]).unwrap();
        assert_eq!(sc_pkt[12], 14);

        let unknown_p = SctpParams {
            chunk: Some(alloc::string::String::from("invalidchunk")),
            ..SctpParams::default()
        };
        assert!(build_sctp_payload(&ctx, &unknown_p, &[]).is_err());

        let l7_sctp = build_sctp_l7_packet(
            "10.0.0.1".parse().unwrap(),
            "10.0.0.2".parse().unwrap(),
            5000,
            3868,
            0xABCD,
            777,
            0,
            1,
            46,
            b"diam",
            false,
        )
        .unwrap();
        assert_eq!(l7_sctp[12], 0);
        assert_eq!(&l7_sctp[16..20], &777_u32.to_be_bytes());
    }
}

