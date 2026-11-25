//! IEEE C37.118 Synchrophasor (PMU/PDC Grid Telemetry) wire payload builder and CRC-CCITT engine.
//!
//! This module implements [`calculate_c37_crc`] and [`build_synchrophasor_payload`], which
//! serialize a [`SynchrophasorSpec`] AST specification into an IEEE C37.118-2005 / C37.118.2-2011
//! frame over TCP or UDP port 4712. It encodes the 14-byte header (`SYNC` `0xAA` + frame type
//! and version nibble, `FRAMESIZE`, `IDCODE`, `SOC`, `FRACSEC`), body layouts for `Command`
//! (`4`), `Header` (`1`), `Data` (`0`), `CFG-1` (`2`), `CFG-2` (`3`), and `CFG-3` (`5`), and the
//! trailing 2-byte CRC-CCITT (`0x1021`, initial `0xFFFF`).

use crate::ast::*;
use crate::builders::WireContext;
use alloc::vec::Vec;

/// Default Second of Century (`SOC`) UNIX timestamp (`2023-11-14T22:13:20Z`).
pub(crate) const DEFAULT_C37_SOC: u32 = 1_700_000_000;

/// Computes the IEEE C37.118 16-bit CRC-CCITT (`0x1021`, initial `0xFFFF`, non-reflected).
pub fn calculate_c37_crc(data: &[u8]) -> u16 {
    let mut crc: u16 = 0xFFFF;
    for &b in data {
        crc ^= u16::from(b) << 8;
        for _ in 0..8 {
            if (crc & 0x8000) != 0 {
                crc = (crc << 1) ^ 0x1021;
            } else {
                crc <<= 1;
            }
        }
    }
    crc
}

/// Parses an IEEE C37.118 frame type name or numeric code into a 3-bit frame type (`0..=5`).
fn parse_c37_frame_type(raw: &str) -> u8 {
    let norm = raw.trim().to_ascii_uppercase().replace(['_', '-'], "");
    match norm.as_str() {
        "DATA" | "0" => 0,
        "HEADER" | "HDR" | "1" => 1,
        "CFG1" | "2" => 2,
        "CFG2" | "3" => 3,
        "CMD" | "COMMAND" | "4" => 4,
        "CFG3" | "5" => 5,
        _ => 4,
    }
}

/// Appends a 16-byte space-padded ASCII label used for C37.118 station and channel names.
fn push_padded_16(out: &mut Vec<u8>, s: &str) {
    let bytes = s.as_bytes();
    let take = bytes.len().min(16);
    out.extend_from_slice(&bytes[..take]);
    for _ in take..16 {
        out.push(b' ');
    }
}

/// Builds an IEEE C37.118 Synchrophasor packet payload over TCP or UDP port 4712.
pub fn build_synchrophasor_payload(
    _ctx: &WireContext,
    spec: &SynchrophasorSpec,
    payload_bytes: &[u8],
) -> Vec<u8> {
    let frame_type = if let Some(mt) = spec.msg_type {
        parse_c37_frame_type(mt)
    } else if spec.station.is_some() {
        3
    } else if spec.status.is_some() {
        0
    } else {
        4
    };
    let version = spec.version.unwrap_or(1) & 0x0F;
    let id_code = spec.id_code.unwrap_or(1);
    let soc = spec.soc.unwrap_or(DEFAULT_C37_SOC);
    let frac_sec = spec.frac_sec.unwrap_or(0);

    let mut body = Vec::new();
    match frame_type {
        0 => {
            body.extend_from_slice(&spec.status.unwrap_or(0).to_be_bytes());
            if !payload_bytes.is_empty() {
                body.extend_from_slice(payload_bytes);
            }
        }
        1 => {
            if payload_bytes.is_empty() {
                body.extend_from_slice(b"PMU_1 Header\n");
            } else {
                body.extend_from_slice(payload_bytes);
            }
        }
        2 | 3 => {
            body.extend_from_slice(&1_000_000u32.to_be_bytes()); // TIME_BASE
            body.extend_from_slice(&1u16.to_be_bytes()); // NUM_PMU = 1
            push_padded_16(&mut body, spec.station.unwrap_or("PMU_1"));
            body.extend_from_slice(&id_code.to_be_bytes()); // PMU IDCODE
            body.extend_from_slice(&0u16.to_be_bytes()); // FORMAT
            body.extend_from_slice(&1u16.to_be_bytes()); // PHNMR = 1
            body.extend_from_slice(&0u16.to_be_bytes()); // ANNMR = 0
            body.extend_from_slice(&0u16.to_be_bytes()); // DGNMR = 0
            push_padded_16(&mut body, "VA"); // CHNAM (16B)
            body.extend_from_slice(&0u32.to_be_bytes()); // PHUNIT (4B)
            body.extend_from_slice(&0u16.to_be_bytes()); // FNOM: 60Hz (0)
            body.extend_from_slice(&1u16.to_be_bytes()); // CFGCNT = 1
            body.extend_from_slice(&30i16.to_be_bytes()); // DATA_RATE = 30 fps
            if !payload_bytes.is_empty() {
                body.extend_from_slice(payload_bytes);
            }
        }
        5 => {
            body.extend_from_slice(&0u16.to_be_bytes()); // CONT_IDX
            body.extend_from_slice(&1_000_000u32.to_be_bytes()); // TIME_BASE
            body.extend_from_slice(&0u16.to_be_bytes()); // NUM_PMU = 0
            body.extend_from_slice(&30i16.to_be_bytes()); // DATA_RATE = 30 fps
            if !payload_bytes.is_empty() {
                body.extend_from_slice(payload_bytes);
            }
        }
        _ => {
            // Command frame (4)
            body.extend_from_slice(&spec.cmd.unwrap_or(5).to_be_bytes());
            if !payload_bytes.is_empty() {
                body.extend_from_slice(payload_bytes);
            }
        }
    }

    let frame_size = u16::try_from(14usize.saturating_add(body.len()).saturating_add(2))
        .unwrap_or(u16::MAX);
    let sync = 0xAA00u16 | (u16::from(frame_type & 0x07) << 4) | u16::from(version);

    let mut pkt = Vec::with_capacity(usize::from(frame_size));
    pkt.extend_from_slice(&sync.to_be_bytes());
    pkt.extend_from_slice(&frame_size.to_be_bytes());
    pkt.extend_from_slice(&id_code.to_be_bytes());
    pkt.extend_from_slice(&soc.to_be_bytes());
    pkt.extend_from_slice(&frac_sec.to_be_bytes());
    pkt.extend_from_slice(&body);

    let crc = spec.crc.unwrap_or_else(|| calculate_c37_crc(&pkt));
    pkt.extend_from_slice(&crc.to_be_bytes());
    pkt
}
