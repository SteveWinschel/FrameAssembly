//! IEEE 802.1D / IEEE 802.1w Spanning Tree Protocol (STP / RSTP) BPDU wire frame builder.
//!
//! Synthesizes 35-byte Configuration and Rapid Spanning Tree BPDUs encapsulated inside IEEE 802.3
//! length-framed Ethernet packets addressed to the Bridge Group multicast MAC `01:80:C2:00:00:00`
//! with a 3-byte IEEE 802.2 LLC header (`DSAP = 0x42`, `SSAP = 0x42`, `Control = 0x03`). Encodes
//! Protocol Identifier `0x0000`, Version (`0x00` for STP, `0x02` for RSTP), BPDU Type (`0x00` or
//! `0x02`), Flags, 8-byte Root ID, 4-byte Root Path Cost, 8-byte Bridge ID, 2-byte Port ID, and
//! 1/256-second scaled timers (Message Age, Max Age, Hello Time, Forward Delay).
//!
//! Canonical `.fasm` syntax:
//! `a -> b [STP | RSTP] [ROOT_ID "<str>"] [BRIDGE_ID "<str>"] [PORT_ID <u16>] [COST <u32>] [MAX_AGE <u16>] [HELLO_TIME <u16>] [FORWARD_DELAY <u16>] [FLAGS <u8>]`

use crate::ast::*;
use crate::builders::WireContext;
use crate::error::CompilerError;
use crate::packet::build_ethernet_and_l2;
use alloc::vec::Vec;

/// Parses a bridge or root identifier string into an 8-byte IEEE 802.1D Bridge ID (`2B Priority + 6B MAC`).
fn encode_bridge_id(id_str: Option<&str>, default_mac: [u8; 6]) -> [u8; 8] {
    let mut out = [0u8; 8];
    out[0..2].copy_from_slice(&0x8000_u16.to_be_bytes());
    out[2..8].copy_from_slice(&default_mac);

    let Some(raw) = id_str else {
        return out;
    };
    let s = raw.trim();
    if s.is_empty() {
        return out;
    }

    if let Some((prio_part, mac_part)) = s.split_once('/') {
        let prio = if let Some(hex) = prio_part.strip_prefix("0x").or_else(|| prio_part.strip_prefix("0X")) {
            u16::from_str_radix(hex, 16).unwrap_or(0x8000)
        } else {
            prio_part.parse::<u16>().unwrap_or(0x8000)
        };
        out[0..2].copy_from_slice(&prio.to_be_bytes());
        if let Some(mac) = parse_mac_str(mac_part) {
            out[2..8].copy_from_slice(&mac);
        }
        return out;
    }

    if let Some(mac) = parse_mac_str(s) {
        out[2..8].copy_from_slice(&mac);
        return out;
    }

    let hex_candidate = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s);
    if hex_candidate.len() <= 16 && hex_candidate.chars().all(|c| c.is_ascii_hexdigit()) {
        if let Ok(val) = u64::from_str_radix(hex_candidate, 16) {
            return val.to_be_bytes();
        }
    }

    let bytes = s.as_bytes();
    let len = bytes.len().min(8);
    out[..len].copy_from_slice(&bytes[..len]);
    out
}

/// Parses a colon- or hyphen-separated 6-octet MAC string.
fn parse_mac_str(s: &str) -> Option<[u8; 6]> {
    let mut mac = [0u8; 6];
    let mut count = 0usize;
    for part in s.split([':', '-']) {
        if count >= 6 {
            return None;
        }
        mac[count] = u8::from_str_radix(part.trim(), 16).ok()?;
        count += 1;
    }
    if count == 6 { Some(mac) } else { None }
}

/// Builds an IEEE 802.1D / 802.1w Spanning Tree Protocol (STP) BPDU wire frame.
///
/// # Errors
/// Returns `CompilerError::BackendError` if construction fails.
pub fn build_stp_frame(
    ctx: &WireContext,
    spec: &StpSpec,
    payload: &[u8],
) -> Result<Vec<u8>, CompilerError> {
    // 35-byte Configuration BPDU (or 36-byte RSTP BPDU with Version 1 Length = 0)
    let mut bpdu = Vec::with_capacity(36 + payload.len());
    // Protocol Identifier: 0x0000 (STP)
    bpdu.extend_from_slice(&0_u16.to_be_bytes());
    // Protocol Version: 0x00 (STP) or 0x02 (RSTP)
    bpdu.push(if spec.is_rstp { 2 } else { 0 });
    // BPDU Type: 0x00 (Configuration) or 0x02 (RSTP)
    bpdu.push(if spec.is_rstp { 2 } else { 0 });
    // Flags: 0x00
    bpdu.push(spec.flags.unwrap_or(0));

    // Root ID (8 bytes: 2B Priority + 6B MAC)
    let root_id = encode_bridge_id(spec.root_id, ctx.src_mac);
    bpdu.extend_from_slice(&root_id);

    // Root Path Cost (4 bytes)
    bpdu.extend_from_slice(&spec.cost.unwrap_or(0).to_be_bytes());

    // Bridge ID (8 bytes: 2B Priority + 6B MAC)
    let bridge_id = encode_bridge_id(spec.bridge_id, ctx.src_mac);
    bpdu.extend_from_slice(&bridge_id);

    // Port ID (2 bytes: 0x8001 = priority 128, port 1)
    bpdu.extend_from_slice(&spec.port_id.unwrap_or(0x8001).to_be_bytes());

    // Message Age (2 bytes: in 1/256ths of a second, 0)
    bpdu.extend_from_slice(&0_u16.to_be_bytes());
    // Max Age (2 bytes: default 20s = 0x1400)
    let max_age = spec.max_age.unwrap_or(20) << 8;
    bpdu.extend_from_slice(&max_age.to_be_bytes());
    // Hello Time (2 bytes: default 2s = 0x0200)
    let hello = spec.hello_time.unwrap_or(2) << 8;
    bpdu.extend_from_slice(&hello.to_be_bytes());
    // Forward Delay (2 bytes: default 15s = 0x0F00)
    let fwd_delay = spec.forward_delay.unwrap_or(15) << 8;
    bpdu.extend_from_slice(&fwd_delay.to_be_bytes());

    // IEEE 802.1D-2004 §9.3.3: RSTP (Version 2) appends 1-byte Version 1 Length = 0x00 (byte 36)
    if spec.is_rstp {
        bpdu.push(0x00);
    }

    bpdu.extend_from_slice(payload);

    // IEEE 802.3 LLC Framing: DSAP 0x42, SSAP 0x42, Control 0x03
    let mut llc_packet = Vec::with_capacity(3 + bpdu.len());
    llc_packet.push(0x42);
    llc_packet.push(0x42);
    llc_packet.push(0x03);
    llc_packet.extend_from_slice(&bpdu);

    // 802.3 Length field
    let length_field = llc_packet.len() as u16;
    let dst_mac = ctx.l2.dst_mac.unwrap_or([0x01, 0x80, 0xc2, 0x00, 0x00, 0x00]);

    Ok(build_ethernet_and_l2(ctx.src_mac, dst_mac, ctx.l2, length_field, &llc_packet))
}

