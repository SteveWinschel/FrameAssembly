//! IEC 60870-5-104 (Telecontrol Equipment and Systems over TCP/IP) wire payload builder.
//!
//! This module implements [`build_iec104_payload`], which serializes an [`Iec104Spec`] AST
//! specification into an IEC 60870-5-104 APDU over TCP port 2404. It supports 6-byte APCI
//! `U`-frames (`STARTDT`, `STOPDT`, `TESTFR` act/con), 6-byte `S`-frames (`N(R)` supervisory
//! acknowledgment), and `I`-frames (`N(S)`/`N(R)` + ASDU with `TypeID`, `VSQ`, 2-octet `COT`,
//! 16-bit `CA`, 24-bit `IOA`, and typed information elements for `M_SP_NA_1`, `M_DP_NA_1`,
//! `M_ME_NA_1`, `M_ME_NB_1`, `M_ME_NC_1` IEEE 754 float, `M_SP_TB_1`, `C_SC_NA_1`, `C_DC_NA_1`,
//! `C_IC_NA_1`, and `C_CS_NA_1`).

use crate::ast::*;
use crate::builders::WireContext;
use alloc::vec::Vec;

/// Fixed deterministic 7-byte CP56Time2a timestamp (`2025-01-01 00:00:00.000`).
const DEFAULT_CP56_TIME: [u8; 7] = [0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 25];

/// Builds a 6-byte APCI U-frame or S-frame if `spec.msg_type` selects one, or returns `None` for I-frames.
fn build_non_i_frame(spec: &Iec104Spec<'_>) -> Option<Vec<u8>> {
    let raw = spec.msg_type?;
    let norm = raw.trim().to_ascii_uppercase().replace(['_', '-'], "");
    let ctrl = match norm.as_str() {
        "I" | "IFRAME" => return None,
        "S" | "SFRAME" => {
            let rx = (spec.rx_seq.unwrap_or(0) & 0x7FFF) << 1;
            let rx_le = rx.to_le_bytes();
            return Some(alloc::vec![0x68, 0x04, 0x01, 0x00, rx_le[0], rx_le[1]]);
        }
        "STARTDT" | "STARTDTACT" | "U" | "UFRAME" => {
            if spec.confirm {
                0x0Bu8
            } else {
                0x07u8
            }
        }
        "STARTDTCON" => 0x0Bu8,
        "STOPDT" | "STOPDTACT" => {
            if spec.confirm {
                0x23u8
            } else {
                0x13u8
            }
        }
        "STOPDTCON" => 0x23u8,
        "TESTFR" | "TESTFRACT" => {
            if spec.confirm {
                0x83u8
            } else {
                0x43u8
            }
        }
        "TESTFRCON" => 0x83u8,
        _ => return None,
    };
    Some(alloc::vec![0x68, 0x04, ctrl, 0x00, 0x00, 0x00])
}

/// Builds an IEC 60870-5-104 APCI + ASDU packet payload.
pub fn build_iec104_payload(
    _ctx: &WireContext,
    spec: &Iec104Spec,
    payload_bytes: &[u8],
) -> Vec<u8> {
    if let Some(u_or_s) = build_non_i_frame(spec) {
        return u_or_s;
    }

    let tx = (spec.tx_seq.unwrap_or(0) & 0x7FFF) << 1;
    let rx = (spec.rx_seq.unwrap_or(0) & 0x7FFF) << 1;
    let type_id = if spec.real_value.is_some() && spec.type_id.is_none() {
        13
    } else {
        spec.type_id.unwrap_or(100)
    };
    let cot = spec.cot.unwrap_or(if spec.confirm {
        7
    } else if type_id >= 45 {
        6
    } else {
        3
    }) & 0x3F;
    let ca = spec.ca.unwrap_or(1);
    let ioa = spec
        .ioa
        .unwrap_or(if matches!(type_id, 100 | 103) { 0 } else { 1 })
        & 0x00FF_FFFF;

    let mut asdu = Vec::with_capacity(24 + payload_bytes.len());
    asdu.push(type_id);
    asdu.push(0x01); // VSQ: SQ=0, NumIx=1
    asdu.push(cot);
    asdu.push(0x00); // Originator Address
    asdu.extend_from_slice(&ca.to_le_bytes());

    // 24-bit little-endian Information Object Address (IOA)
    asdu.push(ioa as u8);
    asdu.push((ioa >> 8) as u8);
    asdu.push((ioa >> 16) as u8);

    let mut consumed_payload = false;
    match type_id {
        1 | 3 | 45 | 46 => {
            asdu.push((spec.value.unwrap_or(1) & 0xFF) as u8);
        }
        9 | 11 => {
            let v = (spec.value.unwrap_or(0) & 0xFFFF) as u16;
            asdu.extend_from_slice(&v.to_le_bytes());
            asdu.push(0x00); // QDS
        }
        13 => {
            let bits = spec.real_value.unwrap_or(0f32.to_bits());
            asdu.extend_from_slice(&bits.to_le_bytes());
            asdu.push(0x00); // QDS
        }
        30 => {
            asdu.push((spec.value.unwrap_or(1) & 0xFF) as u8);
            asdu.extend_from_slice(&DEFAULT_CP56_TIME);
        }
        100 => {
            asdu.push((spec.value.unwrap_or(20) & 0xFF) as u8); // QOI: 20 (Station interrogation)
        }
        103 => {
            asdu.extend_from_slice(&DEFAULT_CP56_TIME);
        }
        _ => {
            if payload_bytes.is_empty() {
                asdu.push((spec.value.unwrap_or(0) & 0xFF) as u8);
            } else {
                let max_extra = 249usize.saturating_sub(asdu.len());
                asdu.extend_from_slice(&payload_bytes[..payload_bytes.len().min(max_extra)]);
                consumed_payload = true;
            }
        }
    }

    if !consumed_payload && !payload_bytes.is_empty() {
        let max_extra = 249usize.saturating_sub(asdu.len());
        asdu.extend_from_slice(&payload_bytes[..payload_bytes.len().min(max_extra)]);
    }

    let apdu_len = u8::try_from(4 + asdu.len()).unwrap_or(253);
    let mut pkt = Vec::with_capacity(2 + usize::from(apdu_len));
    pkt.push(0x68);
    pkt.push(apdu_len);
    pkt.extend_from_slice(&tx.to_le_bytes());
    pkt.extend_from_slice(&rx.to_le_bytes());
    pkt.extend_from_slice(&asdu);
    pkt
}
