//! Building Automation and Control Networks over IP (BACnet/IP, ASHRAE 135) Layer 7 PCAP-to-`.frasm` decompiler.
//!
//! This module implements fuzz-safe wire-to-AST dissection for `bacnet`/IP BVLC (`0x81`, unicast
//! `0x0A` or broadcast `0x0B`), NPDU (`\x01\x00`), and APDU messages over UDP and SCTP (port
//! `47808` and secondary BACnet ports). It decodes `Who-Is` (`whois`), `I-Am` (`iam`),
//! `ReadProperty` (`readproperty`), `WriteProperty` (`writeproperty`), and `Complex-ACK`
//! (`complexack`, `0x30`) services along with `invokeid`, `objecttype`, `objectinstance`,
//! `propertyid`, unsigned `value` (`0x24`), and finite IEEE 754 `real` (`0x44`) fields.

use alloc::format;
use alloc::string::String;

use crate::ast::{Protocol, TransportProto};
use crate::reverse::ProtocolDissection;

/// Formats an IEEE 754 `f32` parsed from big-endian wire bytes as a `real` token, rejecting NaN/Inf.
fn push_bacnet_real_token(tokens: &mut String, bytes: &[u8; 4]) -> Option<()> {
    let val = f32::from_bits(u32::from_be_bytes(*bytes));
    if !val.is_finite() {
        return None;
    }
    let rendered = format!("{val}");
    if rendered.contains(['e', 'E']) {
        tokens.push_str(&format!(" real \"{rendered}\""));
    } else {
        tokens.push_str(&format!(" real {rendered}"));
    }
    Some(())
}

/// Dissects a `bacnet`/IP BVLC (`0x81`) + NPDU + APDU message over UDP or SCTP.
pub(crate) fn dissect_bacnet(
    transport: TransportProto,
    _src_port: u16,
    _dst_port: u16,
    payload: &[u8],
) -> Option<ProtocolDissection> {
    if !matches!(transport, TransportProto::Udp | TransportProto::Sctp)
        || payload.len() < 8
        || payload[0] != 0x81
        || !matches!(payload[1], 0x0A | 0x0B)
        || u16::from_be_bytes([payload[2], payload[3]]) as usize != payload.len()
        || &payload[4..6] != b"\x01\x00"
    {
        return None;
    }
    let apdu = &payload[6..];
    let mut tokens = String::from("bacnet");
    let residual: &[u8];

    if payload[1] == 0x0B && apdu.starts_with(&[0x10, 0x08]) {
        tokens.push_str(" whois");
        if apdu.len() >= 7 && apdu[2] == 0x24 {
            let val = u32::from_be_bytes([apdu[3], apdu[4], apdu[5], apdu[6]]);
            tokens.push_str(&format!(" value {val}"));
            residual = &apdu[7..];
        } else if apdu.len() >= 7 && apdu[2] == 0x44 {
            push_bacnet_real_token(&mut tokens, &[apdu[3], apdu[4], apdu[5], apdu[6]])?;
            residual = &apdu[7..];
        } else {
            residual = &apdu[2..];
        }
    } else if payload[1] == 0x0A
        && apdu.len() >= 14
        && &apdu[0..3] == b"\x10\x00\xC4"
        && &apdu[7..14] == b"\x22\x04\x00\x91\x00\x21\x01"
    {
        tokens.push_str(" iam");
        let oid = u32::from_be_bytes([apdu[3], apdu[4], apdu[5], apdu[6]]);
        let otype = (oid >> 22) as u16;
        let oinst = oid & 0x3F_FFFF;
        if otype != 8 {
            tokens.push_str(&format!(" objecttype {otype}"));
        }
        if oinst != 1234 {
            tokens.push_str(&format!(" objectinstance {oinst}"));
        }
        if apdu.len() >= 19 && apdu[14] == 0x24 {
            let val = u32::from_be_bytes([apdu[15], apdu[16], apdu[17], apdu[18]]);
            tokens.push_str(&format!(" value {val}"));
            residual = &apdu[19..];
        } else if apdu.len() >= 19 && apdu[14] == 0x44 {
            push_bacnet_real_token(&mut tokens, &[apdu[15], apdu[16], apdu[17], apdu[18]])?;
            residual = &apdu[19..];
        } else {
            residual = &apdu[14..];
        }
    } else if payload[1] == 0x0A && apdu.len() >= 10 {
        let (is_complex_ack, svc, invoke_id, obj_off) =
            if apdu.len() >= 11 && &apdu[0..2] == b"\x00\x05" && matches!(apdu[3], 0x0C | 0x0F) {
                (false, apdu[3], apdu[2], 4usize)
            } else if apdu[0] == 0x30 && apdu[2] == 0x0C {
                (true, 0x0C, apdu[1], 3usize)
            } else {
                return None;
            };
        if apdu.len() < obj_off + 7
            || apdu[obj_off] != 0x0C
            || !matches!(apdu[obj_off + 5], 0x19 | 0x1A)
        {
            return None;
        }
        let oid = u32::from_be_bytes([
            apdu[obj_off + 1],
            apdu[obj_off + 2],
            apdu[obj_off + 3],
            apdu[obj_off + 4],
        ]);
        let otype = (oid >> 22) as u16;
        let oinst = oid & 0x3F_FFFF;
        let (prop_id, val_off) = if apdu[obj_off + 5] == 0x19 {
            (apdu[obj_off + 6] as u32, obj_off + 7)
        } else {
            if apdu.len() < obj_off + 8 {
                return None;
            }
            let p = u16::from_be_bytes([apdu[obj_off + 6], apdu[obj_off + 7]]) as u32;
            if p <= 0xFF {
                return None;
            }
            (p, obj_off + 8)
        };

        if is_complex_ack {
            tokens.push_str(" complexack");
        } else if svc == 0x0F {
            tokens.push_str(" writeproperty");
        } else {
            tokens.push_str(" readproperty");
        }
        if invoke_id != 1 {
            tokens.push_str(&format!(" invokeid {invoke_id}"));
        }
        if otype != 8 {
            tokens.push_str(&format!(" objecttype {otype}"));
        }
        if oinst != 1234 {
            tokens.push_str(&format!(" objectinstance {oinst}"));
        }
        if prop_id != 85 {
            tokens.push_str(&format!(" propertyid {prop_id}"));
        }

        if apdu.len() >= val_off + 7 && apdu[val_off] == 0x3E && apdu[val_off + 6] == 0x3F {
            match apdu[val_off + 1] {
                0x24 => {
                    let val = u32::from_be_bytes([
                        apdu[val_off + 2],
                        apdu[val_off + 3],
                        apdu[val_off + 4],
                        apdu[val_off + 5],
                    ]);
                    if (!is_complex_ack && svc == 0x0C) || val != 0 {
                        tokens.push_str(&format!(" value {val}"));
                    }
                }
                0x44 => {
                    push_bacnet_real_token(
                        &mut tokens,
                        &[
                            apdu[val_off + 2],
                            apdu[val_off + 3],
                            apdu[val_off + 4],
                            apdu[val_off + 5],
                        ],
                    )?;
                }
                _ => return None,
            }
            residual = &apdu[val_off + 7..];
        } else if !is_complex_ack && svc == 0x0C {
            residual = &apdu[val_off..];
        } else {
            return None;
        }
    } else {
        return None;
    }

    Some(ProtocolDissection {
        protocol: Protocol::Bacnet,
        tokens,
        residual_payload: residual.to_vec(),
        explicit_transport: None,
    })
}
