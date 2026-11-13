//! Building Automation and Control Networks over IP (BACnet/IP, ASHRAE 135) Layer 7 PCAP-to-`.frasm` decompiler.
//!
//! This module implements fuzz-safe wire-to-AST dissection for `bacnet`/IP BVLC (`0x81`, unicast
//! `0x0A` or broadcast `0x0B`), NPDU (`\x01\x00`), and APDU messages over UDP (port `47808` and
//! secondary BACnet UDP ports). It decodes `Who-Is` (`whois`), `I-Am` (`iam`), `ReadProperty`
//! (`readproperty`), and `WriteProperty` (`writeproperty`) services along with `invokeid`,
//! `objecttype`, `objectinstance`, `propertyid`, and `value` modifiers.

use alloc::format;
use alloc::string::String;

use crate::ast::{Protocol, TransportProto};
use crate::reverse::ProtocolDissection;

/// Dissects a `bacnet`/IP BVLC (`0x81`) + NPDU + APDU message over UDP.
pub(crate) fn dissect_bacnet(
    transport: TransportProto,
    _src_port: u16,
    _dst_port: u16,
    payload: &[u8],
) -> Option<ProtocolDissection> {
    if !matches!(transport, TransportProto::Udp)
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
        } else {
            residual = &apdu[14..];
        }
    } else if payload[1] == 0x0A
        && apdu.len() >= 11
        && &apdu[0..2] == b"\x00\x05"
        && matches!(apdu[3], 0x0C | 0x0F)
        && apdu[4] == 0x0C
        && apdu[9] == 0x19
    {
        let invoke_id = apdu[2];
        let svc = apdu[3];
        let oid = u32::from_be_bytes([apdu[5], apdu[6], apdu[7], apdu[8]]);
        let otype = (oid >> 22) as u16;
        let oinst = oid & 0x3F_FFFF;
        let prop_id = apdu[10] as u32;

        if svc == 0x0F {
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
        if apdu.len() >= 18 && apdu[11] == 0x3E && apdu[12] == 0x24 && apdu[17] == 0x3F {
            let val = u32::from_be_bytes([apdu[13], apdu[14], apdu[15], apdu[16]]);
            if svc == 0x0C || val != 0 {
                tokens.push_str(&format!(" value {val}"));
            }
            residual = &apdu[18..];
        } else if svc == 0x0C {
            residual = &apdu[11..];
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
