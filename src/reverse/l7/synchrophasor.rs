//! IEEE C37.118 Synchrophasor (PMU/PDC Telemetry) Layer 7 PCAP-to-`.frasm` decompiler.
//!
//! This module implements fuzz-safe wire-to-AST dissection for `synchrophasor` IEEE C37.118-2005
//! and C37.118.2-2011 frames (`0xAA` sync byte with exact `FRAMESIZE` and CRC-CCITT validation
//! on custom ports) over TCP, UDP, and SCTP transports (ports `4712` and `4713`). It decodes
//! `Command` (`cmd`), `Header` (`header`), `Data` (`data` + `status`), `CFG-1` (`cfg1`),
//! `CFG-2` (`cfg2` + `station`), and `CFG-3` (`cfg3`) frames along with `version`, `id`,
//! `timestamp`, `fracsec`, and `crc` overrides.

use alloc::format;
use alloc::string::String;

use crate::ast::{Protocol, TransportProto};
use crate::builders::l7::synchrophasor::{DEFAULT_C37_SOC, calculate_c37_crc};
use crate::reverse::{ProtocolDissection, be_u16, be_u32};

use super::quote_raw_str;

/// Validates a 16-byte space-padded ASCII station or channel field and returns its trimmed string.
fn parse_padded_16(bytes: &[u8]) -> Option<&str> {
    if bytes.len() != 16 {
        return None;
    }
    let s = core::str::from_utf8(bytes).ok()?;
    let trimmed = s.trim_end_matches(' ');
    if trimmed.chars().all(|c| !c.is_control()) {
        Some(trimmed)
    } else {
        None
    }
}

/// Dissects an IEEE C37.118 `synchrophasor` frame over TCP, UDP, or SCTP.
pub(crate) fn dissect_synchrophasor(
    transport: TransportProto,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Option<ProtocolDissection> {
    if !matches!(
        transport,
        TransportProto::Tcp | TransportProto::Udp | TransportProto::Sctp
    ) || payload.len() < 16
        || payload[0] != 0xAA
    {
        return None;
    }

    let frame_type = (payload[1] >> 4) & 0x07;
    let version = payload[1] & 0x0F;
    let frame_size = usize::from(be_u16(payload, 2));
    if frame_type > 5 || version == 0 || frame_size != payload.len() {
        return None;
    }

    let expected_crc = calculate_c37_crc(&payload[..payload.len() - 2]);
    let wire_crc = be_u16(payload, payload.len() - 2);
    let on_known_port = matches!(src_port, 4712 | 4713) || matches!(dst_port, 4712 | 4713);
    if !on_known_port && wire_crc != expected_crc {
        return None;
    }

    let id_code = be_u16(payload, 4);
    let soc = be_u32(payload, 6);
    let frac_sec = be_u32(payload, 10);
    let body = &payload[14..payload.len() - 2];

    let mut tokens = String::from("synchrophasor");
    let residual: &[u8] = match frame_type {
        0 => {
            if body.len() < 2 {
                return None;
            }
            let status = be_u16(body, 0);
            tokens.push_str(" msgtype \"data\"");
            if status != 0 {
                tokens.push_str(&format!(" status 0x{status:04x}"));
            }
            &body[2..]
        }
        1 => {
            tokens.push_str(" msgtype \"header\"");
            if body == b"PMU_1 Header\n" {
                &[]
            } else {
                body
            }
        }
        2 | 3 => {
            if body.len() < 58
                || be_u32(body, 0) != 1_000_000
                || be_u16(body, 4) != 1
                || be_u16(body, 22) != id_code
                || body[24..32] != [0, 0, 0, 1, 0, 0, 0, 0]
                || body[32..48] != *b"VA              "
                || body[48..56] != [0, 0, 0, 0, 0, 0, 0, 1]
                || body[56..58] != [0x00, 0x1E]
            {
                return None;
            }
            let stn = parse_padded_16(&body[6..22])?;
            tokens.push_str(if frame_type == 2 {
                " msgtype \"cfg1\""
            } else {
                " msgtype \"cfg2\""
            });
            if stn != "PMU_1" {
                tokens.push_str(&format!(" station \"{}\"", quote_raw_str(stn)));
            }
            &body[58..]
        }
        5 => {
            if body.len() < 10
                || body[..10] != [0x00, 0x00, 0x00, 0x0F, 0x42, 0x40, 0x00, 0x00, 0x00, 0x1E]
            {
                return None;
            }
            tokens.push_str(" msgtype \"cfg3\"");
            &body[10..]
        }
        _ => {
            if body.len() < 2 {
                return None;
            }
            let cmd = be_u16(body, 0);
            if cmd != 5 {
                tokens.push_str(&format!(" cmd {cmd}"));
            }
            &body[2..]
        }
    };

    if version != 1 {
        tokens.push_str(&format!(" version {version}"));
    }
    if id_code != 1 {
        tokens.push_str(&format!(" id {id_code}"));
    }
    if soc != DEFAULT_C37_SOC {
        tokens.push_str(&format!(" timestamp {soc}"));
    }
    if frac_sec != 0 {
        tokens.push_str(&format!(" fracsec 0x{frac_sec:08x}"));
    }
    if wire_crc != expected_crc {
        tokens.push_str(&format!(" crc 0x{wire_crc:04x}"));
    }

    Some(ProtocolDissection {
        protocol: Protocol::Synchrophasor,
        tokens,
        residual_payload: residual.to_vec(),
        explicit_transport: if matches!(transport, TransportProto::Udp) {
            Some(TransportProto::Udp)
        } else {
            None
        },
    })
}
