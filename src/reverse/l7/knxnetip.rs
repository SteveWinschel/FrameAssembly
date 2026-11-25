//! KNXnet/IP Building Automation (ISO/IEC 14543-3 / EN 50090) Layer 7 PCAP-to-`.frasm` decompiler.
//!
//! This module implements fuzz-safe wire-to-AST dissection for `knxnetip` frames over UDP, TCP,
//! and SCTP port `3671`. It validates the 6-byte KNXnet/IP header (`0x06 0x10`, service type,
//! exact total length) and decodes Discovery/Description (`0x0201`–`0x0204`), Connection
//! Management (`0x0205`–`0x020A`), Tunneling (`0x0420` `TunnelReq`, `0x0421` `TunnelAck`), and
//! Routing (`0x0530` `RoutingInd`) alongside `cEMI` `GroupValueRead` and `GroupValueWrite` fields.

use alloc::format;
use alloc::string::String;

use crate::ast::{Protocol, TransportProto};
use crate::reverse::ProtocolDissection;

/// Validates an 8-byte KNXnet/IP IPv4 HPAI block (`len=8`, `proto=0x01|0x02`).
fn is_valid_hpai(slice: &[u8]) -> bool {
    slice.len() == 8 && slice[0] == 0x08 && matches!(slice[1], 0x01 | 0x02)
}

/// Validates the 60-byte Device Info + Supported Service Families DIBs synthesized by the forward builder.
fn parse_device_dibs(slice: &[u8]) -> Option<u16> {
    if slice.len() < 60
        || slice[0..4] != [54, 0x01, 0x02, 0x00]
        || slice[6..18] != [0, 0, 0, 1, 2, 3, 4, 5, 224, 0, 23, 12]
        || !slice[24..54].starts_with(b"FrameAssembly KNX")
        || slice[54..60] != [6, 0x02, 0x02, 0x01, 0x04, 0x01]
    {
        return None;
    }
    Some(u16::from_be_bytes([slice[4], slice[5]]))
}

/// Parses a cEMI `L_Data.req`/`L_Data.ind` GroupValueRead/Write frame and returns trailing payload bytes.
fn parse_cemi_body<'a>(
    cemi: &'a [u8],
    expected_mc: u8,
    tokens: &mut String,
) -> Option<&'a [u8]> {
    if cemi.len() < 11
        || cemi[0] != expected_mc
        || cemi[1] != 0x00
        || cemi[2] != 0xBC
        || cemi[3] != 0xE0
        || cemi[9] != 0x00
    {
        return None;
    }
    let src = u16::from_be_bytes([cemi[4], cemi[5]]);
    let dst = u16::from_be_bytes([cemi[6], cemi[7]]);
    let npdu_len = usize::from(cemi[8]);
    let frame_end = 10usize.checked_add(npdu_len)?;
    if npdu_len == 0 || cemi.len() < frame_end {
        return None;
    }
    if src != 0x1101 {
        tokens.push_str(&format!(" src 0x{src:04x}"));
    }
    if dst != 0x0801 {
        tokens.push_str(&format!(" dst 0x{dst:04x}"));
    }

    let apci_lo = cemi[10];
    if apci_lo == 0x00 && npdu_len == 1 {
        tokens.push_str(" read");
        return Some(&cemi[frame_end..]);
    }
    if (apci_lo & 0xC0) != 0x80 {
        return None;
    }
    if npdu_len == 1 {
        let val = u32::from(apci_lo & 0x3F);
        if val != 1 {
            tokens.push_str(&format!(" value {val}"));
        }
        return Some(&cemi[frame_end..]);
    }
    if apci_lo != 0x80 {
        return None;
    }
    let data = &cemi[11..frame_end];
    match data.len() {
        1 if data[0] >= 64 => {
            tokens.push_str(&format!(" value {}", data[0]));
            Some(&cemi[frame_end..])
        }
        2 => {
            let val = u16::from_be_bytes([data[0], data[1]]);
            if val > 0xFF && cemi.len() == frame_end {
                tokens.push_str(&format!(" value {val}"));
                Some(&[])
            } else {
                Some(data)
            }
        }
        4 => {
            let val = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
            if val > 0xFFFF && cemi.len() == frame_end {
                tokens.push_str(&format!(" value {val}"));
                Some(&[])
            } else {
                Some(data)
            }
        }
        _ if cemi.len() == frame_end => Some(data),
        _ => None,
    }
}

/// Dissects an ISO/IEC 14543-3 `knxnetip` frame over UDP, TCP, or SCTP.
pub(crate) fn dissect_knxnetip(
    transport: TransportProto,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Option<ProtocolDissection> {
    if !matches!(
        transport,
        TransportProto::Udp | TransportProto::Tcp | TransportProto::Sctp
    ) || payload.len() < 6
        || payload[0] != 0x06
        || payload[1] != 0x10
    {
        return None;
    }
    let svc = u16::from_be_bytes([payload[2], payload[3]]);
    let total_len = u16::from_be_bytes([payload[4], payload[5]]) as usize;
    if total_len != payload.len() {
        return None;
    }
    let on_known_port = src_port == 3671 || dst_port == 3671;
    if !on_known_port && !matches!(svc, 0x0201..=0x020A | 0x0420 | 0x0421 | 0x0530) {
        return None;
    }

    let body = &payload[6..];
    let mut tokens = String::from("knxnetip");
    let residual: &[u8] = match svc {
        0x0201 => {
            if !is_valid_hpai(body.get(0..8)?) {
                return None;
            }
            tokens.push_str(" service \"searchreq\"");
            &body[8..]
        }
        0x0202 => {
            if !is_valid_hpai(body.get(0..8)?) {
                return None;
            }
            let src = parse_device_dibs(body.get(8..68)?)?;
            tokens.push_str(" service \"searchresp\"");
            if src != 0x1101 {
                tokens.push_str(&format!(" src 0x{src:04x}"));
            }
            &body[68..]
        }
        0x0203 => {
            if !is_valid_hpai(body.get(0..8)?) {
                return None;
            }
            tokens.push_str(" service \"descreq\"");
            &body[8..]
        }
        0x0204 => {
            let src = parse_device_dibs(body.get(0..60)?)?;
            tokens.push_str(" service \"descresp\"");
            if src != 0x1101 {
                tokens.push_str(&format!(" src 0x{src:04x}"));
            }
            &body[60..]
        }
        0x0205 => {
            if !is_valid_hpai(body.get(0..8)?)
                || !is_valid_hpai(body.get(8..16)?)
                || body.get(16..20)? != [0x04, 0x04, 0x02, 0x00]
            {
                return None;
            }
            tokens.push_str(" connect");
            &body[20..]
        }
        0x0206 => {
            if body.len() < 14
                || !is_valid_hpai(body.get(2..10)?)
                || body.get(10..12)? != [0x04, 0x04]
            {
                return None;
            }
            tokens.push_str(" connack");
            if body[0] != 1 {
                tokens.push_str(&format!(" channel {}", body[0]));
            }
            if body[1] != 0 {
                tokens.push_str(&format!(" status {}", body[1]));
            }
            let src = u16::from_be_bytes([body[12], body[13]]);
            if src != 0x1101 {
                tokens.push_str(&format!(" src 0x{src:04x}"));
            }
            &body[14..]
        }
        0x0207 | 0x0209 => {
            if body.len() < 10 || body[1] != 0x00 || !is_valid_hpai(body.get(2..10)?) {
                return None;
            }
            if svc == 0x0207 {
                tokens.push_str(" service \"connstatereq\"");
            } else {
                tokens.push_str(" disconnect");
            }
            if body[0] != 1 {
                tokens.push_str(&format!(" channel {}", body[0]));
            }
            &body[10..]
        }
        0x0208 | 0x020A => {
            if body.len() < 2 {
                return None;
            }
            tokens.push_str(if svc == 0x0208 {
                " service \"connstateresp\""
            } else {
                " service \"disconnectresp\""
            });
            if body[0] != 1 {
                tokens.push_str(&format!(" channel {}", body[0]));
            }
            if body[1] != 0 {
                tokens.push_str(&format!(" status {}", body[1]));
            }
            &body[2..]
        }
        0x0421 => {
            if body.len() < 4 || body[0] != 0x04 {
                return None;
            }
            tokens.push_str(" service \"tunnelack\"");
            if body[1] != 1 {
                tokens.push_str(&format!(" channel {}", body[1]));
            }
            if body[2] != 0 {
                tokens.push_str(&format!(" seqnum {}", body[2]));
            }
            if body[3] != 0 {
                tokens.push_str(&format!(" status {}", body[3]));
            }
            &body[4..]
        }
        0x0420 => {
            if body.len() < 15 || body[0] != 0x04 || body[3] != 0x00 {
                return None;
            }
            if body[1] != 1 {
                tokens.push_str(&format!(" channel {}", body[1]));
            }
            if body[2] != 0 {
                tokens.push_str(&format!(" seqnum {}", body[2]));
            }
            parse_cemi_body(&body[4..], 0x11, &mut tokens)?
        }
        0x0530 => {
            tokens.push_str(" service \"routingind\"");
            parse_cemi_body(body, 0x29, &mut tokens)?
        }
        _ => return None,
    };

    Some(ProtocolDissection {
        protocol: Protocol::Knxnetip,
        tokens,
        residual_payload: residual.to_vec(),
        explicit_transport: matches!(transport, TransportProto::Tcp).then_some(TransportProto::Tcp),
    })
}
