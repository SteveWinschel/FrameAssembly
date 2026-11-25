//! KNXnet/IP Building Automation (ISO/IEC 14543-3 / EN 50090) wire payload builder.
//!
//! This module implements [`build_knxnetip_payload`], which serializes a [`KnxnetipSpec`] AST
//! node into an ISO/IEC 14543-3 KNXnet/IP frame over UDP port 3671. It builds the 6-byte common
//! KNXnet/IP header (`0x06`, version `0x10`, 16-bit Service Type, 16-bit Total Length) alongside
//! HPAI endpoints, Device Information Blocks (`DIB`), Tunneling Connection Headers, and cEMI
//! `L_Data.req`/`L_Data.ind` frames encoding `GroupValueRead` and `GroupValueWrite` APDUs.

use crate::ast::*;
use crate::builders::WireContext;
use alloc::vec::Vec;
use core::net::IpAddr;

/// Parses a KNXnet/IP service name or 16-bit numeric code into a Service Type Identifier.
fn parse_knx_service(raw: &str) -> u16 {
    let trimmed = raw.trim();
    if let Some(hex) = trimmed.strip_prefix("0x").or_else(|| trimmed.strip_prefix("0X"))
        && let Ok(val) = u16::from_str_radix(hex, 16)
    {
        return val;
    }
    if let Ok(val) = trimmed.parse::<u16>() {
        return val;
    }
    match trimmed.to_ascii_uppercase().replace(['_', '-'], "").as_str() {
        "SEARCHREQ" | "SEARCHREQUEST" | "SEARCH" => 0x0201,
        "SEARCHRESP" | "SEARCHRESPONSE" => 0x0202,
        "DESCREQ" | "DESCRIPTIONREQUEST" => 0x0203,
        "DESCRESP" | "DESCRIPTIONRESPONSE" => 0x0204,
        "CONNECT" | "CONNECTREQ" | "CONNECTREQUEST" => 0x0205,
        "CONNACK" | "CONNECTRESP" | "CONNECTRESPONSE" => 0x0206,
        "CONNSTATEREQ" | "CONNECTIONSTATEREQUEST" => 0x0207,
        "CONNSTATERESP" | "CONNECTIONSTATERESPONSE" => 0x0208,
        "DISCONNECT" | "DISCONNECTREQ" | "DISCONNECTREQUEST" => 0x0209,
        "DISCONNECTRESP" | "DISCONNECTRESPONSE" => 0x020A,
        "TUNNEL" | "TUNNELREQ" | "TUNNELINGREQUEST" => 0x0420,
        "TUNNELACK" | "TUNNELINGACK" => 0x0421,
        "ROUTING" | "ROUTINGIND" | "ROUTINGINDICATION" => 0x0530,
        _ => 0x0420,
    }
}

/// Appends an 8-byte KNXnet/IP IPv4 HPAI structure using `ctx.src_ip` and `ctx.src_port`.
fn push_hpai(body: &mut Vec<u8>, ctx: &WireContext) {
    let ip4 = match ctx.src_ip {
        IpAddr::V4(v4) => v4.octets(),
        IpAddr::V6(_) => [10, 0, 0, 1],
    };
    let proto_code = if matches!(ctx.transport, Some(TransportProto::Tcp)) {
        0x02
    } else {
        0x01
    };
    body.push(0x08);
    body.push(proto_code);
    body.extend_from_slice(&ip4);
    body.extend_from_slice(&ctx.src_port.to_be_bytes());
}

/// Appends KNXnet/IP Device Information DIB (`54B`) and Supported Service Families DIB (`6B`).
fn push_device_dibs(body: &mut Vec<u8>, ctx: &WireContext, knx_addr: u16) {
    body.extend_from_slice(&[54, 0x01, 0x02, 0x00]); // len=54, DevInfo=1, TP1=2, status=0
    body.extend_from_slice(&knx_addr.to_be_bytes());
    body.extend_from_slice(&0u16.to_be_bytes()); // Project installation ID
    body.extend_from_slice(&[0x00, 0x01, 0x02, 0x03, 0x04, 0x05]); // KNX serial
    body.extend_from_slice(&[224, 0, 23, 12]); // Routing multicast 224.0.23.12
    body.extend_from_slice(&ctx.src_mac);
    let mut name = [0u8; 30];
    let label = b"FrameAssembly KNX";
    name[..label.len()].copy_from_slice(label);
    body.extend_from_slice(&name);

    // Supported Service Families DIB: Core v1 (0x02, 1), Tunneling v1 (0x04, 1)
    body.extend_from_slice(&[6, 0x02, 0x02, 0x01, 0x04, 0x01]);
}

/// Appends a cEMI `L_Data.req` (`0x11`) or `L_Data.ind` (`0x29`) GroupValueRead/Write frame.
fn push_cemi_frame(body: &mut Vec<u8>, msg_code: u8, spec: &KnxnetipSpec, payload_bytes: &[u8]) {
    let src = spec.src.unwrap_or(0x1101);
    let dst = spec.dst.unwrap_or(0x0801);
    body.push(msg_code);
    body.push(0x00); // Additional Info Length
    body.push(0xBC); // Ctrl1: Standard, non-repeat, domain broadcast, low prio
    body.push(0xE0); // Ctrl2: Group address, hop count 6
    body.extend_from_slice(&src.to_be_bytes());
    body.extend_from_slice(&dst.to_be_bytes());

    if spec.is_read {
        body.extend_from_slice(&[0x01, 0x00, 0x00]); // GroupValueRead
        if !payload_bytes.is_empty() {
            body.extend_from_slice(payload_bytes);
        }
    } else if spec.value.is_none() && !payload_bytes.is_empty() {
        let chunk = &payload_bytes[..payload_bytes.len().min(250)];
        body.push((1 + chunk.len()) as u8);
        body.push(0x00);
        body.push(0x80);
        body.extend_from_slice(chunk);
    } else {
        let val = spec.value.unwrap_or(1);
        if val <= 63 {
            body.extend_from_slice(&[0x01, 0x00, 0x80 | (val as u8)]);
        } else if val <= 0xFF {
            body.extend_from_slice(&[0x02, 0x00, 0x80, val as u8]);
        } else if val <= 0xFFFF {
            let b = (val as u16).to_be_bytes();
            body.extend_from_slice(&[0x03, 0x00, 0x80, b[0], b[1]]);
        } else {
            let b = val.to_be_bytes();
            body.extend_from_slice(&[0x05, 0x00, 0x80, b[0], b[1], b[2], b[3]]);
        }
        if !payload_bytes.is_empty() {
            body.extend_from_slice(payload_bytes);
        }
    }
}

/// Builds an ISO/IEC 14543-3 KNXnet/IP UDP packet payload.
pub fn build_knxnetip_payload(
    ctx: &WireContext,
    spec: &KnxnetipSpec,
    payload_bytes: &[u8],
) -> Vec<u8> {
    let svc = parse_knx_service(spec.service.unwrap_or("tunnelreq"));
    let channel = spec.channel.unwrap_or(1);
    let seq = spec.seq_num.unwrap_or(0);
    let status = spec.status.unwrap_or(0);
    let src = spec.src.unwrap_or(0x1101);

    let mut body = Vec::new();
    match svc {
        0x0201 | 0x0203 => {
            push_hpai(&mut body, ctx);
            if !payload_bytes.is_empty() {
                body.extend_from_slice(payload_bytes);
            }
        }
        0x0202 => {
            push_hpai(&mut body, ctx);
            push_device_dibs(&mut body, ctx, src);
            if !payload_bytes.is_empty() {
                body.extend_from_slice(payload_bytes);
            }
        }
        0x0204 => {
            push_device_dibs(&mut body, ctx, src);
            if !payload_bytes.is_empty() {
                body.extend_from_slice(payload_bytes);
            }
        }
        0x0205 => {
            push_hpai(&mut body, ctx);
            push_hpai(&mut body, ctx);
            body.extend_from_slice(&[0x04, 0x04, 0x02, 0x00]); // Tunnel link-layer CRI
            if !payload_bytes.is_empty() {
                body.extend_from_slice(payload_bytes);
            }
        }
        0x0206 => {
            body.push(channel);
            body.push(status);
            push_hpai(&mut body, ctx);
            let s = src.to_be_bytes();
            body.extend_from_slice(&[0x04, 0x04, s[0], s[1]]); // Tunnel CRD
            if !payload_bytes.is_empty() {
                body.extend_from_slice(payload_bytes);
            }
        }
        0x0207 | 0x0209 => {
            body.push(channel);
            body.push(0x00);
            push_hpai(&mut body, ctx);
            if !payload_bytes.is_empty() {
                body.extend_from_slice(payload_bytes);
            }
        }
        0x0208 | 0x020A => {
            body.push(channel);
            body.push(status);
            if !payload_bytes.is_empty() {
                body.extend_from_slice(payload_bytes);
            }
        }
        0x0421 => {
            body.extend_from_slice(&[0x04, channel, seq, status]);
            if !payload_bytes.is_empty() {
                body.extend_from_slice(payload_bytes);
            }
        }
        0x0530 => {
            push_cemi_frame(&mut body, 0x29, spec, payload_bytes);
        }
        0x0420 => {
            body.extend_from_slice(&[0x04, channel, seq, 0x00]);
            push_cemi_frame(&mut body, 0x11, spec, payload_bytes);
        }
        _ => {
            if !payload_bytes.is_empty() {
                body.extend_from_slice(payload_bytes);
            }
        }
    }

    let total_len = u16::try_from(6usize.saturating_add(body.len())).unwrap_or(u16::MAX);
    let mut pkt = Vec::with_capacity(usize::from(total_len));
    pkt.push(0x06); // Header Length: 6
    pkt.push(0x10); // Protocol Version: 1.0
    pkt.extend_from_slice(&svc.to_be_bytes());
    pkt.extend_from_slice(&total_len.to_be_bytes());
    pkt.extend_from_slice(&body);
    pkt
}
