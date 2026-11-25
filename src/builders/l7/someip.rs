//! AUTOSAR SOME/IP and Service Discovery (SOME/IP-SD) wire payload builder.
//!
//! This module implements [`build_someip_payload`], which serializes a [`SomeipSpec`] AST node
//! into an AUTOSAR SOME/IP or SOME/IP-SD binary frame over UDP or TCP port 30490. Every packet
//! begins with the 16-byte big-endian SOME/IP header (`Service ID`, `Method ID`, `Length`,
//! `Client ID`, `Session ID`, `Protocol Version`, `Interface Version`, `Message Type`, and
//! `Return Code`). Bare `someip` and SD modifiers synthesize a valid SOME/IP-SD (`0xFFFF8100`)
//! entry block (`FindService`, `OfferService`, `SubscribeEventgroup`, or `SubscribeEventgroupAck`)
//! with optional IPv4 (`0x04`) or IPv6 (`0x06`) Endpoint Options.

use alloc::vec::Vec;
use core::net::IpAddr;

use crate::ast::*;
use crate::builders::WireContext;

/// Parses a SOME/IP message type string or numeric byte into its AUTOSAR message type octet.
fn parse_someip_msg_type(raw: &str) -> u8 {
    let norm = raw.trim().to_ascii_uppercase().replace(['_', '-'], "");
    match norm.as_str() {
        "REQUEST" => 0x00,
        "REQUESTNOREPLY" => 0x01,
        "NOTIFICATION" => 0x02,
        "RESPONSE" => 0x80,
        "ERROR" => 0x81,
        _ => {
            if let Some(hex) = norm.strip_prefix("0X") {
                u8::from_str_radix(hex, 16).unwrap_or(0x00)
            } else {
                norm.parse::<u8>().unwrap_or(0x00)
            }
        }
    }
}

/// Parses a SOME/IP-SD entry selector string into its 8-bit SD entry type code.
fn parse_someip_sd_type(raw: &str) -> u8 {
    let norm = raw.trim().to_ascii_uppercase().replace(['_', '-'], "");
    match norm.as_str() {
        "FINDSERVICE" => 0x00,
        "OFFERSERVICE" => 0x01,
        "SUBSCRIBE" | "SUBSCRIBEEVENTGROUP" => 0x06,
        "SUBSCRIBEACK" | "SUBSCRIBEEVENTGROUPACK" => 0x07,
        _ => 0x00,
    }
}

/// Builds an AUTOSAR SOME/IP or SOME/IP-SD application payload from [`SomeipSpec`].
pub fn build_someip_payload(
    ctx: &WireContext,
    spec: &SomeipSpec,
    payload_bytes: &[u8],
) -> Vec<u8> {
    let has_sd_fields = spec.sd_type.is_some()
        || spec.sd_flags.is_some()
        || spec.sd_service.is_some()
        || spec.instance_id.is_some()
        || spec.major_ver.is_some()
        || spec.sd_ttl.is_some()
        || spec.minor_ver.is_some()
        || spec.endpoint_ip.is_some()
        || spec.endpoint_port.is_some();

    let has_rpc_fields = spec.msg_type.is_some()
        || spec.service_id.is_some_and(|s| s != 0xFFFF)
        || spec.method_id.is_some_and(|m| m != 0x8100);

    let is_sd = (spec.service_id == Some(0xFFFF) && spec.method_id == Some(0x8100))
        || has_sd_fields
        || (!has_rpc_fields && payload_bytes.is_empty());

    let (service_id, method_id, default_client, default_msg) = if is_sd {
        (
            spec.service_id.unwrap_or(0xFFFF),
            spec.method_id.unwrap_or(0x8100),
            0x0000u16,
            "notification",
        )
    } else {
        (
            spec.service_id.unwrap_or(0x0001),
            spec.method_id.unwrap_or(0x0001),
            0x0001u16,
            "request",
        )
    };

    let client_id = spec.client_id.unwrap_or(default_client);
    let session_id = spec.session_id.unwrap_or(1);
    let proto_ver = spec.proto_ver.unwrap_or(1);
    let iface_ver = spec.iface_ver.unwrap_or(1);
    let msg_type = parse_someip_msg_type(spec.msg_type.unwrap_or(default_msg));
    let return_code = spec.return_code.unwrap_or(0);

    let mut body = Vec::new();
    if is_sd && service_id == 0xFFFF && method_id == 0x8100 && payload_bytes.is_empty() {
        let entry_type = parse_someip_sd_type(spec.sd_type.unwrap_or("findservice"));
        let sd_flags = spec.sd_flags.unwrap_or(0xC0);
        let sd_service = spec.sd_service.unwrap_or(0x1234);
        let default_inst = if entry_type == 0x00 { 0xFFFF } else { 0x0001 };
        let instance_id = spec.instance_id.unwrap_or(default_inst);
        let major_ver = spec.major_ver.unwrap_or(1);
        let sd_ttl = spec.sd_ttl.unwrap_or(3) & 0x00FF_FFFF;
        let default_minor = if matches!(entry_type, 0x06 | 0x07) {
            1
        } else {
            0
        };
        let minor_ver = spec.minor_ver.unwrap_or(default_minor);

        let mut options = Vec::new();
        let has_endpoint = spec.endpoint_ip.is_some() || spec.endpoint_port.is_some();
        if has_endpoint {
            let ep_ip = spec.endpoint_ip.unwrap_or(ctx.src_ip);
            let ep_port = spec.endpoint_port.unwrap_or(30509);
            let l4_proto = if ctx.transport == Some(TransportProto::Tcp) {
                0x06u8
            } else {
                0x11u8
            };
            match ep_ip {
                IpAddr::V4(v4) => {
                    options.extend_from_slice(&9u16.to_be_bytes()); // Length: 9
                    options.push(0x04); // IPv4 Endpoint Option
                    options.push(0x00); // Reserved
                    options.extend_from_slice(&v4.octets());
                    options.push(0x00); // Reserved
                    options.push(l4_proto);
                    options.extend_from_slice(&ep_port.to_be_bytes());
                }
                IpAddr::V6(v6) => {
                    options.extend_from_slice(&21u16.to_be_bytes()); // Length: 21
                    options.push(0x06); // IPv6 Endpoint Option
                    options.push(0x00); // Reserved
                    options.extend_from_slice(&v6.octets());
                    options.push(0x00); // Reserved
                    options.push(l4_proto);
                    options.extend_from_slice(&ep_port.to_be_bytes());
                }
            }
        }

        body.push(sd_flags);
        body.extend_from_slice(&[0x00, 0x00, 0x00]); // Reserved
        body.extend_from_slice(&16u32.to_be_bytes()); // Entries Array Length (16B)

        // 16-byte SOME/IP-SD Entry
        body.push(entry_type);
        body.push(0x00); // Index 1st Options
        body.push(0x00); // Index 2nd Options
        body.push(if has_endpoint { 0x10 } else { 0x00 }); // Num Options 1 | Num Options 2
        body.extend_from_slice(&sd_service.to_be_bytes());
        body.extend_from_slice(&instance_id.to_be_bytes());
        body.push(major_ver);
        let ttl_bytes = sd_ttl.to_be_bytes();
        body.extend_from_slice(&ttl_bytes[1..4]);
        if matches!(entry_type, 0x06 | 0x07) {
            body.extend_from_slice(&0u16.to_be_bytes()); // Reserved + Initial Data Flag
            body.extend_from_slice(&((minor_ver & 0xFFFF) as u16).to_be_bytes());
        } else {
            body.extend_from_slice(&minor_ver.to_be_bytes());
        }

        body.extend_from_slice(&(options.len() as u32).to_be_bytes());
        body.extend_from_slice(&options);
    } else if !payload_bytes.is_empty() {
        body.extend_from_slice(payload_bytes);
    }

    let length = u32::try_from(8usize.saturating_add(body.len())).unwrap_or(u32::MAX);
    let mut pkt = Vec::with_capacity(16 + body.len());
    pkt.extend_from_slice(&service_id.to_be_bytes());
    pkt.extend_from_slice(&method_id.to_be_bytes());
    pkt.extend_from_slice(&length.to_be_bytes());
    pkt.extend_from_slice(&client_id.to_be_bytes());
    pkt.extend_from_slice(&session_id.to_be_bytes());
    pkt.push(proto_ver);
    pkt.push(iface_ver);
    pkt.push(msg_type);
    pkt.push(return_code);
    pkt.extend_from_slice(&body);
    pkt
}
