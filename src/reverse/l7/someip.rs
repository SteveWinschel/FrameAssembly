//! AUTOSAR SOME/IP and Service Discovery (SOME/IP-SD) Layer 7 PCAP-to-`.frasm` decompiler.
//!
//! This module implements fuzz-safe wire-to-AST dissection for AUTOSAR `someip` RPC and
//! `someip-sd` (`0xFFFF8100`) messages over UDP, TCP, and SCTP transports (port `30490` and
//! secondary SOME/IP endpoints). It decodes the 16-byte SOME/IP header (`serviceid`,
//! `methodid`, `clientid`, `sessionid`, `protover`, `ifacever`, `msgtype` / shorthand flags,
//! `returncode`) as well as SOME/IP-SD entries (`findservice`, `offerservice`, `subscribe`,
//! `subscribeack`, `flags`, `sdservice`, `instanceid`, `majorver`, `sdttl`, `minorver`) and
//! IPv4 (`0x04`) or IPv6 (`0x06`) Endpoint Options (`endpointip`, `endpointport`).

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write as _;
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::ast::{Protocol, TransportProto};
use crate::reverse::ProtocolDissection;

/// Dissects a canonical SOME/IP-SD single-entry payload into SD modifier tokens.
fn dissect_someip_sd_body(body: &[u8], tokens: &mut String) -> Option<Vec<u8>> {
    if body.len() < 28 {
        return None;
    }
    if body[1..4] != [0x00, 0x00, 0x00] {
        return None;
    }
    let sd_flags = body[0];
    let entries_len = u32::from_be_bytes([body[4], body[5], body[6], body[7]]) as usize;
    if entries_len != 16 {
        return None;
    }
    let entry = &body[8..24];
    let entry_type = entry[0];
    if !matches!(entry_type, 0x00 | 0x01 | 0x06 | 0x07) {
        return None;
    }
    if entry[1] != 0x00 || entry[2] != 0x00 || !matches!(entry[3], 0x00 | 0x10) {
        return None;
    }
    let num_opts = entry[3] >> 4;
    let sd_service = u16::from_be_bytes([entry[4], entry[5]]);
    let instance_id = u16::from_be_bytes([entry[6], entry[7]]);
    let major_ver = entry[8];
    let sd_ttl = u32::from_be_bytes([0, entry[9], entry[10], entry[11]]);
    let minor_ver = if matches!(entry_type, 0x06 | 0x07) {
        if entry[12] != 0x00 || entry[13] != 0x00 {
            return None;
        }
        u32::from(u16::from_be_bytes([entry[14], entry[15]]))
    } else {
        u32::from_be_bytes([entry[12], entry[13], entry[14], entry[15]])
    };

    let opts_len = u32::from_be_bytes([body[24], body[25], body[26], body[27]]) as usize;
    let opts_end = 28usize.checked_add(opts_len)?;
    if opts_end != body.len() {
        return None;
    }
    let opts = &body[28..opts_end];

    let ep_info: Option<(IpAddr, u16)> = if num_opts == 0 {
        if !opts.is_empty() {
            return None;
        }
        None
    } else if opts.len() == 12 && opts[0..4] == [0x00, 0x09, 0x04, 0x00] && opts[8] == 0x00 {
        let ip = IpAddr::V4(Ipv4Addr::new(opts[4], opts[5], opts[6], opts[7]));
        let port = u16::from_be_bytes([opts[10], opts[11]]);
        Some((ip, port))
    } else if opts.len() == 24 && opts[0..4] == [0x00, 0x15, 0x06, 0x00] && opts[20] == 0x00 {
        let mut arr = [0u8; 16];
        arr.copy_from_slice(&opts[4..20]);
        let port = u16::from_be_bytes([opts[22], opts[23]]);
        Some((IpAddr::V6(Ipv6Addr::from(arr)), port))
    } else {
        return None;
    };

    match entry_type {
        0x00 => {}
        0x01 => tokens.push_str(" offerservice"),
        0x06 => tokens.push_str(" subscribe"),
        0x07 => tokens.push_str(" subscribeack"),
        _ => return None,
    }
    if sd_flags != 0xC0 {
        let _ = write!(tokens, " flags 0x{sd_flags:02x}");
    }
    if sd_service != 0x1234 {
        let _ = write!(tokens, " sdservice 0x{sd_service:04x}");
    }
    let default_inst = if entry_type == 0x00 { 0xFFFF } else { 0x0001 };
    if instance_id != default_inst {
        let _ = write!(tokens, " instanceid 0x{instance_id:04x}");
    }
    if major_ver != 1 {
        let _ = write!(tokens, " majorver {major_ver}");
    }
    if sd_ttl != 3 {
        let _ = write!(tokens, " sdttl {sd_ttl}");
    }
    let default_minor = if matches!(entry_type, 0x06 | 0x07) {
        1
    } else {
        0
    };
    if minor_ver != default_minor {
        let _ = write!(tokens, " minorver {minor_ver}");
    }
    if let Some((ip, port)) = ep_info {
        let _ = write!(tokens, " endpointip {ip}");
        if port != 30509 {
            let _ = write!(tokens, " endpointport {port}");
        }
    }

    Some(Vec::new())
}

/// Dissects an AUTOSAR `someip` or `someip-sd` message over UDP, TCP, or SCTP.
pub(crate) fn dissect_someip(
    transport: TransportProto,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Option<ProtocolDissection> {
    if payload.len() < 16
        || !matches!(
            transport,
            TransportProto::Udp | TransportProto::Tcp | TransportProto::Sctp
        )
    {
        return None;
    }

    let service_id = u16::from_be_bytes([payload[0], payload[1]]);
    let method_id = u16::from_be_bytes([payload[2], payload[3]]);
    let someip_len = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]) as usize;
    let client_id = u16::from_be_bytes([payload[8], payload[9]]);
    let session_id = u16::from_be_bytes([payload[10], payload[11]]);
    let proto_ver = payload[12];
    let iface_ver = payload[13];
    let msg_type = payload[14];
    let return_code = payload[15];

    if proto_ver != 1
        || someip_len < 8
        || 8usize.checked_add(someip_len) != Some(payload.len())
        || !matches!(msg_type, 0x00 | 0x01 | 0x02 | 0x80 | 0x81)
    {
        return None;
    }

    let is_sd_id = service_id == 0xFFFF && method_id == 0x8100;
    if src_port != 30490 && dst_port != 30490 && !is_sd_id {
        return None;
    }

    let body = &payload[16..];
    let mut tokens = String::from("someip");
    let explicit_transport = if matches!(transport, TransportProto::Tcp) {
        Some(TransportProto::Tcp)
    } else {
        None
    };

    let mut sd_tokens = String::new();
    let decoded_sd = if is_sd_id {
        dissect_someip_sd_body(body, &mut sd_tokens)
    } else {
        None
    };

    let residual: Vec<u8>;
    if let Some(res) = decoded_sd {
        if msg_type != 0x02 {
            if sd_tokens.is_empty() {
                tokens.push_str(" findservice");
            }
            let _ = write!(tokens, " msgtype 0x{msg_type:02x}");
        }
        if client_id != 0 {
            let _ = write!(tokens, " clientid {client_id}");
        }
        tokens.push_str(&sd_tokens);
        residual = res;
    } else {
        if is_sd_id {
            let _ = write!(tokens, " serviceid 0xffff methodid 0x8100");
        } else {
            if service_id != 0x0001 {
                let _ = write!(tokens, " serviceid 0x{service_id:04x}");
            }
            if method_id != 0x0001 {
                let _ = write!(tokens, " methodid 0x{method_id:04x}");
            }
        }
        match msg_type {
            0x00 => {
                if !is_sd_id && service_id == 0x0001 && method_id == 0x0001 {
                    tokens.push_str(" request");
                }
            }
            0x01 => tokens.push_str(" requestnoreply"),
            0x02 => tokens.push_str(" notification"),
            0x80 => tokens.push_str(" response"),
            0x81 => tokens.push_str(" error"),
            _ => return None,
        }
        if client_id != 0x0001 {
            let _ = write!(tokens, " clientid {client_id}");
        }
        residual = body.to_vec();
    }

    if session_id != 1 {
        let _ = write!(tokens, " sessionid {session_id}");
    }
    if iface_ver != 1 {
        let _ = write!(tokens, " ifacever {iface_ver}");
    }
    if return_code != 0 {
        let _ = write!(tokens, " returncode 0x{return_code:02x}");
    }

    Some(ProtocolDissection {
        protocol: Protocol::Someip,
        tokens,
        residual_payload: residual,
        explicit_transport,
    })
}
