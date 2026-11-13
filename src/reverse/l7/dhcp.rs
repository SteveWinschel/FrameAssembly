//! Dynamic Host Configuration Protocol (`dhcp`, RFC 2131 / RFC 8415) Layer 7 PCAP-to-`.frasm` decompiler.
//!
//! This module implements the fuzz-safe reverse dissectors for both IPv4 BOOTP / `dhcp` (RFC 2131
//! and RFC 2132 over UDP ports `67` and `68`) and `DHCPv6` (RFC 8415 over UDP ports `546` and
//! `547`). It decodes transaction identifiers (`xid`), client/server IPv4 addresses (`ciaddr`,
//! `yiaddr`, `siaddr`), client hardware MAC addresses (`chaddr`), and DHCP options (`subnetmask`,
//! `router`, `dnsserver`, `hostname`, `leasetime`) into canonical `.frasm` modifiers.

use alloc::format;
use alloc::string::ToString;
use alloc::vec::Vec;
use core::fmt::Write as _;
use core::net::Ipv4Addr;

use crate::ast::Protocol;
use crate::reverse::{ProtocolDissection, be_u16, be_u32, format_mac_lower, ipv4_at, push_if};

use super::{is_printable_ascii_str, ok_dissect, push_opt, push_str_if};

/// Dissects an RFC 2131 DHCPv4 or RFC 8415 DHCPv6 payload over UDP ports `67`/`68` or `546`/`547`.
pub(crate) fn dissect_dhcp(payload: &[u8], is_ipv6: bool) -> Option<ProtocolDissection> {
    if is_ipv6 {
        dissect_dhcpv6(payload)
    } else {
        dissect_dhcpv4(payload)
    }
}

/// Dissects an RFC 2131 BOOTP / DHCPv4 payload (236B header + 4B magic cookie + TLV options).
pub(crate) fn dissect_dhcpv4(payload: &[u8]) -> Option<ProtocolDissection> {
    if payload.len() < 241 || payload[236..240] != [99, 130, 83, 99] {
        return None;
    }

    let (xid, ciaddr, yiaddr, siaddr) = (
        be_u32(payload, 4),
        ipv4_at(payload, 12),
        ipv4_at(payload, 16),
        ipv4_at(payload, 20),
    );
    let mut chaddr = [0u8; 6];
    chaddr.copy_from_slice(&payload[28..34]);

    let (mut msg_type, mut subnet_mask, mut router, mut dns_server, mut hostname, mut lease_time) =
        (None, None, None, None, None, None);
    let mut residual_payload = Vec::new();

    let mut idx = 240usize;
    while idx < payload.len() {
        let opt = payload[idx];
        if opt == 255 {
            break;
        }
        if opt == 0 {
            residual_payload.push(0);
            idx += 1;
            continue;
        }
        if idx + 1 >= payload.len() {
            residual_payload.extend_from_slice(&payload[idx..]);
            break;
        }
        let len = payload[idx + 1] as usize;
        if idx + 2 + len > payload.len() {
            let end_slice = if payload.last() == Some(&255) {
                &payload[idx..payload.len() - 1]
            } else {
                &payload[idx..]
            };
            residual_payload.extend_from_slice(end_slice);
            break;
        }
        let val = &payload[idx + 2..idx + 2 + len];
        match opt {
            53 if len == 1 && msg_type.is_none() => msg_type = Some(val[0]),
            1 if len == 4 && subnet_mask.is_none() => subnet_mask = Some(ipv4_at(val, 0)),
            3 if len == 4 && router.is_none() => router = Some(ipv4_at(val, 0)),
            6 if len == 4 && dns_server.is_none() => dns_server = Some(ipv4_at(val, 0)),
            12 if hostname.is_none() => {
                if let Some(s) = is_printable_ascii_str(val) {
                    hostname = Some(s.to_string());
                } else {
                    residual_payload.extend_from_slice(&payload[idx..idx + 2 + len]);
                }
            }
            51 if len == 4 && lease_time.is_none() => lease_time = Some(be_u32(val, 0)),
            _ => residual_payload.extend_from_slice(&payload[idx..idx + 2 + len]),
        }
        idx += 2 + len;
    }

    let bootp_flags = be_u16(payload, 10);
    let mut tokens = match (msg_type.unwrap_or(1), bootp_flags) {
        (1, 0x8000) => "dhcp discover".to_string(),
        (1, 0x0000) => "dhcp".to_string(),
        (2, 0x0000) => "dhcp offer".to_string(),
        (3, 0x0000) => "dhcp request".to_string(),
        (5, 0x0000) => "dhcp ack".to_string(),
        (7, 0x0000) => "dhcp release".to_string(),
        _ => return None,
    };
    if xid != 0x1234_5678 {
        let _ = write!(tokens, " xid 0x{xid:08x}");
    }
    push_if(&mut tokens, "ciaddr", ciaddr, Ipv4Addr::UNSPECIFIED);
    push_if(&mut tokens, "yiaddr", yiaddr, Ipv4Addr::UNSPECIFIED);
    push_if(&mut tokens, "siaddr", siaddr, Ipv4Addr::UNSPECIFIED);
    let _ = write!(tokens, " chaddr {}", format_mac_lower(chaddr));
    push_opt(&mut tokens, "subnetmask", subnet_mask);
    push_opt(&mut tokens, "router", router);
    push_opt(&mut tokens, "dnsserver", dns_server);
    if let Some(h) = hostname {
        push_str_if(&mut tokens, "hostname", &h, "");
    }
    push_opt(&mut tokens, "leasetime", lease_time);

    ok_dissect(Protocol::Dhcp, tokens, residual_payload)
}

/// Dissects an RFC 8415 DHCPv6 payload (1B msg-type + 3B transaction-id + Option 1 DUID-LL).
pub(crate) fn dissect_dhcpv6(payload: &[u8]) -> Option<ProtocolDissection> {
    if payload.len() < 4 {
        return None;
    }
    let msg_kw = match payload[0] {
        1 => "solicit",
        2 => "advertise",
        3 => "request",
        7 => "reply",
        8 => "release",
        _ => return None,
    };
    let xid = ((payload[1] as u32) << 16) | ((payload[2] as u32) << 8) | (payload[3] as u32);

    let mut chaddr_opt = None;
    let mut residual_payload = Vec::new();
    if payload.len() >= 18 && payload[4..12] == [0, 1, 0, 10, 0, 3, 0, 1] {
        let mut chaddr = [0u8; 6];
        chaddr.copy_from_slice(&payload[12..18]);
        chaddr_opt = Some(chaddr);
        residual_payload.extend_from_slice(&payload[18..]);
    } else if payload.len() > 4 {
        residual_payload.extend_from_slice(&payload[4..]);
    }

    let mut tokens = format!("dhcp {msg_kw}");
    if xid != 0x0012_3456 {
        let _ = write!(tokens, " xid 0x{xid:06x}");
    }
    if let Some(chaddr) = chaddr_opt {
        let _ = write!(tokens, " chaddr {}", format_mac_lower(chaddr));
    }

    ok_dissect(Protocol::Dhcp, tokens, residual_payload)
}
