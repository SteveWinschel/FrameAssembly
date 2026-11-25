//! Dynamic Host Configuration Protocol (`dhcp`, RFC 2131 / RFC 8415) Layer 7 PCAP-to-`.frasm` decompiler.
//!
//! This module implements the fuzz-safe reverse dissectors for both IPv4 BOOTP / `dhcp` (RFC 2131
//! and RFC 2132 over UDP ports `67` and `68`) and `DHCPv6` (RFC 8415 over UDP ports `546` and
//! `547`). It decodes transaction identifiers (`xid`), client/server addresses (`ciaddr`, `yiaddr`,
//! `siaddr`), client hardware MACs (`chaddr`), DHCPv4 Options `1`/`3`/`6`/`12`/`50`/`51`/`53`/`54`/`55`,
//! and DHCPv6 Options `1`/`2`/`3`/`5`/`23`/`39` into canonical `.frasm` modifiers.

use alloc::format;
use alloc::string::ToString;
use alloc::vec::Vec;
use core::fmt::Write as _;
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::ast::Protocol;
use crate::reverse::{
    ProtocolDissection, be_u16, be_u32, format_mac_lower, ipv4_at, ipv6_at, push_if,
};

use super::{is_printable_ascii_str, ok_dissect, push_opt, push_str_if};

/// Dissects an RFC 2131 DHCPv4 or RFC 8415 DHCPv6 payload over UDP ports `67`/`68` or `546`/`547`.
pub(crate) fn dissect_dhcp(
    payload: &[u8],
    is_ipv6: bool,
    dst_ip: Option<IpAddr>,
) -> Option<ProtocolDissection> {
    if is_ipv6 {
        dissect_dhcpv6(payload)
    } else {
        dissect_dhcpv4(payload, dst_ip)
    }
}

/// Dissects an RFC 2131 BOOTP / DHCPv4 payload (236B header + 4B magic cookie + TLV options).
pub(crate) fn dissect_dhcpv4(payload: &[u8], dst_ip: Option<IpAddr>) -> Option<ProtocolDissection> {
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
    let (mut seen_req_ip, mut seen_server_id, mut seen_prl) = (false, false, false);
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
        let raw_opt = &payload[idx..idx + 2 + len];
        let mtype = msg_type.unwrap_or(1);
        let is_server_msg = matches!(mtype, 2 | 5);
        match opt {
            53 if len == 1 && msg_type.is_none() => msg_type = Some(val[0]),
            1 if len == 4 && subnet_mask.is_none() && residual_payload.is_empty() => {
                subnet_mask = Some(ipv4_at(val, 0));
            }
            3 if len == 4 && router.is_none() && residual_payload.is_empty() => {
                router = Some(ipv4_at(val, 0));
            }
            6 if len == 4 && dns_server.is_none() && residual_payload.is_empty() => {
                dns_server = Some(ipv4_at(val, 0));
            }
            12 if hostname.is_none() && residual_payload.is_empty() => {
                if let Some(s) = is_printable_ascii_str(val) {
                    hostname = Some(s.to_string());
                } else {
                    residual_payload.extend_from_slice(raw_opt);
                }
            }
            50 if len == 4
                && !is_server_msg
                && !seen_req_ip
                && residual_payload.is_empty()
                && ((yiaddr != Ipv4Addr::UNSPECIFIED && ipv4_at(val, 0) == yiaddr)
                    || (yiaddr == Ipv4Addr::UNSPECIFIED && mtype == 3)) =>
            {
                seen_req_ip = true;
            }
            51 if len == 4 && lease_time.is_none() && residual_payload.is_empty() => {
                lease_time = Some(be_u32(val, 0));
            }
            54 if len == 4 && !seen_server_id && residual_payload.is_empty() => {
                let sid = ipv4_at(val, 0);
                let matches_expected = if !siaddr.is_unspecified() {
                    sid == siaddr
                } else if matches!(mtype, 2 | 5) {
                    true
                } else if matches!(mtype, 3 | 7) {
                    match dst_ip {
                        Some(IpAddr::V4(v4))
                            if !v4.is_unspecified()
                                && !v4.is_multicast()
                                && v4 != Ipv4Addr::BROADCAST =>
                        {
                            sid == v4
                        }
                        _ => sid == Ipv4Addr::new(192, 168, 1, 1),
                    }
                } else {
                    false
                };
                if matches_expected {
                    seen_server_id = true;
                } else {
                    residual_payload.extend_from_slice(raw_opt);
                }
            }
            55 if !seen_prl
                && residual_payload.is_empty()
                && matches!(mtype, 1 | 3)
                && val == [1, 3, 6, 15, 51, 54] =>
            {
                seen_prl = true;
            }
            _ => residual_payload.extend_from_slice(raw_opt),
        }
        idx += 2 + len;
    }

    let resolved_mtype = msg_type.unwrap_or(1);
    let bootp_flags = be_u16(payload, 10);
    let mut tokens = match (resolved_mtype, bootp_flags) {
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
    if let Some(lease) = lease_time
        && !(matches!(resolved_mtype, 2 | 5) && lease == 3600)
    {
        let _ = write!(tokens, " leasetime {lease}");
    }

    ok_dissect(Protocol::Dhcp, tokens, residual_payload)
}

/// Dissects an RFC 8415 DHCPv6 payload (1B msg-type + 3B transaction-id + TLV options).
pub(crate) fn dissect_dhcpv6(payload: &[u8]) -> Option<ProtocolDissection> {
    if payload.len() < 4 {
        return None;
    }
    let msg_type = payload[0];
    let msg_kw = match msg_type {
        1 => "solicit",
        2 => "advertise",
        3 => "request",
        7 => "reply",
        8 => "release",
        _ => return None,
    };
    let is_server_msg = matches!(msg_type, 2 | 7);
    let xid = ((payload[1] as u32) << 16) | ((payload[2] as u32) << 8) | (payload[3] as u32);

    let mut chaddr_opt: Option<[u8; 6]> = None;
    let mut seen_server_id = false;
    let mut yiaddr_opt: Option<Ipv6Addr> = None;
    let mut lease_opt: Option<u32> = None;
    let mut dns_opt: Option<Ipv6Addr> = None;
    let mut hostname_opt: Option<alloc::string::String> = None;
    let mut residual_payload = Vec::new();

    let mut idx = 4usize;
    while idx < payload.len() {
        let Some(hdr_end) = idx.checked_add(4) else {
            residual_payload.extend_from_slice(&payload[idx..]);
            break;
        };
        if hdr_end > payload.len() {
            residual_payload.extend_from_slice(&payload[idx..]);
            break;
        }
        let opt_code = be_u16(payload, idx);
        let opt_len = usize::from(be_u16(payload, idx + 2));
        let Some(opt_end) = hdr_end.checked_add(opt_len) else {
            residual_payload.extend_from_slice(&payload[idx..]);
            break;
        };
        if opt_end > payload.len() {
            residual_payload.extend_from_slice(&payload[idx..]);
            break;
        }
        let val = &payload[hdr_end..opt_end];
        let raw_opt = &payload[idx..opt_end];

        if opt_code == 1
            && opt_len == 10
            && val[..4] == [0, 3, 0, 1]
            && chaddr_opt.is_none()
            && !seen_server_id
            && yiaddr_opt.is_none()
            && dns_opt.is_none()
            && hostname_opt.is_none()
            && residual_payload.is_empty()
        {
            let mut mac = [0u8; 6];
            mac.copy_from_slice(&val[4..10]);
            chaddr_opt = Some(mac);
        } else if is_server_msg
            && opt_code == 2
            && opt_len == 10
            && val[..4] == [0, 3, 0, 1]
            && chaddr_opt.is_some()
            && !seen_server_id
            && yiaddr_opt.is_none()
            && dns_opt.is_none()
            && hostname_opt.is_none()
            && residual_payload.is_empty()
        {
            seen_server_id = true;
        } else if opt_code == 3
            && opt_len == 40
            && val[..4] == [0, 0, 0, 1]
            && val[12..16] == [0, 5, 0, 24]
            && yiaddr_opt.is_none()
            && dns_opt.is_none()
            && hostname_opt.is_none()
            && residual_payload.is_empty()
        {
            let t1 = be_u32(val, 4);
            let t2 = be_u32(val, 8);
            let pref = be_u32(val, 32);
            let valid = be_u32(val, 36);
            let expected_t2 = ((u64::from(valid) * 4) / 5) as u32;
            if pref == valid && t1 == valid / 2 && t2 == expected_t2 {
                yiaddr_opt = Some(ipv6_at(val, 16));
                lease_opt = Some(valid);
            } else {
                residual_payload.extend_from_slice(raw_opt);
            }
        } else if opt_code == 23
            && opt_len == 16
            && dns_opt.is_none()
            && hostname_opt.is_none()
            && residual_payload.is_empty()
        {
            dns_opt = Some(ipv6_at(val, 0));
        } else if opt_code == 39
            && opt_len >= 1
            && val[0] == 0
            && hostname_opt.is_none()
            && residual_payload.is_empty()
        {
            if let Some(s) = is_printable_ascii_str(&val[1..]) {
                hostname_opt = Some(s.to_string());
            } else {
                residual_payload.extend_from_slice(raw_opt);
            }
        } else {
            residual_payload.extend_from_slice(raw_opt);
        }

        idx = opt_end;
    }

    if chaddr_opt.is_none() || (is_server_msg && !seen_server_id) {
        return None;
    }

    let mut tokens = format!("dhcp {msg_kw}");
    if xid != 0x0012_3456 {
        let _ = write!(tokens, " xid 0x{xid:06x}");
    }
    push_opt(&mut tokens, "yiaddr", yiaddr_opt);
    if let Some(chaddr) = chaddr_opt {
        let _ = write!(tokens, " chaddr {}", format_mac_lower(chaddr));
    }
    push_opt(&mut tokens, "dnsserver", dns_opt);
    if let Some(h) = hostname_opt {
        if h.is_empty() {
            tokens.push_str(" hostname \"\"");
        } else {
            push_str_if(&mut tokens, "hostname", &h, "");
        }
    }
    if let Some(lease) = lease_opt
        && lease != 3600
    {
        let _ = write!(tokens, " leasetime {lease}");
    }

    ok_dissect(Protocol::Dhcp, tokens, residual_payload)
}
