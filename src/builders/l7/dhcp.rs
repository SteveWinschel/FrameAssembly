//! DHCP protocol wire builder.

use crate::ast::*;
use crate::builders::WireContext;
use alloc::vec::Vec;
use core::net::IpAddr;

/// Builds an RFC 2131 DHCPv4 or RFC 8415 DHCPv6 payload, returning payload, source port, and destination port.
pub fn build_dhcp_payload(
    ctx: &WireContext,
    spec: &DhcpSpec,
    payload_bytes: &[u8],
) -> (Vec<u8>, u16, u16) {
    if ctx.src_ip.is_ipv4() {
        // DHCPv4 (BOOTP)
        let is_server_msg = spec.is_offer || spec.is_ack;
        let op = if is_server_msg { 2u8 } else { 1u8 };
        let xid = spec.xid.unwrap_or(0x12345678);

        let mut pkt = Vec::with_capacity(300);
        pkt.push(op); // op
        pkt.push(1); // htype: Ethernet
        pkt.push(6); // hlen: 6
        pkt.push(0); // hops: 0
        pkt.extend_from_slice(&xid.to_be_bytes());
        pkt.extend_from_slice(&0u16.to_be_bytes()); // secs
        let flags = if spec.is_discover { 0x8000u16 } else { 0u16 };
        pkt.extend_from_slice(&flags.to_be_bytes());

        // ciaddr (Client IP)
        if let Some(IpAddr::V4(v4)) = spec.ciaddr {
            pkt.extend_from_slice(&v4.octets());
        } else {
            pkt.extend_from_slice(&[0, 0, 0, 0]);
        }

        // yiaddr ("Your" client IP)
        if let Some(IpAddr::V4(v4)) = spec.yiaddr {
            pkt.extend_from_slice(&v4.octets());
        } else {
            pkt.extend_from_slice(&[0, 0, 0, 0]);
        }

        // siaddr (Server IP)
        if let Some(IpAddr::V4(v4)) = spec.siaddr {
            pkt.extend_from_slice(&v4.octets());
        } else {
            pkt.extend_from_slice(&[0, 0, 0, 0]);
        }

        // giaddr (Relay agent IP)
        pkt.extend_from_slice(&[0, 0, 0, 0]);

        // chaddr (Client hardware address: 16 bytes)
        let chaddr = spec.chaddr.unwrap_or(ctx.src_mac);
        pkt.extend_from_slice(&chaddr);
        pkt.extend_from_slice(&[0u8; 10]);

        // sname (Server host name: 64 bytes)
        pkt.extend_from_slice(&[0u8; 64]);
        // file (Boot file name: 128 bytes)
        pkt.extend_from_slice(&[0u8; 128]);

        // Magic Cookie (RFC 1497: 99, 130, 83, 99)
        pkt.extend_from_slice(&[99, 130, 83, 99]);

        // Option 53: DHCP Message Type
        let msg_type = if spec.is_discover {
            1u8 // DHCPDISCOVER
        } else if spec.is_offer {
            2u8 // DHCPOFFER
        } else if spec.is_request {
            3u8 // DHCPREQUEST
        } else if spec.is_ack {
            5u8 // DHCPACK
        } else if spec.is_release {
            7u8 // DHCPRELEASE
        } else {
            1u8 // Default DHCPDISCOVER
        };
        pkt.extend_from_slice(&[53, 1, msg_type]);

        // Option 1: Subnet Mask
        if let Some(IpAddr::V4(v4)) = spec.subnet_mask {
            pkt.extend_from_slice(&[1, 4]);
            pkt.extend_from_slice(&v4.octets());
        }

        // Option 3: Router
        if let Some(IpAddr::V4(v4)) = spec.router {
            pkt.extend_from_slice(&[3, 4]);
            pkt.extend_from_slice(&v4.octets());
        }

        // Option 6: DNS Server
        if let Some(IpAddr::V4(v4)) = spec.dns_server {
            pkt.extend_from_slice(&[6, 4]);
            pkt.extend_from_slice(&v4.octets());
        }

        // Option 12: Hostname
        if let Some(hostname) = spec.hostname {
            let bytes = hostname.as_bytes();
            pkt.push(12);
            pkt.push(bytes.len() as u8);
            pkt.extend_from_slice(bytes);
        }

        // Option 51: IP Address Lease Time
        if let Some(lease) = spec.lease_time {
            pkt.extend_from_slice(&[51, 4]);
            pkt.extend_from_slice(&lease.to_be_bytes());
        }

        if !payload_bytes.is_empty() {
            pkt.extend_from_slice(payload_bytes);
        }

        // Option 255: End
        pkt.push(255);

        let (sport, dport) = if is_server_msg { (67, 68) } else { (68, 67) };
        (pkt, sport, dport)
    } else {
        // DHCPv6
        let msg_type = if spec.is_solicit || spec.is_discover {
            1u8 // SOLICIT
        } else if spec.is_advertise || spec.is_offer {
            2u8 // ADVERTISE
        } else if spec.is_request {
            3u8 // REQUEST
        } else if spec.is_reply || spec.is_ack {
            7u8 // REPLY
        } else if spec.is_release {
            8u8 // RELEASE
        } else {
            1u8 // Default SOLICIT
        };

        let xid = spec.xid.unwrap_or(0x123456);
        let mut pkt = alloc::vec![
            msg_type,
            // 3-byte Transaction ID
            (xid >> 16) as u8,
            (xid >> 8) as u8,
            xid as u8,
        ];

        // Option 1: Client Identifier (DUID-LL)
        pkt.extend_from_slice(&[0, 1, 0, 10]); // Option 1, len 10
        pkt.extend_from_slice(&[0, 3, 0, 1]); // DUID-LL (type 3), HW type 1
        pkt.extend_from_slice(&ctx.src_mac);

        if !payload_bytes.is_empty() {
            pkt.extend_from_slice(payload_bytes);
        }

        let (sport, dport) = if spec.is_advertise || spec.is_reply || spec.is_ack {
            (547, 546)
        } else {
            (546, 547)
        };
        (pkt, sport, dport)
    }
}
