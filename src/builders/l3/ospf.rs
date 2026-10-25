//! Open Shortest Path First (OSPFv2 RFC 2328 / OSPFv3 RFC 5340) Layer 3 wire builder.
//!
//! Serializes an [`OspfSpec`] into a 44-byte RFC 2328 OSPF Hello packet encapsulated directly over
//! IP protocol `89` (`0x59`) and addressed to AllSPFRouters (`224.0.0.5` for IPv4, `ff02::5` for
//! IPv6). The 24-byte OSPF header encodes Version `2`, Type `1` (`HELLO`), 16-bit `Packet Length`,
//! 32-bit `Router ID` (`ROUTER_ID`), 32-bit `Area ID` (`AREA_ID`, default `0`), 16-bit Internet
//! Checksum, `AuType = 0`, and 8-byte zeroed Authentication, followed by a 20-byte Hello body with
//! `255.255.255.0` mask, `HELLO_INTERVAL` (`10`s), `Options = 0x02` (E-bit), `PRIORITY` (`1`), and `DEAD_INTERVAL` (`40`s).
//!
//! Canonical `.fasm` syntax:
//! `a -> b OSPF [HELLO | DBD | LSR | LSU | LSACK] [ROUTER_ID <ipv4>] [AREA_ID <u32>] [HELLO_INTERVAL <u16>] [DEAD_INTERVAL <u32>] [PRIORITY <u8>]`

use crate::ast::*;
use crate::builders::WireContext;
use crate::packet::internet_checksum;
use alloc::vec::Vec;
use core::net::IpAddr;

/// Builds an RFC 2328 / RFC 5340 OSPF payload over IP protocol `89`.
pub fn build_ospf_payload(ctx: &WireContext, spec: &OspfSpec, payload: &[u8]) -> (Vec<u8>, IpAddr, u8) {
    let router_id = match spec.router_id {
        Some(IpAddr::V4(r)) => r.octets(),
        _ => match ctx.src_ip {
            IpAddr::V4(s) => s.octets(),
            _ => [10, 0, 0, 1],
        },
    };

    let ospf_type = spec.ospf_type.unwrap_or(OspfType::Hello);
    let type_code = match ospf_type {
        OspfType::Hello => 1_u8,
        OspfType::Dbd => 2_u8,
        OspfType::Lsr => 3_u8,
        OspfType::Lsu => 4_u8,
        OspfType::LsAck => 5_u8,
    };

    let mut ospf = Vec::with_capacity(44 + payload.len());
    // 24-byte OSPF Header
    ospf.push(2); // Version 2
    ospf.push(type_code);
    ospf.extend_from_slice(&0_u16.to_be_bytes()); // Length placeholder
    ospf.extend_from_slice(&router_id);
    ospf.extend_from_slice(&spec.area_id.unwrap_or(0).to_be_bytes());
    ospf.extend_from_slice(&[0, 0]); // Checksum placeholder
    ospf.extend_from_slice(&0_u16.to_be_bytes()); // AuType 0
    ospf.extend_from_slice(&[0u8; 8]); // Authentication 8 bytes

    match ospf_type {
        OspfType::Hello => {
            // 20-byte Hello Body
            ospf.extend_from_slice(&[255, 255, 255, 0]); // Network Mask
            ospf.extend_from_slice(&spec.hello_interval.unwrap_or(10).to_be_bytes());
            ospf.push(0x02); // Options: E-bit
            ospf.push(spec.priority.unwrap_or(1));
            ospf.extend_from_slice(&spec.dead_interval.unwrap_or(40).to_be_bytes());
            ospf.extend_from_slice(&[0u8; 4]); // Designated Router
            ospf.extend_from_slice(&[0u8; 4]); // Backup Designated Router
        }
        OspfType::Dbd => {
            // 8-byte Database Description Body (RFC 2328 §A.3.3)
            ospf.extend_from_slice(&1500_u16.to_be_bytes()); // Interface MTU
            ospf.push(0x02); // Options: E-bit
            ospf.push(0x07); // Flags: Init | More | Master
            ospf.extend_from_slice(&spec.dead_interval.unwrap_or(1).to_be_bytes()); // DD Sequence Number
        }
        OspfType::Lsr => {
            // 12-byte Link State Request Body (RFC 2328 §A.3.4)
            ospf.extend_from_slice(&1_u32.to_be_bytes()); // LS Type: Router-LSA
            ospf.extend_from_slice(&router_id); // Link State ID
            ospf.extend_from_slice(&router_id); // Advertising Router
        }
        OspfType::Lsu => {
            // 4-byte Link State Update Header (# LSAs = 0)
            ospf.extend_from_slice(&0_u32.to_be_bytes());
        }
        OspfType::LsAck => {
            // 20-byte LSA Header Acknowledgment (RFC 2328 §A.3.6)
            ospf.extend_from_slice(&spec.hello_interval.unwrap_or(1).to_be_bytes()); // LS Age
            ospf.push(0x02); // Options
            ospf.push(1); // LS Type: Router-LSA
            ospf.extend_from_slice(&router_id);
            ospf.extend_from_slice(&router_id);
            ospf.extend_from_slice(&0x8000_0001_u32.to_be_bytes()); // LS Sequence Number
            ospf.extend_from_slice(&0_u16.to_be_bytes()); // LS Checksum
            ospf.extend_from_slice(&20_u16.to_be_bytes()); // Length
        }
    }
    ospf.extend_from_slice(payload);

    let total_len = ospf.len() as u16;
    ospf[2..4].copy_from_slice(&total_len.to_be_bytes());

    let cksum = internet_checksum(&[&ospf[..]]);
    ospf[12..14].copy_from_slice(&cksum.to_be_bytes());

    let dst_ip = match ctx.dst_ip {
        IpAddr::V6(_) => IpAddr::V6(core::net::Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 5)),
        _ => IpAddr::V4(core::net::Ipv4Addr::new(224, 0, 0, 5)),
    };

    (ospf, dst_ip, 89)
}

