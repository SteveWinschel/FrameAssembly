//! Cisco Discovery Protocol (CDPv2) Layer 2 PCAP-to-`.frasm` decompiler.
//!
//! This module implements the fuzz-safe PCAP and PCAPNG decompiler for Cisco Discovery Protocol
//! (`cdp`) advertisements carried inside IEEE 802.3 LLC/SNAP (`AA AA 03 00 00 0C 20 00`). It
//! parses the CDP version (`version`), Holdtime (`ttl`), and Type 1 through Type 6 plus Native VLAN
//! TLVs (`deviceid`, `addr`, `portid`, `capabilities`, `swversion`, `platform`, `nativevlan`) while
//! preserving unrecognized or trailing bytes in the residual payload slice.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write as _;
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::ast::Protocol;
use crate::reverse::l7::{checked_be_u16, checked_be_u32, quote_raw_str};
use crate::reverse::{ProtocolDissection, push_hex, push_if, sd};

/// Parses the first IPv4 or IPv6 address inside a CDP Addresses (`0x0002`) TLV body.
fn parse_first_cdp_addr(val: &[u8]) -> Option<IpAddr> {
    let count = checked_be_u32(val, 0)?;
    if count == 0 {
        return None;
    }
    let proto_type = *val.get(4)?;
    let proto_len = usize::from(*val.get(5)?);
    let proto_off = 6usize;
    let alen_off = proto_off.checked_add(proto_len)?;
    let proto_bytes = val.get(proto_off..alen_off)?;
    let addr_len = usize::from(checked_be_u16(val, alen_off)?);
    let addr_off = alen_off.checked_add(2)?;
    let addr_end = addr_off.checked_add(addr_len)?;
    let addr_bytes = val.get(addr_off..addr_end)?;

    let is_v4 = (proto_type == 1 && proto_bytes == [0xCC])
        || (proto_type == 2 && proto_bytes == [0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x08, 0x00]);
    let is_v6 = (proto_type == 1 && proto_bytes == [0x8E])
        || (proto_type == 2 && proto_bytes == [0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x86, 0xDD]);

    if is_v4 && addr_bytes.len() == 4 {
        Some(IpAddr::V4(Ipv4Addr::new(
            addr_bytes[0],
            addr_bytes[1],
            addr_bytes[2],
            addr_bytes[3],
        )))
    } else if is_v6 && addr_bytes.len() == 16 {
        let mut oct = [0u8; 16];
        oct.copy_from_slice(addr_bytes);
        Some(IpAddr::V6(Ipv6Addr::from(oct)))
    } else {
        None
    }
}

/// Decompiles a Cisco Discovery Protocol (`cdp`) LLC/SNAP payload into a [`ProtocolDissection`].
pub(crate) fn dissect_cdp(b: &[u8]) -> ProtocolDissection {
    let pdu = b
        .strip_prefix(&[0xAA, 0xAA, 0x03, 0x00, 0x00, 0x0C, 0x20, 0x00])
        .unwrap_or(b);
    if pdu.len() < 4 {
        return sd(Protocol::Cdp, String::from("cdp"), pdu.to_vec());
    }

    let mut t = String::from("cdp");
    push_if(&mut t, "version", pdu[0], 2);
    push_if(&mut t, "ttl", pdu[1], 180);

    let mut pos = 4usize;
    let mut ext = Vec::new();
    while pos + 4 <= pdu.len() {
        let Some(tlv_type) = checked_be_u16(pdu, pos) else {
            break;
        };
        let Some(tlv_len) = checked_be_u16(pdu, pos + 2) else {
            break;
        };
        if tlv_len < 4 {
            break;
        }
        let Some(end) = pos.checked_add(usize::from(tlv_len)) else {
            break;
        };
        let Some(val) = pdu.get(pos + 4..end) else {
            break;
        };
        let raw_tlv = pdu.get(pos..end).unwrap_or(&[]);
        pos = end;

        match tlv_type {
            0x0001 => {
                if let Ok(s) = core::str::from_utf8(val) {
                    if s != "switch1" {
                        let _ = write!(t, " deviceid \"{}\"", quote_raw_str(s));
                    }
                } else {
                    ext.extend_from_slice(raw_tlv);
                }
            }
            0x0002 => {
                let count = checked_be_u32(val, 0);
                if count == Some(0) && val.len() == 4 {
                    // Explicit zero-address TLV emitted by MAC-only CDP hosts; elide cleanly.
                } else if count == Some(1)
                    && let Some(ip) = parse_first_cdp_addr(val)
                {
                    let _ = write!(t, " addr {ip}");
                } else if let Some(ip) = parse_first_cdp_addr(val) {
                    let _ = write!(t, " addr {ip}");
                } else {
                    ext.extend_from_slice(raw_tlv);
                }
            }
            0x0003 => {
                if let Ok(s) = core::str::from_utf8(val) {
                    if s != "GigabitEthernet0/1" {
                        let _ = write!(t, " portid \"{}\"", quote_raw_str(s));
                    }
                } else {
                    ext.extend_from_slice(raw_tlv);
                }
            }
            0x0004 => {
                if val.len() == 4
                    && let Some(caps) = checked_be_u32(val, 0)
                {
                    push_hex(&mut t, "capabilities", u64::from(caps), 0x0000_0028, 8);
                } else {
                    ext.extend_from_slice(raw_tlv);
                }
            }
            0x0005 => {
                if let Ok(s) = core::str::from_utf8(val) {
                    if s != "Cisco IOS Software" {
                        let _ = write!(t, " swversion \"{}\"", quote_raw_str(s));
                    }
                } else {
                    ext.extend_from_slice(raw_tlv);
                }
            }
            0x0006 => {
                if let Ok(s) = core::str::from_utf8(val) {
                    if s != "cisco WS-C3750" {
                        let _ = write!(t, " platform \"{}\"", quote_raw_str(s));
                    }
                } else {
                    ext.extend_from_slice(raw_tlv);
                }
            }
            0x000A => {
                if val.len() == 2
                    && let Some(vlan) = checked_be_u16(val, 0)
                {
                    let _ = write!(t, " nativevlan {vlan}");
                } else {
                    ext.extend_from_slice(raw_tlv);
                }
            }
            _ => ext.extend_from_slice(raw_tlv),
        }
    }

    if let Some(rem) = pdu.get(pos..) {
        ext.extend_from_slice(rem);
    }

    sd(Protocol::Cdp, t, ext)
}
