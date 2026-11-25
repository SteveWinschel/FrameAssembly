//! Cisco Discovery Protocol (CDPv2) wire frame builder.
//!
//! Synthesizes CDPv2 advertisements encapsulated in IEEE 802.3 length-framed Ethernet frames with
//! an IEEE 802.2 LLC/SNAP header (`DSAP = 0xAA`, `SSAP = 0xAA`, `Control = 0x03`, Cisco OUI
//! `00:00:0C`, Protocol ID `0x2000`) addressed by default to the CDP multicast MAC
//! `01:00:0C:CC:CC:CC`. Encodes Version (`2`), Holdtime/TTL (`180`), Cisco CDP checksum (including
//! the odd-length signed trailing-byte quirk), mandatory TLVs (`0x0001`..`0x0006`), and optional
//! Native VLAN (`0x000A`).
//!
//! Canonical `.frasm` syntax:
//! `a -> b cdp [version <u8>] [ttl <u8>] [deviceid "<str>"] [addr <ip>] [portid "<str>"] [capabilities <u32>] [swversion "<str>"] [platform "<str>"] [nativevlan <u16>]`

use crate::ast::*;
use crate::builders::WireContext;
use crate::error::CompilerError;
use crate::packet::{build_ieee8023_llc_frame, internet_checksum};
use alloc::format;
use alloc::vec::Vec;
use core::net::IpAddr;

/// IEEE 802.3 SNAP Organizationally Unique Identifier (`00:00:0C`) and CDP Protocol ID (`0x2000`).
const CDP_SNAP_HEADER: [u8; 5] = [0x00, 0x00, 0x0C, 0x20, 0x00];

/// Appends a CDP Type-Length-Value record where `length` includes the 4-byte TLV header.
fn push_cdp_tlv(out: &mut Vec<u8>, tlv_type: u16, value: &[u8]) -> Result<(), CompilerError> {
    let total_len = 4usize.saturating_add(value.len());
    let len_u16 = u16::try_from(total_len).map_err(|_| {
        CompilerError::BackendError(format!(
            "CDP TLV 0x{tlv_type:04x} length ({total_len} bytes) exceeds 16-bit maximum"
        ))
    })?;
    out.extend_from_slice(&tlv_type.to_be_bytes());
    out.extend_from_slice(&len_u16.to_be_bytes());
    out.extend_from_slice(value);
    Ok(())
}

/// Computes the 16-bit Cisco CDP checksum, matching Wireshark's odd-length signed last-byte rule.
fn cdp_checksum(pdu: &[u8]) -> u16 {
    if pdu.len().is_multiple_of(2) {
        return internet_checksum(&[pdu]);
    }
    let last = pdu[pdu.len() - 1];
    let mut padded = Vec::with_capacity(pdu.len() + 1);
    padded.extend_from_slice(&pdu[..pdu.len() - 1]);
    if (last & 0x80) != 0 {
        padded.push(0xFF);
        padded.push(last.wrapping_sub(1));
    } else {
        padded.push(0x00);
        padded.push(last);
    }
    internet_checksum(&[&padded])
}

/// Encodes a CDP Addresses (`0x0002`) TLV entry using NLPID protocol codes (`0xCC` IPv4, `0x8E` IPv6).
fn encode_cdp_addresses(addr: Option<IpAddr>, src_ip: IpAddr) -> Vec<u8> {
    let selected = addr.or_else(|| (!src_ip.is_unspecified()).then_some(src_ip));
    let Some(ip) = selected else {
        return 0_u32.to_be_bytes().to_vec();
    };
    let mut val = Vec::with_capacity(26);
    val.extend_from_slice(&1_u32.to_be_bytes());
    match ip {
        IpAddr::V4(v4) => {
            val.extend_from_slice(&[0x01, 0x01, 0xCC, 0x00, 0x04]);
            val.extend_from_slice(&v4.octets());
        }
        IpAddr::V6(v6) => {
            val.extend_from_slice(&[0x01, 0x01, 0x8E, 0x00, 0x10]);
            val.extend_from_slice(&v6.octets());
        }
    }
    val
}

/// Builds a Cisco Discovery Protocol (CDPv2) frame over IEEE 802.3 LLC/SNAP (`0x2000`).
///
/// # Errors
/// Returns `CompilerError::BackendError` if TLV lengths overflow or IEEE 802.3 LLC exceeds 1500 bytes.
pub fn build_cdp_frame(
    ctx: &WireContext,
    spec: &CdpSpec,
    payload: &[u8],
) -> Result<Vec<u8>, CompilerError> {
    let mut pdu = Vec::with_capacity(96 + payload.len());
    let version = spec.version.unwrap_or(2);
    let ttl = spec.ttl.or(ctx.l3.ttl).unwrap_or(180);

    pdu.push(version);
    pdu.push(ttl);
    pdu.extend_from_slice(&[0x00, 0x00]); // Checksum placeholder

    push_cdp_tlv(&mut pdu, 0x0001, spec.device_id.unwrap_or("switch1").as_bytes())?;
    let addr_val = encode_cdp_addresses(spec.addr, ctx.src_ip);
    push_cdp_tlv(&mut pdu, 0x0002, &addr_val)?;
    push_cdp_tlv(
        &mut pdu,
        0x0003,
        spec.port_id.unwrap_or("GigabitEthernet0/1").as_bytes(),
    )?;
    push_cdp_tlv(
        &mut pdu,
        0x0004,
        &spec.capabilities.unwrap_or(0x0000_0028).to_be_bytes(),
    )?;
    push_cdp_tlv(
        &mut pdu,
        0x0005,
        spec.sw_version.unwrap_or("Cisco IOS Software").as_bytes(),
    )?;
    push_cdp_tlv(
        &mut pdu,
        0x0006,
        spec.platform.unwrap_or("cisco WS-C3750").as_bytes(),
    )?;
    if let Some(vlan) = spec.native_vlan {
        push_cdp_tlv(&mut pdu, 0x000A, &vlan.to_be_bytes())?;
    }
    pdu.extend_from_slice(payload);

    let csum = cdp_checksum(&pdu);
    pdu[2..4].copy_from_slice(&csum.to_be_bytes());

    let mut snap_payload = Vec::with_capacity(CDP_SNAP_HEADER.len() + pdu.len());
    snap_payload.extend_from_slice(&CDP_SNAP_HEADER);
    snap_payload.extend_from_slice(&pdu);

    let llc_len = 3usize.saturating_add(snap_payload.len());
    if llc_len > 1500 {
        return Err(CompilerError::BackendError(format!(
            "IEEE 802.3 CDP LLC/SNAP length ({llc_len} bytes) exceeds 1500-byte maximum"
        )));
    }

    let dst_mac = ctx.l2.dst_mac.unwrap_or([0x01, 0x00, 0x0c, 0xcc, 0xcc, 0xcc]);
    Ok(build_ieee8023_llc_frame(
        ctx.src_mac,
        dst_mac,
        ctx.l2,
        0xAA,
        0xAA,
        0x03,
        &snap_payload,
    ))
}
