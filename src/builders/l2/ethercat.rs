//! EtherCAT Industrial Real-Time Protocol (IEC 61158-4-12) wire frame builder.
//!
//! Synthesizes Beckhoff / ETG EtherCAT real-time control frames over native Ethernet II
//! (`EtherType = 0x88A4`, default even on IP-configured hosts) or UDP port `34980` when
//! `transport udp` is specified. Encodes the 2-byte little-endian EtherCAT Frame Header
//! (`Length` 11 bits, `Type = 1`) and a little-endian EtherCAT Datagram (`Cmd`, `Idx`, `ADP`,
//! `ADO`, 11-bit `Len`, `IRQ`, payload data bytes, and 16-bit Working Counter `WKC`).
//!
//! Canonical `.frasm` syntax:
//! `a -> b ethercat [cmd <str>] [nop | read | write] [idx <u8>] [adp <u16>] [ado <u16>] [addr <u32>] [offset <u16>] [irq <u16>] [wkc <u16>] [transport udp]`

use crate::ast::*;
use crate::builders::WireContext;
use crate::error::CompilerError;
use crate::packet::{build_ethernet_and_l2, build_ip_packet, build_udp_datagram_with_opts};
use alloc::string::ToString;
use alloc::vec::Vec;

/// Maps an EtherCAT command mnemonic or numeric string into its 8-bit IEC 61158 command code.
fn parse_ethercat_cmd(raw: &str) -> u8 {
    let norm = raw.trim().to_ascii_uppercase().replace(['_', '-'], "");
    match norm.as_str() {
        "NOP" => 0,
        "APRD" => 1,
        "APWR" => 2,
        "APRW" => 3,
        "FPRD" => 4,
        "FPWR" => 5,
        "FPRW" => 6,
        "BRD" => 7,
        "BWR" => 8,
        "BRW" => 9,
        "LRD" => 10,
        "LWR" => 11,
        "LRW" => 12,
        "ARMW" => 13,
        "FRMW" => 14,
        _ => {
            if let Some(hex) = norm.strip_prefix("0X") {
                u8::from_str_radix(hex, 16).unwrap_or(1)
            } else {
                norm.parse::<u8>().unwrap_or(1)
            }
        }
    }
}

/// Builds an EtherCAT Frame Header (2B LE) + EtherCAT Datagram payload.
///
/// # Errors
/// Returns `CompilerError::BackendError` if datagram data exceeds the 11-bit EtherCAT length ceiling.
pub fn build_ethercat_payload(
    spec: &EthercatSpec,
    payload: &[u8],
) -> Result<Vec<u8>, CompilerError> {
    let cmd = parse_ethercat_cmd(spec.cmd.unwrap_or("APRD"));
    let idx = spec.idx.unwrap_or(0);
    let adp = spec.adp.unwrap_or(0);
    let ado = spec.ado.unwrap_or(0);
    let irq = spec.irq.unwrap_or(0);
    let wkc = spec.wkc.unwrap_or(0);

    let data: &[u8] = if payload.is_empty() {
        &[0x00, 0x00]
    } else {
        payload
    };
    let dgram_len = 12usize.saturating_add(data.len());
    if data.len() > 1486 || dgram_len > 2047 {
        return Err(CompilerError::BackendError(alloc::format!(
            "EtherCAT datagram length ({dgram_len} bytes) exceeds 11-bit EtherCAT header limit"
        )));
    }

    let len_flags: u16 = (data.len() as u16) & 0x07FF;
    let frame_hdr: u16 = (1_u16 << 12) | ((dgram_len as u16) & 0x07FF);

    let mut out = Vec::with_capacity(2 + dgram_len);
    out.extend_from_slice(&frame_hdr.to_le_bytes());
    out.push(cmd);
    out.push(idx);
    out.extend_from_slice(&adp.to_le_bytes());
    out.extend_from_slice(&ado.to_le_bytes());
    out.extend_from_slice(&len_flags.to_le_bytes());
    out.extend_from_slice(&irq.to_le_bytes());
    out.extend_from_slice(data);
    out.extend_from_slice(&wkc.to_le_bytes());
    Ok(out)
}

/// Builds a complete EtherCAT wire frame (native L2 `0x88A4` by default, or UDP `34980` on `transport udp`).
///
/// # Errors
/// Returns `CompilerError::BackendError` if UDP endpoints are invalid or datagram length overflows.
pub fn build_ethercat_frame(
    ctx: &WireContext,
    spec: &EthercatSpec,
    payload: &[u8],
) -> Result<Vec<u8>, CompilerError> {
    let body = build_ethercat_payload(spec, payload)?;
    if ctx.transport == Some(TransportProto::Udp) {
        if ctx.src_ip.is_unspecified() || ctx.dst_ip.is_unspecified() {
            return Err(CompilerError::BackendError(
                "EtherCAT with 'transport udp' requires IP addresses on both endpoints"
                    .to_string(),
            ));
        }
        let dport = if ctx.dst_port == 0 { 34980 } else { ctx.dst_port };
        let udp = build_udp_datagram_with_opts(
            ctx.src_ip,
            ctx.dst_ip,
            ctx.src_port,
            dport,
            &body,
            ctx.l4,
        )?;
        let ip_pkt = build_ip_packet(ctx.src_ip, ctx.dst_ip, 17, ctx.l3, &udp)?;
        let ethertype = if ctx.src_ip.is_ipv4() { 0x0800 } else { 0x86DD };
        return Ok(build_ethernet_and_l2(
            ctx.src_mac,
            ctx.dst_mac,
            ctx.l2,
            ethertype,
            &ip_pkt,
        ));
    }

    let dst_mac = ctx.l2.dst_mac.unwrap_or(ctx.dst_mac);
    Ok(build_ethernet_and_l2(
        ctx.src_mac,
        dst_mac,
        ctx.l2,
        0x88A4,
        &body,
    ))
}
