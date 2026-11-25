//! Cisco Skinny Client Control Protocol (SCCP) Layer 7 wire packet builder.
//!
//! This module implements [`build_sccp_payload`], which synthesizes deterministic little-endian
//! Cisco Skinny Client Control Protocol (SCCP) messages over TCP port 2000. It prepends the
//! 12-byte Skinny header (`DataLength` `u32` LE covering Message ID plus body, `HeaderVersion`
//! `u32` LE, and `MessageID` `u32` LE) to Standards-compliant Cisco CallManager message bodies
//! including `Register`, `RegisterAck`, `KeepAlive`, `KeepAliveAck`, `OffHook`, `OnHook`,
//! `KeypadButton`, `CallState`, `StartTone`, `StopTone`, `OpenReceiveChannel`, and
//! `OpenReceiveChannelAck`.

use alloc::vec::Vec;
use core::net::{IpAddr, Ipv4Addr};

use crate::ast::*;
use crate::builders::WireContext;

/// Builds a Cisco Skinny Client Control Protocol (SCCP) TCP port 2000 packet payload.
///
/// Syntax mapping: `sccp [register | registerack | keepalive | keepaliveack | offhook | onhook | keypadbutton | callstate | starttone | stoptone | openreceivechannel | openreceivechannelack | msgtype <str>] [version <u32>] [devicename <str>] [line <u32>] [callid <u32>] [state <u32>] [button <u32>] [tone <u32>] [addr <ip>] [mediaport <u16>]`
#[doc(alias = "SCCP")]
#[doc(alias = "SKINNY")]
pub fn build_sccp_payload(
    _ctx: &WireContext,
    spec: &SccpSpec,
    payload_bytes: &[u8],
) -> Vec<u8> {
    let norm = spec
        .msg_type
        .unwrap_or("REGISTER")
        .to_ascii_uppercase()
        .replace(['_', '-'], "");
    let header_version = spec.header_version.unwrap_or(0);
    let line = spec.line.unwrap_or(1);
    let call_id = spec.call_id.unwrap_or(100);
    let ip_octets = match spec.addr {
        Some(IpAddr::V4(v4)) => v4.octets(),
        _ => Ipv4Addr::new(192, 0, 2, 1).octets(),
    };

    let (msg_id, body): (u32, Vec<u8>) = match norm.as_str() {
        "KEEPALIVE" => (0x0000, Vec::new()),
        "KEEPALIVEACK" => (0x0100, Vec::new()),
        "REGISTERACK" => {
            let mut b = Vec::with_capacity(20);
            b.extend_from_slice(&30u32.to_le_bytes()); // keepAliveInterval
            b.extend_from_slice(b"M/D/YA\x00\x00"); // dateTemplate[6] + 2B padding
            b.extend_from_slice(&30u32.to_le_bytes()); // secondaryKeepAliveInterval
            b.extend_from_slice(&0u32.to_le_bytes()); // maxConferences
            (0x0081, b)
        }
        "OFFHOOK" => {
            let mut b = Vec::with_capacity(8);
            b.extend_from_slice(&line.to_le_bytes());
            b.extend_from_slice(&call_id.to_le_bytes());
            (0x0006, b)
        }
        "ONHOOK" => {
            let mut b = Vec::with_capacity(8);
            b.extend_from_slice(&line.to_le_bytes());
            b.extend_from_slice(&call_id.to_le_bytes());
            (0x0007, b)
        }
        "KEYPADBUTTON" => {
            let mut b = Vec::with_capacity(12);
            b.extend_from_slice(&spec.button.unwrap_or(1).to_le_bytes());
            b.extend_from_slice(&line.to_le_bytes());
            b.extend_from_slice(&call_id.to_le_bytes());
            (0x0003, b)
        }
        "CALLSTATE" => {
            let mut b = Vec::with_capacity(24);
            b.extend_from_slice(&spec.call_state.unwrap_or(1).to_le_bytes());
            b.extend_from_slice(&line.to_le_bytes());
            b.extend_from_slice(&call_id.to_le_bytes());
            b.extend_from_slice(&0u32.to_le_bytes()); // privacy
            b.extend_from_slice(&0u32.to_le_bytes()); // precedenceLevel
            b.extend_from_slice(&0u32.to_le_bytes()); // precedenceDomain
            (0x0111, b)
        }
        "STARTTONE" => {
            let mut b = Vec::with_capacity(16);
            b.extend_from_slice(&spec.tone.unwrap_or(0x21).to_le_bytes());
            b.extend_from_slice(&0u32.to_le_bytes()); // toneDirection
            b.extend_from_slice(&line.to_le_bytes());
            b.extend_from_slice(&call_id.to_le_bytes());
            (0x0082, b)
        }
        "STOPTONE" => {
            let mut b = Vec::with_capacity(8);
            b.extend_from_slice(&line.to_le_bytes());
            b.extend_from_slice(&call_id.to_le_bytes());
            (0x0083, b)
        }
        "OPENRECEIVECHANNEL" => {
            let mut b = alloc::vec![0u8; 92];
            b[0..4].copy_from_slice(&call_id.to_le_bytes()); // conferenceId
            b[4..8].copy_from_slice(&1u32.to_le_bytes()); // passThruPartyId
            b[8..12].copy_from_slice(&20u32.to_le_bytes()); // milliSecondPacketSize
            b[12..16].copy_from_slice(&4u32.to_le_bytes()); // compressionType (G.711u)
            b[24..28].copy_from_slice(&call_id.to_le_bytes()); // callReference
            (0x0105, b)
        }
        "OPENRECEIVECHANNELACK" => {
            let mut b = Vec::with_capacity(16);
            b.extend_from_slice(&0u32.to_le_bytes()); // orcStatus = ok
            b.extend_from_slice(&ip_octets);
            b.extend_from_slice(&u32::from(spec.media_port.unwrap_or(20000)).to_le_bytes());
            b.extend_from_slice(&call_id.to_le_bytes());
            (0x0022, b)
        }
        _ => {
            // RegisterMessage (0x0001, 36 bytes body)
            let dev = spec.device_name.unwrap_or("SEP001122334455").as_bytes();
            let mut b = Vec::with_capacity(36);
            let mut name_buf = [0u8; 16];
            let copy_len = dev.len().min(15);
            name_buf[..copy_len].copy_from_slice(&dev[..copy_len]);
            b.extend_from_slice(&name_buf);
            b.extend_from_slice(&0u32.to_le_bytes()); // stationUserId
            b.extend_from_slice(&line.to_le_bytes()); // stationInstance
            b.extend_from_slice(&ip_octets);
            b.extend_from_slice(&7u32.to_le_bytes()); // deviceType = Cisco 7960
            b.extend_from_slice(&0u32.to_le_bytes()); // maxStreams
            (0x0001, b)
        }
    };

    let data_len = (4 + body.len()) as u32;
    let mut pkt = Vec::with_capacity(12 + body.len() + payload_bytes.len());
    pkt.extend_from_slice(&data_len.to_le_bytes());
    pkt.extend_from_slice(&header_version.to_le_bytes());
    pkt.extend_from_slice(&msg_id.to_le_bytes());
    pkt.extend_from_slice(&body);
    if !payload_bytes.is_empty() {
        pkt.extend_from_slice(payload_bytes);
    }
    pkt
}
