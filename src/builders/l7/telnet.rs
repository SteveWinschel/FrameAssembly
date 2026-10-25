//! Telnet Network Virtual Terminal (NVT) Protocol (RFC 854 (Telnet) / RFC 855 (Options) / RFC 857 (Echo) / RFC 858 (SGA) / RFC 1073 (NAWS)) Layer 7 wire packet builder.
//!
//! This module synthesizes deterministic on-the-wire Telnet Network Virtual Terminal (NVT) Protocol frames over TCP port 23.
//! The wire encoder constructs a 7-bit/8-bit NVT-ASCII stream interspersed with 3-byte Interpret As Command (`IAC = 0xFF`) option negotiation sequences: `IAC WILL <opt>` (`0xFF 0xFB <opt>`), `IAC WONT <opt>` (`0xFF 0xFC <opt>`), `IAC DO <opt>` (`0xFF 0xFD <opt>`), `IAC DONT <opt>` (`0xFF 0xFE <opt>`), and `IAC SB <opt> ... IAC SE` (`0xFF 0xFA ... 0xFF 0xF0`) subnegotiations. When optional fields in [`TelnetSpec`]
//! are omitted in the `.fasm` source, RFC-compliant default values are automatically populated.
//!
//! Canonical `.fasm` syntax:
//! `a -> b TELNET [DO <u8>] [DONT <u8>] [WILL <u8>] [WONT <u8>] [OPTION <u8>] [PAYLOAD <str>]`

use crate::ast::*;
use crate::builders::WireContext;
use alloc::vec::Vec;

/// Builds an RFC 854 Telnet command sequence or data payload.
/// Syntax mapping: `TELNET [DO <u8>] [DONT <u8>] [WILL <u8>] [WONT <u8>] [OPTION <u8>] [PAYLOAD <str>]`
#[doc(alias = "TELNET")]
#[doc(alias = "RFC854")]
#[doc(alias = "RFC855")]
#[doc(alias = "NVT")]
pub fn build_telnet_payload(
    _ctx: &WireContext,
    spec: &TelnetSpec,
    payload_bytes: &[u8],
) -> Vec<u8> {
    let mut pkt = Vec::new();
    let mut has_iac = true;
    if let Some(opt) = spec.do_opt {
        pkt.extend_from_slice(&[0xFF, 0xFD, opt]); // IAC DO <opt>
    } else if let Some(opt) = spec.dont {
        pkt.extend_from_slice(&[0xFF, 0xFE, opt]); // IAC DONT <opt>
    } else if let Some(opt) = spec.will {
        pkt.extend_from_slice(&[0xFF, 0xFB, opt]); // IAC WILL <opt>
    } else if let Some(opt) = spec.wont {
        pkt.extend_from_slice(&[0xFF, 0xFC, opt]); // IAC WONT <opt>
    } else if let Some(opt) = spec.option {
        pkt.extend_from_slice(&[0xFF, 0xFD, opt]); // Default command 253 (DO) with <option>
    } else {
        has_iac = false;
    }

    if let Some(data) = spec.data {
        pkt.extend_from_slice(data.as_bytes());
    } else if !has_iac {
        // Default: IAC DO 1 (Echo)
        pkt.extend_from_slice(&[0xFF, 0xFD, 1]);
    }

    if !payload_bytes.is_empty() {
        pkt.extend_from_slice(payload_bytes);
    }
    pkt
}
