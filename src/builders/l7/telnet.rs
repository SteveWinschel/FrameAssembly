//! TELNET protocol wire builder.

use crate::ast::*;
use crate::builders::WireContext;
use alloc::vec::Vec;

/// Builds an RFC 854 Telnet command sequence or data payload.
pub fn build_telnet_payload(
    _ctx: &WireContext,
    spec: &TelnetSpec,
    payload_bytes: &[u8],
) -> Vec<u8> {
    let mut pkt = Vec::new();
    if let Some(opt) = spec.do_opt {
        pkt.extend_from_slice(&[0xFF, 0xFD, opt]); // IAC DO <opt>
    } else if let Some(opt) = spec.dont {
        pkt.extend_from_slice(&[0xFF, 0xFE, opt]); // IAC DONT <opt>
    } else if let Some(opt) = spec.will {
        pkt.extend_from_slice(&[0xFF, 0xFB, opt]); // IAC WILL <opt>
    } else if let Some(opt) = spec.wont {
        pkt.extend_from_slice(&[0xFF, 0xFC, opt]); // IAC WONT <opt>
    } else if let Some(data) = spec.data {
        pkt.extend_from_slice(data.as_bytes());
    } else {
        // Default: IAC DO 1 (Echo)
        pkt.extend_from_slice(&[0xFF, 0xFD, 1]);
    }

    if !payload_bytes.is_empty() {
        pkt.extend_from_slice(payload_bytes);
    }
    pkt
}
