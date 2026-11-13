//! Link Layer Discovery Protocol (LLDP, IEEE 802.1AB) Layer 2 PCAP-to-`.frasm` decompiler.
//!
//! This module implements the fuzz-safe PCAP and PCAPNG decompiler for IEEE 802.1AB Link Layer
//! Discovery Protocol (`lldp`, EtherType `0x88CC`) frames in FrameAssembly. It walks the TLV chain
//! to extract Chassis ID (`chassisid`), Port ID (`portid`), Time-to-Live (`ttl`), System Name
//! (`sysname`), and System Description (`sysdesc`) attributes while preserving unknown or
//! vendor-specific TLVs in the residual payload slice.

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt::Write as _;

use crate::ast::Protocol;
use crate::reverse::{
    ProtocolDissection, be_u16, escape_fasm_string, format_mac_lower, mac_at, push_if, sd,
};

/// Decompiles an IEEE 802.1AB `lldp` frame (`0x88CC`) into a [`ProtocolDissection`].
pub(crate) fn dissect_lldp(b: &[u8], src_mac: [u8; 6]) -> ProtocolDissection {
    let b = b.strip_suffix(&[0, 0]).unwrap_or(b);
    let (mut t, mut pos, mut ext) = (String::from("lldp"), 0usize, Vec::new());
    while pos + 2 <= b.len() {
        let hdr = be_u16(b, pos);
        let (tlv_type, tlv_len) = (hdr >> 9, (hdr & 0x01FF) as usize);
        pos += 2;
        if tlv_type == 0 && tlv_len == 0 {
            ext.extend_from_slice(&[0, 0]);
            ext.extend_from_slice(&b[pos..]);
            break;
        }
        if pos + tlv_len > b.len() {
            ext.extend_from_slice(&b[pos - 2..]);
            break;
        }
        let val = &b[pos..pos + tlv_len];
        pos += tlv_len;
        match tlv_type {
            1 if !val.is_empty() => {
                let is_def_mac = val.len() == 7 && val[0] == 4 && mac_at(&val[1..], 0) == src_mac;
                if !is_def_mac {
                    let cid = if val[0] == 4 && val.len() == 7 {
                        format_mac_lower(mac_at(&val[1..], 0))
                    } else {
                        core::str::from_utf8(&val[1..]).unwrap_or("").to_string()
                    };
                    if !cid.is_empty() {
                        let _ = write!(t, " chassisid \"{}\"", escape_fasm_string(&cid));
                    }
                }
            }
            2 if !val.is_empty() => {
                if let Ok(s) = core::str::from_utf8(&val[1..])
                    && s != "eth0"
                {
                    let _ = write!(t, " portid \"{}\"", escape_fasm_string(s));
                }
            }
            3 if val.len() == 2 => push_if(&mut t, "ttl", be_u16(val, 0), 120),
            5 | 6 => {
                if let Ok(s) = core::str::from_utf8(val) {
                    let _ = write!(
                        t,
                        " {} \"{}\"",
                        if tlv_type == 5 { "sysname" } else { "sysdesc" },
                        escape_fasm_string(s)
                    );
                }
            }
            _ => {
                ext.extend_from_slice(&hdr.to_be_bytes());
                ext.extend_from_slice(val);
            }
        }
    }
    if pos < b.len() && ext.is_empty() {
        ext.extend_from_slice(&b[pos..]);
    }
    sd(Protocol::Lldp, t, ext)
}
