//! Extensible Authentication Protocol over LAN (EAPOL, IEEE 802.1X) Layer 2 PCAP-to-`.fasm` decompiler.
//!
//! This module implements the fuzz-safe PCAP and PCAPNG decompiler for IEEE 802.1X Port-Based
//! Network Access Control (`eapol`, EtherType `0x888E`) frames in FrameAssembly. It decodes the
//! protocol version (`version`), packet type (`eappacket`, `start`, `logoff`, `key`), embedded
//! RFC 3748 EAP header fields (`eapcode`, `eapid`, `eapmethod`), and UTF-8 Identity strings
//! (`identity`) while preserving any trailing authentication bytes as residual payload.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt::Write as _;

use crate::ast::Protocol;
use crate::reverse::{ProtocolDissection, be_u16, escape_fasm_string, push_if, sd};

/// Decompiles an IEEE 802.1X `eapol` frame (`0x888E`) into a [`ProtocolDissection`].
pub(crate) fn dissect_eapol(b: &[u8]) -> ProtocolDissection {
    let body = &b[4..4 + (be_u16(b, 2) as usize).min(b.len().saturating_sub(4))];
    let mut t = String::from("eapol");
    push_if(&mut t, "version", b[0], 1);
    match b[1] {
        1 => return sd(Protocol::Eapol, format!("{t} start"), body.to_vec()),
        2 => return sd(Protocol::Eapol, format!("{t} logoff"), body.to_vec()),
        3 => return sd(Protocol::Eapol, format!("{t} key"), body.to_vec()),
        _ => t.push_str(" eappacket"),
    }
    let mut res = Vec::new();
    if body.len() >= 4 {
        let eap_code = body[0];
        push_if(&mut t, "eapcode", eap_code, 1);
        push_if(&mut t, "eapid", body[1], 1);
        if (eap_code == 1 || eap_code == 2) && body.len() >= 5 {
            let eap_method = body[4];
            push_if(&mut t, "eapmethod", eap_method, 1);
            if eap_method == 1
                && let Ok(id_str) = core::str::from_utf8(&body[5..])
            {
                let esc = if !id_str.contains('"')
                    && !id_str.ends_with('\\')
                    && !id_str.contains('\n')
                    && !id_str.contains('\r')
                {
                    id_str.to_string()
                } else {
                    escape_fasm_string(id_str)
                };
                if !esc.is_empty() {
                    let _ = write!(t, " identity \"{esc}\"");
                }
            } else {
                res.extend_from_slice(&body[5..]);
            }
        } else if body.len() > 4 {
            res.extend_from_slice(&body[4..]);
        }
    }
    sd(Protocol::Eapol, t, res)
}
