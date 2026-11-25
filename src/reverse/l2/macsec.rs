//! IEEE 802.1AE MACsec (`macsec`, EtherType `0x88E5`) Layer 2 PCAP-to-`.frasm` decompiler.
//!
//! This module implements the fuzz-safe PCAP and PCAPNG decompiler for IEEE 802.1AE Media Access
//! Control Security (`macsec`) frames encapsulated under Ethernet II EtherType `0x88E5`. It decodes
//! the Security Tag (`tci`, `an`, `sl`, `pn`, and optional 8-byte `sci` when `SC = 0x20` is set),
//! preserves any non-default 16-byte Integrity Check Value (`icv`), and elides the builder's
//! default synthetic user-data stubs on bare `macsec` captures.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write as _;

use crate::ast::Protocol;
use crate::builders::l2::macsec::{
    DEFAULT_MACSEC_CLR_STUB, DEFAULT_MACSEC_ENC_STUB, default_macsec_sci,
};
use crate::reverse::l7::checked_be_u32;
use crate::reverse::{ProtocolDissection, bytes_to_hex_lower, push_hex, push_if, sd};

/// Decompiles an IEEE 802.1AE `macsec` payload (`0x88E5`) into a [`ProtocolDissection`].
pub(crate) fn dissect_macsec(b: &[u8], src_mac: [u8; 6]) -> ProtocolDissection {
    if b.len() < 6 {
        return sd(Protocol::Macsec, String::from("macsec"), b.to_vec());
    }

    let tci_an = b[0];
    let tci = tci_an & 0xFC;
    let an = tci_an & 0x03;
    let sl = b[1] & 0x3F;
    let pn = checked_be_u32(b, 2).unwrap_or(1);
    let has_sc = (tci & 0x20) != 0;
    let sectag_len = if has_sc { 14usize } else { 6usize };

    let mut t = String::from("macsec");
    push_hex(&mut t, "tci", u64::from(tci), 0x2C, 2);
    push_if(&mut t, "an", an, 0);
    push_if(&mut t, "sl", sl, 0);
    push_if(&mut t, "pn", pn, 1);

    if has_sc {
        let Some(sci_bytes) = b.get(6..14) else {
            return sd(Protocol::Macsec, t, b.get(6..).unwrap_or(&[]).to_vec());
        };
        let mut sci_arr = [0u8; 8];
        sci_arr.copy_from_slice(sci_bytes);
        let sci = u64::from_be_bytes(sci_arr);
        push_hex(&mut t, "sci", sci, default_macsec_sci(src_mac), 16);
    }

    let Some(icv_start) = b.len().checked_sub(16) else {
        return sd(
            Protocol::Macsec,
            t,
            b.get(sectag_len..).unwrap_or(&[]).to_vec(),
        );
    };
    if icv_start < sectag_len {
        return sd(
            Protocol::Macsec,
            t,
            b.get(sectag_len..).unwrap_or(&[]).to_vec(),
        );
    }

    let user_data = b.get(sectag_len..icv_start).unwrap_or(&[]);
    let icv = b.get(icv_start..).unwrap_or(&[]);
    if icv != [0u8; 16] {
        let _ = write!(t, " icv \"{}\"", bytes_to_hex_lower(icv));
    }

    let is_default_stub = if (tci & 0x08) != 0 {
        user_data == DEFAULT_MACSEC_ENC_STUB
    } else {
        user_data == DEFAULT_MACSEC_CLR_STUB
    };
    let residual = if is_default_stub {
        Vec::new()
    } else {
        user_data.to_vec()
    };

    sd(Protocol::Macsec, t, residual)
}
