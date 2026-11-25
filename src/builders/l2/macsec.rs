//! IEEE 802.1AE Media Access Control Security (MACsec) wire frame builder.
//!
//! Synthesizes IEEE 802.1AE MACsec frames over Ethernet II (`EtherType = 0x88E5`). Encodes the
//! Security Tag (SecTAG) containing the 6-bit Tag Control Information (`TCI`, default `0x2C` =
//! `SC|E|C`), 2-bit Association Number (`AN`), 6-bit Short Length (`SL`), 32-bit Packet Number
//! (`PN`), optional 8-byte Secure Channel Identifier (`SCI` when the `SC` bit `0x20` is set),
//! protected user data, and trailing 16-byte Integrity Check Value (`ICV`).
//!
//! Canonical `.frasm` syntax:
//! `a -> b macsec [tci <u8>] [an <u8>] [sl <u8>] [pn <u32>] [sci <u64>] [icv "<hex>"]`

use crate::ast::*;
use crate::builders::WireContext;
use crate::error::CompilerError;
use crate::packet::build_ethernet_and_l2;
use alloc::vec::Vec;

/// IEEE 802.1AE `SC` (Secure Channel Identifier present) bit inside `TCI`.
const MACSEC_TCI_SC: u8 = 0x20;
/// IEEE 802.1AE `E` (Encryption enabled) bit inside `TCI`.
const MACSEC_TCI_E: u8 = 0x08;
/// Default synthetic encrypted payload stub emitted when `payload` is empty and `E = 1`.
pub(crate) const DEFAULT_MACSEC_ENC_STUB: [u8; 16] = [0xAA; 16];
/// Default unencrypted IEEE 802.3 Experimental EtherType + 2-byte stub when `payload` is empty and `E = 0`.
pub(crate) const DEFAULT_MACSEC_CLR_STUB: [u8; 4] = [0x88, 0xB5, 0x00, 0x00];

/// Derives the default 64-bit MACsec Secure Channel Identifier (`<6B src_mac><port_id 0x0001>`).
pub(crate) fn default_macsec_sci(src_mac: [u8; 6]) -> u64 {
    u64::from_be_bytes([
        src_mac[0], src_mac[1], src_mac[2], src_mac[3], src_mac[4], src_mac[5], 0x00, 0x01,
    ])
}

/// Builds an IEEE 802.1AE MACsec wire frame (`EtherType = 0x88E5`).
///
/// # Errors
/// Returns `CompilerError::BackendError` if construction fails.
pub fn build_macsec_frame(
    ctx: &WireContext,
    spec: &MacsecSpec,
    payload: &[u8],
) -> Result<Vec<u8>, CompilerError> {
    let tci = spec.tci.unwrap_or(0x2C) & 0xFC;
    let an = spec.an.unwrap_or(0) & 0x03;
    let sl = spec.sl.unwrap_or(0) & 0x3F;
    let pn = spec.pn.unwrap_or(1);

    let mut frame = Vec::with_capacity(32 + payload.len());
    frame.push(tci | an);
    frame.push(sl);
    frame.extend_from_slice(&pn.to_be_bytes());

    if (tci & MACSEC_TCI_SC) != 0 {
        let sci = spec.sci.unwrap_or_else(|| default_macsec_sci(ctx.src_mac));
        frame.extend_from_slice(&sci.to_be_bytes());
    }

    if !payload.is_empty() {
        frame.extend_from_slice(payload);
    } else if (tci & MACSEC_TCI_E) != 0 {
        frame.extend_from_slice(&DEFAULT_MACSEC_ENC_STUB);
    } else {
        frame.extend_from_slice(&DEFAULT_MACSEC_CLR_STUB);
    }

    let mut icv_buf = [0u8; 16];
    if let Some(icv) = &spec.icv {
        let n = icv.len().min(16);
        icv_buf[..n].copy_from_slice(&icv[..n]);
    }
    frame.extend_from_slice(&icv_buf);

    let dst_mac = ctx.l2.dst_mac.unwrap_or(ctx.dst_mac);
    Ok(build_ethernet_and_l2(
        ctx.src_mac,
        dst_mac,
        ctx.l2,
        0x88E5,
        &frame,
    ))
}
