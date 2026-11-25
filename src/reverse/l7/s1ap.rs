//! 4G LTE S1 Application Protocol (S1AP, 3GPP TS 36.413, ITU-T X.691 APER) Layer 7 decompiler.
//!
//! This module implements fuzz-safe reverse dissection for `s1ap` SCTP packets on port `36412`
//! (PPID `18`). It validates APER `S1AP-PDU` framing, open-type length determinants, and
//! every `ProtocolIE-Field` boundary, reconstructs procedure shorthands and modifiers
//! (`mmeueid`, `enbueid`, `plmn`, `enbid`, `tac`, `enbname`, `naspdu`), and retains custom IEs
//! in `residual_payload` so forward recompilation reproduces identical bytes.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write as _;

use crate::ast::{Protocol, TransportProto};
use crate::reverse::{ProtocolDissection, bytes_to_hex_lower};

use super::{is_valid_raw_string_body, quote_raw_str};

/// Default EPS NAS Attach Request bytes synthesized when `naspdu` is omitted on NAS procedures.
const DEFAULT_EPS_NAS_PDU: [u8; 21] = [
    0x07, 0x41, 0x71, 0x08, 0x09, 0x10, 0x10, 0x00, 0x00, 0x00, 0x00, 0x10, 0x02, 0x80, 0x20, 0x00,
    0x04, 0x02, 0x01, 0xD0, 0x11,
];

/// Parses an ITU-T X.691 APER length determinant (`< 16384`), returning `(len, consumed)`.
fn parse_aper_len(bytes: &[u8]) -> Option<(usize, usize)> {
    let b0 = *bytes.first()?;
    if (b0 & 0x80) == 0 {
        Some((b0 as usize, 1))
    } else if (b0 & 0xC0) == 0x80 {
        let b1 = *bytes.get(1)?;
        Some((u16::from_be_bytes([b0 & 0x3F, b1]) as usize, 2))
    } else {
        None
    }
}

/// Decodes 3GPP TS 24.008 3-byte BCD PLMN octets into canonical ASCII (`"00101"` or `"310410"`).
fn decode_plmn_bytes(b: &[u8]) -> Option<String> {
    if b.len() != 3 {
        return None;
    }
    let mcc1 = b[0] & 0x0F;
    let mcc2 = b[0] >> 4;
    let mcc3 = b[1] & 0x0F;
    let mnc3 = b[1] >> 4;
    let mnc1 = b[2] & 0x0F;
    let mnc2 = b[2] >> 4;
    if mcc1 > 9 || mcc2 > 9 || mcc3 > 9 || mnc1 > 9 || mnc2 > 9 || (mnc3 > 9 && mnc3 != 0x0F) {
        return None;
    }
    if mnc3 == 0x0F {
        Some(format!("{mcc1}{mcc2}{mcc3}{mnc1}{mnc2}"))
    } else {
        Some(format!("{mcc1}{mcc2}{mcc3}{mnc1}{mnc2}{mnc3}"))
    }
}

/// Decodes an S1AP length-prefixed unsigned integer with 2-bit `len - 1` header at bit offset `shift`.
fn decode_s1ap_ue_id(data: &[u8], shift: u8, max_bytes: usize) -> Option<u32> {
    let b0 = *data.first()?;
    let used_mask = 0x03 << shift;
    if (b0 & !used_mask) != 0 {
        return None;
    }
    let nbytes = (((b0 >> shift) & 0x03) as usize) + 1;
    if nbytes > max_bytes || data.len() != 1 + nbytes {
        return None;
    }
    if nbytes > 1 && data[1] == 0 {
        return None;
    }
    let mut val = 0u32;
    for &byte in &data[1..] {
        val = (val << 8) | (byte as u32);
    }
    Some(val)
}

/// Decodes `PrintableString (SIZE(1..150, ...))` (`eNBname` / `MMEname`).
fn decode_s1ap_name(data: &[u8]) -> Option<&str> {
    if data.len() < 3 {
        return None;
    }
    if (data[0] & 0x80) != 0 || (data[1] & 0x7F) != 0 {
        return None;
    }
    let len = ((((data[0] & 0x7F) as usize) << 1) | ((data[1] >> 7) as usize)) + 1;
    if !(1..=150).contains(&len) || data.len() != 2 + len {
        return None;
    }
    let s = core::str::from_utf8(data.get(2..)?).ok()?;
    is_valid_raw_string_body(s).then_some(s)
}

/// Resolves `(choice_byte, proc_code)` to `(shorthand, default_crit_byte)`.
fn lookup_s1ap_proc(choice_byte: u8, proc_code: u8) -> Option<(&'static str, u8)> {
    match (choice_byte, proc_code) {
        (0x00, 17) => Some(("s1setuprequest", 0x00)),
        (0x20, 17) => Some(("s1setupresponse", 0x00)),
        (0x40, 17) => Some(("s1setupfailure", 0x00)),
        (0x00, 12) => Some(("initialuemessage", 0x40)),
        (0x00, 11) => Some(("downlinknastransport", 0x40)),
        (0x00, 13) => Some(("uplinknastransport", 0x40)),
        (0x00, 23) => Some(("uecontextreleasecommand", 0x00)),
        (0x20, 23) => Some(("uecontextreleasecomplete", 0x00)),
        (0x00, 15) => Some(("errorindication", 0x40)),
        _ => None,
    }
}

/// Dissects a 3GPP TS 36.413 S1AP SCTP packet (`port 36412`, PPID `18`).
pub(crate) fn dissect_s1ap(
    transport: TransportProto,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Option<ProtocolDissection> {
    if !matches!(transport, TransportProto::Sctp)
        || !(src_port == 36412 || dst_port == 36412)
        || payload.len() < 7
    {
        return None;
    }
    let choice_byte = payload[0];
    let proc_code = payload[1];
    let crit_byte = payload[2];
    if !matches!(choice_byte, 0x00 | 0x20 | 0x40) || !matches!(crit_byte, 0x00 | 0x40 | 0x80) {
        return None;
    }
    let (body_len, len_hdr) = parse_aper_len(payload.get(3..)?)?;
    if body_len < 3 || payload.len() != 3usize.checked_add(len_hdr)?.checked_add(body_len)? {
        return None;
    }
    let body = payload.get(3 + len_hdr..)?;
    if body[0] != 0x00 {
        return None;
    }
    let ie_count = u16::from_be_bytes([body[1], body[2]]) as usize;
    let mut pos = 3usize;
    let mut ies: Vec<(u16, u8, &[u8], &[u8])> = Vec::with_capacity(ie_count.min(32));
    for _ in 0..ie_count {
        let ie_hdr = body.get(pos..pos.checked_add(3)?)?;
        let ie_id = u16::from_be_bytes([ie_hdr[0], ie_hdr[1]]);
        let ie_crit = ie_hdr[2];
        if !matches!(ie_crit, 0x00 | 0x40 | 0x80) {
            return None;
        }
        let (ie_len, ie_len_sz) = parse_aper_len(body.get(pos + 3..)?)?;
        let val_start = pos.checked_add(3)?.checked_add(ie_len_sz)?;
        let val_end = val_start.checked_add(ie_len)?;
        let ie_val = body.get(val_start..val_end)?;
        let full_ie = body.get(pos..val_end)?;
        ies.push((ie_id, ie_crit, ie_val, full_ie));
        pos = val_end;
    }
    if pos != body.len() {
        return None;
    }

    let mut tokens = String::from("s1ap");
    let named_proc = lookup_s1ap_proc(choice_byte, proc_code);
    if let Some((shorthand, def_crit)) = named_proc {
        if shorthand != "s1setuprequest" {
            let _ = write!(tokens, " {shorthand}");
        }
        if crit_byte != def_crit {
            let crit_str = match crit_byte {
                0x00 => "reject",
                0x40 => "ignore",
                _ => "notify",
            };
            let _ = write!(tokens, " criticality \"{crit_str}\"");
        }
    } else {
        let msg_str = match choice_byte {
            0x00 => "initiating",
            0x20 => "successful",
            _ => "unsuccessful",
        };
        let _ = write!(tokens, " msgtype \"{msg_str}\" proccode {proc_code}");
        if crit_byte != 0x00 {
            let crit_str = if crit_byte == 0x40 { "ignore" } else { "notify" };
            let _ = write!(tokens, " criticality \"{crit_str}\"");
        }
    }

    let mut plmn: Option<String> = None;
    let mut enb_id: Option<u32> = None;
    let mut tac: Option<u16> = None;
    let mut enb_name: Option<&str> = None;
    let mut mme_ue_id: Option<u32> = None;
    let mut enb_ue_id: Option<u32> = None;
    let mut nas_pdu: Option<&[u8]> = None;
    let mut residual = Vec::new();
    let mut fallback_raw = false;

    for &(ie_id, ie_crit, ie_val, full_ie) in &ies {
        if !fallback_raw {
            let handled = match (choice_byte, proc_code, ie_id, ie_crit) {
                (0x00, 17, 59, 0x00)
                    if ie_val.len() == 8
                        && ie_val[0] == 0x00
                        && ie_val[4] == 0x00
                        && (ie_val[7] & 0x0F) == 0 =>
                {
                    if let Some(p) = decode_plmn_bytes(&ie_val[1..4]) {
                        plmn = Some(p);
                        enb_id = Some(u32::from_be_bytes([0, ie_val[5], ie_val[6], ie_val[7]]) >> 4);
                        true
                    } else {
                        false
                    }
                }
                (0x00, 17, 60, 0x40) | (0x20, 17, 61, 0x40) if enb_name.is_none() => {
                    decode_s1ap_name(ie_val).map(|s| enb_name = Some(s)).is_some()
                }
                (0x00, 17, 64, 0x00)
                    if ie_val.len() == 7
                        && ie_val[0] == 0x00
                        && (ie_val[1] & 0xC0) == 0
                        && (ie_val[3] & 0x3F) == 0 =>
                {
                    if let Some(p) = decode_plmn_bytes(&ie_val[4..7]) {
                        if plmn.as_deref().is_none_or(|cur| cur == p) {
                            plmn = Some(p);
                            let packed = u32::from_be_bytes([0, ie_val[1], ie_val[2], ie_val[3]]) >> 6;
                            tac = Some(packed as u16);
                            true
                        } else {
                            false
                        }
                    } else {
                        false
                    }
                }
                (0x00, 17, 137, 0x40) if ie_val == [0x40] => true,
                (0x20, 17, 105, 0x00)
                    if ie_val.len() == 11
                        && &ie_val[0..2] == b"\x00\x00"
                        && &ie_val[5..11] == b"\x00\x00\x00\x01\x00\x01" =>
                {
                    if let Some(p) = decode_plmn_bytes(&ie_val[2..5]) {
                        if plmn.as_deref().is_none_or(|cur| cur == p) {
                            plmn = Some(p);
                            true
                        } else {
                            false
                        }
                    } else {
                        false
                    }
                }
                (0x20, 17, 87, 0x00) if ie_val == [0xFF] => true,
                (0x40, 17, 2, 0x40) | (0x00, 23, 2, 0x40) | (0x00, 15, 2, 0x40)
                    if ie_val == [0x8A] =>
                {
                    true
                }
                (0x00, 11..=13, 8, 0x00) | (0x20, 23, 8, 0x40) | (0x00, 15, 8, 0x40)
                    if enb_ue_id.is_none() =>
                {
                    decode_s1ap_ue_id(ie_val, 6, 3)
                        .map(|v| enb_ue_id = Some(v))
                        .is_some()
                }
                (0x00, 11 | 13, 0, 0x00) | (0x20, 23, 0, 0x40) | (0x00, 15, 0, 0x40)
                    if mme_ue_id.is_none() =>
                {
                    decode_s1ap_ue_id(ie_val, 6, 4)
                        .map(|v| mme_ue_id = Some(v))
                        .is_some()
                }
                (0x00, 11..=13, 26, 0x00) if nas_pdu.is_none() => {
                    if let Some((nlen, nhdr)) = parse_aper_len(ie_val) {
                        if ie_val.len() == nhdr + nlen {
                            nas_pdu = Some(&ie_val[nhdr..]);
                            true
                        } else {
                            false
                        }
                    } else {
                        false
                    }
                }
                (0x00, 12, 67, 0x00) | (0x00, 13, 67, 0x40)
                    if ie_val.len() == 6 && ie_val[0] == 0x00 =>
                {
                    if let Some(p) = decode_plmn_bytes(&ie_val[1..4]) {
                        if plmn.as_deref().is_none_or(|cur| cur == p) {
                            plmn = Some(p);
                            tac = Some(u16::from_be_bytes([ie_val[4], ie_val[5]]));
                            true
                        } else {
                            false
                        }
                    } else {
                        false
                    }
                }
                (0x00, 12 | 13, 100, 0x40)
                    if ie_val.len() == 8
                        && ie_val[0] == 0x00
                        && &ie_val[4..8] == b"\x00\x00\x00\x10" =>
                {
                    if let Some(p) = decode_plmn_bytes(&ie_val[1..4]) {
                        if plmn.as_deref().is_none_or(|cur| cur == p) {
                            plmn = Some(p);
                            true
                        } else {
                            false
                        }
                    } else {
                        false
                    }
                }
                (0x00, 12, 134, 0x40) if ie_val == [0x30] => true,
                (0x00, 23, 99, 0x00) if mme_ue_id.is_none() && enb_ue_id.is_none() => {
                    if let Some(b0) = ie_val.first() {
                        if (b0 & 0xF3) == 0 {
                            let mme_len = (((b0 >> 2) & 0x03) as usize) + 1;
                            if ie_val.len() > 1 + mme_len {
                                let mme_slice = &ie_val[1..1 + mme_len];
                                let mut m = 0u32;
                                for &x in mme_slice {
                                    m = (m << 8) | (x as u32);
                                }
                                let mme_canonical = !(mme_len > 1 && mme_slice[0] == 0);
                                if mme_canonical {
                                    if let Some(e) = decode_s1ap_ue_id(&ie_val[1 + mme_len..], 6, 3) {
                                        mme_ue_id = Some(m);
                                        enb_ue_id = Some(e);
                                        true
                                    } else {
                                        false
                                    }
                                } else {
                                    false
                                }
                            } else {
                                false
                            }
                        } else {
                            false
                        }
                    } else {
                        false
                    }
                }
                _ => false,
            };
            if handled {
                continue;
            }
            fallback_raw = true;
        }
        residual.extend_from_slice(full_ie);
    }

    if let Some(mme) = mme_ue_id
        && (mme != 1 || named_proc.is_none() || (choice_byte == 0x00 && proc_code == 15))
    {
        let _ = write!(tokens, " mmeueid {mme}");
    }
    if let Some(enb) = enb_ue_id
        && (enb != 1 || named_proc.is_none() || (choice_byte == 0x00 && proc_code == 15))
    {
        let _ = write!(tokens, " enbueid {enb}");
    }
    if let Some(ref p) = plmn
        && p != "00101"
    {
        let _ = write!(tokens, " plmn \"{}\"", quote_raw_str(p));
    }
    if let Some(eid) = enb_id
        && eid != 1
    {
        let _ = write!(tokens, " enbid {eid}");
    }
    if let Some(t) = tac
        && t != 1
    {
        let _ = write!(tokens, " tac {t}");
    }
    if let Some(name) = enb_name {
        let _ = write!(tokens, " enbname \"{}\"", quote_raw_str(name));
    }
    if let Some(nas) = nas_pdu
        && nas != DEFAULT_EPS_NAS_PDU
    {
        let _ = write!(tokens, " naspdu \"{}\"", bytes_to_hex_lower(nas));
    }

    Some(ProtocolDissection {
        protocol: Protocol::S1ap,
        tokens,
        residual_payload: residual,
        explicit_transport: None,
    })
}
