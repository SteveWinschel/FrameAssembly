//! 5G NG Application Protocol (NGAP, 3GPP TS 38.413, ITU-T X.691 APER) Layer 7 decompiler.
//!
//! This module implements fuzz-safe reverse dissection for `ngap` SCTP packets on port `38412`
//! (PPID `60`). It strictly validates APER `NGAP-PDU` framing, open-type length determinants,
//! and every `ProtocolIE-Field` boundary, extracts high-level `.frasm` procedure keywords and
//! modifiers (`amfueid`, `ranueid`, `plmn`, `gnbid`, `tac`, `ranname`, `naspdu`), and preserves
//! any custom or out-of-order IEs in `residual_payload` for exact roundtrip parity.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write as _;

use crate::ast::{Protocol, TransportProto};
use crate::reverse::{ProtocolDissection, bytes_to_hex_lower};

use super::{is_valid_raw_string_body, quote_raw_str};

/// Default 5GS NAS-PDU bytes synthesized when `naspdu` is omitted on NAS procedures.
const DEFAULT_5GS_NAS_PDU: [u8; 19] = [
    0x7e, 0x00, 0x41, 0x79, 0x00, 0x0d, 0x01, 0x00, 0xf1, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x01,
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

/// Decodes an ASN.1 APER length-prefixed unsigned integer with `shift` bits for `len - 1`.
fn decode_len_prefixed_uint(data: &[u8], shift: u8, max_bytes: usize) -> Option<u64> {
    let b0 = *data.first()?;
    let mask = if shift == 5 { 0x07 } else { 0x03 };
    let used_bits_mask = mask << shift;
    if (b0 & !used_bits_mask) != 0 {
        return None;
    }
    let nbytes = (((b0 >> shift) & mask) as usize) + 1;
    if nbytes > max_bytes || data.len() != 1 + nbytes {
        return None;
    }
    if nbytes > 1 && data[1] == 0 {
        return None;
    }
    let mut val = 0u64;
    for &byte in &data[1..] {
        val = (val << 8) | (byte as u64);
    }
    Some(val)
}

/// Decodes `PrintableString (SIZE(1..150, ...))` (`RANNodeName` / `AMFName`).
fn decode_ran_name(data: &[u8]) -> Option<&str> {
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
fn lookup_ngap_proc(choice_byte: u8, proc_code: u8) -> Option<(&'static str, u8)> {
    match (choice_byte, proc_code) {
        (0x00, 21) => Some(("ngsetuprequest", 0x00)),
        (0x20, 21) => Some(("ngsetupresponse", 0x00)),
        (0x40, 21) => Some(("ngsetupfailure", 0x00)),
        (0x00, 15) => Some(("initialuemessage", 0x40)),
        (0x00, 4) => Some(("downlinknastransport", 0x40)),
        (0x00, 46) => Some(("uplinknastransport", 0x40)),
        (0x00, 41) => Some(("uecontextreleasecommand", 0x00)),
        (0x20, 41) => Some(("uecontextreleasecomplete", 0x00)),
        (0x00, 9) => Some(("errorindication", 0x40)),
        _ => None,
    }
}

/// Dissects a 3GPP TS 38.413 NGAP SCTP packet (`port 38412`, PPID `60`).
pub(crate) fn dissect_ngap(
    transport: TransportProto,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Option<ProtocolDissection> {
    if !matches!(transport, TransportProto::Sctp)
        || !(src_port == 38412 || dst_port == 38412)
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

    let mut tokens = String::from("ngap");
    let named_proc = lookup_ngap_proc(choice_byte, proc_code);
    if let Some((shorthand, def_crit)) = named_proc {
        if shorthand != "ngsetuprequest" {
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
    let mut gnb_id: Option<u32> = None;
    let mut tac: Option<u32> = None;
    let mut ran_name: Option<&str> = None;
    let mut amf_ue_id: Option<u64> = None;
    let mut ran_ue_id: Option<u32> = None;
    let mut nas_pdu: Option<&[u8]> = None;
    let mut residual = Vec::new();
    let mut fallback_raw = false;

    for &(ie_id, ie_crit, ie_val, full_ie) in &ies {
        if !fallback_raw {
            let handled = match (choice_byte, proc_code, ie_id, ie_crit) {
                (0x00, 21, 27, 0x00) if ie_val.len() == 8 && ie_val[0] == 0x00 && ie_val[4] == 0x10 => {
                    if let Some(p) = decode_plmn_bytes(&ie_val[1..4]) {
                        plmn = Some(p);
                        gnb_id = Some(u32::from_be_bytes([0, ie_val[5], ie_val[6], ie_val[7]]));
                        true
                    } else {
                        false
                    }
                }
                (0x00, 21, 82, 0x40) if ran_name.is_none() => {
                    decode_ran_name(ie_val).map(|s| ran_name = Some(s)).is_some()
                }
                (0x00, 21, 102, 0x00)
                    if ie_val.len() == 13
                        && &ie_val[0..2] == b"\x00\x00"
                        && ie_val[5] == 0x00
                        && &ie_val[9..13] == b"\x00\x00\x00\x08" =>
                {
                    if let Some(p) = decode_plmn_bytes(&ie_val[6..9]) {
                        if plmn.as_deref().is_none_or(|cur| cur == p) {
                            plmn = Some(p);
                            tac = Some(u32::from_be_bytes([0, ie_val[2], ie_val[3], ie_val[4]]));
                            true
                        } else {
                            false
                        }
                    } else {
                        false
                    }
                }
                (0x00, 21, 21, 0x40) if ie_val == [0x40] => true,
                (0x20, 21, 1, 0x00) if ran_name.is_none() => {
                    decode_ran_name(ie_val).map(|s| ran_name = Some(s)).is_some()
                }
                (0x20, 21, 96, 0x00)
                    if ie_val.len() == 8
                        && &ie_val[0..2] == b"\x00\x00"
                        && &ie_val[5..8] == b"\x01\x00\x40" =>
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
                (0x20, 21, 86, 0x40) if ie_val == [0xFF] => true,
                (0x20, 21, 80, 0x00)
                    if ie_val.len() == 8 && ie_val[0] == 0x00 && &ie_val[4..8] == b"\x00\x00\x00\x08" =>
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
                (0x40, 21, 15, 0x40) | (0x00, 41, 15, 0x40) | (0x00, 9, 15, 0x40)
                    if ie_val == [0x8A] =>
                {
                    true
                }
                (0x00, 15, 85, 0x00) | (0x00, 4, 85, 0x00) | (0x00, 46, 85, 0x00)
                | (0x20, 41, 85, 0x40)
                    if ran_ue_id.is_none() =>
                {
                    if let Some(v) = decode_len_prefixed_uint(ie_val, 6, 4)
                        .and_then(|x| u32::try_from(x).ok())
                    {
                        ran_ue_id = Some(v);
                        true
                    } else {
                        false
                    }
                }
                (0x00, 4, 10, 0x00) | (0x00, 46, 10, 0x00) | (0x20, 41, 10, 0x40)
                    if amf_ue_id.is_none() =>
                {
                    if let Some(v) = decode_len_prefixed_uint(ie_val, 5, 5) {
                        amf_ue_id = Some(v);
                        true
                    } else {
                        false
                    }
                }
                (0x00, 15 | 4 | 46, 38, 0x00) if nas_pdu.is_none() => {
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
                (0x00, 15, 121, 0x00) | (0x00, 46, 121, 0x40)
                    if ie_val.len() == 15
                        && ie_val[0] == 0x40
                        && &ie_val[4..9] == b"\x00\x00\x00\x00\x10" =>
                {
                    if let (Some(p1), Some(p2)) = (
                        decode_plmn_bytes(&ie_val[1..4]),
                        decode_plmn_bytes(&ie_val[9..12]),
                    ) {
                        if p1 == p2 && plmn.as_deref().is_none_or(|cur| cur == p1) {
                            plmn = Some(p1);
                            tac = Some(u32::from_be_bytes([0, ie_val[12], ie_val[13], ie_val[14]]));
                            true
                        } else {
                            false
                        }
                    } else {
                        false
                    }
                }
                (0x00, 15, 90, 0x40) if ie_val == [0x18] => true,
                (0x00, 41, 114, 0x00) if amf_ue_id.is_none() && ran_ue_id.is_none() => {
                    if let Some(b0) = ie_val.first() {
                        if (b0 & 0xF1) == 0 {
                            let amf_len = (((b0 >> 1) & 0x07) as usize) + 1;
                            if amf_len <= 5 && ie_val.len() > 1 + amf_len {
                                let amf_slice = &ie_val[1..1 + amf_len];
                                let mut a = 0u64;
                                for &x in amf_slice {
                                    a = (a << 8) | (x as u64);
                                }
                                let amf_canonical = !(amf_len > 1 && amf_slice[0] == 0);
                                if amf_canonical {
                                    if let Some(r) = decode_len_prefixed_uint(&ie_val[1 + amf_len..], 6, 4)
                                        .and_then(|x| u32::try_from(x).ok())
                                    {
                                        amf_ue_id = Some(a);
                                        ran_ue_id = Some(r);
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
                (0x00, 9, 10, 0x40) if amf_ue_id.is_none() => {
                    if let Some(v) = decode_len_prefixed_uint(ie_val, 5, 5) {
                        amf_ue_id = Some(v);
                        true
                    } else {
                        false
                    }
                }
                (0x00, 9, 85, 0x40) if ran_ue_id.is_none() => {
                    if let Some(v) = decode_len_prefixed_uint(ie_val, 6, 4)
                        .and_then(|x| u32::try_from(x).ok())
                    {
                        ran_ue_id = Some(v);
                        true
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

    if let Some(amf) = amf_ue_id
        && (amf != 1 || named_proc.is_none() || (choice_byte == 0x00 && proc_code == 9))
    {
        let _ = write!(tokens, " amfueid {amf}");
    }
    if let Some(ran) = ran_ue_id
        && (ran != 1 || named_proc.is_none() || (choice_byte == 0x00 && proc_code == 9))
    {
        let _ = write!(tokens, " ranueid {ran}");
    }
    if let Some(ref p) = plmn
        && p != "00101"
    {
        let _ = write!(tokens, " plmn \"{}\"", quote_raw_str(p));
    }
    if let Some(gid) = gnb_id
        && gid != 1
    {
        let _ = write!(tokens, " gnbid {gid}");
    }
    if let Some(t) = tac
        && t != 1
    {
        let _ = write!(tokens, " tac {t}");
    }
    if let Some(name) = ran_name {
        let default_name = if choice_byte == 0x20 && proc_code == 21 {
            "amf"
        } else {
            ""
        };
        if name != default_name {
            let _ = write!(tokens, " ranname \"{}\"", quote_raw_str(name));
        }
    }
    if let Some(nas) = nas_pdu
        && nas != DEFAULT_5GS_NAS_PDU
    {
        let _ = write!(tokens, " naspdu \"{}\"", bytes_to_hex_lower(nas));
    }

    Some(ProtocolDissection {
        protocol: Protocol::Ngap,
        tokens,
        residual_payload: residual,
        explicit_transport: None,
    })
}
