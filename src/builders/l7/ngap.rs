//! 5G NG Application Protocol (NGAP, 3GPP TS 38.413, ITU-T X.691 APER) Layer 7 wire builder.
//!
//! This module serializes [`NgapSpec`] into valid ITU-T X.691 Aligned PER (APER) `NGAP-PDU`
//! frames transported over SCTP port `38412` (PPID `60`). It encodes `InitiatingMessage`,
//! `SuccessfulOutcome`, and `UnsuccessfulOutcome` containers along with canonical 3GPP TS 38.413
//! `ProtocolIE-Field` values and appends custom raw APER IE streams from `payload_bytes`.

use alloc::vec::Vec;

use crate::ast::*;
use crate::builders::WireContext;

/// Default 5GS NAS Registration Request payload used when `naspdu` is omitted on NAS procedures.
const DEFAULT_5GS_NAS_PDU: [u8; 19] = [
    0x7e, 0x00, 0x41, 0x79, 0x00, 0x0d, 0x01, 0x00, 0xf1, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x01,
];

/// Appends an ITU-T X.691 APER unconstrained / open-type length determinant (`< 16384`).
fn push_aper_len(buf: &mut Vec<u8>, len: usize) {
    if len < 128 {
        buf.push(len as u8);
    } else {
        let v = (0x8000u16) | ((len as u16) & 0x3FFF);
        buf.extend_from_slice(&v.to_be_bytes());
    }
}

/// Appends a single NGAP `ProtocolIE-Field` `(id, criticality, value_bytes)`.
fn push_ie(ies: &mut Vec<Vec<u8>>, id: u16, crit: u8, val: &[u8]) {
    let mut out = Vec::with_capacity(4 + val.len());
    out.extend_from_slice(&id.to_be_bytes());
    out.push(crit);
    push_aper_len(&mut out, val.len());
    out.extend_from_slice(val);
    ies.push(out);
}

/// Encodes a 5- or 6-digit PLMN string (e.g., `"00101"` or `"310410"`) into 3GPP TS 24.008 BCD octets.
fn encode_plmn(plmn: Option<&str>) -> [u8; 3] {
    let raw = plmn.unwrap_or("00101");
    let digits: Vec<u8> = raw
        .bytes()
        .filter(|b| b.is_ascii_digit())
        .map(|b| b - b'0')
        .collect();
    match digits.as_slice() {
        [mcc1, mcc2, mcc3, mnc1, mnc2] => [
            (mcc2 << 4) | mcc1,
            0xF0 | mcc3,
            (mnc2 << 4) | mnc1,
        ],
        [mcc1, mcc2, mcc3, mnc1, mnc2, mnc3] => [
            (mcc2 << 4) | mcc1,
            (mnc3 << 4) | mcc3,
            (mnc2 << 4) | mnc1,
        ],
        _ => [0x00, 0xF1, 0x10],
    }
}

/// Encodes an ASN.1 constrained integer whose byte count fits in 1..=N octets (`len - 1` shifted into top bits).
fn encode_len_prefixed_uint(val: u64, shift: u8, max_bytes: usize) -> Vec<u8> {
    let be = val.to_be_bytes();
    let mut start = 8usize.saturating_sub(max_bytes);
    while start < 7 && be[start] == 0 {
        start += 1;
    }
    let slice = &be[start..8];
    let len_minus_1 = (slice.len().saturating_sub(1)) as u8;
    let mut out = Vec::with_capacity(1 + slice.len());
    out.push(len_minus_1 << shift);
    out.extend_from_slice(slice);
    out
}

/// Encodes `PrintableString (SIZE(1..150, ...))` (`RANNodeName` / `AMFName`) in ITU-T X.691 APER.
fn encode_ran_name(name: &str) -> Vec<u8> {
    let bytes = name.as_bytes();
    let clamped = if bytes.len() > 150 {
        &bytes[..150]
    } else if bytes.is_empty() {
        b"gnb"
    } else {
        bytes
    };
    let lm1 = (clamped.len() - 1) as u8;
    let mut out = Vec::with_capacity(2 + clamped.len());
    out.push(lm1 >> 1);
    out.push((lm1 & 1) << 7);
    out.extend_from_slice(clamped);
    out
}

/// Encodes IE 27 `GlobalRANNodeID` (`GlobalGNB-ID`) with 24-bit `gNB-ID`.
fn encode_global_gnb_id(plmn: [u8; 3], gnb_id: u32) -> [u8; 8] {
    let id_be = (gnb_id & 0x00FF_FFFF).to_be_bytes();
    [0x00, plmn[0], plmn[1], plmn[2], 0x10, id_be[1], id_be[2], id_be[3]]
}

/// Encodes IE 102 `SupportedTAList` (single TAC + single PLMN + single `sST = 0x01`).
fn encode_supported_ta_list(plmn: [u8; 3], tac: u32) -> [u8; 13] {
    let tac_be = (tac & 0x00FF_FFFF).to_be_bytes();
    [
        0x00, 0x00, tac_be[1], tac_be[2], tac_be[3], 0x00, plmn[0], plmn[1], plmn[2], 0x00, 0x00,
        0x00, 0x08,
    ]
}

/// Encodes IE 121 `UserLocationInformation` (`userLocationInformationNR`) using `plmn` and `tac`.
fn encode_uli_nr(plmn: [u8; 3], tac: u32) -> [u8; 15] {
    let tac_be = (tac & 0x00FF_FFFF).to_be_bytes();
    [
        0x40, plmn[0], plmn[1], plmn[2], 0x00, 0x00, 0x00, 0x00, 0x10, plmn[0], plmn[1], plmn[2],
        tac_be[1], tac_be[2], tac_be[3],
    ]
}

/// Encodes IE 114 `UE-NGAP-IDs` (`uE-NGAP-ID-pair`) in APER.
fn encode_ue_ngap_id_pair(amf_ue_id: u64, ran_ue_id: u32) -> Vec<u8> {
    let amf = encode_len_prefixed_uint(amf_ue_id & 0x00FF_FFFF_FFFF, 1, 5);
    let ran = encode_len_prefixed_uint(ran_ue_id as u64, 6, 4);
    let mut out = Vec::with_capacity(amf.len() + ran.len());
    out.extend_from_slice(&amf);
    out.extend_from_slice(&ran);
    out
}

/// Parses `raw` as a concatenation of valid NGAP APER `ProtocolIE-Field`s, returning `(id, raw_slice)` slices.
fn scan_raw_ies(raw: &[u8]) -> Option<Vec<(u16, &[u8])>> {
    if raw.is_empty() {
        return None;
    }
    let mut out = Vec::new();
    let mut pos = 0usize;
    while pos < raw.len() {
        if raw.len() - pos < 4 {
            return None;
        }
        let id = u16::from_be_bytes([raw[pos], raw[pos + 1]]);
        let crit = raw[pos + 2];
        if !matches!(crit, 0x00 | 0x40 | 0x80) {
            return None;
        }
        let b0 = raw[pos + 3];
        let (val_len, hdr_len) = if (b0 & 0x80) == 0 {
            (b0 as usize, 4usize)
        } else if (b0 & 0xC0) == 0x80 && raw.len() - pos >= 5 {
            (
                (u16::from_be_bytes([b0 & 0x3F, raw[pos + 4]])) as usize,
                5usize,
            )
        } else {
            return None;
        };
        let total = hdr_len.checked_add(val_len)?;
        if pos + total > raw.len() {
            return None;
        }
        out.push((id, &raw[pos..pos + total]));
        pos += total;
    }
    Some(out)
}

/// Resolves NGAP shorthand or generic PDU selection to `(choice_byte, proc_code, default_crit_byte, is_named)`.
fn resolve_ngap_proc(pdu_type: Option<&str>) -> (u8, u8, u8, bool) {
    match pdu_type {
        None | Some("ngsetuprequest") => (0x00, 21, 0x00, true),
        Some("ngsetupresponse") => (0x20, 21, 0x00, true),
        Some("ngsetupfailure") => (0x40, 21, 0x00, true),
        Some("initialuemessage") => (0x00, 15, 0x40, true),
        Some("downlinknastransport") => (0x00, 4, 0x40, true),
        Some("uplinknastransport") => (0x00, 46, 0x40, true),
        Some("uecontextreleasecommand") => (0x00, 41, 0x00, true),
        Some("uecontextreleasecomplete") => (0x20, 41, 0x00, true),
        Some("errorindication") => (0x00, 9, 0x40, true),
        Some("initiating") => (0x00, 21, 0x00, false),
        Some("successful") => (0x20, 21, 0x00, false),
        Some("unsuccessful") => (0x40, 21, 0x00, false),
        Some(_) => (0x00, 21, 0x00, false),
    }
}

/// Builds a 3GPP TS 38.413 NGAP APER payload from `spec` and optional `payload_bytes`.
pub fn build_ngap_payload(
    _ctx: &WireContext,
    spec: &NgapSpec<'_>,
    payload_bytes: &[u8],
) -> Vec<u8> {
    let (choice_byte, def_proc, def_crit, is_named) = resolve_ngap_proc(spec.pdu_type);
    let proc_code = spec.proc_code.unwrap_or(def_proc);
    let crit_byte = match spec.criticality {
        Some("reject") => 0x00,
        Some("ignore") => 0x40,
        Some("notify") => 0x80,
        _ => def_crit,
    };

    let plmn = encode_plmn(spec.plmn);
    let gnb_id = spec.gnb_id.unwrap_or(1);
    let tac = spec.tac.unwrap_or(1);
    let amf_ue_id = spec.amf_ue_id.unwrap_or(1);
    let ran_ue_id = spec.ran_ue_id.unwrap_or(1);

    let raw_ies = scan_raw_ies(payload_bytes);
    let nas_fallback: &[u8] = if let Some(ref nas) = spec.nas_pdu {
        nas.as_slice()
    } else if !payload_bytes.is_empty() && raw_ies.is_none() {
        payload_bytes
    } else {
        &DEFAULT_5GS_NAS_PDU
    };

    let has_raw_ie = |id: u16| -> bool {
        raw_ies
            .as_ref()
            .is_some_and(|list| list.iter().any(|(x, _)| *x == id))
    };

    let mut ies: Vec<Vec<u8>> = Vec::new();
    let matched_named = is_named || spec.pdu_type.is_none();

    match (choice_byte, proc_code) {
        (0x00, 21) if matched_named => {
            if spec.plmn.is_some() || spec.gnb_id.is_some() || !has_raw_ie(27) {
                let val = encode_global_gnb_id(plmn, gnb_id);
                push_ie(&mut ies, 27, 0x00, &val);
            }
            if let Some(name) = spec.ran_name {
                let val = encode_ran_name(name);
                push_ie(&mut ies, 82, 0x40, &val);
            }
            if spec.plmn.is_some() || spec.tac.is_some() || !has_raw_ie(102) {
                let val = encode_supported_ta_list(plmn, tac);
                push_ie(&mut ies, 102, 0x00, &val);
            }
            if !has_raw_ie(21) {
                push_ie(&mut ies, 21, 0x40, &[0x40]);
            }
        }
        (0x20, 21) if matched_named => {
            let amf_name = spec.ran_name.unwrap_or("amf");
            if spec.ran_name.is_some() || !has_raw_ie(1) {
                let val = encode_ran_name(amf_name);
                push_ie(&mut ies, 1, 0x00, &val);
            }
            if spec.plmn.is_some() || !has_raw_ie(96) {
                let guami = [0x00, 0x00, plmn[0], plmn[1], plmn[2], 0x01, 0x00, 0x40];
                push_ie(&mut ies, 96, 0x00, &guami);
            }
            if !has_raw_ie(86) {
                push_ie(&mut ies, 86, 0x40, &[0xFF]);
            }
            if spec.plmn.is_some() || !has_raw_ie(80) {
                let plmn_sup = [0x00, plmn[0], plmn[1], plmn[2], 0x00, 0x00, 0x00, 0x08];
                push_ie(&mut ies, 80, 0x00, &plmn_sup);
            }
        }
        (0x40, 21) if matched_named => {
            if !has_raw_ie(15) {
                push_ie(&mut ies, 15, 0x40, &[0x8A]);
            }
        }
        (0x00, 15) if matched_named => {
            if spec.ran_ue_id.is_some() || !has_raw_ie(85) {
                let val = encode_len_prefixed_uint(ran_ue_id as u64, 6, 4);
                push_ie(&mut ies, 85, 0x00, &val);
            }
            if spec.nas_pdu.is_some() || !has_raw_ie(38) {
                let mut nas_val = Vec::with_capacity(2 + nas_fallback.len());
                push_aper_len(&mut nas_val, nas_fallback.len());
                nas_val.extend_from_slice(nas_fallback);
                push_ie(&mut ies, 38, 0x00, &nas_val);
            }
            if spec.plmn.is_some() || spec.tac.is_some() || !has_raw_ie(121) {
                let val = encode_uli_nr(plmn, tac);
                push_ie(&mut ies, 121, 0x00, &val);
            }
            if !has_raw_ie(90) {
                push_ie(&mut ies, 90, 0x40, &[0x18]);
            }
        }
        (0x00, 4) if matched_named => {
            if spec.amf_ue_id.is_some() || !has_raw_ie(10) {
                let val = encode_len_prefixed_uint(amf_ue_id & 0x00FF_FFFF_FFFF, 5, 5);
                push_ie(&mut ies, 10, 0x00, &val);
            }
            if spec.ran_ue_id.is_some() || !has_raw_ie(85) {
                let val = encode_len_prefixed_uint(ran_ue_id as u64, 6, 4);
                push_ie(&mut ies, 85, 0x00, &val);
            }
            if spec.nas_pdu.is_some() || !has_raw_ie(38) {
                let mut nas_val = Vec::with_capacity(2 + nas_fallback.len());
                push_aper_len(&mut nas_val, nas_fallback.len());
                nas_val.extend_from_slice(nas_fallback);
                push_ie(&mut ies, 38, 0x00, &nas_val);
            }
        }
        (0x00, 46) if matched_named => {
            if spec.amf_ue_id.is_some() || !has_raw_ie(10) {
                let val = encode_len_prefixed_uint(amf_ue_id & 0x00FF_FFFF_FFFF, 5, 5);
                push_ie(&mut ies, 10, 0x00, &val);
            }
            if spec.ran_ue_id.is_some() || !has_raw_ie(85) {
                let val = encode_len_prefixed_uint(ran_ue_id as u64, 6, 4);
                push_ie(&mut ies, 85, 0x00, &val);
            }
            if spec.nas_pdu.is_some() || !has_raw_ie(38) {
                let mut nas_val = Vec::with_capacity(2 + nas_fallback.len());
                push_aper_len(&mut nas_val, nas_fallback.len());
                nas_val.extend_from_slice(nas_fallback);
                push_ie(&mut ies, 38, 0x00, &nas_val);
            }
            if spec.plmn.is_some() || spec.tac.is_some() || !has_raw_ie(121) {
                let val = encode_uli_nr(plmn, tac);
                push_ie(&mut ies, 121, 0x40, &val);
            }
        }
        (0x00, 41) if matched_named => {
            if spec.amf_ue_id.is_some() || spec.ran_ue_id.is_some() || !has_raw_ie(114) {
                let val = encode_ue_ngap_id_pair(amf_ue_id, ran_ue_id);
                push_ie(&mut ies, 114, 0x00, &val);
            }
            if !has_raw_ie(15) {
                push_ie(&mut ies, 15, 0x40, &[0x8A]);
            }
        }
        (0x20, 41) if matched_named => {
            if spec.amf_ue_id.is_some() || !has_raw_ie(10) {
                let val = encode_len_prefixed_uint(amf_ue_id & 0x00FF_FFFF_FFFF, 5, 5);
                push_ie(&mut ies, 10, 0x40, &val);
            }
            if spec.ran_ue_id.is_some() || !has_raw_ie(85) {
                let val = encode_len_prefixed_uint(ran_ue_id as u64, 6, 4);
                push_ie(&mut ies, 85, 0x40, &val);
            }
        }
        (0x00, 9) if matched_named => {
            if !has_raw_ie(15) {
                push_ie(&mut ies, 15, 0x40, &[0x8A]);
            }
            if let Some(amf) = spec.amf_ue_id {
                let val = encode_len_prefixed_uint(amf & 0x00FF_FFFF_FFFF, 5, 5);
                push_ie(&mut ies, 10, 0x40, &val);
            }
            if let Some(ran) = spec.ran_ue_id {
                let val = encode_len_prefixed_uint(ran as u64, 6, 4);
                push_ie(&mut ies, 85, 0x40, &val);
            }
        }
        _ => {
            if let Some(amf) = spec.amf_ue_id {
                let val = encode_len_prefixed_uint(amf & 0x00FF_FFFF_FFFF, 5, 5);
                push_ie(&mut ies, 10, 0x40, &val);
            }
            if let Some(ran) = spec.ran_ue_id {
                let val = encode_len_prefixed_uint(ran as u64, 6, 4);
                push_ie(&mut ies, 85, 0x40, &val);
            }
            if let Some(ref nas) = spec.nas_pdu {
                let mut nas_val = Vec::with_capacity(2 + nas.len());
                push_aper_len(&mut nas_val, nas.len());
                nas_val.extend_from_slice(nas);
                push_ie(&mut ies, 38, 0x40, &nas_val);
            } else if !payload_bytes.is_empty() && raw_ies.is_none() {
                let mut nas_val = Vec::with_capacity(2 + payload_bytes.len());
                push_aper_len(&mut nas_val, payload_bytes.len());
                nas_val.extend_from_slice(payload_bytes);
                push_ie(&mut ies, 38, 0x40, &nas_val);
            }
        }
    }

    if let Some(list) = raw_ies {
        for (_, raw_ie) in list {
            ies.push(raw_ie.to_vec());
        }
    }

    let ie_count = ies.len() as u16;
    let body_len = 3 + ies.iter().map(Vec::len).sum::<usize>();
    let mut out = Vec::with_capacity(6 + body_len);
    out.push(choice_byte);
    out.push(proc_code);
    out.push(crit_byte);
    push_aper_len(&mut out, body_len);
    out.push(0x00);
    out.extend_from_slice(&ie_count.to_be_bytes());
    for ie in ies {
        out.extend_from_slice(&ie);
    }
    out
}
