//! 4G LTE S1 Application Protocol (S1AP, 3GPP TS 36.413, ITU-T X.691 APER) Layer 7 wire builder.
//!
//! This module serializes [`S1apSpec`] into valid ITU-T X.691 Aligned PER (APER) `S1AP-PDU`
//! frames transported over SCTP port `36412` (PPID `18`). It builds `InitiatingMessage`,
//! `SuccessfulOutcome`, and `UnsuccessfulOutcome` containers along with TS 36.413 `ProtocolIE-Field`
//! encodings and appends custom raw APER IE streams from `payload_bytes`.

use alloc::vec::Vec;

use crate::ast::*;
use crate::builders::WireContext;

/// Default EPS NAS Attach Request message used when `naspdu` is omitted on NAS procedures.
const DEFAULT_EPS_NAS_PDU: [u8; 21] = [
    0x07, 0x41, 0x71, 0x08, 0x09, 0x10, 0x10, 0x00, 0x00, 0x00, 0x00, 0x10, 0x02, 0x80, 0x20, 0x00,
    0x04, 0x02, 0x01, 0xD0, 0x11,
];

/// Appends an ITU-T X.691 APER open-type length determinant (`< 16384`).
fn push_aper_len(buf: &mut Vec<u8>, len: usize) {
    if len < 128 {
        buf.push(len as u8);
    } else {
        let v = (0x8000u16) | ((len as u16) & 0x3FFF);
        buf.extend_from_slice(&v.to_be_bytes());
    }
}

/// Appends a single S1AP `ProtocolIE-Field` `(id, criticality, value_bytes)`.
fn push_ie(ies: &mut Vec<Vec<u8>>, id: u16, crit: u8, val: &[u8]) {
    let mut out = Vec::with_capacity(4 + val.len());
    out.extend_from_slice(&id.to_be_bytes());
    out.push(crit);
    push_aper_len(&mut out, val.len());
    out.extend_from_slice(val);
    ies.push(out);
}

/// Encodes a 5- or 6-digit PLMN string into 3GPP TS 24.008 3-byte BCD format.
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

/// Encodes `MME-UE-S1AP-ID` (`0..=u32::MAX`) or `ENB-UE-S1AP-ID` (`0..=16777215`) in APER.
fn encode_s1ap_ue_id(val: u32, shift: u8, max_bytes: usize) -> Vec<u8> {
    let be = val.to_be_bytes();
    let mut start = 4usize.saturating_sub(max_bytes);
    while start < 3 && be[start] == 0 {
        start += 1;
    }
    let slice = &be[start..4];
    let lm1 = (slice.len() - 1) as u8;
    let mut out = Vec::with_capacity(1 + slice.len());
    out.push(lm1 << shift);
    out.extend_from_slice(slice);
    out
}

/// Encodes `PrintableString (SIZE(1..150, ...))` (`eNBname` / `MMEname`) in ITU-T X.691 APER.
fn encode_s1ap_name(name: &str) -> Vec<u8> {
    let bytes = name.as_bytes();
    let clamped = if bytes.len() > 150 {
        &bytes[..150]
    } else if bytes.is_empty() {
        b"enb"
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

/// Encodes IE 59 `Global-ENB-ID` with 20-bit `macroENB-ID`.
fn encode_global_enb_id(plmn: [u8; 3], enb_id: u32) -> [u8; 8] {
    let shifted = ((enb_id & 0x000F_FFFF) << 4).to_be_bytes();
    [0x00, plmn[0], plmn[1], plmn[2], 0x00, shifted[1], shifted[2], shifted[3]]
}

/// Encodes IE 64 `SupportedTAs` (single item, unaligned 2-byte `tAC` per X.691 §17.5 + 3-byte PLMN).
fn encode_supported_tas(plmn: [u8; 3], tac: u16) -> [u8; 7] {
    let packed = (tac as u32) << 6;
    let pb = packed.to_be_bytes();
    [0x00, pb[1], pb[2], pb[3], plmn[0], plmn[1], plmn[2]]
}

/// Encodes IE 67 `TAI` (`plmn` + `tac`).
fn encode_tai(plmn: [u8; 3], tac: u16) -> [u8; 6] {
    let tb = tac.to_be_bytes();
    [0x00, plmn[0], plmn[1], plmn[2], tb[0], tb[1]]
}

/// Encodes IE 100 `EUTRAN-CGI` (`plmn` + fixed cell identity `1`).
fn encode_ecgi(plmn: [u8; 3]) -> [u8; 8] {
    [0x00, plmn[0], plmn[1], plmn[2], 0x00, 0x00, 0x00, 0x10]
}

/// Encodes IE 99 `UE-S1AP-IDs` (`uE-S1AP-ID-pair`) in APER.
fn encode_ue_s1ap_id_pair(mme_ue_id: u32, enb_ue_id: u32) -> Vec<u8> {
    let mme = encode_s1ap_ue_id(mme_ue_id, 2, 4);
    let enb = encode_s1ap_ue_id(enb_ue_id & 0x00FF_FFFF, 6, 3);
    let mut out = Vec::with_capacity(mme.len() + enb.len());
    out.extend_from_slice(&mme);
    out.extend_from_slice(&enb);
    out
}

/// Scans `raw` as a clean sequence of S1AP APER `ProtocolIE-Field`s.
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

/// Resolves S1AP shorthand or generic PDU selection to `(choice_byte, proc_code, default_crit_byte, is_named)`.
fn resolve_s1ap_proc(pdu_type: Option<&str>) -> (u8, u8, u8, bool) {
    match pdu_type {
        None | Some("s1setuprequest") => (0x00, 17, 0x00, true),
        Some("s1setupresponse") => (0x20, 17, 0x00, true),
        Some("s1setupfailure") => (0x40, 17, 0x00, true),
        Some("initialuemessage") => (0x00, 12, 0x40, true),
        Some("downlinknastransport") => (0x00, 11, 0x40, true),
        Some("uplinknastransport") => (0x00, 13, 0x40, true),
        Some("uecontextreleasecommand") => (0x00, 23, 0x00, true),
        Some("uecontextreleasecomplete") => (0x20, 23, 0x00, true),
        Some("errorindication") => (0x00, 15, 0x40, true),
        Some("initiating") => (0x00, 17, 0x00, false),
        Some("successful") => (0x20, 17, 0x00, false),
        Some("unsuccessful") => (0x40, 17, 0x00, false),
        Some(_) => (0x00, 17, 0x00, false),
    }
}

/// Builds a 3GPP TS 36.413 S1AP APER payload from `spec` and optional `payload_bytes`.
pub fn build_s1ap_payload(
    _ctx: &WireContext,
    spec: &S1apSpec<'_>,
    payload_bytes: &[u8],
) -> Vec<u8> {
    let (choice_byte, def_proc, def_crit, is_named) = resolve_s1ap_proc(spec.pdu_type);
    let proc_code = spec.proc_code.unwrap_or(def_proc);
    let crit_byte = match spec.criticality {
        Some("reject") => 0x00,
        Some("ignore") => 0x40,
        Some("notify") => 0x80,
        _ => def_crit,
    };

    let plmn = encode_plmn(spec.plmn);
    let enb_id = spec.enb_id.unwrap_or(1);
    let tac = spec.tac.unwrap_or(1);
    let mme_ue_id = spec.mme_ue_id.unwrap_or(1);
    let enb_ue_id = spec.enb_ue_id.unwrap_or(1);

    let raw_ies = scan_raw_ies(payload_bytes);
    let nas_fallback: &[u8] = if let Some(ref nas) = spec.nas_pdu {
        nas.as_slice()
    } else if !payload_bytes.is_empty() && raw_ies.is_none() {
        payload_bytes
    } else {
        &DEFAULT_EPS_NAS_PDU
    };

    let has_raw_ie = |id: u16| -> bool {
        raw_ies
            .as_ref()
            .is_some_and(|list| list.iter().any(|(x, _)| *x == id))
    };

    let mut ies: Vec<Vec<u8>> = Vec::new();
    let matched_named = is_named || spec.pdu_type.is_none();

    match (choice_byte, proc_code) {
        (0x00, 17) if matched_named => {
            if spec.plmn.is_some() || spec.enb_id.is_some() || !has_raw_ie(59) {
                let val = encode_global_enb_id(plmn, enb_id);
                push_ie(&mut ies, 59, 0x00, &val);
            }
            if let Some(name) = spec.enb_name {
                let val = encode_s1ap_name(name);
                push_ie(&mut ies, 60, 0x40, &val);
            }
            if spec.plmn.is_some() || spec.tac.is_some() || !has_raw_ie(64) {
                let val = encode_supported_tas(plmn, tac);
                push_ie(&mut ies, 64, 0x00, &val);
            }
            if !has_raw_ie(137) {
                push_ie(&mut ies, 137, 0x40, &[0x40]);
            }
        }
        (0x20, 17) if matched_named => {
            if let Some(name) = spec.enb_name {
                let val = encode_s1ap_name(name);
                push_ie(&mut ies, 61, 0x40, &val);
            }
            if spec.plmn.is_some() || !has_raw_ie(105) {
                let gummeis = [
                    0x00, 0x00, plmn[0], plmn[1], plmn[2], 0x00, 0x00, 0x00, 0x01, 0x00, 0x01,
                ];
                push_ie(&mut ies, 105, 0x00, &gummeis);
            }
            if !has_raw_ie(87) {
                push_ie(&mut ies, 87, 0x00, &[0xFF]);
            }
        }
        (0x40, 17) if matched_named => {
            if !has_raw_ie(2) {
                push_ie(&mut ies, 2, 0x40, &[0x8A]);
            }
        }
        (0x00, 12) if matched_named => {
            if spec.enb_ue_id.is_some() || !has_raw_ie(8) {
                let val = encode_s1ap_ue_id(enb_ue_id & 0x00FF_FFFF, 6, 3);
                push_ie(&mut ies, 8, 0x00, &val);
            }
            if spec.nas_pdu.is_some() || !has_raw_ie(26) {
                let mut nas_val = Vec::with_capacity(2 + nas_fallback.len());
                push_aper_len(&mut nas_val, nas_fallback.len());
                nas_val.extend_from_slice(nas_fallback);
                push_ie(&mut ies, 26, 0x00, &nas_val);
            }
            if spec.plmn.is_some() || spec.tac.is_some() || !has_raw_ie(67) {
                let val = encode_tai(plmn, tac);
                push_ie(&mut ies, 67, 0x00, &val);
            }
            if spec.plmn.is_some() || !has_raw_ie(100) {
                let val = encode_ecgi(plmn);
                push_ie(&mut ies, 100, 0x40, &val);
            }
            if !has_raw_ie(134) {
                push_ie(&mut ies, 134, 0x40, &[0x30]);
            }
        }
        (0x00, 11) if matched_named => {
            if spec.mme_ue_id.is_some() || !has_raw_ie(0) {
                let val = encode_s1ap_ue_id(mme_ue_id, 6, 4);
                push_ie(&mut ies, 0, 0x00, &val);
            }
            if spec.enb_ue_id.is_some() || !has_raw_ie(8) {
                let val = encode_s1ap_ue_id(enb_ue_id & 0x00FF_FFFF, 6, 3);
                push_ie(&mut ies, 8, 0x00, &val);
            }
            if spec.nas_pdu.is_some() || !has_raw_ie(26) {
                let mut nas_val = Vec::with_capacity(2 + nas_fallback.len());
                push_aper_len(&mut nas_val, nas_fallback.len());
                nas_val.extend_from_slice(nas_fallback);
                push_ie(&mut ies, 26, 0x00, &nas_val);
            }
        }
        (0x00, 13) if matched_named => {
            if spec.mme_ue_id.is_some() || !has_raw_ie(0) {
                let val = encode_s1ap_ue_id(mme_ue_id, 6, 4);
                push_ie(&mut ies, 0, 0x00, &val);
            }
            if spec.enb_ue_id.is_some() || !has_raw_ie(8) {
                let val = encode_s1ap_ue_id(enb_ue_id & 0x00FF_FFFF, 6, 3);
                push_ie(&mut ies, 8, 0x00, &val);
            }
            if spec.nas_pdu.is_some() || !has_raw_ie(26) {
                let mut nas_val = Vec::with_capacity(2 + nas_fallback.len());
                push_aper_len(&mut nas_val, nas_fallback.len());
                nas_val.extend_from_slice(nas_fallback);
                push_ie(&mut ies, 26, 0x00, &nas_val);
            }
            if spec.plmn.is_some() || !has_raw_ie(100) {
                let val = encode_ecgi(plmn);
                push_ie(&mut ies, 100, 0x40, &val);
            }
            if spec.plmn.is_some() || spec.tac.is_some() || !has_raw_ie(67) {
                let val = encode_tai(plmn, tac);
                push_ie(&mut ies, 67, 0x40, &val);
            }
        }
        (0x00, 23) if matched_named => {
            if spec.mme_ue_id.is_some() || spec.enb_ue_id.is_some() || !has_raw_ie(99) {
                let val = encode_ue_s1ap_id_pair(mme_ue_id, enb_ue_id);
                push_ie(&mut ies, 99, 0x00, &val);
            }
            if !has_raw_ie(2) {
                push_ie(&mut ies, 2, 0x40, &[0x8A]);
            }
        }
        (0x20, 23) if matched_named => {
            if spec.mme_ue_id.is_some() || !has_raw_ie(0) {
                let val = encode_s1ap_ue_id(mme_ue_id, 6, 4);
                push_ie(&mut ies, 0, 0x40, &val);
            }
            if spec.enb_ue_id.is_some() || !has_raw_ie(8) {
                let val = encode_s1ap_ue_id(enb_ue_id & 0x00FF_FFFF, 6, 3);
                push_ie(&mut ies, 8, 0x40, &val);
            }
        }
        (0x00, 15) if matched_named => {
            if !has_raw_ie(2) {
                push_ie(&mut ies, 2, 0x40, &[0x8A]);
            }
            if let Some(mme) = spec.mme_ue_id {
                let val = encode_s1ap_ue_id(mme, 6, 4);
                push_ie(&mut ies, 0, 0x40, &val);
            }
            if let Some(enb) = spec.enb_ue_id {
                let val = encode_s1ap_ue_id(enb & 0x00FF_FFFF, 6, 3);
                push_ie(&mut ies, 8, 0x40, &val);
            }
        }
        _ => {
            if let Some(mme) = spec.mme_ue_id {
                let val = encode_s1ap_ue_id(mme, 6, 4);
                push_ie(&mut ies, 0, 0x40, &val);
            }
            if let Some(enb) = spec.enb_ue_id {
                let val = encode_s1ap_ue_id(enb & 0x00FF_FFFF, 6, 3);
                push_ie(&mut ies, 8, 0x40, &val);
            }
            if let Some(ref nas) = spec.nas_pdu {
                let mut nas_val = Vec::with_capacity(2 + nas.len());
                push_aper_len(&mut nas_val, nas.len());
                nas_val.extend_from_slice(nas);
                push_ie(&mut ies, 26, 0x40, &nas_val);
            } else if !payload_bytes.is_empty() && raw_ies.is_none() {
                let mut nas_val = Vec::with_capacity(2 + payload_bytes.len());
                push_aper_len(&mut nas_val, payload_bytes.len());
                nas_val.extend_from_slice(payload_bytes);
                push_ie(&mut ies, 26, 0x40, &nas_val);
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
