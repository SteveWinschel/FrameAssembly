//! IEC 61850-9-2LE Sampled Values (`sv`, EtherType `0x88BA`) ASN.1 BER wire frame builder.
//!
//! Synthesizes IEC 61850-9-2 / 9-2LE Sampled Measured Values multicast frames over Ethernet II
//! (`EtherType = 0x88BA`) addressed by default to the IEC TC57 multicast MAC `01:0C:CD:04:00:01`.
//! Encodes the 8-byte SV transport header (`APPID`, `Length`, `Reserved1` with Ed2 `S` simulation
//! bit, `Reserved2`) followed by the ASN.1 BER `[APPLICATION 0]` (`0x60`) `savPdu` carrying
//! `noASDU` (`1`) and a single `ASDU` (`0x30`) with `svID`, optional `datSet`, `smpCnt`, `confRev`,
//! `smpSynch`, optional `smpRate`, and 64-byte IEC 61850-9-2LE `seqOfData` phasor samples.
//!
//! Canonical `.frasm` syntax:
//! `a -> b sv [appid <u16>] [svid "<str>"] [datset "<str>"] [smpcnt <u16>] [confrev <u32>] [smpsynch <0|1|2>] [smprate <u16>] [simulation]`

use crate::ast::*;
use crate::builders::WireContext;
use crate::error::CompilerError;
use crate::packet::build_ethernet_and_l2;
use alloc::vec::Vec;

/// Appends an ASN.1 BER definite-length TLV (`tag || len || val`) into `out`.
fn push_ber_tlv(out: &mut Vec<u8>, tag: u8, val: &[u8]) {
    out.push(tag);
    let len = val.len();
    if len < 0x80 {
        out.push(len as u8);
    } else if len <= 0xFF {
        out.push(0x81);
        out.push(len as u8);
    } else {
        out.push(0x82);
        out.extend_from_slice(&(len as u16).to_be_bytes());
    }
    out.extend_from_slice(val);
}

/// Builds an IEC 61850-9-2LE Sampled Values wire payload (8-byte header + ASN.1 BER `savPdu`).
pub fn build_sv_payload(spec: &SvSpec, payload: &[u8]) -> Vec<u8> {
    let sv_id = spec.sv_id.unwrap_or("IED1MU01");
    let smp_cnt = spec.smp_cnt.unwrap_or(0);
    let conf_rev = spec.conf_rev.unwrap_or(1);
    let smp_synch = spec.smp_synch.unwrap_or(2);

    let mut asdu_body = Vec::with_capacity(96 + payload.len());
    push_ber_tlv(&mut asdu_body, 0x80, sv_id.as_bytes());
    if let Some(ds) = spec.dat_set {
        push_ber_tlv(&mut asdu_body, 0x81, ds.as_bytes());
    }
    push_ber_tlv(&mut asdu_body, 0x82, &smp_cnt.to_be_bytes());
    push_ber_tlv(&mut asdu_body, 0x83, &conf_rev.to_be_bytes());
    push_ber_tlv(&mut asdu_body, 0x85, &[smp_synch]);
    if let Some(rate) = spec.smp_rate {
        push_ber_tlv(&mut asdu_body, 0x86, &rate.to_be_bytes());
    }
    if payload.is_empty() {
        let default_samples = [0u8; 64];
        push_ber_tlv(&mut asdu_body, 0x87, &default_samples);
    } else {
        push_ber_tlv(&mut asdu_body, 0x87, payload);
    }

    let mut seq_asdu_body = Vec::with_capacity(4 + asdu_body.len());
    push_ber_tlv(&mut seq_asdu_body, 0x30, &asdu_body);

    let mut sv_pdu_body = Vec::with_capacity(8 + seq_asdu_body.len());
    push_ber_tlv(&mut sv_pdu_body, 0x80, &[1]); // noASDU = 1
    push_ber_tlv(&mut sv_pdu_body, 0xA2, &seq_asdu_body);

    let mut apdu = Vec::with_capacity(4 + sv_pdu_body.len());
    push_ber_tlv(&mut apdu, 0x60, &sv_pdu_body);

    let appid = spec.appid.unwrap_or(0x4000);
    let total_len = u16::try_from(8usize.saturating_add(apdu.len())).unwrap_or(u16::MAX);
    let res1: u16 = if spec.simulation { 0x8000 } else { 0x0000 };

    let mut out = Vec::with_capacity(8 + apdu.len());
    out.extend_from_slice(&appid.to_be_bytes());
    out.extend_from_slice(&total_len.to_be_bytes());
    out.extend_from_slice(&res1.to_be_bytes());
    out.extend_from_slice(&0_u16.to_be_bytes());
    out.extend_from_slice(&apdu);
    out
}

/// Builds a complete IEEE 802.3 Ethernet II IEC 61850 Sampled Values wire frame (`EtherType = 0x88BA`).
///
/// # Errors
/// Returns `CompilerError::BackendError` if wire construction fails.
pub fn build_sv_frame(
    ctx: &WireContext,
    spec: &SvSpec,
    payload: &[u8],
) -> Result<Vec<u8>, CompilerError> {
    let sv_pkt = build_sv_payload(spec, payload);
    let dst_mac = ctx
        .l2
        .dst_mac
        .unwrap_or([0x01, 0x0C, 0xCD, 0x04, 0x00, 0x01]);
    Ok(build_ethernet_and_l2(
        ctx.src_mac,
        dst_mac,
        ctx.l2,
        0x88BA,
        &sv_pkt,
    ))
}
