//! IEC 61850-8-1 GOOSE (EtherType `0x88B8`) ASN.1 BER wire frame builder.
//!
//! Synthesizes IEC 61850-8-1 Generic Object Oriented Substation Event (GOOSE) multicast frames
//! over Ethernet II (`EtherType = 0x88B8`) addressed by default to the IEC TC57 multicast MAC
//! `01:0C:CD:01:00:01`. Encodes the 8-byte GOOSE transport header (`APPID`, `Length`,
//! `Reserved1`, `Reserved2`) followed by the ASN.1 BER `[APPLICATION 1]` (`0x61`) `goosePdu`
//! carrying `gocbRef`, `timeAllowedToLive`, `datSet`, `goID`, `t` UTC timestamp, `stNum`,
//! `sqNum`, `simulation`, `confRev`, `ndsCom`, `numDatSetEntries`, and `allData`.
//!
//! Canonical `.frasm` syntax:
//! `a -> b goose [appid <u16>] [gocbref "<str>"] [timetolive <u32>] [datset "<str>"] [goid "<str>"] [stnum <u32>] [sqnum <u32>] [simulation] [confrev <u32>] [ndscom] [numdatsetentries <u32>]`

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

/// Appends an ASN.1 BER unsigned integer encoded in minimal two's-complement big-endian bytes.
fn push_ber_uint(out: &mut Vec<u8>, tag: u8, val: u32) {
    let be = val.to_be_bytes();
    let start = be.iter().position(|&b| b != 0).unwrap_or(3);
    let sig = &be[start..];
    if (sig[0] & 0x80) != 0 {
        let mut buf = Vec::with_capacity(sig.len() + 1);
        buf.push(0x00);
        buf.extend_from_slice(sig);
        push_ber_tlv(out, tag, &buf);
    } else {
        push_ber_tlv(out, tag, sig);
    }
}

/// Builds an IEC 61850-8-1 GOOSE wire payload (8-byte header + ASN.1 BER `goosePdu`).
pub fn build_goose_payload(spec: &GooseSpec, payload: &[u8]) -> Vec<u8> {
    let gocb_ref = spec.gocb_ref.unwrap_or("IED1/LLN0$GO$gcb01");
    let ttl_ms = spec.time_to_live.unwrap_or(2000);
    let dat_set = spec.dat_set.unwrap_or("IED1/LLN0$ds01");
    let go_id = spec.go_id.unwrap_or("gcb01");
    let st_num = spec.st_num.unwrap_or(1);
    let sq_num = spec.sq_num.unwrap_or(0);
    let sim_byte = if spec.simulation { 0x01_u8 } else { 0x00_u8 };
    let conf_rev = spec.conf_rev.unwrap_or(1);
    let nds_byte = if spec.nds_com { 0x01_u8 } else { 0x00_u8 };

    let num_entries = spec
        .num_entries
        .unwrap_or(if payload.is_empty() { 2 } else { 1 });

    let mut all_data = Vec::new();
    if !payload.is_empty() {
        push_ber_tlv(&mut all_data, 0x89, payload);
        for _ in 1..num_entries.min(64) {
            push_ber_tlv(&mut all_data, 0x83, &[0x00]);
        }
    } else if num_entries == 2 {
        push_ber_tlv(&mut all_data, 0x83, &[0x00]);
        push_ber_tlv(&mut all_data, 0x84, &[0x03, 0x00]);
    } else {
        for _ in 0..num_entries.min(64) {
            push_ber_tlv(&mut all_data, 0x83, &[0x00]);
        }
    }

    let mut pdu_body = Vec::with_capacity(96 + all_data.len());
    push_ber_tlv(&mut pdu_body, 0x80, gocb_ref.as_bytes());
    push_ber_uint(&mut pdu_body, 0x81, ttl_ms);
    push_ber_tlv(&mut pdu_body, 0x82, dat_set.as_bytes());
    push_ber_tlv(&mut pdu_body, 0x83, go_id.as_bytes());
    push_ber_tlv(&mut pdu_body, 0x84, &[0u8; 8]); // UTC Timestamp t (8B)
    push_ber_uint(&mut pdu_body, 0x85, st_num);
    push_ber_uint(&mut pdu_body, 0x86, sq_num);
    push_ber_tlv(&mut pdu_body, 0x87, &[sim_byte]);
    push_ber_uint(&mut pdu_body, 0x88, conf_rev);
    push_ber_tlv(&mut pdu_body, 0x89, &[nds_byte]);
    push_ber_uint(&mut pdu_body, 0x8A, num_entries);
    push_ber_tlv(&mut pdu_body, 0xAB, &all_data);

    let mut apdu = Vec::with_capacity(4 + pdu_body.len());
    push_ber_tlv(&mut apdu, 0x61, &pdu_body);

    let appid = spec.appid.unwrap_or(0x1000);
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

/// Builds a complete IEEE 802.3 Ethernet II IEC 61850 GOOSE wire frame (`EtherType = 0x88B8`).
///
/// # Errors
/// Returns `CompilerError::BackendError` if wire construction fails.
pub fn build_goose_frame(
    ctx: &WireContext,
    spec: &GooseSpec,
    payload: &[u8],
) -> Result<Vec<u8>, CompilerError> {
    let goose_pkt = build_goose_payload(spec, payload);
    let dst_mac = ctx
        .l2
        .dst_mac
        .unwrap_or([0x01, 0x0C, 0xCD, 0x01, 0x00, 0x01]);
    Ok(build_ethernet_and_l2(
        ctx.src_mac,
        dst_mac,
        ctx.l2,
        0x88B8,
        &goose_pkt,
    ))
}
