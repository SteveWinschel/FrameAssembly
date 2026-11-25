//! NVM Express over Fabrics TCP Transport (`NVMe/TCP`) Layer 7 wire payload builder.
//!
//! This module implements [`build_nvmetcp_payload`], which serializes a [`NvmetcpSpec`] AST
//! specification into an NVMe/TCP Protocol Data Unit over TCP port 4420. It constructs the
//! 8-byte little-endian common header (`PduType`, `Flags`, `HLEN`, `PDO`, `PLEN`), synthesizing
//! `ICReq` (`0x00`, 128 bytes), `ICResp` (`0x01`, 128 bytes), `H2CTermReq`/`C2HTermReq`
//! (`0x02`/`0x03`, 24 bytes), `CapsuleCmd` (`0x04` carrying a 64-byte NVMe SQE), `CapsuleResp`
//! (`0x05` carrying a 16-byte NVMe CQE), `H2CData`/`C2HData` (`0x06`/`0x07`), and `R2T` (`0x09`),
//! with optional Castagnoli CRC-32C header (`HDGST`) and data (`DDGST`) digests.

use crate::ast::*;
use crate::builders::WireContext;
use alloc::vec::Vec;

/// Reflected Castagnoli CRC-32C polynomial used for NVMe/TCP header and data digests.
const CRC32C_POLY: u32 = 0x82F6_3B78;

/// Computes the Castagnoli CRC-32C digest over `data`.
fn crc32c(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &b in data {
        crc ^= u32::from(b);
        for _ in 0..8 {
            crc = if (crc & 1) != 0 {
                (crc >> 1) ^ CRC32C_POLY
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

/// Resolves the NVMe/TCP `PduType` code and normalized label from `spec`.
fn resolve_pdu_type(spec: &NvmetcpSpec) -> (u8, alloc::string::String) {
    let raw = spec.pdu_type.unwrap_or(
        if spec.opcode.is_some() || spec.nsid.is_some() {
            "capsulecmd"
        } else if spec.status.is_some() || spec.qid.is_some() {
            "capsuleresp"
        } else if spec.offset.is_some() || spec.count.is_some() {
            "read"
        } else {
            "icreq"
        },
    );
    let norm = raw.trim().to_ascii_uppercase().replace(['_', '-'], "");
    let pdu_code = match norm.as_str() {
        "ICREQ" | "0" => 0x00,
        "ICRESP" | "1" => 0x01,
        "H2CTERM" | "H2CTERMREQ" | "2" => 0x02,
        "C2HTERM" | "C2HTERMREQ" | "3" => 0x03,
        "CAPSULECMD" | "CMD" | "4" | "READ" | "WRITE" | "IDENTIFY" | "FLUSH" => 0x04,
        "CAPSULERESP" | "RESPONSE" | "5" => 0x05,
        "H2CDATA" | "6" => 0x06,
        "C2HDATA" | "7" => 0x07,
        "R2T" | "9" => 0x09,
        _ => {
            if let Some(hex) = norm.strip_prefix("0X") {
                u8::from_str_radix(hex, 16).unwrap_or(0x00)
            } else {
                norm.parse::<u8>().unwrap_or(0x00)
            }
        }
    };
    (pdu_code, norm)
}

/// Builds an NVMe/TCP Protocol Data Unit payload.
pub fn build_nvmetcp_payload(
    _ctx: &WireContext,
    spec: &NvmetcpSpec,
    payload_bytes: &[u8],
) -> Vec<u8> {
    let (pdu_code, norm) = resolve_pdu_type(spec);
    let cid = spec.req_id.unwrap_or(1);
    let nsid = spec.nsid.unwrap_or(1);
    let qid = spec.qid.unwrap_or(1);
    let status = spec.status.unwrap_or(0);
    let offset = spec.offset.unwrap_or(0);
    let count = spec.count.unwrap_or(8);

    let default_flags = match pdu_code {
        0x06 => 0x04, // H2CData LAST_PDU
        0x07 => 0x0C, // C2HData LAST_PDU | SUCCESS
        _ => 0x00,
    };
    let flags = spec.flags.unwrap_or(default_flags);
    let has_hdgst = (flags & 0x01) != 0;
    let has_ddgst = (flags & 0x02) != 0;

    let mut hdr = Vec::new();
    let mut data: &[u8] = &[];

    match pdu_code {
        0x00 => {
            // ICReq (128 bytes)
            hdr.resize(128, 0u8);
            hdr[0] = 0x00;
            hdr[1] = flags;
            hdr[2] = 128;
            hdr[12..16].copy_from_slice(&16u32.to_le_bytes()); // MAXR2T
        }
        0x01 => {
            // ICResp (128 bytes)
            hdr.resize(128, 0u8);
            hdr[0] = 0x01;
            hdr[1] = flags;
            hdr[2] = 128;
            hdr[12..16].copy_from_slice(&131_072u32.to_le_bytes()); // MAXDATA
        }
        0x02 | 0x03 => {
            // H2CTermReq / C2HTermReq (24 bytes)
            hdr.resize(24, 0u8);
            hdr[0] = pdu_code;
            hdr[1] = flags;
            hdr[2] = 24;
            let fes = if spec.status.is_some() { status } else { 1 };
            hdr[8..10].copy_from_slice(&fes.to_le_bytes());
        }
        0x04 => {
            // CapsuleCmd (8B common + 64B NVMe SQE = 72 bytes)
            hdr.resize(72, 0u8);
            hdr[0] = 0x04;
            hdr[1] = flags;
            hdr[2] = 72;
            let sqe_opc = spec.opcode.unwrap_or(match norm.as_str() {
                "WRITE" => 0x01,
                "IDENTIFY" => 0x06,
                "FLUSH" => 0x00,
                _ => 0x02, // NVM Read
            });
            hdr[8] = sqe_opc;
            hdr[9] = 0x40; // PSDT = 01b (SGL)
            hdr[10..12].copy_from_slice(&cid.to_le_bytes());
            let eff_nsid = if sqe_opc == 0x06 && spec.nsid.is_none() {
                0
            } else {
                nsid
            };
            hdr[12..16].copy_from_slice(&eff_nsid.to_le_bytes());
            // SGL1 (offset 32..48 in PDU = SQE 24..40)
            let data_len_u32 = u32::try_from(payload_bytes.len()).unwrap_or(u32::MAX);
            hdr[40..44].copy_from_slice(&data_len_u32.to_le_bytes());
            hdr[47] = 0x00; // Data Block Descriptor
            // CDW10..11 SLBA (SQE 40..48 = PDU 48..56)
            hdr[48..56].copy_from_slice(&u64::from(offset).to_le_bytes());
            // CDW12 NLB 0-based (SQE 48..52 = PDU 56..60)
            let nlb = count.saturating_sub(1);
            hdr[56..60].copy_from_slice(&nlb.to_le_bytes());
            data = payload_bytes;
        }
        0x05 => {
            // CapsuleResp (8B common + 16B NVMe CQE = 24 bytes)
            hdr.resize(24, 0u8);
            hdr[0] = 0x05;
            hdr[1] = flags;
            hdr[2] = 24;
            hdr[16..18].copy_from_slice(&1u16.to_le_bytes()); // SQHD
            hdr[18..20].copy_from_slice(&qid.to_le_bytes()); // SQID
            hdr[20..22].copy_from_slice(&cid.to_le_bytes()); // CID
            let cqe_status = (status << 1) | 0x0001; // Phase = 1
            hdr[22..24].copy_from_slice(&cqe_status.to_le_bytes());
        }
        0x06 | 0x07 => {
            // H2CData / C2HData (24 bytes)
            hdr.resize(24, 0u8);
            hdr[0] = pdu_code;
            hdr[1] = flags;
            hdr[2] = 24;
            hdr[8..10].copy_from_slice(&cid.to_le_bytes()); // CCCID
            hdr[10..12].copy_from_slice(&1u16.to_le_bytes()); // TTAG
            hdr[12..16].copy_from_slice(&offset.to_le_bytes()); // DATAO
            let datal = u32::try_from(payload_bytes.len()).unwrap_or(u32::MAX);
            hdr[16..20].copy_from_slice(&datal.to_le_bytes()); // DATAL
            data = payload_bytes;
        }
        0x09 => {
            // R2T (24 bytes)
            hdr.resize(24, 0u8);
            hdr[0] = 0x09;
            hdr[1] = flags;
            hdr[2] = 24;
            hdr[8..10].copy_from_slice(&cid.to_le_bytes()); // CCCID
            hdr[10..12].copy_from_slice(&1u16.to_le_bytes()); // TTAG
            hdr[12..16].copy_from_slice(&offset.to_le_bytes()); // R2TO
            let r2tl = spec.count.unwrap_or(4096);
            hdr[16..20].copy_from_slice(&r2tl.to_le_bytes()); // R2TL
        }
        _ => {
            hdr.resize(24, 0u8);
            hdr[0] = pdu_code;
            hdr[1] = flags;
            hdr[2] = 24;
            data = payload_bytes;
        }
    }

    let hlen = hdr.len();
    let hdgst_len = if has_hdgst { 4 } else { 0 };
    let ddgst_len = if has_ddgst && !data.is_empty() { 4 } else { 0 };
    let pdo = if data.is_empty() {
        0u8
    } else {
        u8::try_from(hlen + hdgst_len).unwrap_or(u8::MAX)
    };
    let plen = u32::try_from(hlen + hdgst_len + data.len() + ddgst_len).unwrap_or(u32::MAX);
    hdr[3] = pdo;
    hdr[4..8].copy_from_slice(&plen.to_le_bytes());

    let mut pkt = Vec::with_capacity(plen as usize);
    pkt.extend_from_slice(&hdr);
    if has_hdgst {
        pkt.extend_from_slice(&crc32c(&hdr).to_le_bytes());
    }
    if !data.is_empty() {
        pkt.extend_from_slice(data);
        if has_ddgst {
            pkt.extend_from_slice(&crc32c(data).to_le_bytes());
        }
    }
    pkt
}
