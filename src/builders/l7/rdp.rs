//! Remote Desktop Protocol (`rdp`, MS-RDPBCGR over TPKT + X.224 COTP) Layer 7 wire builder.
//!
//! This module implements [`build_rdp_payload`], which synthesizes Microsoft Remote Desktop
//! Protocol (`[MS-RDPBCGR]`) session establishment packets over TCP port 3389. It encapsulates
//! X.224 Connection Request (`x224cr` with optional `Cookie: mstshash=...` and `RDP_NEG_REQ`),
//! X.224 Connection Confirm (`x224cc` with `RDP_NEG_RSP`), and X.224 Data + T.125 MCS
//! `Connect-Initial` (`mcs` with GCC `ConferenceCreateRequest` and 132-byte `CS_CORE` desktop
//! geometry and workstation name) inside RFC 1006 TPKT headers (`0x03 0x00`).

use crate::ast::RdpSpec;
use crate::builders::WireContext;
use alloc::format;
use alloc::vec::Vec;

/// Appends an ASN.1 BER definite length field (`short` `< 128`, `long` `>= 128`).
fn push_ber_len(out: &mut Vec<u8>, len: usize) {
    if len < 128 {
        out.push(len as u8);
    } else if len <= 0xFF {
        out.push(0x81);
        out.push(len as u8);
    } else {
        out.push(0x82);
        out.extend_from_slice(&(u16::try_from(len).unwrap_or(u16::MAX)).to_be_bytes());
    }
}

/// Appends an ASN.1 BER TLV with single-byte `tag` and `content` bytes.
fn push_ber_tlv(out: &mut Vec<u8>, tag: u8, content: &[u8]) {
    out.push(tag);
    push_ber_len(out, content.len());
    out.extend_from_slice(content);
}

/// Appends an ASN.1 PER aligned length determinant (`< 128` 1 byte, `128..16384` 2 bytes).
fn push_per_len(out: &mut Vec<u8>, len: usize) {
    if len < 128 {
        out.push(len as u8);
    } else {
        let clamped = len.min(16383) as u16;
        out.push(0x80 | ((clamped >> 8) as u8));
        out.push((clamped & 0xFF) as u8);
    }
}

/// Builds a 132-byte MS-RDPBCGR §2.2.1.3.2 `CS_CORE` (`0xC001`) Client Core Data block.
fn build_rdp_cs_core(width: u16, height: u16, client_name: &str) -> Vec<u8> {
    let mut core = Vec::with_capacity(132);
    core.extend_from_slice(&0xC001u16.to_le_bytes()); // User Data Header Type: CS_CORE
    core.extend_from_slice(&132u16.to_le_bytes()); // User Data Header Length: 132
    core.extend_from_slice(&0x0008_0004u32.to_le_bytes()); // version: RDP 5.0+
    core.extend_from_slice(&width.to_le_bytes());
    core.extend_from_slice(&height.to_le_bytes());
    core.extend_from_slice(&0xCA01u16.to_le_bytes()); // colorDepth: RNS_UD_COLOR_8BPP
    core.extend_from_slice(&0xAA03u16.to_le_bytes()); // SASSequence: RNS_UD_SAS_DEL
    core.extend_from_slice(&0x0000_0409u32.to_le_bytes()); // keyboardLayout: US English
    core.extend_from_slice(&2600u32.to_le_bytes()); // clientBuild
    let mut name_buf = [0u8; 32];
    for (idx, unit) in client_name.encode_utf16().take(15).enumerate() {
        let b = unit.to_le_bytes();
        name_buf[idx * 2] = b[0];
        name_buf[idx * 2 + 1] = b[1];
    }
    core.extend_from_slice(&name_buf); // clientName (32 bytes UTF-16LE)
    core.extend_from_slice(&4u32.to_le_bytes()); // keyboardType: Enhanced 101/102
    core.extend_from_slice(&0u32.to_le_bytes()); // keyboardSubType
    core.extend_from_slice(&12u32.to_le_bytes()); // keyboardFunctionKey
    core.extend_from_slice(&[0u8; 64]); // imeFileName
    core
}

/// Builds a T.125 MCS `Connect-Initial` (`0x7F 0x65`) PDU wrapping GCC `ConferenceCreateRequest` + `CS_CORE`.
fn build_mcs_connect_initial(spec: &RdpSpec) -> Vec<u8> {
    let width = spec.width.unwrap_or(1024);
    let height = spec.height.unwrap_or(768);
    let client_name = spec.cookie.unwrap_or("WORKSTATION");
    let cs_core = build_rdp_cs_core(width, height, client_name);

    let mut connect_pdu = Vec::with_capacity(16 + cs_core.len());
    connect_pdu.extend_from_slice(&[
        0x00, 0x08, 0x00, 0x10, 0x00, 0x01, 0xc0, 0x00, 0x44, 0x75, 0x63, 0x61,
    ]);
    push_per_len(&mut connect_pdu, cs_core.len());
    connect_pdu.extend_from_slice(&cs_core);

    let mut gcc = Vec::with_capacity(10 + connect_pdu.len());
    gcc.extend_from_slice(&[0x00, 0x05, 0x00, 0x14, 0x7c, 0x00, 0x01]);
    push_per_len(&mut gcc, connect_pdu.len());
    gcc.extend_from_slice(&connect_pdu);

    let mut ci_body = Vec::with_capacity(120 + gcc.len());
    ci_body.extend_from_slice(&[0x04, 0x01, 0x01]); // callingDomainSelector
    ci_body.extend_from_slice(&[0x04, 0x01, 0x01]); // calledDomainSelector
    ci_body.extend_from_slice(&[0x01, 0x01, 0xff]); // upwardFlag: TRUE
    // targetParameters (26B SEQUENCE body, positive maxMCSPDUsize=65535)
    ci_body.extend_from_slice(&[
        0x30, 0x1a, 0x02, 0x01, 0x22, 0x02, 0x01, 0x02, 0x02, 0x01, 0x00, 0x02, 0x01, 0x01, 0x02,
        0x01, 0x00, 0x02, 0x01, 0x01, 0x02, 0x03, 0x00, 0xff, 0xff, 0x02, 0x01, 0x02,
    ]);
    // minimumParameters (25B SEQUENCE body)
    ci_body.extend_from_slice(&[
        0x30, 0x19, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x02,
        0x01, 0x00, 0x02, 0x01, 0x01, 0x02, 0x02, 0x04, 0x20, 0x02, 0x01, 0x02,
    ]);
    // maximumParameters (29B SEQUENCE body)
    ci_body.extend_from_slice(&[
        0x30, 0x1d, 0x02, 0x03, 0x00, 0xff, 0xff, 0x02, 0x03, 0x00, 0xfc, 0x17, 0x02, 0x03, 0x00,
        0xff, 0xff, 0x02, 0x01, 0x01, 0x02, 0x01, 0x00, 0x02, 0x01, 0x01, 0x02, 0x03, 0x00, 0xff,
        0xff, 0x02, 0x01, 0x02,
    ]);
    push_ber_tlv(&mut ci_body, 0x04, &gcc);

    let mut out = Vec::with_capacity(4 + ci_body.len());
    out.extend_from_slice(&[0x7f, 0x65]); // [APPLICATION 101] IMPLICIT Connect-Initial
    push_ber_len(&mut out, ci_body.len());
    out.extend_from_slice(&ci_body);
    out
}

/// Builds an MS-RDPBCGR (`rdp`) TPKT + X.224 + RDP handshake wire payload for TCP port 3389.
pub fn build_rdp_payload(
    _ctx: &WireContext,
    spec: &RdpSpec,
    payload_bytes: &[u8],
) -> Vec<u8> {
    let stage = if let Some(mt) = spec.msg_type {
        let norm = mt.trim().to_ascii_lowercase().replace(['_', '-'], "");
        match norm.as_str() {
            "x224cr" | "cr" | "connectrequest" => 1u8,
            "x224cc" | "cc" | "connectconfirm" => 2u8,
            "mcs" | "connectinitial" => 3u8,
            _ => 1u8,
        }
    } else if spec.width.is_some() || spec.height.is_some() {
        3u8
    } else {
        1u8
    };

    let mut cotp_and_body = Vec::new();
    match stage {
        2 => {
            // X.224 Connection Confirm (0xD0) + RDP_NEG_RSP (8 bytes)
            let mut user_data = Vec::with_capacity(8 + payload_bytes.len());
            user_data.push(0x02); // TYPE_RDP_NEG_RSP
            user_data.push(spec.flags.unwrap_or(0x00));
            user_data.extend_from_slice(&8u16.to_le_bytes());
            user_data.extend_from_slice(&spec.proto.unwrap_or(0x0000_0002).to_le_bytes());
            let max_extra = 248usize.saturating_sub(user_data.len());
            user_data.extend_from_slice(&payload_bytes[..payload_bytes.len().min(max_extra)]);

            cotp_and_body.push((6 + user_data.len()) as u8); // LI
            cotp_and_body.push(0xD0); // CC CDT
            cotp_and_body.extend_from_slice(&0u16.to_be_bytes()); // DST-REF
            cotp_and_body.extend_from_slice(&spec.session_id.unwrap_or(0x1234).to_be_bytes());
            cotp_and_body.push(0x00); // Class 0
            cotp_and_body.extend_from_slice(&user_data);
        }
        3 => {
            // X.224 DT Data (02 F0 80) + T.125 MCS Connect-Initial
            cotp_and_body.extend_from_slice(&[0x02, 0xF0, 0x80]);
            cotp_and_body.extend_from_slice(&build_mcs_connect_initial(spec));
            cotp_and_body.extend_from_slice(payload_bytes);
        }
        _ => {
            // X.224 Connection Request (0xE0) + optional Cookie + RDP_NEG_REQ (8 bytes)
            let mut user_data = Vec::new();
            if let Some(cookie) = spec.cookie {
                let line = format!("Cookie: mstshash={cookie}\r\n");
                let max_cookie = 248usize.saturating_sub(8);
                user_data.extend_from_slice(&line.as_bytes()[..line.len().min(max_cookie)]);
            }
            user_data.push(0x01); // TYPE_RDP_NEG_REQ
            user_data.push(spec.flags.unwrap_or(0x00));
            user_data.extend_from_slice(&8u16.to_le_bytes());
            user_data.extend_from_slice(&spec.proto.unwrap_or(0x0000_0003).to_le_bytes());
            let max_extra = 248usize.saturating_sub(user_data.len());
            user_data.extend_from_slice(&payload_bytes[..payload_bytes.len().min(max_extra)]);

            cotp_and_body.push((6 + user_data.len()) as u8); // LI
            cotp_and_body.push(0xE0); // CR CDT
            cotp_and_body.extend_from_slice(&0u16.to_be_bytes()); // DST-REF
            cotp_and_body.extend_from_slice(&spec.session_id.unwrap_or(0).to_be_bytes());
            cotp_and_body.push(0x00); // Class 0
            cotp_and_body.extend_from_slice(&user_data);
        }
    }

    let max_body = usize::from(u16::MAX).saturating_sub(4);
    if cotp_and_body.len() > max_body {
        cotp_and_body.truncate(max_body);
    }
    let total_len = (4 + cotp_and_body.len()) as u16;
    let mut pkt = Vec::with_capacity(usize::from(total_len));
    pkt.push(0x03); // TPKT Version 3
    pkt.push(0x00); // Reserved
    pkt.extend_from_slice(&total_len.to_be_bytes());
    pkt.extend_from_slice(&cotp_and_body);
    pkt
}
