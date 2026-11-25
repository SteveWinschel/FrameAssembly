//! Distributed Computing Environment / Remote Procedure Call (`dcerpc`, C706 / MS-RPCE) Layer 7 wire builder.
//!
//! This module implements [`build_dcerpc_payload`], which synthesizes connection-oriented DCE/RPC
//! v5 (`ncacn_ip_tcp`) protocol data units over TCP port 135 (RPC Endpoint Mapper) and dynamic
//! RPC service ports. It encodes the 16-byte DCE/RPC v5 common header (`rpc_vers = 5`, `PTYPE`,
//! `pfc_flags`, little-endian `packed_drep`, `frag_length`, `auth_length`, and `call_id`),
//! Microsoft mixed-endian interface and object UUIDs, NDR 2.0 transfer syntax negotiation, and
//! `Bind`, `Bind_ack`, `Bind_nak`, `Alter_context`, `Request`, `Response`, and `Fault` bodies.

use crate::ast::DcerpcSpec;
use crate::builders::WireContext;
use alloc::vec::Vec;

/// NDR 2.0 transfer syntax UUID (`8a885d04-1ceb-11c9-9fe8-08002b104860`) in MS mixed-endian order.
const NDR20_UUID_LE: [u8; 16] = [
    0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11, 0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60,
];

/// Default Endpoint Mapper (`epm`) UUID (`e1af8308-5d1f-11c9-91a4-08002b14a0fa`) in mixed-endian order.
const EPM_UUID_LE: [u8; 16] = [
    0x08, 0x83, 0xaf, 0xe1, 0x1f, 0x5d, 0xc9, 0x11, 0x91, 0xa4, 0x08, 0x00, 0x2b, 0x14, 0xa0, 0xfa,
];

/// Resolves a DCE/RPC interface service alias or canonical UUID string to `(mixed_endian_uuid, default_ver)`.
fn resolve_dcerpc_uuid(raw: &str) -> ([u8; 16], &'static str) {
    let trimmed = raw.trim().trim_matches(['{', '}']);
    let norm: alloc::string::String = trimmed
        .chars()
        .filter(|c| *c != '-' && *c != '_')
        .map(|c| c.to_ascii_lowercase())
        .collect();
    match norm.as_str() {
        "epm" | "epmapper" => return (EPM_UUID_LE, "3.0"),
        "drsuapi" => return (parse_uuid_hex("e35142354b0611d1ab0400c04fc2dcd2").unwrap_or(EPM_UUID_LE), "4.0"),
        "samr" => return (parse_uuid_hex("123457781234abcdef000123456789ac").unwrap_or(EPM_UUID_LE), "1.0"),
        "lsarpc" => return (parse_uuid_hex("123457781234abcdef000123456789ab").unwrap_or(EPM_UUID_LE), "0.0"),
        "svcctl" => return (parse_uuid_hex("367abb81984435f1ad3298f038001003").unwrap_or(EPM_UUID_LE), "2.0"),
        "winreg" => return (parse_uuid_hex("338cd001224431f1aaaa900038001003").unwrap_or(EPM_UUID_LE), "1.0"),
        "atsvc" => return (parse_uuid_hex("1ff706820a5130e8076d740be8cee98b").unwrap_or(EPM_UUID_LE), "1.0"),
        "srvsvc" => return (parse_uuid_hex("4b324fc8167001d312785a47bf6ee188").unwrap_or(EPM_UUID_LE), "3.0"),
        "wkssvc" => return (parse_uuid_hex("6bffd098a1123610983346c3f87e345a").unwrap_or(EPM_UUID_LE), "1.0"),
        "netlogon" => return (parse_uuid_hex("123456781234abcdef0001234567cffb").unwrap_or(EPM_UUID_LE), "1.0"),
        _ => {}
    }
    (parse_uuid_hex(&norm).unwrap_or(EPM_UUID_LE), "3.0")
}

/// Decodes 32 hexadecimal characters into a Microsoft mixed-endian 16-byte UUID.
fn parse_uuid_hex(hex: &str) -> Option<[u8; 16]> {
    if hex.len() != 32 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut raw = [0u8; 16];
    let bytes = hex.as_bytes();
    for (i, slot) in raw.iter_mut().enumerate() {
        let pair = core::str::from_utf8(&bytes[i * 2..i * 2 + 2]).ok()?;
        *slot = u8::from_str_radix(pair, 16).ok()?;
    }
    Some([
        raw[3], raw[2], raw[1], raw[0], raw[5], raw[4], raw[7], raw[6], raw[8], raw[9], raw[10],
        raw[11], raw[12], raw[13], raw[14], raw[15],
    ])
}

/// Parses a `"major.minor"` interface version string into a 32-bit packed little-endian representation.
fn parse_if_version(raw: &str) -> [u8; 4] {
    let trimmed = raw.trim();
    let (maj_s, min_s) = trimmed.split_once('.').unwrap_or((trimmed, "0"));
    let major = maj_s.parse::<u16>().unwrap_or(3);
    let minor = min_s.parse::<u16>().unwrap_or(0);
    let mut out = [0u8; 4];
    out[0..2].copy_from_slice(&major.to_le_bytes());
    out[2..4].copy_from_slice(&minor.to_le_bytes());
    out
}

/// Parses a DCE/RPC PDU type keyword or numeric identifier into a `PTYPE` byte.
fn parse_dcerpc_pdu_type(raw: &str) -> u8 {
    let norm = raw.trim().to_ascii_lowercase().replace(['_', '-'], "");
    match norm.as_str() {
        "request" => 0,
        "ping" => 1,
        "response" => 2,
        "fault" => 3,
        "working" => 4,
        "nocall" => 5,
        "reject" => 6,
        "ack" => 7,
        "clcancel" => 8,
        "fack" => 9,
        "cancelack" => 10,
        "bind" => 11,
        "bindack" => 12,
        "bindnak" => 13,
        "altercontext" => 14,
        "altercontextresp" => 15,
        "shutdown" => 16,
        "cocancel" => 17,
        "orphaned" => 18,
        _ => raw.trim().parse::<u8>().unwrap_or(11),
    }
}

/// Builds a connection-oriented DCE/RPC v5 (`dcerpc`) wire payload for TCP port 135.
pub fn build_dcerpc_payload(
    _ctx: &WireContext,
    spec: &DcerpcSpec,
    payload_bytes: &[u8],
) -> Vec<u8> {
    let ptype = if let Some(p) = spec.pdu_type {
        parse_dcerpc_pdu_type(p)
    } else if spec.opnum.is_some() || !payload_bytes.is_empty() {
        0 // Request
    } else if spec.status.is_some() && spec.uuid.is_none() {
        3 // Fault
    } else {
        11 // Bind
    };

    let (if_uuid, default_ver) = spec
        .uuid
        .map(resolve_dcerpc_uuid)
        .unwrap_or((EPM_UUID_LE, "3.0"));
    let if_ver_bytes = parse_if_version(spec.if_version.unwrap_or(default_ver));
    let call_id = spec.call_id.unwrap_or(1);
    let ctx_id = spec.ctx_id.unwrap_or(0);
    let mut pfc_flags = spec.flags.unwrap_or(0x03);
    if ptype == 0 && spec.uuid.is_some() {
        pfc_flags |= 0x80; // PFC_OBJECT_UUID
    }

    let mut body = Vec::new();
    match ptype {
        11 | 14 => {
            // Bind (11) / Alter_context (14)
            body.extend_from_slice(&5840u16.to_le_bytes()); // max_xmit_frag
            body.extend_from_slice(&5840u16.to_le_bytes()); // max_recv_frag
            body.extend_from_slice(&0u32.to_le_bytes()); // assoc_group_id
            body.push(1); // n_context_elem
            body.push(0); // reserved
            body.extend_from_slice(&0u16.to_le_bytes()); // reserved2
            body.extend_from_slice(&ctx_id.to_le_bytes()); // p_cont_id
            body.push(1); // n_transfer_syn
            body.push(0); // reserved
            body.extend_from_slice(&if_uuid);
            body.extend_from_slice(&if_ver_bytes);
            body.extend_from_slice(&NDR20_UUID_LE);
            body.extend_from_slice(&2u32.to_le_bytes()); // NDR 2.0 (major 2, minor 0)
            body.extend_from_slice(payload_bytes);
        }
        12 | 15 => {
            // Bind_ack (12) / Alter_context_resp (15)
            body.extend_from_slice(&5840u16.to_le_bytes()); // max_xmit_frag
            body.extend_from_slice(&5840u16.to_le_bytes()); // max_recv_frag
            body.extend_from_slice(&1u32.to_le_bytes()); // assoc_group_id
            body.extend_from_slice(&4u16.to_le_bytes()); // sec_addr length ("135\0")
            body.extend_from_slice(b"135\0");
            body.extend_from_slice(&[0x00, 0x00]); // 4-byte alignment padding before p_result_list_t
            body.push(1); // n_results
            body.push(0); // reserved
            body.extend_from_slice(&0u16.to_le_bytes()); // reserved2
            let result_code = spec.status.unwrap_or(0).min(u32::from(u16::MAX)) as u16;
            body.extend_from_slice(&result_code.to_le_bytes()); // result (0 = acceptance)
            body.extend_from_slice(&0u16.to_le_bytes()); // reason
            body.extend_from_slice(&NDR20_UUID_LE);
            body.extend_from_slice(&2u32.to_le_bytes());
            body.extend_from_slice(payload_bytes);
        }
        13 => {
            // Bind_nak (13)
            let reason = spec.status.unwrap_or(1).min(u32::from(u16::MAX)) as u16;
            body.extend_from_slice(&reason.to_le_bytes()); // provider_reject_reason
            body.push(1); // n_protocols
            body.push(5); // major version 5
            body.push(0); // minor version 0
            body.extend_from_slice(payload_bytes);
        }
        2 => {
            // Response (2)
            let alloc_hint = u32::try_from(payload_bytes.len()).unwrap_or(u32::MAX);
            body.extend_from_slice(&alloc_hint.to_le_bytes());
            body.extend_from_slice(&ctx_id.to_le_bytes());
            body.push(0); // cancel_count
            body.push(0); // reserved
            body.extend_from_slice(payload_bytes);
        }
        3 => {
            // Fault (3)
            let fault_status = spec.status.unwrap_or(0x1c01_0002); // nca_s_op_rng_error
            body.extend_from_slice(&0u32.to_le_bytes()); // alloc_hint
            body.extend_from_slice(&ctx_id.to_le_bytes());
            body.push(0); // cancel_count
            body.push(0); // reserved
            body.extend_from_slice(&fault_status.to_le_bytes());
            body.extend_from_slice(&0u32.to_le_bytes()); // reserved2
            body.extend_from_slice(payload_bytes);
        }
        _ => {
            // Request (0)
            let alloc_hint = u32::try_from(payload_bytes.len()).unwrap_or(u32::MAX);
            body.extend_from_slice(&alloc_hint.to_le_bytes());
            body.extend_from_slice(&ctx_id.to_le_bytes());
            body.extend_from_slice(&spec.opnum.unwrap_or(0).to_le_bytes());
            if (pfc_flags & 0x80) != 0 {
                body.extend_from_slice(&if_uuid);
            }
            body.extend_from_slice(payload_bytes);
        }
    }

    let max_body = usize::from(u16::MAX).saturating_sub(16);
    if body.len() > max_body {
        body.truncate(max_body);
    }
    let frag_len = (16 + body.len()) as u16;
    let mut pkt = Vec::with_capacity(usize::from(frag_len));
    pkt.push(5); // rpc_vers = 5
    pkt.push(0); // rpc_vers_minor = 0
    pkt.push(ptype);
    pkt.push(pfc_flags);
    pkt.extend_from_slice(&[0x10, 0x00, 0x00, 0x00]); // packed_drep (little-endian, ASCII, IEEE)
    pkt.extend_from_slice(&frag_len.to_le_bytes());
    pkt.extend_from_slice(&0u16.to_le_bytes()); // auth_length
    pkt.extend_from_slice(&call_id.to_le_bytes());
    pkt.extend_from_slice(&body);
    pkt
}
