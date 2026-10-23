//! TACACS protocol wire builder.

use crate::ast::*;
use crate::builders::WireContext;
use alloc::vec::Vec;

/// Builds an RFC 8907 TACACS+ packet payload.
pub fn build_tacacs_payload(
    _ctx: &WireContext,
    spec: &TacacsSpec,
    payload_bytes: &[u8],
) -> Vec<u8> {
    let type_code = match spec.tacacs_type.unwrap_or("AUTHEN").to_ascii_uppercase().as_str() {
        "AUTHEN" => 1u8,
        "AUTHOR" => 2u8,
        "ACCT" => 3u8,
        _ => 1u8,
    };
    let seq_no = spec.seq.unwrap_or(1);
    let flags = spec.flags.unwrap_or(0x01); // TAC_PLUS_UNENCRYPTED_FLAG
    let session_id = spec.session_id.unwrap_or(0x12345678);

    let user = spec.user.unwrap_or("admin");
    let user_bytes = user.as_bytes();
    let data = spec.data.unwrap_or("");
    let data_bytes = data.as_bytes();

    let mut body = Vec::new();
    if type_code == 1 {
        // TACACS+ Authentication START packet body
        body.push(1); // action: TAC_PLUS_AUTHEN_LOGIN
        body.push(1); // priv_lvl
        body.push(1); // authen_type: TAC_PLUS_AUTHEN_TYPE_ASCII
        body.push(1); // service: TAC_PLUS_AUTHEN_SVC_LOGIN
        body.push(user_bytes.len() as u8); // user_len
        body.push(0); // port_len
        body.push(0); // rem_addr_len
        body.push(data_bytes.len() as u8); // data_len
        body.extend_from_slice(user_bytes);
        body.extend_from_slice(data_bytes);
    }
    if !payload_bytes.is_empty() {
        body.extend_from_slice(payload_bytes);
    }

    let length = body.len() as u32;
    let mut pkt = Vec::with_capacity(12 + body.len());
    pkt.push(0xC0); // major_version = 12, minor_version = 0
    pkt.push(type_code);
    pkt.push(seq_no);
    pkt.push(flags);
    pkt.extend_from_slice(&session_id.to_be_bytes());
    pkt.extend_from_slice(&length.to_be_bytes());
    pkt.extend_from_slice(&body);
    pkt
}
