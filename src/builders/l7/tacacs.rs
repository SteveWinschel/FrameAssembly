//! Terminal Access Controller Access-Control System Plus (TACACS+) (RFC 8907) Layer 7 wire packet builder.
//!
//! This module synthesizes deterministic on-the-wire Terminal Access Controller Access-Control System Plus (TACACS+) frames over TCP port 49.
//! The wire encoder constructs a 12-byte fixed TACACS+ header (8-bit Version byte: 4-bit major 0xC + 4-bit minor 0x0/0x1; 8-bit Type: 1 AUTHEN, 2 AUTHOR, 3 ACCT; 8-bit seq_no; 8-bit flags bitmask e.g. 0x01 TAC_PLUS_UNENCRYPTED_FLAG; 32-bit big-endian session_id; 32-bit big-endian body length) followed by Authentication START/REPLY/CONTINUE, Authorization REQUEST/RESPONSE, or Accounting START/STOP/WATCHDOG body. When optional fields in [`TacacsSpec`]
//! are omitted in the `.fasm` source, RFC-compliant default values are automatically populated.
//!
//! Canonical `.fasm` syntax:
//! `a -> b TACACS [TYPE AUTHEN | TYPE AUTHOR | TYPE ACCT | AUTHEN | AUTHOR | ACCT] [SEQ <u8>] [FLAGS <u8>] [SESSION_ID <u32>] [USER <str>] [PAYLOAD <str>]`

use crate::ast::*;
use crate::builders::WireContext;
use alloc::vec::Vec;

/// Builds an RFC 8907 TACACS+ packet payload.
/// Syntax mapping: `TACACS [TYPE AUTHEN | TYPE AUTHOR | TYPE ACCT | AUTHEN | AUTHOR | ACCT] [SEQ <u8>] [FLAGS <u8>] [SESSION_ID <u32>] [USER <str>] [PAYLOAD <str>]`
#[doc(alias = "TACACS")]
#[doc(alias = "TACACS_PLUS")]
#[doc(alias = "RFC8907")]
#[doc(alias = "AUTHEN")]
#[doc(alias = "AUTHOR")]
#[doc(alias = "ACCT")]
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
    match type_code {
        2 => {
            // TACACS+ Authorization REQUEST packet body (RFC 8907 §6.1)
            body.push(1); // authen_method: TAC_PLUS_AUTHEN_METH_NOT_SET
            body.push(1); // priv_lvl
            body.push(1); // authen_type: TAC_PLUS_AUTHEN_TYPE_ASCII
            body.push(1); // authen_service: TAC_PLUS_AUTHEN_SVC_LOGIN
            body.push(user_bytes.len() as u8); // user_len
            body.push(0); // port_len
            body.push(0); // rem_addr_len
            if data_bytes.is_empty() {
                body.push(0); // arg_cnt = 0
            } else {
                body.push(1); // arg_cnt = 1
                body.push(data_bytes.len() as u8); // arg_1_len
            }
            body.extend_from_slice(user_bytes);
            body.extend_from_slice(data_bytes);
        }
        3 => {
            // TACACS+ Accounting REQUEST packet body (RFC 8907 §7.1)
            body.push(0x02); // flags: TAC_PLUS_ACCT_FLAG_START
            body.push(1); // authen_method
            body.push(1); // priv_lvl
            body.push(1); // authen_type: TAC_PLUS_AUTHEN_TYPE_ASCII
            body.push(1); // authen_service: TAC_PLUS_AUTHEN_SVC_LOGIN
            body.push(user_bytes.len() as u8); // user_len
            body.push(0); // port_len
            body.push(0); // rem_addr_len
            if data_bytes.is_empty() {
                body.push(0); // arg_cnt = 0
            } else {
                body.push(1); // arg_cnt = 1
                body.push(data_bytes.len() as u8); // arg_1_len
            }
            body.extend_from_slice(user_bytes);
            body.extend_from_slice(data_bytes);
        }
        _ => {
            // TACACS+ Authentication START packet body (RFC 8907 §5.1)
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
