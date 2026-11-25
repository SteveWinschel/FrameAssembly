//! Terminal Access Controller Access-Control System Plus (TACACS+) (RFC 8907) Layer 7 wire packet builder.
//!
//! This module synthesizes deterministic on-the-wire Terminal Access Controller Access-Control System Plus (TACACS+) frames over TCP port 49.
//! The wire encoder constructs a 12-byte fixed TACACS+ header (8-bit Version byte: `0xC1` minor version 1 for Authentication or `0xC0` for Authorization/Accounting; 8-bit Type: 1 AUTHEN, 2 AUTHOR, 3 ACCT; 8-bit seq_no; 8-bit flags bitmask e.g. `0x01` `TAC_PLUS_UNENCRYPTED_FLAG`; 32-bit big-endian session_id; 32-bit big-endian body length) followed by Authentication START, Authorization REQUEST, or Accounting START body with optional RFC 8907 §4.5 MD5 body obfuscation when `TAC_PLUS_UNENCRYPTED_FLAG` is cleared.
//!
//! Canonical `.frasm` syntax:
//! `a -> b tacacs [type authen | type author | type acct | authen | author | acct] [seq <u8>] [flags <u8>] [sessionid <u32>] [user <str>] [data <str>] [payload <str>]`

use crate::ast::*;
use crate::builders::WireContext;
use alloc::vec::Vec;
use md5::Md5;
use sha2::Digest;

/// Deterministic fallback shared secret used for RFC 8907 §4.5 MD5 body obfuscation.
pub(crate) const DEFAULT_TACACS_KEY: &[u8] = b"tacacs";

/// Applies symmetric RFC 8907 §4.5 MD5 pseudo-random pad XOR obfuscation to a TACACS+ body.
pub(crate) fn obfuscate_tacacs_body(
    body: &mut [u8],
    session_id: u32,
    key: &[u8],
    version: u8,
    seq_no: u8,
) {
    let mut prev_hash = [0u8; 16];
    let mut offset = 0usize;
    while offset < body.len() {
        let mut hasher = Md5::default();
        hasher.update(session_id.to_be_bytes());
        hasher.update(key);
        hasher.update([version, seq_no]);
        if offset > 0 {
            hasher.update(prev_hash);
        }
        let digest = hasher.finalize();
        prev_hash.copy_from_slice(&digest);
        let chunk_len = (body.len() - offset).min(16);
        for (byte, pad) in body[offset..offset + chunk_len]
            .iter_mut()
            .zip(&digest[..chunk_len])
        {
            *byte ^= *pad;
        }
        offset += chunk_len;
    }
}

/// Builds an RFC 8907 TACACS+ packet payload.
/// Syntax mapping: `tacacs [type authen | type author | type acct | authen | author | acct] [seq <u8>] [flags <u8>] [sessionid <u32>] [user <str>] [payload <str>]`
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
    let type_norm = spec
        .tacacs_type
        .unwrap_or("authen")
        .to_ascii_uppercase()
        .replace(['_', '-'], "");
    let type_code = match type_norm.as_str() {
        "AUTHEN" => 1u8,
        "AUTHOR" => 2u8,
        "ACCT" => 3u8,
        _ => 1u8,
    };
    let seq_no = spec.seq.unwrap_or(1);
    let flags = spec.flags.unwrap_or(0x01); // TAC_PLUS_UNENCRYPTED_FLAG
    let session_id = spec.session_id.unwrap_or(0x12345678);

    let user = spec.user.unwrap_or("admin");
    let raw_user = user.as_bytes();
    let user_bytes = &raw_user[..raw_user.len().min(255)];
    let data = spec.data.unwrap_or("");
    let raw_data = data.as_bytes();
    let data_bytes = &raw_data[..raw_data.len().min(255)];

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

    let version = if type_code == 1 { 0xC1u8 } else { 0xC0u8 };
    if (flags & 0x01) == 0 {
        obfuscate_tacacs_body(&mut body, session_id, DEFAULT_TACACS_KEY, version, seq_no);
    }

    let length = body.len() as u32;
    let mut pkt = Vec::with_capacity(12 + body.len());
    pkt.push(version); // major_version = 12, minor_version = 1 (AUTHEN) / 0 (AUTHOR, ACCT)
    pkt.push(type_code);
    pkt.push(seq_no);
    pkt.push(flags);
    pkt.extend_from_slice(&session_id.to_be_bytes());
    pkt.extend_from_slice(&length.to_be_bytes());
    pkt.extend_from_slice(&body);
    pkt
}
