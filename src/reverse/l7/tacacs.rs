//! Terminal Access Controller Access-Control System Plus (`tacacs`, RFC 8907) Layer 7 PCAP-to-`.frasm` decompiler.
//!
//! This module implements the fuzz-safe reverse dissector for RFC 8907 `tacacs` (`TACACS+`) AAA
//! packets carried over TCP port `49`. It validates the 12-byte TACACS+ common header (`0xC0`
//! major version nibble) and decodes authentication (`authen`), authorization (`author`), and
//! accounting (`acct`) bodies along with `seq`, `flags`, `sessionid`, `user`, and `data`
//! modifiers.

use alloc::format;
use core::fmt::Write as _;

use crate::ast::Protocol;
use crate::reverse::{ProtocolDissection, be_u32, push_if};

use super::{is_printable_ascii_str, ok_dissect, push_str_if};

/// Dissects an RFC 8907 `tacacs` packet over TCP port `49`.
pub(crate) fn dissect_tacacs(payload: &[u8]) -> Option<ProtocolDissection> {
    if payload.len() < 12 || (payload[0] & 0xF0) != 0xC0 {
        return None;
    }
    let type_code = payload[1];
    let type_kw = match type_code {
        1 => "authen",
        2 => "author",
        3 => "acct",
        _ => return None,
    };
    let (seq, flags, session_id, body) =
        (payload[2], payload[3], be_u32(payload, 4), &payload[12..]);

    let hdr_off = usize::from(type_code == 3);
    if body.len() < hdr_off + 8 {
        return None;
    }
    let (u_len, p_len, r_len, cnt_or_dlen) = (
        body[hdr_off + 4] as usize,
        body[hdr_off + 5] as usize,
        body[hdr_off + 6] as usize,
        body[hdr_off + 7] as usize,
    );
    let (args_hdr_end, data_len) = if type_code == 1 {
        (8usize, cnt_or_dlen)
    } else {
        let end = hdr_off + 8 + cnt_or_dlen;
        let d_len: usize = body
            .get(hdr_off + 8..end)?
            .iter()
            .map(|&b| b as usize)
            .sum();
        (end, d_len)
    };
    let d_start = args_hdr_end + u_len + p_len + r_len;
    let total_fixed = d_start + data_len;
    let user_str = is_printable_ascii_str(body.get(args_hdr_end..args_hdr_end + u_len)?)?;
    let data_str = is_printable_ascii_str(body.get(d_start..total_fixed)?)?;

    let mut tokens = format!("tacacs {type_kw}");
    push_if(&mut tokens, "seq", seq, 1);
    if flags != 0x01 {
        let _ = write!(tokens, " flags 0x{flags:02x}");
    }
    if session_id != 0x1234_5678 {
        let _ = write!(tokens, " sessionid 0x{session_id:08x}");
    }
    push_str_if(&mut tokens, "user", user_str, "admin");
    push_str_if(&mut tokens, "data", data_str, "");

    ok_dissect(Protocol::Tacacs, tokens, body[total_fixed..].to_vec())
}
