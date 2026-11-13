//! Simple Network Management Protocol v3 (`snmp3`, RFC 3414 / RFC 3826 / RFC 7860) Layer 7 PCAP-to-`.frasm` decompiler.
//!
//! This module implements the fuzz-safe ASN.1 Basic Encoding Rules (BER) reverse dissector for
//! RFC 3414 User-based Security Model (USM) `snmp3` messages over UDP ports `161`, `162`, `10161`,
//! and `10162`. It decodes `USMSecurityParameters` (`user`, `engineid`, `engineboots`,
//! `enginetime`) and cleartext `ScopedPdu` bodies (`contextname`, `reqid`, `oid`, and SMIv2
//! `varbind` entries). Encrypted `ScopedPduData::EncryptedPdu` payloads (`priv` flag `0x02`)
//! return `None` so the decompiler never attempts to decrypt ciphertext without keys and instead
//! steps down cleanly to a lossless `udp` + `hexpayload` statement.

use alloc::format;
use alloc::string::String;

use crate::ast::Protocol;
use crate::reverse::{ProtocolDissection, bytes_to_hex_lower, push_if};

use super::snmp1::int_val;
use super::snmp2::{append_v2_pdu_body_tokens, v2_pdu_keyword};
use super::{ok_dissect, push_str_if};

/// Dissects an RFC 3414 `snmp3` (USM) ASN.1 BER payload.
///
/// When `msg.scoped_data` is `ScopedPduData::EncryptedPdu(_)` or the privacy bit (`0x02`) is set
/// in `msg.global_data.flags`, this function returns `None` so the decompiler steps down cleanly
/// to lossless `udp` + `hexpayload`. For `ScopedPduData::CleartextPdu`, `noAuthNoPriv` packets
/// (`flags & 0x01 == 0`) round-trip as `snmp3` statements, whereas `authNoPriv` packets
/// (`flags & 0x01 != 0`) carry an HMAC in `msgAuthenticationParameters` whose secret password is
/// not in the capture, causing the byte-for-byte compiler oracle to step down to `udp` +
/// `hexpayload`.
pub(crate) fn dissect_snmp3(payload: &[u8]) -> Option<ProtocolDissection> {
    use rasn_snmp::v3::{Message, ScopedPduData, USMSecurityParameters};

    let (msg, rem): (Message, &[u8]) = rasn::ber::decode_with_remainder(payload).ok()?;
    if int_val::<u32>(&msg.version) != Some(3) {
        return None;
    }

    let flags = msg.global_data.flags.as_ref().first().copied().unwrap_or(0);
    if (flags & 0x02) != 0 {
        return None;
    }

    let ScopedPduData::CleartextPdu(scoped) = &msg.scoped_data else {
        return None;
    };

    let usm: USMSecurityParameters = rasn::ber::decode(msg.security_parameters.as_ref()).ok()?;
    let user = core::str::from_utf8(usm.user_name.as_ref()).ok()?;
    let engine_id_hex = bytes_to_hex_lower(usm.authoritative_engine_id.as_ref());
    let boots = int_val::<u32>(&usm.authoritative_engine_boots).unwrap_or(0);
    let time = int_val::<u32>(&usm.authoritative_engine_time).unwrap_or(0);

    let tokens = format_scoped_pdu_tokens(scoped, user, &engine_id_hex, boots, time)?;
    ok_dissect(Protocol::Snmp3, tokens, rem.to_vec())
}

/// Formats an SNMPv3 `ScopedPdu` and USM header parameters into canonical `.frasm` tokens.
fn format_scoped_pdu_tokens(
    scoped_pdu: &rasn_snmp::v3::ScopedPdu,
    user: &str,
    engine_id_hex: &str,
    engine_boots: u32,
    engine_time: u32,
) -> Option<String> {
    let mut tokens = format!("snmp3 {}", v2_pdu_keyword(&scoped_pdu.data)?);
    append_usm_header_tokens(&mut tokens, user, engine_id_hex, engine_boots, engine_time);
    push_str_if(
        &mut tokens,
        "contextname",
        core::str::from_utf8(scoped_pdu.name.as_ref()).ok()?,
        "",
    );
    append_v2_pdu_body_tokens(&mut tokens, &scoped_pdu.data)?;
    Some(tokens)
}

/// Appends SNMPv3 USM header modifiers (`user`, `engineid`, `engineboots`, `enginetime`).
fn append_usm_header_tokens(
    tokens: &mut String,
    user: &str,
    engine_id_hex: &str,
    boots: u32,
    time: u32,
) {
    push_str_if(tokens, "user", user, "admin");
    if !engine_id_hex.is_empty() {
        push_str_if(tokens, "engineid", engine_id_hex, "8000000001");
    }
    push_if(tokens, "engineboots", boots, 0);
    push_if(tokens, "enginetime", time, 0);
}
