//! Transport Layer Security (`tls`, RFC 8446 / RFC 5246) Layer 7 PCAP-to-`.frasm` decompiler.
//!
//! This module implements the fuzz-safe reverse dissector for unencrypted outer RFC 8446 (TLS 1.3)
//! and RFC 5246 (TLS 1.2) record and handshake messages (`clienthello`, `serverhello`,
//! `certificate`, `finished`, `alert`, `appdata`). It decodes `recordversion`,
//! `handshakeversion`, cipher suites (`ciphersuite`), Server Name Indication (`sni` extension
//! `0x0000`), Application-Layer Protocol Negotiation (`alpn` extension `0x0010`), and TLS 1.3
//! extensions (`0x002b` `supported_versions`, `0x000a` `supported_groups`, `0x000d`
//! `signature_algorithms`, `0x0033` `key_share`). Unsupported or multi-record segments return
//! `None` to step down cleanly to `tcp` + `hexpayload`.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write as _;

use crate::ast::Protocol;
use crate::reverse::{ProtocolDissection, sd};

use super::{checked_be_u16, push_str_mod};

/// Checks whether `payload` begins with a valid TLS record header (`content_type` 21..=23, version `0x0300..=0x0304`).
pub(crate) fn is_tls_signature(payload: &[u8]) -> bool {
    matches!(payload.first(), Some(21..=23))
        && matches!(checked_be_u16(payload, 1), Some(0x0300..=0x0304))
}

/// Validates wire lengths of an RFC 8446 TLS 1.3 handshake extension (`0x002b`, `0x000a`, `0x000d`, `0x0033`).
fn is_valid_tls13_extension(hs_type: u8, ext_type: u16, ext_data: &[u8]) -> bool {
    match ext_type {
        0x002b => {
            if hs_type == 1 {
                ext_data.len() >= 3
                    && usize::from(ext_data[0]) + 1 == ext_data.len()
                    && ext_data[0].is_multiple_of(2)
            } else {
                ext_data.len() == 2
            }
        }
        0x000a | 0x000d => {
            let Some(list_len) = checked_be_u16(ext_data, 0) else {
                return false;
            };
            list_len >= 2
                && list_len.is_multiple_of(2)
                && usize::from(list_len) + 2 == ext_data.len()
        }
        0x0033 => {
            if hs_type == 1 {
                let Some(shares_len) = checked_be_u16(ext_data, 0) else {
                    return false;
                };
                if usize::from(shares_len) + 2 != ext_data.len() {
                    return false;
                }
                let mut p = 2usize;
                while p < ext_data.len() {
                    let Some(klen) = checked_be_u16(ext_data, p + 2) else {
                        return false;
                    };
                    let Some(next) = p.checked_add(4).and_then(|x| x.checked_add(usize::from(klen)))
                    else {
                        return false;
                    };
                    if next > ext_data.len() {
                        return false;
                    }
                    p = next;
                }
                p == ext_data.len()
            } else {
                let Some(klen) = checked_be_u16(ext_data, 2) else {
                    return false;
                };
                4usize.checked_add(usize::from(klen)) == Some(ext_data.len())
            }
        }
        _ => false,
    }
}

/// Dissects an RFC 8446 / RFC 5246 TLS record and handshake payload.
pub(crate) fn dissect_tls(payload: &[u8]) -> Option<ProtocolDissection> {
    let content_type = *payload.first()?;
    if !matches!(content_type, 21..=23) {
        return None;
    }
    let rec_version = checked_be_u16(payload, 1)?;
    let rec_len = checked_be_u16(payload, 3)? as usize;
    if 5usize.checked_add(rec_len)? != payload.len() {
        return None;
    }
    let body = payload.get(5..5 + rec_len)?;

    if content_type != 22 {
        let mut tokens = String::from(if content_type == 21 {
            "tls alert"
        } else {
            "tls appdata"
        });
        if rec_version != 0x0303 {
            let _ = write!(tokens, " recordversion 0x{rec_version:04x}");
        }
        let is_default_body = (content_type == 21 && body == [2, 40])
            || (content_type == 23 && body == b"\x00\x01\x02\x03\x04\x05\x06\x07");
        let residual = if is_default_body {
            Vec::new()
        } else {
            body.to_vec()
        };
        return Some(sd(Protocol::Tls, tokens, residual));
    }

    if body.len() < 4 {
        return None;
    }
    let hs_type = body[0];
    let hs_len = ((body[1] as usize) << 16) | ((body[2] as usize) << 8) | (body[3] as usize);
    if 4usize.checked_add(hs_len)? > body.len() {
        return None;
    }
    let hs_body = body.get(4..4 + hs_len)?;
    let trailing = body.get(4 + hs_len..)?;

    let mut tokens = String::from("tls");
    let mut residual_payload = Vec::new();

    match hs_type {
        11 | 20 => {
            if !trailing.is_empty() {
                return None;
            }
            tokens.push_str(if hs_type == 11 {
                " certificate"
            } else {
                " finished"
            });
            if rec_version != 0x0303 {
                let _ = write!(tokens, " recordversion 0x{rec_version:04x}");
            }
            let is_default = (hs_type == 11 && hs_body == [0x00, 0x00, 0x00])
                || (hs_type == 20 && hs_body == [0xdd; 32]);
            if !is_default {
                residual_payload = hs_body.to_vec();
            }
        }
        1 | 2 => {
            if !trailing.is_empty() {
                return None;
            }
            tokens.push_str(if hs_type == 1 {
                " clienthello"
            } else {
                " serverhello"
            });
            if rec_version != 0x0303 {
                let _ = write!(tokens, " recordversion 0x{rec_version:04x}");
            }
            if hs_body.len() < 35 {
                return None;
            }
            let hs_version = checked_be_u16(hs_body, 0)?;

            let mut pos = 35usize.checked_add(hs_body[34] as usize)?;
            let cs = if hs_type == 1 {
                let cs_len = checked_be_u16(hs_body, pos)? as usize;
                if cs_len < 2 || !cs_len.is_multiple_of(2) {
                    return None;
                }
                let val = checked_be_u16(hs_body, pos + 2)?;
                pos = pos.checked_add(2)?.checked_add(cs_len)?;
                let comp_len = *hs_body.get(pos)? as usize;
                pos = pos.checked_add(1)?.checked_add(comp_len)?;
                val
            } else {
                let val = checked_be_u16(hs_body, pos)?;
                pos = pos.checked_add(3)?;
                val
            };

            let is_tls13 = (0x1301..=0x1305).contains(&cs)
                || rec_version == 0x0304
                || hs_version == 0x0304;
            let expected_hs_ver = if is_tls13 { 0x0303 } else { rec_version };
            if hs_version != expected_hs_ver {
                let _ = write!(tokens, " handshakeversion 0x{hs_version:04x}");
            }

            let mut sni_opt: Option<&str> = None;
            let mut alpn_opt: Option<&str> = None;
            let mut ext_payload = Vec::new();
            if let Some(exts_len) = checked_be_u16(hs_body, pos) {
                pos += 2;
                let exts_end = pos.checked_add(exts_len as usize)?;
                if exts_end != hs_body.len() {
                    return None;
                }
                while pos < exts_end {
                    let ext_type = checked_be_u16(hs_body, pos)?;
                    let ext_len = checked_be_u16(hs_body, pos + 2)? as usize;
                    pos += 4;
                    let ext_end = pos.checked_add(ext_len)?;
                    if ext_end > exts_end {
                        return None;
                    }
                    let ext_data = hs_body.get(pos..ext_end)?;
                    if ext_type == 0x0000
                        && sni_opt.is_none()
                        && let Some(nlen) = checked_be_u16(ext_data, 3)
                        && 5usize.checked_add(nlen as usize) == Some(ext_data.len())
                        && let Ok(s) = core::str::from_utf8(&ext_data[5..])
                    {
                        sni_opt = Some(s);
                    } else if ext_type == 0x0010
                        && alpn_opt.is_none()
                        && let Some(&plen) = ext_data.get(2)
                        && 3usize.checked_add(plen as usize) == Some(ext_data.len())
                        && let Ok(s) = core::str::from_utf8(&ext_data[3..])
                    {
                        alpn_opt = Some(s);
                    } else if is_valid_tls13_extension(hs_type, ext_type, ext_data) {
                        // RFC 8446 mandatory TLS 1.3 handshake extensions
                    } else if ext_type == 0xFFFF && ext_end == exts_end && !ext_data.is_empty() {
                        ext_payload = ext_data.to_vec();
                    } else {
                        return None;
                    }
                    pos = ext_end;
                }
            } else if pos != hs_body.len() {
                return None;
            }

            if let Some(sni) = sni_opt {
                push_str_mod(&mut tokens, "sni", sni);
            }
            if cs != 0x1301 {
                let _ = write!(tokens, " ciphersuite 0x{cs:04x}");
            }
            if let Some(alpn) = alpn_opt {
                push_str_mod(&mut tokens, "alpn", alpn);
            }
            residual_payload = ext_payload;
        }
        _ => return None,
    }

    Some(sd(Protocol::Tls, tokens, residual_payload))
}
