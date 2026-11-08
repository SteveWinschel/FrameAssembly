//! Transport Layer Security (`TLS`, RFC 8446 / RFC 5246) Layer 7 PCAP-to-`.fasm` decompiler.
//!
//! This module implements the fuzz-safe reverse dissector for unencrypted outer RFC 8446 (TLS 1.3)
//! and RFC 5246 (TLS 1.2) record and handshake messages (`client_hello`, `server_hello`,
//! `certificate`, `finished`, `alert`, `app_data`). It decodes `record_version`,
//! `handshake_version`, cipher suites (`ciphersuite`), Server Name Indication (`sni` extension
//! `0x0000`), and Application-Layer Protocol Negotiation (`alpn` extension `0x0010`). It never
//! attempts cryptographic decryption: opaque `app_data` or `alert` bodies are preserved via
//! residual payload, and unsupported or encrypted multi-record segments return `None` to step down
//! cleanly to `tcp` with `payload` or `hexpayload`.

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
            "tls app_data"
        });
        if rec_version != 0x0303 {
            let _ = write!(tokens, " record_version 0x{rec_version:04x}");
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
                let _ = write!(tokens, " record_version 0x{rec_version:04x}");
            }
            let is_default = (hs_type == 11 && hs_body == [0x00, 0x00, 0x00])
                || (hs_type == 20 && hs_body == [0xdd; 32]);
            if !is_default {
                residual_payload = hs_body.to_vec();
            }
        }
        1 | 2 => {
            tokens.push_str(if hs_type == 1 {
                " client_hello"
            } else {
                " server_hello"
            });
            if rec_version != 0x0303 {
                let _ = write!(tokens, " record_version 0x{rec_version:04x}");
            }
            if hs_body.len() < 35 {
                return None;
            }
            let hs_version = checked_be_u16(hs_body, 0)?;
            if hs_version != rec_version {
                let _ = write!(tokens, " handshake_version 0x{hs_version:04x}");
            }

            let mut pos = 35usize.checked_add(hs_body[34] as usize)?;
            let cs = if hs_type == 1 {
                let cs_len = checked_be_u16(hs_body, pos)? as usize;
                if cs_len < 2 {
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

            let mut sni_opt: Option<&str> = None;
            let mut alpn_opt: Option<&str> = None;
            if let Some(exts_len) = checked_be_u16(hs_body, pos) {
                pos += 2;
                let exts_end = pos.checked_add(exts_len as usize)?.min(hs_body.len());
                while pos + 4 <= exts_end {
                    let ext_type = checked_be_u16(hs_body, pos)?;
                    let ext_len = checked_be_u16(hs_body, pos + 2)? as usize;
                    pos += 4;
                    let Some(ext_data) = hs_body.get(pos..pos.checked_add(ext_len)?) else {
                        break;
                    };
                    if ext_type == 0x0000
                        && let Some(nlen) = checked_be_u16(ext_data, 3)
                        && let Some(nb) = ext_data.get(5..5usize.checked_add(nlen as usize)?)
                        && let Ok(s) = core::str::from_utf8(nb)
                    {
                        sni_opt = Some(s);
                    } else if ext_type == 0x0010
                        && let Some(&plen) = ext_data.get(2)
                        && let Some(pb) = ext_data.get(3..3usize.checked_add(plen as usize)?)
                        && let Ok(s) = core::str::from_utf8(pb)
                    {
                        alpn_opt = Some(s);
                    }
                    pos += ext_len;
                }
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
            residual_payload = trailing.to_vec();
        }
        _ => return None,
    }

    Some(sd(Protocol::Tls, tokens, residual_payload))
}
