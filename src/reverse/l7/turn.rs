//! Traversal Using Relays around NAT (`turn`, RFC 8656 / RFC 5766) Layer 7 PCAP-to-`.frasm` decompiler.
//!
//! This module implements the fuzz-safe reverse dissector for RFC 8656 / RFC 5766 `turn` relay
//! frames carried over UDP, TCP, or SCTP port `3478`. It decodes both 4-byte `ChannelData`
//! headers (`0x4000..=0x7FFF` with optional TCP 4-byte padding) and STUN-formatted TURN control
//! messages (`Allocate`, `Refresh`, `CreatePermission`, `ChannelBind`, `Send`, `Data`), elides
//! protocol defaults (`17` UDP transport, `600`s lifetime, `0x4000` channel, `401` error), and
//! preserves non-UDP transport overrides.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write as _;
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::ast::{Protocol, TransportProto};
use crate::reverse::{ProtocolDissection, sd_tp};

use super::{checked_be_u16, checked_be_u32, is_valid_raw_string_body, quote_raw_str};

/// Decodes a STUN/TURN XOR-encoded IPv4 or IPv6 address TLV value into `(IpAddr, port)`.
fn decode_xor_addr(aval: &[u8], payload: &[u8]) -> Option<(IpAddr, u16)> {
    if aval.len() < 4 {
        return None;
    }
    let xport = checked_be_u16(aval, 2)? ^ 0x2112;
    let family = aval.get(1).copied()?;
    let ip = if family == 1 && aval.len() == 8 {
        IpAddr::V4(Ipv4Addr::from(
            (checked_be_u32(aval, 4)? ^ 0x2112_A442).to_be_bytes(),
        ))
    } else if family == 2 && aval.len() == 20 {
        let mask = payload.get(4..20)?;
        IpAddr::V6(Ipv6Addr::from(core::array::from_fn(|i| {
            aval[4 + i] ^ mask[i]
        })))
    } else {
        return None;
    };
    Some((ip, xport))
}

/// Checks whether `buf` parses as a sequence of raw STUN/TURN TLV attributes.
fn looks_like_turn_attrs(buf: &[u8]) -> bool {
    if buf.is_empty() || !buf.len().is_multiple_of(4) {
        return false;
    }
    let mut pos = 0usize;
    while pos < buf.len() {
        let Some(hdr) = buf.get(pos..pos + 4) else {
            return false;
        };
        let atype = u16::from_be_bytes([hdr[0], hdr[1]]);
        let alen = usize::from(u16::from_be_bytes([hdr[2], hdr[3]]));
        if matches!(
            atype,
            0x0000 | 0x0009 | 0x000C | 0x000D | 0x0012 | 0x0013 | 0x0016 | 0x0019 | 0x0020 | 0x8022
        ) {
            return false;
        }
        let padded = (alen + 3) & !3;
        let Some(next) = pos.checked_add(4).and_then(|p| p.checked_add(padded)) else {
            return false;
        };
        if next > buf.len() || !buf[pos + 4 + alen..next].iter().all(|&b| b == 0) {
            return false;
        }
        pos = next;
    }
    pos == buf.len()
}

/// Returns the default reason phrase synthesized for a TURN error status code.
fn expected_turn_reason(code: u16) -> &'static str {
    match code {
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        420 => "Unknown Attribute",
        437 => "Allocation Mismatch",
        438 => "Stale Nonce",
        440 => "Address Family Not Supported",
        441 => "Wrong Credentials",
        442 => "Unsupported Transport Protocol",
        443 => "Peer Address Family Mismatch",
        486 => "Allocation Quota Reached",
        500 => "Server Error",
        508 => "Insufficient Capacity",
        _ => "Error",
    }
}

/// Dissects a TURN control or `ChannelData` message over UDP, TCP, or SCTP port `3478`.
pub(crate) fn dissect_turn(
    transport: TransportProto,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Option<ProtocolDissection> {
    let explicit_transport = match transport {
        TransportProto::Udp => None,
        tp => Some(tp),
    };

    if (src_port == 3478 || dst_port == 3478) && payload.len() >= 4 {
        let ch = checked_be_u16(payload, 0)?;
        if (0x4000..=0x7FFF).contains(&ch) {
            let dlen = usize::from(checked_be_u16(payload, 2)?);
            let padded = (dlen + 3) & !3;
            let valid_len = if transport == TransportProto::Tcp {
                4usize.checked_add(padded) == Some(payload.len())
                    && payload
                        .get(4 + dlen..)
                        .is_some_and(|p| p.iter().all(|&b| b == 0))
            } else {
                4usize.checked_add(dlen) == Some(payload.len())
                    || (4usize.checked_add(padded) == Some(payload.len())
                        && payload
                            .get(4 + dlen..)
                            .is_some_and(|p| p.iter().all(|&b| b == 0)))
            };
            if valid_len {
                let mut tokens = String::from("turn channeldata");
                if ch != 0x4000 {
                    let _ = write!(tokens, " channel 0x{ch:04x}");
                }
                let residual = payload.get(4..4 + dlen)?.to_vec();
                return Some(sd_tp(Protocol::Turn, tokens, residual, explicit_transport));
            }
        }
    }

    if payload.len() < 20 || payload.get(4..8)? != [0x21, 0x12, 0xA4, 0x42] {
        return None;
    }
    let msg_type = checked_be_u16(payload, 0)?;
    let attr_len = usize::from(checked_be_u16(payload, 2)?);
    if 20usize.checked_add(attr_len)? != payload.len() {
        return None;
    }

    let mut tokens = match msg_type {
        0x0003 => String::from("turn"),
        0x0103 => String::from("turn allocate response"),
        0x0113 => String::from("turn allocate error"),
        0x0004 => String::from("turn refresh"),
        0x0104 => String::from("turn refresh response"),
        0x0114 => String::from("turn refresh error"),
        0x0016 => String::from("turn sendindication"),
        0x0017 => String::from("turn dataindication"),
        0x0008 => String::from("turn createpermission"),
        0x0108 => String::from("turn createpermission response"),
        0x0118 => String::from("turn createpermission error"),
        0x0009 => String::from("turn channelbind"),
        0x0109 => String::from("turn channelbind response"),
        0x0119 => String::from("turn channelbind error"),
        _ => return None,
    };

    let txid = checked_be_u32(payload, 8)?;
    if txid != 0x1122_3344 {
        let _ = write!(tokens, " txid 0x{txid:08x}");
    }

    let attrs = payload.get(20..20 + attr_len)?;
    let mut pos = 0usize;
    let mut residual = Vec::new();
    let (mut seen_rt, mut seen_lt, mut seen_ch, mut seen_rel, mut seen_peer, mut seen_xma, mut seen_err, mut seen_sw) =
        (false, false, false, false, false, false, false, false);

    while pos + 4 <= attrs.len() {
        let atype = checked_be_u16(attrs, pos)?;
        let alen = usize::from(checked_be_u16(attrs, pos + 2)?);
        let padded_len = (alen + 3) & !3;
        let Some(aval) = attrs.get(pos + 4..pos.checked_add(4)?.checked_add(alen)?) else {
            residual = attrs.get(pos..)?.to_vec();
            break;
        };

        if atype == 0x0019 && !seen_rt && alen == 4 && aval.get(1..4) == Some(&[0, 0, 0]) {
            let proto = aval[0];
            if !(msg_type == 0x0003 && proto == 17) {
                let _ = write!(tokens, " requestedtransport {proto}");
            }
            seen_rt = true;
        } else if atype == 0x000D && !seen_lt && alen == 4 {
            let lt = checked_be_u32(aval, 0)?;
            if !(matches!(msg_type, 0x0103 | 0x0004 | 0x0104) && lt == 600) {
                let _ = write!(tokens, " lifetime {lt}");
            }
            seen_lt = true;
        } else if atype == 0x000C && !seen_ch && alen == 4 && aval.get(2..4) == Some(&[0, 0]) {
            let ch = checked_be_u16(aval, 0)?;
            if (0x4000..=0x7FFF).contains(&ch) {
                if !(msg_type == 0x0009 && ch == 0x4000) {
                    let _ = write!(tokens, " channel 0x{ch:04x}");
                }
                seen_ch = true;
            } else {
                residual = attrs.get(pos..)?.to_vec();
                break;
            }
        } else if atype == 0x0016 && !seen_rel {
            let Some((ip, port)) = decode_xor_addr(aval, payload) else {
                residual = attrs.get(pos..)?.to_vec();
                break;
            };
            let is_def = msg_type == 0x0103
                && ip == IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10))
                && port == 49152;
            if !is_def {
                if port == 49152 {
                    let _ = write!(tokens, " xorrelayedaddr {ip}");
                } else {
                    let _ = write!(tokens, " xorrelayedaddr {ip} {port}");
                }
            }
            seen_rel = true;
        } else if atype == 0x0012 && !seen_peer {
            let Some((ip, port)) = decode_xor_addr(aval, payload) else {
                residual = attrs.get(pos..)?.to_vec();
                break;
            };
            let is_def = matches!(msg_type, 0x0008 | 0x0009 | 0x0016 | 0x0017)
                && ip == IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))
                && port == 5004;
            if !is_def {
                if port == 5004 {
                    let _ = write!(tokens, " xorpeeraddr {ip}");
                } else {
                    let _ = write!(tokens, " xorpeeraddr {ip} {port}");
                }
            }
            seen_peer = true;
        } else if atype == 0x0020 && !seen_xma {
            let Some((ip, port)) = decode_xor_addr(aval, payload) else {
                residual = attrs.get(pos..)?.to_vec();
                break;
            };
            if port == 12345 {
                let _ = write!(tokens, " xormappedaddr {ip}");
            } else {
                let _ = write!(tokens, " xormappedaddr {ip} {port}");
            }
            seen_xma = true;
        } else if atype == 0x0009 && !seen_err && alen >= 4 {
            let code = u16::from(aval[2]) * 100 + u16::from(aval[3]);
            let reason_ok = core::str::from_utf8(aval.get(4..)?)
                .is_ok_and(|r| r == expected_turn_reason(code));
            if reason_ok {
                let is_def_err =
                    matches!(msg_type, 0x0113 | 0x0114 | 0x0118 | 0x0119) && code == 401;
                if !is_def_err {
                    let _ = write!(tokens, " errcode {code}");
                }
                seen_err = true;
            } else {
                residual = attrs.get(pos..)?.to_vec();
                break;
            }
        } else if atype == 0x8022
            && !seen_sw
            && let Ok(sw_str) = core::str::from_utf8(aval)
            && is_valid_raw_string_body(sw_str)
        {
            let _ = write!(tokens, " software \"{}\"", quote_raw_str(sw_str));
            seen_sw = true;
        } else if (atype == 0xFFFF || (atype == 0x0013 && matches!(msg_type, 0x0016 | 0x0017)))
            && pos.checked_add(4)?.checked_add(padded_len)? == attrs.len()
            && attrs
                .get(pos + 4 + alen..pos + 4 + padded_len)
                .is_some_and(|p| p.iter().all(|&b| b == 0))
            && !aval.is_empty()
            && !looks_like_turn_attrs(aval)
        {
            residual = aval.to_vec();
            break;
        } else {
            residual = attrs.get(pos..)?.to_vec();
            break;
        }
        pos = pos.checked_add(4)?.checked_add(padded_len)?;
    }

    Some(sd_tp(Protocol::Turn, tokens, residual, explicit_transport))
}
