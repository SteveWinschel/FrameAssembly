//! Secure Shell Transport Layer Protocol (SSH-2) (RFC 4253 (Transport) / RFC 4252 (UserAuth) / RFC 4254 (Connection)) Layer 7 wire packet builder.
//!
//! This module synthesizes deterministic on-the-wire Secure Shell Transport Layer Protocol (SSH-2) frames over TCP port 22.
//! The wire encoder constructs a CRLF-terminated protocol version identification string (`SSH-2.0-softwareversion\r\n`) followed by binary packet framing (32-bit packet_length, 8-bit padding_length, 8-bit SSH message code such as `20` SSH_MSG_KEXINIT with 16-byte random cookie and algorithm name-lists, `21` SSH_MSG_NEWKEYS, `50` SSH_MSG_USERAUTH_REQUEST, `90` SSH_MSG_CHANNEL_OPEN, random padding, and MAC). When optional fields in [`SshSpec`]
//! are omitted in the `.fasm` source, RFC-compliant default values are automatically populated.
//!
//! Canonical `.fasm` syntax:
//! `a -> b SSH [BANNER <str>] [KEXINIT] [NEWKEYS] [MSG_CODE <u8>] [PAYLOAD <str>]`

use crate::ast::*;
use crate::builders::WireContext;
use alloc::vec::Vec;

/// Builds an RFC 4253 SSH banner or binary packet payload.
/// Syntax mapping: `SSH [BANNER <str>] [KEXINIT] [NEWKEYS] [MSG_CODE <u8>] [PAYLOAD <str>]`
#[doc(alias = "SSH")]
#[doc(alias = "SSH2")]
#[doc(alias = "RFC4253")]
#[doc(alias = "KEXINIT")]
#[doc(alias = "NEWKEYS")]
pub fn build_ssh_payload(
    _ctx: &WireContext,
    spec: &SshSpec,
    payload_bytes: &[u8],
) -> Vec<u8> {
    if spec.is_kexinit || spec.is_newkeys || spec.msg_code.is_some() || spec.cookie.is_some() {
        let code = spec.msg_code.unwrap_or(if spec.is_newkeys && !spec.is_kexinit {
            21 // SSH_MSG_NEWKEYS
        } else {
            20 // SSH_MSG_KEXINIT
        });

        let mut body = Vec::new();
        body.push(code);

        if code == 20 || spec.is_kexinit || spec.cookie.is_some() {
            let mut cookie_bytes = [0xAAu8; 16];
            if let Some(c_str) = spec.cookie {
                let raw = c_str.as_bytes();
                if raw.len() == 32 && raw.iter().all(|b| b.is_ascii_hexdigit()) {
                    for (i, pair) in raw.as_chunks::<2>().0.iter().enumerate() {
                        if let Ok(s) = core::str::from_utf8(pair)
                            && let Ok(val) = u8::from_str_radix(s, 16)
                        {
                            cookie_bytes[i] = val;
                        }
                    }
                } else {
                    let copy_len = raw.len().min(16);
                    cookie_bytes[..copy_len].copy_from_slice(&raw[..copy_len]);
                }
            }
            body.extend_from_slice(&cookie_bytes);
        }

        if !payload_bytes.is_empty() {
            body.extend_from_slice(payload_bytes);
        }

        let unpadded = 5 + body.len();
        let rem = unpadded % 8;
        let mut pad_len = if rem == 0 { 0 } else { 8 - rem };
        if pad_len < 4 {
            pad_len += 8;
        }
        let packet_length = (1 + body.len() + pad_len) as u32;

        let mut pkt = Vec::with_capacity(4 + packet_length as usize);
        if let Some(banner) = spec.banner {
            pkt.extend_from_slice(format!("{}\r\n", banner).as_bytes());
        }
        pkt.extend_from_slice(&packet_length.to_be_bytes());
        pkt.push(pad_len as u8);
        pkt.extend_from_slice(&body);
        pkt.resize(pkt.len() + pad_len, 0);
        return pkt;
    }

    if let Some(banner) = spec.banner {
        let mut bytes = format!("{}\r\n", banner).into_bytes();
        if !payload_bytes.is_empty() {
            bytes.extend_from_slice(payload_bytes);
        }
        bytes
    } else {
        // Default RFC 4253 §4.2 identification banner
        let banner_str = "SSH-2.0-FrameAssembly_1.0\r\n";
        let mut bytes = banner_str.as_bytes().to_vec();
        if !payload_bytes.is_empty() {
            bytes.extend_from_slice(payload_bytes);
        }
        bytes
    }
}
