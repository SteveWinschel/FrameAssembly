//! Virtual Network Computing Remote Framebuffer Protocol (`vnc`, RFC 6143) Layer 7 PCAP-to-`.frasm` decompiler.
//!
//! This module implements the fuzz-safe reverse dissector for RFC 6143 Remote Framebuffer (`vnc`)
//! version banners (`RFB 003.008\n`), security negotiation handshakes, `ClientInit`, `ServerInit`
//! pixel format advertisements, `SetEncodings`, `FramebufferUpdateRequest`, `KeyEvent`,
//! `PointerEvent`, and `Bell` messages carried over TCP or SCTP ports `5900..=5909`. Default
//! fields are elided cleanly while preserving trailing payload bytes in `residual_payload`.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write as _;

use crate::ast::{Protocol, TransportProto};
use crate::reverse::{ProtocolDissection, sd};

use super::{checked_be_u16, checked_be_u32, is_valid_raw_string_body, push_str_mod};

/// Standard 16-byte RFC 6143 §7.4 TrueColor pixel format emitted by `build_vnc_payload`.
const DEFAULT_PIXEL_FORMAT: [u8; 16] = [
    32, 24, 0, 1, 0, 255, 0, 255, 0, 255, 16, 8, 0, 0, 0, 0,
];

/// Returns `true` when `(src_port, dst_port)` identifies a VNC server display endpoint.
fn is_vnc_server_src(src_port: u16, dst_port: u16) -> bool {
    let vnc_port = |p: u16| (5900..=5909).contains(&p);
    (vnc_port(src_port) && !vnc_port(dst_port)) || (src_port < 1024 && dst_port >= 1024)
}

/// Checks whether `bytes` is a valid 12-byte RFC 6143 `RFB XXX.YYY\n` version string.
fn parse_rfb_version(bytes: &[u8]) -> Option<&str> {
    if bytes.len() < 12 || !bytes.starts_with(b"RFB ") || bytes[7] != b'.' || bytes[11] != b'\n' {
        return None;
    }
    if !bytes[4..7].iter().all(u8::is_ascii_digit) || !bytes[8..11].iter().all(u8::is_ascii_digit) {
        return None;
    }
    core::str::from_utf8(bytes.get(4..11)?).ok()
}

/// Dissects an RFC 6143 VNC / RFB handshake or message over TCP or SCTP ports `5900..=5909`.
pub(crate) fn dissect_vnc(
    transport: TransportProto,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Option<ProtocolDissection> {
    if !matches!(transport, TransportProto::Tcp | TransportProto::Sctp)
        || (!(5900..=5909).contains(&src_port) && !(5900..=5909).contains(&dst_port))
        || payload.is_empty()
    {
        return None;
    }

    let server_src = is_vnc_server_src(src_port, dst_port);

    // 1. RFB ProtocolVersion banner (12 bytes: `RFB 003.008\n`)
    if let Some(ver) = parse_rfb_version(payload) {
        let mut tokens = String::from("vnc");
        if ver != "003.008" {
            push_str_mod(&mut tokens, "version", ver);
        }
        return Some(sd(Protocol::Vnc, tokens, payload.get(12..)?.to_vec()));
    }

    // 2. ServerInit (width + height + 16B TrueColor pixel format + name_len + name)
    if payload.len() >= 24 && payload.get(4..20) == Some(&DEFAULT_PIXEL_FORMAT) {
        let w = checked_be_u16(payload, 0)?;
        let h = checked_be_u16(payload, 2)?;
        let name_len = usize::try_from(checked_be_u32(payload, 20)?).ok()?;
        let name_end = 24usize.checked_add(name_len)?;
        let name_bytes = payload.get(24..name_end)?;
        let name = core::str::from_utf8(name_bytes).ok()?;
        if !is_valid_raw_string_body(name) {
            return None;
        }
        let mut tokens = String::from("vnc msgtype \"serverinit\"");
        if w != 1024 {
            let _ = write!(tokens, " width {w}");
        }
        if h != 768 {
            let _ = write!(tokens, " height {h}");
        }
        if name != "FrameAssembly" {
            push_str_mod(&mut tokens, "desktop", name);
        }
        return Some(sd(Protocol::Vnc, tokens, payload.get(name_end..)?.to_vec()));
    }

    // 3. Client-to-server RFB interaction messages
    if !server_src {
        if payload.len() >= 20
            && payload[0] == 2
            && payload[1] == 0
            && checked_be_u16(payload, 2) == Some(4)
            && payload.get(4..20)
                == Some(&[0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 5, 0, 0, 0, 16])
        {
            return Some(sd(
                Protocol::Vnc,
                String::from("vnc msgtype \"setencodings\""),
                payload.get(20..)?.to_vec(),
            ));
        }
        if payload.len() >= 10
            && payload[0] == 3
            && payload[1] <= 1
            && checked_be_u16(payload, 6).is_some_and(|w| w > 0)
            && checked_be_u16(payload, 8).is_some_and(|h| h > 0)
        {
            let inc = payload[1];
            let x = checked_be_u16(payload, 2)?;
            let y = checked_be_u16(payload, 4)?;
            let w = checked_be_u16(payload, 6)?;
            let h = checked_be_u16(payload, 8)?;
            let mut tokens = String::from("vnc msgtype \"fbupdatereq\"");
            if inc != 0 {
                let _ = write!(tokens, " flags {inc}");
            }
            if x != 0 {
                let _ = write!(tokens, " xpos {x}");
            }
            if y != 0 {
                let _ = write!(tokens, " ypos {y}");
            }
            if w != 1024 {
                let _ = write!(tokens, " width {w}");
            }
            if h != 768 {
                let _ = write!(tokens, " height {h}");
            }
            return Some(sd(Protocol::Vnc, tokens, payload.get(10..)?.to_vec()));
        }
        if payload.len() >= 8 && payload[0] == 4 && payload[1] <= 1 && payload[2..4] == [0, 0] {
            let down = payload[1];
            let key = checked_be_u32(payload, 4)?;
            let mut tokens = String::from("vnc msgtype \"keyevent\"");
            if down != 1 {
                let _ = write!(tokens, " flags {down}");
            }
            if key != 0x0061 {
                let _ = write!(tokens, " key 0x{key:04x}");
            }
            return Some(sd(Protocol::Vnc, tokens, payload.get(8..)?.to_vec()));
        }
        if payload.len() >= 6 && payload[0] == 5 {
            let mask = payload[1];
            let x = checked_be_u16(payload, 2)?;
            let y = checked_be_u16(payload, 4)?;
            let mut tokens = String::from("vnc msgtype \"pointerevent\"");
            if mask != 0 {
                let _ = write!(tokens, " flags {mask}");
            }
            if x != 0 {
                let _ = write!(tokens, " xpos {x}");
            }
            if y != 0 {
                let _ = write!(tokens, " ypos {y}");
            }
            return Some(sd(Protocol::Vnc, tokens, payload.get(6..)?.to_vec()));
        }
        if payload.len() == 1 && payload[0] <= 1 {
            let mut tokens = String::from("vnc msgtype \"clientinit\"");
            if payload[0] != 1 {
                let _ = write!(tokens, " flags {}", payload[0]);
            }
            return Some(sd(Protocol::Vnc, tokens, Vec::new()));
        }
        if payload.len() == 1 && payload[0] >= 2 {
            return Some(sd(
                Protocol::Vnc,
                format!("vnc msgtype \"security\" securitytype {}", payload[0]),
                Vec::new(),
            ));
        }
    } else {
        // 4. Server-to-client Security list, SecurityResult, and Bell
        if payload.len() == 2 && payload[0] == 1 {
            let mut tokens = String::from("vnc msgtype \"security\"");
            if payload[1] != 1 {
                let _ = write!(tokens, " securitytype {}", payload[1]);
            }
            return Some(sd(Protocol::Vnc, tokens, Vec::new()));
        }
        if payload.len() == 4 && matches!(checked_be_u32(payload, 0), Some(0 | 1)) {
            let res = checked_be_u32(payload, 0)?;
            let mut tokens = String::from("vnc msgtype \"securityresult\"");
            if res != 0 {
                let _ = write!(tokens, " flags {res}");
            }
            return Some(sd(Protocol::Vnc, tokens, Vec::new()));
        }
        if payload == [2] {
            return Some(sd(
                Protocol::Vnc,
                String::from("vnc msgtype \"bell\""),
                Vec::new(),
            ));
        }
    }

    None
}
