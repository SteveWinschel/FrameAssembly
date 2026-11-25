//! Virtual Network Computing Remote Framebuffer Protocol (VNC / RFB 003.008, RFC 6143) Layer 7 wire packet builder.
//!
//! This module synthesizes deterministic on-the-wire Remote Framebuffer (`vnc`) frames over TCP
//! port 5900. When optional fields are omitted, bare `vnc` statements emit the RFC 6143 §7.1.1
//! `RFB 003.008\n` protocol version handshake. Explicit `msgtype` selectors or RFB parameters
//! synthesize `security`, `securityresult`, `clientinit`, `serverinit` (with true-color pixel
//! format and desktop title), `setencodings`, `fbupdatereq`, `keyevent`, `pointerevent`, and
//! `bell` PDUs.
//!
//! Canonical `.frasm` syntax:
//! `a -> b vnc [msgtype <str>] [version <str>] [securitytype <u8>] [width <u16>] [height <u16>] [desktop <str>] [key <u32>] [flags <u8>] [xpos <u16>] [ypos <u16>]`

use crate::ast::*;
use crate::builders::WireContext;
use alloc::format;
use alloc::vec::Vec;

/// Returns `true` when the resolved source port identifies a VNC server display endpoint.
fn is_vnc_server_src(ctx: &WireContext) -> bool {
    let vnc_port = |p: u16| (5900..=5909).contains(&p);
    (vnc_port(ctx.src_port) && !vnc_port(ctx.dst_port))
        || (ctx.src_port < 1024 && ctx.dst_port >= 1024)
}

/// Formats an RFB 12-byte ASCII ProtocolVersion banner (`RFB XXX.YYY\n`).
fn format_rfb_version(ver_opt: Option<&str>) -> [u8; 12] {
    let raw = ver_opt.unwrap_or("003.008").trim();
    let trimmed = raw
        .strip_prefix("RFB ")
        .or_else(|| raw.strip_prefix("rfb "))
        .unwrap_or(raw)
        .trim_end_matches('\n');
    let (maj, min) = if let Some((a, b)) = trimmed.split_once('.') {
        (
            a.parse::<u16>().unwrap_or(3).min(999),
            b.parse::<u16>().unwrap_or(8).min(999),
        )
    } else {
        (3, 8)
    };
    let banner = format!("RFB {maj:03}.{min:03}\n");
    let mut out = *b"RFB 003.008\n";
    let b = banner.as_bytes();
    if b.len() == 12 {
        out.copy_from_slice(b);
    }
    out
}

/// Appends the standard 16-byte RFC 6143 §7.4 32-bpp little-endian TrueColor pixel format.
fn push_default_pixel_format(pkt: &mut Vec<u8>) {
    pkt.extend_from_slice(&[
        32, // bits-per-pixel
        24, // depth
        0,  // big-endian-flag (little-endian)
        1,  // true-colour-flag
        0, 255, // red-max (255)
        0, 255, // green-max (255)
        0, 255, // blue-max (255)
        16,  // red-shift
        8,   // green-shift
        0,   // blue-shift
        0, 0, 0, // padding
    ]);
}

/// Builds an RFC 6143 VNC (RFB 003.008) handshake or interaction PDU payload.
///
/// Syntax mapping: `vnc [msgtype <str>] [version <str>] [securitytype <u8>] [width <u16>] [height <u16>] [desktop <str>] [key <u32>] [flags <u8>] [xpos <u16>] [ypos <u16>]`
#[doc(alias = "VNC")]
#[doc(alias = "RFB")]
#[doc(alias = "RFC6143")]
pub fn build_vnc_payload(
    ctx: &WireContext,
    spec: &VncSpec,
    payload_bytes: &[u8],
) -> Vec<u8> {
    let inferred = if spec.msg_type.is_some() {
        spec.msg_type.unwrap_or("version")
    } else if spec.desktop.is_some() {
        "serverinit"
    } else if spec.key.is_some() {
        "keyevent"
    } else if spec.xpos.is_some() || spec.ypos.is_some() {
        "pointerevent"
    } else if spec.width.is_some() || spec.height.is_some() {
        "serverinit"
    } else if spec.security_type.is_some() {
        "security"
    } else if spec.flags.is_some() && spec.version.is_none() {
        "clientinit"
    } else {
        "version"
    };

    let norm = inferred.trim().to_ascii_uppercase().replace(['_', '-'], "");
    let mut pkt = Vec::new();
    match norm.as_str() {
        "SECURITY" | "SECURITYTYPES" => {
            let st = spec.security_type.unwrap_or(1);
            if is_vnc_server_src(ctx) {
                pkt.push(1);
                pkt.push(st);
            } else {
                pkt.push(st);
            }
        }
        "SECURITYRESULT" => {
            let res = u32::from(spec.flags.unwrap_or(0));
            pkt.extend_from_slice(&res.to_be_bytes());
        }
        "CLIENTINIT" => {
            pkt.push(spec.flags.unwrap_or(1));
        }
        "SERVERINIT" => {
            let w = spec.width.unwrap_or(1024);
            let h = spec.height.unwrap_or(768);
            let name = spec.desktop.unwrap_or("FrameAssembly").as_bytes();
            pkt.extend_from_slice(&w.to_be_bytes());
            pkt.extend_from_slice(&h.to_be_bytes());
            push_default_pixel_format(&mut pkt);
            pkt.extend_from_slice(&(name.len() as u32).to_be_bytes());
            pkt.extend_from_slice(name);
        }
        "SETENCODINGS" => {
            pkt.push(2);
            pkt.push(0);
            pkt.extend_from_slice(&4u16.to_be_bytes());
            for enc in [0i32, 1, 5, 16] {
                pkt.extend_from_slice(&enc.to_be_bytes());
            }
        }
        "FBUPDATEREQ" | "FRAMEBUFFERUPDATEREQUEST" => {
            let inc = spec.flags.unwrap_or(0);
            let x = spec.xpos.unwrap_or(0);
            let y = spec.ypos.unwrap_or(0);
            let w = spec.width.unwrap_or(1024);
            let h = spec.height.unwrap_or(768);
            pkt.push(3);
            pkt.push(inc);
            pkt.extend_from_slice(&x.to_be_bytes());
            pkt.extend_from_slice(&y.to_be_bytes());
            pkt.extend_from_slice(&w.to_be_bytes());
            pkt.extend_from_slice(&h.to_be_bytes());
        }
        "KEYEVENT" => {
            let down = spec.flags.unwrap_or(1);
            let key = spec.key.unwrap_or(0x0061);
            pkt.push(4);
            pkt.push(down);
            pkt.extend_from_slice(&[0, 0]);
            pkt.extend_from_slice(&key.to_be_bytes());
        }
        "POINTEREVENT" => {
            let mask = spec.flags.unwrap_or(0);
            let x = spec.xpos.unwrap_or(0);
            let y = spec.ypos.unwrap_or(0);
            pkt.push(5);
            pkt.push(mask);
            pkt.extend_from_slice(&x.to_be_bytes());
            pkt.extend_from_slice(&y.to_be_bytes());
        }
        "BELL" => {
            pkt.push(2);
        }
        _ => {
            pkt.extend_from_slice(&format_rfb_version(spec.version));
        }
    }

    if !payload_bytes.is_empty() {
        pkt.extend_from_slice(payload_bytes);
    }
    pkt
}
