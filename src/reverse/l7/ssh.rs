//! Secure Shell Transport Layer Protocol (`SSH`, RFC 4253) Layer 7 PCAP-to-`.fasm` decompiler.
//!
//! This module implements the fuzz-safe reverse dissector for unencrypted RFC 4253 `SSH` protocol
//! version identification banners (`SSH-2.0-...`, `SSH-1.99-...`) and outer binary packet framing
//! (`kexinit` message code `20` with 16-byte `cookie`, `newkeys` message code `21`, or arbitrary
//! `msg_code` values such as `50` userauth, `90` channel open, and `94` channel data) carried over
//! TCP ports `22`, `2222`, and `830`. It never attempts cryptographic decryption: encrypted post-key
//! exchange records that do not match unencrypted RFC 4253 framing return `None` to step down
//! cleanly to `tcp` with `payload` or `hexpayload`.

use alloc::string::String;
use core::fmt::Write as _;

use crate::ast::Protocol;
use crate::reverse::{ProtocolDissection, bytes_to_hex_lower, sd};

use super::{checked_be_u32, find_subslice, push_str_mod};

/// Dissects an RFC 4253 SSH version banner or binary transport packet on TCP port `22`.
pub(crate) fn dissect_ssh(payload: &[u8]) -> Option<ProtocolDissection> {
    let mut tokens = String::from("ssh");
    let mut bin_slice = payload;

    if payload.starts_with(b"SSH-") {
        let crlf = find_subslice(payload, b"\r\n")?;
        let banner = core::str::from_utf8(payload.get(..crlf)?).ok()?;
        let after_banner = payload.get(crlf + 2..)?;

        if after_banner.is_empty() || !is_ssh_binary_packet(after_banner) {
            if banner != "SSH-2.0-FrameAssembly_1.0" {
                push_str_mod(&mut tokens, "banner", banner);
            }
            return Some(sd(Protocol::Ssh, tokens, after_banner.to_vec()));
        }
        push_str_mod(&mut tokens, "banner", banner);
        bin_slice = after_banner;
    }

    if !is_ssh_binary_packet(bin_slice) {
        return None;
    }

    let pkt_len = checked_be_u32(bin_slice, 0)? as usize;
    let pad_len = *bin_slice.get(4)? as usize;
    let body_len = pkt_len.checked_sub(1)?.checked_sub(pad_len)?;
    let body = bin_slice.get(5..5usize.checked_add(body_len)?)?;
    let code = *body.first()?;

    let residual = if code == 20 {
        let cookie_bytes = body.get(1..17)?;
        tokens.push_str(" kexinit");
        if cookie_bytes != [0xAAu8; 16] {
            let _ = write!(tokens, " cookie \"{}\"", bytes_to_hex_lower(cookie_bytes));
        }
        body.get(17..)?.to_vec()
    } else if code == 21 {
        tokens.push_str(" newkeys");
        body.get(1..)?.to_vec()
    } else {
        let _ = write!(tokens, " msg_code {code}");
        body.get(1..)?.to_vec()
    };

    Some(sd(Protocol::Ssh, tokens, residual))
}

/// Checks whether `buf` matches FrameAssembly's RFC 4253 binary SSH packet framing and padding.
fn is_ssh_binary_packet(buf: &[u8]) -> bool {
    let Some(pkt_len) = checked_be_u32(buf, 0).map(|v| v as usize) else {
        return false;
    };
    if 4usize.checked_add(pkt_len) != Some(buf.len()) {
        return false;
    }
    let Some(&pad_b) = buf.get(4) else {
        return false;
    };
    let pad_len = pad_b as usize;
    if pad_len < 4 || pkt_len < 2 + pad_len {
        return false;
    }
    let unpadded = 5 + (pkt_len - 1 - pad_len);
    let rem = unpadded % 8;
    let mut expected_pad = if rem == 0 { 0 } else { 8 - rem };
    if expected_pad < 4 {
        expected_pad += 8;
    }
    pad_len == expected_pad
        && buf
            .get(buf.len() - pad_len..)
            .is_some_and(|p| p.iter().all(|&b| b == 0))
}
