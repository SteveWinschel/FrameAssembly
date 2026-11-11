//! Simple Service Discovery Protocol (`ssdp`, UPnP HTTPU) Layer 7 PCAP-to-`.fasm` decompiler.
//!
//! This module implements the fuzz-safe reverse dissector for UPnP `ssdp` multicast discovery
//! queries (`M-SEARCH * HTTP/1.1` -> `msearch`) and presence announcements (`NOTIFY * HTTP/1.1` ->
//! `notify`) carried over UDP port `1900`. It enforces duplicate-free CRLF header parsing, decodes
//! `hosthdr`, `man`, `mx`, `st`, `nt`, `nts`, `usn`, and `location` headers into canonical
//! `.fasm` modifiers while eliding RFC defaults, and preserves trailing bytes in
//! `residual_payload`.

use alloc::string::String;
use core::fmt::Write as _;

use crate::ast::Protocol;
use crate::reverse::{ProtocolDissection, sd};

use super::{push_str_mod, split_crlf_headers};

/// Dissects a UPnP SSDP multicast discovery (`M-SEARCH`) or advertisement (`NOTIFY`) datagram on UDP port `1900`.
pub(crate) fn dissect_ssdp(payload: &[u8]) -> Option<ProtocolDissection> {
    let (hdr_str, trailing) = split_crlf_headers(payload)?;
    let mut lines = hdr_str.split("\r\n");
    let is_notify = match lines.next()? {
        "M-SEARCH * HTTP/1.1" => false,
        "NOTIFY * HTTP/1.1" => true,
        _ => return None,
    };

    let mut tokens = String::from(if is_notify {
        "ssdp notify"
    } else {
        "ssdp msearch"
    });
    let mut seen = 0u8;
    for hline in lines {
        let (k, v) = hline.split_once(": ")?;
        let bit = match k {
            "HOST" => 1,
            "MAN" => 2,
            "MX" => 4,
            "ST" if !is_notify => 8,
            "NT" => 16,
            "NTS" => 32,
            "USN" => 64,
            "LOCATION" => 128,
            _ => return None,
        };
        if (seen & bit) != 0 {
            return None;
        }
        seen |= bit;
        match k {
            "HOST" if v != "239.255.255.250:1900" => push_str_mod(&mut tokens, "hosthdr", v),
            "MAN" if is_notify || v != "\"ssdp:discover\"" => push_str_mod(&mut tokens, "man", v),
            "MX" => {
                let mx: u8 = v.parse().ok()?;
                if is_notify || mx != 3 {
                    let _ = write!(tokens, " mx {mx}");
                }
            }
            "ST" if v != "ssdp:all" => push_str_mod(&mut tokens, "st", v),
            "NT" if !is_notify || v != "ssdp:all" => push_str_mod(&mut tokens, "nt", v),
            "NTS" if !is_notify || v != "ssdp:alive" => push_str_mod(&mut tokens, "nts", v),
            "HOST" | "MAN" | "ST" | "NT" | "NTS" => {}
            "USN" => push_str_mod(&mut tokens, "usn", v),
            "LOCATION" => push_str_mod(&mut tokens, "location", v),
            _ => return None,
        }
    }

    Some(sd(Protocol::Ssdp, tokens, trailing.to_vec()))
}
