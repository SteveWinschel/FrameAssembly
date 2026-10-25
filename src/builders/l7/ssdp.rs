//! Simple Service Discovery Protocol (SSDP / UPnP) (UPnP Device Architecture 1.1 / 2.0 (HTTPU over UDP Multicast)) Layer 7 wire packet builder.
//!
//! This module synthesizes deterministic on-the-wire Simple Service Discovery Protocol (SSDP / UPnP) frames over UDP port 1900 (IPv4 multicast 239.255.255.250 / IPv6 ff02::c or ff05::c).
//! The wire encoder constructs a HTTP-over-UDP (HTTPU) multicast datagram beginning with `M-SEARCH * HTTP/1.1\r\n` active discovery request or `NOTIFY * HTTP/1.1\r\n` presence advertisement, carrying `HOST:`, `MAN:` (`"ssdp:discover"`), `MX:` delay seconds, `ST:` Search Target, `NT:` Notification Type, `NTS:` (`ssdp:alive`, `ssdp:byebye`, `ssdp:update`), `USN:` Unique Service Name, and `LOCATION:` XML device descriptor URL. When optional fields in [`SsdpSpec`]
//! are omitted in the `.fasm` source, RFC-compliant default values are automatically populated.
//!
//! Canonical `.fasm` syntax:
//! `a -> b SSDP [MSEARCH | NOTIFY] [HOST_HDR <str>] [MAN <str>] [MX <u8>] [ST <str>] [NT <str>] [NTS <str>] [USN <str>] [LOCATION <str>]`

use crate::ast::*;
use crate::builders::WireContext;
use alloc::vec::Vec;

/// Builds an SSDP discovery request or notification string.
/// Syntax mapping: `SSDP [MSEARCH | NOTIFY] [HOST_HDR <str>] [MAN <str>] [MX <u8>] [ST <str>] [NT <str>] [NTS <str>] [USN <str>] [LOCATION <str>]`
#[doc(alias = "SSDP")]
#[doc(alias = "UPNP")]
#[doc(alias = "MSEARCH")]
#[doc(alias = "DLNA")]
pub fn build_ssdp_payload(
    _ctx: &WireContext,
    spec: &SsdpSpec,
    payload_bytes: &[u8],
) -> Vec<u8> {
    let method = if spec.is_notify && !spec.is_msearch {
        "NOTIFY"
    } else {
        "M-SEARCH"
    };
    let host = spec.host_hdr.unwrap_or("239.255.255.250:1900");
    let st = spec.st.unwrap_or("ssdp:all");

    let mut out = format!("{} * HTTP/1.1\r\nHOST: {}\r\n", method, host);
    if method == "NOTIFY" {
        let nt = spec.nt.unwrap_or(st);
        let nts = spec.nts.unwrap_or("ssdp:alive");
        out.push_str(&format!("NT: {}\r\nNTS: {}\r\n", nt, nts));
        if let Some(man) = spec.man {
            out.push_str(&format!("MAN: {}\r\n", man));
        }
        if let Some(mx) = spec.mx {
            out.push_str(&format!("MX: {}\r\n", mx));
        }
    } else {
        let man = spec.man.unwrap_or("\"ssdp:discover\"");
        let mx = spec.mx.unwrap_or(3);
        out.push_str(&format!("MAN: {}\r\nMX: {}\r\nST: {}\r\n", man, mx, st));
        if let Some(nt) = spec.nt {
            out.push_str(&format!("NT: {}\r\n", nt));
        }
        if let Some(nts) = spec.nts {
            out.push_str(&format!("NTS: {}\r\n", nts));
        }
    }
    if let Some(usn) = spec.usn {
        out.push_str(&format!("USN: {}\r\n", usn));
    }
    if let Some(location) = spec.location {
        out.push_str(&format!("LOCATION: {}\r\n", location));
    }
    out.push_str("\r\n");

    let mut bytes = out.into_bytes();
    if !payload_bytes.is_empty() {
        bytes.extend_from_slice(payload_bytes);
    }
    bytes
}
