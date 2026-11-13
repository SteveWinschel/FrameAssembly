//! WHOIS Directory Protocol (`whois`, RFC 3912) Layer 7 PCAP-to-`.frasm` decompiler.
//!
//! This module implements the fuzz-safe reverse dissector for RFC 3912 `whois` domain registration
//! queries and structured responses (`Domain Name: ...` and `Registrar: ...` header lines) carried
//! over TCP port `43`. It validates CRLF line terminators, decodes `query` and `response` keywords
//! along with `domain` and `registrar` modifiers, and preserves any additional registry response
//! lines after the CRLF delimiters as residual payload bytes.

use alloc::string::String;

use super::{find_subslice, push_str_mod};
use crate::ast::Protocol;
use crate::reverse::{ProtocolDissection, sd};

/// Dissects an RFC 3912 WHOIS query or response on TCP port `43`.
pub(crate) fn dissect_whois(payload: &[u8]) -> Option<ProtocolDissection> {
    if let Some(after_dn) = payload.strip_prefix(b"Domain Name: ") {
        let crlf1 = find_subslice(after_dn, b"\r\n")?;
        let domain = core::str::from_utf8(after_dn.get(..crlf1)?).ok()?;
        let after_reg = after_dn.get(crlf1 + 2..)?.strip_prefix(b"Registrar: ")?;
        let crlf2 = find_subslice(after_reg, b"\r\n")?;
        let registrar = core::str::from_utf8(after_reg.get(..crlf2)?).ok()?;
        let trailing = after_reg.get(crlf2 + 2..)?;

        let mut tokens = String::from("whois response");
        if domain != "example.com" {
            push_str_mod(&mut tokens, "domain", domain);
        }
        if registrar != "IANA" {
            push_str_mod(&mut tokens, "registrar", registrar);
        }
        return Some(sd(Protocol::Whois, tokens, trailing.to_vec()));
    }

    let crlf = find_subslice(payload, b"\r\n")?;
    let domain = core::str::from_utf8(payload.get(..crlf)?).ok()?;
    let mut tokens = String::from("whois query");
    if domain != "example.com" {
        push_str_mod(&mut tokens, "domain", domain);
    }
    Some(sd(
        Protocol::Whois,
        tokens,
        payload.get(crlf + 2..)?.to_vec(),
    ))
}
