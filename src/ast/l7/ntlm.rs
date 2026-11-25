//! NT LAN Manager Authentication over HTTP (`ntlm`, MS-NLMP / RFC 4559) Layer 7 AST definitions.
//!
//! This module defines the zero-copy Abstract Syntax Tree (AST) configuration parameters for
//! synthesizing HTTP-carried NTLM challenge-response authentication frames over TCP port 80. On the
//! wire, client `negotiate` (Type 1) and `authenticate` (Type 3) messages are encoded as Base64
//! `NTLMSSP\0` blobs inside `Authorization: NTLM <base64>` HTTP requests, while server `challenge`
//! (Type 2) responses carry Base64 `NTLMSSP\0` blobs inside `HTTP/1.1 401 Unauthorized`
//! `WWW-Authenticate: NTLM <base64>` headers. Every field in [`NtlmSpec`] is optional for bare
//! default synthesis. Canonical `.frasm` syntax:
//! `a -> b ntlm [negotiate | challenge | authenticate] [msgtype <str>] [domain <str>] [user <str>] [workstation <str>] [nonce <str>] [flags <u32>] [method <str>] [uri <str>] [hosthdr <str>] [status <u16>]`.

/// Microsoft NT LAN Manager (`[MS-NLMP]`) over HTTP Layer 7 protocol specification.
///
/// Syntax mapping: `ntlm [negotiate | challenge | authenticate] [msgtype <str>] [domain <str>] [user <str>] [workstation <str>] [nonce <str>] [flags <u32>] [method <str>] [uri <str>] [hosthdr <str>] [status <u16>]`
#[doc(alias = "ntlm")]
#[doc(alias = "NTLMSSP")]
#[doc(alias = "MS-NLMP")]
#[doc(alias = "RFC 4559")]
#[doc(alias = "negotiate")]
#[doc(alias = "challenge")]
#[doc(alias = "authenticate")]
#[doc(alias = "msgtype")]
#[doc(alias = "domain")]
#[doc(alias = "user")]
#[doc(alias = "workstation")]
#[doc(alias = "nonce")]
#[doc(alias = "flags")]
#[doc(alias = "method")]
#[doc(alias = "uri")]
#[doc(alias = "hosthdr")]
#[doc(alias = "status")]
#[doc(alias = "80")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NtlmSpec<'a> {
    /// NTLMSSP message stage (`negotiate` Type 1, `challenge` Type 2, `authenticate` Type 3).
    pub msg_type: Option<&'a str>,
    /// Target or NetBIOS domain name (`domain <str>`, e.g., `"CORP"`).
    pub domain: Option<&'a str>,
    /// Authenticated username for Type 3 `authenticate` messages (`user <str>`, e.g., `"alice"`).
    pub user: Option<&'a str>,
    /// Client workstation or server NetBIOS computer name (`workstation <str>`, e.g., `"WS01"`).
    pub workstation: Option<&'a str>,
    /// 8-byte Type 2 Server Challenge nonce in hexadecimal (`nonce <str>`).
    pub nonce: Option<&'a str>,
    /// 32-bit NTLMSSP `NegotiateFlags` bitmask (`flags <u32>`).
    pub flags: Option<u32>,
    /// HTTP request method for Type 1 / Type 3 requests (`method <str>`, default `"GET"`).
    pub method: Option<&'a str>,
    /// HTTP request target URI (`uri <str>`, default `"/"`).
    pub uri: Option<&'a str>,
    /// HTTP `Host` header override (`hosthdr <str>`).
    pub host_hdr: Option<&'a str>,
    /// HTTP status code for Type 2 `challenge` responses (`status <u16>`, default `401`).
    pub status: Option<u16>,
}
