//! Secure Shell Transport Layer Protocol (SSH-2) (RFC 4253 (Transport) / RFC 4252 (UserAuth) / RFC 4254 (Connection)) Layer 7 AST definitions.
//!
//! This module defines the abstract syntax tree (AST) configuration parameters for synthesizing
//! Secure Shell Transport Layer Protocol (SSH-2) packets over TCP port 22. On the wire, the protocol uses a CRLF-terminated protocol version identification string (`SSH-2.0-softwareversion\r\n`) followed by binary packet framing (32-bit packet_length, 8-bit padding_length, 8-bit SSH message code such as `20` SSH_MSG_KEXINIT with 16-byte random cookie and algorithm name-lists, `21` SSH_MSG_NEWKEYS, `50` SSH_MSG_USERAUTH_REQUEST, `90` SSH_MSG_CHANNEL_OPEN, random padding, and MAC).
//! Every field in [`SshSpec`] is optional so authors can emit zero-configuration default
//! frames or override specific protocol header fields and attributes.
//!
//! Canonical `.fasm` syntax:
//! `a -> b SSH [BANNER <str>] [KEXINIT] [NEWKEYS] [MSG_CODE <u8>] [COOKIE <str>] [PAYLOAD <str>]`

/// RFC 4253 Secure Shell Protocol specification.
///
/// Syntax mapping: `SSH [BANNER <str>] [KEXINIT] [NEWKEYS] [MSG_CODE <u8>] [COOKIE <str>] [PAYLOAD <str>]`
#[doc(alias = "SSH")]
#[doc(alias = "SSH2")]
#[doc(alias = "RFC 4253")]
#[doc(alias = "RFC4253")]
#[doc(alias = "RFC 4252")]
#[doc(alias = "RFC 4254")]
#[doc(alias = "BANNER")]
#[doc(alias = "KEXINIT")]
#[doc(alias = "NEWKEYS")]
#[doc(alias = "MSG_CODE")]
#[doc(alias = "COOKIE")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SshSpec<'a> {
    /// Version exchange banner (`BANNER <str>`).
    pub banner: Option<&'a str>,
    /// Key exchange init flag (`KEXINIT`).
    pub is_kexinit: bool,
    /// New keys flag (`NEWKEYS`).
    pub is_newkeys: bool,
    /// Message code number (`MSG_CODE <u8>`).
    pub msg_code: Option<u8>,
    /// 16-byte cookie hex string (`COOKIE <str>`).
    pub cookie: Option<&'a str>,
}
