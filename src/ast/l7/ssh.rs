//! Secure Shell Transport Layer Protocol (SSH-2) (RFC 4253 (Transport) / RFC 4252 (UserAuth) / RFC 4254 (Connection)) Layer 7 AST definitions.
//!
//! This module defines the abstract syntax tree (AST) configuration parameters for synthesizing
//! Secure Shell Transport Layer Protocol (SSH-2) packets over TCP port 22. On the wire, the protocol uses a CRLF-terminated protocol version identification string (`ssh-2.0-softwareversion\r\n`) followed by binary packet framing (32-bit packet_length, 8-bit padding_length, 8-bit SSH message code such as `20` SSH_MSG_KEXINIT with 16-byte random cookie and algorithm name-lists, `21` SSH_MSG_NEWKEYS, `50` SSH_MSG_USERAUTH_REQUEST, `90` SSH_MSG_CHANNEL_OPEN, random padding, and MAC).
//! Every field in [`SshSpec`] is optional so authors can emit zero-configuration default
//! frames or override specific protocol header fields and attributes.
//!
//! Canonical `.frasm` syntax:
//! `a -> b ssh [banner <str>] [kexinit] [newkeys] [msgcode <u8>] [cookie <str>] [payload <str>]`

/// RFC 4253 Secure Shell Protocol specification.
///
/// Syntax mapping: `ssh [banner <str>] [kexinit] [newkeys] [msgcode <u8>] [cookie <str>] [payload <str>]`
#[doc(alias = "ssh")]
#[doc(alias = "SSH2")]
#[doc(alias = "RFC 4253")]
#[doc(alias = "RFC4253")]
#[doc(alias = "RFC 4252")]
#[doc(alias = "RFC 4254")]
#[doc(alias = "banner")]
#[doc(alias = "kexinit")]
#[doc(alias = "newkeys")]
#[doc(alias = "msgcode")]
#[doc(alias = "cookie")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SshSpec<'a> {
    /// Version exchange banner (`banner <str>`).
    pub banner: Option<&'a str>,
    /// Key exchange init flag (`kexinit`).
    pub is_kexinit: bool,
    /// New keys flag (`newkeys`).
    pub is_newkeys: bool,
    /// Message code number (`msgcode <u8>`).
    pub msg_code: Option<u8>,
    /// 16-byte cookie hex string (`cookie <str>`).
    pub cookie: Option<&'a str>,
}
