//! SSH protocol AST definitions.

/// RFC 4253 Secure Shell Protocol specification.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SshSpec<'a> {
    /// Version exchange banner.
    pub banner: Option<&'a str>,
    /// Key exchange init flag.
    pub is_kexinit: bool,
    /// New keys flag.
    pub is_newkeys: bool,
    /// Message code number.
    pub msg_code: Option<u8>,
    /// 16-byte cookie hex string.
    pub cookie: Option<&'a str>,
}
