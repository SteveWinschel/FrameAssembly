//! Memcached Binary and ASCII Caching Protocol Abstract Syntax Tree (AST) definitions.
//!
//! This module defines [`MemcachedSpec`], the zero-copy AST representation of a Memcached key-value
//! cache command over TCP or UDP port 11211. On the wire, the Memcached ASCII protocol transmits
//! human-readable command lines (`get <key>\r\n`, `set <key> <flags> <exptime> <bytes>\r\n`,
//! `stats\r\n`, `version\r\n`), whereas the Memcached Binary Protocol uses a fixed 24-byte header
//! (`0x80` request magic, 1-byte opcode, 2-byte key length, 1-byte extras length, 4-byte total
//! body length, 4-byte opaque token, and 8-byte CAS version). Canonical `.fasm` syntax:
//! `memcached [cmd <str>] [key <str>] [value <str>] [flags <u32>] [exptime <u32>] [opcode <u8>] [opaque <u32>] [cas <u64>]`.

/// Memcached ASCII and Binary caching protocol specification.
///
/// Syntax mapping: `memcached [cmd <str>] [key <str>] [value <str>] [flags <u32>] [exptime <u32>] [opcode <u8>] [opaque <u32>] [cas <u64>]`
#[doc(alias = "memcached")]
#[doc(alias = "11211")]
#[doc(alias = "cmd")]
#[doc(alias = "key")]
#[doc(alias = "value")]
#[doc(alias = "flags")]
#[doc(alias = "exptime")]
#[doc(alias = "opcode")]
#[doc(alias = "opaque")]
#[doc(alias = "cas")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MemcachedSpec<'a> {
    /// Memcached command verb (`cmd <str>`, e.g., `"GET"`, `"SET"`, `"ADD"`, `"DELETE"`, `"STATS"`).
    pub cmd: Option<&'a str>,
    /// Cache item key string (`key <str>`).
    pub key: Option<&'a str>,
    /// Client-defined 32-bit flags integer (`flags <u32>`).
    pub flags: Option<u32>,
    /// Expiration time in seconds (`exptime <u32>`).
    pub exptime: Option<u32>,
    /// Cache item value payload (`value <str>`).
    pub value: Option<&'a str>,
    /// Optional binary protocol opcode override (`opcode <u8>`).
    pub opcode: Option<u8>,
    /// 32-bit binary protocol correlation token (`opaque <u32>`).
    pub opaque: Option<u32>,
    /// 64-bit Compare-And-Swap version identifier (`cas <u64>`).
    pub cas: Option<u64>,
}
