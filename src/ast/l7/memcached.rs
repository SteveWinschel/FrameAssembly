//! Memcached Binary and ASCII Caching Protocol Abstract Syntax Tree (AST) definitions.
//!
//! This module defines [`MemcachedSpec`], the zero-copy AST representation of a Memcached key-value
//! cache command over TCP or UDP port 11211. On the wire, the Memcached ASCII protocol transmits
//! human-readable command lines (`get <key>\r\n`, `set <key> <flags> <exptime> <bytes>\r\n`,
//! `stats\r\n`, `version\r\n`), whereas the Memcached Binary Protocol uses a fixed 24-byte header
//! (`0x80` request magic, 1-byte opcode, 2-byte key length, 1-byte extras length, 4-byte total
//! body length, 4-byte opaque token, and 8-byte CAS version). Canonical `.fasm` syntax:
//! `MEMCACHED [CMD <str>] [KEY <str>] [VALUE <str>] [FLAGS <u32>] [EXPTIME <u32>] [OPCODE <u8>] [OPAQUE <u32>] [CAS <u64>]`.

/// Memcached ASCII and Binary caching protocol specification.
///
/// Syntax mapping: `MEMCACHED [CMD <str>] [KEY <str>] [VALUE <str>] [FLAGS <u32>] [EXPTIME <u32>] [OPCODE <u8>] [OPAQUE <u32>] [CAS <u64>]`
#[doc(alias = "MEMCACHED")]
#[doc(alias = "11211")]
#[doc(alias = "CMD")]
#[doc(alias = "KEY")]
#[doc(alias = "VALUE")]
#[doc(alias = "FLAGS")]
#[doc(alias = "EXPTIME")]
#[doc(alias = "OPCODE")]
#[doc(alias = "OPAQUE")]
#[doc(alias = "CAS")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MemcachedSpec<'a> {
    /// Memcached command verb (`CMD <str>`, e.g., `"GET"`, `"SET"`, `"ADD"`, `"DELETE"`, `"STATS"`).
    pub cmd: Option<&'a str>,
    /// Cache item key string (`KEY <str>`).
    pub key: Option<&'a str>,
    /// Client-defined 32-bit flags integer (`FLAGS <u32>`).
    pub flags: Option<u32>,
    /// Expiration time in seconds (`EXPTIME <u32>`).
    pub exptime: Option<u32>,
    /// Cache item value payload (`VALUE <str>`).
    pub value: Option<&'a str>,
    /// Optional binary protocol opcode override (`OPCODE <u8>`).
    pub opcode: Option<u8>,
    /// 32-bit binary protocol correlation token (`OPAQUE <u32>`).
    pub opaque: Option<u32>,
    /// 64-bit Compare-And-Swap version identifier (`CAS <u64>`).
    pub cas: Option<u64>,
}
