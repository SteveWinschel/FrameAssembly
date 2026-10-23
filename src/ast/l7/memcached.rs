//! MEMCACHED protocol AST definitions.

/// Memcached caching protocol specification.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MemcachedSpec<'a> {
    /// Command verb.
    pub cmd: Option<&'a str>,
    /// Key string.
    pub key: Option<&'a str>,
    /// Flags integer.
    pub flags: Option<u32>,
    /// Exptime in seconds.
    pub exptime: Option<u32>,
    /// Value string.
    pub value: Option<&'a str>,
    /// Binary opcode.
    pub opcode: Option<u8>,
    /// Binary opaque value.
    pub opaque: Option<u32>,
    /// Compare-And-Swap counter.
    pub cas: Option<u64>,
}
