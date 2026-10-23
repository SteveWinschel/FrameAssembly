//! REDIS protocol AST definitions.

use alloc::vec::Vec;

/// Redis Serialization Protocol specification.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RedisSpec<'a> {
    /// Redis command verb.
    pub cmd: Option<&'a str>,
    /// Command arguments list.
    pub args: Vec<&'a str>,
    /// Reply type string.
    pub reply_type: Option<&'a str>,
    /// Value string.
    pub value: Option<&'a str>,
}
