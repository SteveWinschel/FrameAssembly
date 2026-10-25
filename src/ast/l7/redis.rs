//! Redis Serialization Protocol (RESP2/RESP3) Abstract Syntax Tree (AST) definitions.
//!
//! This module defines [`RedisSpec`], the zero-copy AST representation of a Redis Serialization
//! Protocol (RESP2/RESP3) client command array or server reply over TCP port 6379 (or 26379 for
//! Redis Sentinel). On the wire, client commands are encoded as RESP Arrays (`*<count>\r\n`) of
//! Bulk Strings (`$<len>\r\n<bytes>\r\n`), while server replies use type-prefixed frames: Simple
//! Strings (`+OK\r\n`), Errors (`-ERR ...\r\n`), Integers (`:<n>\r\n`), or Bulk Strings.
//! Canonical FrameAssembly `.fasm` syntax models Redis traffic via
//! `REDIS [CMD <str>] [ARGS <str>] [REPLY_TYPE <str>] [VALUE <str>]`.

use alloc::vec::Vec;

/// Redis Serialization Protocol (RESP2/RESP3) command or reply specification.
///
/// Syntax mapping: `REDIS [CMD <str>] [ARGS <str>] [REPLY_TYPE <str>] [VALUE <str>]`
#[doc(alias = "REDIS")]
#[doc(alias = "RESP")]
#[doc(alias = "RESP2")]
#[doc(alias = "RESP3")]
#[doc(alias = "CMD")]
#[doc(alias = "ARGS")]
#[doc(alias = "REPLY_TYPE")]
#[doc(alias = "VALUE")]
#[doc(alias = "6379")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RedisSpec<'a> {
    /// Redis command verb (`CMD <str>`, e.g., `"PING"`, `"SET"`, `"GET"`, `"HSET"`, `"XADD"`).
    pub cmd: Option<&'a str>,
    /// Command arguments list (`ARGS <str>`, split on whitespace into RESP bulk strings).
    pub args: Vec<&'a str>,
    /// Server RESP reply type (`REPLY_TYPE <str>`, e.g., `"STATUS"`, `"ERROR"`, `"INTEGER"`, `"BULK"`).
    pub reply_type: Option<&'a str>,
    /// Server reply value or bulk string payload (`VALUE <str>`).
    pub value: Option<&'a str>,
}
