//! MongoDB Wire Protocol (`OP_MSG`, opCode 2013) Layer 7 Abstract Syntax Tree (AST) definitions.
//!
//! This module defines [`MongodbSpec`], the zero-copy AST representation of a MongoDB Wire
//! Protocol `OP_MSG` (`2013`) request or server reply packet transmitted over TCP port 27017. On
//! the wire, each message starts with a 16-byte little-endian `MsgHeader` (`messageLength`,
//! `requestID`, `responseTo`, and `opCode = 2013`), followed by 32-bit `flagBits`, a Section Kind
//! `0` BSON document encoding commands (`ping`, `find`, `insert`, `delete`), collection names,
//! filters, `$db` targets, or server `ok`/`errmsg`/`code` replies, and an optional CRC-32C trailer.
//! Canonical `.frasm` syntax:
//! `mongodb [ping | query | response | ok | err] [cmd <str>] [collection <str>] [db <str>] [filter <str>] [reqid <u32>] [responseto <u32>] [flags <u32>] [errcode <u16>] [errmsg <str>]`.

/// MongoDB Wire Protocol (`OP_MSG`, opCode 2013) specification.
///
/// Syntax mapping: `mongodb [ping | query | response | ok | err] [cmd <str>] [collection <str>] [db <str>] [filter <str>] [reqid <u32>] [responseto <u32>] [flags <u32>] [errcode <u16>] [errmsg <str>]`
#[doc(alias = "mongodb")]
#[doc(alias = "MongoDB")]
#[doc(alias = "OP_MSG")]
#[doc(alias = "BSON")]
#[doc(alias = "27017")]
#[doc(alias = "ping")]
#[doc(alias = "query")]
#[doc(alias = "response")]
#[doc(alias = "ok")]
#[doc(alias = "err")]
#[doc(alias = "cmd")]
#[doc(alias = "collection")]
#[doc(alias = "db")]
#[doc(alias = "filter")]
#[doc(alias = "reqid")]
#[doc(alias = "responseto")]
#[doc(alias = "flags")]
#[doc(alias = "errcode")]
#[doc(alias = "errmsg")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MongodbSpec<'a> {
    /// Server `OP_MSG` success reply flag (`response` / `ok`, encoding `{"ok": 1.0}`).
    pub is_response: bool,
    /// Server `OP_MSG` error reply flag (`err`, encoding `{"ok": 0.0, "errmsg": ..., "code": ...}`).
    pub is_err: bool,
    /// MongoDB command name in the Body BSON document (`cmd <str>`, default `"ping"` or `"find"`).
    pub cmd: Option<&'a str>,
    /// Target database name encoded in `$db` (`db <str>`, default `"admin"`).
    pub db: Option<&'a str>,
    /// Target collection name for collection commands such as `find` (`collection <str>`).
    pub collection: Option<&'a str>,
    /// Query predicate text encoded inside an embedded `filter` BSON subdocument (`filter <str>`).
    pub filter: Option<&'a str>,
    /// 32-bit wire header `requestID` (`reqid <u32>`, default `1`).
    pub req_id: Option<u32>,
    /// 32-bit wire header `responseTo` correlation identifier (`responseto <u32>`).
    pub response_to: Option<u32>,
    /// 32-bit `OP_MSG` `flagBits` field (`flags <u32>`, bit `0x01` appends CRC-32C checksum).
    pub flags: Option<u32>,
    /// 16-bit error code included in error reply BSON documents (`errcode <u16>`, default `1`).
    pub errcode: Option<u16>,
    /// Error message string included in error reply BSON documents (`errmsg <str>`).
    pub errmsg: Option<&'a str>,
}
