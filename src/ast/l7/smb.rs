//! Server Message Block v2/v3 (SMB2/SMB3, MS-SMB2) Abstract Syntax Tree (AST) definitions.
//!
//! This module defines [`SmbSpec`], the zero-copy AST representation of a Microsoft Server Message
//! Block v2/v3 (`[MS-SMB2]`) packet over TCP port 445 (or NetBIOS Session Service port 139).
//! On the wire, an SMB2 frame begins with a 4-byte NetBIOS stream length prefix followed by a
//! 64-byte SMB2 header (`\xFESMB` magic, StructureSize 64, CreditCharge, NTStatus, Command code,
//! Flags, MessageId, TreeId, SessionId, and 16-byte Signature) and command-specific body structures.
//! Canonical FrameAssembly `.fasm` syntax models SMB2 frames using
//! `SMB [COMMAND <str>] [STATUS <u32>] [TREE_ID <u32>] [SESSION_ID <u64>] [MSGID <u64>] [SHARE <str>] [FILENAME <str>]`.

/// Microsoft Server Message Block v2/v3 (`[MS-SMB2]`) protocol specification.
///
/// Syntax mapping: `SMB [COMMAND <str>] [STATUS <u32>] [TREE_ID <u32>] [SESSION_ID <u64>] [MSGID <u64>] [SHARE <str>] [FILENAME <str>]`
#[doc(alias = "SMB")]
#[doc(alias = "MS-SMB2")]
#[doc(alias = "SMB2")]
#[doc(alias = "SMB3")]
#[doc(alias = "CIFS")]
#[doc(alias = "COMMAND")]
#[doc(alias = "STATUS")]
#[doc(alias = "TREE_ID")]
#[doc(alias = "SESSION_ID")]
#[doc(alias = "MSGID")]
#[doc(alias = "SHARE")]
#[doc(alias = "FILENAME")]
#[doc(alias = "445")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SmbSpec<'a> {
    /// SMB2 command name (`COMMAND <str>`, e.g., `"NEGOTIATE"`, `"SESSION_SETUP"`, `"TREE_CONNECT"`, `"CREATE"`, `"READ"`, `"WRITE"`).
    pub command: Option<&'a str>,
    /// NTSTATUS 32-bit return code (`STATUS <u32>`, default `0` for `STATUS_SUCCESS`).
    pub status: Option<u32>,
    /// 32-bit SMB2 Tree ID identifying a mounted share (`TREE_ID <u32>`).
    pub tree_id: Option<u32>,
    /// 64-bit SMB2 Session ID identifying an authenticated user session (`SESSION_ID <u64>`).
    pub session_id: Option<u64>,
    /// 64-bit SMB2 Message ID sequence counter (`MSGID <u64>`).
    pub msgid: Option<u64>,
    /// UNC share path for `TREE_CONNECT` requests (`SHARE <str>`).
    pub share: Option<&'a str>,
    /// Target file or named pipe path for `CREATE` requests (`FILENAME <str>`).
    pub filename: Option<&'a str>,
}
