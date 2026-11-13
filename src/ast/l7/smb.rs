//! Server Message Block v2/v3 (SMB2/SMB3, MS-SMB2) Abstract Syntax Tree (AST) definitions.
//!
//! This module defines [`SmbSpec`], the zero-copy AST representation of a Microsoft Server Message
//! Block v2/v3 (`[MS-SMB2]`) packet over TCP port 445 (or NetBIOS Session Service port 139).
//! On the wire, an SMB2 frame begins with a 4-byte NetBIOS stream length prefix followed by a
//! 64-byte SMB2 header (`\xFESMB` magic, StructureSize 64, CreditCharge, NTStatus, Command code,
//! Flags, MessageId, TreeId, SessionId, and 16-byte Signature) and command-specific body structures.
//! Canonical FrameAssembly `.frasm` syntax models SMB2 frames using
//! `smb [command <str>] [status <u32>] [treeid <u32>] [sessionid <u64>] [msgid <u64>] [share <str>] [filename <str>]`.

/// Microsoft Server Message Block v2/v3 (`[MS-SMB2]`) protocol specification.
///
/// Syntax mapping: `smb [command <str>] [status <u32>] [treeid <u32>] [sessionid <u64>] [msgid <u64>] [share <str>] [filename <str>]`
#[doc(alias = "smb")]
#[doc(alias = "MS-SMB2")]
#[doc(alias = "SMB2")]
#[doc(alias = "SMB3")]
#[doc(alias = "CIFS")]
#[doc(alias = "command")]
#[doc(alias = "status")]
#[doc(alias = "treeid")]
#[doc(alias = "sessionid")]
#[doc(alias = "msgid")]
#[doc(alias = "share")]
#[doc(alias = "filename")]
#[doc(alias = "445")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SmbSpec<'a> {
    /// SMB2 command name (`command <str>`, e.g., `"NEGOTIATE"`, `"SESSION_SETUP"`, `"TREE_CONNECT"`, `"CREATE"`, `"READ"`, `"WRITE"`).
    pub command: Option<&'a str>,
    /// NTSTATUS 32-bit return code (`status <u32>`, default `0` for `STATUS_SUCCESS`).
    pub status: Option<u32>,
    /// 32-bit SMB2 Tree ID identifying a mounted share (`treeid <u32>`).
    pub tree_id: Option<u32>,
    /// 64-bit SMB2 Session ID identifying an authenticated user session (`sessionid <u64>`).
    pub session_id: Option<u64>,
    /// 64-bit SMB2 Message ID sequence counter (`msgid <u64>`).
    pub msgid: Option<u64>,
    /// UNC share path for `treeconnect` requests (`share <str>`).
    pub share: Option<&'a str>,
    /// Target file or named pipe path for `create` requests (`filename <str>`).
    pub filename: Option<&'a str>,
}
