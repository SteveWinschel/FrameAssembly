//! SMB protocol AST definitions.

/// Server Message Block (SMB2/3) specification.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SmbSpec<'a> {
    /// SMB2 command name (e.g. NEGOTIATE, CREATE).
    pub command: Option<&'a str>,
    /// NT status code.
    pub status: Option<u32>,
    /// Message ID.
    pub msgid: Option<u64>,
    /// Tree ID.
    pub tree_id: Option<u32>,
    /// Session ID.
    pub session_id: Option<u64>,
    /// Share name string.
    pub share: Option<&'a str>,
    /// File name string.
    pub filename: Option<&'a str>,
}
