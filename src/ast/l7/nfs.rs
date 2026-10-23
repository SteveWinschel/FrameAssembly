//! NFS protocol AST definitions.

/// Network File System (NFS) specification.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NfsSpec<'a> {
    /// RPC transaction ID.
    pub xid: Option<u32>,
    /// NFS protocol version (3 or 4).
    pub vers: Option<u32>,
    /// RPC procedure name.
    pub proc_name: Option<&'a str>,
    /// Procedure tag string.
    pub tag: Option<&'a str>,
    /// Export or file path string.
    pub path: Option<&'a str>,
}
