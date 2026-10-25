//! Network File System v2/v3/v4 (NFS, RFC 1094 / RFC 1813 / RFC 7530) AST definitions.
//!
//! This module defines [`NfsSpec`], the zero-copy AST representation of a Network File System
//! (NFS) call encapsulated in an ONC RPC v2 (RFC 5531) record-marked message over TCP or UDP port
//! 2049. On the wire, TCP NFS frames carry a 4-byte RPC Record Marking header (with last-fragment
//! bit `0x80000000`), an ONC RPC Call header (XID, Message Type `0`, RPC Version `2`, Program
//! `100003`, NFS Version, Procedure number, and `AUTH_NULL` credentials/verifier), and XDR-encoded
//! compound tags or filehandle paths. Canonical `.fasm` syntax:
//! `NFS [VERS <u32>] [PROC <str>] [TAG <str>] [PATH <str>] [XID <u32>]`.

/// RFC 1813 / RFC 7530 Network File System (NFS) over ONC RPC specification.
///
/// Syntax mapping: `NFS [VERS <u32>] [PROC <str>] [TAG <str>] [PATH <str>] [XID <u32>]`
#[doc(alias = "NFS")]
#[doc(alias = "RFC 7530")]
#[doc(alias = "RFC7530")]
#[doc(alias = "RFC 8881")]
#[doc(alias = "RFC 1813")]
#[doc(alias = "RFC 5531")]
#[doc(alias = "VERS")]
#[doc(alias = "PROC")]
#[doc(alias = "TAG")]
#[doc(alias = "PATH")]
#[doc(alias = "XID")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NfsSpec<'a> {
    /// NFS protocol version number (`VERS <u32>`, e.g., `2`, `3`, or `4`, default `4`).
    pub vers: Option<u32>,
    /// NFS RPC procedure name (`PROC <str>`, e.g., `"NULL"`, `"GETATTR"`, `"LOOKUP"`, `"READ"`, `"WRITE"`, `"COMPOUND"`).
    pub proc_name: Option<&'a str>,
    /// NFSv4 compound operation UTF-8 tag string (`TAG <str>`).
    pub tag: Option<&'a str>,
    /// Export or file path encoded into the XDR call body (`PATH <str>`).
    pub path: Option<&'a str>,
    /// ONC RPC transaction identifier (`XID <u32>`, default `0x12345678`).
    pub xid: Option<u32>,
}
