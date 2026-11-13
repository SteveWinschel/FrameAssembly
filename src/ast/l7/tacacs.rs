//! Terminal Access Controller Access-Control System Plus (TACACS+) (RFC 8907) Layer 7 AST definitions.
//!
//! This module defines the abstract syntax tree (AST) configuration parameters for synthesizing
//! Terminal Access Controller Access-Control System Plus (TACACS+) packets over TCP port 49. On the wire, the protocol uses a 12-byte fixed TACACS+ header (8-bit Version byte: 4-bit major 0xC + 4-bit minor 0x0/0x1; 8-bit Type: 1 AUTHEN, 2 AUTHOR, 3 ACCT; 8-bit seq_no; 8-bit flags bitmask e.g. 0x01 TAC_PLUS_UNENCRYPTED_FLAG; 32-bit big-endian session_id; 32-bit big-endian body length) followed by Authentication START/REPLY/CONTINUE, Authorization REQUEST/RESPONSE, or Accounting START/STOP/WATCHDOG body.
//! Every field in [`TacacsSpec`] is optional so authors can emit zero-configuration default
//! frames or override specific protocol header fields and attributes.
//!
//! Canonical `.frasm` syntax:
//! `a -> b tacacs [type authen | type author | type acct | authen | author | acct] [seq <u8>] [flags <u8>] [sessionid <u32>] [user <str>] [data <str>] [payload <str>]`

/// RFC 8907 TACACS+ authentication & authorization specification.
///
/// Syntax mapping: `tacacs [type authen | type author | type acct | authen | author | acct] [seq <u8>] [flags <u8>] [sessionid <u32>] [user <str>] [data <str>] [payload <str>]`
#[doc(alias = "tacacs")]
#[doc(alias = "TACACS_PLUS")]
#[doc(alias = "RFC 8907")]
#[doc(alias = "RFC8907")]
#[doc(alias = "authen")]
#[doc(alias = "author")]
#[doc(alias = "acct")]
#[doc(alias = "seq")]
#[doc(alias = "flags")]
#[doc(alias = "sessionid")]
#[doc(alias = "user")]
#[doc(alias = "data")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TacacsSpec<'a> {
    /// TACACS+ type (`authen`, `author`, `acct`).
    pub tacacs_type: Option<&'a str>,
    /// Sequence number (`seq <u8>`).
    pub seq: Option<u8>,
    /// Flags byte (`flags <u8>`).
    pub flags: Option<u8>,
    /// Session identifier (`sessionid <u32>`).
    pub session_id: Option<u32>,
    /// User name string (`user <str>`).
    pub user: Option<&'a str>,
    /// Optional data payload (`data <str>`).
    pub data: Option<&'a str>,
}
