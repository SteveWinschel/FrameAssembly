//! Remote Desktop Protocol (`rdp`, MS-RDPBCGR over RFC 1006 TPKT + X.224 COTP) Layer 7 AST definitions.
//!
//! This module defines the zero-copy Abstract Syntax Tree (AST) configuration parameters for
//! synthesizing Microsoft Remote Desktop Protocol (`[MS-RDPBCGR]`) session establishment frames
//! over TCP port 3389. On the wire, packets encapsulate a 4-byte RFC 1006 TPKT header
//! (`0x03 0x00 len`) and ISO 8073 X.224 COTP PDU around X.224 Connection Request (`x224cr` with
//! optional `Cookie: mstshash=...` and `RDP_NEG_REQ`), Connection Confirm (`x224cc` with
//! `RDP_NEG_RSP`), or T.125 MCS `Connect-Initial` (`mcs` with GCC and `CS_CORE` desktop geometry).
//! Canonical `.frasm` syntax:
//! `a -> b rdp [x224cr | x224cc | mcs] [msgtype <str>] [cookie <str>] [proto <u32>] [flags <u8>] [sessionid <u16>] [width <u16>] [height <u16>]`.

/// Microsoft Remote Desktop Protocol (`[MS-RDPBCGR]`) Layer 7 protocol specification.
///
/// Syntax mapping: `rdp [x224cr | x224cc | mcs] [msgtype <str>] [cookie <str>] [proto <u32>] [flags <u8>] [sessionid <u16>] [width <u16>] [height <u16>]`
#[doc(alias = "rdp")]
#[doc(alias = "MS-RDPBCGR")]
#[doc(alias = "TPKT")]
#[doc(alias = "X224")]
#[doc(alias = "MCS")]
#[doc(alias = "x224cr")]
#[doc(alias = "x224cc")]
#[doc(alias = "mcs")]
#[doc(alias = "msgtype")]
#[doc(alias = "cookie")]
#[doc(alias = "proto")]
#[doc(alias = "flags")]
#[doc(alias = "sessionid")]
#[doc(alias = "width")]
#[doc(alias = "height")]
#[doc(alias = "3389")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RdpSpec<'a> {
    /// RDP handshake stage (`x224cr`, `x224cc`, `mcs`, or explicit `msgtype <str>`).
    pub msg_type: Option<&'a str>,
    /// Routing cookie / username (`cookie <str>`, emitted as `Cookie: mstshash=<cookie>` on `x224cr` or `clientName` on `mcs`).
    pub cookie: Option<&'a str>,
    /// Requested or selected RDP security protocol bitmask (`proto <u32>`, e.g., `1` TLS, `2` CredSSP/NLA, `3` TLS|NLA).
    pub proto: Option<u32>,
    /// 8-bit RDP Negotiation Request/Response flags (`flags <u8>`).
    pub flags: Option<u8>,
    /// 16-bit X.224 COTP source connection reference (`sessionid <u16>`).
    pub session_id: Option<u16>,
    /// Client desktop width in pixels for `mcs` Client Core Data (`width <u16>`, default `1024`).
    pub width: Option<u16>,
    /// Client desktop height in pixels for `mcs` Client Core Data (`height <u16>`, default `768`).
    pub height: Option<u16>,
}
