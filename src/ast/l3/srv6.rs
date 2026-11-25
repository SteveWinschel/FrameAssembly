//! Segment Routing over IPv6 (SRv6 Segment Routing Header, RFC 8754) AST definitions.
//!
//! Defines [`Srv6Spec`], the abstract syntax tree node for RFC 8754 IPv6 Segment Routing Headers
//! (Routing Type `4`, IPv6 Next Header `43`). On the wire, the SRH carries an 8-bit `Next Header`
//! (`nextheader`), 8-bit `Hdr Ext Len`, `Routing Type = 4`, `Segments Left` (`segleft`), `Last Entry`,
//! 8-bit `Flags` (`flags`), 16-bit `Tag` (`tag`), and an ordered list of 128-bit IPv6 Segment IDs
//! (`sid <ipv6>`, repeatable) representing the source-routed SRv6 segment path.
//!
//! Canonical `.frasm` syntax:
//! `a -> b srv6 [nextheader <u8>] [segleft <u8>] [flags <u8>] [tag <u16>] [sid <ipv6>]...`

use alloc::vec::Vec;
use core::marker::PhantomData;
use core::net::IpAddr;

/// Segment Routing over IPv6 (SRv6 SRH, RFC 8754) specification over IPv6 Next Header `43`.
///
/// Syntax mapping: `srv6 [nextheader <u8>] [segleft <u8>] [flags <u8>] [tag <u16>] [sid <ipv6>]...`
#[doc(alias = "srv6")]
#[doc(alias = "SRH")]
#[doc(alias = "RFC 8754")]
#[doc(alias = "RFC8754")]
#[doc(alias = "nextheader")]
#[doc(alias = "segleft")]
#[doc(alias = "flags")]
#[doc(alias = "tag")]
#[doc(alias = "sid")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Srv6Spec<'a> {
    /// Upper-layer Next Header protocol number after the SRH (`nextheader <u8>`, default `59` empty or `253` with payload).
    pub next_header: Option<u8>,
    /// Active Segments Left index (`segleft <u8>`, defaults to `sids.len().saturating_sub(1)`).
    pub seg_left: Option<u8>,
    /// 8-bit SRH Flags field (`flags <u8>`, default `0`).
    pub flags: Option<u8>,
    /// 16-bit SRH Tag field (`tag <u16>`, default `0`).
    pub tag: Option<u16>,
    /// Ordered list of 128-bit IPv6 Segment Identifiers (`sid <ipv6>`, repeatable).
    pub sids: Vec<IpAddr>,
    /// Optional lifetime phantom marker for AST uniformity.
    pub _marker: PhantomData<&'a ()>,
}
