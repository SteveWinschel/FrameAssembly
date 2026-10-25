//! Real-time Transport Protocol (RTP) (RFC 3550 / RFC 3551 (RTP/AVP Audio and Video Profiles)) Layer 7 AST definitions.
//!
//! This module defines the abstract syntax tree (AST) configuration parameters for synthesizing
//! Real-time Transport Protocol (RTP) packets over UDP port 5004 (or negotiated even UDP media port). On the wire, the protocol uses a 12-byte fixed RTP header: Byte 0 packs 2-bit Version (`V = 2`), 1-bit Padding (`P`), 1-bit Extension (`X`), and 4-bit CSRC Count (`CC`); Byte 1 packs 1-bit Marker (`M`) and 7-bit Payload Type (`PT`, e.g. `0` PCMU/G.711u, `8` PCMA/G.711a, `9` G.722, `18` G.729, `96..127` dynamic Opus/H.264); followed by 16-bit Sequence Number, 32-bit Media Timestamp, and 32-bit Synchronization Source (`SSRC`) identifier.
//! Every field in [`RtpSpec`] is optional so authors can emit zero-configuration default
//! frames or override specific protocol header fields and attributes.
//!
//! Canonical `.fasm` syntax:
//! `a -> b RTP [PT <u8>] [SEQ <u16>] [TIMESTAMP <u32>] [SSRC <u32>] [MARKER <u8>]`

use core::marker::PhantomData;

/// RFC 3550 Real-time Transport Protocol specification.
///
/// Syntax mapping: `RTP [PT <u8>] [SEQ <u16>] [TIMESTAMP <u32>] [SSRC <u32>] [MARKER <u8>]`
#[doc(alias = "RTP")]
#[doc(alias = "RFC 3550")]
#[doc(alias = "RFC3550")]
#[doc(alias = "RFC 3551")]
#[doc(alias = "RFC3551")]
#[doc(alias = "PT")]
#[doc(alias = "SEQ")]
#[doc(alias = "TIMESTAMP")]
#[doc(alias = "SSRC")]
#[doc(alias = "MARKER")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RtpSpec<'a> {
    /// Payload type (0..=127).
    pub pt: Option<u8>,
    /// Sequence number.
    pub seq: Option<u16>,
    /// Timestamp value.
    pub timestamp: Option<u32>,
    /// Synchronization Source identifier.
    pub ssrc: Option<u32>,
    /// Marker bit (0 or 1).
    pub marker: Option<u8>,
    /// Optional phantom reference.
    pub _marker: PhantomData<&'a ()>,
}
