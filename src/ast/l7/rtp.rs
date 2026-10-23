//! RTP protocol AST definitions.

use core::marker::PhantomData;

/// RFC 3550 Real-time Transport Protocol specification.
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
