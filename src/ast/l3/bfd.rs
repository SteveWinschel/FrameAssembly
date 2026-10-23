//! Bidirectional Forwarding Detection (BFD) AST definitions.

use core::marker::PhantomData;

/// Bidirectional Forwarding Detection (RFC 5880) specification.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct BfdSpec<'a> {
    /// Session State (0 AdminDown, 1 Down, 2 Init, 3 Up).
    pub state: Option<u8>,
    /// Diagnostic code.
    pub diag: Option<u8>,
    /// My Discriminator.
    pub my_disc: Option<u32>,
    /// Your Discriminator.
    pub your_disc: Option<u32>,
    /// Desired Min TX Interval in microseconds.
    pub min_tx: Option<u32>,
    /// Required Min RX Interval in microseconds.
    pub min_rx: Option<u32>,
    /// Detection Multiplier.
    pub mult: Option<u8>,
    /// Optional phantom reference.
    pub _marker: PhantomData<&'a ()>,
}
