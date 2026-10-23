//! WireGuard Secure Network Tunnel AST definitions.

use core::marker::PhantomData;

/// WireGuard packet type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireguardType {
    /// Handshake Initiation (1)
    Initiation,
    /// Handshake Response (2)
    Response,
    /// Cookie Reply (3)
    Cookie,
    /// Transport Data (4)
    Data,
}

/// WireGuard VPN protocol specification.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct WireguardSpec<'a> {
    /// Message Type.
    pub msg_type: Option<WireguardType>,
    /// Sender index.
    pub sender: Option<u32>,
    /// Receiver index.
    pub receiver: Option<u32>,
    /// Counter value.
    pub counter: Option<u64>,
    /// Optional phantom reference.
    pub _marker: PhantomData<&'a ()>,
}
