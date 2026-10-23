//! Link Aggregation Control Protocol (LACP) AST definitions.

use core::marker::PhantomData;

/// Link Aggregation Control Protocol (IEEE 802.3ad / 802.1AX) specification.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LacpSpec<'a> {
    /// Actor System MAC address.
    pub actor_sys: Option<[u8; 6]>,
    /// Actor Key.
    pub actor_key: Option<u16>,
    /// Actor Port number.
    pub actor_port: Option<u16>,
    /// Partner System MAC address.
    pub partner_sys: Option<[u8; 6]>,
    /// Partner Key.
    pub partner_key: Option<u16>,
    /// Partner Port number.
    pub partner_port: Option<u16>,
    /// Actor state flags.
    pub actor_state: Option<u8>,
    /// Partner state flags.
    pub partner_state: Option<u8>,
    /// Optional phantom reference.
    pub _marker: PhantomData<&'a ()>,
}
