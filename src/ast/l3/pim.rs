//! Protocol Independent Multicast (PIM) AST definitions.

use core::marker::PhantomData;
use core::net::IpAddr;

/// Protocol Independent Multicast (RFC 7761) specification.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PimSpec<'a> {
    /// Hello message flag.
    pub is_hello: bool,
    /// Join/Prune flag.
    pub is_join_prune: bool,
    /// Register flag.
    pub is_register: bool,
    /// Multicast Group address.
    pub group: Option<IpAddr>,
    /// Source address.
    pub source: Option<IpAddr>,
    /// Rendezvous Point address.
    pub rp: Option<IpAddr>,
    /// Hold time in seconds.
    pub holdtime: Option<u16>,
    /// DR Priority.
    pub dr_priority: Option<u32>,
    /// Optional phantom reference.
    pub _marker: PhantomData<&'a ()>,
}
