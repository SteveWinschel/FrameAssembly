//! Spanning Tree Protocol (STP / RSTP) AST definitions.

/// Spanning Tree Protocol (IEEE 802.1D / 802.1w) specification.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct StpSpec<'a> {
    /// Root Bridge ID.
    pub root_id: Option<&'a str>,
    /// Bridge ID.
    pub bridge_id: Option<&'a str>,
    /// Port identifier.
    pub port_id: Option<u16>,
    /// Root path cost.
    pub cost: Option<u32>,
    /// Max age in seconds.
    pub max_age: Option<u16>,
    /// Hello time in seconds.
    pub hello_time: Option<u16>,
    /// Forward delay in seconds.
    pub forward_delay: Option<u16>,
    /// BPDU flags.
    pub flags: Option<u8>,
    /// Rapid Spanning Tree Protocol flag.
    pub is_rstp: bool,
}
