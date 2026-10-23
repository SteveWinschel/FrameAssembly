//! IEEE 802.1Q Virtual LAN (VLAN) AST definitions.

/// IEEE 802.1Q VLAN specification.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct VlanSpec {
    /// 12-bit VLAN identifier (1..=4094).
    pub vid: u16,
    /// 3-bit Priority Code Point (0..=7).
    pub pcp: Option<u8>,
    /// 1-bit Drop Eligible Indicator (0..=1).
    pub dei: Option<u8>,
}
