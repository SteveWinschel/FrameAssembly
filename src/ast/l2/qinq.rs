//! IEEE 802.1ad Provider Bridging (QinQ) AST definitions.

/// IEEE 802.1ad QinQ dual VLAN specification.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct QinqSpec {
    /// Outer (service) 12-bit VLAN identifier.
    pub outer_vid: u16,
    /// Inner (customer) 12-bit VLAN identifier.
    pub inner_vid: Option<u16>,
}
