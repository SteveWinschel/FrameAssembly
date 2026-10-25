//! IEEE 802.1ad Provider Bridges (QinQ) dual VLAN tagging AST definitions.
//!
//! Defines the double 802.1Q tag encapsulation specified in IEEE 802.1ad (incorporated into
//! IEEE 802.1Q-2014) for Metro Ethernet and Service Provider carrier bridging. A QinQ frame
//! inserts an outer 4-byte Service VLAN tag (S-Tag, TPID `0x88A8`) containing the 12-bit
//! `outer_vid` (S-VID) ahead of an inner 4-byte Customer VLAN tag (C-Tag, TPID `0x8100`)
//! containing the 12-bit `inner_vid` (C-VID), followed by the encapsulated payload EtherType.
//!
//! Canonical `.fasm` syntax:
//! `a -> b QINQ <outer_vid> [INNER_VLAN <inner_vid>] [<upper_layer_protocol>...]`

/// IEEE 802.1ad QinQ dual VLAN (S-VLAN + C-VLAN) specification.
///
/// Syntax mapping: `QINQ <outer_vid> [INNER_VLAN <inner_vid>]`
#[doc(alias = "QINQ")]
#[doc(alias = "QinQ")]
#[doc(alias = "802.1ad")]
#[doc(alias = "S-VLAN")]
#[doc(alias = "0x88A8")]
#[doc(alias = "INNER_VLAN")]
#[doc(alias = "CVLAN")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct QinqSpec {
    /// Outer (Service Provider S-Tag, TPID `0x88A8`) 12-bit VLAN identifier (`1..=4094`).
    pub outer_vid: u16,
    /// Inner (Customer C-Tag, TPID `0x8100`) 12-bit VLAN identifier (`INNER_VLAN <1..=4094>`).
    pub inner_vid: Option<u16>,
}
