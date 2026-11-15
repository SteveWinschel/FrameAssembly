//! IEEE 802.1ad Provider Bridges (QinQ) dual VLAN tagging AST definitions.
//!
//! Defines the double 802.1Q tag encapsulation specified in IEEE 802.1ad (incorporated into
//! IEEE 802.1Q-2014) for Metro Ethernet and Service Provider carrier bridging. A QinQ frame
//! inserts an outer 4-byte Service VLAN tag (S-Tag, TPID `0x88A8`) containing the 12-bit
//! `outer_vid` (S-VID) ahead of an inner 4-byte Customer VLAN tag (C-Tag, TPID `0x8100`)
//! containing the 12-bit `inner_vid` (C-VID), followed by the encapsulated payload EtherType.
//!
//! Canonical `.frasm` syntax:
//! `a -> b qinq <outer_vid> [innervlan <inner_vid>] [pcp <0..7>] [dei <0..1>] [<upper_layer_protocol>...]`

/// IEEE 802.1ad QinQ dual VLAN (S-VLAN + C-VLAN) specification.
///
/// Syntax mapping: `qinq <outer_vid> [innervlan <inner_vid>] [pcp <0..7>] [dei <0..1>]`
#[doc(alias = "qinq")]
#[doc(alias = "QinQ")]
#[doc(alias = "802.1ad")]
#[doc(alias = "S-VLAN")]
#[doc(alias = "0x88A8")]
#[doc(alias = "innervlan")]
#[doc(alias = "CVLAN")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct QinqSpec {
    /// Outer (Service Provider S-Tag, TPID `0x88A8`) 12-bit VLAN identifier (`0..=4095`).
    pub outer_vid: u16,
    /// Inner (Customer C-Tag, TPID `0x8100`) 12-bit VLAN identifier (`innervlan <0..=4095>`, default `1`).
    pub inner_vid: Option<u16>,
    /// Outer S-Tag 3-bit IEEE 802.1p Priority Code Point (`pcp <0..=7>`, default `0`).
    pub pcp: Option<u8>,
    /// Outer S-Tag 1-bit Drop Eligible Indicator (`dei <0|1>`, default `0`).
    pub dei: Option<u8>,
}
