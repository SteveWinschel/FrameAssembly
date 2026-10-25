//! IEEE 802.1Q Virtual Local Area Network (VLAN) AST definitions.
//!
//! Defines the 32-bit IEEE 802.1Q VLAN tag inserted between the Ethernet Source MAC address
//! and the payload EtherType. The 4-byte 802.1Q header consists of a 16-bit Tag Protocol
//! Identifier (`TPID = 0x8100`) and a 16-bit Tag Control Information (`TCI`) word packing a
//! 3-bit Priority Code Point (`PCP`, IEEE 802.1p Class of Service `0..=7`), a 1-bit Drop
//! Eligible Indicator (`DEI`, `0..=1`), and a 12-bit VLAN Identifier (`VID`, `1..=4094`).
//!
//! Canonical `.fasm` syntax:
//! `a -> b VLAN <vid> [PCP <0..7>] [DEI <0|1>] [<upper_layer_protocol>...]`

/// IEEE 802.1Q single VLAN tag specification.
///
/// Syntax mapping: `VLAN <vid> [PCP <0..7>] [DEI <0|1>]`
#[doc(alias = "VLAN")]
#[doc(alias = "802.1Q")]
#[doc(alias = "802.1p")]
#[doc(alias = "0x8100")]
#[doc(alias = "PCP")]
#[doc(alias = "DEI")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct VlanSpec {
    /// 12-bit VLAN Identifier (`VLAN <1..=4094>`).
    pub vid: u16,
    /// 3-bit IEEE 802.1p Priority Code Point (`PCP <0..=7>`, default `0`).
    pub pcp: Option<u8>,
    /// 1-bit Drop Eligible Indicator (`DEI <0..=1>`, default `0`).
    pub dei: Option<u8>,
}
