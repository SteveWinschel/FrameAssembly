//! Spanning Tree Protocol (STP / RSTP, IEEE 802.1D / IEEE 802.1w) AST definitions.
//!
//! Defines Bridge Protocol Data Unit (BPDU) parameters for classic IEEE 802.1D Spanning Tree
//! Protocol (`Protocol Version = 0x00`, `BPDU Type = 0x00`) and IEEE 802.1w Rapid Spanning Tree
//! Protocol (`Protocol Version = 0x02`, `BPDU Type = 0x02`). STP frames are encapsulated in
//! IEEE 802.3 Ethernet frames addressed to the Bridge Group Address `01:80:C2:00:00:00` with
//! an IEEE 802.2 Logical Link Control (LLC) header (`DSAP = 0x42`, `SSAP = 0x42`, `Control = 0x03`)
//! and a 35-byte Configuration BPDU payload.
//!
//! Canonical `.fasm` syntax:
//! `a -> b [STP | RSTP] [ROOT_ID "<str>"] [BRIDGE_ID "<str>"] [PORT_ID <u16>] [COST <u32>] [MAX_AGE <u16>] [HELLO_TIME <u16>] [FORWARD_DELAY <u16>] [FLAGS <u8>]`

/// Spanning Tree Protocol (IEEE 802.1D / IEEE 802.1w) BPDU specification.
///
/// Syntax mapping: `[STP | RSTP] [ROOT_ID "<str>"] [BRIDGE_ID "<str>"] [PORT_ID <u16>] [COST <u32>] [MAX_AGE <u16>] [HELLO_TIME <u16>] [FORWARD_DELAY <u16>] [FLAGS <u8>]`
#[doc(alias = "STP")]
#[doc(alias = "RSTP")]
#[doc(alias = "802.1D")]
#[doc(alias = "802.1w")]
#[doc(alias = "BPDU")]
#[doc(alias = "ROOT_ID")]
#[doc(alias = "BRIDGE_ID")]
#[doc(alias = "PORT_ID")]
#[doc(alias = "COST")]
#[doc(alias = "MAX_AGE")]
#[doc(alias = "HELLO_TIME")]
#[doc(alias = "FORWARD_DELAY")]
#[doc(alias = "FLAGS")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct StpSpec<'a> {
    /// 64-bit Root Bridge Identifier string representation (`ROOT_ID "<str>"`).
    pub root_id: Option<&'a str>,
    /// 64-bit Transmitting Bridge Identifier string representation (`BRIDGE_ID "<str>"`).
    pub bridge_id: Option<&'a str>,
    /// 16-bit Port Identifier combining 8-bit priority and 8-bit port number (`PORT_ID <u16>`).
    pub port_id: Option<u16>,
    /// 32-bit Root Path Cost (`COST <u32>`).
    pub cost: Option<u32>,
    /// Max Age timer in whole seconds (`MAX_AGE <u16>`, encoded on wire in 1/256s units, default `20`).
    pub max_age: Option<u16>,
    /// Hello Time timer in whole seconds (`HELLO_TIME <u16>`, encoded on wire in 1/256s units, default `2`).
    pub hello_time: Option<u16>,
    /// Forward Delay timer in whole seconds (`FORWARD_DELAY <u16>`, encoded on wire in 1/256s units, default `15`).
    pub forward_delay: Option<u16>,
    /// 8-bit BPDU Flags bitmask (`FLAGS <u8>`: TC, Proposal, Port Role, Learning, Forwarding, Agreement, TCA).
    pub flags: Option<u8>,
    /// Selects IEEE 802.1w Rapid Spanning Tree (`RSTP`, Version 2, BPDU Type `0x02`) when `true`.
    pub is_rstp: bool,
}
