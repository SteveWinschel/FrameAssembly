//! Spanning Tree Protocol (STP / RSTP, IEEE 802.1D / IEEE 802.1w) AST definitions.
//!
//! Defines Bridge Protocol Data Unit (BPDU) parameters for classic IEEE 802.1D Spanning Tree
//! Protocol (`Protocol Version = 0x00`, `BPDU Type = 0x00`) and IEEE 802.1w Rapid Spanning Tree
//! Protocol (`Protocol Version = 0x02`, `BPDU Type = 0x02`). STP frames are encapsulated in
//! IEEE 802.3 Ethernet frames addressed to the Bridge Group Address `01:80:C2:00:00:00` with
//! an IEEE 802.2 Logical Link Control (LLC) header (`DSAP = 0x42`, `SSAP = 0x42`, `Control = 0x03`)
//! and a 35-byte Configuration BPDU payload.
//!
//! Canonical `.frasm` syntax:
//! `a -> b [stp | rstp] [rootid "<str>"] [bridgeid "<str>"] [portid <u16>] [cost <u32>] [maxage <u16>] [hellotime <u16>] [forwarddelay <u16>] [flags <u8>]`

/// Spanning Tree Protocol (IEEE 802.1D / IEEE 802.1w) BPDU specification.
///
/// Syntax mapping: `[stp | rstp] [rootid "<str>"] [bridgeid "<str>"] [portid <u16>] [cost <u32>] [maxage <u16>] [hellotime <u16>] [forwarddelay <u16>] [flags <u8>]`
#[doc(alias = "stp")]
#[doc(alias = "rstp")]
#[doc(alias = "802.1D")]
#[doc(alias = "802.1w")]
#[doc(alias = "BPDU")]
#[doc(alias = "rootid")]
#[doc(alias = "bridgeid")]
#[doc(alias = "portid")]
#[doc(alias = "cost")]
#[doc(alias = "maxage")]
#[doc(alias = "hellotime")]
#[doc(alias = "forwarddelay")]
#[doc(alias = "flags")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct StpSpec<'a> {
    /// 64-bit Root Bridge Identifier string representation (`rootid "<str>"`).
    pub root_id: Option<&'a str>,
    /// 64-bit Transmitting Bridge Identifier string representation (`bridgeid "<str>"`).
    pub bridge_id: Option<&'a str>,
    /// 16-bit Port Identifier combining 8-bit priority and 8-bit port number (`portid <u16>`).
    pub port_id: Option<u16>,
    /// 32-bit Root Path Cost (`cost <u32>`).
    pub cost: Option<u32>,
    /// Max Age timer in whole seconds (`maxage <u16>`, encoded on wire in 1/256s units, default `20`).
    pub max_age: Option<u16>,
    /// Hello Time timer in whole seconds (`hellotime <u16>`, encoded on wire in 1/256s units, default `2`).
    pub hello_time: Option<u16>,
    /// Forward Delay timer in whole seconds (`forwarddelay <u16>`, encoded on wire in 1/256s units, default `15`).
    pub forward_delay: Option<u16>,
    /// 8-bit BPDU Flags bitmask (`flags <u8>`: TC, Proposal, Port Role, Learning, Forwarding, Agreement, TCA).
    pub flags: Option<u8>,
    /// Selects IEEE 802.1w Rapid Spanning Tree (`rstp`, Version 2, BPDU Type `0x02`) when `true`.
    pub is_rstp: bool,
}
