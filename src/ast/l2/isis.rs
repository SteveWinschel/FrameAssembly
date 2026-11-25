//! Intermediate System to Intermediate System (IS-IS, ISO/IEC 10589) AST definitions.
//!
//! Defines the abstract syntax tree structures for ISO/IEC 10589 / RFC 1142 Intermediate System
//! to Intermediate System (`isis`) routing Protocol Data Units encapsulated over IEEE 802.3
//! Ethernet with an ISO CLNS 802.2 LLC header (`DSAP = 0xFE`, `SSAP = 0xFE`, `Control = 0x03`).
//! Every PDU begins with the 8-byte Common Header (`IRPD = 0x83`, `Length Indicator`, `Version = 1`)
//! followed by Level 1/2 LAN IIH (`0x0F`/`0x10`), Point-to-Point IIH (`0x11`), L1/L2 LSP
//! (`0x12`/`0x14`), L1/L2 CSNP (`0x18`/`0x19`), or L1/L2 PSNP (`0x1A`/`0x1B`) headers and TLVs.
//!
//! Canonical `.frasm` syntax:
//! `a -> b isis [l1iih | l2iih | p2piih | l1lsp | l2lsp | l1csnp | l2csnp | l1psnp | l2psnp] [sysid "<str>"] [area "<str>"] [holdtime <u16>] [priority <u8>] [lanid "<str>"] [circuittype <u8>] [lifetime <u16>] [seqnum <u32>] [hostname "<str>"]`

/// ISO/IEC 10589 IS-IS Protocol Data Unit (PDU) type discriminator (`byte 4 & 0x1F`).
#[doc(alias = "ISO 10589")]
#[doc(alias = "CLNS")]
#[doc(alias = "IIH")]
#[doc(alias = "LSP")]
#[doc(alias = "CSNP")]
#[doc(alias = "PSNP")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IsisPduType {
    /// Level 1 LAN IS-to-IS Hello PDU (`0x0F`, header length 27, AllL1ISs `01:80:C2:00:00:14`).
    L1Iih,
    /// Level 2 LAN IS-to-IS Hello PDU (`0x10`, header length 27, AllL2ISs `01:80:C2:00:00:15`).
    L2Iih,
    /// Point-to-Point IS-to-IS Hello PDU (`0x11`, header length 20).
    P2pIih,
    /// Level 1 Link State PDU (`0x12`, header length 27, Fletcher-16 checksummed).
    L1Lsp,
    /// Level 2 Link State PDU (`0x14`, header length 27, Fletcher-16 checksummed).
    L2Lsp,
    /// Level 1 Complete Sequence Numbers PDU (`0x18`, header length 33).
    L1Csnp,
    /// Level 2 Complete Sequence Numbers PDU (`0x19`, header length 33).
    L2Csnp,
    /// Level 1 Partial Sequence Numbers PDU (`0x1A`, header length 17).
    L1Psnp,
    /// Level 2 Partial Sequence Numbers PDU (`0x1B`, header length 17).
    L2Psnp,
}

/// ISO/IEC 10589 IS-IS routing protocol frame specification.
///
/// Syntax mapping: `isis [l1iih | l2iih | p2piih | l1lsp | l2lsp | l1csnp | l2csnp | l1psnp | l2psnp] [sysid "<str>"] [area "<str>"] [holdtime <u16>] [priority <u8>] [lanid "<str>"] [circuittype <u8>] [lifetime <u16>] [seqnum <u32>] [hostname "<str>"]`
#[doc(alias = "isis")]
#[doc(alias = "ISO 10589")]
#[doc(alias = "RFC 1142")]
#[doc(alias = "0x83")]
#[doc(alias = "l1iih")]
#[doc(alias = "l2iih")]
#[doc(alias = "p2piih")]
#[doc(alias = "l1lsp")]
#[doc(alias = "l2lsp")]
#[doc(alias = "l1csnp")]
#[doc(alias = "l2csnp")]
#[doc(alias = "l1psnp")]
#[doc(alias = "l2psnp")]
#[doc(alias = "sysid")]
#[doc(alias = "area")]
#[doc(alias = "holdtime")]
#[doc(alias = "priority")]
#[doc(alias = "lanid")]
#[doc(alias = "circuittype")]
#[doc(alias = "lifetime")]
#[doc(alias = "seqnum")]
#[doc(alias = "hostname")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct IsisSpec<'a> {
    /// IS-IS PDU type (`l1iih`, `l2iih`, `p2piih`, `l1lsp`, `l2lsp`, `l1csnp`, `l2csnp`, `l1psnp`, `l2psnp`).
    pub pdu_type: Option<IsisPduType>,
    /// 6-octet IS-IS System ID (`sysid "<str>"`, e.g., `"0200.0000.0001"`).
    pub sys_id: Option<&'a str>,
    /// Area Address hex string encoded in TLV 1 (`area "<str>"`, default `"49.0001"`).
    pub area: Option<&'a str>,
    /// Holding Timer in seconds for Hello PDUs (`holdtime <u16>`, default `30`).
    pub hold_time: Option<u16>,
    /// DIS election Priority for LAN Hello PDUs (`priority <0..=127>`, default `64`).
    pub priority: Option<u8>,
    /// 7-octet LAN ID (`6B System ID + 1B Pseudonode ID`) for LAN IIH (`lanid "<str>"`).
    pub lan_id: Option<&'a str>,
    /// Circuit Type byte (`1` = L1, `2` = L2, `3` = L1/L2) for IIH PDUs (`circuittype <u8>`).
    pub circuit_type: Option<u8>,
    /// Remaining Lifetime in seconds for LSP PDUs (`lifetime <u16>`, default `1200`).
    pub lifetime: Option<u16>,
    /// 32-bit Sequence Number for LSP PDUs (`seqnum <u32>`, default `1`).
    pub seq_num: Option<u32>,
    /// Optional Dynamic Hostname string encoded in RFC 5301 TLV 137 (`hostname "<str>"`).
    pub hostname: Option<&'a str>,
}
