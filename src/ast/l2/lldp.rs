//! Link Layer Discovery Protocol (LLDP, IEEE 802.1AB) AST definitions.
//!
//! Defines the abstract syntax tree parameters for IEEE 802.1AB Link Layer Discovery Protocol
//! Data Units (LLDPDUs) carried in Ethernet frames with EtherType `0x88CC` and nearest-bridge
//! multicast destination MAC `01:80:C2:00:00:0E`. Every LLDPDU encodes a sequence of Type-Length-Value
//! (TLV) structures with a 7-bit TLV Type and 9-bit TLV Information String Length, beginning with
//! mandatory Chassis ID (Type 1), Port ID (Type 2), and Time To Live (Type 3) TLVs, optional
//! System Name (Type 5) and System Description (Type 6) TLVs, and ending with End Of LLDPDU (Type 0).
//!
//! Canonical `.fasm` syntax:
//! `a -> b LLDP [CHASSIS_ID "<str>"] [PORT_ID "<str>"] [TTL <u16>] [SYSNAME "<str>"] [SYSDESC "<str>"]`

/// Link Layer Discovery Protocol (IEEE 802.1AB) frame specification.
///
/// Syntax mapping: `LLDP [CHASSIS_ID "<str>"] [PORT_ID "<str>"] [TTL <u16>] [SYSNAME "<str>"] [SYSDESC "<str>"]`
#[doc(alias = "LLDP")]
#[doc(alias = "802.1AB")]
#[doc(alias = "0x88CC")]
#[doc(alias = "CHASSIS_ID")]
#[doc(alias = "PORT_ID")]
#[doc(alias = "TTL")]
#[doc(alias = "SYSNAME")]
#[doc(alias = "SYSDESC")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LldpSpec<'a> {
    /// Mandatory Chassis ID TLV string (`CHASSIS_ID "<str>"`, Type 1).
    pub chassis_id: Option<&'a str>,
    /// Mandatory Port ID TLV string (`PORT_ID "<str>"`, Type 2).
    pub port_id: Option<&'a str>,
    /// Mandatory Time To Live in seconds (`TTL <u16>`, Type 3, default `120`).
    pub ttl: Option<u16>,
    /// Optional System Name TLV string (`SYSNAME "<str>"`, Type 5).
    pub sysname: Option<&'a str>,
    /// Optional System Description TLV string (`SYSDESC "<str>"`, Type 6).
    pub sysdesc: Option<&'a str>,
}
