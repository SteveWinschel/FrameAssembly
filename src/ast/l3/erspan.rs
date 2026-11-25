//! Encapsulated Remote Switch Port Analyzer (ERSPAN Type II & III) AST definitions.
//!
//! Defines [`ErspanSpec`] for Cisco Encapsulated Remote SPAN traffic mirrored over GRE (IP
//! protocol `47`) using GRE EtherType `0x88BE` for ERSPAN Type II (`v2`, default) or `0x22EB` for
//! ERSPAN Type III (`v3`). Supports 10-bit monitor `sessionid`, 12-bit original mirrored `vid`,
//! 3-bit Class of Service (`cos`), 32-bit GRE sequence number (`greseq`), Type II 20-bit port
//! `index`, and Type III 32-bit `timestamp` and egress/ingress `direction`.
//!
//! Canonical `.frasm` syntax:
//! `a -> b erspan [v2 | v3 | version <2|3>] [sessionid <u16>] [vid <u16>] [cos <u8>] [greseq <u32>] [index <u32>] [timestamp <u32>] [direction <0|1>]`

use core::marker::PhantomData;

/// Encapsulated Remote SPAN (ERSPAN Type II `0x88BE` / Type III `0x22EB`) specification over GRE (`47`).
///
/// Syntax mapping: `erspan [v2 | v3 | version <2|3>] [sessionid <u16>] [vid <u16>] [cos <u8>] [greseq <u32>] [index <u32>] [timestamp <u32>] [direction <0|1>]`
#[doc(alias = "erspan")]
#[doc(alias = "SPAN")]
#[doc(alias = "0x88BE")]
#[doc(alias = "0x22EB")]
#[doc(alias = "v2")]
#[doc(alias = "v3")]
#[doc(alias = "version")]
#[doc(alias = "sessionid")]
#[doc(alias = "vid")]
#[doc(alias = "cos")]
#[doc(alias = "greseq")]
#[doc(alias = "index")]
#[doc(alias = "timestamp")]
#[doc(alias = "direction")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ErspanSpec<'a> {
    /// ERSPAN protocol version (`2` for Type II `0x88BE` default, `3` for Type III `0x22EB`).
    pub version: Option<u8>,
    /// 10-bit ERSPAN monitor session identifier (`sessionid <0..1023>`, default `1`).
    pub session_id: Option<u16>,
    /// 12-bit mirrored frame original VLAN ID (`vid <0..4095>`, default `0`).
    pub vid: Option<u16>,
    /// 3-bit Class of Service value (`cos <0..7>`, default `0`).
    pub cos: Option<u8>,
    /// 32-bit GRE sequence number (`greseq <u32>`, default `1`).
    pub gre_seq: Option<u32>,
    /// 20-bit ERSPAN Type II port index (`index <0..1048575>`, default `0`).
    pub index: Option<u32>,
    /// 32-bit ERSPAN Type III timestamp (`timestamp <u32>`, default `0`).
    pub timestamp: Option<u32>,
    /// ERSPAN Type III traffic direction bit (`direction <0|1>`, `0` ingress / `1` egress, default `0`).
    pub direction: Option<u8>,
    /// Optional lifetime phantom marker for AST uniformity.
    pub _marker: PhantomData<&'a ()>,
}
