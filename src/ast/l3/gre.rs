//! Generic Routing Encapsulation (GRE, RFC 2784 / RFC 2890) AST definitions.
//!
//! Defines the multiprotocol IP-in-IP and Layer 2 overlay tunneling header specified in RFC 2784 and
//! extended with Key and Sequence Number fields in RFC 2890 over IP protocol `47` (`0x2F`). The GRE
//! header begins with a 16-bit Flags and Version word (`C` Checksum bit `0x8000`, `K` Key bit `0x2000`,
//! `S` Sequence bit `0x1000`, Version `0`) followed by a 16-bit IEEE EtherType `Protocol Type`
//! (`greproto`, default `0x0800` IPv4, `0x6558` NVGRE TEB, `0x88BE` ERSPAN, `0x8847` MPLS) and
//! optional 32-bit Checksum/Reserved (`checksum`), Key (`grekey`), and Sequence (`greseq`) words.
//!
//! Canonical `.frasm` syntax:
//! `a -> b gre [grekey <u32>] [greseq <u32>] [greproto <u16>] [checksum] [payload "<str>" | hexpayload "<hex>"]`

use core::marker::PhantomData;

/// Generic Routing Encapsulation (RFC 2784 / RFC 2890) specification over IP protocol `47`.
///
/// Syntax mapping: `gre [grekey <u32>] [greseq <u32>] [greproto <u16>] [checksum]`
#[doc(alias = "gre")]
#[doc(alias = "RFC 2784")]
#[doc(alias = "RFC2784")]
#[doc(alias = "RFC 2890")]
#[doc(alias = "RFC2890")]
#[doc(alias = "NVGRE")]
#[doc(alias = "ERSPAN")]
#[doc(alias = "grekey")]
#[doc(alias = "greseq")]
#[doc(alias = "greproto")]
#[doc(alias = "checksum")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct GreSpec<'a> {
    /// Optional 32-bit RFC 2890 GRE Key / VSID field (`grekey <u32>`, sets `K` flag `0x2000`).
    pub key: Option<u32>,
    /// Optional 32-bit RFC 2890 Sequence Number field (`greseq <u32>`, sets `S` flag `0x1000`).
    pub seq: Option<u32>,
    /// 16-bit IEEE EtherType of the encapsulated passenger protocol (`greproto <u16>`, default `0x0800`).
    pub proto: Option<u16>,
    /// RFC 2784 Checksum Present flag (`checksum`, sets `C` flag `0x8000` and inserts 32-bit Checksum/Reserved word).
    pub checksum: bool,
    /// Optional lifetime phantom marker for AST uniformity.
    pub _marker: PhantomData<&'a ()>,
}
