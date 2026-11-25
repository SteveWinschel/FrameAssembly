//! Point-to-Point Protocol over Ethernet (PPPoE, RFC 2516) AST definitions.
//!
//! Defines the abstract syntax tree structures for RFC 2516 Point-to-Point Protocol over Ethernet
//! (`pppoe`) across both the PPPoE Discovery Stage (`EtherType = 0x8863`) and the PPPoE Session
//! Stage (`EtherType = 0x8864`). Discovery frames support `padi` (`0x09`), `pado` (`0x07`),
//! `padr` (`0x19`), `pads` (`0x65`), and `padt` (`0xA7`) codes with `Service-Name` (`0x0101`),
//! `AC-Name` (`0x0102`), `Host-Uniq` (`0x0103`), and `AC-Cookie` (`0x0104`) tags, while `session`
//! frames (`0x00`) encapsulate PPP payloads such as LCP (`0xC021`) or IPv4 (`0x0021`).
//!
//! Canonical `.frasm` syntax:
//! `a -> b pppoe [padi | pado | padr | pads | padt | session] [sessionid <u16>] [servicename "<str>"] [acname "<str>"] [hostuniq "<hex>"] [accookie "<hex>"] [pppproto <u16>]`

use alloc::vec::Vec;

/// RFC 2516 PPPoE protocol stage and Discovery Code (`Code` field at byte offset 1).
#[doc(alias = "RFC 2516")]
#[doc(alias = "0x8863")]
#[doc(alias = "0x8864")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PppoeStage {
    /// PPPoE Active Discovery Initiation (`0x09` over `0x8863`, broadcast destination).
    Padi,
    /// PPPoE Active Discovery Offer (`0x07` over `0x8863`).
    Pado,
    /// PPPoE Active Discovery Request (`0x19` over `0x8863`).
    Padr,
    /// PPPoE Active Discovery Session-confirmation (`0x65` over `0x8863`).
    Pads,
    /// PPPoE Active Discovery Terminate (`0xA7` over `0x8863`).
    Padt,
    /// PPPoE Session Data (`0x00` over `0x8864`, carrying encapsulated PPP frames).
    Session,
}

/// Point-to-Point Protocol over Ethernet (RFC 2516) frame specification.
///
/// Syntax mapping: `pppoe [padi | pado | padr | pads | padt | session] [sessionid <u16>] [servicename "<str>"] [acname "<str>"] [hostuniq "<hex>"] [accookie "<hex>"] [pppproto <u16>]`
#[doc(alias = "pppoe")]
#[doc(alias = "RFC 2516")]
#[doc(alias = "0x8863")]
#[doc(alias = "0x8864")]
#[doc(alias = "padi")]
#[doc(alias = "pado")]
#[doc(alias = "padr")]
#[doc(alias = "pads")]
#[doc(alias = "padt")]
#[doc(alias = "session")]
#[doc(alias = "sessionid")]
#[doc(alias = "servicename")]
#[doc(alias = "acname")]
#[doc(alias = "hostuniq")]
#[doc(alias = "accookie")]
#[doc(alias = "pppproto")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PppoeSpec<'a> {
    /// PPPoE Discovery code or Session stage (`padi`, `pado`, `padr`, `pads`, `padt`, `session`).
    pub stage: Option<PppoeStage>,
    /// 16-bit PPPoE Session ID (`sessionid <u16>`, default `0` for PADI/PADO/PADR, `1` for PADS/PADT/session).
    pub session_id: Option<u16>,
    /// Service-Name TLV (`0x0101`, `servicename "<str>"`, default `""` on PADI/PADO/PADR/PADS).
    pub service_name: Option<&'a str>,
    /// Access Concentrator Name TLV (`0x0102`, `acname "<str>"`, default `"ac01"` on PADO).
    pub ac_name: Option<&'a str>,
    /// Host-Uniq opaque binary cookie TLV (`0x0103`, `hostuniq "<hex>"`).
    pub host_uniq: Option<Vec<u8>>,
    /// AC-Cookie opaque binary token TLV (`0x0104`, `accookie "<hex>"`).
    pub ac_cookie: Option<Vec<u8>>,
    /// Encapsulated 16-bit PPP Protocol ID when in `session` stage (`pppproto <u16>`, default `0xC021` LCP).
    pub ppp_proto: Option<u16>,
}
