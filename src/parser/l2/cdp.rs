//! Cisco Discovery Protocol version 2 (`cdp`) TLV parser for FrameAssembly.
//!
//! This module implements the `winnow` parser combinator for `cdp` IEEE 802.3 LLC/SNAP
//! discovery frames (`0x2000`). It parses CDP header version (`version <u8>`) alongside Type 1
//! through Type 6 and Native VLAN TLVs including Device ID (`deviceid`), management IP address
//! (`addr`), Port ID (`portid`), device Capabilities bitmask (`capabilities`), Software Version
//! (`swversion`), hardware Platform (`platform`), and Native VLAN (`nativevlan`), while `ttl`
//! is handled by the universal L2/L3 modifier parser.

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{
    ParsedField, Stream, parse_any_str, parse_ip, parse_u8, parse_u16, parse_u32, tag,
};

/// Parses a CDP protocol declaration or TLV modifier field.
pub(crate) fn parse_cdp_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        alt((
            tag(Token::Cdp).map(|(_, s)| ParsedField::Protocol(Protocol::Cdp, (s.start, s.len()))),
            (tag(Token::Version), cut_err(parse_u8))
                .map(|((_, s), v)| ParsedField::VersionByte(v, (s.start, s.end - s.start))),
            (tag(Token::DeviceId), cut_err(parse_any_str)).map(|((_, s), v)| {
                ParsedField::L7StringField("CDP_DEVICE_ID", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Addr), cut_err(parse_ip)).map(|((_, s), v)| {
                ParsedField::L7IpField("CDP_ADDR", v, (s.start, s.end - s.start))
            }),
            (tag(Token::PortId), cut_err(parse_any_str)).map(|((_, s), v)| {
                ParsedField::PortIdVal(Some(v), None, (s.start, s.end - s.start))
            }),
        )),
        alt((
            (tag(Token::Capabilities), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("CDP_CAPABILITIES", v, (s.start, s.end - s.start))
            }),
            (tag(Token::SwVersion), cut_err(parse_any_str)).map(|((_, s), v)| {
                ParsedField::L7StringField("CDP_SW_VERSION", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Platform), cut_err(parse_any_str)).map(|((_, s), v)| {
                ParsedField::L7StringField("CDP_PLATFORM", v, (s.start, s.end - s.start))
            }),
            (tag(Token::NativeVlan), cut_err(parse_u16)).map(|((_, s), v)| {
                ParsedField::L7U32Field(
                    "CDP_NATIVE_VLAN",
                    u32::from(v),
                    (s.start, s.end - s.start),
                )
            }),
        )),
    ))
    .parse_next(input)
}
