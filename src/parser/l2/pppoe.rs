//! Point-to-Point Protocol over Ethernet (`pppoe`, RFC 2516) Discovery and Session parser.
//!
//! This module implements the `winnow` parser combinator for RFC 2516 `pppoe` frames across both
//! Discovery (`0x8863`) and Session (`0x8864`) stages. It supports `padi`, `pado`, `padr`, `pads`,
//! `padt`, and `session` stage keywords (with optional `type` prefix), 16-bit Session IDs
//! (`sessionid`), Discovery tags (`servicename`, `acname`, `hostuniq`, `accookie`), and
//! encapsulated PPP protocol numbers (`pppproto <u16>` or named shorthands `lcp`/`ipcp`/`ipv4`/`ipv6`).

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err, opt};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{
    ParsedField, Stream, parse_any_str, parse_hex_bytes, parse_str_val, parse_u16, tag,
};

/// Resolves a named PPP protocol shorthand (`lcp`, `ipcp`, `ipv4`, `ipv6`, `pap`, `chap`) to its 16-bit ID.
fn parse_ppp_proto_name<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<u16> {
    parse_str_val
        .verify_map(|s| match s.to_ascii_lowercase().as_str() {
            "lcp" => Some(0xC021),
            "pap" => Some(0xC023),
            "chap" => Some(0xC223),
            "ipcp" => Some(0x8021),
            "ipv6cp" => Some(0x8057),
            "ipv4" | "ip" => Some(0x0021),
            "ipv6" => Some(0x0057),
            _ => None,
        })
        .parse_next(input)
}

/// Parses a PPPoE Discovery code or Session stage keyword (with optional leading `type`).
fn parse_pppoe_stage<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    let (opt_t, (val, s2)) = (
        opt(tag(Token::Type)),
        alt((
            tag(Token::Padi).map(|(_, s)| ("PADI", s)),
            tag(Token::Pado).map(|(_, s)| ("PADO", s)),
            tag(Token::Padr).map(|(_, s)| ("PADR", s)),
            tag(Token::Pads).map(|(_, s)| ("PADS", s)),
            tag(Token::Padt).map(|(_, s)| ("PADT", s)),
            tag(Token::Session).map(|(_, s)| ("SESSION", s)),
        )),
    )
        .parse_next(input)?;
    let start = opt_t.map(|(_, s1)| s1.start).unwrap_or(s2.start);
    Ok(ParsedField::L7StringField(
        "PPPOE_STAGE",
        val,
        (start, s2.end - start),
    ))
}

/// Parses a PPPoE protocol declaration, Discovery tag, or Session field.
pub(crate) fn parse_pppoe_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        alt((
            tag(Token::Pppoe)
                .map(|(_, s)| ParsedField::Protocol(Protocol::Pppoe, (s.start, s.len()))),
            parse_pppoe_stage,
            (tag(Token::SessionId), cut_err(parse_u16)).map(|((_, s), v)| {
                ParsedField::L7U32Field(
                    "PPPOE_SESSION_ID",
                    u32::from(v),
                    (s.start, s.end - s.start),
                )
            }),
            (tag(Token::ServiceName), cut_err(parse_any_str)).map(|((_, s), v)| {
                ParsedField::L7StringField("PPPOE_SERVICE_NAME", v, (s.start, s.end - s.start))
            }),
        )),
        alt((
            (tag(Token::AcName), cut_err(parse_any_str)).map(|((_, s), v)| {
                ParsedField::L7StringField("PPPOE_AC_NAME", v, (s.start, s.end - s.start))
            }),
            (tag(Token::HostUniq), cut_err(parse_hex_bytes)).map(|((_, s), v)| {
                ParsedField::L7BytesField("PPPOE_HOST_UNIQ", v, (s.start, s.end - s.start))
            }),
            (tag(Token::AcCookie), cut_err(parse_hex_bytes)).map(|((_, s), v)| {
                ParsedField::L7BytesField("PPPOE_AC_COOKIE", v, (s.start, s.end - s.start))
            }),
            (
                tag(Token::PppProto),
                cut_err(alt((parse_u16, parse_ppp_proto_name))),
            )
                .map(|((_, s), v)| {
                    ParsedField::L7U32Field(
                        "PPPOE_PPP_PROTO",
                        u32::from(v),
                        (s.start, s.end - s.start),
                    )
                }),
        )),
    ))
    .parse_next(input)
}
