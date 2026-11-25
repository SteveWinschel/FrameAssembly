//! Resource Reservation Protocol (`rsvp`, RFC 2205 / RFC 3209 RSVP-TE) field parser.
//!
//! This module implements the winnow parser combinator for `rsvp` signaling packets carried over
//! IP protocol `46`. It recognizes the `rsvp` protocol keyword, RSVP message types (`path`,
//! `resv`, `patherr`, `resverr`, `pathtear`, `resvtear`, `resvconf`, `hello`), RSVP-TE tunnel and
//! LSP identifiers (`tunnelid <u16>`, `lspid <u16>`), MPLS label values (`label <u32>`), refresh
//! timer intervals (`refresh <u32>`), session endpoints (`srcip`, `dstip`), and `errcode <u8>`.

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{ParsedField, Stream, parse_ip, parse_u32, tag};

/// Parses an RSVP protocol declaration, message type flag, or object field.
pub(crate) fn parse_rsvp_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        alt((
            tag(Token::Rsvp).map(|(_, s)| ParsedField::Protocol(Protocol::Rsvp, (s.start, s.len()))),
            tag(Token::Path)
                .map(|(_, s)| ParsedField::L7StringField("RSVP_MSG", "path", (s.start, s.len()))),
            tag(Token::Resv)
                .map(|(_, s)| ParsedField::L7StringField("RSVP_MSG", "resv", (s.start, s.len()))),
            tag(Token::PathErr).map(|(_, s)| {
                ParsedField::L7StringField("RSVP_MSG", "patherr", (s.start, s.len()))
            }),
            tag(Token::ResvErr).map(|(_, s)| {
                ParsedField::L7StringField("RSVP_MSG", "resverr", (s.start, s.len()))
            }),
            tag(Token::PathTear).map(|(_, s)| {
                ParsedField::L7StringField("RSVP_MSG", "pathtear", (s.start, s.len()))
            }),
            tag(Token::ResvTear).map(|(_, s)| {
                ParsedField::L7StringField("RSVP_MSG", "resvtear", (s.start, s.len()))
            }),
            tag(Token::ResvConf).map(|(_, s)| {
                ParsedField::L7StringField("RSVP_MSG", "resvconf", (s.start, s.len()))
            }),
        )),
        alt((
            tag(Token::Hello)
                .map(|(_, s)| ParsedField::L7StringField("RSVP_MSG", "hello", (s.start, s.len()))),
            (tag(Token::TunnelId), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("RSVP_TUNNEL_ID", v, (s.start, s.end - s.start))
            }),
            (tag(Token::LspId), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("RSVP_LSP_ID", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Label), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("RSVP_LABEL", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Refresh), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("RSVP_REFRESH", v, (s.start, s.end - s.start))
            }),
            (tag(Token::SrcIp), cut_err(parse_ip))
                .map(|((_, s), v)| ParsedField::L7IpField("SRCIP", v, (s.start, s.end - s.start))),
            (tag(Token::DstIp), cut_err(parse_ip))
                .map(|((_, s), v)| ParsedField::L7IpField("DSTIP", v, (s.start, s.end - s.start))),
            (tag(Token::ErrCode), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("RSVP_ERRCODE", v, (s.start, s.end - s.start))
            }),
        )),
    ))
    .parse_next(input)
}
