//! NetBIOS Name Service (`nbns`, RFC 1001 / RFC 1002) Layer 7 field parser.
//!
//! This module implements the `winnow` parser combinator for RFC 1001 and RFC 1002 NetBIOS Name
//! Service (`nbns`) datagrams over UDP port 137 in FrameAssembly `.frasm` specifications. It
//! recognizes the `nbns` protocol keyword, operation shorthands (`query`, `register`, `release`,
//! `refresh`) and explicit `opcode`, response and group flags (`response`, `group`), transaction IDs
//! (`txid`), NetBIOS names (`qname`), 1-byte suffix types (`nbtype`), record types (`qtype`), scope
//! labels (`scope`), IPv4 addresses (`rdata`), response codes (`rcode`), TTLs (`ansttl`), and
//! header flags (`flags`).

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{ParsedField, Stream, parse_any_str, parse_str_val, parse_u16, parse_u32, parse_u8, tag};

/// Parses an NBNS protocol declaration or NetBIOS name query/registration field.
pub(crate) fn parse_nbns_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        alt((
            tag(Token::Nbns)
                .map(|(_, s)| ParsedField::Protocol(Protocol::Nbns, (s.start, s.len()))),
            tag(Token::Query).map(|(_, s)| {
                ParsedField::L7StringField("NBNS_OPCODE", "QUERY", (s.start, s.len()))
            }),
            tag(Token::Register).map(|(_, s)| {
                ParsedField::L7StringField("NBNS_OPCODE", "REGISTER", (s.start, s.len()))
            }),
            tag(Token::Release).map(|(_, s)| {
                ParsedField::L7StringField("NBNS_OPCODE", "RELEASE", (s.start, s.len()))
            }),
            tag(Token::Refresh).map(|(_, s)| {
                ParsedField::L7StringField("NBNS_OPCODE", "REFRESH", (s.start, s.len()))
            }),
            tag(Token::Response)
                .map(|(_, s)| ParsedField::L7Flag("NBNS_RESPONSE", (s.start, s.len()))),
            tag(Token::Group)
                .map(|(_, s)| ParsedField::L7Flag("NBNS_GROUP", (s.start, s.len()))),
        )),
        alt((
            (tag(Token::Opcode), cut_err(parse_any_str)).map(|((_, s), v)| {
                ParsedField::L7StringField("NBNS_OPCODE", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Txid), cut_err(parse_u16)).map(|((_, s), v)| {
                ParsedField::L7U32Field("NBNS_TXID", u32::from(v), (s.start, s.end - s.start))
            }),
            (tag(Token::Qname), cut_err(parse_any_str)).map(|((_, s), v)| {
                ParsedField::L7StringField("NBNS_QNAME", v, (s.start, s.end - s.start))
            }),
            (tag(Token::NbType), cut_err(parse_u8)).map(|((_, s), v)| {
                ParsedField::L7U32Field("NBNS_NB_TYPE", u32::from(v), (s.start, s.end - s.start))
            }),
            (tag(Token::Qtype), cut_err(parse_any_str)).map(|((_, s), v)| {
                ParsedField::L7StringField("NBNS_QTYPE", v, (s.start, s.end - s.start))
            }),
        )),
        alt((
            (tag(Token::Scope), cut_err(parse_str_val)).map(|((_, s), v)| {
                ParsedField::L7StringField("NBNS_SCOPE", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Rdata), cut_err(parse_any_str)).map(|((_, s), v)| {
                ParsedField::L7StringField("NBNS_RDATA", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Rcode), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("NBNS_RCODE", v, (s.start, s.end - s.start))
            }),
            (tag(Token::AnsTtl), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("NBNS_ANS_TTL", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Flags), cut_err(parse_u16)).map(|((_, s), v)| {
                ParsedField::L7U32Field("NBNS_FLAGS", u32::from(v), (s.start, s.end - s.start))
            }),
        )),
    ))
    .parse_next(input)
}
