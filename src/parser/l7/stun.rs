//! Session Traversal Utilities for NAT (STUN) Layer 7 protocol field parser.
//!
//! This module implements the `winnow` parser combinator for RFC 8489 `STUN` binding discovery
//! packets in FrameAssembly `.fasm` specifications. It recognizes the `STUN` protocol keyword,
//! message class flags (`BINDING_REQUEST`, `BINDING_RESPONSE`, `BINDING_ERROR`), transaction IDs
//! (`TXID`), `XOR_MAPPED_ADDR` reflexive IP attributes (with an optional port number), and
//! `SOFTWARE` agent description strings.

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err, opt};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{parse_ip, parse_str_val, parse_u16, parse_u32, tag, ParsedField, Stream};

/// Parses a STUN protocol declaration or binding attribute field.
pub(crate) fn parse_stun_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        tag(Token::Stun).map(|(_, s)| ParsedField::Protocol(Protocol::Stun, (s.start, s.len()))),
        tag(Token::BindingRequest)
            .map(|(_, s)| ParsedField::L7Flag("BINDING_REQUEST", (s.start, s.len()))),
        tag(Token::BindingResponse)
            .map(|(_, s)| ParsedField::L7Flag("BINDING_RESPONSE", (s.start, s.len()))),
        tag(Token::BindingError)
            .map(|(_, s)| ParsedField::L7Flag("BINDING_ERROR", (s.start, s.len()))),
        (tag(Token::Txid), cut_err(parse_u32))
            .map(|((_, s), v)| ParsedField::L7U32Field("TXID", v, (s.start, s.end - s.start))),
        (tag(Token::XorMappedAddr), cut_err(parse_ip), opt(parse_u16)).map(|((_, s), v, _)| {
            ParsedField::L7IpField("XOR_MAPPED_ADDR", v, (s.start, s.end - s.start))
        }),
        (tag(Token::Software), cut_err(parse_str_val)).map(|((_, s), v)| {
            ParsedField::L7StringField("SOFTWARE", v, (s.start, s.end - s.start))
        }),
    ))
    .parse_next(input)
}
