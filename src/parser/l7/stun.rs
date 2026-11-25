//! Session Traversal Utilities for NAT (STUN) Layer 7 protocol field parser.
//!
//! This module implements the `winnow` parser combinator for RFC 8489 `stun` binding discovery
//! packets in FrameAssembly `.frasm` specifications. It recognizes the `stun` protocol keyword,
//! message class flags (`bindingrequest`, `bindingresponse`, `bindingerror`), transaction IDs
//! (`txid`), `xormappedaddr` reflexive IP attributes (with an optional port number), and
//! `software` agent description strings.

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err, opt};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{
    parse_spanned_ip, parse_spanned_u32, parse_str_val, parse_u32, tag, ParsedField, Stream,
};

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
        (tag(Token::XorMappedAddr), cut_err(parse_spanned_ip), opt(parse_spanned_u32)).map(
            |((_, s), (ip, ip_sp), port)| {
                let end = port.map_or(ip_sp.0 + ip_sp.1, |(_, p_sp)| p_sp.0 + p_sp.1);
                ParsedField::StunXorMapped(ip, port.map(|(p, _)| p), (s.start, end - s.start))
            },
        ),
        (tag(Token::Software), cut_err(parse_str_val)).map(|((_, s), v)| {
            ParsedField::L7StringField("SOFTWARE", v, (s.start, s.end - s.start))
        }),
    ))
    .parse_next(input)
}
