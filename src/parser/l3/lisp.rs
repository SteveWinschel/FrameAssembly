//! Locator/ID Separation Protocol (`lisp`, RFC 9300 / RFC 9301) parser for FrameAssembly.
//!
//! This module implements the `winnow` parser combinator for LISP Data-Plane (UDP port `4341`)
//! and Control-Plane (UDP port `4342`) packets. It parses the `lisp` protocol keyword, plane and
//! message type keywords (`data`, `maprequest`, `mapreply`, `mapregister`, `mapnotify`, `ecm`),
//! header flags (`flags <u8>`), 24-bit Instance IDs (`iid <u24>`), 64-bit or 24-bit nonces
//! (`nonce <u64>`), EID prefixes (`eid "<cidr>"`), RLOC addresses (`rloc <ip>`), and locator
//! `priority <u8>` and `weight <u8>` attributes.

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{
    ParsedField, Stream, parse_any_str, parse_ip, parse_u8, parse_u32, parse_u64, tag,
};

/// Parses a LISP protocol declaration, message type, or locator/mapping field.
pub(crate) fn parse_lisp_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        alt((
            tag(Token::Lisp).map(|(_, s)| ParsedField::Protocol(Protocol::Lisp, (s.start, s.len()))),
            tag(Token::Data)
                .map(|(_, s)| ParsedField::L7StringField("LISP_TYPE", "DATA", (s.start, s.len()))),
            tag(Token::MapRequest).map(|(_, s)| {
                ParsedField::L7StringField("LISP_TYPE", "MAPREQUEST", (s.start, s.len()))
            }),
            tag(Token::MapReply).map(|(_, s)| {
                ParsedField::L7StringField("LISP_TYPE", "MAPREPLY", (s.start, s.len()))
            }),
            tag(Token::MapRegister).map(|(_, s)| {
                ParsedField::L7StringField("LISP_TYPE", "MAPREGISTER", (s.start, s.len()))
            }),
            tag(Token::MapNotify).map(|(_, s)| {
                ParsedField::L7StringField("LISP_TYPE", "MAPNOTIFY", (s.start, s.len()))
            }),
            tag(Token::Ecm)
                .map(|(_, s)| ParsedField::L7StringField("LISP_TYPE", "ECM", (s.start, s.len()))),
        )),
        alt((
            (tag(Token::Flags), parse_u8)
                .map(|((_, s), v)| ParsedField::FlagsByte(v, (s.start, s.end - s.start))),
            (tag(Token::Iid), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("LISP_IID", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Nonce), cut_err(parse_u64)).map(|((_, s), v)| {
                ParsedField::L7U64Field("LISP_NONCE", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Eid), cut_err(parse_any_str)).map(|((_, s), v)| {
                ParsedField::L7StringField("LISP_EID", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Rloc), cut_err(parse_ip))
                .map(|((_, s), v)| ParsedField::L7IpField("LISP_RLOC", v, (s.start, s.end - s.start))),
            (tag(Token::Priority), parse_u8).map(|((_, s), v)| {
                ParsedField::PriorityVal(u16::from(v), (s.start, s.end - s.start))
            }),
            (tag(Token::Weight), cut_err(parse_u8)).map(|((_, s), v)| {
                ParsedField::L7U32Field("LISP_WEIGHT", u32::from(v), (s.start, s.end - s.start))
            }),
        )),
    ))
    .parse_next(input)
}
