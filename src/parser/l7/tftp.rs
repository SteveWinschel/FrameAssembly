//! Trivial File Transfer Protocol (TFTP) Layer 7 file transfer field parser.
//!
//! This module implements the `winnow` parser combinator for RFC 1350 `TFTP` read/write requests,
//! data blocks, acknowledgments, and error packets in FrameAssembly `.fasm` specifications. It
//! recognizes the `TFTP` protocol keyword, packet type flags (`RRQ`, `WRQ`, `DATA`, `ACK`, `ERR`),
//! target filenames (`FILENAME`), transfer modes (`MODE`, e.g., `"octet"` or `"netascii"`), block
//! numbers (`BLOCK`), error codes (`ERRCODE`), and error message strings (`ERRMSG`).

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{parse_str_val, parse_u32, tag, ParsedField, Stream};

/// Parses a TFTP protocol declaration or transfer parameter field.
pub(crate) fn parse_tftp_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        alt((
            tag(Token::Tftp)
                .map(|(_, s)| ParsedField::Protocol(Protocol::Tftp, (s.start, s.len()))),
            tag(Token::Rrq).map(|(_, s)| ParsedField::L7Flag("RRQ", (s.start, s.len()))),
            tag(Token::Wrq).map(|(_, s)| ParsedField::L7Flag("WRQ", (s.start, s.len()))),
            tag(Token::Data).map(|(_, s)| ParsedField::L7Flag("DATA", (s.start, s.len()))),
            tag(Token::Ack).map(|(_, s)| ParsedField::L7Flag("ACK", (s.start, s.len()))),
            tag(Token::Err).map(|(_, s)| ParsedField::L7Flag("ERR", (s.start, s.len()))),
            tag(Token::Ident("ERROR")).map(|(_, s)| ParsedField::L7Flag("ERROR", (s.start, s.len()))),
        )),
        alt((
            (tag(Token::Filename), cut_err(parse_str_val)).map(|((_, s), v)| {
                ParsedField::L7StringField("FILENAME", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Mode), parse_str_val)
                .map(|((_, s), v)| ParsedField::L7StringField("MODE", v, (s.start, s.end - s.start))),
            (tag(Token::Block), cut_err(parse_u32))
                .map(|((_, s), v)| ParsedField::L7U32Field("BLOCK", v, (s.start, s.end - s.start))),
            (tag(Token::ErrCode), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("ERRCODE", v, (s.start, s.end - s.start))
            }),
            (tag(Token::ErrMsg), cut_err(parse_str_val)).map(|((_, s), v)| {
                ParsedField::L7StringField("ERRMSG", v, (s.start, s.end - s.start))
            }),
        )),
    ))
    .parse_next(input)
}
