//! Bidirectional Forwarding Detection (`bfd`, RFC 5880) fault detection parser for FrameAssembly.
//!
//! This module implements the winnow parser combinator for `bfd` rapid forwarding-plane failure
//! detection packets over UDP port 3784. It parses session state (`state <0..3>`), diagnostic code
//! (`diag <u8>`), local and remote session discriminators (`mydisc`, `yourdisc`), minimum TX/RX
//! intervals (`mintx`, `minrx`), and detection time multipliers (`mult <u8>`).

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{ParsedField, Stream, parse_u8, parse_u32, tag};

/// Parses a BFD protocol declaration or control field.
pub(crate) fn parse_bfd_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        tag(Token::Bfd).map(|(_, s)| ParsedField::Protocol(Protocol::Bfd, (s.start, s.len()))),
        (tag(Token::State), cut_err(parse_u8))
            .map(|((_, s), v)| ParsedField::HsrpState(v, (s.start, s.end - s.start))),
        (tag(Token::Diag), cut_err(parse_u8))
            .map(|((_, s), v)| ParsedField::Diag(v, (s.start, s.end - s.start))),
        (tag(Token::MyDisc), cut_err(parse_u32))
            .map(|((_, s), v)| ParsedField::MyDisc(v, (s.start, s.end - s.start))),
        (tag(Token::YourDisc), cut_err(parse_u32))
            .map(|((_, s), v)| ParsedField::YourDisc(v, (s.start, s.end - s.start))),
        (tag(Token::MinTx), cut_err(parse_u32))
            .map(|((_, s), v)| ParsedField::MinTx(v, (s.start, s.end - s.start))),
        (tag(Token::MinRx), cut_err(parse_u32))
            .map(|((_, s), v)| ParsedField::MinRx(v, (s.start, s.end - s.start))),
        (tag(Token::Mult), cut_err(parse_u8))
            .map(|((_, s), v)| ParsedField::Mult(v, (s.start, s.end - s.start))),
    ))
    .parse_next(input)
}
