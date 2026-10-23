//! IEEE 802.1X Port-Based Network Access Control (EAPOL) parser.

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{parse_str_val, parse_u8, tag, ParsedField, Stream};

/// Parses an EAPOL protocol declaration or frame field.
pub(crate) fn parse_eapol_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        tag(Token::Eapol).map(|(_, s)| ParsedField::Protocol(Protocol::Eapol, (s.start, s.len()))),
        (tag(Token::Version), cut_err(parse_u8)).map(|((_, s), v)| ParsedField::VersionByte(v, (s.start, s.end - s.start))),
        (tag(Token::EapCode), cut_err(parse_u8)).map(|((_, s), v)| ParsedField::EapCode(v, (s.start, s.end - s.start))),
        (tag(Token::EapId), cut_err(parse_u8)).map(|((_, s), v)| ParsedField::EapId(v, (s.start, s.end - s.start))),
        (tag(Token::EapMethod), cut_err(parse_u8)).map(|((_, s), v)| ParsedField::EapMethod(v, (s.start, s.end - s.start))),
        (tag(Token::Identity), cut_err(parse_str_val)).map(|((_, s), v)| ParsedField::Identity(v, (s.start, s.end - s.start))),
        (
            tag(Token::Type),
            alt((
                tag(Token::Start).value(EapolType::Start),
                tag(Token::Logoff).value(EapolType::Logoff),
                tag(Token::Key).value(EapolType::Key),
                tag(Token::EapPacket).value(EapolType::EapPacket),
            )),
        )
            .map(|((_, s), t)| ParsedField::EapolType(t, (s.start, s.end - s.start))),
    ))
    .parse_next(input)
}
