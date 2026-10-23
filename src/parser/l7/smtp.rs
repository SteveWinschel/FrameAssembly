//! SMTP Layer 7 mail transfer protocol field parser.

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{parse_raw_string_lit, parse_str_val, parse_u32, tag, ParsedField, Stream};

/// Parses an SMTP protocol declaration or mail exchange field.
pub(crate) fn parse_smtp_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        alt((
            tag(Token::Smtp).map(|(_, s)| ParsedField::Protocol(Protocol::Smtp, (s.start, s.len()))),
            (tag(Token::Ehlo), parse_raw_string_lit).map(|((_, s), v)| ParsedField::L7StringField("EHLO_PARAM", v, (s.start, s.end - s.start))),
            (tag(Token::Helo), parse_raw_string_lit).map(|((_, s), v)| ParsedField::L7StringField("HELO_PARAM", v, (s.start, s.end - s.start))),
            tag(Token::Ehlo).map(|(_, s)| ParsedField::L7StringField("CMD", "EHLO", (s.start, s.len()))),
            tag(Token::Helo).map(|(_, s)| ParsedField::L7StringField("CMD", "HELO", (s.start, s.len()))),
            tag(Token::MailFrom).map(|(_, s)| ParsedField::L7StringField("CMD", "MAIL_FROM", (s.start, s.len()))),
            tag(Token::RcptTo).map(|(_, s)| ParsedField::L7StringField("CMD", "RCPT_TO", (s.start, s.len()))),
            tag(Token::Quit).map(|(_, s)| ParsedField::L7StringField("CMD", "QUIT", (s.start, s.len()))),
        )),
        alt((
            (tag(Token::Cmd), cut_err(parse_str_val)).map(|((_, s), v)| ParsedField::L7StringField("CMD", v, (s.start, s.end - s.start))),
            (tag(Token::Param), cut_err(parse_str_val)).map(|((_, s), v)| ParsedField::L7StringField("PARAM", v, (s.start, s.end - s.start))),
            (tag(Token::Code), cut_err(parse_u32)).map(|((_, s), v)| ParsedField::L7U32Field("CODE", v, (s.start, s.end - s.start))),
            (tag(Token::Reply), cut_err(parse_str_val)).map(|((_, s), v)| ParsedField::L7StringField("REPLY", v, (s.start, s.end - s.start))),
            (tag(Token::Body), cut_err(parse_str_val)).map(|((_, s), v)| ParsedField::L7StringField("BODY", v, (s.start, s.end - s.start))),
        )),
    ))
    .parse_next(input)
}
