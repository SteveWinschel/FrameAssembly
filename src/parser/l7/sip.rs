//! SIP Layer 7 VoIP signaling protocol field parser.

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{parse_str_val, parse_u32, tag, ParsedField, Stream};

/// Parses a SIP protocol declaration or message header field.
pub(crate) fn parse_sip_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        alt((
            tag(Token::Sip).map(|(_, s)| ParsedField::Protocol(Protocol::Sip, (s.start, s.len()))),
            tag(Token::Invite).map(|(_, s)| ParsedField::L7StringField("METHOD", "INVITE", (s.start, s.len()))),
            tag(Token::Bye).map(|(_, s)| ParsedField::L7StringField("METHOD", "BYE", (s.start, s.len()))),
            tag(Token::Cancel).map(|(_, s)| ParsedField::L7StringField("METHOD", "CANCEL", (s.start, s.len()))),
            (tag(Token::Method), cut_err(parse_str_val)).map(|((_, s), v)| ParsedField::L7StringField("METHOD", v, (s.start, s.end - s.start))),
            (tag(Token::Uri), cut_err(parse_str_val)).map(|((_, s), v)| ParsedField::L7StringField("URI", v, (s.start, s.end - s.start))),
            (tag(Token::From), cut_err(parse_str_val)).map(|((_, s), v)| ParsedField::L7StringField("FROM", v, (s.start, s.end - s.start))),
            (tag(Token::To), cut_err(parse_str_val)).map(|((_, s), v)| ParsedField::L7StringField("TO", v, (s.start, s.end - s.start))),
            (tag(Token::CallId), cut_err(parse_str_val)).map(|((_, s), v)| ParsedField::L7StringField("CALL_ID", v, (s.start, s.end - s.start))),
        )),
        alt((
            (tag(Token::Cseq), cut_err(parse_u32)).map(|((_, s), v)| ParsedField::L7U32Field("CSEQ", v, (s.start, s.end - s.start))),
            (tag(Token::Via), cut_err(parse_str_val)).map(|((_, s), v)| ParsedField::L7StringField("VIA", v, (s.start, s.end - s.start))),
            (tag(Token::Contact), cut_err(parse_str_val)).map(|((_, s), v)| ParsedField::L7StringField("CONTACT", v, (s.start, s.end - s.start))),
            (tag(Token::ContentType), cut_err(parse_str_val)).map(|((_, s), v)| ParsedField::L7StringField("CONTENT_TYPE", v, (s.start, s.end - s.start))),
            (tag(Token::Status), cut_err(parse_u32)).map(|((_, s), v)| ParsedField::L7U32Field("STATUS", v, (s.start, s.end - s.start))),
            (tag(Token::Reason), cut_err(parse_str_val)).map(|((_, s), v)| ParsedField::L7StringField("REASON", v, (s.start, s.end - s.start))),
            (tag(Token::Body), cut_err(parse_str_val)).map(|((_, s), v)| ParsedField::L7StringField("BODY", v, (s.start, s.end - s.start))),
        )),
    ))
    .parse_next(input)
}
