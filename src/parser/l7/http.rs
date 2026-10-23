//! HTTP Layer 7 web protocol field parser.

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{parse_str_val, parse_u32, tag, ParsedField, Stream};

/// Parses an HTTP protocol declaration or request/response header field.
pub(crate) fn parse_http_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        alt((
            tag(Token::Http).map(|(_, s)| ParsedField::Protocol(Protocol::Http, (s.start, s.len()))),
            (tag(Token::Method), cut_err(parse_str_val)).map(|((_, s), v)| ParsedField::L7StringField("METHOD", v, (s.start, s.end - s.start))),
            (tag(Token::Uri), cut_err(parse_str_val)).map(|((_, s), v)| ParsedField::L7StringField("URI", v, (s.start, s.end - s.start))),
            (tag(Token::Version), cut_err(parse_str_val)).map(|((_, s), v)| ParsedField::L7StringField("VERSION", v, (s.start, s.end - s.start))),
            (tag(Token::HostHdr), cut_err(parse_str_val)).map(|((_, s), v)| ParsedField::L7StringField("HOST_HDR", v, (s.start, s.end - s.start))),
        )),
        alt((
            (tag(Token::UserAgent), cut_err(parse_str_val)).map(|((_, s), v)| ParsedField::L7StringField("USER_AGENT", v, (s.start, s.end - s.start))),
            (tag(Token::ContentType), cut_err(parse_str_val)).map(|((_, s), v)| ParsedField::L7StringField("CONTENT_TYPE", v, (s.start, s.end - s.start))),
            (tag(Token::Status), cut_err(parse_u32)).map(|((_, s), v)| ParsedField::L7U32Field("STATUS", v, (s.start, s.end - s.start))),
            (tag(Token::Reason), cut_err(parse_str_val)).map(|((_, s), v)| ParsedField::L7StringField("REASON", v, (s.start, s.end - s.start))),
            (tag(Token::Body), cut_err(parse_str_val)).map(|((_, s), v)| ParsedField::L7StringField("BODY", v, (s.start, s.end - s.start))),
            (tag(Token::Header), cut_err((parse_str_val, parse_str_val))).map(|((_, s), (k, v))| ParsedField::L7Header(k, v, (s.start, s.end - s.start))),
        )),
    ))
    .parse_next(input)
}
