//! SSDP Layer 7 service discovery protocol field parser.

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{parse_str_val, parse_u32, tag, ParsedField, Stream};

/// Parses an SSDP protocol declaration or service discovery field.
pub(crate) fn parse_ssdp_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        alt((
            tag(Token::Ssdp).map(|(_, s)| ParsedField::Protocol(Protocol::Ssdp, (s.start, s.len()))),
            tag(Token::Msearch).map(|(_, s)| ParsedField::L7Flag("MSEARCH", (s.start, s.len()))),
            tag(Token::Notify).map(|(_, s)| ParsedField::L7Flag("NOTIFY", (s.start, s.len()))),
            (tag(Token::HostHdr), cut_err(parse_str_val)).map(|((_, s), v)| ParsedField::L7StringField("HOST_HDR", v, (s.start, s.end - s.start))),
            (tag(Token::Man), cut_err(parse_str_val)).map(|((_, s), v)| ParsedField::L7StringField("MAN", v, (s.start, s.end - s.start))),
        )),
        alt((
            (tag(Token::Mx), cut_err(parse_u32)).map(|((_, s), v)| ParsedField::L7U32Field("MX", v, (s.start, s.end - s.start))),
            (tag(Token::St), cut_err(parse_str_val)).map(|((_, s), v)| ParsedField::L7StringField("ST", v, (s.start, s.end - s.start))),
            (tag(Token::Nt), cut_err(parse_str_val)).map(|((_, s), v)| ParsedField::L7StringField("NT", v, (s.start, s.end - s.start))),
            (tag(Token::Nts), cut_err(parse_str_val)).map(|((_, s), v)| ParsedField::L7StringField("NTS", v, (s.start, s.end - s.start))),
            (tag(Token::Usn), cut_err(parse_str_val)).map(|((_, s), v)| ParsedField::L7StringField("USN", v, (s.start, s.end - s.start))),
            (tag(Token::Location), cut_err(parse_str_val)).map(|((_, s), v)| ParsedField::L7StringField("LOCATION", v, (s.start, s.end - s.start))),
        )),
    ))
    .parse_next(input)
}
