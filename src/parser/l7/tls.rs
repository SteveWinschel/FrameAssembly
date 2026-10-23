//! TLS Layer 7 security protocol field parser.

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{parse_str_val, parse_u32, tag, ParsedField, Stream};

/// Parses a TLS protocol declaration or handshake/record field.
pub(crate) fn parse_tls_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        alt((
            tag(Token::Tls).map(|(_, s)| ParsedField::Protocol(Protocol::Tls, (s.start, s.len()))),
            tag(Token::ClientHello).map(|(_, s)| ParsedField::L7Flag("CLIENT_HELLO", (s.start, s.len()))),
            tag(Token::ServerHello).map(|(_, s)| ParsedField::L7Flag("SERVER_HELLO", (s.start, s.len()))),
            tag(Token::Certificate).map(|(_, s)| ParsedField::L7Flag("CERTIFICATE", (s.start, s.len()))),
            tag(Token::Finished).map(|(_, s)| ParsedField::L7Flag("FINISHED", (s.start, s.len()))),
            tag(Token::AppData).map(|(_, s)| ParsedField::L7Flag("APP_DATA", (s.start, s.len()))),
        )),
        alt((
            tag(Token::Alert).map(|(_, s)| ParsedField::L7Flag("ALERT", (s.start, s.len()))),
            (tag(Token::RecordVersion), cut_err(parse_u32)).map(|((_, s), v)| ParsedField::L7U32Field("RECORD_VERSION", v, (s.start, s.end - s.start))),
            (tag(Token::HandshakeVersion), cut_err(parse_u32)).map(|((_, s), v)| ParsedField::L7U32Field("HANDSHAKE_VERSION", v, (s.start, s.end - s.start))),
            (tag(Token::Sni), cut_err(parse_str_val)).map(|((_, s), v)| ParsedField::L7StringField("SNI", v, (s.start, s.end - s.start))),
            (tag(Token::Ciphersuite), cut_err(parse_u32)).map(|((_, s), v)| ParsedField::L7U32Field("CIPHERSUITE", v, (s.start, s.end - s.start))),
            (tag(Token::Alpn), cut_err(parse_str_val)).map(|((_, s), v)| ParsedField::L7StringField("ALPN", v, (s.start, s.end - s.start))),
        )),
    ))
    .parse_next(input)
}
