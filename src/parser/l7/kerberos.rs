//! Kerberos v5 (RFC 4120) Layer 7 network authentication protocol field parser.
//!
//! This module implements the `winnow` parser combinator for RFC 4120 `KERBEROS` Key Distribution
//! Center (`KDC`) exchanges in FrameAssembly `.fasm` specifications. It recognizes the `KERBEROS`
//! protocol keyword, ASN.1 message type flags (`AS_REQ`, `AS_REP`, `TGS_REQ`, `TGS_REP`,
//! `KRB_ERROR`), Kerberos realms (`REALM`), client principal names (`CNAME`), service principal
//! names (`SNAME`), and encryption type identifiers (`ETYPE`).

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{parse_str_val, parse_u32, tag, ParsedField, Stream};

/// Parses a Kerberos protocol declaration or ticket field.
pub(crate) fn parse_kerberos_field<'i, 'a>(
    input: &mut Stream<'i, 'a>,
) -> PResult<ParsedField<'a>> {
    alt((
        alt((
            tag(Token::Kerberos)
                .map(|(_, s)| ParsedField::Protocol(Protocol::Kerberos, (s.start, s.len()))),
            tag(Token::AsReq).map(|(_, s)| ParsedField::L7Flag("AS_REQ", (s.start, s.len()))),
            tag(Token::AsRep).map(|(_, s)| ParsedField::L7Flag("AS_REP", (s.start, s.len()))),
            tag(Token::TgsReq).map(|(_, s)| ParsedField::L7Flag("TGS_REQ", (s.start, s.len()))),
            tag(Token::TgsRep).map(|(_, s)| ParsedField::L7Flag("TGS_REP", (s.start, s.len()))),
        )),
        alt((
            tag(Token::KrbError)
                .map(|(_, s)| ParsedField::L7Flag("KRB_ERROR", (s.start, s.len()))),
            (tag(Token::Realm), cut_err(parse_str_val))
                .map(|((_, s), v)| ParsedField::L7StringField("REALM", v, (s.start, s.end - s.start))),
            (tag(Token::Cname), cut_err(parse_str_val))
                .map(|((_, s), v)| ParsedField::L7StringField("CNAME", v, (s.start, s.end - s.start))),
            (tag(Token::Sname), cut_err(parse_str_val))
                .map(|((_, s), v)| ParsedField::L7StringField("SNAME", v, (s.start, s.end - s.start))),
            (tag(Token::Etype), cut_err(parse_u32))
                .map(|((_, s), v)| ParsedField::L7U32Field("ETYPE", v, (s.start, s.end - s.start))),
        )),
    ))
    .parse_next(input)
}
