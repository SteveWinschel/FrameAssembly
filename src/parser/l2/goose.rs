//! IEC 61850-8-1 GOOSE (`goose`) substation multicast Layer 2 parser combinator.
//!
//! This module implements the `winnow` parser combinator for IEC 61850-8-1 Generic Object
//! Oriented Substation Event (`goose`, EtherType `0x88B8`) frames in FrameAssembly `.frasm`
//! specifications. It recognizes the `goose` protocol keyword, 16-bit `appid`, GOOSE control
//! block reference `gocbref`, `timetolive` in milliseconds, `datset` name, `goid`, state and
//! sequence numbers (`stnum`, `sqnum`), `simulation` and `ndscom` flags, `confrev`, and dataset
//! entry count (`numdatsetentries`).

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{ParsedField, Stream, parse_str_val, parse_u32, tag};

/// Parses an IEC 61850 GOOSE protocol declaration or ASN.1 BER PDU field.
pub(crate) fn parse_goose_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        alt((
            tag(Token::Goose)
                .map(|(_, s)| ParsedField::Protocol(Protocol::Goose, (s.start, s.len()))),
            (tag(Token::AppId), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("IEC_APPID", v, (s.start, s.end - s.start))
            }),
            (tag(Token::GocbRef), cut_err(parse_str_val)).map(|((_, s), v)| {
                ParsedField::L7StringField("GOCB_REF", v, (s.start, s.end - s.start))
            }),
            (tag(Token::TimeToLive), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("TIME_TO_LIVE", v, (s.start, s.end - s.start))
            }),
            (tag(Token::DatSet), cut_err(parse_str_val)).map(|((_, s), v)| {
                ParsedField::L7StringField("IEC_DAT_SET", v, (s.start, s.end - s.start))
            }),
            (tag(Token::GoId), cut_err(parse_str_val)).map(|((_, s), v)| {
                ParsedField::L7StringField("GO_ID", v, (s.start, s.end - s.start))
            }),
        )),
        alt((
            (tag(Token::StNum), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("ST_NUM", v, (s.start, s.end - s.start))
            }),
            (tag(Token::SqNum), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("SQ_NUM", v, (s.start, s.end - s.start))
            }),
            tag(Token::Simulation)
                .map(|(_, s)| ParsedField::L7Flag("IEC_SIMULATION", (s.start, s.len()))),
            (tag(Token::ConfRev), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("IEC_CONF_REV", v, (s.start, s.end - s.start))
            }),
            tag(Token::NdsCom).map(|(_, s)| ParsedField::L7Flag("NDS_COM", (s.start, s.len()))),
            (tag(Token::NumDatSetEntries), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("NUM_DAT_SET_ENTRIES", v, (s.start, s.end - s.start))
            }),
        )),
    ))
    .parse_next(input)
}
