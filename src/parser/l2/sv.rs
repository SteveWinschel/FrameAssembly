//! IEC 61850-9-2LE Sampled Values (`sv`) Layer 2 parser combinator for FrameAssembly.
//!
//! This module implements the `winnow` parser combinator for IEC 61850-9-2 / 9-2LE Sampled
//! Values (`sv`, EtherType `0x88BA`) substation merging-unit multicast frames in FrameAssembly
//! `.frasm` specifications. It recognizes the `sv` protocol keyword, 16-bit `appid`, stream
//! identifier `svid`, optional `datset`, 16-bit sample counter `smpcnt`, configuration revision
//! `confrev`, time synchronization status `smpsynch`, optional `smprate`, and Ed2 `simulation` flag.

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{ParsedField, Stream, parse_str_val, parse_u32, tag};

/// Parses an IEC 61850-9-2 Sampled Values protocol declaration or ASDU field.
pub(crate) fn parse_sv_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        alt((
            tag(Token::Sv).map(|(_, s)| ParsedField::Protocol(Protocol::Sv, (s.start, s.len()))),
            (tag(Token::AppId), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("IEC_APPID", v, (s.start, s.end - s.start))
            }),
            (tag(Token::SvId), cut_err(parse_str_val)).map(|((_, s), v)| {
                ParsedField::L7StringField("SV_ID", v, (s.start, s.end - s.start))
            }),
            (tag(Token::DatSet), cut_err(parse_str_val)).map(|((_, s), v)| {
                ParsedField::L7StringField("IEC_DAT_SET", v, (s.start, s.end - s.start))
            }),
        )),
        alt((
            (tag(Token::SmpCnt), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("SMP_CNT", v, (s.start, s.end - s.start))
            }),
            (tag(Token::ConfRev), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("IEC_CONF_REV", v, (s.start, s.end - s.start))
            }),
            (tag(Token::SmpSynch), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("SMP_SYNCH", v, (s.start, s.end - s.start))
            }),
            (tag(Token::SmpRate), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("SMP_RATE", v, (s.start, s.end - s.start))
            }),
            tag(Token::Simulation)
                .map(|(_, s)| ParsedField::L7Flag("IEC_SIMULATION", (s.start, s.len()))),
        )),
    ))
    .parse_next(input)
}
