//! 5G NG Application Protocol (NGAP, 3GPP TS 38.413) Layer 7 winnow parser combinators.
//!
//! This module implements protocol-scoped parsing for `ngap` frame declarations and modifiers
//! including procedure shorthands (`ngsetuprequest`, `ngsetupresponse`, `ngsetupfailure`,
//! `initialuemessage`, `downlinknastransport`, `uplinknastransport`, `uecontextreleasecommand`,
//! `uecontextreleasecomplete`, `errorindication`), generic PDU selectors (`msgtype`, `proccode`,
//! `criticality`), and IE fields (`amfueid`, `ranueid`, `plmn`, `gnbid`, `tac`, `ranname`, `naspdu`).

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{
    ParsedField, Stream, parse_any_str, parse_hex_bytes, parse_u8, parse_u32, parse_u64, tag,
};

/// Parses primary NGAP keyword and common setup/NAS procedure shorthands (`<= 8` `alt` arms).
fn parse_ngap_head<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        tag(Token::Ngap).map(|(_, s)| ParsedField::Protocol(Protocol::Ngap, (s.start, s.end - s.start))),
        tag(Token::NgSetupRequest)
            .map(|(_, s)| ParsedField::L7Flag("ngsetuprequest", (s.start, s.end - s.start))),
        tag(Token::NgSetupResponse)
            .map(|(_, s)| ParsedField::L7Flag("ngsetupresponse", (s.start, s.end - s.start))),
        tag(Token::NgSetupFailure)
            .map(|(_, s)| ParsedField::L7Flag("ngsetupfailure", (s.start, s.end - s.start))),
        tag(Token::InitialUeMessage)
            .map(|(_, s)| ParsedField::L7Flag("initialuemessage", (s.start, s.end - s.start))),
        tag(Token::DownlinkNasTransport)
            .map(|(_, s)| ParsedField::L7Flag("downlinknastransport", (s.start, s.end - s.start))),
        tag(Token::UplinkNasTransport)
            .map(|(_, s)| ParsedField::L7Flag("uplinknastransport", (s.start, s.end - s.start))),
    ))
    .parse_next(input)
}

/// Parses secondary NGAP procedure shorthands and top-level APER header overrides (`<= 8` `alt` arms).
fn parse_ngap_procs<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        tag(Token::UeContextReleaseCommand)
            .map(|(_, s)| ParsedField::L7Flag("uecontextreleasecommand", (s.start, s.end - s.start))),
        tag(Token::UeContextReleaseComplete)
            .map(|(_, s)| ParsedField::L7Flag("uecontextreleasecomplete", (s.start, s.end - s.start))),
        tag(Token::ErrorIndication)
            .map(|(_, s)| ParsedField::L7Flag("errorindication", (s.start, s.end - s.start))),
        (tag(Token::MsgType), cut_err(parse_any_str))
            .map(|((_, s), v)| ParsedField::L7StringField("pdu_type", v, (s.start, s.end - s.start))),
        (tag(Token::ProcCode), cut_err(parse_u8))
            .map(|((_, s), v)| ParsedField::L7U32Field("proc_code", v as u32, (s.start, s.end - s.start))),
        (tag(Token::Criticality), cut_err(parse_any_str))
            .map(|((_, s), v)| ParsedField::L7StringField("criticality", v, (s.start, s.end - s.start))),
    ))
    .parse_next(input)
}

/// Parses NGAP Information Element field modifiers (`<= 8` `alt` arms).
fn parse_ngap_mods<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        (tag(Token::AmfUeId), cut_err(parse_u64))
            .map(|((_, s), v)| ParsedField::L7U64Field("amf_ue_id", v, (s.start, s.end - s.start))),
        (tag(Token::RanUeId), cut_err(parse_u32))
            .map(|((_, s), v)| ParsedField::L7U32Field("ran_ue_id", v, (s.start, s.end - s.start))),
        (tag(Token::Plmn), cut_err(parse_any_str))
            .map(|((_, s), v)| ParsedField::L7StringField("plmn", v, (s.start, s.end - s.start))),
        (tag(Token::GnbId), cut_err(parse_u32))
            .map(|((_, s), v)| ParsedField::L7U32Field("gnb_id", v, (s.start, s.end - s.start))),
        (tag(Token::Tac), cut_err(parse_u32))
            .map(|((_, s), v)| ParsedField::L7U32Field("tac", v, (s.start, s.end - s.start))),
        (tag(Token::RanName), cut_err(parse_any_str))
            .map(|((_, s), v)| ParsedField::L7StringField("ran_name", v, (s.start, s.end - s.start))),
        (tag(Token::NasPdu), cut_err(parse_hex_bytes))
            .map(|((_, s), v)| ParsedField::L7BytesField("nas_pdu", v, (s.start, s.end - s.start))),
    ))
    .parse_next(input)
}

/// Parses an `ngap` protocol keyword or one of its 3GPP TS 38.413 modifier fields.
pub(crate) fn parse_ngap_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((parse_ngap_head, parse_ngap_procs, parse_ngap_mods)).parse_next(input)
}
