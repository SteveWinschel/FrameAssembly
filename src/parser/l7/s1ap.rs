//! 4G LTE S1 Application Protocol (S1AP, 3GPP TS 36.413) Layer 7 winnow parser combinators.
//!
//! This module implements protocol-scoped parsing for `s1ap` frame declarations and modifiers
//! including procedure shorthands (`s1setuprequest`, `s1setupresponse`, `s1setupfailure`,
//! `initialuemessage`, `downlinknastransport`, `uplinknastransport`, `uecontextreleasecommand`,
//! `uecontextreleasecomplete`, `errorindication`), generic PDU selectors (`msgtype`, `proccode`,
//! `criticality`), and IE fields (`mmeueid`, `enbueid`, `plmn`, `enbid`, `tac`, `enbname`, `naspdu`).

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{
    ParsedField, Stream, parse_any_str, parse_hex_bytes, parse_u8, parse_u32, tag,
};

/// Parses primary S1AP keyword and common setup/NAS procedure shorthands (`<= 8` `alt` arms).
fn parse_s1ap_head<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        tag(Token::S1ap).map(|(_, s)| ParsedField::Protocol(Protocol::S1ap, (s.start, s.end - s.start))),
        tag(Token::S1SetupRequest)
            .map(|(_, s)| ParsedField::L7Flag("s1setuprequest", (s.start, s.end - s.start))),
        tag(Token::S1SetupResponse)
            .map(|(_, s)| ParsedField::L7Flag("s1setupresponse", (s.start, s.end - s.start))),
        tag(Token::S1SetupFailure)
            .map(|(_, s)| ParsedField::L7Flag("s1setupfailure", (s.start, s.end - s.start))),
        tag(Token::InitialUeMessage)
            .map(|(_, s)| ParsedField::L7Flag("initialuemessage", (s.start, s.end - s.start))),
        tag(Token::DownlinkNasTransport)
            .map(|(_, s)| ParsedField::L7Flag("downlinknastransport", (s.start, s.end - s.start))),
        tag(Token::UplinkNasTransport)
            .map(|(_, s)| ParsedField::L7Flag("uplinknastransport", (s.start, s.end - s.start))),
    ))
    .parse_next(input)
}

/// Parses secondary S1AP procedure shorthands and top-level APER header overrides (`<= 8` `alt` arms).
fn parse_s1ap_procs<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
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

/// Parses S1AP Information Element field modifiers (`<= 8` `alt` arms).
fn parse_s1ap_mods<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        (tag(Token::MmeUeId), cut_err(parse_u32))
            .map(|((_, s), v)| ParsedField::L7U32Field("mme_ue_id", v, (s.start, s.end - s.start))),
        (tag(Token::EnbUeId), cut_err(parse_u32))
            .map(|((_, s), v)| ParsedField::L7U32Field("enb_ue_id", v, (s.start, s.end - s.start))),
        (tag(Token::Plmn), cut_err(parse_any_str))
            .map(|((_, s), v)| ParsedField::L7StringField("plmn", v, (s.start, s.end - s.start))),
        (tag(Token::EnbId), cut_err(parse_u32))
            .map(|((_, s), v)| ParsedField::L7U32Field("enb_id", v, (s.start, s.end - s.start))),
        (tag(Token::Tac), cut_err(parse_u32))
            .map(|((_, s), v)| ParsedField::L7U32Field("tac", v, (s.start, s.end - s.start))),
        (tag(Token::EnbName), cut_err(parse_any_str))
            .map(|((_, s), v)| ParsedField::L7StringField("enb_name", v, (s.start, s.end - s.start))),
        (tag(Token::NasPdu), cut_err(parse_hex_bytes))
            .map(|((_, s), v)| ParsedField::L7BytesField("nas_pdu", v, (s.start, s.end - s.start))),
    ))
    .parse_next(input)
}

/// Parses an `s1ap` protocol keyword or one of its 3GPP TS 36.413 modifier fields.
pub(crate) fn parse_s1ap_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((parse_s1ap_head, parse_s1ap_procs, parse_s1ap_mods)).parse_next(input)
}
