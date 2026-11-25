//! GPRS Tunneling Protocol Control Plane v2 (`gtpc`, 3GPP TS 29.274) Layer 7 field parser.
//!
//! This module implements the `winnow` parser combinator for 3GPP TS 29.274 `gtpc` GTPv2-C
//! packets over UDP port `2123` in FrameAssembly `.frasm` specifications. It recognizes the `gtpc`
//! protocol keyword, signaling message types (`echorequest`, `echoreply`, `echoresponse`,
//! `createsessionrequest`, `createsessionresponse`, `modifybearerrequest`, `modifybearerresponse`,
//! `deletesessionrequest`, `deletesessionresponse`, or `msgtype`), tunnel identifiers (`teid`),
//! sequence numbers (`seqnum`), and Information Elements (`cause`, `imsi`, `apn`, `rat`,
//! `recovery`, and PDN `addr`).

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{
    ParsedField, Stream, parse_any_str, parse_ip, parse_u32, tag,
};

/// Parses a GTPv2-C protocol declaration or signaling / IE field.
pub(crate) fn parse_gtpc_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        alt((
            tag(Token::Gtpc)
                .map(|(_, s)| ParsedField::Protocol(Protocol::Gtpc, (s.start, s.len()))),
            tag(Token::EchoRequest).map(|(_, s)| {
                ParsedField::L7StringField("MSG_TYPE", "ECHOREQUEST", (s.start, s.len()))
            }),
            tag(Token::EchoReply).map(|(_, s)| {
                ParsedField::L7StringField("MSG_TYPE", "ECHORESPONSE", (s.start, s.len()))
            }),
            tag(Token::EchoResponse).map(|(_, s)| {
                ParsedField::L7StringField("MSG_TYPE", "ECHORESPONSE", (s.start, s.len()))
            }),
            tag(Token::CreateSessionRequest).map(|(_, s)| {
                ParsedField::L7StringField("MSG_TYPE", "CREATESESSIONREQUEST", (s.start, s.len()))
            }),
            tag(Token::CreateSessionResponse).map(|(_, s)| {
                ParsedField::L7StringField("MSG_TYPE", "CREATESESSIONRESPONSE", (s.start, s.len()))
            }),
            tag(Token::ModifyBearerRequest).map(|(_, s)| {
                ParsedField::L7StringField("MSG_TYPE", "MODIFYBEARERREQUEST", (s.start, s.len()))
            }),
        )),
        alt((
            tag(Token::ModifyBearerResponse).map(|(_, s)| {
                ParsedField::L7StringField("MSG_TYPE", "MODIFYBEARERRESPONSE", (s.start, s.len()))
            }),
            tag(Token::DeleteSessionRequest).map(|(_, s)| {
                ParsedField::L7StringField("MSG_TYPE", "DELETESESSIONREQUEST", (s.start, s.len()))
            }),
            tag(Token::DeleteSessionResponse).map(|(_, s)| {
                ParsedField::L7StringField("MSG_TYPE", "DELETESESSIONRESPONSE", (s.start, s.len()))
            }),
            (tag(Token::MsgType), cut_err(parse_any_str)).map(|((_, s), v)| {
                ParsedField::L7StringField("MSG_TYPE", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Teid), cut_err(parse_u32))
                .map(|((_, s), v)| ParsedField::L7U32Field("TEID", v, (s.start, s.end - s.start))),
            (tag(Token::SeqNum), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("SEQ_NUM", v, (s.start, s.end - s.start))
            }),
        )),
        alt((
            (tag(Token::Cause), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("CAUSE", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Imsi), cut_err(parse_any_str)).map(|((_, s), v)| {
                ParsedField::L7StringField("IMSI", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Apn), cut_err(parse_any_str))
                .map(|((_, s), v)| ParsedField::L7StringField("APN", v, (s.start, s.end - s.start))),
            (tag(Token::Rat), cut_err(parse_u32))
                .map(|((_, s), v)| ParsedField::L7U32Field("RAT", v, (s.start, s.end - s.start))),
            (tag(Token::Recovery), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("RECOVERY", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Addr), cut_err(parse_ip))
                .map(|((_, s), v)| ParsedField::L7IpField("ADDR", v, (s.start, s.end - s.start))),
        )),
    ))
    .parse_next(input)
}
