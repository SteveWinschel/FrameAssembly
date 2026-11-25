//! Packet Forwarding Control Protocol (`pfcp`, 3GPP TS 29.244) Layer 7 field parser.
//!
//! This module implements the `winnow` parser combinator for 3GPP TS 29.244 `pfcp` N4/Sx
//! signaling frames over UDP port `8805` in FrameAssembly `.frasm` specifications. It recognizes
//! the `pfcp` protocol keyword, Node and Session message shorthands (`heartbeatrequest`,
//! `heartbeatresponse`, `associationsetuprequest`, `associationsetupresponse`,
//! `sessionestablishmentrequest`, `sessionestablishmentresponse`, `sessionmodificationrequest`,
//! `sessionmodificationresponse`, `sessiondeletionrequest`, `sessiondeletionresponse`, or
//! `msgtype`), 64-bit `seid`, 24-bit `seqnum`, `cause`, `nodeid`, and `recovery` attributes.

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{
    ParsedField, Stream, parse_any_str, parse_u32, parse_u64, tag,
};

/// Parses a PFCP protocol declaration or N4/Sx control-plane field.
pub(crate) fn parse_pfcp_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        alt((
            tag(Token::Pfcp)
                .map(|(_, s)| ParsedField::Protocol(Protocol::Pfcp, (s.start, s.len()))),
            tag(Token::HeartbeatRequest).map(|(_, s)| {
                ParsedField::L7StringField("MSG_TYPE", "HEARTBEATREQUEST", (s.start, s.len()))
            }),
            tag(Token::HeartbeatResponse).map(|(_, s)| {
                ParsedField::L7StringField("MSG_TYPE", "HEARTBEATRESPONSE", (s.start, s.len()))
            }),
            tag(Token::AssociationSetupRequest).map(|(_, s)| {
                ParsedField::L7StringField("MSG_TYPE", "ASSOCIATIONSETUPREQUEST", (s.start, s.len()))
            }),
            tag(Token::AssociationSetupResponse).map(|(_, s)| {
                ParsedField::L7StringField("MSG_TYPE", "ASSOCIATIONSETUPRESPONSE", (s.start, s.len()))
            }),
            tag(Token::SessionEstablishmentRequest).map(|(_, s)| {
                ParsedField::L7StringField(
                    "MSG_TYPE",
                    "SESSIONESTABLISHMENTREQUEST",
                    (s.start, s.len()),
                )
            }),
            tag(Token::SessionEstablishmentResponse).map(|(_, s)| {
                ParsedField::L7StringField(
                    "MSG_TYPE",
                    "SESSIONESTABLISHMENTRESPONSE",
                    (s.start, s.len()),
                )
            }),
        )),
        alt((
            tag(Token::SessionModificationRequest).map(|(_, s)| {
                ParsedField::L7StringField(
                    "MSG_TYPE",
                    "SESSIONMODIFICATIONREQUEST",
                    (s.start, s.len()),
                )
            }),
            tag(Token::SessionModificationResponse).map(|(_, s)| {
                ParsedField::L7StringField(
                    "MSG_TYPE",
                    "SESSIONMODIFICATIONRESPONSE",
                    (s.start, s.len()),
                )
            }),
            tag(Token::SessionDeletionRequest).map(|(_, s)| {
                ParsedField::L7StringField(
                    "MSG_TYPE",
                    "SESSIONDELETIONREQUEST",
                    (s.start, s.len()),
                )
            }),
            tag(Token::SessionDeletionResponse).map(|(_, s)| {
                ParsedField::L7StringField(
                    "MSG_TYPE",
                    "SESSIONDELETIONRESPONSE",
                    (s.start, s.len()),
                )
            }),
            (tag(Token::MsgType), cut_err(parse_any_str)).map(|((_, s), v)| {
                ParsedField::L7StringField("MSG_TYPE", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Seid), cut_err(parse_u64))
                .map(|((_, s), v)| ParsedField::L7U64Field("SEID", v, (s.start, s.end - s.start))),
        )),
        alt((
            (tag(Token::SeqNum), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("SEQ_NUM", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Cause), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("CAUSE", v, (s.start, s.end - s.start))
            }),
            (tag(Token::NodeId), cut_err(parse_any_str)).map(|((_, s), v)| {
                ParsedField::L7StringField("NODE_ID", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Recovery), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("RECOVERY", v, (s.start, s.end - s.start))
            }),
        )),
    ))
    .parse_next(input)
}
