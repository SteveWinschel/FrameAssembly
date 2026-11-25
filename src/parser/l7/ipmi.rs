//! Intelligent Platform Management Interface (`ipmi`) Layer 7 protocol field parser.
//!
//! This module implements the `winnow` parser combinator for RMCP, ASF v2.0, IPMI v1.5, and
//! IPMI v2.0 (`RMCP+`) management packets over UDP port `623` in FrameAssembly `.frasm`
//! specifications. It recognizes the `ipmi` protocol keyword, ASF Presence `ping` and `pong`
//! shorthands, explicit `msgtype` selectors (`ipmi`, `ping`, `pong`, `opensession`,
//! `opensessionresp`, `rakp1` through `rakp4`), protocol `version`, `request`/`response` polarity,
//! `netfn`, `cmd`, `lun`, `rqseq`, `sessionid`, `seqnum`, and completion `status` attributes.

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{
    ParsedField, Stream, parse_any_str, parse_u32, parse_u64, tag,
};

/// Parses an IPMI / RMCP / ASF protocol declaration or management field.
pub(crate) fn parse_ipmi_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        alt((
            tag(Token::Ipmi)
                .map(|(_, s)| ParsedField::Protocol(Protocol::Ipmi, (s.start, s.len()))),
            tag(Token::Ping).map(|(_, s)| {
                ParsedField::L7StringField("MSG_TYPE", "PING", (s.start, s.len()))
            }),
            tag(Token::Pong).map(|(_, s)| {
                ParsedField::L7StringField("MSG_TYPE", "PONG", (s.start, s.len()))
            }),
            (tag(Token::MsgType), cut_err(parse_any_str)).map(|((_, s), v)| {
                ParsedField::L7StringField("MSG_TYPE", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Version), cut_err(parse_u32))
                .map(|((_, s), v)| ParsedField::L7U32Field("VERSION", v, (s.start, s.end - s.start))),
            tag(Token::Request)
                .map(|(_, s)| ParsedField::L7Flag("IPMI_REQUEST", (s.start, s.len()))),
            tag(Token::Response)
                .map(|(_, s)| ParsedField::L7Flag("RESPONSE", (s.start, s.len()))),
        )),
        alt((
            (tag(Token::Netfn), cut_err(parse_u32))
                .map(|((_, s), v)| ParsedField::L7U32Field("NETFN", v, (s.start, s.end - s.start))),
            (tag(Token::Cmd), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("IPMI_CMD", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Lun), cut_err(parse_u32))
                .map(|((_, s), v)| ParsedField::L7U32Field("LUN", v, (s.start, s.end - s.start))),
            (tag(Token::Rqseq), cut_err(parse_u32))
                .map(|((_, s), v)| ParsedField::L7U32Field("RQSEQ", v, (s.start, s.end - s.start))),
            (tag(Token::SessionId), cut_err(parse_u64)).map(|((_, s), v)| {
                ParsedField::L7U64Field("SESSION_ID", v, (s.start, s.end - s.start))
            }),
            (tag(Token::SeqNum), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("SEQ_NUM", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Status), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("STATUS", v, (s.start, s.end - s.start))
            }),
        )),
    ))
    .parse_next(input)
}
