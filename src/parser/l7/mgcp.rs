//! Media Gateway Control Protocol (MGCP, RFC 3435) Layer 7 signaling field parser.
//!
//! This module implements the `winnow` parser combinator for RFC 3435 `mgcp` gateway control
//! commands and responses over UDP ports 2427 and 2727 in FrameAssembly `.frasm` specifications.
//! It recognizes the `mgcp` protocol keyword, command verb shorthands (`crcx`, `mdcx`, `dlcx`,
//! `rqnt`, `ntfy`, `auep`, `aucx`, `rsip`), explicit `method`, transaction IDs (`txid`),
//! `endpoint` targets, response `status` and `reason`, `callid`, `connid`, `localopts`, `mode`,
//! and SDP `body` payloads.

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{
    ParsedField, Stream, parse_any_str, parse_str_val, parse_u32, tag,
};

/// Parses an RFC 3435 MGCP protocol declaration or signaling attribute field.
pub(crate) fn parse_mgcp_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        alt((
            tag(Token::Mgcp).map(|(_, s)| ParsedField::Protocol(Protocol::Mgcp, (s.start, s.len()))),
            tag(Token::Crcx)
                .map(|(_, s)| ParsedField::L7StringField("METHOD", "CRCX", (s.start, s.len()))),
            tag(Token::Mdcx)
                .map(|(_, s)| ParsedField::L7StringField("METHOD", "MDCX", (s.start, s.len()))),
            tag(Token::Dlcx)
                .map(|(_, s)| ParsedField::L7StringField("METHOD", "DLCX", (s.start, s.len()))),
            tag(Token::Rqnt)
                .map(|(_, s)| ParsedField::L7StringField("METHOD", "RQNT", (s.start, s.len()))),
            tag(Token::Ntfy)
                .map(|(_, s)| ParsedField::L7StringField("METHOD", "NTFY", (s.start, s.len()))),
            tag(Token::Auep)
                .map(|(_, s)| ParsedField::L7StringField("METHOD", "AUEP", (s.start, s.len()))),
            tag(Token::Aucx)
                .map(|(_, s)| ParsedField::L7StringField("METHOD", "AUCX", (s.start, s.len()))),
        )),
        alt((
            tag(Token::Rsip)
                .map(|(_, s)| ParsedField::L7StringField("METHOD", "RSIP", (s.start, s.len()))),
            (tag(Token::Method), cut_err(parse_any_str)).map(|((_, s), v)| {
                ParsedField::L7StringField("METHOD", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Txid), cut_err(parse_u32))
                .map(|((_, s), v)| ParsedField::L7U32Field("TXID", v, (s.start, s.end - s.start))),
            (tag(Token::Endpoint), cut_err(parse_str_val)).map(|((_, s), v)| {
                ParsedField::L7StringField("ENDPOINT", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Status), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("STATUS", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Reason), cut_err(parse_str_val)).map(|((_, s), v)| {
                ParsedField::L7StringField("REASON", v, (s.start, s.end - s.start))
            }),
        )),
        alt((
            (tag(Token::CallId), cut_err(parse_any_str)).map(|((_, s), v)| {
                ParsedField::L7StringField("CALL_ID", v, (s.start, s.end - s.start))
            }),
            (tag(Token::ConnId), cut_err(parse_any_str)).map(|((_, s), v)| {
                ParsedField::L7StringField("CONN_ID", v, (s.start, s.end - s.start))
            }),
            (tag(Token::LocalOpts), cut_err(parse_str_val)).map(|((_, s), v)| {
                ParsedField::L7StringField("LOCAL_OPTS", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Mode), cut_err(parse_any_str)).map(|((_, s), v)| {
                ParsedField::L7StringField("MODE", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Body), cut_err(parse_str_val)).map(|((_, s), v)| {
                ParsedField::L7StringField("BODY", v, (s.start, s.end - s.start))
            }),
        )),
    ))
    .parse_next(input)
}
