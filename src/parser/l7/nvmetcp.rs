//! NVM Express over Fabrics TCP Transport (`nvmetcp`) Layer 7 storage field parser.
//!
//! This module implements the `winnow` parser combinator for NVMe/TCP (`nvmetcp`) storage
//! fabric PDUs in FrameAssembly `.frasm` specifications. It recognizes the `nvmetcp` protocol
//! keyword, PDU type shorthands (`icreq`, `icresp`, `read`, `write`, `response`, `h2cdata`,
//! `c2hdata`, `r2t`) and explicit `msgtype`/`cmd` selectors, SQE `opcode`, namespace `nsid`,
//! queue `qid`, command ID (`reqid`), PDU `flags`, completion `status`, LBA/data `offset`, and
//! transfer `count`.

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{parse_any_str, parse_u32, tag, ParsedField, Stream};

/// Parses an NVMe/TCP protocol declaration or fabric PDU modifier field.
pub(crate) fn parse_nvmetcp_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        alt((
            tag(Token::Nvmetcp)
                .map(|(_, s)| ParsedField::Protocol(Protocol::Nvmetcp, (s.start, s.len()))),
            tag(Token::Icreq)
                .map(|(_, s)| ParsedField::L7StringField("MSG_TYPE", "ICREQ", (s.start, s.len()))),
            tag(Token::Icresp)
                .map(|(_, s)| ParsedField::L7StringField("MSG_TYPE", "ICRESP", (s.start, s.len()))),
            tag(Token::Read)
                .map(|(_, s)| ParsedField::L7StringField("MSG_TYPE", "READ", (s.start, s.len()))),
            tag(Token::Write)
                .map(|(_, s)| ParsedField::L7StringField("MSG_TYPE", "WRITE", (s.start, s.len()))),
            tag(Token::Response).map(|(_, s)| {
                ParsedField::L7StringField("MSG_TYPE", "CAPSULERESP", (s.start, s.len()))
            }),
            tag(Token::H2cdata).map(|(_, s)| {
                ParsedField::L7StringField("MSG_TYPE", "H2CDATA", (s.start, s.len()))
            }),
        )),
        alt((
            tag(Token::C2hdata).map(|(_, s)| {
                ParsedField::L7StringField("MSG_TYPE", "C2HDATA", (s.start, s.len()))
            }),
            tag(Token::R2t)
                .map(|(_, s)| ParsedField::L7StringField("MSG_TYPE", "R2T", (s.start, s.len()))),
            (tag(Token::MsgType), parse_any_str).map(|((_, s), v)| {
                ParsedField::L7StringField("MSG_TYPE", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Cmd), parse_any_str).map(|((_, s), v)| {
                ParsedField::L7StringField("MSG_TYPE", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Opcode), parse_u32).map(|((_, s), v)| {
                ParsedField::L7U32Field("OPCODE", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Nsid), cut_err(parse_u32))
                .map(|((_, s), v)| ParsedField::L7U32Field("NSID", v, (s.start, s.end - s.start))),
            (tag(Token::Qid), cut_err(parse_u32))
                .map(|((_, s), v)| ParsedField::L7U32Field("QID", v, (s.start, s.end - s.start))),
        )),
        alt((
            (tag(Token::ReqId), parse_u32).map(|((_, s), v)| {
                ParsedField::L7U32Field("REQ_ID", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Flags), parse_u32)
                .map(|((_, s), v)| ParsedField::L7U32Field("FLAGS", v, (s.start, s.end - s.start))),
            (tag(Token::Status), parse_u32).map(|((_, s), v)| {
                ParsedField::L7U32Field("STATUS", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Offset), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("OFFSET", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Count), parse_u32).map(|((_, s), v)| {
                ParsedField::L7U32Field("NVME_COUNT", v, (s.start, s.end - s.start))
            }),
        )),
    ))
    .parse_next(input)
}
