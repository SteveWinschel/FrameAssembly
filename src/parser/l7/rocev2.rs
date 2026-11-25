//! RDMA over Converged Ethernet v2 (RoCEv2, IBTA Annex A17) Layer 7 field parser.
//!
//! This module implements the `winnow` combinator parser for IBTA Annex A17 `rocev2` frames over
//! UDP port 4791 in FrameAssembly `.frasm` specifications. It recognizes the `rocev2` protocol
//! keyword, RDMA operation shorthands (`read`, `write`) and explicit BTH `opcode` strings or
//! numeric codes, 16-bit Partition Keys (`pkey`), 24-bit Destination Queue Pairs (`destqp`),
//! Acknowledge Request flags (`ackreq`), 24-bit Packet Sequence Numbers (`seqnum`), 64-bit RETH
//! Virtual Addresses (`addr`), 32-bit Remote Keys (`key`) and DMA lengths (`count`), AETH
//! syndromes (`status`) and message numbers (`msgid`), and explicit `crc` ICRC overrides.

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{ParsedField, Stream, parse_any_str, parse_u32, parse_u64, tag};

/// Parses a RoCEv2 protocol declaration or InfiniBand BTH/RETH/AETH field.
pub(crate) fn parse_rocev2_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        alt((
            tag(Token::Rocev2)
                .map(|(_, s)| ParsedField::Protocol(Protocol::Rocev2, (s.start, s.len()))),
            tag(Token::Read).map(|(_, s)| {
                ParsedField::L7StringField("ROCE_OPCODE", "rdmaread", (s.start, s.len()))
            }),
            tag(Token::Write).map(|(_, s)| {
                ParsedField::L7StringField("ROCE_OPCODE", "rdmawrite", (s.start, s.len()))
            }),
            (tag(Token::Opcode), cut_err(parse_any_str)).map(|((_, s), v)| {
                ParsedField::L7StringField("ROCE_OPCODE", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Pkey), cut_err(parse_u32))
                .map(|((_, s), v)| ParsedField::L7U32Field("PKEY", v, (s.start, s.end - s.start))),
            (tag(Token::DestQp), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("DEST_QP", v, (s.start, s.end - s.start))
            }),
            tag(Token::AckReq)
                .map(|(_, s)| ParsedField::L7Flag("ACK_REQ", (s.start, s.len()))),
        )),
        alt((
            (tag(Token::SeqNum), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("ROCE_PSN", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Addr), cut_err(parse_u64)).map(|((_, s), v)| {
                ParsedField::L7U64Field("ROCE_VA", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Key), cut_err(parse_u32))
                .map(|((_, s), v)| ParsedField::L7U32Field("RKEY", v, (s.start, s.end - s.start))),
            (tag(Token::Count), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("DMA_LEN", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Status), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("ROCE_SYNDROME", v, (s.start, s.end - s.start))
            }),
            (tag(Token::MsgId), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("ROCE_MSN", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Crc), cut_err(parse_u32))
                .map(|((_, s), v)| ParsedField::L7U32Field("ICRC", v, (s.start, s.end - s.start))),
        )),
    ))
    .parse_next(input)
}
