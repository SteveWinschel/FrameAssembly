//! IEEE 802.1D Spanning Tree (`STP`) and IEEE 802.1w Rapid Spanning Tree (`RSTP`) BPDU parser.
//!
//! This module implements the winnow parser combinator for Spanning Tree Protocol Bridge Protocol
//! Data Units (BPDUs). It supports root bridge identifier (`ROOT_ID`), designated bridge identifier
//! (`BRIDGE_ID`), port identifier (`PORT_ID`), root path cost (`COST`), timer parameters (`MAX_AGE`,
//! `HELLO_TIME`, `FORWARD_DELAY`), topology change flags (`FLAGS`), and Rapid Spanning Tree mode (`RSTP`).

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{ParsedField, Stream, parse_str_val, parse_u8, parse_u16, parse_u32, tag};

/// Parses an STP protocol declaration or BPDU field.
pub(crate) fn parse_stp_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        alt((
            tag(Token::Stp).map(|(_, s)| ParsedField::Protocol(Protocol::Stp, (s.start, s.len()))),
            (tag(Token::RootId), cut_err(parse_str_val))
                .map(|((_, s), v)| ParsedField::RootId(v, (s.start, s.end - s.start))),
            (tag(Token::BridgeId), cut_err(parse_str_val))
                .map(|((_, s), v)| ParsedField::BridgeId(v, (s.start, s.end - s.start))),
            (
                tag(Token::PortId),
                cut_err(alt((
                    parse_u16.map(|p| (None, Some(p))),
                    parse_str_val.map(|s| (Some(s), None)),
                ))),
            )
                .map(|((_, s), (ps, pu))| ParsedField::PortIdVal(ps, pu, (s.start, s.end - s.start))),
            (tag(Token::Cost), cut_err(parse_u32))
                .map(|((_, s), v)| ParsedField::Cost(v, (s.start, s.end - s.start))),
        )),
        alt((
            (tag(Token::MaxAge), cut_err(parse_u16))
                .map(|((_, s), v)| ParsedField::MaxAge(v, (s.start, s.end - s.start))),
            (tag(Token::HelloTime), cut_err(parse_u16))
                .map(|((_, s), v)| ParsedField::HelloTime(v, (s.start, s.end - s.start))),
            (tag(Token::ForwardDelay), cut_err(parse_u16))
                .map(|((_, s), v)| ParsedField::ForwardDelay(v, (s.start, s.end - s.start))),
            tag(Token::Rstp).map(|(_, s)| ParsedField::Rstp((s.start, s.len()))),
            (tag(Token::Flags), cut_err(parse_u8))
                .map(|((_, s), v)| ParsedField::FlagsByte(v, (s.start, s.end - s.start))),
        )),
    ))
    .parse_next(input)
}
