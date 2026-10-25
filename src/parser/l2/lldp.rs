//! IEEE 802.1AB Link Layer Discovery Protocol (`LLDP`) TLV parser for FrameAssembly.
//!
//! This module implements the winnow parser combinator for `LLDP` neighbor discovery frames.
//! It parses mandatory and optional Type-Length-Value (TLV) attributes including Chassis ID
//! (`CHASSIS_ID`), Port ID (`PORT_ID`), System Name (`SYSNAME`), and System Description
//! (`SYSDESC`) so the backend builder can serialize standards-compliant LLDP Data Units.

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{ParsedField, Stream, parse_str_val, parse_u16, tag};

/// Parses an LLDP protocol declaration or TLV field.
pub(crate) fn parse_lldp_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        tag(Token::Lldp).map(|(_, s)| ParsedField::Protocol(Protocol::Lldp, (s.start, s.len()))),
        (tag(Token::ChassisId), cut_err(parse_str_val))
            .map(|((_, s), v)| ParsedField::ChassisId(v, (s.start, s.end - s.start))),
        (tag(Token::SysName), cut_err(parse_str_val))
            .map(|((_, s), v)| ParsedField::SysName(v, (s.start, s.end - s.start))),
        (tag(Token::SysDesc), cut_err(parse_str_val))
            .map(|((_, s), v)| ParsedField::SysDesc(v, (s.start, s.end - s.start))),
        (
            tag(Token::PortId),
            cut_err(alt((
                parse_u16.map(|p| (None, Some(p))),
                parse_str_val.map(|s| (Some(s), None)),
            ))),
        )
            .map(|((_, s), (ps, pu))| ParsedField::PortIdVal(ps, pu, (s.start, s.end - s.start))),
    ))
    .parse_next(input)
}
