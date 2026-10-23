//! sFlow Layer 7 network sampling protocol field parser.

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{parse_ip, parse_u32, tag, ParsedField, Stream};

/// Parses an sFlow protocol declaration or packet sample field.
pub(crate) fn parse_sflow_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        tag(Token::Sflow).map(|(_, s)| ParsedField::Protocol(Protocol::Sflow, (s.start, s.len()))),
        (tag(Token::AgentIpSflow), cut_err(parse_ip)).map(|((_, s), v)| ParsedField::L7IpField("AGENT_IP", v, (s.start, s.end - s.start))),
        (tag(Token::SubAgentId), cut_err(parse_u32)).map(|((_, s), v)| ParsedField::L7U32Field("SUB_AGENT_ID", v, (s.start, s.end - s.start))),
        (tag(Token::Uptime), cut_err(parse_u32)).map(|((_, s), v)| ParsedField::L7U32Field("UPTIME", v, (s.start, s.end - s.start))),
        (tag(Token::Samples), cut_err(parse_u32)).map(|((_, s), v)| ParsedField::L7U32Field("SAMPLES", v, (s.start, s.end - s.start))),
    ))
    .parse_next(input)
}
