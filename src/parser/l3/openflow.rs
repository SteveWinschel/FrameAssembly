//! OpenFlow Layer 3 SDN control protocol field parser.

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{parse_u16, parse_u32, parse_u64, parse_u8, tag, ParsedField, Stream};

/// Parses an OpenFlow protocol declaration or SDN message field.
pub(crate) fn parse_openflow_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        alt((
            tag(Token::Openflow).map(|(_, s)| ParsedField::Protocol(Protocol::Openflow, (s.start, s.len()))),
            (tag(Token::Version), cut_err(parse_u8)).map(|((_, s), v)| ParsedField::VersionByte(v, (s.start, s.end - s.start))),
            (tag(Token::Xid), cut_err(parse_u32)).map(|((_, s), v)| ParsedField::Xid(v, (s.start, s.end - s.start))),
            (tag(Token::Dpid), cut_err(parse_u64)).map(|((_, s), v)| ParsedField::Dpid(v, (s.start, s.end - s.start))),
            (tag(Token::TableId), cut_err(parse_u8)).map(|((_, s), v)| ParsedField::TableId(v, (s.start, s.end - s.start))),
            (tag(Token::Priority), cut_err(parse_u16)).map(|((_, s), v)| ParsedField::PriorityVal(v, (s.start, s.end - s.start))),
        )),
        alt((
            tag(Token::FeaturesReq).map(|(_, s)| ParsedField::OpenflowType(OpenflowType::FeaturesReq, (s.start, s.len()))),
            tag(Token::FeaturesReply).map(|(_, s)| ParsedField::OpenflowType(OpenflowType::FeaturesReply, (s.start, s.len()))),
            tag(Token::PacketIn).map(|(_, s)| ParsedField::OpenflowType(OpenflowType::PacketIn, (s.start, s.len()))),
            tag(Token::PacketOut).map(|(_, s)| ParsedField::OpenflowType(OpenflowType::PacketOut, (s.start, s.len()))),
            tag(Token::FlowMod).map(|(_, s)| ParsedField::OpenflowType(OpenflowType::FlowMod, (s.start, s.len()))),
            tag(Token::EchoReq).map(|(_, s)| ParsedField::OpenflowType(OpenflowType::EchoReq, (s.start, s.len()))),
            tag(Token::EchoReply).map(|(_, s)| ParsedField::OpenflowType(OpenflowType::EchoReply, (s.start, s.len()))),
        )),
    ))
    .parse_next(input)
}
