//! OpenFlow (`OPENFLOW`) Software-Defined Networking control-plane parser for FrameAssembly.
//!
//! This module implements the winnow parser combinator for `OPENFLOW` SDN controller-to-switch
//! messages over TCP port 6653. It supports both explicit (`TYPE HELLO`, `TYPE FEATURES_REQ`,
//! `TYPE PACKET_IN`, etc.) and bare shorthand message types (`HELLO`, `FEATURES_REQ`,
//! `FEATURES_REPLY`, `PACKET_IN`, `PACKET_OUT`, `FLOW_MOD`, `ECHO_REQ`/`ECHO_REQUEST`,
//! `ECHO_REPLY`), alongside `VERSION`, `XID`, `DPID`, `TABLE_ID`, and `PRIORITY`.

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err, opt};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{ParsedField, Stream, parse_u8, parse_u16, parse_u32, parse_u64, tag};

/// Parses an OpenFlow protocol declaration or SDN message field.
pub(crate) fn parse_openflow_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        alt((
            tag(Token::Openflow)
                .map(|(_, s)| ParsedField::Protocol(Protocol::Openflow, (s.start, s.len()))),
            (tag(Token::Version), parse_u8)
                .map(|((_, s), v)| ParsedField::VersionByte(v, (s.start, s.end - s.start))),
            (tag(Token::Xid), cut_err(parse_u32))
                .map(|((_, s), v)| ParsedField::Xid(v, (s.start, s.end - s.start))),
            (tag(Token::Dpid), cut_err(parse_u64))
                .map(|((_, s), v)| ParsedField::Dpid(v, (s.start, s.end - s.start))),
            (tag(Token::TableId), cut_err(parse_u8))
                .map(|((_, s), v)| ParsedField::TableId(v, (s.start, s.end - s.start))),
            (tag(Token::Priority), parse_u16)
                .map(|((_, s), v)| ParsedField::PriorityVal(v, (s.start, s.end - s.start))),
        )),
        (
            opt(tag(Token::Type)),
            alt((
                tag(Token::FeaturesReq).map(|(_, s)| {
                    ParsedField::OpenflowType(OpenflowType::FeaturesReq, (s.start, s.len()))
                }),
                tag(Token::FeaturesReply).map(|(_, s)| {
                    ParsedField::OpenflowType(OpenflowType::FeaturesReply, (s.start, s.len()))
                }),
                tag(Token::PacketIn).map(|(_, s)| {
                    ParsedField::OpenflowType(OpenflowType::PacketIn, (s.start, s.len()))
                }),
                tag(Token::PacketOut).map(|(_, s)| {
                    ParsedField::OpenflowType(OpenflowType::PacketOut, (s.start, s.len()))
                }),
                tag(Token::FlowMod).map(|(_, s)| {
                    ParsedField::OpenflowType(OpenflowType::FlowMod, (s.start, s.len()))
                }),
                alt((tag(Token::EchoReq), tag(Token::EchoRequest))).map(|(_, s)| {
                    ParsedField::OpenflowType(OpenflowType::EchoReq, (s.start, s.len()))
                }),
                tag(Token::EchoReply).map(|(_, s)| {
                    ParsedField::OpenflowType(OpenflowType::EchoReply, (s.start, s.len()))
                }),
                tag(Token::Hello).map(|(_, s)| ParsedField::HelloWord((s.start, s.len()))),
            )),
        )
            .map(|(opt_t, mut field)| {
                if let Some((_, s1)) = opt_t {
                    match &mut field {
                        ParsedField::OpenflowType(_, span) | ParsedField::HelloWord(span) => {
                            let end = span.0 + span.1;
                            *span = (s1.start, end - s1.start);
                        }
                        _ => {}
                    }
                }
                field
            }),
    ))
    .parse_next(input)
}
