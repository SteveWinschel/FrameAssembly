//! AUTOSAR SOME/IP and SOME/IP-SD Layer 7 automotive Ethernet protocol field parser.
//!
//! This module implements the `winnow` parser combinator for AUTOSAR `someip` RPC and Service
//! Discovery (`someip-sd`) messages over UDP and TCP port 30490 in FrameAssembly `.frasm`
//! specifications. It recognizes the `someip` protocol keyword, RPC message type flags
//! (`request`, `requestnoreply`, `notification`, `response`, `error`, `msgtype`), header fields
//! (`serviceid`, `methodid`, `clientid`, `sessionid`, `protover`, `ifacever`, `returncode`),
//! and Service Discovery entry/option modifiers (`findservice`, `offerservice`, `subscribe`,
//! `subscribeack`, `flags`, `sdservice`, `instanceid`, `majorver`, `sdttl`, `minorver`,
//! `endpointip`, `endpointport`).

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{ParsedField, Stream, parse_any_str, parse_ip, parse_u32, tag};

/// Parses an AUTOSAR SOME/IP or SOME/IP-SD protocol declaration or field modifier.
pub(crate) fn parse_someip_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        alt((
            tag(Token::Someip)
                .map(|(_, s)| ParsedField::Protocol(Protocol::Someip, (s.start, s.len()))),
            tag(Token::FindService).map(|(_, s)| {
                ParsedField::L7StringField("SOMEIP_SD_TYPE", "FINDSERVICE", (s.start, s.len()))
            }),
            tag(Token::OfferService).map(|(_, s)| {
                ParsedField::L7StringField("SOMEIP_SD_TYPE", "OFFERSERVICE", (s.start, s.len()))
            }),
            tag(Token::Subscribe).map(|(_, s)| {
                ParsedField::L7StringField("SOMEIP_SD_TYPE", "SUBSCRIBE", (s.start, s.len()))
            }),
            tag(Token::SubscribeAck).map(|(_, s)| {
                ParsedField::L7StringField("SOMEIP_SD_TYPE", "SUBSCRIBEACK", (s.start, s.len()))
            }),
            tag(Token::Request).map(|(_, s)| {
                ParsedField::L7StringField("MSG_TYPE", "REQUEST", (s.start, s.len()))
            }),
            tag(Token::RequestNoReply).map(|(_, s)| {
                ParsedField::L7StringField("MSG_TYPE", "REQUESTNOREPLY", (s.start, s.len()))
            }),
        )),
        alt((
            tag(Token::Notification).map(|(_, s)| {
                ParsedField::L7StringField("MSG_TYPE", "NOTIFICATION", (s.start, s.len()))
            }),
            tag(Token::Response).map(|(_, s)| {
                ParsedField::L7StringField("MSG_TYPE", "RESPONSE", (s.start, s.len()))
            }),
            tag(Token::ErrorKw).map(|(_, s)| {
                ParsedField::L7StringField("MSG_TYPE", "ERROR", (s.start, s.len()))
            }),
            (tag(Token::MsgType), cut_err(parse_any_str)).map(|((_, s), v)| {
                ParsedField::L7StringField("MSG_TYPE", v, (s.start, s.end - s.start))
            }),
            (tag(Token::ServiceId), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("SOMEIP_SERVICE_ID", v, (s.start, s.end - s.start))
            }),
            (tag(Token::MethodId), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("SOMEIP_METHOD_ID", v, (s.start, s.end - s.start))
            }),
        )),
        alt((
            (tag(Token::ClientId), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("SOMEIP_CLIENT_ID", v, (s.start, s.end - s.start))
            }),
            (tag(Token::SessionId), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("SOMEIP_SESSION_ID", v, (s.start, s.end - s.start))
            }),
            (tag(Token::ProtoVer), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("SOMEIP_PROTO_VER", v, (s.start, s.end - s.start))
            }),
            (tag(Token::IfaceVer), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("SOMEIP_IFACE_VER", v, (s.start, s.end - s.start))
            }),
            (tag(Token::ReturnCode), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("SOMEIP_RETURN_CODE", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Flags), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("SOMEIP_SD_FLAGS", v, (s.start, s.end - s.start))
            }),
        )),
        alt((
            (tag(Token::SdService), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("SOMEIP_SD_SERVICE", v, (s.start, s.end - s.start))
            }),
            (tag(Token::InstanceId), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("SOMEIP_INSTANCE_ID", v, (s.start, s.end - s.start))
            }),
            (tag(Token::MajorVer), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("SOMEIP_MAJOR_VER", v, (s.start, s.end - s.start))
            }),
            (tag(Token::SdTtl), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("SOMEIP_SD_TTL", v, (s.start, s.end - s.start))
            }),
            (tag(Token::MinorVer), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("SOMEIP_MINOR_VER", v, (s.start, s.end - s.start))
            }),
            (tag(Token::EndpointIp), cut_err(parse_ip)).map(|((_, s), ip)| {
                ParsedField::L7IpField("SOMEIP_ENDPOINT_IP", ip, (s.start, s.end - s.start))
            }),
            (tag(Token::EndpointPort), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("SOMEIP_ENDPOINT_PORT", v, (s.start, s.end - s.start))
            }),
        )),
    ))
    .parse_next(input)
}
