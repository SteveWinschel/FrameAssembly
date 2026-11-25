//! Label Distribution Protocol (`ldp`, RFC 5036) field parser for FrameAssembly.
//!
//! This module implements the winnow parser combinator for `ldp` MPLS signaling messages over
//! TCP and UDP port `646`. It recognizes the `ldp` protocol keyword, message types (`hello`,
//! `init`, `keepalive`, `notification`, `labelmapping`, `labelrequest`, `labelwithdraw`,
//! `labelrelease`), LSR router identifiers (`lsrid <ipv4>`), `labelspace <u16>`, `msgid <u32>`,
//! `holdtime <u16>`, MPLS `label <u32>`, FEC `prefix "<cidr>"`, and Notification `status <u32>`.

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{ParsedField, Stream, parse_any_str, parse_ip, parse_u32, tag};

/// Parses an LDP protocol declaration, message type flag, or TLV field.
pub(crate) fn parse_ldp_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        alt((
            tag(Token::Ldp).map(|(_, s)| ParsedField::Protocol(Protocol::Ldp, (s.start, s.len()))),
            tag(Token::Hello)
                .map(|(_, s)| ParsedField::L7StringField("LDP_MSG", "hello", (s.start, s.len()))),
            tag(Token::Init)
                .map(|(_, s)| ParsedField::L7StringField("LDP_MSG", "init", (s.start, s.len()))),
            tag(Token::Keepalive).map(|(_, s)| {
                ParsedField::L7StringField("LDP_MSG", "keepalive", (s.start, s.len()))
            }),
            tag(Token::Notification).map(|(_, s)| {
                ParsedField::L7StringField("LDP_MSG", "notification", (s.start, s.len()))
            }),
            tag(Token::LabelMapping).map(|(_, s)| {
                ParsedField::L7StringField("LDP_MSG", "labelmapping", (s.start, s.len()))
            }),
            tag(Token::LabelRequest).map(|(_, s)| {
                ParsedField::L7StringField("LDP_MSG", "labelrequest", (s.start, s.len()))
            }),
            tag(Token::LabelWithdraw).map(|(_, s)| {
                ParsedField::L7StringField("LDP_MSG", "labelwithdraw", (s.start, s.len()))
            }),
        )),
        alt((
            tag(Token::LabelRelease).map(|(_, s)| {
                ParsedField::L7StringField("LDP_MSG", "labelrelease", (s.start, s.len()))
            }),
            (tag(Token::LsrId), cut_err(parse_ip)).map(|((_, s), v)| {
                ParsedField::L7IpField("LDP_LSR_ID", v, (s.start, s.end - s.start))
            }),
            (tag(Token::LabelSpace), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("LDP_LABEL_SPACE", v, (s.start, s.end - s.start))
            }),
            (tag(Token::MsgId), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("LDP_MSGID", v, (s.start, s.end - s.start))
            }),
            (tag(Token::HoldTime), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("LDP_HOLDTIME", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Label), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("LDP_LABEL", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Prefix), cut_err(parse_any_str)).map(|((_, s), v)| {
                ParsedField::L7StringField("LDP_PREFIX", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Status), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("LDP_STATUS", v, (s.start, s.end - s.start))
            }),
        )),
    ))
    .parse_next(input)
}
