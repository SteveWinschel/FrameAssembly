//! KNXnet/IP Building Automation (ISO/IEC 14543-3 / EN 50090) Layer 7 field parser.
//!
//! This module implements the `winnow` combinator parser for ISO/IEC 14543-3 `knxnetip` frames
//! over UDP port 3671 in FrameAssembly `.frasm` specifications. It recognizes the `knxnetip`
//! protocol keyword, connection management shorthands (`connect`, `connack`, `disconnect`) and
//! explicit `service` names or 16-bit codes, communication channel IDs (`channel`), tunneling
//! sequence counters (`seqnum`), status codes (`status`), KNX source and group destination
//! addresses (`src`, `dst`), and cEMI `read`/`write` `value` fields.

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{ParsedField, Stream, parse_any_str, parse_u32, tag};

/// Parses a KNXnet/IP protocol declaration or building automation field.
pub(crate) fn parse_knxnetip_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        alt((
            tag(Token::Knxnetip)
                .map(|(_, s)| ParsedField::Protocol(Protocol::Knxnetip, (s.start, s.len()))),
            tag(Token::Connect).map(|(_, s)| {
                ParsedField::L7StringField("KNX_SERVICE", "connectreq", (s.start, s.len()))
            }),
            tag(Token::Connack).map(|(_, s)| {
                ParsedField::L7StringField("KNX_SERVICE", "connectresp", (s.start, s.len()))
            }),
            tag(Token::Disconnect).map(|(_, s)| {
                ParsedField::L7StringField("KNX_SERVICE", "disconnectreq", (s.start, s.len()))
            }),
            (tag(Token::Service), cut_err(parse_any_str)).map(|((_, s), v)| {
                ParsedField::L7StringField("KNX_SERVICE", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Channel), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("KNX_CHANNEL", v, (s.start, s.end - s.start))
            }),
            (tag(Token::SeqNum), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("KNX_SEQ", v, (s.start, s.end - s.start))
            }),
        )),
        alt((
            (tag(Token::Status), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("KNX_STATUS", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Src), cut_err(parse_u32))
                .map(|((_, s), v)| ParsedField::L7U32Field("SRC", v, (s.start, s.end - s.start))),
            (tag(Token::Dst), cut_err(parse_u32))
                .map(|((_, s), v)| ParsedField::L7U32Field("DST", v, (s.start, s.end - s.start))),
            tag(Token::Read)
                .map(|(_, s)| ParsedField::L7Flag("KNX_READ", (s.start, s.len()))),
            tag(Token::Write)
                .map(|(_, s)| ParsedField::L7Flag("KNX_WRITE", (s.start, s.len()))),
            (tag(Token::Value), cut_err(parse_u32))
                .map(|((_, s), v)| ParsedField::L7U32Field("VALUE", v, (s.start, s.end - s.start))),
        )),
    ))
    .parse_next(input)
}
