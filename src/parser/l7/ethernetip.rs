//! EtherNet/IP (Common Industrial Protocol over TCP/UDP) Layer 7 field parser.
//!
//! This module implements the `winnow` parser combinator for ODVA `ethernetip` encapsulation and
//! Common Industrial Protocol (`CIP`) frames in FrameAssembly `.fasm` specifications. It
//! recognizes the `ethernetip` protocol keyword, explicit `cmd` strings, shorthand encapsulation
//! commands (`nop`, `listidentity`, `listinterfaces`, `listservices`, `registersession`,
//! `unregistersession`, `sendrrdata`, `sendunitdata`), `status` codes, `sessionhandle` IDs,
//! 64-bit `context` values, and CIP object path attributes (`cipservice`, `cipclass`,
//! `cipinstance`, `cipattr`).

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{parse_any_str, parse_u32, parse_u64, tag, ParsedField, Stream};

/// Parses an EtherNet/IP protocol declaration or CIP session field.
pub(crate) fn parse_ethernetip_field<'i, 'a>(
    input: &mut Stream<'i, 'a>,
) -> PResult<ParsedField<'a>> {
    alt((
        alt((
            tag(Token::Ethernetip)
                .map(|(_, s)| ParsedField::Protocol(Protocol::Ethernetip, (s.start, s.len()))),
            tag(Token::Nop)
                .map(|(_, s)| ParsedField::L7StringField("CMD", "NOP", (s.start, s.len()))),
            tag(Token::ListIdentity).map(|(_, s)| {
                ParsedField::L7StringField("CMD", "LIST_IDENTITY", (s.start, s.len()))
            }),
            tag(Token::ListInterfaces).map(|(_, s)| {
                ParsedField::L7StringField("CMD", "LIST_INTERFACES", (s.start, s.len()))
            }),
            tag(Token::ListServices).map(|(_, s)| {
                ParsedField::L7StringField("CMD", "LIST_SERVICES", (s.start, s.len()))
            }),
            tag(Token::RegisterSession).map(|(_, s)| {
                ParsedField::L7StringField("CMD", "REGISTER_SESSION", (s.start, s.len()))
            }),
            tag(Token::UnregisterSession).map(|(_, s)| {
                ParsedField::L7StringField("CMD", "UNREGISTER_SESSION", (s.start, s.len()))
            }),
            tag(Token::SendRrData).map(|(_, s)| {
                ParsedField::L7StringField("CMD", "SEND_RR_DATA", (s.start, s.len()))
            }),
            tag(Token::SendUnitData).map(|(_, s)| {
                ParsedField::L7StringField("CMD", "SEND_UNIT_DATA", (s.start, s.len()))
            }),
        )),
        alt((
            (tag(Token::Cmd), parse_any_str)
                .map(|((_, s), v)| ParsedField::L7StringField("CMD", v, (s.start, s.end - s.start))),
            (tag(Token::Status), parse_u32).map(|((_, s), v)| {
                ParsedField::L7U32Field("STATUS", v, (s.start, s.end - s.start))
            }),
            (tag(Token::SessionHandle), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("SESSION_HANDLE", v, (s.start, s.end - s.start))
            }),
            (tag(Token::ContextVal), cut_err(parse_u64)).map(|((_, s), v)| {
                ParsedField::L7U64Field("CONTEXT", v, (s.start, s.end - s.start))
            }),
            (tag(Token::CipService), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("CIP_SERVICE", v, (s.start, s.end - s.start))
            }),
            (tag(Token::CipClass), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("CIP_CLASS", v, (s.start, s.end - s.start))
            }),
            (tag(Token::CipInstance), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("CIP_INSTANCE", v, (s.start, s.end - s.start))
            }),
            (tag(Token::CipAttr), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("CIP_ATTR", v, (s.start, s.end - s.start))
            }),
        )),
    ))
    .parse_next(input)
}
