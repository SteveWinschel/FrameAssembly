//! Diagnostics over Internet Protocol (DoIP, ISO 13400-2) Layer 7 automotive field parser.
//!
//! This module implements the `winnow` parser combinator for ISO 13400 `doip` automotive
//! diagnostic frames over TCP and UDP port 13400 in FrameAssembly `.frasm` specifications. It
//! recognizes the `doip` protocol keyword, ISO 13400 payload types (`routingreq`, `routingresp`,
//! `diagnostic`, `diagack`, `diagnack`, `vehicleid`, `vehicleeid`, `vehiclevin`, `announcement`,
//! `alivecheckreq`, `alivecheckresp`, `nack`, `msgtype`), protocol versions (`version`,
//! `invversion`), logical tester/ECU addresses (`src`, `dst`), activation/ACK/NACK `code` bytes,
//! 17-character `vin` strings, and 6-byte `eid`/`gid` identifiers.

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err};
use winnow::error::{ContextError, ErrMode};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{
    ParsedField, Stream, parse_any_str, parse_hex_payload, parse_mac, parse_str_val, parse_u32,
    parse_u64, tag,
};

/// Parses a 6-byte DoIP `eid` or `gid` identifier from MAC notation, 12-hex-digit string, or `u64`.
fn parse_doip_6byte_id<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<[u8; 6]> {
    if let Ok(mac) = parse_mac(input) {
        return Ok(mac);
    }
    let saved = *input;
    if let Ok(bytes) = parse_hex_payload(input) {
        if bytes.len() == 6 {
            let mut arr = [0u8; 6];
            arr.copy_from_slice(&bytes);
            return Ok(arr);
        }
        *input = saved;
        return Err(ErrMode::Cut(ContextError::new()));
    }
    *input = saved;
    if let Ok(val) = parse_u64(input)
        && val <= 0xFFFF_FFFF_FFFF
    {
        let be = val.to_be_bytes();
        return Ok([be[2], be[3], be[4], be[5], be[6], be[7]]);
    }
    *input = saved;
    Err(ErrMode::Backtrack(ContextError::new()))
}

/// Parses an ISO 13400 DoIP protocol declaration or diagnostic session field.
pub(crate) fn parse_doip_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        alt((
            tag(Token::Doip)
                .map(|(_, s)| ParsedField::Protocol(Protocol::Doip, (s.start, s.len()))),
            tag(Token::RoutingReq).map(|(_, s)| {
                ParsedField::L7StringField("MSG_TYPE", "ROUTINGREQ", (s.start, s.len()))
            }),
            tag(Token::RoutingResp).map(|(_, s)| {
                ParsedField::L7StringField("MSG_TYPE", "ROUTINGRESP", (s.start, s.len()))
            }),
            tag(Token::Diagnostic).map(|(_, s)| {
                ParsedField::L7StringField("MSG_TYPE", "DIAGNOSTIC", (s.start, s.len()))
            }),
            tag(Token::DiagAck).map(|(_, s)| {
                ParsedField::L7StringField("MSG_TYPE", "DIAGACK", (s.start, s.len()))
            }),
            tag(Token::DiagNack).map(|(_, s)| {
                ParsedField::L7StringField("MSG_TYPE", "DIAGNACK", (s.start, s.len()))
            }),
            tag(Token::VehicleId).map(|(_, s)| {
                ParsedField::L7StringField("MSG_TYPE", "VEHICLEID", (s.start, s.len()))
            }),
            tag(Token::VehicleEid).map(|(_, s)| {
                ParsedField::L7StringField("MSG_TYPE", "VEHICLEEID", (s.start, s.len()))
            }),
        )),
        alt((
            tag(Token::VehicleVin).map(|(_, s)| {
                ParsedField::L7StringField("MSG_TYPE", "VEHICLEVIN", (s.start, s.len()))
            }),
            tag(Token::Announcement).map(|(_, s)| {
                ParsedField::L7StringField("MSG_TYPE", "ANNOUNCEMENT", (s.start, s.len()))
            }),
            tag(Token::AliveCheckReq).map(|(_, s)| {
                ParsedField::L7StringField("MSG_TYPE", "ALIVECHECKREQ", (s.start, s.len()))
            }),
            tag(Token::AliveCheckResp).map(|(_, s)| {
                ParsedField::L7StringField("MSG_TYPE", "ALIVECHECKRESP", (s.start, s.len()))
            }),
            tag(Token::Nack)
                .map(|(_, s)| ParsedField::L7StringField("MSG_TYPE", "NACK", (s.start, s.len()))),
            (tag(Token::MsgType), cut_err(parse_any_str)).map(|((_, s), v)| {
                ParsedField::L7StringField("MSG_TYPE", v, (s.start, s.end - s.start))
            }),
        )),
        alt((
            (tag(Token::Version), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("DOIP_VERSION", v, (s.start, s.end - s.start))
            }),
            (tag(Token::InvVersion), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("DOIP_INV_VERSION", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Src), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("DOIP_SRC", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Dst), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("DOIP_DST", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Code), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("DOIP_CODE", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Vin), cut_err(parse_str_val)).map(|((_, s), v)| {
                ParsedField::L7StringField("DOIP_VIN", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Eid), cut_err(parse_doip_6byte_id)).map(|((_, s), m)| {
                ParsedField::L7MacField("DOIP_EID", m, (s.start, s.end - s.start))
            }),
            (tag(Token::Gid), cut_err(parse_doip_6byte_id)).map(|((_, s), m)| {
                ParsedField::L7MacField("DOIP_GID", m, (s.start, s.end - s.start))
            }),
        )),
    ))
    .parse_next(input)
}
