//! HART-IP (HCF Spec 085 Industrial Field Instrumentation) Layer 7 protocol field parser.
//!
//! This module implements the `winnow` parser combinator for FieldComm Group `hartip` frames
//! over UDP or TCP port 5094 in FrameAssembly `.frasm` specifications. It recognizes the `hartip`
//! protocol keyword, message ID shorthands (`init`, `close`, `keepalive`) and explicit `msgid`
//! values, response flags (`isresponse`, `response`), protocol `version`, `msgtype`, 8-bit
//! `status`, 16-bit transaction IDs (`txid`), Session Initiate `mode` and inactivity `holdtime`,
//! and embedded HART Token-Passing polling addresses (`addr`) and command numbers (`cmd`).

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err};
use winnow::error::{ContextError, ErrMode};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{ParsedField, Stream, parse_any_str, parse_u32, tag};

/// Parses a HART-IP Message ID (`msgid`) from a `0..=255` integer or mnemonic string.
fn parse_hartip_msgid<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<u32> {
    if let Ok(v) = parse_u32(input) {
        if v <= 255 {
            return Ok(v);
        }
        return Err(ErrMode::Backtrack(ContextError::new()));
    }
    let saved = *input;
    let raw = parse_any_str(input)?;
    let norm = raw.trim().to_ascii_lowercase().replace(['_', '-'], "");
    let id = match norm.as_str() {
        "init" | "initiate" | "sessioninitiate" => 0,
        "close" | "sessionclose" => 1,
        "keepalive" => 2,
        "pt" | "passthrough" | "tokenpassing" => 3,
        "direct" | "directpdu" => 4,
        "discovery" => 5,
        _ => {
            *input = saved;
            return Err(ErrMode::Backtrack(ContextError::new()));
        }
    };
    Ok(id)
}

/// Parses a HART-IP Message Type (`msgtype`) from an integer `0..=255` or mnemonic string.
fn parse_hartip_msgtype<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<&'a str> {
    let saved = *input;
    let raw = parse_any_str(input)?;
    let norm = raw.trim().to_ascii_lowercase().replace(['_', '-'], "");
    let valid = matches!(
        norm.as_str(),
        "0" | "1" | "2" | "3" | "req" | "request" | "resp" | "response" | "pub" | "publish" | "burst" | "nak" | "error"
    );
    if !valid {
        *input = saved;
        return Err(ErrMode::Backtrack(ContextError::new()));
    }
    Ok(raw)
}

/// Parses a HART-IP protocol declaration or message header modifier field.
pub(crate) fn parse_hartip_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        alt((
            tag(Token::Hartip)
                .map(|(_, s)| ParsedField::Protocol(Protocol::Hartip, (s.start, s.len()))),
            tag(Token::Init)
                .map(|(_, s)| ParsedField::L7U32Field("HART_MSG_ID", 0, (s.start, s.len()))),
            tag(Token::Close)
                .map(|(_, s)| ParsedField::L7U32Field("HART_MSG_ID", 1, (s.start, s.len()))),
            tag(Token::Keepalive)
                .map(|(_, s)| ParsedField::L7U32Field("HART_MSG_ID", 2, (s.start, s.len()))),
            tag(Token::IsResponse)
                .map(|(_, s)| ParsedField::L7Flag("IS_RESPONSE", (s.start, s.len()))),
            tag(Token::Response)
                .map(|(_, s)| ParsedField::L7Flag("IS_RESPONSE", (s.start, s.len()))),
        )),
        alt((
            (tag(Token::Version), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("HART_VERSION", v, (s.start, s.end - s.start))
            }),
            (tag(Token::MsgType), cut_err(parse_hartip_msgtype)).map(|((_, s), v)| {
                ParsedField::L7StringField("MSG_TYPE", v, (s.start, s.end - s.start))
            }),
            (tag(Token::MsgId), cut_err(parse_hartip_msgid)).map(|((_, s), v)| {
                ParsedField::L7U32Field("HART_MSG_ID", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Status), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("HART_STATUS", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Txid), cut_err(parse_u32))
                .map(|((_, s), v)| ParsedField::L7U32Field("TXID", v, (s.start, s.end - s.start))),
        )),
        alt((
            (tag(Token::Mode), cut_err(parse_u32))
                .map(|((_, s), v)| ParsedField::L7U32Field("MODE", v, (s.start, s.end - s.start))),
            (tag(Token::HoldTime), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("HOLD_TIME", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Addr), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("HART_ADDR", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Cmd), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("HART_CMD", v, (s.start, s.end - s.start))
            }),
        )),
    ))
    .parse_next(input)
}
