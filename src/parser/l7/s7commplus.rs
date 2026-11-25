//! Siemens S7 Communication Plus (S7commPlus, `0x72` over ISO-on-TCP) Layer 7 field parser.
//!
//! This module implements the `winnow` parser combinator for Siemens `s7commplus` TIA Portal
//! S7-1200/S7-1500 frames over TCP port 102 in FrameAssembly `.frasm` specifications. It
//! recognizes the `s7commplus` protocol keyword, response modifiers (`isresponse`, `response`),
//! protocol version bytes (`version`), opcode numbers or mnemonics (`opcode`), function codes or
//! names (`func`), 16-bit sequence numbers (`seqnum`), 32-bit session identifiers (`sessionid`),
//! target object identifiers (`id`), and transport flags (`flags`).

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err};
use winnow::error::{ContextError, ErrMode};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{ParsedField, Stream, parse_any_str, parse_u32, tag};

/// Parses an S7commPlus opcode from an 8-bit integer or mnemonic (`request`, `response`, `notification`).
fn parse_s7plus_opcode<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<u32> {
    if let Ok(v) = parse_u32(input) {
        if v <= 255 {
            return Ok(v);
        }
        return Err(ErrMode::Backtrack(ContextError::new()));
    }
    let saved = *input;
    let raw = parse_any_str(input)?;
    let norm = raw.trim().to_ascii_lowercase().replace(['_', '-'], "");
    let code = match norm.as_str() {
        "req" | "request" => 0x31,
        "resp" | "response" => 0x32,
        "notify" | "notification" => 0x33,
        _ => {
            *input = saved;
            return Err(ErrMode::Backtrack(ContextError::new()));
        }
    };
    Ok(code)
}

/// Parses a Siemens S7commPlus protocol declaration or header modifier field.
pub(crate) fn parse_s7commplus_field<'i, 'a>(
    input: &mut Stream<'i, 'a>,
) -> PResult<ParsedField<'a>> {
    alt((
        alt((
            tag(Token::S7commplus)
                .map(|(_, s)| ParsedField::Protocol(Protocol::S7commplus, (s.start, s.len()))),
            tag(Token::IsResponse)
                .map(|(_, s)| ParsedField::L7Flag("IS_RESPONSE", (s.start, s.len()))),
            tag(Token::Response)
                .map(|(_, s)| ParsedField::L7Flag("IS_RESPONSE", (s.start, s.len()))),
            (tag(Token::Version), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("S7PLUS_VERSION", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Opcode), cut_err(parse_s7plus_opcode)).map(|((_, s), v)| {
                ParsedField::L7U32Field("OPCODE", v, (s.start, s.end - s.start))
            }),
        )),
        alt((
            (tag(Token::Func), parse_any_str)
                .map(|((_, s), v)| ParsedField::L7StringField("FUNC", v, (s.start, s.end - s.start))),
            (tag(Token::SeqNum), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("S7PLUS_SEQ_NUM", v, (s.start, s.end - s.start))
            }),
            (tag(Token::SessionId), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U64Field("SESSION_ID", v as u64, (s.start, s.end - s.start))
            }),
            (tag(Token::Id), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("OBJECT_ID", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Flags), cut_err(parse_u32))
                .map(|((_, s), v)| ParsedField::L7U32Field("FLAGS", v, (s.start, s.end - s.start))),
        )),
    ))
    .parse_next(input)
}
