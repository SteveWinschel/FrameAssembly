//! IEEE C37.118 Synchrophasor (PMU/PDC Grid Telemetry) Layer 7 field parser.
//!
//! This module implements the `winnow` parser combinator for IEEE C37.118 `synchrophasor`
//! packets over TCP or UDP port 4712 in FrameAssembly `.frasm` specifications. It recognizes the
//! `synchrophasor` protocol keyword, frame types (`msgtype`: `"command"`, `"data"`, `"header"`,
//! `"cfg1"`, `"cfg2"`, `"cfg3"`), protocol version nibbles (`version`), 16-bit PMU/PDC stream
//! source IDs (`id`), Second of Century UNIX timestamps (`timestamp`), fractional-second words
//! (`fracsec`), Command frame instructions (`cmd`), Data frame `STAT` words (`status`), CFG
//! station names (`station`), and explicit 16-bit CRC-CCITT overrides (`crc`).

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err};
use winnow::error::{ContextError, ErrMode};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{ParsedField, Stream, parse_any_str, parse_str_val, parse_u32, tag};

/// Parses an IEEE C37.118 command code from a `0..=65535` integer or mnemonic string.
fn parse_synchrophasor_cmd<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<u32> {
    if let Ok(v) = parse_u32(input) {
        if v <= 65535 {
            return Ok(v);
        }
        return Err(ErrMode::Backtrack(ContextError::new()));
    }
    let saved = *input;
    let raw = parse_any_str(input)?;
    let norm = raw.trim().to_ascii_lowercase().replace(['_', '-'], "");
    let code = match norm.as_str() {
        "dataoff" | "turnoff" => 1,
        "dataon" | "turnon" => 2,
        "sendhdr" | "sendheader" => 3,
        "sendcfg1" => 4,
        "sendcfg2" => 5,
        "sendcfg3" => 6,
        "extended" => 8,
        _ => {
            *input = saved;
            return Err(ErrMode::Backtrack(ContextError::new()));
        }
    };
    Ok(code)
}

/// Parses an IEEE C37.118 Synchrophasor protocol declaration or telemetry header field.
pub(crate) fn parse_synchrophasor_field<'i, 'a>(
    input: &mut Stream<'i, 'a>,
) -> PResult<ParsedField<'a>> {
    alt((
        alt((
            tag(Token::Synchrophasor)
                .map(|(_, s)| ParsedField::Protocol(Protocol::Synchrophasor, (s.start, s.len()))),
            (tag(Token::MsgType), cut_err(parse_any_str)).map(|((_, s), v)| {
                ParsedField::L7StringField("MSG_TYPE", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Version), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("SYN_VERSION", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Id), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("SYN_ID", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Timestamp), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("TIMESTAMP", v, (s.start, s.end - s.start))
            }),
        )),
        alt((
            (tag(Token::FracSec), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("FRAC_SEC", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Cmd), cut_err(parse_synchrophasor_cmd)).map(|((_, s), v)| {
                ParsedField::L7U32Field("SYN_CMD", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Status), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("SYN_STATUS", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Station), cut_err(parse_str_val)).map(|((_, s), v)| {
                ParsedField::L7StringField("STATION", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Crc), cut_err(parse_u32))
                .map(|((_, s), v)| ParsedField::L7U32Field("CRC", v, (s.start, s.end - s.start))),
        )),
    ))
    .parse_next(input)
}
