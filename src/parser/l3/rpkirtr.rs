//! RPKI to Router Protocol (`rpkirtr`, RFC 6810 / RFC 8210) parser for FrameAssembly.
//!
//! This module implements the `winnow` parser combinator for RPKI-RTR cache synchronization PDUs
//! carried over TCP port `323`. It parses the `rpkirtr` protocol keyword, all standard PDU types
//! (`serialnotify`, `serialquery`, `resetquery`, `cacheresponse`, `ipv4prefix`, `ipv6prefix`,
//! `endofdata`, `cachereset`, `errorreport`), `version`, `sessionid`, `serial`, `announce`,
//! `withdraw`, `flags`, CIDR `prefix`, `maxlen`, `asn`, `refresh`/`retry`/`expire` intervals,
//! and `errcode`/`errmsg` diagnostic attributes.

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{
    ParsedField, Stream, parse_any_str, parse_str_val, parse_u8, parse_u16, parse_u32, tag,
};

/// Parses an RPKI-RTR PDU type keyword.
fn parse_rpkirtr_type<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        alt((
            tag(Token::SerialNotify).map(|(_, s)| {
                ParsedField::L7StringField("RPKIRTR_TYPE", "SERIALNOTIFY", (s.start, s.len()))
            }),
            tag(Token::SerialQuery).map(|(_, s)| {
                ParsedField::L7StringField("RPKIRTR_TYPE", "SERIALQUERY", (s.start, s.len()))
            }),
            tag(Token::ResetQuery).map(|(_, s)| {
                ParsedField::L7StringField("RPKIRTR_TYPE", "RESETQUERY", (s.start, s.len()))
            }),
            tag(Token::CacheResponse).map(|(_, s)| {
                ParsedField::L7StringField("RPKIRTR_TYPE", "CACHERESPONSE", (s.start, s.len()))
            }),
            tag(Token::Ipv4Prefix).map(|(_, s)| {
                ParsedField::L7StringField("RPKIRTR_TYPE", "IPV4PREFIX", (s.start, s.len()))
            }),
        )),
        alt((
            tag(Token::Ipv6Prefix).map(|(_, s)| {
                ParsedField::L7StringField("RPKIRTR_TYPE", "IPV6PREFIX", (s.start, s.len()))
            }),
            tag(Token::EndOfData).map(|(_, s)| {
                ParsedField::L7StringField("RPKIRTR_TYPE", "ENDOFDATA", (s.start, s.len()))
            }),
            tag(Token::CacheReset).map(|(_, s)| {
                ParsedField::L7StringField("RPKIRTR_TYPE", "CACHERESET", (s.start, s.len()))
            }),
            tag(Token::ErrorReport).map(|(_, s)| {
                ParsedField::L7StringField("RPKIRTR_TYPE", "ERRORREPORT", (s.start, s.len()))
            }),
        )),
    ))
    .parse_next(input)
}

/// Parses an RPKI-RTR protocol declaration or PDU field.
pub(crate) fn parse_rpkirtr_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        alt((
            tag(Token::Rpkirtr)
                .map(|(_, s)| ParsedField::Protocol(Protocol::Rpkirtr, (s.start, s.len()))),
            parse_rpkirtr_type,
            (tag(Token::Version), parse_u8)
                .map(|((_, s), v)| ParsedField::VersionByte(v, (s.start, s.end - s.start))),
            (tag(Token::SessionId), parse_u16).map(|((_, s), v)| {
                ParsedField::L7U32Field("RPKIRTR_SESSION_ID", u32::from(v), (s.start, s.end - s.start))
            }),
            (tag(Token::Serial), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("RPKIRTR_SERIAL", v, (s.start, s.end - s.start))
            }),
            tag(Token::Announce).map(|(_, s)| ParsedField::FlagsByte(1, (s.start, s.len()))),
            tag(Token::Withdraw).map(|(_, s)| ParsedField::FlagsByte(0, (s.start, s.len()))),
        )),
        alt((
            (tag(Token::Flags), parse_u8)
                .map(|((_, s), v)| ParsedField::FlagsByte(v, (s.start, s.end - s.start))),
            (tag(Token::Prefix), parse_any_str)
                .map(|((_, s), v)| ParsedField::PrefixVal(None, Some(v), (s.start, s.end - s.start))),
            (tag(Token::MaxLen), cut_err(parse_u8)).map(|((_, s), v)| {
                ParsedField::L7U32Field("RPKIRTR_MAX_LEN", u32::from(v), (s.start, s.end - s.start))
            }),
            (tag(Token::Asn), parse_u32)
                .map(|((_, s), v)| ParsedField::Asn(v, (s.start, s.end - s.start))),
            (tag(Token::Refresh), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("RPKIRTR_REFRESH", v, (s.start, s.end - s.start))
            }),
        )),
        alt((
            (tag(Token::Retry), parse_u32).map(|((_, s), v)| {
                ParsedField::L7U32Field("RPKIRTR_RETRY", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Expire), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("RPKIRTR_EXPIRE", v, (s.start, s.end - s.start))
            }),
            (tag(Token::ErrCode), parse_u16).map(|((_, s), v)| {
                ParsedField::L7U32Field("ERRCODE", u32::from(v), (s.start, s.end - s.start))
            }),
            (tag(Token::ErrMsg), parse_str_val)
                .map(|((_, s), v)| ParsedField::L7StringField("ERRMSG", v, (s.start, s.end - s.start))),
        )),
    ))
    .parse_next(input)
}
