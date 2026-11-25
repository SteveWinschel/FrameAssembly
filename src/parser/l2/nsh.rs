//! Network Service Header (`nsh`, RFC 8300) Layer 2 parser combinator for FrameAssembly.
//!
//! This module implements the `winnow` parser combinator for RFC 8300 Service Function Chaining
//! Network Service Header (`nsh`) frames carried over Ethernet II (`0x894F`). It recognizes the
//! `nsh` protocol keyword, Base Header `version` (`0..=3`), `oam` indicator flag, Metadata Type
//! (`mdtype` `1` or `2`), encapsulated Next Protocol (`nextproto` as a numeric `u8` or symbolic
//! `ethernet`/`ipv4`/`ipv6`/`nsh`/`mpls`), 24-bit Service Path Identifier (`spi`), 8-bit Service
//! Index (`si`), and variable/fixed context metadata (`context <hex>`), while universal `ttl`
//! handles the 6-bit NSH service hop TTL.

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{ParsedField, Stream, parse_any_str, parse_hex_bytes, parse_u32, tag};

/// Maps symbolic NSH Next Protocol names (`ethernet`, `ipv4`, `ipv6`, `nsh`, `mpls`) to IANA codes.
fn nsh_next_proto_code(raw: &str) -> Option<u32> {
    if raw.eq_ignore_ascii_case("ipv4") || raw.eq_ignore_ascii_case("ip") {
        Some(1)
    } else if raw.eq_ignore_ascii_case("ipv6") {
        Some(2)
    } else if raw.eq_ignore_ascii_case("ethernet") || raw.eq_ignore_ascii_case("eth") {
        Some(3)
    } else if raw.eq_ignore_ascii_case("nsh") {
        Some(4)
    } else if raw.eq_ignore_ascii_case("mpls") {
        Some(5)
    } else {
        None
    }
}

/// Parses an NSH protocol declaration or Service Function Chaining header field.
pub(crate) fn parse_nsh_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        alt((
            tag(Token::Nsh).map(|(_, s)| ParsedField::Protocol(Protocol::Nsh, (s.start, s.len()))),
            (tag(Token::Version), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("NSH_VERSION", v, (s.start, s.end - s.start))
            }),
            tag(Token::Oam)
                .map(|(_, s)| ParsedField::L7Flag("NSH_OAM", (s.start, s.len()))),
            (tag(Token::MdType), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("NSH_MD_TYPE", v, (s.start, s.end - s.start))
            }),
        )),
        alt((
            (
                tag(Token::NextProto),
                cut_err(alt((
                    parse_u32,
                    parse_any_str
                        .verify(|s| nsh_next_proto_code(s).is_some())
                        .map(|s| nsh_next_proto_code(s).unwrap_or(3)),
                ))),
            )
                .map(|((_, s), v)| {
                    ParsedField::L7U32Field("NSH_NEXT_PROTO", v, (s.start, s.end - s.start))
                }),
            (tag(Token::Spi), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("NSH_SPI", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Si), cut_err(parse_u32))
                .map(|((_, s), v)| ParsedField::L7U32Field("NSH_SI", v, (s.start, s.end - s.start))),
            (tag(Token::ContextVal), cut_err(parse_hex_bytes)).map(|((_, s), b)| {
                ParsedField::L7BytesField("NSH_CONTEXT", b, (s.start, s.end - s.start))
            }),
        )),
    ))
    .parse_next(input)
}
