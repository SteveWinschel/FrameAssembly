//! IEEE 802.1AE MAC Security (`macsec`) SecTAG and ICV parser for FrameAssembly.
//!
//! This module implements the `winnow` parser combinator for IEEE 802.1AE MACsec frames
//! (`EtherType = 0x88E5`). It recognizes the `macsec` protocol keyword and Security Tag
//! attributes including Tag Control Information (`tci <u8>`), Association Number (`an <u8>`),
//! Short Length (`sl <u8>`), 32-bit Packet Number (`pn <u32>`), 64-bit Secure Channel Identifier
//! (`sci <u64>`), and trailing 16-byte Integrity Check Value bytes (`icv "<hex>"`).

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{
    ParsedField, Stream, parse_hex_bytes, parse_u8, parse_u32, parse_u64, tag,
};

/// Parses a MACsec protocol declaration or SecTAG/ICV field.
pub(crate) fn parse_macsec_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        tag(Token::Macsec).map(|(_, s)| ParsedField::Protocol(Protocol::Macsec, (s.start, s.len()))),
        (tag(Token::Tci), cut_err(parse_u8)).map(|((_, s), v)| {
            ParsedField::L7U32Field("MACSEC_TCI", u32::from(v), (s.start, s.end - s.start))
        }),
        (tag(Token::An), cut_err(parse_u8)).map(|((_, s), v)| {
            ParsedField::L7U32Field("MACSEC_AN", u32::from(v), (s.start, s.end - s.start))
        }),
        (tag(Token::Sl), cut_err(parse_u8)).map(|((_, s), v)| {
            ParsedField::L7U32Field("MACSEC_SL", u32::from(v), (s.start, s.end - s.start))
        }),
        (tag(Token::Pn), cut_err(parse_u32))
            .map(|((_, s), v)| ParsedField::L7U32Field("MACSEC_PN", v, (s.start, s.end - s.start))),
        (tag(Token::Sci), cut_err(parse_u64)).map(|((_, s), v)| {
            ParsedField::L7U64Field("MACSEC_SCI", v, (s.start, s.end - s.start))
        }),
        (tag(Token::Icv), cut_err(parse_hex_bytes))
            .map(|((_, s), v)| ParsedField::Icv(v, (s.start, s.end - s.start))),
    ))
    .parse_next(input)
}
