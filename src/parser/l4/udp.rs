//! User Datagram Protocol (`UDP`, RFC 768) protocol parser for FrameAssembly.
//!
//! This module implements the winnow parser combinator for `UDP` datagram frame statements.
//! When `UDP` is selected as the statement protocol, the backend synthesizes an 8-byte RFC 768
//! UDP header with automatic length and IPv4/IPv6 pseudo-header checksum computation around the
//! statement's `SRCPORT`, `DSTPORT`, and `PAYLOAD`/`HEXPAYLOAD` modifiers.

use winnow::ModalResult as PResult;
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{ParsedField, Stream, tag};

/// Parses a UDP protocol declaration.
pub(crate) fn parse_udp_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    tag(Token::Udp)
        .map(|(_, s)| ParsedField::Protocol(Protocol::Udp, (s.start, s.len())))
        .parse_next(input)
}
