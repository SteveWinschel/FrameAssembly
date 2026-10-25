//! Network File System (NFSv3 and NFSv4) Layer 7 ONC RPC file system field parser.
//!
//! This module implements the `winnow` parser combinator for RFC 1813 (`NFS` v3) and RFC 7530
//! (`NFS` v4) remote procedure call frames in FrameAssembly `.fasm` specifications. It recognizes
//! the `NFS` protocol keyword, RPC transaction IDs (`XID`), NFS protocol versions (`VERS`),
//! procedure names (`PROC` and shorthand `COMPOUND`), NFSv4 compound tags (`TAG`), and exported
//! file system paths (`PATH`).

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{parse_any_str, parse_str_val, parse_u32, tag, ParsedField, Stream};

/// Parses an NFS protocol declaration or RPC procedure field.
pub(crate) fn parse_nfs_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        tag(Token::Nfs).map(|(_, s)| ParsedField::Protocol(Protocol::Nfs, (s.start, s.len()))),
        tag(Token::Compound)
            .map(|(_, s)| ParsedField::L7StringField("PROC", "COMPOUND", (s.start, s.len()))),
        (tag(Token::Xid), cut_err(parse_u32))
            .map(|((_, s), v)| ParsedField::Xid(v, (s.start, s.end - s.start))),
        (tag(Token::Vers), cut_err(parse_u32))
            .map(|((_, s), v)| ParsedField::L7U32Field("VERS", v, (s.start, s.end - s.start))),
        (tag(Token::Proc), cut_err(parse_any_str))
            .map(|((_, s), v)| ParsedField::L7StringField("PROC", v, (s.start, s.end - s.start))),
        (tag(Token::Tag), parse_str_val)
            .map(|((_, s), v)| ParsedField::TagVal(None, Some(v), (s.start, s.end - s.start))),
        (tag(Token::Path), cut_err(parse_str_val))
            .map(|((_, s), v)| ParsedField::L7StringField("PATH", v, (s.start, s.end - s.start))),
    ))
    .parse_next(input)
}
