//! Server Message Block (SMB2 and SMB3) Layer 7 file sharing protocol field parser.
//!
//! This module implements the `winnow` parser combinator for MS-SMB2 (`SMB`) network file sharing
//! packets in FrameAssembly `.fasm` specifications. It recognizes the `SMB` protocol keyword,
//! shorthand command tokens (`NEGOTIATE`, `SESSION_SETUP`, `TREE_CONNECT`, `CREATE`,
//! `TREE_DISCONNECT`), explicit `COMMAND` names, NTSTATUS codes (`STATUS`), tree IDs (`TREE_ID`),
//! 64-bit session IDs (`SESSION_ID`), message sequence numbers (`MSGID`), UNC shares (`SHARE`),
//! and target file names (`FILENAME`).

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{parse_any_str, parse_str_val, parse_u32, parse_u64, tag, ParsedField, Stream};

/// Parses an SMB protocol declaration or file sharing command field.
pub(crate) fn parse_smb_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        alt((
            tag(Token::Smb).map(|(_, s)| ParsedField::Protocol(Protocol::Smb, (s.start, s.len()))),
            tag(Token::Negotiate)
                .map(|(_, s)| ParsedField::L7StringField("COMMAND", "NEGOTIATE", (s.start, s.len()))),
            tag(Token::SessionSetup).map(|(_, s)| {
                ParsedField::L7StringField("COMMAND", "SESSION_SETUP", (s.start, s.len()))
            }),
            tag(Token::TreeConnect).map(|(_, s)| {
                ParsedField::L7StringField("COMMAND", "TREE_CONNECT", (s.start, s.len()))
            }),
            tag(Token::Create)
                .map(|(_, s)| ParsedField::L7StringField("COMMAND", "CREATE", (s.start, s.len()))),
            tag(Token::TreeDisconnect).map(|(_, s)| {
                ParsedField::L7StringField("COMMAND", "TREE_DISCONNECT", (s.start, s.len()))
            }),
        )),
        alt((
            (tag(Token::Command), cut_err(parse_any_str)).map(|((_, s), v)| {
                ParsedField::L7StringField("COMMAND", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Status), parse_u32).map(|((_, s), v)| {
                ParsedField::L7U32Field("STATUS", v, (s.start, s.end - s.start))
            }),
            (tag(Token::TreeId), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("TREE_ID", v, (s.start, s.end - s.start))
            }),
            (tag(Token::SessionId), cut_err(parse_u64)).map(|((_, s), v)| {
                ParsedField::L7U64Field("SESSION_ID", v, (s.start, s.end - s.start))
            }),
            (tag(Token::MsgId), parse_u64)
                .map(|((_, s), v)| ParsedField::L7U64Field("MSGID", v, (s.start, s.end - s.start))),
            (tag(Token::Share), cut_err(parse_str_val)).map(|((_, s), v)| {
                ParsedField::L7StringField("SHARE", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Filename), cut_err(parse_str_val)).map(|((_, s), v)| {
                ParsedField::L7StringField("FILENAME", v, (s.start, s.end - s.start))
            }),
        )),
    ))
    .parse_next(input)
}
