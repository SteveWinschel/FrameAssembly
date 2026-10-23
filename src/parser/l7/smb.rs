//! SMB Layer 7 file sharing protocol field parser.

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{parse_str_val, parse_u32, parse_u64, tag, ParsedField, Stream};

/// Parses an SMB protocol declaration or file sharing command field.
pub(crate) fn parse_smb_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        tag(Token::Smb).map(|(_, s)| ParsedField::Protocol(Protocol::Smb, (s.start, s.len()))),
        (tag(Token::Command), cut_err(parse_str_val)).map(|((_, s), v)| ParsedField::L7StringField("COMMAND", v, (s.start, s.end - s.start))),
        (tag(Token::Status), cut_err(parse_u32)).map(|((_, s), v)| ParsedField::L7U32Field("STATUS", v, (s.start, s.end - s.start))),
        (tag(Token::TreeId), cut_err(parse_u32)).map(|((_, s), v)| ParsedField::L7U32Field("TREE_ID", v, (s.start, s.end - s.start))),
        (tag(Token::SessionId), cut_err(parse_u64)).map(|((_, s), v)| ParsedField::L7U64Field("SESSION_ID", v, (s.start, s.end - s.start))),
        (tag(Token::MsgId), cut_err(parse_u64)).map(|((_, s), v)| ParsedField::L7U64Field("MSGID", v, (s.start, s.end - s.start))),
        (tag(Token::Share), cut_err(parse_str_val)).map(|((_, s), v)| ParsedField::L7StringField("SHARE", v, (s.start, s.end - s.start))),
        (tag(Token::Filename), cut_err(parse_str_val)).map(|((_, s), v)| ParsedField::L7StringField("FILENAME", v, (s.start, s.end - s.start))),
    ))
    .parse_next(input)
}
