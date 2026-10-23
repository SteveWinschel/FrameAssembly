//! gRPC Layer 7 RPC protocol field parser.

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{parse_str_val, parse_u32, tag, ParsedField, Stream};

/// Parses a gRPC protocol declaration or RPC call field.
pub(crate) fn parse_grpc_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        tag(Token::Grpc).map(|(_, s)| ParsedField::Protocol(Protocol::Grpc, (s.start, s.len()))),
        (tag(Token::Service), cut_err(parse_str_val)).map(|((_, s), v)| ParsedField::L7StringField("SERVICE", v, (s.start, s.end - s.start))),
        (tag(Token::Method), cut_err(parse_str_val)).map(|((_, s), v)| ParsedField::L7StringField("METHOD", v, (s.start, s.end - s.start))),
        (tag(Token::GrpcStatus), cut_err(parse_u32)).map(|((_, s), v)| ParsedField::L7U32Field("GRPC_STATUS", v, (s.start, s.end - s.start))),
    ))
    .parse_next(input)
}
