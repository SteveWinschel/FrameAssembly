//! Transmission Control Protocol (`TCP`, RFC 9293) header and option parser for FrameAssembly.
//!
//! This module implements the winnow parser combinator for `TCP` segment modifiers, control flags,
//! and RFC 7323 / RFC 2018 TCP header options. It parses receive window size (`WIN`/`WINDOW`),
//! urgent pointer (`URGENT`), Maximum Segment Size (`MSS`), Window Scale (`WSCALE`), Selective
//! Acknowledgment Permitted (`SACK_PERM`), timestamps (`TSVAL`, `TSECR`), and all 8 control bits
//! (`SYN`, `ACK`, `FIN`, `RST`, `PSH`, `URG`, `ECE`, `CWR`).

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{ParsedField, Stream, parse_u8, parse_u16, parse_u32, tag};

/// Parses a TCP protocol declaration, flag, or option field.
pub(crate) fn parse_tcp_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        alt((
            tag(Token::Tcp).map(|(_, s)| ParsedField::Protocol(Protocol::Tcp, (s.start, s.len()))),
            (tag(Token::Win), cut_err(parse_u16))
                .map(|((_, s), v)| ParsedField::Win(v, (s.start, s.end - s.start))),
            (tag(Token::Window), cut_err(parse_u16))
                .map(|((_, s), v)| ParsedField::Win(v, (s.start, s.end - s.start))),
            (tag(Token::Urgent), cut_err(parse_u16))
                .map(|((_, s), v)| ParsedField::Urgent(v, (s.start, s.end - s.start))),
            (tag(Token::Mss), cut_err(parse_u16))
                .map(|((_, s), v)| ParsedField::Mss(v, (s.start, s.end - s.start))),
        )),
        alt((
            (tag(Token::Wscale), cut_err(parse_u8))
                .map(|((_, s), v)| ParsedField::Wscale(v, (s.start, s.end - s.start))),
            tag(Token::SackPerm).map(|(_, s)| ParsedField::SackPerm((s.start, s.len()))),
            (tag(Token::Tsval), cut_err(parse_u32))
                .map(|((_, s), v)| ParsedField::Tsval(v, (s.start, s.end - s.start))),
            (tag(Token::Tsecr), cut_err(parse_u32))
                .map(|((_, s), v)| ParsedField::Tsecr(v, (s.start, s.end - s.start))),
        )),
        alt((
            tag(Token::Syn).map(|(_, s)| ParsedField::Flag(TcpFlag::Syn, (s.start, s.len()))),
            tag(Token::Ack).map(|(_, s)| ParsedField::Flag(TcpFlag::Ack, (s.start, s.len()))),
            tag(Token::Fin).map(|(_, s)| ParsedField::Flag(TcpFlag::Fin, (s.start, s.len()))),
            tag(Token::Rst).map(|(_, s)| ParsedField::Flag(TcpFlag::Rst, (s.start, s.len()))),
            tag(Token::Psh).map(|(_, s)| ParsedField::Flag(TcpFlag::Psh, (s.start, s.len()))),
            tag(Token::Urg).map(|(_, s)| ParsedField::Flag(TcpFlag::Urg, (s.start, s.len()))),
            tag(Token::Ece).map(|(_, s)| ParsedField::Flag(TcpFlag::Ece, (s.start, s.len()))),
            tag(Token::Cwr).map(|(_, s)| ParsedField::Flag(TcpFlag::Cwr, (s.start, s.len()))),
        )),
    ))
    .parse_next(input)
}
