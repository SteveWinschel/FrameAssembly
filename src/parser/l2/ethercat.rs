//! EtherCAT Industrial Real-Time Protocol (`ethercat`, IEC 61158-4-12) Layer 2 parser combinator.
//!
//! This module implements the `winnow` parser combinator for Beckhoff / ETG EtherCAT frames over
//! native Ethernet II (`0x88A4`) and UDP port `34980`. It recognizes the `ethercat` protocol
//! keyword, datagram command `cmd` (supporting `nop`, `aprd`, `apwr`, `aprw`, `fprd`, `fpwr`,
//! `fprw`, `brd`, `bwr`, `brw`, `lrd`, `lwr`, `lrw`, `armw`, `frmw`, or numeric `u8`) plus bare
//! `nop`/`read`/`write` shorthands, datagram index `idx`, 16-bit `adp` and `ado`/`offset`
//! addresses (or 32-bit `addr`), `irq` mask, and Working Counter `wkc`.

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{ParsedField, Stream, parse_any_str, parse_u32, tag};

/// Parses an EtherCAT protocol declaration or datagram header field.
pub(crate) fn parse_ethercat_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        alt((
            tag(Token::Ethercat)
                .map(|(_, s)| ParsedField::Protocol(Protocol::Ethercat, (s.start, s.len()))),
            (tag(Token::Cmd), cut_err(parse_any_str)).map(|((_, s), v)| {
                ParsedField::L7StringField("ECAT_CMD", v, (s.start, s.end - s.start))
            }),
            tag(Token::Nop)
                .map(|(_, s)| ParsedField::L7StringField("ECAT_CMD", "NOP", (s.start, s.len()))),
            tag(Token::Read)
                .map(|(_, s)| ParsedField::L7StringField("ECAT_CMD", "APRD", (s.start, s.len()))),
            tag(Token::Write)
                .map(|(_, s)| ParsedField::L7StringField("ECAT_CMD", "APWR", (s.start, s.len()))),
        )),
        alt((
            (tag(Token::Idx), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("ECAT_IDX", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Adp), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("ECAT_ADP", v, (s.start, s.end - s.start))
            }),
            (alt((tag(Token::Ado), tag(Token::Offset))), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("ECAT_ADO", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Addr), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("ECAT_ADDR", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Irq), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("ECAT_IRQ", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Wkc), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("ECAT_WKC", v, (s.start, s.end - s.start))
            }),
        )),
    ))
    .parse_next(input)
}
