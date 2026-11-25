//! Intermediate System to Intermediate System (`isis`, ISO/IEC 10589) PDU parser for FrameAssembly.
//!
//! This module implements the `winnow` parser combinator for ISO/IEC 10589 `isis` routing PDUs
//! over IEEE 802.3 LLC (`FE:FE:03`, CLNS IRPD `0x83`). It supports bare and `type`-prefixed PDU
//! discriminators (`l1iih`/`hello`, `l2iih`, `p2piih`, `l1lsp`, `l2lsp`, `l1csnp`, `l2csnp`,
//! `l1psnp`, `l2psnp`), System ID (`sysid`), Area Address (`area`), Holding Timer (`holdtime`),
//! Priority (`priority`), LAN ID (`lanid`), Circuit Type (`circuittype`), LSP Remaining Lifetime
//! (`lifetime`), Sequence Number (`seqnum`), and Dynamic Hostname (`hostname`).

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err, opt};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{
    ParsedField, Stream, parse_any_str, parse_u8, parse_u16, parse_u32, tag,
};

/// Validates a string or contextual PDU keyword for `isis type <val>`.
fn normalize_isis_pdu_str(raw: &str) -> Option<&'static str> {
    let norm = raw.to_ascii_uppercase().replace(['_', '-'], "");
    match norm.as_str() {
        "L1IIH" | "HELLO" | "L1HELLO" => Some("L1_IIH"),
        "L2IIH" | "L2HELLO" => Some("L2_IIH"),
        "P2PIIH" | "P2PHELLO" => Some("P2P_IIH"),
        "L1LSP" | "LSP" => Some("L1_LSP"),
        "L2LSP" => Some("L2_LSP"),
        "L1CSNP" | "CSNP" => Some("L1_CSNP"),
        "L2CSNP" => Some("L2_CSNP"),
        "L1PSNP" | "PSNP" => Some("L1_PSNP"),
        "L2PSNP" => Some("L2_PSNP"),
        _ => None,
    }
}

/// Parses an IS-IS PDU discriminator keyword (with optional leading `type` keyword).
fn parse_isis_pdu_type<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    let (opt_t, (val, s2)) = (
        opt(tag(Token::Type)),
        alt((
            alt((
                tag(Token::L1Iih).map(|(_, s)| ("L1_IIH", s)),
                tag(Token::Hello).map(|(_, s)| ("L1_IIH", s)),
                tag(Token::L2Iih).map(|(_, s)| ("L2_IIH", s)),
                tag(Token::P2pIih).map(|(_, s)| ("P2P_IIH", s)),
                tag(Token::L1Lsp).map(|(_, s)| ("L1_LSP", s)),
            )),
            alt((
                tag(Token::L2Lsp).map(|(_, s)| ("L2_LSP", s)),
                tag(Token::L1Csnp).map(|(_, s)| ("L1_CSNP", s)),
                tag(Token::L2Csnp).map(|(_, s)| ("L2_CSNP", s)),
                tag(Token::L1Psnp).map(|(_, s)| ("L1_PSNP", s)),
                tag(Token::L2Psnp).map(|(_, s)| ("L2_PSNP", s)),
            )),
        )),
    )
        .parse_next(input)?;
    let start = opt_t.map(|(_, s1)| s1.start).unwrap_or(s2.start);
    Ok(ParsedField::L7StringField(
        "ISIS_PDU_TYPE",
        val,
        (start, s2.end - start),
    ))
}

/// Parses an IS-IS protocol declaration or PDU/TLV modifier field.
pub(crate) fn parse_isis_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        alt((
            tag(Token::Isis).map(|(_, s)| ParsedField::Protocol(Protocol::Isis, (s.start, s.len()))),
            parse_isis_pdu_type,
            (
                tag(Token::Type),
                cut_err(parse_any_str.verify_map(normalize_isis_pdu_str)),
            )
                .map(|((_, s), v)| ParsedField::L7StringField("ISIS_PDU_TYPE", v, (s.start, s.end - s.start))),
            (tag(Token::SysId), cut_err(parse_any_str)).map(|((_, s), v)| {
                ParsedField::L7StringField("ISIS_SYS_ID", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Area), cut_err(parse_any_str)).map(|((_, s), v)| {
                ParsedField::L7StringField("ISIS_AREA", v, (s.start, s.end - s.start))
            }),
            (tag(Token::HoldTime), cut_err(parse_u16)).map(|((_, s), v)| {
                ParsedField::L7U32Field("ISIS_HOLDTIME", u32::from(v), (s.start, s.end - s.start))
            }),
        )),
        alt((
            (tag(Token::Priority), cut_err(parse_u8)).map(|((_, s), v)| {
                ParsedField::L7U32Field("ISIS_PRIORITY", u32::from(v), (s.start, s.end - s.start))
            }),
            (tag(Token::LanId), cut_err(parse_any_str)).map(|((_, s), v)| {
                ParsedField::L7StringField("ISIS_LAN_ID", v, (s.start, s.end - s.start))
            }),
            (tag(Token::CircuitType), cut_err(parse_u8)).map(|((_, s), v)| {
                ParsedField::L7U32Field(
                    "ISIS_CIRCUIT_TYPE",
                    u32::from(v),
                    (s.start, s.end - s.start),
                )
            }),
            (tag(Token::Lifetime), cut_err(parse_u16)).map(|((_, s), v)| {
                ParsedField::L7U32Field("ISIS_LIFETIME", u32::from(v), (s.start, s.end - s.start))
            }),
            (tag(Token::SeqNum), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("ISIS_SEQ_NUM", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Hostname), cut_err(parse_any_str)).map(|((_, s), v)| {
                ParsedField::L7StringField("ISIS_HOSTNAME", v, (s.start, s.end - s.start))
            }),
        )),
    ))
    .parse_next(input)
}
