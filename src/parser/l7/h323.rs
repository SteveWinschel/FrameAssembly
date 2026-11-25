//! ITU-T H.323 / H.225.0 Call Signaling and RAS Layer 7 protocol field parser.
//!
//! This module implements the `winnow` parser combinator for ITU-T H.323 (`h323`) call signaling
//! and gatekeeper RAS messages in FrameAssembly `.frasm` specifications. It recognizes the `h323`
//! protocol keyword, Q.931/H.225.0 Call Signaling shorthands (`setup`, `callproceeding`,
//! `alerting`, `connect`, `releasecomplete`), RAS shorthands (`grq`, `gcf`, `rrq`, `rcf`, `drq`,
//! `dcf`), explicit `msgtype`, `callref`, `callingparty`, `calledparty`, `cause`, `seqnum`, and
//! `rasaddr` endpoint addresses.

use alloc::vec::Vec;
use core::net::IpAddr;

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err, opt};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{
    ParsedField, Stream, parse_any_str, parse_spanned_ip, parse_spanned_u32, parse_u32, tag,
};

/// Encodes an IPv4/IPv6 address and optional `u32` port into compact bytes for `L7BytesField`.
fn encode_ras_addr_field(ip: IpAddr, port: Option<u32>) -> Vec<u8> {
    let mut out = Vec::with_capacity(21);
    match ip {
        IpAddr::V4(v4) => {
            out.push(4);
            out.extend_from_slice(&v4.octets());
        }
        IpAddr::V6(v6) => {
            out.push(6);
            out.extend_from_slice(&v6.octets());
        }
    }
    if let Some(p) = port {
        out.extend_from_slice(&p.to_be_bytes());
    }
    out
}

/// Parses an ITU-T H.323 / H.225.0 Call Signaling or RAS field.
pub(crate) fn parse_h323_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        alt((
            tag(Token::H323).map(|(_, s)| ParsedField::Protocol(Protocol::H323, (s.start, s.len()))),
            tag(Token::Setup)
                .map(|(_, s)| ParsedField::L7StringField("MSG_TYPE", "SETUP", (s.start, s.len()))),
            tag(Token::CallProceeding).map(|(_, s)| {
                ParsedField::L7StringField("MSG_TYPE", "CALLPROCEEDING", (s.start, s.len()))
            }),
            tag(Token::Alerting).map(|(_, s)| {
                ParsedField::L7StringField("MSG_TYPE", "ALERTING", (s.start, s.len()))
            }),
            tag(Token::Connect)
                .map(|(_, s)| ParsedField::L7StringField("MSG_TYPE", "CONNECT", (s.start, s.len()))),
            tag(Token::ReleaseComplete).map(|(_, s)| {
                ParsedField::L7StringField("MSG_TYPE", "RELEASECOMPLETE", (s.start, s.len()))
            }),
            tag(Token::Grq)
                .map(|(_, s)| ParsedField::L7StringField("MSG_TYPE", "GRQ", (s.start, s.len()))),
            tag(Token::Gcf)
                .map(|(_, s)| ParsedField::L7StringField("MSG_TYPE", "GCF", (s.start, s.len()))),
        )),
        alt((
            tag(Token::Rrq)
                .map(|(_, s)| ParsedField::L7StringField("MSG_TYPE", "RRQ", (s.start, s.len()))),
            tag(Token::Rcf)
                .map(|(_, s)| ParsedField::L7StringField("MSG_TYPE", "RCF", (s.start, s.len()))),
            tag(Token::Drq)
                .map(|(_, s)| ParsedField::L7StringField("MSG_TYPE", "DRQ", (s.start, s.len()))),
            tag(Token::Dcf)
                .map(|(_, s)| ParsedField::L7StringField("MSG_TYPE", "DCF", (s.start, s.len()))),
            (tag(Token::MsgType), cut_err(parse_any_str)).map(|((_, s), v)| {
                ParsedField::L7StringField("MSG_TYPE", v, (s.start, s.end - s.start))
            }),
            (tag(Token::CallRef), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("CALL_REF", v, (s.start, s.end - s.start))
            }),
        )),
        alt((
            (tag(Token::CallingParty), cut_err(parse_any_str)).map(|((_, s), v)| {
                ParsedField::L7StringField("CALLING_PARTY", v, (s.start, s.end - s.start))
            }),
            (tag(Token::CalledParty), cut_err(parse_any_str)).map(|((_, s), v)| {
                ParsedField::L7StringField("CALLED_PARTY", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Cause), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("CAUSE", v, (s.start, s.end - s.start))
            }),
            (tag(Token::SeqNum), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("SEQ_NUM", v, (s.start, s.end - s.start))
            }),
            (tag(Token::RasAddr), cut_err(parse_spanned_ip), opt(parse_spanned_u32)).map(
                |((_, s), (ip, ip_sp), port)| {
                    let end = port.map_or(ip_sp.0 + ip_sp.1, |(_, p_sp)| p_sp.0 + p_sp.1);
                    ParsedField::L7BytesField(
                        "H323_RAS_ADDR",
                        encode_ras_addr_field(ip, port.map(|(p, _)| p)),
                        (s.start, end - s.start),
                    )
                },
            ),
        )),
    ))
    .parse_next(input)
}
