//! Traversal Using Relays around NAT (TURN) Layer 7 relay protocol field parser.
//!
//! This module implements the `winnow` parser combinator for RFC 8656 / RFC 5766 `turn` relay
//! allocation, permission, channel binding, and `ChannelData` framing in FrameAssembly `.frasm`
//! specifications. It recognizes the `turn` protocol keyword, operation shorthands (`allocate`,
//! `refresh`, `createpermission`, `channelbind`, `channeldata`, `sendindication`, `dataindication`),
//! class flags (`request`, `response`, `error`), `msgtype`, `txid`, `channel`, `lifetime`,
//! `requestedtransport`, XOR address tuples (`xormappedaddr`, `xorrelayedaddr`, `xorpeeraddr`),
//! `errcode`, and `software`.

use alloc::vec::Vec;
use core::net::IpAddr;

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err, opt};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{
    ParsedField, Stream, parse_any_str, parse_spanned_ip, parse_spanned_u32, parse_str_val,
    parse_u8, parse_u32, tag,
};

/// Encodes an IPv4/IPv6 address and optional `u32` port into compact bytes for `L7BytesField`.
fn encode_xor_addr_field(ip: IpAddr, port: Option<u32>) -> Vec<u8> {
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

/// Parses a TURN protocol declaration or relay attribute field.
pub(crate) fn parse_turn_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        alt((
            tag(Token::Turn).map(|(_, s)| ParsedField::Protocol(Protocol::Turn, (s.start, s.len()))),
            tag(Token::Allocate)
                .map(|(_, s)| ParsedField::L7StringField("MSG_TYPE", "ALLOCATE", (s.start, s.len()))),
            tag(Token::Refresh)
                .map(|(_, s)| ParsedField::L7StringField("MSG_TYPE", "REFRESH", (s.start, s.len()))),
            tag(Token::CreatePermission).map(|(_, s)| {
                ParsedField::L7StringField("MSG_TYPE", "CREATEPERMISSION", (s.start, s.len()))
            }),
            tag(Token::ChannelBind).map(|(_, s)| {
                ParsedField::L7StringField("MSG_TYPE", "CHANNELBIND", (s.start, s.len()))
            }),
            tag(Token::ChannelData).map(|(_, s)| {
                ParsedField::L7StringField("MSG_TYPE", "CHANNELDATA", (s.start, s.len()))
            }),
            tag(Token::SendIndication).map(|(_, s)| {
                ParsedField::L7StringField("MSG_TYPE", "SENDINDICATION", (s.start, s.len()))
            }),
            tag(Token::DataIndication).map(|(_, s)| {
                ParsedField::L7StringField("MSG_TYPE", "DATAINDICATION", (s.start, s.len()))
            }),
        )),
        alt((
            (tag(Token::MsgType), cut_err(parse_any_str)).map(|((_, s), v)| {
                ParsedField::L7StringField("MSG_TYPE", v, (s.start, s.end - s.start))
            }),
            tag(Token::Request).map(|(_, s)| ParsedField::L7Flag("REQUEST", (s.start, s.len()))),
            tag(Token::Response).map(|(_, s)| ParsedField::L7Flag("RESPONSE", (s.start, s.len()))),
            tag(Token::ErrorKw).map(|(_, s)| ParsedField::L7Flag("ERROR", (s.start, s.len()))),
            (tag(Token::Txid), cut_err(parse_u32))
                .map(|((_, s), v)| ParsedField::L7U32Field("TXID", v, (s.start, s.end - s.start))),
            (tag(Token::Channel), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("CHANNEL", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Lifetime), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("LIFETIME", v, (s.start, s.end - s.start))
            }),
            (
                tag(Token::RequestedTransport),
                cut_err(alt((
                    tag(Token::Udp).value(17u8),
                    tag(Token::Tcp).value(6u8),
                    parse_u8,
                ))),
            )
                .map(|((_, s), v)| {
                    ParsedField::L7U32Field(
                        "REQUESTED_TRANSPORT",
                        u32::from(v),
                        (s.start, s.end - s.start),
                    )
                }),
        )),
        alt((
            (tag(Token::XorMappedAddr), cut_err(parse_spanned_ip), opt(parse_spanned_u32)).map(
                |((_, s), (ip, ip_sp), port)| {
                    let end = port.map_or(ip_sp.0 + ip_sp.1, |(_, p_sp)| p_sp.0 + p_sp.1);
                    ParsedField::StunXorMapped(ip, port.map(|(p, _)| p), (s.start, end - s.start))
                },
            ),
            (
                tag(Token::XorRelayedAddr),
                cut_err(parse_spanned_ip),
                opt(parse_spanned_u32),
            )
                .map(|((_, s), (ip, ip_sp), port)| {
                    let end = port.map_or(ip_sp.0 + ip_sp.1, |(_, p_sp)| p_sp.0 + p_sp.1);
                    ParsedField::L7BytesField(
                        "TURN_XOR_RELAYED",
                        encode_xor_addr_field(ip, port.map(|(p, _)| p)),
                        (s.start, end - s.start),
                    )
                }),
            (tag(Token::XorPeerAddr), cut_err(parse_spanned_ip), opt(parse_spanned_u32)).map(
                |((_, s), (ip, ip_sp), port)| {
                    let end = port.map_or(ip_sp.0 + ip_sp.1, |(_, p_sp)| p_sp.0 + p_sp.1);
                    ParsedField::L7BytesField(
                        "TURN_XOR_PEER",
                        encode_xor_addr_field(ip, port.map(|(p, _)| p)),
                        (s.start, end - s.start),
                    )
                },
            ),
            (tag(Token::ErrCode), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("ERRCODE", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Software), cut_err(parse_str_val)).map(|((_, s), v)| {
                ParsedField::L7StringField("SOFTWARE", v, (s.start, s.end - s.start))
            }),
        )),
    ))
    .parse_next(input)
}
