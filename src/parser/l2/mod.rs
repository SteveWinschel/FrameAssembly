//! Layer 2 protocol and modifier field parsers.

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err};
use winnow::prelude::*;

use crate::lexer::Token;
use crate::parser::{parse_mac, parse_u16, tag, ParsedField, Stream};

/// Address Resolution Protocol parser.
pub mod arp;
/// IEEE 802.1X EAPOL parser.
pub mod eapol;
/// IEEE 802.3ad Link Aggregation Control Protocol parser.
pub mod lacp;
/// IEEE 802.1AB Link Layer Discovery Protocol parser.
pub mod lldp;
/// RFC 3032 Multi-Protocol Label Switching parser.
pub mod mpls;
/// IEEE 802.1ad QinQ dual VLAN parser.
pub mod qinq;
/// IEEE 802.1D / IEEE 802.1w Spanning Tree Protocol parser.
pub mod stp;
/// IEEE 802.1Q Virtual Local Area Network parser.
pub mod vlan;

pub(crate) use arp::*;
pub(crate) use eapol::*;
pub(crate) use lacp::*;
pub(crate) use lldp::*;
pub(crate) use mpls::*;
pub(crate) use qinq::*;
pub(crate) use stp::*;
pub(crate) use vlan::*;

/// Parses a Layer 2 protocol or modifier field from a token stream.
pub(crate) fn parse_l2_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        parse_arp_field,
        parse_vlan_field,
        parse_qinq_field,
        parse_lldp_field,
        parse_stp_field,
        parse_lacp_field,
        parse_eapol_field,
        parse_mpls_field,
        alt((
            (tag(Token::SrcMac), cut_err(parse_mac)).map(|((_, s), v)| ParsedField::SrcMac(v, (s.start, s.end - s.start))),
            (tag(Token::DstMac), cut_err(parse_mac)).map(|((_, s), v)| ParsedField::DstMac(v, (s.start, s.end - s.start))),
            (tag(Token::EtherType), cut_err(parse_u16)).map(|((_, s), v)| ParsedField::EtherType(v, (s.start, s.end - s.start))),
        )),
    ))
    .parse_next(input)
}
