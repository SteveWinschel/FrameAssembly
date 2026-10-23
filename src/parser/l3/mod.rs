//! Layer 3 protocol, routing, and tunnel field parsers.

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err};
use winnow::prelude::*;

use crate::lexer::Token;
use crate::parser::{parse_u16, parse_u32, parse_u8, tag, ParsedField, Stream};

/// AH protocol parser.
pub mod ah;
/// BFD protocol parser.
pub mod bfd;
/// BGP protocol parser.
pub mod bgp;
/// ESP protocol parser.
pub mod esp;
/// GENEVE protocol parser.
pub mod geneve;
/// GRE protocol parser.
pub mod gre;
/// HSRP protocol parser.
pub mod hsrp;
/// ICMP protocol parser.
pub mod icmp;
/// IGMP protocol parser.
pub mod igmp;
/// IKEV2 protocol parser.
pub mod ikev2;
/// IPSEC protocol parser.
pub mod ipsec;
/// MLD protocol parser.
pub mod mld;
/// NDP protocol parser.
pub mod ndp;
/// OPENFLOW protocol parser.
pub mod openflow;
/// OSPF protocol parser.
pub mod ospf;
/// PIM protocol parser.
pub mod pim;
/// RIP protocol parser.
pub mod rip;
/// VRRP protocol parser.
pub mod vrrp;
/// VXLAN protocol parser.
pub mod vxlan;
/// WIREGUARD protocol parser.
pub mod wireguard;

pub(crate) use ah::*;
pub(crate) use bfd::*;
pub(crate) use bgp::*;
pub(crate) use esp::*;
pub(crate) use geneve::*;
pub(crate) use gre::*;
pub(crate) use hsrp::*;
pub(crate) use icmp::*;
pub(crate) use igmp::*;
pub(crate) use ikev2::*;
pub(crate) use ipsec::*;
pub(crate) use mld::*;
pub(crate) use ndp::*;
pub(crate) use openflow::*;
pub(crate) use ospf::*;
pub(crate) use pim::*;
pub(crate) use rip::*;
pub(crate) use vrrp::*;
pub(crate) use vxlan::*;
pub(crate) use wireguard::*;

/// Parses a Layer 3 protocol or modifier field from a token stream.
pub(crate) fn parse_l3_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        alt((
            parse_icmp_field,
            parse_ndp_field,
            parse_igmp_field,
            parse_mld_field,
            parse_gre_field,
            parse_vxlan_field,
            parse_geneve_field,
            parse_ipsec_field,
        )),
        alt((
            parse_esp_field,
            parse_ah_field,
            parse_ikev2_field,
            parse_wireguard_field,
            parse_ospf_field,
            parse_bgp_field,
            parse_rip_field,
            parse_vrrp_field,
        )),
        alt((
            parse_hsrp_field,
            parse_pim_field,
            parse_bfd_field,
            parse_openflow_field,
        )),
        alt((
            (tag(Token::Dscp), cut_err(parse_u32)).map(|((_, s), v)| ParsedField::Dscp(v, (s.start, s.end - s.start))),
            (tag(Token::Ecn), cut_err(parse_u32)).map(|((_, s), v)| ParsedField::Ecn(v, (s.start, s.end - s.start))),
            (tag(Token::Ttl), cut_err(parse_u32)).map(|((_, s), v)| ParsedField::Ttl(v, (s.start, s.end - s.start))),
            (tag(Token::FlowLabel), cut_err(parse_u32)).map(|((_, s), v)| ParsedField::FlowLabel(v, (s.start, s.end - s.start))),
            (tag(Token::IpId), cut_err(parse_u16)).map(|((_, s), v)| ParsedField::IpId(v, (s.start, s.end - s.start))),
            tag(Token::Df).map(|(_, s)| ParsedField::Df((s.start, s.len()))),
            tag(Token::Mf).map(|(_, s)| ParsedField::Mf((s.start, s.len()))),
            (tag(Token::FragOffset), cut_err(parse_u16)).map(|((_, s), v)| ParsedField::FragOffset(v, (s.start, s.end - s.start))),
        )),
        (tag(Token::NextHeader), cut_err(parse_u8)).map(|((_, s), v)| ParsedField::NextHeader(v, (s.start, s.end - s.start))),
    ))
    .parse_next(input)
}
