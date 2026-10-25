//! Layer 3 network-layer, routing, tunneling, and control-plane field parsers for FrameAssembly.
//!
//! This module coordinates syntactic combinators for Layer 3 network headers (`DSCP`, `ECN`,
//! `TTL`, `FLOWLABEL`, `IPID`, `DF`, `MF`, `FRAGOFFSET`, `NEXT_HEADER`) and 19 network-layer,
//! tunneling, security, and routing protocols: `ICMP`, `NDP`, `IGMP`, `MLD`, `GRE`, `VXLAN`,
//! `GENEVE`, `IPSEC`, `ESP`, `AH`, `IKEV2`, `WIREGUARD`, `OSPF`, `BGP`, `RIP`, `VRRP`, `HSRP`,
//! `PIM`, `BFD`, and `OPENFLOW`.

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err};
use winnow::prelude::*;

use crate::lexer::Token;
use crate::parser::{ParsedField, Stream, parse_u8, parse_u16, parse_u32, tag};

/// AH protocol parser.
pub(crate) mod ah;
/// BFD protocol parser.
pub(crate) mod bfd;
/// BGP protocol parser.
pub(crate) mod bgp;
/// ESP protocol parser.
pub(crate) mod esp;
/// GENEVE protocol parser.
pub(crate) mod geneve;
/// GRE protocol parser.
pub(crate) mod gre;
/// HSRP protocol parser.
pub(crate) mod hsrp;
/// ICMP protocol parser.
pub(crate) mod icmp;
/// IGMP protocol parser.
pub(crate) mod igmp;
/// IKEV2 protocol parser.
pub(crate) mod ikev2;
/// IPSEC protocol parser.
pub(crate) mod ipsec;
/// MLD protocol parser.
pub(crate) mod mld;
/// NDP protocol parser.
pub(crate) mod ndp;
/// OPENFLOW protocol parser.
pub(crate) mod openflow;
/// OSPF protocol parser.
pub(crate) mod ospf;
/// PIM protocol parser.
pub(crate) mod pim;
/// RIP protocol parser.
pub(crate) mod rip;
/// VRRP protocol parser.
pub(crate) mod vrrp;
/// VXLAN protocol parser.
pub(crate) mod vxlan;
/// WIREGUARD protocol parser.
pub(crate) mod wireguard;

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
            (tag(Token::Dscp), cut_err(parse_u32))
                .map(|((_, s), v)| ParsedField::Dscp(v, (s.start, s.end - s.start))),
            (tag(Token::Ecn), cut_err(parse_u32))
                .map(|((_, s), v)| ParsedField::Ecn(v, (s.start, s.end - s.start))),
            (tag(Token::Ttl), cut_err(parse_u32))
                .map(|((_, s), v)| ParsedField::Ttl(v, (s.start, s.end - s.start))),
            (tag(Token::FlowLabel), cut_err(parse_u32))
                .map(|((_, s), v)| ParsedField::FlowLabel(v, (s.start, s.end - s.start))),
            (tag(Token::IpId), cut_err(parse_u16))
                .map(|((_, s), v)| ParsedField::IpId(v, (s.start, s.end - s.start))),
            tag(Token::Df).map(|(_, s)| ParsedField::Df((s.start, s.len()))),
            tag(Token::Mf).map(|(_, s)| ParsedField::Mf((s.start, s.len()))),
            (tag(Token::FragOffset), cut_err(parse_u16))
                .map(|((_, s), v)| ParsedField::FragOffset(v, (s.start, s.end - s.start))),
        )),
        (tag(Token::NextHeader), cut_err(parse_u8))
            .map(|((_, s), v)| ParsedField::NextHeader(v, (s.start, s.end - s.start))),
    ))
    .parse_next(input)
}
