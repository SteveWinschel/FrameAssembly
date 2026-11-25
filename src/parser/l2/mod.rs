//! Layer 2 data-link protocol and Ethernet frame modifier parsers for FrameAssembly.
//!
//! This module coordinates syntactic combinators for Layer 2 Ethernet headers and all 18 native
//! data-link protocols: `arp`, `vlan`, `qinq`, `mpls`, `lldp`, `stp`/`rstp`, `lacp`, `eapol`,
//! `cdp`, `isis`, `macsec`, `pfc`, `pppoe`, `nsh`, `profinet`, `goose`, `sv`, and `ethercat`,
//! alongside link-layer source/destination MAC overrides (`srcmac`, `dstmac`), explicit
//! `ethertype`, and trailing `fcs`/`badfcs` Frame Check Sequence directives.

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err};
use winnow::prelude::*;

use crate::lexer::Token;
use crate::parser::{ParsedField, Stream, parse_mac, parse_u16, tag};

pub(crate) mod arp;
pub(crate) mod cdp;
pub(crate) mod eapol;
pub(crate) mod ethercat;
pub(crate) mod goose;
pub(crate) mod isis;
pub(crate) mod lacp;
pub(crate) mod lldp;
pub(crate) mod macsec;
pub(crate) mod mpls;
pub(crate) mod nsh;
pub(crate) mod pfc;
pub(crate) mod pppoe;
pub(crate) mod profinet;
pub(crate) mod qinq;
pub(crate) mod stp;
pub(crate) mod sv;
pub(crate) mod vlan;

pub(crate) use arp::*;
pub(crate) use cdp::*;
pub(crate) use eapol::*;
pub(crate) use ethercat::*;
pub(crate) use goose::*;
pub(crate) use isis::*;
pub(crate) use lacp::*;
pub(crate) use lldp::*;
pub(crate) use macsec::*;
pub(crate) use mpls::*;
pub(crate) use nsh::*;
pub(crate) use pfc::*;
pub(crate) use pppoe::*;
pub(crate) use profinet::*;
pub(crate) use qinq::*;
pub(crate) use stp::*;
pub(crate) use sv::*;
pub(crate) use vlan::*;

/// Parses core Layer 2 protocol fields and generic Ethernet header modifiers (`<= 8` `alt` arms).
pub(crate) fn parse_legacy_l2_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        alt((
            parse_arp_field,
            parse_vlan_field,
            parse_qinq_field,
            parse_lldp_field,
            parse_stp_field,
            parse_lacp_field,
            parse_eapol_field,
            parse_mpls_field,
        )),
        alt((
            (tag(Token::SrcMac), cut_err(parse_mac))
                .map(|((_, s), v)| ParsedField::SrcMac(v, (s.start, s.end - s.start))),
            (tag(Token::DstMac), cut_err(parse_mac))
                .map(|((_, s), v)| ParsedField::DstMac(v, (s.start, s.end - s.start))),
            (tag(Token::EtherType), cut_err(parse_u16))
                .map(|((_, s), v)| ParsedField::EtherType(v, (s.start, s.end - s.start))),
        )),
    ))
    .parse_next(input)
}

/// Parses extended Layer 2 enterprise, fabric, and industrial fieldbus protocols (`<= 8` `alt` arms).
pub(crate) fn parse_ext_l2_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        alt((
            parse_cdp_field,
            parse_isis_field,
            parse_macsec_field,
            parse_pfc_field,
            parse_pppoe_field,
            parse_nsh_field,
            parse_profinet_field,
            parse_goose_field,
        )),
        alt((parse_sv_field, parse_ethercat_field)),
    ))
    .parse_next(input)
}

/// Parses a Layer 2 protocol or modifier field from a token stream.
#[allow(dead_code)]
pub(crate) fn parse_l2_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((parse_legacy_l2_field, parse_ext_l2_field)).parse_next(input)
}
