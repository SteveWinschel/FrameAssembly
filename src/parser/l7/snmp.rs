//! Simple Network Management Protocol (SNMPv1, SNMPv2c, and SNMPv3) field parser.
//!
//! This module implements the `winnow` parser combinator for RFC 1157 (`SNMP1`), RFC 3416
//! (`SNMP2`), and RFC 3414 User-based Security Model (`SNMP3`) protocol data units in FrameAssembly
//! `.fasm` specifications. It recognizes community strings (`COMMUNITY`), USM security parameters
//! (`USER`, `ENGINEID`, `ENGINEBOOTS`, `ENGINETIME`, `CONTEXTNAME`, `AUTH`, `PRIV`), trap headers
//! (`ENTERPRISE`, `AGENTIP`, `GENTRAP`, `SPECTRAP`, `SYSUPTIME`), PDU types (`GET`, `SET`,
//! `RESPONSE`, `TRAP`, `INFORM`, `GETNEXT`, `GETBULK`), and typed ASN.1 `VARBIND` entries.

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err};
use winnow::prelude::*;
use winnow::token::any;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{
    parse_i32, parse_ip, parse_raw_string_lit, parse_str_val, parse_u32, parse_u64, tag,
    ParsedField, Stream,
};

/// Helper to parse an OID string or IP representation.
fn parse_oid_val<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<&'a str> {
    any.verify_map(|(t, _)| match t {
        Token::OidStr(s) | Token::IpAddress(s) => Some(s),
        Token::StringLit(s) => Some(
            s.strip_prefix('"')
                .and_then(|x| x.strip_suffix('"'))
                .unwrap_or(s),
        ),
        _ => None,
    })
    .parse_next(input)
}

/// Helper to parse an OID field.
fn parse_oid<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    let (_, span) = tag(Token::Oid).parse_next(input)?;
    let val = cut_err(parse_oid_val).parse_next(input)?;
    Ok(ParsedField::Oid(val, (span.start, span.end - span.start)))
}

/// Helper to parse an Enterprise OID field.
fn parse_enterprise<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    let (_, span) = tag(Token::Enterprise).parse_next(input)?;
    let val = cut_err(parse_oid_val).parse_next(input)?;
    Ok(ParsedField::Enterprise(
        val,
        (span.start, span.end - span.start),
    ))
}

/// Helper to parse a single VarBind AST entry.
fn parse_varbind<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    let (_, span) = tag(Token::VarBind).parse_next(input)?;
    let oid = cut_err(parse_oid_val).parse_next(input)?;
    let val = cut_err(alt((
        tag(Token::NullVal).value(VarBindType::Null),
        (tag(Token::StringVal), cut_err(parse_raw_string_lit))
            .map(|(_, s)| VarBindType::String(s)),
        (tag(Token::IntVal), cut_err(parse_i32)).map(|(_, v)| VarBindType::Int(v)),
        (tag(Token::TimeTicksVal), cut_err(parse_u32)).map(|(_, v)| VarBindType::TimeTicks(v)),
        (tag(Token::IpVal), cut_err(parse_ip)).map(|(_, i)| VarBindType::Ip(i)),
        (tag(Token::OidVal), cut_err(parse_oid_val)).map(|(_, s)| VarBindType::OidVal(s)),
        (tag(Token::Counter32Val), cut_err(parse_u32)).map(|(_, v)| VarBindType::Counter32(v)),
        (tag(Token::Gauge32Val), cut_err(parse_u32)).map(|(_, v)| VarBindType::Gauge32(v)),
        (tag(Token::Counter64Val), cut_err(parse_u64)).map(|(_, v)| VarBindType::Counter64(v)),
    )))
    .parse_next(input)?;
    Ok(ParsedField::VarBind(
        VarBindAst { oid, val },
        (span.start, span.end - span.start),
    ))
}

/// Helper to parse SNMPv3 authentication parameters.
fn parse_auth<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    let (_, span) = tag(Token::Auth).parse_next(input)?;
    let auth_type = cut_err(alt((
        tag(Token::Md5).value(SnmpAuthType::Md5),
        tag(Token::Sha).value(SnmpAuthType::Sha),
        tag(Token::Sha256).value(SnmpAuthType::Sha256),
        tag(Token::Sha384).value(SnmpAuthType::Sha384),
        tag(Token::Sha512).value(SnmpAuthType::Sha512),
    )))
    .parse_next(input)?;
    let pass = cut_err(parse_raw_string_lit).parse_next(input)?;
    Ok(ParsedField::Auth(
        auth_type,
        pass,
        (span.start, span.end - span.start),
    ))
}

/// Helper to parse SNMPv3 privacy parameters.
fn parse_priv<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    let (_, span) = tag(Token::Priv).parse_next(input)?;
    let priv_type = cut_err(alt((
        tag(Token::Des).value(SnmpPrivType::Des),
        tag(Token::Aes).value(SnmpPrivType::Aes),
    )))
    .parse_next(input)?;
    let pass = cut_err(parse_raw_string_lit).parse_next(input)?;
    Ok(ParsedField::Priv(
        priv_type,
        pass,
        (span.start, span.end - span.start),
    ))
}

/// Parses an SNMP protocol or modifier field from a token stream.
pub(crate) fn parse_snmp_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        alt((
            tag(Token::Snmp1)
                .map(|(_, s)| ParsedField::Protocol(Protocol::Snmp1, (s.start, s.len()))),
            tag(Token::Snmp2)
                .map(|(_, s)| ParsedField::Protocol(Protocol::Snmp2, (s.start, s.len()))),
            tag(Token::Snmp3)
                .map(|(_, s)| ParsedField::Protocol(Protocol::Snmp3, (s.start, s.len()))),
            (tag(Token::Community), cut_err(parse_raw_string_lit))
                .map(|((_, s), v)| ParsedField::Community(v, (s.start, s.end - s.start))),
            (tag(Token::User), parse_str_val)
                .map(|((_, s), v)| ParsedField::User(v, (s.start, s.end - s.start))),
            (tag(Token::SysUpTime), cut_err(parse_u32))
                .map(|((_, s), v)| ParsedField::SysUpTime(v, (s.start, s.end - s.start))),
            (tag(Token::AgentIp), cut_err(parse_ip))
                .map(|((_, s), v)| ParsedField::AgentIp(v, (s.start, s.end - s.start))),
            (tag(Token::GenTrap), cut_err(parse_u32))
                .map(|((_, s), v)| ParsedField::GenTrap(v, (s.start, s.end - s.start))),
        )),
        alt((
            (tag(Token::SpecTrap), cut_err(parse_u32))
                .map(|((_, s), v)| ParsedField::SpecTrap(v, (s.start, s.end - s.start))),
            (tag(Token::EngineId), cut_err(parse_raw_string_lit))
                .map(|((_, s), v)| ParsedField::EngineId(v, (s.start, s.end - s.start))),
            (tag(Token::EngineBoots), cut_err(parse_u32))
                .map(|((_, s), v)| ParsedField::EngineBoots(v, (s.start, s.end - s.start))),
            (tag(Token::EngineTime), cut_err(parse_u32))
                .map(|((_, s), v)| ParsedField::EngineTime(v, (s.start, s.end - s.start))),
            (tag(Token::ContextName), cut_err(parse_raw_string_lit))
                .map(|((_, s), v)| ParsedField::ContextName(v, (s.start, s.end - s.start))),
            (tag(Token::NonRepeaters), cut_err(parse_u32))
                .map(|((_, s), v)| ParsedField::NonRepeaters(v, (s.start, s.end - s.start))),
            (tag(Token::MaxRepetitions), cut_err(parse_u32))
                .map(|((_, s), v)| ParsedField::MaxRepetitions(v, (s.start, s.end - s.start))),
            (tag(Token::ReqId), cut_err(parse_u32))
                .map(|((_, s), v)| ParsedField::ReqId(v, (s.start, s.end - s.start))),
        )),
        alt((
            parse_oid,
            parse_enterprise,
            parse_varbind,
            parse_auth,
            parse_priv,
        )),
        alt((
            tag(Token::Trap)
                .map(|(_, s)| ParsedField::PduType(SnmpPduType::Trap, (s.start, s.len()))),
            tag(Token::Get)
                .map(|(_, s)| ParsedField::PduType(SnmpPduType::Get, (s.start, s.len()))),
            tag(Token::Set)
                .map(|(_, s)| ParsedField::PduType(SnmpPduType::Set, (s.start, s.len()))),
            tag(Token::Response)
                .map(|(_, s)| ParsedField::PduType(SnmpPduType::Response, (s.start, s.len()))),
            tag(Token::Inform)
                .map(|(_, s)| ParsedField::PduType(SnmpPduType::Inform, (s.start, s.len()))),
            tag(Token::GetNext)
                .map(|(_, s)| ParsedField::PduType(SnmpPduType::GetNext, (s.start, s.len()))),
            tag(Token::GetBulk)
                .map(|(_, s)| ParsedField::PduType(SnmpPduType::GetBulk, (s.start, s.len()))),
        )),
    ))
    .parse_next(input)
}
