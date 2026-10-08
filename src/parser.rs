#![allow(clippy::collapsible_if)]
use alloc::string::ToString;
use alloc::vec::Vec;
use core::net::IpAddr;
use core::str::FromStr;

use winnow::Result as PResult;
use winnow::combinator::{alt, opt, repeat, separated};
use winnow::error::ContextError;
use winnow::prelude::*;
use winnow::token::any;

use crate::ast::*;
use crate::error::CompilerError;
use crate::lexer::Token;

/// A stream of lexical tokens mapped to their source spans.
///
/// Used extensively throughout the parser combinators.
pub type Stream<'i, 'a> = &'i [(Token<'a>, core::ops::Range<usize>)];

/// Helper to match a specific token exactly.
///
/// # Examples
/// ```no_run
/// // Internal tag combinator
/// ```
fn tag<'i, 'a: 'i>(
    expected: Token<'a>,
) -> impl Parser<Stream<'i, 'a>, (Token<'a>, core::ops::Range<usize>), ContextError> {
    any.verify(move |(t, _): &(Token<'a>, core::ops::Range<usize>)| *t == expected)
}

/// Helper to parse an identifier token and extract its string value.
///
/// # Examples
/// ```no_run
/// // Internal parse_ident combinator
/// ```
fn parse_ident<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<&'a str> {
    let (t, _) = any
        .verify(|(t, _)| matches!(t, Token::Ident(_)))
        .parse_next(input)?;
    match t {
        Token::Ident(s) => Ok(s),
        _ => unreachable!(),
    }
}

/// Helper to parse a string literal token and extract its inner value without quotes.
///
/// # Examples
/// ```no_run
/// // Internal parse_string_lit combinator
/// ```
fn parse_string_lit<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<&'a str> {
    let (t, _) = any
        .verify(|(t, _)| matches!(t, Token::StringLit(_)))
        .parse_next(input)?;
    match t {
        Token::StringLit(s) => Ok(s
            .strip_prefix('"')
            .and_then(|s| s.strip_suffix('"'))
            .unwrap_or(s)),
        _ => unreachable!(),
    }
}

/// Parses an IP address from a token stream.
fn parse_ip<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<IpAddr> {
    any.verify_map(|(t, _)| match t {
        Token::IpAddress(s) | Token::OidStr(s) => IpAddr::from_str(s).ok(),
        _ => None,
    })
    .parse_next(input)
}

/// Parses a MAC address from a token stream.
fn parse_mac<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<[u8; 6]> {
    any.verify_map(|(t, _)| {
        if let Token::MacAddress(s) = t {
            let parts: Vec<&str> = s.split(':').collect();
            if parts.len() == 6 {
                let mut mac = [0u8; 6];
                for i in 0..6 {
                    mac[i] = u8::from_str_radix(parts[i], 16).ok()?;
                }
                Some(mac)
            } else {
                None
            }
        } else {
            None
        }
    })
    .parse_next(input)
}

/// Parses a `u16` integer.
fn parse_u16<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<u16> {
    any.verify_map(|(t, _)| {
        if let Token::Number(s) = t {
            u16::from_str(s).ok()
        } else {
            None
        }
    })
    .parse_next(input)
}

/// Parses a `u32` integer.
fn parse_u32<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<u32> {
    any.verify_map(|(t, _)| {
        if let Token::Number(s) = t {
            u32::from_str(s).ok()
        } else {
            None
        }
    })
    .parse_next(input)
}

/// Parses a `HOST` block definition.
fn parse_host_def<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<HostDef<'a>> {
    let _ = tag(Token::Host).parse_next(input)?;
    let name = parse_ident(input)?;
    let _ = tag(Token::LBrace).parse_next(input)?;

    let mut ip = None;
    let mut mac = None;

    let _: Vec<()> = repeat(
        0..,
        alt((
            (tag(Token::Ip), parse_ip).map(|(_, i)| ip = Some(i)),
            (tag(Token::Mac), parse_mac).map(|(_, m)| mac = Some(m)),
        )),
    )
    .parse_next(input)?;

    let _ = tag(Token::RBrace).parse_next(input)?;

    if let Some(ip) = ip {
        Ok(HostDef { name, ip, mac })
    } else {
        winnow::combinator::fail.parse_next(input)
    }
}

/// Parses a packet direction arrow (`->` or `<-`).
fn parse_direction<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<Direction> {
    alt((
        tag(Token::RightArrow).value(Direction::LeftToRight),
        tag(Token::LeftArrow).value(Direction::RightToLeft),
    ))
    .parse_next(input)
}

/// Parses a single frame statement within a flow.
fn parse_frame_statement<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<FrameStatement<'a>> {
    let caller = parse_ident(input)?;
    let dir = parse_direction(input)?;
    let callee = parse_ident(input)?;

    let protocol = alt((
        tag(Token::Tcp).value(Protocol::Tcp),
        tag(Token::Udp).value(Protocol::Udp),
        tag(Token::Snmp1).value(Protocol::Snmp1),
        tag(Token::Snmp2).value(Protocol::Snmp2),
        tag(Token::Snmp3).value(Protocol::Snmp3),
    ))
    .parse_next(input)?;

    let mut flags = Vec::new();
    let mut seq = None;
    let mut ack_num = None;
    let mut win = None;
    let mut payload = None;
    let mut wait = None;
    let mut src_port = None;
    let mut dst_port = None;
    let mut community = None;
    let mut user = None;
    let mut oid = None;
    let mut sys_up_time = None;
    let mut pdu_type = None;
    let mut enterprise = None;
    let mut agent_ip = None;
    let mut gen_trap = None;
    let mut spec_trap = None;
    let mut engine_id = None;
    let mut engine_boots = None;
    let mut engine_time = None;
    let mut context_name = None;
    let mut auth = None;
    let mut priv_param = None;
    let mut varbinds = Vec::new();
    let mut non_repeaters = None;
    let mut max_repetitions = None;
    let mut req_id = None;

    enum ParsedField<'a> {
        SrcPort(u16),
        DstPort(u16),
        Seq(u32),
        AckNum(u32),
        Win(u16),
        Payload(&'a str),
        Community(&'a str),
        User(&'a str),
        SysUpTime(u32),
        PduType(SnmpPduType),
        Wait(u64),
        Oid(&'a str),
        Flag(TcpFlag),
        Enterprise(&'a str),
        AgentIp(IpAddr),
        GenTrap(u32),
        SpecTrap(u32),
        EngineId(&'a str),
        EngineBoots(u32),
        EngineTime(u32),
        ContextName(&'a str),
        Auth(SnmpAuthType, &'a str),
        Priv(SnmpPrivType, &'a str),
        VarBind(VarBindAst<'a>),
        NonRepeaters(u32),
        MaxRepetitions(u32),
        ReqId(u32),
    }

    let parse_wait = |input: &mut Stream<'i, 'a>| -> PResult<ParsedField<'a>> {
        let _ = tag(Token::Wait).parse_next(input)?;

        let val = parse_u32(input)?;
        let suffix = alt((
            tag(Token::Ms).value(1_000_000_u64),
            tag(Token::Sec).value(1_000_000_000_u64),
            tag(Token::Min).value(60_000_000_000_u64),
        ))
        .parse_next(input)?;
        Ok(ParsedField::Wait(val as u64 * suffix))
    };

    let parse_oid_val = |input: &mut Stream<'i, 'a>| -> PResult<&'a str> {
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
    };

    let parse_oid = |input: &mut Stream<'i, 'a>| -> PResult<ParsedField<'a>> {
        let _ = tag(Token::Oid).parse_next(input)?;
        parse_oid_val(input).map(ParsedField::Oid)
    };

    let parse_enterprise = |input: &mut Stream<'i, 'a>| -> PResult<ParsedField<'a>> {
        let _ = tag(Token::Enterprise).parse_next(input)?;
        parse_oid_val(input).map(ParsedField::Enterprise)
    };

    let parse_varbind = |input: &mut Stream<'i, 'a>| -> PResult<ParsedField<'a>> {
        let _ = tag(Token::VarBind).parse_next(input)?;
        let oid = parse_oid_val(input)?;
        let val = alt((
            tag(Token::NullVal).value(VarBindType::Null),
            (tag(Token::StringVal), parse_string_lit).map(|(_, s)| VarBindType::String(s)),
            (tag(Token::IntVal), parse_u32).map(|(_, v)| VarBindType::Int(v)),
            (tag(Token::TimeTicksVal), parse_u32).map(|(_, v)| VarBindType::TimeTicks(v)),
            (tag(Token::IpVal), parse_ip).map(|(_, i)| VarBindType::Ip(i)),
        ))
        .parse_next(input)?;
        Ok(ParsedField::VarBind(VarBindAst { oid, val }))
    };

    let parse_auth = |input: &mut Stream<'i, 'a>| -> PResult<ParsedField<'a>> {
        let _ = tag(Token::Auth).parse_next(input)?;
        let auth_type = alt((
            tag(Token::Md5).value(SnmpAuthType::Md5),
            tag(Token::Sha).value(SnmpAuthType::Sha),
            tag(Token::Sha256).value(SnmpAuthType::Sha256),
            tag(Token::Sha384).value(SnmpAuthType::Sha384),
            tag(Token::Sha512).value(SnmpAuthType::Sha512),
        ))
        .parse_next(input)?;
        let pass = parse_string_lit(input)?;
        Ok(ParsedField::Auth(auth_type, pass))
    };

    let parse_priv = |input: &mut Stream<'i, 'a>| -> PResult<ParsedField<'a>> {
        let _ = tag(Token::Priv).parse_next(input)?;
        let priv_type = alt((
            tag(Token::Des).value(SnmpPrivType::Des),
            tag(Token::Aes).value(SnmpPrivType::Aes),
        ))
        .parse_next(input)?;
        let pass = parse_string_lit(input)?;
        Ok(ParsedField::Priv(priv_type, pass))
    };

    let parsed_fields: Vec<ParsedField<'a>> = repeat(
        0..,
        alt((
            alt((
                (tag(Token::SrcPort), parse_u16).map(|(_, v)| ParsedField::SrcPort(v)),
                (tag(Token::DstPort), parse_u16).map(|(_, v)| ParsedField::DstPort(v)),
                (tag(Token::Seq), parse_u32).map(|(_, v)| ParsedField::Seq(v)),
                (tag(Token::AckNum), parse_u32).map(|(_, v)| ParsedField::AckNum(v)),
                (tag(Token::Win), parse_u16).map(|(_, v)| ParsedField::Win(v)),
                (tag(Token::Payload), parse_string_lit).map(|(_, v)| ParsedField::Payload(v)),
                (tag(Token::Community), parse_string_lit).map(|(_, v)| ParsedField::Community(v)),
                (tag(Token::User), parse_string_lit).map(|(_, v)| ParsedField::User(v)),
            )),
            alt((
                (tag(Token::SysUpTime), parse_u32).map(|(_, v)| ParsedField::SysUpTime(v)),
                (tag(Token::AgentIp), parse_ip).map(|(_, v)| ParsedField::AgentIp(v)),
                (tag(Token::GenTrap), parse_u32).map(|(_, v)| ParsedField::GenTrap(v)),
                (tag(Token::SpecTrap), parse_u32).map(|(_, v)| ParsedField::SpecTrap(v)),
                (tag(Token::EngineId), parse_string_lit).map(|(_, v)| ParsedField::EngineId(v)),
                (tag(Token::EngineBoots), parse_u32).map(|(_, v)| ParsedField::EngineBoots(v)),
                (tag(Token::EngineTime), parse_u32).map(|(_, v)| ParsedField::EngineTime(v)),
                (tag(Token::ContextName), parse_string_lit)
                    .map(|(_, v)| ParsedField::ContextName(v)),
            )),
            alt((
                (tag(Token::NonRepeaters), parse_u32).map(|(_, v)| ParsedField::NonRepeaters(v)),
                (tag(Token::MaxRepetitions), parse_u32)
                    .map(|(_, v)| ParsedField::MaxRepetitions(v)),
                (tag(Token::ReqId), parse_u32).map(|(_, v)| ParsedField::ReqId(v)),
            )),
            alt((
                parse_wait,
                parse_oid,
                parse_enterprise,
                parse_varbind,
                parse_auth,
                parse_priv,
            )),
            alt((
                tag(Token::Trap).map(|_| ParsedField::PduType(SnmpPduType::Trap)),
                tag(Token::Get).map(|_| ParsedField::PduType(SnmpPduType::Get)),
                tag(Token::Set).map(|_| ParsedField::PduType(SnmpPduType::Set)),
                tag(Token::Response).map(|_| ParsedField::PduType(SnmpPduType::Response)),
                tag(Token::Inform).map(|_| ParsedField::PduType(SnmpPduType::Inform)),
                tag(Token::GetNext).map(|_| ParsedField::PduType(SnmpPduType::GetNext)),
                tag(Token::GetBulk).map(|_| ParsedField::PduType(SnmpPduType::GetBulk)),
            )),
            alt((
                tag(Token::Syn).map(|_| ParsedField::Flag(TcpFlag::Syn)),
                tag(Token::Ack).map(|_| ParsedField::Flag(TcpFlag::Ack)),
                tag(Token::Fin).map(|_| ParsedField::Flag(TcpFlag::Fin)),
                tag(Token::Rst).map(|_| ParsedField::Flag(TcpFlag::Rst)),
                tag(Token::Psh).map(|_| ParsedField::Flag(TcpFlag::Psh)),
                tag(Token::Urg).map(|_| ParsedField::Flag(TcpFlag::Urg)),
                tag(Token::Ece).map(|_| ParsedField::Flag(TcpFlag::Ece)),
                tag(Token::Cwr).map(|_| ParsedField::Flag(TcpFlag::Cwr)),
            )),
        )),
    )
    .parse_next(input)?;

    for f in parsed_fields {
        match f {
            ParsedField::SrcPort(v) => src_port = Some(v),
            ParsedField::DstPort(v) => dst_port = Some(v),
            ParsedField::Seq(v) => seq = Some(v),
            ParsedField::AckNum(v) => ack_num = Some(v),
            ParsedField::Win(v) => win = Some(v),
            ParsedField::Payload(v) => payload = Some(v),
            ParsedField::Community(v) => community = Some(v),
            ParsedField::User(v) => user = Some(v),
            ParsedField::SysUpTime(v) => sys_up_time = Some(v),
            ParsedField::PduType(v) => pdu_type = Some(v),
            ParsedField::Wait(v) => wait = Some(v),
            ParsedField::Oid(v) => oid = Some(v),
            ParsedField::Flag(flag) => flags.push(flag),
            ParsedField::Enterprise(v) => enterprise = Some(v),
            ParsedField::AgentIp(v) => agent_ip = Some(v),
            ParsedField::GenTrap(v) => gen_trap = Some(v),
            ParsedField::SpecTrap(v) => spec_trap = Some(v),
            ParsedField::EngineId(v) => engine_id = Some(v),
            ParsedField::EngineBoots(v) => engine_boots = Some(v),
            ParsedField::EngineTime(v) => engine_time = Some(v),
            ParsedField::ContextName(v) => context_name = Some(v),
            ParsedField::Auth(t, p) => auth = Some((t, p)),
            ParsedField::Priv(t, p) => priv_param = Some((t, p)),
            ParsedField::VarBind(v) => varbinds.push(v),
            ParsedField::NonRepeaters(v) => non_repeaters = Some(v),
            ParsedField::MaxRepetitions(v) => max_repetitions = Some(v),
            ParsedField::ReqId(v) => req_id = Some(v),
        }
    }

    if protocol == Protocol::Tcp && flags.is_empty() {
        return winnow::combinator::fail.parse_next(input);
    }

    Ok(FrameStatement {
        caller,
        dir,
        callee,
        protocol,
        src_port,
        dst_port,
        flags,
        seq,
        ack_num,
        win,
        payload,
        community,
        user,
        oid,
        sys_up_time,
        pdu_type,
        enterprise,
        agent_ip,
        gen_trap,
        spec_trap,
        engine_id,
        engine_boots,
        engine_time,
        context_name,
        auth,
        priv_param,
        varbinds,
        non_repeaters,
        max_repetitions,
        req_id,
        wait,
    })
}

/// Parses a `FLOW` block definition.
fn parse_flow_def<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<FlowDef<'a>> {
    let _ = tag(Token::Flow).parse_next(input)?;
    let name = parse_ident(input)?;
    let _ = tag(Token::LParen).parse_next(input)?;

    let params: Vec<&'a str> = separated(0.., parse_ident, tag(Token::Comma)).parse_next(input)?;

    let _ = tag(Token::RParen).parse_next(input)?;
    let _ = tag(Token::LBrace).parse_next(input)?;

    let statements: Vec<FrameStatement<'a>> =
        repeat(0.., parse_frame_statement).parse_next(input)?;

    let _ = tag(Token::RBrace).parse_next(input)?;

    Ok(FlowDef {
        name,
        params,
        statements,
    })
}

/// Parses a single argument passed to a flow invocation.
fn parse_argument<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<Argument<'a>> {
    let var = parse_ident(input)?;
    Ok(Argument::Variable(var))
}

/// Parses a flow invocation (e.g. `tcp_handshake(client, server)`).
fn parse_template_invocation<'i, 'a>(
    input: &mut Stream<'i, 'a>,
) -> PResult<TemplateInvocation<'a>> {
    let name = parse_ident(input)?;
    let _ = tag(Token::LParen).parse_next(input)?;

    let args: Vec<Argument<'a>> =
        separated(0.., parse_argument, tag(Token::Comma)).parse_next(input)?;

    let _ = tag(Token::RParen).parse_next(input)?;
    Ok(TemplateInvocation { name, args })
}

/// Parses a statement inside the `COMPILE` block (loop or single invocation).
fn parse_run_statement<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<RunStatement<'a>> {
    if opt(tag(Token::Loop)).parse_next(input)?.is_some() {
        let count = parse_u32(input)?;
        let _ = tag(Token::LBrace).parse_next(input)?;
        let invocations: Vec<TemplateInvocation<'a>> =
            repeat(0.., parse_template_invocation).parse_next(input)?;
        let _ = tag(Token::RBrace).parse_next(input)?;
        Ok(RunStatement::Loop(count, invocations))
    } else {
        let inv = parse_template_invocation(input)?;
        Ok(RunStatement::Invocation(inv))
    }
}

/// Parses the entire `COMPILE` block.
fn parse_compile_block<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<Vec<RunStatement<'a>>> {
    let _ = tag(Token::Compile).parse_next(input)?;
    let _ = tag(Token::LBrace).parse_next(input)?;
    let statements: Vec<RunStatement<'a>> = repeat(0.., parse_run_statement).parse_next(input)?;
    let _ = tag(Token::RBrace).parse_next(input)?;
    Ok(statements)
}

/// Represents a top-level construct parsed from the file.
enum TopLevel<'a> {
    /// A host definition.
    Host(HostDef<'a>),
    /// A flow definition.
    Flow(FlowDef<'a>),
    /// The compile block.
    Compile(Vec<RunStatement<'a>>),
}

/// Parses a single top-level construct (`HOST`, `FLOW`, or `COMPILE`).
fn parse_top_level<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<TopLevel<'a>> {
    alt((
        parse_host_def.map(TopLevel::Host),
        parse_flow_def.map(TopLevel::Flow),
        parse_compile_block.map(TopLevel::Compile),
    ))
    .parse_next(input)
}

/// Parses all top level constructs and constructs the `Program`.
fn parse_all<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<Program<'a>> {
    let mut hosts = Vec::new();
    let mut flows = Vec::new();
    let mut compile_block = None;

    let top_levels: Vec<TopLevel<'a>> = repeat(0.., parse_top_level).parse_next(input)?;

    for tl in top_levels {
        match tl {
            TopLevel::Host(h) => hosts.push(h),
            TopLevel::Flow(f) => flows.push(f),
            TopLevel::Compile(c) => {
                if compile_block.is_some() {
                    return winnow::combinator::fail.parse_next(input);
                }
                compile_block = Some(c);
            }
        }
    }

    if let Some(compile_block) = compile_block {
        Ok(Program {
            hosts,
            flows,
            compile_block,
        })
    } else {
        winnow::combinator::fail.parse_next(input)
    }
}

/// Parses a complete FrameAssembly program from a source string.
///
/// # Examples
/// ```
/// use frameassembly::parser::parse_program;
///
/// let input = "HOST client { IP 10.0.0.1 }\nCOMPILE {}";
/// let program = parse_program(input).unwrap();
/// assert_eq!(program.hosts.len(), 1);
/// ```
///
/// # Errors
/// Returns `CompilerError::ParseError` if:
/// * The input contains syntax errors.
/// * The tokens do not match the expected grammar.
/// * There are unexpected trailing tokens after the program block.
pub fn parse_program<'a>(input_str: &'a str) -> Result<Program<'a>, CompilerError> {
    let tokens = crate::lexer::lex(input_str)?;
    let mut stream: Stream<'_, 'a> = &tokens;

    match parse_all.parse_next(&mut stream) {
        Ok(program) => {
            if !stream.is_empty() {
                let span = stream[0].1.clone();
                return Err(CompilerError::ParseError {
                    message: "Unexpected tokens at end of file".to_string(),
                    src: input_str.to_string(),
                    span: (span.start, span.end - span.start),
                });
            }
            Ok(program)
        }
        Err(e) => {
            let offset = if stream.is_empty() {
                input_str.len()..input_str.len()
            } else {
                stream[0].1.clone()
            };
            Err(CompilerError::ParseError {
                message: alloc::format!("Syntax error: {:?}", e),
                src: input_str.to_string(),
                span: (offset.start, offset.end - offset.start),
            })
        }
    }
}
