//! Semantic validation pass for parsed FrameAssembly AST programs.
//!
//! This module implements [`validate_semantics`], the second stage of the FrameAssembly front-end
//! compiler pipeline. After lexical analysis and syntactic parsing produce a [`Program`], this
//! pass verifies structural and domain invariants across `HOST`, `FLOW`, and `COMPILE` blocks,
//! including duplicate symbol detection, numeric field bounds (`VLAN`, `DSCP`, `ECN`, `TTL`,
//! `FLOWLABEL`, `GENTRAP`), cross-protocol modifier compatibility, flow parameter arity, and
//! homogeneous IPv4/IPv6 or pure-L2 endpoint addressing.

use alloc::string::{String, ToString};
use core::net::IpAddr;
use std::collections::{HashMap, HashSet};

use crate::ast::*;
use crate::error::CompilerError;

/// Returns `true` if `protocol` requires both endpoints to declare an `IP` address in `HOST`,
/// or `false` for Layer 2 protocols that can operate over MAC-only endpoints (`LLDP`, `STP`,
/// `LACP`, `EAPOL`, `VLAN`, `QINQ`, `MPLS`, `ARP`).
pub fn protocol_requires_ip(protocol: &Protocol) -> bool {
    !matches!(
        protocol,
        Protocol::Lldp
            | Protocol::Stp
            | Protocol::Lacp
            | Protocol::Eapol
            | Protocol::Vlan
            | Protocol::Qinq
            | Protocol::Mpls
            | Protocol::Arp
    )
}

/// Validates field bounds, duplicate modifiers, and cross-protocol constraints on a single [`FrameStatement`].
fn validate_frame_statement(stmt: &FrameStatement, src: &str) -> Result<(), CompilerError> {
    // Check duplicate statement modifiers
    if let Some((mod_name, span)) = stmt.duplicate_modifiers.first() {
        return Err(CompilerError::SemanticError {
            message: alloc::format!("Duplicate statement modifier '{}'", mod_name),
            src: src.to_string(),
            span: *span,
        });
    }

    // Check out-of-range fields
    if let Some((vid, span)) = stmt.raw_vlan
        && (vid == 0 || vid > 4094)
    {
        return Err(CompilerError::SemanticError {
            message: alloc::format!("VLAN ID {} out of range (1..=4094)", vid),
            src: src.to_string(),
            span,
        });
    }

    if let Some((dscp, span)) = stmt.raw_dscp
        && dscp > 63
    {
        return Err(CompilerError::SemanticError {
            message: alloc::format!("DSCP {} out of range (0..=63)", dscp),
            src: src.to_string(),
            span,
        });
    }

    if let Some((ecn, span)) = stmt.raw_ecn
        && ecn > 3
    {
        return Err(CompilerError::SemanticError {
            message: alloc::format!("ECN {} out of range (0..=3)", ecn),
            src: src.to_string(),
            span,
        });
    }

    if let Some((ttl, span)) = stmt.raw_ttl
        && ttl > 255
    {
        return Err(CompilerError::SemanticError {
            message: alloc::format!("TTL {} out of range (0..=255)", ttl),
            src: src.to_string(),
            span,
        });
    }

    if let Some((flowlabel, span)) = stmt.raw_flowlabel
        && flowlabel > 0xF_FFFF
    {
        return Err(CompilerError::SemanticError {
            message: alloc::format!(
                "FLOWLABEL {} out of range (0..=1048575 / 0xFFFFF)",
                flowlabel
            ),
            src: src.to_string(),
            span,
        });
    }

    if let Some(gt) = stmt.gen_trap
        && gt > 6
    {
        let span = stmt.raw_gentrap_span.unwrap_or(stmt.span);
        return Err(CompilerError::SemanticError {
            message: alloc::format!("GENTRAP {} out of range (0..=6)", gt),
            src: src.to_string(),
            span,
        });
    }

    // Check duplicate statement modifiers (flags)
    let mut seen_flags = HashSet::new();
    for flag in &stmt.flags {
        if !seen_flags.insert(flag) {
            return Err(CompilerError::SemanticError {
                message: alloc::format!(
                    "Duplicate statement modifier: TCP flag '{:?}' specified multiple times",
                    flag
                ),
                src: src.to_string(),
                span: stmt.span,
            });
        }
    }

    // Check payload vs hexpayload collision
    if stmt.payload.is_some() && stmt.hex_payload.is_some() {
        return Err(CompilerError::SemanticError {
            message: "Duplicate statement modifier: cannot specify both PAYLOAD and HEXPAYLOAD"
                .to_string(),
            src: src.to_string(),
            span: stmt.span,
        });
    }

    // Check cross-protocol modifiers
    match stmt.protocol {
        Protocol::Udp => {
            if !stmt.flags.is_empty() {
                return Err(CompilerError::SemanticError {
                    message: "Invalid cross-protocol modifier: TCP flags cannot be used with UDP"
                        .to_string(),
                    src: src.to_string(),
                    span: stmt.span,
                });
            }
            if stmt.seq.is_some() || stmt.ack_num.is_some() || stmt.win.is_some() {
                return Err(CompilerError::SemanticError {
                    message:
                        "Invalid cross-protocol modifier: SEQ/ACKNUM/WIN cannot be used with UDP"
                            .to_string(),
                    src: src.to_string(),
                    span: stmt.span,
                });
            }
            if stmt.community.is_some()
                || stmt.user.is_some()
                || stmt.oid.is_some()
                || stmt.pdu_type.is_some()
                || !stmt.varbinds.is_empty()
            {
                return Err(CompilerError::SemanticError {
                    message: "Invalid cross-protocol modifier: SNMP fields cannot be used with UDP"
                        .to_string(),
                    src: src.to_string(),
                    span: stmt.span,
                });
            }
        }
        Protocol::Tcp => {
            if stmt.community.is_some()
                || stmt.user.is_some()
                || stmt.oid.is_some()
                || stmt.pdu_type.is_some()
                || !stmt.varbinds.is_empty()
            {
                return Err(CompilerError::SemanticError {
                    message: "Invalid cross-protocol modifier: SNMP fields cannot be used with TCP"
                        .to_string(),
                    src: src.to_string(),
                    span: stmt.span,
                });
            }
        }
        Protocol::Snmp1 => {
            if !stmt.flags.is_empty() {
                return Err(CompilerError::SemanticError {
                    message: "Invalid cross-protocol modifier: TCP flags cannot be used with SNMP1"
                        .to_string(),
                    src: src.to_string(),
                    span: stmt.span,
                });
            }
            if stmt.user.is_some()
                || stmt.engine_id.is_some()
                || stmt.auth.is_some()
                || stmt.priv_param.is_some()
            {
                return Err(CompilerError::SemanticError {
                    message:
                        "Invalid cross-protocol modifier: SNMPv3 USM fields cannot be used with SNMP1"
                            .to_string(),
                    src: src.to_string(),
                    span: stmt.span,
                });
            }
            if stmt.pdu_type == Some(SnmpPduType::GetBulk)
                || stmt.pdu_type == Some(SnmpPduType::Inform)
            {
                return Err(CompilerError::SemanticError {
                    message:
                        "Invalid cross-protocol modifier: GETBULK and INFORM are not supported in SNMP1"
                            .to_string(),
                    src: src.to_string(),
                    span: stmt.span,
                });
            }
        }
        Protocol::Snmp2 => {
            if !stmt.flags.is_empty() {
                return Err(CompilerError::SemanticError {
                    message: "Invalid cross-protocol modifier: TCP flags cannot be used with SNMP2"
                        .to_string(),
                    src: src.to_string(),
                    span: stmt.span,
                });
            }
            if stmt.enterprise.is_some()
                || stmt.agent_ip.is_some()
                || stmt.gen_trap.is_some()
                || stmt.spec_trap.is_some()
            {
                return Err(CompilerError::SemanticError {
                    message:
                        "Invalid cross-protocol modifier: SNMPv1 trap fields cannot be used with SNMP2"
                            .to_string(),
                    src: src.to_string(),
                    span: stmt.span,
                });
            }
            if stmt.user.is_some()
                || stmt.engine_id.is_some()
                || stmt.auth.is_some()
                || stmt.priv_param.is_some()
            {
                return Err(CompilerError::SemanticError {
                    message:
                        "Invalid cross-protocol modifier: SNMPv3 USM fields cannot be used with SNMP2"
                            .to_string(),
                    src: src.to_string(),
                    span: stmt.span,
                });
            }
        }
        Protocol::Snmp3 => {
            if !stmt.flags.is_empty() {
                return Err(CompilerError::SemanticError {
                    message: "Invalid cross-protocol modifier: TCP flags cannot be used with SNMP3"
                        .to_string(),
                    src: src.to_string(),
                    span: stmt.span,
                });
            }
            if stmt.enterprise.is_some()
                || stmt.agent_ip.is_some()
                || stmt.gen_trap.is_some()
                || stmt.spec_trap.is_some()
            {
                return Err(CompilerError::SemanticError {
                    message:
                        "Invalid cross-protocol modifier: SNMPv1 trap fields cannot be used with SNMP3"
                            .to_string(),
                    src: src.to_string(),
                    span: stmt.span,
                });
            }
            if stmt.community.is_some() {
                return Err(CompilerError::SemanticError {
                    message:
                        "Invalid cross-protocol modifier: COMMUNITY cannot be used with SNMP3 (use USER)"
                            .to_string(),
                    src: src.to_string(),
                    span: stmt.span,
                });
            }
        }
        _ => {}
    }

    Ok(())
}

/// Validates IP presence and IPv4/IPv6 address family homogeneity between `caller_host` and `callee_host`.
fn validate_statement_endpoints(
    stmt: &FrameStatement,
    caller_host: &HostDef,
    callee_host: &HostDef,
    src: &str,
) -> Result<(), CompilerError> {
    if protocol_requires_ip(&stmt.protocol) {
        if caller_host.ip.is_none() {
            return Err(CompilerError::SemanticError {
                message: alloc::format!(
                    "Protocol '{:?}' requires an 'IP <address>' field on HOST '{}'",
                    stmt.protocol,
                    caller_host.name
                ),
                src: src.to_string(),
                span: stmt.span,
            });
        }
        if callee_host.ip.is_none() {
            return Err(CompilerError::SemanticError {
                message: alloc::format!(
                    "Protocol '{:?}' requires an 'IP <address>' field on HOST '{}'",
                    stmt.protocol,
                    callee_host.name
                ),
                src: src.to_string(),
                span: stmt.span,
            });
        }
    }

    if let (Some(ip1), Some(ip2)) = (caller_host.ip, callee_host.ip)
        && ip1.is_ipv4() != ip2.is_ipv4()
    {
        return Err(CompilerError::SemanticError {
            message: alloc::format!(
                "Mixed IPv4 and IPv6 endpoints in statement: '{}' ({}) and '{}' ({})",
                caller_host.name,
                ip1,
                callee_host.name,
                ip2
            ),
            src: src.to_string(),
            span: stmt.span,
        });
    }

    if stmt.protocol == Protocol::Arp
        && matches!(
            (caller_host.ip, callee_host.ip),
            (Some(IpAddr::V6(_)), None) | (None, Some(IpAddr::V6(_)))
        )
    {
        return Err(CompilerError::SemanticError {
            message: alloc::format!(
                "Mixed IPv4 and IPv6 endpoints in ARP statement: '{}' and '{}'",
                caller_host.name,
                callee_host.name
            ),
            src: src.to_string(),
            span: stmt.span,
        });
    }

    Ok(())
}

/// Performs semantic validation on a parsed AST, emitting spanned [`CompilerError::SemanticError`].
///
/// # Checks
/// * Mixed IPv4 and IPv6 endpoints in any statement, and required `IP` fields for L3–L7 protocols.
/// * Out-of-range fields (`VLAN > 4094`, `DSCP > 63`, `ECN > 3`, `TTL > 255`, `FLOWLABEL > 0xFFFFF`, `GENTRAP > 6`).
/// * Duplicate `HOST`, `FLOW`, or parameter declarations (case-insensitive).
/// * Duplicate statement modifiers.
/// * Invalid cross-protocol modifiers.
pub fn validate_semantics(program: &Program, src: &str) -> Result<(), CompilerError> {
    // 1. Check duplicate HOST definitions (case-insensitive)
    let mut seen_hosts: HashMap<String, (usize, usize)> = HashMap::new();
    for host in &program.hosts {
        if let Some(first_span) = seen_hosts.insert(host.name.to_ascii_lowercase(), host.span) {
            let _ = first_span;
            return Err(CompilerError::SemanticError {
                message: alloc::format!("Duplicate HOST declaration: '{}'", host.name),
                src: src.to_string(),
                span: host.span,
            });
        }
    }

    // 2. Check duplicate FLOW definitions and duplicate parameter declarations (case-insensitive)
    let mut seen_flows: HashMap<String, (usize, usize)> = HashMap::new();
    for flow in &program.flows {
        if let Some(first_span) = seen_flows.insert(flow.name.to_ascii_lowercase(), flow.span) {
            let _ = first_span;
            return Err(CompilerError::SemanticError {
                message: alloc::format!("Duplicate FLOW declaration: '{}'", flow.name),
                src: src.to_string(),
                span: flow.span,
            });
        }

        let mut seen_params: HashSet<String> = HashSet::new();
        for param in &flow.params {
            if !seen_params.insert(param.to_ascii_lowercase()) {
                return Err(CompilerError::SemanticError {
                    message: alloc::format!(
                        "Duplicate parameter '{}' in FLOW '{}'",
                        param,
                        flow.name
                    ),
                    src: src.to_string(),
                    span: flow.span,
                });
            }
        }

        // Validate statements inside flow
        for stmt in &flow.statements {
            validate_frame_statement(stmt, src)?;
        }
    }

    // 3. Check compile block invocations, inline frame statements, and endpoint IP rules (case-insensitive)
    let host_map: HashMap<String, &HostDef> = program
        .hosts
        .iter()
        .map(|h| (h.name.to_ascii_lowercase(), h))
        .collect();
    let flow_map: HashMap<String, &FlowDef> = program
        .flows
        .iter()
        .map(|f| (f.name.to_ascii_lowercase(), f))
        .collect();

    let check_invocation = |inv: &TemplateInvocation| -> Result<(), CompilerError> {
        let flow = flow_map
            .get(&inv.name.to_ascii_lowercase())
            .ok_or_else(|| CompilerError::SemanticError {
                message: alloc::format!("Undefined flow: '{}'", inv.name),
                src: src.to_string(),
                span: inv.span,
            })?;

        if flow.params.len() != inv.args.len() {
            return Err(CompilerError::SemanticError {
                message: alloc::format!(
                    "Flow '{}' expects {} arguments, got {}",
                    flow.name,
                    flow.params.len(),
                    inv.args.len()
                ),
                src: src.to_string(),
                span: inv.span,
            });
        }

        let mut param_to_host: HashMap<String, &HostDef> = HashMap::new();
        for (i, param_name) in flow.params.iter().enumerate() {
            let Argument::Variable(var_name) = &inv.args[i];
            let host = host_map
                .get(&var_name.to_ascii_lowercase())
                .ok_or_else(|| CompilerError::SemanticError {
                    message: alloc::format!("Undefined host: '{}'", var_name),
                    src: src.to_string(),
                    span: inv.span,
                })?;
            param_to_host.insert(param_name.to_ascii_lowercase(), *host);
        }

        // Validate endpoints in flow statements
        for stmt in &flow.statements {
            let caller_host = param_to_host
                .get(&stmt.caller.node.to_ascii_lowercase())
                .ok_or_else(|| CompilerError::SemanticError {
                    message: alloc::format!(
                        "Unknown caller endpoint '{}' in flow '{}'",
                        stmt.caller.node,
                        flow.name
                    ),
                    src: src.to_string(),
                    span: stmt.span,
                })?;

            let callee_host = param_to_host
                .get(&stmt.callee.node.to_ascii_lowercase())
                .ok_or_else(|| CompilerError::SemanticError {
                    message: alloc::format!(
                        "Unknown callee endpoint '{}' in flow '{}'",
                        stmt.callee.node,
                        flow.name
                    ),
                    src: src.to_string(),
                    span: stmt.span,
                })?;

            validate_statement_endpoints(stmt, caller_host, callee_host, src)?;
        }

        Ok(())
    };

    for run_stmt in &program.compile_block {
        match run_stmt {
            RunStatement::Invocation(inv) => check_invocation(inv)?,
            RunStatement::Frame(stmt) => {
                validate_frame_statement(stmt, src)?;
                let caller_host = host_map
                    .get(&stmt.caller.node.to_ascii_lowercase())
                    .copied()
                    .ok_or_else(|| CompilerError::SemanticError {
                        message: alloc::format!("Undefined host: '{}'", stmt.caller.node),
                        src: src.to_string(),
                        span: stmt.caller.span,
                    })?;
                let callee_host = host_map
                    .get(&stmt.callee.node.to_ascii_lowercase())
                    .copied()
                    .ok_or_else(|| CompilerError::SemanticError {
                        message: alloc::format!("Undefined host: '{}'", stmt.callee.node),
                        src: src.to_string(),
                        span: stmt.callee.span,
                    })?;
                validate_statement_endpoints(stmt, caller_host, callee_host, src)?;
            }
            RunStatement::Loop(_, invocations) => {
                for inv in invocations {
                    check_invocation(inv)?;
                }
            }
        }
    }

    Ok(())
}
