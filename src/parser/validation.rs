//! Semantic validation pass for parsed FrameAssembly AST programs.
//!
//! This module implements [`validate_semantics`], the second stage of the FrameAssembly front-end
//! compiler pipeline. After lexical analysis and syntactic parsing produce a [`Program`], this
//! pass verifies structural and domain invariants across `host`, `flow`, and `compile` blocks,
//! including duplicate symbol detection, strict numeric field bounds (`0..=255` `<u8>`, `0..=65535`
//! `<u16>`, `vlan`/`qinq`/`innervlan` `0..=4095`, `pcp` `0..=7`, `dscp` `0..=63`, `ttl` `0..=255`),
//! RFC 1035 DNS label bounds, SNMPv3 `engineid` hex validation, cross-protocol modifier rules,
//! flow parameter arity, and homogeneous IPv4/IPv6 or pure-L2 endpoint addressing.

use alloc::string::{String, ToString};
use core::net::IpAddr;
use std::collections::{HashMap, HashSet};

use crate::ast::*;
use crate::error::CompilerError;

/// Constructs a spanned [`CompilerError::SemanticError`].
#[inline]
fn sem_err<T>(src: &str, span: (usize, usize), message: impl Into<String>) -> Result<T, CompilerError> {
    Err(CompilerError::SemanticError {
        message: message.into(),
        src: src.to_string(),
        span,
    })
}

/// Returns `true` if `protocol` requires both endpoints to declare an `ip` address in `host`,
/// or `false` for Layer 2 protocols that can operate over MAC-only endpoints (`lldp`, `stp`,
/// `lacp`, `eapol`, `vlan`, `qinq`, `mpls`, `arp`).
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

/// Returns `true` if `protocol` supports the explicit `transport tcp|udp` modifier.
fn supports_transport_override(protocol: &Protocol) -> bool {
    matches!(
        protocol,
        Protocol::Dns
            | Protocol::Sip
            | Protocol::Syslog
            | Protocol::Kerberos
            | Protocol::Nfs
            | Protocol::Memcached
            | Protocol::Modbus
            | Protocol::Dnp3
            | Protocol::Ethernetip
    )
}

/// Formats an internal modifier key (`SACK_PERM`, `INNER_VLAN`, `TTL`) as a lowercase `.frasm` keyword.
fn format_modifier_key(mod_name: &str) -> String {
    match mod_name {
        "PDUTYPE" => "PDU type".to_string(),
        "ARP_OPCODE" => "arp opcode".to_string(),
        "ICMP_TYPE" => "icmp type".to_string(),
        "NDP_TYPE" => "ndp type".to_string(),
        "IGMP_TYPE" => "igmp type".to_string(),
        "IKE_EXCHANGE" => "ikev2 exchange".to_string(),
        "WG_TYPE" => "wireguard type".to_string(),
        "OSPF_TYPE" => "ospf type".to_string(),
        "BGP_TYPE" => "bgp type".to_string(),
        "OPENFLOW_TYPE" => "openflow type".to_string(),
        "GRE_KEY" => "key".to_string(),
        "GRE_SEQ" => "seq".to_string(),
        "GRE_PROTO" => "proto".to_string(),
        other => other
            .chars()
            .filter(|&c| c != '_')
            .map(|c| c.to_ascii_lowercase())
            .collect(),
    }
}

/// Validates RFC 1035 §2.3.4 domain label (`<= 63` octets) and total domain length (`<= 253` octets).
fn validate_dns_domain(
    domain: &str,
    field_name: &str,
    src: &str,
    span: (usize, usize),
) -> Result<(), CompilerError> {
    let trimmed = domain.trim_end_matches('.');
    if trimmed.is_empty() {
        return Ok(());
    }
    if trimmed.len() > 253 {
        return sem_err(
            src,
            span,
            alloc::format!(
                "DNS {field_name} exceeds maximum RFC 1035 domain length of 253 octets ({} octets)",
                trimmed.len()
            ),
        );
    }
    for label in trimmed.split('.') {
        if label.len() > 63 {
            return sem_err(
                src,
                span,
                alloc::format!(
                    "DNS {field_name} label '{}' exceeds maximum RFC 1035 label length of 63 octets ({} octets)",
                    label,
                    label.len()
                ),
            );
        }
    }
    Ok(())
}

/// Validates field bounds, duplicate modifiers, and cross-protocol constraints on a single [`FrameStatement`].
fn validate_frame_statement(stmt: &FrameStatement, src: &str) -> Result<(), CompilerError> {
    let proto_name = alloc::format!("{:?}", stmt.protocol).to_ascii_lowercase();

    // 1. Duplicate statement modifiers and multiple-protocol collisions
    if let Some((mod_name, span)) = stmt.duplicate_modifiers.first() {
        if mod_name == "PROTOCOL" {
            let second_proto = src
                .get(span.0..span.0.saturating_add(span.1))
                .unwrap_or("protocol");
            return sem_err(
                src,
                *span,
                alloc::format!(
                    "Multiple protocols ('{}' and '{}') on one packet line. Write only the application or transport protocol (for example: '{} ...' instead of '{} {} ...', or use 'transport tcp' / 'transport udp' when supported)",
                    proto_name,
                    second_proto,
                    second_proto,
                    proto_name,
                    second_proto
                ),
            );
        }
        return sem_err(
            src,
            *span,
            alloc::format!(
                "Duplicate statement modifier '{}'",
                format_modifier_key(mod_name)
            ),
        );
    }

    // 2. Recorded numeric field bounds (0..=255 u8, 0..=65535 u16, protocol-scoped ranges)
    if let Some((label, val, min, max, span)) = stmt.raw_bounds.first() {
        let pretty = if label.chars().all(|c| c.is_ascii_uppercase() || c == '_')
            && !matches!(*label, "PCP" | "DEI" | "DSCP" | "ECN" | "TTL")
        {
            format_modifier_key(label)
        } else {
            (*label).to_string()
        };
        return sem_err(
            src,
            *span,
            alloc::format!("{pretty} {val} out of range ({min}..={max})"),
        );
    }

    if let Some((vid, span)) = stmt.raw_vlan
        && vid > 4095
    {
        return sem_err(
            src,
            span,
            alloc::format!("VLAN ID {vid} out of range (0..=4095)"),
        );
    }

    if let Some(qinq) = &stmt.l2.qinq {
        if qinq.outer_vid > 4095 {
            return sem_err(
                src,
                stmt.span,
                alloc::format!("QinQ VLAN ID {} out of range (0..=4095)", qinq.outer_vid),
            );
        }
        if let Some(iv) = qinq.inner_vid
            && iv > 4095
        {
            return sem_err(
                src,
                stmt.span,
                alloc::format!("QinQ innervlan ID {iv} out of range (0..=4095)"),
            );
        }
        if let Some(pcp) = qinq.pcp
            && pcp > 7
        {
            return sem_err(
                src,
                stmt.span,
                alloc::format!("PCP {pcp} out of range (0..=7)"),
            );
        }
        if let Some(dei) = qinq.dei
            && dei > 1
        {
            return sem_err(
                src,
                stmt.span,
                alloc::format!("DEI {dei} out of range (0..=1)"),
            );
        }
    }

    if let Some(vlan) = &stmt.l2.vlan {
        if vlan.vid > 4095 {
            return sem_err(
                src,
                stmt.span,
                alloc::format!("VLAN ID {} out of range (0..=4095)", vlan.vid),
            );
        }
        if let Some(pcp) = vlan.pcp
            && pcp > 7
        {
            return sem_err(
                src,
                stmt.span,
                alloc::format!("PCP {pcp} out of range (0..=7)"),
            );
        }
        if let Some(dei) = vlan.dei
            && dei > 1
        {
            return sem_err(
                src,
                stmt.span,
                alloc::format!("DEI {dei} out of range (0..=1)"),
            );
        }
    }

    if let Some(mpls) = &stmt.l2.mpls {
        if mpls.label > 0xF_FFFF {
            return sem_err(
                src,
                stmt.span,
                alloc::format!(
                    "MPLS label {} out of range (0..=1048575 / 0xFFFFF)",
                    mpls.label
                ),
            );
        }
        if let Some(exp) = mpls.exp
            && exp > 7
        {
            return sem_err(
                src,
                stmt.span,
                alloc::format!("MPLS exp {exp} out of range (0..=7)"),
            );
        }
        if let Some(bos) = mpls.bos
            && bos > 1
        {
            return sem_err(
                src,
                stmt.span,
                alloc::format!("MPLS bos {bos} out of range (0..=1)"),
            );
        }
    }

    if let Some((dscp, span)) = stmt.raw_dscp
        && dscp > 63
    {
        return sem_err(
            src,
            span,
            alloc::format!("DSCP {dscp} out of range (0..=63)"),
        );
    }

    if let Some((ecn, span)) = stmt.raw_ecn
        && ecn > 3
    {
        return sem_err(src, span, alloc::format!("ECN {ecn} out of range (0..=3)"));
    }

    if let Some((ttl, span)) = stmt.raw_ttl {
        if stmt.protocol == Protocol::Lldp {
            if ttl > 65535 {
                return sem_err(
                    src,
                    span,
                    alloc::format!("LLDP ttl {ttl} out of range (0..=65535)"),
                );
            }
        } else if ttl > 255 {
            return sem_err(src, span, alloc::format!("TTL {ttl} out of range (0..=255)"));
        }
    }

    if let Some((flowlabel, span)) = stmt.raw_flowlabel
        && flowlabel > 0xF_FFFF
    {
        return sem_err(
            src,
            span,
            alloc::format!("FLOWLABEL {flowlabel} out of range (0..=1048575 / 0xFFFFF)"),
        );
    }

    if let Some(gt) = stmt.gen_trap
        && gt > 6
    {
        return sem_err(
            src,
            stmt.raw_gentrap_span.unwrap_or(stmt.span),
            alloc::format!("GENTRAP {gt} out of range (0..=6)"),
        );
    }

    if stmt.protocol == Protocol::Hsrp
        && let Some((ht, span)) = stmt.raw_hellotime
        && ht > 255
    {
        return sem_err(
            src,
            span,
            alloc::format!("HSRP hellotime {ht} out of range (0..=255)"),
        );
    }

    match &stmt.protocol_spec {
        Some(ProtocolSpec::Syslog(syslog)) => {
            if let Some(fac) = syslog.facility
                && fac > 23
            {
                return sem_err(
                    src,
                    stmt.span,
                    alloc::format!("Syslog facility {fac} out of range (0..=23)"),
                );
            }
            if let Some(sev) = syslog.severity
                && sev > 7
            {
                return sem_err(
                    src,
                    stmt.span,
                    alloc::format!("Syslog severity {sev} out of range (0..=7)"),
                );
            }
        }
        Some(ProtocolSpec::Dns(dns) | ProtocolSpec::Mdns(dns)) => {
            if let Some(qn) = dns.qname {
                validate_dns_domain(qn, "qname", src, stmt.span)?;
            }
            if let Some(rd) = dns.rdata {
                let qt = dns.qtype.unwrap_or("A");
                if qt.eq_ignore_ascii_case("NS")
                    || qt.eq_ignore_ascii_case("CNAME")
                    || qt.eq_ignore_ascii_case("PTR")
                {
                    validate_dns_domain(rd, "rdata", src, stmt.span)?;
                } else if qt.eq_ignore_ascii_case("MX") {
                    let target = rd.split_whitespace().last().unwrap_or(rd);
                    validate_dns_domain(target, "rdata", src, stmt.span)?;
                }
            }
        }
        _ => {}
    }

    // 3. Duplicate TCP flags & payload exclusivity
    let mut seen_flags = HashSet::new();
    for flag in &stmt.flags {
        if !seen_flags.insert(flag) {
            let flag_name = alloc::format!("{:?}", flag).to_ascii_lowercase();
            return sem_err(
                src,
                stmt.span,
                alloc::format!(
                    "Duplicate statement modifier: TCP flag '{flag_name}' specified multiple times"
                ),
            );
        }
    }

    if (stmt.payload.is_some() || stmt.payload_bytes.is_some()) && stmt.hex_payload.is_some() {
        return sem_err(
            src,
            stmt.span,
            "Duplicate statement modifier: cannot specify both 'payload' and 'hexpayload'",
        );
    }

    // 4. Cross-protocol transport, TCP-only flags/options, nop, and SNMP checks
    if stmt.l4.transport.is_some() && !supports_transport_override(&stmt.protocol) {
        return sem_err(
            src,
            stmt.span,
            alloc::format!(
                "Invalid cross-protocol modifier: 'transport' is only supported on dual-transport protocols (dns, sip, syslog, kerberos, nfs, memcached, modbus, dnp3, ethernetip), not '{proto_name}'"
            ),
        );
    }

    if let Some(span) = stmt.raw_nop_span
        && stmt.protocol != Protocol::Ethernetip
    {
        return sem_err(
            src,
            span,
            alloc::format!("Invalid cross-protocol modifier: 'nop' cannot be used with '{proto_name}'"),
        );
    }

    let is_tcp = crate::backend::is_tcp_protocol(&stmt.protocol, stmt.l4.transport);
    if !is_tcp {
        if !stmt.flags.is_empty() {
            return sem_err(
                src,
                stmt.span,
                alloc::format!(
                    "Invalid cross-protocol modifier: TCP flags cannot be used with '{proto_name}'"
                ),
            );
        }
        if stmt.l4.tcp_options.is_some() {
            return sem_err(
                src,
                stmt.span,
                alloc::format!(
                    "Invalid cross-protocol modifier: TCP options (mss, wscale, sackperm, tsval, tsecr) cannot be used with '{proto_name}'"
                ),
            );
        }
        let allows_seq = matches!(
            stmt.protocol,
            Protocol::Sctp
                | Protocol::Icmp
                | Protocol::Gre
                | Protocol::Ipsec
                | Protocol::Esp
                | Protocol::Ah
                | Protocol::Rtp
                | Protocol::Sflow
                | Protocol::Netflow
                | Protocol::Ipfix
        );
        if stmt.ack_num.is_some()
            || stmt.win.is_some()
            || stmt.urgent.is_some()
            || (stmt.seq.is_some() && !allows_seq)
        {
            return sem_err(
                src,
                stmt.span,
                alloc::format!(
                    "Invalid cross-protocol modifier: 'seq'/'acknum'/'win' cannot be used with '{proto_name}'"
                ),
            );
        }
    }

    match stmt.protocol {
        Protocol::Udp | Protocol::Tcp => {
            if stmt.community.is_some()
                || stmt.user.is_some()
                || stmt.oid.is_some()
                || stmt.pdu_type.is_some()
                || !stmt.varbinds.is_empty()
            {
                return sem_err(
                    src,
                    stmt.span,
                    alloc::format!(
                        "Invalid cross-protocol modifier: SNMP fields cannot be used with '{proto_name}'"
                    ),
                );
            }
        }
        Protocol::Snmp1 => {
            if stmt.user.is_some()
                || stmt.engine_id.is_some()
                || stmt.auth.is_some()
                || stmt.priv_param.is_some()
            {
                return sem_err(
                    src,
                    stmt.span,
                    "Invalid cross-protocol modifier: SNMPv3 USM fields cannot be used with 'snmp1'",
                );
            }
            if matches!(
                stmt.pdu_type,
                Some(SnmpPduType::GetBulk | SnmpPduType::Inform | SnmpPduType::Report)
            ) {
                return sem_err(
                    src,
                    stmt.span,
                    "Invalid cross-protocol modifier: 'getbulk', 'inform', and 'report' are not supported in 'snmp1'",
                );
            }
        }
        Protocol::Snmp2 => {
            if stmt.enterprise.is_some()
                || stmt.agent_ip.is_some()
                || stmt.gen_trap.is_some()
                || stmt.spec_trap.is_some()
            {
                return sem_err(
                    src,
                    stmt.span,
                    "Invalid cross-protocol modifier: SNMPv1 trap fields cannot be used with 'snmp2'",
                );
            }
            if stmt.user.is_some()
                || stmt.engine_id.is_some()
                || stmt.auth.is_some()
                || stmt.priv_param.is_some()
            {
                return sem_err(
                    src,
                    stmt.span,
                    "Invalid cross-protocol modifier: SNMPv3 USM fields cannot be used with 'snmp2'",
                );
            }
        }
        Protocol::Snmp3 => {
            if stmt.enterprise.is_some()
                || stmt.agent_ip.is_some()
                || stmt.gen_trap.is_some()
                || stmt.spec_trap.is_some()
            {
                return sem_err(
                    src,
                    stmt.span,
                    "Invalid cross-protocol modifier: SNMPv1 trap fields cannot be used with 'snmp3'",
                );
            }
            if stmt.community.is_some() {
                return sem_err(
                    src,
                    stmt.span,
                    "Invalid cross-protocol modifier: 'community' cannot be used with 'snmp3' (use 'user')",
                );
            }
            if let Some(eid) = stmt.engine_id {
                let hex = eid
                    .strip_prefix("0x")
                    .or_else(|| eid.strip_prefix("0X"))
                    .unwrap_or(eid);
                if hex.is_empty()
                    || !hex.len().is_multiple_of(2)
                    || !hex.bytes().all(|b| b.is_ascii_hexdigit())
                {
                    return sem_err(
                        src,
                        stmt.span,
                        alloc::format!(
                            "Invalid SNMPv3 engineid '{eid}': expected a non-empty even-length hexadecimal string (for example: engineid \"8000000001\")"
                        ),
                    );
                }
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
    let proto_name = alloc::format!("{:?}", stmt.protocol).to_ascii_lowercase();
    if protocol_requires_ip(&stmt.protocol) {
        for h in [caller_host, callee_host] {
            if h.ip.is_none() {
                return sem_err(
                    src,
                    stmt.span,
                    alloc::format!(
                        "Protocol '{proto_name}' requires an 'ip <address>' field on host '{}'",
                        h.name
                    ),
                );
            }
        }
    }

    if let (Some(ip1), Some(ip2)) = (caller_host.ip, callee_host.ip)
        && ip1.is_ipv4() != ip2.is_ipv4()
    {
        return sem_err(
            src,
            stmt.span,
            alloc::format!(
                "Mixed IPv4 and IPv6 endpoints in statement: '{}' ({ip1}) and '{}' ({ip2})",
                caller_host.name,
                callee_host.name
            ),
        );
    }

    if let Some(ip1) = caller_host.ip {
        match stmt.protocol {
            Protocol::Igmp if ip1.is_ipv6() => {
                return sem_err(
                    src,
                    stmt.span,
                    alloc::format!(
                        "Protocol 'igmp' requires IPv4 endpoints ('{}' is IPv6 {ip1}); use 'mld' for IPv6 multicast",
                        caller_host.name
                    ),
                );
            }
            Protocol::Ndp if ip1.is_ipv4() => {
                return sem_err(
                    src,
                    stmt.span,
                    alloc::format!(
                        "Protocol 'ndp' requires IPv6 endpoints ('{}' is IPv4 {ip1}); use 'arp' for IPv4 address resolution",
                        caller_host.name
                    ),
                );
            }
            Protocol::Mld if ip1.is_ipv4() => {
                return sem_err(
                    src,
                    stmt.span,
                    alloc::format!(
                        "Protocol 'mld' requires IPv6 endpoints ('{}' is IPv4 {ip1}); use 'igmp' for IPv4 multicast",
                        caller_host.name
                    ),
                );
            }
            _ => {}
        }
    }

    if stmt.protocol == Protocol::Arp
        && matches!(
            (caller_host.ip, callee_host.ip),
            (Some(IpAddr::V6(_)), None) | (None, Some(IpAddr::V6(_)))
        )
    {
        return sem_err(
            src,
            stmt.span,
            alloc::format!(
                "Mixed IPv4 and IPv6 endpoints in ARP statement: '{}' and '{}'",
                caller_host.name,
                callee_host.name
            ),
        );
    }

    Ok(())
}

/// Validates that an endpoint inside a `flow` matches one of the flow's declared parameters,
/// emitting a helpful parameter-passing hint when the identifier matches a declared `host`.
fn validate_flow_endpoint(
    role: &str,
    ep: &Spanned<&str>,
    flow_name: &str,
    seen_params: &HashSet<String>,
    host_map: &HashMap<String, &HostDef>,
    stmt_span: (usize, usize),
    src: &str,
) -> Result<(), CompilerError> {
    let key = ep.node.to_ascii_lowercase();
    if seen_params.contains(&key) {
        return Ok(());
    }
    if host_map.contains_key(&key) {
        return sem_err(
            src,
            stmt_span,
            alloc::format!(
                "Unknown {role} endpoint '{}' in flow '{flow_name}' — '{}' is a declared host; pass '{}' as a flow parameter: flow {flow_name}(a, b) {{ ... }}",
                ep.node,
                ep.node,
                ep.node
            ),
        );
    }
    sem_err(
        src,
        stmt_span,
        alloc::format!("Unknown {role} endpoint '{}' in flow '{flow_name}'", ep.node),
    )
}

/// Performs semantic validation on a parsed AST, emitting spanned [`CompilerError::SemanticError`].
///
/// # Checks
/// * Mixed IPv4 and IPv6 endpoints in any statement, IP-version rules (`igmp` vs `mld`, `ndp`), and required `ip` fields for L3–L7 protocols.
/// * Out-of-range fields (`0..=255` `<u8>`, `0..=65535` `<u16>`, `vlan`/`qinq`/`innervlan` `0..=4095`, `pcp`/`exp` `0..=7`, `dei`/`bos` `0..=1`, `mpls`, `dscp`, `ecn`, `ttl`, `flowlabel`, `gentrap`, `hellotime`, `syslog` `facility`/`severity`).
/// * Duplicate `host`, `flow`, or parameter declarations (case-insensitive).
/// * Duplicate statement modifiers and L4+L7 protocol collisions.
/// * Invalid cross-protocol modifiers (`transport`, TCP flags/options, `nop`, SNMP version fields).
pub fn validate_semantics(program: &Program, src: &str) -> Result<(), CompilerError> {
    // 1. Check duplicate host definitions (case-insensitive)
    let mut seen_hosts: HashMap<String, (usize, usize)> = HashMap::new();
    for host in &program.hosts {
        if seen_hosts
            .insert(host.name.to_ascii_lowercase(), host.span)
            .is_some()
        {
            return sem_err(
                src,
                host.span,
                alloc::format!("Duplicate host declaration: '{}'", host.name),
            );
        }
    }
    let host_map: HashMap<String, &HostDef> = program
        .hosts
        .iter()
        .map(|h| (h.name.to_ascii_lowercase(), h))
        .collect();

    // 2. Check duplicate flow definitions, parameters, statement bounds, and flow endpoint bindings
    let mut seen_flows: HashMap<String, (usize, usize)> = HashMap::new();
    for flow in &program.flows {
        if seen_flows
            .insert(flow.name.to_ascii_lowercase(), flow.span)
            .is_some()
        {
            return sem_err(
                src,
                flow.span,
                alloc::format!("Duplicate flow declaration: '{}'", flow.name),
            );
        }

        let mut seen_params: HashSet<String> = HashSet::new();
        for param in &flow.params {
            if !seen_params.insert(param.to_ascii_lowercase()) {
                return sem_err(
                    src,
                    flow.span,
                    alloc::format!("Duplicate parameter '{}' in flow '{}'", param, flow.name),
                );
            }
        }

        for stmt in &flow.statements {
            validate_frame_statement(stmt, src)?;
            validate_flow_endpoint(
                "caller",
                &stmt.caller,
                flow.name,
                &seen_params,
                &host_map,
                stmt.span,
                src,
            )?;
            validate_flow_endpoint(
                "callee",
                &stmt.callee,
                flow.name,
                &seen_params,
                &host_map,
                stmt.span,
                src,
            )?;
        }
    }

    // 3. Check compile block invocations, inline frame statements, and endpoint IP rules
    let flow_map: HashMap<String, &FlowDef> = program
        .flows
        .iter()
        .map(|f| (f.name.to_ascii_lowercase(), f))
        .collect();

    let check_invocation = |inv: &TemplateInvocation| -> Result<(), CompilerError> {
        let Some(flow) = flow_map.get(&inv.name.to_ascii_lowercase()) else {
            return sem_err(src, inv.span, alloc::format!("Undefined flow: '{}'", inv.name));
        };

        if flow.params.len() != inv.args.len() {
            return sem_err(
                src,
                inv.span,
                alloc::format!(
                    "Flow '{}' expects {} arguments, got {}",
                    flow.name,
                    flow.params.len(),
                    inv.args.len()
                ),
            );
        }

        let mut param_to_host: HashMap<String, &HostDef> = HashMap::new();
        for (i, param_name) in flow.params.iter().enumerate() {
            let Argument::Variable(var_name) = &inv.args[i];
            let Some(host) = host_map.get(&var_name.to_ascii_lowercase()) else {
                return sem_err(src, inv.span, alloc::format!("Undefined host: '{var_name}'"));
            };
            param_to_host.insert(param_name.to_ascii_lowercase(), *host);
        }

        for stmt in &flow.statements {
            let caller_host = param_to_host[&stmt.caller.node.to_ascii_lowercase()];
            let callee_host = param_to_host[&stmt.callee.node.to_ascii_lowercase()];
            validate_statement_endpoints(stmt, caller_host, callee_host, src)?;
        }

        Ok(())
    };

    for run_stmt in &program.compile_block {
        match run_stmt {
            RunStatement::Invocation(inv) => check_invocation(inv)?,
            RunStatement::Frame(stmt) => {
                validate_frame_statement(stmt, src)?;
                let Some(caller_host) = host_map.get(&stmt.caller.node.to_ascii_lowercase()).copied()
                else {
                    return sem_err(
                        src,
                        stmt.caller.span,
                        alloc::format!("Undefined host: '{}'", stmt.caller.node),
                    );
                };
                let Some(callee_host) = host_map.get(&stmt.callee.node.to_ascii_lowercase()).copied()
                else {
                    return sem_err(
                        src,
                        stmt.callee.span,
                        alloc::format!("Undefined host: '{}'", stmt.callee.node),
                    );
                };
                validate_statement_endpoints(stmt, caller_host, callee_host, src)?;
            }
        }
    }

    Ok(())
}
