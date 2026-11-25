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
/// or `false` for all 18 Layer 2 protocols that can operate over MAC-only endpoints (`lldp`,
/// `stp`, `lacp`, `eapol`, `vlan`, `qinq`, `mpls`, `arp`, `cdp`, `isis`, `macsec`, `pfc`,
/// `pppoe`, `nsh`, `profinet`, `goose`, `sv`, `ethercat`).
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
            | Protocol::Cdp
            | Protocol::Isis
            | Protocol::Macsec
            | Protocol::Pfc
            | Protocol::Pppoe
            | Protocol::Nsh
            | Protocol::Profinet
            | Protocol::Goose
            | Protocol::Sv
            | Protocol::Ethercat
    )
}

/// Returns `true` if `protocol` supports an explicit `transport tcp|udp|sctp` modifier.
fn supports_transport_override(protocol: &Protocol, tp: TransportProto) -> bool {
    let dual_tcp_udp = matches!(
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
            | Protocol::Ldap
            | Protocol::Snmp1
            | Protocol::Snmp2
            | Protocol::Snmp3
            | Protocol::Radius
            | Protocol::Coap
            | Protocol::Mqtt
            | Protocol::Rtsp
            | Protocol::Ntp
            | Protocol::Ldp
            | Protocol::Llmnr
            | Protocol::Twamp
            | Protocol::Rocplus
            | Protocol::Bsap
            | Protocol::Synchrophasor
            | Protocol::Hartip
            | Protocol::Fins
            | Protocol::Melsec
            | Protocol::Someip
            | Protocol::Doip
            | Protocol::C1222
            | Protocol::Turn
            | Protocol::H323
            | Protocol::Mgcp
            | Protocol::Mssql
            | Protocol::Kafka
    );
    match tp {
        TransportProto::Tcp => dual_tcp_udp,
        TransportProto::Udp => {
            dual_tcp_udp
                || matches!(
                    protocol,
                    Protocol::Profinet | Protocol::Ethercat | Protocol::L2tp
                )
        }
        TransportProto::Sctp => is_l7_protocol(protocol),
    }
}

/// Returns `true` if `protocol` is an L7 application protocol capable of running over `transport sctp`.
fn is_l7_protocol(protocol: &Protocol) -> bool {
    !matches!(
        protocol,
        Protocol::Arp
            | Protocol::Lldp
            | Protocol::Stp
            | Protocol::Lacp
            | Protocol::Eapol
            | Protocol::Vlan
            | Protocol::Qinq
            | Protocol::Mpls
            | Protocol::Cdp
            | Protocol::Isis
            | Protocol::Macsec
            | Protocol::Pfc
            | Protocol::Pppoe
            | Protocol::Nsh
            | Protocol::Profinet
            | Protocol::Goose
            | Protocol::Sv
            | Protocol::Ethercat
            | Protocol::Icmp
            | Protocol::Ndp
            | Protocol::Igmp
            | Protocol::Mld
            | Protocol::Gre
            | Protocol::Vxlan
            | Protocol::Geneve
            | Protocol::Ipsec
            | Protocol::Esp
            | Protocol::Ah
            | Protocol::Ikev2
            | Protocol::Wireguard
            | Protocol::Ospf
            | Protocol::Bgp
            | Protocol::Rip
            | Protocol::Vrrp
            | Protocol::Hsrp
            | Protocol::Pim
            | Protocol::Bfd
            | Protocol::Openflow
            | Protocol::Ipip
            | Protocol::Srv6
            | Protocol::Erspan
            | Protocol::Rsvp
            | Protocol::Ldp
            | Protocol::Bmp
            | Protocol::Rpkirtr
            | Protocol::L2tp
            | Protocol::Lisp
            | Protocol::Glbp
            | Protocol::Gtpu
            | Protocol::Tcp
            | Protocol::Udp
            | Protocol::Sctp
    )
}

/// Returns `true` if the frame resolves to a UDP header on the wire (explicit `udp`, UDP tunnel, or UDP L7).
fn is_udp_packet(protocol: &Protocol, transport: Option<TransportProto>) -> bool {
    if matches!(transport, Some(TransportProto::Tcp | TransportProto::Sctp))
        || matches!(protocol, Protocol::Ngap | Protocol::S1ap)
    {
        return false;
    }
    if matches!(
        protocol,
        Protocol::Udp
            | Protocol::Vxlan
            | Protocol::Geneve
            | Protocol::Ikev2
            | Protocol::Wireguard
            | Protocol::Rip
            | Protocol::Hsrp
            | Protocol::Bfd
            | Protocol::L2tp
            | Protocol::Lisp
            | Protocol::Glbp
            | Protocol::Gtpu
    ) {
        return true;
    }
    if transport == Some(TransportProto::Udp)
        && matches!(
            protocol,
            Protocol::Profinet | Protocol::Ethercat | Protocol::Ldp
        )
    {
        return true;
    }
    is_l7_protocol(protocol) && !crate::backend::is_tcp_protocol(protocol, transport)
}

/// Formats an internal modifier key (`SACK_PERM`, `CDP_NATIVE_VLAN`, `origin_host`) as a canonical `.frasm` keyword.
fn format_modifier_key(mod_name: &str) -> String {
    const PROTO_PREFIXES: &[&str] = &[
        "RPKIRTR_", "SOMEIP_", "DCERPC_", "GESRTP_", "MACSEC_", "LLMNR_", "PPPOE_", "SOCKS_",
        "ERSPAN_", "S7PLUS_", "MELSEC_", "C1222_", "ISCSI_", "TWAMP_", "L2TP_", "GLBP_",
        "GTPU_", "IPIP_", "SRV6_", "RSVP_", "NTLM_", "NBNS_", "HART_", "FINS_", "DOIP_",
        "ROCE_", "IPMI_", "NVME_", "TURN_", "H323_", "ISIS_", "CDP_", "PFC_", "NSH_", "LDP_",
        "BMP_", "LISP_", "RDP_", "WSD_", "IRC_", "SYN_", "ROC_", "BSAP_", "KNX_", "ECAT_",
        "VNC_", "PN_",
    ];
    match mod_name {
        "PDUTYPE" => return "PDU type".to_string(),
        "ARP_OPCODE" => return "arp opcode".to_string(),
        "ICMP_TYPE" => return "icmp type".to_string(),
        "NDP_TYPE" => return "ndp type".to_string(),
        "IGMP_TYPE" => return "igmp type".to_string(),
        "IKE_EXCHANGE" => return "ikev2 exchange".to_string(),
        "WG_TYPE" => return "wireguard type".to_string(),
        "OSPF_TYPE" => return "ospf type".to_string(),
        "BGP_TYPE" => return "bgp type".to_string(),
        "OPENFLOW_TYPE" => return "openflow type".to_string(),
        "GRE_KEY" => return "key".to_string(),
        "GRE_SEQ" => return "seq".to_string(),
        "GRE_PROTO" => return "proto".to_string(),
        "PN_DIR" => return "direction".to_string(),
        "GESRTP_PTYPE" | "ISIS_PDU_TYPE" | "PPPOE_STAGE" | "DCERPC_PDU" => {
            return "type".to_string()
        }
        "pdu_type" => return "msgtype".to_string(),
        "SOMEIP_SD_FLAGS" => return "flags".to_string(),
        "MMS_INVOKE_ID" => return "invokeid".to_string(),
        "TURN_XOR_RELAYED" => return "xorrelayedaddr".to_string(),
        "TURN_XOR_PEER" => return "xorpeeraddr".to_string(),
        "H323_RAS_ADDR" => return "rasaddr".to_string(),
        "ROCE_PSN" => return "seqnum".to_string(),
        "ROCE_MSN" => return "msgid".to_string(),
        "ROCE_VA" => return "addr".to_string(),
        "ROCE_SYNDROME" => return "status".to_string(),
        "RKEY" => return "key".to_string(),
        "DMA_LEN" => return "count".to_string(),
        "ICRC" => return "crc".to_string(),
        "WSD_ADDR" => return "addr".to_string(),
        "IRC_PREFIX" => return "prefix".to_string(),
        "IRC_TARGET" => return "target".to_string(),
        "IRC_JOIN_ARG" | "IRC_NICK_ARG" | "IRC_PRIVMSG_ARG" => return "cmd".to_string(),
        "IEC_DAT_SET" => return "datset".to_string(),
        "IEC_CONF_REV" => return "confrev".to_string(),
        "IEC_SIMULATION" => return "simulation".to_string(),
        "IEC_APPID" => return "appid".to_string(),
        "NUM_DAT_SET_ENTRIES" => return "numdatsetentries".to_string(),
        "TIME_TO_LIVE" => return "timetolive".to_string(),
        "NVME_COUNT" => return "count".to_string(),
        "TWAMP_TIMESTAMP" => return "timestamp".to_string(),
        "TWAMP_MODE" => return "mode".to_string(),
        "TWAMP_COUNT" => return "count".to_string(),
        "IPMI_CMD" => return "cmd".to_string(),
        "IPMI_REQUEST" => return "request".to_string(),
        "OBJECT_ID" | "SYN_ID" => return "id".to_string(),
        "ORIGIN_HOST" | "origin_host" => return "originhost".to_string(),
        "ORIGIN_REALM" | "origin_realm" => return "realm".to_string(),
        "api_version" => return "version".to_string(),
        "api" => return "apikey".to_string(),
        "REAL_VALUE" => return "real".to_string(),
        _ => {}
    }

    let mut stripped = mod_name;
    for &pfx in PROTO_PREFIXES {
        if let Some(rest) = stripped.strip_prefix(pfx) {
            stripped = rest;
            break;
        }
    }
    stripped
        .chars()
        .filter(|&c| c != '_')
        .map(|c| c.to_ascii_lowercase())
        .collect()
}

/// Validates RFC 1035 §2.3.4 domain label (`1..=63` octets) and total domain length (`<= 253` octets).
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
        if label.is_empty() {
            return sem_err(
                src,
                span,
                alloc::format!(
                    "DNS {field_name} '{domain}' contains an empty RFC 1035 label (expected 1..=63 octets per label)"
                ),
            );
        }
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
        let pretty = if !label.contains(' ')
            && !label.contains('-')
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

    if stmt.l2.qinq.is_some() && stmt.l2.vlan.is_some() {
        return sem_err(
            src,
            stmt.raw_vlan
                .map(|(_, s)| s)
                .or(stmt.raw_qinq_span)
                .unwrap_or(stmt.span),
            "Invalid L2 combination: cannot specify both 'qinq' and 'vlan' on the same frame — use 'qinq <outer> innervlan <inner>'",
        );
    }

    if let Some(span) = stmt.raw_inner_vlan_span
        && stmt.l2.qinq.is_none()
    {
        return sem_err(
            src,
            span,
            "Orphan 'innervlan' modifier requires 'qinq <outer>' on the same frame",
        );
    }

    if let Some(span) = stmt.raw_pcp_span
        && stmt.l2.vlan.is_none()
        && stmt.l2.qinq.is_none()
    {
        return sem_err(
            src,
            span,
            "Orphan 'pcp' modifier requires 'vlan <id>' or 'qinq <outer>' on the same frame",
        );
    }

    if let Some(span) = stmt.raw_dei_span
        && stmt.l2.vlan.is_none()
        && stmt.l2.qinq.is_none()
    {
        return sem_err(
            src,
            span,
            "Orphan 'dei' modifier requires 'vlan <id>' or 'qinq <outer>' on the same frame",
        );
    }

    if let Some(span) = stmt.raw_mpls_sub_span
        && stmt.l2.mpls_stack.is_empty()
    {
        return sem_err(
            src,
            span,
            "Orphan MPLS modifier ('exp'/'bos'/'mplsttl') requires 'mpls <label>' on the same frame",
        );
    }

    for mpls in &stmt.l2.mpls_stack {
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

    if let Some((fo, span)) = stmt.raw_frag_offset
        && fo > 8191
    {
        return sem_err(
            src,
            span,
            alloc::format!("fragoffset {fo} out of range (0..=8191)"),
        );
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
        } else if stmt.protocol == Protocol::Nsh {
            if ttl > 63 {
                return sem_err(
                    src,
                    span,
                    alloc::format!("NSH ttl {ttl} out of range (0..=63)"),
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
            validate_dns_record_domains(
                dns.qname,
                dns.qtype,
                dns.rdata,
                &dns.rdata_list,
                src,
                stmt.span,
            )?;
        }
        Some(ProtocolSpec::Doh(doh)) => {
            validate_dns_record_domains(
                doh.qname,
                doh.qtype,
                doh.rdata,
                &doh.rdata_list,
                src,
                stmt.span,
            )?;
        }
        Some(ProtocolSpec::Llmnr(llmnr)) => {
            validate_dns_record_domains(
                llmnr.qname,
                llmnr.qtype,
                llmnr.rdata,
                &llmnr.rdata_list,
                src,
                stmt.span,
            )?;
        }
        _ => {}
    }

    /// Validates `qname` and domain-valued `rdata` targets for DNS-family specs.
    fn validate_dns_record_domains(
        qname: Option<&str>,
        qtype: Option<&str>,
        rdata: Option<&str>,
        rdata_list: &[&str],
        src: &str,
        span: (usize, usize),
    ) -> Result<(), CompilerError> {
        if let Some(qn) = qname {
            validate_dns_domain(qn, "qname", src, span)?;
        }
        let qt = qtype.unwrap_or("A");
        let rdatas: &[&str] = if !rdata_list.is_empty() {
            rdata_list
        } else {
            rdata.as_slice()
        };
        for &rd in rdatas {
            if qt.eq_ignore_ascii_case("NS")
                || qt.eq_ignore_ascii_case("CNAME")
                || qt.eq_ignore_ascii_case("PTR")
            {
                validate_dns_domain(rd, "rdata", src, span)?;
            } else if qt.eq_ignore_ascii_case("MX") {
                let target = rd.split_whitespace().last().unwrap_or(rd);
                validate_dns_domain(target, "rdata", src, span)?;
            }
        }
        Ok(())
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

    // 4. Cross-protocol transport, TCP-only flags/options, nop, UDP nochecksum, and SNMP checks
    if let Some(tp) = stmt.l4.transport
        && !supports_transport_override(&stmt.protocol, tp)
    {
        let msg = match tp {
            TransportProto::Sctp => alloc::format!(
                "Invalid cross-protocol modifier: 'transport sctp' is only supported on Layer 7 application protocols, not '{proto_name}'"
            ),
            TransportProto::Tcp | TransportProto::Udp => alloc::format!(
                "Invalid cross-protocol modifier: 'transport' is only supported on multi-transport protocols (dns, sip, syslog, kerberos, nfs, memcached, modbus, dnp3, ethernetip, ldap, snmp1, snmp2, snmp3, radius, coap, mqtt, rtsp, ntp, ldp, llmnr, twamp, rocplus, bsap, synchrophasor, hartip, fins, melsec, someip, doip, c1222, turn, h323, mgcp, mssql, kafka; and 'transport udp' on profinet, ethercat, l2tp), not '{proto_name}'"
            ),
        };
        return sem_err(src, stmt.span, msg);
    }

    if stmt.l4.no_checksum && !is_udp_packet(&stmt.protocol, stmt.l4.transport) {
        return sem_err(
            src,
            stmt.raw_no_checksum_span.unwrap_or(stmt.span),
            alloc::format!(
                "Invalid cross-protocol modifier: 'nochecksum' is only supported on UDP packets, not '{proto_name}'"
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

    let is_tcp = stmt.l4.transport != Some(TransportProto::Sctp)
        && !matches!(stmt.protocol, Protocol::Ngap | Protocol::S1ap)
        && crate::backend::is_tcp_protocol(&stmt.protocol, stmt.l4.transport);
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
        let allows_seq = stmt.l4.transport == Some(TransportProto::Sctp)
            || matches!(
                stmt.protocol,
                Protocol::Sctp
                    | Protocol::Ngap
                    | Protocol::S1ap
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
    if protocol_requires_ip(&stmt.protocol)
        || (matches!(stmt.protocol, Protocol::Profinet | Protocol::Ethercat)
            && stmt.l4.transport == Some(TransportProto::Udp))
    {
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
        if stmt.l3.df && ip1.is_ipv6() {
            return sem_err(
                src,
                stmt.raw_df_span.unwrap_or(stmt.span),
                alloc::format!(
                    "Invalid L3 modifier: 'df' (Don't Fragment) only applies to IPv4, not IPv6 host '{}'",
                    caller_host.name
                ),
            );
        }
        if stmt.raw_flowlabel.is_some() && ip1.is_ipv4() {
            return sem_err(
                src,
                stmt.raw_flowlabel.map(|(_, s)| s).unwrap_or(stmt.span),
                alloc::format!(
                    "Invalid L3 modifier: 'flowlabel' only applies to IPv6, not IPv4 host '{}'",
                    caller_host.name
                ),
            );
        }
        if stmt.l3.bad_ip_checksum && ip1.is_ipv6() {
            return sem_err(
                src,
                stmt.raw_bad_ip_checksum_span.unwrap_or(stmt.span),
                alloc::format!(
                    "Invalid L3 modifier: 'badipchecksum' only applies to IPv4 (IPv6 headers have no IP checksum) on host '{}'",
                    caller_host.name
                ),
            );
        }
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
            Protocol::Srv6 if ip1.is_ipv4() => {
                return sem_err(
                    src,
                    stmt.span,
                    alloc::format!(
                        "Protocol 'srv6' requires IPv6 endpoints ('{}' is IPv4 {ip1})",
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

/// Validates that an endpoint inside a `flow` matches one of the flow's declared parameters
/// or an unshadowed global `host` declaration.
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
    if seen_params.contains(&key) || host_map.contains_key(&key) {
        return Ok(());
    }
    sem_err(
        src,
        stmt_span,
        alloc::format!("Unknown {role} endpoint '{}' in flow '{flow_name}'", ep.node),
    )
}

/// Validates statements inside a [`FlowDef::body`] recursively (frames, nested flow calls, and `repeat`).
fn validate_flow_body(
    items: &[FlowStatement],
    flow_name: &str,
    seen_params: &HashSet<String>,
    host_map: &HashMap<String, &HostDef>,
    flow_map: &HashMap<String, &FlowDef>,
    src: &str,
) -> Result<(), CompilerError> {
    for item in items {
        match item {
            FlowStatement::Frame(stmt) => {
                validate_frame_statement(stmt, src)?;
                validate_flow_endpoint(
                    "caller",
                    &stmt.caller,
                    flow_name,
                    seen_params,
                    host_map,
                    stmt.span,
                    src,
                )?;
                validate_flow_endpoint(
                    "callee",
                    &stmt.callee,
                    flow_name,
                    seen_params,
                    host_map,
                    stmt.span,
                    src,
                )?;
            }
            FlowStatement::Invocation(inv) => {
                let Some(callee_flow) = flow_map.get(&inv.name.to_ascii_lowercase()) else {
                    return sem_err(
                        src,
                        inv.span,
                        alloc::format!("Undefined flow: '{}'", inv.name),
                    );
                };
                if callee_flow.params.len() != inv.args.len() {
                    return sem_err(
                        src,
                        inv.span,
                        alloc::format!(
                            "Flow '{}' expects {} arguments, got {}",
                            callee_flow.name,
                            callee_flow.params.len(),
                            inv.args.len()
                        ),
                    );
                }
                for Argument::Variable(arg_name) in &inv.args {
                    let arg_key = arg_name.to_ascii_lowercase();
                    if !seen_params.contains(&arg_key) && !host_map.contains_key(&arg_key) {
                        return sem_err(
                            src,
                            inv.span,
                            alloc::format!(
                                "Undefined host or parameter '{}' passed to flow '{}' inside flow '{}'",
                                arg_name,
                                callee_flow.name,
                                flow_name
                            ),
                        );
                    }
                }
            }
            FlowStatement::Repeat { body, .. } => {
                validate_flow_body(body, flow_name, seen_params, host_map, flow_map, src)?;
            }
        }
    }
    Ok(())
}

/// Recursively checks [`FlowStatement`] slices for DFS cycles in `flow -> flow` invocations.
fn detect_flow_cycles_in_body(
    flow_key: &str,
    items: &[FlowStatement],
    flow_map: &HashMap<String, &FlowDef>,
    state: &mut HashMap<String, u8>,
    src: &str,
) -> Result<(), CompilerError> {
    for item in items {
        match item {
            FlowStatement::Invocation(inv) => {
                let target_key = inv.name.to_ascii_lowercase();
                match state.get(&target_key).copied().unwrap_or(0) {
                    1 => {
                        return sem_err(
                            src,
                            inv.span,
                            alloc::format!(
                                "Cyclic flow invocation detected: '{}' recursively calls '{}'",
                                flow_key,
                                inv.name
                            ),
                        );
                    }
                    0 => {
                        if let Some(target_flow) = flow_map.get(&target_key) {
                            state.insert(target_key.clone(), 1);
                            detect_flow_cycles_in_body(
                                target_flow.name,
                                &target_flow.body,
                                flow_map,
                                state,
                                src,
                            )?;
                            state.insert(target_key, 2);
                        }
                    }
                    _ => {}
                }
            }
            FlowStatement::Repeat { body, .. } => {
                detect_flow_cycles_in_body(flow_key, body, flow_map, state, src)?;
            }
            FlowStatement::Frame(_) => {}
        }
    }
    Ok(())
}

/// Validates endpoint host binding rules across nested `flow` calls and `repeat` blocks.
fn validate_invocation_with_env(
    inv: &TemplateInvocation,
    caller_env: &HashMap<String, &HostDef>,
    host_map: &HashMap<String, &HostDef>,
    flow_map: &HashMap<String, &FlowDef>,
    src: &str,
) -> Result<(), CompilerError> {
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
        let var_key = var_name.to_ascii_lowercase();
        let host = caller_env
            .get(&var_key)
            .or_else(|| host_map.get(&var_key))
            .copied()
            .ok_or_else(|| CompilerError::SemanticError {
                message: alloc::format!("Undefined host: '{var_name}'"),
                src: src.to_string(),
                span: inv.span,
            })?;
        param_to_host.insert(param_name.to_ascii_lowercase(), host);
    }

    if flow.body.is_empty() && !flow.statements.is_empty() {
        for stmt in &flow.statements {
            let caller_key = stmt.caller.node.to_ascii_lowercase();
            let callee_key = stmt.callee.node.to_ascii_lowercase();
            let caller_host = param_to_host
                .get(&caller_key)
                .or_else(|| host_map.get(&caller_key))
                .copied()
                .ok_or_else(|| CompilerError::SemanticError {
                    message: alloc::format!("Undefined host: '{}'", stmt.caller.node),
                    src: src.to_string(),
                    span: stmt.caller.span,
                })?;
            let callee_host = param_to_host
                .get(&callee_key)
                .or_else(|| host_map.get(&callee_key))
                .copied()
                .ok_or_else(|| CompilerError::SemanticError {
                    message: alloc::format!("Undefined host: '{}'", stmt.callee.node),
                    src: src.to_string(),
                    span: stmt.callee.span,
                })?;
            validate_statement_endpoints(stmt, caller_host, callee_host, src)?;
        }
        return Ok(());
    }

    validate_flow_body_endpoints(&flow.body, &param_to_host, host_map, flow_map, src)
}

/// Validates endpoint host compatibility recursively over [`FlowStatement`] items.
fn validate_flow_body_endpoints(
    items: &[FlowStatement],
    param_env: &HashMap<String, &HostDef>,
    host_map: &HashMap<String, &HostDef>,
    flow_map: &HashMap<String, &FlowDef>,
    src: &str,
) -> Result<(), CompilerError> {
    for item in items {
        match item {
            FlowStatement::Frame(stmt) => {
                let caller_key = stmt.caller.node.to_ascii_lowercase();
                let callee_key = stmt.callee.node.to_ascii_lowercase();
                let caller_host = param_env
                    .get(&caller_key)
                    .or_else(|| host_map.get(&caller_key))
                    .copied()
                    .ok_or_else(|| CompilerError::SemanticError {
                        message: alloc::format!("Undefined host: '{}'", stmt.caller.node),
                        src: src.to_string(),
                        span: stmt.caller.span,
                    })?;
                let callee_host = param_env
                    .get(&callee_key)
                    .or_else(|| host_map.get(&callee_key))
                    .copied()
                    .ok_or_else(|| CompilerError::SemanticError {
                        message: alloc::format!("Undefined host: '{}'", stmt.callee.node),
                        src: src.to_string(),
                        span: stmt.callee.span,
                    })?;
                validate_statement_endpoints(stmt, caller_host, callee_host, src)?;
            }
            FlowStatement::Invocation(inv) => {
                validate_invocation_with_env(inv, param_env, host_map, flow_map, src)?;
            }
            FlowStatement::Repeat { body, .. } => {
                validate_flow_body_endpoints(body, param_env, host_map, flow_map, src)?;
            }
        }
    }
    Ok(())
}

/// Recursively validates `compile` block [`RunStatement`] entries (`Invocation`, `Frame`, and `Repeat`).
fn validate_run_statements(
    items: &[RunStatement],
    host_map: &HashMap<String, &HostDef>,
    flow_map: &HashMap<String, &FlowDef>,
    src: &str,
) -> Result<(), CompilerError> {
    let empty_env = HashMap::new();
    for run_stmt in items {
        match run_stmt {
            RunStatement::Invocation(inv) => {
                validate_invocation_with_env(inv, &empty_env, host_map, flow_map, src)?;
            }
            RunStatement::Frame(stmt) => {
                validate_frame_statement(stmt, src)?;
                let Some(caller_host) =
                    host_map.get(&stmt.caller.node.to_ascii_lowercase()).copied()
                else {
                    return sem_err(
                        src,
                        stmt.caller.span,
                        alloc::format!("Undefined host: '{}'", stmt.caller.node),
                    );
                };
                let Some(callee_host) =
                    host_map.get(&stmt.callee.node.to_ascii_lowercase()).copied()
                else {
                    return sem_err(
                        src,
                        stmt.callee.span,
                        alloc::format!("Undefined host: '{}'", stmt.callee.node),
                    );
                };
                validate_statement_endpoints(stmt, caller_host, callee_host, src)?;
            }
            RunStatement::Repeat { body, .. } => {
                validate_run_statements(body, host_map, flow_map, src)?;
            }
        }
    }
    Ok(())
}

/// Performs semantic validation on a parsed AST, emitting spanned [`CompilerError::SemanticError`].
///
/// # Checks
/// * Mixed IPv4 and IPv6 endpoints in any statement, IP-version rules (`igmp` vs `mld`, `ndp`), and required `ip` fields for L3–L7 protocols.
/// * Out-of-range fields (`0..=255` `<u8>`, `0..=65535` `<u16>`, `vlan`/`qinq`/`innervlan` `0..=4095`, `pcp`/`exp` `0..=7`, `dei`/`bos` `0..=1`, `mpls`, `dscp`, `ecn`, `ttl`, `flowlabel`, `fragoffset` `0..=8191`, `gentrap`, `hellotime`, `syslog` `facility`/`severity`).
/// * Duplicate `host`, `flow`, or parameter declarations (case-insensitive) and acyclic `flow -> flow` calls.
/// * Duplicate statement modifiers and L4+L7 protocol collisions.
/// * Invalid cross-protocol modifiers (`transport`, `nochecksum`, `df` on IPv6, `flowlabel` on IPv4, `badipchecksum` on IPv6, orphan VLAN/QinQ/MPLS modifiers, TCP flags/options, `nop`, SNMP version fields).
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

    // 2. Check duplicate flow definitions and parameters before inspecting nested calls
    let mut seen_flows: HashMap<String, (usize, usize)> = HashMap::new();
    let mut flow_params_map: HashMap<String, HashSet<String>> = HashMap::new();
    for flow in &program.flows {
        let fkey = flow.name.to_ascii_lowercase();
        if seen_flows.insert(fkey.clone(), flow.span).is_some() {
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
        flow_params_map.insert(fkey, seen_params);
    }

    let flow_map: HashMap<String, &FlowDef> = program
        .flows
        .iter()
        .map(|f| (f.name.to_ascii_lowercase(), f))
        .collect();

    // 3. Validate flow bodies (frames, nested invocations, `repeat`, unshadowed global host refs)
    for flow in &program.flows {
        let seen_params = &flow_params_map[&flow.name.to_ascii_lowercase()];
        if flow.body.is_empty() && !flow.statements.is_empty() {
            for stmt in &flow.statements {
                validate_frame_statement(stmt, src)?;
                validate_flow_endpoint(
                    "caller",
                    &stmt.caller,
                    flow.name,
                    seen_params,
                    &host_map,
                    stmt.span,
                    src,
                )?;
                validate_flow_endpoint(
                    "callee",
                    &stmt.callee,
                    flow.name,
                    seen_params,
                    &host_map,
                    stmt.span,
                    src,
                )?;
            }
        } else {
            validate_flow_body(&flow.body, flow.name, seen_params, &host_map, &flow_map, src)?;
        }
    }

    // 4. Detect cyclic `flow -> flow` calls via DFS
    let mut dfs_state: HashMap<String, u8> = HashMap::new();
    for flow in &program.flows {
        let key = flow.name.to_ascii_lowercase();
        if dfs_state.get(&key).copied().unwrap_or(0) == 0 {
            dfs_state.insert(key.clone(), 1);
            detect_flow_cycles_in_body(flow.name, &flow.body, &flow_map, &mut dfs_state, src)?;
            dfs_state.insert(key, 2);
        }
    }

    // 5. Check compile block invocations, inline frame statements, `repeat` blocks, and endpoint rules
    validate_run_statements(&program.compile_block, &host_map, &flow_map, src)?;

    Ok(())
}
