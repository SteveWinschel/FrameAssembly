//! Shadow-state elision and canonical `.fasm` program emitter for the reverse decompiler.
//!
//! This module implements Stage 5 of the FrameAssembly reverse decompilation pipeline
//! ([`emit_fasm_program`]). It emits discovered `host_<N>` declarations followed by a single
//! `compile { ... }` block containing chronological inline directional frame statements. While
//! emitting statements, it maintains a shadow copy of the forward compiler's two-stage port
//! inheritance table (`EndpointPairPorts`) and canonical 4-tuple TCP sequence/acknowledgment state
//! machine (`TcpStreamState`) so redundant default fields (`srcport`, `dstport`, `seq`, `acknum`,
//! `ttl`, `win`, and default `10ms` `wait` intervals) are elided cleanly.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt::Write as _;
use core::net::{IpAddr, Ipv4Addr};
use std::collections::HashMap;

use logos::Logos;

use crate::ast::{Direction, Protocol, TcpFlag, TransportProto};
use crate::backend::is_tcp_protocol;
use crate::lexer::Token;

use super::oracle::verify_with_oracle;
use super::topology::{CaptureTopology, DiscoveredHost, ResolvedFrameEndpoints};
use super::{DissectedPacket, ReverseOutput, format_mac_lower, format_payload_modifier};

/// Default inter-packet wait interval (`10ms` in nanoseconds) used by the forward compiler.
const DEFAULT_WAIT_NS: u64 = 10_000_000;

/// Default TCP initial sequence number (`1000`) used by the forward compiler.
const DEFAULT_TCP_ISN: u32 = 1000;

/// Default TCP window size (`64240`) used by the forward compiler.
const DEFAULT_TCP_WIN: u16 = 64240;

/// Default ephemeral source port (`12345`) used by the forward compiler.
const DEFAULT_SRC_PORT: u16 = 12345;

/// Shadow endpoint-pair port inheritance state mirroring `src/backend/mod.rs`.
#[derive(Debug, Clone, Default)]
struct ShadowEndpointPairPorts {
    /// Last source/caller port associated with the caller endpoint.
    caller_port: Option<u16>,
    /// Last destination/callee port associated with the callee endpoint.
    callee_port: Option<u16>,
    /// Last protocol executed across this endpoint pair.
    last_protocol: Option<Protocol>,
    /// Whether `callee_port` was explicitly overridden by `srcport` or `dstport`.
    callee_port_explicit: bool,
}

/// Shadow 4-tuple TCP sequence progression state mirroring `src/backend/mod.rs`.
#[derive(Debug, Clone)]
struct ShadowTcpStreamState {
    /// Next expected sequence number for endpoint 1.
    seq1: u32,
    /// Next expected sequence number for endpoint 2.
    seq2: u32,
}

/// Canonical 4-tuple key ordering two `(IpAddr, u16)` endpoints lexicographically.
type Canonical4Tuple = ((IpAddr, u16), (IpAddr, u16));

/// Tracks which universal modifier tokens are already present inside `pkt.dissection.tokens`.
#[derive(Debug, Default)]
struct ExistingTokens {
    /// Whether any TCP flag token (`syn`, `ack`, `fin`, `rst`, `psh`, `urg`, `ece`, `cwr`) is present.
    has_tcp_flags: bool,
    /// Whether `mss` is already present.
    has_mss: bool,
    /// Whether `wscale` is already present.
    has_wscale: bool,
    /// Whether `sack_perm` is already present.
    has_sack_perm: bool,
    /// Whether `tsval` is already present.
    has_tsval: bool,
    /// Whether `tsecr` is already present.
    has_tsecr: bool,
    /// Whether `transport` is already present.
    has_transport: bool,
    /// Whether `srcport` is already present.
    has_srcport: bool,
    /// Whether `dstport` is already present.
    has_dstport: bool,
    /// Whether `seq` is already present.
    has_seq: bool,
    /// Whether `acknum` is already present.
    has_acknum: bool,
    /// Whether `win` is already present.
    has_win: bool,
    /// Whether `urgent` is already present.
    has_urgent: bool,
    /// Whether `srcmac` is already present.
    has_srcmac: bool,
    /// Whether `dstmac` is already present.
    has_dstmac: bool,
    /// Whether `ethertype` is already present.
    has_ethertype: bool,
    /// Whether `vlan` is already present.
    has_vlan: bool,
    /// Whether `qinq` is already present.
    has_qinq: bool,
    /// Whether `mpls` is already present.
    has_mpls: bool,
    /// Whether `ttl` is already present.
    has_ttl: bool,
    /// Whether `dscp` is already present.
    has_dscp: bool,
    /// Whether `ecn` is already present.
    has_ecn: bool,
    /// Whether `flowlabel` is already present.
    has_flowlabel: bool,
    /// Whether `ipid` is already present.
    has_ipid: bool,
    /// Whether `df` is already present.
    has_df: bool,
    /// Whether `mf` is already present.
    has_mf: bool,
    /// Whether `fragoffset` is already present.
    has_fragoffset: bool,
    /// Whether `payload` or `hexpayload` is already present.
    has_payload: bool,
}

impl ExistingTokens {
    /// Scans `tokens_str` with the FrameAssembly lexer to record already-emitted modifier keywords.
    fn scan(tokens_str: &str) -> Self {
        let mut out = Self::default();
        for tok in Token::lexer(tokens_str).flatten() {
            match tok {
                Token::Syn
                | Token::Ack
                | Token::Fin
                | Token::Rst
                | Token::Psh
                | Token::Urg
                | Token::Ece
                | Token::Cwr => out.has_tcp_flags = true,
                Token::Mss => out.has_mss = true,
                Token::Wscale => out.has_wscale = true,
                Token::SackPerm => out.has_sack_perm = true,
                Token::Tsval => out.has_tsval = true,
                Token::Tsecr => out.has_tsecr = true,
                Token::Transport => out.has_transport = true,
                Token::SrcPort => out.has_srcport = true,
                Token::DstPort => out.has_dstport = true,
                Token::Seq => out.has_seq = true,
                Token::AckNum => out.has_acknum = true,
                Token::Win => out.has_win = true,
                Token::Urgent => out.has_urgent = true,
                Token::SrcMac => out.has_srcmac = true,
                Token::DstMac => out.has_dstmac = true,
                Token::EtherType => out.has_ethertype = true,
                Token::Vlan => out.has_vlan = true,
                Token::Qinq => out.has_qinq = true,
                Token::Mpls => out.has_mpls = true,
                Token::Ttl => out.has_ttl = true,
                Token::Dscp => out.has_dscp = true,
                Token::Ecn => out.has_ecn = true,
                Token::FlowLabel => out.has_flowlabel = true,
                Token::IpId => out.has_ipid = true,
                Token::Df => out.has_df = true,
                Token::Mf => out.has_mf = true,
                Token::FragOffset => out.has_fragoffset = true,
                Token::Payload | Token::HexPayload => out.has_payload = true,
                _ => {}
            }
        }
        out
    }
}

/// Emits a complete, canonical lowercase `.fasm` program from dissected packets and topology.
pub(crate) fn emit_fasm_program(
    packets: &[DissectedPacket],
    topo: &CaptureTopology,
) -> ReverseOutput {
    if topo.hosts.is_empty() || packets.is_empty() {
        return ReverseOutput {
            fasm: String::from("compile {\n}\n"),
            packet_count: packets.len(),
            host_count: topo.hosts.len(),
        };
    }

    let mut fasm = String::new();
    for host in &topo.hosts {
        let _ = writeln!(fasm, "{}", format_host_line(host));
    }
    fasm.push('\n');
    fasm.push_str("compile {\n");

    let mut endpoint_ports: HashMap<(String, String), ShadowEndpointPairPorts> = HashMap::new();
    let mut tcp_connections: HashMap<Canonical4Tuple, ShadowTcpStreamState> = HashMap::new();

    for (idx, pkt) in packets.iter().enumerate() {
        let ep = topo
            .frame_endpoints
            .get(idx)
            .cloned()
            .unwrap_or(ResolvedFrameEndpoints {
                caller_idx: 0,
                callee_idx: 0,
                dir: Direction::LeftToRight,
                emit_src_mac: None,
                emit_dst_mac: None,
            });
        let caller = &topo.hosts[ep.caller_idx.min(topo.hosts.len() - 1)];
        let callee = &topo.hosts[ep.callee_idx.min(topo.hosts.len() - 1)];
        let arrow = match ep.dir {
            Direction::LeftToRight => "->",
            Direction::RightToLeft => "<-",
        };

        let wait_opt = if idx == 0 {
            None
        } else {
            let prev_ts = packets[idx - 1].timestamp_ns;
            let delta_ns = pkt.timestamp_ns.saturating_sub(prev_ts);
            quantize_wait_delta(delta_ns)
        };

        let candidate_body = build_candidate_statement_body(
            pkt,
            caller,
            callee,
            &ep,
            wait_opt.as_deref(),
            &endpoint_ports,
            &tcp_connections,
        );

        let verified = verify_with_oracle(pkt, caller, callee, &ep, &candidate_body);

        update_shadow_state_after_statement(
            pkt,
            caller,
            callee,
            &ep,
            &verified.statement_body,
            &mut endpoint_ports,
            &mut tcp_connections,
        );

        let _ = writeln!(
            fasm,
            "    {} {} {} {}",
            caller.name, arrow, callee.name, verified.statement_body
        );
    }

    fasm.push_str("}\n");

    ReverseOutput {
        fasm,
        packet_count: packets.len(),
        host_count: topo.hosts.len(),
    }
}

/// Formats a single `host <name> { ... }` declaration line in canonical lowercase syntax.
fn format_host_line(host: &DiscoveredHost) -> String {
    let mut parts = Vec::new();
    if let Some(ip) = host.ip {
        parts.push(format!("ip {ip}"));
    }
    if let Some(mac) = host.mac {
        parts.push(format!("mac {}", format_mac_lower(mac)));
    }
    if parts.is_empty() {
        parts.push(String::from("mac 00:00:00:00:00:01"));
    }
    format!("host {} {{ {} }}", host.name, parts.join(" "))
}

/// Quantizes an inter-packet nanosecond delta into a `wait <u32><unit>` modifier string,
/// returning `None` when `delta_ns == 10_000_000` (`10ms` default).
fn quantize_wait_delta(delta_ns: u64) -> Option<String> {
    if delta_ns == DEFAULT_WAIT_NS {
        return None;
    }
    if delta_ns == 0 {
        return Some(String::from("wait 0ms"));
    }

    const NS_PER_US: u64 = 1_000;
    const NS_PER_MS: u64 = 1_000_000;
    const NS_PER_S: u64 = 1_000_000_000;
    const NS_PER_M: u64 = 60_000_000_000;
    let max_u32 = u32::MAX as u64;

    if delta_ns.is_multiple_of(NS_PER_M) && delta_ns / NS_PER_M <= max_u32 {
        return Some(format!("wait {}m", delta_ns / NS_PER_M));
    }
    if delta_ns.is_multiple_of(NS_PER_S) && delta_ns / NS_PER_S <= max_u32 {
        return Some(format!("wait {}s", delta_ns / NS_PER_S));
    }
    if delta_ns.is_multiple_of(NS_PER_MS) && delta_ns / NS_PER_MS <= max_u32 {
        return Some(format!("wait {}ms", delta_ns / NS_PER_MS));
    }
    if delta_ns.is_multiple_of(NS_PER_US) && delta_ns / NS_PER_US <= max_u32 {
        return Some(format!("wait {}us", delta_ns / NS_PER_US));
    }
    if delta_ns <= max_u32 {
        return Some(format!("wait {delta_ns}ns"));
    }

    // Scaling fallback when `delta_ns > u32::MAX` and not an exact unit multiple.
    if delta_ns / NS_PER_US <= max_u32 {
        Some(format!("wait {}us", delta_ns / NS_PER_US))
    } else if delta_ns / NS_PER_MS <= max_u32 {
        Some(format!("wait {}ms", delta_ns / NS_PER_MS))
    } else if delta_ns / NS_PER_S <= max_u32 {
        Some(format!("wait {}s", delta_ns / NS_PER_S))
    } else {
        Some(format!("wait {}m", (delta_ns / NS_PER_M).min(max_u32)))
    }
}

/// Returns the forward compiler's Stage 1 default destination port for `protocol` and `tokens`.
fn stage1_default_dst_port(protocol: &Protocol, tokens_str: &str) -> u16 {
    match protocol {
        Protocol::Tcp | Protocol::Udp | Protocol::Sctp | Protocol::Http | Protocol::Websocket => 80,
        Protocol::Snmp1 | Protocol::Snmp2 | Protocol::Snmp3 => {
            let is_request_or_resp = Token::lexer(tokens_str).flatten().any(|t| {
                matches!(
                    t,
                    Token::Get | Token::GetNext | Token::GetBulk | Token::Set | Token::Response
                )
            });
            if is_request_or_resp { 161 } else { 162 }
        }
        Protocol::Bgp => 179,
        Protocol::Openflow => 6653,
        Protocol::Vxlan => 4789,
        Protocol::Geneve => 6081,
        Protocol::Ikev2 => 500,
        Protocol::Wireguard => 51820,
        Protocol::Rip => 520,
        Protocol::Hsrp => 1985,
        Protocol::Bfd => 3784,
        Protocol::Dns => 53,
        Protocol::Mdns => 5353,
        Protocol::Dhcp => 67,
        Protocol::Ntp => 123,
        Protocol::Ptp => 319,
        Protocol::Radius => 1812,
        Protocol::Tacacs => 49,
        Protocol::Syslog => 514,
        Protocol::Netflow => 2055,
        Protocol::Ipfix => 4739,
        Protocol::Sflow => 6343,
        Protocol::Tftp => 69,
        Protocol::Ftp => 21,
        Protocol::Ssh => 22,
        Protocol::Telnet => 23,
        Protocol::Http2 | Protocol::Tls | Protocol::Quic => 443,
        Protocol::Grpc => 50051,
        Protocol::Stun => 3478,
        Protocol::Sip => 5060,
        Protocol::Rtp => 5004,
        Protocol::Rtsp => 554,
        Protocol::Smtp => 25,
        Protocol::Imap => 143,
        Protocol::Pop3 => 110,
        Protocol::Kerberos => 88,
        Protocol::Ldap => 389,
        Protocol::Smb => 445,
        Protocol::Nfs => 2049,
        Protocol::Redis => 6379,
        Protocol::Memcached => 11211,
        Protocol::Mysql => 3306,
        Protocol::Postgres => 5432,
        Protocol::Mqtt => 1883,
        Protocol::Coap => 5683,
        Protocol::Amqp => 5672,
        Protocol::Ssdp => 1900,
        Protocol::Whois => 43,
        Protocol::Modbus => 502,
        Protocol::Bacnet => 47808,
        Protocol::Dnp3 => 20000,
        Protocol::S7comm => 102,
        Protocol::Ethernetip => 44818,
        Protocol::Opcua => 4840,
        _ => 0,
    }
}

/// Returns optional `(src_port_override, dst_port_override)` produced by `build_l7_packet_payload`
/// in `src/backend/l7_dispatch.rs`.
fn l7_builder_port_overrides(
    protocol: &Protocol,
    tokens_str: &str,
    is_ipv6: bool,
) -> (Option<u16>, Option<u16>) {
    match protocol {
        Protocol::Mdns => (None, Some(5353)),
        Protocol::Dhcp => {
            let is_server_reply = Token::lexer(tokens_str)
                .flatten()
                .any(|t| matches!(t, Token::Offer | Token::Ack));
            let (sport, dport) = match (is_ipv6, is_server_reply) {
                (false, false) => (68, 67),
                (false, true) => (67, 68),
                (true, false) => (546, 547),
                (true, true) => (547, 546),
            };
            (Some(sport), Some(dport))
        }
        Protocol::Ptp => {
            let is_general = Token::lexer(tokens_str).flatten().any(|t| {
                matches!(
                    t,
                    Token::FollowUp | Token::DelayResp | Token::Announce
                )
            });
            (None, Some(if is_general { 320 } else { 319 }))
        }
        Protocol::Radius => {
            let is_acct = Token::lexer(tokens_str)
                .flatten()
                .any(|t| matches!(t, Token::AccountingRequest | Token::AccountingResponse));
            (None, Some(if is_acct { 1813 } else { 1812 }))
        }
        _ => (None, None),
    }
}

/// Predicts the wire `(src_port, dst_port)` that `execute_statement` in `src/backend/mod.rs`
/// would synthesize if `srcport` and `dstport` were omitted on this statement.
fn predict_wire_ports(
    protocol: &Protocol,
    tokens_str: &str,
    dir: Direction,
    is_ipv6: bool,
    pair_ports: Option<&ShadowEndpointPairPorts>,
) -> (u16, u16) {
    let is_raw_l4 = matches!(protocol, Protocol::Tcp | Protocol::Udp | Protocol::Sctp);
    let can_inherit_callee = is_raw_l4
        || pair_ports.is_some_and(|pp| {
            pp.callee_port_explicit
                && (pp.last_protocol.as_ref() == Some(protocol)
                    || matches!(
                        pp.last_protocol,
                        Some(Protocol::Tcp | Protocol::Udp | Protocol::Sctp)
                    ))
        });
    let inherited_callee_port = if can_inherit_callee {
        pair_ports.and_then(|pp| pp.callee_port)
    } else {
        None
    };
    let caller_port = pair_ports.and_then(|pp| pp.caller_port);
    let default_dst = stage1_default_dst_port(protocol, tokens_str);

    let (mut src_port, mut dst_port) = match dir {
        Direction::LeftToRight => (
            caller_port.unwrap_or(DEFAULT_SRC_PORT),
            inherited_callee_port.unwrap_or(default_dst),
        ),
        Direction::RightToLeft => (
            inherited_callee_port.unwrap_or(default_dst),
            caller_port.unwrap_or(DEFAULT_SRC_PORT),
        ),
    };

    let (l7_sp, l7_dp) = l7_builder_port_overrides(protocol, tokens_str, is_ipv6);
    if let Some(sp) = l7_sp {
        src_port = sp;
    }
    if let Some(dp) = l7_dp {
        if *protocol == Protocol::Radius && dir == Direction::RightToLeft {
            src_port = dp;
        } else {
            dst_port = dp;
        }
    }

    // L3-over-UDP protocols in `src/backend/mod.rs` override `final_dport` (and `final_sport` for RIP/HSRP).
    match protocol {
        Protocol::Rip => {
            let dport = if is_ipv6 { 521 } else { 520 };
            src_port = dport;
            dst_port = dport;
        }
        Protocol::Hsrp => {
            let is_v2 = tokens_str.contains("version 2");
            let dport = if is_v2 { 2029 } else { 1985 };
            src_port = dport;
            dst_port = dport;
        }
        Protocol::Vxlan => dst_port = 4789,
        Protocol::Geneve => dst_port = 6081,
        Protocol::Wireguard => dst_port = 51820,
        Protocol::Ikev2 => dst_port = 500,
        Protocol::Bfd => dst_port = 3784,
        _ => {}
    }

    (src_port, dst_port)
}

/// Builds the candidate statement body (everything after `<caller> ->|<- <callee> `) with
/// shadow-state field elision applied.
fn build_candidate_statement_body(
    pkt: &DissectedPacket,
    caller: &DiscoveredHost,
    callee: &DiscoveredHost,
    ep: &ResolvedFrameEndpoints,
    wait_opt: Option<&str>,
    endpoint_ports: &HashMap<(String, String), ShadowEndpointPairPorts>,
    tcp_connections: &HashMap<Canonical4Tuple, ShadowTcpStreamState>,
) -> String {
    let existing = ExistingTokens::scan(&pkt.dissection.tokens);
    let mut parts: Vec<String> = Vec::new();
    parts.push(pkt.dissection.tokens.trim().to_string());

    let protocol = &pkt.dissection.protocol;
    let transport_override = pkt.dissection.explicit_transport.or(pkt.l4.transport);
    if !existing.has_transport
        && let Some(tp) = transport_override
    {
        match tp {
            TransportProto::Tcp => parts.push(String::from("transport tcp")),
            TransportProto::Udp => parts.push(String::from("transport udp")),
        }
    }

    let (src_host, dst_host) = match ep.dir {
        Direction::LeftToRight => (caller, callee),
        Direction::RightToLeft => (callee, caller),
    };
    let src_ip = src_host
        .ip
        .or(pkt.src_ip)
        .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
    let dst_ip = dst_host
        .ip
        .or(pkt.dst_ip)
        .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
    let is_ipv6 = src_ip.is_ipv6();

    // 1. TCP flags, sequence/ack numbers, window, urgent pointer, and TCP options.
    let is_stream_tcp = is_tcp_protocol(protocol, transport_override);
    let should_emit_tcp_flags = if *protocol == Protocol::Tcp {
        !existing.has_tcp_flags
    } else {
        is_stream_tcp
            && !existing.has_tcp_flags
            && !pkt.l4.tcp_flags.is_empty()
            && !(pkt.l4.tcp_flags.len() == 2
                && pkt.l4.tcp_flags.contains(&TcpFlag::Psh)
                && pkt.l4.tcp_flags.contains(&TcpFlag::Ack))
            && !(*protocol == Protocol::Sip
                && pkt
                    .l4
                    .tcp_flags
                    .iter()
                    .any(|f| matches!(f, TcpFlag::Ack | TcpFlag::Rst)))
    };
    if should_emit_tcp_flags {
        for flag in &pkt.l4.tcp_flags {
            let f_str = match flag {
                TcpFlag::Syn => "syn",
                TcpFlag::Ack => "ack",
                TcpFlag::Fin => "fin",
                TcpFlag::Rst => "rst",
                TcpFlag::Psh => "psh",
                TcpFlag::Urg => "urg",
                TcpFlag::Ece => "ece",
                TcpFlag::Cwr => "cwr",
            };
            parts.push(String::from(f_str));
        }
    }

    // 2. Port elision via shadow `EndpointPairPorts`.
    let pair_key = (
        caller.name.to_ascii_lowercase(),
        callee.name.to_ascii_lowercase(),
    );
    let pair_ports = endpoint_ports.get(&pair_key);
    let (pred_src_port, pred_dst_port) = predict_wire_ports(
        protocol,
        &pkt.dissection.tokens,
        ep.dir,
        is_ipv6,
        pair_ports,
    );

    let effective_src_port = pkt.l4.src_port.unwrap_or(pred_src_port);
    let effective_dst_port = pkt.l4.dst_port.unwrap_or(pred_dst_port);

    if !existing.has_srcport
        && let Some(sp) = pkt.l4.src_port
        && sp != pred_src_port
    {
        parts.push(format!("srcport {sp}"));
    }
    if !existing.has_dstport
        && let Some(dp) = pkt.l4.dst_port
        && dp != pred_dst_port
    {
        parts.push(format!("dstport {dp}"));
    }

    // 3. TCP `seq`, `acknum`, `win`, `urgent`, and RFC 7323 TCP options.
    if is_stream_tcp {
        let ep1 = (src_ip, effective_src_port);
        let ep2 = (dst_ip, effective_dst_port);
        let (key, is_stream_forward) = if ep1 <= ep2 {
            ((ep1, ep2), true)
        } else {
            ((ep2, ep1), false)
        };
        let (expected_sender_seq, expected_receiver_seq) =
            if let Some(stream) = tcp_connections.get(&key) {
                if is_stream_forward {
                    (stream.seq1, stream.seq2)
                } else {
                    (stream.seq2, stream.seq1)
                }
            } else {
                (DEFAULT_TCP_ISN, DEFAULT_TCP_ISN)
            };

        if !existing.has_seq
            && let Some(actual_seq) = pkt.seq
            && actual_seq != expected_sender_seq
        {
            parts.push(format!("seq {actual_seq}"));
        }

        if !existing.has_acknum
            && let Some(actual_ack) = pkt.ack_num
        {
            let should_set_ack = pkt.l4.tcp_flags.contains(&TcpFlag::Ack)
                || (*protocol != Protocol::Tcp && pkt.l4.tcp_flags.is_empty());
            let expected_ack = if should_set_ack {
                expected_receiver_seq
            } else {
                0
            };
            if actual_ack != expected_ack {
                parts.push(format!("acknum {actual_ack}"));
            }
        }

        if !existing.has_win
            && let Some(w) = pkt.win
            && w != DEFAULT_TCP_WIN
        {
            parts.push(format!("win {w}"));
        }
        if !existing.has_urgent
            && let Some(u) = pkt.l4.urgent
            && u != 0
        {
            parts.push(format!("urgent {u}"));
        }
        if let Some(opts) = &pkt.l4.tcp_options {
            if !existing.has_mss
                && let Some(mss) = opts.mss
            {
                parts.push(format!("mss {mss}"));
            }
            if !existing.has_wscale
                && let Some(ws) = opts.wscale
            {
                parts.push(format!("wscale {ws}"));
            }
            if !existing.has_sack_perm && opts.sack_perm {
                parts.push(String::from("sack_perm"));
            }
            if !existing.has_tsval
                && let Some(tsv) = opts.tsval
            {
                parts.push(format!("tsval {tsv}"));
            }
            if !existing.has_tsecr
                && let Some(tse) = opts.tsecr
                && (tse != 0 || opts.tsval.is_none())
            {
                parts.push(format!("tsecr {tse}"));
            }
        }
    }

    // 4. L2 & L3 universal modifiers (`srcmac`, `dstmac`, `vlan`, `qinq`, `mpls`, `ttl`, `dscp`, `ecn`, `flowlabel`, `ipid`, `df`, `mf`, `fragoffset`).
    if !existing.has_srcmac
        && let Some(sm) = ep.emit_src_mac
    {
        parts.push(format!("srcmac {}", format_mac_lower(sm)));
    }
    if !existing.has_dstmac
        && let Some(dm) = ep.emit_dst_mac
    {
        parts.push(format!("dstmac {}", format_mac_lower(dm)));
    }

    if !matches!(protocol, Protocol::Vlan | Protocol::Qinq | Protocol::Mpls) {
        if !existing.has_vlan
            && let Some(v) = &pkt.l2.vlan
        {
            parts.push(format!("vlan {}", v.vid));
            if let Some(pcp) = v.pcp
                && pcp != 0
            {
                parts.push(format!("pcp {pcp}"));
            }
            if let Some(dei) = v.dei
                && dei != 0
            {
                parts.push(format!("dei {dei}"));
            }
        }
        if !existing.has_qinq
            && let Some(q) = &pkt.l2.qinq
        {
            parts.push(format!("qinq {}", q.outer_vid));
            if let Some(iv) = q.inner_vid {
                parts.push(format!("inner_vlan {iv}"));
            }
        }
        if !existing.has_mpls
            && let Some(m) = &pkt.l2.mpls
        {
            parts.push(format!("mpls {}", m.label));
            if let Some(exp) = m.exp
                && exp != 0
            {
                parts.push(format!("exp {exp}"));
            }
            if let Some(bos) = m.bos
                && bos != 1
            {
                parts.push(format!("bos {bos}"));
            }
            if let Some(ttl) = m.ttl
                && ttl != 64
            {
                parts.push(format!("mpls_ttl {ttl}"));
            }
        }
    } else if !pkt.has_ip_header
        && !existing.has_ethertype
        && pkt.inner_ethertype != 0x88B5
        && !(*protocol == Protocol::Mpls && matches!(pkt.inner_ethertype, 0x8847 | 0x8848))
    {
        parts.push(format!("ethertype 0x{:04x}", pkt.inner_ethertype));
    }

    if pkt.has_ip_header {
        let default_ttl = if matches!(protocol, Protocol::Ndp | Protocol::Vrrp)
            || (*protocol == Protocol::Arp && is_ipv6)
        {
            255
        } else {
            64
        };
        if !existing.has_ttl
            && let Some(ttl) = pkt.l3.ttl
            && ttl != default_ttl
        {
            parts.push(format!("ttl {ttl}"));
        }
        if !existing.has_dscp
            && let Some(dscp) = pkt.l3.dscp
            && dscp != 0
        {
            parts.push(format!("dscp {dscp}"));
        }
        if !existing.has_ecn
            && let Some(ecn) = pkt.l3.ecn
            && ecn != 0
        {
            parts.push(format!("ecn {ecn}"));
        }
        if is_ipv6
            && !existing.has_flowlabel
            && let Some(fl) = pkt.l3.flowlabel
            && fl != 0
        {
            parts.push(format!("flowlabel 0x{fl:x}"));
        }
        if !is_ipv6 {
            if !existing.has_ipid
                && let Some(ipid) = pkt.l3.ipid
                && ipid != 0x1234
            {
                parts.push(format!("ipid 0x{ipid:04x}"));
            }
            if !existing.has_df && pkt.l3.df {
                parts.push(String::from("df"));
            }
            if !existing.has_mf && pkt.l3.mf {
                parts.push(String::from("mf"));
            }
            if !existing.has_fragoffset
                && let Some(fo) = pkt.l3.frag_offset
                && fo != 0
            {
                parts.push(format!("fragoffset {fo}"));
            }
        }
    }

    // 5. Residual payload (`payload "..."` or `hexpayload "..."`).
    if !existing.has_payload && !pkt.dissection.residual_payload.is_empty() {
        let pmod = format_payload_modifier(&pkt.dissection.residual_payload);
        if !pmod.is_empty() {
            parts.push(pmod);
        }
    }

    // 6. Inter-packet wait modifier (`wait <u32><ns|us|ms|s|m>`).
    if let Some(w) = wait_opt {
        parts.push(w.to_string());
    }

    parts.join(" ")
}

/// Updates the shadow `EndpointPairPorts` and `TcpStreamState` tables after `verified_body` is
/// selected by the oracle, mirroring `execute_statement` in `src/backend/mod.rs`.
fn update_shadow_state_after_statement(
    pkt: &DissectedPacket,
    caller: &DiscoveredHost,
    callee: &DiscoveredHost,
    ep: &ResolvedFrameEndpoints,
    verified_body: &str,
    endpoint_ports: &mut HashMap<(String, String), ShadowEndpointPairPorts>,
    tcp_connections: &mut HashMap<Canonical4Tuple, ShadowTcpStreamState>,
) {
    let scanned = ExistingTokens::scan(verified_body);
    let first_tok = Token::lexer(verified_body).flatten().next();
    let effective_protocol = match first_tok {
        Some(Token::Tcp) => Protocol::Tcp,
        Some(Token::Udp) => Protocol::Udp,
        Some(Token::Vlan) => Protocol::Vlan,
        Some(Token::Qinq) => Protocol::Qinq,
        Some(Token::Mpls) => Protocol::Mpls,
        _ => pkt.dissection.protocol.clone(),
    };

    let (src_host, dst_host) = match ep.dir {
        Direction::LeftToRight => (caller, callee),
        Direction::RightToLeft => (callee, caller),
    };
    let src_ip = src_host
        .ip
        .or(pkt.src_ip)
        .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
    let dst_ip = dst_host
        .ip
        .or(pkt.dst_ip)
        .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
    let is_ipv6 = src_ip.is_ipv6();

    let pair_key = (
        caller.name.to_ascii_lowercase(),
        callee.name.to_ascii_lowercase(),
    );
    let is_raw_l4 = matches!(
        effective_protocol,
        Protocol::Tcp | Protocol::Udp | Protocol::Sctp
    );

    let (mut src_port, mut dst_port) = {
        let pair_ports = endpoint_ports.entry(pair_key.clone()).or_default();
        let can_inherit_callee = is_raw_l4
            || (pair_ports.callee_port_explicit
                && (pair_ports.last_protocol.as_ref() == Some(&effective_protocol)
                    || matches!(
                        pair_ports.last_protocol,
                        Some(Protocol::Tcp | Protocol::Udp | Protocol::Sctp)
                    )));
        let inherited_callee_port = if can_inherit_callee {
            pair_ports.callee_port
        } else {
            None
        };
        let default_dst = stage1_default_dst_port(&effective_protocol, verified_body);

        let explicit_sp = if scanned.has_srcport {
            pkt.l4.src_port
        } else {
            None
        };
        let explicit_dp = if scanned.has_dstport {
            pkt.l4.dst_port
        } else {
            None
        };

        match ep.dir {
            Direction::LeftToRight => {
                let s_port = explicit_sp
                    .or(pair_ports.caller_port)
                    .unwrap_or(DEFAULT_SRC_PORT);
                let d_port = explicit_dp.or(inherited_callee_port).unwrap_or(default_dst);
                if explicit_dp.is_some() {
                    pair_ports.callee_port_explicit = true;
                } else if !can_inherit_callee {
                    pair_ports.callee_port_explicit = false;
                }
                pair_ports.caller_port = Some(s_port);
                pair_ports.callee_port = Some(d_port);
                pair_ports.last_protocol = Some(effective_protocol.clone());
                (s_port, d_port)
            }
            Direction::RightToLeft => {
                let s_port = explicit_sp.or(inherited_callee_port).unwrap_or(default_dst);
                let d_port = explicit_dp
                    .or(pair_ports.caller_port)
                    .unwrap_or(DEFAULT_SRC_PORT);
                if explicit_sp.is_some() {
                    pair_ports.callee_port_explicit = true;
                } else if !can_inherit_callee {
                    pair_ports.callee_port_explicit = false;
                }
                pair_ports.callee_port = Some(s_port);
                pair_ports.caller_port = Some(d_port);
                pair_ports.last_protocol = Some(effective_protocol.clone());
                (s_port, d_port)
            }
        }
    };

    let (l7_sp, l7_dp) = l7_builder_port_overrides(&effective_protocol, verified_body, is_ipv6);
    if let Some(sp) = l7_sp
        && !scanned.has_srcport
    {
        src_port = sp;
    }
    if let Some(dp) = l7_dp {
        if effective_protocol == Protocol::Radius && ep.dir == Direction::RightToLeft {
            if !scanned.has_srcport {
                src_port = dp;
            }
        } else if !scanned.has_dstport {
            dst_port = dp;
        }
    }
    if (l7_sp.is_some() || l7_dp.is_some())
        && let Some(pair_ports) = endpoint_ports.get_mut(&pair_key)
    {
        match ep.dir {
            Direction::LeftToRight => {
                pair_ports.caller_port = Some(src_port);
                pair_ports.callee_port = Some(dst_port);
            }
            Direction::RightToLeft => {
                pair_ports.callee_port = Some(src_port);
                pair_ports.caller_port = Some(dst_port);
            }
        }
    }

    let transport_override = pkt.dissection.explicit_transport.or(pkt.l4.transport);
    if is_tcp_protocol(&effective_protocol, transport_override) {
        let ep1 = (src_ip, src_port);
        let ep2 = (dst_ip, dst_port);
        let (key, is_stream_forward) = if ep1 <= ep2 {
            ((ep1, ep2), true)
        } else {
            ((ep2, ep1), false)
        };
        let stream = tcp_connections.entry(key).or_insert(ShadowTcpStreamState {
            seq1: DEFAULT_TCP_ISN,
            seq2: DEFAULT_TCP_ISN,
        });
        let sender_seq = if is_stream_forward {
            &mut stream.seq1
        } else {
            &mut stream.seq2
        };

        let seq_val = if scanned.has_seq {
            let s = pkt.seq.unwrap_or(*sender_seq);
            *sender_seq = s;
            s
        } else {
            *sender_seq
        };

        let mut advance = pkt.l4_payload.len() as u32;
        if effective_protocol == Protocol::Tcp || scanned.has_tcp_flags {
            if pkt.l4.tcp_flags.contains(&TcpFlag::Syn) {
                advance += 1;
            }
            if pkt.l4.tcp_flags.contains(&TcpFlag::Fin) {
                advance += 1;
            }
        }
        *sender_seq = seq_val.wrapping_add(advance);
    }
}
