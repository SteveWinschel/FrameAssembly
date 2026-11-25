//! Shadow-state elision and canonical `.frasm` program emitter for the reverse decompiler.
//!
//! This module implements Stage 5 of the FrameAssembly reverse decompilation pipeline
//! ([`emit_fasm_program`]). It emits discovered `host<N>` declarations followed by a single
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

use super::oracle::{OracleCache, insert_before_wait, verify_with_oracle_cached};
use super::topology::{CaptureTopology, DiscoveredHost, ResolvedFrameEndpoints};
use super::{
    DissectedPacket, ReverseOutput, escape_fasm_string, format_mac_lower, format_payload_modifier,
};

/// Default inter-packet wait interval (`10ms` in nanoseconds) used by the forward compiler.
const DEFAULT_WAIT_NS: u64 = 10_000_000;

/// Default TCP initial sequence number (`1000`) used by the forward compiler.
const DEFAULT_TCP_ISN: u32 = 1000;

/// Default TCP window size (`64240`) used by the forward compiler.
const DEFAULT_TCP_WIN: u16 = 64240;

/// Default ephemeral source port (`12345`) used by the forward compiler.
const DEFAULT_SRC_PORT: u16 = 12345;

/// Transport-layer namespace isolating TCP, UDP, and SCTP shadow port inheritance state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum PortTransportClass {
    /// Connection-oriented TCP and L7-over-TCP protocols.
    Tcp,
    /// Datagram UDP and L3/L7-over-UDP protocols.
    Udp,
    /// Stream Control Transmission Protocol (`sctp`).
    Sctp,
}

/// Canonical shadow endpoint-pair port state mirroring `src/backend/mod.rs::EndpointPairPorts`.
#[derive(Debug, Clone, Default)]
struct ShadowEndpointPairPorts {
    /// Port bound to the lexicographically first host (`ep_a`, or initiator on loopback).
    port_a: Option<u16>,
    /// Port bound to the lexicographically second host (`ep_b`, or responder on loopback).
    port_b: Option<u16>,
    /// Whether `ep_b` (`true`) or `ep_a` (`false`) is the active server/responder endpoint.
    server_is_b: Option<bool>,
    /// Last protocol executed across this endpoint pair.
    last_protocol: Option<Protocol>,
    /// Whether the server port was explicitly overridden by `srcport` or `dstport`.
    server_port_explicit: bool,
}

/// Canonical key `(ep_a, ep_b, transport_class)` for transport-scoped port inheritance.
type PortPairKey = (String, String, PortTransportClass);

/// Shadow 4-tuple TCP sequence progression state mirroring `src/backend/mod.rs::TcpStreamState`.
#[derive(Debug, Clone)]
struct ShadowTcpStreamState {
    /// Next expected sequence number for endpoint 1.
    seq1: u32,
    /// Next expected sequence number for endpoint 2.
    seq2: u32,
    /// Whether endpoint 1 has already transmitted at least one segment on this stream.
    sent1: bool,
    /// Whether endpoint 2 has already transmitted at least one segment on this stream.
    sent2: bool,
    /// Whether `FIN` or `RST` teardown has been observed on this 4-tuple.
    closed: bool,
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
    /// Whether `sackperm` is already present.
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
    /// Whether `fcs` is already present.
    has_fcs: bool,
    /// Whether `badfcs` is already present.
    has_badfcs: bool,
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
    /// Whether `routeralert` is already present.
    has_routeralert: bool,
    /// Whether `payload` or `hexpayload` is already present.
    has_payload: bool,
}

impl ExistingTokens {
    /// Scans `tokens_str` with the FrameAssembly lexer to record already-emitted modifier keywords.
    fn scan(tokens_str: &str) -> Self {
        let mut out = Self::default();
        let mut seen_netflow_ipfix = false;
        let mut seen_tacacs = false;
        for tok in Token::lexer(tokens_str).flatten() {
            match tok {
                Token::Netflow | Token::Ipfix => seen_netflow_ipfix = true,
                Token::Tacacs => seen_tacacs = true,
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
                Token::SrcPort if !seen_netflow_ipfix => out.has_srcport = true,
                Token::DstPort if !seen_netflow_ipfix => out.has_dstport = true,
                Token::Seq if !seen_tacacs => out.has_seq = true,
                Token::AckNum => out.has_acknum = true,
                Token::Win => out.has_win = true,
                Token::Urgent => out.has_urgent = true,
                Token::SrcMac => out.has_srcmac = true,
                Token::DstMac => out.has_dstmac = true,
                Token::EtherType => out.has_ethertype = true,
                Token::Vlan => out.has_vlan = true,
                Token::Qinq => out.has_qinq = true,
                Token::Mpls => out.has_mpls = true,
                Token::Fcs => out.has_fcs = true,
                Token::BadFcs => out.has_badfcs = true,
                Token::Ttl => out.has_ttl = true,
                Token::Dscp => out.has_dscp = true,
                Token::Ecn => out.has_ecn = true,
                Token::FlowLabel => out.has_flowlabel = true,
                Token::IpId => out.has_ipid = true,
                Token::Df => out.has_df = true,
                Token::Mf => out.has_mf = true,
                Token::FragOffset => out.has_fragoffset = true,
                Token::RouterAlert => out.has_routeralert = true,
                Token::Payload | Token::HexPayload => out.has_payload = true,
                _ => {}
            }
        }
        out
    }
}

/// Emits a complete, canonical lowercase `.frasm` program from dissected packets, topology, and per-frame comments.
pub(crate) fn emit_fasm_program(
    packets: &[DissectedPacket],
    topo: &CaptureTopology,
    comments: &[Option<String>],
) -> ReverseOutput {
    if topo.hosts.is_empty() || packets.is_empty() {
        return ReverseOutput {
            fasm: String::from("compile {\n}\n"),
            packet_count: packets.len(),
            host_count: topo.hosts.len(),
            warnings: Vec::new(),
        };
    }

    let mut fasm = String::new();
    for host in &topo.hosts {
        let _ = writeln!(fasm, "{}", format_host_line(host));
    }
    fasm.push('\n');
    fasm.push_str("compile {\n");

    let mut endpoint_ports: HashMap<PortPairKey, ShadowEndpointPairPorts> = HashMap::new();
    let mut tcp_connections: HashMap<Canonical4Tuple, ShadowTcpStreamState> = HashMap::new();
    let mut oracle_cache = OracleCache::default();

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

        let wait_opt = if idx + 1 < packets.len() {
            let next_ts = packets[idx + 1].timestamp_ns;
            let delta_ns = next_ts.saturating_sub(pkt.timestamp_ns);
            quantize_wait_delta(delta_ns)
        } else {
            None
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

        let verified = verify_with_oracle_cached(
            pkt,
            caller,
            callee,
            &ep,
            &candidate_body,
            &mut oracle_cache,
        );

        update_shadow_state_after_statement(
            pkt,
            caller,
            callee,
            &ep,
            &verified.statement_body,
            &mut endpoint_ports,
            &mut tcp_connections,
        );

        let emitted_body = match comments
            .get(idx)
            .and_then(|c| c.as_deref())
            .filter(|s| !s.is_empty())
        {
            Some(comment_text) => {
                let comment_mod = format!("comment \"{}\"", escape_fasm_string(comment_text));
                insert_before_wait(&verified.statement_body, &comment_mod)
            }
            None => verified.statement_body,
        };

        let _ = writeln!(
            fasm,
            "    {} {} {} {}",
            caller.name, arrow, callee.name, emitted_body
        );
    }

    fasm.push_str("}\n");

    ReverseOutput {
        fasm,
        packet_count: packets.len(),
        host_count: topo.hosts.len(),
        warnings: Vec::new(),
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

/// Returns `true` when `tokens_str` selects an H.225.0 RAS operation (`grq`/`gcf`/`rrq`/`rcf`/`drq`/`dcf`).
fn is_h323_ras_tokens(tokens_str: &str) -> bool {
    Token::lexer(tokens_str).flatten().any(|t| {
        matches!(
            t,
            Token::Grq | Token::Gcf | Token::Rrq | Token::Rcf | Token::Drq | Token::Dcf
        )
    })
}

/// Returns `true` when `tokens_str` selects an RFC 9301 LISP Control-Plane operation (UDP `4342`).
fn is_lisp_control_tokens(tokens_str: &str) -> bool {
    let mut has_data = false;
    let mut has_ctrl = false;
    for t in Token::lexer(tokens_str).flatten() {
        if matches!(t, Token::Data) {
            has_data = true;
        } else if matches!(
            t,
            Token::MapRequest
                | Token::MapReply
                | Token::MapRegister
                | Token::MapNotify
                | Token::Ecm
        ) {
            has_ctrl = true;
        }
    }
    !has_data && has_ctrl
}

/// Returns `true` when `tokens_str` explicitly selects L2TPv3 (`v3` or `version 3`).
fn is_l2tp_v3_tokens(tokens_str: &str) -> bool {
    let mut saw_version = false;
    for t in Token::lexer(tokens_str).flatten() {
        if matches!(t, Token::V3) {
            return true;
        }
        if saw_version && matches!(t, Token::Number("3")) {
            return true;
        }
        saw_version = matches!(t, Token::Version);
    }
    false
}

/// Mirrors `src/backend/mod.rs::statement_uses_tcp` using reverse token metadata.
fn shadow_uses_tcp(
    protocol: &Protocol,
    tokens_str: &str,
    transport_override: Option<TransportProto>,
) -> bool {
    if *protocol == Protocol::H323 {
        if let Some(tr) = transport_override {
            return tr == TransportProto::Tcp;
        }
        return !is_h323_ras_tokens(tokens_str);
    }
    is_tcp_protocol(protocol, transport_override)
}

/// Returns the forward compiler's Stage 1 default destination port for `protocol` and `tokens`.
fn stage1_default_dst_port(protocol: &Protocol, tokens_str: &str) -> u16 {
    match protocol {
        Protocol::Tcp
        | Protocol::Udp
        | Protocol::Sctp
        | Protocol::Http
        | Protocol::Websocket
        | Protocol::Ntlm
        | Protocol::Doh => 80,
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
        Protocol::Ldp => 646,
        Protocol::Bmp => 1790,
        Protocol::Rpkirtr => 323,
        Protocol::L2tp => 1701,
        Protocol::Lisp => 4341,
        Protocol::Glbp => 3222,
        Protocol::Gtpu => 2152,
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
        Protocol::Stun | Protocol::Turn => 3478,
        Protocol::Sip => 5060,
        Protocol::Rtp => 5004,
        Protocol::Rtcp => 5005,
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
        Protocol::S7comm | Protocol::Mms | Protocol::S7commplus => 102,
        Protocol::Ethernetip => 44818,
        Protocol::Opcua => 4840,
        Protocol::Dcerpc => 135,
        Protocol::Rdp => 3389,
        Protocol::Llmnr => 5355,
        Protocol::Nbns => 137,
        Protocol::Socks => 1080,
        Protocol::Vnc => 5900,
        Protocol::Wsdiscovery => 3702,
        Protocol::Irc => 6667,
        Protocol::Iec104 => 2404,
        Protocol::Synchrophasor => 4712,
        Protocol::Hartip => 5094,
        Protocol::Fins => 9600,
        Protocol::Melsec => 5000,
        Protocol::Someip => 30490,
        Protocol::Doip => 13400,
        Protocol::C1222 => 1153,
        Protocol::Gesrtp => 18245,
        Protocol::Rocplus => 4000,
        Protocol::Bsap => 1234,
        Protocol::Knxnetip => 3671,
        Protocol::Rocev2 => 4791,
        Protocol::Ipmi => 623,
        Protocol::Twamp => 862,
        Protocol::Netconf => 830,
        Protocol::Gtpc => 2123,
        Protocol::Pfcp => 8805,
        Protocol::Diameter => 3868,
        Protocol::Ngap => 38412,
        Protocol::S1ap => 36412,
        Protocol::Mssql => 1433,
        Protocol::Kafka => 9092,
        Protocol::Mongodb => 27017,
        Protocol::Tns => 1521,
        Protocol::Iscsi => 3260,
        Protocol::Nvmetcp => 4420,
        Protocol::H323 => 1720,
        Protocol::Sccp => 2000,
        Protocol::Mgcp => 2427,
        _ => 0,
    }
}

/// Resolves the transport- and spec-adjusted server destination port matching
/// `resolve_and_record_ports` in `src/backend/mod.rs`.
fn effective_default_srv_port(
    protocol: &Protocol,
    tokens_str: &str,
    transport_override: Option<TransportProto>,
) -> u16 {
    let is_udp = transport_override == Some(TransportProto::Udp)
        || tokens_str.contains("transport udp");
    match (protocol, is_udp) {
        (Protocol::Profinet, true) => 34964,
        (Protocol::Ethercat, true) => 34980,
        (Protocol::L2tp, false) if is_l2tp_v3_tokens(tokens_str) => 0,
        (Protocol::H323, true) => 1719,
        (Protocol::H323, false) if is_h323_ras_tokens(tokens_str) => 1719,
        _ => stage1_default_dst_port(protocol, tokens_str),
    }
}

/// Returns optional `(src_port_override, dst_port_override)` produced by `build_l7_packet_payload`
/// in `src/backend/l7_dispatch.rs` or L3 builder overrides (`lisp`) in `src/backend/mod.rs`.
fn l7_builder_port_overrides(
    protocol: &Protocol,
    tokens_str: &str,
    dir: Direction,
    is_ipv6: bool,
    transport_override: Option<TransportProto>,
) -> (Option<u16>, Option<u16>) {
    match protocol {
        Protocol::Mdns => (None, Some(5353)),
        Protocol::Llmnr => (None, Some(5355)),
        Protocol::H323 => {
            let is_udp = transport_override == Some(TransportProto::Udp)
                || tokens_str.contains("transport udp");
            let dport = if is_udp || is_h323_ras_tokens(tokens_str) {
                1719
            } else {
                1720
            };
            (None, Some(dport))
        }
        Protocol::Lisp => {
            let dport = if is_lisp_control_tokens(tokens_str) {
                4342
            } else {
                4341
            };
            (None, Some(dport))
        }
        Protocol::Dhcp => {
            let is_server_reply = Token::lexer(tokens_str)
                .flatten()
                .any(|t| matches!(t, Token::Offer | Token::Ack | Token::Advertise | Token::Reply));
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
            let ptp_port = if is_general { 320 } else { 319 };
            if dir == Direction::RightToLeft {
                (Some(ptp_port), None)
            } else {
                (None, Some(ptp_port))
            }
        }
        Protocol::Radius => {
            let is_acct = Token::lexer(tokens_str)
                .flatten()
                .any(|t| matches!(t, Token::AccountingRequest | Token::AccountingResponse));
            (None, Some(if is_acct { 1813 } else { 1812 }))
        }
        Protocol::Ethernetip
            if transport_override == Some(TransportProto::Udp)
                || tokens_str.contains("transport udp") =>
        {
            (None, Some(2222))
        }
        _ => (None, None),
    }
}

/// Computes the transport-scoped [`PortPairKey`] and `src_is_b` flag matching `src/backend/mod.rs`.
fn canonical_port_key(
    protocol: &Protocol,
    tokens_str: &str,
    transport_override: Option<TransportProto>,
    src_name_lower: &str,
    dst_name_lower: &str,
    dir: Direction,
) -> (PortPairKey, bool) {
    let transport_class = if *protocol == Protocol::Sctp
        || transport_override == Some(TransportProto::Sctp)
        || matches!(protocol, Protocol::Ngap | Protocol::S1ap)
    {
        PortTransportClass::Sctp
    } else if shadow_uses_tcp(protocol, tokens_str, transport_override) {
        PortTransportClass::Tcp
    } else {
        PortTransportClass::Udp
    };
    let (ep_a, ep_b, src_is_b) = if src_name_lower == dst_name_lower {
        (
            src_name_lower.to_string(),
            dst_name_lower.to_string(),
            dir == Direction::RightToLeft,
        )
    } else if src_name_lower < dst_name_lower {
        (src_name_lower.to_string(), dst_name_lower.to_string(), false)
    } else {
        (dst_name_lower.to_string(), src_name_lower.to_string(), true)
    };
    ((ep_a, ep_b, transport_class), src_is_b)
}

/// Canonicalizes two `(IpAddr, u16)` socket endpoints into `(key, is_forward)`.
fn canonical_4tuple(src: (IpAddr, u16), dst: (IpAddr, u16)) -> (Canonical4Tuple, bool) {
    if src <= dst {
        ((src, dst), true)
    } else {
        ((dst, src), false)
    }
}

/// Rotates an ephemeral client `src_port` away from a torn-down (`FIN`/`RST`) TCP 4-tuple,
/// matching `src/backend/mod.rs`.
fn rotate_closed_client_port(
    src_ip: IpAddr,
    src_port: u16,
    dst_ip: IpAddr,
    dst_port: u16,
    tcp_connections: &HashMap<Canonical4Tuple, ShadowTcpStreamState>,
) -> u16 {
    let mut candidate = if (1024..65535).contains(&src_port) {
        src_port + 1
    } else {
        12346
    };
    for _ in 0..1024 {
        if candidate == dst_port {
            candidate = if candidate == 65535 {
                1024
            } else {
                candidate + 1
            };
            continue;
        }
        let cand_key = canonical_4tuple((src_ip, candidate), (dst_ip, dst_port)).0;
        if !tcp_connections.contains_key(&cand_key) {
            break;
        }
        candidate = if candidate == 65535 {
            1024
        } else {
            candidate + 1
        };
    }
    candidate
}

/// Endpoint and transport context used by `predict_wire_ports` to synthesize default wire ports.
#[derive(Debug, Clone, Copy)]
struct WirePortContext<'a> {
    /// Directional arrow (`->` or `<-`) of the emitted statement.
    dir: Direction,
    /// Whether the IP header uses IPv6 (`true`) or IPv4 (`false`).
    is_ipv6: bool,
    /// Explicit or observed L4 transport override (`tcp`, `udp`, or `sctp`).
    transport_override: Option<TransportProto>,
    /// Lowercased source host name used to detect loopback traffic.
    src_name_lower: &'a str,
    /// Lowercased destination host name used to detect loopback traffic.
    dst_name_lower: &'a str,
    /// Whether the source host corresponds to `ep_b` in the canonical pair key.
    src_is_b: bool,
    /// Previously recorded shadow port state for this endpoint pair, if any.
    pair_ports: Option<&'a ShadowEndpointPairPorts>,
}

/// Predicts the wire `(src_port, dst_port, src_is_server)` that `execute_statement` in
/// `src/backend/mod.rs` would synthesize if `srcport` and `dstport` were omitted on this statement.
fn predict_wire_ports(
    protocol: &Protocol,
    tokens_str: &str,
    ctx: &WirePortContext<'_>,
) -> (u16, u16, bool) {
    let default_srv_port =
        effective_default_srv_port(protocol, tokens_str, ctx.transport_override);
    if default_srv_port == 0 {
        return (DEFAULT_SRC_PORT, 0, false);
    }

    let is_raw_l4 = matches!(protocol, Protocol::Tcp | Protocol::Udp | Protocol::Sctp);
    let src_is_server = match ctx.dir {
        Direction::RightToLeft => true,
        Direction::LeftToRight => {
            ctx.src_name_lower != ctx.dst_name_lower
                && ctx.pair_ports.is_some_and(|pp| {
                    pp.server_is_b == Some(ctx.src_is_b)
                        && (is_raw_l4 || pp.last_protocol.as_ref() == Some(protocol))
                })
        }
    };
    let active_server_is_b = if src_is_server {
        ctx.src_is_b
    } else {
        !ctx.src_is_b
    };
    let effective_pp = ctx
        .pair_ports
        .filter(|pp| pp.server_is_b.is_none() || pp.server_is_b == Some(active_server_is_b));

    let (stored_client, stored_server) = match effective_pp {
        Some(pp) if active_server_is_b => (pp.port_a, pp.port_b),
        Some(pp) => (pp.port_b, pp.port_a),
        None => (None, None),
    };

    let can_inherit_server = is_raw_l4
        || effective_pp.is_some_and(|pp| {
            pp.server_port_explicit
                && (pp.last_protocol.as_ref() == Some(protocol)
                    || matches!(
                        pp.last_protocol,
                        Some(Protocol::Tcp | Protocol::Udp | Protocol::Sctp)
                    ))
        });
    let inherited_server = if can_inherit_server {
        stored_server
    } else {
        None
    };

    let (mut src_port, mut dst_port) = if src_is_server {
        (
            inherited_server.unwrap_or(default_srv_port),
            stored_client.unwrap_or(DEFAULT_SRC_PORT),
        )
    } else {
        (
            stored_client.unwrap_or(DEFAULT_SRC_PORT),
            inherited_server.unwrap_or(default_srv_port),
        )
    };

    let (l7_sp, l7_dp) = l7_builder_port_overrides(
        protocol,
        tokens_str,
        ctx.dir,
        ctx.is_ipv6,
        ctx.transport_override,
    );
    if matches!(
        protocol,
        Protocol::Radius
            | Protocol::Ethernetip
            | Protocol::H323
            | Protocol::Llmnr
            | Protocol::Lisp
    ) {
        if let Some(srv_port) = l7_sp.or(l7_dp) {
            if src_is_server {
                src_port = srv_port;
            } else {
                dst_port = srv_port;
            }
        }
    } else {
        if let Some(sp) = l7_sp {
            src_port = sp;
        }
        if let Some(dp) = l7_dp {
            dst_port = dp;
        }
    }

    // L3-over-UDP protocols in `src/backend/mod.rs` override `final_dport` (and `final_sport` for RIP/HSRP).
    match protocol {
        Protocol::Rip => {
            let dport = if ctx.is_ipv6 { 521 } else { 520 };
            src_port = dport;
            dst_port = dport;
        }
        Protocol::Hsrp => {
            let is_v2 = ctx.is_ipv6 || tokens_str.contains("version 2");
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

    (src_port, dst_port, src_is_server)
}

/// Builds the candidate statement body (everything after `<caller> ->|<- <callee> `) with
/// shadow-state field elision applied.
fn build_candidate_statement_body(
    pkt: &DissectedPacket,
    caller: &DiscoveredHost,
    callee: &DiscoveredHost,
    ep: &ResolvedFrameEndpoints,
    wait_opt: Option<&str>,
    endpoint_ports: &HashMap<PortPairKey, ShadowEndpointPairPorts>,
    tcp_connections: &HashMap<Canonical4Tuple, ShadowTcpStreamState>,
) -> String {
    let existing = ExistingTokens::scan(&pkt.dissection.tokens);
    let mut prefix_parts: Vec<String> = Vec::new();
    let mut parts: Vec<String> = Vec::new();
    parts.push(pkt.dissection.tokens.trim().to_string());

    let protocol = &pkt.dissection.protocol;
    let transport_override = pkt.dissection.explicit_transport.or(pkt.l4.transport);
    if !existing.has_transport
        && let Some(tp) = transport_override
        && !(matches!(protocol, Protocol::Ngap | Protocol::S1ap) && tp == TransportProto::Sctp)
    {
        match tp {
            TransportProto::Tcp => parts.push(String::from("transport tcp")),
            TransportProto::Udp => parts.push(String::from("transport udp")),
            TransportProto::Sctp => parts.push(String::from("transport sctp")),
        }
    }

    let (src_host, dst_host) = match ep.dir {
        Direction::LeftToRight => (caller, callee),
        Direction::RightToLeft => (callee, caller),
    };
    let src_name_lower = src_host.name.to_ascii_lowercase();
    let dst_name_lower = dst_host.name.to_ascii_lowercase();
    let src_ip = src_host
        .ip
        .or(pkt.src_ip)
        .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
    let dst_ip = if pkt.dst_ip.is_some_and(super::topology::is_unicast_ip) {
        dst_host.ip.or(pkt.dst_ip)
    } else {
        pkt.dst_ip.or(dst_host.ip)
    }
    .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
    let is_ipv6 = src_ip.is_ipv6();

    // 1. TCP flags, sequence/ack numbers, window, urgent pointer, and TCP options.
    let is_stream_tcp = shadow_uses_tcp(protocol, &pkt.dissection.tokens, transport_override);
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

    // 2. Port elision via transport-scoped shadow `EndpointPairPorts`.
    let (pair_key, src_is_b) = canonical_port_key(
        protocol,
        &pkt.dissection.tokens,
        transport_override,
        &src_name_lower,
        &dst_name_lower,
        ep.dir,
    );
    let pair_ports = endpoint_ports.get(&pair_key);
    let port_ctx = WirePortContext {
        dir: ep.dir,
        is_ipv6,
        transport_override,
        src_name_lower: &src_name_lower,
        dst_name_lower: &dst_name_lower,
        src_is_b,
        pair_ports,
    };
    let (mut pred_src_port, pred_dst_port, src_is_server) =
        predict_wire_ports(protocol, &pkt.dissection.tokens, &port_ctx);

    let is_fresh_syn = is_stream_tcp
        && pkt.l4.tcp_flags.contains(&TcpFlag::Syn)
        && !pkt.l4.tcp_flags.contains(&TcpFlag::Ack);
    let tentative_dst_port = pkt.l4.dst_port.unwrap_or(pred_dst_port);
    if is_fresh_syn && !src_is_server {
        let initial_key = canonical_4tuple((src_ip, pred_src_port), (dst_ip, tentative_dst_port)).0;
        if tcp_connections.get(&initial_key).is_some_and(|s| s.closed) {
            pred_src_port = rotate_closed_client_port(
                src_ip,
                pred_src_port,
                dst_ip,
                tentative_dst_port,
                tcp_connections,
            );
        }
    }

    let effective_src_port = pkt.l4.src_port.unwrap_or(pred_src_port);
    let effective_dst_port = pkt.l4.dst_port.unwrap_or(pred_dst_port);

    if !existing.has_srcport
        && let Some(sp) = pkt.l4.src_port
        && sp != pred_src_port
    {
        if matches!(protocol, Protocol::Netflow | Protocol::Ipfix) {
            prefix_parts.push(format!("srcport {sp}"));
        } else {
            parts.push(format!("srcport {sp}"));
        }
    }
    if !existing.has_dstport
        && let Some(dp) = pkt.l4.dst_port
        && dp != pred_dst_port
    {
        if matches!(protocol, Protocol::Netflow | Protocol::Ipfix) {
            prefix_parts.push(format!("dstport {dp}"));
        } else {
            parts.push(format!("dstport {dp}"));
        }
    }

    // 3. TCP `seq`, `acknum`, `win`, `urgent`, and RFC 7323 TCP options.
    if is_stream_tcp {
        let (key, is_stream_forward) =
            canonical_4tuple((src_ip, effective_src_port), (dst_ip, effective_dst_port));
        let (expected_sender_seq, expected_receiver_seq) =
            if let Some(stream) = tcp_connections.get(&key) {
                if is_fresh_syn && stream.closed {
                    (DEFAULT_TCP_ISN, DEFAULT_TCP_ISN)
                } else if is_stream_forward {
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
            if *protocol == Protocol::Tacacs {
                prefix_parts.push(format!("seq {actual_seq}"));
            } else {
                parts.push(format!("seq {actual_seq}"));
            }
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
                parts.push(String::from("sackperm"));
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

    // 4. L2 & L3 universal modifiers (`srcmac`, `dstmac`, `vlan`, `qinq`, `mpls`, `fcs`/`badfcs`, `ttl`, `dscp`, `ecn`, `flowlabel`, `ipid`, `df`, `mf`, `fragoffset`, `routeralert`).
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
            if let Some(iv) = q.inner_vid
                && iv != 1
            {
                parts.push(format!("innervlan {iv}"));
            }
            if let Some(pcp) = q.pcp
                && pcp != 0
            {
                parts.push(format!("pcp {pcp}"));
            }
            if let Some(dei) = q.dei
                && dei != 0
            {
                parts.push(format!("dei {dei}"));
            }
        }
        let mpls_entries: &[crate::ast::MplsSpec] = if !pkt.l2.mpls_stack.is_empty() {
            &pkt.l2.mpls_stack
        } else {
            pkt.l2.mpls.as_slice()
        };
        if !existing.has_mpls && !mpls_entries.is_empty() {
            let total = mpls_entries.len();
            for (idx, m) in mpls_entries.iter().enumerate() {
                parts.push(format!("mpls {}", m.label));
                if let Some(exp) = m.exp
                    && exp != 0
                {
                    parts.push(format!("exp {exp}"));
                }
                let default_bos = u8::from(idx + 1 == total);
                if let Some(bos) = m.bos
                    && bos != default_bos
                {
                    parts.push(format!("bos {bos}"));
                }
                if let Some(ttl) = m.ttl
                    && ttl != 64
                {
                    parts.push(format!("mplsttl {ttl}"));
                }
            }
        }
    } else if !pkt.has_ip_header
        && !existing.has_ethertype
        && pkt.inner_ethertype != 0x88B5
        && !(*protocol == Protocol::Mpls && matches!(pkt.inner_ethertype, 0x8847 | 0x8848))
    {
        parts.push(format!("ethertype 0x{:04x}", pkt.inner_ethertype));
    }

    if !existing.has_fcs && pkt.l2.fcs {
        parts.push(String::from("fcs"));
    }
    if !existing.has_badfcs && pkt.l2.bad_fcs {
        parts.push(String::from("badfcs"));
    }

    if pkt.has_ip_header {
        let default_ttl = if matches!(protocol, Protocol::Ndp | Protocol::Vrrp | Protocol::Bfd)
            || (*protocol == Protocol::Arp && is_ipv6)
            || (*protocol == Protocol::Rip && is_ipv6)
        {
            255
        } else if matches!(
            protocol,
            Protocol::Igmp
                | Protocol::Mld
                | Protocol::Ospf
                | Protocol::Pim
                | Protocol::Hsrp
                | Protocol::Glbp
                | Protocol::Llmnr
        ) || (*protocol == Protocol::Rip && !is_ipv6)
        {
            1
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
        if !existing.has_ipid
            && let Some(ipid) = pkt.l3.ipid
            && (is_ipv6 || ipid != 0)
        {
            parts.push(format!("ipid 0x{ipid:04x}"));
        }
        if !is_ipv6 && !existing.has_df && pkt.l3.df {
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
        if !existing.has_routeralert && pkt.l3.router_alert {
            parts.push(String::from("routeralert"));
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

    if prefix_parts.is_empty() {
        parts.join(" ")
    } else {
        prefix_parts.extend(parts);
        prefix_parts.join(" ")
    }
}

/// Updates the shadow `EndpointPairPorts` and `TcpStreamState` tables after `verified_body` is
/// selected by the oracle, mirroring `execute_statement` in `src/backend/mod.rs`.
fn update_shadow_state_after_statement(
    pkt: &DissectedPacket,
    caller: &DiscoveredHost,
    callee: &DiscoveredHost,
    ep: &ResolvedFrameEndpoints,
    verified_body: &str,
    endpoint_ports: &mut HashMap<PortPairKey, ShadowEndpointPairPorts>,
    tcp_connections: &mut HashMap<Canonical4Tuple, ShadowTcpStreamState>,
) {
    let scanned = ExistingTokens::scan(verified_body);
    let first_tok = Token::lexer(verified_body).flatten().next();
    let effective_protocol = match first_tok {
        Some(Token::Tcp) => Protocol::Tcp,
        Some(Token::Udp) => Protocol::Udp,
        Some(Token::Sctp) => Protocol::Sctp,
        Some(Token::Vlan) => Protocol::Vlan,
        Some(Token::Qinq) => Protocol::Qinq,
        Some(Token::Mpls) => Protocol::Mpls,
        _ => pkt.dissection.protocol.clone(),
    };

    let (src_host, dst_host) = match ep.dir {
        Direction::LeftToRight => (caller, callee),
        Direction::RightToLeft => (callee, caller),
    };
    let src_name_lower = src_host.name.to_ascii_lowercase();
    let dst_name_lower = dst_host.name.to_ascii_lowercase();
    let src_ip = src_host
        .ip
        .or(pkt.src_ip)
        .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
    let dst_ip = if pkt.dst_ip.is_some_and(super::topology::is_unicast_ip) {
        dst_host.ip.or(pkt.dst_ip)
    } else {
        pkt.dst_ip.or(dst_host.ip)
    }
    .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
    let is_ipv6 = src_ip.is_ipv6();

    let transport_override = pkt.dissection.explicit_transport.or(pkt.l4.transport);
    let default_srv_port =
        effective_default_srv_port(&effective_protocol, verified_body, transport_override);

    let (mut src_port, mut dst_port, port_slot) = if default_srv_port == 0 {
        let sp = if scanned.has_srcport {
            pkt.l4.src_port.unwrap_or(DEFAULT_SRC_PORT)
        } else {
            DEFAULT_SRC_PORT
        };
        let dp = if scanned.has_dstport {
            pkt.l4.dst_port.unwrap_or(0)
        } else {
            0
        };
        (sp, dp, None)
    } else {
        let is_raw_l4 = matches!(
            effective_protocol,
            Protocol::Tcp | Protocol::Udp | Protocol::Sctp
        );
        let (pair_key, src_is_b) = canonical_port_key(
            &effective_protocol,
            verified_body,
            transport_override,
            &src_name_lower,
            &dst_name_lower,
            ep.dir,
        );
        let pair_ports = endpoint_ports.entry(pair_key.clone()).or_default();

        let src_is_server = match ep.dir {
            Direction::RightToLeft => true,
            Direction::LeftToRight => {
                src_name_lower != dst_name_lower
                    && pair_ports.server_is_b == Some(src_is_b)
                    && (is_raw_l4 || pair_ports.last_protocol.as_ref() == Some(&effective_protocol))
            }
        };
        let active_server_is_b = if src_is_server { src_is_b } else { !src_is_b };
        if pair_ports.server_is_b.is_some() && pair_ports.server_is_b != Some(active_server_is_b) {
            *pair_ports = ShadowEndpointPairPorts::default();
        }
        pair_ports.server_is_b = Some(active_server_is_b);

        let (stored_client, stored_server) = if active_server_is_b {
            (pair_ports.port_a, pair_ports.port_b)
        } else {
            (pair_ports.port_b, pair_ports.port_a)
        };

        let can_inherit_server = is_raw_l4
            || (pair_ports.server_port_explicit
                && (pair_ports.last_protocol.as_ref() == Some(&effective_protocol)
                    || matches!(
                        pair_ports.last_protocol,
                        Some(Protocol::Tcp | Protocol::Udp | Protocol::Sctp)
                    )));
        let inherited_server = if can_inherit_server {
            stored_server
        } else {
            None
        };

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

        let (s_port, d_port) = if src_is_server {
            let sp = explicit_sp.or(inherited_server).unwrap_or(default_srv_port);
            let dp = explicit_dp.or(stored_client).unwrap_or(DEFAULT_SRC_PORT);
            if explicit_sp.is_some() {
                pair_ports.server_port_explicit = true;
            } else if !can_inherit_server {
                pair_ports.server_port_explicit = false;
            }
            (sp, dp)
        } else {
            let sp = explicit_sp.or(stored_client).unwrap_or(DEFAULT_SRC_PORT);
            let dp = explicit_dp.or(inherited_server).unwrap_or(default_srv_port);
            if explicit_dp.is_some() {
                pair_ports.server_port_explicit = true;
            } else if !can_inherit_server {
                pair_ports.server_port_explicit = false;
            }
            (sp, dp)
        };

        if src_is_b {
            pair_ports.port_b = Some(s_port);
            pair_ports.port_a = Some(d_port);
        } else {
            pair_ports.port_a = Some(s_port);
            pair_ports.port_b = Some(d_port);
        }
        pair_ports.last_protocol = Some(effective_protocol.clone());

        (s_port, d_port, Some((pair_key, src_is_b, src_is_server)))
    };

    let src_is_server = port_slot.as_ref().is_some_and(|(_, _, sis)| *sis);
    let (l7_sp, l7_dp) = l7_builder_port_overrides(
        &effective_protocol,
        verified_body,
        ep.dir,
        is_ipv6,
        transport_override,
    );
    if matches!(
        effective_protocol,
        Protocol::Radius
            | Protocol::Ethernetip
            | Protocol::H323
            | Protocol::Llmnr
            | Protocol::Lisp
    ) {
        if let Some(srv_port) = l7_sp.or(l7_dp) {
            if src_is_server {
                if !scanned.has_srcport {
                    src_port = srv_port;
                }
            } else if !scanned.has_dstport {
                dst_port = srv_port;
            }
        }
    } else {
        if let Some(sp) = l7_sp
            && !scanned.has_srcport
        {
            src_port = sp;
        }
        if let Some(dp) = l7_dp
            && !scanned.has_dstport
        {
            dst_port = dp;
        }
    }
    if (l7_sp.is_some() || l7_dp.is_some())
        && let Some((ref key, src_is_b, _)) = port_slot
        && let Some(pair_ports) = endpoint_ports.get_mut(key)
    {
        if src_is_b {
            pair_ports.port_b = Some(src_port);
            pair_ports.port_a = Some(dst_port);
        } else {
            pair_ports.port_a = Some(src_port);
            pair_ports.port_b = Some(dst_port);
        }
    }

    if shadow_uses_tcp(&effective_protocol, verified_body, transport_override) {
        let is_fresh_syn = pkt.l4.tcp_flags.contains(&TcpFlag::Syn)
            && !pkt.l4.tcp_flags.contains(&TcpFlag::Ack);
        let initial_key = canonical_4tuple((src_ip, src_port), (dst_ip, dst_port)).0;
        if is_fresh_syn && tcp_connections.get(&initial_key).is_some_and(|s| s.closed) {
            if !scanned.has_srcport && !src_is_server {
                src_port = rotate_closed_client_port(
                    src_ip,
                    src_port,
                    dst_ip,
                    dst_port,
                    tcp_connections,
                );
                if let Some((ref key, src_is_b, _)) = port_slot
                    && let Some(pair_ports) = endpoint_ports.get_mut(key)
                {
                    if src_is_b {
                        pair_ports.port_b = Some(src_port);
                    } else {
                        pair_ports.port_a = Some(src_port);
                    }
                }
            } else if let Some(existing) = tcp_connections.get_mut(&initial_key) {
                existing.seq1 = DEFAULT_TCP_ISN;
                existing.seq2 = DEFAULT_TCP_ISN;
                existing.sent1 = false;
                existing.sent2 = false;
                existing.closed = false;
            }
        }

        let (key, is_stream_forward) = canonical_4tuple((src_ip, src_port), (dst_ip, dst_port));
        let stream = tcp_connections.entry(key).or_insert(ShadowTcpStreamState {
            seq1: DEFAULT_TCP_ISN,
            seq2: DEFAULT_TCP_ISN,
            sent1: false,
            sent2: false,
            closed: false,
        });
        let (sender_seq, sender_sent) = if is_stream_forward {
            (&mut stream.seq1, &mut stream.sent1)
        } else {
            (&mut stream.seq2, &mut stream.sent2)
        };

        let seq_val = if scanned.has_seq {
            pkt.seq.unwrap_or(*sender_seq)
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
        let candidate_next = seq_val.wrapping_add(advance);
        if !*sender_sent {
            *sender_seq = candidate_next;
            *sender_sent = true;
        } else {
            *sender_seq = (*sender_seq).max(candidate_next);
        }
        if pkt.l4.tcp_flags.contains(&TcpFlag::Fin) || pkt.l4.tcp_flags.contains(&TcpFlag::Rst) {
            stream.closed = true;
        }
    }
}
