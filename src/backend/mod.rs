//! Deterministic backend evaluation and `.pcap` / `PCAPNG` wire packet emission engine.
//!
//! This module evaluates a validated [`Program`] AST, resolves host endpoints across flow
//! invocations and inline `compile` frame statements, maintains transport-scoped bidirectional
//! port inheritance and canonical 4-tuple TCP sequence/acknowledgment state machines, derives
//! RFC 1112 IPv4 and RFC 2464 IPv6 multicast MAC addresses alongside declaration-order unicast
//! defaults, and emits nanosecond-precision wire frames via [`compile_program`] and [`generate_pcap`].

use crate::ast::*;
use crate::error::CompilerError;
use crate::packet::build_wire_packet;
use crate::pcap::write_capture_file_with_metadata;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::net::IpAddr;
use std::collections::HashMap;

pub(crate) mod l7_dispatch;

use l7_dispatch::build_l7_packet_payload;

/// Maximum number of frames emitted by a single program (enforced across `repeat` and nested `flow` calls).
pub const MAX_EMITTED_FRAMES: usize = 100_000;

/// Safety depth cap guarding nested `flow` execution against programmatic AST cycles.
const MAX_FLOW_DEPTH: usize = 64;

/// Compiled wire Ethernet frame paired with nanosecond timestamp and optional PCAPNG packet comment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledFrame {
    /// Raw synthesized Ethernet II / IEEE 802.3 frame bytes.
    pub data: Vec<u8>,
    /// Capture timestamp in nanoseconds since the Unix epoch.
    pub timestamp_ns: u64,
    /// Optional per-packet comment propagated from `FrameStatement::comment`.
    pub comment: Option<String>,
}

/// Formats a [`CompilerError`] into a clean human-readable message without `Debug` enum wrappers.
fn err_msg(err: CompilerError) -> String {
    match err {
        CompilerError::BackendError(msg) => msg,
        other => alloc::format!("{}", other),
    }
}

/// Resolves a host definition for a given argument in a flow invocation from the environment.
///
/// # Examples
/// ```
/// use std::collections::HashMap;
/// use frameassembly::ast::{Argument, HostDef};
/// use frameassembly::backend::resolve_endpoint;
///
/// let mut env = HashMap::new();
/// env.insert("h1", HostDef { name: "h1", ip: None, mac: Some([0; 6]), span: (0, 2) });
/// assert!(resolve_endpoint(&Argument::Variable("h1"), &env).is_ok());
/// ```
///
/// # Errors
/// Returns a `String` error if the variable name is not defined in the environment.
pub fn resolve_endpoint<'a>(
    arg: &Argument<'a>,
    env: &HashMap<&'a str, HostDef<'a>>,
) -> Result<HostDef<'a>, String> {
    match arg {
        Argument::Variable(var_name) => {
            if let Some(val) = env.get(var_name) {
                Ok(val.clone())
            } else if let Some((_, val)) =
                env.iter().find(|(k, _)| k.eq_ignore_ascii_case(var_name))
            {
                Ok(val.clone())
            } else {
                Err(alloc::format!("Undefined variable: '{}'", var_name))
            }
        }
    }
}

/// Derives an Ethernet MAC address for an endpoint following RFC 2464, RFC 1112, or caller/callee defaults.
fn derive_mac(
    host_mac: Option<[u8; 6]>,
    stmt_mac: Option<[u8; 6]>,
    ip: Option<IpAddr>,
    is_caller: bool,
) -> [u8; 6] {
    let idx = usize::from(!is_caller);
    derive_host_mac(host_mac, stmt_mac, ip, idx)
}

/// Derives an Ethernet MAC address using statement override, host MAC, multicast RFCs, or 1-based host declaration index.
fn derive_host_mac(
    host_mac: Option<[u8; 6]>,
    stmt_mac: Option<[u8; 6]>,
    ip: Option<IpAddr>,
    host_index: usize,
) -> [u8; 6] {
    if let Some(mac) = stmt_mac {
        return mac;
    }
    if let Some(mac) = host_mac {
        return mac;
    }
    match ip {
        Some(IpAddr::V4(v4)) if v4.is_broadcast() => {
            return [0xFF; 6];
        }
        Some(IpAddr::V6(v6)) if v6.octets()[0] == 0xFF => {
            let octets = v6.octets();
            return [0x33, 0x33, octets[12], octets[13], octets[14], octets[15]];
        }
        Some(IpAddr::V4(v4)) if (224..=239).contains(&v4.octets()[0]) => {
            let octets = v4.octets();
            return [0x01, 0x00, 0x5E, octets[1] & 0x7F, octets[2], octets[3]];
        }
        _ => {}
    }
    let id = (host_index as u32).saturating_add(1).to_be_bytes();
    [0x00, 0x00, id[0], id[1], id[2], id[3]]
}

/// Returns the standard default destination port for a given protocol (`0` for non-L4-port protocols).
fn default_dst_port(protocol: &Protocol, pdu_type: Option<&SnmpPduType>) -> u16 {
    match protocol {
        Protocol::Tcp | Protocol::Udp | Protocol::Sctp => 80,
        Protocol::Snmp1 | Protocol::Snmp2 | Protocol::Snmp3 => {
            match pdu_type.unwrap_or(&SnmpPduType::Trap) {
                SnmpPduType::Trap | SnmpPduType::Inform | SnmpPduType::Report => 162,
                SnmpPduType::Get
                | SnmpPduType::GetNext
                | SnmpPduType::GetBulk
                | SnmpPduType::Set
                | SnmpPduType::Response => 161,
            }
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
        Protocol::Http | Protocol::Websocket | Protocol::Ntlm | Protocol::Doh => 80,
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
        Protocol::Arp
        | Protocol::Vlan
        | Protocol::Qinq
        | Protocol::Lldp
        | Protocol::Stp
        | Protocol::Lacp
        | Protocol::Eapol
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
        | Protocol::Ipsec
        | Protocol::Esp
        | Protocol::Ah
        | Protocol::Ospf
        | Protocol::Vrrp
        | Protocol::Pim
        | Protocol::Ipip
        | Protocol::Srv6
        | Protocol::Erspan
        | Protocol::Rsvp => 0,
    }
}

/// Transport-layer namespace isolating TCP, UDP, and SCTP port inheritance state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum PortTransportClass {
    /// Connection-oriented TCP and L7-over-TCP protocols.
    Tcp,
    /// Datagram UDP and L3/L7-over-UDP protocols.
    Udp,
    /// Stream Control Transmission Protocol (`sctp`).
    Sctp,
}

/// Canonical endpoint-pair port state tracked across `->`, `<-`, and reversed `s -> c` statements.
#[derive(Debug, Clone, Default)]
struct EndpointPairPorts {
    /// Port bound to the lexicographically first host (`ep_a`, or initiator on loopback).
    pub port_a: Option<u16>,
    /// Port bound to the lexicographically second host (`ep_b`, or responder on loopback).
    pub port_b: Option<u16>,
    /// Whether `ep_b` (`true`) or `ep_a` (`false`) is the active server/responder endpoint.
    pub server_is_b: Option<bool>,
    /// Last protocol that updated the server port.
    pub last_protocol: Option<Protocol>,
    /// Whether the server port was set via an explicit `srcport` or `dstport` modifier.
    pub server_port_explicit: bool,
}

/// Canonical key `(ep_a, ep_b, transport_class)` for transport-scoped port inheritance.
type PortPairKey = (String, String, PortTransportClass);

/// Canonical 4-tuple TCP stream state machine maintaining sequence progression and teardown state.
#[derive(Debug, Clone)]
struct TcpStreamState {
    /// Sequence number for transmissions from endpoint 1.
    pub seq1: u32,
    /// Sequence number for transmissions from endpoint 2.
    pub seq2: u32,
    /// Whether endpoint 1 has already transmitted at least one segment on this stream.
    pub sent1: bool,
    /// Whether endpoint 2 has already transmitted at least one segment on this stream.
    pub sent2: bool,
    /// Whether `FIN` or `RST` teardown has been observed on this 4-tuple.
    pub closed: bool,
}

/// Canonical SCTP association state tracking verification tag and monotonic TSN per direction.
#[derive(Debug, Clone)]
struct SctpAssocState {
    /// Active verification tag shared across the endpoint pair when omitted in statements.
    pub vtag: u32,
    /// Next TSN for transmissions from endpoint 1.
    pub tsn1: u32,
    /// Next TSN for transmissions from endpoint 2.
    pub tsn2: u32,
}

/// Canonical 4-tuple key representing two sorted socket endpoints.
type Canonical4Tuple = ((IpAddr, u16), (IpAddr, u16));

/// Canonical host-pair key ordering two endpoint names alphabetically.
type HostPairKey = (String, String);

/// Determines if the given protocol uses TCP transport based on protocol defaults and overrides.
pub(crate) fn is_tcp_protocol(protocol: &Protocol, transport: Option<TransportProto>) -> bool {
    if matches!(
        protocol,
        Protocol::Udp | Protocol::Sctp | Protocol::Mdns | Protocol::Ngap | Protocol::S1ap
    ) {
        return false;
    }
    if *protocol == Protocol::Tcp {
        return true;
    }
    if let Some(tr) = transport {
        return match tr {
            TransportProto::Tcp => true,
            TransportProto::Udp | TransportProto::Sctp => false,
        };
    }
    matches!(
        protocol,
        Protocol::Bgp
            | Protocol::Openflow
            | Protocol::Ldp
            | Protocol::Bmp
            | Protocol::Rpkirtr
            | Protocol::Tacacs
            | Protocol::Ftp
            | Protocol::Ssh
            | Protocol::Telnet
            | Protocol::Http
            | Protocol::Http2
            | Protocol::Grpc
            | Protocol::Websocket
            | Protocol::Tls
            | Protocol::Rtsp
            | Protocol::Smtp
            | Protocol::Imap
            | Protocol::Pop3
            | Protocol::Ldap
            | Protocol::Smb
            | Protocol::Redis
            | Protocol::Mysql
            | Protocol::Postgres
            | Protocol::Mqtt
            | Protocol::Amqp
            | Protocol::Whois
            | Protocol::S7comm
            | Protocol::Opcua
            | Protocol::Modbus
            | Protocol::Nfs
            | Protocol::Memcached
            | Protocol::Dnp3
            | Protocol::Ethernetip
            | Protocol::Dcerpc
            | Protocol::Ntlm
            | Protocol::Rdp
            | Protocol::Socks
            | Protocol::Vnc
            | Protocol::Doh
            | Protocol::Irc
            | Protocol::Iec104
            | Protocol::Mms
            | Protocol::S7commplus
            | Protocol::Gesrtp
            | Protocol::Netconf
            | Protocol::Diameter
            | Protocol::Mongodb
            | Protocol::Tns
            | Protocol::Iscsi
            | Protocol::Nvmetcp
            | Protocol::Sccp
            | Protocol::Synchrophasor
            | Protocol::Melsec
            | Protocol::Doip
            | Protocol::Rocplus
            | Protocol::H323
            | Protocol::Mssql
            | Protocol::Kafka
    )
}

/// Determines whether a parsed statement uses TCP transport, accounting for H.323 RAS vs H.225 signaling.
pub(crate) fn statement_uses_tcp(stmt: &FrameStatement<'_>) -> bool {
    if stmt.protocol == Protocol::H323 {
        if let Some(tr) = stmt.l4.transport {
            return tr == TransportProto::Tcp;
        }
        if let Some(ProtocolSpec::H323(spec)) = &stmt.protocol_spec {
            return !crate::builders::l7::is_h323_ras(spec, stmt.l4.transport);
        }
        return true;
    }
    is_tcp_protocol(&stmt.protocol, stmt.l4.transport)
}

/// Resolves `(src_port, dst_port)` and updates canonical transport-scoped [`EndpointPairPorts`].
fn resolve_and_record_ports(
    stmt: &FrameStatement<'_>,
    src_name_lower: &str,
    dst_name_lower: &str,
    endpoint_ports: &mut HashMap<PortPairKey, EndpointPairPorts>,
) -> (u16, u16, Option<(PortPairKey, bool, bool)>) {
    let default_srv_port = match (&stmt.protocol, stmt.l4.transport) {
        (Protocol::Profinet, Some(TransportProto::Udp)) => 34964,
        (Protocol::Ethercat, Some(TransportProto::Udp)) => 34980,
        (Protocol::L2tp, tr)
            if tr != Some(TransportProto::Udp)
                && matches!(
                    &stmt.protocol_spec,
                    Some(ProtocolSpec::L2tp(s)) if s.version == Some(3)
                ) =>
        {
            0
        }
        (Protocol::H323, tr)
            if matches!(
                &stmt.protocol_spec,
                Some(ProtocolSpec::H323(s)) if crate::builders::l7::is_h323_ras(s, tr)
            ) =>
        {
            1719
        }
        (Protocol::H323, Some(TransportProto::Udp)) => 1719,
        _ => default_dst_port(&stmt.protocol, stmt.pdu_type.as_ref()),
    };
    if default_srv_port == 0 {
        let sp = stmt.src_port.unwrap_or(12345);
        let dp = stmt.dst_port.unwrap_or(0);
        return (sp, dp, None);
    }

    let transport_class = if stmt.protocol == Protocol::Sctp
        || stmt.l4.transport == Some(TransportProto::Sctp)
        || matches!(stmt.protocol, Protocol::Ngap | Protocol::S1ap)
    {
        PortTransportClass::Sctp
    } else if statement_uses_tcp(stmt) {
        PortTransportClass::Tcp
    } else {
        PortTransportClass::Udp
    };

    let (ep_a, ep_b, src_is_b) = if src_name_lower == dst_name_lower {
        (
            src_name_lower.to_string(),
            dst_name_lower.to_string(),
            stmt.dir == Direction::RightToLeft,
        )
    } else if src_name_lower < dst_name_lower {
        (src_name_lower.to_string(), dst_name_lower.to_string(), false)
    } else {
        (dst_name_lower.to_string(), src_name_lower.to_string(), true)
    };
    let dst_is_b = !src_is_b;
    let pair_key = (ep_a, ep_b, transport_class);
    let is_raw_l4 = matches!(stmt.protocol, Protocol::Tcp | Protocol::Udp | Protocol::Sctp);

    let pair_ports = endpoint_ports.entry(pair_key.clone()).or_default();

    let src_is_server = match stmt.dir {
        Direction::RightToLeft => true,
        Direction::LeftToRight => {
            src_name_lower != dst_name_lower
                && pair_ports.server_is_b == Some(src_is_b)
                && (is_raw_l4 || pair_ports.last_protocol.as_ref() == Some(&stmt.protocol))
        }
    };
    let active_server_is_b = if src_is_server { src_is_b } else { dst_is_b };
    if pair_ports.server_is_b.is_some() && pair_ports.server_is_b != Some(active_server_is_b) {
        *pair_ports = EndpointPairPorts::default();
    }
    pair_ports.server_is_b = Some(active_server_is_b);

    let (stored_client, stored_server) = if active_server_is_b {
        (pair_ports.port_a, pair_ports.port_b)
    } else {
        (pair_ports.port_b, pair_ports.port_a)
    };

    let can_inherit_server = is_raw_l4
        || (pair_ports.server_port_explicit
            && (pair_ports.last_protocol.as_ref() == Some(&stmt.protocol)
                || matches!(
                    pair_ports.last_protocol,
                    Some(Protocol::Tcp | Protocol::Udp | Protocol::Sctp)
                )));
    let inherited_server = if can_inherit_server {
        stored_server
    } else {
        None
    };

    let (s_port, d_port) = if src_is_server {
        let sp = stmt.src_port.or(inherited_server).unwrap_or(default_srv_port);
        let dp = stmt.dst_port.or(stored_client).unwrap_or(12345);
        if stmt.src_port.is_some() {
            pair_ports.server_port_explicit = true;
        } else if !can_inherit_server {
            pair_ports.server_port_explicit = false;
        }
        (sp, dp)
    } else {
        let sp = stmt.src_port.or(stored_client).unwrap_or(12345);
        let dp = stmt.dst_port.or(inherited_server).unwrap_or(default_srv_port);
        if stmt.dst_port.is_some() {
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
    pair_ports.last_protocol = Some(stmt.protocol.clone());

    (s_port, d_port, Some((pair_key, src_is_b, src_is_server)))
}

/// Canonicalizes a socket 4-tuple `(ip1, port1) <-> (ip2, port2)` and returns `(key, forward)`.
fn canonical_4tuple(
    src: (IpAddr, u16),
    dst: (IpAddr, u16),
) -> (Canonical4Tuple, bool) {
    if src <= dst {
        ((src, dst), true)
    } else {
        ((dst, src), false)
    }
}

/// Synthesizes payload bytes for Layer 3 routing/control protocols carried over TCP/UDP/SCTP (`bgp`, `openflow`, `ldp`, `bmp`, `rpkirtr`).
fn build_l3_stream_payload(
    stmt: &FrameStatement<'_>,
    ctx: &crate::builders::WireContext<'_>,
    payload_bytes: &[u8],
) -> Option<(Vec<u8>, bool)> {
    let is_tcp = statement_uses_tcp(stmt);
    let body = match stmt.protocol {
        Protocol::Bgp => {
            let spec = match &stmt.protocol_spec {
                Some(ProtocolSpec::Bgp(s)) => s.clone(),
                _ => BgpSpec::default(),
            };
            crate::builders::l3_tunnel::build_bgp_payload(ctx, &spec, payload_bytes).0
        }
        Protocol::Openflow => {
            let spec = match &stmt.protocol_spec {
                Some(ProtocolSpec::Openflow(s)) => s.clone(),
                _ => OpenflowSpec::default(),
            };
            crate::builders::l3_tunnel::build_openflow_payload(&spec, payload_bytes).0
        }
        Protocol::Ldp => {
            let spec = match &stmt.protocol_spec {
                Some(ProtocolSpec::Ldp(s)) => s.clone(),
                _ => LdpSpec::default(),
            };
            crate::builders::l3_tunnel::build_ldp_payload(ctx, &spec, payload_bytes).0
        }
        Protocol::Bmp => {
            let spec = match &stmt.protocol_spec {
                Some(ProtocolSpec::Bmp(s)) => s.clone(),
                _ => BmpSpec::default(),
            };
            crate::builders::l3_tunnel::build_bmp_payload(ctx, &spec, payload_bytes).0
        }
        Protocol::Rpkirtr => {
            let spec = match &stmt.protocol_spec {
                Some(ProtocolSpec::Rpkirtr(s)) => s.clone(),
                _ => RpkirtrSpec::default(),
            };
            crate::builders::l3_tunnel::build_rpkirtr_payload(ctx, &spec, payload_bytes).0
        }
        _ => return None,
    };
    Some((body, is_tcp))
}

/// Synthesizes a single wire frame from a resolved [`FrameStatement`] and updates backend state.
#[allow(clippy::too_many_arguments)]
fn execute_statement(
    stmt: &FrameStatement<'_>,
    caller_ep: &HostDef<'_>,
    callee_ep: &HostDef<'_>,
    host_indices: &HashMap<String, usize>,
    current_time_ns: &mut u64,
    endpoint_ports: &mut HashMap<PortPairKey, EndpointPairPorts>,
    tcp_connections: &mut HashMap<Canonical4Tuple, TcpStreamState>,
    sctp_associations: &mut HashMap<HostPairKey, SctpAssocState>,
    packet_buffer: &mut Vec<CompiledFrame>,
) -> Result<(), String> {
    if packet_buffer.len() >= MAX_EMITTED_FRAMES {
        return Err(alloc::format!(
            "Program exceeds maximum emitted frame limit ({MAX_EMITTED_FRAMES})"
        ));
    }

    let (src_host, dst_host) = match stmt.dir {
        Direction::LeftToRight => (caller_ep, callee_ep),
        Direction::RightToLeft => (callee_ep, caller_ep),
    };

    let src_ip = src_host
        .ip
        .unwrap_or(IpAddr::V4(core::net::Ipv4Addr::UNSPECIFIED));
    let mut dst_ip = dst_host
        .ip
        .unwrap_or(IpAddr::V4(core::net::Ipv4Addr::UNSPECIFIED));

    let src_name_lower = src_host.name.to_ascii_lowercase();
    let dst_name_lower = dst_host.name.to_ascii_lowercase();
    let src_idx = host_indices.get(&src_name_lower).copied().unwrap_or(0);
    let dst_idx = host_indices.get(&dst_name_lower).copied().unwrap_or(1);

    let src_mac = derive_host_mac(src_host.mac, stmt.l2.src_mac, src_host.ip, src_idx);
    let mut dst_mac = derive_host_mac(dst_host.mac, stmt.l2.dst_mac, dst_host.ip, dst_idx);

    // Stage 1: Transport-scoped canonical endpoint-pair port inheritance
    let (mut src_port, mut dst_port, port_slot) =
        resolve_and_record_ports(stmt, &src_name_lower, &dst_name_lower, endpoint_ports);

    let payload_bytes = stmt.effective_payload().unwrap_or(&[]);

    let mut effective_l3 = stmt.l3.clone();
    if effective_l3.ttl.is_none() {
        if matches!(stmt.protocol, Protocol::Ndp | Protocol::Vrrp | Protocol::Bfd)
            || (stmt.protocol == Protocol::Arp && src_ip.is_ipv6())
            || (stmt.protocol == Protocol::Rip && src_ip.is_ipv6())
        {
            effective_l3.ttl = Some(255);
        } else if matches!(
            stmt.protocol,
            Protocol::Igmp
                | Protocol::Mld
                | Protocol::Ospf
                | Protocol::Pim
                | Protocol::Hsrp
                | Protocol::Glbp
                | Protocol::Llmnr
        ) || (stmt.protocol == Protocol::Rip && !src_ip.is_ipv6())
        {
            effective_l3.ttl = Some(1);
        }
    }

    let ctx = crate::builders::WireContext {
        src_ip,
        dst_ip,
        src_mac,
        dst_mac,
        transport: stmt.l4.transport,
        src_port,
        dst_port,
        seq: stmt.seq,
        ack: stmt.ack_num,
        l2: &stmt.l2,
        l3: &effective_l3,
        l4: &stmt.l4,
    };

    let src_is_server = port_slot.as_ref().is_some_and(|(_, _, sis)| *sis);
    let l7_res = build_l7_packet_payload(&ctx, stmt, payload_bytes);
    if let Some(res) = &l7_res {
        if matches!(
            stmt.protocol,
            Protocol::Radius | Protocol::Ethernetip | Protocol::H323 | Protocol::Llmnr
        ) {
            if let Some(srv_port) = res.src_port.or(res.dst_port) {
                if src_is_server {
                    if stmt.src_port.is_none() {
                        src_port = srv_port;
                    }
                } else if stmt.dst_port.is_none() {
                    dst_port = srv_port;
                }
            }
        } else {
            if let Some(sp) = res.src_port
                && stmt.src_port.is_none()
            {
                src_port = sp;
            }
            if let Some(dp) = res.dst_port
                && stmt.dst_port.is_none()
            {
                dst_port = dp;
            }
        }
        if let Some((ref key, src_is_b, _)) = port_slot
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
        if let Some(target_ip) = res.target_ip {
            let apply_target = stmt.protocol == Protocol::Mdns
                || dst_ip.is_unspecified()
                || dst_ip.is_multicast()
                || dst_ip == IpAddr::V4(core::net::Ipv4Addr::BROADCAST);
            if apply_target && dst_ip != target_ip {
                dst_ip = target_ip;
                dst_mac = derive_mac(None, stmt.l2.dst_mac, Some(target_ip), false);
            }
        }
    }

    // Stage 2: Canonical 4-Tuple TCP Sequence and Acknowledgment State Machine
    let mut final_seq = stmt.seq;
    let mut final_ack_num = stmt.ack_num;

    let is_stream_tcp = statement_uses_tcp(stmt);

    if is_stream_tcp {
        let is_fresh_syn =
            stmt.flags.contains(&TcpFlag::Syn) && !stmt.flags.contains(&TcpFlag::Ack);
        let initial_key = canonical_4tuple((src_ip, src_port), (dst_ip, dst_port)).0;
        if is_fresh_syn && tcp_connections.get(&initial_key).is_some_and(|s| s.closed) {
            if stmt.src_port.is_none() && !src_is_server {
                let mut candidate = if (1024..65535).contains(&src_port) {
                    src_port + 1
                } else {
                    12346
                };
                for _ in 0..1024 {
                    if candidate == dst_port {
                        candidate = if candidate == 65535 { 1024 } else { candidate + 1 };
                        continue;
                    }
                    let cand_key = canonical_4tuple((src_ip, candidate), (dst_ip, dst_port)).0;
                    if !tcp_connections.contains_key(&cand_key) {
                        break;
                    }
                    candidate = if candidate == 65535 { 1024 } else { candidate + 1 };
                }
                src_port = candidate;
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
                existing.seq1 = 1000;
                existing.seq2 = 1000;
                existing.sent1 = false;
                existing.sent2 = false;
                existing.closed = false;
            }
        }

        let (key, is_stream_forward) = canonical_4tuple((src_ip, src_port), (dst_ip, dst_port));

        let stream = tcp_connections.entry(key).or_insert(TcpStreamState {
            seq1: 1000,
            seq2: 1000,
            sent1: false,
            sent2: false,
            closed: false,
        });

        let (sender_seq, receiver_seq, sender_sent) = if is_stream_forward {
            (&mut stream.seq1, &mut stream.seq2, &mut stream.sent1)
        } else {
            (&mut stream.seq2, &mut stream.seq1, &mut stream.sent2)
        };

        let seq_val = stmt.seq.unwrap_or(*sender_seq);
        final_seq = Some(seq_val);

        let should_set_ack = stmt.flags.contains(&TcpFlag::Ack)
            || (stmt.protocol != Protocol::Tcp && stmt.flags.is_empty());
        if final_ack_num.is_none() && should_set_ack {
            final_ack_num = Some(*receiver_seq);
        }

        let payload_len = if let Some(res) = &l7_res {
            res.payload.len() as u32
        } else if let Some((l3_payload, _)) = build_l3_stream_payload(stmt, &ctx, payload_bytes) {
            l3_payload.len() as u32
        } else {
            payload_bytes.len() as u32
        };

        let mut advance = payload_len;
        if stmt.flags.contains(&TcpFlag::Syn) {
            advance += 1;
        }
        if stmt.flags.contains(&TcpFlag::Fin) {
            advance += 1;
        }
        let candidate_next = seq_val.wrapping_add(advance);
        if !*sender_sent {
            *sender_seq = candidate_next;
            *sender_sent = true;
        } else {
            *sender_seq = (*sender_seq).max(candidate_next);
        }
        if stmt.flags.contains(&TcpFlag::Fin) || stmt.flags.contains(&TcpFlag::Rst) {
            stream.closed = true;
        }
    }

    macro_rules! build_l2_spec {
        ($variant:ident, $builder:path) => {{
            match &stmt.protocol_spec {
                Some(ProtocolSpec::$variant(spec)) => {
                    $builder(&ctx, spec, payload_bytes).map_err(err_msg)?
                }
                _ => $builder(&ctx, &Default::default(), payload_bytes).map_err(err_msg)?,
            }
        }};
    }

    let emit_raw_ip = |body: &[u8], proto: u8| -> Result<Vec<u8>, String> {
        let ip_pkt = crate::packet::build_ip_packet(src_ip, dst_ip, proto, &effective_l3, body)
            .map_err(err_msg)?;
        Ok(crate::packet::build_ethernet_and_l2(
            src_mac,
            dst_mac,
            &stmt.l2,
            if src_ip.is_ipv4() { 0x0800 } else { 0x86DD },
            &ip_pkt,
        ))
    };

    let emit_udp = |target_ip: IpAddr,
                    target_mac: [u8; 6],
                    s_port: u16,
                    d_port: u16,
                    body: &[u8]|
     -> Result<Vec<u8>, String> {
        build_wire_packet(
            src_ip,
            target_ip,
            src_mac,
            target_mac,
            &stmt.l2,
            &effective_l3,
            &stmt.l4,
            false,
            s_port,
            d_port,
            &stmt.flags,
            final_seq,
            final_ack_num,
            stmt.win,
            stmt.urgent,
            Some(body),
        )
        .map_err(err_msg)
    };

    let packet_data: Vec<u8> = match stmt.protocol {
        // Layer 2 protocols
        Protocol::Arp => {
            let spec = match &stmt.protocol_spec {
                Some(ProtocolSpec::Arp(s)) => s.clone(),
                _ => ArpSpec::default(),
            };
            crate::builders::l2::build_arp_frame(&ctx, &spec, payload_bytes).map_err(err_msg)?
        }
        Protocol::Vlan => {
            let spec = match &stmt.protocol_spec {
                Some(ProtocolSpec::Vlan(s)) => s.clone(),
                _ => stmt.l2.vlan.clone().unwrap_or_default(),
            };
            crate::builders::l2::build_vlan_frame(&ctx, &spec, payload_bytes).map_err(err_msg)?
        }
        Protocol::Qinq => {
            let spec = match &stmt.protocol_spec {
                Some(ProtocolSpec::Qinq(s)) => s.clone(),
                _ => stmt.l2.qinq.clone().unwrap_or_default(),
            };
            crate::builders::l2::build_qinq_frame(&ctx, &spec, payload_bytes).map_err(err_msg)?
        }
        Protocol::Lldp => {
            let spec = match &stmt.protocol_spec {
                Some(ProtocolSpec::Lldp(s)) => s.clone(),
                _ => LldpSpec::default(),
            };
            crate::builders::l2::build_lldp_frame(&ctx, &spec, payload_bytes).map_err(err_msg)?
        }
        Protocol::Stp => {
            let spec = match &stmt.protocol_spec {
                Some(ProtocolSpec::Stp(s)) => s.clone(),
                _ => StpSpec::default(),
            };
            crate::builders::l2::build_stp_frame(&ctx, &spec, payload_bytes).map_err(err_msg)?
        }
        Protocol::Lacp => {
            let spec = match &stmt.protocol_spec {
                Some(ProtocolSpec::Lacp(s)) => s.clone(),
                _ => LacpSpec::default(),
            };
            crate::builders::l2::build_lacp_frame(&ctx, &spec, payload_bytes).map_err(err_msg)?
        }
        Protocol::Eapol => {
            let spec = match &stmt.protocol_spec {
                Some(ProtocolSpec::Eapol(s)) => s.clone(),
                _ => EapolSpec::default(),
            };
            crate::builders::l2::build_eapol_frame(&ctx, &spec, payload_bytes).map_err(err_msg)?
        }
        Protocol::Mpls => {
            let spec = match &stmt.protocol_spec {
                Some(ProtocolSpec::Mpls(s)) => s.clone(),
                _ => stmt.l2.mpls.clone().unwrap_or_default(),
            };
            crate::builders::l2::build_mpls_frame(&ctx, &spec, payload_bytes).map_err(err_msg)?
        }
        Protocol::Cdp => build_l2_spec!(Cdp, crate::builders::l2::build_cdp_frame),
        Protocol::Isis => build_l2_spec!(Isis, crate::builders::l2::build_isis_frame),
        Protocol::Macsec => build_l2_spec!(Macsec, crate::builders::l2::build_macsec_frame),
        Protocol::Pfc => build_l2_spec!(Pfc, crate::builders::l2::build_pfc_frame),
        Protocol::Pppoe => build_l2_spec!(Pppoe, crate::builders::l2::build_pppoe_frame),
        Protocol::Nsh => build_l2_spec!(Nsh, crate::builders::l2::build_nsh_frame),
        Protocol::Goose => build_l2_spec!(Goose, crate::builders::l2::build_goose_frame),
        Protocol::Sv => build_l2_spec!(Sv, crate::builders::l2::build_sv_frame),
        Protocol::Profinet => {
            let spec = match &stmt.protocol_spec {
                Some(ProtocolSpec::Profinet(s)) => s.clone(),
                _ => ProfinetSpec::default(),
            };
            if stmt.l4.transport == Some(TransportProto::Udp) {
                if src_host.ip.is_none() || dst_host.ip.is_none() {
                    return Err(String::from(
                        "PROFINET over UDP requires hosts with IP addresses",
                    ));
                }
                let pn_payload =
                    crate::builders::l2::build_profinet_payload(&ctx, &spec, payload_bytes);
                emit_udp(dst_ip, dst_mac, src_port, dst_port, &pn_payload)?
            } else {
                crate::builders::l2::build_profinet_frame(&ctx, &spec, payload_bytes)
                    .map_err(err_msg)?
            }
        }
        Protocol::Ethercat => {
            let spec = match &stmt.protocol_spec {
                Some(ProtocolSpec::Ethercat(s)) => s.clone(),
                _ => EthercatSpec::default(),
            };
            if stmt.l4.transport == Some(TransportProto::Udp) {
                if src_host.ip.is_none() || dst_host.ip.is_none() {
                    return Err(String::from(
                        "EtherCAT over UDP requires hosts with IP addresses",
                    ));
                }
                let ec_payload =
                    crate::builders::l2::build_ethercat_payload(&spec, payload_bytes)
                        .map_err(err_msg)?;
                emit_udp(dst_ip, dst_mac, src_port, dst_port, &ec_payload)?
            } else {
                crate::builders::l2::build_ethercat_frame(&ctx, &spec, payload_bytes)
                    .map_err(err_msg)?
            }
        }
        // Layer 3 / Tunnel / Routing / Security
        Protocol::Icmp => {
            let spec = match &stmt.protocol_spec {
                Some(ProtocolSpec::Icmp(s)) => s.clone(),
                _ => IcmpSpec::default(),
            };
            let (mut icmp_body, proto) =
                crate::builders::l3_tunnel::build_icmp_payload(&ctx, &spec, payload_bytes)
                    .map_err(err_msg)?;
            if stmt.l4.bad_checksum && icmp_body.len() >= 4 {
                icmp_body[3] ^= 0x01;
            }
            let ip_pkt =
                crate::packet::build_ip_packet(src_ip, dst_ip, proto, &effective_l3, &icmp_body)
                    .map_err(err_msg)?;
            crate::packet::build_ethernet_and_l2(
                src_mac,
                dst_mac,
                &stmt.l2,
                if src_ip.is_ipv4() { 0x0800 } else { 0x86DD },
                &ip_pkt,
            )
        }
        Protocol::Ndp => {
            let spec = match &stmt.protocol_spec {
                Some(ProtocolSpec::Ndp(s)) => s.clone(),
                _ => NdpSpec::default(),
            };
            let (ndp_body, target_ip, proto) =
                crate::builders::l3_tunnel::build_ndp_payload(&ctx, &spec, payload_bytes)
                    .map_err(err_msg)?;
            let effective_dst_mac = derive_mac(None, stmt.l2.dst_mac, Some(target_ip), false);
            let ip_pkt =
                crate::packet::build_ip_packet(src_ip, target_ip, proto, &effective_l3, &ndp_body)
                    .map_err(err_msg)?;
            crate::packet::build_ethernet_and_l2(src_mac, effective_dst_mac, &stmt.l2, 0x86DD, &ip_pkt)
        }
        Protocol::Igmp => {
            let spec = match &stmt.protocol_spec {
                Some(ProtocolSpec::Igmp(s)) => s.clone(),
                _ => IgmpSpec::default(),
            };
            let (igmp_body, target_ip, proto) =
                crate::builders::l3_tunnel::build_igmp_payload(&ctx, &spec, payload_bytes)
                    .map_err(err_msg)?;
            let effective_dst_mac = derive_mac(None, stmt.l2.dst_mac, Some(target_ip), false);
            let ip_pkt =
                crate::packet::build_ip_packet(src_ip, target_ip, proto, &effective_l3, &igmp_body)
                    .map_err(err_msg)?;
            crate::packet::build_ethernet_and_l2(src_mac, effective_dst_mac, &stmt.l2, 0x0800, &ip_pkt)
        }
        Protocol::Mld => {
            let spec = match &stmt.protocol_spec {
                Some(ProtocolSpec::Mld(s)) => s.clone(),
                _ => MldSpec::default(),
            };
            let (mld_body, target_ip, proto) =
                crate::builders::l3_tunnel::build_mld_payload(&ctx, &spec, payload_bytes)
                    .map_err(err_msg)?;
            let effective_dst_mac = derive_mac(None, stmt.l2.dst_mac, Some(target_ip), false);
            let ip_pkt =
                crate::packet::build_ip_packet(src_ip, target_ip, proto, &effective_l3, &mld_body)
                    .map_err(err_msg)?;
            crate::packet::build_ethernet_and_l2(src_mac, effective_dst_mac, &stmt.l2, 0x86DD, &ip_pkt)
        }
        Protocol::Gre => {
            let spec = match &stmt.protocol_spec {
                Some(ProtocolSpec::Gre(s)) => s.clone(),
                _ => GreSpec::default(),
            };
            let (gre_body, proto) =
                crate::builders::l3_tunnel::build_gre_payload(&ctx, &spec, payload_bytes);
            let ip_pkt =
                crate::packet::build_ip_packet(src_ip, dst_ip, proto, &effective_l3, &gre_body)
                    .map_err(err_msg)?;
            crate::packet::build_ethernet_and_l2(
                src_mac,
                dst_mac,
                &stmt.l2,
                if src_ip.is_ipv4() { 0x0800 } else { 0x86DD },
                &ip_pkt,
            )
        }
        Protocol::Vxlan => {
            let l4_payload = if effective_l3.frag_offset.unwrap_or(0) > 0 {
                payload_bytes.to_vec()
            } else {
                let spec = match &stmt.protocol_spec {
                    Some(ProtocolSpec::Vxlan(s)) => s.clone(),
                    _ => VxlanSpec::default(),
                };
                let (vxlan_payload, _) =
                    crate::builders::l3_tunnel::build_vxlan_payload(&spec, payload_bytes);
                crate::packet::build_udp_datagram_with_opts(
                    src_ip,
                    dst_ip,
                    src_port,
                    dst_port,
                    &vxlan_payload,
                    &stmt.l4,
                )
                .map_err(err_msg)?
            };
            let ip_pkt =
                crate::packet::build_ip_packet(src_ip, dst_ip, 17, &effective_l3, &l4_payload)
                    .map_err(err_msg)?;
            crate::packet::build_ethernet_and_l2(
                src_mac,
                dst_mac,
                &stmt.l2,
                if src_ip.is_ipv4() { 0x0800 } else { 0x86DD },
                &ip_pkt,
            )
        }
        Protocol::Geneve => {
            let l4_payload = if effective_l3.frag_offset.unwrap_or(0) > 0 {
                payload_bytes.to_vec()
            } else {
                let spec = match &stmt.protocol_spec {
                    Some(ProtocolSpec::Geneve(s)) => s.clone(),
                    _ => GeneveSpec::default(),
                };
                let (geneve_payload, _) =
                    crate::builders::l3_tunnel::build_geneve_payload(&spec, payload_bytes);
                crate::packet::build_udp_datagram_with_opts(
                    src_ip,
                    dst_ip,
                    src_port,
                    dst_port,
                    &geneve_payload,
                    &stmt.l4,
                )
                .map_err(err_msg)?
            };
            let ip_pkt =
                crate::packet::build_ip_packet(src_ip, dst_ip, 17, &effective_l3, &l4_payload)
                    .map_err(err_msg)?;
            crate::packet::build_ethernet_and_l2(
                src_mac,
                dst_mac,
                &stmt.l2,
                if src_ip.is_ipv4() { 0x0800 } else { 0x86DD },
                &ip_pkt,
            )
        }
        Protocol::Ipsec | Protocol::Esp => {
            let spec = match &stmt.protocol_spec {
                Some(ProtocolSpec::Ipsec(s)) | Some(ProtocolSpec::Esp(s)) => s.clone(),
                _ => IpsecSpec::default(),
            };
            let (esp_body, proto) =
                crate::builders::l3_tunnel::build_ipsec_esp_payload(&spec, payload_bytes);
            let ip_pkt =
                crate::packet::build_ip_packet(src_ip, dst_ip, proto, &effective_l3, &esp_body)
                    .map_err(err_msg)?;
            crate::packet::build_ethernet_and_l2(
                src_mac,
                dst_mac,
                &stmt.l2,
                if src_ip.is_ipv4() { 0x0800 } else { 0x86DD },
                &ip_pkt,
            )
        }
        Protocol::Ah => {
            let spec = match &stmt.protocol_spec {
                Some(ProtocolSpec::Ah(s)) => s.clone(),
                _ => AhSpec::default(),
            };
            let (ah_body, proto) =
                crate::builders::l3_tunnel::build_ipsec_ah_payload(&spec, payload_bytes);
            let ip_pkt =
                crate::packet::build_ip_packet(src_ip, dst_ip, proto, &effective_l3, &ah_body)
                    .map_err(err_msg)?;
            crate::packet::build_ethernet_and_l2(
                src_mac,
                dst_mac,
                &stmt.l2,
                if src_ip.is_ipv4() { 0x0800 } else { 0x86DD },
                &ip_pkt,
            )
        }
        Protocol::Ikev2 => {
            let l4_payload = if effective_l3.frag_offset.unwrap_or(0) > 0 {
                payload_bytes.to_vec()
            } else {
                let spec = match &stmt.protocol_spec {
                    Some(ProtocolSpec::Ikev2(s)) => s.clone(),
                    _ => Ikev2Spec::default(),
                };
                let (ike_payload, _) =
                    crate::builders::l3_tunnel::build_ikev2_payload(&spec, payload_bytes);
                crate::packet::build_udp_datagram_with_opts(
                    src_ip,
                    dst_ip,
                    src_port,
                    dst_port,
                    &ike_payload,
                    &stmt.l4,
                )
                .map_err(err_msg)?
            };
            let ip_pkt =
                crate::packet::build_ip_packet(src_ip, dst_ip, 17, &effective_l3, &l4_payload)
                    .map_err(err_msg)?;
            crate::packet::build_ethernet_and_l2(
                src_mac,
                dst_mac,
                &stmt.l2,
                if src_ip.is_ipv4() { 0x0800 } else { 0x86DD },
                &ip_pkt,
            )
        }
        Protocol::Wireguard => {
            let l4_payload = if effective_l3.frag_offset.unwrap_or(0) > 0 {
                payload_bytes.to_vec()
            } else {
                let spec = match &stmt.protocol_spec {
                    Some(ProtocolSpec::Wireguard(s)) => s.clone(),
                    _ => WireguardSpec::default(),
                };
                let (wg_payload, _) =
                    crate::builders::l3_tunnel::build_wireguard_payload(&spec, payload_bytes);
                crate::packet::build_udp_datagram_with_opts(
                    src_ip,
                    dst_ip,
                    src_port,
                    dst_port,
                    &wg_payload,
                    &stmt.l4,
                )
                .map_err(err_msg)?
            };
            let ip_pkt =
                crate::packet::build_ip_packet(src_ip, dst_ip, 17, &effective_l3, &l4_payload)
                    .map_err(err_msg)?;
            crate::packet::build_ethernet_and_l2(
                src_mac,
                dst_mac,
                &stmt.l2,
                if src_ip.is_ipv4() { 0x0800 } else { 0x86DD },
                &ip_pkt,
            )
        }
        Protocol::Ospf => {
            let spec = match &stmt.protocol_spec {
                Some(ProtocolSpec::Ospf(s)) => s.clone(),
                _ => OspfSpec::default(),
            };
            let (ospf_body, target_ip, proto) =
                crate::builders::l3_tunnel::build_ospf_payload(&ctx, &spec, payload_bytes);
            let effective_dst_ip = if dst_ip.is_unspecified() || dst_ip.is_multicast() {
                target_ip
            } else {
                dst_ip
            };
            let effective_dst_mac = if effective_dst_ip == dst_ip {
                dst_mac
            } else {
                derive_mac(None, stmt.l2.dst_mac, Some(effective_dst_ip), false)
            };
            let ip_pkt = crate::packet::build_ip_packet(
                src_ip,
                effective_dst_ip,
                proto,
                &effective_l3,
                &ospf_body,
            )
            .map_err(err_msg)?;
            crate::packet::build_ethernet_and_l2(
                src_mac,
                effective_dst_mac,
                &stmt.l2,
                if src_ip.is_ipv4() { 0x0800 } else { 0x86DD },
                &ip_pkt,
            )
        }
        Protocol::Rip => {
            let spec = match &stmt.protocol_spec {
                Some(ProtocolSpec::Rip(s)) => s.clone(),
                _ => RipSpec::default(),
            };
            let (rip_payload, target_ip, dport) =
                crate::builders::l3_tunnel::build_rip_payload(&ctx, &spec, payload_bytes);
            let effective_dst_ip = if dst_ip.is_unspecified() || dst_ip.is_multicast() {
                target_ip
            } else {
                dst_ip
            };
            let effective_dst_mac = if effective_dst_ip == dst_ip {
                dst_mac
            } else {
                derive_mac(None, stmt.l2.dst_mac, Some(effective_dst_ip), false)
            };
            let final_sport = stmt.src_port.unwrap_or(dport);
            let final_dport = stmt.dst_port.unwrap_or(dport);
            let l4_payload = if effective_l3.frag_offset.unwrap_or(0) > 0 {
                payload_bytes.to_vec()
            } else {
                crate::packet::build_udp_datagram_with_opts(
                    src_ip,
                    effective_dst_ip,
                    final_sport,
                    final_dport,
                    &rip_payload,
                    &stmt.l4,
                )
                .map_err(err_msg)?
            };
            let ip_pkt = crate::packet::build_ip_packet(
                src_ip,
                effective_dst_ip,
                17,
                &effective_l3,
                &l4_payload,
            )
            .map_err(err_msg)?;
            crate::packet::build_ethernet_and_l2(
                src_mac,
                effective_dst_mac,
                &stmt.l2,
                if src_ip.is_ipv4() { 0x0800 } else { 0x86DD },
                &ip_pkt,
            )
        }
        Protocol::Vrrp => {
            let spec = match &stmt.protocol_spec {
                Some(ProtocolSpec::Vrrp(s)) => s.clone(),
                _ => VrrpSpec::default(),
            };
            let (vrrp_body, target_ip, proto) =
                crate::builders::l3_tunnel::build_vrrp_payload(&ctx, &spec, payload_bytes);
            let effective_dst_mac = derive_mac(None, stmt.l2.dst_mac, Some(target_ip), false);
            let ip_pkt =
                crate::packet::build_ip_packet(src_ip, target_ip, proto, &effective_l3, &vrrp_body)
                    .map_err(err_msg)?;
            crate::packet::build_ethernet_and_l2(
                src_mac,
                effective_dst_mac,
                &stmt.l2,
                if src_ip.is_ipv4() { 0x0800 } else { 0x86DD },
                &ip_pkt,
            )
        }
        Protocol::Hsrp => {
            let spec = match &stmt.protocol_spec {
                Some(ProtocolSpec::Hsrp(s)) => s.clone(),
                _ => HsrpSpec::default(),
            };
            let (hsrp_payload, target_ip, dport) =
                crate::builders::l3_tunnel::build_hsrp_payload(&ctx, &spec, payload_bytes);
            let effective_dst_ip = if dst_ip.is_unspecified() || dst_ip.is_multicast() {
                target_ip
            } else {
                dst_ip
            };
            let effective_dst_mac = if effective_dst_ip == dst_ip {
                dst_mac
            } else {
                derive_mac(None, stmt.l2.dst_mac, Some(effective_dst_ip), false)
            };
            let final_sport = stmt.src_port.unwrap_or(dport);
            let final_dport = stmt.dst_port.unwrap_or(dport);
            let l4_payload = if effective_l3.frag_offset.unwrap_or(0) > 0 {
                payload_bytes.to_vec()
            } else {
                crate::packet::build_udp_datagram_with_opts(
                    src_ip,
                    effective_dst_ip,
                    final_sport,
                    final_dport,
                    &hsrp_payload,
                    &stmt.l4,
                )
                .map_err(err_msg)?
            };
            let ip_pkt = crate::packet::build_ip_packet(
                src_ip,
                effective_dst_ip,
                17,
                &effective_l3,
                &l4_payload,
            )
            .map_err(err_msg)?;
            crate::packet::build_ethernet_and_l2(
                src_mac,
                effective_dst_mac,
                &stmt.l2,
                if src_ip.is_ipv4() { 0x0800 } else { 0x86DD },
                &ip_pkt,
            )
        }
        Protocol::Pim => {
            let spec = match &stmt.protocol_spec {
                Some(ProtocolSpec::Pim(s)) => s.clone(),
                _ => PimSpec::default(),
            };
            let (pim_body, target_ip, proto) =
                crate::builders::l3_tunnel::build_pim_payload(&ctx, &spec, payload_bytes);
            let is_mcast = match target_ip {
                IpAddr::V4(v4) => v4.is_multicast(),
                IpAddr::V6(v6) => v6.is_multicast(),
            };
            let effective_dst_mac = if is_mcast {
                derive_mac(None, stmt.l2.dst_mac, Some(target_ip), false)
            } else {
                dst_mac
            };
            let ip_pkt =
                crate::packet::build_ip_packet(src_ip, target_ip, proto, &effective_l3, &pim_body)
                    .map_err(err_msg)?;
            crate::packet::build_ethernet_and_l2(
                src_mac,
                effective_dst_mac,
                &stmt.l2,
                if src_ip.is_ipv4() { 0x0800 } else { 0x86DD },
                &ip_pkt,
            )
        }
        Protocol::Bfd => {
            let l4_payload = if effective_l3.frag_offset.unwrap_or(0) > 0 {
                payload_bytes.to_vec()
            } else {
                let spec = match &stmt.protocol_spec {
                    Some(ProtocolSpec::Bfd(s)) => s.clone(),
                    _ => BfdSpec::default(),
                };
                let (bfd_payload, _) =
                    crate::builders::l3_tunnel::build_bfd_payload(&spec, payload_bytes);
                crate::packet::build_udp_datagram_with_opts(
                    src_ip,
                    dst_ip,
                    src_port,
                    dst_port,
                    &bfd_payload,
                    &stmt.l4,
                )
                .map_err(err_msg)?
            };
            let ip_pkt =
                crate::packet::build_ip_packet(src_ip, dst_ip, 17, &effective_l3, &l4_payload)
                    .map_err(err_msg)?;
            crate::packet::build_ethernet_and_l2(
                src_mac,
                dst_mac,
                &stmt.l2,
                if src_ip.is_ipv4() { 0x0800 } else { 0x86DD },
                &ip_pkt,
            )
        }
        Protocol::Ipip => {
            let (body, proto) = match &stmt.protocol_spec {
                Some(ProtocolSpec::Ipip(spec)) => {
                    crate::builders::l3_tunnel::build_ipip_payload(&ctx, spec, payload_bytes)
                }
                _ => crate::builders::l3_tunnel::build_ipip_payload(
                    &ctx,
                    &Default::default(),
                    payload_bytes,
                ),
            };
            emit_raw_ip(&body, proto)?
        }
        Protocol::Srv6 => {
            let (body, proto) = match &stmt.protocol_spec {
                Some(ProtocolSpec::Srv6(spec)) => {
                    crate::builders::l3_tunnel::build_srv6_payload(&ctx, spec, payload_bytes)
                }
                _ => crate::builders::l3_tunnel::build_srv6_payload(
                    &ctx,
                    &Default::default(),
                    payload_bytes,
                ),
            }
            .map_err(err_msg)?;
            emit_raw_ip(&body, proto)?
        }
        Protocol::Erspan => {
            let (body, proto) = match &stmt.protocol_spec {
                Some(ProtocolSpec::Erspan(spec)) => {
                    crate::builders::l3_tunnel::build_erspan_payload(&ctx, spec, payload_bytes)
                }
                _ => crate::builders::l3_tunnel::build_erspan_payload(
                    &ctx,
                    &Default::default(),
                    payload_bytes,
                ),
            };
            emit_raw_ip(&body, proto)?
        }
        Protocol::Rsvp => {
            let (body, proto) = match &stmt.protocol_spec {
                Some(ProtocolSpec::Rsvp(spec)) => {
                    crate::builders::l3_tunnel::build_rsvp_payload(&ctx, spec, payload_bytes)
                }
                _ => crate::builders::l3_tunnel::build_rsvp_payload(
                    &ctx,
                    &Default::default(),
                    payload_bytes,
                ),
            };
            emit_raw_ip(&body, proto)?
        }
        Protocol::L2tp => {
            let (body, use_ip_115, _dport) = match &stmt.protocol_spec {
                Some(ProtocolSpec::L2tp(spec)) => {
                    crate::builders::l3_tunnel::build_l2tp_payload(&ctx, spec, payload_bytes)
                }
                _ => crate::builders::l3_tunnel::build_l2tp_payload(
                    &ctx,
                    &Default::default(),
                    payload_bytes,
                ),
            };
            if use_ip_115 {
                emit_raw_ip(&body, 115)?
            } else {
                emit_udp(dst_ip, dst_mac, src_port, dst_port, &body)?
            }
        }
        Protocol::Lisp => {
            let (body, dport) = match &stmt.protocol_spec {
                Some(ProtocolSpec::Lisp(spec)) => {
                    crate::builders::l3_tunnel::build_lisp_payload(&ctx, spec, payload_bytes)
                }
                _ => crate::builders::l3_tunnel::build_lisp_payload(
                    &ctx,
                    &Default::default(),
                    payload_bytes,
                ),
            };
            if src_is_server {
                if stmt.src_port.is_none() {
                    src_port = dport;
                }
            } else if stmt.dst_port.is_none() {
                dst_port = dport;
            }
            if let Some((ref key, src_is_b, _)) = port_slot
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
            emit_udp(dst_ip, dst_mac, src_port, dst_port, &body)?
        }
        Protocol::Glbp => {
            let (body, target_ip, _dport) = match &stmt.protocol_spec {
                Some(ProtocolSpec::Glbp(spec)) => {
                    crate::builders::l3_tunnel::build_glbp_payload(&ctx, spec, payload_bytes)
                }
                _ => crate::builders::l3_tunnel::build_glbp_payload(
                    &ctx,
                    &Default::default(),
                    payload_bytes,
                ),
            };
            let effective_dst_ip = if dst_ip.is_unspecified() || dst_ip.is_multicast() {
                target_ip
            } else {
                dst_ip
            };
            let effective_dst_mac = if effective_dst_ip == dst_ip {
                dst_mac
            } else {
                derive_mac(None, stmt.l2.dst_mac, Some(effective_dst_ip), false)
            };
            emit_udp(effective_dst_ip, effective_dst_mac, src_port, dst_port, &body)?
        }
        Protocol::Gtpu => {
            let (body, _dport) = match &stmt.protocol_spec {
                Some(ProtocolSpec::Gtpu(spec)) => {
                    crate::builders::l3_tunnel::build_gtpu_payload(&ctx, spec, payload_bytes)
                }
                _ => crate::builders::l3_tunnel::build_gtpu_payload(
                    &ctx,
                    &Default::default(),
                    payload_bytes,
                ),
            };
            emit_udp(dst_ip, dst_mac, src_port, dst_port, &body)?
        }
        // Layer 4 Transports
        Protocol::Sctp => {
            let l4_payload = if effective_l3.frag_offset.unwrap_or(0) > 0 {
                payload_bytes.to_vec()
            } else {
                let ctx_ports = crate::builders::WireContext {
                    src_port,
                    dst_port,
                    ..ctx
                };
                let spec = match &stmt.protocol_spec {
                    Some(ProtocolSpec::Sctp(s)) => s.clone(),
                    _ => stmt.l4.sctp_params.clone().unwrap_or_default(),
                };
                let (sctp_pkt, _proto) =
                    crate::builders::transport::build_sctp_payload(&ctx_ports, &spec, payload_bytes)
                        .map_err(err_msg)?;
                sctp_pkt
            };
            let ip_pkt =
                crate::packet::build_ip_packet(src_ip, dst_ip, 132, &effective_l3, &l4_payload)
                    .map_err(err_msg)?;
            crate::packet::build_ethernet_and_l2(
                src_mac,
                dst_mac,
                &stmt.l2,
                if src_ip.is_ipv4() { 0x0800 } else { 0x86DD },
                &ip_pkt,
            )
        }
        // TCP / UDP / Application protocols over TCP/UDP
        Protocol::Tcp
        | Protocol::Udp
        | Protocol::Bgp
        | Protocol::Openflow
        | Protocol::Ldp
        | Protocol::Bmp
        | Protocol::Rpkirtr
        | Protocol::Snmp1
        | Protocol::Snmp2
        | Protocol::Snmp3
        | Protocol::Dns
        | Protocol::Mdns
        | Protocol::Dhcp
        | Protocol::Ntp
        | Protocol::Ptp
        | Protocol::Radius
        | Protocol::Tacacs
        | Protocol::Syslog
        | Protocol::Netflow
        | Protocol::Ipfix
        | Protocol::Sflow
        | Protocol::Tftp
        | Protocol::Ftp
        | Protocol::Ssh
        | Protocol::Telnet
        | Protocol::Http
        | Protocol::Http2
        | Protocol::Grpc
        | Protocol::Websocket
        | Protocol::Tls
        | Protocol::Quic
        | Protocol::Stun
        | Protocol::Sip
        | Protocol::Rtp
        | Protocol::Rtsp
        | Protocol::Smtp
        | Protocol::Imap
        | Protocol::Pop3
        | Protocol::Kerberos
        | Protocol::Ldap
        | Protocol::Smb
        | Protocol::Nfs
        | Protocol::Redis
        | Protocol::Memcached
        | Protocol::Mysql
        | Protocol::Postgres
        | Protocol::Mqtt
        | Protocol::Coap
        | Protocol::Amqp
        | Protocol::Ssdp
        | Protocol::Whois
        | Protocol::Modbus
        | Protocol::Bacnet
        | Protocol::Dnp3
        | Protocol::S7comm
        | Protocol::Ethernetip
        | Protocol::Opcua
        | Protocol::Dcerpc
        | Protocol::Ntlm
        | Protocol::Rdp
        | Protocol::Llmnr
        | Protocol::Nbns
        | Protocol::Socks
        | Protocol::Vnc
        | Protocol::Doh
        | Protocol::Wsdiscovery
        | Protocol::Irc
        | Protocol::Iec104
        | Protocol::Mms
        | Protocol::S7commplus
        | Protocol::Synchrophasor
        | Protocol::Hartip
        | Protocol::Fins
        | Protocol::Melsec
        | Protocol::Someip
        | Protocol::Doip
        | Protocol::C1222
        | Protocol::Gesrtp
        | Protocol::Rocplus
        | Protocol::Bsap
        | Protocol::Knxnetip
        | Protocol::Rocev2
        | Protocol::Ipmi
        | Protocol::Twamp
        | Protocol::Netconf
        | Protocol::Gtpc
        | Protocol::Pfcp
        | Protocol::Diameter
        | Protocol::Ngap
        | Protocol::S1ap
        | Protocol::Mssql
        | Protocol::Kafka
        | Protocol::Mongodb
        | Protocol::Tns
        | Protocol::Iscsi
        | Protocol::Nvmetcp
        | Protocol::Rtcp
        | Protocol::Turn
        | Protocol::H323
        | Protocol::Sccp
        | Protocol::Mgcp => {
            let (effective_dst_ip, effective_dst_mac) = (dst_ip, dst_mac);

            let (actual_payload, is_tcp) = if let Some(res) = l7_res {
                (res.payload, res.is_tcp)
            } else if let Some(l3_res) = build_l3_stream_payload(stmt, &ctx, payload_bytes) {
                l3_res
            } else {
                match stmt.protocol {
                    Protocol::Tcp => (payload_bytes.to_vec(), true),
                    Protocol::Udp => (payload_bytes.to_vec(), false),
                    Protocol::Snmp1 => {
                        (crate::builders::snmp::build_snmp1_payload(stmt, src_ip)?, false)
                    }
                    Protocol::Snmp2 => (crate::builders::snmp::build_snmp2_payload(stmt)?, false),
                    Protocol::Snmp3 => (crate::builders::snmp::build_snmp3_payload(stmt)?, false),
                    _ => unreachable!(),
                }
            };

            if !matches!(stmt.protocol, Protocol::Tcp | Protocol::Udp)
                && (stmt.l4.transport == Some(TransportProto::Sctp)
                    || matches!(stmt.protocol, Protocol::Ngap | Protocol::S1ap))
            {
                let (assoc_key, is_assoc_forward) = if src_name_lower <= dst_name_lower {
                    ((src_name_lower.clone(), dst_name_lower.clone()), true)
                } else {
                    ((dst_name_lower.clone(), src_name_lower.clone()), false)
                };
                let assoc = sctp_associations.entry(assoc_key).or_insert(SctpAssocState {
                    vtag: 0x1234_5678,
                    tsn1: 1000,
                    tsn2: 1000,
                });
                let sctp_p = stmt.l4.sctp_params.as_ref();
                let vtag = if let Some(v) = sctp_p.and_then(|p| p.vtag) {
                    assoc.vtag = v;
                    v
                } else {
                    assoc.vtag
                };
                let sender_tsn = if is_assoc_forward {
                    &mut assoc.tsn1
                } else {
                    &mut assoc.tsn2
                };
                let tsn = if let Some(t) = stmt.seq {
                    *sender_tsn = (*sender_tsn).max(t.wrapping_add(1));
                    t
                } else {
                    let t = *sender_tsn;
                    *sender_tsn = t.wrapping_add(1);
                    t
                };
                let stream = sctp_p.and_then(|p| p.stream).unwrap_or(0);
                let ssn = sctp_p.and_then(|p| p.ssn).unwrap_or(0);
                let default_ppid = match stmt.protocol {
                    Protocol::Ngap => 60,
                    Protocol::S1ap => 18,
                    Protocol::Diameter => 46,
                    _ => 0,
                };
                let ppid = sctp_p.and_then(|p| p.ppid).unwrap_or(default_ppid);
                let l4_payload = if effective_l3.frag_offset.unwrap_or(0) > 0 {
                    actual_payload
                } else {
                    crate::builders::transport::build_sctp_l7_packet(
                        src_ip,
                        effective_dst_ip,
                        src_port,
                        dst_port,
                        vtag,
                        tsn,
                        stream,
                        ssn,
                        ppid,
                        &actual_payload,
                        stmt.l4.bad_checksum,
                    )
                    .map_err(err_msg)?
                };
                let ip_pkt = crate::packet::build_ip_packet(
                    src_ip,
                    effective_dst_ip,
                    132,
                    &effective_l3,
                    &l4_payload,
                )
                .map_err(err_msg)?;
                crate::packet::build_ethernet_and_l2(
                    src_mac,
                    effective_dst_mac,
                    &stmt.l2,
                    if src_ip.is_ipv4() { 0x0800 } else { 0x86DD },
                    &ip_pkt,
                )
            } else {
                let flags = if is_tcp && stmt.flags.is_empty() {
                    vec![TcpFlag::Psh, TcpFlag::Ack]
                } else {
                    stmt.flags.clone()
                };

                build_wire_packet(
                    src_ip,
                    effective_dst_ip,
                    src_mac,
                    effective_dst_mac,
                    &stmt.l2,
                    &effective_l3,
                    &stmt.l4,
                    is_tcp,
                    src_port,
                    dst_port,
                    &flags,
                    final_seq,
                    final_ack_num,
                    stmt.win,
                    stmt.urgent,
                    Some(&actual_payload),
                )
                .map_err(err_msg)?
            }
        }
    };

    packet_buffer.push(CompiledFrame {
        data: packet_data,
        timestamp_ns: *current_time_ns,
        comment: stmt.comment.clone(),
    });
    let wait_time = stmt.wait.unwrap_or(10_000_000); // 10ms default post-packet delay
    *current_time_ns = current_time_ns.saturating_add(wait_time);
    Ok(())
}

/// Mutable compiler state threaded across recursive `compile`, `flow`, and `repeat` execution.
struct ExecutionState<'a> {
    /// Global declared hosts mapped by source identifier.
    env: &'a HashMap<&'a str, HostDef<'a>>,
    /// Host declaration indices mapped by lowercase identifier for default unicast MAC derivation.
    host_indices: &'a HashMap<String, usize>,
    /// Declared flow templates mapped by lowercase identifier.
    flows: &'a HashMap<String, &'a FlowDef<'a>>,
    /// Monotonic simulated wire clock in nanoseconds.
    current_time_ns: u64,
    /// Per-(host-pair, transport) active port inheritance state.
    endpoint_ports: HashMap<PortPairKey, EndpointPairPorts>,
    /// Per-4-tuple TCP sequence and teardown tracking state.
    tcp_connections: HashMap<Canonical4Tuple, TcpStreamState>,
    /// Per-host-pair SCTP association verification tag and TSN tracking state.
    sctp_associations: HashMap<HostPairKey, SctpAssocState>,
    /// Accumulated compiled frames with timestamps and optional comments.
    packet_buffer: Vec<CompiledFrame>,
}

/// Resolves an endpoint name against local `flow` parameter bindings first, then global `hosts`.
fn resolve_host_or_param<'a>(
    name: &'a str,
    param_map: Option<&HashMap<String, HostDef<'a>>>,
    env: &HashMap<&'a str, HostDef<'a>>,
    is_caller: bool,
) -> Result<HostDef<'a>, String> {
    if let Some(params) = param_map
        && let Some(ep) = params.get(&name.to_ascii_lowercase())
    {
        return Ok(ep.clone());
    }
    resolve_endpoint(&Argument::Variable(name), env).map_err(|err| {
        if param_map.is_some() {
            if is_caller {
                alloc::format!("Unknown caller '{}' in flow", name)
            } else {
                alloc::format!("Unknown callee '{}' in flow", name)
            }
        } else {
            err
        }
    })
}

/// Evaluates a single `flow` template invocation with optional caller parameter bindings.
fn execute_flow_invocation<'a>(
    invocation: &TemplateInvocation<'a>,
    outer_params: Option<&HashMap<String, HostDef<'a>>>,
    state: &mut ExecutionState<'a>,
    depth: usize,
) -> Result<(), String> {
    if depth >= MAX_FLOW_DEPTH {
        return Err(alloc::format!(
            "Flow nesting depth exceeded maximum limit ({MAX_FLOW_DEPTH}) invoking '{}'",
            invocation.name
        ));
    }
    let flow = state
        .flows
        .get(&invocation.name.to_ascii_lowercase())
        .copied()
        .ok_or_else(|| alloc::format!("Undefined flow: '{}'", invocation.name))?;

    if flow.params.len() != invocation.args.len() {
        return Err(alloc::format!(
            "Flow '{}' expects {} arguments, got {}",
            flow.name,
            flow.params.len(),
            invocation.args.len()
        ));
    }

    let mut param_map = HashMap::new();
    for (i, param_name) in flow.params.iter().enumerate() {
        let Argument::Variable(var_name) = &invocation.args[i];
        let endpoint = resolve_host_or_param(var_name, outer_params, state.env, false)?;
        param_map.insert(param_name.to_ascii_lowercase(), endpoint);
    }

    if !flow.body.is_empty() {
        execute_flow_statements(&flow.body, Some(&param_map), state, depth + 1)
    } else {
        for stmt in &flow.statements {
            let caller_ep =
                resolve_host_or_param(stmt.caller.node, Some(&param_map), state.env, true)?;
            let callee_ep =
                resolve_host_or_param(stmt.callee.node, Some(&param_map), state.env, false)?;
            execute_statement(
                stmt,
                &caller_ep,
                &callee_ep,
                state.host_indices,
                &mut state.current_time_ns,
                &mut state.endpoint_ports,
                &mut state.tcp_connections,
                &mut state.sctp_associations,
                &mut state.packet_buffer,
            )?;
        }
        Ok(())
    }
}

/// Recursively executes `flow` body statements including inline frames, nested calls, and `repeat` loops.
fn execute_flow_statements<'a>(
    body: &[FlowStatement<'a>],
    param_map: Option<&HashMap<String, HostDef<'a>>>,
    state: &mut ExecutionState<'a>,
    depth: usize,
) -> Result<(), String> {
    for item in body {
        match item {
            FlowStatement::Frame(stmt) => {
                let caller_ep =
                    resolve_host_or_param(stmt.caller.node, param_map, state.env, true)?;
                let callee_ep =
                    resolve_host_or_param(stmt.callee.node, param_map, state.env, false)?;
                execute_statement(
                    stmt,
                    &caller_ep,
                    &callee_ep,
                    state.host_indices,
                    &mut state.current_time_ns,
                    &mut state.endpoint_ports,
                    &mut state.tcp_connections,
                    &mut state.sctp_associations,
                    &mut state.packet_buffer,
                )?;
            }
            FlowStatement::Invocation(inv) => {
                execute_flow_invocation(inv, param_map, state, depth)?;
            }
            FlowStatement::Repeat { count, body, .. } => {
                for iter_idx in 0..*count {
                    let before = state.packet_buffer.len();
                    execute_flow_statements(body, param_map, state, depth)?;
                    if iter_idx == 0 && state.packet_buffer.len() == before {
                        break;
                    }
                }
            }
        }
    }
    Ok(())
}

/// Recursively executes `compile` block statements including invocations, inline frames, and `repeat` loops.
fn execute_run_statements<'a>(
    statements: &[RunStatement<'a>],
    state: &mut ExecutionState<'a>,
) -> Result<(), String> {
    for stmt in statements {
        match stmt {
            RunStatement::Invocation(inv) => {
                execute_flow_invocation(inv, None, state, 0)?;
            }
            RunStatement::Frame(frame_stmt) => {
                let caller_ep =
                    resolve_endpoint(&Argument::Variable(frame_stmt.caller.node), state.env)?;
                let callee_ep =
                    resolve_endpoint(&Argument::Variable(frame_stmt.callee.node), state.env)?;
                execute_statement(
                    frame_stmt,
                    &caller_ep,
                    &callee_ep,
                    state.host_indices,
                    &mut state.current_time_ns,
                    &mut state.endpoint_ports,
                    &mut state.tcp_connections,
                    &mut state.sctp_associations,
                    &mut state.packet_buffer,
                )?;
            }
            RunStatement::Repeat { count, body, .. } => {
                for iter_idx in 0..*count {
                    let before = state.packet_buffer.len();
                    execute_run_statements(body, state)?;
                    if iter_idx == 0 && state.packet_buffer.len() == before {
                        break;
                    }
                }
            }
        }
    }
    Ok(())
}

/// Synthesized [`CompiledFrame`] buffer paired with resolved `(host_name, ip_addr)` mappings.
type CompiledProgramWithMetadata = (Vec<CompiledFrame>, Vec<(String, IpAddr)>);

/// Evaluates the [`Program`] AST and synthesizes [`CompiledFrame`] packets paired with resolved host
/// IP name mappings (`(host_name, ip_addr)` for PCAPNG `NameResolutionBlock` emission).
///
/// # Errors
/// Returns a `String` error if endpoint resolution, frame count limits ([`MAX_EMITTED_FRAMES`]),
/// or wire packet construction fails.
pub fn compile_program_with_metadata(
    program: &Program,
) -> Result<CompiledProgramWithMetadata, String> {
    let mut env = HashMap::new();
    let mut host_indices = HashMap::new();
    let mut hosts_meta = Vec::new();
    for (idx, host) in program.hosts.iter().enumerate() {
        env.insert(host.name, host.clone());
        host_indices.insert(host.name.to_ascii_lowercase(), idx);
        if let Some(ip) = host.ip {
            hosts_meta.push((host.name.to_string(), ip));
        }
    }

    let mut flows = HashMap::new();
    for f in &program.flows {
        flows.insert(f.name.to_ascii_lowercase(), f);
    }

    let mut state = ExecutionState {
        env: &env,
        host_indices: &host_indices,
        flows: &flows,
        current_time_ns: 1_700_000_000_000_000_000,
        endpoint_ports: HashMap::new(),
        tcp_connections: HashMap::new(),
        sctp_associations: HashMap::new(),
        packet_buffer: Vec::new(),
    };

    execute_run_statements(&program.compile_block, &mut state)?;
    Ok((state.packet_buffer, hosts_meta))
}

/// Evaluates the [`Program`] AST and synthesizes raw Ethernet frames paired with nanosecond timestamps in memory.
///
/// # Examples
/// ```
/// use frameassembly::parser::parse_program;
/// use frameassembly::backend::compile_program;
///
/// let src = "host a { ip 10.0.0.1 }\nhost b { ip 10.0.0.2 }\nflow f(c, s) { c -> s icmp echorequest }\ncompile { f(a, b) }";
/// let program = parse_program(src).unwrap();
/// let packets = compile_program(&program).unwrap();
/// assert_eq!(packets.len(), 1);
/// ```
///
/// # Errors
/// Returns a `String` error if endpoint resolution or wire packet construction fails.
pub fn compile_program(program: &Program) -> Result<Vec<(Vec<u8>, u64)>, String> {
    let (frames, _) = compile_program_with_metadata(program)?;
    Ok(frames
        .into_iter()
        .map(|f| (f.data, f.timestamp_ns))
        .collect())
}

/// Evaluates the AST and writes the output capture file at `output_path`.
///
/// Writes classic libpcap (`.pcap`) when `output_path` ends with `.pcap` (case-insensitive)
/// and metadata-rich `PCAPNG` (with host `NameResolutionBlock` records and packet comments)
/// otherwise via [`write_capture_file_with_metadata`].
///
/// # Examples
/// ```no_run
/// use frameassembly::ast::Program;
/// use frameassembly::backend::generate_pcap;
///
/// let program = Program { hosts: vec![], flows: vec![], compile_block: vec![] };
/// generate_pcap(&program, "output.pcap").unwrap();
/// ```
///
/// # Errors
/// Returns a `String` containing the error message if:
/// * Network endpoints cannot be resolved.
/// * Capture serialization or file writing fails.
/// * Packet length or protocol limits are exceeded.
pub fn generate_pcap(program: &Program, output_path: &str) -> Result<(), String> {
    let (frames, hosts) = compile_program_with_metadata(program)?;
    let raw_meta: Vec<(Vec<u8>, u64, Option<String>)> = frames
        .into_iter()
        .map(|f| (f.data, f.timestamp_ns, f.comment))
        .collect();
    write_capture_file_with_metadata(&raw_meta, &hosts, output_path)
}

#[cfg(test)]
mod tests;
