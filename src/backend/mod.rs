//! Deterministic backend evaluation and PCAPNG wire packet emission engine.
//!
//! This module evaluates a validated [`Program`] AST, resolves host endpoints across flow
//! invocations and `LOOP` blocks, maintains two-stage TCP/UDP port inheritance and canonical
//! 4-tuple TCP sequence/acknowledgment state machines, derives RFC 1112 IPv4 and RFC 2464 IPv6
//! multicast MAC addresses, and emits nanosecond-precision wire frames via [`compile_program`]
//! and [`generate_pcap`].

use crate::ast::*;
use crate::packet::build_wire_packet;
use crate::pcap::PcapWriter;
use alloc::string::String;
use alloc::vec::Vec;
use core::net::IpAddr;
use std::collections::HashMap;

pub(crate) mod l7_dispatch;

use l7_dispatch::build_l7_packet_payload;

/// Resolves a host definition for a given argument in a flow invocation from the environment.
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

/// Derives an Ethernet MAC address for an endpoint following RFC 2464, RFC 1112, or deterministic unicast defaults.
fn derive_mac(
    host_mac: Option<[u8; 6]>,
    stmt_mac: Option<[u8; 6]>,
    ip: IpAddr,
    is_caller: bool,
) -> [u8; 6] {
    if let Some(mac) = stmt_mac {
        return mac;
    }
    if let Some(mac) = host_mac {
        return mac;
    }
    match ip {
        IpAddr::V6(v6) => {
            let octets = v6.octets();
            // RFC 2464: ff00::/8 IPv6 multicast
            if octets[0] == 0xFF {
                [0x33, 0x33, octets[12], octets[13], octets[14], octets[15]]
            } else if is_caller {
                [0x00, 0x00, 0x00, 0x00, 0x00, 0x01]
            } else {
                [0x00, 0x00, 0x00, 0x00, 0x00, 0x02]
            }
        }
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            // RFC 1112: 224.0.0.0/4 IPv4 multicast (224..=239)
            if (224..=239).contains(&octets[0]) {
                [0x01, 0x00, 0x5E, octets[1] & 0x7F, octets[2], octets[3]]
            } else if is_caller {
                [0x00, 0x00, 0x00, 0x00, 0x00, 0x01]
            } else {
                [0x00, 0x00, 0x00, 0x00, 0x00, 0x02]
            }
        }
    }
}

/// Returns the standard default destination port for a given protocol.
fn default_dst_port(protocol: &Protocol, pdu_type: Option<&SnmpPduType>) -> u16 {
    match protocol {
        Protocol::Tcp => 80,
        Protocol::Udp => 80,
        Protocol::Sctp => 80,
        Protocol::Snmp1 | Protocol::Snmp2 | Protocol::Snmp3 => {
            match pdu_type.unwrap_or(&SnmpPduType::Trap) {
                SnmpPduType::Trap | SnmpPduType::Inform => 162,
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
        Protocol::Http => 80,
        Protocol::Http2 => 443,
        Protocol::Grpc => 50051,
        Protocol::Websocket => 80,
        Protocol::Tls => 443,
        Protocol::Quic => 443,
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
        Protocol::Arp
        | Protocol::Vlan
        | Protocol::Qinq
        | Protocol::Lldp
        | Protocol::Stp
        | Protocol::Lacp
        | Protocol::Eapol
        | Protocol::Mpls
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
        | Protocol::Pim => 0,
    }
}

/// Endpoint pair ports tracked across forward and reversed statement arrows.
#[derive(Debug, Clone, Default)]
struct EndpointPairPorts {
    /// Port associated with the caller endpoint.
    pub caller_port: Option<u16>,
    /// Port associated with the callee endpoint.
    pub callee_port: Option<u16>,
    /// Last protocol that updated `callee_port`.
    pub last_protocol: Option<Protocol>,
    /// Whether `callee_port` was set by an explicit `SRCPORT` or `DSTPORT` modifier.
    pub callee_port_explicit: bool,
}


/// Canonical 4-tuple TCP stream state machine maintaining sequence progression.
#[derive(Debug, Clone)]
struct TcpStreamState {
    /// Sequence number for transmissions from endpoint 1.
    pub seq1: u32,
    /// Sequence number for transmissions from endpoint 2.
    pub seq2: u32,
}

/// Canonical 4-tuple key representing two sorted socket endpoints.
type Canonical4Tuple = ((IpAddr, u16), (IpAddr, u16));

/// Determines if the given protocol uses TCP transport based on protocol defaults and overrides.
pub(crate) fn is_tcp_protocol(protocol: &Protocol, transport: Option<TransportProto>) -> bool {
    match protocol {
        Protocol::Tcp
        | Protocol::Bgp
        | Protocol::Openflow
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
        | Protocol::Opcua => true,

        Protocol::Modbus
        | Protocol::Nfs
        | Protocol::Memcached
        | Protocol::Dnp3
        | Protocol::Ethernetip => transport != Some(TransportProto::Udp),

        Protocol::Dns
        | Protocol::Sip
        | Protocol::Syslog
        | Protocol::Kerberos => transport == Some(TransportProto::Tcp),

        _ => false,
    }
}

/// Evaluates the [`Program`] AST and synthesizes raw Ethernet frames paired with nanosecond timestamps in memory.
///
/// # Examples
/// ```
/// use frameassembly::parser::parse_program;
/// use frameassembly::backend::compile_program;
///
/// let src = "HOST a { IP 10.0.0.1 }\nHOST b { IP 10.0.0.2 }\nFLOW f(c, s) { c -> s ICMP ECHO_REQUEST }\nCOMPILE { f(a, b) }";
/// let program = parse_program(src).unwrap();
/// let packets = compile_program(&program).unwrap();
/// assert_eq!(packets.len(), 1);
/// ```
///
/// # Errors
/// Returns a `String` error if endpoint resolution or wire packet construction fails.
pub fn compile_program(program: &Program) -> Result<Vec<(Vec<u8>, u64)>, String> {
    let statements = &program.compile_block;

    let mut env = HashMap::new();
    for host in &program.hosts {
        env.insert(host.name, host.clone());
    }

    let mut flows = HashMap::new();
    for f in &program.flows {
        flows.insert(f.name.to_ascii_lowercase(), f);
    }

    let mut packet_buffer: Vec<(Vec<u8>, u64)> = Vec::new();

    let mut current_time_ns: u64 = 1_700_000_000_000_000_000;

    // Stage 1: Port inheritance remembered per endpoint pair (case-insensitive)
    let mut endpoint_ports: HashMap<(String, String), EndpointPairPorts> = HashMap::new();

    // Stage 2: Canonical 4-tuple TCP connection state machine
    let mut tcp_connections: HashMap<Canonical4Tuple, TcpStreamState> = HashMap::new();

    let mut execute_invocation = |invocation: &TemplateInvocation| -> Result<(), String> {
        let flow = flows
            .get(&invocation.name.to_ascii_lowercase())
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
            let endpoint = resolve_endpoint(&invocation.args[i], &env)?;
            param_map.insert(param_name.to_ascii_lowercase(), endpoint);
        }

        for stmt in &flow.statements {
            let caller_key = stmt.caller.node.to_ascii_lowercase();
            let callee_key = stmt.callee.node.to_ascii_lowercase();
            let caller_ep = param_map
                .get(&caller_key)
                .ok_or_else(|| alloc::format!("Unknown caller '{}' in flow", stmt.caller.node))?;
            let callee_ep = param_map
                .get(&callee_key)
                .ok_or_else(|| alloc::format!("Unknown callee '{}' in flow", stmt.callee.node))?;

            // Resolve Source and Destination based on Direction
            let (src_host, dst_host, is_forward) = match stmt.dir {
                Direction::LeftToRight => (caller_ep, callee_ep, true),
                Direction::RightToLeft => (callee_ep, caller_ep, false),
            };

            let src_ip = src_host.ip;
            let dst_ip = dst_host.ip;

            // MAC derivation with multicast auto-derivation (RFC 2464 / RFC 1112)
            let src_mac = derive_mac(src_host.mac, stmt.l2.src_mac, src_ip, is_forward);
            let dst_mac = derive_mac(dst_host.mac, stmt.l2.dst_mac, dst_ip, !is_forward);

            // Stage 1: Two-Stage Port Inheritance
            let pair_key = (caller_key, callee_key);
            let is_raw_l4 = matches!(stmt.protocol, Protocol::Tcp | Protocol::Udp | Protocol::Sctp);

            let (mut src_port, mut dst_port) = {
                let pair_ports = endpoint_ports.entry(pair_key.clone()).or_default();
                let can_inherit_callee = is_raw_l4
                    || (pair_ports.callee_port_explicit
                        && (pair_ports.last_protocol.as_ref() == Some(&stmt.protocol)
                            || matches!(
                                pair_ports.last_protocol,
                                Some(Protocol::Tcp | Protocol::Udp | Protocol::Sctp)
                            )));
                let inherited_callee_port = if can_inherit_callee {
                    pair_ports.callee_port
                } else {
                    None
                };

                match stmt.dir {
                    Direction::LeftToRight => {
                        let default_dst = default_dst_port(&stmt.protocol, stmt.pdu_type.as_ref());
                        let s_port = stmt.src_port.or(pair_ports.caller_port).unwrap_or(12345);
                        let d_port = stmt.dst_port.or(inherited_callee_port).unwrap_or(default_dst);
                        if stmt.dst_port.is_some() {
                            pair_ports.callee_port_explicit = true;
                        } else if !can_inherit_callee {
                            pair_ports.callee_port_explicit = false;
                        }
                        pair_ports.caller_port = Some(s_port);
                        pair_ports.callee_port = Some(d_port);
                        pair_ports.last_protocol = Some(stmt.protocol.clone());
                        (s_port, d_port)
                    }
                    Direction::RightToLeft => {
                        let default_src = default_dst_port(&stmt.protocol, stmt.pdu_type.as_ref());
                        let s_port = stmt.src_port.or(inherited_callee_port).unwrap_or(default_src);
                        let d_port = stmt.dst_port.or(pair_ports.caller_port).unwrap_or(12345);
                        if stmt.src_port.is_some() {
                            pair_ports.callee_port_explicit = true;
                        } else if !can_inherit_callee {
                            pair_ports.callee_port_explicit = false;
                        }
                        pair_ports.callee_port = Some(s_port);
                        pair_ports.caller_port = Some(d_port);
                        pair_ports.last_protocol = Some(stmt.protocol.clone());
                        (s_port, d_port)
                    }
                }
            };

            let payload_bytes = stmt.effective_payload().unwrap_or(&[]);

            let mut effective_l3 = stmt.l3.clone();
            if effective_l3.ttl.is_none()
                && (matches!(stmt.protocol, Protocol::Ndp | Protocol::Vrrp)
                    || (stmt.protocol == Protocol::Arp && src_ip.is_ipv6()))
            {
                effective_l3.ttl = Some(255);
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

            let l7_res = build_l7_packet_payload(&ctx, stmt, payload_bytes);
            if let Some(res) = &l7_res {
                if let Some(sp) = res.src_port
                    && stmt.src_port.is_none()
                {
                    src_port = sp;
                }
                if let Some(dp) = res.dst_port {
                    if stmt.protocol == Protocol::Radius && stmt.dir == Direction::RightToLeft {
                        if stmt.src_port.is_none() {
                            src_port = dp;
                        }
                    } else if stmt.dst_port.is_none() {
                        dst_port = dp;
                    }
                }
                if let Some(pair_ports) = endpoint_ports.get_mut(&pair_key) {
                    match stmt.dir {
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
            }

            // Stage 2: Canonical 4-Tuple TCP Sequence and Acknowledgment State Machine
            let mut final_seq = stmt.seq;
            let mut final_ack_num = stmt.ack_num;

            let is_stream_tcp = is_tcp_protocol(&stmt.protocol, stmt.l4.transport);

            if is_stream_tcp {
                let ep1 = (src_ip, src_port);
                let ep2 = (dst_ip, dst_port);
                let (key, is_stream_forward) = if ep1 <= ep2 {
                    ((ep1, ep2), true)
                } else {
                    ((ep2, ep1), false)
                };

                let stream = tcp_connections.entry(key).or_insert(TcpStreamState {
                    seq1: 1000,
                    seq2: 1000,
                });

                let (sender_seq, receiver_seq) = if is_stream_forward {
                    (&mut stream.seq1, &mut stream.seq2)
                } else {
                    (&mut stream.seq2, &mut stream.seq1)
                };

                let seq_val = if let Some(s) = stmt.seq {
                    *sender_seq = s;
                    s
                } else {
                    *sender_seq
                };
                final_seq = Some(seq_val);

                if final_ack_num.is_none() && (stmt.flags.contains(&TcpFlag::Ack) || stmt.protocol == Protocol::Bgp || stmt.protocol == Protocol::Openflow || is_stream_tcp) {
                    final_ack_num = Some(*receiver_seq);
                }

                let payload_len = if let Some(res) = &l7_res {
                    res.payload.len() as u32
                } else {
                    match stmt.protocol {
                        Protocol::Bgp => {
                            let spec = match &stmt.protocol_spec {
                                Some(ProtocolSpec::Bgp(s)) => s.clone(),
                                _ => BgpSpec::default(),
                            };
                            let (bgp_payload, _) = crate::builders::l3_tunnel::build_bgp_payload(&ctx, &spec, payload_bytes);
                            bgp_payload.len() as u32
                        }
                        Protocol::Openflow => {
                            let spec = match &stmt.protocol_spec {
                                Some(ProtocolSpec::Openflow(s)) => s.clone(),
                                _ => OpenflowSpec::default(),
                            };
                            let (of_payload, _) = crate::builders::l3_tunnel::build_openflow_payload(&spec, payload_bytes);
                            of_payload.len() as u32
                        }
                        _ => payload_bytes.len() as u32,
                    }
                };

                let mut advance = payload_len;
                if stmt.flags.contains(&TcpFlag::Syn) {
                    advance += 1;
                }
                if stmt.flags.contains(&TcpFlag::Fin) {
                    advance += 1;
                }
                *sender_seq = seq_val.wrapping_add(advance);
            }

            let wait_time = stmt.wait.unwrap_or(10_000_000); // 10ms default
            current_time_ns += wait_time;


            let packet_data: Vec<u8> = match stmt.protocol {
                // Layer 2 protocols
                Protocol::Arp => {
                    let spec = match &stmt.protocol_spec {
                        Some(ProtocolSpec::Arp(s)) => s.clone(),
                        _ => ArpSpec::default(),
                    };
                    crate::builders::l2::build_arp_frame(&ctx, &spec, payload_bytes)
                        .map_err(|e| alloc::format!("{:?}", e))?
                }
                Protocol::Vlan => {
                    let spec = match &stmt.protocol_spec {
                        Some(ProtocolSpec::Vlan(s)) => s.clone(),
                        _ => stmt.l2.vlan.clone().unwrap_or_default(),
                    };
                    crate::builders::l2::build_vlan_frame(&ctx, &spec, payload_bytes)
                        .map_err(|e| alloc::format!("{:?}", e))?
                }
                Protocol::Qinq => {
                    let spec = match &stmt.protocol_spec {
                        Some(ProtocolSpec::Qinq(s)) => s.clone(),
                        _ => stmt.l2.qinq.clone().unwrap_or_default(),
                    };
                    crate::builders::l2::build_qinq_frame(&ctx, &spec, payload_bytes)
                        .map_err(|e| alloc::format!("{:?}", e))?
                }
                Protocol::Lldp => {
                    let spec = match &stmt.protocol_spec {
                        Some(ProtocolSpec::Lldp(s)) => s.clone(),
                        _ => LldpSpec::default(),
                    };
                    crate::builders::l2::build_lldp_frame(&ctx, &spec, payload_bytes)
                        .map_err(|e| alloc::format!("{:?}", e))?
                }
                Protocol::Stp => {
                    let spec = match &stmt.protocol_spec {
                        Some(ProtocolSpec::Stp(s)) => s.clone(),
                        _ => StpSpec::default(),
                    };
                    crate::builders::l2::build_stp_frame(&ctx, &spec, payload_bytes)
                        .map_err(|e| alloc::format!("{:?}", e))?
                }
                Protocol::Lacp => {
                    let spec = match &stmt.protocol_spec {
                        Some(ProtocolSpec::Lacp(s)) => s.clone(),
                        _ => LacpSpec::default(),
                    };
                    crate::builders::l2::build_lacp_frame(&ctx, &spec, payload_bytes)
                        .map_err(|e| alloc::format!("{:?}", e))?
                }
                Protocol::Eapol => {
                    let spec = match &stmt.protocol_spec {
                        Some(ProtocolSpec::Eapol(s)) => s.clone(),
                        _ => EapolSpec::default(),
                    };
                    crate::builders::l2::build_eapol_frame(&ctx, &spec, payload_bytes)
                        .map_err(|e| alloc::format!("{:?}", e))?
                }
                Protocol::Mpls => {
                    let spec = match &stmt.protocol_spec {
                        Some(ProtocolSpec::Mpls(s)) => s.clone(),
                        _ => stmt.l2.mpls.clone().unwrap_or_default(),
                    };
                    crate::builders::l2::build_mpls_frame(&ctx, &spec, payload_bytes)
                        .map_err(|e| alloc::format!("{:?}", e))?
                }
                // Layer 3 / Tunnel / Routing / Security
                Protocol::Icmp => {
                    let spec = match &stmt.protocol_spec {
                        Some(ProtocolSpec::Icmp(s)) => s.clone(),
                        _ => IcmpSpec::default(),
                    };
                    let (icmp_body, proto) = crate::builders::l3_tunnel::build_icmp_payload(&ctx, &spec, payload_bytes)
                        .map_err(|e| alloc::format!("{:?}", e))?;
                    let ip_pkt = crate::packet::build_ip_packet(src_ip, dst_ip, proto, &effective_l3, &icmp_body)
                        .map_err(|e| alloc::format!("{:?}", e))?;
                    crate::packet::build_ethernet_and_l2(src_mac, dst_mac, &stmt.l2, if src_ip.is_ipv4() { 0x0800 } else { 0x86DD }, &ip_pkt)
                }
                Protocol::Ndp => {
                    let spec = match &stmt.protocol_spec {
                        Some(ProtocolSpec::Ndp(s)) => s.clone(),
                        _ => NdpSpec::default(),
                    };
                    let (ndp_body, target_ip, proto) = crate::builders::l3_tunnel::build_ndp_payload(&ctx, &spec, payload_bytes)
                        .map_err(|e| alloc::format!("{:?}", e))?;
                    let effective_dst_mac = derive_mac(None, stmt.l2.dst_mac, target_ip, false);
                    let ip_pkt = crate::packet::build_ip_packet(src_ip, target_ip, proto, &effective_l3, &ndp_body)
                        .map_err(|e| alloc::format!("{:?}", e))?;
                    crate::packet::build_ethernet_and_l2(src_mac, effective_dst_mac, &stmt.l2, 0x86DD, &ip_pkt)
                }
                Protocol::Igmp => {
                    let spec = match &stmt.protocol_spec {
                        Some(ProtocolSpec::Igmp(s)) => s.clone(),
                        _ => IgmpSpec::default(),
                    };
                    let (igmp_body, target_ip, proto) = crate::builders::l3_tunnel::build_igmp_payload(&ctx, &spec, payload_bytes)
                        .map_err(|e| alloc::format!("{:?}", e))?;
                    let effective_dst_mac = derive_mac(None, stmt.l2.dst_mac, target_ip, false);
                    let ip_pkt = crate::packet::build_ip_packet(src_ip, target_ip, proto, &effective_l3, &igmp_body)
                        .map_err(|e| alloc::format!("{:?}", e))?;
                    crate::packet::build_ethernet_and_l2(src_mac, effective_dst_mac, &stmt.l2, 0x0800, &ip_pkt)
                }
                Protocol::Mld => {
                    let spec = match &stmt.protocol_spec {
                        Some(ProtocolSpec::Mld(s)) => s.clone(),
                        _ => MldSpec::default(),
                    };
                    let (mld_body, target_ip, proto) = crate::builders::l3_tunnel::build_mld_payload(&ctx, &spec, payload_bytes)
                        .map_err(|e| alloc::format!("{:?}", e))?;
                    let effective_dst_mac = derive_mac(None, stmt.l2.dst_mac, target_ip, false);
                    let ip_pkt = crate::packet::build_ip_packet(src_ip, target_ip, proto, &effective_l3, &mld_body)
                        .map_err(|e| alloc::format!("{:?}", e))?;
                    crate::packet::build_ethernet_and_l2(src_mac, effective_dst_mac, &stmt.l2, 0x86DD, &ip_pkt)
                }
                Protocol::Gre => {
                    let spec = match &stmt.protocol_spec {
                        Some(ProtocolSpec::Gre(s)) => s.clone(),
                        _ => GreSpec::default(),
                    };
                    let (gre_body, proto) = crate::builders::l3_tunnel::build_gre_payload(&ctx, &spec, payload_bytes);
                    let ip_pkt = crate::packet::build_ip_packet(src_ip, dst_ip, proto, &effective_l3, &gre_body)
                        .map_err(|e| alloc::format!("{:?}", e))?;
                    crate::packet::build_ethernet_and_l2(src_mac, dst_mac, &stmt.l2, if src_ip.is_ipv4() { 0x0800 } else { 0x86DD }, &ip_pkt)
                }
                Protocol::Vxlan => {
                    let spec = match &stmt.protocol_spec {
                        Some(ProtocolSpec::Vxlan(s)) => s.clone(),
                        _ => VxlanSpec::default(),
                    };
                    let (vxlan_payload, dport) = crate::builders::l3_tunnel::build_vxlan_payload(&spec, payload_bytes);
                    let final_dport = stmt.dst_port.unwrap_or(dport);
                    let udp_pkt = crate::packet::build_udp_datagram(src_ip, dst_ip, src_port, final_dport, &vxlan_payload)
                        .map_err(|e| alloc::format!("{:?}", e))?;
                    let ip_pkt = crate::packet::build_ip_packet(src_ip, dst_ip, 17, &effective_l3, &udp_pkt)
                        .map_err(|e| alloc::format!("{:?}", e))?;
                    crate::packet::build_ethernet_and_l2(src_mac, dst_mac, &stmt.l2, if src_ip.is_ipv4() { 0x0800 } else { 0x86DD }, &ip_pkt)
                }
                Protocol::Geneve => {
                    let spec = match &stmt.protocol_spec {
                        Some(ProtocolSpec::Geneve(s)) => s.clone(),
                        _ => GeneveSpec::default(),
                    };
                    let (geneve_payload, dport) = crate::builders::l3_tunnel::build_geneve_payload(&spec, payload_bytes);
                    let final_dport = stmt.dst_port.unwrap_or(dport);
                    let udp_pkt = crate::packet::build_udp_datagram(src_ip, dst_ip, src_port, final_dport, &geneve_payload)
                        .map_err(|e| alloc::format!("{:?}", e))?;
                    let ip_pkt = crate::packet::build_ip_packet(src_ip, dst_ip, 17, &effective_l3, &udp_pkt)
                        .map_err(|e| alloc::format!("{:?}", e))?;
                    crate::packet::build_ethernet_and_l2(src_mac, dst_mac, &stmt.l2, if src_ip.is_ipv4() { 0x0800 } else { 0x86DD }, &ip_pkt)
                }
                Protocol::Ipsec | Protocol::Esp => {
                    let spec = match &stmt.protocol_spec {
                        Some(ProtocolSpec::Ipsec(s)) | Some(ProtocolSpec::Esp(s)) => s.clone(),
                        _ => IpsecSpec::default(),
                    };
                    let (esp_body, proto) = crate::builders::l3_tunnel::build_ipsec_esp_payload(&spec, payload_bytes);
                    let ip_pkt = crate::packet::build_ip_packet(src_ip, dst_ip, proto, &effective_l3, &esp_body)
                        .map_err(|e| alloc::format!("{:?}", e))?;
                    crate::packet::build_ethernet_and_l2(src_mac, dst_mac, &stmt.l2, if src_ip.is_ipv4() { 0x0800 } else { 0x86DD }, &ip_pkt)
                }
                Protocol::Ah => {
                    let spec = match &stmt.protocol_spec {
                        Some(ProtocolSpec::Ah(s)) => s.clone(),
                        _ => AhSpec::default(),
                    };
                    let (ah_body, proto) = crate::builders::l3_tunnel::build_ipsec_ah_payload(&spec, payload_bytes);
                    let ip_pkt = crate::packet::build_ip_packet(src_ip, dst_ip, proto, &effective_l3, &ah_body)
                        .map_err(|e| alloc::format!("{:?}", e))?;
                    crate::packet::build_ethernet_and_l2(src_mac, dst_mac, &stmt.l2, if src_ip.is_ipv4() { 0x0800 } else { 0x86DD }, &ip_pkt)
                }
                Protocol::Ikev2 => {
                    let spec = match &stmt.protocol_spec {
                        Some(ProtocolSpec::Ikev2(s)) => s.clone(),
                        _ => Ikev2Spec::default(),
                    };
                    let (ike_payload, dport) = crate::builders::l3_tunnel::build_ikev2_payload(&spec, payload_bytes);
                    let final_dport = stmt.dst_port.unwrap_or(dport);
                    let udp_pkt = crate::packet::build_udp_datagram(src_ip, dst_ip, src_port, final_dport, &ike_payload)
                        .map_err(|e| alloc::format!("{:?}", e))?;
                    let ip_pkt = crate::packet::build_ip_packet(src_ip, dst_ip, 17, &effective_l3, &udp_pkt)
                        .map_err(|e| alloc::format!("{:?}", e))?;
                    crate::packet::build_ethernet_and_l2(src_mac, dst_mac, &stmt.l2, if src_ip.is_ipv4() { 0x0800 } else { 0x86DD }, &ip_pkt)
                }
                Protocol::Wireguard => {
                    let spec = match &stmt.protocol_spec {
                        Some(ProtocolSpec::Wireguard(s)) => s.clone(),
                        _ => WireguardSpec::default(),
                    };
                    let (wg_payload, dport) = crate::builders::l3_tunnel::build_wireguard_payload(&spec, payload_bytes);
                    let final_dport = stmt.dst_port.unwrap_or(dport);
                    let udp_pkt = crate::packet::build_udp_datagram(src_ip, dst_ip, src_port, final_dport, &wg_payload)
                        .map_err(|e| alloc::format!("{:?}", e))?;
                    let ip_pkt = crate::packet::build_ip_packet(src_ip, dst_ip, 17, &effective_l3, &udp_pkt)
                        .map_err(|e| alloc::format!("{:?}", e))?;
                    crate::packet::build_ethernet_and_l2(src_mac, dst_mac, &stmt.l2, if src_ip.is_ipv4() { 0x0800 } else { 0x86DD }, &ip_pkt)
                }
                Protocol::Ospf => {
                    let spec = match &stmt.protocol_spec {
                        Some(ProtocolSpec::Ospf(s)) => s.clone(),
                        _ => OspfSpec::default(),
                    };
                    let (ospf_body, target_ip, proto) = crate::builders::l3_tunnel::build_ospf_payload(&ctx, &spec, payload_bytes);
                    let effective_dst_mac = derive_mac(None, stmt.l2.dst_mac, target_ip, false);
                    let ip_pkt = crate::packet::build_ip_packet(src_ip, target_ip, proto, &effective_l3, &ospf_body)
                        .map_err(|e| alloc::format!("{:?}", e))?;
                    crate::packet::build_ethernet_and_l2(src_mac, effective_dst_mac, &stmt.l2, if src_ip.is_ipv4() { 0x0800 } else { 0x86DD }, &ip_pkt)
                }
                Protocol::Rip => {
                    let spec = match &stmt.protocol_spec {
                        Some(ProtocolSpec::Rip(s)) => s.clone(),
                        _ => RipSpec::default(),
                    };
                    let (rip_payload, target_ip, dport) = crate::builders::l3_tunnel::build_rip_payload(&ctx, &spec, payload_bytes);
                    let effective_dst_mac = derive_mac(None, stmt.l2.dst_mac, target_ip, false);
                    let final_sport = stmt.src_port.unwrap_or(dport);
                    let final_dport = stmt.dst_port.unwrap_or(dport);
                    let udp_pkt = crate::packet::build_udp_datagram(src_ip, target_ip, final_sport, final_dport, &rip_payload)
                        .map_err(|e| alloc::format!("{:?}", e))?;
                    let ip_pkt = crate::packet::build_ip_packet(src_ip, target_ip, 17, &effective_l3, &udp_pkt)
                        .map_err(|e| alloc::format!("{:?}", e))?;
                    crate::packet::build_ethernet_and_l2(src_mac, effective_dst_mac, &stmt.l2, if src_ip.is_ipv4() { 0x0800 } else { 0x86DD }, &ip_pkt)
                }
                Protocol::Vrrp => {
                    let spec = match &stmt.protocol_spec {
                        Some(ProtocolSpec::Vrrp(s)) => s.clone(),
                        _ => VrrpSpec::default(),
                    };
                    let (vrrp_body, target_ip, proto) = crate::builders::l3_tunnel::build_vrrp_payload(&ctx, &spec, payload_bytes);
                    let effective_dst_mac = derive_mac(None, stmt.l2.dst_mac, target_ip, false);
                    let ip_pkt = crate::packet::build_ip_packet(src_ip, target_ip, proto, &effective_l3, &vrrp_body)
                        .map_err(|e| alloc::format!("{:?}", e))?;
                    crate::packet::build_ethernet_and_l2(src_mac, effective_dst_mac, &stmt.l2, if src_ip.is_ipv4() { 0x0800 } else { 0x86DD }, &ip_pkt)
                }
                Protocol::Hsrp => {
                    let spec = match &stmt.protocol_spec {
                        Some(ProtocolSpec::Hsrp(s)) => s.clone(),
                        _ => HsrpSpec::default(),
                    };
                    let (hsrp_payload, target_ip, dport) = crate::builders::l3_tunnel::build_hsrp_payload(&ctx, &spec, payload_bytes);
                    let effective_dst_mac = derive_mac(None, stmt.l2.dst_mac, target_ip, false);
                    let final_sport = stmt.src_port.unwrap_or(dport);
                    let final_dport = stmt.dst_port.unwrap_or(dport);
                    let udp_pkt = crate::packet::build_udp_datagram(src_ip, target_ip, final_sport, final_dport, &hsrp_payload)
                        .map_err(|e| alloc::format!("{:?}", e))?;
                    let ip_pkt = crate::packet::build_ip_packet(src_ip, target_ip, 17, &effective_l3, &udp_pkt)
                        .map_err(|e| alloc::format!("{:?}", e))?;
                    crate::packet::build_ethernet_and_l2(src_mac, effective_dst_mac, &stmt.l2, if src_ip.is_ipv4() { 0x0800 } else { 0x86DD }, &ip_pkt)
                }
                Protocol::Pim => {
                    let spec = match &stmt.protocol_spec {
                        Some(ProtocolSpec::Pim(s)) => s.clone(),
                        _ => PimSpec::default(),
                    };
                    let (pim_body, target_ip, proto) = crate::builders::l3_tunnel::build_pim_payload(&ctx, &spec, payload_bytes);
                    let effective_dst_mac = derive_mac(None, stmt.l2.dst_mac, target_ip, false);
                    let ip_pkt = crate::packet::build_ip_packet(src_ip, target_ip, proto, &effective_l3, &pim_body)
                        .map_err(|e| alloc::format!("{:?}", e))?;
                    crate::packet::build_ethernet_and_l2(src_mac, effective_dst_mac, &stmt.l2, if src_ip.is_ipv4() { 0x0800 } else { 0x86DD }, &ip_pkt)
                }
                Protocol::Bfd => {
                    let spec = match &stmt.protocol_spec {
                        Some(ProtocolSpec::Bfd(s)) => s.clone(),
                        _ => BfdSpec::default(),
                    };
                    let (bfd_payload, dport) = crate::builders::l3_tunnel::build_bfd_payload(&spec, payload_bytes);
                    let final_dport = stmt.dst_port.unwrap_or(dport);
                    let udp_pkt = crate::packet::build_udp_datagram(src_ip, dst_ip, src_port, final_dport, &bfd_payload)
                        .map_err(|e| alloc::format!("{:?}", e))?;
                    let ip_pkt = crate::packet::build_ip_packet(src_ip, dst_ip, 17, &effective_l3, &udp_pkt)
                        .map_err(|e| alloc::format!("{:?}", e))?;
                    crate::packet::build_ethernet_and_l2(src_mac, dst_mac, &stmt.l2, if src_ip.is_ipv4() { 0x0800 } else { 0x86DD }, &ip_pkt)
                }
                // Layer 4 Transports
                Protocol::Sctp => {
                    let spec = match &stmt.protocol_spec {
                        Some(ProtocolSpec::Sctp(s)) => s.clone(),
                        _ => stmt.l4.sctp_params.clone().unwrap_or_default(),
                    };
                    let (sctp_pkt, proto) = crate::builders::transport::build_sctp_payload(&ctx, &spec, payload_bytes)
                        .map_err(|e| alloc::format!("{:?}", e))?;
                    let ip_pkt = crate::packet::build_ip_packet(src_ip, dst_ip, proto, &effective_l3, &sctp_pkt)
                        .map_err(|e| alloc::format!("{:?}", e))?;
                    crate::packet::build_ethernet_and_l2(src_mac, dst_mac, &stmt.l2, if src_ip.is_ipv4() { 0x0800 } else { 0x86DD }, &ip_pkt)
                }
                // TCP / UDP / Application protocols over TCP/UDP
                Protocol::Tcp
                | Protocol::Udp
                | Protocol::Bgp
                | Protocol::Openflow
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
                | Protocol::Opcua => {
                    let (effective_dst_ip, effective_dst_mac) =
                        if let Some(target_ip) = l7_res.as_ref().and_then(|r| r.target_ip) {
                            (
                                target_ip,
                                derive_mac(None, stmt.l2.dst_mac, target_ip, false),
                            )
                        } else {
                            (dst_ip, dst_mac)
                        };

                    let (actual_payload, is_tcp) = if let Some(res) = l7_res {
                        (res.payload, res.is_tcp)
                    } else {
                        match stmt.protocol {
                            Protocol::Tcp => (payload_bytes.to_vec(), true),
                            Protocol::Udp => (payload_bytes.to_vec(), false),
                            Protocol::Bgp => {
                                let spec = match &stmt.protocol_spec {
                                    Some(ProtocolSpec::Bgp(s)) => s.clone(),
                                    _ => BgpSpec::default(),
                                };
                                let (bgp_payload, _) = crate::builders::l3_tunnel::build_bgp_payload(&ctx, &spec, payload_bytes);
                                (bgp_payload, true)
                            }
                            Protocol::Openflow => {
                                let spec = match &stmt.protocol_spec {
                                    Some(ProtocolSpec::Openflow(s)) => s.clone(),
                                    _ => OpenflowSpec::default(),
                                };
                                let (of_payload, _) = crate::builders::l3_tunnel::build_openflow_payload(&spec, payload_bytes);
                                (of_payload, true)
                            }
                            Protocol::Snmp1 => (crate::builders::snmp::build_snmp1_payload(stmt, src_ip)?, false),
                            Protocol::Snmp2 => (crate::builders::snmp::build_snmp2_payload(stmt)?, false),
                            Protocol::Snmp3 => (crate::builders::snmp::build_snmp3_payload(stmt)?, false),
                            _ => unreachable!(),
                        }
                    };

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
                    .map_err(|e| alloc::format!("{:?}", e))?
                }
            };

            packet_buffer.push((packet_data, current_time_ns));
        }
        Ok(())
    };


    for stmt in statements {
        match stmt {
            RunStatement::Invocation(inv) => execute_invocation(inv)?,
            RunStatement::Loop(count, invocations) => {
                for _ in 0..*count {
                    for inv in invocations {
                        execute_invocation(inv)?;
                    }
                }
            }
        }
    }

    Ok(packet_buffer)
}

/// Evaluates the AST and generates the PCAP file at the specified output path.
///
/// This walks the [`Program`] AST via [`compile_program`], builds each packet, and writes it
/// to the specified `.pcap` / `.pcapng` file path.
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
/// * PCAP writing fails.
/// * Unrecognized protocol combinations occur.
pub fn generate_pcap(program: &Program, output_path: &str) -> Result<(), String> {
    let packet_buffer = compile_program(program)?;

    let mut pcap = PcapWriter::create(output_path)
        .map_err(|e| alloc::format!("Failed to create PCAP file: {}", e))?;
    for (packet_data, timestamp_ns) in packet_buffer {
        pcap.write_packet(&packet_data, timestamp_ns)
            .map_err(|e| alloc::format!("Failed to write packet: {}", e))?;
    }

    Ok(())
}

#[cfg(test)]
mod tests;

