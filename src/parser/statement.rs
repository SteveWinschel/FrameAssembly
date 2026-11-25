//! Frame statement parser and L2/L3/L4/SNMP field state accumulator.
//!
//! This module implements [`FrameBuilder`] and [`parse_frame_statement`], which parse a single
//! directional packet transmission statement (`<caller> -> <callee> <protocol> [modifiers...]`)
//! inside a `flow` or `compile` block. It maintains protocol-scoped field dispatch via
//! [`parse_protocol_keyword`] and [`dispatch_protocol_field`] so that shared modifier tokens
//! resolve cleanly to the active protocol, tracks duplicate modifiers for semantic validation,
//! and constructs the final [`FrameStatement`] AST node.

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::net::IpAddr;
use std::collections::HashSet;

use winnow::ModalResult as PResult;
use winnow::combinator::cut_err;
use winnow::error::ErrMode;
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;

use super::fields::{
    dispatch_protocol_field, parse_fallback_field, parse_protocol_keyword, parse_universal_field,
};
use super::{ParsedField, Stream, parse_direction, parse_spanned_ident};

/// Raw MPLS label stack entry `(label, exp, bos, ttl, span)`.
type RawMplsEntry = (u32, Option<u8>, Option<u8>, Option<u8>, (usize, usize));

/// Accumulator state for constructing a [`FrameStatement`] from parsed modifier fields.
pub(crate) struct FrameBuilder<'a> {
    /// Active protocol for the statement.
    pub(crate) protocol: Option<Protocol>,
    /// TCP flags list.
    pub(crate) flags: Vec<TcpFlag>,
    /// TCP / ICMP / IPsec / SCTP sequence number.
    pub(crate) seq: Option<u32>,
    /// TCP acknowledgment number.
    pub(crate) ack_num: Option<u32>,
    /// TCP window size.
    pub(crate) win: Option<u16>,
    /// Decoded string payload.
    pub(crate) payload: Option<String>,
    /// Decoded raw byte payload (preserving `\x80`..`\xff` as raw octets).
    pub(crate) payload_bytes: Option<Vec<u8>>,
    /// Decoded binary hex payload.
    pub(crate) hex_payload: Option<Vec<u8>>,
    /// Optional per-frame PCAPNG comment (`comment <str>`).
    pub(crate) comment: Option<String>,
    /// Inter-packet delay in nanoseconds.
    pub(crate) wait: Option<u64>,
    /// Source port override.
    pub(crate) src_port: Option<u16>,
    /// Destination port override.
    pub(crate) dst_port: Option<u16>,
    /// SNMPv1/v2c community string.
    pub(crate) community: Option<&'a str>,
    /// SNMPv3 / RADIUS / TACACS+ user string.
    pub(crate) user: Option<&'a str>,
    /// SNMP OID string.
    pub(crate) oid: Option<&'a str>,
    /// SNMP system uptime.
    pub(crate) sys_up_time: Option<u32>,
    /// SNMP PDU type.
    pub(crate) pdu_type: Option<SnmpPduType>,
    /// SNMPv1 enterprise OID.
    pub(crate) enterprise: Option<&'a str>,
    /// SNMPv1 agent IP.
    pub(crate) agent_ip: Option<IpAddr>,
    /// SNMPv1 generic trap ID.
    pub(crate) gen_trap: Option<u32>,
    /// SNMPv1 specific trap ID.
    pub(crate) spec_trap: Option<u32>,
    /// SNMPv3 engine ID.
    pub(crate) engine_id: Option<&'a str>,
    /// SNMPv3 engine boots.
    pub(crate) engine_boots: Option<u32>,
    /// SNMPv3 engine time.
    pub(crate) engine_time: Option<u32>,
    /// SNMPv3 context name.
    pub(crate) context_name: Option<&'a str>,
    /// SNMPv3 authentication type and passphrase.
    pub(crate) auth: Option<(SnmpAuthType, &'a str)>,
    /// SNMPv3 privacy type and passphrase.
    pub(crate) priv_param: Option<(SnmpPrivType, &'a str)>,
    /// SNMP variable bindings list.
    pub(crate) varbinds: Vec<VarBindAst<'a>>,
    /// SNMPv2c/v3 non-repeaters count.
    pub(crate) non_repeaters: Option<u32>,
    /// SNMPv2c/v3 max-repetitions count.
    pub(crate) max_repetitions: Option<u32>,
    /// SNMPv2c/v3 request ID.
    pub(crate) req_id: Option<u32>,
    /// Raw VLAN ID and span.
    pub(crate) vlan_val: Option<(u32, (usize, usize))>,
    /// Raw DSCP value and span.
    pub(crate) dscp_val: Option<(u32, (usize, usize))>,
    /// Raw ECN value and span.
    pub(crate) ecn_val: Option<(u32, (usize, usize))>,
    /// Raw TTL value and span.
    pub(crate) ttl_val: Option<(u32, (usize, usize))>,
    /// Raw IPv6 Flow Label and span.
    pub(crate) flowlabel_val: Option<(u32, (usize, usize))>,
    /// Raw 802.1p PCP and span.
    pub(crate) pcp_val: Option<(u8, (usize, usize))>,
    /// Raw 802.1Q DEI and span.
    pub(crate) dei_val: Option<(u8, (usize, usize))>,
    /// Raw 802.1ad QinQ outer VLAN ID and span.
    pub(crate) qinq_val: Option<(u16, (usize, usize))>,
    /// Raw 802.1ad QinQ inner VLAN ID and span.
    pub(crate) inner_vlan_val: Option<(u16, (usize, usize))>,
    /// Raw MPLS label stack entries `(label, exp, bos, ttl, span)`.
    pub(crate) mpls_entries: Vec<RawMplsEntry>,
    /// Append valid Ethernet FCS trailer (`fcs`).
    pub(crate) fcs: bool,
    /// Append corrupted Ethernet FCS trailer (`badfcs`).
    pub(crate) bad_fcs: bool,
    /// Raw source MAC and span.
    pub(crate) src_mac_val: Option<([u8; 6], (usize, usize))>,
    /// Raw destination MAC and span.
    pub(crate) dst_mac_val: Option<([u8; 6], (usize, usize))>,
    /// Raw EtherType override and span.
    pub(crate) ethertype_val: Option<(u16, (usize, usize))>,
    /// Raw IPv4 Identification and span.
    pub(crate) ipid_val: Option<(u16, (usize, usize))>,
    /// IPv4 Don't Fragment flag.
    pub(crate) df_val: bool,
    /// IPv4 More Fragments flag.
    pub(crate) mf_val: bool,
    /// Raw IPv4 Fragment Offset and span.
    pub(crate) frag_offset_val: Option<(u16, (usize, usize))>,
    /// IPv4/IPv6 Router Alert flag.
    pub(crate) router_alert: bool,
    /// Corrupt IPv4 header checksum flag.
    pub(crate) bad_ip_checksum: bool,
    /// Explicit L4 transport protocol override.
    pub(crate) transport_val: Option<TransportProto>,
    /// Corrupt L4 checksum flag.
    pub(crate) bad_checksum: bool,
    /// Zero UDP checksum flag.
    pub(crate) no_checksum: bool,
    /// Raw TCP Urgent pointer and span.
    pub(crate) urgent_val: Option<(u16, (usize, usize))>,
    /// Raw TCP MSS option and span.
    pub(crate) mss_val: Option<(u16, (usize, usize))>,
    /// Raw TCP Window Scale option and span.
    pub(crate) wscale_val: Option<(u8, (usize, usize))>,
    /// TCP SACK Permitted option flag.
    pub(crate) sack_perm_val: bool,
    /// TCP SACK blocks `(left, right)`.
    pub(crate) sack_blocks: Vec<(u32, u32)>,
    /// Raw TCP TSval option and span.
    pub(crate) tsval_val: Option<(u32, (usize, usize))>,
    /// Raw TCP TSecr option and span.
    pub(crate) tsecr_val: Option<(u32, (usize, usize))>,
    /// TCP MD5 digest bytes (`tcpmd5 <hex>`).
    pub(crate) tcp_md5: Option<Vec<u8>>,
    /// TCP Fast Open cookie bytes (`tfo <hex>`).
    pub(crate) tfo: Option<Vec<u8>>,
    /// Raw SCTP Verification Tag and span.
    pub(crate) vtag_val: Option<(u32, (usize, usize))>,
    /// Raw SCTP Stream ID and span.
    pub(crate) stream_val: Option<(u16, (usize, usize))>,
    /// Raw SCTP Stream Sequence Number and span.
    pub(crate) ssn_val: Option<(u16, (usize, usize))>,
    /// Raw SCTP Payload Protocol Identifier and span.
    pub(crate) ppid_val: Option<(u32, (usize, usize))>,
    /// Raw SCTP Chunk type and span.
    pub(crate) chunk_val: Option<(String, (usize, usize))>,
    /// ARP operation code.
    pub(crate) arp_opcode: Option<ArpOpcode>,
    /// Gratuitous ARP flag.
    pub(crate) is_gratuitous: bool,
    /// ARP Sender Hardware Address.
    pub(crate) sha: Option<[u8; 6]>,
    /// ARP Sender Protocol Address.
    pub(crate) spa: Option<IpAddr>,
    /// ARP Target Hardware Address.
    pub(crate) tha: Option<[u8; 6]>,
    /// ARP Target Protocol Address.
    pub(crate) tpa: Option<IpAddr>,
    /// LLDP Chassis ID.
    pub(crate) chassis_id: Option<&'a str>,
    /// LLDP Port ID string.
    pub(crate) port_id_str: Option<&'a str>,
    /// LLDP System Name.
    pub(crate) sysname: Option<&'a str>,
    /// LLDP System Description.
    pub(crate) sysdesc: Option<&'a str>,
    /// STP Root Bridge ID.
    pub(crate) root_id: Option<&'a str>,
    /// STP Bridge ID.
    pub(crate) bridge_id: Option<&'a str>,
    /// STP numeric Port ID.
    pub(crate) port_id_u16: Option<u16>,
    /// STP Root Path Cost.
    pub(crate) stp_cost: Option<u32>,
    /// STP Max Age.
    pub(crate) max_age: Option<u16>,
    /// STP Hello Time.
    pub(crate) hello_time: Option<u16>,
    /// STP Forward Delay.
    pub(crate) forward_delay: Option<u16>,
    /// RSTP mode flag.
    pub(crate) is_rstp: bool,
    /// STP BPDU flags byte.
    pub(crate) stp_flags: Option<u8>,
    /// LACP Actor System MAC.
    pub(crate) actor_sys: Option<[u8; 6]>,
    /// LACP Actor Key.
    pub(crate) actor_key: Option<u16>,
    /// LACP Actor Port.
    pub(crate) actor_port: Option<u16>,
    /// LACP Partner System MAC.
    pub(crate) partner_sys: Option<[u8; 6]>,
    /// LACP Partner Key.
    pub(crate) partner_key: Option<u16>,
    /// LACP Partner Port.
    pub(crate) partner_port: Option<u16>,
    /// LACP Actor State byte.
    pub(crate) actor_state: Option<u8>,
    /// LACP Partner State byte.
    pub(crate) partner_state: Option<u8>,
    /// Protocol version byte (EAPOL, IGMP, VRRP, OpenFlow).
    pub(crate) version_byte: Option<u8>,
    /// EAPOL packet type.
    pub(crate) eapol_type: Option<EapolType>,
    /// EAP code byte.
    pub(crate) eap_code: Option<u8>,
    /// EAP identifier byte.
    pub(crate) eap_id: Option<u8>,
    /// EAP authentication method byte.
    pub(crate) eap_method: Option<u8>,
    /// EAP identity string.
    pub(crate) identity_str: Option<&'a str>,
    /// ICMP message type choice.
    pub(crate) icmp_type_choice: Option<IcmpTypeChoice>,
    /// ICMP numeric type override.
    pub(crate) icmp_type_val: Option<u8>,
    /// ICMP numeric code override.
    pub(crate) icmp_code_val: Option<u8>,
    /// ICMP echo identifier.
    pub(crate) icmp_id_val: Option<u16>,
    /// ICMP redirect gateway IP.
    pub(crate) gateway_ip: Option<IpAddr>,
    /// NDP message type.
    pub(crate) ndp_type: Option<NdpType>,
    /// NDP target IPv6 address.
    pub(crate) target_ip: Option<IpAddr>,
    /// NDP source link-layer address MAC.
    pub(crate) slla_mac: Option<[u8; 6]>,
    /// NDP target link-layer address MAC.
    pub(crate) tlla_mac: Option<[u8; 6]>,
    /// NDP router lifetime.
    pub(crate) router_lifetime: Option<u16>,
    /// IGMP message type.
    pub(crate) igmp_type: Option<IgmpType>,
    /// IGMP / PIM multicast group IP.
    pub(crate) group_ip: Option<IpAddr>,
    /// IGMP max response time.
    pub(crate) max_resp: Option<u8>,
    /// MLD message type.
    pub(crate) mld_type: Option<MldType>,
    /// MLD multicast IPv6 address.
    pub(crate) multicast_addr: Option<IpAddr>,
    /// MLD max response delay.
    pub(crate) max_resp_delay: Option<u16>,
    /// GRE key value.
    pub(crate) gre_key: Option<u32>,
    /// GRE sequence number.
    pub(crate) gre_seq: Option<u32>,
    /// GRE encapsulated protocol EtherType.
    pub(crate) gre_proto: Option<u16>,
    /// GRE checksum present flag.
    pub(crate) gre_checksum: bool,
    /// VXLAN / GENEVE Virtual Network Identifier.
    pub(crate) vni_val: Option<u32>,
    /// GENEVE option class.
    pub(crate) opt_class: Option<u16>,
    /// GENEVE option type.
    pub(crate) opt_type: Option<u8>,
    /// GENEVE inner protocol EtherType.
    pub(crate) protocol_type: Option<u16>,
    /// IPsec ESP/AH Security Parameters Index.
    pub(crate) spi_val: Option<u32>,
    /// IPsec ESP Initialization Vector bytes.
    pub(crate) iv_val: Option<Vec<u8>>,
    /// IPsec ESP/AH Integrity Check Value bytes.
    pub(crate) icv_val: Option<Vec<u8>>,
    /// IPsec / IPv6 Next Header protocol number.
    pub(crate) next_header_val: Option<u8>,
    /// IKEv2 Initiator SPI.
    pub(crate) initiator_spi: Option<u64>,
    /// IKEv2 Responder SPI.
    pub(crate) responder_spi: Option<u64>,
    /// IKEv2 Exchange mode.
    pub(crate) ike_exchange: Option<IkeExchange>,
    /// IKEv2 Message ID.
    pub(crate) ike_msgid: Option<u32>,
    /// IKEv2 header flags byte.
    pub(crate) ike_flags: Option<u8>,
    /// IKEv2 Next Payload type byte.
    pub(crate) next_payload: Option<u8>,
    /// WireGuard message type.
    pub(crate) wireguard_type: Option<WireguardType>,
    /// WireGuard sender index.
    pub(crate) wg_sender: Option<u32>,
    /// WireGuard receiver index.
    pub(crate) wg_receiver: Option<u32>,
    /// WireGuard packet counter.
    pub(crate) wg_counter: Option<u64>,
    /// OSPF packet type.
    pub(crate) ospf_type: Option<OspfType>,
    /// OSPF Router ID.
    pub(crate) router_id_ip: Option<IpAddr>,
    /// OSPF Area ID.
    pub(crate) area_id_val: Option<u32>,
    /// OSPF Hello interval.
    pub(crate) hello_interval: Option<u16>,
    /// OSPF Router Dead interval.
    pub(crate) dead_interval: Option<u32>,
    /// OSPF / VRRP / HSRP / OpenFlow priority value and span.
    pub(crate) priority_val: Option<(u16, (usize, usize))>,
    /// BGP message type.
    pub(crate) bgp_type: Option<BgpType>,
    /// BGP Autonomous System Number.
    pub(crate) asn_val: Option<u32>,
    /// BGP / PIM / HSRP Hold Time and span.
    pub(crate) holdtime_val: Option<(u16, (usize, usize))>,
    /// BGP Identifier IP.
    pub(crate) bgpid_ip: Option<IpAddr>,
    /// BGP CIDR prefix string.
    pub(crate) prefix_str: Option<&'a str>,
    /// BGP / RIP Next Hop IP.
    pub(crate) nexthop_ip: Option<IpAddr>,
    /// RIP command type.
    pub(crate) rip_cmd: Option<RipCommand>,
    /// RIP route prefix IP.
    pub(crate) rip_prefix: Option<IpAddr>,
    /// RIP hop count metric.
    pub(crate) rip_metric: Option<u32>,
    /// RIP route tag.
    pub(crate) rip_tag: Option<u16>,
    /// VRRP Virtual Router ID.
    pub(crate) vrid_val: Option<u8>,
    /// VRRP Advertisement Interval.
    pub(crate) adv_int_val: Option<u16>,
    /// VRRP / HSRP Virtual IP.
    pub(crate) vip_ip: Option<IpAddr>,
    /// HSRP router state.
    pub(crate) hsrp_state: Option<u8>,
    /// HSRP standby group number.
    pub(crate) hsrp_group: Option<u8>,
    /// HSRP authentication string.
    pub(crate) hsrp_auth: Option<&'a str>,
    /// HSRP hello time.
    pub(crate) hsrp_hellotime: Option<u8>,
    /// Raw `hellotime` value and span for HSRP semantic range validation (`0..=255`).
    pub(crate) raw_hellotime: Option<(u16, (usize, usize))>,
    /// PIM Hello message flag.
    pub(crate) pim_is_hello: bool,
    /// PIM Join/Prune message flag.
    pub(crate) pim_is_join_prune: bool,
    /// PIM Register message flag.
    pub(crate) pim_is_register: bool,
    /// PIM multicast source IP.
    pub(crate) pim_source: Option<IpAddr>,
    /// PIM Rendezvous Point IP.
    pub(crate) pim_rp: Option<IpAddr>,
    /// PIM Designated Router priority.
    pub(crate) pim_dr_priority: Option<u32>,
    /// BFD session state.
    pub(crate) bfd_state: Option<u8>,
    /// BFD diagnostic code.
    pub(crate) bfd_diag: Option<u8>,
    /// BFD My Discriminator.
    pub(crate) bfd_my_disc: Option<u32>,
    /// BFD Your Discriminator.
    pub(crate) bfd_your_disc: Option<u32>,
    /// BFD Desired Min TX Interval.
    pub(crate) bfd_min_tx: Option<u32>,
    /// BFD Required Min RX Interval.
    pub(crate) bfd_min_rx: Option<u32>,
    /// BFD Detect Multiplier.
    pub(crate) bfd_mult: Option<u8>,
    /// OpenFlow message type.
    pub(crate) openflow_type: Option<OpenflowType>,
    /// OpenFlow Transaction ID.
    pub(crate) of_xid: Option<u32>,
    /// OpenFlow Datapath ID.
    pub(crate) of_dpid: Option<u64>,
    /// OpenFlow Table ID.
    pub(crate) of_table_id: Option<u8>,
    /// OpenFlow flow priority.
    pub(crate) of_priority: Option<u16>,
    /// DNS / mDNS specification.
    pub(crate) dns_spec: DnsSpec<'a>,
    /// DHCP / DHCPv6 specification.
    pub(crate) dhcp_spec: DhcpSpec<'a>,
    /// NTP specification.
    pub(crate) ntp_spec: NtpSpec<'a>,
    /// PTP specification.
    pub(crate) ptp_spec: PtpSpec<'a>,
    /// RADIUS specification.
    pub(crate) radius_spec: RadiusSpec<'a>,
    /// TACACS+ specification.
    pub(crate) tacacs_spec: TacacsSpec<'a>,
    /// Syslog specification.
    pub(crate) syslog_spec: SyslogSpec<'a>,
    /// NetFlow specification.
    pub(crate) netflow_spec: NetflowSpec<'a>,
    /// IPFIX specification.
    pub(crate) ipfix_spec: IpfixSpec<'a>,
    /// sFlow specification.
    pub(crate) sflow_spec: SflowSpec<'a>,
    /// TFTP specification.
    pub(crate) tftp_spec: TftpSpec<'a>,
    /// FTP specification.
    pub(crate) ftp_spec: FtpSpec<'a>,
    /// SSH specification.
    pub(crate) ssh_spec: SshSpec<'a>,
    /// Telnet specification.
    pub(crate) telnet_spec: TelnetSpec<'a>,
    /// HTTP/1.1 specification.
    pub(crate) http_spec: HttpSpec<'a>,
    /// HTTP/2 specification.
    pub(crate) http2_spec: Http2Spec<'a>,
    /// gRPC specification.
    pub(crate) grpc_spec: GrpcSpec<'a>,
    /// WebSocket specification.
    pub(crate) websocket_spec: WebsocketSpec<'a>,
    /// TLS specification.
    pub(crate) tls_spec: TlsSpec<'a>,
    /// QUIC specification.
    pub(crate) quic_spec: QuicSpec<'a>,
    /// STUN specification.
    pub(crate) stun_spec: StunSpec<'a>,
    /// SIP specification.
    pub(crate) sip_spec: SipSpec<'a>,
    /// RTP specification.
    pub(crate) rtp_spec: RtpSpec<'a>,
    /// RTSP specification.
    pub(crate) rtsp_spec: RtspSpec<'a>,
    /// SMTP specification.
    pub(crate) smtp_spec: SmtpSpec<'a>,
    /// IMAP specification.
    pub(crate) imap_spec: ImapSpec<'a>,
    /// POP3 specification.
    pub(crate) pop3_spec: Pop3Spec<'a>,
    /// Kerberos specification.
    pub(crate) kerberos_spec: KerberosSpec<'a>,
    /// LDAP specification.
    pub(crate) ldap_spec: LdapSpec<'a>,
    /// SMB2/3 specification.
    pub(crate) smb_spec: SmbSpec<'a>,
    /// NFSv4 specification.
    pub(crate) nfs_spec: NfsSpec<'a>,
    /// Redis RESP specification.
    pub(crate) redis_spec: RedisSpec<'a>,
    /// Memcached specification.
    pub(crate) memcached_spec: MemcachedSpec<'a>,
    /// MySQL specification.
    pub(crate) mysql_spec: MysqlSpec<'a>,
    /// PostgreSQL specification.
    pub(crate) postgres_spec: PostgresSpec<'a>,
    /// MQTT specification.
    pub(crate) mqtt_spec: MqttSpec<'a>,
    /// CoAP specification.
    pub(crate) coap_spec: CoapSpec<'a>,
    /// AMQP specification.
    pub(crate) amqp_spec: AmqpSpec<'a>,
    /// SSDP specification.
    pub(crate) ssdp_spec: SsdpSpec<'a>,
    /// WHOIS specification.
    pub(crate) whois_spec: WhoisSpec<'a>,
    /// Modbus TCP specification.
    pub(crate) modbus_spec: ModbusSpec<'a>,
    /// BACnet/IP specification.
    pub(crate) bacnet_spec: BacnetSpec<'a>,
    /// DNP3 specification.
    pub(crate) dnp3_spec: DNP3SpecAlias<'a>,
    /// S7comm specification.
    pub(crate) s7comm_spec: S7commSpec<'a>,
    /// EtherNet/IP specification.
    pub(crate) ethernetip_spec: EthernetipSpec<'a>,
    /// OPC UA specification.
    pub(crate) opcua_spec: OpcuaSpec<'a>,
    /// Cisco Discovery Protocol (`cdp`) specification.
    pub(crate) cdp_spec: CdpSpec<'a>,
    /// IS-IS (`isis`) specification.
    pub(crate) isis_spec: IsisSpec<'a>,
    /// MACsec (`macsec`) specification.
    pub(crate) macsec_spec: MacsecSpec,
    /// IEEE 802.1Qbb PFC (`pfc`) specification.
    pub(crate) pfc_spec: PfcSpec,
    /// PPPoE (`pppoe`) specification.
    pub(crate) pppoe_spec: PppoeSpec<'a>,
    /// Network Service Header (`nsh`) specification.
    pub(crate) nsh_spec: NshSpec,
    /// PROFINET IO (`profinet`) specification.
    pub(crate) profinet_spec: ProfinetSpec<'a>,
    /// IEC 61850 GOOSE (`goose`) specification.
    pub(crate) goose_spec: GooseSpec<'a>,
    /// IEC 61850 Sampled Values (`sv`) specification.
    pub(crate) sv_spec: SvSpec<'a>,
    /// EtherCAT (`ethercat`) specification.
    pub(crate) ethercat_spec: EthercatSpec<'a>,
    /// IP-in-IP (`ipip`) specification.
    pub(crate) ipip_spec: IpipSpec<'a>,
    /// Segment Routing over IPv6 (`srv6`) specification.
    pub(crate) srv6_spec: Srv6Spec<'a>,
    /// ERSPAN (`erspan`) specification.
    pub(crate) erspan_spec: ErspanSpec<'a>,
    /// RSVP / RSVP-TE (`rsvp`) specification.
    pub(crate) rsvp_spec: RsvpSpec<'a>,
    /// Label Distribution Protocol (`ldp`) specification.
    pub(crate) ldp_spec: LdpSpec<'a>,
    /// BGP Monitoring Protocol (`bmp`) specification.
    pub(crate) bmp_spec: BmpSpec<'a>,
    /// RPKI-to-Router (`rpkirtr`) specification.
    pub(crate) rpkirtr_spec: RpkirtrSpec<'a>,
    /// Layer 2 Tunneling Protocol (`l2tp`) specification.
    pub(crate) l2tp_spec: L2tpSpec<'a>,
    /// LISP (`lisp`) specification.
    pub(crate) lisp_spec: LispSpec<'a>,
    /// Cisco GLBP (`glbp`) specification.
    pub(crate) glbp_spec: GlbpSpec<'a>,
    /// GTPv1-U (`gtpu`) specification.
    pub(crate) gtpu_spec: GtpuSpec<'a>,
    /// DCE/RPC (`dcerpc`) specification.
    pub(crate) dcerpc_spec: DcerpcSpec<'a>,
    /// NTLM / HTTP-NTLM (`ntlm`) specification.
    pub(crate) ntlm_spec: NtlmSpec<'a>,
    /// RDP / X.224 (`rdp`) specification.
    pub(crate) rdp_spec: RdpSpec<'a>,
    /// LLMNR (`llmnr`) specification.
    pub(crate) llmnr_spec: LlmnrSpec<'a>,
    /// NetBIOS Name Service (`nbns`) specification.
    pub(crate) nbns_spec: NbnsSpec<'a>,
    /// SOCKS4/5 (`socks`) specification.
    pub(crate) socks_spec: SocksSpec<'a>,
    /// VNC / RFB (`vnc`) specification.
    pub(crate) vnc_spec: VncSpec<'a>,
    /// DNS over HTTPS (`doh`) specification.
    pub(crate) doh_spec: DohSpec<'a>,
    /// WS-Discovery (`wsdiscovery`) specification.
    pub(crate) wsdiscovery_spec: WsdiscoverySpec<'a>,
    /// IRC (`irc`) specification.
    pub(crate) irc_spec: IrcSpec<'a>,
    /// IEC 60870-5-104 (`iec104`) specification.
    pub(crate) iec104_spec: Iec104Spec<'a>,
    /// ISO 9506 / IEC 61850 MMS (`mms`) specification.
    pub(crate) mms_spec: MmsSpec<'a>,
    /// Siemens S7commPlus (`s7commplus`) specification.
    pub(crate) s7commplus_spec: S7commplusSpec<'a>,
    /// IEEE C37.118 Synchrophasor (`synchrophasor`) specification.
    pub(crate) synchrophasor_spec: SynchrophasorSpec<'a>,
    /// HART-IP (`hartip`) specification.
    pub(crate) hartip_spec: HartipSpec<'a>,
    /// Omron FINS (`fins`) specification.
    pub(crate) fins_spec: FinsSpec<'a>,
    /// Mitsubishi MELSEC MC (`melsec`) specification.
    pub(crate) melsec_spec: MelsecSpec<'a>,
    /// AUTOSAR SOME/IP (`someip`) specification.
    pub(crate) someip_spec: SomeipSpec<'a>,
    /// ISO 13400 DoIP (`doip`) specification.
    pub(crate) doip_spec: DoipSpec<'a>,
    /// ANSI C12.22 (`c1222`) specification.
    pub(crate) c1222_spec: C1222Spec<'a>,
    /// GE-SRTP (`gesrtp`) specification.
    pub(crate) gesrtp_spec: GesrtpSpec<'a>,
    /// Emerson ROC Plus (`rocplus`) specification.
    pub(crate) rocplus_spec: RocplusSpec<'a>,
    /// Bristol BSAP (`bsap`) specification.
    pub(crate) bsap_spec: BsapSpec<'a>,
    /// KNXnet/IP (`knxnetip`) specification.
    pub(crate) knxnetip_spec: KnxnetipSpec<'a>,
    /// RDMA over Converged Ethernet v2 (`rocev2`) specification.
    pub(crate) rocev2_spec: Rocev2Spec<'a>,
    /// IPMI / RMCP+ (`ipmi`) specification.
    pub(crate) ipmi_spec: IpmiSpec<'a>,
    /// TWAMP (`twamp`) specification.
    pub(crate) twamp_spec: TwampSpec<'a>,
    /// NETCONF (`netconf`) specification.
    pub(crate) netconf_spec: NetconfSpec<'a>,
    /// GTPv2-C (`gtpc`) specification.
    pub(crate) gtpc_spec: GtpcSpec<'a>,
    /// 5G PFCP (`pfcp`) specification.
    pub(crate) pfcp_spec: PfcpSpec<'a>,
    /// Diameter (`diameter`) specification.
    pub(crate) diameter_spec: DiameterSpec<'a>,
    /// 5G NGAP (`ngap`) specification.
    pub(crate) ngap_spec: NgapSpec<'a>,
    /// 4G S1AP (`s1ap`) specification.
    pub(crate) s1ap_spec: S1apSpec<'a>,
    /// Microsoft SQL Server TDS (`mssql`) specification.
    pub(crate) mssql_spec: MssqlSpec<'a>,
    /// Apache Kafka (`kafka`) specification.
    pub(crate) kafka_spec: KafkaSpec<'a>,
    /// MongoDB Wire (`mongodb`) specification.
    pub(crate) mongodb_spec: MongodbSpec<'a>,
    /// Oracle TNS (`tns`) specification.
    pub(crate) tns_spec: TnsSpec<'a>,
    /// iSCSI (`iscsi`) specification.
    pub(crate) iscsi_spec: IscsiSpec<'a>,
    /// NVMe/TCP (`nvmetcp`) specification.
    pub(crate) nvmetcp_spec: NvmetcpSpec<'a>,
    /// RTCP (`rtcp`) specification.
    pub(crate) rtcp_spec: RtcpSpec<'a>,
    /// TURN (`turn`) specification.
    pub(crate) turn_spec: TurnSpec<'a>,
    /// ITU-T H.323 (`h323`) specification.
    pub(crate) h323_spec: H323Spec<'a>,
    /// Cisco SCCP (`sccp`) specification.
    pub(crate) sccp_spec: SccpSpec<'a>,
    /// MGCP (`mgcp`) specification.
    pub(crate) mgcp_spec: MgcpSpec<'a>,
    /// Recorded duplicate modifiers and their source spans.
    pub(crate) duplicate_modifiers: Vec<(String, (usize, usize))>,
    /// Set of modifier keys already encountered in the statement.
    pub(crate) seen_modifier_keys: HashSet<&'static str>,
    /// Source span of GENTRAP modifier if present.
    pub(crate) gentrap_span: Option<(usize, usize)>,
    /// Recorded out-of-range numeric values `(label, value, min, max, span)`.
    pub(crate) raw_bounds: Vec<RawBoundEntry>,
    /// Deferred protocol-sensitive numeric checks `(key, value, span)` evaluated once `protocol` is finalized.
    pub(crate) deferred_u32_fields: Vec<(&'static str, u32, (usize, usize))>,
    /// Deferred protocol-sensitive `u64` checks `(key, value, span)` evaluated once `protocol` is finalized.
    pub(crate) deferred_u64_fields: Vec<(&'static str, u64, (usize, usize))>,
    /// Source span of a bare `nop` modifier if encountered.
    pub(crate) raw_nop_span: Option<(usize, usize)>,
    /// Source span of `qinq` modifier if encountered.
    pub(crate) raw_qinq_span: Option<(usize, usize)>,
    /// Source span of `innervlan` modifier if encountered.
    pub(crate) raw_inner_vlan_span: Option<(usize, usize)>,
    /// Source span of `pcp` modifier if encountered.
    pub(crate) raw_pcp_span: Option<(usize, usize)>,
    /// Source span of `dei` modifier if encountered.
    pub(crate) raw_dei_span: Option<(usize, usize)>,
    /// Source span of an orphan `exp`/`bos`/`mplsttl` modifier if encountered before `mpls`.
    pub(crate) raw_mpls_sub_span: Option<(usize, usize)>,
    /// Source span of `df` modifier if encountered.
    pub(crate) raw_df_span: Option<(usize, usize)>,
    /// Source span of `nochecksum` modifier if encountered.
    pub(crate) raw_no_checksum_span: Option<(usize, usize)>,
    /// Source span of `badipchecksum` modifier if encountered.
    pub(crate) raw_bad_ip_checksum_span: Option<(usize, usize)>,
    /// End byte offset of the statement.
    pub(crate) stmt_end_offset: usize,
}

/// Type alias for `Dnp3Spec`.
type DNP3SpecAlias<'a> = Dnp3Spec<'a>;

impl<'a> FrameBuilder<'a> {
    /// Creates a new `FrameBuilder` initialized at the given callee span end offset.
    pub(crate) fn new(callee_end: usize) -> Self {
        Self {
            protocol: None,
            flags: Vec::new(),
            seq: None,
            ack_num: None,
            win: None,
            payload: None,
            payload_bytes: None,
            hex_payload: None,
            comment: None,
            wait: None,
            src_port: None,
            dst_port: None,
            community: None,
            user: None,
            oid: None,
            sys_up_time: None,
            pdu_type: None,
            enterprise: None,
            agent_ip: None,
            gen_trap: None,
            spec_trap: None,
            engine_id: None,
            engine_boots: None,
            engine_time: None,
            context_name: None,
            auth: None,
            priv_param: None,
            varbinds: Vec::new(),
            non_repeaters: None,
            max_repetitions: None,
            req_id: None,
            vlan_val: None,
            dscp_val: None,
            ecn_val: None,
            ttl_val: None,
            flowlabel_val: None,
            pcp_val: None,
            dei_val: None,
            qinq_val: None,
            inner_vlan_val: None,
            mpls_entries: Vec::new(),
            fcs: false,
            bad_fcs: false,
            src_mac_val: None,
            dst_mac_val: None,
            ethertype_val: None,
            ipid_val: None,
            df_val: false,
            mf_val: false,
            frag_offset_val: None,
            router_alert: false,
            bad_ip_checksum: false,
            transport_val: None,
            bad_checksum: false,
            no_checksum: false,
            urgent_val: None,
            mss_val: None,
            wscale_val: None,
            sack_perm_val: false,
            sack_blocks: Vec::new(),
            tsval_val: None,
            tsecr_val: None,
            tcp_md5: None,
            tfo: None,
            vtag_val: None,
            stream_val: None,
            ssn_val: None,
            ppid_val: None,
            chunk_val: None,
            arp_opcode: None,
            is_gratuitous: false,
            sha: None,
            spa: None,
            tha: None,
            tpa: None,
            chassis_id: None,
            port_id_str: None,
            sysname: None,
            sysdesc: None,
            root_id: None,
            bridge_id: None,
            port_id_u16: None,
            stp_cost: None,
            max_age: None,
            hello_time: None,
            forward_delay: None,
            is_rstp: false,
            stp_flags: None,
            actor_sys: None,
            actor_key: None,
            actor_port: None,
            partner_sys: None,
            partner_key: None,
            partner_port: None,
            actor_state: None,
            partner_state: None,
            version_byte: None,
            eapol_type: None,
            eap_code: None,
            eap_id: None,
            eap_method: None,
            identity_str: None,
            icmp_type_choice: None,
            icmp_type_val: None,
            icmp_code_val: None,
            icmp_id_val: None,
            gateway_ip: None,
            ndp_type: None,
            target_ip: None,
            slla_mac: None,
            tlla_mac: None,
            router_lifetime: None,
            igmp_type: None,
            group_ip: None,
            max_resp: None,
            mld_type: None,
            multicast_addr: None,
            max_resp_delay: None,
            gre_key: None,
            gre_seq: None,
            gre_proto: None,
            gre_checksum: false,
            vni_val: None,
            opt_class: None,
            opt_type: None,
            protocol_type: None,
            spi_val: None,
            iv_val: None,
            icv_val: None,
            next_header_val: None,
            initiator_spi: None,
            responder_spi: None,
            ike_exchange: None,
            ike_msgid: None,
            ike_flags: None,
            next_payload: None,
            wireguard_type: None,
            wg_sender: None,
            wg_receiver: None,
            wg_counter: None,
            ospf_type: None,
            router_id_ip: None,
            area_id_val: None,
            hello_interval: None,
            dead_interval: None,
            priority_val: None,
            bgp_type: None,
            asn_val: None,
            holdtime_val: None,
            bgpid_ip: None,
            prefix_str: None,
            nexthop_ip: None,
            rip_cmd: None,
            rip_prefix: None,
            rip_metric: None,
            rip_tag: None,
            vrid_val: None,
            adv_int_val: None,
            vip_ip: None,
            hsrp_state: None,
            hsrp_group: None,
            hsrp_auth: None,
            hsrp_hellotime: None,
            raw_hellotime: None,
            pim_is_hello: false,
            pim_is_join_prune: false,
            pim_is_register: false,
            pim_source: None,
            pim_rp: None,
            pim_dr_priority: None,
            bfd_state: None,
            bfd_diag: None,
            bfd_my_disc: None,
            bfd_your_disc: None,
            bfd_min_tx: None,
            bfd_min_rx: None,
            bfd_mult: None,
            openflow_type: None,
            of_xid: None,
            of_dpid: None,
            of_table_id: None,
            of_priority: None,
            dns_spec: DnsSpec::default(),
            dhcp_spec: DhcpSpec::default(),
            ntp_spec: NtpSpec::default(),
            ptp_spec: PtpSpec::default(),
            radius_spec: RadiusSpec::default(),
            tacacs_spec: TacacsSpec::default(),
            syslog_spec: SyslogSpec::default(),
            netflow_spec: NetflowSpec::default(),
            ipfix_spec: IpfixSpec::default(),
            sflow_spec: SflowSpec::default(),
            tftp_spec: TftpSpec::default(),
            ftp_spec: FtpSpec::default(),
            ssh_spec: SshSpec::default(),
            telnet_spec: TelnetSpec::default(),
            http_spec: HttpSpec::default(),
            http2_spec: Http2Spec::default(),
            grpc_spec: GrpcSpec::default(),
            websocket_spec: WebsocketSpec::default(),
            tls_spec: TlsSpec::default(),
            quic_spec: QuicSpec::default(),
            stun_spec: StunSpec::default(),
            sip_spec: SipSpec::default(),
            rtp_spec: RtpSpec::default(),
            rtsp_spec: RtspSpec::default(),
            smtp_spec: SmtpSpec::default(),
            imap_spec: ImapSpec::default(),
            pop3_spec: Pop3Spec::default(),
            kerberos_spec: KerberosSpec::default(),
            ldap_spec: LdapSpec::default(),
            smb_spec: SmbSpec::default(),
            nfs_spec: NfsSpec::default(),
            redis_spec: RedisSpec::default(),
            memcached_spec: MemcachedSpec::default(),
            mysql_spec: MysqlSpec::default(),
            postgres_spec: PostgresSpec::default(),
            mqtt_spec: MqttSpec::default(),
            coap_spec: CoapSpec::default(),
            amqp_spec: AmqpSpec::default(),
            ssdp_spec: SsdpSpec::default(),
            whois_spec: WhoisSpec::default(),
            modbus_spec: ModbusSpec::default(),
            bacnet_spec: BacnetSpec::default(),
            dnp3_spec: Dnp3Spec::default(),
            s7comm_spec: S7commSpec::default(),
            ethernetip_spec: EthernetipSpec::default(),
            opcua_spec: OpcuaSpec::default(),
            cdp_spec: CdpSpec::default(),
            isis_spec: IsisSpec::default(),
            macsec_spec: MacsecSpec::default(),
            pfc_spec: PfcSpec::default(),
            pppoe_spec: PppoeSpec::default(),
            nsh_spec: NshSpec::default(),
            profinet_spec: ProfinetSpec::default(),
            goose_spec: GooseSpec::default(),
            sv_spec: SvSpec::default(),
            ethercat_spec: EthercatSpec::default(),
            ipip_spec: IpipSpec::default(),
            srv6_spec: Srv6Spec::default(),
            erspan_spec: ErspanSpec::default(),
            rsvp_spec: RsvpSpec::default(),
            ldp_spec: LdpSpec::default(),
            bmp_spec: BmpSpec::default(),
            rpkirtr_spec: RpkirtrSpec::default(),
            l2tp_spec: L2tpSpec::default(),
            lisp_spec: LispSpec::default(),
            glbp_spec: GlbpSpec::default(),
            gtpu_spec: GtpuSpec::default(),
            dcerpc_spec: DcerpcSpec::default(),
            ntlm_spec: NtlmSpec::default(),
            rdp_spec: RdpSpec::default(),
            llmnr_spec: LlmnrSpec::default(),
            nbns_spec: NbnsSpec::default(),
            socks_spec: SocksSpec::default(),
            vnc_spec: VncSpec::default(),
            doh_spec: DohSpec::default(),
            wsdiscovery_spec: WsdiscoverySpec::default(),
            irc_spec: IrcSpec::default(),
            iec104_spec: Iec104Spec::default(),
            mms_spec: MmsSpec::default(),
            s7commplus_spec: S7commplusSpec::default(),
            synchrophasor_spec: SynchrophasorSpec::default(),
            hartip_spec: HartipSpec::default(),
            fins_spec: FinsSpec::default(),
            melsec_spec: MelsecSpec::default(),
            someip_spec: SomeipSpec::default(),
            doip_spec: DoipSpec::default(),
            c1222_spec: C1222Spec::default(),
            gesrtp_spec: GesrtpSpec::default(),
            rocplus_spec: RocplusSpec::default(),
            bsap_spec: BsapSpec::default(),
            knxnetip_spec: KnxnetipSpec::default(),
            rocev2_spec: Rocev2Spec::default(),
            ipmi_spec: IpmiSpec::default(),
            twamp_spec: TwampSpec::default(),
            netconf_spec: NetconfSpec::default(),
            gtpc_spec: GtpcSpec::default(),
            pfcp_spec: PfcpSpec::default(),
            diameter_spec: DiameterSpec::default(),
            ngap_spec: NgapSpec::default(),
            s1ap_spec: S1apSpec::default(),
            mssql_spec: MssqlSpec::default(),
            kafka_spec: KafkaSpec::default(),
            mongodb_spec: MongodbSpec::default(),
            tns_spec: TnsSpec::default(),
            iscsi_spec: IscsiSpec::default(),
            nvmetcp_spec: NvmetcpSpec::default(),
            rtcp_spec: RtcpSpec::default(),
            turn_spec: TurnSpec::default(),
            h323_spec: H323Spec::default(),
            sccp_spec: SccpSpec::default(),
            mgcp_spec: MgcpSpec::default(),
            duplicate_modifiers: Vec::new(),
            seen_modifier_keys: HashSet::new(),
            gentrap_span: None,
            raw_bounds: Vec::new(),
            deferred_u32_fields: Vec::new(),
            deferred_u64_fields: Vec::new(),
            raw_nop_span: None,
            raw_qinq_span: None,
            raw_inner_vlan_span: None,
            raw_pcp_span: None,
            raw_dei_span: None,
            raw_mpls_sub_span: None,
            raw_df_span: None,
            raw_no_checksum_span: None,
            raw_bad_ip_checksum_span: None,
            stmt_end_offset: callee_end,
        }
    }

    /// Records a modifier key and tracks duplicates for semantic validation.
    pub(crate) fn record_mod(&mut self, key: &'static str, span: (usize, usize)) {
        if key != "ARGS" && !self.seen_modifier_keys.insert(key) {
            self.duplicate_modifiers.push((key.to_string(), span));
        }
    }

    /// Records a modifier key, tracks duplicates, and advances `stmt_end_offset`.
    pub(crate) fn touch_mod(&mut self, key: &'static str, span: (usize, usize)) {
        self.record_mod(key, span);
        self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
    }

    /// Records an out-of-range numeric field violation if `val < min || val > max`.
    pub(crate) fn check_bound(
        &mut self,
        label: &'static str,
        val: u64,
        min: u64,
        max: u64,
        span: (usize, usize),
    ) {
        if val < min || val > max {
            self.raw_bounds.push((label, val, min, max, span));
        }
    }
}

/// Parses a single frame statement within a flow using protocol-scoped field dispatch.
pub(crate) fn parse_frame_statement<'i, 'a>(
    input: &mut Stream<'i, 'a>,
) -> PResult<FrameStatement<'a>> {
    let stmt_start_input = *input;
    let caller = parse_spanned_ident(input)?;
    let dir = parse_direction(input)?;

    // Commit to frame statement parsing once arrow is encountered
    let callee = cut_err(parse_spanned_ident).parse_next(input)?;

    let mut parsed_fields: Vec<ParsedField<'a>> = Vec::new();
    let mut current_protocol: Option<Protocol> = None;
    let mut last_end: usize = callee.span.0 + callee.span.1;

    while !input.is_empty() {
        // Stop if we reached the closing brace of the flow/compile/repeat block or the start of the next statement
        if matches!(input[0].0, Token::RBrace | Token::Repeat)
            || (input.len() >= 2 && matches!(input[1].0, Token::RightArrow | Token::LeftArrow))
            || (input.len() >= 2 && matches!(input[1].0, Token::LParen))
        {
            break;
        }

        let saved = *input;
        let advance_end = |before: &Stream<'i, 'a>, after: &Stream<'i, 'a>, end_ref: &mut usize| {
            let consumed = before.len().saturating_sub(after.len());
            if consumed > 0 {
                *end_ref = (*end_ref).max(before[consumed - 1].1.end);
            }
        };

        // 1. Try universal modifiers (wait, payload, hexpayload, comment, L2/L3/L4 header fields)
        match parse_universal_field(input, current_protocol.as_ref()) {
            Ok(field) => {
                advance_end(&saved, input, &mut last_end);
                if let ParsedField::Protocol(ref p, _) = field {
                    current_protocol = Some(p.clone());
                }
                parsed_fields.push(field);
                continue;
            }
            Err(ErrMode::Cut(e)) => return Err(ErrMode::Cut(e)),
            Err(_) => {
                *input = saved;
            }
        }

        // 2. Fail-closed post-protocol dispatch: once a protocol keyword is active, ONLY
        //    universal modifiers, that active protocol's fields, or another explicit protocol
        //    keyword (flagged as Multiple protocols in semantic validation) are permitted.
        if let Some(ref proto) = current_protocol {
            match dispatch_protocol_field(proto, input) {
                Ok(field) => {
                    advance_end(&saved, input, &mut last_end);
                    if let ParsedField::Protocol(ref p, _) = field {
                        current_protocol = Some(p.clone());
                    }
                    parsed_fields.push(field);
                    continue;
                }
                Err(ErrMode::Cut(e)) => return Err(ErrMode::Cut(e)),
                Err(_) => {
                    *input = saved;
                }
            }

            match parse_protocol_keyword(input) {
                Ok(field) => {
                    advance_end(&saved, input, &mut last_end);
                    if let ParsedField::Protocol(ref p, _) = field {
                        current_protocol = Some(p.clone());
                    }
                    parsed_fields.push(field);
                    continue;
                }
                Err(ErrMode::Cut(e)) => return Err(ErrMode::Cut(e)),
                Err(_) => {
                    *input = saved;
                    return Err(ErrMode::Cut(winnow::error::ContextError::new()));
                }
            }
        }

        // 3. Before any protocol keyword is active, try explicit protocol keywords first
        //    (preventing `bacnet` `whois` from shadowing `whois`), then pre-protocol fields.
        match parse_protocol_keyword(input) {
            Ok(field) => {
                advance_end(&saved, input, &mut last_end);
                if let ParsedField::Protocol(ref p, _) = field {
                    current_protocol = Some(p.clone());
                }
                parsed_fields.push(field);
                continue;
            }
            Err(ErrMode::Cut(e)) => return Err(ErrMode::Cut(e)),
            Err(_) => {
                *input = saved;
            }
        }

        match parse_fallback_field(input) {
            Ok(field) => {
                advance_end(&saved, input, &mut last_end);
                if let ParsedField::Protocol(ref p, _) = field {
                    current_protocol = Some(p.clone());
                }
                parsed_fields.push(field);
                continue;
            }
            Err(ErrMode::Cut(e)) => return Err(ErrMode::Cut(e)),
            Err(_) => {
                *input = saved;
                break;
            }
        }
    }

    let mut builder = FrameBuilder::new(last_end);
    for f in &parsed_fields {
        builder.apply_field(f);
    }

    let stopped_at_stmt_boundary = input.is_empty()
        || matches!(input[0].0, Token::RBrace | Token::Repeat)
        || (input.len() >= 2
            && matches!(
                input[1].0,
                Token::RightArrow | Token::LeftArrow | Token::LParen
            ));
    if stopped_at_stmt_boundary && !builder.has_explicit_protocol() {
        *input = stmt_start_input;
        return Err(ErrMode::Cut(winnow::error::ContextError::new()));
    }

    Ok(builder.finish(caller, dir, callee))
}
