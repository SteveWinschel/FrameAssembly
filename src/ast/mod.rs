//! Abstract Syntax Tree (AST) Definitions for the FrameAssembly Compiler.
//!
//! This module hierarchy defines the complete intermediate representation for parsed `.fasm`
//! protocol specification programs, including [`HostDef`] endpoint declarations, parameterized
//! [`FlowDef`] templates, [`FrameStatement`] protocol specifications, [`Protocol`] discriminators,
//! and [`Program`] execution blocks. Layer-specific specifications and header modifiers are
//! organized into dedicated submodules across OSI Layer 2 ([`l2`]), Layer 3 ([`l3`]), Layer 4
//! ([`l4`]), and Layer 7 ([`l7`]), and re-exported with `#[doc(inline)]` at the crate AST root.

use alloc::string::String;
use alloc::vec::Vec;
use core::net::IpAddr;

pub mod l2;
pub mod l3;
pub mod l4;
pub mod l7;

/// SNMP protocol specifications and variable bindings (backwards-compatible alias for [`l7::snmp`]).
pub mod snmp {
    #[doc(inline)]
    pub use super::l7::snmp::*;
}

#[doc(inline)]
pub use l2::*;
#[doc(inline)]
pub use l3::*;
#[doc(inline)]
pub use l4::*;
#[doc(inline)]
pub use l7::*;

/// Type alias for standard IP address representation.
pub type IpAddress = core::net::IpAddr;

/// An AST node paired with its source byte span `(start, length)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Spanned<T> {
    /// The inner node value.
    pub node: T,
    /// Source code span as `(start_offset, length)`.
    pub span: (usize, usize),
}

impl<T> Spanned<T> {
    /// Constructs a new spanned AST node.
    pub fn new(node: T, span: (usize, usize)) -> Self {
        Self { node, span }
    }
}

impl<T> core::ops::Deref for Spanned<T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        &self.node
    }
}

/// A host definition with an IP and optional MAC address.
///
/// Syntax mapping: `HOST <name> { IP <ip_addr> [MAC <mac_addr>] }`
///
/// # Examples
/// ```frameassembly
/// // PROMPT: Declare IPv4 endpoints with explicit MAC addresses and execute an ICMP Echo Request.
/// // TOKENS: HOST, IP, MAC, FLOW, ICMP, ECHO_REQUEST, COMPILE
/// // INSTRUCTION: Declare two IPv4 hosts.
/// HOST client { IP 10.0.0.1 MAC 00:11:22:33:44:55 }
/// HOST server { IP 10.0.0.2 MAC 00:aa:bb:cc:dd:ee }
/// // INSTRUCTION: Define a minimal ICMP flow.
/// FLOW ping(a, b) {
///     a -> b ICMP ECHO_REQUEST
/// }
/// // INSTRUCTION: Compile the flow.
/// COMPILE {
///     ping(client, server)
/// }
/// ```
#[doc(alias = "HOST")]
#[doc(alias = "IP")]
#[doc(alias = "MAC")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostDef<'a> {
    /// The name of the host.
    pub name: &'a str,
    /// The IP address of the host.
    pub ip: IpAddr,
    /// The optional MAC address of the host.
    pub mac: Option<[u8; 6]>,
    /// Source span of the host definition.
    pub span: (usize, usize),
}

/// The direction of the packet in a template statement.
///
/// # Examples
/// ```rust
/// use frameassembly::ast::Direction;
/// let dir = Direction::LeftToRight;
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Left-to-right packet direction (`->` operator).
    LeftToRight, // ->
    /// Right-to-left packet direction (`<-` operator).
    RightToLeft, // <-
}

/// Type alias for Direction.
pub type ArrowDirection = Direction;

/// Represents the supported network protocols.
///
/// # Examples
/// ```rust
/// use frameassembly::ast::Protocol;
/// let proto = Protocol::Tcp;
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Protocol {
    /// Transmission Control Protocol (RFC 9293)
    Tcp,
    /// User Datagram Protocol (RFC 768)
    Udp,
    /// Stream Control Transmission Protocol (RFC 9260)
    Sctp,
    /// Simple Network Management Protocol v1 (RFC 1157)
    Snmp1,
    /// Simple Network Management Protocol v2c (RFC 3416)
    Snmp2,
    /// Simple Network Management Protocol v3 (RFC 3411)
    Snmp3,
    /// Address Resolution Protocol (RFC 826)
    Arp,
    /// IEEE 802.1Q Virtual Local Area Network
    Vlan,
    /// IEEE 802.1ad Provider Bridging (QinQ)
    Qinq,
    /// IEEE 802.1AB Link Layer Discovery Protocol
    Lldp,
    /// IEEE 802.1D / IEEE 802.1w Spanning Tree Protocol
    Stp,
    /// IEEE 802.3ad / IEEE 802.1AX Link Aggregation Control Protocol
    Lacp,
    /// IEEE 802.1X Port-Based Network Access Control
    Eapol,
    /// RFC 3032 Multi-Protocol Label Switching
    Mpls,
    /// RFC 792 / RFC 4443 Internet Control Message Protocol (v4/v6)
    Icmp,
    /// RFC 4861 IPv6 Neighbor Discovery Protocol
    Ndp,
    /// RFC 2236 / RFC 3376 Internet Group Management Protocol
    Igmp,
    /// RFC 2710 / RFC 3810 Multicast Listener Discovery
    Mld,
    /// RFC 2784 / RFC 2890 Generic Routing Encapsulation
    Gre,
    /// RFC 7348 Virtual eXtensible Local Area Network
    Vxlan,
    /// RFC 8926 Generic Network Virtualization Encapsulation
    Geneve,
    /// RFC 4301 / RFC 4303 IP Security Architecture (ESP encapsulation)
    Ipsec,
    /// RFC 4303 IP Encapsulating Security Payload
    Esp,
    /// RFC 4302 IP Authentication Header
    Ah,
    /// RFC 7296 Internet Key Exchange Protocol Version 2
    Ikev2,
    /// WireGuard Secure Network Tunnel Protocol
    Wireguard,
    /// RFC 2328 / RFC 5340 Open Shortest Path First
    Ospf,
    /// RFC 4271 Border Gateway Protocol 4
    Bgp,
    /// RFC 2453 / RFC 2080 Routing Information Protocol
    Rip,
    /// RFC 5798 Virtual Router Redundancy Protocol
    Vrrp,
    /// RFC 2281 Cisco Hot Standby Router Protocol
    Hsrp,
    /// RFC 7761 Protocol Independent Multicast - Sparse Mode
    Pim,
    /// RFC 5880 Bidirectional Forwarding Detection
    Bfd,
    /// OpenFlow Switch Specification
    Openflow,
    /// RFC 1035 Domain Name System
    Dns,
    /// RFC 6762 Multicast DNS
    Mdns,
    /// RFC 2131 / RFC 8415 Dynamic Host Configuration Protocol
    Dhcp,
    /// RFC 5905 Network Time Protocol
    Ntp,
    /// IEEE 1588v2 Precision Time Protocol
    Ptp,
    /// RFC 2865 Remote Authentication Dial-In User Service
    Radius,
    /// RFC 8907 Terminal Access Controller Access-Control System Plus
    Tacacs,
    /// RFC 5424 The Syslog Protocol
    Syslog,
    /// Cisco NetFlow v5/v9 Flow Export
    Netflow,
    /// RFC 7011 IP Flow Information Export
    Ipfix,
    /// sFlow v5 Network Sampling Datagram
    Sflow,
    /// RFC 1350 Trivial File Transfer Protocol
    Tftp,
    /// RFC 959 File Transfer Protocol
    Ftp,
    /// RFC 4253 Secure Shell Protocol
    Ssh,
    /// RFC 854 Telnet Protocol
    Telnet,
    /// RFC 9110 Hypertext Transfer Protocol
    Http,
    /// RFC 9113 HTTP/2 Framing
    Http2,
    /// gRPC Remote Procedure Calls
    Grpc,
    /// RFC 6455 The WebSocket Protocol
    Websocket,
    /// RFC 8446 Transport Layer Security
    Tls,
    /// RFC 9000 QUIC Transport Protocol
    Quic,
    /// RFC 8489 Session Traversal Utilities for NAT
    Stun,
    /// RFC 3261 Session Initiation Protocol
    Sip,
    /// RFC 3550 Real-time Transport Protocol
    Rtp,
    /// RFC 7826 Real-Time Streaming Protocol
    Rtsp,
    /// RFC 5321 Simple Mail Transfer Protocol
    Smtp,
    /// RFC 9051 Internet Message Access Protocol
    Imap,
    /// RFC 1939 Post Office Protocol version 3
    Pop3,
    /// RFC 4120 Kerberos Network Authentication Service
    Kerberos,
    /// RFC 4511 Lightweight Directory Access Protocol
    Ldap,
    /// Server Message Block Protocol
    Smb,
    /// RFC 7530 / RFC 8881 Network File System
    Nfs,
    /// Redis Serialization Protocol
    Redis,
    /// Memcached Memory Caching Protocol
    Memcached,
    /// MySQL Client/Server Protocol
    Mysql,
    /// PostgreSQL Frontend/Backend Protocol
    Postgres,
    /// MQ Telemetry Transport
    Mqtt,
    /// RFC 7252 Constrained Application Protocol
    Coap,
    /// Advanced Message Queuing Protocol 0-9-1
    Amqp,
    /// Simple Service Discovery Protocol
    Ssdp,
    /// RFC 3912 WHOIS Protocol
    Whois,
    /// Modbus Application Protocol
    Modbus,
    /// ANSI/ASHRAE 135 BACnet Building Automation Protocol
    Bacnet,
    /// IEEE 1815-2012 Distributed Network Protocol
    Dnp3,
    /// Siemens S7 Communication on ISO-on-TCP
    S7comm,
    /// ODVA EtherNet/IP & CIP Protocol
    Ethernetip,
    /// OPC Unified Architecture Binary Protocol
    Opcua,
}

/// Protocol specification holding protocol-specific fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtocolSpec<'a> {
    /// TCP protocol.
    Tcp,
    /// UDP protocol.
    Udp,
    /// SCTP transport parameters.
    Sctp(SctpParams),
    /// SNMPv1 protocol.
    Snmp1(Snmp1Spec<'a>),
    /// SNMPv2c protocol.
    Snmp2(Snmp2Spec<'a>),
    /// SNMPv3 protocol.
    Snmp3(Snmp3Spec<'a>),
    /// Address Resolution Protocol.
    Arp(ArpSpec<'a>),
    /// IEEE 802.1Q VLAN specification.
    Vlan(VlanSpec),
    /// IEEE 802.1ad QinQ specification.
    Qinq(QinqSpec),
    /// IEEE 802.1AB Link Layer Discovery Protocol.
    Lldp(LldpSpec<'a>),
    /// IEEE 802.1D Spanning Tree Protocol BPDU.
    Stp(StpSpec<'a>),
    /// IEEE 802.3ad Link Aggregation Control Protocol.
    Lacp(LacpSpec<'a>),
    /// IEEE 802.1X EAPOL protocol.
    Eapol(EapolSpec<'a>),
    /// RFC 3032 MPLS label stack.
    Mpls(MplsSpec),
    /// RFC 792 / RFC 4443 ICMP protocol.
    Icmp(IcmpSpec<'a>),
    /// RFC 4861 NDP protocol.
    Ndp(NdpSpec<'a>),
    /// RFC 2236 / RFC 3376 IGMP protocol.
    Igmp(IgmpSpec<'a>),
    /// RFC 2710 / RFC 3810 MLD protocol.
    Mld(MldSpec<'a>),
    /// RFC 2784 GRE protocol.
    Gre(GreSpec<'a>),
    /// RFC 7348 VXLAN protocol.
    Vxlan(VxlanSpec<'a>),
    /// RFC 8926 GENEVE protocol.
    Geneve(GeneveSpec<'a>),
    /// RFC 4303 IPsec ESP protocol.
    Ipsec(IpsecSpec<'a>),
    /// RFC 4303 ESP protocol alias.
    Esp(IpsecSpec<'a>),
    /// RFC 4302 IPsec AH protocol.
    Ah(AhSpec<'a>),
    /// RFC 7296 IKEv2 protocol.
    Ikev2(Ikev2Spec<'a>),
    /// WireGuard VPN protocol.
    Wireguard(WireguardSpec<'a>),
    /// RFC 2328 / RFC 5340 OSPF protocol.
    Ospf(OspfSpec<'a>),
    /// RFC 4271 BGP protocol.
    Bgp(BgpSpec<'a>),
    /// RFC 2453 / RFC 2080 RIP protocol.
    Rip(RipSpec<'a>),
    /// RFC 5798 VRRP protocol.
    Vrrp(VrrpSpec<'a>),
    /// RFC 2281 HSRP protocol.
    Hsrp(HsrpSpec<'a>),
    /// RFC 7761 PIM protocol.
    Pim(PimSpec<'a>),
    /// RFC 5880 BFD protocol.
    Bfd(BfdSpec<'a>),
    /// OpenFlow protocol.
    Openflow(OpenflowSpec<'a>),
    /// RFC 1035 DNS protocol.
    Dns(DnsSpec<'a>),
    /// RFC 6762 mDNS protocol.
    Mdns(DnsSpec<'a>),
    /// DHCP protocol.
    Dhcp(DhcpSpec<'a>),
    /// RFC 5905 NTP protocol.
    Ntp(NtpSpec<'a>),
    /// IEEE 1588 PTP protocol.
    Ptp(PtpSpec<'a>),
    /// RFC 2865 RADIUS protocol.
    Radius(RadiusSpec<'a>),
    /// RFC 8907 TACACS+ protocol.
    Tacacs(TacacsSpec<'a>),
    /// RFC 5424 Syslog protocol.
    Syslog(SyslogSpec<'a>),
    /// NetFlow v5/v9 protocol.
    Netflow(NetflowSpec<'a>),
    /// RFC 7011 IPFIX protocol.
    Ipfix(IpfixSpec<'a>),
    /// sFlow v5 protocol.
    Sflow(SflowSpec<'a>),
    /// RFC 1350 TFTP protocol.
    Tftp(TftpSpec<'a>),
    /// RFC 959 FTP protocol.
    Ftp(FtpSpec<'a>),
    /// RFC 4253 SSH protocol.
    Ssh(SshSpec<'a>),
    /// RFC 854 Telnet protocol.
    Telnet(TelnetSpec<'a>),
    /// RFC 9110 HTTP protocol.
    Http(HttpSpec<'a>),
    /// RFC 9113 HTTP/2 protocol.
    Http2(Http2Spec<'a>),
    /// gRPC protocol.
    Grpc(GrpcSpec<'a>),
    /// RFC 6455 WebSocket protocol.
    Websocket(WebsocketSpec<'a>),
    /// RFC 8446 TLS protocol.
    Tls(TlsSpec<'a>),
    /// RFC 9000 QUIC protocol.
    Quic(QuicSpec<'a>),
    /// RFC 8489 STUN protocol.
    Stun(StunSpec<'a>),
    /// RFC 3261 SIP protocol.
    Sip(SipSpec<'a>),
    /// RFC 3550 RTP protocol.
    Rtp(RtpSpec<'a>),
    /// RFC 7826 RTSP protocol.
    Rtsp(RtspSpec<'a>),
    /// RFC 5321 SMTP protocol.
    Smtp(SmtpSpec<'a>),
    /// RFC 9051 IMAP protocol.
    Imap(ImapSpec<'a>),
    /// RFC 1939 POP3 protocol.
    Pop3(Pop3Spec<'a>),
    /// RFC 4120 Kerberos protocol.
    Kerberos(KerberosSpec<'a>),
    /// RFC 4511 LDAP protocol.
    Ldap(LdapSpec<'a>),
    /// SMB2/3 protocol.
    Smb(SmbSpec<'a>),
    /// RFC 7530 NFS protocol.
    Nfs(NfsSpec<'a>),
    /// Redis RESP protocol.
    Redis(RedisSpec<'a>),
    /// Memcached protocol.
    Memcached(MemcachedSpec<'a>),
    /// MySQL protocol.
    Mysql(MysqlSpec<'a>),
    /// PostgreSQL protocol.
    Postgres(PostgresSpec<'a>),
    /// MQTT protocol.
    Mqtt(MqttSpec<'a>),
    /// RFC 7252 CoAP protocol.
    Coap(CoapSpec<'a>),
    /// AMQP 0-9-1 protocol.
    Amqp(AmqpSpec<'a>),
    /// SSDP protocol.
    Ssdp(SsdpSpec<'a>),
    /// RFC 3912 WHOIS protocol.
    Whois(WhoisSpec<'a>),
    /// Modbus protocol.
    Modbus(ModbusSpec<'a>),
    /// BACnet/IP protocol.
    Bacnet(BacnetSpec<'a>),
    /// IEEE 1815 DNP3 protocol.
    Dnp3(Dnp3Spec<'a>),
    /// Siemens S7comm protocol.
    S7comm(S7commSpec<'a>),
    /// ODVA EtherNet/IP protocol.
    Ethernetip(EthernetipSpec<'a>),
    /// OPC UA protocol.
    Opcua(OpcuaSpec<'a>),
    /// Raw payload.
    Raw(Vec<u8>),
}

/// A single frame statement inside a flow.
///
/// Syntax mapping: `<caller> ->|<- <callee> [L2/L3/L4 modifiers] <Protocol> [ProtocolSpec] [WAIT <duration>]`
///
/// # Examples
/// ```text
/// client -> server TCP SYN ACK PAYLOAD "World" WAIT 10ms
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrameStatement<'a> {
    /// The caller (source) identifier with span.
    pub caller: Spanned<&'a str>,
    /// The direction of the packet.
    pub dir: Direction,
    /// Alias for direction matching the layered contract.
    pub arrow: ArrowDirection,
    /// The callee (destination) identifier with span.
    pub callee: Spanned<&'a str>,
    /// The protocol used.
    pub protocol: Protocol,
    /// Optional protocol-specific scoped details.
    pub protocol_spec: Option<ProtocolSpec<'a>>,
    /// Layer 2 modifiers.
    pub l2: L2Modifiers,
    /// Layer 3 modifiers.
    pub l3: L3Modifiers,
    /// Layer 4 modifiers.
    pub l4: L4Modifiers,
    /// Optional string payload.
    pub payload: Option<String>,
    /// Optional raw binary hex payload.
    pub hex_payload: Option<Vec<u8>>,
    /// Optional wait time before sending the packet (in nanoseconds).
    pub wait: Option<u64>,
    /// Source span of this statement.
    pub span: (usize, usize),
    /// Raw parsed VLAN ID and span for semantic range validation.
    pub raw_vlan: Option<(u32, (usize, usize))>,
    /// Raw parsed DSCP and span for semantic range validation.
    pub raw_dscp: Option<(u32, (usize, usize))>,
    /// Raw parsed ECN and span for semantic range validation.
    pub raw_ecn: Option<(u32, (usize, usize))>,
    /// Raw parsed TTL and span for semantic range validation.
    pub raw_ttl: Option<(u32, (usize, usize))>,
    /// Raw parsed FLOWLABEL and span for semantic range validation.
    pub raw_flowlabel: Option<(u32, (usize, usize))>,
    /// Raw parsed GENTRAP span for semantic range validation.
    pub raw_gentrap_span: Option<(usize, usize)>,
    /// Any duplicate statement modifiers detected during parsing.
    pub duplicate_modifiers: Vec<(String, (usize, usize))>,

    // Flat compatibility fields for snmp_builder and backend
    /// Optional source port.
    pub src_port: Option<u16>,
    /// Optional destination port.
    pub dst_port: Option<u16>,
    /// TCP flags.
    pub flags: Vec<TcpFlag>,
    /// Optional TCP sequence number.
    pub seq: Option<u32>,
    /// Optional TCP acknowledgment number.
    pub ack_num: Option<u32>,
    /// Optional TCP window size.
    pub win: Option<u16>,
    /// Optional TCP urgent pointer.
    pub urgent: Option<u16>,
    /// Optional SNMP community string.
    pub community: Option<&'a str>,
    /// Optional SNMP user.
    pub user: Option<&'a str>,
    /// Optional SNMP OID.
    pub oid: Option<&'a str>,
    /// Optional SNMP system uptime.
    pub sys_up_time: Option<u32>,
    /// PDU Type.
    pub pdu_type: Option<SnmpPduType>,
    /// Optional enterprise OID for v1 traps.
    pub enterprise: Option<&'a str>,
    /// Optional agent IP for v1 traps.
    pub agent_ip: Option<IpAddr>,
    /// Optional generic trap for v1 traps.
    pub gen_trap: Option<u32>,
    /// Optional specific trap for v1 traps.
    pub spec_trap: Option<u32>,
    /// Optional engine ID for v3.
    pub engine_id: Option<&'a str>,
    /// Optional engine boots for v3.
    pub engine_boots: Option<u32>,
    /// Optional engine time for v3.
    pub engine_time: Option<u32>,
    /// Optional context name for v3.
    pub context_name: Option<&'a str>,
    /// Optional auth params for v3.
    pub auth: Option<(SnmpAuthType, &'a str)>,
    /// Optional priv params for v3.
    pub priv_param: Option<(SnmpPrivType, &'a str)>,
    /// List of variable bindings.
    pub varbinds: Vec<VarBindAst<'a>>,
    /// Optional Non-Repeaters for GETBULK.
    pub non_repeaters: Option<u32>,
    /// Optional Max-Repetitions for GETBULK.
    pub max_repetitions: Option<u32>,
    /// Optional Request ID.
    pub req_id: Option<u32>,
}

impl<'a> FrameStatement<'a> {
    /// Returns the effective payload bytes for this frame statement.
    ///
    /// Prioritizes `hex_payload` if present, falling back to UTF-8 bytes of `payload`.
    pub fn effective_payload(&self) -> Option<&[u8]> {
        if let Some(hex) = &self.hex_payload {
            Some(hex.as_slice())
        } else {
            self.payload.as_deref().map(str::as_bytes)
        }
    }
}

/// A flow definition in the form `FLOW name(arg1, arg2) { statements }`
///
/// Syntax mapping: `FLOW <name>(<param1>, <param2>) { <statements> }`
///
/// # Examples
/// ```text
/// FLOW name(arg1, arg2) {
///     arg1 -> arg2 TCP SYN
/// }
/// ```
#[doc(alias = "FLOW")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowDef<'a> {
    /// The name of the flow.
    pub name: &'a str,
    /// The parameters of the flow.
    pub params: Vec<&'a str>,
    /// The statements inside the flow.
    pub statements: Vec<FrameStatement<'a>>,
    /// Source span of this flow definition.
    pub span: (usize, usize),
}

/// An argument passed to a flow invocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Argument<'a> {
    /// A simple variable reference, e.g., `my_client`
    Variable(&'a str),
}

/// A flow invocation, e.g., `tcp_handshake(my_client, google_dns)`
///
/// # Examples
/// ```rust
/// use frameassembly::ast::{TemplateInvocation, Argument};
/// let inv = TemplateInvocation { name: "handshake", args: vec![], span: (0, 0) };
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TemplateInvocation<'a> {
    /// The name of the flow being invoked.
    pub name: &'a str,
    /// The arguments passed to the flow.
    pub args: Vec<Argument<'a>>,
    /// Source span of the invocation.
    pub span: (usize, usize),
}

/// A statement in the run/compile block, can be a loop or a single invocation
#[doc(alias = "COMPILE")]
#[doc(alias = "LOOP")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RunStatement<'a> {
    /// A single template invocation directly in the block
    Invocation(TemplateInvocation<'a>),
    /// A loop block containing a count and inner invocations
    Loop(u32, Vec<TemplateInvocation<'a>>),
}

/// The root of the AST containing all assignments, flows, and the compile block.
///
/// # Examples
/// ```rust
/// use frameassembly::ast::Program;
/// let prog = Program { hosts: vec![], flows: vec![], compile_block: vec![] };
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Program<'a> {
    /// The list of host definitions.
    pub hosts: Vec<HostDef<'a>>,
    /// The list of flow definitions.
    pub flows: Vec<FlowDef<'a>>,
    /// The list of statements in the compile block.
    pub compile_block: Vec<RunStatement<'a>>,
}
