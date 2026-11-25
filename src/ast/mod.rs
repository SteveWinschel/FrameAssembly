//! Abstract Syntax Tree (AST) Definitions for the FrameAssembly Compiler.
//!
//! This module hierarchy defines the complete intermediate representation for parsed `.frasm`
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

/// A host definition with an optional IP and optional MAC address.
///
/// Syntax mapping: `host <name> { [ip <ip_addr>] [mac <mac_addr>] }`
///
/// # Examples
/// ```frameassembly
/// // PROMPT: Declare IPv4 endpoints with explicit MAC addresses and execute an ICMP Echo Request.
/// // TOKENS: host, ip, mac, flow, icmp, echorequest, compile
/// // INSTRUCTION: Declare two IPv4 hosts.
/// host client { ip 10.0.0.1 mac 00:11:22:33:44:55 }
/// host server { ip 10.0.0.2 mac 00:aa:bb:cc:dd:ee }
/// // INSTRUCTION: Define a minimal ICMP flow.
/// flow ping(a, b) {
///     a -> b icmp echorequest
/// }
/// // INSTRUCTION: Compile the flow.
/// compile {
///     ping(client, server)
/// }
/// ```
#[doc(alias = "host")]
#[doc(alias = "ip")]
#[doc(alias = "mac")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostDef<'a> {
    /// The name of the host.
    pub name: &'a str,
    /// The optional IP address of the host (omitted for pure Layer 2 MAC-only endpoints).
    pub ip: Option<IpAddr>,
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
    /// Cisco Discovery Protocol v2 (802.3 LLC/SNAP)
    Cdp,
    /// ISO/IEC 10589 Intermediate System to Intermediate System
    Isis,
    /// IEEE 802.1AE Media Access Control Security
    Macsec,
    /// IEEE 802.1Qbb Priority-based Flow Control
    Pfc,
    /// RFC 2516 Point-to-Point Protocol over Ethernet
    Pppoe,
    /// RFC 8300 Network Service Header
    Nsh,
    /// IEC 61158-6-10 PROFINET IO Real-Time and Context Manager
    Profinet,
    /// IEC 61850-8-1 Generic Object Oriented Substation Event
    Goose,
    /// IEC 61850-9-2LE Sampled Values
    Sv,
    /// IEC 61158-4-12 EtherCAT Industrial Real-Time Protocol
    Ethercat,
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
    /// RFC 2003 / RFC 2473 / RFC 4213 IP-in-IP Encapsulation
    Ipip,
    /// RFC 8754 Segment Routing over IPv6
    Srv6,
    /// Encapsulated Remote Switch Port Analyzer (Type II & III)
    Erspan,
    /// RFC 2205 / RFC 3209 Resource Reservation Protocol
    Rsvp,
    /// RFC 5036 Label Distribution Protocol
    Ldp,
    /// RFC 7854 BGP Monitoring Protocol
    Bmp,
    /// RFC 6810 / RFC 8210 RPKI to Router Protocol
    Rpkirtr,
    /// RFC 2661 / RFC 3931 Layer 2 Tunneling Protocol
    L2tp,
    /// RFC 9300 / RFC 9301 Locator/ID Separation Protocol
    Lisp,
    /// Cisco Gateway Load Balancing Protocol
    Glbp,
    /// 3GPP TS 29.281 GPRS Tunneling Protocol User Plane
    Gtpu,
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
    /// Distributed Computing Environment / Remote Procedure Call
    Dcerpc,
    /// NT LAN Manager Authentication over HTTP
    Ntlm,
    /// Remote Desktop Protocol (MS-RDPBCGR over TPKT/X.224)
    Rdp,
    /// RFC 4795 Link-Local Multicast Name Resolution
    Llmnr,
    /// RFC 1001 / RFC 1002 NetBIOS Name Service
    Nbns,
    /// RFC 1928 / RFC 1929 SOCKS Version 5 Proxy Protocol
    Socks,
    /// Virtual Network Computing Remote Framebuffer Protocol
    Vnc,
    /// RFC 8484 DNS over HTTPS
    Doh,
    /// OASIS Web Services Dynamic Discovery
    Wsdiscovery,
    /// RFC 1459 / RFC 2812 Internet Relay Chat Protocol
    Irc,
    /// IEC 60870-5-104 Telecontrol Protocol
    Iec104,
    /// ISO 9506 / IEC 61850 Manufacturing Message Specification
    Mms,
    /// Siemens S7 Communication Plus
    S7commplus,
    /// IEEE C37.118 Synchrophasor Telemetry Protocol
    Synchrophasor,
    /// HCF Spec 085 HART-IP Protocol
    Hartip,
    /// Omron Factory Interface Network Service
    Fins,
    /// Mitsubishi MELSEC MC Protocol / SLMP
    Melsec,
    /// AUTOSAR SOME/IP and Service Discovery
    Someip,
    /// ISO 13400-2 Diagnostics over Internet Protocol
    Doip,
    /// ANSI C12.22 / IEEE 1703 Smart Grid Metering Protocol
    C1222,
    /// GE Fanuc Service Request Transport Protocol
    Gesrtp,
    /// Emerson ROC Plus SCADA Protocol
    Rocplus,
    /// Bristol Standard Asynchronous Protocol over IP
    Bsap,
    /// ISO/IEC 14543-3 KNXnet/IP Building Automation Protocol
    Knxnetip,
    /// RDMA over Converged Ethernet v2
    Rocev2,
    /// Intelligent Platform Management Interface (RMCP / IPMI)
    Ipmi,
    /// RFC 5357 / RFC 6038 Two-Way Active Measurement Protocol
    Twamp,
    /// RFC 6241 / RFC 6242 Network Configuration Protocol
    Netconf,
    /// 3GPP TS 29.274 GPRS Tunneling Protocol Control Plane v2
    Gtpc,
    /// 3GPP TS 29.244 Packet Forwarding Control Protocol
    Pfcp,
    /// RFC 6733 Diameter Base Protocol
    Diameter,
    /// 3GPP TS 38.413 5G NG Application Protocol
    Ngap,
    /// 3GPP TS 36.413 4G LTE S1 Application Protocol
    S1ap,
    /// Microsoft SQL Server Tabular Data Stream
    Mssql,
    /// Apache Kafka Binary Wire Protocol
    Kafka,
    /// MongoDB Wire Protocol
    Mongodb,
    /// Oracle Transparent Network Substrate
    Tns,
    /// RFC 7143 Internet Small Computer Systems Interface
    Iscsi,
    /// NVM Express over Fabrics TCP Transport
    Nvmetcp,
    /// RFC 3550 Real-time Transport Control Protocol
    Rtcp,
    /// RFC 8656 / RFC 5766 Traversal Using Relays around NAT
    Turn,
    /// ITU-T H.323 / H.225.0 Call Signaling and RAS
    H323,
    /// Cisco Skinny Client Control Protocol
    Sccp,
    /// RFC 3435 Media Gateway Control Protocol
    Mgcp,
}

impl Protocol {
    /// Returns the canonical uppercase display label for packet ladders and IDE inspectors.
    pub const fn display_label(&self) -> &'static str {
        match self {
            Self::Tcp => "TCP",
            Self::Udp => "UDP",
            Self::Sctp => "SCTP",
            Self::Snmp1 => "SNMP1",
            Self::Snmp2 => "SNMP2",
            Self::Snmp3 => "SNMP3",
            Self::Arp => "ARP",
            Self::Vlan => "VLAN",
            Self::Qinq => "QINQ",
            Self::Lldp => "LLDP",
            Self::Stp => "STP",
            Self::Lacp => "LACP",
            Self::Eapol => "EAPOL",
            Self::Mpls => "MPLS",
            Self::Cdp => "CDP",
            Self::Isis => "ISIS",
            Self::Macsec => "MACSEC",
            Self::Pfc => "PFC",
            Self::Pppoe => "PPPOE",
            Self::Nsh => "NSH",
            Self::Profinet => "PROFINET",
            Self::Goose => "GOOSE",
            Self::Sv => "SV",
            Self::Ethercat => "ETHERCAT",
            Self::Icmp => "ICMP",
            Self::Ndp => "NDP",
            Self::Igmp => "IGMP",
            Self::Mld => "MLD",
            Self::Gre => "GRE",
            Self::Vxlan => "VXLAN",
            Self::Geneve => "GENEVE",
            Self::Ipsec => "IPSEC",
            Self::Esp => "ESP",
            Self::Ah => "AH",
            Self::Ikev2 => "IKEV2",
            Self::Wireguard => "WIREGUARD",
            Self::Ospf => "OSPF",
            Self::Bgp => "BGP",
            Self::Rip => "RIP",
            Self::Vrrp => "VRRP",
            Self::Hsrp => "HSRP",
            Self::Pim => "PIM",
            Self::Bfd => "BFD",
            Self::Openflow => "OPENFLOW",
            Self::Ipip => "IPIP",
            Self::Srv6 => "SRV6",
            Self::Erspan => "ERSPAN",
            Self::Rsvp => "RSVP",
            Self::Ldp => "LDP",
            Self::Bmp => "BMP",
            Self::Rpkirtr => "RPKIRTR",
            Self::L2tp => "L2TP",
            Self::Lisp => "LISP",
            Self::Glbp => "GLBP",
            Self::Gtpu => "GTPU",
            Self::Dns => "DNS",
            Self::Mdns => "MDNS",
            Self::Dhcp => "DHCP",
            Self::Ntp => "NTP",
            Self::Ptp => "PTP",
            Self::Radius => "RADIUS",
            Self::Tacacs => "TACACS",
            Self::Syslog => "SYSLOG",
            Self::Netflow => "NETFLOW",
            Self::Ipfix => "IPFIX",
            Self::Sflow => "SFLOW",
            Self::Tftp => "TFTP",
            Self::Ftp => "FTP",
            Self::Ssh => "SSH",
            Self::Telnet => "TELNET",
            Self::Http => "HTTP",
            Self::Http2 => "HTTP2",
            Self::Grpc => "GRPC",
            Self::Websocket => "WEBSOCKET",
            Self::Tls => "TLS",
            Self::Quic => "QUIC",
            Self::Stun => "STUN",
            Self::Sip => "SIP",
            Self::Rtp => "RTP",
            Self::Rtsp => "RTSP",
            Self::Smtp => "SMTP",
            Self::Imap => "IMAP",
            Self::Pop3 => "POP3",
            Self::Kerberos => "KERBEROS",
            Self::Ldap => "LDAP",
            Self::Smb => "SMB",
            Self::Nfs => "NFS",
            Self::Redis => "REDIS",
            Self::Memcached => "MEMCACHED",
            Self::Mysql => "MYSQL",
            Self::Postgres => "POSTGRES",
            Self::Mqtt => "MQTT",
            Self::Coap => "COAP",
            Self::Amqp => "AMQP",
            Self::Ssdp => "SSDP",
            Self::Whois => "WHOIS",
            Self::Modbus => "MODBUS",
            Self::Bacnet => "BACNET",
            Self::Dnp3 => "DNP3",
            Self::S7comm => "S7COMM",
            Self::Ethernetip => "ETHERNETIP",
            Self::Opcua => "OPCUA",
            Self::Dcerpc => "DCERPC",
            Self::Ntlm => "NTLM",
            Self::Rdp => "RDP",
            Self::Llmnr => "LLMNR",
            Self::Nbns => "NBNS",
            Self::Socks => "SOCKS",
            Self::Vnc => "VNC",
            Self::Doh => "DOH",
            Self::Wsdiscovery => "WSDISCOVERY",
            Self::Irc => "IRC",
            Self::Iec104 => "IEC104",
            Self::Mms => "MMS",
            Self::S7commplus => "S7COMMPLUS",
            Self::Synchrophasor => "SYNCHROPHASOR",
            Self::Hartip => "HARTIP",
            Self::Fins => "FINS",
            Self::Melsec => "MELSEC",
            Self::Someip => "SOMEIP",
            Self::Doip => "DOIP",
            Self::C1222 => "C1222",
            Self::Gesrtp => "GESRTP",
            Self::Rocplus => "ROCPLUS",
            Self::Bsap => "BSAP",
            Self::Knxnetip => "KNXNETIP",
            Self::Rocev2 => "ROCEV2",
            Self::Ipmi => "IPMI",
            Self::Twamp => "TWAMP",
            Self::Netconf => "NETCONF",
            Self::Gtpc => "GTPC",
            Self::Pfcp => "PFCP",
            Self::Diameter => "DIAMETER",
            Self::Ngap => "NGAP",
            Self::S1ap => "S1AP",
            Self::Mssql => "MSSQL",
            Self::Kafka => "KAFKA",
            Self::Mongodb => "MONGODB",
            Self::Tns => "TNS",
            Self::Iscsi => "ISCSI",
            Self::Nvmetcp => "NVMETCP",
            Self::Rtcp => "RTCP",
            Self::Turn => "TURN",
            Self::H323 => "H323",
            Self::Sccp => "SCCP",
            Self::Mgcp => "MGCP",
        }
    }
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
    /// Cisco Discovery Protocol v2.
    Cdp(CdpSpec<'a>),
    /// ISO/IEC 10589 IS-IS protocol.
    Isis(IsisSpec<'a>),
    /// IEEE 802.1AE MACsec protocol.
    Macsec(MacsecSpec),
    /// IEEE 802.1Qbb Priority Flow Control.
    Pfc(PfcSpec),
    /// RFC 2516 PPPoE protocol.
    Pppoe(PppoeSpec<'a>),
    /// RFC 8300 Network Service Header.
    Nsh(NshSpec),
    /// IEC 61158-6-10 PROFINET protocol.
    Profinet(ProfinetSpec<'a>),
    /// IEC 61850-8-1 GOOSE protocol.
    Goose(GooseSpec<'a>),
    /// IEC 61850-9-2LE Sampled Values protocol.
    Sv(SvSpec<'a>),
    /// IEC 61158-4-12 EtherCAT protocol.
    Ethercat(EthercatSpec<'a>),
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
    /// RFC 2003 / RFC 2473 / RFC 4213 IP-in-IP protocol.
    Ipip(IpipSpec<'a>),
    /// RFC 8754 SRv6 Segment Routing Header.
    Srv6(Srv6Spec<'a>),
    /// ERSPAN Type II & III protocol.
    Erspan(ErspanSpec<'a>),
    /// RFC 2205 / RFC 3209 RSVP protocol.
    Rsvp(RsvpSpec<'a>),
    /// RFC 5036 LDP protocol.
    Ldp(LdpSpec<'a>),
    /// RFC 7854 BMP protocol.
    Bmp(BmpSpec<'a>),
    /// RFC 6810 / RFC 8210 RPKI-RTR protocol.
    Rpkirtr(RpkirtrSpec<'a>),
    /// RFC 2661 / RFC 3931 L2TP protocol.
    L2tp(L2tpSpec<'a>),
    /// RFC 9300 / RFC 9301 LISP protocol.
    Lisp(LispSpec<'a>),
    /// Cisco GLBP protocol.
    Glbp(GlbpSpec<'a>),
    /// 3GPP TS 29.281 GTPv1-U protocol.
    Gtpu(GtpuSpec<'a>),
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
    /// DCE/RPC protocol.
    Dcerpc(DcerpcSpec<'a>),
    /// NTLM over HTTP protocol.
    Ntlm(NtlmSpec<'a>),
    /// Remote Desktop Protocol.
    Rdp(RdpSpec<'a>),
    /// RFC 4795 LLMNR protocol.
    Llmnr(LlmnrSpec<'a>),
    /// RFC 1001 / RFC 1002 NetBIOS Name Service.
    Nbns(NbnsSpec<'a>),
    /// RFC 1928 / RFC 1929 SOCKS v5 protocol.
    Socks(SocksSpec<'a>),
    /// VNC / RFB protocol.
    Vnc(VncSpec<'a>),
    /// RFC 8484 DNS over HTTPS protocol.
    Doh(DohSpec<'a>),
    /// OASIS WS-Discovery protocol.
    Wsdiscovery(WsdiscoverySpec<'a>),
    /// RFC 1459 / RFC 2812 IRC protocol.
    Irc(IrcSpec<'a>),
    /// IEC 60870-5-104 protocol.
    Iec104(Iec104Spec<'a>),
    /// ISO 9506 / IEC 61850 MMS protocol.
    Mms(MmsSpec<'a>),
    /// Siemens S7commPlus protocol.
    S7commplus(S7commplusSpec<'a>),
    /// IEEE C37.118 Synchrophasor protocol.
    Synchrophasor(SynchrophasorSpec<'a>),
    /// HART-IP protocol.
    Hartip(HartipSpec<'a>),
    /// Omron FINS protocol.
    Fins(FinsSpec<'a>),
    /// Mitsubishi MELSEC MC / SLMP protocol.
    Melsec(MelsecSpec<'a>),
    /// AUTOSAR SOME/IP and SOME/IP-SD protocol.
    Someip(SomeipSpec<'a>),
    /// ISO 13400-2 DoIP protocol.
    Doip(DoipSpec<'a>),
    /// ANSI C12.22 / IEEE 1703 protocol.
    C1222(C1222Spec<'a>),
    /// GE-SRTP protocol.
    Gesrtp(GesrtpSpec<'a>),
    /// Emerson ROC Plus protocol.
    Rocplus(RocplusSpec<'a>),
    /// BSAP-IP protocol.
    Bsap(BsapSpec<'a>),
    /// KNXnet/IP protocol.
    Knxnetip(KnxnetipSpec<'a>),
    /// RoCEv2 protocol.
    Rocev2(Rocev2Spec<'a>),
    /// RMCP / IPMI protocol.
    Ipmi(IpmiSpec<'a>),
    /// RFC 5357 / RFC 6038 TWAMP protocol.
    Twamp(TwampSpec<'a>),
    /// RFC 6241 / RFC 6242 NETCONF protocol.
    Netconf(NetconfSpec<'a>),
    /// 3GPP TS 29.274 GTPv2-C protocol.
    Gtpc(GtpcSpec<'a>),
    /// 3GPP TS 29.244 PFCP protocol.
    Pfcp(PfcpSpec<'a>),
    /// RFC 6733 Diameter protocol.
    Diameter(DiameterSpec<'a>),
    /// 3GPP TS 38.413 NGAP protocol.
    Ngap(NgapSpec<'a>),
    /// 3GPP TS 36.413 S1AP protocol.
    S1ap(S1apSpec<'a>),
    /// Microsoft SQL Server MS-TDS protocol.
    Mssql(MssqlSpec<'a>),
    /// Apache Kafka binary protocol.
    Kafka(KafkaSpec<'a>),
    /// MongoDB wire protocol.
    Mongodb(MongodbSpec<'a>),
    /// Oracle TNS protocol.
    Tns(TnsSpec<'a>),
    /// RFC 7143 iSCSI protocol.
    Iscsi(IscsiSpec<'a>),
    /// NVMe/TCP protocol.
    Nvmetcp(NvmetcpSpec<'a>),
    /// RFC 3550 RTCP protocol.
    Rtcp(RtcpSpec<'a>),
    /// RFC 8656 / RFC 5766 TURN protocol.
    Turn(TurnSpec<'a>),
    /// ITU-T H.323 / H.225.0 protocol.
    H323(H323Spec<'a>),
    /// Cisco SCCP protocol.
    Sccp(SccpSpec<'a>),
    /// RFC 3435 MGCP protocol.
    Mgcp(MgcpSpec<'a>),
    /// Raw payload.
    Raw(Vec<u8>),
}

/// Recorded numeric bound entry `(label, value, min, max, span)` for semantic range validation.
pub type RawBoundEntry = (&'static str, u64, u64, u64, (usize, usize));

/// A single frame statement inside a flow.
///
/// Syntax mapping: `<caller> ->|<- <callee> [l2/l3/l4 modifiers] <protocol> [protocol_spec] [wait <duration>]`
///
/// # Examples
/// ```text
/// client -> server tcp syn ack payload "World" wait 10ms
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
    /// Optional raw byte sequence decoded from `payload` (preserving `\x80`..`\xff` as raw octets).
    pub payload_bytes: Option<Vec<u8>>,
    /// Optional raw binary hex payload.
    pub hex_payload: Option<Vec<u8>>,
    /// Optional per-frame PCAPNG Enhanced Packet Block comment (`comment <str>`).
    pub comment: Option<String>,
    /// Optional wait time before sending the packet (in nanoseconds).
    pub wait: Option<u64>,
    /// Source span of this statement.
    pub span: (usize, usize),
    /// Raw parsed VLAN ID and span for semantic range validation.
    pub raw_vlan: Option<(u32, (usize, usize))>,
    /// Raw parsed `qinq` modifier span for semantic conflict checks.
    pub raw_qinq_span: Option<(usize, usize)>,
    /// Raw parsed `innervlan` modifier span for semantic parent checks.
    pub raw_inner_vlan_span: Option<(usize, usize)>,
    /// Raw parsed `pcp` modifier span for semantic parent checks.
    pub raw_pcp_span: Option<(usize, usize)>,
    /// Raw parsed `dei` modifier span for semantic parent checks.
    pub raw_dei_span: Option<(usize, usize)>,
    /// Raw parsed MPLS sub-modifier (`exp`/`bos`/`mplsttl`) span for semantic parent checks.
    pub raw_mpls_sub_span: Option<(usize, usize)>,
    /// Raw parsed DSCP and span for semantic range validation.
    pub raw_dscp: Option<(u32, (usize, usize))>,
    /// Raw parsed ECN and span for semantic range validation.
    pub raw_ecn: Option<(u32, (usize, usize))>,
    /// Raw parsed TTL and span for semantic range validation.
    pub raw_ttl: Option<(u32, (usize, usize))>,
    /// Raw parsed FLOWLABEL and span for semantic range validation.
    pub raw_flowlabel: Option<(u32, (usize, usize))>,
    /// Raw parsed `df` modifier span for IPv6 incompatibility checks.
    pub raw_df_span: Option<(usize, usize)>,
    /// Raw parsed `fragoffset` modifier value and span for range/family validation.
    pub raw_frag_offset: Option<(u32, (usize, usize))>,
    /// Raw parsed `nochecksum` modifier span for non-UDP incompatibility checks.
    pub raw_no_checksum_span: Option<(usize, usize)>,
    /// Raw parsed `badipchecksum` modifier span for IPv6 incompatibility checks.
    pub raw_bad_ip_checksum_span: Option<(usize, usize)>,
    /// Raw parsed GENTRAP span for semantic range validation.
    pub raw_gentrap_span: Option<(usize, usize)>,
    /// Raw parsed `hellotime` value and span for HSRP semantic range validation (`0..=255`).
    pub raw_hellotime: Option<(u16, (usize, usize))>,
    /// Raw numeric field values `(label, value, min, max, span)` recorded for semantic range validation.
    pub raw_bounds: Vec<RawBoundEntry>,
    /// Source span of a bare `nop` modifier for cross-protocol validation.
    pub raw_nop_span: Option<(usize, usize)>,
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
    /// Prioritizes `hex_payload` if present, then `payload_bytes` (preserving single-octet
    /// `\x80`..`\xff` escapes), falling back to UTF-8 bytes of `payload`.
    pub fn effective_payload(&self) -> Option<&[u8]> {
        if let Some(hex) = &self.hex_payload {
            Some(hex.as_slice())
        } else if let Some(bytes) = &self.payload_bytes {
            Some(bytes.as_slice())
        } else {
            self.payload.as_deref().map(str::as_bytes)
        }
    }
}

/// A statement inside a `flow` definition body.
///
/// Syntax mapping: `flow <name>(<params>) { <frame | invocation | repeat> ... }`
#[doc(alias = "flow")]
#[doc(alias = "repeat")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FlowStatement<'a> {
    /// A directional packet statement inside the flow body.
    Frame(alloc::boxed::Box<FrameStatement<'a>>),
    /// A nested flow invocation inside the flow body.
    Invocation(TemplateInvocation<'a>),
    /// A `repeat <count> { ... }` block inside the flow body.
    Repeat {
        /// Number of loop iterations (`u64`).
        count: u64,
        /// Nested flow statements repeated `count` times.
        body: Vec<FlowStatement<'a>>,
        /// Source span of the `repeat` block.
        span: (usize, usize),
    },
}

/// A flow definition in the form `flow name(arg1, arg2) { statements }`
///
/// Syntax mapping: `flow <name>(<param1>, <param2>) { <statements> }`
///
/// # Examples
/// ```text
/// flow name(arg1, arg2) {
///     arg1 -> arg2 tcp syn
/// }
/// ```
#[doc(alias = "flow")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowDef<'a> {
    /// The name of the flow.
    pub name: &'a str,
    /// The parameters of the flow.
    pub params: Vec<&'a str>,
    /// Top-level frame statements inside the flow (backwards-compatibility projection).
    pub statements: Vec<FrameStatement<'a>>,
    /// Structured statements inside the flow body (frames, nested invocations, and `repeat` blocks).
    pub body: Vec<FlowStatement<'a>>,
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

/// A statement in the `compile` block, which can be a flow invocation, an inline frame statement, or a `repeat` block.
#[doc(alias = "compile")]
#[doc(alias = "repeat")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RunStatement<'a> {
    /// A single template invocation directly in the block.
    Invocation(TemplateInvocation<'a>),
    /// An inline directional frame statement directly inside `compile`.
    Frame(alloc::boxed::Box<FrameStatement<'a>>),
    /// A `repeat <count> { ... }` block inside `compile`.
    Repeat {
        /// Number of loop iterations (`u64`).
        count: u64,
        /// Nested compile statements repeated `count` times.
        body: Vec<RunStatement<'a>>,
        /// Source span of the `repeat` block.
        span: (usize, usize),
    },
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

impl<'a> Program<'a> {
    /// Maximum number of protocols collected in [`Self::emitted_protocols`] to bound cyclic/large `repeat` expansion.
    const MAX_COLLECTED_PROTOCOLS: usize = 100_000;

    /// Returns the ordered sequence of [`Protocol`] variants emitted by evaluating [`Self::compile_block`].
    pub fn emitted_protocols(&self) -> Vec<Protocol> {
        let mut out = Vec::new();
        let mut visiting = Vec::new();
        self.collect_run_protocols(&self.compile_block, &mut visiting, &mut out);
        out
    }

    /// Recursively collects emitted [`Protocol`] variants from `compile` block [`RunStatement`] items.
    fn collect_run_protocols(
        &self,
        items: &[RunStatement<'a>],
        visiting: &mut Vec<&'a str>,
        out: &mut Vec<Protocol>,
    ) {
        for item in items {
            if out.len() >= Self::MAX_COLLECTED_PROTOCOLS {
                break;
            }
            match item {
                RunStatement::Frame(stmt) => out.push(stmt.protocol.clone()),
                RunStatement::Invocation(inv) => {
                    self.collect_flow_by_name(inv.name, visiting, out);
                }
                RunStatement::Repeat { count, body, .. } => {
                    let cap = (*count).min(Self::MAX_COLLECTED_PROTOCOLS as u64) as usize;
                    for _ in 0..cap {
                        if out.len() >= Self::MAX_COLLECTED_PROTOCOLS || body.is_empty() {
                            break;
                        }
                        self.collect_run_protocols(body, visiting, out);
                    }
                }
            }
        }
    }

    /// Resolves a flow definition by name and collects its emitted [`Protocol`] variants while avoiding cycles.
    fn collect_flow_by_name(
        &self,
        name: &str,
        visiting: &mut Vec<&'a str>,
        out: &mut Vec<Protocol>,
    ) {
        let Some(flow) = self
            .flows
            .iter()
            .find(|f| f.name.eq_ignore_ascii_case(name))
        else {
            return;
        };
        if visiting.iter().any(|&v| v.eq_ignore_ascii_case(flow.name)) {
            return;
        }
        visiting.push(flow.name);
        if flow.body.is_empty() && !flow.statements.is_empty() {
            for stmt in &flow.statements {
                if out.len() >= Self::MAX_COLLECTED_PROTOCOLS {
                    break;
                }
                out.push(stmt.protocol.clone());
            }
        } else {
            self.collect_flow_statements(&flow.body, visiting, out);
        }
        visiting.pop();
    }

    /// Recursively collects emitted [`Protocol`] variants from [`FlowStatement`] items inside a flow body.
    fn collect_flow_statements(
        &self,
        items: &[FlowStatement<'a>],
        visiting: &mut Vec<&'a str>,
        out: &mut Vec<Protocol>,
    ) {
        for item in items {
            if out.len() >= Self::MAX_COLLECTED_PROTOCOLS {
                break;
            }
            match item {
                FlowStatement::Frame(stmt) => out.push(stmt.protocol.clone()),
                FlowStatement::Invocation(inv) => {
                    self.collect_flow_by_name(inv.name, visiting, out);
                }
                FlowStatement::Repeat { count, body, .. } => {
                    let cap = (*count).min(Self::MAX_COLLECTED_PROTOCOLS as u64) as usize;
                    for _ in 0..cap {
                        if out.len() >= Self::MAX_COLLECTED_PROTOCOLS || body.is_empty() {
                            break;
                        }
                        self.collect_flow_statements(body, visiting, out);
                    }
                }
            }
        }
    }
}
