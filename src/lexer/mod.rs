//! Zero-copy lexical analyzer and token specification for the FrameAssembly DSL.
//!
//! Built on the [`logos`] finite-automaton generator, this module defines the [`Token`] enumeration
//! and [`lex`] entry point for scanning `.fasm` source files into byte-spanned token streams.
//! It recognizes structural keywords (`HOST`, `FLOW`, `COMPILE`, `LOOP`), directional arrows,
//! all 81 L2–L7 protocol identifiers, header and payload modifiers, time units (`ns`, `us`, `ms`,
//! `s`, `m`), IPv4/IPv6/MAC address literals, ASN.1 OIDs, and quoted strings.

use logos::Logos;


/// Represents all lexical tokens recognized by the FrameAssembly DSL.
///
/// The lexer ignores whitespace and single-line comments.
///
/// # Examples
/// ```
/// use frameassembly::lexer::Token;
///
/// let token = Token::Host;
/// assert_eq!(token, Token::Host);
/// ```
#[derive(Logos, Debug, PartialEq, Clone)]
#[logos(skip r"[ \t\r\n\f]+")]
#[logos(skip r"//.*")]
pub enum Token<'a> {
    /// `HOST` keyword
    #[token("HOST")]
    Host,
    /// `FLOW` keyword
    #[token("FLOW")]
    Flow,
    /// `IP` keyword
    #[token("IP")]
    Ip,
    /// `MAC` keyword
    #[token("MAC")]
    Mac,
    /// `COMPILE` keyword
    #[token("COMPILE")]
    Compile,
    /// `LOOP` keyword
    #[token("LOOP")]
    Loop,
    /// `TCP` keyword
    #[token("TCP")]
    Tcp,
    /// `UDP` keyword
    #[token("UDP")]
    Udp,
    /// `SYN` flag
    #[token("SYN")]
    Syn,
    /// `ACK` flag
    #[token("ACK")]
    Ack,
    /// `FIN` flag
    #[token("FIN")]
    Fin,
    /// `RST` flag
    #[token("RST")]
    Rst,
    /// `PSH` flag
    #[token("PSH")]
    Psh,
    /// `URG` flag
    #[token("URG")]
    Urg,
    /// `ECE` flag
    #[token("ECE")]
    Ece,
    /// `CWR` flag
    #[token("CWR")]
    Cwr,
    /// `SRCPORT` keyword
    #[token("SRCPORT")]
    SrcPort,
    /// `DSTPORT` keyword
    #[token("DSTPORT")]
    DstPort,
    /// `SEQ` keyword
    #[token("SEQ")]
    Seq,
    /// `ACKNUM` keyword
    #[token("ACKNUM")]
    AckNum,
    /// `WIN` keyword
    #[token("WIN")]
    Win,
    /// `PAYLOAD` keyword
    #[token("PAYLOAD")]
    Payload,
    /// `HEXPAYLOAD` keyword
    #[token("HEXPAYLOAD")]
    HexPayload,
    /// `WAIT` keyword
    #[token("WAIT")]
    Wait,
    /// `VLAN` keyword
    #[token("VLAN")]
    Vlan,
    /// `DSCP` keyword
    #[token("DSCP")]
    Dscp,
    /// `ECN` keyword
    #[token("ECN")]
    Ecn,
    /// `TTL` keyword
    #[token("TTL")]
    Ttl,
    /// `FLOWLABEL` keyword
    #[token("FLOWLABEL")]
    FlowLabel,
    /// `SNMP1` keyword
    #[token("SNMP1")]
    Snmp1,
    /// `SNMP2` keyword
    #[token("SNMP2")]
    Snmp2,
    /// `SNMP3` keyword
    #[token("SNMP3")]
    Snmp3,
    /// `TRAP` keyword
    #[token("TRAP")]
    Trap,
    /// `GET` keyword
    #[token("GET")]
    Get,
    /// `SET` keyword
    #[token("SET")]
    Set,
    /// `RESPONSE` keyword
    #[token("RESPONSE")]
    Response,
    /// `INFORM` keyword
    #[token("INFORM")]
    Inform,
    /// `GETNEXT` keyword
    #[token("GETNEXT")]
    GetNext,
    /// `GETBULK` keyword
    #[token("GETBULK")]
    GetBulk,
    /// `COMMUNITY` keyword
    #[token("COMMUNITY")]
    Community,
    /// `USER` keyword
    #[token("USER")]
    User,
    /// `OID` keyword
    #[token("OID")]
    Oid,
    /// `SYSUPTIME` keyword
    #[token("SYSUPTIME")]
    SysUpTime,

    /// `VARBIND` keyword
    #[token("VARBIND")]
    VarBind,
    /// `NULLVAL` keyword
    #[token("NULLVAL")]
    #[token("NULL")]
    NullVal,
    /// `STRING` keyword
    #[token("STRING")]
    StringVal,
    /// `INT` keyword
    #[token("INT")]
    IntVal,
    /// `TIMETICKS` keyword
    #[token("TIMETICKS")]
    TimeTicksVal,
    /// `IPVAL` keyword
    #[token("IPVAL")]
    IpVal,
    /// `OIDVAL` keyword
    #[token("OIDVAL")]
    OidVal,
    /// `COUNTER32` keyword
    #[token("COUNTER32")]
    Counter32Val,
    /// `GAUGE32` keyword
    #[token("GAUGE32")]
    Gauge32Val,
    /// `COUNTER64` keyword
    #[token("COUNTER64")]
    Counter64Val,

    /// `ENTERPRISE` keyword
    #[token("ENTERPRISE")]
    Enterprise,
    /// `AGENTIP` keyword
    #[token("AGENTIP")]
    AgentIp,
    /// `GENTRAP` keyword
    #[token("GENTRAP")]
    GenTrap,
    /// `SPECTRAP` keyword
    #[token("SPECTRAP")]
    SpecTrap,

    /// `ENGINEID` keyword
    #[token("ENGINEID")]
    EngineId,
    /// `ENGINEBOOTS` keyword
    #[token("ENGINEBOOTS")]
    EngineBoots,
    /// `ENGINETIME` keyword
    #[token("ENGINETIME")]
    EngineTime,
    /// `CONTEXTNAME` keyword
    #[token("CONTEXTNAME")]
    ContextName,
    /// `AUTH` keyword
    #[token("AUTH")]
    Auth,
    /// `PRIV` keyword
    #[token("PRIV")]
    Priv,
    /// `MD5` keyword
    #[token("MD5")]
    Md5,
    /// `SHA` keyword
    #[token("SHA")]
    Sha,
    /// `SHA256` keyword
    #[token("SHA256")]
    Sha256,
    /// `SHA384` keyword
    #[token("SHA384")]
    Sha384,
    /// `SHA512` keyword
    #[token("SHA512")]
    Sha512,
    /// `DES` keyword
    #[token("DES")]
    Des,
    /// `AES` keyword
    #[token("AES")]
    Aes,

    /// `NONREPEATERS` keyword
    #[token("NONREPEATERS")]
    NonRepeaters,
    /// `MAXREPETITIONS` keyword
    #[token("MAXREPETITIONS")]
    MaxRepetitions,
    /// `REQID` keyword
    #[token("REQID")]
    ReqId,

    // Layer 2 modifiers
    /// `PCP` keyword
    #[token("PCP")]
    Pcp,
    /// `DEI` keyword
    #[token("DEI")]
    Dei,
    /// `QINQ` keyword
    #[token("QINQ")]
    Qinq,
    /// `INNER_VLAN` keyword
    #[token("INNER_VLAN")]
    InnerVlan,
    /// `MPLS` keyword
    #[token("MPLS")]
    Mpls,
    /// `EXP` or `TC` keyword
    #[token("EXP")]
    #[token("TC")]
    Exp,
    /// `BOS` keyword
    #[token("BOS")]
    Bos,
    /// `MPLS_TTL` keyword
    #[token("MPLS_TTL")]
    MplsTtl,
    /// `SRCMAC` keyword
    #[token("SRCMAC")]
    SrcMac,
    /// `DSTMAC` keyword
    #[token("DSTMAC")]
    DstMac,
    /// `ETHERTYPE` keyword
    #[token("ETHERTYPE")]
    EtherType,

    // Layer 3 modifiers
    /// `IPID` keyword
    #[token("IPID")]
    IpId,
    /// `DF` keyword
    #[token("DF")]
    Df,
    /// `MF` keyword
    #[token("MF")]
    Mf,
    /// `FRAGOFFSET` keyword
    #[token("FRAGOFFSET")]
    FragOffset,

    // Layer 4 modifiers
    /// `TRANSPORT` keyword
    #[token("TRANSPORT")]
    Transport,
    /// `WINDOW` keyword
    #[token("WINDOW")]
    Window,
    /// `URGENT` keyword
    #[token("URGENT")]
    Urgent,
    /// `MSS` keyword
    #[token("MSS")]
    Mss,
    /// `WSCALE` keyword
    #[token("WSCALE")]
    Wscale,
    /// `SACK_PERM` keyword
    #[token("SACK_PERM")]
    #[token("SACKPERM")]
    SackPerm,
    /// `TSVAL` keyword
    #[token("TSVAL")]
    Tsval,
    /// `TSECR` keyword
    #[token("TSECR")]
    Tsecr,

    // SCTP overrides
    /// `VTAG` keyword
    #[token("VTAG")]
    Vtag,
    /// `STREAM` keyword
    #[token("STREAM")]
    Stream,
    /// `SSN` keyword
    #[token("SSN")]
    Ssn,
    /// `PPID` keyword
    #[token("PPID")]
    Ppid,
    /// `CHUNK` keyword
    #[token("CHUNK")]
    Chunk,

    // Category 1: Layer 2 & DC Protocols
    /// `ARP` keyword
    #[token("ARP")]
    Arp,
    /// `LLDP` keyword
    #[token("LLDP")]
    Lldp,
    /// `STP` keyword
    #[token("STP")]
    Stp,
    /// `LACP` keyword
    #[token("LACP")]
    Lacp,
    /// `EAPOL` keyword
    #[token("EAPOL")]
    Eapol,

    // Category 2: Layer 3, Tunneling, Security & Routing Protocols
    /// `ICMP` keyword
    #[token("ICMP")]
    Icmp,
    /// `NDP` keyword
    #[token("NDP")]
    Ndp,
    /// `IGMP` keyword
    #[token("IGMP")]
    Igmp,
    /// `MLD` keyword
    #[token("MLD")]
    Mld,
    /// `GRE` keyword
    #[token("GRE")]
    Gre,
    /// `VXLAN` keyword
    #[token("VXLAN")]
    Vxlan,
    /// `GENEVE` keyword
    #[token("GENEVE")]
    Geneve,
    /// `IPSEC` keyword
    #[token("IPSEC")]
    Ipsec,
    /// `ESP` keyword
    #[token("ESP")]
    Esp,
    /// `AH` keyword
    #[token("AH")]
    Ah,
    /// `IKEV2` keyword
    #[token("IKEV2")]
    Ikev2,
    /// `WIREGUARD` keyword
    #[token("WIREGUARD")]
    Wireguard,
    /// `OSPF` keyword
    #[token("OSPF")]
    Ospf,
    /// `BGP` keyword
    #[token("BGP")]
    Bgp,
    /// `RIP` keyword
    #[token("RIP")]
    Rip,
    /// `VRRP` keyword
    #[token("VRRP")]
    Vrrp,
    /// `HSRP` keyword
    #[token("HSRP")]
    Hsrp,
    /// `PIM` keyword
    #[token("PIM")]
    Pim,
    /// `BFD` keyword
    #[token("BFD")]
    Bfd,
    /// `OPENFLOW` keyword
    #[token("OPENFLOW")]
    Openflow,

    // Category 3: Layer 4 Transports
    /// `SCTP` keyword
    #[token("SCTP")]
    Sctp,

    // Protocol Sub-keywords
    /// `REQUEST` keyword
    #[token("REQUEST")]
    Request,
    /// `REPLY` keyword
    #[token("REPLY")]
    Reply,
    /// `GRATUITOUS` keyword
    #[token("GRATUITOUS")]
    Gratuitous,
    /// `GARP` keyword
    #[token("GARP")]
    Garp,
    /// `SPA` keyword
    #[token("SPA")]
    Spa,
    /// `THA` keyword
    #[token("THA")]
    Tha,
    /// `TPA` keyword
    #[token("TPA")]
    Tpa,
    /// `SENDERMAC` keyword
    #[token("SENDERMAC")]
    SenderMac,
    /// `TARGETMAC` keyword
    #[token("TARGETMAC")]
    TargetMac,
    /// `SENDERIP` keyword
    #[token("SENDERIP")]
    SenderIp,
    /// `TARGETIP` keyword
    #[token("TARGETIP")]
    TargetIp,

    /// `CHASSIS_ID` keyword
    #[token("CHASSIS_ID")]
    ChassisId,
    /// `PORT_ID` keyword
    #[token("PORT_ID")]
    PortId,
    /// `SYSNAME` keyword
    #[token("SYSNAME")]
    SysName,
    /// `SYSDESC` keyword
    #[token("SYSDESC")]
    SysDesc,

    /// `ROOT_ID` keyword
    #[token("ROOT_ID")]
    RootId,
    /// `BRIDGE_ID` keyword
    #[token("BRIDGE_ID")]
    BridgeId,
    /// `COST` keyword
    #[token("COST")]
    Cost,
    /// `MAX_AGE` keyword
    #[token("MAX_AGE")]
    MaxAge,
    /// `HELLO_TIME` keyword
    #[token("HELLO_TIME")]
    HelloTime,
    /// `FORWARD_DELAY` keyword
    #[token("FORWARD_DELAY")]
    ForwardDelay,
    /// `RSTP` keyword
    #[token("RSTP")]
    Rstp,
    /// `FLAGS` keyword
    #[token("FLAGS")]
    Flags,

    /// `ACTOR_SYS` keyword
    #[token("ACTOR_SYS")]
    ActorSys,
    /// `ACTOR_KEY` keyword
    #[token("ACTOR_KEY")]
    ActorKey,
    /// `ACTOR_PORT` keyword
    #[token("ACTOR_PORT")]
    ActorPort,
    /// `PARTNER_SYS` keyword
    #[token("PARTNER_SYS")]
    PartnerSys,
    /// `PARTNER_KEY` keyword
    #[token("PARTNER_KEY")]
    PartnerKey,
    /// `PARTNER_PORT` keyword
    #[token("PARTNER_PORT")]
    PartnerPort,
    /// `ACTOR_STATE` keyword
    #[token("ACTOR_STATE")]
    ActorState,
    /// `PARTNER_STATE` keyword
    #[token("PARTNER_STATE")]
    PartnerState,

    /// `VERSION` keyword
    #[token("VERSION")]
    Version,
    /// `TYPE` keyword
    #[token("TYPE")]
    Type,
    /// `EAP_PACKET` keyword
    #[token("EAP_PACKET")]
    EapPacket,
    /// `START` keyword
    #[token("START")]
    Start,
    /// `LOGOFF` keyword
    #[token("LOGOFF")]
    Logoff,
    /// `KEY` keyword
    #[token("KEY")]
    Key,
    /// `EAP_CODE` keyword
    #[token("EAP_CODE")]
    EapCode,
    /// `EAP_ID` keyword
    #[token("EAP_ID")]
    EapId,
    /// `EAP_METHOD` keyword
    #[token("EAP_METHOD")]
    EapMethod,
    /// `IDENTITY` keyword
    #[token("IDENTITY")]
    Identity,

    /// `LABEL` keyword
    #[token("LABEL")]
    Label,

    /// `ECHO_REQUEST` keyword
    #[token("ECHO_REQUEST")]
    EchoRequest,
    /// `ECHO_REPLY` keyword
    #[token("ECHO_REPLY")]
    EchoReply,
    /// `DEST_UNREACH` keyword
    #[token("DEST_UNREACH")]
    DestUnreach,
    /// `TIME_EXCEEDED` keyword
    #[token("TIME_EXCEEDED")]
    TimeExceeded,
    /// `REDIRECT` keyword
    #[token("REDIRECT")]
    Redirect,
    /// `CODE` keyword
    #[token("CODE")]
    Code,
    /// `ID` keyword
    #[token("ID")]
    Id,
    /// `GATEWAY` keyword
    #[token("GATEWAY")]
    Gateway,

    /// `ROUTER_SOLICIT` keyword
    #[token("ROUTER_SOLICIT")]
    RouterSolicit,
    /// `ROUTER_ADVERT` keyword
    #[token("ROUTER_ADVERT")]
    RouterAdvert,
    /// `NEIGHBOR_SOLICIT` keyword
    #[token("NEIGHBOR_SOLICIT")]
    NeighborSolicit,
    /// `NEIGHBOR_ADVERT` keyword
    #[token("NEIGHBOR_ADVERT")]
    NeighborAdvert,
    /// `TARGET` keyword
    #[token("TARGET")]
    Target,
    /// `SLLA` keyword
    #[token("SLLA")]
    Slla,
    /// `TLLA` keyword
    #[token("TLLA")]
    Tlla,
    /// `ROUTER_LIFETIME` keyword
    #[token("ROUTER_LIFETIME")]
    RouterLifetime,

    /// `QUERY` keyword
    #[token("QUERY")]
    Query,
    /// `REPORT` keyword
    #[token("REPORT")]
    Report,
    /// `LEAVE` keyword
    #[token("LEAVE")]
    Leave,
    /// `GROUP` keyword
    #[token("GROUP")]
    Group,
    /// `MAX_RESP` keyword
    #[token("MAX_RESP")]
    MaxResp,
    /// `V1` keyword
    #[token("V1")]
    V1,
    /// `V2` keyword
    #[token("V2")]
    V2,
    /// `V3` keyword
    #[token("V3")]
    V3,

    /// `DONE` keyword
    #[token("DONE")]
    Done,
    /// `MULTICAST_ADDR` keyword
    #[token("MULTICAST_ADDR")]
    MulticastAddr,
    /// `MAX_RESP_DELAY` keyword
    #[token("MAX_RESP_DELAY")]
    MaxRespDelay,

    /// `GRE_KEY` keyword
    #[token("GRE_KEY")]
    GreKey,
    /// `GRE_SEQ` keyword
    #[token("GRE_SEQ")]
    GreSeq,
    /// `GRE_PROTO` keyword
    #[token("GRE_PROTO")]
    GreProto,
    /// `CHECKSUM` keyword
    #[token("CHECKSUM")]
    Checksum,

    /// `VNI` keyword
    #[token("VNI")]
    Vni,
    /// `VNID` keyword
    #[token("VNID")]
    Vnid,

    /// `OPT_CLASS` keyword
    #[token("OPT_CLASS")]
    OptClass,
    /// `OPT_TYPE` keyword
    #[token("OPT_TYPE")]
    OptType,
    /// `PROTOCOL_TYPE` keyword
    #[token("PROTOCOL_TYPE")]
    ProtocolType,

    /// `SPI` keyword
    #[token("SPI")]
    Spi,
    /// `IV` keyword
    #[token("IV")]
    Iv,
    /// `ICV` keyword
    #[token("ICV")]
    Icv,
    /// `NEXT_HEADER` keyword
    #[token("NEXT_HEADER")]
    NextHeader,

    /// `INITIATOR_SPI` keyword
    #[token("INITIATOR_SPI")]
    InitiatorSpi,
    /// `RESPONDER_SPI` keyword
    #[token("RESPONDER_SPI")]
    ResponderSpi,
    /// `EXCHANGE` keyword
    #[token("EXCHANGE")]
    Exchange,
    /// `SA_INIT` keyword
    #[token("SA_INIT")]
    SaInit,
    /// `CREATE_CHILD_SA` keyword
    #[token("CREATE_CHILD_SA")]
    CreateChildSa,
    /// `INFORMATIONAL` keyword
    #[token("INFORMATIONAL")]
    Informational,
    /// `MSGID` keyword
    #[token("MSGID")]
    MsgId,
    /// `NEXT_PAYLOAD` keyword
    #[token("NEXT_PAYLOAD")]
    NextPayload,

    /// `INITIATION` keyword
    #[token("INITIATION")]
    Initiation,
    /// `COOKIE` keyword
    #[token("COOKIE")]
    Cookie,
    /// `DATA` keyword
    #[token("DATA")]
    Data,
    /// `SENDER` keyword
    #[token("SENDER")]
    Sender,
    /// `RECEIVER` keyword
    #[token("RECEIVER")]
    Receiver,
    /// `COUNTER` keyword
    #[token("COUNTER")]
    Counter,

    /// `HELLO` keyword
    #[token("HELLO")]
    Hello,
    /// `DBD` keyword
    #[token("DBD")]
    Dbd,
    /// `LSR` keyword
    #[token("LSR")]
    Lsr,
    /// `LSU` keyword
    #[token("LSU")]
    Lsu,
    /// `LSACK` keyword
    #[token("LSACK")]
    LsAck,
    /// `ROUTER_ID` keyword
    #[token("ROUTER_ID")]
    RouterId,
    /// `AREA_ID` keyword
    #[token("AREA_ID")]
    AreaId,
    /// `HELLO_INTERVAL` keyword
    #[token("HELLO_INTERVAL")]
    HelloInterval,
    /// `DEAD_INTERVAL` keyword
    #[token("DEAD_INTERVAL")]
    DeadInterval,
    /// `PRIORITY` keyword
    #[token("PRIORITY")]
    Priority,

    /// `OPEN` keyword
    #[token("OPEN")]
    Open,
    /// `UPDATE` keyword
    #[token("UPDATE")]
    Update,
    /// `NOTIFICATION` keyword
    #[token("NOTIFICATION")]
    Notification,
    /// `KEEPALIVE` keyword
    #[token("KEEPALIVE")]
    Keepalive,
    /// `ASN` keyword
    #[token("ASN")]
    Asn,
    /// `HOLDTIME` keyword
    #[token("HOLDTIME")]
    HoldTime,
    /// `BGPID` keyword
    #[token("BGPID")]
    BgpId,
    /// `PREFIX` keyword
    #[token("PREFIX")]
    Prefix,
    /// `NLRI` keyword
    #[token("NLRI")]
    Nlri,
    /// `NEXTHOP` keyword
    #[token("NEXTHOP")]
    NextHop,

    /// `METRIC` keyword
    #[token("METRIC")]
    Metric,
    /// `TAG` keyword
    #[token("TAG")]
    Tag,

    /// `VRID` keyword
    #[token("VRID")]
    Vrid,
    /// `ADV_INT` keyword
    #[token("ADV_INT")]
    AdvInt,
    /// `VIP` keyword
    #[token("VIP")]
    Vip,

    /// `HELLOTIME` keyword
    #[token("HELLOTIME")]
    HelloTimeHsrp,
    /// `STATE` keyword
    #[token("STATE")]
    State,

    /// `JOIN_PRUNE` keyword
    #[token("JOIN_PRUNE")]
    JoinPrune,
    /// `REGISTER` keyword
    #[token("REGISTER")]
    Register,
    /// `SOURCE` keyword
    #[token("SOURCE")]
    Source,
    /// `RP` keyword
    #[token("RP")]
    Rp,
    /// `DR_PRIORITY` keyword
    #[token("DR_PRIORITY")]
    DrPriority,

    /// `DIAG` keyword
    #[token("DIAG")]
    Diag,
    /// `MY_DISC` keyword
    #[token("MY_DISC")]
    MyDisc,
    /// `YOUR_DISC` keyword
    #[token("YOUR_DISC")]
    YourDisc,
    /// `MIN_TX` keyword
    #[token("MIN_TX")]
    MinTx,
    /// `MIN_RX` keyword
    #[token("MIN_RX")]
    MinRx,
    /// `MULT` keyword
    #[token("MULT")]
    Mult,

    /// `FEATURES_REQ` keyword
    #[token("FEATURES_REQ")]
    FeaturesReq,
    /// `FEATURES_REPLY` keyword
    #[token("FEATURES_REPLY")]
    FeaturesReply,
    /// `PACKET_IN` keyword
    #[token("PACKET_IN")]
    PacketIn,
    /// `PACKET_OUT` keyword
    #[token("PACKET_OUT")]
    PacketOut,
    /// `FLOW_MOD` keyword
    #[token("FLOW_MOD")]
    FlowMod,
    /// `ECHO_REQ` keyword
    #[token("ECHO_REQ")]
    EchoReq,
    /// `XID` keyword
    #[token("XID")]
    Xid,
    /// `DPID` keyword
    #[token("DPID")]
    Dpid,
    /// `TABLE_ID` keyword
    #[token("TABLE_ID")]
    TableId,

    /// `INIT` keyword
    #[token("INIT")]
    Init,
    /// `INIT_ACK` keyword
    #[token("INIT_ACK")]
    InitAck,
    /// `SACK` keyword
    #[token("SACK")]
    Sack,
    /// `HEARTBEAT` keyword
    #[token("HEARTBEAT")]
    Heartbeat,
    /// `HEARTBEAT_ACK` keyword
    #[token("HEARTBEAT_ACK")]
    HeartbeatAck,
    /// `ABORT` keyword
    #[token("ABORT")]
    Abort,
    /// `SHUTDOWN` keyword
    #[token("SHUTDOWN")]
    Shutdown,
    /// `COOKIE_ECHO` keyword
    #[token("COOKIE_ECHO")]
    CookieEcho,
    /// `COOKIE_ACK` keyword
    #[token("COOKIE_ACK")]
    CookieAck,
    /// `TSN` keyword
    #[token("TSN")]
    Tsn,

    // Category 4: Layer 7 Network Infrastructure, Management & Telemetry
    /// `DNS` keyword
    #[token("DNS")]
    Dns,
    /// `MDNS` keyword
    #[token("MDNS")]
    Mdns,
    /// `DHCP` keyword
    #[token("DHCP")]
    Dhcp,
    /// `NTP` keyword
    #[token("NTP")]
    Ntp,
    /// `PTP` keyword
    #[token("PTP")]
    Ptp,
    /// `RADIUS` keyword
    #[token("RADIUS")]
    Radius,
    /// `TACACS` keyword
    #[token("TACACS")]
    Tacacs,
    /// `SYSLOG` keyword
    #[token("SYSLOG")]
    Syslog,
    /// `NETFLOW` keyword
    #[token("NETFLOW")]
    Netflow,
    /// `IPFIX` keyword
    #[token("IPFIX")]
    Ipfix,
    /// `SFLOW` keyword
    #[token("SFLOW")]
    Sflow,

    // Category 5: Layer 7 Web, App, Directory, Mail, Storage & Messaging
    /// `TFTP` keyword
    #[token("TFTP")]
    Tftp,
    /// `FTP` keyword
    #[token("FTP")]
    Ftp,
    /// `SSH` keyword
    #[token("SSH")]
    Ssh,
    /// `TELNET` keyword
    #[token("TELNET")]
    Telnet,
    /// `HTTP` keyword
    #[token("HTTP")]
    Http,
    /// `HTTP2` keyword
    #[token("HTTP2")]
    Http2,
    /// `GRPC` keyword
    #[token("GRPC")]
    Grpc,
    /// `WEBSOCKET` keyword
    #[token("WEBSOCKET")]
    Websocket,
    /// `TLS` keyword
    #[token("TLS")]
    Tls,
    /// `QUIC` keyword
    #[token("QUIC")]
    Quic,
    /// `STUN` keyword
    #[token("STUN")]
    Stun,
    /// `SIP` keyword
    #[token("SIP")]
    Sip,
    /// `RTP` keyword
    #[token("RTP")]
    Rtp,
    /// `RTSP` keyword
    #[token("RTSP")]
    Rtsp,
    /// `SMTP` keyword
    #[token("SMTP")]
    Smtp,
    /// `IMAP` keyword
    #[token("IMAP")]
    Imap,
    /// `POP3` keyword
    #[token("POP3")]
    Pop3,
    /// `KERBEROS` keyword
    #[token("KERBEROS")]
    Kerberos,
    /// `LDAP` keyword
    #[token("LDAP")]
    Ldap,
    /// `SMB` keyword
    #[token("SMB")]
    Smb,
    /// `NFS` keyword
    #[token("NFS")]
    Nfs,
    /// `REDIS` keyword
    #[token("REDIS")]
    Redis,
    /// `MEMCACHED` keyword
    #[token("MEMCACHED")]
    Memcached,
    /// `MYSQL` keyword
    #[token("MYSQL")]
    Mysql,
    /// `POSTGRES` keyword
    #[token("POSTGRES")]
    Postgres,
    /// `MQTT` keyword
    #[token("MQTT")]
    Mqtt,
    /// `COAP` keyword
    #[token("COAP")]
    Coap,
    /// `AMQP` keyword
    #[token("AMQP")]
    Amqp,
    /// `SSDP` keyword
    #[token("SSDP")]
    Ssdp,
    /// `WHOIS` keyword
    #[token("WHOIS")]
    Whois,

    // Category 6: Layer 7 Industrial / OT Protocols
    /// `MODBUS` keyword
    #[token("MODBUS")]
    Modbus,
    /// `BACNET` keyword
    #[token("BACNET")]
    Bacnet,
    /// `DNP3` keyword
    #[token("DNP3")]
    Dnp3,
    /// `S7COMM` keyword
    #[token("S7COMM")]
    S7comm,
    /// `ETHERNETIP` keyword
    #[token("ETHERNETIP")]
    Ethernetip,
    /// `OPCUA` keyword
    #[token("OPCUA")]
    Opcua,

    // Category 4 Sub-keywords
    /// `TXID` keyword
    #[token("TXID")]
    Txid,
    /// `QNAME` keyword
    #[token("QNAME")]
    Qname,
    /// `QTYPE` keyword
    #[token("QTYPE")]
    Qtype,
    /// `RDATA` keyword
    #[token("RDATA")]
    Rdata,
    /// `RCODE` keyword
    #[token("RCODE")]
    Rcode,
    /// `ANS_TTL` keyword
    #[token("ANS_TTL")]
    AnsTtl,

    /// `DISCOVER` keyword
    #[token("DISCOVER")]
    Discover,
    /// `SOLICIT` keyword
    #[token("SOLICIT")]
    Solicit,
    /// `OFFER` keyword
    #[token("OFFER")]
    Offer,
    /// `ADVERTISE` keyword
    #[token("ADVERTISE")]
    Advertise,
    /// `RELEASE` keyword
    #[token("RELEASE")]
    Release,
    /// `CIADDR` keyword
    #[token("CIADDR")]
    Ciaddr,
    /// `YIADDR` keyword
    #[token("YIADDR")]
    Yiaddr,
    /// `SIADDR` keyword
    #[token("SIADDR")]
    Siaddr,
    /// `CHADDR` keyword
    #[token("CHADDR")]
    Chaddr,
    /// `HOSTNAME` keyword
    #[token("HOSTNAME")]
    Hostname,
    /// `DNS_SERVER` keyword
    #[token("DNS_SERVER")]
    DnsServer,
    /// `ROUTER` keyword
    #[token("ROUTER")]
    Router,
    /// `SUBNET_MASK` keyword
    #[token("SUBNET_MASK")]
    SubnetMask,
    /// `LEASE_TIME` keyword
    #[token("LEASE_TIME")]
    LeaseTime,

    /// `LI` keyword
    #[token("LI")]
    Li,
    /// `VN` keyword
    #[token("VN")]
    Vn,
    /// `MODE` keyword
    #[token("MODE")]
    Mode,
    /// `STRATUM` keyword
    #[token("STRATUM")]
    Stratum,
    /// `POLL` keyword
    #[token("POLL")]
    Poll,
    /// `PRECISION` keyword
    #[token("PRECISION")]
    Precision,
    /// `REFID` keyword
    #[token("REFID")]
    RefId,
    /// `TX_TIMESTAMP` keyword
    #[token("TX_TIMESTAMP")]
    TxTimestamp,

    /// `MSG_TYPE` keyword
    #[token("MSG_TYPE")]
    MsgType,
    /// `SYNC` keyword
    #[token("SYNC")]
    Sync,
    /// `DELAY_REQ` keyword
    #[token("DELAY_REQ")]
    DelayReq,
    /// `FOLLOW_UP` keyword
    #[token("FOLLOW_UP")]
    FollowUp,
    /// `DELAY_RESP` keyword
    #[token("DELAY_RESP")]
    DelayResp,
    /// `ANNOUNCE` keyword
    #[token("ANNOUNCE")]
    Announce,
    /// `DOMAIN` keyword
    #[token("DOMAIN")]
    Domain,
    /// `SEQ_ID` keyword
    #[token("SEQ_ID")]
    SeqId,
    /// `CLOCK_ID` keyword
    #[token("CLOCK_ID")]
    ClockId,

    /// `ACCESS_REQUEST` keyword
    #[token("ACCESS_REQUEST")]
    AccessRequest,
    /// `ACCESS_ACCEPT` keyword
    #[token("ACCESS_ACCEPT")]
    AccessAccept,
    /// `ACCESS_REJECT` keyword
    #[token("ACCESS_REJECT")]
    AccessReject,
    /// `ACCESS_CHALLENGE` keyword
    #[token("ACCESS_CHALLENGE")]
    AccessChallenge,
    /// `ACCOUNTING_REQUEST` keyword
    #[token("ACCOUNTING_REQUEST")]
    AccountingRequest,
    /// `ACCOUNTING_RESPONSE` keyword
    #[token("ACCOUNTING_RESPONSE")]
    AccountingResponse,
    /// `NAS_IP` keyword
    #[token("NAS_IP")]
    NasIp,
    /// `SERVICE_TYPE` keyword
    #[token("SERVICE_TYPE")]
    ServiceType,
    /// `FRAMED_IP` keyword
    #[token("FRAMED_IP")]
    FramedIp,

    /// `AUTHEN` keyword
    #[token("AUTHEN")]
    Authen,
    /// `AUTHOR` keyword
    #[token("AUTHOR")]
    Author,
    /// `ACCT` keyword
    #[token("ACCT")]
    Acct,
    /// `SESSION_ID` keyword
    #[token("SESSION_ID")]
    SessionId,

    /// `FACILITY` keyword
    #[token("FACILITY")]
    Facility,
    /// `SEVERITY` keyword
    #[token("SEVERITY")]
    Severity,
    /// `PRI` keyword
    #[token("PRI")]
    Pri,
    /// `APP` keyword
    #[token("APP")]
    App,
    /// `PROCID` keyword
    #[token("PROCID")]
    Procid,
    /// `MSG` keyword
    #[token("MSG")]
    Msg,

    /// `SRCIP` keyword
    #[token("SRCIP")]
    SrcIp,
    /// `DSTIP` keyword
    #[token("DSTIP")]
    DstIp,
    /// `PROTO` keyword
    #[token("PROTO")]
    Proto,
    /// `PACKETS` keyword
    #[token("PACKETS")]
    Packets,
    /// `OCTETS` keyword
    #[token("OCTETS")]
    Octets,
    /// `DOMAIN_ID` keyword
    #[token("DOMAIN_ID")]
    DomainId,

    /// `AGENT_IP` keyword
    #[token("AGENT_IP")]
    AgentIpSflow,
    /// `SUB_AGENT_ID` keyword
    #[token("SUB_AGENT_ID")]
    SubAgentId,
    /// `UPTIME` keyword
    #[token("UPTIME")]
    Uptime,
    /// `SAMPLES` keyword
    #[token("SAMPLES")]
    Samples,

    // Category 5 Sub-keywords
    /// `RRQ` keyword
    #[token("RRQ")]
    Rrq,
    /// `WRQ` keyword
    #[token("WRQ")]
    Wrq,
    /// `FILENAME` keyword
    #[token("FILENAME")]
    Filename,
    /// `BLOCK` keyword
    #[token("BLOCK")]
    Block,
    /// `ERRCODE` keyword
    #[token("ERRCODE")]
    ErrCode,
    /// `ERRMSG` keyword
    #[token("ERRMSG")]
    ErrMsg,

    /// `CMD` keyword
    #[token("CMD")]
    Cmd,
    /// `ARG` keyword
    #[token("ARG")]
    Arg,

    /// `BANNER` keyword
    #[token("BANNER")]
    Banner,
    /// `KEXINIT` keyword
    #[token("KEXINIT")]
    KexInit,
    /// `NEWKEYS` keyword
    #[token("NEWKEYS")]
    NewKeys,
    /// `MSG_CODE` keyword
    #[token("MSG_CODE")]
    MsgCode,

    /// `WILL` keyword
    #[token("WILL")]
    Will,
    /// `WONT` keyword
    #[token("WONT")]
    Wont,
    /// `DO` keyword
    #[token("DO")]
    DoCmd,
    /// `DONT` keyword
    #[token("DONT")]
    Dont,
    /// `OPTION` keyword
    #[token("OPTION")]
    Option,

    /// `POST` keyword
    #[token("POST")]
    Post,
    /// `PUT` keyword
    #[token("PUT")]
    Put,
    /// `DELETE` keyword
    #[token("DELETE")]
    Delete,
    /// `HEAD` keyword
    #[token("HEAD")]
    Head,
    /// `OPTIONS` keyword
    #[token("OPTIONS")]
    Options,
    /// `PATCH` keyword
    #[token("PATCH")]
    Patch,
    /// `URI` keyword
    #[token("URI")]
    Uri,
    /// `HOST_HDR` keyword
    #[token("HOST_HDR")]
    HostHdr,
    /// `USER_AGENT` keyword
    #[token("USER_AGENT")]
    UserAgent,
    /// `CONTENT_TYPE` keyword
    #[token("CONTENT_TYPE")]
    ContentType,
    /// `STATUS` keyword
    #[token("STATUS")]
    Status,
    /// `REASON` keyword
    #[token("REASON")]
    Reason,
    /// `HEADER` keyword
    #[token("HEADER")]
    Header,
    /// `BODY` keyword
    #[token("BODY")]
    Body,

    /// `PREFACE` keyword
    #[token("PREFACE")]
    Preface,
    /// `SETTINGS` keyword
    #[token("SETTINGS")]
    Settings,
    /// `HEADERS` keyword
    #[token("HEADERS")]
    Headers,
    /// `WINDOW_UPDATE` keyword
    #[token("WINDOW_UPDATE")]
    WindowUpdate,
    /// `PING` keyword
    #[token("PING")]
    Ping,
    /// `GOAWAY` keyword
    #[token("GOAWAY")]
    Goaway,
    /// `STREAM_ID` keyword
    #[token("STREAM_ID")]
    StreamId,

    /// `SERVICE` keyword
    #[token("SERVICE")]
    Service,
    /// `METHOD` keyword
    #[token("METHOD")]
    Method,
    /// `GRPC_STATUS` keyword
    #[token("GRPC_STATUS")]
    GrpcStatus,

    /// `OPCODE` keyword
    #[token("OPCODE")]
    Opcode,
    /// `TEXT` keyword
    #[token("TEXT")]
    Text,
    /// `BINARY` keyword
    #[token("BINARY")]
    Binary,
    /// `PONG` keyword
    #[token("PONG")]
    Pong,
    /// `CLOSE` keyword
    #[token("CLOSE")]
    Close,
    /// `FIN_BIT` keyword
    #[token("FIN_BIT")]
    FinBit,
    /// `MASK_KEY` keyword
    #[token("MASK_KEY")]
    MaskKey,

    /// `CLIENT_HELLO` keyword
    #[token("CLIENT_HELLO")]
    ClientHello,
    /// `SERVER_HELLO` keyword
    #[token("SERVER_HELLO")]
    ServerHello,
    /// `CERTIFICATE` keyword
    #[token("CERTIFICATE")]
    Certificate,
    /// `FINISHED` keyword
    #[token("FINISHED")]
    Finished,
    /// `APP_DATA` keyword
    #[token("APP_DATA")]
    AppData,
    /// `ALERT` keyword
    #[token("ALERT")]
    Alert,
    /// `RECORD_VERSION` keyword
    #[token("RECORD_VERSION")]
    RecordVersion,
    /// `HANDSHAKE_VERSION` keyword
    #[token("HANDSHAKE_VERSION")]
    HandshakeVersion,
    /// `SNI` keyword
    #[token("SNI")]
    Sni,
    /// `CIPHERSUITE` keyword
    #[token("CIPHERSUITE")]
    Ciphersuite,
    /// `ALPN` keyword
    #[token("ALPN")]
    Alpn,

    /// `INITIAL` keyword
    #[token("INITIAL")]
    Initial,
    /// `ZERO_RTT` keyword
    #[token("ZERO_RTT")]
    ZeroRtt,
    /// `HANDSHAKE` keyword
    #[token("HANDSHAKE")]
    Handshake,
    /// `RETRY` keyword
    #[token("RETRY")]
    Retry,
    /// `SHORT` keyword
    #[token("SHORT")]
    Short,
    /// `DCID` keyword
    #[token("DCID")]
    Dcid,
    /// `SCID` keyword
    #[token("SCID")]
    Scid,
    /// `TOKEN` keyword
    #[token("TOKEN")]
    Token,
    /// `PKT_NUM` keyword
    #[token("PKT_NUM")]
    PktNum,

    /// `BINDING_REQUEST` keyword
    #[token("BINDING_REQUEST")]
    BindingRequest,
    /// `BINDING_RESPONSE` keyword
    #[token("BINDING_RESPONSE")]
    BindingResponse,
    /// `BINDING_ERROR` keyword
    #[token("BINDING_ERROR")]
    BindingError,
    /// `XOR_MAPPED_ADDR` keyword
    #[token("XOR_MAPPED_ADDR")]
    XorMappedAddr,
    /// `SOFTWARE` keyword
    #[token("SOFTWARE")]
    Software,

    /// `INVITE` keyword
    #[token("INVITE")]
    Invite,
    /// `BYE` keyword
    #[token("BYE")]
    Bye,
    /// `CANCEL` keyword
    #[token("CANCEL")]
    Cancel,
    /// `FROM` keyword
    #[token("FROM")]
    From,
    /// `TO` keyword
    #[token("TO")]
    To,
    /// `CALL_ID` keyword
    #[token("CALL_ID")]
    CallId,
    /// `CSEQ` keyword
    #[token("CSEQ")]
    Cseq,
    /// `VIA` keyword
    #[token("VIA")]
    Via,
    /// `CONTACT` keyword
    #[token("CONTACT")]
    Contact,

    /// `PT` keyword
    #[token("PT")]
    Pt,
    /// `TIMESTAMP` keyword
    #[token("TIMESTAMP")]
    Timestamp,
    /// `SSRC` keyword
    #[token("SSRC")]
    Ssrc,
    /// `MARKER` keyword
    #[token("MARKER")]
    Marker,

    /// `DESCRIBE` keyword
    #[token("DESCRIBE")]
    Describe,
    /// `SETUP` keyword
    #[token("SETUP")]
    Setup,
    /// `PLAY` keyword
    #[token("PLAY")]
    Play,
    /// `TEARDOWN` keyword
    #[token("TEARDOWN")]
    Teardown,
    /// `TRANSPORT_HDR` keyword
    #[token("TRANSPORT_HDR")]
    TransportHdr,
    /// `SESSION` keyword
    #[token("SESSION")]
    Session,

    /// `EHLO` keyword
    #[token("EHLO")]
    Ehlo,
    /// `HELO` keyword
    #[token("HELO")]
    Helo,
    /// `MAIL_FROM` keyword
    #[token("MAIL_FROM")]
    MailFrom,
    /// `RCPT_TO` keyword
    #[token("RCPT_TO")]
    RcptTo,
    /// `QUIT` keyword
    #[token("QUIT")]
    Quit,
    /// `PARAM` keyword
    #[token("PARAM")]
    Param,

    /// `OK` keyword
    #[token("OK")]
    Ok,
    /// `ERR` keyword
    #[token("ERR")]
    Err,

    /// `AS_REQ` keyword
    #[token("AS_REQ")]
    AsReq,
    /// `AS_REP` keyword
    #[token("AS_REP")]
    AsRep,
    /// `TGS_REQ` keyword
    #[token("TGS_REQ")]
    TgsReq,
    /// `TGS_REP` keyword
    #[token("TGS_REP")]
    TgsRep,
    /// `KRB_ERROR` keyword
    #[token("KRB_ERROR")]
    KrbError,
    /// `REALM` keyword
    #[token("REALM")]
    Realm,
    /// `CNAME` keyword
    #[token("CNAME")]
    Cname,
    /// `SNAME` keyword
    #[token("SNAME")]
    Sname,
    /// `ETYPE` keyword
    #[token("ETYPE")]
    Etype,

    /// `BIND_REQ` keyword
    #[token("BIND_REQ")]
    BindReq,
    /// `BIND_RES` keyword
    #[token("BIND_RES")]
    BindRes,
    /// `SEARCH_REQ` keyword
    #[token("SEARCH_REQ")]
    SearchReq,
    /// `SEARCH_ENTRY` keyword
    #[token("SEARCH_ENTRY")]
    SearchEntry,
    /// `SEARCH_DONE` keyword
    #[token("SEARCH_DONE")]
    SearchDone,
    /// `UNBIND_REQ` keyword
    #[token("UNBIND_REQ")]
    UnbindReq,
    /// `BASE_DN` keyword
    #[token("BASE_DN")]
    BaseDn,
    /// `FILTER` keyword
    #[token("FILTER")]
    Filter,
    /// `RESULT_CODE` keyword
    #[token("RESULT_CODE")]
    ResultCode,

    /// `COMMAND` keyword
    #[token("COMMAND")]
    Command,
    /// `NEGOTIATE` keyword
    #[token("NEGOTIATE")]
    Negotiate,
    /// `SESSION_SETUP` keyword
    #[token("SESSION_SETUP")]
    SessionSetup,
    /// `TREE_CONNECT` keyword
    #[token("TREE_CONNECT")]
    TreeConnect,
    /// `CREATE` keyword
    #[token("CREATE")]
    Create,
    /// `TREE_DISCONNECT` keyword
    #[token("TREE_DISCONNECT")]
    TreeDisconnect,
    /// `TREE_ID` keyword
    #[token("TREE_ID")]
    TreeId,
    /// `SHARE` keyword
    #[token("SHARE")]
    Share,

    /// `VERS` keyword
    #[token("VERS")]
    Vers,
    /// `PROC` keyword
    #[token("PROC")]
    Proc,
    /// `PATH` keyword
    #[token("PATH")]
    Path,
    /// `COMPOUND` keyword
    #[token("COMPOUND")]
    Compound,

    /// `ARGS` keyword
    #[token("ARGS")]
    Args,
    /// `REPLY_TYPE` keyword
    #[token("REPLY_TYPE")]
    ReplyType,
    /// `VALUE` keyword
    #[token("VALUE")]
    Value,

    /// `EXPTIME` keyword
    #[token("EXPTIME")]
    Exptime,
    /// `OPAQUE` keyword
    #[token("OPAQUE")]
    Opaque,
    /// `CAS` keyword
    #[token("CAS")]
    Cas,

    /// `GREETING` keyword
    #[token("GREETING")]
    Greeting,
    /// `LOGIN` keyword
    #[token("LOGIN")]
    Login,
    /// `SQL` keyword
    #[token("SQL")]
    Sql,
    /// `EOF` keyword
    #[token("EOF")]
    Eof,
    /// `SERVER_VERSION` keyword
    #[token("SERVER_VERSION")]
    ServerVersion,
    /// `DB` keyword
    #[token("DB")]
    Db,

    /// `STARTUP` keyword
    #[token("STARTUP")]
    Startup,
    /// `READY_FOR_QUERY` keyword
    #[token("READY_FOR_QUERY")]
    ReadyForQuery,
    /// `COMMAND_COMPLETE` keyword
    #[token("COMMAND_COMPLETE")]
    CommandComplete,
    /// `ERROR_RESPONSE` keyword
    #[token("ERROR_RESPONSE")]
    ErrorResponse,
    /// `AUTH_OK` keyword
    #[token("AUTH_OK")]
    AuthOk,

    /// `CONNECT` keyword
    #[token("CONNECT")]
    Connect,
    /// `CONNACK` keyword
    #[token("CONNACK")]
    Connack,
    /// `PUBLISH` keyword
    #[token("PUBLISH")]
    Publish,
    /// `PUBACK` keyword
    #[token("PUBACK")]
    Puback,
    /// `SUBSCRIBE` keyword
    #[token("SUBSCRIBE")]
    Subscribe,
    /// `SUBACK` keyword
    #[token("SUBACK")]
    Suback,
    /// `PINGREQ` keyword
    #[token("PINGREQ")]
    Pingreq,
    /// `PINGRESP` keyword
    #[token("PINGRESP")]
    Pingresp,
    /// `DISCONNECT` keyword
    #[token("DISCONNECT")]
    Disconnect,
    /// `CLIENT_ID` keyword
    #[token("CLIENT_ID")]
    ClientId,
    /// `TOPIC` keyword
    #[token("TOPIC")]
    Topic,
    /// `QOS` keyword
    #[token("QOS")]
    Qos,
    /// `RETAIN` keyword
    #[token("RETAIN")]
    Retain,
    /// `PKT_ID` keyword
    #[token("PKT_ID")]
    PktId,
    /// `RETURN_CODE` keyword
    #[token("RETURN_CODE")]
    ReturnCode,

    /// `CON` keyword
    #[token("CON")]
    Con,
    /// `NON` keyword
    #[token("NON")]
    Non,
    /// `CHANGED` keyword
    #[token("CHANGED")]
    Changed,
    /// `CREATED` keyword
    #[token("CREATED")]
    Created,
    /// `NOT_FOUND` keyword
    #[token("NOT_FOUND")]
    NotFound,
    /// `URI_PATH` keyword
    #[token("URI_PATH")]
    UriPath,
    /// `CONTENT_FORMAT` keyword
    #[token("CONTENT_FORMAT")]
    ContentFormat,

    /// `PROTOCOL_HEADER` keyword
    #[token("PROTOCOL_HEADER")]
    ProtocolHeader,
    /// `CONNECTION_START` keyword
    #[token("CONNECTION_START")]
    ConnectionStart,
    /// `CHANNEL_OPEN` keyword
    #[token("CHANNEL_OPEN")]
    ChannelOpen,
    /// `BASIC_PUBLISH` keyword
    #[token("BASIC_PUBLISH")]
    BasicPublish,
    /// `BASIC_DELIVER` keyword
    #[token("BASIC_DELIVER")]
    BasicDeliver,
    /// `CHANNEL` keyword
    #[token("CHANNEL")]
    Channel,
    /// `ROUTING_KEY` keyword
    #[token("ROUTING_KEY")]
    RoutingKey,

    /// `MSEARCH` keyword
    #[token("MSEARCH")]
    Msearch,
    /// `NOTIFY` keyword
    #[token("NOTIFY")]
    Notify,
    /// `MAN` keyword
    #[token("MAN")]
    Man,
    /// `MX` keyword
    #[token("MX")]
    Mx,
    /// `ST` keyword
    #[token("ST")]
    St,
    /// `NT` keyword
    #[token("NT")]
    Nt,
    /// `NTS` keyword
    #[token("NTS")]
    Nts,
    /// `USN` keyword
    #[token("USN")]
    Usn,
    /// `LOCATION` keyword
    #[token("LOCATION")]
    Location,

    /// `REGISTRAR` keyword
    #[token("REGISTRAR")]
    Registrar,

    // Category 6 Sub-keywords
    /// `PROTO_ID` keyword
    #[token("PROTO_ID")]
    ProtoId,
    /// `UNITID` keyword
    #[token("UNITID")]
    UnitId,
    /// `FUNC` keyword
    #[token("FUNC")]
    Func,
    /// `READ_COILS` keyword
    #[token("READ_COILS")]
    ReadCoils,
    /// `READ_DISCRETE_INPUTS` keyword
    #[token("READ_DISCRETE_INPUTS")]
    ReadDiscreteInputs,
    /// `READ_HOLDING_REGISTERS` keyword
    #[token("READ_HOLDING_REGISTERS")]
    ReadHoldingRegisters,
    /// `READ_INPUT_REGISTERS` keyword
    #[token("READ_INPUT_REGISTERS")]
    ReadInputRegisters,
    /// `WRITE_SINGLE_COIL` keyword
    #[token("WRITE_SINGLE_COIL")]
    WriteSingleCoil,
    /// `WRITE_SINGLE_REGISTER` keyword
    #[token("WRITE_SINGLE_REGISTER")]
    WriteSingleRegister,
    /// `WRITE_MULTIPLE_REGISTERS` keyword
    #[token("WRITE_MULTIPLE_REGISTERS")]
    WriteMultipleRegisters,
    /// `ADDR` keyword
    #[token("ADDR")]
    Addr,
    /// `COUNT` keyword
    #[token("COUNT")]
    Count,
    /// `IS_RESPONSE` keyword
    #[token("IS_RESPONSE")]
    IsResponse,

    /// `WHO_IS` keyword
    #[token("WHO_IS")]
    WhoIs,
    /// `I_AM` keyword
    #[token("I_AM")]
    IAm,
    /// `READ_PROPERTY` keyword
    #[token("READ_PROPERTY")]
    ReadProperty,
    /// `WRITE_PROPERTY` keyword
    #[token("WRITE_PROPERTY")]
    WriteProperty,
    /// `INVOKE_ID` keyword
    #[token("INVOKE_ID")]
    InvokeId,
    /// `OBJECT_TYPE` keyword
    #[token("OBJECT_TYPE")]
    ObjectType,
    /// `OBJECT_INSTANCE` keyword
    #[token("OBJECT_INSTANCE")]
    ObjectInstance,
    /// `PROPERTY_ID` keyword
    #[token("PROPERTY_ID")]
    PropertyId,

    /// `CONFIRM` keyword
    #[token("CONFIRM")]
    Confirm,
    /// `SELECT` keyword
    #[token("SELECT")]
    Select,
    /// `OPERATE` keyword
    #[token("OPERATE")]
    Operate,
    /// `DIRECT_OPERATE` keyword
    #[token("DIRECT_OPERATE")]
    DirectOperate,
    /// `UNSOLICITED_RESPONSE` keyword
    #[token("UNSOLICITED_RESPONSE")]
    UnsolicitedResponse,
    /// `VARIATION` keyword
    #[token("VARIATION")]
    Variation,
    /// `CRC` keyword
    #[token("CRC")]
    Crc,
    /// `SRC` keyword
    #[token("SRC")]
    Src,
    /// `DST` keyword
    #[token("DST")]
    Dst,

    /// `ROSCTR` keyword
    #[token("ROSCTR")]
    Rosctr,
    /// `PDU_REF` keyword
    #[token("PDU_REF")]
    PduRef,
    /// `SETUP_COMM` keyword
    #[token("SETUP_COMM")]
    SetupComm,
    /// `READ_VAR` keyword
    #[token("READ_VAR")]
    ReadVar,
    /// `WRITE_VAR` keyword
    #[token("WRITE_VAR")]
    WriteVar,
    /// `PLC_CONTROL` keyword
    #[token("PLC_CONTROL")]
    PlcControl,
    /// `AREA` keyword
    #[token("AREA")]
    Area,
    /// `DB_NUM` keyword
    #[token("DB_NUM")]
    DbNum,
    /// `OFFSET` keyword
    #[token("OFFSET")]
    Offset,

    /// `LIST_SERVICES` keyword
    #[token("LIST_SERVICES")]
    ListServices,
    /// `LIST_IDENTITY` keyword
    #[token("LIST_IDENTITY")]
    ListIdentity,
    /// `LIST_INTERFACES` keyword
    #[token("LIST_INTERFACES")]
    ListInterfaces,
    /// `REGISTER_SESSION` keyword
    #[token("REGISTER_SESSION")]
    RegisterSession,
    /// `UNREGISTER_SESSION` keyword
    #[token("UNREGISTER_SESSION")]
    UnregisterSession,
    /// `SEND_RR_DATA` keyword
    #[token("SEND_RR_DATA")]
    SendRrData,
    /// `SEND_UNIT_DATA` keyword
    #[token("SEND_UNIT_DATA")]
    SendUnitData,
    /// `SESSION_HANDLE` keyword
    #[token("SESSION_HANDLE")]
    SessionHandle,
    /// `CONTEXT` keyword
    #[token("CONTEXT")]
    ContextVal,
    /// `CIP_SERVICE` keyword
    #[token("CIP_SERVICE")]
    CipService,
    /// `CIP_CLASS` keyword
    #[token("CIP_CLASS")]
    CipClass,
    /// `CIP_INSTANCE` keyword
    #[token("CIP_INSTANCE")]
    CipInstance,
    /// `CIP_ATTR` keyword
    #[token("CIP_ATTR")]
    CipAttr,

    /// `CHUNK_TYPE` keyword
    #[token("CHUNK_TYPE")]
    ChunkType,
    /// `SECURE_CHANNEL_ID` keyword
    #[token("SECURE_CHANNEL_ID")]
    SecureChannelId,
    /// `TOKEN_ID` keyword
    #[token("TOKEN_ID")]
    TokenId,
    /// `SEQ_NUM` keyword
    #[token("SEQ_NUM")]
    SeqNum,
    /// `ENDPOINT_URL` keyword
    #[token("ENDPOINT_URL")]
    EndpointUrl,
    /// `NODE_ID` keyword
    #[token("NODE_ID")]
    NodeId,

    /// `->` operator
    #[token("->")]
    RightArrow,
    /// `<-` operator
    #[token("<-")]
    LeftArrow,
    /// `{` token
    #[token("{")]
    LBrace,
    /// `}` token
    #[token("}")]
    RBrace,
    /// `(` token
    #[token("(")]
    LParen,
    /// `)` token
    #[token(")")]
    RParen,
    /// `,` token
    #[token(",")]
    Comma,

    // Time suffixes
    /// `ns` suffix
    #[token("ns", priority = 2)]
    Ns,
    /// `us` suffix
    #[token("us", priority = 2)]
    Us,
    /// `ms` suffix
    #[token("ms", priority = 2)]
    Ms,
    /// `s` suffix
    #[token("s", priority = 2)]
    Sec,
    /// `m` suffix
    #[token("m", priority = 2)]
    Min,

    /// Identifier
    #[regex("[a-zA-Z_][a-zA-Z0-9_]*", priority = 1)]
    Ident(&'a str),

    /// String literal
    #[regex(r#""([^"\\]|\\.)*""#)]
    StringLit(&'a str),

    // Match IPv4 and IPv6-like strings loosely, parser will validate
    /// IPv4/IPv6 address
    #[regex(r"[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+", priority = 5)]
    #[regex(r"::[0-9a-fA-F:.]*|[0-9a-fA-F]{1,4}(:[0-9a-fA-F:.]*)+", priority = 2)]
    IpAddress(&'a str),

    // Match MAC addresses loosely
    /// MAC address
    #[regex(r"([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}", priority = 6)]
    MacAddress(&'a str),

    // Match OIDs loosely
    /// SNMP OID
    #[regex(r"\.?[0-9]+(\.[0-9]+)*", priority = 3)]
    OidStr(&'a str),

    /// Numeric literal (supports decimal and hex integers)
    #[regex(r"-?[0-9]+|0[xX][0-9a-fA-F]+", priority = 4)]
    Number(&'a str),
}

/// Lexes an input string into a sequence of tokens and their source spans.
///
/// # Examples
/// ```
/// use frameassembly::lexer::lex;
///
/// let input = "HOST example { IP 10.0.0.1 }";
/// let tokens = lex(input).unwrap();
/// assert_eq!(tokens.len(), 6);
/// ```
///
/// # Errors
/// Returns a `CompilerError::LexError` if an unrecognized sequence of characters is encountered.
pub fn lex<'a>(
    input: &'a str,
) -> Result<alloc::vec::Vec<(Token<'a>, std::ops::Range<usize>)>, crate::error::CompilerError> {
    let mut lexer = Token::lexer(input);
    let mut tokens = alloc::vec::Vec::new();
    while let Some(res) = lexer.next() {
        match res {
            Ok(token) => tokens.push((token, lexer.span())),
            Err(_) => {
                return Err(crate::error::CompilerError::LexError {
                    src: input.to_string(),
                    span: (lexer.span().start, lexer.span().end - lexer.span().start),
                });
            }
        }
    }
    Ok(tokens)
}

#[cfg(test)]
mod tests;
