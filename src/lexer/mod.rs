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
  /// `HOST`
  #[token("HOST", ignore(ascii_case))] Host,
  /// `FLOW`
  #[token("FLOW", ignore(ascii_case))] Flow,
  /// `IP`
  #[token("IP", ignore(ascii_case))] Ip,
  /// `MAC`
  #[token("MAC", ignore(ascii_case))] Mac,
  /// `COMPILE`
  #[token("COMPILE", ignore(ascii_case))] Compile,
  /// `LOOP`
  #[token("LOOP", ignore(ascii_case))] Loop,
  /// `TCP`
  #[token("TCP", ignore(ascii_case))] Tcp,
  /// `UDP`
  #[token("UDP", ignore(ascii_case))] Udp,
  /// `SYN`
  #[token("SYN", ignore(ascii_case))] Syn,
  /// `ACK`
  #[token("ACK", ignore(ascii_case))] Ack,
  /// `FIN`
  #[token("FIN", ignore(ascii_case))] Fin,
  /// `RST`
  #[token("RST", ignore(ascii_case))] Rst,
  /// `PSH`
  #[token("PSH", ignore(ascii_case))] Psh,
  /// `URG`
  #[token("URG", ignore(ascii_case))] Urg,
  /// `ECE`
  #[token("ECE", ignore(ascii_case))] Ece,
  /// `CWR`
  #[token("CWR", ignore(ascii_case))] Cwr,
  /// `SRCPORT`
  #[token("SRCPORT", ignore(ascii_case))] SrcPort,
  /// `DSTPORT`
  #[token("DSTPORT", ignore(ascii_case))] DstPort,
  /// `SEQ`
  #[token("SEQ", ignore(ascii_case))] Seq,
  /// `ACKNUM`
  #[token("ACKNUM", ignore(ascii_case))] AckNum,
  /// `WIN`
  #[token("WIN", ignore(ascii_case))] Win,
  /// `PAYLOAD`
  #[token("PAYLOAD", ignore(ascii_case))] Payload,
  /// `HEXPAYLOAD`
  #[token("HEXPAYLOAD", ignore(ascii_case))] HexPayload,
  /// `WAIT`
  #[token("WAIT", ignore(ascii_case))] Wait,
  /// `VLAN`
  #[token("VLAN", ignore(ascii_case))] Vlan,
  /// `DSCP`
  #[token("DSCP", ignore(ascii_case))] Dscp,
  /// `ECN`
  #[token("ECN", ignore(ascii_case))] Ecn,
  /// `TTL`
  #[token("TTL", ignore(ascii_case))] Ttl,
  /// `FLOWLABEL`
  #[token("FLOWLABEL", ignore(ascii_case))] FlowLabel,
  /// `SNMP1`
  #[token("SNMP1", ignore(ascii_case))] Snmp1,
  /// `SNMP2`
  #[token("SNMP2", ignore(ascii_case))] Snmp2,
  /// `SNMP3`
  #[token("SNMP3", ignore(ascii_case))] Snmp3,
  /// `TRAP`
  #[token("TRAP", ignore(ascii_case))] Trap,
  /// `GET`
  #[token("GET", ignore(ascii_case))] Get,
  /// `SET`
  #[token("SET", ignore(ascii_case))] Set,
  /// `RESPONSE`
  #[token("RESPONSE", ignore(ascii_case))] Response,
  /// `INFORM`
  #[token("INFORM", ignore(ascii_case))] Inform,
  /// `GETNEXT`
  #[token("GETNEXT", ignore(ascii_case))] GetNext,
  /// `GETBULK`
  #[token("GETBULK", ignore(ascii_case))] GetBulk,
  /// `COMMUNITY`
  #[token("COMMUNITY", ignore(ascii_case))] Community,
  /// `USER`
  #[token("USER", ignore(ascii_case))] User,
  /// `OID`
  #[token("OID", ignore(ascii_case))] Oid,
  /// `SYSUPTIME`
  #[token("SYSUPTIME", ignore(ascii_case))] SysUpTime,
  /// `VARBIND`
  #[token("VARBIND", ignore(ascii_case))] VarBind,
  /// `NULLVAL`
  #[token("NULLVAL", ignore(ascii_case))]
  #[token("NULL", ignore(ascii_case))] NullVal,
  /// `STRING`
  #[token("STRING", ignore(ascii_case))] StringVal,
  /// `INT`
  #[token("INT", ignore(ascii_case))] IntVal,
  /// `TIMETICKS`
  #[token("TIMETICKS", ignore(ascii_case))] TimeTicksVal,
  /// `IPVAL`
  #[token("IPVAL", ignore(ascii_case))] IpVal,
  /// `OIDVAL`
  #[token("OIDVAL", ignore(ascii_case))] OidVal,
  /// `COUNTER32`
  #[token("COUNTER32", ignore(ascii_case))] Counter32Val,
  /// `GAUGE32`
  #[token("GAUGE32", ignore(ascii_case))] Gauge32Val,
  /// `COUNTER64`
  #[token("COUNTER64", ignore(ascii_case))] Counter64Val,
  /// `ENTERPRISE`
  #[token("ENTERPRISE", ignore(ascii_case))] Enterprise,
  /// `AGENTIP`
  #[token("AGENTIP", ignore(ascii_case))] AgentIp,
  /// `GENTRAP`
  #[token("GENTRAP", ignore(ascii_case))] GenTrap,
  /// `SPECTRAP`
  #[token("SPECTRAP", ignore(ascii_case))] SpecTrap,
  /// `ENGINEID`
  #[token("ENGINEID", ignore(ascii_case))] EngineId,
  /// `ENGINEBOOTS`
  #[token("ENGINEBOOTS", ignore(ascii_case))] EngineBoots,
  /// `ENGINETIME`
  #[token("ENGINETIME", ignore(ascii_case))] EngineTime,
  /// `CONTEXTNAME`
  #[token("CONTEXTNAME", ignore(ascii_case))] ContextName,
  /// `AUTH`
  #[token("AUTH", ignore(ascii_case))] Auth,
  /// `PRIV`
  #[token("PRIV", ignore(ascii_case))] Priv,
  /// `MD5`
  #[token("MD5", ignore(ascii_case))] Md5,
  /// `SHA`
  #[token("SHA", ignore(ascii_case))] Sha,
  /// `SHA256`
  #[token("SHA256", ignore(ascii_case))] Sha256,
  /// `SHA384`
  #[token("SHA384", ignore(ascii_case))] Sha384,
  /// `SHA512`
  #[token("SHA512", ignore(ascii_case))] Sha512,
  /// `DES`
  #[token("DES", ignore(ascii_case))] Des,
  /// `AES`
  #[token("AES", ignore(ascii_case))] Aes,
  /// `NONREPEATERS`
  #[token("NONREPEATERS", ignore(ascii_case))] NonRepeaters,
  /// `MAXREPETITIONS`
  #[token("MAXREPETITIONS", ignore(ascii_case))] MaxRepetitions,
  /// `REQID`
  #[token("REQID", ignore(ascii_case))] ReqId,
  // Layer 2 modifiers
  /// `PCP`
  #[token("PCP", ignore(ascii_case))] Pcp,
  /// `DEI`
  #[token("DEI", ignore(ascii_case))] Dei,
  /// `QINQ`
  #[token("QINQ", ignore(ascii_case))] Qinq,
  /// `INNER_VLAN`
  #[token("INNER_VLAN", ignore(ascii_case))] InnerVlan,
  /// `MPLS`
  #[token("MPLS", ignore(ascii_case))] Mpls,
  /// `EXP` or `TC`
  #[token("EXP", ignore(ascii_case))]
  #[token("TC", ignore(ascii_case))] Exp,
  /// `BOS`
  #[token("BOS", ignore(ascii_case))] Bos,
  /// `MPLS_TTL`
  #[token("MPLS_TTL", ignore(ascii_case))] MplsTtl,
  /// `SRCMAC`
  #[token("SRCMAC", ignore(ascii_case))] SrcMac,
  /// `DSTMAC`
  #[token("DSTMAC", ignore(ascii_case))] DstMac,
  /// `ETHERTYPE`
  #[token("ETHERTYPE", ignore(ascii_case))] EtherType,
  // Layer 3 modifiers
  /// `IPID`
  #[token("IPID", ignore(ascii_case))] IpId,
  /// `DF`
  #[token("DF", ignore(ascii_case))] Df,
  /// `MF`
  #[token("MF", ignore(ascii_case))] Mf,
  /// `FRAGOFFSET`
  #[token("FRAGOFFSET", ignore(ascii_case))] FragOffset,
  // Layer 4 modifiers
  /// `TRANSPORT`
  #[token("TRANSPORT", ignore(ascii_case))] Transport,
  /// `WINDOW`
  #[token("WINDOW", ignore(ascii_case))] Window,
  /// `URGENT`
  #[token("URGENT", ignore(ascii_case))] Urgent,
  /// `MSS`
  #[token("MSS", ignore(ascii_case))] Mss,
  /// `WSCALE`
  #[token("WSCALE", ignore(ascii_case))] Wscale,
  /// `SACK_PERM`
  #[token("SACK_PERM", ignore(ascii_case))]
  #[token("SACKPERM", ignore(ascii_case))] SackPerm,
  /// `TSVAL`
  #[token("TSVAL", ignore(ascii_case))] Tsval,
  /// `TSECR`
  #[token("TSECR", ignore(ascii_case))] Tsecr,
  // SCTP overrides
  /// `VTAG`
  #[token("VTAG", ignore(ascii_case))] Vtag,
  /// `STREAM`
  #[token("STREAM", ignore(ascii_case))] Stream,
  /// `SSN`
  #[token("SSN", ignore(ascii_case))] Ssn,
  /// `PPID`
  #[token("PPID", ignore(ascii_case))] Ppid,
  /// `CHUNK`
  #[token("CHUNK", ignore(ascii_case))] Chunk,
  // Category 1: Layer 2 & DC Protocols
  /// `ARP`
  #[token("ARP", ignore(ascii_case))] Arp,
  /// `LLDP`
  #[token("LLDP", ignore(ascii_case))] Lldp,
  /// `STP`
  #[token("STP", ignore(ascii_case))] Stp,
  /// `LACP`
  #[token("LACP", ignore(ascii_case))] Lacp,
  /// `EAPOL`
  #[token("EAPOL", ignore(ascii_case))] Eapol,
  // Category 2: Layer 3, Tunneling, Security & Routing Protocols
  /// `ICMP`
  #[token("ICMP", ignore(ascii_case))] Icmp,
  /// `NDP`
  #[token("NDP", ignore(ascii_case))] Ndp,
  /// `IGMP`
  #[token("IGMP", ignore(ascii_case))] Igmp,
  /// `MLD`
  #[token("MLD", ignore(ascii_case))] Mld,
  /// `GRE`
  #[token("GRE", ignore(ascii_case))] Gre,
  /// `VXLAN`
  #[token("VXLAN", ignore(ascii_case))] Vxlan,
  /// `GENEVE`
  #[token("GENEVE", ignore(ascii_case))] Geneve,
  /// `IPSEC`
  #[token("IPSEC", ignore(ascii_case))] Ipsec,
  /// `ESP`
  #[token("ESP", ignore(ascii_case))] Esp,
  /// `AH`
  #[token("AH", ignore(ascii_case))] Ah,
  /// `IKEV2`
  #[token("IKEV2", ignore(ascii_case))] Ikev2,
  /// `WIREGUARD`
  #[token("WIREGUARD", ignore(ascii_case))] Wireguard,
  /// `OSPF`
  #[token("OSPF", ignore(ascii_case))] Ospf,
  /// `BGP`
  #[token("BGP", ignore(ascii_case))] Bgp,
  /// `RIP`
  #[token("RIP", ignore(ascii_case))] Rip,
  /// `VRRP`
  #[token("VRRP", ignore(ascii_case))] Vrrp,
  /// `HSRP`
  #[token("HSRP", ignore(ascii_case))] Hsrp,
  /// `PIM`
  #[token("PIM", ignore(ascii_case))] Pim,
  /// `BFD`
  #[token("BFD", ignore(ascii_case))] Bfd,
  /// `OPENFLOW`
  #[token("OPENFLOW", ignore(ascii_case))] Openflow,
  // Category 3: Layer 4 Transports
  /// `SCTP`
  #[token("SCTP", ignore(ascii_case))] Sctp,
  // Protocol Sub-keywords
  /// `REQUEST`
  #[token("REQUEST", ignore(ascii_case))] Request,
  /// `REPLY`
  #[token("REPLY", ignore(ascii_case))] Reply,
  /// `GRATUITOUS`
  #[token("GRATUITOUS", ignore(ascii_case))] Gratuitous,
  /// `GARP`
  #[token("GARP", ignore(ascii_case))] Garp,
  /// `SPA`
  #[token("SPA", ignore(ascii_case))] Spa,
  /// `THA`
  #[token("THA", ignore(ascii_case))] Tha,
  /// `TPA`
  #[token("TPA", ignore(ascii_case))] Tpa,
  /// `SENDERMAC`
  #[token("SENDERMAC", ignore(ascii_case))] SenderMac,
  /// `TARGETMAC`
  #[token("TARGETMAC", ignore(ascii_case))] TargetMac,
  /// `SENDERIP`
  #[token("SENDERIP", ignore(ascii_case))] SenderIp,
  /// `TARGETIP`
  #[token("TARGETIP", ignore(ascii_case))] TargetIp,
  /// `CHASSIS_ID`
  #[token("CHASSIS_ID", ignore(ascii_case))] ChassisId,
  /// `PORT_ID`
  #[token("PORT_ID", ignore(ascii_case))] PortId,
  /// `SYSNAME`
  #[token("SYSNAME", ignore(ascii_case))] SysName,
  /// `SYSDESC`
  #[token("SYSDESC", ignore(ascii_case))] SysDesc,
  /// `ROOT_ID`
  #[token("ROOT_ID", ignore(ascii_case))] RootId,
  /// `BRIDGE_ID`
  #[token("BRIDGE_ID", ignore(ascii_case))] BridgeId,
  /// `COST`
  #[token("COST", ignore(ascii_case))] Cost,
  /// `MAX_AGE`
  #[token("MAX_AGE", ignore(ascii_case))] MaxAge,
  /// `HELLO_TIME`
  #[token("HELLO_TIME", ignore(ascii_case))] HelloTime,
  /// `FORWARD_DELAY`
  #[token("FORWARD_DELAY", ignore(ascii_case))] ForwardDelay,
  /// `RSTP`
  #[token("RSTP", ignore(ascii_case))] Rstp,
  /// `FLAGS`
  #[token("FLAGS", ignore(ascii_case))] Flags,
  /// `ACTOR_SYS`
  #[token("ACTOR_SYS", ignore(ascii_case))] ActorSys,
  /// `ACTOR_KEY`
  #[token("ACTOR_KEY", ignore(ascii_case))] ActorKey,
  /// `ACTOR_PORT`
  #[token("ACTOR_PORT", ignore(ascii_case))] ActorPort,
  /// `PARTNER_SYS`
  #[token("PARTNER_SYS", ignore(ascii_case))] PartnerSys,
  /// `PARTNER_KEY`
  #[token("PARTNER_KEY", ignore(ascii_case))] PartnerKey,
  /// `PARTNER_PORT`
  #[token("PARTNER_PORT", ignore(ascii_case))] PartnerPort,
  /// `ACTOR_STATE`
  #[token("ACTOR_STATE", ignore(ascii_case))] ActorState,
  /// `PARTNER_STATE`
  #[token("PARTNER_STATE", ignore(ascii_case))] PartnerState,
  /// `VERSION`
  #[token("VERSION", ignore(ascii_case))] Version,
  /// `TYPE`
  #[token("TYPE", ignore(ascii_case))] Type,
  /// `EAP_PACKET`
  #[token("EAP_PACKET", ignore(ascii_case))] EapPacket,
  /// `START`
  #[token("START", ignore(ascii_case))] Start,
  /// `LOGOFF`
  #[token("LOGOFF", ignore(ascii_case))] Logoff,
  /// `KEY`
  #[token("KEY", ignore(ascii_case))] Key,
  /// `EAP_CODE`
  #[token("EAP_CODE", ignore(ascii_case))] EapCode,
  /// `EAP_ID`
  #[token("EAP_ID", ignore(ascii_case))] EapId,
  /// `EAP_METHOD`
  #[token("EAP_METHOD", ignore(ascii_case))] EapMethod,
  /// `IDENTITY`
  #[token("IDENTITY", ignore(ascii_case))] Identity,
  /// `LABEL`
  #[token("LABEL", ignore(ascii_case))] Label,
  /// `ECHO_REQUEST`
  #[token("ECHO_REQUEST", ignore(ascii_case))] EchoRequest,
  /// `ECHO_REPLY`
  #[token("ECHO_REPLY", ignore(ascii_case))] EchoReply,
  /// `DEST_UNREACH`
  #[token("DEST_UNREACH", ignore(ascii_case))] DestUnreach,
  /// `TIME_EXCEEDED`
  #[token("TIME_EXCEEDED", ignore(ascii_case))] TimeExceeded,
  /// `REDIRECT`
  #[token("REDIRECT", ignore(ascii_case))] Redirect,
  /// `CODE`
  #[token("CODE", ignore(ascii_case))] Code,
  /// `ID`
  #[token("ID", ignore(ascii_case))] Id,
  /// `GATEWAY`
  #[token("GATEWAY", ignore(ascii_case))] Gateway,
  /// `ROUTER_SOLICIT`
  #[token("ROUTER_SOLICIT", ignore(ascii_case))] RouterSolicit,
  /// `ROUTER_ADVERT`
  #[token("ROUTER_ADVERT", ignore(ascii_case))] RouterAdvert,
  /// `NEIGHBOR_SOLICIT`
  #[token("NEIGHBOR_SOLICIT", ignore(ascii_case))] NeighborSolicit,
  /// `NEIGHBOR_ADVERT`
  #[token("NEIGHBOR_ADVERT", ignore(ascii_case))] NeighborAdvert,
  /// `TARGET`
  #[token("TARGET", ignore(ascii_case))] Target,
  /// `SLLA`
  #[token("SLLA", ignore(ascii_case))] Slla,
  /// `TLLA`
  #[token("TLLA", ignore(ascii_case))] Tlla,
  /// `ROUTER_LIFETIME`
  #[token("ROUTER_LIFETIME", ignore(ascii_case))] RouterLifetime,
  /// `QUERY`
  #[token("QUERY", ignore(ascii_case))] Query,
  /// `REPORT`
  #[token("REPORT", ignore(ascii_case))] Report,
  /// `LEAVE`
  #[token("LEAVE", ignore(ascii_case))] Leave,
  /// `GROUP`
  #[token("GROUP", ignore(ascii_case))] Group,
  /// `MAX_RESP`
  #[token("MAX_RESP", ignore(ascii_case))] MaxResp,
  /// `V1`
  #[token("V1", ignore(ascii_case))] V1,
  /// `V2`
  #[token("V2", ignore(ascii_case))] V2,
  /// `V3`
  #[token("V3", ignore(ascii_case))] V3,
  /// `DONE`
  #[token("DONE", ignore(ascii_case))] Done,
  /// `MULTICAST_ADDR`
  #[token("MULTICAST_ADDR", ignore(ascii_case))] MulticastAddr,
  /// `MAX_RESP_DELAY`
  #[token("MAX_RESP_DELAY", ignore(ascii_case))] MaxRespDelay,
  /// `GRE_KEY`
  #[token("GRE_KEY", ignore(ascii_case))] GreKey,
  /// `GRE_SEQ`
  #[token("GRE_SEQ", ignore(ascii_case))] GreSeq,
  /// `GRE_PROTO`
  #[token("GRE_PROTO", ignore(ascii_case))] GreProto,
  /// `CHECKSUM`
  #[token("CHECKSUM", ignore(ascii_case))] Checksum,
  /// `VNI`
  #[token("VNI", ignore(ascii_case))] Vni,
  /// `VNID`
  #[token("VNID", ignore(ascii_case))] Vnid,
  /// `OPT_CLASS`
  #[token("OPT_CLASS", ignore(ascii_case))] OptClass,
  /// `OPT_TYPE`
  #[token("OPT_TYPE", ignore(ascii_case))] OptType,
  /// `PROTOCOL_TYPE`
  #[token("PROTOCOL_TYPE", ignore(ascii_case))] ProtocolType,
  /// `SPI`
  #[token("SPI", ignore(ascii_case))] Spi,
  /// `IV`
  #[token("IV", ignore(ascii_case))] Iv,
  /// `ICV`
  #[token("ICV", ignore(ascii_case))] Icv,
  /// `NEXT_HEADER`
  #[token("NEXT_HEADER", ignore(ascii_case))] NextHeader,
  /// `INITIATOR_SPI`
  #[token("INITIATOR_SPI", ignore(ascii_case))] InitiatorSpi,
  /// `RESPONDER_SPI`
  #[token("RESPONDER_SPI", ignore(ascii_case))] ResponderSpi,
  /// `EXCHANGE`
  #[token("EXCHANGE", ignore(ascii_case))] Exchange,
  /// `SA_INIT`
  #[token("SA_INIT", ignore(ascii_case))] SaInit,
  /// `CREATE_CHILD_SA`
  #[token("CREATE_CHILD_SA", ignore(ascii_case))] CreateChildSa,
  /// `INFORMATIONAL`
  #[token("INFORMATIONAL", ignore(ascii_case))] Informational,
  /// `MSGID`
  #[token("MSGID", ignore(ascii_case))] MsgId,
  /// `NEXT_PAYLOAD`
  #[token("NEXT_PAYLOAD", ignore(ascii_case))] NextPayload,
  /// `INITIATION`
  #[token("INITIATION", ignore(ascii_case))] Initiation,
  /// `COOKIE`
  #[token("COOKIE", ignore(ascii_case))] Cookie,
  /// `DATA`
  #[token("DATA", ignore(ascii_case))] Data,
  /// `SENDER`
  #[token("SENDER", ignore(ascii_case))] Sender,
  /// `RECEIVER`
  #[token("RECEIVER", ignore(ascii_case))] Receiver,
  /// `COUNTER`
  #[token("COUNTER", ignore(ascii_case))] Counter,
  /// `HELLO`
  #[token("HELLO", ignore(ascii_case))] Hello,
  /// `DBD`
  #[token("DBD", ignore(ascii_case))] Dbd,
  /// `LSR`
  #[token("LSR", ignore(ascii_case))] Lsr,
  /// `LSU`
  #[token("LSU", ignore(ascii_case))] Lsu,
  /// `LSACK`
  #[token("LSACK", ignore(ascii_case))] LsAck,
  /// `ROUTER_ID`
  #[token("ROUTER_ID", ignore(ascii_case))] RouterId,
  /// `AREA_ID`
  #[token("AREA_ID", ignore(ascii_case))] AreaId,
  /// `HELLO_INTERVAL`
  #[token("HELLO_INTERVAL", ignore(ascii_case))] HelloInterval,
  /// `DEAD_INTERVAL`
  #[token("DEAD_INTERVAL", ignore(ascii_case))] DeadInterval,
  /// `PRIORITY`
  #[token("PRIORITY", ignore(ascii_case))] Priority,
  /// `OPEN`
  #[token("OPEN", ignore(ascii_case))] Open,
  /// `UPDATE`
  #[token("UPDATE", ignore(ascii_case))] Update,
  /// `NOTIFICATION`
  #[token("NOTIFICATION", ignore(ascii_case))] Notification,
  /// `KEEPALIVE`
  #[token("KEEPALIVE", ignore(ascii_case))] Keepalive,
  /// `ASN`
  #[token("ASN", ignore(ascii_case))] Asn,
  /// `HOLDTIME`
  #[token("HOLDTIME", ignore(ascii_case))] HoldTime,
  /// `BGPID`
  #[token("BGPID", ignore(ascii_case))] BgpId,
  /// `PREFIX`
  #[token("PREFIX", ignore(ascii_case))] Prefix,
  /// `NLRI`
  #[token("NLRI", ignore(ascii_case))] Nlri,
  /// `NEXTHOP`
  #[token("NEXTHOP", ignore(ascii_case))] NextHop,
  /// `METRIC`
  #[token("METRIC", ignore(ascii_case))] Metric,
  /// `TAG`
  #[token("TAG", ignore(ascii_case))] Tag,
  /// `VRID`
  #[token("VRID", ignore(ascii_case))] Vrid,
  /// `ADV_INT`
  #[token("ADV_INT", ignore(ascii_case))] AdvInt,
  /// `VIP`
  #[token("VIP", ignore(ascii_case))] Vip,
  /// `HELLOTIME`
  #[token("HELLOTIME", ignore(ascii_case))] HelloTimeHsrp,
  /// `STATE`
  #[token("STATE", ignore(ascii_case))] State,
  /// `JOIN_PRUNE`
  #[token("JOIN_PRUNE", ignore(ascii_case))] JoinPrune,
  /// `REGISTER`
  #[token("REGISTER", ignore(ascii_case))] Register,
  /// `SOURCE`
  #[token("SOURCE", ignore(ascii_case))] Source,
  /// `RP`
  #[token("RP", ignore(ascii_case))] Rp,
  /// `DR_PRIORITY`
  #[token("DR_PRIORITY", ignore(ascii_case))] DrPriority,
  /// `DIAG`
  #[token("DIAG", ignore(ascii_case))] Diag,
  /// `MY_DISC`
  #[token("MY_DISC", ignore(ascii_case))] MyDisc,
  /// `YOUR_DISC`
  #[token("YOUR_DISC", ignore(ascii_case))] YourDisc,
  /// `MIN_TX`
  #[token("MIN_TX", ignore(ascii_case))] MinTx,
  /// `MIN_RX`
  #[token("MIN_RX", ignore(ascii_case))] MinRx,
  /// `MULT`
  #[token("MULT", ignore(ascii_case))] Mult,
  /// `FEATURES_REQ`
  #[token("FEATURES_REQ", ignore(ascii_case))] FeaturesReq,
  /// `FEATURES_REPLY`
  #[token("FEATURES_REPLY", ignore(ascii_case))] FeaturesReply,
  /// `PACKET_IN`
  #[token("PACKET_IN", ignore(ascii_case))] PacketIn,
  /// `PACKET_OUT`
  #[token("PACKET_OUT", ignore(ascii_case))] PacketOut,
  /// `FLOW_MOD`
  #[token("FLOW_MOD", ignore(ascii_case))] FlowMod,
  /// `ECHO_REQ`
  #[token("ECHO_REQ", ignore(ascii_case))] EchoReq,
  /// `XID`
  #[token("XID", ignore(ascii_case))] Xid,
  /// `DPID`
  #[token("DPID", ignore(ascii_case))] Dpid,
  /// `TABLE_ID`
  #[token("TABLE_ID", ignore(ascii_case))] TableId,
  /// `INIT`
  #[token("INIT", ignore(ascii_case))] Init,
  /// `INIT_ACK`
  #[token("INIT_ACK", ignore(ascii_case))] InitAck,
  /// `SACK`
  #[token("SACK", ignore(ascii_case))] Sack,
  /// `HEARTBEAT`
  #[token("HEARTBEAT", ignore(ascii_case))] Heartbeat,
  /// `HEARTBEAT_ACK`
  #[token("HEARTBEAT_ACK", ignore(ascii_case))] HeartbeatAck,
  /// `ABORT`
  #[token("ABORT", ignore(ascii_case))] Abort,
  /// `SHUTDOWN`
  #[token("SHUTDOWN", ignore(ascii_case))] Shutdown,
  /// `COOKIE_ECHO`
  #[token("COOKIE_ECHO", ignore(ascii_case))] CookieEcho,
  /// `COOKIE_ACK`
  #[token("COOKIE_ACK", ignore(ascii_case))] CookieAck,
  /// `TSN`
  #[token("TSN", ignore(ascii_case))] Tsn,
  // Category 4: Layer 7 Network Infrastructure, Management & Telemetry
  /// `DNS`
  #[token("DNS", ignore(ascii_case))] Dns,
  /// `MDNS`
  #[token("MDNS", ignore(ascii_case))] Mdns,
  /// `DHCP`
  #[token("DHCP", ignore(ascii_case))] Dhcp,
  /// `NTP`
  #[token("NTP", ignore(ascii_case))] Ntp,
  /// `PTP`
  #[token("PTP", ignore(ascii_case))] Ptp,
  /// `RADIUS`
  #[token("RADIUS", ignore(ascii_case))] Radius,
  /// `TACACS`
  #[token("TACACS", ignore(ascii_case))] Tacacs,
  /// `SYSLOG`
  #[token("SYSLOG", ignore(ascii_case))] Syslog,
  /// `NETFLOW`
  #[token("NETFLOW", ignore(ascii_case))] Netflow,
  /// `IPFIX`
  #[token("IPFIX", ignore(ascii_case))] Ipfix,
  /// `SFLOW`
  #[token("SFLOW", ignore(ascii_case))] Sflow,
  // Category 5: Layer 7 Web, App, Directory, Mail, Storage & Messaging
  /// `TFTP`
  #[token("TFTP", ignore(ascii_case))] Tftp,
  /// `FTP`
  #[token("FTP", ignore(ascii_case))] Ftp,
  /// `SSH`
  #[token("SSH", ignore(ascii_case))] Ssh,
  /// `TELNET`
  #[token("TELNET", ignore(ascii_case))] Telnet,
  /// `HTTP`
  #[token("HTTP", ignore(ascii_case))] Http,
  /// `HTTP2`
  #[token("HTTP2", ignore(ascii_case))] Http2,
  /// `GRPC`
  #[token("GRPC", ignore(ascii_case))] Grpc,
  /// `WEBSOCKET`
  #[token("WEBSOCKET", ignore(ascii_case))] Websocket,
  /// `TLS`
  #[token("TLS", ignore(ascii_case))] Tls,
  /// `QUIC`
  #[token("QUIC", ignore(ascii_case))] Quic,
  /// `STUN`
  #[token("STUN", ignore(ascii_case))] Stun,
  /// `SIP`
  #[token("SIP", ignore(ascii_case))] Sip,
  /// `RTP`
  #[token("RTP", ignore(ascii_case))] Rtp,
  /// `RTSP`
  #[token("RTSP", ignore(ascii_case))] Rtsp,
  /// `SMTP`
  #[token("SMTP", ignore(ascii_case))] Smtp,
  /// `IMAP`
  #[token("IMAP", ignore(ascii_case))] Imap,
  /// `POP3`
  #[token("POP3", ignore(ascii_case))] Pop3,
  /// `KERBEROS`
  #[token("KERBEROS", ignore(ascii_case))] Kerberos,
  /// `LDAP`
  #[token("LDAP", ignore(ascii_case))] Ldap,
  /// `SMB`
  #[token("SMB", ignore(ascii_case))] Smb,
  /// `NFS`
  #[token("NFS", ignore(ascii_case))] Nfs,
  /// `REDIS`
  #[token("REDIS", ignore(ascii_case))] Redis,
  /// `MEMCACHED`
  #[token("MEMCACHED", ignore(ascii_case))] Memcached,
  /// `MYSQL`
  #[token("MYSQL", ignore(ascii_case))] Mysql,
  /// `POSTGRES`
  #[token("POSTGRES", ignore(ascii_case))] Postgres,
  /// `MQTT`
  #[token("MQTT", ignore(ascii_case))] Mqtt,
  /// `COAP`
  #[token("COAP", ignore(ascii_case))] Coap,
  /// `AMQP`
  #[token("AMQP", ignore(ascii_case))] Amqp,
  /// `SSDP`
  #[token("SSDP", ignore(ascii_case))] Ssdp,
  /// `WHOIS`
  #[token("WHOIS", ignore(ascii_case))] Whois,
  // Category 6: Layer 7 Industrial / OT Protocols
  /// `MODBUS`
  #[token("MODBUS", ignore(ascii_case))] Modbus,
  /// `BACNET`
  #[token("BACNET", ignore(ascii_case))] Bacnet,
  /// `DNP3`
  #[token("DNP3", ignore(ascii_case))] Dnp3,
  /// `S7COMM`
  #[token("S7COMM", ignore(ascii_case))] S7comm,
  /// `ETHERNETIP`
  #[token("ETHERNETIP", ignore(ascii_case))] Ethernetip,
  /// `OPCUA`
  #[token("OPCUA", ignore(ascii_case))] Opcua,
  // Category 4 Sub-keywords
  /// `TXID`
  #[token("TXID", ignore(ascii_case))] Txid,
  /// `QNAME`
  #[token("QNAME", ignore(ascii_case))] Qname,
  /// `QTYPE`
  #[token("QTYPE", ignore(ascii_case))] Qtype,
  /// `RDATA`
  #[token("RDATA", ignore(ascii_case))] Rdata,
  /// `RCODE`
  #[token("RCODE", ignore(ascii_case))] Rcode,
  /// `ANS_TTL`
  #[token("ANS_TTL", ignore(ascii_case))] AnsTtl,
  /// `DISCOVER`
  #[token("DISCOVER", ignore(ascii_case))] Discover,
  /// `SOLICIT`
  #[token("SOLICIT", ignore(ascii_case))] Solicit,
  /// `OFFER`
  #[token("OFFER", ignore(ascii_case))] Offer,
  /// `ADVERTISE`
  #[token("ADVERTISE", ignore(ascii_case))] Advertise,
  /// `RELEASE`
  #[token("RELEASE", ignore(ascii_case))] Release,
  /// `CIADDR`
  #[token("CIADDR", ignore(ascii_case))] Ciaddr,
  /// `YIADDR`
  #[token("YIADDR", ignore(ascii_case))] Yiaddr,
  /// `SIADDR`
  #[token("SIADDR", ignore(ascii_case))] Siaddr,
  /// `CHADDR`
  #[token("CHADDR", ignore(ascii_case))] Chaddr,
  /// `HOSTNAME`
  #[token("HOSTNAME", ignore(ascii_case))] Hostname,
  /// `DNS_SERVER`
  #[token("DNS_SERVER", ignore(ascii_case))] DnsServer,
  /// `ROUTER`
  #[token("ROUTER", ignore(ascii_case))] Router,
  /// `SUBNET_MASK`
  #[token("SUBNET_MASK", ignore(ascii_case))] SubnetMask,
  /// `LEASE_TIME`
  #[token("LEASE_TIME", ignore(ascii_case))] LeaseTime,
  /// `LI`
  #[token("LI", ignore(ascii_case))] Li,
  /// `VN`
  #[token("VN", ignore(ascii_case))] Vn,
  /// `MODE`
  #[token("MODE", ignore(ascii_case))] Mode,
  /// `STRATUM`
  #[token("STRATUM", ignore(ascii_case))] Stratum,
  /// `POLL`
  #[token("POLL", ignore(ascii_case))] Poll,
  /// `PRECISION`
  #[token("PRECISION", ignore(ascii_case))] Precision,
  /// `REFID`
  #[token("REFID", ignore(ascii_case))] RefId,
  /// `TX_TIMESTAMP`
  #[token("TX_TIMESTAMP", ignore(ascii_case))] TxTimestamp,
  /// `MSG_TYPE`
  #[token("MSG_TYPE", ignore(ascii_case))] MsgType,
  /// `SYNC`
  #[token("SYNC", ignore(ascii_case))] Sync,
  /// `DELAY_REQ`
  #[token("DELAY_REQ", ignore(ascii_case))] DelayReq,
  /// `FOLLOW_UP`
  #[token("FOLLOW_UP", ignore(ascii_case))] FollowUp,
  /// `DELAY_RESP`
  #[token("DELAY_RESP", ignore(ascii_case))] DelayResp,
  /// `ANNOUNCE`
  #[token("ANNOUNCE", ignore(ascii_case))] Announce,
  /// `DOMAIN`
  #[token("DOMAIN", ignore(ascii_case))] Domain,
  /// `SEQ_ID`
  #[token("SEQ_ID", ignore(ascii_case))] SeqId,
  /// `CLOCK_ID`
  #[token("CLOCK_ID", ignore(ascii_case))] ClockId,
  /// `ACCESS_REQUEST`
  #[token("ACCESS_REQUEST", ignore(ascii_case))] AccessRequest,
  /// `ACCESS_ACCEPT`
  #[token("ACCESS_ACCEPT", ignore(ascii_case))] AccessAccept,
  /// `ACCESS_REJECT`
  #[token("ACCESS_REJECT", ignore(ascii_case))] AccessReject,
  /// `ACCESS_CHALLENGE`
  #[token("ACCESS_CHALLENGE", ignore(ascii_case))] AccessChallenge,
  /// `ACCOUNTING_REQUEST`
  #[token("ACCOUNTING_REQUEST", ignore(ascii_case))] AccountingRequest,
  /// `ACCOUNTING_RESPONSE`
  #[token("ACCOUNTING_RESPONSE", ignore(ascii_case))] AccountingResponse,
  /// `NAS_IP`
  #[token("NAS_IP", ignore(ascii_case))] NasIp,
  /// `SERVICE_TYPE`
  #[token("SERVICE_TYPE", ignore(ascii_case))] ServiceType,
  /// `FRAMED_IP`
  #[token("FRAMED_IP", ignore(ascii_case))] FramedIp,
  /// `AUTHEN`
  #[token("AUTHEN", ignore(ascii_case))] Authen,
  /// `AUTHOR`
  #[token("AUTHOR", ignore(ascii_case))] Author,
  /// `ACCT`
  #[token("ACCT", ignore(ascii_case))] Acct,
  /// `SESSION_ID`
  #[token("SESSION_ID", ignore(ascii_case))] SessionId,
  /// `FACILITY`
  #[token("FACILITY", ignore(ascii_case))] Facility,
  /// `SEVERITY`
  #[token("SEVERITY", ignore(ascii_case))] Severity,
  /// `PRI`
  #[token("PRI", ignore(ascii_case))] Pri,
  /// `APP`
  #[token("APP", ignore(ascii_case))] App,
  /// `PROCID`
  #[token("PROCID", ignore(ascii_case))] Procid,
  /// `MSG`
  #[token("MSG", ignore(ascii_case))] Msg,
  /// `SRCIP`
  #[token("SRCIP", ignore(ascii_case))] SrcIp,
  /// `DSTIP`
  #[token("DSTIP", ignore(ascii_case))] DstIp,
  /// `PROTO`
  #[token("PROTO", ignore(ascii_case))] Proto,
  /// `PACKETS`
  #[token("PACKETS", ignore(ascii_case))] Packets,
  /// `OCTETS`
  #[token("OCTETS", ignore(ascii_case))] Octets,
  /// `DOMAIN_ID`
  #[token("DOMAIN_ID", ignore(ascii_case))] DomainId,
  /// `AGENT_IP`
  #[token("AGENT_IP", ignore(ascii_case))] AgentIpSflow,
  /// `SUB_AGENT_ID`
  #[token("SUB_AGENT_ID", ignore(ascii_case))] SubAgentId,
  /// `UPTIME`
  #[token("UPTIME", ignore(ascii_case))] Uptime,
  /// `SAMPLES`
  #[token("SAMPLES", ignore(ascii_case))] Samples,
  // Category 5 Sub-keywords
  /// `RRQ`
  #[token("RRQ", ignore(ascii_case))] Rrq,
  /// `WRQ`
  #[token("WRQ", ignore(ascii_case))] Wrq,
  /// `FILENAME`
  #[token("FILENAME", ignore(ascii_case))] Filename,
  /// `BLOCK`
  #[token("BLOCK", ignore(ascii_case))] Block,
  /// `ERRCODE`
  #[token("ERRCODE", ignore(ascii_case))] ErrCode,
  /// `ERRMSG`
  #[token("ERRMSG", ignore(ascii_case))] ErrMsg,
  /// `CMD`
  #[token("CMD", ignore(ascii_case))] Cmd,
  /// `ARG`
  #[token("ARG", ignore(ascii_case))] Arg,
  /// `BANNER`
  #[token("BANNER", ignore(ascii_case))] Banner,
  /// `KEXINIT`
  #[token("KEXINIT", ignore(ascii_case))] KexInit,
  /// `NEWKEYS`
  #[token("NEWKEYS", ignore(ascii_case))] NewKeys,
  /// `MSG_CODE`
  #[token("MSG_CODE", ignore(ascii_case))] MsgCode,
  /// `WILL`
  #[token("WILL", ignore(ascii_case))] Will,
  /// `WONT`
  #[token("WONT", ignore(ascii_case))] Wont,
  /// `DO`
  #[token("DO", ignore(ascii_case))] DoCmd,
  /// `DONT`
  #[token("DONT", ignore(ascii_case))] Dont,
  /// `OPTION`
  #[token("OPTION", ignore(ascii_case))] Option,
  /// `POST`
  #[token("POST", ignore(ascii_case))] Post,
  /// `PUT`
  #[token("PUT", ignore(ascii_case))] Put,
  /// `DELETE`
  #[token("DELETE", ignore(ascii_case))] Delete,
  /// `HEAD`
  #[token("HEAD", ignore(ascii_case))] Head,
  /// `OPTIONS`
  #[token("OPTIONS", ignore(ascii_case))] Options,
  /// `PATCH`
  #[token("PATCH", ignore(ascii_case))] Patch,
  /// `URI`
  #[token("URI", ignore(ascii_case))] Uri,
  /// `HOST_HDR`
  #[token("HOST_HDR", ignore(ascii_case))] HostHdr,
  /// `USER_AGENT`
  #[token("USER_AGENT", ignore(ascii_case))] UserAgent,
  /// `CONTENT_TYPE`
  #[token("CONTENT_TYPE", ignore(ascii_case))] ContentType,
  /// `STATUS`
  #[token("STATUS", ignore(ascii_case))] Status,
  /// `REASON`
  #[token("REASON", ignore(ascii_case))] Reason,
  /// `HEADER`
  #[token("HEADER", ignore(ascii_case))] Header,
  /// `BODY`
  #[token("BODY", ignore(ascii_case))] Body,
  /// `PREFACE`
  #[token("PREFACE", ignore(ascii_case))] Preface,
  /// `SETTINGS`
  #[token("SETTINGS", ignore(ascii_case))] Settings,
  /// `HEADERS`
  #[token("HEADERS", ignore(ascii_case))] Headers,
  /// `WINDOW_UPDATE`
  #[token("WINDOW_UPDATE", ignore(ascii_case))] WindowUpdate,
  /// `PING`
  #[token("PING", ignore(ascii_case))] Ping,
  /// `GOAWAY`
  #[token("GOAWAY", ignore(ascii_case))] Goaway,
  /// `STREAM_ID`
  #[token("STREAM_ID", ignore(ascii_case))] StreamId,
  /// `SERVICE`
  #[token("SERVICE", ignore(ascii_case))] Service,
  /// `METHOD`
  #[token("METHOD", ignore(ascii_case))] Method,
  /// `GRPC_STATUS`
  #[token("GRPC_STATUS", ignore(ascii_case))] GrpcStatus,
  /// `OPCODE`
  #[token("OPCODE", ignore(ascii_case))] Opcode,
  /// `TEXT`
  #[token("TEXT", ignore(ascii_case))] Text,
  /// `BINARY`
  #[token("BINARY", ignore(ascii_case))] Binary,
  /// `PONG`
  #[token("PONG", ignore(ascii_case))] Pong,
  /// `CLOSE`
  #[token("CLOSE", ignore(ascii_case))] Close,
  /// `FIN_BIT`
  #[token("FIN_BIT", ignore(ascii_case))] FinBit,
  /// `MASK_KEY`
  #[token("MASK_KEY", ignore(ascii_case))] MaskKey,
  /// `CLIENT_HELLO`
  #[token("CLIENT_HELLO", ignore(ascii_case))] ClientHello,
  /// `SERVER_HELLO`
  #[token("SERVER_HELLO", ignore(ascii_case))] ServerHello,
  /// `CERTIFICATE`
  #[token("CERTIFICATE", ignore(ascii_case))] Certificate,
  /// `FINISHED`
  #[token("FINISHED", ignore(ascii_case))] Finished,
  /// `APP_DATA`
  #[token("APP_DATA", ignore(ascii_case))] AppData,
  /// `ALERT`
  #[token("ALERT", ignore(ascii_case))] Alert,
  /// `RECORD_VERSION`
  #[token("RECORD_VERSION", ignore(ascii_case))] RecordVersion,
  /// `HANDSHAKE_VERSION`
  #[token("HANDSHAKE_VERSION", ignore(ascii_case))] HandshakeVersion,
  /// `SNI`
  #[token("SNI", ignore(ascii_case))] Sni,
  /// `CIPHERSUITE`
  #[token("CIPHERSUITE", ignore(ascii_case))] Ciphersuite,
  /// `ALPN`
  #[token("ALPN", ignore(ascii_case))] Alpn,
  /// `INITIAL`
  #[token("INITIAL", ignore(ascii_case))] Initial,
  /// `ZERO_RTT`
  #[token("ZERO_RTT", ignore(ascii_case))] ZeroRtt,
  /// `HANDSHAKE`
  #[token("HANDSHAKE", ignore(ascii_case))] Handshake,
  /// `RETRY`
  #[token("RETRY", ignore(ascii_case))] Retry,
  /// `SHORT`
  #[token("SHORT", ignore(ascii_case))] Short,
  /// `DCID`
  #[token("DCID", ignore(ascii_case))] Dcid,
  /// `SCID`
  #[token("SCID", ignore(ascii_case))] Scid,
  /// `TOKEN`
  #[token("TOKEN", ignore(ascii_case))] Token,
  /// `PKT_NUM`
  #[token("PKT_NUM", ignore(ascii_case))] PktNum,
  /// `BINDING_REQUEST`
  #[token("BINDING_REQUEST", ignore(ascii_case))] BindingRequest,
  /// `BINDING_RESPONSE`
  #[token("BINDING_RESPONSE", ignore(ascii_case))] BindingResponse,
  /// `BINDING_ERROR`
  #[token("BINDING_ERROR", ignore(ascii_case))] BindingError,
  /// `XOR_MAPPED_ADDR`
  #[token("XOR_MAPPED_ADDR", ignore(ascii_case))] XorMappedAddr,
  /// `SOFTWARE`
  #[token("SOFTWARE", ignore(ascii_case))] Software,
  /// `INVITE`
  #[token("INVITE", ignore(ascii_case))] Invite,
  /// `BYE`
  #[token("BYE", ignore(ascii_case))] Bye,
  /// `CANCEL`
  #[token("CANCEL", ignore(ascii_case))] Cancel,
  /// `FROM`
  #[token("FROM", ignore(ascii_case))] From,
  /// `TO`
  #[token("TO", ignore(ascii_case))] To,
  /// `CALL_ID`
  #[token("CALL_ID", ignore(ascii_case))] CallId,
  /// `CSEQ`
  #[token("CSEQ", ignore(ascii_case))] Cseq,
  /// `VIA`
  #[token("VIA", ignore(ascii_case))] Via,
  /// `CONTACT`
  #[token("CONTACT", ignore(ascii_case))] Contact,
  /// `PT`
  #[token("PT", ignore(ascii_case))] Pt,
  /// `TIMESTAMP`
  #[token("TIMESTAMP", ignore(ascii_case))] Timestamp,
  /// `SSRC`
  #[token("SSRC", ignore(ascii_case))] Ssrc,
  /// `MARKER`
  #[token("MARKER", ignore(ascii_case))] Marker,
  /// `DESCRIBE`
  #[token("DESCRIBE", ignore(ascii_case))] Describe,
  /// `SETUP`
  #[token("SETUP", ignore(ascii_case))] Setup,
  /// `PLAY`
  #[token("PLAY", ignore(ascii_case))] Play,
  /// `TEARDOWN`
  #[token("TEARDOWN", ignore(ascii_case))] Teardown,
  /// `TRANSPORT_HDR`
  #[token("TRANSPORT_HDR", ignore(ascii_case))] TransportHdr,
  /// `SESSION`
  #[token("SESSION", ignore(ascii_case))] Session,
  /// `EHLO`
  #[token("EHLO", ignore(ascii_case))] Ehlo,
  /// `HELO`
  #[token("HELO", ignore(ascii_case))] Helo,
  /// `MAIL_FROM`
  #[token("MAIL_FROM", ignore(ascii_case))] MailFrom,
  /// `RCPT_TO`
  #[token("RCPT_TO", ignore(ascii_case))] RcptTo,
  /// `QUIT`
  #[token("QUIT", ignore(ascii_case))] Quit,
  /// `PARAM`
  #[token("PARAM", ignore(ascii_case))] Param,
  /// `OK`
  #[token("OK", ignore(ascii_case))] Ok,
  /// `ERR`
  #[token("ERR", ignore(ascii_case))] Err,
  /// `AS_REQ`
  #[token("AS_REQ", ignore(ascii_case))] AsReq,
  /// `AS_REP`
  #[token("AS_REP", ignore(ascii_case))] AsRep,
  /// `TGS_REQ`
  #[token("TGS_REQ", ignore(ascii_case))] TgsReq,
  /// `TGS_REP`
  #[token("TGS_REP", ignore(ascii_case))] TgsRep,
  /// `KRB_ERROR`
  #[token("KRB_ERROR", ignore(ascii_case))] KrbError,
  /// `REALM`
  #[token("REALM", ignore(ascii_case))] Realm,
  /// `CNAME`
  #[token("CNAME", ignore(ascii_case))] Cname,
  /// `SNAME`
  #[token("SNAME", ignore(ascii_case))] Sname,
  /// `ETYPE`
  #[token("ETYPE", ignore(ascii_case))] Etype,
  /// `BIND_REQ`
  #[token("BIND_REQ", ignore(ascii_case))] BindReq,
  /// `BIND_RES`
  #[token("BIND_RES", ignore(ascii_case))] BindRes,
  /// `SEARCH_REQ`
  #[token("SEARCH_REQ", ignore(ascii_case))] SearchReq,
  /// `SEARCH_ENTRY`
  #[token("SEARCH_ENTRY", ignore(ascii_case))] SearchEntry,
  /// `SEARCH_DONE`
  #[token("SEARCH_DONE", ignore(ascii_case))] SearchDone,
  /// `UNBIND_REQ`
  #[token("UNBIND_REQ", ignore(ascii_case))] UnbindReq,
  /// `BASE_DN`
  #[token("BASE_DN", ignore(ascii_case))] BaseDn,
  /// `FILTER`
  #[token("FILTER", ignore(ascii_case))] Filter,
  /// `RESULT_CODE`
  #[token("RESULT_CODE", ignore(ascii_case))] ResultCode,
  /// `COMMAND`
  #[token("COMMAND", ignore(ascii_case))] Command,
  /// `NEGOTIATE`
  #[token("NEGOTIATE", ignore(ascii_case))] Negotiate,
  /// `SESSION_SETUP`
  #[token("SESSION_SETUP", ignore(ascii_case))] SessionSetup,
  /// `TREE_CONNECT`
  #[token("TREE_CONNECT", ignore(ascii_case))] TreeConnect,
  /// `CREATE`
  #[token("CREATE", ignore(ascii_case))] Create,
  /// `TREE_DISCONNECT`
  #[token("TREE_DISCONNECT", ignore(ascii_case))] TreeDisconnect,
  /// `TREE_ID`
  #[token("TREE_ID", ignore(ascii_case))] TreeId,
  /// `SHARE`
  #[token("SHARE", ignore(ascii_case))] Share,
  /// `VERS`
  #[token("VERS", ignore(ascii_case))] Vers,
  /// `PROC`
  #[token("PROC", ignore(ascii_case))] Proc,
  /// `PATH`
  #[token("PATH", ignore(ascii_case))] Path,
  /// `COMPOUND`
  #[token("COMPOUND", ignore(ascii_case))] Compound,
  /// `ARGS`
  #[token("ARGS", ignore(ascii_case))] Args,
  /// `REPLY_TYPE`
  #[token("REPLY_TYPE", ignore(ascii_case))] ReplyType,
  /// `VALUE`
  #[token("VALUE", ignore(ascii_case))] Value,
  /// `EXPTIME`
  #[token("EXPTIME", ignore(ascii_case))] Exptime,
  /// `OPAQUE`
  #[token("OPAQUE", ignore(ascii_case))] Opaque,
  /// `CAS`
  #[token("CAS", ignore(ascii_case))] Cas,
  /// `GREETING`
  #[token("GREETING", ignore(ascii_case))] Greeting,
  /// `LOGIN`
  #[token("LOGIN", ignore(ascii_case))] Login,
  /// `SQL`
  #[token("SQL", ignore(ascii_case))] Sql,
  /// `EOF`
  #[token("EOF", ignore(ascii_case))] Eof,
  /// `SERVER_VERSION`
  #[token("SERVER_VERSION", ignore(ascii_case))] ServerVersion,
  /// `DB`
  #[token("DB", ignore(ascii_case))] Db,
  /// `STARTUP`
  #[token("STARTUP", ignore(ascii_case))] Startup,
  /// `READY_FOR_QUERY`
  #[token("READY_FOR_QUERY", ignore(ascii_case))] ReadyForQuery,
  /// `COMMAND_COMPLETE`
  #[token("COMMAND_COMPLETE", ignore(ascii_case))] CommandComplete,
  /// `ERROR_RESPONSE`
  #[token("ERROR_RESPONSE", ignore(ascii_case))] ErrorResponse,
  /// `AUTH_OK`
  #[token("AUTH_OK", ignore(ascii_case))] AuthOk,
  /// `CONNECT`
  #[token("CONNECT", ignore(ascii_case))] Connect,
  /// `CONNACK`
  #[token("CONNACK", ignore(ascii_case))] Connack,
  /// `PUBLISH`
  #[token("PUBLISH", ignore(ascii_case))] Publish,
  /// `PUBACK`
  #[token("PUBACK", ignore(ascii_case))] Puback,
  /// `SUBSCRIBE`
  #[token("SUBSCRIBE", ignore(ascii_case))] Subscribe,
  /// `SUBACK`
  #[token("SUBACK", ignore(ascii_case))] Suback,
  /// `PINGREQ`
  #[token("PINGREQ", ignore(ascii_case))] Pingreq,
  /// `PINGRESP`
  #[token("PINGRESP", ignore(ascii_case))] Pingresp,
  /// `DISCONNECT`
  #[token("DISCONNECT", ignore(ascii_case))] Disconnect,
  /// `CLIENT_ID`
  #[token("CLIENT_ID", ignore(ascii_case))] ClientId,
  /// `TOPIC`
  #[token("TOPIC", ignore(ascii_case))] Topic,
  /// `QOS`
  #[token("QOS", ignore(ascii_case))] Qos,
  /// `RETAIN`
  #[token("RETAIN", ignore(ascii_case))] Retain,
  /// `PKT_ID`
  #[token("PKT_ID", ignore(ascii_case))] PktId,
  /// `RETURN_CODE`
  #[token("RETURN_CODE", ignore(ascii_case))] ReturnCode,
  /// `CON`
  #[token("CON", ignore(ascii_case))] Con,
  /// `NON`
  #[token("NON", ignore(ascii_case))] Non,
  /// `CHANGED`
  #[token("CHANGED", ignore(ascii_case))] Changed,
  /// `CREATED`
  #[token("CREATED", ignore(ascii_case))] Created,
  /// `NOT_FOUND`
  #[token("NOT_FOUND", ignore(ascii_case))] NotFound,
  /// `URI_PATH`
  #[token("URI_PATH", ignore(ascii_case))] UriPath,
  /// `CONTENT_FORMAT`
  #[token("CONTENT_FORMAT", ignore(ascii_case))] ContentFormat,
  /// `PROTOCOL_HEADER`
  #[token("PROTOCOL_HEADER", ignore(ascii_case))] ProtocolHeader,
  /// `CONNECTION_START`
  #[token("CONNECTION_START", ignore(ascii_case))] ConnectionStart,
  /// `CHANNEL_OPEN`
  #[token("CHANNEL_OPEN", ignore(ascii_case))] ChannelOpen,
  /// `BASIC_PUBLISH`
  #[token("BASIC_PUBLISH", ignore(ascii_case))] BasicPublish,
  /// `BASIC_DELIVER`
  #[token("BASIC_DELIVER", ignore(ascii_case))] BasicDeliver,
  /// `CHANNEL`
  #[token("CHANNEL", ignore(ascii_case))] Channel,
  /// `ROUTING_KEY`
  #[token("ROUTING_KEY", ignore(ascii_case))] RoutingKey,
  /// `MSEARCH`
  #[token("MSEARCH", ignore(ascii_case))] Msearch,
  /// `NOTIFY`
  #[token("NOTIFY", ignore(ascii_case))] Notify,
  /// `MAN`
  #[token("MAN", ignore(ascii_case))] Man,
  /// `MX`
  #[token("MX", ignore(ascii_case))] Mx,
  /// `ST`
  #[token("ST", ignore(ascii_case))] St,
  /// `NT`
  #[token("NT", ignore(ascii_case))] Nt,
  /// `NTS`
  #[token("NTS", ignore(ascii_case))] Nts,
  /// `USN`
  #[token("USN", ignore(ascii_case))] Usn,
  /// `LOCATION`
  #[token("LOCATION", ignore(ascii_case))] Location,
  /// `REGISTRAR`
  #[token("REGISTRAR", ignore(ascii_case))] Registrar,
  // Category 6 Sub-keywords
  /// `PROTO_ID`
  #[token("PROTO_ID", ignore(ascii_case))] ProtoId,
  /// `UNITID`
  #[token("UNITID", ignore(ascii_case))] UnitId,
  /// `FUNC`
  #[token("FUNC", ignore(ascii_case))] Func,
  /// `READ_COILS`
  #[token("READ_COILS", ignore(ascii_case))] ReadCoils,
  /// `READ_DISCRETE_INPUTS`
  #[token("READ_DISCRETE_INPUTS", ignore(ascii_case))] ReadDiscreteInputs,
  /// `READ_HOLDING_REGISTERS`
  #[token("READ_HOLDING_REGISTERS", ignore(ascii_case))] ReadHoldingRegisters,
  /// `READ_INPUT_REGISTERS`
  #[token("READ_INPUT_REGISTERS", ignore(ascii_case))] ReadInputRegisters,
  /// `WRITE_SINGLE_COIL`
  #[token("WRITE_SINGLE_COIL", ignore(ascii_case))] WriteSingleCoil,
  /// `WRITE_SINGLE_REGISTER`
  #[token("WRITE_SINGLE_REGISTER", ignore(ascii_case))] WriteSingleRegister,
  /// `WRITE_MULTIPLE_REGISTERS`
  #[token("WRITE_MULTIPLE_REGISTERS", ignore(ascii_case))] WriteMultipleRegisters,
  /// `ADDR`
  #[token("ADDR", ignore(ascii_case))] Addr,
  /// `COUNT`
  #[token("COUNT", ignore(ascii_case))] Count,
  /// `IS_RESPONSE`
  #[token("IS_RESPONSE", ignore(ascii_case))] IsResponse,
  /// `WHO_IS`
  #[token("WHO_IS", ignore(ascii_case))] WhoIs,
  /// `I_AM`
  #[token("I_AM", ignore(ascii_case))] IAm,
  /// `READ_PROPERTY`
  #[token("READ_PROPERTY", ignore(ascii_case))] ReadProperty,
  /// `WRITE_PROPERTY`
  #[token("WRITE_PROPERTY", ignore(ascii_case))] WriteProperty,
  /// `INVOKE_ID`
  #[token("INVOKE_ID", ignore(ascii_case))] InvokeId,
  /// `OBJECT_TYPE`
  #[token("OBJECT_TYPE", ignore(ascii_case))] ObjectType,
  /// `OBJECT_INSTANCE`
  #[token("OBJECT_INSTANCE", ignore(ascii_case))] ObjectInstance,
  /// `PROPERTY_ID`
  #[token("PROPERTY_ID", ignore(ascii_case))] PropertyId,
  /// `CONFIRM`
  #[token("CONFIRM", ignore(ascii_case))] Confirm,
  /// `SELECT`
  #[token("SELECT", ignore(ascii_case))] Select,
  /// `OPERATE`
  #[token("OPERATE", ignore(ascii_case))] Operate,
  /// `DIRECT_OPERATE`
  #[token("DIRECT_OPERATE", ignore(ascii_case))] DirectOperate,
  /// `UNSOLICITED_RESPONSE`
  #[token("UNSOLICITED_RESPONSE", ignore(ascii_case))] UnsolicitedResponse,
  /// `VARIATION`
  #[token("VARIATION", ignore(ascii_case))] Variation,
  /// `CRC`
  #[token("CRC", ignore(ascii_case))] Crc,
  /// `SRC`
  #[token("SRC", ignore(ascii_case))] Src,
  /// `DST`
  #[token("DST", ignore(ascii_case))] Dst,
  /// `ROSCTR`
  #[token("ROSCTR", ignore(ascii_case))] Rosctr,
  /// `PDU_REF`
  #[token("PDU_REF", ignore(ascii_case))] PduRef,
  /// `SETUP_COMM`
  #[token("SETUP_COMM", ignore(ascii_case))] SetupComm,
  /// `READ_VAR`
  #[token("READ_VAR", ignore(ascii_case))] ReadVar,
  /// `WRITE_VAR`
  #[token("WRITE_VAR", ignore(ascii_case))] WriteVar,
  /// `PLC_CONTROL`
  #[token("PLC_CONTROL", ignore(ascii_case))] PlcControl,
  /// `AREA`
  #[token("AREA", ignore(ascii_case))] Area,
  /// `DB_NUM`
  #[token("DB_NUM", ignore(ascii_case))] DbNum,
  /// `OFFSET`
  #[token("OFFSET", ignore(ascii_case))] Offset,
  /// `LIST_SERVICES`
  #[token("LIST_SERVICES", ignore(ascii_case))] ListServices,
  /// `LIST_IDENTITY`
  #[token("LIST_IDENTITY", ignore(ascii_case))] ListIdentity,
  /// `LIST_INTERFACES`
  #[token("LIST_INTERFACES", ignore(ascii_case))] ListInterfaces,
  /// `REGISTER_SESSION`
  #[token("REGISTER_SESSION", ignore(ascii_case))] RegisterSession,
  /// `UNREGISTER_SESSION`
  #[token("UNREGISTER_SESSION", ignore(ascii_case))] UnregisterSession,
  /// `SEND_RR_DATA`
  #[token("SEND_RR_DATA", ignore(ascii_case))] SendRrData,
  /// `SEND_UNIT_DATA`
  #[token("SEND_UNIT_DATA", ignore(ascii_case))] SendUnitData,
  /// `SESSION_HANDLE`
  #[token("SESSION_HANDLE", ignore(ascii_case))] SessionHandle,
  /// `CONTEXT`
  #[token("CONTEXT", ignore(ascii_case))] ContextVal,
  /// `CIP_SERVICE`
  #[token("CIP_SERVICE", ignore(ascii_case))] CipService,
  /// `CIP_CLASS`
  #[token("CIP_CLASS", ignore(ascii_case))] CipClass,
  /// `CIP_INSTANCE`
  #[token("CIP_INSTANCE", ignore(ascii_case))] CipInstance,
  /// `CIP_ATTR`
  #[token("CIP_ATTR", ignore(ascii_case))] CipAttr,
  /// `CHUNK_TYPE`
  #[token("CHUNK_TYPE", ignore(ascii_case))] ChunkType,
  /// `SECURE_CHANNEL_ID`
  #[token("SECURE_CHANNEL_ID", ignore(ascii_case))] SecureChannelId,
  /// `TOKEN_ID`
  #[token("TOKEN_ID", ignore(ascii_case))] TokenId,
  /// `SEQ_NUM`
  #[token("SEQ_NUM", ignore(ascii_case))] SeqNum,
  /// `ENDPOINT_URL`
  #[token("ENDPOINT_URL", ignore(ascii_case))] EndpointUrl,
  /// `NODE_ID`
  #[token("NODE_ID", ignore(ascii_case))] NodeId,
  /// `->`
  #[token("->")] RightArrow,
  /// `<-`
  #[token("<-")] LeftArrow,
  /// `{`
  #[token("{")] LBrace,
  /// `}`
  #[token("}")] RBrace,
  /// `(`
  #[token("(")] LParen,
  /// `)`
  #[token(")")] RParen,
  /// `,`
  #[token(",")] Comma,
  // Time suffixes
  /// `ns`
  #[token("ns", priority = 2, ignore(ascii_case))] Ns,
  /// `us`
  #[token("us", priority = 2, ignore(ascii_case))] Us,
  /// `ms`
  #[token("ms", priority = 2, ignore(ascii_case))] Ms,
  /// `s`
  #[token("s", priority = 2, ignore(ascii_case))] Sec,
  /// `m`
  #[token("m", priority = 2, ignore(ascii_case))] Min,
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
