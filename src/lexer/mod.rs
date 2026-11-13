//! Zero-copy lexical analyzer and token specification for the FrameAssembly v3.0 language.
//!
//! Built on the [`logos`] deterministic finite-automaton generator, this module defines the
//! [`Token`] enumeration and [`lex`] entry point for scanning `.frasm` source files into
//! byte-spanned token streams. Every built-in structural keyword (`host`, `flow`, `compile`),
//! all 81 Layer 2 through Layer 7 protocol identifiers, header and payload modifiers, and time
//! units (`ns`, `us`, `ms`, `s`, `m`) are strictly lowercase alphanumeric (`[a-z0-9]+` without
//! `_` or `-`), while user-defined endpoint and flow identifiers permit flexible casing, `_`, and
//! internal `-` (`fw-dmz-01`, `core_sw`).

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
#[logos(skip r"//[^\r\n]*")]
pub enum Token<'a> {
  /// `host`
  #[token("host")] Host,
  /// `flow`
  #[token("flow")] Flow,
  /// `ip`
  #[token("ip")] Ip,
  /// `mac`
  #[token("mac")] Mac,
  /// `compile`
  #[token("compile")] Compile,
  /// `tcp`
  #[token("tcp")] Tcp,
  /// `udp`
  #[token("udp")] Udp,
  /// `syn`
  #[token("syn")] Syn,
  /// `ack`
  #[token("ack")] Ack,
  /// `fin`
  #[token("fin")] Fin,
  /// `rst`
  #[token("rst")] Rst,
  /// `psh`
  #[token("psh")] Psh,
  /// `urg`
  #[token("urg")] Urg,
  /// `ece`
  #[token("ece")] Ece,
  /// `cwr`
  #[token("cwr")] Cwr,
  /// `srcport`
  #[token("srcport")] SrcPort,
  /// `dstport`
  #[token("dstport")] DstPort,
  /// `seq`
  #[token("seq")] Seq,
  /// `acknum`
  #[token("acknum")] AckNum,
  /// `win`
  #[token("win")] Win,
  /// `payload`
  #[token("payload")] Payload,
  /// `hexpayload`
  #[token("hexpayload")] HexPayload,
  /// `wait`
  #[token("wait")] Wait,
  /// `vlan`
  #[token("vlan")] Vlan,
  /// `dscp`
  #[token("dscp")] Dscp,
  /// `ecn`
  #[token("ecn")] Ecn,
  /// `ttl`
  #[token("ttl")] Ttl,
  /// `flowlabel`
  #[token("flowlabel")] FlowLabel,
  /// `snmp1`
  #[token("snmp1")] Snmp1,
  /// `snmp2`
  #[token("snmp2")] Snmp2,
  /// `snmp3`
  #[token("snmp3")] Snmp3,
  /// `trap`
  #[token("trap")] Trap,
  /// `get`
  #[token("get")] Get,
  /// `set`
  #[token("set")] Set,
  /// `response`
  #[token("response")] Response,
  /// `inform`
  #[token("inform")] Inform,
  /// `getnext`
  #[token("getnext")] GetNext,
  /// `getbulk`
  #[token("getbulk")] GetBulk,
  /// `community`
  #[token("community")] Community,
  /// `user`
  #[token("user")] User,
  /// `oid`
  #[token("oid")] Oid,
  /// `sysuptime`
  #[token("sysuptime")] SysUpTime,
  /// `varbind`
  #[token("varbind")] VarBind,
  /// `nullval` or `null`
  #[token("nullval")]
  #[token("null")] NullVal,
  /// `string`
  #[token("string")] StringVal,
  /// `int`
  #[token("int")] IntVal,
  /// `timeticks`
  #[token("timeticks")] TimeTicksVal,
  /// `ipval`
  #[token("ipval")] IpVal,
  /// `oidval`
  #[token("oidval")] OidVal,
  /// `counter32`
  #[token("counter32")] Counter32Val,
  /// `gauge32`
  #[token("gauge32")] Gauge32Val,
  /// `counter64`
  #[token("counter64")] Counter64Val,
  /// `enterprise`
  #[token("enterprise")] Enterprise,
  /// `agentip`
  #[token("agentip")] AgentIp,
  /// `gentrap`
  #[token("gentrap")] GenTrap,
  /// `spectrap`
  #[token("spectrap")] SpecTrap,
  /// `engineid`
  #[token("engineid")] EngineId,
  /// `engineboots`
  #[token("engineboots")] EngineBoots,
  /// `enginetime`
  #[token("enginetime")] EngineTime,
  /// `contextname`
  #[token("contextname")] ContextName,
  /// `auth`
  #[token("auth")] Auth,
  /// `priv`
  #[token("priv")] Priv,
  /// `md5`
  #[token("md5")] Md5,
  /// `sha`
  #[token("sha")] Sha,
  /// `sha256`
  #[token("sha256")] Sha256,
  /// `sha384`
  #[token("sha384")] Sha384,
  /// `sha512`
  #[token("sha512")] Sha512,
  /// `des`
  #[token("des")] Des,
  /// `aes`
  #[token("aes")] Aes,
  /// `nonrepeaters`
  #[token("nonrepeaters")] NonRepeaters,
  /// `maxrepetitions`
  #[token("maxrepetitions")] MaxRepetitions,
  /// `reqid`
  #[token("reqid")] ReqId,
  // Layer 2 modifiers
  /// `pcp`
  #[token("pcp")] Pcp,
  /// `dei`
  #[token("dei")] Dei,
  /// `qinq`
  #[token("qinq")] Qinq,
  /// `innervlan`
  #[token("innervlan")] InnerVlan,
  /// `mpls`
  #[token("mpls")] Mpls,
  /// `exp` or `tc`
  #[token("exp")]
  #[token("tc")] Exp,
  /// `bos`
  #[token("bos")] Bos,
  /// `mplsttl`
  #[token("mplsttl")] MplsTtl,
  /// `srcmac`
  #[token("srcmac")] SrcMac,
  /// `dstmac`
  #[token("dstmac")] DstMac,
  /// `ethertype`
  #[token("ethertype")] EtherType,
  // Layer 3 modifiers
  /// `ipid`
  #[token("ipid")] IpId,
  /// `df`
  #[token("df")] Df,
  /// `mf`
  #[token("mf")] Mf,
  /// `fragoffset`
  #[token("fragoffset")] FragOffset,
  // Layer 4 modifiers
  /// `transport`
  #[token("transport")] Transport,
  /// `window`
  #[token("window")] Window,
  /// `urgent`
  #[token("urgent")] Urgent,
  /// `mss`
  #[token("mss")] Mss,
  /// `wscale`
  #[token("wscale")] Wscale,
  /// `sackperm`
  #[token("sackperm")] SackPerm,
  /// `tsval`
  #[token("tsval")] Tsval,
  /// `tsecr`
  #[token("tsecr")] Tsecr,
  // SCTP overrides
  /// `vtag`
  #[token("vtag")] Vtag,
  /// `stream`
  #[token("stream")] Stream,
  /// `ssn`
  #[token("ssn")] Ssn,
  /// `ppid`
  #[token("ppid")] Ppid,
  /// `chunk`
  #[token("chunk")] Chunk,
  // Category 1: Layer 2 & DC Protocols
  /// `arp`
  #[token("arp")] Arp,
  /// `lldp`
  #[token("lldp")] Lldp,
  /// `stp`
  #[token("stp")] Stp,
  /// `lacp`
  #[token("lacp")] Lacp,
  /// `eapol`
  #[token("eapol")] Eapol,
  // Category 2: Layer 3, Tunneling, Security & Routing Protocols
  /// `icmp`
  #[token("icmp")] Icmp,
  /// `ndp`
  #[token("ndp")] Ndp,
  /// `igmp`
  #[token("igmp")] Igmp,
  /// `mld`
  #[token("mld")] Mld,
  /// `gre`
  #[token("gre")] Gre,
  /// `vxlan`
  #[token("vxlan")] Vxlan,
  /// `geneve`
  #[token("geneve")] Geneve,
  /// `ipsec`
  #[token("ipsec")] Ipsec,
  /// `esp`
  #[token("esp")] Esp,
  /// `ah`
  #[token("ah")] Ah,
  /// `ikev2`
  #[token("ikev2")] Ikev2,
  /// `wireguard`
  #[token("wireguard")] Wireguard,
  /// `ospf`
  #[token("ospf")] Ospf,
  /// `bgp`
  #[token("bgp")] Bgp,
  /// `rip`
  #[token("rip")] Rip,
  /// `vrrp`
  #[token("vrrp")] Vrrp,
  /// `hsrp`
  #[token("hsrp")] Hsrp,
  /// `pim`
  #[token("pim")] Pim,
  /// `bfd`
  #[token("bfd")] Bfd,
  /// `openflow`
  #[token("openflow")] Openflow,
  // Category 3: Layer 4 Transports
  /// `sctp`
  #[token("sctp")] Sctp,
  // Protocol Sub-keywords
  /// `request`
  #[token("request")] Request,
  /// `reply`
  #[token("reply")] Reply,
  /// `gratuitous`
  #[token("gratuitous")] Gratuitous,
  /// `garp`
  #[token("garp")] Garp,
  /// `spa`
  #[token("spa")] Spa,
  /// `tha`
  #[token("tha")] Tha,
  /// `tpa`
  #[token("tpa")] Tpa,
  /// `sendermac`
  #[token("sendermac")] SenderMac,
  /// `targetmac`
  #[token("targetmac")] TargetMac,
  /// `senderip`
  #[token("senderip")] SenderIp,
  /// `targetip`
  #[token("targetip")] TargetIp,
  /// `chassisid`
  #[token("chassisid")] ChassisId,
  /// `portid`
  #[token("portid")] PortId,
  /// `sysname`
  #[token("sysname")] SysName,
  /// `sysdesc`
  #[token("sysdesc")] SysDesc,
  /// `rootid`
  #[token("rootid")] RootId,
  /// `bridgeid`
  #[token("bridgeid")] BridgeId,
  /// `cost`
  #[token("cost")] Cost,
  /// `maxage`
  #[token("maxage")] MaxAge,
  /// `hellotime`
  #[token("hellotime")] HelloTime,
  /// `forwarddelay`
  #[token("forwarddelay")] ForwardDelay,
  /// `rstp`
  #[token("rstp")] Rstp,
  /// `flags`
  #[token("flags")] Flags,
  /// `actorsys`
  #[token("actorsys")] ActorSys,
  /// `actorkey`
  #[token("actorkey")] ActorKey,
  /// `actorport`
  #[token("actorport")] ActorPort,
  /// `partnersys`
  #[token("partnersys")] PartnerSys,
  /// `partnerkey`
  #[token("partnerkey")] PartnerKey,
  /// `partnerport`
  #[token("partnerport")] PartnerPort,
  /// `actorstate`
  #[token("actorstate")] ActorState,
  /// `partnerstate`
  #[token("partnerstate")] PartnerState,
  /// `version`
  #[token("version")] Version,
  /// `type`
  #[token("type")] Type,
  /// `eappacket`
  #[token("eappacket")] EapPacket,
  /// `start`
  #[token("start")] Start,
  /// `logoff`
  #[token("logoff")] Logoff,
  /// `key`
  #[token("key")] Key,
  /// `eapcode`
  #[token("eapcode")] EapCode,
  /// `eapid`
  #[token("eapid")] EapId,
  /// `eapmethod`
  #[token("eapmethod")] EapMethod,
  /// `identity`
  #[token("identity")] Identity,
  /// `label`
  #[token("label")] Label,
  /// `echorequest`
  #[token("echorequest")] EchoRequest,
  /// `echoreply`
  #[token("echoreply")] EchoReply,
  /// `destunreach`
  #[token("destunreach")] DestUnreach,
  /// `timeexceeded`
  #[token("timeexceeded")] TimeExceeded,
  /// `redirect`
  #[token("redirect")] Redirect,
  /// `code`
  #[token("code")] Code,
  /// `id`
  #[token("id")] Id,
  /// `gateway`
  #[token("gateway")] Gateway,
  /// `routersolicit`
  #[token("routersolicit")] RouterSolicit,
  /// `routeradvert`
  #[token("routeradvert")] RouterAdvert,
  /// `neighborsolicit`
  #[token("neighborsolicit")] NeighborSolicit,
  /// `neighboradvert`
  #[token("neighboradvert")] NeighborAdvert,
  /// `target`
  #[token("target")] Target,
  /// `slla`
  #[token("slla")] Slla,
  /// `tlla`
  #[token("tlla")] Tlla,
  /// `routerlifetime`
  #[token("routerlifetime")] RouterLifetime,
  /// `query`
  #[token("query")] Query,
  /// `report`
  #[token("report")] Report,
  /// `leave`
  #[token("leave")] Leave,
  /// `group`
  #[token("group")] Group,
  /// `maxresp`
  #[token("maxresp")] MaxResp,
  /// `v1`
  #[token("v1")] V1,
  /// `v2`
  #[token("v2")] V2,
  /// `v3`
  #[token("v3")] V3,
  /// `done`
  #[token("done")] Done,
  /// `multicastaddr`
  #[token("multicastaddr")] MulticastAddr,
  /// `maxrespdelay`
  #[token("maxrespdelay")] MaxRespDelay,
  /// `grekey`
  #[token("grekey")] GreKey,
  /// `greseq`
  #[token("greseq")] GreSeq,
  /// `greproto`
  #[token("greproto")] GreProto,
  /// `checksum`
  #[token("checksum")] Checksum,
  /// `vni`
  #[token("vni")] Vni,
  /// `vnid`
  #[token("vnid")] Vnid,
  /// `optclass`
  #[token("optclass")] OptClass,
  /// `opttype`
  #[token("opttype")] OptType,
  /// `protocoltype`
  #[token("protocoltype")] ProtocolType,
  /// `spi`
  #[token("spi")] Spi,
  /// `iv`
  #[token("iv")] Iv,
  /// `icv`
  #[token("icv")] Icv,
  /// `nextheader`
  #[token("nextheader")] NextHeader,
  /// `initiatorspi`
  #[token("initiatorspi")] InitiatorSpi,
  /// `responderspi`
  #[token("responderspi")] ResponderSpi,
  /// `exchange`
  #[token("exchange")] Exchange,
  /// `sainit`
  #[token("sainit")] SaInit,
  /// `createchildsa`
  #[token("createchildsa")] CreateChildSa,
  /// `informational`
  #[token("informational")] Informational,
  /// `msgid`
  #[token("msgid")] MsgId,
  /// `nextpayload`
  #[token("nextpayload")] NextPayload,
  /// `initiation`
  #[token("initiation")] Initiation,
  /// `cookie`
  #[token("cookie")] Cookie,
  /// `data`
  #[token("data")] Data,
  /// `sender`
  #[token("sender")] Sender,
  /// `receiver`
  #[token("receiver")] Receiver,
  /// `counter`
  #[token("counter")] Counter,
  /// `hello`
  #[token("hello")] Hello,
  /// `dbd`
  #[token("dbd")] Dbd,
  /// `lsr`
  #[token("lsr")] Lsr,
  /// `lsu`
  #[token("lsu")] Lsu,
  /// `lsack`
  #[token("lsack")] LsAck,
  /// `routerid`
  #[token("routerid")] RouterId,
  /// `areaid`
  #[token("areaid")] AreaId,
  /// `hellointerval`
  #[token("hellointerval")] HelloInterval,
  /// `deadinterval`
  #[token("deadinterval")] DeadInterval,
  /// `priority`
  #[token("priority")] Priority,
  /// `open`
  #[token("open")] Open,
  /// `update`
  #[token("update")] Update,
  /// `notification`
  #[token("notification")] Notification,
  /// `keepalive`
  #[token("keepalive")] Keepalive,
  /// `asn`
  #[token("asn")] Asn,
  /// `holdtime`
  #[token("holdtime")] HoldTime,
  /// `bgpid`
  #[token("bgpid")] BgpId,
  /// `prefix`
  #[token("prefix")] Prefix,
  /// `nlri`
  #[token("nlri")] Nlri,
  /// `nexthop`
  #[token("nexthop")] NextHop,
  /// `metric`
  #[token("metric")] Metric,
  /// `tag`
  #[token("tag")] Tag,
  /// `vrid`
  #[token("vrid")] Vrid,
  /// `advint`
  #[token("advint")] AdvInt,
  /// `vip`
  #[token("vip")] Vip,
  /// `state`
  #[token("state")] State,
  /// `joinprune`
  #[token("joinprune")] JoinPrune,
  /// `register`
  #[token("register")] Register,
  /// `source`
  #[token("source")] Source,
  /// `rp`
  #[token("rp")] Rp,
  /// `drpriority`
  #[token("drpriority")] DrPriority,
  /// `diag`
  #[token("diag")] Diag,
  /// `mydisc`
  #[token("mydisc")] MyDisc,
  /// `yourdisc`
  #[token("yourdisc")] YourDisc,
  /// `mintx`
  #[token("mintx")] MinTx,
  /// `minrx`
  #[token("minrx")] MinRx,
  /// `mult`
  #[token("mult")] Mult,
  /// `featuresreq`
  #[token("featuresreq")] FeaturesReq,
  /// `featuresreply`
  #[token("featuresreply")] FeaturesReply,
  /// `packetin`
  #[token("packetin")] PacketIn,
  /// `packetout`
  #[token("packetout")] PacketOut,
  /// `flowmod`
  #[token("flowmod")] FlowMod,
  /// `echoreq`
  #[token("echoreq")] EchoReq,
  /// `xid`
  #[token("xid")] Xid,
  /// `dpid`
  #[token("dpid")] Dpid,
  /// `tableid`
  #[token("tableid")] TableId,
  /// `init`
  #[token("init")] Init,
  /// `initack`
  #[token("initack")] InitAck,
  /// `sack`
  #[token("sack")] Sack,
  /// `heartbeat`
  #[token("heartbeat")] Heartbeat,
  /// `heartbeatack`
  #[token("heartbeatack")] HeartbeatAck,
  /// `abort`
  #[token("abort")] Abort,
  /// `shutdown`
  #[token("shutdown")] Shutdown,
  /// `shutdownack`
  #[token("shutdownack")] ShutdownAck,
  /// `cookieecho`
  #[token("cookieecho")] CookieEcho,
  /// `cookieack`
  #[token("cookieack")] CookieAck,
  /// `tsn`
  #[token("tsn")] Tsn,
  // Category 4: Layer 7 Network Infrastructure, Management & Telemetry
  /// `dns`
  #[token("dns")] Dns,
  /// `mdns`
  #[token("mdns")] Mdns,
  /// `dhcp`
  #[token("dhcp")] Dhcp,
  /// `ntp`
  #[token("ntp")] Ntp,
  /// `ptp`
  #[token("ptp")] Ptp,
  /// `radius`
  #[token("radius")] Radius,
  /// `tacacs`
  #[token("tacacs")] Tacacs,
  /// `syslog`
  #[token("syslog")] Syslog,
  /// `netflow`
  #[token("netflow")] Netflow,
  /// `ipfix`
  #[token("ipfix")] Ipfix,
  /// `sflow`
  #[token("sflow")] Sflow,
  // Category 5: Layer 7 Web, App, Directory, Mail, Storage & Messaging
  /// `tftp`
  #[token("tftp")] Tftp,
  /// `ftp`
  #[token("ftp")] Ftp,
  /// `ssh`
  #[token("ssh")] Ssh,
  /// `telnet`
  #[token("telnet")] Telnet,
  /// `http`
  #[token("http")] Http,
  /// `http2`
  #[token("http2")] Http2,
  /// `grpc`
  #[token("grpc")] Grpc,
  /// `websocket`
  #[token("websocket")] Websocket,
  /// `tls`
  #[token("tls")] Tls,
  /// `quic`
  #[token("quic")] Quic,
  /// `stun`
  #[token("stun")] Stun,
  /// `sip`
  #[token("sip")] Sip,
  /// `rtp`
  #[token("rtp")] Rtp,
  /// `rtsp`
  #[token("rtsp")] Rtsp,
  /// `smtp`
  #[token("smtp")] Smtp,
  /// `imap`
  #[token("imap")] Imap,
  /// `pop3`
  #[token("pop3")] Pop3,
  /// `kerberos`
  #[token("kerberos")] Kerberos,
  /// `ldap`
  #[token("ldap")] Ldap,
  /// `smb`
  #[token("smb")] Smb,
  /// `nfs`
  #[token("nfs")] Nfs,
  /// `redis`
  #[token("redis")] Redis,
  /// `memcached`
  #[token("memcached")] Memcached,
  /// `mysql`
  #[token("mysql")] Mysql,
  /// `postgres`
  #[token("postgres")] Postgres,
  /// `mqtt`
  #[token("mqtt")] Mqtt,
  /// `coap`
  #[token("coap")] Coap,
  /// `amqp`
  #[token("amqp")] Amqp,
  /// `ssdp`
  #[token("ssdp")] Ssdp,
  /// `whois`
  #[token("whois")] Whois,
  // Category 6: Layer 7 Industrial / OT Protocols
  /// `modbus`
  #[token("modbus")] Modbus,
  /// `bacnet`
  #[token("bacnet")] Bacnet,
  /// `dnp3`
  #[token("dnp3")] Dnp3,
  /// `s7comm`
  #[token("s7comm")] S7comm,
  /// `ethernetip`
  #[token("ethernetip")] Ethernetip,
  /// `opcua`
  #[token("opcua")] Opcua,
  // Category 4 Sub-keywords
  /// `txid`
  #[token("txid")] Txid,
  /// `qname`
  #[token("qname")] Qname,
  /// `qtype`
  #[token("qtype")] Qtype,
  /// `rdata`
  #[token("rdata")] Rdata,
  /// `rcode`
  #[token("rcode")] Rcode,
  /// `ansttl`
  #[token("ansttl")] AnsTtl,
  /// `discover`
  #[token("discover")] Discover,
  /// `solicit`
  #[token("solicit")] Solicit,
  /// `offer`
  #[token("offer")] Offer,
  /// `advertise`
  #[token("advertise")] Advertise,
  /// `release`
  #[token("release")] Release,
  /// `ciaddr`
  #[token("ciaddr")] Ciaddr,
  /// `yiaddr`
  #[token("yiaddr")] Yiaddr,
  /// `siaddr`
  #[token("siaddr")] Siaddr,
  /// `chaddr`
  #[token("chaddr")] Chaddr,
  /// `hostname`
  #[token("hostname")] Hostname,
  /// `dnsserver`
  #[token("dnsserver")] DnsServer,
  /// `router`
  #[token("router")] Router,
  /// `subnetmask`
  #[token("subnetmask")] SubnetMask,
  /// `leasetime`
  #[token("leasetime")] LeaseTime,
  /// `li`
  #[token("li")] Li,
  /// `vn`
  #[token("vn")] Vn,
  /// `mode`
  #[token("mode")] Mode,
  /// `stratum`
  #[token("stratum")] Stratum,
  /// `poll`
  #[token("poll")] Poll,
  /// `precision`
  #[token("precision")] Precision,
  /// `refid`
  #[token("refid")] RefId,
  /// `txtimestamp`
  #[token("txtimestamp")] TxTimestamp,
  /// `msgtype`
  #[token("msgtype")] MsgType,
  /// `sync`
  #[token("sync")] Sync,
  /// `delayreq`
  #[token("delayreq")] DelayReq,
  /// `followup`
  #[token("followup")] FollowUp,
  /// `delayresp`
  #[token("delayresp")] DelayResp,
  /// `announce`
  #[token("announce")] Announce,
  /// `domain`
  #[token("domain")] Domain,
  /// `seqid`
  #[token("seqid")] SeqId,
  /// `clockid`
  #[token("clockid")] ClockId,
  /// `accessrequest`
  #[token("accessrequest")] AccessRequest,
  /// `accessaccept`
  #[token("accessaccept")] AccessAccept,
  /// `accessreject`
  #[token("accessreject")] AccessReject,
  /// `accesschallenge`
  #[token("accesschallenge")] AccessChallenge,
  /// `accountingrequest`
  #[token("accountingrequest")] AccountingRequest,
  /// `accountingresponse`
  #[token("accountingresponse")] AccountingResponse,
  /// `nasip`
  #[token("nasip")] NasIp,
  /// `servicetype`
  #[token("servicetype")] ServiceType,
  /// `framedip`
  #[token("framedip")] FramedIp,
  /// `authen`
  #[token("authen")] Authen,
  /// `author`
  #[token("author")] Author,
  /// `acct`
  #[token("acct")] Acct,
  /// `sessionid`
  #[token("sessionid")] SessionId,
  /// `facility`
  #[token("facility")] Facility,
  /// `severity`
  #[token("severity")] Severity,
  /// `pri`
  #[token("pri")] Pri,
  /// `app`
  #[token("app")] App,
  /// `procid`
  #[token("procid")] Procid,
  /// `msg`
  #[token("msg")] Msg,
  /// `srcip`
  #[token("srcip")] SrcIp,
  /// `dstip`
  #[token("dstip")] DstIp,
  /// `proto`
  #[token("proto")] Proto,
  /// `packets`
  #[token("packets")] Packets,
  /// `octets`
  #[token("octets")] Octets,
  /// `domainid`
  #[token("domainid")] DomainId,
  /// `subagentid`
  #[token("subagentid")] SubAgentId,
  /// `uptime`
  #[token("uptime")] Uptime,
  /// `samples`
  #[token("samples")] Samples,
  // Category 5 Sub-keywords
  /// `rrq`
  #[token("rrq")] Rrq,
  /// `wrq`
  #[token("wrq")] Wrq,
  /// `filename`
  #[token("filename")] Filename,
  /// `block`
  #[token("block")] Block,
  /// `errcode`
  #[token("errcode")] ErrCode,
  /// `errmsg`
  #[token("errmsg")] ErrMsg,
  /// `cmd`
  #[token("cmd")] Cmd,
  /// `arg`
  #[token("arg")] Arg,
  /// `banner`
  #[token("banner")] Banner,
  /// `kexinit`
  #[token("kexinit")] KexInit,
  /// `newkeys`
  #[token("newkeys")] NewKeys,
  /// `msgcode`
  #[token("msgcode")] MsgCode,
  /// `will`
  #[token("will")] Will,
  /// `wont`
  #[token("wont")] Wont,
  /// `do`
  #[token("do")] DoCmd,
  /// `dont`
  #[token("dont")] Dont,
  /// `option`
  #[token("option")] Option,
  /// `post`
  #[token("post")] Post,
  /// `put`
  #[token("put")] Put,
  /// `delete`
  #[token("delete")] Delete,
  /// `head`
  #[token("head")] Head,
  /// `options`
  #[token("options")] Options,
  /// `patch`
  #[token("patch")] Patch,
  /// `uri`
  #[token("uri")] Uri,
  /// `hosthdr`
  #[token("hosthdr")] HostHdr,
  /// `useragent`
  #[token("useragent")] UserAgent,
  /// `contenttype`
  #[token("contenttype")] ContentType,
  /// `status`
  #[token("status")] Status,
  /// `reason`
  #[token("reason")] Reason,
  /// `header`
  #[token("header")] Header,
  /// `body`
  #[token("body")] Body,
  /// `preface`
  #[token("preface")] Preface,
  /// `settings`
  #[token("settings")] Settings,
  /// `headers`
  #[token("headers")] Headers,
  /// `windowupdate`
  #[token("windowupdate")] WindowUpdate,
  /// `ping`
  #[token("ping")] Ping,
  /// `goaway`
  #[token("goaway")] Goaway,
  /// `streamid`
  #[token("streamid")] StreamId,
  /// `service`
  #[token("service")] Service,
  /// `method`
  #[token("method")] Method,
  /// `grpcstatus`
  #[token("grpcstatus")] GrpcStatus,
  /// `opcode`
  #[token("opcode")] Opcode,
  /// `text`
  #[token("text")] Text,
  /// `binary`
  #[token("binary")] Binary,
  /// `pong`
  #[token("pong")] Pong,
  /// `close`
  #[token("close")] Close,
  /// `finbit`
  #[token("finbit")] FinBit,
  /// `maskkey`
  #[token("maskkey")] MaskKey,
  /// `clienthello`
  #[token("clienthello")] ClientHello,
  /// `serverhello`
  #[token("serverhello")] ServerHello,
  /// `certificate`
  #[token("certificate")] Certificate,
  /// `finished`
  #[token("finished")] Finished,
  /// `appdata`
  #[token("appdata")] AppData,
  /// `alert`
  #[token("alert")] Alert,
  /// `recordversion`
  #[token("recordversion")] RecordVersion,
  /// `handshakeversion`
  #[token("handshakeversion")] HandshakeVersion,
  /// `sni`
  #[token("sni")] Sni,
  /// `ciphersuite`
  #[token("ciphersuite")] Ciphersuite,
  /// `alpn`
  #[token("alpn")] Alpn,
  /// `initial`
  #[token("initial")] Initial,
  /// `zerortt`
  #[token("zerortt")] ZeroRtt,
  /// `handshake`
  #[token("handshake")] Handshake,
  /// `retry`
  #[token("retry")] Retry,
  /// `short`
  #[token("short")] Short,
  /// `dcid`
  #[token("dcid")] Dcid,
  /// `scid`
  #[token("scid")] Scid,
  /// `token`
  #[token("token")] Token,
  /// `pktnum`
  #[token("pktnum")] PktNum,
  /// `bindingrequest`
  #[token("bindingrequest")] BindingRequest,
  /// `bindingresponse`
  #[token("bindingresponse")] BindingResponse,
  /// `bindingerror`
  #[token("bindingerror")] BindingError,
  /// `xormappedaddr`
  #[token("xormappedaddr")] XorMappedAddr,
  /// `software`
  #[token("software")] Software,
  /// `invite`
  #[token("invite")] Invite,
  /// `bye`
  #[token("bye")] Bye,
  /// `cancel`
  #[token("cancel")] Cancel,
  /// `from`
  #[token("from")] From,
  /// `to`
  #[token("to")] To,
  /// `callid`
  #[token("callid")] CallId,
  /// `cseq`
  #[token("cseq")] Cseq,
  /// `via`
  #[token("via")] Via,
  /// `contact`
  #[token("contact")] Contact,
  /// `pt`
  #[token("pt")] Pt,
  /// `timestamp`
  #[token("timestamp")] Timestamp,
  /// `ssrc`
  #[token("ssrc")] Ssrc,
  /// `marker`
  #[token("marker")] Marker,
  /// `describe`
  #[token("describe")] Describe,
  /// `setup`
  #[token("setup")] Setup,
  /// `play`
  #[token("play")] Play,
  /// `teardown`
  #[token("teardown")] Teardown,
  /// `transporthdr`
  #[token("transporthdr")] TransportHdr,
  /// `session`
  #[token("session")] Session,
  /// `ehlo`
  #[token("ehlo")] Ehlo,
  /// `helo`
  #[token("helo")] Helo,
  /// `mailfrom`
  #[token("mailfrom")] MailFrom,
  /// `rcptto`
  #[token("rcptto")] RcptTo,
  /// `quit`
  #[token("quit")] Quit,
  /// `param`
  #[token("param")] Param,
  /// `ok`
  #[token("ok")] Ok,
  /// `err`
  #[token("err")] Err,
  /// `error`
  #[token("error")] ErrorKw,
  /// `asreq`
  #[token("asreq")] AsReq,
  /// `asrep`
  #[token("asrep")] AsRep,
  /// `tgsreq`
  #[token("tgsreq")] TgsReq,
  /// `tgsrep`
  #[token("tgsrep")] TgsRep,
  /// `krberror`
  #[token("krberror")] KrbError,
  /// `realm`
  #[token("realm")] Realm,
  /// `cname`
  #[token("cname")] Cname,
  /// `sname`
  #[token("sname")] Sname,
  /// `etype`
  #[token("etype")] Etype,
  /// `bindreq`
  #[token("bindreq")] BindReq,
  /// `bindres`
  #[token("bindres")] BindRes,
  /// `searchreq`
  #[token("searchreq")] SearchReq,
  /// `searchentry`
  #[token("searchentry")] SearchEntry,
  /// `searchdone`
  #[token("searchdone")] SearchDone,
  /// `unbindreq`
  #[token("unbindreq")] UnbindReq,
  /// `basedn`
  #[token("basedn")] BaseDn,
  /// `filter`
  #[token("filter")] Filter,
  /// `resultcode`
  #[token("resultcode")] ResultCode,
  /// `command`
  #[token("command")] Command,
  /// `negotiate`
  #[token("negotiate")] Negotiate,
  /// `sessionsetup`
  #[token("sessionsetup")] SessionSetup,
  /// `treeconnect`
  #[token("treeconnect")] TreeConnect,
  /// `create`
  #[token("create")] Create,
  /// `treedisconnect`
  #[token("treedisconnect")] TreeDisconnect,
  /// `treeid`
  #[token("treeid")] TreeId,
  /// `share`
  #[token("share")] Share,
  /// `vers`
  #[token("vers")] Vers,
  /// `proc`
  #[token("proc")] Proc,
  /// `path`
  #[token("path")] Path,
  /// `compound`
  #[token("compound")] Compound,
  /// `args`
  #[token("args")] Args,
  /// `replytype`
  #[token("replytype")] ReplyType,
  /// `value`
  #[token("value")] Value,
  /// `exptime`
  #[token("exptime")] Exptime,
  /// `opaque`
  #[token("opaque")] Opaque,
  /// `cas`
  #[token("cas")] Cas,
  /// `greeting`
  #[token("greeting")] Greeting,
  /// `login`
  #[token("login")] Login,
  /// `sql`
  #[token("sql")] Sql,
  /// `eof`
  #[token("eof")] Eof,
  /// `serverversion`
  #[token("serverversion")] ServerVersion,
  /// `db`
  #[token("db")] Db,
  /// `startup`
  #[token("startup")] Startup,
  /// `readyforquery`
  #[token("readyforquery")] ReadyForQuery,
  /// `commandcomplete`
  #[token("commandcomplete")] CommandComplete,
  /// `errorresponse`
  #[token("errorresponse")] ErrorResponse,
  /// `authok`
  #[token("authok")] AuthOk,
  /// `connect`
  #[token("connect")] Connect,
  /// `connack`
  #[token("connack")] Connack,
  /// `publish`
  #[token("publish")] Publish,
  /// `puback`
  #[token("puback")] Puback,
  /// `subscribe`
  #[token("subscribe")] Subscribe,
  /// `suback`
  #[token("suback")] Suback,
  /// `pingreq`
  #[token("pingreq")] Pingreq,
  /// `pingresp`
  #[token("pingresp")] Pingresp,
  /// `disconnect`
  #[token("disconnect")] Disconnect,
  /// `clientid`
  #[token("clientid")] ClientId,
  /// `topic`
  #[token("topic")] Topic,
  /// `qos`
  #[token("qos")] Qos,
  /// `retain`
  #[token("retain")] Retain,
  /// `pkttype`
  #[token("pkttype")] PktType,
  /// `pktid`
  #[token("pktid")] PktId,
  /// `returncode`
  #[token("returncode")] ReturnCode,
  /// `con`
  #[token("con")] Con,
  /// `non`
  #[token("non")] Non,
  /// `changed`
  #[token("changed")] Changed,
  /// `created`
  #[token("created")] Created,
  /// `notfound`
  #[token("notfound")] NotFound,
  /// `uripath`
  #[token("uripath")] UriPath,
  /// `contentformat`
  #[token("contentformat")] ContentFormat,
  /// `protocolheader`
  #[token("protocolheader")] ProtocolHeader,
  /// `connectionstart`
  #[token("connectionstart")] ConnectionStart,
  /// `channelopen`
  #[token("channelopen")] ChannelOpen,
  /// `basicpublish`
  #[token("basicpublish")] BasicPublish,
  /// `basicdeliver`
  #[token("basicdeliver")] BasicDeliver,
  /// `channel`
  #[token("channel")] Channel,
  /// `routingkey`
  #[token("routingkey")] RoutingKey,
  /// `msearch`
  #[token("msearch")] Msearch,
  /// `notify`
  #[token("notify")] Notify,
  /// `man`
  #[token("man")] Man,
  /// `mx`
  #[token("mx")] Mx,
  /// `st`
  #[token("st")] St,
  /// `nt`
  #[token("nt")] Nt,
  /// `nts`
  #[token("nts")] Nts,
  /// `usn`
  #[token("usn")] Usn,
  /// `location`
  #[token("location")] Location,
  /// `registrar`
  #[token("registrar")] Registrar,
  // Category 6 Sub-keywords
  /// `protoid`
  #[token("protoid")] ProtoId,
  /// `unitid`
  #[token("unitid")] UnitId,
  /// `func`
  #[token("func")] Func,
  /// `readcoils`
  #[token("readcoils")] ReadCoils,
  /// `readdiscreteinputs`
  #[token("readdiscreteinputs")] ReadDiscreteInputs,
  /// `readholdingregisters`
  #[token("readholdingregisters")] ReadHoldingRegisters,
  /// `readinputregisters`
  #[token("readinputregisters")] ReadInputRegisters,
  /// `writesinglecoil`
  #[token("writesinglecoil")] WriteSingleCoil,
  /// `writesingleregister`
  #[token("writesingleregister")] WriteSingleRegister,
  /// `writemultipleregisters`
  #[token("writemultipleregisters")] WriteMultipleRegisters,
  /// `addr`
  #[token("addr")] Addr,
  /// `count`
  #[token("count")] Count,
  /// `isresponse`
  #[token("isresponse")] IsResponse,
  /// `iam`
  #[token("iam")] IAm,
  /// `readproperty`
  #[token("readproperty")] ReadProperty,
  /// `writeproperty`
  #[token("writeproperty")] WriteProperty,
  /// `invokeid`
  #[token("invokeid")] InvokeId,
  /// `objecttype`
  #[token("objecttype")] ObjectType,
  /// `objectinstance`
  #[token("objectinstance")] ObjectInstance,
  /// `propertyid`
  #[token("propertyid")] PropertyId,
  /// `confirm`
  #[token("confirm")] Confirm,
  /// `read`
  #[token("read")] Read,
  /// `write`
  #[token("write")] Write,
  /// `select`
  #[token("select")] Select,
  /// `operate`
  #[token("operate")] Operate,
  /// `directoperate`
  #[token("directoperate")] DirectOperate,
  /// `unsolicitedresponse`
  #[token("unsolicitedresponse")] UnsolicitedResponse,
  /// `variation`
  #[token("variation")] Variation,
  /// `crc`
  #[token("crc")] Crc,
  /// `src`
  #[token("src")] Src,
  /// `dst`
  #[token("dst")] Dst,
  /// `rosctr`
  #[token("rosctr")] Rosctr,
  /// `pduref`
  #[token("pduref")] PduRef,
  /// `setupcomm`
  #[token("setupcomm")] SetupComm,
  /// `readvar`
  #[token("readvar")] ReadVar,
  /// `writevar`
  #[token("writevar")] WriteVar,
  /// `plccontrol`
  #[token("plccontrol")] PlcControl,
  /// `area`
  #[token("area")] Area,
  /// `dbnum`
  #[token("dbnum")] DbNum,
  /// `offset`
  #[token("offset")] Offset,
  /// `nop`
  #[token("nop")] Nop,
  /// `listservices`
  #[token("listservices")] ListServices,
  /// `listidentity`
  #[token("listidentity")] ListIdentity,
  /// `listinterfaces`
  #[token("listinterfaces")] ListInterfaces,
  /// `registersession`
  #[token("registersession")] RegisterSession,
  /// `unregistersession`
  #[token("unregistersession")] UnregisterSession,
  /// `sendrrdata`
  #[token("sendrrdata")] SendRrData,
  /// `sendunitdata`
  #[token("sendunitdata")] SendUnitData,
  /// `sessionhandle`
  #[token("sessionhandle")] SessionHandle,
  /// `context`
  #[token("context")] ContextVal,
  /// `cipservice`
  #[token("cipservice")] CipService,
  /// `cipclass`
  #[token("cipclass")] CipClass,
  /// `cipinstance`
  #[token("cipinstance")] CipInstance,
  /// `cipattr`
  #[token("cipattr")] CipAttr,
  /// `chunktype`
  #[token("chunktype")] ChunkType,
  /// `securechannelid`
  #[token("securechannelid")] SecureChannelId,
  /// `tokenid`
  #[token("tokenid")] TokenId,
  /// `seqnum`
  #[token("seqnum")] SeqNum,
  /// `endpointurl`
  #[token("endpointurl")] EndpointUrl,
  /// `nodeid`
  #[token("nodeid")] NodeId,
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
  #[token("ns", priority = 2)] Ns,
  /// `us`
  #[token("us", priority = 2)] Us,
  /// `ms`
  #[token("ms", priority = 2)] Ms,
  /// `s`
  #[token("s", priority = 2)] Sec,
  /// `m`
  #[token("m", priority = 2)] Min,
  /// User-defined identifier (allows uppercase, `_`, and internal `-`, stopping before `->`).
  #[regex(r"[a-zA-Z_][a-zA-Z0-9_]*(-[a-zA-Z0-9_]+)*", priority = 1)]
  Ident(&'a str),
  /// String literal
  #[regex(r#""([^"\\]|\\.)*""#)]
  StringLit(&'a str),
  // Match IPv4 and IPv6-like strings loosely, parser will validate
  /// IPv4/IPv6 address
  #[regex(r"[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+", priority = 5)]
  #[regex(r"::[0-9a-fA-F:.]*|[0-9a-fA-F]{1,4}(:[0-9a-fA-F:.]*)+", priority = 2)]
  IpAddress(&'a str),
  // Match MAC addresses in colon (00:1a:2b:3c:4d:5e), hyphen (00-1A-2B-3C-4D-5E), or Cisco dotted-quad (001a.2b3c.4d5e) notation
  /// MAC address
  #[regex(r"([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}", priority = 6)]
  #[regex(r"([0-9a-fA-F]{2}-){5}[0-9a-fA-F]{2}", priority = 6)]
  #[regex(r"[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}", priority = 6)]
  MacAddress(&'a str),
  // Match OIDs loosely
  /// SNMP OID
  #[regex(r"\.?[0-9]+(\.[0-9]+)*", priority = 3)]
  OidStr(&'a str),
  /// Numeric literal (supports decimal and hex integers)
  #[regex(r"-?[0-9]+|0[xX][0-9a-fA-F]+", priority = 4)]
  Number(&'a str),
}

/// Expands a single-byte lexer failure span for multi-character constructs (`/24`, `/*`, `'...'`).
fn expand_lex_error_span(input: &str, span: std::ops::Range<usize>) -> (usize, usize) {
    let start = span.start.min(input.len());
    let rest = &input[start..];
    let bytes = rest.as_bytes();
    let len = if bytes.starts_with(b"/*") || bytes.starts_with(b"*/") {
        2
    } else if bytes.first() == Some(&b'/') && bytes.get(1).is_some_and(|b| b.is_ascii_digit()) {
        1 + bytes[1..].iter().take_while(|b| b.is_ascii_digit()).count()
    } else if bytes.first() == Some(&b'\'') {
        let line_rest = rest.lines().next().unwrap_or(rest);
        if let Some(close_idx) = line_rest.get(1..).and_then(|s| s.find('\'')) {
            close_idx + 2
        } else {
            span.end.saturating_sub(span.start).max(1)
        }
    } else {
        span.end.saturating_sub(span.start).max(1)
    };
    (start, len)
}

/// Lexes an input string into a sequence of tokens and their source spans.
///
/// # Examples
/// ```
/// use frameassembly::lexer::lex;
///
/// let input = "host example { ip 10.0.0.1 }";
/// let tokens = lex(input).unwrap();
/// assert_eq!(tokens.len(), 6);
/// ```
///
/// # Errors
/// Returns a `CompilerError::LexError` if an unrecognized sequence of characters is encountered.
pub fn lex<'a>(
    input: &'a str,
) -> Result<alloc::vec::Vec<(Token<'a>, std::ops::Range<usize>)>, crate::error::CompilerError> {
    let mut base = 0usize;
    let mut lexer = Token::lexer(input);
    let mut tokens = alloc::vec::Vec::new();
    while let Some(res) = lexer.next() {
        let local_span = lexer.span();
        let abs_start = base + local_span.start;
        let mut abs_end = base + local_span.end;
        match res {
            Ok(mut token) => {
                // Guard against logos 0.14 DFA non-rewinding lookahead on `(-[a-zA-Z0-9_]+)*`
                // when an identifier or keyword is followed directly by `->` (with no space).
                if abs_end > abs_start
                    && !matches!(token, Token::LeftArrow | Token::StringLit(_))
                    && input.as_bytes()[abs_end - 1] == b'-'
                {
                    abs_end -= 1;
                    let slice = &input[abs_start..abs_end];
                    token = match token {
                        Token::Ident(_) => Token::Ident(slice),
                        Token::MacAddress(_) => Token::MacAddress(slice),
                        Token::IpAddress(_) => Token::IpAddress(slice),
                        Token::OidStr(_) => Token::OidStr(slice),
                        Token::Number(_) => Token::Number(slice),
                        other => other,
                    };
                    tokens.push((token, abs_start..abs_end));
                    base = abs_end;
                    lexer = Token::lexer(&input[base..]);
                } else {
                    tokens.push((token, abs_start..abs_end));
                }
            }
            Err(_) => {
                return Err(crate::error::CompilerError::LexError {
                    src: input.to_string(),
                    span: expand_lex_error_span(input, abs_start..abs_end),
                });
            }
        }
    }
    Ok(tokens)
}

/// Checks whether normalizing `raw` to ASCII lowercase with `'_'` and `'-'` stripped matches a
/// built-in FrameAssembly v3.0 keyword (returning `Some(kw)` when `raw != kw`).
pub(crate) fn suggest_v2_lowercase_keyword(raw: &str) -> Option<alloc::string::String> {
    if raw.is_empty() {
        return None;
    }
    let normalized: alloc::string::String = raw
        .chars()
        .filter(|&c| c != '_' && c != '-')
        .map(|c| c.to_ascii_lowercase())
        .collect();
    if normalized.is_empty() || normalized == raw {
        return None;
    }
    if !normalized.as_bytes()[0].is_ascii_lowercase()
        || !normalized
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
    {
        return None;
    }
    let mut lx = Token::lexer(&normalized);
    match (lx.next(), lx.next()) {
        (Some(Ok(tok)), None) if !matches!(tok, Token::Ident(_)) => Some(normalized),
        _ => None,
    }
}

#[cfg(test)]
mod tests;
