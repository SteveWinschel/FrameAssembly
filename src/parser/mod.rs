//! FrameAssembly Parser.
//!
//! Provides two-phase parsing for FrameAssembly DSL definitions using winnow combinators:
//! 1. Lexical token stream parsing (`Stream`) into strongly typed AST representations (`Program`, `HostDef`, `FlowDef`, `FrameStatement`).
//! 2. Semantic validation of structural invariants (endpoint types, protocol compatibility, ranges).

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::net::IpAddr;
use core::str::FromStr;
use std::collections::{HashMap, HashSet};

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err, opt, repeat, separated};
use winnow::error::{ContextError, ErrMode};
use winnow::prelude::*;
use winnow::token::any;

use crate::ast::*;
use crate::error::CompilerError;
use crate::lexer::Token;

/// Layer 2 field parsers.
pub mod l2;
/// Layer 3 field parsers.
pub mod l3;
/// Layer 4 field parsers.
pub mod l4;
/// Layer 7 field parsers.
pub mod l7;
/// SNMP field parsers.
/// SNMP protocol parser (backwards-compatible alias).
pub mod snmp {
    pub(crate) use super::l7::snmp::*;
}
#[cfg(test)]
mod tests;

/// A stream of lexical tokens mapped to their source spans.
///
/// Used extensively throughout the parser combinators.
pub type Stream<'i, 'a> = &'i [(Token<'a>, core::ops::Range<usize>)];

/// Helper to match a specific token exactly, returning the token and its source span.
pub(crate) fn tag<'i, 'a: 'i>(
    expected: Token<'a>,
) -> impl Parser<Stream<'i, 'a>, (Token<'a>, core::ops::Range<usize>), ErrMode<ContextError>> {
    any.verify(move |(t, _): &(Token<'a>, core::ops::Range<usize>)| *t == expected)
}

/// Helper to parse an identifier or contextual keyword, returning its spanned node.
pub(crate) fn parse_spanned_ident<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<Spanned<&'a str>> {
    let (t, span) = any
        .verify(|(t, _)| {
            !matches!(
                t,
                Token::RightArrow
                    | Token::LeftArrow
                    | Token::LBrace
                    | Token::RBrace
                    | Token::LParen
                    | Token::RParen
                    | Token::Comma
                    | Token::StringLit(_)
                    | Token::IpAddress(_)
                    | Token::MacAddress(_)
                    | Token::OidStr(_)
                    | Token::Number(_)
            )
        })
        .parse_next(input)?;

    let name = match t {
        Token::Ident(s) => s,
        Token::Ns => "ns",
        Token::Us => "us",
        Token::Ms => "ms",
        Token::Sec => "s",
        Token::Min => "m",
        Token::Tcp => "TCP",
        Token::Udp => "UDP",
        Token::Snmp1 => "SNMP1",
        Token::Snmp2 => "SNMP2",
        Token::Snmp3 => "SNMP3",
        Token::Syn => "SYN",
        Token::Ack => "ACK",
        Token::Fin => "FIN",
        Token::Rst => "RST",
        Token::Psh => "PSH",
        Token::Urg => "URG",
        Token::Ece => "ECE",
        Token::Cwr => "CWR",
        Token::SrcPort => "SRCPORT",
        Token::DstPort => "DSTPORT",
        Token::Seq => "SEQ",
        Token::AckNum => "ACKNUM",
        Token::Win => "WIN",
        Token::Payload => "PAYLOAD",
        Token::HexPayload => "HEXPAYLOAD",
        Token::Wait => "WAIT",
        Token::Vlan => "VLAN",
        Token::Dscp => "DSCP",
        Token::Ecn => "ECN",
        Token::Ttl => "TTL",
        Token::FlowLabel => "FLOWLABEL",
        Token::Trap => "TRAP",
        Token::Get => "GET",
        Token::Set => "SET",
        Token::Response => "RESPONSE",
        Token::Inform => "INFORM",
        Token::GetNext => "GETNEXT",
        Token::GetBulk => "GETBULK",
        Token::Community => "COMMUNITY",
        Token::User => "USER",
        Token::Oid => "OID",
        Token::SysUpTime => "SYSUPTIME",
        Token::VarBind => "VARBIND",
        Token::NullVal => "NULLVAL",
        Token::StringVal => "STRING",
        Token::IntVal => "INT",
        Token::TimeTicksVal => "TIMETICKS",
        Token::IpVal => "IPVAL",
        Token::OidVal => "OIDVAL",
        Token::Counter32Val => "COUNTER32",
        Token::Gauge32Val => "GAUGE32",
        Token::Counter64Val => "COUNTER64",
        Token::Enterprise => "ENTERPRISE",
        Token::AgentIp => "AGENTIP",
        Token::GenTrap => "GENTRAP",
        Token::SpecTrap => "SPECTRAP",
        Token::EngineId => "ENGINEID",
        Token::EngineBoots => "ENGINEBOOTS",
        Token::EngineTime => "ENGINETIME",
        Token::ContextName => "CONTEXTNAME",
        Token::Auth => "AUTH",
        Token::Priv => "PRIV",
        Token::Md5 => "MD5",
        Token::Sha => "SHA",
        Token::Sha256 => "SHA256",
        Token::Sha384 => "SHA384",
        Token::Sha512 => "SHA512",
        Token::Des => "DES",
        Token::Aes => "AES",
        Token::NonRepeaters => "NONREPEATERS",
        Token::MaxRepetitions => "MAXREPETITIONS",
        Token::ReqId => "REQID",
        Token::Pcp => "PCP",
        Token::Dei => "DEI",
        Token::Qinq => "QINQ",
        Token::InnerVlan => "INNER_VLAN",
        Token::Mpls => "MPLS",
        Token::Exp => "EXP",
        Token::Bos => "BOS",
        Token::MplsTtl => "MPLS_TTL",
        Token::SrcMac => "SRCMAC",
        Token::DstMac => "DSTMAC",
        Token::EtherType => "ETHERTYPE",
        Token::IpId => "IPID",
        Token::Df => "DF",
        Token::Mf => "MF",
        Token::FragOffset => "FRAGOFFSET",
        Token::Transport => "TRANSPORT",
        Token::Window => "WINDOW",
        Token::Urgent => "URGENT",
        Token::Mss => "MSS",
        Token::Wscale => "WSCALE",
        Token::SackPerm => "SACK_PERM",
        Token::Tsval => "TSVAL",
        Token::Tsecr => "TSECR",
        Token::Vtag => "VTAG",
        Token::Stream => "STREAM",
        Token::Ssn => "SSN",
        Token::Ppid => "PPID",
        Token::Chunk => "CHUNK",
        Token::Arp => "ARP",
        Token::Lldp => "LLDP",
        Token::Stp => "STP",
        Token::Lacp => "LACP",
        Token::Eapol => "EAPOL",
        Token::Icmp => "ICMP",
        Token::Ndp => "NDP",
        Token::Igmp => "IGMP",
        Token::Mld => "MLD",
        Token::Gre => "GRE",
        Token::Vxlan => "VXLAN",
        Token::Geneve => "GENEVE",
        Token::Ipsec => "IPSEC",
        Token::Esp => "ESP",
        Token::Ah => "AH",
        Token::Ikev2 => "IKEV2",
        Token::Wireguard => "WIREGUARD",
        Token::Ospf => "OSPF",
        Token::Bgp => "BGP",
        Token::Rip => "RIP",
        Token::Vrrp => "VRRP",
        Token::Hsrp => "HSRP",
        Token::Pim => "PIM",
        Token::Bfd => "BFD",
        Token::Openflow => "OPENFLOW",
        Token::Sctp => "SCTP",
        Token::Request => "REQUEST",
        Token::Reply => "REPLY",
        Token::Gratuitous => "GRATUITOUS",
        Token::Spa => "SPA",
        Token::Tha => "THA",
        Token::Tpa => "TPA",
        Token::SenderMac => "SENDERMAC",
        Token::TargetMac => "TARGETMAC",
        Token::SenderIp => "SENDERIP",
        Token::TargetIp => "TARGETIP",
        Token::ChassisId => "CHASSIS_ID",
        Token::PortId => "PORT_ID",
        Token::SysName => "SYSNAME",
        Token::SysDesc => "SYSDESC",
        Token::RootId => "ROOT_ID",
        Token::BridgeId => "BRIDGE_ID",
        Token::Cost => "COST",
        Token::MaxAge => "MAX_AGE",
        Token::HelloTime => "HELLO_TIME",
        Token::ForwardDelay => "FORWARD_DELAY",
        Token::Rstp => "RSTP",
        Token::Flags => "FLAGS",
        Token::ActorSys => "ACTOR_SYS",
        Token::ActorKey => "ACTOR_KEY",
        Token::ActorPort => "ACTOR_PORT",
        Token::PartnerSys => "PARTNER_SYS",
        Token::PartnerKey => "PARTNER_KEY",
        Token::PartnerPort => "PARTNER_PORT",
        Token::ActorState => "ACTOR_STATE",
        Token::PartnerState => "PARTNER_STATE",
        Token::Version => "VERSION",
        Token::Type => "TYPE",
        Token::EapPacket => "EAP_PACKET",
        Token::Start => "START",
        Token::Logoff => "LOGOFF",
        Token::Key => "KEY",
        Token::EapCode => "EAP_CODE",
        Token::EapId => "EAP_ID",
        Token::EapMethod => "EAP_METHOD",
        Token::Identity => "IDENTITY",
        Token::Label => "LABEL",
        Token::EchoRequest => "ECHO_REQUEST",
        Token::EchoReply => "ECHO_REPLY",
        Token::DestUnreach => "DEST_UNREACH",
        Token::TimeExceeded => "TIME_EXCEEDED",
        Token::Redirect => "REDIRECT",
        Token::Code => "CODE",
        Token::Id => "ID",
        Token::Gateway => "GATEWAY",
        Token::RouterSolicit => "ROUTER_SOLICIT",
        Token::RouterAdvert => "ROUTER_ADVERT",
        Token::NeighborSolicit => "NEIGHBOR_SOLICIT",
        Token::NeighborAdvert => "NEIGHBOR_ADVERT",
        Token::Target => "TARGET",
        Token::Slla => "SLLA",
        Token::Tlla => "TLLA",
        Token::RouterLifetime => "ROUTER_LIFETIME",
        Token::Query => "QUERY",
        Token::Report => "REPORT",
        Token::Leave => "LEAVE",
        Token::Group => "GROUP",
        Token::MaxResp => "MAX_RESP",
        Token::V1 => "V1",
        Token::V2 => "V2",
        Token::V3 => "V3",
        Token::Done => "DONE",
        Token::MulticastAddr => "MULTICAST_ADDR",
        Token::MaxRespDelay => "MAX_RESP_DELAY",
        Token::GreKey => "GRE_KEY",
        Token::GreSeq => "GRE_SEQ",
        Token::GreProto => "GRE_PROTO",
        Token::Checksum => "CHECKSUM",
        Token::Vni => "VNI",
        Token::Vnid => "VNID",
        Token::OptClass => "OPT_CLASS",
        Token::OptType => "OPT_TYPE",
        Token::ProtocolType => "PROTOCOL_TYPE",
        Token::Spi => "SPI",
        Token::Iv => "IV",
        Token::Icv => "ICV",
        Token::NextHeader => "NEXT_HEADER",
        Token::InitiatorSpi => "INITIATOR_SPI",
        Token::ResponderSpi => "RESPONDER_SPI",
        Token::Exchange => "EXCHANGE",
        Token::SaInit => "SA_INIT",
        Token::CreateChildSa => "CREATE_CHILD_SA",
        Token::Informational => "INFORMATIONAL",
        Token::MsgId => "MSGID",
        Token::Initiation => "INITIATION",
        Token::Cookie => "COOKIE",
        Token::Data => "DATA",
        Token::Sender => "SENDER",
        Token::Receiver => "RECEIVER",
        Token::Counter => "COUNTER",
        Token::Hello => "HELLO",
        Token::Dbd => "DBD",
        Token::Lsr => "LSR",
        Token::Lsu => "LSU",
        Token::LsAck => "LSACK",
        Token::RouterId => "ROUTER_ID",
        Token::AreaId => "AREA_ID",
        Token::HelloInterval => "HELLO_INTERVAL",
        Token::DeadInterval => "DEAD_INTERVAL",
        Token::Priority => "PRIORITY",
        Token::Open => "OPEN",
        Token::Update => "UPDATE",
        Token::Notification => "NOTIFICATION",
        Token::Keepalive => "KEEPALIVE",
        Token::Asn => "ASN",
        Token::HoldTime => "HOLDTIME",
        Token::BgpId => "BGPID",
        Token::Prefix => "PREFIX",
        Token::Nlri => "NLRI",
        Token::NextHop => "NEXTHOP",
        Token::Metric => "METRIC",
        Token::Tag => "TAG",
        Token::Vrid => "VRID",
        Token::AdvInt => "ADV_INT",
        Token::Vip => "VIP",
        Token::HelloTimeHsrp => "HELLOTIME",
        Token::State => "STATE",
        Token::JoinPrune => "JOIN_PRUNE",
        Token::Register => "REGISTER",
        Token::Source => "SOURCE",
        Token::Rp => "RP",
        Token::DrPriority => "DR_PRIORITY",
        Token::Diag => "DIAG",
        Token::MyDisc => "MY_DISC",
        Token::YourDisc => "YOUR_DISC",
        Token::MinTx => "MIN_TX",
        Token::MinRx => "MIN_RX",
        Token::Mult => "MULT",
        Token::FeaturesReq => "FEATURES_REQ",
        Token::FeaturesReply => "FEATURES_REPLY",
        Token::PacketIn => "PACKET_IN",
        Token::PacketOut => "PACKET_OUT",
        Token::FlowMod => "FLOW_MOD",
        Token::EchoReq => "ECHO_REQ",
        Token::Xid => "XID",
        Token::Dpid => "DPID",
        Token::TableId => "TABLE_ID",
        Token::Init => "INIT",
        Token::InitAck => "INIT_ACK",
        Token::Sack => "SACK",
        Token::Heartbeat => "HEARTBEAT",
        Token::HeartbeatAck => "HEARTBEAT_ACK",
        Token::Abort => "ABORT",
        Token::Shutdown => "SHUTDOWN",
        Token::CookieEcho => "COOKIE_ECHO",
        Token::CookieAck => "COOKIE_ACK",
        Token::Tsn => "TSN",
        Token::Dns => "DNS",
        Token::Mdns => "MDNS",
        Token::Dhcp => "DHCP",
        Token::Ntp => "NTP",
        Token::Ptp => "PTP",
        Token::Radius => "RADIUS",
        Token::Tacacs => "TACACS",
        Token::Syslog => "SYSLOG",
        Token::Netflow => "NETFLOW",
        Token::Ipfix => "IPFIX",
        Token::Sflow => "SFLOW",
        Token::Tftp => "TFTP",
        Token::Ftp => "FTP",
        Token::Ssh => "SSH",
        Token::Telnet => "TELNET",
        Token::Http => "HTTP",
        Token::Http2 => "HTTP2",
        Token::Grpc => "GRPC",
        Token::Websocket => "WEBSOCKET",
        Token::Tls => "TLS",
        Token::Quic => "QUIC",
        Token::Stun => "STUN",
        Token::Sip => "SIP",
        Token::Rtp => "RTP",
        Token::Rtsp => "RTSP",
        Token::Smtp => "SMTP",
        Token::Imap => "IMAP",
        Token::Pop3 => "POP3",
        Token::Kerberos => "KERBEROS",
        Token::Ldap => "LDAP",
        Token::Smb => "SMB",
        Token::Nfs => "NFS",
        Token::Redis => "REDIS",
        Token::Memcached => "MEMCACHED",
        Token::Mysql => "MYSQL",
        Token::Postgres => "POSTGRES",
        Token::Mqtt => "MQTT",
        Token::Coap => "COAP",
        Token::Amqp => "AMQP",
        Token::Ssdp => "SSDP",
        Token::Whois => "WHOIS",
        Token::Modbus => "MODBUS",
        Token::Bacnet => "BACNET",
        Token::Dnp3 => "DNP3",
        Token::S7comm => "S7COMM",
        Token::Ethernetip => "ETHERNETIP",
        Token::Opcua => "OPCUA",
        Token::Txid => "TXID",
        Token::Qname => "QNAME",
        Token::Qtype => "QTYPE",
        Token::Rdata => "RDATA",
        Token::Rcode => "RCODE",
        Token::AnsTtl => "ANS_TTL",
        Token::Discover => "DISCOVER",
        Token::Solicit => "SOLICIT",
        Token::Offer => "OFFER",
        Token::Advertise => "ADVERTISE",
        Token::Release => "RELEASE",
        Token::Ciaddr => "CIADDR",
        Token::Yiaddr => "YIADDR",
        Token::Siaddr => "SIADDR",
        Token::Chaddr => "CHADDR",
        Token::Hostname => "HOSTNAME",
        Token::DnsServer => "DNS_SERVER",
        Token::Router => "ROUTER",
        Token::SubnetMask => "SUBNET_MASK",
        Token::LeaseTime => "LEASE_TIME",
        Token::Li => "LI",
        Token::Vn => "VN",
        Token::Mode => "MODE",
        Token::Stratum => "STRATUM",
        Token::Poll => "POLL",
        Token::Precision => "PRECISION",
        Token::RefId => "REFID",
        Token::TxTimestamp => "TX_TIMESTAMP",
        Token::MsgType => "MSG_TYPE",
        Token::Sync => "SYNC",
        Token::DelayReq => "DELAY_REQ",
        Token::FollowUp => "FOLLOW_UP",
        Token::DelayResp => "DELAY_RESP",
        Token::Announce => "ANNOUNCE",
        Token::Domain => "DOMAIN",
        Token::SeqId => "SEQ_ID",
        Token::ClockId => "CLOCK_ID",
        Token::AccessRequest => "ACCESS_REQUEST",
        Token::AccessAccept => "ACCESS_ACCEPT",
        Token::AccessReject => "ACCESS_REJECT",
        Token::AccessChallenge => "ACCESS_CHALLENGE",
        Token::AccountingRequest => "ACCOUNTING_REQUEST",
        Token::AccountingResponse => "ACCOUNTING_RESPONSE",
        Token::NasIp => "NAS_IP",
        Token::ServiceType => "SERVICE_TYPE",
        Token::FramedIp => "FRAMED_IP",
        Token::Authen => "AUTHEN",
        Token::Author => "AUTHOR",
        Token::Acct => "ACCT",
        Token::SessionId => "SESSION_ID",
        Token::Facility => "FACILITY",
        Token::Severity => "SEVERITY",
        Token::Pri => "PRI",
        Token::App => "APP",
        Token::Procid => "PROCID",
        Token::Msg => "MSG",
        Token::SrcIp => "SRCIP",
        Token::DstIp => "DSTIP",
        Token::Proto => "PROTO",
        Token::Packets => "PACKETS",
        Token::Octets => "OCTETS",
        Token::DomainId => "DOMAIN_ID",
        Token::AgentIpSflow => "AGENT_IP",
        Token::SubAgentId => "SUB_AGENT_ID",
        Token::Uptime => "UPTIME",
        Token::Samples => "SAMPLES",
        Token::Rrq => "RRQ",
        Token::Wrq => "WRQ",
        Token::Filename => "FILENAME",
        Token::Block => "BLOCK",
        Token::ErrCode => "ERRCODE",
        Token::ErrMsg => "ERRMSG",
        Token::Cmd => "CMD",
        Token::Arg => "ARG",
        Token::Banner => "BANNER",
        Token::KexInit => "KEXINIT",
        Token::NewKeys => "NEWKEYS",
        Token::MsgCode => "MSG_CODE",
        Token::Will => "WILL",
        Token::Wont => "WONT",
        Token::DoCmd => "DO",
        Token::Dont => "DONT",
        Token::Option => "OPTION",
        Token::Post => "POST",
        Token::Put => "PUT",
        Token::Delete => "DELETE",
        Token::Head => "HEAD",
        Token::Options => "OPTIONS",
        Token::Patch => "PATCH",
        Token::Uri => "URI",
        Token::HostHdr => "HOST_HDR",
        Token::UserAgent => "USER_AGENT",
        Token::ContentType => "CONTENT_TYPE",
        Token::Status => "STATUS",
        Token::Reason => "REASON",
        Token::Header => "HEADER",
        Token::Body => "BODY",
        Token::Preface => "PREFACE",
        Token::Settings => "SETTINGS",
        Token::Headers => "HEADERS",
        Token::WindowUpdate => "WINDOW_UPDATE",
        Token::Ping => "PING",
        Token::Goaway => "GOAWAY",
        Token::StreamId => "STREAM_ID",
        Token::Service => "SERVICE",
        Token::Method => "METHOD",
        Token::GrpcStatus => "GRPC_STATUS",
        Token::Opcode => "OPCODE",
        Token::Text => "TEXT",
        Token::Binary => "BINARY",
        Token::Pong => "PONG",
        Token::Close => "CLOSE",
        Token::FinBit => "FIN_BIT",
        Token::MaskKey => "MASK_KEY",
        Token::ClientHello => "CLIENT_HELLO",
        Token::ServerHello => "SERVER_HELLO",
        Token::Certificate => "CERTIFICATE",
        Token::Finished => "FINISHED",
        Token::AppData => "APP_DATA",
        Token::Alert => "ALERT",
        Token::RecordVersion => "RECORD_VERSION",
        Token::HandshakeVersion => "HANDSHAKE_VERSION",
        Token::Sni => "SNI",
        Token::Ciphersuite => "CIPHERSUITE",
        Token::Alpn => "ALPN",
        Token::Initial => "INITIAL",
        Token::ZeroRtt => "ZERO_RTT",
        Token::Handshake => "HANDSHAKE",
        Token::Retry => "RETRY",
        Token::Short => "SHORT",
        Token::Dcid => "DCID",
        Token::Scid => "SCID",
        Token::Token => "TOKEN",
        Token::PktNum => "PKT_NUM",
        Token::BindingRequest => "BINDING_REQUEST",
        Token::BindingResponse => "BINDING_RESPONSE",
        Token::BindingError => "BINDING_ERROR",
        Token::XorMappedAddr => "XOR_MAPPED_ADDR",
        Token::Software => "SOFTWARE",
        Token::Invite => "INVITE",
        Token::Bye => "BYE",
        Token::Cancel => "CANCEL",
        Token::From => "FROM",
        Token::To => "TO",
        Token::CallId => "CALL_ID",
        Token::Cseq => "CSEQ",
        Token::Via => "VIA",
        Token::Contact => "CONTACT",
        Token::Pt => "PT",
        Token::Timestamp => "TIMESTAMP",
        Token::Ssrc => "SSRC",
        Token::Marker => "MARKER",
        Token::Describe => "DESCRIBE",
        Token::Setup => "SETUP",
        Token::Play => "PLAY",
        Token::Teardown => "TEARDOWN",
        Token::TransportHdr => "TRANSPORT_HDR",
        Token::Session => "SESSION",
        Token::Ehlo => "EHLO",
        Token::Helo => "HELO",
        Token::MailFrom => "MAIL_FROM",
        Token::RcptTo => "RCPT_TO",
        Token::Quit => "QUIT",
        Token::Param => "PARAM",
        Token::Ok => "OK",
        Token::Err => "ERR",
        Token::AsReq => "AS_REQ",
        Token::AsRep => "AS_REP",
        Token::TgsReq => "TGS_REQ",
        Token::TgsRep => "TGS_REP",
        Token::KrbError => "KRB_ERROR",
        Token::Realm => "REALM",
        Token::Cname => "CNAME",
        Token::Sname => "SNAME",
        Token::Etype => "ETYPE",
        Token::BindReq => "BIND_REQ",
        Token::BindRes => "BIND_RES",
        Token::SearchReq => "SEARCH_REQ",
        Token::SearchEntry => "SEARCH_ENTRY",
        Token::SearchDone => "SEARCH_DONE",
        Token::UnbindReq => "UNBIND_REQ",
        Token::BaseDn => "BASE_DN",
        Token::Filter => "FILTER",
        Token::ResultCode => "RESULT_CODE",
        Token::Command => "COMMAND",
        Token::Negotiate => "NEGOTIATE",
        Token::SessionSetup => "SESSION_SETUP",
        Token::TreeConnect => "TREE_CONNECT",
        Token::Create => "CREATE",
        Token::TreeDisconnect => "TREE_DISCONNECT",
        Token::TreeId => "TREE_ID",
        Token::Share => "SHARE",
        Token::Vers => "VERS",
        Token::Proc => "PROC",
        Token::Path => "PATH",
        Token::Compound => "COMPOUND",
        Token::Args => "ARGS",
        Token::ReplyType => "REPLY_TYPE",
        Token::Value => "VALUE",
        Token::Exptime => "EXPTIME",
        Token::Opaque => "OPAQUE",
        Token::Cas => "CAS",
        Token::Greeting => "GREETING",
        Token::Login => "LOGIN",
        Token::Sql => "SQL",
        Token::Eof => "EOF",
        Token::ServerVersion => "SERVER_VERSION",
        Token::Db => "DB",
        Token::Startup => "STARTUP",
        Token::ReadyForQuery => "READY_FOR_QUERY",
        Token::CommandComplete => "COMMAND_COMPLETE",
        Token::ErrorResponse => "ERROR_RESPONSE",
        Token::AuthOk => "AUTH_OK",
        Token::Connect => "CONNECT",
        Token::Connack => "CONNACK",
        Token::Publish => "PUBLISH",
        Token::Puback => "PUBACK",
        Token::Subscribe => "SUBSCRIBE",
        Token::Suback => "SUBACK",
        Token::Pingreq => "PINGREQ",
        Token::Pingresp => "PINGRESP",
        Token::Disconnect => "DISCONNECT",
        Token::ClientId => "CLIENT_ID",
        Token::Topic => "TOPIC",
        Token::Qos => "QOS",
        Token::Retain => "RETAIN",
        Token::PktId => "PKT_ID",
        Token::ReturnCode => "RETURN_CODE",
        Token::Con => "CON",
        Token::Non => "NON",
        Token::Changed => "CHANGED",
        Token::Created => "CREATED",
        Token::NotFound => "NOT_FOUND",
        Token::UriPath => "URI_PATH",
        Token::ContentFormat => "CONTENT_FORMAT",
        Token::ProtocolHeader => "PROTOCOL_HEADER",
        Token::ConnectionStart => "CONNECTION_START",
        Token::ChannelOpen => "CHANNEL_OPEN",
        Token::BasicPublish => "BASIC_PUBLISH",
        Token::BasicDeliver => "BASIC_DELIVER",
        Token::Channel => "CHANNEL",
        Token::RoutingKey => "ROUTING_KEY",
        Token::Msearch => "MSEARCH",
        Token::Notify => "NOTIFY",
        Token::Man => "MAN",
        Token::Mx => "MX",
        Token::St => "ST",
        Token::Nt => "NT",
        Token::Nts => "NTS",
        Token::Usn => "USN",
        Token::Location => "LOCATION",
        Token::Registrar => "REGISTRAR",
        Token::ProtoId => "PROTO_ID",
        Token::UnitId => "UNITID",
        Token::Func => "FUNC",
        Token::ReadCoils => "READ_COILS",
        Token::ReadDiscreteInputs => "READ_DISCRETE_INPUTS",
        Token::ReadHoldingRegisters => "READ_HOLDING_REGISTERS",
        Token::ReadInputRegisters => "READ_INPUT_REGISTERS",
        Token::WriteSingleCoil => "WRITE_SINGLE_COIL",
        Token::WriteSingleRegister => "WRITE_SINGLE_REGISTER",
        Token::WriteMultipleRegisters => "WRITE_MULTIPLE_REGISTERS",
        Token::Addr => "ADDR",
        Token::Count => "COUNT",
        Token::IsResponse => "IS_RESPONSE",
        Token::WhoIs => "WHO_IS",
        Token::IAm => "I_AM",
        Token::ReadProperty => "READ_PROPERTY",
        Token::WriteProperty => "WRITE_PROPERTY",
        Token::InvokeId => "INVOKE_ID",
        Token::ObjectType => "OBJECT_TYPE",
        Token::ObjectInstance => "OBJECT_INSTANCE",
        Token::PropertyId => "PROPERTY_ID",
        Token::Confirm => "CONFIRM",
        Token::Select => "SELECT",
        Token::Operate => "OPERATE",
        Token::DirectOperate => "DIRECT_OPERATE",
        Token::UnsolicitedResponse => "UNSOLICITED_RESPONSE",
        Token::Variation => "VARIATION",
        Token::Crc => "CRC",
        Token::Src => "SRC",
        Token::Dst => "DST",
        Token::Rosctr => "ROSCTR",
        Token::PduRef => "PDU_REF",
        Token::SetupComm => "SETUP_COMM",
        Token::ReadVar => "READ_VAR",
        Token::WriteVar => "WRITE_VAR",
        Token::PlcControl => "PLC_CONTROL",
        Token::Area => "AREA",
        Token::DbNum => "DB_NUM",
        Token::Offset => "OFFSET",
        Token::ListServices => "LIST_SERVICES",
        Token::ListIdentity => "LIST_IDENTITY",
        Token::ListInterfaces => "LIST_INTERFACES",
        Token::RegisterSession => "REGISTER_SESSION",
        Token::UnregisterSession => "UNREGISTER_SESSION",
        Token::SendRrData => "SEND_RR_DATA",
        Token::SendUnitData => "SEND_UNIT_DATA",
        Token::SessionHandle => "SESSION_HANDLE",
        Token::ContextVal => "CONTEXT",
        Token::CipService => "CIP_SERVICE",
        Token::CipClass => "CIP_CLASS",
        Token::CipInstance => "CIP_INSTANCE",
        Token::CipAttr => "CIP_ATTR",
        Token::ChunkType => "CHUNK_TYPE",
        Token::SecureChannelId => "SECURE_CHANNEL_ID",
        Token::TokenId => "TOKEN_ID",
        Token::SeqNum => "SEQ_NUM",
        Token::EndpointUrl => "ENDPOINT_URL",
        Token::NodeId => "NODE_ID",
        _ => unreachable!(),
    };
    Ok(Spanned::new(name, (span.start, span.end - span.start)))
}

/// Helper to parse an identifier token and extract its string value.
pub(crate) fn parse_ident<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<&'a str> {
    parse_spanned_ident.map(|s| s.node).parse_next(input)
}

/// Decodes string escape sequences (`\r`, `\n`, `\t`, `\\`, `\"`, `\'`, `\xHH`, `\uXXXX`).
///
/// # Errors
/// Returns an error message if an invalid or incomplete escape sequence is encountered.
pub fn unescape_string(s: &str) -> Result<String, String> {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some('r') => out.push('\r'),
                Some('n') => out.push('\n'),
                Some('t') => out.push('\t'),
                Some('\\') => out.push('\\'),
                Some('"') => out.push('"'),
                Some('\'') => out.push('\''),
                Some('x') => {
                    let h1 = chars
                        .next()
                        .ok_or_else(|| "Incomplete \\x escape sequence".to_string())?;
                    let h2 = chars
                        .next()
                        .ok_or_else(|| "Incomplete \\x escape sequence".to_string())?;
                    let mut hex_buf = [0u8; 2];
                    hex_buf[0] = h1 as u8;
                    hex_buf[1] = h2 as u8;
                    let hex_str = core::str::from_utf8(&hex_buf)
                        .map_err(|_| "Invalid ASCII hex digit in \\x".to_string())?;
                    let byte = u8::from_str_radix(hex_str, 16)
                        .map_err(|_| alloc::format!("Invalid hex byte in \\x: {}", hex_str))?;
                    out.push(byte as char);
                }
                Some('u') => {
                    let mut hex_buf = [0u8; 4];
                    for b in &mut hex_buf {
                        let ch = chars
                            .next()
                            .ok_or_else(|| "Incomplete \\u escape sequence".to_string())?;
                        *b = ch as u8;
                    }
                    let hex_str = core::str::from_utf8(&hex_buf)
                        .map_err(|_| "Invalid ASCII hex digit in \\u".to_string())?;
                    let code = u32::from_str_radix(hex_str, 16)
                        .map_err(|_| alloc::format!("Invalid unicode hex in \\u: {}", hex_str))?;
                    let ch = char::from_u32(code)
                        .ok_or_else(|| alloc::format!("Invalid unicode codepoint: {:x}", code))?;
                    out.push(ch);
                }
                Some(other) => out.push(other),
                None => return Err("Dangling backslash at end of string".to_string()),
            }
        } else {
            out.push(c);
        }
    }
    Ok(out)
}

/// Helper to parse a raw string literal token and extract its inner value without quotes.
pub(crate) fn parse_raw_string_lit<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<&'a str> {
    let (t, _) = any
        .verify(|(t, _)| matches!(t, Token::StringLit(_)))
        .parse_next(input)?;
    match t {
        Token::StringLit(s) => Ok(s
            .strip_prefix('"')
            .and_then(|s| s.strip_suffix('"'))
            .unwrap_or(s)),
        _ => unreachable!(),
    }
}

/// Helper to parse a string literal and decode its escape sequences.
pub(crate) fn parse_string_lit<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<String> {
    let raw = parse_raw_string_lit(input)?;
    unescape_string(raw).map_err(|_| winnow::error::ErrMode::Cut(ContextError::new()))
}

/// Parses a raw hex payload string into bytes.
pub(crate) fn parse_hex_payload<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<Vec<u8>> {
    let raw = parse_raw_string_lit(input)?;
    let clean: String = raw
        .chars()
        .filter(|c| !c.is_whitespace() && *c != ':')
        .collect();
    if !clean.len().is_multiple_of(2) {
        return Err(winnow::error::ErrMode::Cut(ContextError::new()));
    }
    let mut bytes = Vec::with_capacity(clean.len() / 2);
    for i in (0..clean.len()).step_by(2) {
        let b = u8::from_str_radix(&clean[i..i + 2], 16)
            .map_err(|_| winnow::error::ErrMode::Cut(ContextError::new()))?;
        bytes.push(b);
    }
    Ok(bytes)
}

/// Helper to parse a string value that might be a quoted string, an identifier, or a keyword.
pub(crate) fn parse_str_val<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<&'a str> {
    alt((parse_raw_string_lit, parse_ident)).parse_next(input)
}

/// Helper to parse raw hex bytes from either a hex string or hex numeric literal.
pub(crate) fn parse_hex_bytes<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<Vec<u8>> {
    alt((
        parse_hex_payload,
        parse_u64.map(|v| {
            let b = v.to_be_bytes();
            let leading = b.iter().take_while(|&&x| x == 0).count();
            if leading == 8 {
                alloc::vec![0]
            } else {
                b[leading..].to_vec()
            }
        }),
    ))
    .parse_next(input)
}

/// Parses an IP address from a token stream.
pub(crate) fn parse_ip<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<IpAddr> {
    any.verify_map(|(t, _)| match t {
        Token::IpAddress(s) | Token::OidStr(s) => IpAddr::from_str(s).ok(),
        _ => None,
    })
    .parse_next(input)
}

/// Parses a MAC address from a token stream.
pub(crate) fn parse_mac<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<[u8; 6]> {
    any.verify_map(|(t, _)| {
        if let Token::MacAddress(s) = t {
            let parts: Vec<&str> = s.split(':').collect();
            if parts.len() == 6 {
                let mut mac = [0u8; 6];
                for i in 0..6 {
                    mac[i] = u8::from_str_radix(parts[i], 16).ok()?;
                }
                Some(mac)
            } else {
                None
            }
        } else {
            None
        }
    })
    .parse_next(input)
}

/// Parses a `u8` integer supporting decimal and hex.
pub(crate) fn parse_u8<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<u8> {
    any.verify_map(|(t, _)| {
        if let Token::Number(s) = t {
            if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
                u8::from_str_radix(hex, 16).ok()
            } else {
                u8::from_str(s).ok()
            }
        } else {
            None
        }
    })
    .parse_next(input)
}

/// Parses a `u16` integer supporting decimal and hex.
pub(crate) fn parse_u16<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<u16> {
    any.verify_map(|(t, _)| {
        if let Token::Number(s) = t {
            if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
                u16::from_str_radix(hex, 16).ok()
            } else {
                u16::from_str(s).ok()
            }
        } else {
            None
        }
    })
    .parse_next(input)
}

/// Parses a `u32` integer and returns its span, supporting decimal and hex.
pub(crate) fn parse_spanned_u32<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<(u32, (usize, usize))> {
    any.verify_map(|(t, span): (Token<'a>, core::ops::Range<usize>)| {
        if let Token::Number(s) = t {
            let val = if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
                u32::from_str_radix(hex, 16).ok()
            } else {
                u32::from_str(s).ok()
            }?;
            Some((val, (span.start, span.end - span.start)))
        } else {
            None
        }
    })
    .parse_next(input)
}

/// Parses a `u32` integer.
pub(crate) fn parse_u32<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<u32> {
    parse_spanned_u32.map(|(v, _)| v).parse_next(input)
}

/// Parses an `i32` signed integer.
pub(crate) fn parse_i32<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<i32> {
    any.verify_map(|(t, _)| {
        if let Token::Number(s) = t {
            if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
                i32::from_str_radix(hex, 16).ok()
            } else {
                i32::from_str(s).ok()
            }
        } else {
            None
        }
    })
    .parse_next(input)
}

/// Parses a `u64` unsigned integer.
pub(crate) fn parse_u64<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<u64> {
    any.verify_map(|(t, _)| {
        if let Token::Number(s) = t {
            if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
                u64::from_str_radix(hex, 16).ok()
            } else {
                u64::from_str(s).ok()
            }
        } else {
            None
        }
    })
    .parse_next(input)
}

/// Parses a `HOST` block definition with precision `cut_err`.
pub(crate) fn parse_host_def<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<HostDef<'a>> {
    let (_, host_kw_span) = tag(Token::Host).parse_next(input)?;
    let name_spanned = cut_err(parse_spanned_ident).parse_next(input)?;
    let _ = cut_err(tag(Token::LBrace)).parse_next(input)?;

    let mut ip = None;
    let mut mac = None;

    let _: Vec<()> = repeat(
        0..,
        alt((
            (tag(Token::Ip), cut_err(parse_ip)).map(|(_, i)| ip = Some(i)),
            (tag(Token::Mac), cut_err(parse_mac)).map(|(_, m)| mac = Some(m)),
        )),
    )
    .parse_next(input)?;

    let (_, rbrace_span) = cut_err(tag(Token::RBrace)).parse_next(input)?;

    if let Some(ip) = ip {
        Ok(HostDef {
            name: name_spanned.node,
            ip,
            mac,
            span: (host_kw_span.start, rbrace_span.end - host_kw_span.start),
        })
    } else {
        Err(winnow::error::ErrMode::Cut(ContextError::new()))
    }
}

/// Parses a packet direction arrow (`->` or `<-`).
pub(crate) fn parse_direction<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<Direction> {
    alt((
        tag(Token::RightArrow).value(Direction::LeftToRight),
        tag(Token::LeftArrow).value(Direction::RightToLeft),
    ))
    .parse_next(input)
}

/// Internal field representation parsed from a frame statement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ParsedField<'a> {
    /// Source port override.
    SrcPort(u16, (usize, usize)),
    /// Destination port override.
    DstPort(u16, (usize, usize)),
    /// TCP sequence number.
    Seq(u32, (usize, usize)),
    /// TCP acknowledgment number.
    AckNum(u32, (usize, usize)),
    /// TCP window size.
    Win(u16, (usize, usize)),
    /// Decoded string payload.
    Payload(String, (usize, usize)),
    /// Raw binary hex payload.
    HexPayload(Vec<u8>, (usize, usize)),
    /// Community string.
    Community(&'a str, (usize, usize)),
    /// User name.
    User(&'a str, (usize, usize)),
    /// System uptime.
    SysUpTime(u32, (usize, usize)),
    /// PDU Type.
    PduType(SnmpPduType, (usize, usize)),
    /// Delay duration.
    Wait(u64, (usize, usize)),
    /// Object Identifier.
    Oid(&'a str, (usize, usize)),
    /// TCP flag.
    Flag(TcpFlag, (usize, usize)),
    /// Enterprise OID.
    Enterprise(&'a str, (usize, usize)),
    /// Agent IP address.
    AgentIp(IpAddr, (usize, usize)),
    /// Generic trap code.
    GenTrap(u32, (usize, usize)),
    /// Specific trap code.
    SpecTrap(u32, (usize, usize)),
    /// Engine ID.
    EngineId(&'a str, (usize, usize)),
    /// Engine boots.
    EngineBoots(u32, (usize, usize)),
    /// Engine time.
    EngineTime(u32, (usize, usize)),
    /// Context name.
    ContextName(&'a str, (usize, usize)),
    /// Authentication parameters.
    Auth(SnmpAuthType, &'a str, (usize, usize)),
    /// Privacy parameters.
    Priv(SnmpPrivType, &'a str, (usize, usize)),
    /// Variable binding.
    VarBind(VarBindAst<'a>, (usize, usize)),
    /// Non-Repeaters for GETBULK.
    NonRepeaters(u32, (usize, usize)),
    /// Max-Repetitions for GETBULK.
    MaxRepetitions(u32, (usize, usize)),
    /// Request ID.
    ReqId(u32, (usize, usize)),
    /// VLAN ID.
    Vlan(u32, (usize, usize)),
    /// DSCP value.
    Dscp(u32, (usize, usize)),
    /// ECN value.
    Ecn(u32, (usize, usize)),
    /// TTL value.
    Ttl(u32, (usize, usize)),
    /// Flow label value.
    FlowLabel(u32, (usize, usize)),
    /// Protocol token.
    Protocol(Protocol, (usize, usize)),
    /// Priority Code Point.
    Pcp(u8, (usize, usize)),
    /// Drop Eligible Indicator.
    Dei(u8, (usize, usize)),
    /// QinQ outer VLAN.
    Qinq(u16, (usize, usize)),
    /// QinQ inner VLAN.
    InnerVlan(u16, (usize, usize)),
    /// MPLS label.
    Mpls(u32, (usize, usize)),
    /// MPLS EXP / TC.
    Exp(u8, (usize, usize)),
    /// MPLS Bottom-of-Stack.
    Bos(u8, (usize, usize)),
    /// MPLS TTL.
    MplsTtl(u8, (usize, usize)),
    /// Source MAC override.
    SrcMac([u8; 6], (usize, usize)),
    /// Destination MAC override.
    DstMac([u8; 6], (usize, usize)),
    /// Custom EtherType override.
    EtherType(u16, (usize, usize)),
    /// IPv4 Identification.
    IpId(u16, (usize, usize)),
    /// IPv4 Don't Fragment flag.
    Df((usize, usize)),
    /// IPv4 More Fragments flag.
    Mf((usize, usize)),
    /// IPv4 Fragment offset.
    FragOffset(u16, (usize, usize)),
    /// Transport protocol.
    Transport(TransportProto, (usize, usize)),
    /// TCP Urgent pointer.
    Urgent(u16, (usize, usize)),
    /// TCP MSS option.
    Mss(u16, (usize, usize)),
    /// TCP Window Scale option.
    Wscale(u8, (usize, usize)),
    /// TCP SACK Permitted option.
    SackPerm((usize, usize)),
    /// TCP Timestamp Value option.
    Tsval(u32, (usize, usize)),
    /// TCP Timestamp Echo Reply option.
    Tsecr(u32, (usize, usize)),
    /// SCTP Verification Tag.
    Vtag(u32, (usize, usize)),
    /// SCTP Stream Identifier.
    Stream(u16, (usize, usize)),
    /// SCTP Stream Sequence Number.
    Ssn(u16, (usize, usize)),
    /// SCTP Payload Protocol Identifier.
    Ppid(u32, (usize, usize)),
    /// SCTP Chunk type.
    Chunk(String, (usize, usize)),
    /// ARP Opcode.
    ArpOpcode(ArpOpcode, (usize, usize)),
    /// Gratuitous ARP flag.
    Gratuitous((usize, usize)),
    /// Sender Hardware Address (MAC).
    Sha([u8; 6], (usize, usize)),
    /// Sender Protocol Address (IP).
    Spa(IpAddr, (usize, usize)),
    /// Target Hardware Address (MAC).
    Tha([u8; 6], (usize, usize)),
    /// Target Protocol Address (IP).
    Tpa(IpAddr, (usize, usize)),
    /// LLDP Chassis ID.
    ChassisId(&'a str, (usize, usize)),
    /// LLDP / STP Port ID.
    PortIdVal(Option<&'a str>, Option<u16>, (usize, usize)),
    /// LLDP System Name.
    SysName(&'a str, (usize, usize)),
    /// LLDP System Description.
    SysDesc(&'a str, (usize, usize)),
    /// STP Root Bridge ID.
    RootId(&'a str, (usize, usize)),
    /// STP Bridge ID.
    BridgeId(&'a str, (usize, usize)),
    /// STP Root Cost.
    Cost(u32, (usize, usize)),
    /// STP Max Age.
    MaxAge(u16, (usize, usize)),
    /// STP Hello Time.
    HelloTime(u16, (usize, usize)),
    /// STP Forward Delay.
    ForwardDelay(u16, (usize, usize)),
    /// STP RSTP flag.
    Rstp((usize, usize)),
    /// Flags byte.
    FlagsByte(u8, (usize, usize)),
    /// LACP Actor System.
    ActorSys([u8; 6], (usize, usize)),
    /// LACP Actor Key.
    ActorKey(u16, (usize, usize)),
    /// LACP Actor Port.
    ActorPort(u16, (usize, usize)),
    /// LACP Partner System.
    PartnerSys([u8; 6], (usize, usize)),
    /// LACP Partner Key.
    PartnerKey(u16, (usize, usize)),
    /// LACP Partner Port.
    PartnerPort(u16, (usize, usize)),
    /// LACP Actor State.
    ActorState(u8, (usize, usize)),
    /// LACP Partner State.
    PartnerState(u8, (usize, usize)),
    /// Protocol Version byte.
    VersionByte(u8, (usize, usize)),
    /// EAPOL Packet Type.
    EapolType(EapolType, (usize, usize)),
    /// EAP Code.
    EapCode(u8, (usize, usize)),
    /// EAP Identifier.
    EapId(u8, (usize, usize)),
    /// EAP Method.
    EapMethod(u8, (usize, usize)),
    /// Identity string.
    Identity(&'a str, (usize, usize)),
    /// ICMP message type choice.
    IcmpTypeChoice(IcmpTypeChoice, (usize, usize)),
    /// ICMP ID.
    IcmpId(u16, (usize, usize)),
    /// Gateway IP address.
    Gateway(IpAddr, (usize, usize)),
    /// NDP Message Type.
    NdpType(NdpType, (usize, usize)),
    /// Target IP or MAC address.
    TargetVal(Option<IpAddr>, Option<[u8; 6]>, (usize, usize)),
    /// Source Link-Layer Address option.
    Slla([u8; 6], (usize, usize)),
    /// Target Link-Layer Address option.
    Tlla([u8; 6], (usize, usize)),
    /// Router Lifetime.
    RouterLifetime(u16, (usize, usize)),
    /// IGMP message type.
    IgmpType(IgmpType, (usize, usize)),
    /// Multicast Group IP address or HSRP group number.
    GroupVal(Option<IpAddr>, Option<u8>, (usize, usize)),
    /// IGMP Max Response time.
    MaxResp(u8, (usize, usize)),
    /// MLD message type.
    MldType(MldType, (usize, usize)),
    /// Multicast IPv6 address.
    MulticastAddr(IpAddr, (usize, usize)),
    /// MLD Max Response Delay.
    MaxRespDelay(u16, (usize, usize)),
    /// GRE Key.
    GreKey(u32, (usize, usize)),
    /// GRE Sequence Number.
    GreSeq(u32, (usize, usize)),
    /// GRE Protocol type.
    GreProto(u16, (usize, usize)),
    /// Checksum flag.
    ChecksumFlag((usize, usize)),
    /// VXLAN / GENEVE VNI.
    Vni(u32, (usize, usize)),
    /// GENEVE Option Class.
    OptClass(u16, (usize, usize)),
    /// GENEVE Option Type.
    OptType(u8, (usize, usize)),
    /// GENEVE Protocol Type.
    ProtocolType(u16, (usize, usize)),
    /// IPsec SPI.
    Spi(u32, (usize, usize)),
    /// IPsec Initialization Vector.
    Iv(Vec<u8>, (usize, usize)),
    /// IPsec Integrity Check Value.
    Icv(Vec<u8>, (usize, usize)),
    /// Next Header protocol number.
    NextHeader(u8, (usize, usize)),
    /// IKEv2 Initiator SPI.
    InitiatorSpi(u64, (usize, usize)),
    /// IKEv2 Responder SPI.
    ResponderSpi(u64, (usize, usize)),
    /// IKEv2 Exchange type.
    IkeExchange(IkeExchange, (usize, usize)),
    /// IKEv2 Message ID.
    MsgId(u32, (usize, usize)),
    /// IKEv2 Next Payload.
    NextPayload(u8, (usize, usize)),
    /// WireGuard packet type.
    WireguardType(WireguardType, (usize, usize)),
    /// WireGuard Sender index.
    Sender(u32, (usize, usize)),
    /// WireGuard Receiver index.
    Receiver(u32, (usize, usize)),
    /// WireGuard Counter.
    Counter(u64, (usize, usize)),
    /// OSPF packet type.
    OspfType(OspfType, (usize, usize)),
    /// HELLO keyword (shared between OSPF and PIM).
    HelloWord((usize, usize)),
    /// OSPF Router ID.
    RouterId(IpAddr, (usize, usize)),
    /// OSPF Area ID.
    AreaId(u32, (usize, usize)),
    /// OSPF Hello Interval.
    HelloInterval(u16, (usize, usize)),
    /// OSPF Dead Interval.
    DeadInterval(u32, (usize, usize)),
    /// Priority value (u16).
    PriorityVal(u16, (usize, usize)),
    /// BGP message type.
    BgpType(BgpType, (usize, usize)),
    /// BGP ASN.
    Asn(u32, (usize, usize)),
    /// BGP / PIM Hold Time.
    HoldTime(u16, (usize, usize)),
    /// BGP ID.
    BgpId(IpAddr, (usize, usize)),
    /// Prefix IP or String value.
    PrefixVal(Option<IpAddr>, Option<&'a str>, (usize, usize)),
    /// Next Hop IP address.
    NextHop(IpAddr, (usize, usize)),
    /// RIP metric.
    Metric(u32, (usize, usize)),
    /// Protocol tag (RIP u16 or IMAP/NFS string).
    TagVal(Option<u16>, Option<&'a str>, (usize, usize)),
    /// VRRP VRID.
    Vrid(u8, (usize, usize)),
    /// VRRP Advertisement Interval.
    AdvInt(u16, (usize, usize)),
    /// Virtual IP address.
    Vip(IpAddr, (usize, usize)),
    /// HSRP State.
    HsrpState(u8, (usize, usize)),
    /// HSRP Hello time.
    HelloTimeHsrp(u8, (usize, usize)),
    /// PIM Join/Prune flag.
    PimJoinPrune((usize, usize)),
    /// PIM Register flag.
    PimRegister((usize, usize)),
    /// Source IP.
    SourceIp(IpAddr, (usize, usize)),
    /// Rendezvous Point IP.
    Rp(IpAddr, (usize, usize)),
    /// PIM DR Priority.
    DrPriority(u32, (usize, usize)),
    /// BFD Diag code.
    Diag(u8, (usize, usize)),
    /// BFD My Discriminator.
    MyDisc(u32, (usize, usize)),
    /// BFD Your Discriminator.
    YourDisc(u32, (usize, usize)),
    /// BFD Min TX interval.
    MinTx(u32, (usize, usize)),
    /// BFD Min RX interval.
    MinRx(u32, (usize, usize)),
    /// BFD Multiplier.
    Mult(u8, (usize, usize)),
    /// OpenFlow message type.
    OpenflowType(OpenflowType, (usize, usize)),
    /// OpenFlow Transaction ID.
    Xid(u32, (usize, usize)),
    /// OpenFlow Datapath ID.
    Dpid(u64, (usize, usize)),
    /// OpenFlow Table ID.
    TableId(u8, (usize, usize)),
    /// Generic L7 string-valued attribute.
    L7StringField(&'static str, &'a str, (usize, usize)),
    /// Generic L7 u32-valued attribute.
    L7U32Field(&'static str, u32, (usize, usize)),
    /// Generic L7 u64-valued attribute.
    L7U64Field(&'static str, u64, (usize, usize)),
    /// Generic L7 IP-valued attribute.
    L7IpField(&'static str, IpAddr, (usize, usize)),
    /// Generic L7 MAC-valued attribute.
    L7MacField(&'static str, [u8; 6], (usize, usize)),
    /// Generic L7 standalone flag attribute.
    L7Flag(&'static str, (usize, usize)),
    /// L7 HTTP header pair attribute.
    L7Header(&'a str, &'a str, (usize, usize)),
}


/// Parses a single frame statement within a flow.
pub(crate) fn parse_frame_statement<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<FrameStatement<'a>> {
    let caller = parse_spanned_ident(input)?;
    let dir = parse_direction(input)?;

    // Commit to frame statement parsing once arrow is encountered
    let callee = cut_err(parse_spanned_ident).parse_next(input)?;

    let mut protocol: Option<Protocol> = None;
    let mut flags = Vec::new();
    let mut seq = None;
    let mut ack_num = None;
    let mut win = None;
    let mut payload = None;
    let mut hex_payload = None;
    let mut wait = None;
    let mut src_port = None;
    let mut dst_port = None;
    let mut community = None;
    let mut user = None;
    let mut oid = None;
    let mut sys_up_time = None;
    let mut pdu_type = None;
    let mut enterprise = None;
    let mut agent_ip = None;
    let mut gen_trap = None;
    let mut spec_trap = None;
    let mut engine_id = None;
    let mut engine_boots = None;
    let mut engine_time = None;
    let mut context_name = None;
    let mut auth = None;
    let mut priv_param = None;
    let mut varbinds = Vec::new();
    let mut non_repeaters = None;
    let mut max_repetitions = None;
    let mut req_id = None;
    let mut vlan_val = None;
    let mut dscp_val = None;
    let mut ecn_val = None;
    let mut ttl_val = None;
    let mut flowlabel_val = None;
    let mut pcp_val = None;
    let mut dei_val = None;
    let mut qinq_val = None;
    let mut inner_vlan_val = None;
    let mut mpls_val = None;
    let mut exp_val = None;
    let mut bos_val = None;
    let mut mpls_ttl_val = None;
    let mut src_mac_val = None;
    let mut dst_mac_val = None;
    let mut ethertype_val = None;
    let mut ipid_val = None;
    let mut df_val = false;
    let mut mf_val = false;
    let mut frag_offset_val = None;
    let mut transport_val = None;
    let mut urgent_val = None;
    let mut mss_val = None;
    let mut wscale_val = None;
    let mut sack_perm_val = false;
    let mut tsval_val = None;
    let mut tsecr_val = None;
    let mut vtag_val = None;
    let mut stream_val = None;
    let mut ssn_val = None;
    let mut ppid_val = None;
    let mut chunk_val = None;

    let mut arp_opcode = None;
    let mut is_gratuitous = false;
    let mut sha = None;
    let mut spa = None;
    let mut tha = None;
    let mut tpa = None;

    let mut chassis_id = None;
    let mut port_id_str = None;
    let mut sysname = None;
    let mut sysdesc = None;

    let mut root_id = None;
    let mut bridge_id = None;
    let mut port_id_u16 = None;
    let mut stp_cost = None;
    let mut max_age = None;
    let mut hello_time = None;
    let mut forward_delay = None;
    let mut is_rstp = false;
    let mut stp_flags = None;

    let mut actor_sys = None;
    let mut actor_key = None;
    let mut actor_port = None;
    let mut partner_sys = None;
    let mut partner_key = None;
    let mut partner_port = None;
    let mut actor_state = None;
    let mut partner_state = None;

    let mut version_byte = None;
    let mut eapol_type = None;
    let mut eap_code = None;
    let mut eap_id = None;
    let mut eap_method = None;
    let mut identity_str = None;

    let mut icmp_type_choice = None;
    let icmp_type_val = None;
    let mut icmp_code_val = None;
    let mut icmp_id_val = None;
    let mut gateway_ip = None;

    let mut ndp_type = None;
    let mut target_ip = None;
    let mut slla_mac = None;
    let mut tlla_mac = None;
    let mut router_lifetime = None;

    let mut igmp_type = None;
    let mut group_ip = None;
    let mut max_resp = None;

    let mut mld_type = None;
    let mut multicast_addr = None;
    let mut max_resp_delay = None;

    let mut gre_key = None;
    let mut gre_seq = None;
    let mut gre_proto = None;
    let mut gre_checksum = false;

    let mut vni_val = None;
    let mut opt_class = None;
    let mut opt_type = None;
    let mut protocol_type = None;

    let mut spi_val = None;
    let mut iv_val = None;
    let mut icv_val = None;
    let mut next_header_val = None;

    let mut initiator_spi = None;
    let mut responder_spi = None;
    let mut ike_exchange = None;
    let mut ike_msgid = None;
    let mut ike_flags = None;
    let mut next_payload = None;

    let mut wireguard_type = None;
    let mut wg_sender = None;
    let mut wg_receiver = None;
    let mut wg_counter = None;

    let mut ospf_type = None;
    let mut router_id_ip = None;
    let mut area_id_val = None;
    let mut hello_interval = None;
    let mut dead_interval = None;
    let mut priority_val = None;

    let mut bgp_type = None;
    let mut asn_val = None;
    let mut holdtime_val = None;
    let mut bgpid_ip = None;
    let mut prefix_str = None;
    let mut nexthop_ip = None;

    let mut rip_cmd = None;
    let mut rip_prefix = None;
    let mut rip_metric = None;
    let mut rip_tag = None;

    let mut vrid_val = None;
    let mut adv_int_val = None;
    let mut vip_ip = None;

    let mut hsrp_state = None;
    let mut hsrp_group = None;
    let hsrp_auth = None;
    let mut hsrp_hellotime = None;

    let mut pim_is_hello = false;
    let mut pim_is_join_prune = false;
    let mut pim_is_register = false;
    let mut pim_source = None;
    let mut pim_rp = None;
    let mut pim_dr_priority = None;

    let mut bfd_state = None;
    let mut bfd_diag = None;
    let mut bfd_my_disc = None;
    let mut bfd_your_disc = None;
    let mut bfd_min_tx = None;
    let mut bfd_min_rx = None;
    let mut bfd_mult = None;

    let mut openflow_type = None;
    let mut of_xid = None;
    let mut of_dpid = None;
    let mut of_table_id = None;
    let mut of_priority = None;

    let mut dns_spec = DnsSpec::default();
    let mut dhcp_spec = DhcpSpec::default();
    let mut ntp_spec = NtpSpec::default();
    let mut ptp_spec = PtpSpec::default();
    let mut radius_spec = RadiusSpec::default();
    let mut tacacs_spec = TacacsSpec::default();
    let mut syslog_spec = SyslogSpec::default();
    let mut netflow_spec = NetflowSpec::default();
    let mut ipfix_spec = IpfixSpec::default();
    let mut sflow_spec = SflowSpec::default();

    let mut tftp_spec = TftpSpec::default();
    let mut ftp_spec = FtpSpec::default();
    let mut ssh_spec = SshSpec::default();
    let mut telnet_spec = TelnetSpec::default();
    let mut http_spec = HttpSpec::default();
    let mut http2_spec = Http2Spec::default();
    let mut grpc_spec = GrpcSpec::default();
    let mut websocket_spec = WebsocketSpec::default();
    let mut tls_spec = TlsSpec::default();
    let mut quic_spec = QuicSpec::default();
    let mut stun_spec = StunSpec::default();
    let mut sip_spec = SipSpec::default();
    let mut rtp_spec = RtpSpec::default();
    let mut rtsp_spec = RtspSpec::default();
    let mut smtp_spec = SmtpSpec::default();
    let mut imap_spec = ImapSpec::default();
    let mut pop3_spec = Pop3Spec::default();
    let mut kerberos_spec = KerberosSpec::default();
    let mut ldap_spec = LdapSpec::default();
    let mut smb_spec = SmbSpec::default();
    let mut nfs_spec = NfsSpec::default();
    let mut redis_spec = RedisSpec::default();
    let mut memcached_spec = MemcachedSpec::default();
    let mut mysql_spec = MysqlSpec::default();
    let mut postgres_spec = PostgresSpec::default();
    let mut mqtt_spec = MqttSpec::default();
    let mut coap_spec = CoapSpec::default();
    let mut amqp_spec = AmqpSpec::default();
    let mut ssdp_spec = SsdpSpec::default();
    let mut whois_spec = WhoisSpec::default();

    let mut modbus_spec = ModbusSpec::default();
    let mut bacnet_spec = BacnetSpec::default();
    let mut dnp3_spec = Dnp3Spec::default();
    let mut s7comm_spec = S7commSpec::default();
    let mut ethernetip_spec = EthernetipSpec::default();
    let mut opcua_spec = OpcuaSpec::default();


    let parse_wait = |input: &mut Stream<'i, 'a>| -> PResult<ParsedField<'a>> {
        let (_, wait_kw_span) = tag(Token::Wait).parse_next(input)?;
        let val = cut_err(parse_u32).parse_next(input)?;
        let suffix = cut_err(alt((
            tag(Token::Ns).value(1_u64),
            tag(Token::Us).value(1_000_u64),
            tag(Token::Ms).value(1_000_000_u64),
            tag(Token::Sec).value(1_000_000_000_u64),
            tag(Token::Min).value(60_000_000_000_u64),
        )))
        .parse_next(input)?;

        let end_offset = if let Some(last_tok) = input.first() {
            last_tok.1.start
        } else {
            wait_kw_span.end
        };
        Ok(ParsedField::Wait(
            val as u64 * suffix,
            (wait_kw_span.start, end_offset - wait_kw_span.start),
        ))
    };

    let parse_payload = |input: &mut Stream<'i, 'a>| -> PResult<ParsedField<'a>> {
        let ((_, s), v) = (tag(Token::Payload), cut_err(parse_string_lit)).parse_next(input)?;
        Ok(ParsedField::Payload(v, (s.start, s.end - s.start)))
    };

    let parse_hex_payload_field = |input: &mut Stream<'i, 'a>| -> PResult<ParsedField<'a>> {
        let ((_, s), v) = (tag(Token::HexPayload), cut_err(parse_hex_payload)).parse_next(input)?;
        Ok(ParsedField::HexPayload(v, (s.start, s.end - s.start)))
    };

    let parsed_fields: Vec<ParsedField<'a>> = repeat(
        0..,
        alt((
            parse_wait,
            parse_payload,
            parse_hex_payload_field,
            l2::parse_l2_field,
            l3::parse_l3_field,
            l4::parse_l4_field,
            snmp::parse_snmp_field,
            l7::parse_l7_field,
        )),
    )
    .parse_next(input)?;

    let mut duplicate_modifiers = Vec::new();
    let mut seen_modifier_keys = HashSet::new();
    let mut gentrap_span = None;

    let mut record_mod = |key: &'static str, span: (usize, usize)| {
        if !seen_modifier_keys.insert(key) {
            duplicate_modifiers.push((key.to_string(), span));
        }
    };

    let mut stmt_end_offset = callee.span.0 + callee.span.1;

    for f in &parsed_fields {
        match f {
            ParsedField::SrcPort(v, span) => {
                record_mod("SRCPORT", *span);
                src_port = Some(*v);
                stmt_end_offset = stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::DstPort(v, span) => {
                record_mod("DSTPORT", *span);
                dst_port = Some(*v);
                stmt_end_offset = stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::Seq(v, span) => {
                record_mod("SEQ", *span);
                seq = Some(*v);
                stmt_end_offset = stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::AckNum(v, span) => {
                record_mod("ACKNUM", *span);
                ack_num = Some(*v);
                stmt_end_offset = stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::Win(v, span) => {
                record_mod("WIN", *span);
                win = Some(*v);
                stmt_end_offset = stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::Payload(v, span) => {
                record_mod("PAYLOAD", *span);
                payload = Some(v.clone());
                stmt_end_offset = stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::HexPayload(v, span) => {
                record_mod("HEXPAYLOAD", *span);
                hex_payload = Some(v.clone());
                stmt_end_offset = stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::Community(v, span) => {
                record_mod("COMMUNITY", *span);
                community = Some(*v);
                stmt_end_offset = stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::User(v, span) => {
                record_mod("USER", *span);
                user = Some(*v);
                stmt_end_offset = stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::SysUpTime(v, span) => {
                record_mod("SYSUPTIME", *span);
                sys_up_time = Some(*v);
                stmt_end_offset = stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::PduType(v, span) => {
                record_mod("PDUTYPE", *span);
                pdu_type = Some(v.clone());
                stmt_end_offset = stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::Wait(v, span) => {
                record_mod("WAIT", *span);
                wait = Some(*v);
                stmt_end_offset = stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::Oid(v, span) => {
                record_mod("OID", *span);
                oid = Some(*v);
                stmt_end_offset = stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::Flag(flag, span) => {
                flags.push(flag.clone());
                stmt_end_offset = stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::Enterprise(v, span) => {
                record_mod("ENTERPRISE", *span);
                enterprise = Some(*v);
                stmt_end_offset = stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::AgentIp(v, span) => {
                record_mod("AGENTIP", *span);
                agent_ip = Some(*v);
                stmt_end_offset = stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::GenTrap(v, span) => {
                record_mod("GENTRAP", *span);
                gen_trap = Some(*v);
                gentrap_span = Some(*span);
                stmt_end_offset = stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::SpecTrap(v, span) => {
                record_mod("SPECTRAP", *span);
                spec_trap = Some(*v);
                stmt_end_offset = stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::EngineId(v, span) => {
                record_mod("ENGINEID", *span);
                engine_id = Some(*v);
                stmt_end_offset = stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::EngineBoots(v, span) => {
                record_mod("ENGINEBOOTS", *span);
                engine_boots = Some(*v);
                stmt_end_offset = stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::EngineTime(v, span) => {
                record_mod("ENGINETIME", *span);
                engine_time = Some(*v);
                stmt_end_offset = stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::ContextName(v, span) => {
                record_mod("CONTEXTNAME", *span);
                context_name = Some(*v);
                stmt_end_offset = stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::Auth(t, p, span) => {
                record_mod("AUTH", *span);
                auth = Some((t.clone(), *p));
                stmt_end_offset = stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::Priv(t, p, span) => {
                record_mod("PRIV", *span);
                priv_param = Some((t.clone(), *p));
                stmt_end_offset = stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::VarBind(v, span) => {
                varbinds.push(v.clone());
                stmt_end_offset = stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::NonRepeaters(v, span) => {
                record_mod("NONREPEATERS", *span);
                non_repeaters = Some(*v);
                stmt_end_offset = stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::MaxRepetitions(v, span) => {
                record_mod("MAXREPETITIONS", *span);
                max_repetitions = Some(*v);
                stmt_end_offset = stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::ReqId(v, span) => {
                record_mod("REQID", *span);
                req_id = Some(*v);
                stmt_end_offset = stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::Vlan(v, span) => {
                record_mod("VLAN", *span);
                vlan_val = Some((*v, *span));
                stmt_end_offset = stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::Dscp(v, span) => {
                record_mod("DSCP", *span);
                dscp_val = Some((*v, *span));
                stmt_end_offset = stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::Ecn(v, span) => {
                record_mod("ECN", *span);
                ecn_val = Some((*v, *span));
                stmt_end_offset = stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::Ttl(v, span) => {
                record_mod("TTL", *span);
                ttl_val = Some((*v, *span));
                stmt_end_offset = stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::FlowLabel(v, span) => {
                record_mod("FLOWLABEL", *span);
                flowlabel_val = Some((*v, *span));
                stmt_end_offset = stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::Protocol(p, span) => {
                record_mod("PROTOCOL", *span);
                protocol = Some(p.clone());
                stmt_end_offset = stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::Pcp(v, span) => {
                record_mod("PCP", *span);
                pcp_val = Some((*v, *span));
                stmt_end_offset = stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::Dei(v, span) => {
                record_mod("DEI", *span);
                dei_val = Some((*v, *span));
                stmt_end_offset = stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::Qinq(v, span) => {
                record_mod("QINQ", *span);
                qinq_val = Some((*v, *span));
                stmt_end_offset = stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::InnerVlan(v, span) => {
                record_mod("INNER_VLAN", *span);
                inner_vlan_val = Some((*v, *span));
                stmt_end_offset = stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::Mpls(v, span) => {
                record_mod("MPLS", *span);
                mpls_val = Some((*v, *span));
                stmt_end_offset = stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::Exp(v, span) => {
                record_mod("EXP", *span);
                exp_val = Some((*v, *span));
                stmt_end_offset = stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::Bos(v, span) => {
                record_mod("BOS", *span);
                bos_val = Some((*v, *span));
                stmt_end_offset = stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::MplsTtl(v, span) => {
                record_mod("MPLS_TTL", *span);
                mpls_ttl_val = Some((*v, *span));
                stmt_end_offset = stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::SrcMac(v, span) => {
                record_mod("SRCMAC", *span);
                src_mac_val = Some((*v, *span));
                stmt_end_offset = stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::DstMac(v, span) => {
                record_mod("DSTMAC", *span);
                dst_mac_val = Some((*v, *span));
                stmt_end_offset = stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::EtherType(v, span) => {
                record_mod("ETHERTYPE", *span);
                ethertype_val = Some((*v, *span));
                stmt_end_offset = stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::IpId(v, span) => {
                record_mod("IPID", *span);
                ipid_val = Some((*v, *span));
                stmt_end_offset = stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::Df(span) => {
                record_mod("DF", *span);
                df_val = true;
                stmt_end_offset = stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::Mf(span) => {
                record_mod("MF", *span);
                mf_val = true;
                stmt_end_offset = stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::FragOffset(v, span) => {
                record_mod("FRAGOFFSET", *span);
                frag_offset_val = Some((*v, *span));
                stmt_end_offset = stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::Transport(v, span) => {
                record_mod("TRANSPORT", *span);
                transport_val = Some(*v);
                stmt_end_offset = stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::Urgent(v, span) => {
                record_mod("URGENT", *span);
                urgent_val = Some((*v, *span));
                stmt_end_offset = stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::Mss(v, span) => {
                record_mod("MSS", *span);
                mss_val = Some((*v, *span));
                stmt_end_offset = stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::Wscale(v, span) => {
                record_mod("WSCALE", *span);
                wscale_val = Some((*v, *span));
                stmt_end_offset = stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::SackPerm(span) => {
                record_mod("SACK_PERM", *span);
                sack_perm_val = true;
                stmt_end_offset = stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::Tsval(v, span) => {
                record_mod("TSVAL", *span);
                tsval_val = Some((*v, *span));
                stmt_end_offset = stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::Tsecr(v, span) => {
                record_mod("TSECR", *span);
                tsecr_val = Some((*v, *span));
                stmt_end_offset = stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::Vtag(v, span) => {
                record_mod("VTAG", *span);
                vtag_val = Some((*v, *span));
                stmt_end_offset = stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::Stream(v, span) => {
                record_mod("STREAM", *span);
                stream_val = Some((*v, *span));
                stmt_end_offset = stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::Ssn(v, span) => {
                record_mod("SSN", *span);
                ssn_val = Some((*v, *span));
                stmt_end_offset = stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::Ppid(v, span) => {
                record_mod("PPID", *span);
                ppid_val = Some((*v, *span));
                stmt_end_offset = stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::Chunk(v, span) => {
                record_mod("CHUNK", *span);
                chunk_val = Some((v.clone(), *span));
                stmt_end_offset = stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::ArpOpcode(v, span) => {
                record_mod("OPCODE", *span);
                arp_opcode = Some(*v);
                stmt_end_offset = stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::Gratuitous(span) => {
                record_mod("GARP", *span);
                is_gratuitous = true;
                stmt_end_offset = stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::Sha(v, span) => {
                record_mod("SHA", *span);
                sha = Some(*v);
                stmt_end_offset = stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::Spa(v, span) => {
                record_mod("SPA", *span);
                spa = Some(*v);
                stmt_end_offset = stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::Tha(v, span) => {
                record_mod("THA", *span);
                tha = Some(*v);
                stmt_end_offset = stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::Tpa(v, span) => {
                record_mod("TPA", *span);
                tpa = Some(*v);
                stmt_end_offset = stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::ChassisId(v, span) => {
                record_mod("CHASSIS_ID", *span);
                chassis_id = Some(*v);
                stmt_end_offset = stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::PortIdVal(ps, pu, span) => {
                record_mod("PORT_ID", *span);
                if let Some(s) = ps {
                    port_id_str = Some(*s);
                }
                if let Some(u) = pu {
                    port_id_u16 = Some(*u);
                }
                stmt_end_offset = stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::SysName(v, span) => {
                record_mod("SYSNAME", *span);
                sysname = Some(*v);
                stmt_end_offset = stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::SysDesc(v, span) => {
                record_mod("SYSDESC", *span);
                sysdesc = Some(*v);
                stmt_end_offset = stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::RootId(v, span) => {
                record_mod("ROOT_ID", *span);
                root_id = Some(*v);
                stmt_end_offset = stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::BridgeId(v, span) => {
                record_mod("BRIDGE_ID", *span);
                bridge_id = Some(*v);
                stmt_end_offset = stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::Cost(v, span) => {
                record_mod("COST", *span);
                stp_cost = Some(*v);
                stmt_end_offset = stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::MaxAge(v, span) => {
                record_mod("MAX_AGE", *span);
                max_age = Some(*v);
                stmt_end_offset = stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::HelloTime(v, span) => {
                record_mod("HELLO_TIME", *span);
                hello_time = Some(*v);
                stmt_end_offset = stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::ForwardDelay(v, span) => {
                record_mod("FORWARD_DELAY", *span);
                forward_delay = Some(*v);
                stmt_end_offset = stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::Rstp(span) => {
                record_mod("RSTP", *span);
                is_rstp = true;
                stmt_end_offset = stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::FlagsByte(v, span) => {
                record_mod("FLAGS", *span);
                stp_flags = Some(*v);
                ike_flags = Some(*v);
                stmt_end_offset = stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::ActorSys(v, span) => {
                record_mod("ACTOR_SYS", *span);
                actor_sys = Some(*v);
                stmt_end_offset = stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::ActorKey(v, span) => {
                record_mod("ACTOR_KEY", *span);
                actor_key = Some(*v);
                stmt_end_offset = stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::ActorPort(v, span) => {
                record_mod("ACTOR_PORT", *span);
                actor_port = Some(*v);
                stmt_end_offset = stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::PartnerSys(v, span) => {
                record_mod("PARTNER_SYS", *span);
                partner_sys = Some(*v);
                stmt_end_offset = stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::PartnerKey(v, span) => {
                record_mod("PARTNER_KEY", *span);
                partner_key = Some(*v);
                stmt_end_offset = stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::PartnerPort(v, span) => {
                record_mod("PARTNER_PORT", *span);
                partner_port = Some(*v);
                stmt_end_offset = stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::ActorState(v, span) => {
                record_mod("ACTOR_STATE", *span);
                actor_state = Some(*v);
                stmt_end_offset = stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::PartnerState(v, span) => {
                record_mod("PARTNER_STATE", *span);
                partner_state = Some(*v);
                stmt_end_offset = stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::VersionByte(v, span) => {
                record_mod("VERSION", *span);
                version_byte = Some(*v);
                stmt_end_offset = stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::EapolType(v, span) => {
                record_mod("EAPOL_TYPE", *span);
                eapol_type = Some(*v);
                stmt_end_offset = stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::EapCode(v, span) => {
                record_mod("EAP_CODE", *span);
                eap_code = Some(*v);
                stmt_end_offset = stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::EapId(v, span) => {
                record_mod("EAP_ID", *span);
                eap_id = Some(*v);
                stmt_end_offset = stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::EapMethod(v, span) => {
                record_mod("EAP_METHOD", *span);
                eap_method = Some(*v);
                stmt_end_offset = stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::Identity(v, span) => {
                record_mod("IDENTITY", *span);
                identity_str = Some(*v);
                stmt_end_offset = stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::IcmpTypeChoice(v, span) => {
                record_mod("ICMP_TYPE_CHOICE", *span);
                icmp_type_choice = Some(*v);
                stmt_end_offset = stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::IcmpId(v, span) => {
                record_mod("ICMP_ID", *span);
                icmp_id_val = Some(*v);
                stmt_end_offset = stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::Gateway(v, span) => {
                record_mod("GATEWAY", *span);
                gateway_ip = Some(*v);
                stmt_end_offset = stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::NdpType(v, span) => {
                record_mod("NDP_TYPE", *span);
                ndp_type = Some(*v);
                stmt_end_offset = stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::TargetVal(ip, mac, span) => {
                record_mod("TARGET", *span);
                if let Some(i) = ip {
                    target_ip = Some(*i);
                }
                if let Some(m) = mac {
                    tlla_mac = Some(*m);
                }
                stmt_end_offset = stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::Slla(v, span) => {
                record_mod("SLLA", *span);
                slla_mac = Some(*v);
                stmt_end_offset = stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::Tlla(v, span) => {
                record_mod("TLLA", *span);
                tlla_mac = Some(*v);
                stmt_end_offset = stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::RouterLifetime(v, span) => {
                record_mod("ROUTER_LIFETIME", *span);
                router_lifetime = Some(*v);
                stmt_end_offset = stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::IgmpType(v, span) => {
                record_mod("IGMP_TYPE", *span);
                igmp_type = Some(*v);
                stmt_end_offset = stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::GroupVal(ip, g, span) => {
                record_mod("GROUP", *span);
                if let Some(i) = ip {
                    group_ip = Some(*i);
                }
                if let Some(u) = g {
                    hsrp_group = Some(*u);
                }
                stmt_end_offset = stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::MaxResp(v, span) => {
                record_mod("MAX_RESP", *span);
                max_resp = Some(*v);
                stmt_end_offset = stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::MldType(v, span) => {
                record_mod("MLD_TYPE", *span);
                mld_type = Some(*v);
                stmt_end_offset = stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::MulticastAddr(v, span) => {
                record_mod("MULTICAST_ADDR", *span);
                multicast_addr = Some(*v);
                stmt_end_offset = stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::MaxRespDelay(v, span) => {
                record_mod("MAX_RESP_DELAY", *span);
                max_resp_delay = Some(*v);
                stmt_end_offset = stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::GreKey(v, span) => {
                record_mod("GRE_KEY", *span);
                gre_key = Some(*v);
                stmt_end_offset = stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::GreSeq(v, span) => {
                record_mod("GRE_SEQ", *span);
                gre_seq = Some(*v);
                stmt_end_offset = stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::GreProto(v, span) => {
                record_mod("GRE_PROTO", *span);
                gre_proto = Some(*v);
                stmt_end_offset = stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::ChecksumFlag(span) => {
                record_mod("CHECKSUM", *span);
                gre_checksum = true;
                stmt_end_offset = stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::Vni(v, span) => {
                record_mod("VNI", *span);
                vni_val = Some(*v);
                stmt_end_offset = stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::OptClass(v, span) => {
                record_mod("OPT_CLASS", *span);
                opt_class = Some(*v);
                stmt_end_offset = stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::OptType(v, span) => {
                record_mod("OPT_TYPE", *span);
                opt_type = Some(*v);
                stmt_end_offset = stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::ProtocolType(v, span) => {
                record_mod("PROTOCOL_TYPE", *span);
                protocol_type = Some(*v);
                stmt_end_offset = stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::Spi(v, span) => {
                record_mod("SPI", *span);
                spi_val = Some(*v);
                stmt_end_offset = stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::Iv(v, span) => {
                record_mod("IV", *span);
                iv_val = Some(v.clone());
                stmt_end_offset = stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::Icv(v, span) => {
                record_mod("ICV", *span);
                icv_val = Some(v.clone());
                stmt_end_offset = stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::NextHeader(v, span) => {
                record_mod("NEXT_HEADER", *span);
                next_header_val = Some(*v);
                stmt_end_offset = stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::InitiatorSpi(v, span) => {
                record_mod("INITIATOR_SPI", *span);
                initiator_spi = Some(*v);
                stmt_end_offset = stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::ResponderSpi(v, span) => {
                record_mod("RESPONDER_SPI", *span);
                responder_spi = Some(*v);
                stmt_end_offset = stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::IkeExchange(v, span) => {
                record_mod("IKE_EXCHANGE", *span);
                ike_exchange = Some(*v);
                stmt_end_offset = stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::MsgId(v, span) => {
                record_mod("MSG_ID", *span);
                ike_msgid = Some(*v);
                stmt_end_offset = stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::NextPayload(v, span) => {
                record_mod("NEXT_PAYLOAD", *span);
                next_payload = Some(*v);
                stmt_end_offset = stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::WireguardType(v, span) => {
                record_mod("WG_TYPE", *span);
                wireguard_type = Some(*v);
                stmt_end_offset = stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::Sender(v, span) => {
                record_mod("SENDER", *span);
                wg_sender = Some(*v);
                stmt_end_offset = stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::Receiver(v, span) => {
                record_mod("RECEIVER", *span);
                wg_receiver = Some(*v);
                stmt_end_offset = stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::Counter(v, span) => {
                record_mod("COUNTER", *span);
                wg_counter = Some(*v);
                stmt_end_offset = stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::OspfType(v, span) => {
                record_mod("OSPF_TYPE", *span);
                ospf_type = Some(*v);
                stmt_end_offset = stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::HelloWord(span) => {
                pim_is_hello = true;
                if ospf_type.is_none() {
                    ospf_type = Some(OspfType::Hello);
                }
                stmt_end_offset = stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::RouterId(v, span) => {
                record_mod("ROUTER_ID", *span);
                router_id_ip = Some(*v);
                stmt_end_offset = stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::AreaId(v, span) => {
                record_mod("AREA_ID", *span);
                area_id_val = Some(*v);
                stmt_end_offset = stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::HelloInterval(v, span) => {
                record_mod("HELLO_INTERVAL", *span);
                hello_interval = Some(*v);
                stmt_end_offset = stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::DeadInterval(v, span) => {
                record_mod("DEAD_INTERVAL", *span);
                dead_interval = Some(*v);
                stmt_end_offset = stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::PriorityVal(v, span) => {
                record_mod("PRIORITY", *span);
                priority_val = Some(*v);
                of_priority = Some(*v);
                stmt_end_offset = stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::BgpType(v, span) => {
                record_mod("BGP_TYPE", *span);
                bgp_type = Some(*v);
                stmt_end_offset = stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::Asn(v, span) => {
                record_mod("ASN", *span);
                asn_val = Some(*v);
                stmt_end_offset = stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::HoldTime(v, span) => {
                record_mod("HOLD_TIME", *span);
                holdtime_val = Some(*v);
                stmt_end_offset = stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::BgpId(v, span) => {
                record_mod("BGP_ID", *span);
                bgpid_ip = Some(*v);
                stmt_end_offset = stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::PrefixVal(ip, st, span) => {
                record_mod("PREFIX", *span);
                if let Some(i) = ip {
                    rip_prefix = Some(*i);
                }
                if let Some(s) = st {
                    prefix_str = Some(*s);
                }
                stmt_end_offset = stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::NextHop(v, span) => {
                record_mod("NEXT_HOP", *span);
                nexthop_ip = Some(*v);
                stmt_end_offset = stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::Metric(v, span) => {
                record_mod("METRIC", *span);
                rip_metric = Some(*v);
                stmt_end_offset = stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::TagVal(u, s, span) => {
                record_mod("TAG", *span);
                if let Some(v) = u {
                    rip_tag = Some(*v);
                }
                if let Some(str_val) = s {
                    imap_spec.tag = Some(*str_val);
                    nfs_spec.tag = Some(*str_val);
                }
                stmt_end_offset = stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::Vrid(v, span) => {
                record_mod("VRID", *span);
                vrid_val = Some(*v);
                stmt_end_offset = stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::AdvInt(v, span) => {
                record_mod("ADV_INT", *span);
                adv_int_val = Some(*v);
                stmt_end_offset = stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::Vip(v, span) => {
                record_mod("VIP", *span);
                vip_ip = Some(*v);
                stmt_end_offset = stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::HsrpState(v, span) => {
                record_mod("STATE", *span);
                hsrp_state = Some(*v);
                bfd_state = Some(*v);
                stmt_end_offset = stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::HelloTimeHsrp(v, span) => {
                record_mod("HELLO_TIME_HSRP", *span);
                hsrp_hellotime = Some(*v);
                stmt_end_offset = stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::PimJoinPrune(span) => {
                record_mod("JOIN_PRUNE", *span);
                pim_is_join_prune = true;
                stmt_end_offset = stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::PimRegister(span) => {
                record_mod("REGISTER", *span);
                pim_is_register = true;
                stmt_end_offset = stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::SourceIp(v, span) => {
                record_mod("SOURCE", *span);
                pim_source = Some(*v);
                stmt_end_offset = stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::Rp(v, span) => {
                record_mod("RP", *span);
                pim_rp = Some(*v);
                stmt_end_offset = stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::DrPriority(v, span) => {
                record_mod("DR_PRIORITY", *span);
                pim_dr_priority = Some(*v);
                stmt_end_offset = stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::Diag(v, span) => {
                record_mod("DIAG", *span);
                bfd_diag = Some(*v);
                stmt_end_offset = stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::MyDisc(v, span) => {
                record_mod("MY_DISC", *span);
                bfd_my_disc = Some(*v);
                stmt_end_offset = stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::YourDisc(v, span) => {
                record_mod("YOUR_DISC", *span);
                bfd_your_disc = Some(*v);
                stmt_end_offset = stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::MinTx(v, span) => {
                record_mod("MIN_TX", *span);
                bfd_min_tx = Some(*v);
                stmt_end_offset = stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::MinRx(v, span) => {
                record_mod("MIN_RX", *span);
                bfd_min_rx = Some(*v);
                stmt_end_offset = stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::Mult(v, span) => {
                record_mod("MULT", *span);
                bfd_mult = Some(*v);
                stmt_end_offset = stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::OpenflowType(v, span) => {
                record_mod("OPENFLOW_TYPE", *span);
                openflow_type = Some(*v);
                stmt_end_offset = stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::Xid(v, span) => {
                record_mod("XID", *span);
                of_xid = Some(*v);
                stmt_end_offset = stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::Dpid(v, span) => {
                record_mod("DPID", *span);
                of_dpid = Some(*v);
                stmt_end_offset = stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::TableId(v, span) => {
                record_mod("TABLE_ID", *span);
                of_table_id = Some(*v);
                stmt_end_offset = stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::L7StringField(key, val, span) => {
                record_mod(key, *span);
                stmt_end_offset = stmt_end_offset.max(span.0 + span.1);
                match *key {
                    "QNAME" => dns_spec.qname = Some(*val),
                    "QTYPE" => dns_spec.qtype = Some(*val),
                    "RDATA" => dns_spec.rdata = Some(*val),
                    "HOSTNAME" => {
                        dhcp_spec.hostname = Some(*val);
                        syslog_spec.hostname = Some(*val);
                    }
                    "REFID" => ntp_spec.refid = Some(*val),
                    "MSG_TYPE" => {
                        ptp_spec.msg_type = Some(*val);
                        coap_spec.msg_type = Some(*val);
                        opcua_spec.msg_type = Some(*val);
                    }
                    "CLOCK_ID" => ptp_spec.clock_id = Some(*val),
                    "DOMAIN" => {
                        whois_spec.domain = Some(*val);
                        if let Ok(d) = val.parse::<u8>() {
                            ptp_spec.domain = Some(d);
                        }
                    }
                    "CODE" => {
                        radius_spec.code = Some(*val);
                        coap_spec.code = Some(*val);
                    }
                    "TACACS_TYPE" => tacacs_spec.tacacs_type = Some(*val),
                    "DATA" => {
                        tacacs_spec.data = Some(*val);
                        telnet_spec.data = Some(*val);
                    }
                    "APP" => syslog_spec.app = Some(*val),
                    "PROCID" => syslog_spec.procid = Some(*val),
                    "MSGID" => syslog_spec.msgid = Some(*val),
                    "MSG" => syslog_spec.msg = Some(*val),
                    "FILENAME" => {
                        tftp_spec.filename = Some(*val);
                        smb_spec.filename = Some(*val);
                    }
                    "MODE" => tftp_spec.mode = Some(*val),
                    "ERRMSG" => tftp_spec.errmsg = Some(*val),
                    "CMD" => {
                        ftp_spec.cmd = Some(*val);
                        smtp_spec.cmd = Some(*val);
                        imap_spec.cmd = Some(*val);
                        pop3_spec.cmd = Some(*val);
                        redis_spec.cmd = Some(*val);
                        memcached_spec.cmd = Some(*val);
                        ethernetip_spec.cmd = Some(*val);
                    }
                    "ARG" => {
                        ftp_spec.arg = Some(*val);
                        imap_spec.arg = Some(*val);
                        pop3_spec.arg = Some(*val);
                    }
                    "REPLY" => {
                        ftp_spec.reply = Some(*val);
                        smtp_spec.reply = Some(*val);
                    }
                    "EHLO_PARAM" => {
                        smtp_spec.cmd = Some("EHLO");
                        smtp_spec.param = Some(*val);
                    }
                    "HELO_PARAM" => {
                        smtp_spec.cmd = Some("HELO");
                        smtp_spec.param = Some(*val);
                    }
                    "BANNER" => ssh_spec.banner = Some(*val),
                    "COOKIE" => ssh_spec.cookie = Some(*val),
                    "METHOD" => {
                        http_spec.method = Some(*val);
                        grpc_spec.method = Some(*val);
                        sip_spec.method = Some(*val);
                        rtsp_spec.method = Some(*val);
                    }
                    "URI" => {
                        http_spec.uri = Some(*val);
                        sip_spec.uri = Some(*val);
                        rtsp_spec.uri = Some(*val);
                    }
                    "VERSION" => http_spec.version = Some(*val),
                    "HOST_HDR" => {
                        http_spec.host_hdr = Some(*val);
                        ssdp_spec.host_hdr = Some(*val);
                    }
                    "USER_AGENT" => http_spec.user_agent = Some(*val),
                    "CONTENT_TYPE" => {
                        http_spec.content_type = Some(*val);
                        sip_spec.content_type = Some(*val);
                    }
                    "STATUS" => {
                        imap_spec.status = Some(*val);
                        if let Ok(st) = val.parse::<u16>() {
                            http_spec.status = Some(st);
                            sip_spec.status = Some(st);
                            rtsp_spec.status = Some(st);
                        }
                    }
                    "REASON" => {
                        http_spec.reason = Some(*val);
                        sip_spec.reason = Some(*val);
                    }
                    "BODY" => {
                        http_spec.body = Some(*val);
                        smtp_spec.body = Some(*val);
                        sip_spec.body = Some(*val);
                    }
                    "SERVICE" => grpc_spec.service = Some(*val),
                    "OPCODE" => websocket_spec.opcode = Some(*val),
                    "SNI" => tls_spec.sni = Some(*val),
                    "ALPN" => tls_spec.alpn = Some(*val),
                    "TOKEN" => quic_spec.token = Some(*val),
                    "SOFTWARE" => stun_spec.software = Some(*val),
                    "FROM" => sip_spec.from = Some(*val),
                    "TO" => sip_spec.to = Some(*val),
                    "CALL_ID" => sip_spec.call_id = Some(*val),
                    "VIA" => sip_spec.via = Some(*val),
                    "CONTACT" => sip_spec.contact = Some(*val),
                    "TRANSPORT_HDR" => rtsp_spec.transport_hdr = Some(*val),
                    "SESSION" => rtsp_spec.session = Some(*val),
                    "PARAM" => smtp_spec.param = Some(*val),
                    "RESPONSE" => {
                        imap_spec.response = Some(*val);
                        pop3_spec.response = Some(*val);
                    }
                    "REALM" => kerberos_spec.realm = Some(*val),
                    "CNAME" => kerberos_spec.cname = Some(*val),
                    "SNAME" => kerberos_spec.sname = Some(*val),
                    "BASE_DN" => ldap_spec.base_dn = Some(*val),
                    "FILTER" => ldap_spec.filter = Some(*val),
                    "COMMAND" => smb_spec.command = Some(*val),
                    "SHARE" => smb_spec.share = Some(*val),
                    "PROC" => nfs_spec.proc_name = Some(*val),
                    "PATH" => nfs_spec.path = Some(*val),
                    "ARGS" => redis_spec.args.push(*val),
                    "REPLY_TYPE" => redis_spec.reply_type = Some(*val),
                    "VALUE" | "VALUE_STR" => {
                        redis_spec.value = Some(*val);
                        memcached_spec.value = Some(*val);
                    }
                    "KEY" => memcached_spec.key = Some(*val),
                    "SERVER_VERSION" => mysql_spec.server_version = Some(*val),
                    "SQL" => {
                        mysql_spec.sql = Some(*val);
                        postgres_spec.sql = Some(*val);
                    }
                    "DB" => {
                        mysql_spec.db = Some(*val);
                        postgres_spec.db = Some(*val);
                    }
                    "PKT_TYPE" => mqtt_spec.pkt_type = Some(*val),
                    "CLIENT_ID" => mqtt_spec.client_id = Some(*val),
                    "TOPIC" => mqtt_spec.topic = Some(*val),
                    "URI_PATH" => coap_spec.uri_path = Some(*val),
                    "EXCHANGE" => amqp_spec.exchange = Some(*val),
                    "ROUTING_KEY" => amqp_spec.routing_key = Some(*val),
                    "MAN" => ssdp_spec.man = Some(*val),
                    "ST" => ssdp_spec.st = Some(*val),
                    "NT" => ssdp_spec.nt = Some(*val),
                    "NTS" => ssdp_spec.nts = Some(*val),
                    "USN" => ssdp_spec.usn = Some(*val),
                    "LOCATION" => ssdp_spec.location = Some(*val),
                    "REGISTRAR" => whois_spec.registrar = Some(*val),
                    "FUNC" => {
                        modbus_spec.func = Some(*val);
                        dnp3_spec.func = Some(*val);
                        s7comm_spec.func = Some(*val);
                    }
                    "ROSCTR" => s7comm_spec.rosctr = Some(*val),
                    "ENDPOINT_URL" => opcua_spec.endpoint_url = Some(*val),
                    "NODE_ID" => opcua_spec.node_id = Some(*val),
                    "CHUNK_TYPE" => opcua_spec.chunk_type = val.chars().next(),
                    _ => {}
                }
            }
            ParsedField::L7U32Field(key, val, span) => {
                record_mod(key, *span);
                stmt_end_offset = stmt_end_offset.max(span.0 + span.1);
                match *key {
                    "TXID" => {
                        dns_spec.txid = Some(*val as u16);
                        modbus_spec.txid = Some(*val as u16);
                    }
                    "CODE" => {
                        icmp_code_val = Some(*val as u8);
                        ftp_spec.code = Some(*val as u16);
                        smtp_spec.code = Some(*val as u16);
                    }
                    "DOMAIN" => ptp_spec.domain = Some(*val as u8),
                    "RCODE" => dns_spec.rcode = Some(*val as u8),
                    "ANS_TTL" => dns_spec.ans_ttl = Some(*val),
                    "LEASE_TIME" => dhcp_spec.lease_time = Some(*val),
                    "LI" => ntp_spec.li = Some(*val as u8),
                    "VN" => ntp_spec.vn = Some(*val as u8),
                    "MODE" => ntp_spec.mode = Some(*val as u8),
                    "STRATUM" => ntp_spec.stratum = Some(*val as u8),
                    "POLL" => ntp_spec.poll = Some(*val as u8),
                    "PRECISION" => ntp_spec.precision = Some(*val as i8),
                    "SEQ_ID" => ptp_spec.seq_id = Some(*val as u16),
                    "SERVICE_TYPE" => radius_spec.service_type = Some(*val),
                    "FACILITY" => syslog_spec.facility = Some(*val as u8),
                    "SEVERITY" => syslog_spec.severity = Some(*val as u8),
                    "PRI" => syslog_spec.pri = Some(*val as u8),
                    "MSGID" => {
                        ldap_spec.msgid = Some(*val as i32);
                        coap_spec.msgid = Some(*val as u16);
                    }
                    "PROTO" => {
                        netflow_spec.proto = Some(*val as u8);
                        ipfix_spec.proto = Some(*val as u8);
                    }
                    "PACKETS" => {
                        netflow_spec.packets = Some(*val);
                        ipfix_spec.packets = Some(*val);
                    }
                    "OCTETS" => {
                        netflow_spec.octets = Some(*val);
                        ipfix_spec.octets = Some(*val);
                    }
                    "DOMAIN_ID" => ipfix_spec.domain_id = Some(*val),
                    "SUB_AGENT_ID" => sflow_spec.sub_agent_id = Some(*val),
                    "UPTIME" => sflow_spec.uptime = Some(*val),
                    "SAMPLES" => sflow_spec.samples = Some(*val),
                    "BLOCK" => tftp_spec.block = Some(*val as u16),
                    "ERRCODE" => {
                        tftp_spec.errcode = Some(*val as u16);
                        mysql_spec.errcode = Some(*val as u16);
                    }
                    "MSG_CODE" => ssh_spec.msg_code = Some(*val as u8),
                    "WILL" => telnet_spec.will = Some(*val as u8),
                    "WONT" => telnet_spec.wont = Some(*val as u8),
                    "DO" => telnet_spec.do_opt = Some(*val as u8),
                    "DONT" => telnet_spec.dont = Some(*val as u8),
                    "OPTION" => telnet_spec.option = Some(*val as u8),
                    "STATUS" => {
                        http_spec.status = Some(*val as u16);
                        sip_spec.status = Some(*val as u16);
                        rtsp_spec.status = Some(*val as u16);
                        smb_spec.status = Some(*val);
                        ethernetip_spec.status = Some(*val);
                    }
                    "STREAM_ID" => http2_spec.stream_id = Some(*val),
                    "GRPC_STATUS" => grpc_spec.grpc_status = Some(*val),
                    "FIN_BIT" => websocket_spec.fin_bit = Some(*val as u8),
                    "MASK_KEY" => websocket_spec.mask_key = Some(*val),
                    "RECORD_VERSION" => tls_spec.record_version = Some(*val as u16),
                    "HANDSHAKE_VERSION" => tls_spec.handshake_version = Some(*val as u16),
                    "CIPHERSUITE" => tls_spec.ciphersuite = Some(*val as u16),
                    "PKT_NUM" => quic_spec.pkt_num = Some(*val),
                    "CSEQ" => {
                        sip_spec.cseq = Some(*val);
                        rtsp_spec.cseq = Some(*val);
                    }
                    "PT" => rtp_spec.pt = Some(*val as u8),
                    "TIMESTAMP" => rtp_spec.timestamp = Some(*val),
                    "SSRC" => rtp_spec.ssrc = Some(*val),
                    "MARKER" => rtp_spec.marker = Some(*val as u8),
                    "ETYPE" => kerberos_spec.etype = Some(*val as i32),
                    "RESULT_CODE" => ldap_spec.result_code = Some(*val),
                    "TREE_ID" => smb_spec.tree_id = Some(*val),
                    "VERS" => nfs_spec.vers = Some(*val),
                    "EXPTIME" => memcached_spec.exptime = Some(*val),
                    "OPAQUE" => memcached_spec.opaque = Some(*val),
                    "QOS" => mqtt_spec.qos = Some(*val as u8),
                    "PKT_ID" => mqtt_spec.pkt_id = Some(*val as u16),
                    "KEEPALIVE" => mqtt_spec.keepalive = Some(*val as u16),
                    "RETURN_CODE" => mqtt_spec.return_code = Some(*val as u8),
                    "TOKEN" => coap_spec.token = Some(*val),
                    "CONTENT_FORMAT" => coap_spec.content_format = Some(*val as u16),
                    "CHANNEL" => amqp_spec.channel = Some(*val as u16),
                    "MX" => ssdp_spec.mx = Some(*val as u8),
                    "PROTO_ID" => modbus_spec.proto_id = Some(*val as u16),
                    "UNITID" => modbus_spec.unitid = Some(*val as u8),
                    "ADDR" => modbus_spec.addr = Some(*val as u16),
                    "COUNT" => modbus_spec.count = Some(*val as u16),
                    "VALUE" => {
                        modbus_spec.value = Some(*val as u16);
                        bacnet_spec.value = Some(*val);
                    }
                    "INVOKE_ID" => bacnet_spec.invoke_id = Some(*val as u8),
                    "OBJECT_TYPE" => bacnet_spec.object_type = Some(*val as u16),
                    "OBJECT_INSTANCE" => bacnet_spec.object_instance = Some(*val),
                    "PROPERTY_ID" => bacnet_spec.property_id = Some(*val),
                    "SRC" => dnp3_spec.src = Some(*val as u16),
                    "DST" => dnp3_spec.dst = Some(*val as u16),
                    "GROUP" => dnp3_spec.group = Some(*val as u8),
                    "VARIATION" => dnp3_spec.variation = Some(*val as u8),
                    "CRC" => dnp3_spec.crc = Some(*val as u16),
                    "PDU_REF" => s7comm_spec.pdu_ref = Some(*val as u16),
                    "AREA" => s7comm_spec.area = Some(*val as u8),
                    "DB_NUM" => s7comm_spec.db_num = Some(*val as u16),
                    "OFFSET" => s7comm_spec.offset = Some(*val),
                    "SESSION_HANDLE" => ethernetip_spec.session_handle = Some(*val),
                    "CIP_SERVICE" => ethernetip_spec.cip_service = Some(*val as u8),
                    "CIP_CLASS" => ethernetip_spec.cip_class = Some(*val as u16),
                    "CIP_INSTANCE" => ethernetip_spec.cip_instance = Some(*val as u16),
                    "CIP_ATTR" => ethernetip_spec.cip_attr = Some(*val as u16),
                    "SECURE_CHANNEL_ID" => opcua_spec.secure_channel_id = Some(*val),
                    "TOKEN_ID" => opcua_spec.token_id = Some(*val),
                    "SEQ_NUM" => opcua_spec.seq_num = Some(*val),
                    "REQ_ID" => opcua_spec.req_id = Some(*val),
                    _ => {}
                }
            }
            ParsedField::L7U64Field(key, val, span) => {
                record_mod(key, *span);
                stmt_end_offset = stmt_end_offset.max(span.0 + span.1);
                match *key {
                    "TX_TIMESTAMP" => ntp_spec.tx_timestamp = Some(*val),
                    "SESSION_ID" => {
                        tacacs_spec.session_id = Some(*val as u32);
                        smb_spec.session_id = Some(*val);
                    }
                    "DCID" => quic_spec.dcid = Some(*val),
                    "SCID" => quic_spec.scid = Some(*val),
                    "MSGID" => smb_spec.msgid = Some(*val),
                    "CAS" => memcached_spec.cas = Some(*val),
                    "CONTEXT" => ethernetip_spec.context = Some(*val),
                    _ => {}
                }
            }
            ParsedField::L7IpField(key, val, span) => {
                record_mod(key, *span);
                stmt_end_offset = stmt_end_offset.max(span.0 + span.1);
                match *key {
                    "CIADDR" => dhcp_spec.ciaddr = Some(*val),
                    "YIADDR" => dhcp_spec.yiaddr = Some(*val),
                    "SIADDR" => dhcp_spec.siaddr = Some(*val),
                    "DNS_SERVER" => dhcp_spec.dns_server = Some(*val),
                    "ROUTER" => dhcp_spec.router = Some(*val),
                    "SUBNET_MASK" => dhcp_spec.subnet_mask = Some(*val),
                    "NAS_IP" => radius_spec.nas_ip = Some(*val),
                    "FRAMED_IP" => radius_spec.framed_ip = Some(*val),
                    "SRCIP" => {
                        netflow_spec.srcip = Some(*val);
                        ipfix_spec.srcip = Some(*val);
                    }
                    "DSTIP" => {
                        netflow_spec.dstip = Some(*val);
                        ipfix_spec.dstip = Some(*val);
                    }
                    "AGENT_IP" => sflow_spec.agent_ip = Some(*val),
                    "XOR_MAPPED_ADDR" => stun_spec.xor_mapped_addr = Some(*val),
                    _ => {}
                }
            }
            ParsedField::L7MacField(key, val, span) => {
                record_mod(key, *span);
                stmt_end_offset = stmt_end_offset.max(span.0 + span.1);
                if *key == "CHADDR" {
                    dhcp_spec.chaddr = Some(*val);
                }
            }
            ParsedField::L7Flag(key, span) => {
                record_mod(key, *span);
                stmt_end_offset = stmt_end_offset.max(span.0 + span.1);
                match *key {
                    "QUERY" => {
                        dns_spec.is_query = true;
                        whois_spec.is_query = true;
                    }
                    "RESPONSE" => {
                        dns_spec.is_response = true;
                        whois_spec.is_response = true;
                    }
                    "DISCOVER" => dhcp_spec.is_discover = true,
                    "SOLICIT" => dhcp_spec.is_solicit = true,
                    "OFFER" => dhcp_spec.is_offer = true,
                    "ADVERTISE" => dhcp_spec.is_advertise = true,
                    "REQUEST" => dhcp_spec.is_request = true,
                    "ACK" => dhcp_spec.is_ack = true,
                    "REPLY" => dhcp_spec.is_reply = true,
                    "RELEASE" => dhcp_spec.is_release = true,
                    "SYNC" => ptp_spec.msg_type = Some("SYNC"),
                    "DELAY_REQ" => ptp_spec.msg_type = Some("DELAY_REQ"),
                    "FOLLOW_UP" => ptp_spec.msg_type = Some("FOLLOW_UP"),
                    "DELAY_RESP" => ptp_spec.msg_type = Some("DELAY_RESP"),
                    "ANNOUNCE" => ptp_spec.msg_type = Some("ANNOUNCE"),
                    "RRQ" => tftp_spec.is_rrq = true,
                    "WRQ" => tftp_spec.is_wrq = true,
                    "KEXINIT" => ssh_spec.is_kexinit = true,
                    "NEWKEYS" => ssh_spec.is_newkeys = true,
                    "PREFACE" => http2_spec.is_preface = true,
                    "SETTINGS" => http2_spec.is_settings = true,
                    "HEADERS" => http2_spec.is_headers = true,
                    "WINDOW_UPDATE" => http2_spec.is_window_update = true,
                    "PING" => http2_spec.is_ping = true,
                    "GOAWAY" => http2_spec.is_goaway = true,
                    "CLIENT_HELLO" => tls_spec.is_client_hello = true,
                    "SERVER_HELLO" => tls_spec.is_server_hello = true,
                    "CERTIFICATE" => tls_spec.is_certificate = true,
                    "FINISHED" => tls_spec.is_finished = true,
                    "APP_DATA" => tls_spec.is_app_data = true,
                    "ALERT" => tls_spec.is_alert = true,
                    "INITIAL" => quic_spec.is_initial = true,
                    "ZERO_RTT" => quic_spec.is_zero_rtt = true,
                    "HANDSHAKE" => quic_spec.is_handshake = true,
                    "RETRY" => quic_spec.is_retry = true,
                    "SHORT" => quic_spec.is_short = true,
                    "BINDING_REQUEST" => stun_spec.is_binding_request = true,
                    "BINDING_RESPONSE" => stun_spec.is_binding_response = true,
                    "BINDING_ERROR" => stun_spec.is_binding_error = true,
                    "OK" => {
                        pop3_spec.is_ok = true;
                        mysql_spec.is_ok = true;
                    }
                    "ERR" => {
                        pop3_spec.is_err = true;
                        mysql_spec.is_err = true;
                    }
                    "AS_REQ" => kerberos_spec.is_as_req = true,
                    "AS_REP" => kerberos_spec.is_as_rep = true,
                    "TGS_REQ" => kerberos_spec.is_tgs_req = true,
                    "TGS_REP" => kerberos_spec.is_tgs_rep = true,
                    "KRB_ERROR" => kerberos_spec.is_krb_error = true,
                    "BIND_REQ" => ldap_spec.is_bind_req = true,
                    "BIND_RES" => ldap_spec.is_bind_res = true,
                    "SEARCH_REQ" => ldap_spec.is_search_req = true,
                    "SEARCH_ENTRY" => ldap_spec.is_search_entry = true,
                    "SEARCH_DONE" => ldap_spec.is_search_done = true,
                    "UNBIND_REQ" => ldap_spec.is_unbind_req = true,
                    "GREETING" => mysql_spec.is_greeting = true,
                    "LOGIN" => mysql_spec.is_login = true,
                    "EOF" => mysql_spec.is_eof = true,
                    "STARTUP" => postgres_spec.is_startup = true,
                    "READY_FOR_QUERY" => postgres_spec.is_ready_for_query = true,
                    "COMMAND_COMPLETE" => postgres_spec.is_command_complete = true,
                    "ERROR_RESPONSE" => postgres_spec.is_error_response = true,
                    "AUTH_OK" => postgres_spec.is_auth_ok = true,
                    "RETAIN" => mqtt_spec.retain = Some(true),
                    "PROTOCOL_HEADER" => amqp_spec.is_protocol_header = true,
                    "CONNECTION_START" => amqp_spec.is_connection_start = true,
                    "CHANNEL_OPEN" => amqp_spec.is_channel_open = true,
                    "BASIC_PUBLISH" => amqp_spec.is_basic_publish = true,
                    "BASIC_DELIVER" => amqp_spec.is_basic_deliver = true,
                    "HEARTBEAT" => amqp_spec.is_heartbeat = true,
                    "MSEARCH" => ssdp_spec.is_msearch = true,
                    "NOTIFY" => ssdp_spec.is_notify = true,
                    "IS_RESPONSE" => modbus_spec.is_response = true,
                    "WHO_IS" => bacnet_spec.is_who_is = true,
                    "I_AM" => bacnet_spec.is_i_am = true,
                    "READ_PROPERTY" => bacnet_spec.is_read_property = true,
                    "WRITE_PROPERTY" => bacnet_spec.is_write_property = true,
                    _ => {}
                }
            }
            ParsedField::L7Header(k, v, span) => {
                http_spec.headers.push((*k, *v));
                stmt_end_offset = stmt_end_offset.max(span.0 + span.1);
            }
        }
    }

    let protocol = match (protocol, transport_val) {
        (Some(p), _) => p,
        (None, Some(TransportProto::Udp)) => Protocol::Udp,
        (None, Some(TransportProto::Tcp)) => Protocol::Tcp,
        (None, None) => {
            if vlan_val.is_some() {
                Protocol::Vlan
            } else if qinq_val.is_some() {
                Protocol::Qinq
            } else if mpls_val.is_some() {
                Protocol::Mpls
            } else {
                Protocol::Tcp
            }
        }
    };

    if protocol == Protocol::Rip {
        if arp_opcode == Some(ArpOpcode::Request) {
            rip_cmd = Some(RipCommand::Request);
        } else if arp_opcode == Some(ArpOpcode::Reply) || pdu_type == Some(SnmpPduType::Response) {
            rip_cmd = Some(RipCommand::Response);
        }
    }

    if protocol == Protocol::Memcached {
        if let Some(ref pt) = pdu_type {
            match pt {
                SnmpPduType::Get => memcached_spec.cmd = Some("GET"),
                SnmpPduType::Set => memcached_spec.cmd = Some("SET"),
                _ => {}
            }
            pdu_type = None;
        }
        if memcached_spec.cmd.is_none() {
            memcached_spec.cmd = http_spec.method;
        }
    }

    if protocol == Protocol::Tcp && flags.is_empty() {
        if payload.is_some() || hex_payload.is_some() {
            flags.push(TcpFlag::Psh);
            flags.push(TcpFlag::Ack);
        } else {
            flags.push(TcpFlag::Syn);
        }
    }

    let vlan = vlan_val.map(|(v, _)| VlanSpec {
        vid: v as u16,
        pcp: pcp_val.map(|(p, _)| p),
        dei: dei_val.map(|(d, _)| d),
    });
    let qinq = qinq_val.map(|(v, _)| QinqSpec {
        outer_vid: v,
        inner_vid: inner_vlan_val.map(|(iv, _)| iv),
    });
    let mpls = mpls_val.map(|(lbl, _)| MplsSpec {
        label: lbl,
        exp: exp_val.map(|(e, _)| e),
        bos: bos_val.map(|(b, _)| b),
        ttl: mpls_ttl_val.map(|(t, _)| t),
    });
    let l2 = L2Modifiers {
        src_mac: src_mac_val.map(|(m, _)| m),
        dst_mac: dst_mac_val.map(|(m, _)| m),
        ethertype: ethertype_val.map(|(e, _)| e),
        vlan: vlan.clone(),
        qinq: qinq.clone(),
        mpls: mpls.clone(),
    };

    let l3 = L3Modifiers {
        ttl: ttl_val.and_then(|(v, _)| if v <= 255 { Some(v as u8) } else { None }),
        dscp: dscp_val.and_then(|(v, _)| if v <= 63 { Some(v as u8) } else { None }),
        ecn: ecn_val.and_then(|(v, _)| if v <= 3 { Some(v as u8) } else { None }),
        flowlabel: flowlabel_val.map(|(v, _)| v),
        ipid: ipid_val.map(|(v, _)| v),
        df: df_val,
        mf: mf_val,
        frag_offset: frag_offset_val.map(|(v, _)| v),
    };

    let tcp_options = if mss_val.is_some()
        || wscale_val.is_some()
        || sack_perm_val
        || tsval_val.is_some()
        || tsecr_val.is_some()
    {
        Some(TcpOptions {
            mss: mss_val.map(|(v, _)| v),
            wscale: wscale_val.map(|(v, _)| v),
            sack_perm: sack_perm_val,
            tsval: tsval_val.map(|(v, _)| v),
            tsecr: tsecr_val.map(|(v, _)| v),
        })
    } else {
        None
    };

    let sctp_params = if vtag_val.is_some()
        || stream_val.is_some()
        || ssn_val.is_some()
        || ppid_val.is_some()
        || chunk_val.is_some()
    {
        Some(SctpParams {
            vtag: vtag_val.map(|(v, _)| v),
            stream: stream_val.map(|(v, _)| v),
            ssn: ssn_val.map(|(v, _)| v),
            ppid: ppid_val.map(|(v, _)| v),
            chunk: chunk_val.map(|(v, _)| v),
        })
    } else {
        None
    };

    let l4 = L4Modifiers {
        src_port,
        dst_port,
        transport: transport_val,
        tcp_flags: flags.clone(),
        urgent: urgent_val.map(|(v, _)| v),
        tcp_options,
        sctp_params: sctp_params.clone(),
    };

    let protocol_spec = match protocol {
        Protocol::Tcp => Some(ProtocolSpec::Tcp),
        Protocol::Udp => Some(ProtocolSpec::Udp),
        Protocol::Sctp => Some(ProtocolSpec::Sctp(sctp_params.unwrap_or_default())),
        Protocol::Snmp1 => Some(ProtocolSpec::Snmp1(Snmp1Spec {
            community,
            enterprise,
            agent_ip,
            gen_trap,
            spec_trap,
            sys_up_time,
            varbinds: varbinds.clone(),
            pdu_type: pdu_type.clone(),
        })),
        Protocol::Snmp2 => Some(ProtocolSpec::Snmp2(Snmp2Spec {
            community,
            varbinds: varbinds.clone(),
            pdu_type: pdu_type.clone(),
            non_repeaters,
            max_repetitions,
            req_id,
        })),
        Protocol::Snmp3 => Some(ProtocolSpec::Snmp3(Snmp3Spec {
            user,
            engine_id,
            engine_boots,
            engine_time,
            context_name,
            auth: auth.clone(),
            priv_param: priv_param.clone(),
            varbinds: varbinds.clone(),
            pdu_type: pdu_type.clone(),
            non_repeaters,
            max_repetitions,
            req_id,
        })),
        Protocol::Arp => Some(ProtocolSpec::Arp(ArpSpec {
            opcode: arp_opcode,
            is_gratuitous,
            sha,
            spa,
            tha,
            tpa,
            _marker: core::marker::PhantomData,
        })),
        Protocol::Vlan => Some(ProtocolSpec::Vlan(vlan.unwrap_or_default())),
        Protocol::Qinq => Some(ProtocolSpec::Qinq(qinq.unwrap_or_default())),
        Protocol::Mpls => Some(ProtocolSpec::Mpls(mpls.unwrap_or_default())),
        Protocol::Lldp => Some(ProtocolSpec::Lldp(LldpSpec {
            chassis_id,
            port_id: port_id_str,
            ttl: ttl_val.map(|(t, _)| t as u16),
            sysname,
            sysdesc,
        })),
        Protocol::Stp => Some(ProtocolSpec::Stp(StpSpec {
            root_id,
            bridge_id,
            port_id: port_id_u16,
            cost: stp_cost,
            max_age,
            hello_time,
            forward_delay,
            flags: stp_flags,
            is_rstp,
        })),
        Protocol::Lacp => Some(ProtocolSpec::Lacp(LacpSpec {
            actor_sys,
            actor_key,
            actor_port,
            partner_sys,
            partner_key,
            partner_port,
            actor_state,
            partner_state,
            _marker: core::marker::PhantomData,
        })),
        Protocol::Eapol => Some(ProtocolSpec::Eapol(EapolSpec {
            version: version_byte,
            packet_type: eapol_type,
            eap_code,
            eap_id,
            eap_method,
            identity: identity_str,
        })),
        Protocol::Icmp => Some(ProtocolSpec::Icmp(IcmpSpec {
            type_choice: icmp_type_choice,
            icmp_type: icmp_type_val,
            icmp_code: icmp_code_val,
            id: icmp_id_val,
            seq: seq.map(|s| s as u16),
            gateway: gateway_ip,
            _marker: core::marker::PhantomData,
        })),
        Protocol::Ndp => Some(ProtocolSpec::Ndp(NdpSpec {
            ndp_type,
            target: target_ip,
            slla: slla_mac,
            tlla: tlla_mac,
            router_lifetime,
            _marker: core::marker::PhantomData,
        })),
        Protocol::Igmp => Some(ProtocolSpec::Igmp(IgmpSpec {
            igmp_type,
            group: group_ip,
            max_resp,
            version: version_byte,
            _marker: core::marker::PhantomData,
        })),
        Protocol::Mld => Some(ProtocolSpec::Mld(MldSpec {
            mld_type,
            multicast_addr,
            max_resp_delay,
            _marker: core::marker::PhantomData,
        })),
        Protocol::Gre => Some(ProtocolSpec::Gre(GreSpec {
            key: gre_key,
            seq: gre_seq,
            proto: gre_proto,
            checksum: gre_checksum,
            _marker: core::marker::PhantomData,
        })),
        Protocol::Vxlan => Some(ProtocolSpec::Vxlan(VxlanSpec {
            vni: vni_val,
            _marker: core::marker::PhantomData,
        })),
        Protocol::Geneve => Some(ProtocolSpec::Geneve(GeneveSpec {
            vni: vni_val,
            opt_class,
            opt_type,
            protocol_type,
            _marker: core::marker::PhantomData,
        })),
        Protocol::Ipsec => Some(ProtocolSpec::Ipsec(IpsecSpec {
            spi: spi_val,
            seq,
            iv: iv_val,
            icv: icv_val,
            next_header: next_header_val,
            _marker: core::marker::PhantomData,
        })),
        Protocol::Esp => Some(ProtocolSpec::Esp(IpsecSpec {
            spi: spi_val,
            seq,
            iv: iv_val,
            icv: icv_val,
            next_header: next_header_val,
            _marker: core::marker::PhantomData,
        })),
        Protocol::Ah => Some(ProtocolSpec::Ah(AhSpec {
            spi: spi_val,
            seq,
            icv: icv_val,
            next_header: next_header_val,
            _marker: core::marker::PhantomData,
        })),
        Protocol::Ikev2 => Some(ProtocolSpec::Ikev2(Ikev2Spec {
            initiator_spi,
            responder_spi,
            exchange: ike_exchange,
            msgid: ike_msgid,
            flags: ike_flags,
            next_payload,
            _marker: core::marker::PhantomData,
        })),
        Protocol::Wireguard => Some(ProtocolSpec::Wireguard(WireguardSpec {
            msg_type: wireguard_type,
            sender: wg_sender,
            receiver: wg_receiver,
            counter: wg_counter,
            _marker: core::marker::PhantomData,
        })),
        Protocol::Ospf => Some(ProtocolSpec::Ospf(OspfSpec {
            ospf_type,
            router_id: router_id_ip,
            area_id: area_id_val,
            hello_interval,
            dead_interval,
            priority: priority_val.map(|p| p as u8),
            _marker: core::marker::PhantomData,
        })),
        Protocol::Bgp => Some(ProtocolSpec::Bgp(BgpSpec {
            bgp_type,
            asn: asn_val,
            holdtime: holdtime_val,
            bgpid: bgpid_ip,
            prefix: prefix_str,
            nexthop: nexthop_ip,
        })),
        Protocol::Rip => Some(ProtocolSpec::Rip(RipSpec {
            command: rip_cmd,
            prefix: rip_prefix,
            metric: rip_metric,
            nexthop: nexthop_ip,
            tag: rip_tag,
            _marker: core::marker::PhantomData,
        })),
        Protocol::Vrrp => Some(ProtocolSpec::Vrrp(VrrpSpec {
            vrid: vrid_val,
            priority: priority_val.map(|p| p as u8),
            adv_int: adv_int_val,
            vip: vip_ip,
            version: version_byte,
            _marker: core::marker::PhantomData,
        })),
        Protocol::Hsrp => Some(ProtocolSpec::Hsrp(HsrpSpec {
            group: hsrp_group,
            priority: priority_val.map(|p| p as u8),
            state: hsrp_state,
            auth: hsrp_auth,
            vip: vip_ip,
            hellotime: hsrp_hellotime,
            holdtime: holdtime_val.map(|h| h as u8),
        })),
        Protocol::Pim => Some(ProtocolSpec::Pim(PimSpec {
            is_hello: pim_is_hello,
            is_join_prune: pim_is_join_prune,
            is_register: pim_is_register,
            group: group_ip,
            source: pim_source,
            rp: pim_rp,
            holdtime: holdtime_val,
            dr_priority: pim_dr_priority,
            _marker: core::marker::PhantomData,
        })),
        Protocol::Bfd => Some(ProtocolSpec::Bfd(BfdSpec {
            state: bfd_state,
            diag: bfd_diag,
            my_disc: bfd_my_disc,
            your_disc: bfd_your_disc,
            min_tx: bfd_min_tx,
            min_rx: bfd_min_rx,
            mult: bfd_mult,
            _marker: core::marker::PhantomData,
        })),
        Protocol::Openflow => Some(ProtocolSpec::Openflow(OpenflowSpec {
            version: version_byte,
            of_type: openflow_type,
            xid: of_xid,
            dpid: of_dpid,
            table_id: of_table_id,
            priority: of_priority,
            _marker: core::marker::PhantomData,
        })),
        Protocol::Dns => Some(ProtocolSpec::Dns(dns_spec)),
        Protocol::Mdns => Some(ProtocolSpec::Mdns(dns_spec)),
        Protocol::Dhcp => Some(ProtocolSpec::Dhcp(dhcp_spec)),
        Protocol::Ntp => Some(ProtocolSpec::Ntp(ntp_spec)),
        Protocol::Ptp => Some(ProtocolSpec::Ptp(ptp_spec)),
        Protocol::Radius => Some(ProtocolSpec::Radius(radius_spec)),
        Protocol::Tacacs => Some(ProtocolSpec::Tacacs(tacacs_spec)),
        Protocol::Syslog => Some(ProtocolSpec::Syslog(syslog_spec)),
        Protocol::Netflow => Some(ProtocolSpec::Netflow(netflow_spec)),
        Protocol::Ipfix => Some(ProtocolSpec::Ipfix(ipfix_spec)),
        Protocol::Sflow => Some(ProtocolSpec::Sflow(sflow_spec)),
        Protocol::Tftp => Some(ProtocolSpec::Tftp(tftp_spec)),
        Protocol::Ftp => Some(ProtocolSpec::Ftp(ftp_spec)),
        Protocol::Ssh => Some(ProtocolSpec::Ssh(ssh_spec)),
        Protocol::Telnet => Some(ProtocolSpec::Telnet(telnet_spec)),
        Protocol::Http => Some(ProtocolSpec::Http(http_spec)),
        Protocol::Http2 => Some(ProtocolSpec::Http2(http2_spec)),
        Protocol::Grpc => Some(ProtocolSpec::Grpc(grpc_spec)),
        Protocol::Websocket => Some(ProtocolSpec::Websocket(websocket_spec)),
        Protocol::Tls => Some(ProtocolSpec::Tls(tls_spec)),
        Protocol::Quic => Some(ProtocolSpec::Quic(quic_spec)),
        Protocol::Stun => Some(ProtocolSpec::Stun(stun_spec)),
        Protocol::Sip => Some(ProtocolSpec::Sip(sip_spec)),
        Protocol::Rtp => Some(ProtocolSpec::Rtp(rtp_spec)),
        Protocol::Rtsp => Some(ProtocolSpec::Rtsp(rtsp_spec)),
        Protocol::Smtp => Some(ProtocolSpec::Smtp(smtp_spec)),
        Protocol::Imap => Some(ProtocolSpec::Imap(imap_spec)),
        Protocol::Pop3 => Some(ProtocolSpec::Pop3(pop3_spec)),
        Protocol::Kerberos => Some(ProtocolSpec::Kerberos(kerberos_spec)),
        Protocol::Ldap => Some(ProtocolSpec::Ldap(ldap_spec)),
        Protocol::Smb => Some(ProtocolSpec::Smb(smb_spec)),
        Protocol::Nfs => Some(ProtocolSpec::Nfs(nfs_spec)),
        Protocol::Redis => Some(ProtocolSpec::Redis(redis_spec)),
        Protocol::Memcached => Some(ProtocolSpec::Memcached(memcached_spec)),
        Protocol::Mysql => Some(ProtocolSpec::Mysql(mysql_spec)),
        Protocol::Postgres => Some(ProtocolSpec::Postgres(postgres_spec)),
        Protocol::Mqtt => Some(ProtocolSpec::Mqtt(mqtt_spec)),
        Protocol::Coap => Some(ProtocolSpec::Coap(coap_spec)),
        Protocol::Amqp => Some(ProtocolSpec::Amqp(amqp_spec)),
        Protocol::Ssdp => Some(ProtocolSpec::Ssdp(ssdp_spec)),
        Protocol::Whois => Some(ProtocolSpec::Whois(whois_spec)),
        Protocol::Modbus => Some(ProtocolSpec::Modbus(modbus_spec)),
        Protocol::Bacnet => Some(ProtocolSpec::Bacnet(bacnet_spec)),
        Protocol::Dnp3 => Some(ProtocolSpec::Dnp3(dnp3_spec)),
        Protocol::S7comm => Some(ProtocolSpec::S7comm(s7comm_spec)),
        Protocol::Ethernetip => Some(ProtocolSpec::Ethernetip(ethernetip_spec)),
        Protocol::Opcua => Some(ProtocolSpec::Opcua(opcua_spec)),
    };

    let statement_span = (caller.span.0, stmt_end_offset - caller.span.0);

    Ok(FrameStatement {
        caller,
        dir,
        arrow: dir,
        callee,
        protocol,
        protocol_spec,
        l2,
        l3,
        l4,
        payload,
        hex_payload,
        wait,
        span: statement_span,
        raw_vlan: vlan_val,
        raw_dscp: dscp_val,
        raw_ecn: ecn_val,
        raw_ttl: ttl_val,
        raw_flowlabel: flowlabel_val,
        raw_gentrap_span: gentrap_span,
        duplicate_modifiers,
        src_port,
        dst_port,
        flags,
        seq,
        ack_num,
        win,
        urgent: urgent_val.map(|(v, _)| v),
        community,
        user,
        oid,
        sys_up_time,
        pdu_type,
        enterprise,
        agent_ip,
        gen_trap,
        spec_trap,
        engine_id,
        engine_boots,
        engine_time,
        context_name,
        auth,
        priv_param,
        varbinds,
        non_repeaters,
        max_repetitions,
        req_id,
    })
}


/// Parses a `FLOW` block definition with precision `cut_err`.
pub(crate) fn parse_flow_def<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<FlowDef<'a>> {
    let (_, flow_kw_span) = tag(Token::Flow).parse_next(input)?;
    let name = cut_err(parse_spanned_ident).parse_next(input)?;
    let _ = cut_err(tag(Token::LParen)).parse_next(input)?;

    let params: Vec<&'a str> =
        cut_err(separated(0.., parse_ident, tag(Token::Comma))).parse_next(input)?;

    let _ = cut_err(tag(Token::RParen)).parse_next(input)?;
    let _ = cut_err(tag(Token::LBrace)).parse_next(input)?;

    let statements: Vec<FrameStatement<'a>> =
        cut_err(repeat(0.., parse_frame_statement)).parse_next(input)?;

    let (_, rbrace_span) = cut_err(tag(Token::RBrace)).parse_next(input)?;

    Ok(FlowDef {
        name: name.node,
        params,
        statements,
        span: (flow_kw_span.start, rbrace_span.end - flow_kw_span.start),
    })
}

/// Parses a single argument passed to a flow invocation.
pub(crate) fn parse_argument<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<Argument<'a>> {
    let var = parse_ident(input)?;
    Ok(Argument::Variable(var))
}

/// Parses a flow invocation (e.g. `tcp_handshake(client, server)`).
pub(crate) fn parse_template_invocation<'i, 'a>(
    input: &mut Stream<'i, 'a>,
) -> PResult<TemplateInvocation<'a>> {
    let name_spanned = parse_spanned_ident(input)?;
    let _ = tag(Token::LParen).parse_next(input)?;

    let args: Vec<Argument<'a>> =
        separated(0.., parse_argument, tag(Token::Comma)).parse_next(input)?;

    let (_, rparen_span) = tag(Token::RParen).parse_next(input)?;
    Ok(TemplateInvocation {
        name: name_spanned.node,
        args,
        span: (
            name_spanned.span.0,
            rparen_span.end - name_spanned.span.0,
        ),
    })
}

/// Parses a statement inside the `COMPILE` block (loop or single invocation) with precision `cut_err`.
pub(crate) fn parse_run_statement<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<RunStatement<'a>> {
    if opt(tag(Token::Loop)).parse_next(input)?.is_some() {
        let count = cut_err(parse_u32).parse_next(input)?;
        let _ = cut_err(tag(Token::LBrace)).parse_next(input)?;
        let invocations: Vec<TemplateInvocation<'a>> =
            cut_err(repeat(0.., parse_template_invocation)).parse_next(input)?;
        let _ = cut_err(tag(Token::RBrace)).parse_next(input)?;
        Ok(RunStatement::Loop(count, invocations))
    } else {
        let inv = parse_template_invocation(input)?;
        Ok(RunStatement::Invocation(inv))
    }
}

/// Parses the entire `COMPILE` block with precision `cut_err`.
pub(crate) fn parse_compile_block<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<Vec<RunStatement<'a>>> {
    let _ = tag(Token::Compile).parse_next(input)?;
    let _ = cut_err(tag(Token::LBrace)).parse_next(input)?;
    let statements: Vec<RunStatement<'a>> =
        cut_err(repeat(0.., parse_run_statement)).parse_next(input)?;
    let _ = cut_err(tag(Token::RBrace)).parse_next(input)?;
    Ok(statements)
}

/// Represents a top-level construct parsed from the file.
pub(crate) enum TopLevel<'a> {
    /// A host definition.
    Host(HostDef<'a>),
    /// A flow definition.
    Flow(FlowDef<'a>),
    /// The compile block.
    Compile(Vec<RunStatement<'a>>),
}

/// Parses a single top-level construct (`HOST`, `FLOW`, or `COMPILE`).
pub(crate) fn parse_top_level<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<TopLevel<'a>> {
    alt((
        parse_host_def.map(TopLevel::Host),
        parse_flow_def.map(TopLevel::Flow),
        parse_compile_block.map(TopLevel::Compile),
    ))
    .parse_next(input)
}

/// Parses all top level constructs and constructs the `Program`.
pub(crate) fn parse_all<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<Program<'a>> {
    let mut hosts = Vec::new();
    let mut flows = Vec::new();
    let mut compile_block = None;

    let top_levels: Vec<TopLevel<'a>> = repeat(0.., parse_top_level).parse_next(input)?;

    for tl in top_levels {
        match tl {
            TopLevel::Host(h) => hosts.push(h),
            TopLevel::Flow(f) => flows.push(f),
            TopLevel::Compile(c) => {
                if compile_block.is_some() {
                    return Err(winnow::error::ErrMode::Cut(ContextError::new()));
                }
                compile_block = Some(c);
            }
        }
    }

    if let Some(compile_block) = compile_block {
        Ok(Program {
            hosts,
            flows,
            compile_block,
        })
    } else {
        Err(winnow::error::ErrMode::Cut(ContextError::new()))
    }
}

/// Performs semantic validation on a parsed AST, emitting spanned `CompilerError::SemanticError`.
///
/// # Checks
/// * Mixed IPv4 and IPv6 endpoints in any statement.
/// * Out-of-range fields (`VLAN > 4094`, `DSCP > 63`, `ECN > 3`, `TTL > 255`, `FLOWLABEL > 0xFFFFF`, `GENTRAP > 6`).
/// * Duplicate `HOST`, `FLOW`, or parameter declarations.
/// * Duplicate statement modifiers.
/// * Invalid cross-protocol modifiers.
pub fn validate_semantics(program: &Program, src: &str) -> Result<(), CompilerError> {
    // 1. Check duplicate HOST definitions
    let mut seen_hosts: HashMap<&str, (usize, usize)> = HashMap::new();
    for host in &program.hosts {
        if let Some(first_span) = seen_hosts.insert(host.name, host.span) {
            let _ = first_span;
            return Err(CompilerError::SemanticError {
                message: alloc::format!("Duplicate HOST declaration: '{}'", host.name),
                src: src.to_string(),
                span: host.span,
            });
        }
    }

    // 2. Check duplicate FLOW definitions and duplicate parameter declarations
    let mut seen_flows: HashMap<&str, (usize, usize)> = HashMap::new();
    for flow in &program.flows {
        if let Some(first_span) = seen_flows.insert(flow.name, flow.span) {
            let _ = first_span;
            return Err(CompilerError::SemanticError {
                message: alloc::format!("Duplicate FLOW declaration: '{}'", flow.name),
                src: src.to_string(),
                span: flow.span,
            });
        }

        let mut seen_params = HashSet::new();
        for param in &flow.params {
            if !seen_params.insert(*param) {
                return Err(CompilerError::SemanticError {
                    message: alloc::format!("Duplicate parameter '{}' in FLOW '{}'", param, flow.name),
                    src: src.to_string(),
                    span: flow.span,
                });
            }
        }

        // Validate statements inside flow
        for stmt in &flow.statements {
            // Check duplicate statement modifiers
            if let Some((mod_name, span)) = stmt.duplicate_modifiers.first() {
                return Err(CompilerError::SemanticError {
                    message: alloc::format!("Duplicate statement modifier '{}'", mod_name),
                    src: src.to_string(),
                    span: *span,
                });
            }

            // Check out-of-range fields
            if let Some((vid, span)) = stmt.raw_vlan
                && (vid == 0 || vid > 4094)
            {
                return Err(CompilerError::SemanticError {
                    message: alloc::format!("VLAN ID {} out of range (1..=4094)", vid),
                    src: src.to_string(),
                    span,
                });
            }

            if let Some((dscp, span)) = stmt.raw_dscp
                && dscp > 63
            {
                return Err(CompilerError::SemanticError {
                    message: alloc::format!("DSCP {} out of range (0..=63)", dscp),
                    src: src.to_string(),
                    span,
                });
            }

            if let Some((ecn, span)) = stmt.raw_ecn
                && ecn > 3
            {
                return Err(CompilerError::SemanticError {
                    message: alloc::format!("ECN {} out of range (0..=3)", ecn),
                    src: src.to_string(),
                    span,
                });
            }

            if let Some((ttl, span)) = stmt.raw_ttl
                && ttl > 255
            {
                return Err(CompilerError::SemanticError {
                    message: alloc::format!("TTL {} out of range (0..=255)", ttl),
                    src: src.to_string(),
                    span,
                });
            }

            if let Some((flowlabel, span)) = stmt.raw_flowlabel
                && flowlabel > 0xF_FFFF
            {
                return Err(CompilerError::SemanticError {
                    message: alloc::format!(
                        "FLOWLABEL {} out of range (0..=1048575 / 0xFFFFF)",
                        flowlabel
                    ),
                    src: src.to_string(),
                    span,
                });
            }

            if let Some(gt) = stmt.gen_trap
                && gt > 6
            {
                let span = stmt.raw_gentrap_span.unwrap_or(stmt.span);
                return Err(CompilerError::SemanticError {
                    message: alloc::format!("GENTRAP {} out of range (0..=6)", gt),
                    src: src.to_string(),
                    span,
                });
            }

            // Check duplicate statement modifiers (flags)
            let mut seen_flags = HashSet::new();
            for flag in &stmt.flags {
                if !seen_flags.insert(flag) {
                    return Err(CompilerError::SemanticError {
                        message: alloc::format!("Duplicate statement modifier: TCP flag '{:?}' specified multiple times", flag),
                        src: src.to_string(),
                        span: stmt.span,
                    });
                }
            }

            // Check payload vs hexpayload collision
            if stmt.payload.is_some() && stmt.hex_payload.is_some() {
                return Err(CompilerError::SemanticError {
                    message: "Duplicate statement modifier: cannot specify both PAYLOAD and HEXPAYLOAD".to_string(),
                    src: src.to_string(),
                    span: stmt.span,
                });
            }

            // Check cross-protocol modifiers
            match stmt.protocol {
                Protocol::Udp => {
                    if !stmt.flags.is_empty() {
                        return Err(CompilerError::SemanticError {
                            message: "Invalid cross-protocol modifier: TCP flags cannot be used with UDP".to_string(),
                            src: src.to_string(),
                            span: stmt.span,
                        });
                    }
                    if stmt.seq.is_some() || stmt.ack_num.is_some() || stmt.win.is_some() {
                        return Err(CompilerError::SemanticError {
                            message: "Invalid cross-protocol modifier: SEQ/ACKNUM/WIN cannot be used with UDP".to_string(),
                            src: src.to_string(),
                            span: stmt.span,
                        });
                    }
                    if stmt.community.is_some()
                        || stmt.user.is_some()
                        || stmt.oid.is_some()
                        || stmt.pdu_type.is_some()
                        || !stmt.varbinds.is_empty()
                    {
                        return Err(CompilerError::SemanticError {
                            message: "Invalid cross-protocol modifier: SNMP fields cannot be used with UDP".to_string(),
                            src: src.to_string(),
                            span: stmt.span,
                        });
                    }
                }
                Protocol::Tcp => {
                    if stmt.community.is_some()
                        || stmt.user.is_some()
                        || stmt.oid.is_some()
                        || stmt.pdu_type.is_some()
                        || !stmt.varbinds.is_empty()
                    {
                        return Err(CompilerError::SemanticError {
                            message: "Invalid cross-protocol modifier: SNMP fields cannot be used with TCP".to_string(),
                            src: src.to_string(),
                            span: stmt.span,
                        });
                    }
                }
                Protocol::Snmp1 => {
                    if !stmt.flags.is_empty() {
                        return Err(CompilerError::SemanticError {
                            message: "Invalid cross-protocol modifier: TCP flags cannot be used with SNMP1".to_string(),
                            src: src.to_string(),
                            span: stmt.span,
                        });
                    }
                    if stmt.user.is_some()
                        || stmt.engine_id.is_some()
                        || stmt.auth.is_some()
                        || stmt.priv_param.is_some()
                    {
                        return Err(CompilerError::SemanticError {
                            message: "Invalid cross-protocol modifier: SNMPv3 USM fields cannot be used with SNMP1".to_string(),
                            src: src.to_string(),
                            span: stmt.span,
                        });
                    }
                    if stmt.pdu_type == Some(SnmpPduType::GetBulk)
                        || stmt.pdu_type == Some(SnmpPduType::Inform)
                    {
                        return Err(CompilerError::SemanticError {
                            message: "Invalid cross-protocol modifier: GETBULK and INFORM are not supported in SNMP1".to_string(),
                            src: src.to_string(),
                            span: stmt.span,
                        });
                    }
                }
                Protocol::Snmp2 => {
                    if !stmt.flags.is_empty() {
                        return Err(CompilerError::SemanticError {
                            message: "Invalid cross-protocol modifier: TCP flags cannot be used with SNMP2".to_string(),
                            src: src.to_string(),
                            span: stmt.span,
                        });
                    }
                    if stmt.enterprise.is_some()
                        || stmt.agent_ip.is_some()
                        || stmt.gen_trap.is_some()
                        || stmt.spec_trap.is_some()
                    {
                        return Err(CompilerError::SemanticError {
                            message: "Invalid cross-protocol modifier: SNMPv1 trap fields cannot be used with SNMP2".to_string(),
                            src: src.to_string(),
                            span: stmt.span,
                        });
                    }
                    if stmt.user.is_some()
                        || stmt.engine_id.is_some()
                        || stmt.auth.is_some()
                        || stmt.priv_param.is_some()
                    {
                        return Err(CompilerError::SemanticError {
                            message: "Invalid cross-protocol modifier: SNMPv3 USM fields cannot be used with SNMP2".to_string(),
                            src: src.to_string(),
                            span: stmt.span,
                        });
                    }
                }
                Protocol::Snmp3 => {
                    if !stmt.flags.is_empty() {
                        return Err(CompilerError::SemanticError {
                            message: "Invalid cross-protocol modifier: TCP flags cannot be used with SNMP3".to_string(),
                            src: src.to_string(),
                            span: stmt.span,
                        });
                    }
                    if stmt.enterprise.is_some()
                        || stmt.agent_ip.is_some()
                        || stmt.gen_trap.is_some()
                        || stmt.spec_trap.is_some()
                    {
                        return Err(CompilerError::SemanticError {
                            message: "Invalid cross-protocol modifier: SNMPv1 trap fields cannot be used with SNMP3".to_string(),
                            src: src.to_string(),
                            span: stmt.span,
                        });
                    }
                    if stmt.community.is_some() {
                        return Err(CompilerError::SemanticError {
                            message: "Invalid cross-protocol modifier: COMMUNITY cannot be used with SNMP3 (use USER)".to_string(),
                            src: src.to_string(),
                            span: stmt.span,
                        });
                    }
                }
                _ => {}
            }
        }
    }

    // 3. Check compile block invocations and mixed IPv4/IPv6 endpoints
    let host_map: HashMap<&str, &HostDef> =
        program.hosts.iter().map(|h| (h.name, h)).collect();
    let flow_map: HashMap<&str, &FlowDef> =
        program.flows.iter().map(|f| (f.name, f)).collect();

    let check_invocation = |inv: &TemplateInvocation| -> Result<(), CompilerError> {
        let flow = flow_map.get(inv.name).ok_or_else(|| CompilerError::SemanticError {
            message: alloc::format!("Undefined flow: '{}'", inv.name),
            src: src.to_string(),
            span: inv.span,
        })?;

        if flow.params.len() != inv.args.len() {
            return Err(CompilerError::SemanticError {
                message: alloc::format!(
                    "Flow '{}' expects {} arguments, got {}",
                    flow.name,
                    flow.params.len(),
                    inv.args.len()
                ),
                src: src.to_string(),
                span: inv.span,
            });
        }

        let mut param_to_host = HashMap::new();
        for (i, param_name) in flow.params.iter().enumerate() {
            let Argument::Variable(var_name) = &inv.args[i];
            let host = host_map.get(*var_name).ok_or_else(|| CompilerError::SemanticError {
                message: alloc::format!("Undefined host: '{}'", var_name),
                src: src.to_string(),
                span: inv.span,
            })?;
            param_to_host.insert(*param_name, *host);
        }

        // Validate endpoints in flow statements
        for stmt in &flow.statements {
            let caller_host = param_to_host
                .get(stmt.caller.node)
                .ok_or_else(|| CompilerError::SemanticError {
                    message: alloc::format!(
                        "Unknown caller endpoint '{}' in flow '{}'",
                        stmt.caller.node,
                        flow.name
                    ),
                    src: src.to_string(),
                    span: stmt.span,
                })?;

            let callee_host = param_to_host
                .get(stmt.callee.node)
                .ok_or_else(|| CompilerError::SemanticError {
                    message: alloc::format!(
                        "Unknown callee endpoint '{}' in flow '{}'",
                        stmt.callee.node,
                        flow.name
                    ),
                    src: src.to_string(),
                    span: stmt.span,
                })?;

            // Check mixed IPv4 / IPv6 endpoints
            if caller_host.ip.is_ipv4() != callee_host.ip.is_ipv4() {
                return Err(CompilerError::SemanticError {
                    message: alloc::format!(
                        "Mixed IPv4 and IPv6 endpoints in statement: '{}' ({}) and '{}' ({})",
                        caller_host.name,
                        caller_host.ip,
                        callee_host.name,
                        callee_host.ip
                    ),
                    src: src.to_string(),
                    span: stmt.span,
                });
            }
        }

        Ok(())
    };

    for run_stmt in &program.compile_block {
        match run_stmt {
            RunStatement::Invocation(inv) => check_invocation(inv)?,
            RunStatement::Loop(_, invocations) => {
                for inv in invocations {
                    check_invocation(inv)?;
                }
            }
        }
    }

    Ok(())
}

/// Parses a complete FrameAssembly program from a source string and validates semantic invariants.
///
/// # Examples
/// ```
/// use frameassembly::parser::parse_program;
///
/// let input = "HOST client { IP 10.0.0.1 }\nCOMPILE {}";
/// let program = parse_program(input).unwrap();
/// assert_eq!(program.hosts.len(), 1);
/// ```
///
/// # Errors
/// Returns `CompilerError::ParseError` or `CompilerError::SemanticError` if:
/// * The input contains syntax errors.
/// * The tokens do not match the expected grammar.
/// * There are unexpected trailing tokens after the program block.
/// * Semantic rules (ranges, mixed IP versions, duplicate declarations) are violated.
pub fn parse_program<'a>(input_str: &'a str) -> Result<Program<'a>, CompilerError> {
    let tokens = crate::lexer::lex(input_str)?;
    let mut stream: Stream<'_, 'a> = &tokens;

    let program = match parse_all.parse_next(&mut stream) {
        Ok(program) => {
            if !stream.is_empty() {
                let span = stream[0].1.clone();
                return Err(CompilerError::ParseError {
                    message: "Unexpected tokens at end of file".to_string(),
                    src: input_str.to_string(),
                    span: (span.start, span.end - span.start),
                });
            }
            program
        }
        Err(e) => {
            let offset = if stream.is_empty() {
                input_str.len()..input_str.len()
            } else {
                stream[0].1.clone()
            };
            return Err(CompilerError::ParseError {
                message: alloc::format!("Syntax error: {:?}", e),
                src: input_str.to_string(),
                span: (offset.start, offset.end - offset.start),
            });
        }
    };

    validate_semantics(&program, input_str)?;

    Ok(program)
}

