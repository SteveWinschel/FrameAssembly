//! Protocol-scoped field representations and modifier dispatch for FrameAssembly statements.
//!
//! This module defines the [`ParsedField`] intermediate representation produced by all Layer 2
//! through Layer 7 combinator parsers, along with [`parse_universal_field`],
//! [`dispatch_protocol_field`], and [`parse_fallback_field`]. By dispatching to the active
//! protocol's field parser before falling back to cross-layer combinators, shared keywords
//! (`COOKIE`, `DATA`, `VALUE`, `VERSION`, `STATUS`, `TOKEN`, `MSGID`, `GET`, `SET`, `RESPONSE`,
//! `REQID`, `ECHO_REPLY`, `QUERY`, `REPORT`, `REQUEST`, `REPLY`, `KEEPALIVE`) never shadow one
//! another across protocol boundaries.

use alloc::string::String;
use alloc::vec::Vec;
use core::net::IpAddr;

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err, opt};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;

use super::{
    Stream, l2, l3, l4, l7, parse_hex_payload, parse_mac, parse_string_lit, parse_u8, parse_u16,
    parse_u32, snmp, tag,
};

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
    /// HELLO keyword (shared between OSPF, PIM, and OpenFlow).
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

/// Parses a `WAIT <u32><unit>` modifier.
pub(crate) fn parse_wait<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
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
}

/// Parses a `PAYLOAD <string>` modifier.
pub(crate) fn parse_payload<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    let ((_, s), v) = (tag(Token::Payload), cut_err(parse_string_lit)).parse_next(input)?;
    Ok(ParsedField::Payload(v, (s.start, s.end - s.start)))
}

/// Parses a `HEXPAYLOAD <string>` modifier.
pub(crate) fn parse_hex_payload_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    let ((_, s), v) = (tag(Token::HexPayload), cut_err(parse_hex_payload)).parse_next(input)?;
    Ok(ParsedField::HexPayload(v, (s.start, s.end - s.start)))
}

/// Parses universal frame modifiers (timing, payload, L2/L3/L4 header fields).
pub(crate) fn parse_universal_field<'i, 'a>(
    input: &mut Stream<'i, 'a>,
    current_protocol: Option<&Protocol>,
) -> PResult<ParsedField<'a>> {
    // For CoAP, DHCP, TFTP, and SIP, ACK and RST are protocol-specific message types or methods rather than TCP flags.
    if matches!(
        current_protocol,
        Some(Protocol::Coap | Protocol::Dhcp | Protocol::Tftp | Protocol::Sip)
    ) && let Some((tok, _, _)) = input.first()
        && matches!(tok, Token::Ack | Token::Rst)
    {
        return Err(winnow::error::ErrMode::Backtrack(
            winnow::error::ContextError::new(),
        ));
    }

    alt((
        alt((
            parse_wait,
            parse_payload,
            parse_hex_payload_field,
            (tag(Token::SrcMac), cut_err(parse_mac))
                .map(|((_, s), v)| ParsedField::SrcMac(v, (s.start, s.end - s.start))),
            (tag(Token::DstMac), cut_err(parse_mac))
                .map(|((_, s), v)| ParsedField::DstMac(v, (s.start, s.end - s.start))),
            (tag(Token::EtherType), cut_err(parse_u16))
                .map(|((_, s), v)| ParsedField::EtherType(v, (s.start, s.end - s.start))),
            (tag(Token::Vlan), opt(parse_u32))
                .map(|((_, s), v)| ParsedField::Vlan(v.unwrap_or(1), (s.start, s.end - s.start))),
            (tag(Token::Pcp), cut_err(parse_u8))
                .map(|((_, s), v)| ParsedField::Pcp(v, (s.start, s.end - s.start))),
            (tag(Token::Dei), cut_err(parse_u8))
                .map(|((_, s), v)| ParsedField::Dei(v, (s.start, s.end - s.start))),
        )),
        alt((
            (tag(Token::Qinq), opt(parse_u16))
                .map(|((_, s), v)| ParsedField::Qinq(v.unwrap_or(1), (s.start, s.end - s.start))),
            (tag(Token::InnerVlan), cut_err(parse_u16))
                .map(|((_, s), v)| ParsedField::InnerVlan(v, (s.start, s.end - s.start))),
            (tag(Token::Mpls), opt(parse_u32))
                .map(|((_, s), v)| ParsedField::Mpls(v.unwrap_or(0), (s.start, s.end - s.start))),
            (tag(Token::Exp), cut_err(parse_u8))
                .map(|((_, s), v)| ParsedField::Exp(v, (s.start, s.end - s.start))),
            (tag(Token::Bos), cut_err(parse_u8))
                .map(|((_, s), v)| ParsedField::Bos(v, (s.start, s.end - s.start))),
            (tag(Token::MplsTtl), cut_err(parse_u8))
                .map(|((_, s), v)| ParsedField::MplsTtl(v, (s.start, s.end - s.start))),
        )),
        alt((
            (tag(Token::Dscp), cut_err(parse_u32))
                .map(|((_, s), v)| ParsedField::Dscp(v, (s.start, s.end - s.start))),
            (tag(Token::Ecn), cut_err(parse_u32))
                .map(|((_, s), v)| ParsedField::Ecn(v, (s.start, s.end - s.start))),
            (tag(Token::Ttl), cut_err(parse_u32))
                .map(|((_, s), v)| ParsedField::Ttl(v, (s.start, s.end - s.start))),
            (tag(Token::FlowLabel), cut_err(parse_u32))
                .map(|((_, s), v)| ParsedField::FlowLabel(v, (s.start, s.end - s.start))),
            (tag(Token::IpId), cut_err(parse_u16))
                .map(|((_, s), v)| ParsedField::IpId(v, (s.start, s.end - s.start))),
            tag(Token::Df).map(|(_, s)| ParsedField::Df((s.start, s.len()))),
            tag(Token::Mf).map(|(_, s)| ParsedField::Mf((s.start, s.len()))),
            (tag(Token::FragOffset), cut_err(parse_u16))
                .map(|((_, s), v)| ParsedField::FragOffset(v, (s.start, s.end - s.start))),
            (tag(Token::NextHeader), cut_err(parse_u8))
                .map(|((_, s), v)| ParsedField::NextHeader(v, (s.start, s.end - s.start))),
        )),
        alt((
            (tag(Token::SrcPort), cut_err(parse_u16))
                .map(|((_, s), v)| ParsedField::SrcPort(v, (s.start, s.end - s.start))),
            (tag(Token::DstPort), cut_err(parse_u16))
                .map(|((_, s), v)| ParsedField::DstPort(v, (s.start, s.end - s.start))),
            (
                tag(Token::Transport),
                cut_err(alt((
                    tag(Token::Tcp).value(TransportProto::Tcp),
                    tag(Token::Udp).value(TransportProto::Udp),
                ))),
            )
                .map(|((_, s), v)| ParsedField::Transport(v, (s.start, s.end - s.start))),
            (tag(Token::Seq), cut_err(parse_u32))
                .map(|((_, s), v)| ParsedField::Seq(v, (s.start, s.end - s.start))),
            (tag(Token::AckNum), cut_err(parse_u32))
                .map(|((_, s), v)| ParsedField::AckNum(v, (s.start, s.end - s.start))),
            (tag(Token::Win), cut_err(parse_u16))
                .map(|((_, s), v)| ParsedField::Win(v, (s.start, s.end - s.start))),
            (tag(Token::Window), cut_err(parse_u16))
                .map(|((_, s), v)| ParsedField::Win(v, (s.start, s.end - s.start))),
            (tag(Token::Urgent), cut_err(parse_u16))
                .map(|((_, s), v)| ParsedField::Urgent(v, (s.start, s.end - s.start))),
        )),
        alt((
            (tag(Token::Mss), cut_err(parse_u16))
                .map(|((_, s), v)| ParsedField::Mss(v, (s.start, s.end - s.start))),
            (tag(Token::Wscale), cut_err(parse_u8))
                .map(|((_, s), v)| ParsedField::Wscale(v, (s.start, s.end - s.start))),
            tag(Token::SackPerm).map(|(_, s)| ParsedField::SackPerm((s.start, s.len()))),
            (tag(Token::Tsval), cut_err(parse_u32))
                .map(|((_, s), v)| ParsedField::Tsval(v, (s.start, s.end - s.start))),
            (tag(Token::Tsecr), cut_err(parse_u32))
                .map(|((_, s), v)| ParsedField::Tsecr(v, (s.start, s.end - s.start))),
        )),
        alt((
            tag(Token::Syn).map(|(_, s)| ParsedField::Flag(TcpFlag::Syn, (s.start, s.len()))),
            tag(Token::Ack).map(|(_, s)| ParsedField::Flag(TcpFlag::Ack, (s.start, s.len()))),
            tag(Token::Fin).map(|(_, s)| ParsedField::Flag(TcpFlag::Fin, (s.start, s.len()))),
            tag(Token::Rst).map(|(_, s)| ParsedField::Flag(TcpFlag::Rst, (s.start, s.len()))),
            tag(Token::Psh).map(|(_, s)| ParsedField::Flag(TcpFlag::Psh, (s.start, s.len()))),
            tag(Token::Urg).map(|(_, s)| ParsedField::Flag(TcpFlag::Urg, (s.start, s.len()))),
            tag(Token::Ece).map(|(_, s)| ParsedField::Flag(TcpFlag::Ece, (s.start, s.len()))),
            tag(Token::Cwr).map(|(_, s)| ParsedField::Flag(TcpFlag::Cwr, (s.start, s.len()))),
        )),
    ))
    .parse_next(input)
}

/// Dispatches directly to the active protocol's combinator parser to prevent cross-protocol shadowing.
pub(crate) fn dispatch_protocol_field<'i, 'a>(
    proto: &Protocol,
    input: &mut Stream<'i, 'a>,
) -> PResult<ParsedField<'a>> {
    match proto {
        Protocol::Arp => l2::parse_arp_field(input),
        Protocol::Vlan => l2::parse_vlan_field(input),
        Protocol::Qinq => l2::parse_qinq_field(input),
        Protocol::Mpls => l2::parse_mpls_field(input),
        Protocol::Lldp => l2::parse_lldp_field(input),
        Protocol::Stp => l2::parse_stp_field(input),
        Protocol::Lacp => l2::parse_lacp_field(input),
        Protocol::Eapol => l2::parse_eapol_field(input),

        Protocol::Icmp => l3::parse_icmp_field(input),
        Protocol::Ndp => l3::parse_ndp_field(input),
        Protocol::Igmp => l3::parse_igmp_field(input),
        Protocol::Mld => l3::parse_mld_field(input),
        Protocol::Gre => l3::parse_gre_field(input),
        Protocol::Vxlan => l3::parse_vxlan_field(input),
        Protocol::Geneve => l3::parse_geneve_field(input),
        Protocol::Ipsec => l3::parse_ipsec_field(input),
        Protocol::Esp => alt((l3::parse_esp_field, l3::parse_ipsec_field)).parse_next(input),
        Protocol::Ah => alt((l3::parse_ah_field, l3::parse_ipsec_field)).parse_next(input),
        Protocol::Ikev2 => l3::parse_ikev2_field(input),
        Protocol::Wireguard => l3::parse_wireguard_field(input),
        Protocol::Ospf => l3::parse_ospf_field(input),
        Protocol::Bgp => l3::parse_bgp_field(input),
        Protocol::Rip => l3::parse_rip_field(input),
        Protocol::Vrrp => l3::parse_vrrp_field(input),
        Protocol::Hsrp => l3::parse_hsrp_field(input),
        Protocol::Pim => l3::parse_pim_field(input),
        Protocol::Bfd => l3::parse_bfd_field(input),
        Protocol::Openflow => l3::parse_openflow_field(input),

        Protocol::Tcp => l4::parse_tcp_field(input),
        Protocol::Udp => l4::parse_udp_field(input),
        Protocol::Sctp => l4::parse_sctp_field(input),

        Protocol::Snmp1 | Protocol::Snmp2 | Protocol::Snmp3 => snmp::parse_snmp_field(input),

        Protocol::Amqp => l7::parse_amqp_field(input),
        Protocol::Bacnet => l7::parse_bacnet_field(input),
        Protocol::Coap => l7::parse_coap_field(input),
        Protocol::Dhcp => l7::parse_dhcp_field(input),
        Protocol::Dnp3 => l7::parse_dnp3_field(input),
        Protocol::Dns => l7::parse_dns_field(input),
        Protocol::Ethernetip => l7::parse_ethernetip_field(input),
        Protocol::Ftp => l7::parse_ftp_field(input),
        Protocol::Grpc => l7::parse_grpc_field(input),
        Protocol::Http => l7::parse_http_field(input),
        Protocol::Http2 => l7::parse_http2_field(input),
        Protocol::Imap => l7::parse_imap_field(input),
        Protocol::Ipfix => l7::parse_ipfix_field(input),
        Protocol::Kerberos => l7::parse_kerberos_field(input),
        Protocol::Ldap => l7::parse_ldap_field(input),
        Protocol::Mdns => l7::parse_mdns_field(input),
        Protocol::Memcached => l7::parse_memcached_field(input),
        Protocol::Modbus => l7::parse_modbus_field(input),
        Protocol::Mqtt => l7::parse_mqtt_field(input),
        Protocol::Mysql => l7::parse_mysql_field(input),
        Protocol::Netflow => l7::parse_netflow_field(input),
        Protocol::Nfs => l7::parse_nfs_field(input),
        Protocol::Ntp => l7::parse_ntp_field(input),
        Protocol::Opcua => l7::parse_opcua_field(input),
        Protocol::Pop3 => l7::parse_pop3_field(input),
        Protocol::Postgres => l7::parse_postgres_field(input),
        Protocol::Ptp => l7::parse_ptp_field(input),
        Protocol::Quic => l7::parse_quic_field(input),
        Protocol::Radius => l7::parse_radius_field(input),
        Protocol::Redis => l7::parse_redis_field(input),
        Protocol::Rtp => l7::parse_rtp_field(input),
        Protocol::Rtsp => l7::parse_rtsp_field(input),
        Protocol::S7comm => l7::parse_s7comm_field(input),
        Protocol::Sflow => l7::parse_sflow_field(input),
        Protocol::Sip => l7::parse_sip_field(input),
        Protocol::Smb => l7::parse_smb_field(input),
        Protocol::Smtp => l7::parse_smtp_field(input),
        Protocol::Ssdp => l7::parse_ssdp_field(input),
        Protocol::Ssh => l7::parse_ssh_field(input),
        Protocol::Stun => l7::parse_stun_field(input),
        Protocol::Syslog => l7::parse_syslog_field(input),
        Protocol::Tacacs => l7::parse_tacacs_field(input),
        Protocol::Telnet => l7::parse_telnet_field(input),
        Protocol::Tftp => l7::parse_tftp_field(input),
        Protocol::Tls => l7::parse_tls_field(input),
        Protocol::Websocket => l7::parse_websocket_field(input),
        Protocol::Whois => l7::parse_whois_field(input),
    }
}

/// Fallback parser across all L2, L3, L4, SNMP, and L7 protocol and field parsers.
pub(crate) fn parse_fallback_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        l2::parse_l2_field,
        l3::parse_l3_field,
        l4::parse_l4_field,
        snmp::parse_snmp_field,
        l7::parse_l7_field,
    ))
    .parse_next(input)
}
