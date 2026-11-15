//! Layer 2, Layer 3, Layer 4, and SNMP field accumulation for [`FrameBuilder`].
//!
//! This module implements [`FrameBuilder::apply_field`], which updates the statement accumulator's
//! intermediate fields when a [`ParsedField`] modifier is parsed from a frame statement. It handles
//! all universal timing and payload modifiers, Layer 2 Ethernet/VLAN/MPLS/ARP/LLDP/STP/LACP/EAPOL
//! fields, Layer 3 IP/ICMP/NDP/IGMP/MLD/GRE/VXLAN/GENEVE/IPsec/IKEv2/WireGuard/OSPF/BGP/RIP/VRRP/HSRP/PIM/BFD/OpenFlow
//! fields, Layer 4 TCP/UDP/SCTP fields, and SNMPv1/v2c/v3 USM/VarBind attributes, delegating
//! generic Layer 7 attributes to [`FrameBuilder::apply_l7_field`].

use crate::ast::*;
use super::fields::ParsedField;
use super::statement::FrameBuilder;

impl<'a> FrameBuilder<'a> {
    /// Applies a single [`ParsedField`] to the builder state.
    pub(crate) fn apply_field(&mut self, f: &ParsedField<'a>) {
        match f {
            ParsedField::SrcPort(v, span) => {
                if matches!(self.protocol, Some(Protocol::Netflow | Protocol::Ipfix)) {
                    let key = if self.seen_modifier_keys.contains("SRCPORT")
                        && self.netflow_spec.srcport.is_none()
                        && self.ipfix_spec.srcport.is_none()
                    {
                        "FLOW_SRCPORT"
                    } else {
                        "SRCPORT"
                    };
                    self.touch_mod(key, *span);
                    self.netflow_spec.srcport = Some(*v);
                    self.ipfix_spec.srcport = Some(*v);
                } else {
                    self.touch_mod("SRCPORT", *span);
                    self.src_port = Some(*v);
                }
            }
            ParsedField::DstPort(v, span) => {
                if matches!(self.protocol, Some(Protocol::Netflow | Protocol::Ipfix)) {
                    let key = if self.seen_modifier_keys.contains("DSTPORT")
                        && self.netflow_spec.dstport.is_none()
                        && self.ipfix_spec.dstport.is_none()
                    {
                        "FLOW_DSTPORT"
                    } else {
                        "DSTPORT"
                    };
                    self.touch_mod(key, *span);
                    self.netflow_spec.dstport = Some(*v);
                    self.ipfix_spec.dstport = Some(*v);
                } else {
                    self.touch_mod("DSTPORT", *span);
                    self.dst_port = Some(*v);
                }
            }
            ParsedField::Seq(v, span) => {
                self.touch_mod("SEQ", *span);
                self.seq = Some(*v);
                self.gre_seq = Some(*v);
                self.rtp_spec.seq = Some(*v as u16);
                self.sflow_spec.seq = Some(*v);
                self.deferred_u32_fields.push(("SEQ", *v, *span));
            }
            ParsedField::AckNum(v, span) => {
                self.touch_mod("ACKNUM", *span);
                self.ack_num = Some(*v);
            }
            ParsedField::Win(v, span) => {
                self.touch_mod("WIN", *span);
                self.win = Some(*v);
            }
            ParsedField::Payload(v_str, v_bytes, span) => {
                self.touch_mod("PAYLOAD", *span);
                self.payload = Some(v_str.clone());
                self.payload_bytes = Some(v_bytes.clone());
            }
            ParsedField::HexPayload(v, span) => {
                self.touch_mod("HEXPAYLOAD", *span);
                self.hex_payload = Some(v.clone());
            }
            ParsedField::Community(v, span) => {
                self.touch_mod("COMMUNITY", *span);
                self.community = Some(*v);
            }
            ParsedField::User(v, span) => {
                self.touch_mod("USER", *span);
                self.user = Some(*v);
                self.radius_spec.user = Some(*v);
                self.tacacs_spec.user = Some(*v);
                self.mysql_spec.user = Some(*v);
                self.postgres_spec.user = Some(*v);
            }
            ParsedField::SysUpTime(v, span) => {
                self.touch_mod("SYSUPTIME", *span);
                self.sys_up_time = Some(*v);
            }
            ParsedField::PduType(v, span) => {
                self.touch_mod("PDUTYPE", *span);
                self.pdu_type = Some(v.clone());
            }
            ParsedField::Wait(v, span) => {
                self.touch_mod("WAIT", *span);
                self.wait = Some(*v);
            }
            ParsedField::Oid(v, span) => {
                self.touch_mod("OID", *span);
                self.oid = Some(*v);
            }
            ParsedField::Flag(flag, span) => {
                self.flags.push(flag.clone());
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::Enterprise(v, span) => {
                self.touch_mod("ENTERPRISE", *span);
                self.enterprise = Some(*v);
            }
            ParsedField::AgentIp(v, span) => {
                self.touch_mod("AGENTIP", *span);
                self.agent_ip = Some(*v);
                self.sflow_spec.agent_ip = Some(*v);
            }
            ParsedField::GenTrap(v, span) => {
                self.touch_mod("GENTRAP", *span);
                self.gen_trap = Some(*v);
                self.gentrap_span = Some(*span);
            }
            ParsedField::SpecTrap(v, span) => {
                self.touch_mod("SPECTRAP", *span);
                self.spec_trap = Some(*v);
            }
            ParsedField::EngineId(v, span) => {
                self.touch_mod("ENGINEID", *span);
                self.engine_id = Some(*v);
            }
            ParsedField::EngineBoots(v, span) => {
                self.touch_mod("ENGINEBOOTS", *span);
                self.engine_boots = Some(*v);
            }
            ParsedField::EngineTime(v, span) => {
                self.touch_mod("ENGINETIME", *span);
                self.engine_time = Some(*v);
            }
            ParsedField::ContextName(v, span) => {
                self.touch_mod("CONTEXTNAME", *span);
                self.context_name = Some(*v);
            }
            ParsedField::Auth(t, p, span) => {
                self.touch_mod("AUTH", *span);
                self.auth = Some((t.clone(), *p));
            }
            ParsedField::Priv(t, p, span) => {
                self.touch_mod("PRIV", *span);
                self.priv_param = Some((t.clone(), *p));
            }
            ParsedField::VarBind(v, span) => {
                self.varbinds.push(v.clone());
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::NonRepeaters(v, span) => {
                self.touch_mod("NONREPEATERS", *span);
                self.non_repeaters = Some(*v);
            }
            ParsedField::MaxRepetitions(v, span) => {
                self.touch_mod("MAXREPETITIONS", *span);
                self.max_repetitions = Some(*v);
            }
            ParsedField::ReqId(v, span) => {
                self.touch_mod("REQID", *span);
                self.req_id = Some(*v);
                self.opcua_spec.req_id = Some(*v);
            }
            ParsedField::Vlan(v, span) => {
                self.touch_mod("VLAN", *span);
                self.vlan_val = Some((*v, *span));
            }
            ParsedField::Dscp(v, span) => {
                self.touch_mod("DSCP", *span);
                self.dscp_val = Some((*v, *span));
            }
            ParsedField::Ecn(v, span) => {
                self.touch_mod("ECN", *span);
                self.ecn_val = Some((*v, *span));
            }
            ParsedField::Ttl(v, span) => {
                self.touch_mod("TTL", *span);
                self.ttl_val = Some((*v, *span));
            }
            ParsedField::FlowLabel(v, span) => {
                self.touch_mod("FLOWLABEL", *span);
                self.flowlabel_val = Some((*v, *span));
            }
            ParsedField::Protocol(p, span) => {
                self.touch_mod("PROTOCOL", *span);
                self.protocol = Some(p.clone());
            }
            ParsedField::Pcp(v, span) => {
                self.touch_mod("PCP", *span);
                self.check_bound("PCP", *v as u64, 0, 7, *span);
                self.pcp_val = Some((*v, *span));
            }
            ParsedField::Dei(v, span) => {
                self.touch_mod("DEI", *span);
                self.check_bound("DEI", *v as u64, 0, 1, *span);
                self.dei_val = Some((*v, *span));
            }
            ParsedField::Qinq(v, span) => {
                self.touch_mod("QINQ", *span);
                self.check_bound("QinQ VLAN ID", *v as u64, 0, 4095, *span);
                self.qinq_val = Some((*v, *span));
            }
            ParsedField::InnerVlan(v, span) => {
                self.touch_mod("INNER_VLAN", *span);
                self.check_bound("QinQ innervlan ID", *v as u64, 0, 4095, *span);
                self.inner_vlan_val = Some((*v, *span));
            }
            ParsedField::Mpls(v, span) => {
                self.touch_mod("MPLS", *span);
                self.mpls_val = Some((*v, *span));
            }
            ParsedField::Exp(v, span) => {
                self.touch_mod("EXP", *span);
                self.check_bound("MPLS exp", *v as u64, 0, 7, *span);
                self.exp_val = Some((*v, *span));
            }
            ParsedField::Bos(v, span) => {
                self.touch_mod("BOS", *span);
                self.check_bound("MPLS bos", *v as u64, 0, 1, *span);
                self.bos_val = Some((*v, *span));
            }
            ParsedField::MplsTtl(v, span) => {
                self.touch_mod("MPLS_TTL", *span);
                self.mpls_ttl_val = Some((*v, *span));
            }
            ParsedField::SrcMac(v, span) => {
                self.touch_mod("SRCMAC", *span);
                self.src_mac_val = Some((*v, *span));
            }
            ParsedField::DstMac(v, span) => {
                self.touch_mod("DSTMAC", *span);
                self.dst_mac_val = Some((*v, *span));
            }
            ParsedField::EtherType(v, span) => {
                self.touch_mod("ETHERTYPE", *span);
                self.ethertype_val = Some((*v, *span));
            }
            ParsedField::IpId(v, span) => {
                self.touch_mod("IPID", *span);
                self.ipid_val = Some((*v, *span));
            }
            ParsedField::Df(span) => {
                self.touch_mod("DF", *span);
                self.df_val = true;
            }
            ParsedField::Mf(span) => {
                self.touch_mod("MF", *span);
                self.mf_val = true;
            }
            ParsedField::FragOffset(v, span) => {
                self.touch_mod("FRAGOFFSET", *span);
                self.frag_offset_val = Some((*v, *span));
            }
            ParsedField::Transport(v, span) => {
                self.touch_mod("TRANSPORT", *span);
                self.transport_val = Some(*v);
            }
            ParsedField::Urgent(v, span) => {
                self.touch_mod("URGENT", *span);
                self.urgent_val = Some((*v, *span));
            }
            ParsedField::Mss(v, span) => {
                self.touch_mod("MSS", *span);
                self.mss_val = Some((*v, *span));
            }
            ParsedField::Wscale(v, span) => {
                self.touch_mod("WSCALE", *span);
                self.wscale_val = Some((*v, *span));
            }
            ParsedField::SackPerm(span) => {
                self.touch_mod("SACK_PERM", *span);
                self.sack_perm_val = true;
            }
            ParsedField::Tsval(v, span) => {
                self.touch_mod("TSVAL", *span);
                self.tsval_val = Some((*v, *span));
            }
            ParsedField::Tsecr(v, span) => {
                self.touch_mod("TSECR", *span);
                self.tsecr_val = Some((*v, *span));
            }
            ParsedField::Vtag(v, span) => {
                self.touch_mod("VTAG", *span);
                self.vtag_val = Some((*v, *span));
            }
            ParsedField::Stream(v, span) => {
                self.touch_mod("STREAM", *span);
                self.stream_val = Some((*v, *span));
            }
            ParsedField::Ssn(v, span) => {
                self.touch_mod("SSN", *span);
                self.ssn_val = Some((*v, *span));
            }
            ParsedField::Ppid(v, span) => {
                self.touch_mod("PPID", *span);
                self.ppid_val = Some((*v, *span));
            }
            ParsedField::Chunk(v, span) => {
                self.touch_mod("CHUNK", *span);
                self.chunk_val = Some((v.clone(), *span));
            }
            ParsedField::ArpOpcode(v, span) => {
                self.touch_mod("OPCODE", *span);
                self.arp_opcode = Some(*v);
            }
            ParsedField::Gratuitous(span) => {
                self.touch_mod("GARP", *span);
                self.is_gratuitous = true;
            }
            ParsedField::Sha(v, span) => {
                self.touch_mod("SHA", *span);
                self.sha = Some(*v);
            }
            ParsedField::Spa(v, span) => {
                self.touch_mod("SPA", *span);
                self.spa = Some(*v);
            }
            ParsedField::Tha(v, span) => {
                self.touch_mod("THA", *span);
                self.tha = Some(*v);
            }
            ParsedField::Tpa(v, span) => {
                self.touch_mod("TPA", *span);
                self.tpa = Some(*v);
            }
            ParsedField::ChassisId(v, span) => {
                self.touch_mod("CHASSIS_ID", *span);
                self.chassis_id = Some(*v);
            }
            ParsedField::PortIdVal(ps, pu, span) => {
                self.touch_mod("PORT_ID", *span);
                if let Some(s) = ps {
                    self.port_id_str = Some(*s);
                }
                if let Some(u) = pu {
                    self.port_id_u16 = Some(*u);
                }
            }
            ParsedField::SysName(v, span) => {
                self.touch_mod("SYSNAME", *span);
                self.sysname = Some(*v);
            }
            ParsedField::SysDesc(v, span) => {
                self.touch_mod("SYSDESC", *span);
                self.sysdesc = Some(*v);
            }
            ParsedField::RootId(v, span) => {
                self.touch_mod("ROOT_ID", *span);
                self.root_id = Some(*v);
            }
            ParsedField::BridgeId(v, span) => {
                self.touch_mod("BRIDGE_ID", *span);
                self.bridge_id = Some(*v);
            }
            ParsedField::Cost(v, span) => {
                self.touch_mod("COST", *span);
                self.stp_cost = Some(*v);
            }
            ParsedField::MaxAge(v, span) => {
                self.touch_mod("MAX_AGE", *span);
                self.max_age = Some(*v);
            }
            ParsedField::HelloTime(v, span) => {
                self.touch_mod("HELLO_TIME", *span);
                self.hello_time = Some(*v);
                self.hsrp_hellotime = Some((*v).min(255) as u8);
                self.raw_hellotime = Some((*v, *span));
            }
            ParsedField::ForwardDelay(v, span) => {
                self.touch_mod("FORWARD_DELAY", *span);
                self.forward_delay = Some(*v);
            }
            ParsedField::Rstp(span) => {
                self.touch_mod("RSTP", *span);
                self.is_rstp = true;
            }
            ParsedField::FlagsByte(v, span) => {
                self.touch_mod("FLAGS", *span);
                self.stp_flags = Some(*v);
                self.ike_flags = Some(*v);
                self.tacacs_spec.flags = Some(*v);
                self.memcached_spec.flags = Some(*v as u32);
            }
            ParsedField::ActorSys(v, span) => {
                self.touch_mod("ACTOR_SYS", *span);
                self.actor_sys = Some(*v);
            }
            ParsedField::ActorKey(v, span) => {
                self.touch_mod("ACTOR_KEY", *span);
                self.actor_key = Some(*v);
            }
            ParsedField::ActorPort(v, span) => {
                self.touch_mod("ACTOR_PORT", *span);
                self.actor_port = Some(*v);
            }
            ParsedField::PartnerSys(v, span) => {
                self.touch_mod("PARTNER_SYS", *span);
                self.partner_sys = Some(*v);
            }
            ParsedField::PartnerKey(v, span) => {
                self.touch_mod("PARTNER_KEY", *span);
                self.partner_key = Some(*v);
            }
            ParsedField::PartnerPort(v, span) => {
                self.touch_mod("PARTNER_PORT", *span);
                self.partner_port = Some(*v);
            }
            ParsedField::ActorState(v, span) => {
                self.touch_mod("ACTOR_STATE", *span);
                self.actor_state = Some(*v);
            }
            ParsedField::PartnerState(v, span) => {
                self.touch_mod("PARTNER_STATE", *span);
                self.partner_state = Some(*v);
            }
            ParsedField::VersionByte(v, span) => {
                self.touch_mod("VERSION", *span);
                self.version_byte = Some(*v);
                self.quic_spec.version = Some(*v as u32);
            }
            ParsedField::EapolType(v, span) => {
                self.touch_mod("EAPOL_TYPE", *span);
                self.eapol_type = Some(*v);
            }
            ParsedField::EapCode(v, span) => {
                self.touch_mod("EAP_CODE", *span);
                self.eap_code = Some(*v);
            }
            ParsedField::EapId(v, span) => {
                self.touch_mod("EAP_ID", *span);
                self.eap_id = Some(*v);
            }
            ParsedField::EapMethod(v, span) => {
                self.touch_mod("EAP_METHOD", *span);
                self.eap_method = Some(*v);
            }
            ParsedField::Identity(v, span) => {
                self.touch_mod("IDENTITY", *span);
                self.identity_str = Some(*v);
            }
            ParsedField::IcmpTypeChoice(v, span) => {
                self.touch_mod("ICMP_TYPE_CHOICE", *span);
                self.icmp_type_choice = Some(*v);
            }
            ParsedField::IcmpId(v, span) => {
                self.touch_mod("ICMP_ID", *span);
                self.icmp_id_val = Some(*v);
                self.radius_spec.id = Some(*v as u8);
                self.deferred_u32_fields.push(("ICMP_ID", *v as u32, *span));
            }
            ParsedField::Gateway(v, span) => {
                self.touch_mod("GATEWAY", *span);
                self.gateway_ip = Some(*v);
            }
            ParsedField::NdpType(v, span) => {
                self.touch_mod("NDP_TYPE", *span);
                self.ndp_type = Some(*v);
            }
            ParsedField::TargetVal(ip, mac, span) => {
                self.touch_mod("TARGET", *span);
                if let Some(i) = ip {
                    self.target_ip = Some(*i);
                }
                if let Some(m) = mac {
                    self.tlla_mac = Some(*m);
                }
            }
            ParsedField::Slla(v, span) => {
                self.touch_mod("SLLA", *span);
                self.slla_mac = Some(*v);
            }
            ParsedField::Tlla(v, span) => {
                self.touch_mod("TLLA", *span);
                self.tlla_mac = Some(*v);
            }
            ParsedField::RouterLifetime(v, span) => {
                self.touch_mod("ROUTER_LIFETIME", *span);
                self.router_lifetime = Some(*v);
            }
            ParsedField::IgmpType(v, span) => {
                self.touch_mod("IGMP_TYPE", *span);
                self.igmp_type = Some(*v);
            }
            ParsedField::GroupVal(ip, g, span) => {
                self.touch_mod("GROUP", *span);
                if let Some(i) = ip {
                    self.group_ip = Some(*i);
                }
                if let Some(u) = g {
                    self.hsrp_group = Some(*u);
                }
            }
            ParsedField::MaxResp(v, span) => {
                self.touch_mod("MAX_RESP", *span);
                self.max_resp = Some(*v);
            }
            ParsedField::MldType(v, span) => {
                self.touch_mod("MLD_TYPE", *span);
                self.mld_type = Some(*v);
            }
            ParsedField::MulticastAddr(v, span) => {
                self.touch_mod("MULTICAST_ADDR", *span);
                self.multicast_addr = Some(*v);
            }
            ParsedField::MaxRespDelay(v, span) => {
                self.touch_mod("MAX_RESP_DELAY", *span);
                self.max_resp_delay = Some(*v);
            }
            ParsedField::GreKey(v, span) => {
                self.touch_mod("GRE_KEY", *span);
                self.gre_key = Some(*v);
            }
            ParsedField::GreSeq(v, span) => {
                self.touch_mod("GRE_SEQ", *span);
                self.gre_seq = Some(*v);
            }
            ParsedField::GreProto(v, span) => {
                self.touch_mod("GRE_PROTO", *span);
                self.gre_proto = Some(*v);
            }
            ParsedField::ChecksumFlag(span) => {
                self.touch_mod("CHECKSUM", *span);
                self.gre_checksum = true;
            }
            ParsedField::Vni(v, span) => {
                self.touch_mod("VNI", *span);
                self.vni_val = Some(*v);
            }
            ParsedField::OptClass(v, span) => {
                self.touch_mod("OPT_CLASS", *span);
                self.opt_class = Some(*v);
            }
            ParsedField::OptType(v, span) => {
                self.touch_mod("OPT_TYPE", *span);
                self.opt_type = Some(*v);
            }
            ParsedField::ProtocolType(v, span) => {
                self.touch_mod("PROTOCOL_TYPE", *span);
                self.protocol_type = Some(*v);
            }
            ParsedField::Spi(v, span) => {
                self.touch_mod("SPI", *span);
                self.spi_val = Some(*v);
            }
            ParsedField::Iv(v, span) => {
                self.touch_mod("IV", *span);
                self.iv_val = Some(v.clone());
            }
            ParsedField::Icv(v, span) => {
                self.touch_mod("ICV", *span);
                self.icv_val = Some(v.clone());
            }
            ParsedField::NextHeader(v, span) => {
                self.touch_mod("NEXT_HEADER", *span);
                self.next_header_val = Some(*v);
            }
            ParsedField::InitiatorSpi(v, span) => {
                self.touch_mod("INITIATOR_SPI", *span);
                self.initiator_spi = Some(*v);
            }
            ParsedField::ResponderSpi(v, span) => {
                self.touch_mod("RESPONDER_SPI", *span);
                self.responder_spi = Some(*v);
            }
            ParsedField::IkeExchange(v, span) => {
                self.touch_mod("IKE_EXCHANGE", *span);
                self.ike_exchange = Some(*v);
            }
            ParsedField::MsgId(v, span) => {
                self.touch_mod("MSG_ID", *span);
                self.ike_msgid = Some(*v);
                self.ldap_spec.msgid = Some(*v as i32);
                self.coap_spec.msgid = Some(*v as u16);
                self.smb_spec.msgid = Some(*v as u64);
                self.deferred_u32_fields.push(("MSGID", *v, *span));
            }
            ParsedField::NextPayload(v, span) => {
                self.touch_mod("NEXT_PAYLOAD", *span);
                self.next_payload = Some(*v);
            }
            ParsedField::WireguardType(v, span) => {
                self.touch_mod("WG_TYPE", *span);
                self.wireguard_type = Some(*v);
            }
            ParsedField::Sender(v, span) => {
                self.touch_mod("SENDER", *span);
                self.wg_sender = Some(*v);
            }
            ParsedField::Receiver(v, span) => {
                self.touch_mod("RECEIVER", *span);
                self.wg_receiver = Some(*v);
            }
            ParsedField::Counter(v, span) => {
                self.touch_mod("COUNTER", *span);
                self.wg_counter = Some(*v);
            }
            ParsedField::OspfType(v, span) => {
                self.touch_mod("OSPF_TYPE", *span);
                self.ospf_type = Some(*v);
            }
            ParsedField::HelloWord(span) => {
                self.pim_is_hello = true;
                if self.ospf_type.is_none() {
                    self.ospf_type = Some(OspfType::Hello);
                }
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::RouterId(v, span) => {
                self.touch_mod("ROUTER_ID", *span);
                self.router_id_ip = Some(*v);
            }
            ParsedField::AreaId(v, span) => {
                self.touch_mod("AREA_ID", *span);
                self.area_id_val = Some(*v);
            }
            ParsedField::HelloInterval(v, span) => {
                self.touch_mod("HELLO_INTERVAL", *span);
                self.hello_interval = Some(*v);
            }
            ParsedField::DeadInterval(v, span) => {
                self.touch_mod("DEAD_INTERVAL", *span);
                self.dead_interval = Some(*v);
            }
            ParsedField::PriorityVal(v, span) => {
                self.touch_mod("PRIORITY", *span);
                self.priority_val = Some((*v, *span));
                self.of_priority = Some(*v);
            }
            ParsedField::BgpType(v, span) => {
                self.touch_mod("BGP_TYPE", *span);
                self.bgp_type = Some(*v);
            }
            ParsedField::Asn(v, span) => {
                self.touch_mod("ASN", *span);
                self.asn_val = Some(*v);
            }
            ParsedField::HoldTime(v, span) => {
                self.touch_mod("HOLD_TIME", *span);
                self.holdtime_val = Some((*v, *span));
            }
            ParsedField::BgpId(v, span) => {
                self.touch_mod("BGP_ID", *span);
                self.bgpid_ip = Some(*v);
            }
            ParsedField::PrefixVal(ip, st, span) => {
                self.touch_mod("PREFIX", *span);
                if let Some(i) = ip {
                    self.rip_prefix = Some(*i);
                }
                if let Some(s) = st {
                    self.prefix_str = Some(*s);
                }
            }
            ParsedField::NextHop(v, span) => {
                self.touch_mod("NEXT_HOP", *span);
                self.nexthop_ip = Some(*v);
            }
            ParsedField::Metric(v, span) => {
                self.touch_mod("METRIC", *span);
                self.rip_metric = Some(*v);
            }
            ParsedField::TagVal(u, s, span) => {
                self.touch_mod("TAG", *span);
                if let Some(v) = u {
                    self.rip_tag = Some(*v);
                }
                if let Some(str_val) = s {
                    self.imap_spec.tag = Some(*str_val);
                    self.nfs_spec.tag = Some(*str_val);
                }
            }
            ParsedField::Vrid(v, span) => {
                self.touch_mod("VRID", *span);
                self.vrid_val = Some(*v);
                self.deferred_u32_fields.push(("VRID", *v as u32, *span));
            }
            ParsedField::AdvInt(v, span) => {
                self.touch_mod("ADV_INT", *span);
                self.adv_int_val = Some(*v);
            }
            ParsedField::Vip(v, span) => {
                self.touch_mod("VIP", *span);
                self.vip_ip = Some(*v);
            }
            ParsedField::HsrpState(v, span) => {
                self.touch_mod("STATE", *span);
                self.hsrp_state = Some(*v);
                self.bfd_state = Some(*v);
            }
            ParsedField::PimJoinPrune(span) => {
                self.touch_mod("JOIN_PRUNE", *span);
                self.pim_is_join_prune = true;
            }
            ParsedField::PimRegister(span) => {
                self.touch_mod("REGISTER", *span);
                self.pim_is_register = true;
            }
            ParsedField::SourceIp(v, span) => {
                self.touch_mod("SOURCE", *span);
                self.pim_source = Some(*v);
            }
            ParsedField::Rp(v, span) => {
                self.touch_mod("RP", *span);
                self.pim_rp = Some(*v);
            }
            ParsedField::DrPriority(v, span) => {
                self.touch_mod("DR_PRIORITY", *span);
                self.pim_dr_priority = Some(*v);
            }
            ParsedField::Diag(v, span) => {
                self.touch_mod("DIAG", *span);
                self.bfd_diag = Some(*v);
            }
            ParsedField::MyDisc(v, span) => {
                self.touch_mod("MY_DISC", *span);
                self.bfd_my_disc = Some(*v);
            }
            ParsedField::YourDisc(v, span) => {
                self.touch_mod("YOUR_DISC", *span);
                self.bfd_your_disc = Some(*v);
            }
            ParsedField::MinTx(v, span) => {
                self.touch_mod("MIN_TX", *span);
                self.bfd_min_tx = Some(*v);
            }
            ParsedField::MinRx(v, span) => {
                self.touch_mod("MIN_RX", *span);
                self.bfd_min_rx = Some(*v);
            }
            ParsedField::Mult(v, span) => {
                self.touch_mod("MULT", *span);
                self.bfd_mult = Some(*v);
            }
            ParsedField::OpenflowType(v, span) => {
                self.touch_mod("OPENFLOW_TYPE", *span);
                self.openflow_type = Some(*v);
            }
            ParsedField::Xid(v, span) => {
                self.touch_mod("XID", *span);
                self.of_xid = Some(*v);
                self.dhcp_spec.xid = Some(*v);
                self.nfs_spec.xid = Some(*v);
            }
            ParsedField::Dpid(v, span) => {
                self.touch_mod("DPID", *span);
                self.of_dpid = Some(*v);
            }
            ParsedField::TableId(v, span) => {
                self.touch_mod("TABLE_ID", *span);
                self.of_table_id = Some(*v);
            }
            ParsedField::L7StringField(..)
            | ParsedField::L7U32Field(..)
            | ParsedField::L7U64Field(..)
            | ParsedField::L7IpField(..)
            | ParsedField::L7MacField(..)
            | ParsedField::L7Flag(..)
            | ParsedField::L7Header(..) => self.apply_l7_field(f),
        }
    }
}
