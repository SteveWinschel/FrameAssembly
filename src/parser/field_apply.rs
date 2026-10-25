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
                self.record_mod("SRCPORT", *span);
                self.src_port = Some(*v);
                self.netflow_spec.srcport = Some(*v);
                self.ipfix_spec.srcport = Some(*v);
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::DstPort(v, span) => {
                self.record_mod("DSTPORT", *span);
                self.dst_port = Some(*v);
                self.netflow_spec.dstport = Some(*v);
                self.ipfix_spec.dstport = Some(*v);
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::Seq(v, span) => {
                self.record_mod("SEQ", *span);
                self.seq = Some(*v);
                self.gre_seq = Some(*v);
                self.tacacs_spec.seq = Some(*v as u8);
                self.rtp_spec.seq = Some(*v as u16);
                self.sflow_spec.seq = Some(*v);
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::AckNum(v, span) => {
                self.record_mod("ACKNUM", *span);
                self.ack_num = Some(*v);
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::Win(v, span) => {
                self.record_mod("WIN", *span);
                self.win = Some(*v);
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::Payload(v, span) => {
                self.record_mod("PAYLOAD", *span);
                self.payload = Some(v.clone());
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::HexPayload(v, span) => {
                self.record_mod("HEXPAYLOAD", *span);
                self.hex_payload = Some(v.clone());
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::Community(v, span) => {
                self.record_mod("COMMUNITY", *span);
                self.community = Some(*v);
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::User(v, span) => {
                self.record_mod("USER", *span);
                self.user = Some(*v);
                self.radius_spec.user = Some(*v);
                self.tacacs_spec.user = Some(*v);
                self.mysql_spec.user = Some(*v);
                self.postgres_spec.user = Some(*v);
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::SysUpTime(v, span) => {
                self.record_mod("SYSUPTIME", *span);
                self.sys_up_time = Some(*v);
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::PduType(v, span) => {
                self.record_mod("PDUTYPE", *span);
                self.pdu_type = Some(v.clone());
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::Wait(v, span) => {
                self.record_mod("WAIT", *span);
                self.wait = Some(*v);
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::Oid(v, span) => {
                self.record_mod("OID", *span);
                self.oid = Some(*v);
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::Flag(flag, span) => {
                self.flags.push(flag.clone());
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::Enterprise(v, span) => {
                self.record_mod("ENTERPRISE", *span);
                self.enterprise = Some(*v);
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::AgentIp(v, span) => {
                self.record_mod("AGENTIP", *span);
                self.agent_ip = Some(*v);
                self.sflow_spec.agent_ip = Some(*v);
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::GenTrap(v, span) => {
                self.record_mod("GENTRAP", *span);
                self.gen_trap = Some(*v);
                self.gentrap_span = Some(*span);
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::SpecTrap(v, span) => {
                self.record_mod("SPECTRAP", *span);
                self.spec_trap = Some(*v);
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::EngineId(v, span) => {
                self.record_mod("ENGINEID", *span);
                self.engine_id = Some(*v);
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::EngineBoots(v, span) => {
                self.record_mod("ENGINEBOOTS", *span);
                self.engine_boots = Some(*v);
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::EngineTime(v, span) => {
                self.record_mod("ENGINETIME", *span);
                self.engine_time = Some(*v);
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::ContextName(v, span) => {
                self.record_mod("CONTEXTNAME", *span);
                self.context_name = Some(*v);
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::Auth(t, p, span) => {
                self.record_mod("AUTH", *span);
                self.auth = Some((t.clone(), *p));
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::Priv(t, p, span) => {
                self.record_mod("PRIV", *span);
                self.priv_param = Some((t.clone(), *p));
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::VarBind(v, span) => {
                self.varbinds.push(v.clone());
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::NonRepeaters(v, span) => {
                self.record_mod("NONREPEATERS", *span);
                self.non_repeaters = Some(*v);
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::MaxRepetitions(v, span) => {
                self.record_mod("MAXREPETITIONS", *span);
                self.max_repetitions = Some(*v);
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::ReqId(v, span) => {
                self.record_mod("REQID", *span);
                self.req_id = Some(*v);
                self.opcua_spec.req_id = Some(*v);
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::Vlan(v, span) => {
                self.record_mod("VLAN", *span);
                self.vlan_val = Some((*v, *span));
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::Dscp(v, span) => {
                self.record_mod("DSCP", *span);
                self.dscp_val = Some((*v, *span));
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::Ecn(v, span) => {
                self.record_mod("ECN", *span);
                self.ecn_val = Some((*v, *span));
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::Ttl(v, span) => {
                self.record_mod("TTL", *span);
                self.ttl_val = Some((*v, *span));
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::FlowLabel(v, span) => {
                self.record_mod("FLOWLABEL", *span);
                self.flowlabel_val = Some((*v, *span));
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::Protocol(p, span) => {
                self.record_mod("PROTOCOL", *span);
                self.protocol = Some(p.clone());
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::Pcp(v, span) => {
                self.record_mod("PCP", *span);
                self.pcp_val = Some((*v, *span));
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::Dei(v, span) => {
                self.record_mod("DEI", *span);
                self.dei_val = Some((*v, *span));
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::Qinq(v, span) => {
                self.record_mod("QINQ", *span);
                self.qinq_val = Some((*v, *span));
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::InnerVlan(v, span) => {
                self.record_mod("INNER_VLAN", *span);
                self.inner_vlan_val = Some((*v, *span));
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::Mpls(v, span) => {
                self.record_mod("MPLS", *span);
                self.mpls_val = Some((*v, *span));
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::Exp(v, span) => {
                self.record_mod("EXP", *span);
                self.exp_val = Some((*v, *span));
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::Bos(v, span) => {
                self.record_mod("BOS", *span);
                self.bos_val = Some((*v, *span));
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::MplsTtl(v, span) => {
                self.record_mod("MPLS_TTL", *span);
                self.mpls_ttl_val = Some((*v, *span));
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::SrcMac(v, span) => {
                self.record_mod("SRCMAC", *span);
                self.src_mac_val = Some((*v, *span));
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::DstMac(v, span) => {
                self.record_mod("DSTMAC", *span);
                self.dst_mac_val = Some((*v, *span));
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::EtherType(v, span) => {
                self.record_mod("ETHERTYPE", *span);
                self.ethertype_val = Some((*v, *span));
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::IpId(v, span) => {
                self.record_mod("IPID", *span);
                self.ipid_val = Some((*v, *span));
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::Df(span) => {
                self.record_mod("DF", *span);
                self.df_val = true;
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::Mf(span) => {
                self.record_mod("MF", *span);
                self.mf_val = true;
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::FragOffset(v, span) => {
                self.record_mod("FRAGOFFSET", *span);
                self.frag_offset_val = Some((*v, *span));
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::Transport(v, span) => {
                self.record_mod("TRANSPORT", *span);
                self.transport_val = Some(*v);
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::Urgent(v, span) => {
                self.record_mod("URGENT", *span);
                self.urgent_val = Some((*v, *span));
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::Mss(v, span) => {
                self.record_mod("MSS", *span);
                self.mss_val = Some((*v, *span));
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::Wscale(v, span) => {
                self.record_mod("WSCALE", *span);
                self.wscale_val = Some((*v, *span));
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::SackPerm(span) => {
                self.record_mod("SACK_PERM", *span);
                self.sack_perm_val = true;
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::Tsval(v, span) => {
                self.record_mod("TSVAL", *span);
                self.tsval_val = Some((*v, *span));
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::Tsecr(v, span) => {
                self.record_mod("TSECR", *span);
                self.tsecr_val = Some((*v, *span));
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::Vtag(v, span) => {
                self.record_mod("VTAG", *span);
                self.vtag_val = Some((*v, *span));
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::Stream(v, span) => {
                self.record_mod("STREAM", *span);
                self.stream_val = Some((*v, *span));
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::Ssn(v, span) => {
                self.record_mod("SSN", *span);
                self.ssn_val = Some((*v, *span));
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::Ppid(v, span) => {
                self.record_mod("PPID", *span);
                self.ppid_val = Some((*v, *span));
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::Chunk(v, span) => {
                self.record_mod("CHUNK", *span);
                self.chunk_val = Some((v.clone(), *span));
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::ArpOpcode(v, span) => {
                self.record_mod("OPCODE", *span);
                self.arp_opcode = Some(*v);
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::Gratuitous(span) => {
                self.record_mod("GARP", *span);
                self.is_gratuitous = true;
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::Sha(v, span) => {
                self.record_mod("SHA", *span);
                self.sha = Some(*v);
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::Spa(v, span) => {
                self.record_mod("SPA", *span);
                self.spa = Some(*v);
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::Tha(v, span) => {
                self.record_mod("THA", *span);
                self.tha = Some(*v);
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::Tpa(v, span) => {
                self.record_mod("TPA", *span);
                self.tpa = Some(*v);
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::ChassisId(v, span) => {
                self.record_mod("CHASSIS_ID", *span);
                self.chassis_id = Some(*v);
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::PortIdVal(ps, pu, span) => {
                self.record_mod("PORT_ID", *span);
                if let Some(s) = ps {
                    self.port_id_str = Some(*s);
                }
                if let Some(u) = pu {
                    self.port_id_u16 = Some(*u);
                }
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::SysName(v, span) => {
                self.record_mod("SYSNAME", *span);
                self.sysname = Some(*v);
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::SysDesc(v, span) => {
                self.record_mod("SYSDESC", *span);
                self.sysdesc = Some(*v);
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::RootId(v, span) => {
                self.record_mod("ROOT_ID", *span);
                self.root_id = Some(*v);
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::BridgeId(v, span) => {
                self.record_mod("BRIDGE_ID", *span);
                self.bridge_id = Some(*v);
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::Cost(v, span) => {
                self.record_mod("COST", *span);
                self.stp_cost = Some(*v);
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::MaxAge(v, span) => {
                self.record_mod("MAX_AGE", *span);
                self.max_age = Some(*v);
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::HelloTime(v, span) => {
                self.record_mod("HELLO_TIME", *span);
                self.hello_time = Some(*v);
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::ForwardDelay(v, span) => {
                self.record_mod("FORWARD_DELAY", *span);
                self.forward_delay = Some(*v);
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::Rstp(span) => {
                self.record_mod("RSTP", *span);
                self.is_rstp = true;
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::FlagsByte(v, span) => {
                self.record_mod("FLAGS", *span);
                self.stp_flags = Some(*v);
                self.ike_flags = Some(*v);
                self.tacacs_spec.flags = Some(*v);
                self.memcached_spec.flags = Some(*v as u32);
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::ActorSys(v, span) => {
                self.record_mod("ACTOR_SYS", *span);
                self.actor_sys = Some(*v);
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::ActorKey(v, span) => {
                self.record_mod("ACTOR_KEY", *span);
                self.actor_key = Some(*v);
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::ActorPort(v, span) => {
                self.record_mod("ACTOR_PORT", *span);
                self.actor_port = Some(*v);
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::PartnerSys(v, span) => {
                self.record_mod("PARTNER_SYS", *span);
                self.partner_sys = Some(*v);
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::PartnerKey(v, span) => {
                self.record_mod("PARTNER_KEY", *span);
                self.partner_key = Some(*v);
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::PartnerPort(v, span) => {
                self.record_mod("PARTNER_PORT", *span);
                self.partner_port = Some(*v);
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::ActorState(v, span) => {
                self.record_mod("ACTOR_STATE", *span);
                self.actor_state = Some(*v);
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::PartnerState(v, span) => {
                self.record_mod("PARTNER_STATE", *span);
                self.partner_state = Some(*v);
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::VersionByte(v, span) => {
                self.record_mod("VERSION", *span);
                self.version_byte = Some(*v);
                self.quic_spec.version = Some(*v as u32);
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::EapolType(v, span) => {
                self.record_mod("EAPOL_TYPE", *span);
                self.eapol_type = Some(*v);
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::EapCode(v, span) => {
                self.record_mod("EAP_CODE", *span);
                self.eap_code = Some(*v);
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::EapId(v, span) => {
                self.record_mod("EAP_ID", *span);
                self.eap_id = Some(*v);
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::EapMethod(v, span) => {
                self.record_mod("EAP_METHOD", *span);
                self.eap_method = Some(*v);
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::Identity(v, span) => {
                self.record_mod("IDENTITY", *span);
                self.identity_str = Some(*v);
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::IcmpTypeChoice(v, span) => {
                self.record_mod("ICMP_TYPE_CHOICE", *span);
                self.icmp_type_choice = Some(*v);
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::IcmpId(v, span) => {
                self.record_mod("ICMP_ID", *span);
                self.icmp_id_val = Some(*v);
                self.radius_spec.id = Some(*v as u8);
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::Gateway(v, span) => {
                self.record_mod("GATEWAY", *span);
                self.gateway_ip = Some(*v);
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::NdpType(v, span) => {
                self.record_mod("NDP_TYPE", *span);
                self.ndp_type = Some(*v);
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::TargetVal(ip, mac, span) => {
                self.record_mod("TARGET", *span);
                if let Some(i) = ip {
                    self.target_ip = Some(*i);
                }
                if let Some(m) = mac {
                    self.tlla_mac = Some(*m);
                }
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::Slla(v, span) => {
                self.record_mod("SLLA", *span);
                self.slla_mac = Some(*v);
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::Tlla(v, span) => {
                self.record_mod("TLLA", *span);
                self.tlla_mac = Some(*v);
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::RouterLifetime(v, span) => {
                self.record_mod("ROUTER_LIFETIME", *span);
                self.router_lifetime = Some(*v);
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::IgmpType(v, span) => {
                self.record_mod("IGMP_TYPE", *span);
                self.igmp_type = Some(*v);
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::GroupVal(ip, g, span) => {
                self.record_mod("GROUP", *span);
                if let Some(i) = ip {
                    self.group_ip = Some(*i);
                }
                if let Some(u) = g {
                    self.hsrp_group = Some(*u);
                }
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::MaxResp(v, span) => {
                self.record_mod("MAX_RESP", *span);
                self.max_resp = Some(*v);
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::MldType(v, span) => {
                self.record_mod("MLD_TYPE", *span);
                self.mld_type = Some(*v);
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::MulticastAddr(v, span) => {
                self.record_mod("MULTICAST_ADDR", *span);
                self.multicast_addr = Some(*v);
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::MaxRespDelay(v, span) => {
                self.record_mod("MAX_RESP_DELAY", *span);
                self.max_resp_delay = Some(*v);
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::GreKey(v, span) => {
                self.record_mod("GRE_KEY", *span);
                self.gre_key = Some(*v);
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::GreSeq(v, span) => {
                self.record_mod("GRE_SEQ", *span);
                self.gre_seq = Some(*v);
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::GreProto(v, span) => {
                self.record_mod("GRE_PROTO", *span);
                self.gre_proto = Some(*v);
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::ChecksumFlag(span) => {
                self.record_mod("CHECKSUM", *span);
                self.gre_checksum = true;
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::Vni(v, span) => {
                self.record_mod("VNI", *span);
                self.vni_val = Some(*v);
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::OptClass(v, span) => {
                self.record_mod("OPT_CLASS", *span);
                self.opt_class = Some(*v);
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::OptType(v, span) => {
                self.record_mod("OPT_TYPE", *span);
                self.opt_type = Some(*v);
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::ProtocolType(v, span) => {
                self.record_mod("PROTOCOL_TYPE", *span);
                self.protocol_type = Some(*v);
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::Spi(v, span) => {
                self.record_mod("SPI", *span);
                self.spi_val = Some(*v);
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::Iv(v, span) => {
                self.record_mod("IV", *span);
                self.iv_val = Some(v.clone());
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::Icv(v, span) => {
                self.record_mod("ICV", *span);
                self.icv_val = Some(v.clone());
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::NextHeader(v, span) => {
                self.record_mod("NEXT_HEADER", *span);
                self.next_header_val = Some(*v);
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::InitiatorSpi(v, span) => {
                self.record_mod("INITIATOR_SPI", *span);
                self.initiator_spi = Some(*v);
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::ResponderSpi(v, span) => {
                self.record_mod("RESPONDER_SPI", *span);
                self.responder_spi = Some(*v);
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::IkeExchange(v, span) => {
                self.record_mod("IKE_EXCHANGE", *span);
                self.ike_exchange = Some(*v);
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::MsgId(v, span) => {
                self.record_mod("MSG_ID", *span);
                self.ike_msgid = Some(*v);
                self.ldap_spec.msgid = Some(*v as i32);
                self.coap_spec.msgid = Some(*v as u16);
                self.smb_spec.msgid = Some(*v as u64);
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::NextPayload(v, span) => {
                self.record_mod("NEXT_PAYLOAD", *span);
                self.next_payload = Some(*v);
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::WireguardType(v, span) => {
                self.record_mod("WG_TYPE", *span);
                self.wireguard_type = Some(*v);
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::Sender(v, span) => {
                self.record_mod("SENDER", *span);
                self.wg_sender = Some(*v);
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::Receiver(v, span) => {
                self.record_mod("RECEIVER", *span);
                self.wg_receiver = Some(*v);
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::Counter(v, span) => {
                self.record_mod("COUNTER", *span);
                self.wg_counter = Some(*v);
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::OspfType(v, span) => {
                self.record_mod("OSPF_TYPE", *span);
                self.ospf_type = Some(*v);
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::HelloWord(span) => {
                self.pim_is_hello = true;
                if self.ospf_type.is_none() {
                    self.ospf_type = Some(OspfType::Hello);
                }
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::RouterId(v, span) => {
                self.record_mod("ROUTER_ID", *span);
                self.router_id_ip = Some(*v);
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::AreaId(v, span) => {
                self.record_mod("AREA_ID", *span);
                self.area_id_val = Some(*v);
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::HelloInterval(v, span) => {
                self.record_mod("HELLO_INTERVAL", *span);
                self.hello_interval = Some(*v);
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::DeadInterval(v, span) => {
                self.record_mod("DEAD_INTERVAL", *span);
                self.dead_interval = Some(*v);
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::PriorityVal(v, span) => {
                self.record_mod("PRIORITY", *span);
                self.priority_val = Some(*v);
                self.of_priority = Some(*v);
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::BgpType(v, span) => {
                self.record_mod("BGP_TYPE", *span);
                self.bgp_type = Some(*v);
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::Asn(v, span) => {
                self.record_mod("ASN", *span);
                self.asn_val = Some(*v);
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::HoldTime(v, span) => {
                self.record_mod("HOLD_TIME", *span);
                self.holdtime_val = Some(*v);
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::BgpId(v, span) => {
                self.record_mod("BGP_ID", *span);
                self.bgpid_ip = Some(*v);
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::PrefixVal(ip, st, span) => {
                self.record_mod("PREFIX", *span);
                if let Some(i) = ip {
                    self.rip_prefix = Some(*i);
                }
                if let Some(s) = st {
                    self.prefix_str = Some(*s);
                }
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::NextHop(v, span) => {
                self.record_mod("NEXT_HOP", *span);
                self.nexthop_ip = Some(*v);
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::Metric(v, span) => {
                self.record_mod("METRIC", *span);
                self.rip_metric = Some(*v);
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::TagVal(u, s, span) => {
                self.record_mod("TAG", *span);
                if let Some(v) = u {
                    self.rip_tag = Some(*v);
                }
                if let Some(str_val) = s {
                    self.imap_spec.tag = Some(*str_val);
                    self.nfs_spec.tag = Some(*str_val);
                }
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::Vrid(v, span) => {
                self.record_mod("VRID", *span);
                self.vrid_val = Some(*v);
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::AdvInt(v, span) => {
                self.record_mod("ADV_INT", *span);
                self.adv_int_val = Some(*v);
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::Vip(v, span) => {
                self.record_mod("VIP", *span);
                self.vip_ip = Some(*v);
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::HsrpState(v, span) => {
                self.record_mod("STATE", *span);
                self.hsrp_state = Some(*v);
                self.bfd_state = Some(*v);
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::HelloTimeHsrp(v, span) => {
                self.record_mod("HELLO_TIME_HSRP", *span);
                self.hsrp_hellotime = Some(*v);
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::PimJoinPrune(span) => {
                self.record_mod("JOIN_PRUNE", *span);
                self.pim_is_join_prune = true;
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::PimRegister(span) => {
                self.record_mod("REGISTER", *span);
                self.pim_is_register = true;
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::SourceIp(v, span) => {
                self.record_mod("SOURCE", *span);
                self.pim_source = Some(*v);
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::Rp(v, span) => {
                self.record_mod("RP", *span);
                self.pim_rp = Some(*v);
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::DrPriority(v, span) => {
                self.record_mod("DR_PRIORITY", *span);
                self.pim_dr_priority = Some(*v);
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::Diag(v, span) => {
                self.record_mod("DIAG", *span);
                self.bfd_diag = Some(*v);
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::MyDisc(v, span) => {
                self.record_mod("MY_DISC", *span);
                self.bfd_my_disc = Some(*v);
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::YourDisc(v, span) => {
                self.record_mod("YOUR_DISC", *span);
                self.bfd_your_disc = Some(*v);
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::MinTx(v, span) => {
                self.record_mod("MIN_TX", *span);
                self.bfd_min_tx = Some(*v);
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::MinRx(v, span) => {
                self.record_mod("MIN_RX", *span);
                self.bfd_min_rx = Some(*v);
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::Mult(v, span) => {
                self.record_mod("MULT", *span);
                self.bfd_mult = Some(*v);
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::OpenflowType(v, span) => {
                self.record_mod("OPENFLOW_TYPE", *span);
                self.openflow_type = Some(*v);
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::Xid(v, span) => {
                self.record_mod("XID", *span);
                self.of_xid = Some(*v);
                self.dhcp_spec.xid = Some(*v);
                self.nfs_spec.xid = Some(*v);
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::Dpid(v, span) => {
                self.record_mod("DPID", *span);
                self.of_dpid = Some(*v);
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::TableId(v, span) => {
                self.record_mod("TABLE_ID", *span);
                self.of_table_id = Some(*v);
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
            }
            ParsedField::L7StringField(..)
            | ParsedField::L7U32Field(..)
            | ParsedField::L7U64Field(..)
            | ParsedField::L7IpField(..)
            | ParsedField::L7MacField(..)
            | ParsedField::L7Flag(..)
            | ParsedField::L7Header(..) => {
                self.apply_l7_field(f);
            }
        }
    }
}
