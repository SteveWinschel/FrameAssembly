//! Final [`FrameStatement`] synthesis from accumulated [`FrameBuilder`] state.
//!
//! This module implements [`FrameBuilder::finish`], which executes after all universal, Layer 2,
//! Layer 3, Layer 4, and Layer 7 [`ParsedField`](super::fields::ParsedField) modifiers have been
//! applied to a statement's [`FrameBuilder`]. It resolves default transport and encapsulation
//! protocols, synthesizes strongly typed [`L2Modifiers`], [`L3Modifiers`], [`L4Modifiers`], and
//! [`ProtocolSpec`] payloads across all 81 supported protocols, and returns the spanned
//! [`FrameStatement`] AST node.

use crate::ast::*;
use super::statement::FrameBuilder;

impl<'a> FrameBuilder<'a> {
    /// Finalizes the [`FrameBuilder`] and produces a complete [`FrameStatement`] AST node.
    pub(crate) fn finish(
        mut self,
        caller: Spanned<&'a str>,
        dir: Direction,
        callee: Spanned<&'a str>,
    ) -> FrameStatement<'a> {
        let protocol = match (self.protocol, self.transport_val) {
            (Some(p), _) => p,
            (None, Some(TransportProto::Udp)) => Protocol::Udp,
            (None, Some(TransportProto::Tcp)) => Protocol::Tcp,
            (None, None) => {
                if self.vlan_val.is_some() {
                    Protocol::Vlan
                } else if self.qinq_val.is_some() {
                    Protocol::Qinq
                } else if self.mpls_val.is_some() {
                    Protocol::Mpls
                } else {
                    Protocol::Tcp
                }
            }
        };

        if protocol == Protocol::Rip {
            if self.arp_opcode == Some(ArpOpcode::Request) {
                self.rip_cmd = Some(RipCommand::Request);
            } else if self.arp_opcode == Some(ArpOpcode::Reply)
                || self.pdu_type == Some(SnmpPduType::Response)
            {
                self.rip_cmd = Some(RipCommand::Response);
            }
        }

        if protocol == Protocol::Memcached {
            if let Some(ref pt) = self.pdu_type {
                match pt {
                    SnmpPduType::Get => self.memcached_spec.cmd = Some("GET"),
                    SnmpPduType::Set => self.memcached_spec.cmd = Some("SET"),
                    _ => {}
                }
                self.pdu_type = None;
            }
            if self.memcached_spec.cmd.is_none() {
                self.memcached_spec.cmd = self.http_spec.method;
            }
        }

        if protocol == Protocol::Tcp && self.flags.is_empty() {
            if self.payload.is_some() || self.hex_payload.is_some() {
                self.flags.push(TcpFlag::Psh);
                self.flags.push(TcpFlag::Ack);
            } else {
                self.flags.push(TcpFlag::Syn);
            }
        }

        let vlan = self.vlan_val.map(|(v, _)| VlanSpec {
            vid: v as u16,
            pcp: self.pcp_val.map(|(p, _)| p),
            dei: self.dei_val.map(|(d, _)| d),
        });
        let qinq = self.qinq_val.map(|(v, _)| QinqSpec {
            outer_vid: v,
            inner_vid: self.inner_vlan_val.map(|(iv, _)| iv),
        });
        let mpls = self.mpls_val.map(|(lbl, _)| MplsSpec {
            label: lbl,
            exp: self.exp_val.map(|(e, _)| e),
            bos: self.bos_val.map(|(b, _)| b),
            ttl: self.mpls_ttl_val.map(|(t, _)| t),
        });
        let l2 = L2Modifiers {
            src_mac: self.src_mac_val.map(|(m, _)| m),
            dst_mac: self.dst_mac_val.map(|(m, _)| m),
            ethertype: self.ethertype_val.map(|(e, _)| e),
            vlan: vlan.clone(),
            qinq: qinq.clone(),
            mpls: mpls.clone(),
        };

        let l3 = L3Modifiers {
            ttl: self
                .ttl_val
                .and_then(|(v, _)| if v <= 255 { Some(v as u8) } else { None }),
            dscp: self
                .dscp_val
                .and_then(|(v, _)| if v <= 63 { Some(v as u8) } else { None }),
            ecn: self
                .ecn_val
                .and_then(|(v, _)| if v <= 3 { Some(v as u8) } else { None }),
            flowlabel: self.flowlabel_val.map(|(v, _)| v),
            ipid: self.ipid_val.map(|(v, _)| v),
            df: self.df_val,
            mf: self.mf_val,
            frag_offset: self.frag_offset_val.map(|(v, _)| v),
        };

        let tcp_options = if self.mss_val.is_some()
            || self.wscale_val.is_some()
            || self.sack_perm_val
            || self.tsval_val.is_some()
            || self.tsecr_val.is_some()
        {
            Some(TcpOptions {
                mss: self.mss_val.map(|(v, _)| v),
                wscale: self.wscale_val.map(|(v, _)| v),
                sack_perm: self.sack_perm_val,
                tsval: self.tsval_val.map(|(v, _)| v),
                tsecr: self.tsecr_val.map(|(v, _)| v),
            })
        } else {
            None
        };

        let sctp_params = if self.vtag_val.is_some()
            || self.stream_val.is_some()
            || self.ssn_val.is_some()
            || self.ppid_val.is_some()
            || self.chunk_val.is_some()
        {
            Some(SctpParams {
                vtag: self.vtag_val.map(|(v, _)| v),
                stream: self.stream_val.map(|(v, _)| v),
                ssn: self.ssn_val.map(|(v, _)| v),
                ppid: self.ppid_val.map(|(v, _)| v),
                chunk: self.chunk_val.map(|(v, _)| v),
            })
        } else {
            None
        };

        let l4 = L4Modifiers {
            src_port: self.src_port,
            dst_port: self.dst_port,
            transport: self.transport_val,
            tcp_flags: self.flags.clone(),
            urgent: self.urgent_val.map(|(v, _)| v),
            tcp_options,
            sctp_params: sctp_params.clone(),
        };

        let protocol_spec = match protocol {
            Protocol::Tcp => Some(ProtocolSpec::Tcp),
            Protocol::Udp => Some(ProtocolSpec::Udp),
            Protocol::Sctp => Some(ProtocolSpec::Sctp(sctp_params.unwrap_or_default())),
            Protocol::Snmp1 => Some(ProtocolSpec::Snmp1(Snmp1Spec {
                community: self.community,
                enterprise: self.enterprise,
                agent_ip: self.agent_ip,
                gen_trap: self.gen_trap,
                spec_trap: self.spec_trap,
                sys_up_time: self.sys_up_time,
                varbinds: self.varbinds.clone(),
                pdu_type: self.pdu_type.clone(),
            })),
            Protocol::Snmp2 => Some(ProtocolSpec::Snmp2(Snmp2Spec {
                community: self.community,
                varbinds: self.varbinds.clone(),
                pdu_type: self.pdu_type.clone(),
                non_repeaters: self.non_repeaters,
                max_repetitions: self.max_repetitions,
                req_id: self.req_id,
            })),
            Protocol::Snmp3 => Some(ProtocolSpec::Snmp3(Snmp3Spec {
                user: self.user,
                engine_id: self.engine_id,
                engine_boots: self.engine_boots,
                engine_time: self.engine_time,
                context_name: self.context_name,
                auth: self.auth.clone(),
                priv_param: self.priv_param.clone(),
                varbinds: self.varbinds.clone(),
                pdu_type: self.pdu_type.clone(),
                non_repeaters: self.non_repeaters,
                max_repetitions: self.max_repetitions,
                req_id: self.req_id,
            })),
            Protocol::Arp => Some(ProtocolSpec::Arp(ArpSpec {
                opcode: self.arp_opcode,
                is_gratuitous: self.is_gratuitous,
                sha: self.sha,
                spa: self.spa,
                tha: self.tha,
                tpa: self.tpa,
                _marker: core::marker::PhantomData,
            })),
            Protocol::Vlan => Some(ProtocolSpec::Vlan(vlan.unwrap_or_default())),
            Protocol::Qinq => Some(ProtocolSpec::Qinq(qinq.unwrap_or_default())),
            Protocol::Mpls => Some(ProtocolSpec::Mpls(mpls.unwrap_or_default())),
            Protocol::Lldp => Some(ProtocolSpec::Lldp(LldpSpec {
                chassis_id: self.chassis_id,
                port_id: self.port_id_str,
                ttl: self.ttl_val.map(|(t, _)| t as u16),
                sysname: self.sysname,
                sysdesc: self.sysdesc,
            })),
            Protocol::Stp => Some(ProtocolSpec::Stp(StpSpec {
                root_id: self.root_id,
                bridge_id: self.bridge_id,
                port_id: self.port_id_u16,
                cost: self.stp_cost,
                max_age: self.max_age,
                hello_time: self.hello_time,
                forward_delay: self.forward_delay,
                flags: self.stp_flags,
                is_rstp: self.is_rstp,
            })),
            Protocol::Lacp => Some(ProtocolSpec::Lacp(LacpSpec {
                actor_sys: self.actor_sys,
                actor_key: self.actor_key,
                actor_port: self.actor_port,
                partner_sys: self.partner_sys,
                partner_key: self.partner_key,
                partner_port: self.partner_port,
                actor_state: self.actor_state,
                partner_state: self.partner_state,
                _marker: core::marker::PhantomData,
            })),
            Protocol::Eapol => Some(ProtocolSpec::Eapol(EapolSpec {
                version: self.version_byte,
                packet_type: self.eapol_type,
                eap_code: self.eap_code,
                eap_id: self.eap_id,
                eap_method: self.eap_method,
                identity: self.identity_str,
            })),
            Protocol::Icmp => Some(ProtocolSpec::Icmp(IcmpSpec {
                type_choice: self.icmp_type_choice,
                icmp_type: self.icmp_type_val,
                icmp_code: self.icmp_code_val,
                id: self.icmp_id_val,
                seq: self.seq.map(|s| s as u16),
                gateway: self.gateway_ip,
                _marker: core::marker::PhantomData,
            })),
            Protocol::Ndp => Some(ProtocolSpec::Ndp(NdpSpec {
                ndp_type: self.ndp_type,
                target: self.target_ip,
                slla: self.slla_mac,
                tlla: self.tlla_mac,
                router_lifetime: self.router_lifetime,
                _marker: core::marker::PhantomData,
            })),
            Protocol::Igmp => Some(ProtocolSpec::Igmp(IgmpSpec {
                igmp_type: self.igmp_type,
                group: self.group_ip,
                max_resp: self.max_resp,
                version: self.version_byte,
                _marker: core::marker::PhantomData,
            })),
            Protocol::Mld => Some(ProtocolSpec::Mld(MldSpec {
                mld_type: self.mld_type.or(match self.igmp_type {
                    Some(IgmpType::Query) => Some(MldType::Query),
                    Some(IgmpType::Report) => Some(MldType::Report),
                    Some(IgmpType::Leave) => Some(MldType::Done),
                    None => None,
                }),
                multicast_addr: self.multicast_addr.or(self.group_ip),
                max_resp_delay: self.max_resp_delay.or_else(|| self.max_resp.map(u16::from)),
                _marker: core::marker::PhantomData,
            })),
            Protocol::Gre => Some(ProtocolSpec::Gre(GreSpec {
                key: self.gre_key,
                seq: self.gre_seq.or(self.seq),
                proto: self.gre_proto,
                checksum: self.gre_checksum,
                _marker: core::marker::PhantomData,
            })),
            Protocol::Vxlan => Some(ProtocolSpec::Vxlan(VxlanSpec {
                vni: self.vni_val,
                _marker: core::marker::PhantomData,
            })),
            Protocol::Geneve => Some(ProtocolSpec::Geneve(GeneveSpec {
                vni: self.vni_val,
                opt_class: self.opt_class,
                opt_type: self.opt_type,
                protocol_type: self.protocol_type,
                _marker: core::marker::PhantomData,
            })),
            Protocol::Ipsec => Some(ProtocolSpec::Ipsec(IpsecSpec {
                spi: self.spi_val,
                seq: self.seq,
                iv: self.iv_val,
                icv: self.icv_val,
                next_header: self.next_header_val,
                _marker: core::marker::PhantomData,
            })),
            Protocol::Esp => Some(ProtocolSpec::Esp(IpsecSpec {
                spi: self.spi_val,
                seq: self.seq,
                iv: self.iv_val,
                icv: self.icv_val,
                next_header: self.next_header_val,
                _marker: core::marker::PhantomData,
            })),
            Protocol::Ah => Some(ProtocolSpec::Ah(AhSpec {
                spi: self.spi_val,
                seq: self.seq,
                icv: self.icv_val,
                next_header: self.next_header_val,
                _marker: core::marker::PhantomData,
            })),
            Protocol::Ikev2 => Some(ProtocolSpec::Ikev2(Ikev2Spec {
                initiator_spi: self.initiator_spi,
                responder_spi: self.responder_spi,
                exchange: self.ike_exchange,
                msgid: self.ike_msgid,
                flags: self.ike_flags,
                next_payload: self.next_payload,
                _marker: core::marker::PhantomData,
            })),
            Protocol::Wireguard => Some(ProtocolSpec::Wireguard(WireguardSpec {
                msg_type: self.wireguard_type,
                sender: self.wg_sender,
                receiver: self.wg_receiver,
                counter: self.wg_counter,
                _marker: core::marker::PhantomData,
            })),
            Protocol::Ospf => Some(ProtocolSpec::Ospf(OspfSpec {
                ospf_type: self.ospf_type,
                router_id: self.router_id_ip,
                area_id: self.area_id_val,
                hello_interval: self.hello_interval,
                dead_interval: self.dead_interval,
                priority: self.priority_val.map(|p| p as u8),
                _marker: core::marker::PhantomData,
            })),
            Protocol::Bgp => Some(ProtocolSpec::Bgp(BgpSpec {
                bgp_type: self.bgp_type,
                asn: self.asn_val,
                holdtime: self.holdtime_val,
                bgpid: self.bgpid_ip,
                prefix: self.prefix_str,
                nexthop: self.nexthop_ip,
            })),
            Protocol::Rip => Some(ProtocolSpec::Rip(RipSpec {
                command: self.rip_cmd,
                prefix: self.rip_prefix,
                metric: self.rip_metric,
                nexthop: self.nexthop_ip,
                tag: self.rip_tag,
                _marker: core::marker::PhantomData,
            })),
            Protocol::Vrrp => Some(ProtocolSpec::Vrrp(VrrpSpec {
                vrid: self.vrid_val,
                priority: self.priority_val.map(|p| p as u8),
                adv_int: self.adv_int_val,
                vip: self.vip_ip,
                version: self.version_byte,
                _marker: core::marker::PhantomData,
            })),
            Protocol::Hsrp => Some(ProtocolSpec::Hsrp(HsrpSpec {
                group: self.hsrp_group,
                priority: self.priority_val.map(|p| p as u8),
                state: self.hsrp_state,
                auth: self.hsrp_auth,
                vip: self.vip_ip,
                hellotime: self.hsrp_hellotime,
                holdtime: self.holdtime_val.map(|h| h as u8),
            })),
            Protocol::Pim => Some(ProtocolSpec::Pim(PimSpec {
                is_hello: self.pim_is_hello,
                is_join_prune: self.pim_is_join_prune,
                is_register: self.pim_is_register,
                group: self.group_ip,
                source: self.pim_source,
                rp: self.pim_rp,
                holdtime: self.holdtime_val,
                dr_priority: self.pim_dr_priority,
                _marker: core::marker::PhantomData,
            })),
            Protocol::Bfd => Some(ProtocolSpec::Bfd(BfdSpec {
                state: self.bfd_state,
                diag: self.bfd_diag,
                my_disc: self.bfd_my_disc,
                your_disc: self.bfd_your_disc,
                min_tx: self.bfd_min_tx,
                min_rx: self.bfd_min_rx,
                mult: self.bfd_mult,
                _marker: core::marker::PhantomData,
            })),
            Protocol::Openflow => Some(ProtocolSpec::Openflow(OpenflowSpec {
                version: self.version_byte,
                of_type: self.openflow_type,
                xid: self.of_xid,
                dpid: self.of_dpid,
                table_id: self.of_table_id,
                priority: self.of_priority,
                _marker: core::marker::PhantomData,
            })),
            Protocol::Dns => Some(ProtocolSpec::Dns(self.dns_spec)),
            Protocol::Mdns => Some(ProtocolSpec::Mdns(self.dns_spec)),
            Protocol::Dhcp => Some(ProtocolSpec::Dhcp(self.dhcp_spec)),
            Protocol::Ntp => Some(ProtocolSpec::Ntp(self.ntp_spec)),
            Protocol::Ptp => Some(ProtocolSpec::Ptp(self.ptp_spec)),
            Protocol::Radius => Some(ProtocolSpec::Radius(self.radius_spec)),
            Protocol::Tacacs => Some(ProtocolSpec::Tacacs(self.tacacs_spec)),
            Protocol::Syslog => Some(ProtocolSpec::Syslog(self.syslog_spec)),
            Protocol::Netflow => Some(ProtocolSpec::Netflow(self.netflow_spec)),
            Protocol::Ipfix => Some(ProtocolSpec::Ipfix(self.ipfix_spec)),
            Protocol::Sflow => Some(ProtocolSpec::Sflow(self.sflow_spec)),
            Protocol::Tftp => Some(ProtocolSpec::Tftp(self.tftp_spec)),
            Protocol::Ftp => Some(ProtocolSpec::Ftp(self.ftp_spec)),
            Protocol::Ssh => Some(ProtocolSpec::Ssh(self.ssh_spec)),
            Protocol::Telnet => Some(ProtocolSpec::Telnet(self.telnet_spec)),
            Protocol::Http => Some(ProtocolSpec::Http(self.http_spec)),
            Protocol::Http2 => Some(ProtocolSpec::Http2(self.http2_spec)),
            Protocol::Grpc => Some(ProtocolSpec::Grpc(self.grpc_spec)),
            Protocol::Websocket => Some(ProtocolSpec::Websocket(self.websocket_spec)),
            Protocol::Tls => Some(ProtocolSpec::Tls(self.tls_spec)),
            Protocol::Quic => Some(ProtocolSpec::Quic(self.quic_spec)),
            Protocol::Stun => Some(ProtocolSpec::Stun(self.stun_spec)),
            Protocol::Sip => Some(ProtocolSpec::Sip(self.sip_spec)),
            Protocol::Rtp => Some(ProtocolSpec::Rtp(self.rtp_spec)),
            Protocol::Rtsp => Some(ProtocolSpec::Rtsp(self.rtsp_spec)),
            Protocol::Smtp => Some(ProtocolSpec::Smtp(self.smtp_spec)),
            Protocol::Imap => Some(ProtocolSpec::Imap(self.imap_spec)),
            Protocol::Pop3 => Some(ProtocolSpec::Pop3(self.pop3_spec)),
            Protocol::Kerberos => Some(ProtocolSpec::Kerberos(self.kerberos_spec)),
            Protocol::Ldap => Some(ProtocolSpec::Ldap(self.ldap_spec)),
            Protocol::Smb => Some(ProtocolSpec::Smb(self.smb_spec)),
            Protocol::Nfs => Some(ProtocolSpec::Nfs(self.nfs_spec)),
            Protocol::Redis => Some(ProtocolSpec::Redis(self.redis_spec)),
            Protocol::Memcached => Some(ProtocolSpec::Memcached(self.memcached_spec)),
            Protocol::Mysql => Some(ProtocolSpec::Mysql(self.mysql_spec)),
            Protocol::Postgres => Some(ProtocolSpec::Postgres(self.postgres_spec)),
            Protocol::Mqtt => Some(ProtocolSpec::Mqtt(self.mqtt_spec)),
            Protocol::Coap => Some(ProtocolSpec::Coap(self.coap_spec)),
            Protocol::Amqp => Some(ProtocolSpec::Amqp(self.amqp_spec)),
            Protocol::Ssdp => Some(ProtocolSpec::Ssdp(self.ssdp_spec)),
            Protocol::Whois => Some(ProtocolSpec::Whois(self.whois_spec)),
            Protocol::Modbus => Some(ProtocolSpec::Modbus(self.modbus_spec)),
            Protocol::Bacnet => Some(ProtocolSpec::Bacnet(self.bacnet_spec)),
            Protocol::Dnp3 => Some(ProtocolSpec::Dnp3(self.dnp3_spec)),
            Protocol::S7comm => Some(ProtocolSpec::S7comm(self.s7comm_spec)),
            Protocol::Ethernetip => Some(ProtocolSpec::Ethernetip(self.ethernetip_spec)),
            Protocol::Opcua => Some(ProtocolSpec::Opcua(self.opcua_spec)),
        };

        let statement_span = (caller.span.0, self.stmt_end_offset - caller.span.0);

        FrameStatement {
            caller,
            dir,
            arrow: dir,
            callee,
            protocol,
            protocol_spec,
            l2,
            l3,
            l4,
            payload: self.payload,
            hex_payload: self.hex_payload,
            wait: self.wait,
            span: statement_span,
            raw_vlan: self.vlan_val,
            raw_dscp: self.dscp_val,
            raw_ecn: self.ecn_val,
            raw_ttl: self.ttl_val,
            raw_flowlabel: self.flowlabel_val,
            raw_gentrap_span: self.gentrap_span,
            duplicate_modifiers: self.duplicate_modifiers,
            src_port: self.src_port,
            dst_port: self.dst_port,
            flags: self.flags,
            seq: self.seq,
            ack_num: self.ack_num,
            win: self.win,
            urgent: self.urgent_val.map(|(v, _)| v),
            community: self.community,
            user: self.user,
            oid: self.oid,
            sys_up_time: self.sys_up_time,
            pdu_type: self.pdu_type,
            enterprise: self.enterprise,
            agent_ip: self.agent_ip,
            gen_trap: self.gen_trap,
            spec_trap: self.spec_trap,
            engine_id: self.engine_id,
            engine_boots: self.engine_boots,
            engine_time: self.engine_time,
            context_name: self.context_name,
            auth: self.auth,
            priv_param: self.priv_param,
            varbinds: self.varbinds,
            non_repeaters: self.non_repeaters,
            max_repetitions: self.max_repetitions,
            req_id: self.req_id,
        }
    }
}
