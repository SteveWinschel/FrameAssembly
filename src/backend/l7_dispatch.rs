//! Layer 7 application, infrastructure, telemetry, and industrial OT payload dispatch.
//!
//! This submodule bridges the backend evaluation loop in [`super::compile_program`] with the
//! protocol-specific wire builders in [`crate::builders::l7_infra`], [`crate::builders::l7_app`],
//! and [`crate::builders::l7_ot`]. For any Layer 7 [`Protocol`], [`build_l7_packet_payload`]
//! extracts the typed [`ProtocolSpec`] from the AST statement (falling back to protocol defaults),
//! determines whether the transport is stream-oriented TCP or datagram-oriented UDP via
//! [`super::statement_uses_tcp`], and returns the serialized application-layer byte buffer.

use alloc::vec::Vec;
use core::net::IpAddr;

use crate::ast::*;
use crate::builders::WireContext;

use super::statement_uses_tcp;

/// Encapsulates the serialized Layer 7 payload alongside dynamic transport ports and multicast target IPs returned by wire builders.
#[derive(Debug, Clone)]
pub(crate) struct L7DispatchResult {
    /// Serialized Layer 7 application, telemetry, or industrial OT wire payload bytes.
    pub payload: Vec<u8>,
    /// Indicates whether the protocol uses stream-oriented TCP transport (`true`) or datagram-oriented UDP (`false`).
    pub is_tcp: bool,
    /// Optional builder-returned source port override (e.g., DHCPv4 `68`/`67` or DHCPv6 `546`/`547`).
    pub src_port: Option<u16>,
    /// Optional builder-returned destination port override (e.g., DHCP `67`/`547`, mDNS `5353`, PTP `319`/`320`, RADIUS `1812`/`1813`).
    pub dst_port: Option<u16>,
    /// Optional builder-returned multicast/broadcast target IP default (mDNS, SSDP, PTP, DHCP/DHCPv6).
    pub target_ip: Option<IpAddr>,
}

/// Builds the L7 application, telemetry, or industrial protocol payload and preserves builder-returned ports and target IPs.
pub(crate) fn build_l7_packet_payload(
    ctx: &WireContext,
    stmt: &FrameStatement,
    payload_bytes: &[u8],
) -> Option<L7DispatchResult> {
    let is_tcp = if matches!(stmt.protocol, Protocol::Mdns | Protocol::Ngap | Protocol::S1ap) {
        false
    } else {
        statement_uses_tcp(stmt)
    };
    let mut src_port_override = None;
    let mut dst_port_override = None;
    let mut target_ip_override = None;

    macro_rules! build_spec {
        ($variant:ident, $builder:path) => {{
            match &stmt.protocol_spec {
                Some(ProtocolSpec::$variant(spec)) => $builder(ctx, spec, payload_bytes),
                _ => $builder(ctx, &Default::default(), payload_bytes),
            }
        }};
    }

    let payload = match stmt.protocol {
        Protocol::Dns => {
            let spec = match &stmt.protocol_spec {
                Some(ProtocolSpec::Dns(s)) => s.clone(),
                _ => DnsSpec::default(),
            };
            crate::builders::l7_infra::build_dns_payload(ctx, &spec, payload_bytes, is_tcp)
        }
        Protocol::Mdns => {
            let spec = match &stmt.protocol_spec {
                Some(ProtocolSpec::Mdns(s)) => s.clone(),
                _ => DnsSpec::default(),
            };
            let (p, target_ip, dport) =
                crate::builders::l7_infra::build_mdns_payload(ctx, &spec, payload_bytes);
            dst_port_override = Some(dport);
            target_ip_override = Some(target_ip);
            p
        }
        Protocol::Dhcp => {
            let spec = match &stmt.protocol_spec {
                Some(ProtocolSpec::Dhcp(s)) => s.clone(),
                _ => DhcpSpec::default(),
            };
            let (p, sport, dport) =
                crate::builders::l7_infra::build_dhcp_payload(ctx, &spec, payload_bytes);
            src_port_override = Some(sport);
            dst_port_override = Some(dport);
            if dport == 67 || (dport == 68 && ctx.dst_ip.is_unspecified()) {
                target_ip_override = Some(IpAddr::V4(core::net::Ipv4Addr::BROADCAST));
            } else if dport == 547 || (dport == 546 && ctx.dst_ip.is_unspecified()) {
                target_ip_override = Some(IpAddr::V6(core::net::Ipv6Addr::new(
                    0xff02, 0, 0, 0, 0, 0, 1, 2,
                )));
            }
            p
        }
        Protocol::Ntp => {
            let spec = match &stmt.protocol_spec {
                Some(ProtocolSpec::Ntp(s)) => s.clone(),
                _ => NtpSpec::default(),
            };
            crate::builders::l7_infra::build_ntp_payload(ctx, &spec, payload_bytes)
        }
        Protocol::Ptp => {
            let spec = match &stmt.protocol_spec {
                Some(ProtocolSpec::Ptp(s)) => s.clone(),
                _ => PtpSpec::default(),
            };
            let (p, dport) =
                crate::builders::l7_infra::build_ptp_payload(ctx, &spec, payload_bytes);
            if stmt.dir == Direction::RightToLeft {
                src_port_override = Some(dport);
            } else {
                dst_port_override = Some(dport);
            }
            target_ip_override = Some(if ctx.src_ip.is_ipv6() || ctx.dst_ip.is_ipv6() {
                IpAddr::V6(core::net::Ipv6Addr::new(0xff0e, 0, 0, 0, 0, 0, 0, 0x0181))
            } else {
                IpAddr::V4(core::net::Ipv4Addr::new(224, 0, 1, 129))
            });
            p
        }
        Protocol::Radius => {
            let spec = match &stmt.protocol_spec {
                Some(ProtocolSpec::Radius(s)) => s.clone(),
                _ => RadiusSpec::default(),
            };
            let (p, dport) =
                crate::builders::l7_infra::build_radius_payload(ctx, &spec, payload_bytes);
            dst_port_override = Some(dport);
            p
        }
        Protocol::Tacacs => {
            let spec = match &stmt.protocol_spec {
                Some(ProtocolSpec::Tacacs(s)) => s.clone(),
                _ => TacacsSpec::default(),
            };
            crate::builders::l7_infra::build_tacacs_payload(ctx, &spec, payload_bytes)
        }
        Protocol::Syslog => {
            let spec = match &stmt.protocol_spec {
                Some(ProtocolSpec::Syslog(s)) => s.clone(),
                _ => SyslogSpec::default(),
            };
            crate::builders::l7_infra::build_syslog_payload(ctx, &spec, payload_bytes)
        }
        Protocol::Netflow => {
            let spec = match &stmt.protocol_spec {
                Some(ProtocolSpec::Netflow(s)) => s.clone(),
                _ => NetflowSpec::default(),
            };
            crate::builders::l7_infra::build_netflow_payload(ctx, &spec, payload_bytes)
        }
        Protocol::Ipfix => {
            let spec = match &stmt.protocol_spec {
                Some(ProtocolSpec::Ipfix(s)) => s.clone(),
                _ => IpfixSpec::default(),
            };
            crate::builders::l7_infra::build_ipfix_payload(ctx, &spec, payload_bytes)
        }
        Protocol::Sflow => {
            let spec = match &stmt.protocol_spec {
                Some(ProtocolSpec::Sflow(s)) => s.clone(),
                _ => SflowSpec::default(),
            };
            crate::builders::l7_infra::build_sflow_payload(ctx, &spec, payload_bytes)
        }
        Protocol::Tftp => {
            let spec = match &stmt.protocol_spec {
                Some(ProtocolSpec::Tftp(s)) => s.clone(),
                _ => TftpSpec::default(),
            };
            crate::builders::l7_app::build_tftp_payload(ctx, &spec, payload_bytes)
        }
        Protocol::Ftp => {
            let spec = match &stmt.protocol_spec {
                Some(ProtocolSpec::Ftp(s)) => s.clone(),
                _ => FtpSpec::default(),
            };
            crate::builders::l7_app::build_ftp_payload(ctx, &spec, payload_bytes)
        }
        Protocol::Ssh => {
            let spec = match &stmt.protocol_spec {
                Some(ProtocolSpec::Ssh(s)) => s.clone(),
                _ => SshSpec::default(),
            };
            crate::builders::l7_app::build_ssh_payload(ctx, &spec, payload_bytes)
        }
        Protocol::Telnet => {
            let spec = match &stmt.protocol_spec {
                Some(ProtocolSpec::Telnet(s)) => s.clone(),
                _ => TelnetSpec::default(),
            };
            crate::builders::l7_app::build_telnet_payload(ctx, &spec, payload_bytes)
        }
        Protocol::Http => {
            let spec = match &stmt.protocol_spec {
                Some(ProtocolSpec::Http(s)) => s.clone(),
                _ => HttpSpec::default(),
            };
            crate::builders::l7_app::build_http_payload(ctx, &spec, payload_bytes)
        }
        Protocol::Http2 => {
            let spec = match &stmt.protocol_spec {
                Some(ProtocolSpec::Http2(s)) => s.clone(),
                _ => Http2Spec::default(),
            };
            crate::builders::l7_app::build_http2_payload(ctx, &spec, payload_bytes)
        }
        Protocol::Grpc => {
            let spec = match &stmt.protocol_spec {
                Some(ProtocolSpec::Grpc(s)) => s.clone(),
                _ => GrpcSpec::default(),
            };
            crate::builders::l7_app::build_grpc_payload(ctx, &spec, payload_bytes)
        }
        Protocol::Websocket => {
            let mut spec = match &stmt.protocol_spec {
                Some(ProtocolSpec::Websocket(s)) => s.clone(),
                _ => WebsocketSpec::default(),
            };
            if spec.payload.is_none()
                && (stmt.payload.as_deref() == Some("")
                    || stmt.hex_payload.as_deref() == Some(&[][..]))
            {
                spec.payload = Some("");
            }
            crate::builders::l7_app::build_websocket_payload(ctx, &spec, payload_bytes)
        }
        Protocol::Tls => {
            let spec = match &stmt.protocol_spec {
                Some(ProtocolSpec::Tls(s)) => s.clone(),
                _ => TlsSpec::default(),
            };
            crate::builders::l7_app::build_tls_payload(ctx, &spec, payload_bytes)
        }
        Protocol::Quic => {
            let spec = match &stmt.protocol_spec {
                Some(ProtocolSpec::Quic(s)) => s.clone(),
                _ => QuicSpec::default(),
            };
            crate::builders::l7_app::build_quic_payload(ctx, &spec, payload_bytes)
        }
        Protocol::Stun => {
            let spec = match &stmt.protocol_spec {
                Some(ProtocolSpec::Stun(s)) => s.clone(),
                _ => StunSpec::default(),
            };
            crate::builders::l7_app::build_stun_payload(ctx, &spec, payload_bytes)
        }
        Protocol::Sip => {
            let spec = match &stmt.protocol_spec {
                Some(ProtocolSpec::Sip(s)) => s.clone(),
                _ => SipSpec::default(),
            };
            crate::builders::l7_app::build_sip_payload(ctx, &spec, payload_bytes)
        }
        Protocol::Rtp => {
            let spec = match &stmt.protocol_spec {
                Some(ProtocolSpec::Rtp(s)) => s.clone(),
                _ => RtpSpec::default(),
            };
            crate::builders::l7_app::build_rtp_payload(ctx, &spec, payload_bytes)
        }
        Protocol::Rtsp => {
            let spec = match &stmt.protocol_spec {
                Some(ProtocolSpec::Rtsp(s)) => s.clone(),
                _ => RtspSpec::default(),
            };
            crate::builders::l7_app::build_rtsp_payload(ctx, &spec, payload_bytes)
        }
        Protocol::Smtp => {
            let spec = match &stmt.protocol_spec {
                Some(ProtocolSpec::Smtp(s)) => s.clone(),
                _ => SmtpSpec::default(),
            };
            crate::builders::l7_app::build_smtp_payload(ctx, &spec, payload_bytes)
        }
        Protocol::Imap => {
            let spec = match &stmt.protocol_spec {
                Some(ProtocolSpec::Imap(s)) => s.clone(),
                _ => ImapSpec::default(),
            };
            crate::builders::l7_app::build_imap_payload(ctx, &spec, payload_bytes)
        }
        Protocol::Pop3 => {
            let spec = match &stmt.protocol_spec {
                Some(ProtocolSpec::Pop3(s)) => s.clone(),
                _ => Pop3Spec::default(),
            };
            crate::builders::l7_app::build_pop3_payload(ctx, &spec, payload_bytes)
        }
        Protocol::Kerberos => {
            let spec = match &stmt.protocol_spec {
                Some(ProtocolSpec::Kerberos(s)) => s.clone(),
                _ => KerberosSpec::default(),
            };
            crate::builders::l7_app::build_kerberos_payload(ctx, &spec, payload_bytes)
        }
        Protocol::Ldap => {
            let spec = match &stmt.protocol_spec {
                Some(ProtocolSpec::Ldap(s)) => s.clone(),
                _ => LdapSpec::default(),
            };
            crate::builders::l7_app::build_ldap_payload(ctx, &spec, payload_bytes)
        }
        Protocol::Smb => {
            let spec = match &stmt.protocol_spec {
                Some(ProtocolSpec::Smb(s)) => s.clone(),
                _ => SmbSpec::default(),
            };
            crate::builders::l7_app::build_smb_payload(ctx, &spec, payload_bytes)
        }
        Protocol::Nfs => {
            let spec = match &stmt.protocol_spec {
                Some(ProtocolSpec::Nfs(s)) => s.clone(),
                _ => NfsSpec::default(),
            };
            crate::builders::l7_app::build_nfs_payload(ctx, &spec, payload_bytes)
        }
        Protocol::Redis => {
            let spec = match &stmt.protocol_spec {
                Some(ProtocolSpec::Redis(s)) => s.clone(),
                _ => RedisSpec::default(),
            };
            crate::builders::l7_app::build_redis_payload(ctx, &spec, payload_bytes)
        }
        Protocol::Memcached => {
            let spec = match &stmt.protocol_spec {
                Some(ProtocolSpec::Memcached(s)) => s.clone(),
                _ => MemcachedSpec::default(),
            };
            crate::builders::l7_app::build_memcached_payload(ctx, &spec, payload_bytes)
        }
        Protocol::Mysql => {
            let spec = match &stmt.protocol_spec {
                Some(ProtocolSpec::Mysql(s)) => s.clone(),
                _ => MysqlSpec::default(),
            };
            crate::builders::l7_app::build_mysql_payload(ctx, &spec, payload_bytes)
        }
        Protocol::Postgres => {
            let spec = match &stmt.protocol_spec {
                Some(ProtocolSpec::Postgres(s)) => s.clone(),
                _ => PostgresSpec::default(),
            };
            crate::builders::l7_app::build_postgres_payload(ctx, &spec, payload_bytes)
        }
        Protocol::Mqtt => {
            let spec = match &stmt.protocol_spec {
                Some(ProtocolSpec::Mqtt(s)) => s.clone(),
                _ => MqttSpec::default(),
            };
            crate::builders::l7_app::build_mqtt_payload(ctx, &spec, payload_bytes)
        }
        Protocol::Coap => {
            let spec = match &stmt.protocol_spec {
                Some(ProtocolSpec::Coap(s)) => s.clone(),
                _ => CoapSpec::default(),
            };
            crate::builders::l7_app::build_coap_payload(ctx, &spec, payload_bytes)
        }
        Protocol::Amqp => {
            let spec = match &stmt.protocol_spec {
                Some(ProtocolSpec::Amqp(s)) => s.clone(),
                _ => AmqpSpec::default(),
            };
            crate::builders::l7_app::build_amqp_payload(ctx, &spec, payload_bytes)
        }
        Protocol::Ssdp => {
            let spec = match &stmt.protocol_spec {
                Some(ProtocolSpec::Ssdp(s)) => s.clone(),
                _ => SsdpSpec::default(),
            };
            target_ip_override = Some(if ctx.src_ip.is_ipv6() || ctx.dst_ip.is_ipv6() {
                IpAddr::V6(core::net::Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0x000c))
            } else {
                IpAddr::V4(core::net::Ipv4Addr::new(239, 255, 255, 250))
            });
            crate::builders::l7_app::build_ssdp_payload(ctx, &spec, payload_bytes)
        }
        Protocol::Whois => {
            let spec = match &stmt.protocol_spec {
                Some(ProtocolSpec::Whois(s)) => s.clone(),
                _ => WhoisSpec::default(),
            };
            crate::builders::l7_app::build_whois_payload(ctx, &spec, payload_bytes)
        }
        Protocol::Modbus => {
            let spec = match &stmt.protocol_spec {
                Some(ProtocolSpec::Modbus(s)) => s.clone(),
                _ => ModbusSpec::default(),
            };
            crate::builders::l7_ot::build_modbus_payload(ctx, &spec, payload_bytes)
        }
        Protocol::Bacnet => {
            let spec = match &stmt.protocol_spec {
                Some(ProtocolSpec::Bacnet(s)) => s.clone(),
                _ => BacnetSpec::default(),
            };
            crate::builders::l7_ot::build_bacnet_payload(ctx, &spec, payload_bytes)
        }
        Protocol::Dnp3 => {
            let spec = match &stmt.protocol_spec {
                Some(ProtocolSpec::Dnp3(s)) => s.clone(),
                _ => Dnp3Spec::default(),
            };
            crate::builders::l7_ot::build_dnp3_payload(ctx, &spec, payload_bytes)
        }
        Protocol::S7comm => {
            let spec = match &stmt.protocol_spec {
                Some(ProtocolSpec::S7comm(s)) => s.clone(),
                _ => S7commSpec::default(),
            };
            crate::builders::l7_ot::build_s7comm_payload(ctx, &spec, payload_bytes)
        }
        Protocol::Ethernetip => {
            let spec = match &stmt.protocol_spec {
                Some(ProtocolSpec::Ethernetip(s)) => s.clone(),
                _ => EthernetipSpec::default(),
            };
            if !is_tcp {
                if stmt.dir == Direction::RightToLeft {
                    src_port_override = Some(2222);
                } else {
                    dst_port_override = Some(2222);
                }
            }
            crate::builders::l7_ot::build_ethernetip_payload(ctx, &spec, payload_bytes)
        }
        Protocol::Opcua => {
            let spec = match &stmt.protocol_spec {
                Some(ProtocolSpec::Opcua(s)) => s.clone(),
                _ => OpcuaSpec::default(),
            };
            crate::builders::l7_ot::build_opcua_payload(ctx, &spec, payload_bytes)
        }
        Protocol::Dcerpc => build_spec!(Dcerpc, crate::builders::l7::build_dcerpc_payload),
        Protocol::Ntlm => build_spec!(Ntlm, crate::builders::l7::build_ntlm_payload),
        Protocol::Rdp => build_spec!(Rdp, crate::builders::l7::build_rdp_payload),
        Protocol::Llmnr => {
            let spec = match &stmt.protocol_spec {
                Some(ProtocolSpec::Llmnr(s)) => s.clone(),
                _ => LlmnrSpec::default(),
            };
            let (p, target_ip, dport) =
                crate::builders::l7::build_llmnr_payload(ctx, &spec, payload_bytes, is_tcp);
            dst_port_override = Some(dport);
            target_ip_override = target_ip;
            p
        }
        Protocol::Nbns => build_spec!(Nbns, crate::builders::l7::build_nbns_payload),
        Protocol::Socks => build_spec!(Socks, crate::builders::l7::build_socks_payload),
        Protocol::Vnc => build_spec!(Vnc, crate::builders::l7::build_vnc_payload),
        Protocol::Doh => build_spec!(Doh, crate::builders::l7::build_doh_payload),
        Protocol::Wsdiscovery => {
            target_ip_override = Some(if ctx.src_ip.is_ipv6() || ctx.dst_ip.is_ipv6() {
                IpAddr::V6(core::net::Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0x000c))
            } else {
                IpAddr::V4(core::net::Ipv4Addr::new(239, 255, 255, 250))
            });
            build_spec!(Wsdiscovery, crate::builders::l7::build_wsdiscovery_payload)
        }
        Protocol::Irc => build_spec!(Irc, crate::builders::l7::build_irc_payload),
        Protocol::Iec104 => build_spec!(Iec104, crate::builders::l7::build_iec104_payload),
        Protocol::Mms => build_spec!(Mms, crate::builders::l7::build_mms_payload),
        Protocol::S7commplus => {
            build_spec!(S7commplus, crate::builders::l7::build_s7commplus_payload)
        }
        Protocol::Synchrophasor => {
            build_spec!(
                Synchrophasor,
                crate::builders::l7::build_synchrophasor_payload
            )
        }
        Protocol::Hartip => build_spec!(Hartip, crate::builders::l7::build_hartip_payload),
        Protocol::Fins => build_spec!(Fins, crate::builders::l7::build_fins_payload),
        Protocol::Melsec => build_spec!(Melsec, crate::builders::l7::build_melsec_payload),
        Protocol::Someip => build_spec!(Someip, crate::builders::l7::build_someip_payload),
        Protocol::Doip => build_spec!(Doip, crate::builders::l7::build_doip_payload),
        Protocol::C1222 => build_spec!(C1222, crate::builders::l7::build_c1222_payload),
        Protocol::Gesrtp => build_spec!(Gesrtp, crate::builders::l7::build_gesrtp_payload),
        Protocol::Rocplus => build_spec!(Rocplus, crate::builders::l7::build_rocplus_payload),
        Protocol::Bsap => build_spec!(Bsap, crate::builders::l7::build_bsap_payload),
        Protocol::Knxnetip => build_spec!(Knxnetip, crate::builders::l7::build_knxnetip_payload),
        Protocol::Rocev2 => build_spec!(Rocev2, crate::builders::l7::build_rocev2_payload),
        Protocol::Ipmi => build_spec!(Ipmi, crate::builders::l7::build_ipmi_payload),
        Protocol::Twamp => build_spec!(Twamp, crate::builders::l7::build_twamp_payload),
        Protocol::Netconf => build_spec!(Netconf, crate::builders::l7::build_netconf_payload),
        Protocol::Gtpc => build_spec!(Gtpc, crate::builders::l7::build_gtpc_payload),
        Protocol::Pfcp => build_spec!(Pfcp, crate::builders::l7::build_pfcp_payload),
        Protocol::Diameter => build_spec!(Diameter, crate::builders::l7::build_diameter_payload),
        Protocol::Ngap => build_spec!(Ngap, crate::builders::l7::build_ngap_payload),
        Protocol::S1ap => build_spec!(S1ap, crate::builders::l7::build_s1ap_payload),
        Protocol::Mssql => build_spec!(Mssql, crate::builders::l7::build_mssql_payload),
        Protocol::Kafka => build_spec!(Kafka, crate::builders::l7::build_kafka_payload),
        Protocol::Mongodb => build_spec!(Mongodb, crate::builders::l7::build_mongodb_payload),
        Protocol::Tns => build_spec!(Tns, crate::builders::l7::build_tns_payload),
        Protocol::Iscsi => build_spec!(Iscsi, crate::builders::l7::build_iscsi_payload),
        Protocol::Nvmetcp => build_spec!(Nvmetcp, crate::builders::l7::build_nvmetcp_payload),
        Protocol::Rtcp => build_spec!(Rtcp, crate::builders::l7::build_rtcp_payload),
        Protocol::Turn => build_spec!(Turn, crate::builders::l7::build_turn_payload),
        Protocol::H323 => {
            let spec = match &stmt.protocol_spec {
                Some(ProtocolSpec::H323(s)) => s.clone(),
                _ => H323Spec::default(),
            };
            let (p, dport) = crate::builders::l7::build_h323_payload(ctx, &spec, payload_bytes);
            dst_port_override = Some(dport);
            p
        }
        Protocol::Sccp => build_spec!(Sccp, crate::builders::l7::build_sccp_payload),
        Protocol::Mgcp => build_spec!(Mgcp, crate::builders::l7::build_mgcp_payload),
        _ => return None,
    };
    Some(L7DispatchResult {
        payload,
        is_tcp,
        src_port: src_port_override,
        dst_port: dst_port_override,
        target_ip: target_ip_override,
    })
}

