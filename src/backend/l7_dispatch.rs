//! Layer 7 application, infrastructure, telemetry, and industrial OT payload dispatch.
//!
//! This submodule bridges the backend evaluation loop in [`super::compile_program`] with the
//! protocol-specific wire builders in [`crate::builders::l7_infra`], [`crate::builders::l7_app`],
//! and [`crate::builders::l7_ot`]. For any Layer 7 [`Protocol`], [`build_l7_packet_payload`]
//! extracts the typed [`ProtocolSpec`] from the AST statement (falling back to protocol defaults),
//! determines whether the transport is stream-oriented TCP or datagram-oriented UDP via
//! [`super::is_tcp_protocol`], and returns the serialized application-layer byte buffer.

use alloc::vec::Vec;
use core::net::IpAddr;

use crate::ast::*;
use crate::builders::WireContext;

use super::is_tcp_protocol;

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
    /// Optional builder-returned multicast target IP override (e.g., mDNS `224.0.0.251` or `ff02::fb`).
    pub target_ip: Option<IpAddr>,
}

/// Builds the L7 application, telemetry, or industrial protocol payload and preserves builder-returned ports and target IPs.
pub(crate) fn build_l7_packet_payload(
    ctx: &WireContext,
    stmt: &FrameStatement,
    payload_bytes: &[u8],
) -> Option<L7DispatchResult> {
    let is_tcp = is_tcp_protocol(&stmt.protocol, stmt.l4.transport);
    let mut src_port_override = None;
    let mut dst_port_override = None;
    let mut target_ip_override = None;

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
            dst_port_override = Some(dport);
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
            let spec = match &stmt.protocol_spec {
                Some(ProtocolSpec::Websocket(s)) => s.clone(),
                _ => WebsocketSpec::default(),
            };
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
            crate::builders::l7_ot::build_ethernetip_payload(ctx, &spec, payload_bytes)
        }
        Protocol::Opcua => {
            let spec = match &stmt.protocol_spec {
                Some(ProtocolSpec::Opcua(s)) => s.clone(),
                _ => OpcuaSpec::default(),
            };
            crate::builders::l7_ot::build_opcua_payload(ctx, &spec, payload_bytes)
        }
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

