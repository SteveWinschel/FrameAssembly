//! Layer 7 application, network management, telemetry, web, security, VoIP, telecom, storage,
//! database, message broker, and industrial OT protocol PCAP-to-`.frasm` decompilers.
//!
//! This module organizes all 94 Layer 7 protocol dissectors (covering 92 Layer 7 protocols across
//! SNMPv1/v2c/v3) into 1-to-1 per-protocol files mirroring `src/ast/l7/`, `src/parser/l7/`, and
//! `src/builders/l7/`. The top-level [`dissect_l7`] dispatcher routes TCP, UDP, and SCTP
//! application payloads across three domain tiers:
//! 1. **Infrastructure, Naming, Management & Telemetry**: `snmp1`, `snmp2`, `snmp3`, `dns`,
//!    `mdns`, `llmnr`, `nbns`, `dhcp`, `ntp`, `ptp`, `radius`, `tacacs`, `syslog`, `netflow`,
//!    `ipfix`, `sflow`, `ipmi`, `gtpc`, `pfcp`.
//! 2. **Web, Security, Remote Access, Telecom, Media & VoIP**: `ntlm`, `doh`, `http`, `http2`,
//!    `grpc`, `websocket`, `tls`, `quic`, `tftp`, `ftp`, `netconf`, `ssh`, `telnet`, `whois`,
//!    `dcerpc`, `rdp`, `socks`, `vnc`, `wsdiscovery`, `irc`, `sip`, `rtp`, `rtcp`, `turn`, `stun`,
//!    `ssdp`, `rtsp`, `twamp`, `h323`, `sccp`, `mgcp`, `rocev2`.
//! 3. **Mail, Directory, Storage, Databases, Telecom Control, Messaging & Industrial OT**: `smtp`,
//!    `imap`, `pop3`, `kerberos`, `ldap`, `smb`, `nfs`, `redis`, `memcached`, `mysql`, `postgres`,
//!    `mssql`, `kafka`, `mongodb`, `tns`, `iscsi`, `nvmetcp`, `mqtt`, `coap`, `amqp`, `diameter`,
//!    `ngap`, `s1ap`, `modbus`, `bacnet`, `dnp3`, `s7comm`, `s7commplus`, `mms`, `iec104`,
//!    `ethernetip`, `opcua`, `synchrophasor`, `hartip`, `fins`, `melsec`, `someip`, `doip`, `c1222`,
//!    `gesrtp`, `rocplus`, `bsap`, `knxnetip`.

pub(crate) mod amqp;
pub(crate) mod bacnet;
pub(crate) mod bsap;
pub(crate) mod c1222;
pub(crate) mod coap;
pub(crate) mod dcerpc;
pub(crate) mod dhcp;
pub(crate) mod diameter;
pub(crate) mod dnp3;
pub(crate) mod dns;
pub(crate) mod doh;
pub(crate) mod doip;
pub(crate) mod ethernetip;
pub(crate) mod fins;
pub(crate) mod ftp;
pub(crate) mod gesrtp;
pub(crate) mod grpc;
pub(crate) mod gtpc;
pub(crate) mod h323;
pub(crate) mod hartip;
pub(crate) mod http;
pub(crate) mod http2;
pub(crate) mod iec104;
pub(crate) mod imap;
pub(crate) mod ipfix;
pub(crate) mod ipmi;
pub(crate) mod irc;
pub(crate) mod iscsi;
pub(crate) mod kafka;
pub(crate) mod kerberos;
pub(crate) mod knxnetip;
pub(crate) mod ldap;
pub(crate) mod llmnr;
pub(crate) mod mdns;
pub(crate) mod melsec;
pub(crate) mod memcached;
pub(crate) mod mgcp;
pub(crate) mod mms;
pub(crate) mod modbus;
pub(crate) mod mongodb;
pub(crate) mod mqtt;
pub(crate) mod mssql;
pub(crate) mod mysql;
pub(crate) mod nbns;
pub(crate) mod netconf;
pub(crate) mod netflow;
pub(crate) mod nfs;
pub(crate) mod ngap;
pub(crate) mod ntlm;
pub(crate) mod ntp;
pub(crate) mod nvmetcp;
pub(crate) mod opcua;
pub(crate) mod pfcp;
pub(crate) mod pop3;
pub(crate) mod postgres;
pub(crate) mod ptp;
pub(crate) mod quic;
pub(crate) mod radius;
pub(crate) mod rdp;
pub(crate) mod redis;
pub(crate) mod rocev2;
pub(crate) mod rocplus;
pub(crate) mod rtcp;
pub(crate) mod rtp;
pub(crate) mod rtsp;
pub(crate) mod s1ap;
pub(crate) mod s7comm;
pub(crate) mod s7commplus;
pub(crate) mod sccp;
pub(crate) mod sflow;
pub(crate) mod sip;
pub(crate) mod smb;
pub(crate) mod smtp;
pub(crate) mod snmp1;
pub(crate) mod snmp2;
pub(crate) mod snmp3;
pub(crate) mod socks;
pub(crate) mod someip;
pub(crate) mod ssdp;
pub(crate) mod ssh;
pub(crate) mod stun;
pub(crate) mod synchrophasor;
pub(crate) mod syslog;
pub(crate) mod tacacs;
pub(crate) mod telnet;
pub(crate) mod tftp;
pub(crate) mod tls;
pub(crate) mod tns;
pub(crate) mod turn;
pub(crate) mod twamp;
pub(crate) mod vnc;
pub(crate) mod websocket;
pub(crate) mod whois;
pub(crate) mod wsdiscovery;

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt::Write as _;
use core::net::{IpAddr, Ipv4Addr};

use crate::ast::{Protocol, TransportProto};
use crate::reverse::{ProtocolDissection, escape_fasm_string, push_if};

/// Dispatches a TCP, UDP, or SCTP application-layer payload across all Layer 7 protocol dissectors.
pub(crate) fn dissect_l7(
    transport: TransportProto,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
    is_ipv6: bool,
    dst_ip: Option<IpAddr>,
) -> Option<ProtocolDissection> {
    if payload.is_empty() {
        return None;
    }
    let mut out = dissect_infra(transport, payload, src_port, dst_port, is_ipv6, dst_ip)
        .or_else(|| dissect_web(transport, payload, src_port, dst_port, dst_ip))
        .or_else(|| dissect_data_ot(transport, src_port, dst_port, payload))?;
    if matches!(transport, TransportProto::Sctp)
        && out.explicit_transport.is_none()
        && !matches!(out.protocol, Protocol::Ngap | Protocol::S1ap)
    {
        out.explicit_transport = Some(TransportProto::Sctp);
    }
    Some(out)
}

/// Invokes `f` if `sp` or `dp` matches any port in `ports`.
fn on_ports(
    sp: u16,
    dp: u16,
    ports: &[u16],
    f: impl FnOnce() -> Option<ProtocolDissection>,
) -> Option<ProtocolDissection> {
    ports.iter().any(|&p| sp == p || dp == p).then(f).flatten()
}

/// Dispatches Layer 7 infrastructure, SNMP, AAA, naming, time, cellular control, and flow telemetry protocols.
fn dissect_infra(
    transport: TransportProto,
    payload: &[u8],
    sp: u16,
    dp: u16,
    is_ipv6: bool,
    dst_ip: Option<IpAddr>,
) -> Option<ProtocolDissection> {
    if matches!(transport, TransportProto::Tcp) {
        return on_ports(sp, dp, &[53], || dns::dissect_dns(payload, true))
            .or_else(|| on_ports(sp, dp, &[5355], || llmnr::dissect_llmnr(payload, true)))
            .or_else(|| on_ports(sp, dp, &[49], || tacacs::dissect_tacacs(payload)))
            .or_else(|| {
                on_ports(sp, dp, &[514, 1514, 6514], || {
                    syslog::dissect_syslog(payload, true)
                })
            });
    }
    if matches!(transport, TransportProto::Sctp)
        && let Some(d) = on_ports(sp, dp, &[49], || tacacs::dissect_tacacs(payload))
    {
        return Some(d);
    }
    netflow::dissect_netflow(payload, sp, dp)
        .or_else(|| ipfix::dissect_ipfix(payload, sp, dp))
        .or_else(|| sflow::dissect_sflow(payload, sp, dp))
        .or_else(|| {
            on_ports(sp, dp, &[161, 162, 10161, 10162], || {
                snmp3::dissect_snmp3(payload)
                    .or_else(|| snmp2::dissect_snmp2(payload))
                    .or_else(|| snmp1::dissect_snmp1(payload, is_ipv6))
            })
        })
        .or_else(|| on_ports(sp, dp, &[53], || dns::dissect_dns(payload, false)))
        .or_else(|| on_ports(sp, dp, &[5353], || mdns::dissect_mdns(payload)))
        .or_else(|| on_ports(sp, dp, &[5355], || llmnr::dissect_llmnr(payload, false)))
        .or_else(|| on_ports(sp, dp, &[137], || nbns::dissect_nbns(payload)))
        .or_else(|| {
            on_ports(sp, dp, &[67, 68, 546, 547], || {
                dhcp::dissect_dhcp(payload, is_ipv6, dst_ip)
            })
        })
        .or_else(|| on_ports(sp, dp, &[123], || ntp::dissect_ntp(payload)))
        .or_else(|| on_ports(sp, dp, &[319, 320], || ptp::dissect_ptp(payload)))
        .or_else(|| {
            on_ports(sp, dp, &[1812, 1813, 1645, 1646], || {
                radius::dissect_radius(payload)
            })
        })
        .or_else(|| {
            on_ports(sp, dp, &[514, 1514, 6514], || {
                syslog::dissect_syslog(payload, false)
            })
        })
        .or_else(|| on_ports(sp, dp, &[623], || ipmi::dissect_ipmi(payload)))
        .or_else(|| on_ports(sp, dp, &[2123], || gtpc::dissect_gtpc(payload)))
        .or_else(|| on_ports(sp, dp, &[8805], || pfcp::dissect_pfcp(payload)))
}

/// Dispatches Layer 7 web, cloud-native, security, remote access, telecom, media, and VoIP protocols.
fn dissect_web(
    transport: TransportProto,
    payload: &[u8],
    src_port: u16,
    dst_port: u16,
    dst_ip: Option<IpAddr>,
) -> Option<ProtocolDissection> {
    let any_port = |ps: &[u16]| ps.contains(&src_port) || ps.contains(&dst_port);
    let p80 = any_port(&[80, 8080, 8000]);
    let p443 = any_port(&[443, 8443, 6443]);
    let p_sip = any_port(&[5060, 5061]);
    let p_grpc = any_port(&[50051, 50001, 2379, 9339, 9559, 7233, 8001]);
    let p_rtcp = any_port(&[5005, 50005, 10001, 10003, 60001]);
    let p_vnc = (5900..=5909).contains(&src_port) || (5900..=5909).contains(&dst_port);
    let p_irc = any_port(&[6665, 6666, 6667, 6668, 6669, 6697]);
    let is_h2 = payload.starts_with(http2::H2_PREFACE);
    let is_http = http::is_http_signature(payload);
    let is_ntlm = ntlm::is_ntlm_http_signature(payload);
    let is_sip = sip::is_sip_signature(payload);
    let is_tls = tls::is_tls_signature(payload);
    let is_grpc_h2 = grpc::is_http2_grpc_signature(payload);
    let is_stun_magic =
        payload.len() >= 20 && payload.get(4..8) == Some(&[0x21, 0x12, 0xA4, 0x42]);
    let try_h2 = |b: &[u8]| http2::dissect_http2(b, src_port, dst_port, dst_ip);
    let try_ws = |b: &[u8]| websocket::dissect_websocket(b, src_port, dst_port);
    if matches!(transport, TransportProto::Tcp | TransportProto::Sctp) {
        return None
            .or_else(|| p_grpc.then(|| grpc::dissect_grpc(payload, src_port, dst_port, true)).flatten())
            .or_else(|| is_grpc_h2.then(|| grpc::dissect_grpc(payload, src_port, dst_port, p_grpc)).flatten())
            .or_else(|| (p80 && is_ntlm).then(|| ntlm::dissect_ntlm(payload)).flatten())
            .or_else(|| p80.then(|| doh::dissect_doh(payload, src_port, dst_port, dst_ip)).flatten())
            .or_else(|| (p80 && is_h2).then(|| try_h2(payload)).flatten())
            .or_else(|| (p80 && is_http).then(|| http::dissect_http(payload)).flatten())
            .or_else(|| p80.then(|| try_h2(payload)).flatten())
            .or_else(|| p80.then(|| try_ws(payload)).flatten())
            .or_else(|| p80.then(|| http::dissect_http(payload)).flatten())
            .or_else(|| (p443 && is_ntlm).then(|| ntlm::dissect_ntlm(payload)).flatten())
            .or_else(|| p443.then(|| doh::dissect_doh(payload, src_port, dst_port, dst_ip)).flatten())
            .or_else(|| (p443 && is_h2).then(|| try_h2(payload)).flatten())
            .or_else(|| (p443 && is_tls).then(|| tls::dissect_tls(payload)).flatten())
            .or_else(|| p443.then(|| try_h2(payload)).flatten())
            .or_else(|| p443.then(|| try_ws(payload)).flatten())
            .or_else(|| (p443 && is_http).then(|| http::dissect_http(payload)).flatten())
            .or_else(|| any_port(&[21, 2121]).then(|| ftp::dissect_ftp(payload)).flatten())
            .or_else(|| any_port(&[830]).then(|| netconf::dissect_netconf(payload)).flatten())
            .or_else(|| any_port(&[22, 2222, 830]).then(|| ssh::dissect_ssh(payload)).flatten())
            .or_else(|| {
                any_port(&[4000])
                    .then(|| rocplus::dissect_rocplus(transport, src_port, dst_port, payload))
                    .flatten()
            })
            .or_else(|| any_port(&[23, 2323, 2001, 4000]).then(|| telnet::dissect_telnet(payload)).flatten())
            .or_else(|| any_port(&[43]).then(|| whois::dissect_whois(payload)).flatten())
            .or_else(|| any_port(&[554, 8554]).then(|| rtsp::dissect_rtsp(payload)).flatten())
            .or_else(|| p_sip.then(|| sip::dissect_sip(payload, transport)).flatten())
            .or_else(|| any_port(&[135]).then(|| dcerpc::dissect_dcerpc(payload)).flatten())
            .or_else(|| any_port(&[3389]).then(|| rdp::dissect_rdp(payload)).flatten())
            .or_else(|| any_port(&[1080]).then(|| socks::dissect_socks(transport, src_port, dst_port, payload)).flatten())
            .or_else(|| p_vnc.then(|| vnc::dissect_vnc(transport, src_port, dst_port, payload)).flatten())
            .or_else(|| p_irc.then(|| irc::dissect_irc(transport, src_port, dst_port, payload)).flatten())
            .or_else(|| any_port(&[1720]).then(|| h323::dissect_h323(transport, src_port, dst_port, payload)).flatten())
            .or_else(|| any_port(&[2000]).then(|| sccp::dissect_sccp(transport, src_port, dst_port, payload)).flatten())
            .or_else(|| any_port(&[3478]).then(|| turn::dissect_turn(transport, src_port, dst_port, payload)).flatten())
            .or_else(|| {
                (matches!(transport, TransportProto::Sctp) && any_port(&[3478, 19302]))
                    .then(|| stun::dissect_stun(payload))
                    .flatten()
            })
            .or_else(|| any_port(&[2427, 2727]).then(|| mgcp::dissect_mgcp(transport, src_port, dst_port, payload)).flatten())
            .or_else(|| any_port(&[862]).then(|| twamp::dissect_twamp(transport, src_port, dst_port, payload)).flatten())
            .or_else(|| (matches!(transport, TransportProto::Sctp) && p_rtcp).then(|| rtcp::dissect_rtcp(payload)).flatten())
            .or_else(|| {
                (matches!(transport, TransportProto::Sctp) && any_port(&[3702]))
                    .then(|| wsdiscovery::dissect_wsdiscovery(transport, src_port, dst_port, payload))
                    .flatten()
            })
            .or_else(|| {
                (matches!(transport, TransportProto::Sctp) && any_port(&[4791]))
                    .then(|| rocev2::dissect_rocev2(transport, src_port, dst_port, payload))
                    .flatten()
            })
            .or_else(|| {
                (matches!(transport, TransportProto::Sctp) && any_port(&[1900]))
                    .then(|| ssdp::dissect_ssdp(payload))
                    .flatten()
            })
            .or_else(|| is_h2.then(|| try_h2(payload)).flatten())
            .or_else(|| is_tls.then(|| tls::dissect_tls(payload)).flatten())
            .or_else(|| {
                (payload.starts_with(b"SSH-2.0-") || payload.starts_with(b"SSH-1.99-"))
                    .then(|| ssh::dissect_ssh(payload))
                    .flatten()
            })
            .or_else(|| netconf::dissect_netconf(payload))
            .or_else(|| rtsp::is_rtsp_signature(payload).then(|| rtsp::dissect_rtsp(payload)).flatten())
            .or_else(|| is_sip.then(|| sip::dissect_sip(payload, transport)).flatten())
            .or_else(|| mgcp::is_mgcp_signature(payload).then(|| mgcp::dissect_mgcp(transport, src_port, dst_port, payload)).flatten())
            .or_else(|| is_ntlm.then(|| ntlm::dissect_ntlm(payload)).flatten())
            .or_else(|| doh::dissect_doh(payload, src_port, dst_port, dst_ip))
            .or_else(|| is_http.then(|| http::dissect_http(payload)).flatten())
            .or_else(|| {
                (payload.starts_with(b"Domain Name: ")
                    && find_subslice(payload, b"\r\nRegistrar: ").is_some())
                .then(|| whois::dissect_whois(payload))
                .flatten()
            })
            .or_else(|| is_stun_magic.then(|| turn::dissect_turn(transport, src_port, dst_port, payload)).flatten())
            .or_else(|| {
                (matches!(transport, TransportProto::Sctp) && is_stun_magic)
                    .then(|| stun::dissect_stun(payload))
                    .flatten()
            })
            .or_else(|| {
                matches!(transport, TransportProto::Sctp)
                    .then(|| wsdiscovery::dissect_wsdiscovery(transport, src_port, dst_port, payload))
                    .flatten()
            });
    }

    let p_quic = p443
        || any_port(&[4433, 853, 179])
        || (any_port(&[5684])
            && ((payload[0] & 0x80) != 0 || payload.get(6..11) == Some(b"COAP_")));
    let p_rtp = any_port(&[5004, 50004, 10000, 10002, 60000]);
    None.or_else(|| p_quic.then(|| quic::dissect_quic(payload)).flatten())
        .or_else(|| {
            (any_port(&[69]) || (any_port(&[50100]) && any_port(&[54120])))
                .then(|| tftp::dissect_tftp(payload))
                .flatten()
        })
        .or_else(|| p_sip.then(|| sip::dissect_sip(payload, transport)).flatten())
        .or_else(|| p_rtp.then(|| rtp::dissect_rtp(payload)).flatten())
        .or_else(|| p_rtcp.then(|| rtcp::dissect_rtcp(payload)).flatten())
        .or_else(|| any_port(&[3478]).then(|| turn::dissect_turn(transport, src_port, dst_port, payload)).flatten())
        .or_else(|| any_port(&[3478, 19302]).then(|| stun::dissect_stun(payload)).flatten())
        .or_else(|| any_port(&[1719]).then(|| h323::dissect_h323(transport, src_port, dst_port, payload)).flatten())
        .or_else(|| any_port(&[2427, 2727]).then(|| mgcp::dissect_mgcp(transport, src_port, dst_port, payload)).flatten())
        .or_else(|| any_port(&[862]).then(|| twamp::dissect_twamp(transport, src_port, dst_port, payload)).flatten())
        .or_else(|| any_port(&[3702]).then(|| wsdiscovery::dissect_wsdiscovery(transport, src_port, dst_port, payload)).flatten())
        .or_else(|| any_port(&[4791]).then(|| rocev2::dissect_rocev2(transport, src_port, dst_port, payload)).flatten())
        .or_else(|| any_port(&[1900]).then(|| ssdp::dissect_ssdp(payload)).flatten())
        .or_else(|| {
            (payload.starts_with(b"M-SEARCH * HTTP/1.1\r\n")
                || payload.starts_with(b"NOTIFY * HTTP/1.1\r\n"))
            .then(|| ssdp::dissect_ssdp(payload))
            .flatten()
        })
        .or_else(|| is_sip.then(|| sip::dissect_sip(payload, transport)).flatten())
        .or_else(|| mgcp::is_mgcp_signature(payload).then(|| mgcp::dissect_mgcp(transport, src_port, dst_port, payload)).flatten())
        .or_else(|| wsdiscovery::dissect_wsdiscovery(transport, src_port, dst_port, payload))
        .or_else(|| is_stun_magic.then(|| turn::dissect_turn(transport, src_port, dst_port, payload)).flatten())
        .or_else(|| is_stun_magic.then(|| stun::dissect_stun(payload)).flatten())
        .or_else(|| {
            (payload.starts_with(&[0x06, 0x00, 0xFF]) && matches!(payload.get(3), Some(0x06 | 0x07)))
                .then(|| ipmi::dissect_ipmi(payload))
                .flatten()
        })
        .or_else(|| gtpc::dissect_gtpc(payload))
        .or_else(|| pfcp::dissect_pfcp(payload))
}

/// Dispatches Layer 7 mail, directory, storage, database, cache, telecom, messaging, and OT protocols.
fn dissect_data_ot(
    transport: TransportProto,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Option<ProtocolDissection> {
    let any_port = |ps: &[u16]| ps.contains(&src_port) || ps.contains(&dst_port);

    // 1. Port-prioritized dispatch across Data, Database, Telecom, and Industrial OT protocols.
    if any_port(&[25, 465, 587, 2525])
        && let Some(d) = smtp::dissect_smtp(transport, src_port, dst_port, payload)
    {
        return Some(d);
    }
    if any_port(&[143, 993])
        && let Some(d) = imap::dissect_imap(transport, src_port, dst_port, payload)
    {
        return Some(d);
    }
    if any_port(&[110, 995])
        && let Some(d) = pop3::dissect_pop3(transport, src_port, dst_port, payload)
    {
        return Some(d);
    }
    if any_port(&[445, 139])
        && let Some(d) = smb::dissect_smb(transport, src_port, dst_port, payload)
    {
        return Some(d);
    }
    if any_port(&[6379, 26379])
        && let Some(d) = redis::dissect_redis(transport, src_port, dst_port, payload)
    {
        return Some(d);
    }
    if any_port(&[3306])
        && let Some(d) = mysql::dissect_mysql(transport, src_port, dst_port, payload)
    {
        return Some(d);
    }
    if any_port(&[5432, 6432, 9999])
        && let Some(d) = postgres::dissect_postgres(transport, src_port, dst_port, payload)
    {
        return Some(d);
    }
    if any_port(&[1433])
        && let Some(d) = mssql::dissect_mssql(transport, src_port, dst_port, payload)
    {
        return Some(d);
    }
    if any_port(&[9092])
        && let Some(d) = kafka::dissect_kafka(transport, src_port, dst_port, payload)
    {
        return Some(d);
    }
    if any_port(&[27017])
        && let Some(d) = mongodb::dissect_mongodb(transport, src_port, dst_port, payload)
    {
        return Some(d);
    }
    if any_port(&[1521, 2483, 2484])
        && let Some(d) = tns::dissect_tns(transport, src_port, dst_port, payload)
    {
        return Some(d);
    }
    if any_port(&[3260])
        && let Some(d) = iscsi::dissect_iscsi(transport, src_port, dst_port, payload)
    {
        return Some(d);
    }
    if any_port(&[4420, 8009])
        && let Some(d) = nvmetcp::dissect_nvmetcp(transport, src_port, dst_port, payload)
    {
        return Some(d);
    }
    if any_port(&[88])
        && let Some(d) = kerberos::dissect_kerberos(transport, src_port, dst_port, payload)
    {
        return Some(d);
    }
    if any_port(&[389, 636, 3268])
        && let Some(d) = ldap::dissect_ldap(transport, src_port, dst_port, payload)
    {
        return Some(d);
    }
    if any_port(&[2049])
        && let Some(d) = nfs::dissect_nfs(transport, src_port, dst_port, payload)
    {
        return Some(d);
    }
    if any_port(&[11211, 11212])
        && let Some(d) = memcached::dissect_memcached(transport, src_port, dst_port, payload)
    {
        return Some(d);
    }
    if any_port(&[1883, 8883])
        && let Some(d) = mqtt::dissect_mqtt(transport, src_port, dst_port, payload)
    {
        return Some(d);
    }
    if any_port(&[5672, 5671])
        && let Some(d) = amqp::dissect_amqp(transport, src_port, dst_port, payload)
    {
        return Some(d);
    }
    if any_port(&[3868])
        && let Some(d) = diameter::dissect_diameter(transport, src_port, dst_port, payload)
    {
        return Some(d);
    }
    if any_port(&[38412])
        && let Some(d) = ngap::dissect_ngap(transport, src_port, dst_port, payload)
    {
        return Some(d);
    }
    if any_port(&[36412])
        && let Some(d) = s1ap::dissect_s1ap(transport, src_port, dst_port, payload)
    {
        return Some(d);
    }
    if any_port(&[102]) {
        if let Some(d) = s7comm::dissect_s7comm(transport, src_port, dst_port, payload) {
            return Some(d);
        }
        if let Some(d) = s7commplus::dissect_s7commplus(transport, src_port, dst_port, payload) {
            return Some(d);
        }
        if let Some(d) = mms::dissect_mms(transport, src_port, dst_port, payload) {
            return Some(d);
        }
    }
    if any_port(&[4840])
        && let Some(d) = opcua::dissect_opcua(transport, src_port, dst_port, payload)
    {
        return Some(d);
    }
    if any_port(&[5683, 5684])
        && let Some(d) = coap::dissect_coap(transport, src_port, dst_port, payload)
    {
        return Some(d);
    }
    if any_port(&[47808])
        && let Some(d) = bacnet::dissect_bacnet(transport, src_port, dst_port, payload)
    {
        return Some(d);
    }
    if any_port(&[502])
        && let Some(d) = modbus::dissect_modbus(transport, src_port, dst_port, payload)
    {
        return Some(d);
    }
    if any_port(&[20000])
        && let Some(d) = dnp3::dissect_dnp3(transport, src_port, dst_port, payload)
    {
        return Some(d);
    }
    if any_port(&[44818, 2222])
        && let Some(d) = ethernetip::dissect_ethernetip(transport, src_port, dst_port, payload)
    {
        return Some(d);
    }
    if any_port(&[2404])
        && let Some(d) = iec104::dissect_iec104(transport, src_port, dst_port, payload)
    {
        return Some(d);
    }
    if any_port(&[4712, 4713])
        && let Some(d) = synchrophasor::dissect_synchrophasor(transport, src_port, dst_port, payload)
    {
        return Some(d);
    }
    if any_port(&[5094])
        && let Some(d) = hartip::dissect_hartip(transport, src_port, dst_port, payload)
    {
        return Some(d);
    }
    if any_port(&[9600])
        && let Some(d) = fins::dissect_fins(transport, src_port, dst_port, payload)
    {
        return Some(d);
    }
    if any_port(&[5000, 5007])
        && let Some(d) = melsec::dissect_melsec(transport, src_port, dst_port, payload)
    {
        return Some(d);
    }
    if any_port(&[30490])
        && let Some(d) = someip::dissect_someip(transport, src_port, dst_port, payload)
    {
        return Some(d);
    }
    if any_port(&[13400])
        && let Some(d) = doip::dissect_doip(transport, src_port, dst_port, payload)
    {
        return Some(d);
    }
    if any_port(&[1153])
        && let Some(d) = c1222::dissect_c1222(transport, src_port, dst_port, payload)
    {
        return Some(d);
    }
    if any_port(&[18245])
        && let Some(d) = gesrtp::dissect_gesrtp(transport, src_port, dst_port, payload)
    {
        return Some(d);
    }
    if any_port(&[4000])
        && let Some(d) = rocplus::dissect_rocplus(transport, src_port, dst_port, payload)
    {
        return Some(d);
    }
    if any_port(&[1234])
        && let Some(d) = bsap::dissect_bsap(transport, src_port, dst_port, payload)
    {
        return Some(d);
    }
    if any_port(&[3671])
        && let Some(d) = knxnetip::dissect_knxnetip(transport, src_port, dst_port, payload)
    {
        return Some(d);
    }

    // 2. Signature-based fallback for custom-port flows across Data/OT/Telecom/TPKT dissectors.
    smb::dissect_smb(transport, src_port, dst_port, payload)
        .or_else(|| postgres::dissect_postgres(transport, src_port, dst_port, payload))
        .or_else(|| s7comm::dissect_s7comm(transport, src_port, dst_port, payload))
        .or_else(|| s7commplus::dissect_s7commplus(transport, src_port, dst_port, payload))
        .or_else(|| mms::dissect_mms(transport, src_port, dst_port, payload))
        .or_else(|| {
            (matches!(transport, TransportProto::Tcp | TransportProto::Sctp)
                && payload.starts_with(&[0x03, 0x00]))
            .then(|| h323::dissect_h323(transport, src_port, dst_port, payload))
            .flatten()
        })
        .or_else(|| {
            matches!(transport, TransportProto::Tcp | TransportProto::Sctp)
                .then(|| rdp::dissect_rdp(payload))
                .flatten()
        })
        .or_else(|| {
            matches!(transport, TransportProto::Tcp | TransportProto::Sctp)
                .then(|| dcerpc::dissect_dcerpc(payload))
                .flatten()
        })
        .or_else(|| opcua::dissect_opcua(transport, src_port, dst_port, payload))
        .or_else(|| amqp::dissect_amqp(transport, src_port, dst_port, payload))
        .or_else(|| mqtt::dissect_mqtt(transport, src_port, dst_port, payload))
        .or_else(|| bacnet::dissect_bacnet(transport, src_port, dst_port, payload))
        .or_else(|| dnp3::dissect_dnp3(transport, src_port, dst_port, payload))
        .or_else(|| ethernetip::dissect_ethernetip(transport, src_port, dst_port, payload))
        .or_else(|| nfs::dissect_nfs(transport, src_port, dst_port, payload))
        .or_else(|| kerberos::dissect_kerberos(transport, src_port, dst_port, payload))
        .or_else(|| memcached::dissect_memcached(transport, src_port, dst_port, payload))
        .or_else(|| iec104::dissect_iec104(transport, src_port, dst_port, payload))
        .or_else(|| synchrophasor::dissect_synchrophasor(transport, src_port, dst_port, payload))
        .or_else(|| hartip::dissect_hartip(transport, src_port, dst_port, payload))
        .or_else(|| {
            matches!(transport, TransportProto::Tcp)
                .then(|| fins::dissect_fins(transport, src_port, dst_port, payload))
                .flatten()
        })
        .or_else(|| melsec::dissect_melsec(transport, src_port, dst_port, payload))
        .or_else(|| someip::dissect_someip(transport, src_port, dst_port, payload))
        .or_else(|| doip::dissect_doip(transport, src_port, dst_port, payload))
        .or_else(|| c1222::dissect_c1222(transport, src_port, dst_port, payload))
        .or_else(|| rocplus::dissect_rocplus(transport, src_port, dst_port, payload))
        .or_else(|| knxnetip::dissect_knxnetip(transport, src_port, dst_port, payload))
        .or_else(|| diameter::dissect_diameter(transport, src_port, dst_port, payload))
        .or_else(|| mongodb::dissect_mongodb(transport, src_port, dst_port, payload))
        .or_else(|| tns::dissect_tns(transport, src_port, dst_port, payload))
        .or_else(|| iscsi::dissect_iscsi(transport, src_port, dst_port, payload))
        .or_else(|| nvmetcp::dissect_nvmetcp(transport, src_port, dst_port, payload))
}

/// Checks whether a byte slice is valid printable ASCII suitable for a `.frasm` string literal.
pub(crate) fn is_printable_ascii_str(bytes: &[u8]) -> Option<&str> {
    let s = core::str::from_utf8(bytes).ok()?;
    s.bytes().all(|b| (0x20..=0x7E).contains(&b)).then_some(s)
}

/// Formats `s` for `parse_raw_string_lit`, escaping only when raw syntax would mis-tokenize.
pub(crate) fn quote_raw_str(s: &str) -> String {
    if crate::reverse::is_valid_raw_string_body(s) {
        s.to_string()
    } else {
        escape_fasm_string(s)
    }
}

/// Appends ` <kw> "<quoted>"` to `out` when `val != default`.
pub(crate) fn push_str_if(out: &mut String, kw: &str, val: &str, default: &str) {
    if val != default {
        let _ = write!(out, " {kw} \"{}\"", quote_raw_str(val));
    }
}

/// Appends ` <kw> <v>` to `out` when `val` is `Some(v)`.
pub(crate) fn push_opt<T: core::fmt::Display>(out: &mut String, kw: &str, val: Option<T>) {
    if let Some(v) = val {
        let _ = write!(out, " {kw} {v}");
    }
}

/// Constructs a [`ProtocolDissection`] with default L4 transport.
pub(crate) fn ok_dissect(
    protocol: Protocol,
    tokens: String,
    residual_payload: Vec<u8>,
) -> Option<ProtocolDissection> {
    Some(ProtocolDissection {
        protocol,
        tokens,
        residual_payload,
        explicit_transport: None,
    })
}

/// Appends common NetFlow/IPFIX flow record fields (`srcip`, `dstip`, `proto`, `packets`, `octets`).
pub(crate) fn append_flow_record_tokens(
    tokens: &mut String,
    flow_src: Ipv4Addr,
    flow_dst: Ipv4Addr,
    proto: u8,
    packets: u32,
    octets: u32,
) {
    let _ = write!(tokens, " srcip {flow_src} dstip {flow_dst}");
    push_if(tokens, "proto", proto, 6);
    push_if(tokens, "packets", packets, 1);
    push_if(tokens, "octets", octets, 64);
}

/// Reads a checked big-endian `u16` at `offset` from `buf`.
pub(crate) fn checked_be_u16(buf: &[u8], offset: usize) -> Option<u16> {
    let b = buf.get(offset..offset.checked_add(2)?)?;
    Some(u16::from_be_bytes([b[0], b[1]]))
}

/// Reads a checked big-endian `u32` at `offset` from `buf`.
pub(crate) fn checked_be_u32(buf: &[u8], offset: usize) -> Option<u32> {
    let b = buf.get(offset..offset.checked_add(4)?)?;
    Some(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
}

/// Checks whether a string slice can be placed inside `"..."` in `.frasm` source and round-tripped
/// verbatim through `Token::StringLit` and `parse_raw_string_lit`.
pub(crate) fn is_valid_raw_string_body(s: &str) -> bool {
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if b < 0x20 || b == 0x7f || b == b'"' {
            return false;
        }
        if b == b'\\' {
            if bytes.get(i + 1).is_none_or(|&n| n < 0x20 || n == 0x7f) {
                return false;
            }
            i += 2;
            continue;
        }
        i += 1;
    }
    crate::parser::ident::unescape_bytes(s).is_ok()
}

/// Formats a string value as a quoted `.frasm` string literal (`"..."`), preserving existing valid
/// escape sequences for `parse_raw_string_lit` and escaping raw quotes or control characters.
pub(crate) fn quote_web_str(s: &str) -> String {
    if is_valid_raw_string_body(s) {
        format!("\"{s}\"")
    } else {
        format!("\"{}\"", escape_fasm_string(s))
    }
}

/// Appends `" <key> \"<val>\""` to `tokens`.
pub(crate) fn push_str_mod(tokens: &mut String, key: &str, val: &str) {
    let _ = write!(tokens, " {key} {}", quote_web_str(val));
}

/// Appends `<key> "<str>"` if `body_bytes` is valid raw UTF-8, or returns `body_bytes` as residual payload.
pub(crate) fn attach_text_body(tokens: &mut String, key: &str, body_bytes: &[u8]) -> Vec<u8> {
    if body_bytes.is_empty() {
        return Vec::new();
    }
    if let Ok(s) = core::str::from_utf8(body_bytes)
        && is_valid_raw_string_body(s)
    {
        push_str_mod(tokens, key, s);
        Vec::new()
    } else {
        body_bytes.to_vec()
    }
}

/// Searches for the first occurrence of `needle` inside `haystack`.
pub(crate) fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Splits a CRLF-delimited header block (`\r\n\r\n`) into its UTF-8 header text and trailing body.
pub(crate) fn split_crlf_headers(payload: &[u8]) -> Option<(&str, &[u8])> {
    let hdr_end = find_subslice(payload, b"\r\n\r\n")?;
    Some((
        core::str::from_utf8(payload.get(..hdr_end)?).ok()?,
        payload.get(hdr_end + 4..)?,
    ))
}

/// Extracts the first CRLF-terminated line from `payload` as a UTF-8 string slice.
pub(crate) fn first_crlf_line(payload: &[u8]) -> Option<&str> {
    let crlf = find_subslice(payload, b"\r\n")?;
    core::str::from_utf8(payload.get(..crlf)?).ok()
}
