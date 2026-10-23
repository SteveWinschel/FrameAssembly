//! Layer 7 application, infrastructure, telemetry, and industrial OT protocol field parsers.

use winnow::ModalResult as PResult;
use winnow::combinator::alt;
use winnow::prelude::*;

use crate::parser::{ParsedField, Stream};

/// AMQP protocol parser.
pub mod amqp;
/// BACNET protocol parser.
pub mod bacnet;
/// COAP protocol parser.
pub mod coap;
/// DHCP protocol parser.
pub mod dhcp;
/// DNP3 protocol parser.
pub mod dnp3;
/// DNS protocol parser.
pub mod dns;
/// ETHERNETIP protocol parser.
pub mod ethernetip;
/// FTP protocol parser.
pub mod ftp;
/// GRPC protocol parser.
pub mod grpc;
/// HTTP protocol parser.
pub mod http;
/// HTTP2 protocol parser.
pub mod http2;
/// IMAP protocol parser.
pub mod imap;
/// IPFIX protocol parser.
pub mod ipfix;
/// KERBEROS protocol parser.
pub mod kerberos;
/// LDAP protocol parser.
pub mod ldap;
/// MDNS protocol parser.
pub mod mdns;
/// MEMCACHED protocol parser.
pub mod memcached;
/// MODBUS protocol parser.
pub mod modbus;
/// MQTT protocol parser.
pub mod mqtt;
/// MYSQL protocol parser.
pub mod mysql;
/// NETFLOW protocol parser.
pub mod netflow;
/// NFS protocol parser.
pub mod nfs;
/// NTP protocol parser.
pub mod ntp;
/// OPCUA protocol parser.
pub mod opcua;
/// POP3 protocol parser.
pub mod pop3;
/// POSTGRES protocol parser.
pub mod postgres;
/// PTP protocol parser.
pub mod ptp;
/// QUIC protocol parser.
pub mod quic;
/// RADIUS protocol parser.
pub mod radius;
/// REDIS protocol parser.
pub mod redis;
/// RTP protocol parser.
pub mod rtp;
/// RTSP protocol parser.
pub mod rtsp;
/// S7COMM protocol parser.
pub mod s7comm;
/// SFLOW protocol parser.
pub mod sflow;
/// SIP protocol parser.
pub mod sip;
/// SMB protocol parser.
pub mod smb;
/// SMTP protocol parser.
pub mod smtp;
/// SNMP protocol parser.
pub mod snmp;
/// SSDP protocol parser.
pub mod ssdp;
/// SSH protocol parser.
pub mod ssh;
/// STUN protocol parser.
pub mod stun;
/// SYSLOG protocol parser.
pub mod syslog;
/// TACACS protocol parser.
pub mod tacacs;
/// TELNET protocol parser.
pub mod telnet;
/// TFTP protocol parser.
pub mod tftp;
/// TLS protocol parser.
pub mod tls;
/// WEBSOCKET protocol parser.
pub mod websocket;
/// WHOIS protocol parser.
pub mod whois;

pub(crate) use amqp::*;
pub(crate) use bacnet::*;
pub(crate) use coap::*;
pub(crate) use dhcp::*;
pub(crate) use dnp3::*;
pub(crate) use dns::*;
pub(crate) use ethernetip::*;
pub(crate) use ftp::*;
pub(crate) use grpc::*;
pub(crate) use http::*;
pub(crate) use http2::*;
pub(crate) use imap::*;
pub(crate) use ipfix::*;
pub(crate) use kerberos::*;
pub(crate) use ldap::*;
pub(crate) use mdns::*;
pub(crate) use memcached::*;
pub(crate) use modbus::*;
pub(crate) use mqtt::*;
pub(crate) use mysql::*;
pub(crate) use netflow::*;
pub(crate) use nfs::*;
pub(crate) use ntp::*;
pub(crate) use opcua::*;
pub(crate) use pop3::*;
pub(crate) use postgres::*;
pub(crate) use ptp::*;
pub(crate) use quic::*;
pub(crate) use radius::*;
pub(crate) use redis::*;
pub(crate) use rtp::*;
pub(crate) use rtsp::*;
pub(crate) use s7comm::*;
pub(crate) use sflow::*;
pub(crate) use sip::*;
pub(crate) use smb::*;
pub(crate) use smtp::*;
pub(crate) use snmp::*;
pub(crate) use ssdp::*;
pub(crate) use ssh::*;
pub(crate) use stun::*;
pub(crate) use syslog::*;
pub(crate) use tacacs::*;
pub(crate) use telnet::*;
pub(crate) use tftp::*;
pub(crate) use tls::*;
pub(crate) use websocket::*;
pub(crate) use whois::*;

/// Parses a Layer 7 protocol declaration or protocol-specific attribute field from a token stream.
pub(crate) fn parse_l7_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        alt((
            parse_amqp_field,
            parse_bacnet_field,
            parse_coap_field,
            parse_dhcp_field,
            parse_dnp3_field,
            parse_dns_field,
            parse_ethernetip_field,
            parse_ftp_field,
        )),
        alt((
            parse_grpc_field,
            parse_http_field,
            parse_http2_field,
            parse_imap_field,
            parse_ipfix_field,
            parse_kerberos_field,
            parse_ldap_field,
            parse_mdns_field,
        )),
        alt((
            parse_memcached_field,
            parse_modbus_field,
            parse_mqtt_field,
            parse_mysql_field,
            parse_netflow_field,
            parse_nfs_field,
            parse_ntp_field,
            parse_opcua_field,
        )),
        alt((
            parse_pop3_field,
            parse_postgres_field,
            parse_ptp_field,
            parse_quic_field,
            parse_radius_field,
            parse_redis_field,
            parse_rtp_field,
            parse_rtsp_field,
        )),
        alt((
            parse_s7comm_field,
            parse_sflow_field,
            parse_sip_field,
            parse_smb_field,
            parse_smtp_field,
            parse_snmp_field,
            parse_ssdp_field,
            parse_ssh_field,
        )),
        alt((
            parse_stun_field,
            parse_syslog_field,
            parse_tacacs_field,
            parse_telnet_field,
            parse_tftp_field,
            parse_tls_field,
            parse_websocket_field,
            parse_whois_field,
        )),
    ))
    .parse_next(input)
}
