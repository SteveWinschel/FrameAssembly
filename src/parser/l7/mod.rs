//! Layer 7 application, infrastructure, telemetry, and industrial OT protocol field parsers.
//!
//! This module organizes the syntactic combinator parsers for all 50 Layer 7 protocols supported by
//! the FrameAssembly language, including core infrastructure services (`DNS`, `mDNS`, `DHCP`, `NTP`,
//! `PTP`), network management and telemetry (`SNMPv1`/`v2c`/`v3`, `RADIUS`, `TACACS+`, `Syslog`,
//! `NetFlow`, `IPFIX`, `sFlow`), web and RPC transport (`HTTP/1.1`, `HTTP/2`, `gRPC`, `WebSocket`,
//! `TLS`, `QUIC`), real-time media (`STUN`, `SIP`, `RTP`, `RTSP`), enterprise directory and storage
//! (`SMTP`, `IMAP`, `POP3`, `Kerberos`, `LDAP`, `SMB`, `NFS`, `SSH`, `Telnet`, `FTP`, `TFTP`),
//! data/IoT messaging (`Redis`, `Memcached`, `MySQL`, `PostgreSQL`, `MQTT`, `CoAP`, `AMQP`, `SSDP`,
//! `WHOIS`), and industrial SCADA/OT (`Modbus`, `BACnet`, `DNP3`, `S7comm`, `EtherNet/IP`, `OPC UA`).

use winnow::ModalResult as PResult;
use winnow::combinator::alt;
use winnow::prelude::*;

use crate::parser::{ParsedField, Stream};

/// AMQP protocol parser.
pub(crate) mod amqp;
/// BACNET protocol parser.
pub(crate) mod bacnet;
/// COAP protocol parser.
pub(crate) mod coap;
/// DHCP protocol parser.
pub(crate) mod dhcp;
/// DNP3 protocol parser.
pub(crate) mod dnp3;
/// DNS protocol parser.
pub(crate) mod dns;
/// ETHERNETIP protocol parser.
pub(crate) mod ethernetip;
/// FTP protocol parser.
pub(crate) mod ftp;
/// GRPC protocol parser.
pub(crate) mod grpc;
/// HTTP protocol parser.
pub(crate) mod http;
/// HTTP2 protocol parser.
pub(crate) mod http2;
/// IMAP protocol parser.
pub(crate) mod imap;
/// IPFIX protocol parser.
pub(crate) mod ipfix;
/// KERBEROS protocol parser.
pub(crate) mod kerberos;
/// LDAP protocol parser.
pub(crate) mod ldap;
/// MDNS protocol parser.
pub(crate) mod mdns;
/// MEMCACHED protocol parser.
pub(crate) mod memcached;
/// MODBUS protocol parser.
pub(crate) mod modbus;
/// MQTT protocol parser.
pub(crate) mod mqtt;
/// MYSQL protocol parser.
pub(crate) mod mysql;
/// NETFLOW protocol parser.
pub(crate) mod netflow;
/// NFS protocol parser.
pub(crate) mod nfs;
/// NTP protocol parser.
pub(crate) mod ntp;
/// OPCUA protocol parser.
pub(crate) mod opcua;
/// POP3 protocol parser.
pub(crate) mod pop3;
/// POSTGRES protocol parser.
pub(crate) mod postgres;
/// PTP protocol parser.
pub(crate) mod ptp;
/// QUIC protocol parser.
pub(crate) mod quic;
/// RADIUS protocol parser.
pub(crate) mod radius;
/// REDIS protocol parser.
pub(crate) mod redis;
/// RTP protocol parser.
pub(crate) mod rtp;
/// RTSP protocol parser.
pub(crate) mod rtsp;
/// S7COMM protocol parser.
pub(crate) mod s7comm;
/// SFLOW protocol parser.
pub(crate) mod sflow;
/// SIP protocol parser.
pub(crate) mod sip;
/// SMB protocol parser.
pub(crate) mod smb;
/// SMTP protocol parser.
pub(crate) mod smtp;
/// SNMP protocol parser.
pub(crate) mod snmp;
/// SSDP protocol parser.
pub(crate) mod ssdp;
/// SSH protocol parser.
pub(crate) mod ssh;
/// STUN protocol parser.
pub(crate) mod stun;
/// SYSLOG protocol parser.
pub(crate) mod syslog;
/// TACACS protocol parser.
pub(crate) mod tacacs;
/// TELNET protocol parser.
pub(crate) mod telnet;
/// TFTP protocol parser.
pub(crate) mod tftp;
/// TLS protocol parser.
pub(crate) mod tls;
/// WEBSOCKET protocol parser.
pub(crate) mod websocket;
/// WHOIS protocol parser.
pub(crate) mod whois;

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
