//! Layer 7 application, infrastructure, telemetry, and industrial OT protocol field parsers.
//!
//! This module organizes the syntactic combinator parsers for all 50 Layer 7 protocols supported by
//! the FrameAssembly language, including core infrastructure services (`dns`, `mdns`, `dhcp`, `ntp`,
//! `ptp`), network management and telemetry (`SNMPv1`/`v2c`/`v3`, `radius`, `tacacs+`, `Syslog`,
//! `NetFlow`, `ipfix`, `sFlow`), web and RPC transport (`http/1.1`, `http/2`, `gRPC`, `WebSocket`,
//! `tls`, `quic`), real-time media (`stun`, `sip`, `rtp`, `rtsp`), enterprise directory and storage
//! (`smtp`, `imap`, `pop3`, `Kerberos`, `ldap`, `smb`, `nfs`, `ssh`, `Telnet`, `ftp`, `tftp`),
//! data/IoT messaging (`Redis`, `Memcached`, `MySQL`, `PostgreSQL`, `mqtt`, `CoAP`, `amqp`, `ssdp`,
//! `whois`), and industrial SCADA/OT (`Modbus`, `BACnet`, `dnp3`, `S7comm`, `EtherNet/IP`, `OPC UA`).

use winnow::ModalResult as PResult;
use winnow::combinator::alt;
use winnow::prelude::*;

use crate::parser::{ParsedField, Stream};

pub(crate) mod amqp;
pub(crate) mod bacnet;
pub(crate) mod coap;
pub(crate) mod dhcp;
pub(crate) mod dnp3;
pub(crate) mod dns;
pub(crate) mod ethernetip;
pub(crate) mod ftp;
pub(crate) mod grpc;
pub(crate) mod http;
pub(crate) mod http2;
pub(crate) mod imap;
pub(crate) mod ipfix;
pub(crate) mod kerberos;
pub(crate) mod ldap;
pub(crate) mod mdns;
pub(crate) mod memcached;
pub(crate) mod modbus;
pub(crate) mod mqtt;
pub(crate) mod mysql;
pub(crate) mod netflow;
pub(crate) mod nfs;
pub(crate) mod ntp;
pub(crate) mod opcua;
pub(crate) mod pop3;
pub(crate) mod postgres;
pub(crate) mod ptp;
pub(crate) mod quic;
pub(crate) mod radius;
pub(crate) mod redis;
pub(crate) mod rtp;
pub(crate) mod rtsp;
pub(crate) mod s7comm;
pub(crate) mod sflow;
pub(crate) mod sip;
pub(crate) mod smb;
pub(crate) mod smtp;
pub(crate) mod snmp;
pub(crate) mod ssdp;
pub(crate) mod ssh;
pub(crate) mod stun;
pub(crate) mod syslog;
pub(crate) mod tacacs;
pub(crate) mod telnet;
pub(crate) mod tftp;
pub(crate) mod tls;
pub(crate) mod websocket;
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
