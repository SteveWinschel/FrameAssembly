//! Layer 7 application, infrastructure, telemetry, enterprise, 5G/4G telecom, storage, and OT parsers.
//!
//! This module organizes the syntactic combinator parsers for all 94 Layer 7 protocols supported by
//! FrameAssembly across infrastructure services (`dns`, `mdns`, `llmnr`, `nbns`, `dhcp`, `ntp`,
//! `ptp`), management (`SNMPv1`/`v2c`/`v3`, `radius`, `tacacs+`, `Syslog`, `netconf`, `ipmi`,
//! `twamp`), web/RPC (`http`, `http2`, `doh`, `grpc`, `websocket`, `tls`, `quic`, `dcerpc`,
//! `ntlm`, `rdp`, `socks`, `vnc`, `wsdiscovery`), media (`stun`, `turn`, `sip`, `rtp`, `rtcp`,
//! `rtsp`, `h323`, `sccp`, `mgcp`), databases/queues (`mssql`, `kafka`, `mongodb`, `tns`,
//! `mysql`, `postgres`, `redis`, `memcached`, `mqtt`, `coap`, `amqp`), storage (`iscsi`, `nvmetcp`,
//! `smb`, `nfs`), telecom (`diameter`, `gtpc`, `pfcp`, `ngap`, `s1ap`), and OT/ICS (`modbus`,
//! `bacnet`, `dnp3`, `s7comm`, `s7commplus`, `iec104`, `mms`, `synchrophasor`, `hartip`, `fins`,
//! `melsec`, `someip`, `doip`, `c1222`, `gesrtp`, `rocplus`, `bsap`, `knxnetip`, `rocev2`).

use winnow::ModalResult as PResult;
use winnow::combinator::alt;
use winnow::prelude::*;

use crate::parser::{ParsedField, Stream};

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
pub(crate) mod snmp;
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

pub(crate) use amqp::*;
pub(crate) use bacnet::*;
pub(crate) use bsap::*;
pub(crate) use c1222::*;
pub(crate) use coap::*;
pub(crate) use dcerpc::*;
pub(crate) use dhcp::*;
pub(crate) use diameter::*;
pub(crate) use dnp3::*;
pub(crate) use dns::*;
pub(crate) use doh::*;
pub(crate) use doip::*;
pub(crate) use ethernetip::*;
pub(crate) use fins::*;
pub(crate) use ftp::*;
pub(crate) use gesrtp::*;
pub(crate) use grpc::*;
pub(crate) use gtpc::*;
pub(crate) use h323::*;
pub(crate) use hartip::*;
pub(crate) use http::*;
pub(crate) use http2::*;
pub(crate) use iec104::*;
pub(crate) use imap::*;
pub(crate) use ipfix::*;
pub(crate) use ipmi::*;
pub(crate) use irc::*;
pub(crate) use iscsi::*;
pub(crate) use kafka::*;
pub(crate) use kerberos::*;
pub(crate) use knxnetip::*;
pub(crate) use ldap::*;
pub(crate) use llmnr::*;
pub(crate) use mdns::*;
pub(crate) use melsec::*;
pub(crate) use memcached::*;
pub(crate) use mgcp::*;
pub(crate) use mms::*;
pub(crate) use modbus::*;
pub(crate) use mongodb::*;
pub(crate) use mqtt::*;
pub(crate) use mssql::*;
pub(crate) use mysql::*;
pub(crate) use nbns::*;
pub(crate) use netconf::*;
pub(crate) use netflow::*;
pub(crate) use nfs::*;
pub(crate) use ngap::*;
pub(crate) use ntlm::*;
pub(crate) use ntp::*;
pub(crate) use nvmetcp::*;
pub(crate) use opcua::*;
pub(crate) use pfcp::*;
pub(crate) use pop3::*;
pub(crate) use postgres::*;
pub(crate) use ptp::*;
pub(crate) use quic::*;
pub(crate) use radius::*;
pub(crate) use rdp::*;
pub(crate) use redis::*;
pub(crate) use rocev2::*;
pub(crate) use rocplus::*;
pub(crate) use rtcp::*;
pub(crate) use rtp::*;
pub(crate) use rtsp::*;
pub(crate) use s1ap::*;
pub(crate) use s7comm::*;
pub(crate) use s7commplus::*;
pub(crate) use sccp::*;
pub(crate) use sflow::*;
pub(crate) use sip::*;
pub(crate) use smb::*;
pub(crate) use smtp::*;
pub(crate) use snmp::*;
pub(crate) use socks::*;
pub(crate) use someip::*;
pub(crate) use ssdp::*;
pub(crate) use ssh::*;
pub(crate) use stun::*;
pub(crate) use synchrophasor::*;
pub(crate) use syslog::*;
pub(crate) use tacacs::*;
pub(crate) use telnet::*;
pub(crate) use tftp::*;
pub(crate) use tls::*;
pub(crate) use tns::*;
pub(crate) use turn::*;
pub(crate) use twamp::*;
pub(crate) use vnc::*;
pub(crate) use websocket::*;
pub(crate) use whois::*;
pub(crate) use wsdiscovery::*;

/// Parses core Layer 7 protocol declarations and attribute fields (`<= 8` `alt` arms per tuple).
pub(crate) fn parse_legacy_l7_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
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

/// Parses extended Layer 7 enterprise, telecom, storage, and OT/ICS protocol fields (`<= 8` `alt` arms).
pub(crate) fn parse_ext_l7_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        alt((
            parse_bsap_field,
            parse_c1222_field,
            parse_dcerpc_field,
            parse_diameter_field,
            parse_doh_field,
            parse_doip_field,
            parse_fins_field,
            parse_gesrtp_field,
        )),
        alt((
            parse_gtpc_field,
            parse_h323_field,
            parse_hartip_field,
            parse_iec104_field,
            parse_ipmi_field,
            parse_irc_field,
            parse_iscsi_field,
            parse_kafka_field,
        )),
        alt((
            parse_knxnetip_field,
            parse_llmnr_field,
            parse_melsec_field,
            parse_mgcp_field,
            parse_mms_field,
            parse_mongodb_field,
            parse_mssql_field,
            parse_nbns_field,
        )),
        alt((
            parse_netconf_field,
            parse_ngap_field,
            parse_ntlm_field,
            parse_nvmetcp_field,
            parse_pfcp_field,
            parse_rdp_field,
            parse_rocev2_field,
            parse_rocplus_field,
        )),
        alt((
            parse_rtcp_field,
            parse_s1ap_field,
            parse_s7commplus_field,
            parse_sccp_field,
            parse_socks_field,
            parse_someip_field,
            parse_synchrophasor_field,
            parse_tns_field,
        )),
        alt((
            parse_turn_field,
            parse_twamp_field,
            parse_vnc_field,
            parse_wsdiscovery_field,
        )),
    ))
    .parse_next(input)
}

/// Parses a Layer 7 protocol declaration or protocol-specific attribute field from a token stream.
#[allow(dead_code)]
pub(crate) fn parse_l7_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((parse_legacy_l7_field, parse_ext_l7_field)).parse_next(input)
}
