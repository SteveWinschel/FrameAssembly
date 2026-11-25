//! Layer 7 field accumulation and application-layer modifier dispatch for [`FrameBuilder`].
//!
//! This module implements [`FrameBuilder::apply_l7_field`], which updates the statement
//! accumulator's protocol-specific Layer 7 [`ProtocolSpec`] state when
//! an [`L7StringField`](super::fields::ParsedField::L7StringField),
//! [`L7U32Field`](super::fields::ParsedField::L7U32Field),
//! [`L7I32Field`](super::fields::ParsedField::L7I32Field),
//! [`L7U64Field`](super::fields::ParsedField::L7U64Field),
//! [`L7BytesField`](super::fields::ParsedField::L7BytesField),
//! [`StunXorMapped`](super::fields::ParsedField::StunXorMapped),
//! [`L7IpField`](super::fields::ParsedField::L7IpField),
//! [`L7MacField`](super::fields::ParsedField::L7MacField),
//! [`L7Flag`](super::fields::ParsedField::L7Flag), or
//! [`L7Header`](super::fields::ParsedField::L7Header) modifier is parsed from a frame statement.
//! It records modifier spans for duplicate detection, advances the statement end byte offset, and
//! routes each keyed attribute to the corresponding Layer 7 specification struct.

use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::ast::{BmpType, GlbpType, GtpuType, IpipVersion, IsisPduType, LdpType, LispType, PppoeStage, RpkirtrType, RsvpType};

use super::fields::ParsedField;
use super::statement::FrameBuilder;

/// Decodes a packed `[family(1), ip(4|16), optional port_be(4)]` buffer produced by `TURN` and `H.323` address parsers.
fn decode_packed_addr_port(bytes: &[u8]) -> Option<(IpAddr, Option<u32>)> {
    match bytes.first().copied() {
        Some(4) if bytes.len() == 5 || bytes.len() == 9 => {
            let ip = IpAddr::V4(Ipv4Addr::new(bytes[1], bytes[2], bytes[3], bytes[4]));
            let port = if bytes.len() == 9 {
                Some(u32::from_be_bytes([bytes[5], bytes[6], bytes[7], bytes[8]]))
            } else {
                None
            };
            Some((ip, port))
        }
        Some(6) if bytes.len() == 17 || bytes.len() == 21 => {
            let mut oct = [0u8; 16];
            oct.copy_from_slice(&bytes[1..17]);
            let ip = IpAddr::V6(Ipv6Addr::from(oct));
            let port = if bytes.len() == 21 {
                Some(u32::from_be_bytes([bytes[17], bytes[18], bytes[19], bytes[20]]))
            } else {
                None
            };
            Some((ip, port))
        }
        _ => None,
    }
}

/// Maps an internal IS-IS PDU discriminator string to [`IsisPduType`].
fn parse_isis_pdu_type(raw: &str) -> Option<IsisPduType> {
    match raw.trim().to_ascii_uppercase().replace(['_', '-'], "").as_str() {
        "L1IIH" => Some(IsisPduType::L1Iih),
        "L2IIH" => Some(IsisPduType::L2Iih),
        "P2PIIH" => Some(IsisPduType::P2pIih),
        "L1LSP" => Some(IsisPduType::L1Lsp),
        "L2LSP" => Some(IsisPduType::L2Lsp),
        "L1CSNP" => Some(IsisPduType::L1Csnp),
        "L2CSNP" => Some(IsisPduType::L2Csnp),
        "L1PSNP" => Some(IsisPduType::L1Psnp),
        "L2PSNP" => Some(IsisPduType::L2Psnp),
        _ => None,
    }
}

/// Maps a PPPoE stage string to [`PppoeStage`].
fn parse_pppoe_stage(raw: &str) -> Option<PppoeStage> {
    match raw.trim().to_ascii_uppercase().as_str() {
        "PADI" => Some(PppoeStage::Padi),
        "PADO" => Some(PppoeStage::Pado),
        "PADR" => Some(PppoeStage::Padr),
        "PADS" => Some(PppoeStage::Pads),
        "PADT" => Some(PppoeStage::Padt),
        "SESSION" => Some(PppoeStage::Session),
        _ => None,
    }
}

/// Maps an RSVP message discriminator string to [`RsvpType`].
fn parse_rsvp_type(raw: &str) -> Option<RsvpType> {
    match raw.trim().to_ascii_lowercase().replace(['_', '-'], "").as_str() {
        "path" => Some(RsvpType::Path),
        "resv" => Some(RsvpType::Resv),
        "patherr" => Some(RsvpType::PathErr),
        "resverr" => Some(RsvpType::ResvErr),
        "pathtear" => Some(RsvpType::PathTear),
        "resvtear" => Some(RsvpType::ResvTear),
        "resvconf" => Some(RsvpType::ResvConf),
        "hello" => Some(RsvpType::Hello),
        _ => None,
    }
}

/// Maps an LDP message discriminator string to [`LdpType`].
fn parse_ldp_type(raw: &str) -> Option<LdpType> {
    match raw.trim().to_ascii_lowercase().replace(['_', '-'], "").as_str() {
        "hello" => Some(LdpType::Hello),
        "init" => Some(LdpType::Init),
        "keepalive" => Some(LdpType::Keepalive),
        "notification" => Some(LdpType::Notification),
        "labelmapping" => Some(LdpType::LabelMapping),
        "labelrequest" => Some(LdpType::LabelRequest),
        "labelwithdraw" => Some(LdpType::LabelWithdraw),
        "labelrelease" => Some(LdpType::LabelRelease),
        _ => None,
    }
}

/// Maps a BMP message type string to [`BmpType`].
fn parse_bmp_type(raw: &str) -> Option<BmpType> {
    match raw.trim().to_ascii_uppercase().replace(['_', '-'], "").as_str() {
        "ROUTEMON" | "ROUTEMONITORING" => Some(BmpType::RouteMonitoring),
        "STATSREPORT" => Some(BmpType::StatsReport),
        "PEERDOWN" => Some(BmpType::PeerDown),
        "PEERUP" => Some(BmpType::PeerUp),
        "INITIATION" => Some(BmpType::Initiation),
        "TERMINATION" => Some(BmpType::Termination),
        _ => None,
    }
}

/// Maps an RPKI-RTR PDU type string to [`RpkirtrType`].
fn parse_rpkirtr_type(raw: &str) -> Option<RpkirtrType> {
    match raw.trim().to_ascii_uppercase().replace(['_', '-'], "").as_str() {
        "SERIALNOTIFY" => Some(RpkirtrType::SerialNotify),
        "SERIALQUERY" => Some(RpkirtrType::SerialQuery),
        "RESETQUERY" => Some(RpkirtrType::ResetQuery),
        "CACHERESPONSE" => Some(RpkirtrType::CacheResponse),
        "IPV4PREFIX" => Some(RpkirtrType::Ipv4Prefix),
        "IPV6PREFIX" => Some(RpkirtrType::Ipv6Prefix),
        "ENDOFDATA" => Some(RpkirtrType::EndOfData),
        "CACHERESET" => Some(RpkirtrType::CacheReset),
        "ERRORREPORT" => Some(RpkirtrType::ErrorReport),
        _ => None,
    }
}

/// Maps a LISP packet type string to [`LispType`].
fn parse_lisp_type(raw: &str) -> Option<LispType> {
    match raw.trim().to_ascii_uppercase().replace(['_', '-'], "").as_str() {
        "DATA" => Some(LispType::Data),
        "MAPREQUEST" => Some(LispType::MapRequest),
        "MAPREPLY" => Some(LispType::MapReply),
        "MAPREGISTER" => Some(LispType::MapRegister),
        "MAPNOTIFY" => Some(LispType::MapNotify),
        "ECM" => Some(LispType::Ecm),
        _ => None,
    }
}

/// Maps a GLBP packet type string to [`GlbpType`].
fn parse_glbp_type(raw: &str) -> Option<GlbpType> {
    match raw.trim().to_ascii_uppercase().as_str() {
        "HELLO" => Some(GlbpType::Hello),
        "REQUEST" => Some(GlbpType::Request),
        "RESPONSE" => Some(GlbpType::Response),
        _ => None,
    }
}

/// Maps a GTP-U packet type string to [`GtpuType`].
fn parse_gtpu_type(raw: &str) -> Option<GtpuType> {
    match raw.trim().to_ascii_uppercase().replace(['_', '-'], "").as_str() {
        "GPDU" => Some(GtpuType::Gpdu),
        "ECHOREQUEST" => Some(GtpuType::EchoRequest),
        "ECHOREPLY" => Some(GtpuType::EchoReply),
        "ERRORINDICATION" => Some(GtpuType::ErrorIndication),
        "ENDMARKER" => Some(GtpuType::EndMarker),
        _ => None,
    }
}

impl<'a> FrameBuilder<'a> {
    /// Applies a parsed Layer 7, extended Layer 2/3, or scoped modifier field to the builder state.
    pub(crate) fn apply_l7_field(&mut self, f: &ParsedField<'a>) {
        match f {
            ParsedField::L7StringField(key, val, span) => {
                let mod_key = match *key {
                    "EIP_NOP" | "IRC_NICK_ARG" | "IRC_JOIN_ARG" | "IRC_PRIVMSG_ARG" | "cmd" => {
                        "CMD"
                    }
                    "pdu_type" => "MSG_TYPE",
                    "errcode" => "ERRCODE",
                    "value" => "VALUE",
                    "group" => "GROUP",
                    "key" => "KEY",
                    _ => *key,
                };
                if !matches!(*key, "RDATA" | "LLMNR_RDATA") {
                    self.record_mod(mod_key, *span);
                }
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
                match *key {
                    "EIP_NOP" => {
                        self.ethernetip_spec.cmd = Some(*val);
                        self.raw_nop_span = Some(*span);
                    }
                    "QNAME" => {
                        self.dns_spec.qname = Some(*val);
                        self.doh_spec.qname = Some(*val);
                    }
                    "QTYPE" => {
                        self.dns_spec.qtype = Some(*val);
                        self.doh_spec.qtype = Some(*val);
                    }
                    "RDATA" => {
                        if self.dns_spec.rdata.is_none() {
                            self.dns_spec.rdata = Some(*val);
                        }
                        self.dns_spec.rdata_list.push(*val);
                        if self.doh_spec.rdata.is_none() {
                            self.doh_spec.rdata = Some(*val);
                        }
                        self.doh_spec.rdata_list.push(*val);
                    }
                    "HOSTNAME" => {
                        self.dhcp_spec.hostname = Some(*val);
                        self.syslog_spec.hostname = Some(*val);
                    }
                    "REFID" => self.ntp_spec.refid = Some(*val),
                    "MSG_TYPE" => {
                        self.ptp_spec.msg_type = Some(*val);
                        self.coap_spec.msg_type = Some(*val);
                        self.opcua_spec.msg_type = Some(*val);
                        self.vnc_spec.msg_type = Some(*val);
                        self.wsdiscovery_spec.msg_type = Some(*val);
                        self.iec104_spec.msg_type = Some(*val);
                        self.synchrophasor_spec.msg_type = Some(*val);
                        self.hartip_spec.msg_type = Some(*val);
                        self.someip_spec.msg_type = Some(*val);
                        self.doip_spec.msg_type = Some(*val);
                        self.ipmi_spec.msg_type = Some(*val);
                        self.twamp_spec.msg_type = Some(*val);
                        self.netconf_spec.msg_type = Some(*val);
                        self.gtpc_spec.msg_type = Some(*val);
                        self.pfcp_spec.msg_type = Some(*val);
                        self.tns_spec.msg_type = Some(*val);
                        self.nvmetcp_spec.pdu_type = Some(*val);
                        self.turn_spec.msg_type = Some(*val);
                        self.h323_spec.msg_type = Some(*val);
                        self.sccp_spec.msg_type = Some(*val);
                    }
                    "CLOCK_ID" => self.ptp_spec.clock_id = Some(*val),
                    "DOMAIN" => {
                        self.whois_spec.domain = Some(*val);
                        self.mms_spec.domain = Some(*val);
                        if let Ok(d) = val.parse::<u8>() {
                            self.ptp_spec.domain = Some(d);
                        }
                    }
                    "CODE" => {
                        self.radius_spec.code = Some(*val);
                        self.coap_spec.code = Some(*val);
                    }
                    "TACACS_TYPE" => self.tacacs_spec.tacacs_type = Some(*val),
                    "USER" => {
                        self.user = Some(*val);
                        self.radius_spec.user = Some(*val);
                        self.tacacs_spec.user = Some(*val);
                        self.mysql_spec.user = Some(*val);
                        self.postgres_spec.user = Some(*val);
                        self.socks_spec.user = Some(*val);
                    }
                    "DATA" => {
                        self.tacacs_spec.data = Some(*val);
                        self.telnet_spec.data = Some(*val);
                    }
                    "APP" => self.syslog_spec.app = Some(*val),
                    "PROCID" => self.syslog_spec.procid = Some(*val),
                    "MSGID" => {
                        self.syslog_spec.msgid = Some(*val);
                        self.wsdiscovery_spec.msgid = Some(*val);
                        self.netconf_spec.msg_id = Some(*val);
                    }
                    "MSG" => {
                        self.syslog_spec.msg = Some(*val);
                        self.irc_spec.msg = Some(*val);
                    }
                    "FILENAME" => {
                        self.tftp_spec.filename = Some(*val);
                        self.smb_spec.filename = Some(*val);
                    }
                    "MODE" => {
                        self.tftp_spec.mode = Some(*val);
                        self.mgcp_spec.mode = Some(*val);
                    }
                    "ERRMSG" => {
                        self.tftp_spec.errmsg = Some(*val);
                        self.rpkirtr_spec.err_msg = Some(*val);
                        self.mongodb_spec.errmsg = Some(*val);
                    }
                    "CMD" => {
                        self.ftp_spec.cmd = Some(*val);
                        self.smtp_spec.cmd = Some(*val);
                        self.imap_spec.cmd = Some(*val);
                        self.pop3_spec.cmd = Some(*val);
                        self.redis_spec.cmd = Some(*val);
                        self.memcached_spec.cmd = Some(*val);
                        self.ethernetip_spec.cmd = Some(*val);
                        self.socks_spec.cmd = Some(*val);
                        self.irc_spec.cmd = Some(*val);
                        self.fins_spec.cmd = Some(*val);
                        self.melsec_spec.cmd = Some(*val);
                        self.mongodb_spec.cmd = Some(*val);
                        self.iscsi_spec.cmd = Some(*val);
                    }
                    "ARG" => {
                        self.ftp_spec.arg = Some(*val);
                        self.imap_spec.arg = Some(*val);
                        self.pop3_spec.arg = Some(*val);
                    }
                    "REPLY" => {
                        self.ftp_spec.reply = Some(*val);
                        self.smtp_spec.reply = Some(*val);
                    }
                    "EHLO_PARAM" => {
                        self.smtp_spec.cmd = Some("EHLO");
                        self.smtp_spec.param = Some(*val);
                    }
                    "HELO_PARAM" => {
                        self.smtp_spec.cmd = Some("HELO");
                        self.smtp_spec.param = Some(*val);
                    }
                    "MAIL_FROM_PARAM" => {
                        self.smtp_spec.cmd = Some("MAIL FROM");
                        self.smtp_spec.param = Some(*val);
                    }
                    "RCPT_TO_PARAM" => {
                        self.smtp_spec.cmd = Some("RCPT TO");
                        self.smtp_spec.param = Some(*val);
                    }
                    "BANNER" => self.ssh_spec.banner = Some(*val),
                    "COOKIE" => self.ssh_spec.cookie = Some(*val),
                    "METHOD" => {
                        self.http_spec.method = Some(*val);
                        self.grpc_spec.method = Some(*val);
                        self.sip_spec.method = Some(*val);
                        self.rtsp_spec.method = Some(*val);
                        self.socks_spec.method = Some(*val);
                        self.doh_spec.method = Some(*val);
                        self.mgcp_spec.method = Some(*val);
                    }
                    "URI" => {
                        self.http_spec.uri = Some(*val);
                        self.sip_spec.uri = Some(*val);
                        self.rtsp_spec.uri = Some(*val);
                        self.doh_spec.uri = Some(*val);
                    }
                    "VERSION" => {
                        self.http_spec.version = Some(*val);
                        self.vnc_spec.version = Some(*val);
                    }
                    "HOST_HDR" => {
                        self.http_spec.host_hdr = Some(*val);
                        self.ssdp_spec.host_hdr = Some(*val);
                        self.doh_spec.host_hdr = Some(*val);
                    }
                    "USER_AGENT" => {
                        self.http_spec.user_agent = Some(*val);
                        self.doh_spec.user_agent = Some(*val);
                    }
                    "CONTENT_TYPE" => {
                        self.http_spec.content_type = Some(*val);
                        self.sip_spec.content_type = Some(*val);
                    }
                    "STATUS" => {
                        self.imap_spec.status = Some(*val);
                        if let Ok(st) = val.parse::<u16>() {
                            self.http_spec.status = Some(st);
                            self.sip_spec.status = Some(st);
                            self.rtsp_spec.status = Some(st);
                        }
                    }
                    "REASON" => {
                        self.http_spec.reason = Some(*val);
                        self.sip_spec.reason = Some(*val);
                        self.doh_spec.reason = Some(*val);
                        self.rtcp_spec.reason = Some(*val);
                        self.mgcp_spec.reason = Some(*val);
                    }
                    "BODY" => {
                        self.http_spec.body = Some(*val);
                        self.smtp_spec.body = Some(*val);
                        self.sip_spec.body = Some(*val);
                        self.netconf_spec.body = Some(*val);
                        self.mgcp_spec.body = Some(*val);
                    }
                    "SERVICE" => {
                        self.grpc_spec.service = Some(*val);
                        self.mms_spec.service = Some(*val);
                        self.tns_spec.service = Some(*val);
                    }
                    "OPCODE" => self.websocket_spec.opcode = Some(*val),
                    "SNI" => self.tls_spec.sni = Some(*val),
                    "ALPN" => self.tls_spec.alpn = Some(*val),
                    "DCID" => {
                        let s = val
                            .strip_prefix("0x")
                            .or_else(|| val.strip_prefix("0X"))
                            .unwrap_or(*val);
                        if let Ok(v) = u64::from_str_radix(s, 16).or_else(|_| s.parse::<u64>()) {
                            self.quic_spec.dcid = Some(v);
                        }
                    }
                    "SCID" => {
                        let s = val
                            .strip_prefix("0x")
                            .or_else(|| val.strip_prefix("0X"))
                            .unwrap_or(*val);
                        if let Ok(v) = u64::from_str_radix(s, 16).or_else(|_| s.parse::<u64>()) {
                            self.quic_spec.scid = Some(v);
                        }
                    }
                    "TOKEN" => {
                        self.quic_spec.token = Some(*val);
                        let s = val
                            .strip_prefix("0x")
                            .or_else(|| val.strip_prefix("0X"))
                            .unwrap_or(*val);
                        if let Ok(tv) = u32::from_str_radix(s, 16).or_else(|_| s.parse::<u32>()) {
                            self.coap_spec.token = Some(tv);
                        }
                    }
                    "SOFTWARE" => {
                        self.stun_spec.software = Some(*val);
                        self.turn_spec.software = Some(*val);
                    }
                    "FROM" => self.sip_spec.from = Some(*val),
                    "TO" => self.sip_spec.to = Some(*val),
                    "CALL_ID" => {
                        self.sip_spec.call_id = Some(*val);
                        self.mgcp_spec.call_id = Some(*val);
                    }
                    "VIA" => self.sip_spec.via = Some(*val),
                    "CONTACT" => self.sip_spec.contact = Some(*val),
                    "TRANSPORT_HDR" => self.rtsp_spec.transport_hdr = Some(*val),
                    "SESSION" => self.rtsp_spec.session = Some(*val),
                    "PARAM" => {
                        self.smtp_spec.param = Some(*val);
                        self.irc_spec.param = Some(*val);
                    }
                    "RESPONSE" => {
                        self.imap_spec.response = Some(*val);
                        self.pop3_spec.response = Some(*val);
                    }
                    "REALM" => self.kerberos_spec.realm = Some(*val),
                    "CNAME" => {
                        self.kerberos_spec.cname = Some(*val);
                        self.rtcp_spec.cname = Some(*val);
                    }
                    "SNAME" => self.kerberos_spec.sname = Some(*val),
                    "BASE_DN" => self.ldap_spec.base_dn = Some(*val),
                    "FILTER" => {
                        self.ldap_spec.filter = Some(*val);
                        self.mongodb_spec.filter = Some(*val);
                    }
                    "COMMAND" => self.smb_spec.command = Some(*val),
                    "SHARE" => self.smb_spec.share = Some(*val),
                    "PROC" => self.nfs_spec.proc_name = Some(*val),
                    "PATH" => self.nfs_spec.path = Some(*val),
                    "ARGS" => self.redis_spec.args.push(*val),
                    "REPLY_TYPE" => self.redis_spec.reply_type = Some(*val),
                    "VALUE" | "VALUE_STR" => {
                        self.redis_spec.value = Some(*val);
                        self.memcached_spec.value = Some(*val);
                    }
                    "KEY" => {
                        self.memcached_spec.key = Some(*val);
                        self.redis_spec.args.push(*val);
                    }
                    "SERVER_VERSION" => self.mysql_spec.server_version = Some(*val),
                    "SQL" => {
                        self.mysql_spec.sql = Some(*val);
                        self.postgres_spec.sql = Some(*val);
                        self.tns_spec.sql = Some(*val);
                    }
                    "DB" => {
                        self.mysql_spec.db = Some(*val);
                        self.postgres_spec.db = Some(*val);
                        self.mongodb_spec.db = Some(*val);
                    }
                    "PKT_TYPE" => self.mqtt_spec.pkt_type = Some(*val),
                    "CLIENT_ID" => self.mqtt_spec.client_id = Some(*val),
                    "TOPIC" => self.mqtt_spec.topic = Some(*val),
                    "URI_PATH" => self.coap_spec.uri_path = Some(*val),
                    "EXCHANGE" => self.amqp_spec.exchange = Some(*val),
                    "ROUTING_KEY" => self.amqp_spec.routing_key = Some(*val),
                    "MAN" => self.ssdp_spec.man = Some(*val),
                    "ST" => self.ssdp_spec.st = Some(*val),
                    "NT" => self.ssdp_spec.nt = Some(*val),
                    "NTS" => self.ssdp_spec.nts = Some(*val),
                    "USN" => self.ssdp_spec.usn = Some(*val),
                    "LOCATION" => self.ssdp_spec.location = Some(*val),
                    "REGISTRAR" => self.whois_spec.registrar = Some(*val),
                    "FUNC" => {
                        self.modbus_spec.func = Some(*val);
                        self.dnp3_spec.func = Some(*val);
                        self.s7comm_spec.func = Some(*val);
                        self.s7commplus_spec.func = Some(*val);
                        self.gesrtp_spec.func = Some(*val);
                        self.bsap_spec.func = Some(*val);
                    }
                    "ROSCTR" => self.s7comm_spec.rosctr = Some(*val),
                    "AREA" => {
                        let upper = val.to_ascii_uppercase();
                        let code = match upper.as_str() {
                            "PE" | "I" => 0x81,
                            "PA" | "Q" => 0x82,
                            "MK" | "M" => 0x83,
                            "DB" => 0x84,
                            "CT" | "C" => 0x1C,
                            "TM" | "T" => 0x1D,
                            _ => {
                                if let Some(hex) = upper.strip_prefix("0X") {
                                    u8::from_str_radix(hex, 16).unwrap_or(0x84)
                                } else {
                                    val.parse::<u8>().unwrap_or(0x84)
                                }
                            }
                        };
                        self.s7comm_spec.area = Some(code);
                    }
                    "ENDPOINT_URL" => self.opcua_spec.endpoint_url = Some(*val),
                    "NODE_ID" => {
                        self.opcua_spec.node_id = Some(*val);
                        self.pfcp_spec.node_id = Some(*val);
                    }
                    "CHUNK_TYPE" => {
                        self.opcua_spec.chunk_type =
                            val.chars().next().map(|c| c.to_ascii_uppercase());
                    }
                    "HSRP_AUTH" => self.hsrp_auth = Some(*val),
                    "CDP_DEVICE_ID" => self.cdp_spec.device_id = Some(*val),
                    "CDP_PLATFORM" => self.cdp_spec.platform = Some(*val),
                    "CDP_SW_VERSION" => self.cdp_spec.sw_version = Some(*val),
                    "ECAT_CMD" => self.ethercat_spec.cmd = Some(*val),
                    "GOCB_REF" => self.goose_spec.gocb_ref = Some(*val),
                    "GO_ID" => self.goose_spec.go_id = Some(*val),
                    "IEC_DAT_SET" => {
                        self.goose_spec.dat_set = Some(*val);
                        self.sv_spec.dat_set = Some(*val);
                    }
                    "SV_ID" => self.sv_spec.sv_id = Some(*val),
                    "ISIS_AREA" => self.isis_spec.area = Some(*val),
                    "ISIS_HOSTNAME" => self.isis_spec.hostname = Some(*val),
                    "ISIS_LAN_ID" => self.isis_spec.lan_id = Some(*val),
                    "ISIS_PDU_TYPE" => self.isis_spec.pdu_type = parse_isis_pdu_type(val),
                    "ISIS_SYS_ID" => self.isis_spec.sys_id = Some(*val),
                    "PPPOE_AC_NAME" => self.pppoe_spec.ac_name = Some(*val),
                    "PPPOE_SERVICE_NAME" => self.pppoe_spec.service_name = Some(*val),
                    "PPPOE_STAGE" => self.pppoe_spec.stage = parse_pppoe_stage(val),
                    "PN_SERVICE" => self.profinet_spec.service = Some(*val),
                    "BMP_TYPE" => self.bmp_spec.msg_type = parse_bmp_type(val),
                    "GLBP_AUTH" => self.glbp_spec.auth = Some(*val),
                    "GLBP_TYPE" => self.glbp_spec.msg_type = parse_glbp_type(val),
                    "GTPU_TYPE" => self.gtpu_spec.msg_type = parse_gtpu_type(val),
                    "L2TP_MSG_TYPE" => self.l2tp_spec.msg_type = Some(*val),
                    "LDP_MSG" => self.ldp_spec.msg_type = parse_ldp_type(val),
                    "LDP_PREFIX" => self.ldp_spec.prefix = Some(*val),
                    "LISP_EID" => self.lisp_spec.eid = Some(*val),
                    "LISP_TYPE" => self.lisp_spec.msg_type = parse_lisp_type(val),
                    "RPKIRTR_TYPE" => self.rpkirtr_spec.pdu_type = parse_rpkirtr_type(val),
                    "RSVP_MSG" => self.rsvp_spec.msg_type = parse_rsvp_type(val),
                    "C1222_CALLED_AP" => self.c1222_spec.called_ap = Some(*val),
                    "C1222_CALLING_AP" => self.c1222_spec.calling_ap = Some(*val),
                    "C1222_SERVICE" => self.c1222_spec.service = Some(*val),
                    "DCERPC_PDU" => self.dcerpc_spec.pdu_type = Some(*val),
                    "DCERPC_UUID" => self.dcerpc_spec.uuid = Some(*val),
                    "DCERPC_VERS" => self.dcerpc_spec.if_version = Some(*val),
                    "cmd" => self.diameter_spec.cmd = Some(*val),
                    "dst_host" => self.diameter_spec.dst_host = Some(*val),
                    "dst_realm" => self.diameter_spec.dst_realm = Some(*val),
                    "origin_host" => self.diameter_spec.origin_host = Some(*val),
                    "origin_realm" => self.diameter_spec.origin_realm = Some(*val),
                    "session_id" => self.diameter_spec.session_id = Some(*val),
                    "DOIP_VIN" => self.doip_spec.vin = Some(*val),
                    "GESRTP_PTYPE" => self.gesrtp_spec.ptype = Some(*val),
                    "APN" => self.gtpc_spec.apn = Some(*val),
                    "IMSI" => self.gtpc_spec.imsi = Some(*val),
                    "CALLED_PARTY" => self.h323_spec.called_party = Some(*val),
                    "CALLING_PARTY" => self.h323_spec.calling_party = Some(*val),
                    "IRC_JOIN_ARG" => {
                        self.irc_spec.cmd = Some("JOIN");
                        self.irc_spec.target = Some(*val);
                    }
                    "IRC_NICK_ARG" => {
                        self.irc_spec.cmd = Some("NICK");
                        self.irc_spec.target = Some(*val);
                    }
                    "IRC_PRIVMSG_ARG" => {
                        self.irc_spec.cmd = Some("PRIVMSG");
                        self.irc_spec.target = Some(*val);
                    }
                    "IRC_PREFIX" => self.irc_spec.prefix = Some(*val),
                    "IRC_TARGET" => self.irc_spec.target = Some(*val),
                    "INITIATOR" => self.iscsi_spec.initiator = Some(*val),
                    "ISCSI_TARGET" => self.iscsi_spec.target = Some(*val),
                    "api" => self.kafka_spec.api = Some(*val),
                    "client_id" => self.kafka_spec.client_id = Some(*val),
                    "group" => self.kafka_spec.group = Some(*val),
                    "key" => self.kafka_spec.key = Some(*val),
                    "topic" => self.kafka_spec.topic = Some(*val),
                    "value" => self.kafka_spec.value = Some(*val),
                    "KNX_SERVICE" => self.knxnetip_spec.service = Some(*val),
                    "LLMNR_QNAME" => self.llmnr_spec.qname = Some(*val),
                    "LLMNR_QTYPE" => self.llmnr_spec.qtype = Some(*val),
                    "LLMNR_RDATA" => {
                        if self.llmnr_spec.rdata.is_none() {
                            self.llmnr_spec.rdata = Some(*val);
                        }
                        self.llmnr_spec.rdata_list.push(*val);
                    }
                    "CONN_ID" => self.mgcp_spec.conn_id = Some(*val),
                    "ENDPOINT" => self.mgcp_spec.endpoint = Some(*val),
                    "LOCAL_OPTS" => self.mgcp_spec.local_opts = Some(*val),
                    "ITEM" => self.mms_spec.item = Some(*val),
                    "COLLECTION" => self.mongodb_spec.collection = Some(*val),
                    "pkt_type" => self.mssql_spec.pkt_type = Some(*val),
                    "db" => self.mssql_spec.db = Some(*val),
                    "sql" => self.mssql_spec.sql = Some(*val),
                    "NBNS_OPCODE" => self.nbns_spec.opcode = Some(*val),
                    "NBNS_QNAME" => self.nbns_spec.qname = Some(*val),
                    "NBNS_QTYPE" => self.nbns_spec.qtype = Some(*val),
                    "NBNS_RDATA" => self.nbns_spec.rdata = Some(*val),
                    "NBNS_SCOPE" => self.nbns_spec.scope = Some(*val),
                    "CAPABILITY" => self.netconf_spec.capability = Some(*val),
                    "OPERATION" => self.netconf_spec.operation = Some(*val),
                    "criticality" => {
                        self.ngap_spec.criticality = Some(*val);
                        self.s1ap_spec.criticality = Some(*val);
                    }
                    "pdu_type" => {
                        self.ngap_spec.pdu_type = Some(*val);
                        self.s1ap_spec.pdu_type = Some(*val);
                    }
                    "plmn" => {
                        self.ngap_spec.plmn = Some(*val);
                        self.s1ap_spec.plmn = Some(*val);
                    }
                    "ran_name" => self.ngap_spec.ran_name = Some(*val),
                    "enb_name" => self.s1ap_spec.enb_name = Some(*val),
                    "NTLM_DOMAIN" => self.ntlm_spec.domain = Some(*val),
                    "NTLM_HOST_HDR" => self.ntlm_spec.host_hdr = Some(*val),
                    "NTLM_METHOD" => self.ntlm_spec.method = Some(*val),
                    "NTLM_MSG_TYPE" => self.ntlm_spec.msg_type = Some(*val),
                    "NTLM_NONCE" => self.ntlm_spec.nonce = Some(*val),
                    "NTLM_URI" => self.ntlm_spec.uri = Some(*val),
                    "NTLM_USER" => self.ntlm_spec.user = Some(*val),
                    "NTLM_WORKSTATION" => self.ntlm_spec.workstation = Some(*val),
                    "RDP_COOKIE" => self.rdp_spec.cookie = Some(*val),
                    "RDP_MSG_TYPE" => self.rdp_spec.msg_type = Some(*val),
                    "ROCE_OPCODE" => self.rocev2_spec.opcode = Some(*val),
                    "ROC_OPCODE" => self.rocplus_spec.opcode = Some(*val),
                    "DEVICE_NAME" => self.sccp_spec.device_name = Some(*val),
                    "PASSWORD" => self.socks_spec.password = Some(*val),
                    "SOCKS_ADDR" => self.socks_spec.addr = Some(*val),
                    "SOMEIP_SD_TYPE" => self.someip_spec.sd_type = Some(*val),
                    "STATION" => self.synchrophasor_spec.station = Some(*val),
                    "SID" => self.tns_spec.sid = Some(*val),
                    "DESKTOP" => self.vnc_spec.desktop = Some(*val),
                    "SCOPES" => self.wsdiscovery_spec.scopes = Some(*val),
                    "TYPES" => self.wsdiscovery_spec.types = Some(*val),
                    "WSD_ADDR" => self.wsdiscovery_spec.addr = Some(*val),
                    "XADDRS" => self.wsdiscovery_spec.xaddrs = Some(*val),
                    _ => {}
                }
            }
            ParsedField::L7U32Field(key, val, span) => {
                let mod_key = match *key {
                    "MODBUS_EXC" | "errcode" => "ERRCODE",
                    "REAL_VALUE" => "REAL",
                    "ECAT_ADDR" => "ECAT_ADP",
                    "ISCSI_TARGET" => "TARGET",
                    "NVME_COUNT" | "TWAMP_COUNT" => "COUNT",
                    "MMS_INVOKE_ID" => "INVOKE_ID",
                    "TWAMP_MODE" => "MODE",
                    "S7PLUS_VERSION" | "SYN_VERSION" | "HART_VERSION" => "VERSION",
                    "S7PLUS_SEQ_NUM" => "SEQ_NUM",
                    "OBJECT_ID" | "SYN_ID" => "ID",
                    "SYN_CMD" | "HART_CMD" => "CMD",
                    "SYN_STATUS" | "HART_STATUS" => "STATUS",
                    "HART_MSG_ID" => "MSGID",
                    "HART_ADDR" | "MELSEC_ADDR" => "ADDR",
                    "FINS_AREA" => "AREA",
                    "MELSEC_ENDCODE" => "ENDCODE",
                    "SOMEIP_SD_FLAGS" => "FLAGS",
                    _ => *key,
                };
                self.record_mod(mod_key, *span);
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
                match *key {
                    "TACACS_SEQ" => self.check_bound("tacacs seq", *val as u64, 0, 255, *span),
                    "FACILITY" => self.check_bound("Syslog facility", *val as u64, 0, 23, *span),
                    "SEVERITY" => self.check_bound("Syslog severity", *val as u64, 0, 7, *span),
                    "MODBUS_EXC" => self.check_bound("Modbus errcode", *val as u64, 0, 255, *span),
                    "ERSPAN_DIRECTION" => self.check_bound(key, *val as u64, 0, 1, *span),
                    "MACSEC_AN" | "NSH_VERSION" => self.check_bound(key, *val as u64, 0, 3, *span),
                    "ERSPAN_COS" => self.check_bound(key, *val as u64, 0, 7, *span),
                    "LLMNR_RCODE" | "NBNS_RCODE" | "NSH_MD_TYPE" => {
                        self.check_bound(key, *val as u64, 0, 15, *span)
                    }
                    "SYN_VERSION" => self.check_bound(key, *val as u64, 1, 15, *span),
                    "ISIS_CIRCUIT_TYPE" | "S7PLUS_VERSION" => {
                        self.check_bound(key, *val as u64, 1, 3, *span)
                    }
                    "ERSPAN_VERSION" => self.check_bound(key, *val as u64, 2, 3, *span),
                    "IPIP_VERSION" => self.check_bound(key, *val as u64, 4, 6, *span),
                    "TYPE_ID" => self.check_bound(key, *val as u64, 1, 255, *span),
                    "HART_ADDR" | "GTPU_QFI" | "INNER_DSCP" | "MACSEC_SL" => {
                        self.check_bound(key, *val as u64, 0, 63, *span)
                    }
                    "ISIS_PRIORITY" => self.check_bound(key, *val as u64, 0, 127, *span),
                    "RPKIRTR_MAX_LEN" => self.check_bound(key, *val as u64, 0, 128, *span),
                    "ICMP_TYPE" | "DOMAIN" | "RCODE" | "LI" | "VN" | "MODE" | "STRATUM"
                    | "POLL" | "PRI" | "PROTO" | "MSG_CODE" | "WILL" | "WONT" | "DO" | "DONT"
                    | "OPTION" | "FIN_BIT" | "PT" | "MARKER" | "OPCODE" | "QOS" | "RETURN_CODE"
                    | "MX" | "UNITID" | "INVOKE_ID" | "GROUP" | "VARIATION" | "AREA"
                    | "CIP_SERVICE" | "BMP_PEER_TYPE" | "CAUSE" | "COT" | "C1222_EPSEM_CTRL"
                    | "C1222_ERRCODE" | "DCERPC_FLAGS" | "DOIP_CODE" | "DOIP_INV_VERSION"
                    | "DOIP_VERSION" | "FINS_AREA" | "FINS_DA1" | "FINS_DA2" | "FINS_DNA"
                    | "FINS_ICF" | "FINS_SA1" | "FINS_SA2" | "FINS_SID" | "FINS_SNA"
                    | "FRACTION" | "GLBP_FORWARDER" | "GLBP_STATE" | "GLBP_WEIGHT"
                    | "GTPU_NPDU" | "HART_CMD" | "HART_MSG_ID" | "HART_STATUS" | "HART_VERSION"
                    | "INNER_TTL" | "KNX_CHANNEL" | "KNX_SEQ" | "KNX_STATUS" | "LISP_WEIGHT"
                    | "MELSEC_DEVICE" | "MELSEC_NETWORK" | "MELSEC_PC" | "MELSEC_STATION"
                    | "NETFN" | "NSH_NEXT_PROTO" | "NSH_SI" | "PN_DATA_STATUS"
                    | "PN_TRANSFER_STATUS" | "RAT" | "RDP_FLAGS" | "ROCE_SYNDROME" | "ROC_ADDR"
                    | "ROC_DST" | "ROC_PARAM" | "ROC_SRC" | "ROC_TYPE" | "RQSEQ"
                    | "RSVP_ERRCODE" | "SECURITY_TYPE" | "SENDER_TTL" | "SMP_SYNCH"
                    | "SOCKS_STATUS" | "SOCKS_VERSION" | "SOMEIP_IFACE_VER" | "SOMEIP_MAJOR_VER"
                    | "SOMEIP_PROTO_VER" | "SOMEIP_RETURN_CODE" | "SOMEIP_SD_FLAGS"
                    | "SRV6_FLAGS" | "SRV6_SEG_LEFT" | "VNC_FLAGS" | "BSAP_COUNT" | "BSAP_SEQ"
                    | "ECAT_IDX" | "IPMI_CMD" | "pkt_id" | "proc_code" => {
                        self.check_bound(key, *val as u64, 0, 255, *span)
                    }
                    "ERSPAN_SESSION_ID" | "GLBP_GROUP" => {
                        self.check_bound(key, *val as u64, 0, 1023, *span)
                    }
                    "CDP_NATIVE_VLAN" | "ERSPAN_VID" => {
                        self.check_bound(key, *val as u64, 0, 4095, *span)
                    }
                    "TX_SEQ" | "RX_SEQ" => self.check_bound(key, *val as u64, 0, 32767, *span),
                    "SEQ_ID" | "BLOCK" | "ERRCODE" | "RECORD_VERSION" | "HANDSHAKE_VERSION"
                    | "CIPHERSUITE" | "PKT_ID" | "KEEPALIVE" | "CONTENT_FORMAT" | "CHANNEL"
                    | "PROTO_ID" | "ADDR" | "COUNT" | "OBJECT_TYPE" | "SRC" | "DST" | "CRC"
                    | "PDU_REF" | "DB_NUM" | "CIP_CLASS" | "CIP_INSTANCE" | "CIP_ATTR"
                    | "UDP_SIZE" | "BMP_REASON" | "C1222_TABLE_ID" | "CA" | "CALL_REF"
                    | "DCERPC_CTX_ID" | "DCERPC_OPNUM" | "DOIP_DST" | "DOIP_SRC"
                    | "ECAT_ADDR" | "ECAT_ADO" | "ECAT_ADP" | "ECAT_IRQ" | "ECAT_WKC"
                    | "ERROR_ESTIMATE" | "GLBP_REDIRECT" | "GLBP_TIMEOUT" | "GTPU_SEQNUM"
                    | "HEIGHT" | "IEC_APPID" | "ISIS_HOLDTIME" | "ISIS_LIFETIME"
                    | "L2TP_FLAGS" | "L2TP_NR" | "L2TP_NS" | "LDP_HOLDTIME" | "LDP_LABEL_SPACE"
                    | "LLMNR_FLAGS" | "LLMNR_TXID" | "MEDIA_PORT" | "MELSEC_ENDCODE"
                    | "MELSEC_IO" | "MELSEC_SUBCMD" | "MELSEC_TIMER" | "NBNS_FLAGS"
                    | "NBNS_TXID" | "NTLM_STATUS" | "PADDING" | "PFC_ENABLE" | "PFC_Q0"
                    | "PFC_Q1" | "PFC_Q2" | "PFC_Q3" | "PFC_Q4" | "PFC_Q5" | "PFC_Q6" | "PFC_Q7"
                    | "PFC_QUANTA" | "PKEY" | "PN_CYCLE" | "PN_FRAME_ID" | "PORT"
                    | "PPPOE_PPP_PROTO" | "PPPOE_SESSION_ID" | "QID" | "RDP_HEIGHT"
                    | "RDP_SESSION_ID" | "RDP_WIDTH" | "RPKIRTR_SESSION_ID" | "RSVP_LSP_ID"
                    | "RSVP_TUNNEL_ID" | "S7PLUS_SEQ_NUM" | "SMP_CNT" | "SMP_RATE"
                    | "SOMEIP_CLIENT_ID" | "SOMEIP_ENDPOINT_PORT" | "SOMEIP_INSTANCE_ID"
                    | "SOMEIP_METHOD_ID" | "SOMEIP_SD_SERVICE" | "SOMEIP_SERVICE_ID"
                    | "SOMEIP_SESSION_ID" | "SRV6_TAG" | "SYN_CMD" | "SYN_ID" | "SYN_STATUS"
                    | "TARGET_PORT" | "WIDTH" | "XPOS" | "YPOS" | "api_version" | "spid" => {
                        self.check_bound(key, *val as u64, 0, 65535, *span);
                    }
                    "ERSPAN_INDEX" | "RSVP_LABEL" | "LDP_LABEL" => {
                        self.check_bound(key, *val as u64, 0, 0xF_FFFF, *span);
                    }
                    "NSH_SPI" | "LISP_IID" | "MELSEC_ADDR" | "IOA" | "DEST_QP"
                    | "ROCE_PSN" | "ROCE_MSN" | "LOST" => {
                        self.check_bound(key, *val as u64, 0, 0xFF_FFFF, *span);
                    }
                    "TXID" | "CODE" | "MSGID" | "STATUS" | "FLAGS" | "VALUE" | "VERSION"
                    | "SEQ_NUM" | "REQ_ID" | "RECOVERY" | "LUN" | "tac" => {
                        self.deferred_u32_fields.push((*key, *val, *span));
                    }
                    _ => {}
                }
                match *key {
                    "TACACS_SEQ" => self.tacacs_spec.seq = Some(*val as u8),
                    "TXID" => {
                        self.dns_spec.txid = Some(*val as u16);
                        self.modbus_spec.txid = Some(*val as u16);
                        self.stun_spec.txid = Some(*val);
                        self.doh_spec.txid = Some(*val as u16);
                        self.hartip_spec.txid = Some(*val as u16);
                        self.turn_spec.txid = Some(*val);
                        self.mgcp_spec.txid = Some(*val);
                    }
                    "ICMP_TYPE" => self.icmp_type_val = Some(*val as u8),
                    "CODE" => {
                        self.icmp_code_val = Some(*val as u8);
                        self.ftp_spec.code = Some(*val as u16);
                        self.smtp_spec.code = Some(*val as u16);
                    }
                    "DOMAIN" => self.ptp_spec.domain = Some(*val as u8),
                    "RCODE" => {
                        self.dns_spec.rcode = Some(*val as u8);
                        self.doh_spec.rcode = Some(*val as u8);
                    }
                    "ANS_TTL" => {
                        self.dns_spec.ans_ttl = Some(*val);
                        self.doh_spec.ans_ttl = Some(*val);
                    }
                    "UDP_SIZE" => {
                        self.dns_spec.udp_size = Some(*val as u16);
                        self.doh_spec.udp_size = Some(*val as u16);
                    }
                    "MODBUS_EXC" => self.modbus_spec.exception_code = Some(*val as u8),
                    "REAL_VALUE" => {
                        self.bacnet_spec.real_value = Some(*val);
                        self.iec104_spec.real_value = Some(*val);
                    }
                    "LEASE_TIME" => self.dhcp_spec.lease_time = Some(*val),
                    "LI" => self.ntp_spec.li = Some(*val as u8),
                    "VN" => self.ntp_spec.vn = Some(*val as u8),
                    "MODE" => {
                        self.ntp_spec.mode = Some(*val as u8);
                        self.hartip_spec.master_type = Some(*val as u8);
                    }
                    "STRATUM" => self.ntp_spec.stratum = Some(*val as u8),
                    "POLL" => self.ntp_spec.poll = Some(*val as u8),
                    "PRECISION" => self.ntp_spec.precision = Some(*val as i8),
                    "SEQ_ID" => self.ptp_spec.seq_id = Some(*val as u16),
                    "SERVICE_TYPE" => self.radius_spec.service_type = Some(*val),
                    "FACILITY" => self.syslog_spec.facility = Some(*val as u8),
                    "SEVERITY" => self.syslog_spec.severity = Some(*val as u8),
                    "PRI" => self.syslog_spec.pri = Some(*val as u8),
                    "MSGID" => {
                        self.ldap_spec.msgid = Some(*val as i32);
                        self.coap_spec.msgid = Some(*val as u16);
                        self.smb_spec.msgid = Some(*val as u64);
                    }
                    "PROTO" => {
                        self.netflow_spec.proto = Some(*val as u8);
                        self.ipfix_spec.proto = Some(*val as u8);
                        self.ipip_spec.proto = Some(*val as u8);
                    }
                    "PACKETS" => {
                        self.netflow_spec.packets = Some(*val);
                        self.ipfix_spec.packets = Some(*val);
                        self.rtcp_spec.packets = Some(*val);
                    }
                    "OCTETS" => {
                        self.netflow_spec.octets = Some(*val);
                        self.ipfix_spec.octets = Some(*val);
                        self.rtcp_spec.octets = Some(*val);
                    }
                    "DOMAIN_ID" => self.ipfix_spec.domain_id = Some(*val),
                    "SUB_AGENT_ID" => self.sflow_spec.sub_agent_id = Some(*val),
                    "UPTIME" => self.sflow_spec.uptime = Some(*val),
                    "SAMPLES" => self.sflow_spec.samples = Some(*val),
                    "BLOCK" => self.tftp_spec.block = Some(*val as u16),
                    "ERRCODE" => {
                        self.tftp_spec.errcode = Some(*val as u16);
                        self.mysql_spec.errcode = Some(*val as u16);
                        self.rpkirtr_spec.err_code = Some(*val as u16);
                        self.fins_spec.errcode = Some(*val as u16);
                        self.mongodb_spec.errcode = Some(*val as u16);
                        self.tns_spec.errcode = Some(*val as u16);
                        self.turn_spec.errcode = Some(*val as u16);
                    }
                    "MSG_CODE" => self.ssh_spec.msg_code = Some(*val as u8),
                    "WILL" => self.telnet_spec.will = Some(*val as u8),
                    "WONT" => self.telnet_spec.wont = Some(*val as u8),
                    "DO" => self.telnet_spec.do_opt = Some(*val as u8),
                    "DONT" => self.telnet_spec.dont = Some(*val as u8),
                    "OPTION" => self.telnet_spec.option = Some(*val as u8),
                    "STATUS" => {
                        self.http_spec.status = Some(*val as u16);
                        self.sip_spec.status = Some(*val as u16);
                        self.rtsp_spec.status = Some(*val as u16);
                        self.smb_spec.status = Some(*val);
                        self.ethernetip_spec.status = Some(*val);
                        self.doh_spec.status = Some(*val as u16);
                        self.gesrtp_spec.status = Some(*val as u16);
                        self.nvmetcp_spec.status = Some(*val as u16);
                        self.mgcp_spec.status = Some(*val as u16);
                        self.iscsi_spec.status = Some(*val as u8);
                        self.ipmi_spec.status = Some(*val as u8);
                        self.twamp_spec.status = Some(*val as u8);
                    }
                    "STREAM_ID" => self.http2_spec.stream_id = Some(*val),
                    "GRPC_STATUS" => self.grpc_spec.grpc_status = Some(*val),
                    "FIN_BIT" => self.websocket_spec.fin_bit = Some(*val as u8),
                    "MASK_KEY" => self.websocket_spec.mask_key = Some(*val),
                    "RECORD_VERSION" => self.tls_spec.record_version = Some(*val as u16),
                    "HANDSHAKE_VERSION" => self.tls_spec.handshake_version = Some(*val as u16),
                    "CIPHERSUITE" => self.tls_spec.ciphersuite = Some(*val as u16),
                    "VERSION" => {
                        self.quic_spec.version = Some(*val);
                        self.ipmi_spec.version = Some(*val as u8);
                        self.tns_spec.version = Some(*val as u16);
                        self.sccp_spec.header_version = Some(*val);
                    }
                    "PKT_NUM" => self.quic_spec.pkt_num = Some(*val),
                    "CSEQ" => {
                        self.sip_spec.cseq = Some(*val);
                        self.rtsp_spec.cseq = Some(*val);
                    }
                    "PT" => {
                        self.rtp_spec.pt = Some(*val as u8);
                        self.rtcp_spec.pt = Some(*val as u8);
                    }
                    "TIMESTAMP" => {
                        self.rtp_spec.timestamp = Some(*val);
                        self.rtcp_spec.timestamp = Some(*val);
                        self.synchrophasor_spec.soc = Some(*val);
                    }
                    "SSRC" => {
                        self.rtp_spec.ssrc = Some(*val);
                        self.rtcp_spec.ssrc = Some(*val);
                    }
                    "MARKER" => self.rtp_spec.marker = Some(*val as u8),
                    "ETYPE" => self.kerberos_spec.etype = Some(*val as i32),
                    "RESULT_CODE" => self.ldap_spec.result_code = Some(*val),
                    "TREE_ID" => self.smb_spec.tree_id = Some(*val),
                    "VERS" => self.nfs_spec.vers = Some(*val),
                    "FLAGS" => {
                        self.stp_flags = Some(*val as u8);
                        self.ike_flags = Some(*val as u8);
                        self.tacacs_spec.flags = Some(*val as u8);
                        self.memcached_spec.flags = Some(*val);
                        self.s7commplus_spec.flags = Some(*val as u8);
                        self.iscsi_spec.flags = Some(*val as u8);
                        self.nvmetcp_spec.flags = Some(*val as u8);
                        self.tns_spec.flags = Some(*val as u16);
                        self.mongodb_spec.flags = Some(*val);
                    }
                    "EXPTIME" => self.memcached_spec.exptime = Some(*val),
                    "OPCODE" => {
                        self.memcached_spec.opcode = Some(*val as u8);
                        self.s7commplus_spec.opcode = Some(*val as u8);
                        self.iscsi_spec.opcode = Some(*val as u8);
                        self.nvmetcp_spec.opcode = Some(*val as u8);
                    }
                    "OPAQUE" => self.memcached_spec.opaque = Some(*val),
                    "QOS" => self.mqtt_spec.qos = Some(*val as u8),
                    "PKT_ID" => self.mqtt_spec.pkt_id = Some(*val as u16),
                    "KEEPALIVE" => self.mqtt_spec.keepalive = Some(*val as u16),
                    "RETURN_CODE" => self.mqtt_spec.return_code = Some(*val as u8),
                    "TOKEN" => self.coap_spec.token = Some(*val),
                    "CONTENT_FORMAT" => self.coap_spec.content_format = Some(*val as u16),
                    "CHANNEL" => {
                        self.amqp_spec.channel = Some(*val as u16);
                        self.turn_spec.channel = Some(*val as u16);
                    }
                    "MX" => self.ssdp_spec.mx = Some(*val as u8),
                    "PROTO_ID" => self.modbus_spec.proto_id = Some(*val as u16),
                    "UNITID" => self.modbus_spec.unitid = Some(*val as u8),
                    "ADDR" => {
                        self.modbus_spec.addr = Some(*val as u16);
                        self.fins_spec.addr = Some(*val as u16);
                        self.gesrtp_spec.addr = Some(*val as u16);
                        self.bsap_spec.addr = Some(*val as u16);
                    }
                    "COUNT" => {
                        self.modbus_spec.count = Some(*val as u16);
                        self.s7comm_spec.count = Some(*val as u16);
                        self.fins_spec.count = Some(*val as u16);
                        self.melsec_spec.count = Some(*val as u16);
                        self.gesrtp_spec.count = Some(*val as u16);
                    }
                    "VALUE" => {
                        self.modbus_spec.value = Some(*val as u16);
                        self.bacnet_spec.value = Some(*val);
                        self.iec104_spec.value = Some(*val);
                        self.mms_spec.value = Some(*val);
                        self.fins_spec.value = Some(*val as u16);
                        self.melsec_spec.value = Some(*val as u16);
                        self.c1222_spec.value = Some(*val as u16);
                        self.gesrtp_spec.value = Some(*val);
                        self.rocplus_spec.value = Some(*val);
                        self.bsap_spec.value = Some(*val);
                        self.knxnetip_spec.value = Some(*val);
                    }
                    "INVOKE_ID" => self.bacnet_spec.invoke_id = Some(*val as u8),
                    "OBJECT_TYPE" => self.bacnet_spec.object_type = Some(*val as u16),
                    "OBJECT_INSTANCE" => self.bacnet_spec.object_instance = Some(*val),
                    "PROPERTY_ID" => self.bacnet_spec.property_id = Some(*val),
                    "SRC" => {
                        self.dnp3_spec.src = Some(*val as u16);
                        self.bsap_spec.src = Some(*val as u16);
                        self.knxnetip_spec.src = Some(*val as u16);
                    }
                    "DST" => {
                        self.dnp3_spec.dst = Some(*val as u16);
                        self.bsap_spec.dst = Some(*val as u16);
                        self.knxnetip_spec.dst = Some(*val as u16);
                    }
                    "GROUP" => {
                        self.dnp3_spec.group = Some(*val as u8);
                        self.rocplus_spec.group = Some(*val as u8);
                    }
                    "VARIATION" => self.dnp3_spec.variation = Some(*val as u8),
                    "CRC" => {
                        self.dnp3_spec.crc = Some(*val as u16);
                        self.synchrophasor_spec.crc = Some(*val as u16);
                        self.rocplus_spec.crc = Some(*val as u16);
                    }
                    "PDU_REF" => self.s7comm_spec.pdu_ref = Some(*val as u16),
                    "AREA" => {
                        self.s7comm_spec.area = Some(*val as u8);
                        self.gesrtp_spec.area = Some(*val as u8);
                    }
                    "DB_NUM" => self.s7comm_spec.db_num = Some(*val as u16),
                    "OFFSET" => {
                        self.s7comm_spec.offset = Some(*val);
                        self.iscsi_spec.offset = Some(*val);
                        self.nvmetcp_spec.offset = Some(*val);
                    }
                    "SESSION_HANDLE" => self.ethernetip_spec.session_handle = Some(*val),
                    "CIP_SERVICE" => self.ethernetip_spec.cip_service = Some(*val as u8),
                    "CIP_CLASS" => self.ethernetip_spec.cip_class = Some(*val as u16),
                    "CIP_INSTANCE" => self.ethernetip_spec.cip_instance = Some(*val as u16),
                    "CIP_ATTR" => self.ethernetip_spec.cip_attr = Some(*val as u16),
                    "SECURE_CHANNEL_ID" => self.opcua_spec.secure_channel_id = Some(*val),
                    "TOKEN_ID" => self.opcua_spec.token_id = Some(*val),
                    "SEQ_NUM" => {
                        self.opcua_spec.seq_num = Some(*val);
                        self.gesrtp_spec.seq_num = Some(*val as u16);
                        self.h323_spec.seq_num = Some(*val as u16);
                        self.ipmi_spec.seq_num = Some(*val);
                        self.twamp_spec.seq_num = Some(*val);
                        self.gtpc_spec.seq_num = Some(*val);
                        self.pfcp_spec.seq_num = Some(*val);
                        self.rtcp_spec.seq_num = Some(*val);
                    }
                    "REQ_ID" => {
                        self.opcua_spec.req_id = Some(*val);
                        self.nvmetcp_spec.req_id = Some(*val as u16);
                        self.mongodb_spec.req_id = Some(*val);
                    }
                    "CDP_CAPABILITIES" => self.cdp_spec.capabilities = Some(*val),
                    "CDP_NATIVE_VLAN" => self.cdp_spec.native_vlan = Some(*val as u16),
                    "ECAT_ADDR" | "ECAT_ADP" => self.ethercat_spec.adp = Some(*val as u16),
                    "ECAT_ADO" => self.ethercat_spec.ado = Some(*val as u16),
                    "ECAT_IDX" => self.ethercat_spec.idx = Some(*val as u8),
                    "ECAT_IRQ" => self.ethercat_spec.irq = Some(*val as u16),
                    "ECAT_WKC" => self.ethercat_spec.wkc = Some(*val as u16),
                    "IEC_APPID" => {
                        self.goose_spec.appid = Some(*val as u16);
                        self.sv_spec.appid = Some(*val as u16);
                    }
                    "IEC_CONF_REV" => {
                        self.goose_spec.conf_rev = Some(*val);
                        self.sv_spec.conf_rev = Some(*val);
                    }
                    "NUM_DAT_SET_ENTRIES" => self.goose_spec.num_entries = Some(*val),
                    "SQ_NUM" => self.goose_spec.sq_num = Some(*val),
                    "ST_NUM" => self.goose_spec.st_num = Some(*val),
                    "TIME_TO_LIVE" => self.goose_spec.time_to_live = Some(*val),
                    "SMP_CNT" => self.sv_spec.smp_cnt = Some(*val as u16),
                    "SMP_RATE" => self.sv_spec.smp_rate = Some(*val as u16),
                    "SMP_SYNCH" => self.sv_spec.smp_synch = Some(*val as u8),
                    "ISIS_CIRCUIT_TYPE" => self.isis_spec.circuit_type = Some(*val as u8),
                    "ISIS_HOLDTIME" => self.isis_spec.hold_time = Some(*val as u16),
                    "ISIS_LIFETIME" => self.isis_spec.lifetime = Some(*val as u16),
                    "ISIS_PRIORITY" => self.isis_spec.priority = Some(*val as u8),
                    "ISIS_SEQ_NUM" => self.isis_spec.seq_num = Some(*val),
                    "MACSEC_AN" => self.macsec_spec.an = Some(*val as u8),
                    "MACSEC_PN" => self.macsec_spec.pn = Some(*val),
                    "MACSEC_SL" => self.macsec_spec.sl = Some(*val as u8),
                    "MACSEC_TCI" => self.macsec_spec.tci = Some(*val as u8),
                    "NSH_MD_TYPE" => self.nsh_spec.md_type = Some(*val as u8),
                    "NSH_NEXT_PROTO" => self.nsh_spec.next_proto = Some(*val as u8),
                    "NSH_SI" => self.nsh_spec.si = Some(*val as u8),
                    "NSH_SPI" => self.nsh_spec.spi = Some(*val),
                    "NSH_VERSION" => self.nsh_spec.version = Some(*val as u8),
                    "PFC_ENABLE" => self.pfc_spec.enable = Some(*val as u16),
                    "PFC_QUANTA" => self.pfc_spec.quanta = Some(*val as u16),
                    "PFC_Q0" => self.pfc_spec.class_quanta[0] = Some(*val as u16),
                    "PFC_Q1" => self.pfc_spec.class_quanta[1] = Some(*val as u16),
                    "PFC_Q2" => self.pfc_spec.class_quanta[2] = Some(*val as u16),
                    "PFC_Q3" => self.pfc_spec.class_quanta[3] = Some(*val as u16),
                    "PFC_Q4" => self.pfc_spec.class_quanta[4] = Some(*val as u16),
                    "PFC_Q5" => self.pfc_spec.class_quanta[5] = Some(*val as u16),
                    "PFC_Q6" => self.pfc_spec.class_quanta[6] = Some(*val as u16),
                    "PFC_Q7" => self.pfc_spec.class_quanta[7] = Some(*val as u16),
                    "PPPOE_PPP_PROTO" => self.pppoe_spec.ppp_proto = Some(*val as u16),
                    "PPPOE_SESSION_ID" => self.pppoe_spec.session_id = Some(*val as u16),
                    "PN_CYCLE" => self.profinet_spec.cycle = Some(*val as u16),
                    "PN_DATA_STATUS" => self.profinet_spec.data_status = Some(*val as u8),
                    "PN_FRAME_ID" => self.profinet_spec.frame_id = Some(*val as u16),
                    "PN_TRANSFER_STATUS" => self.profinet_spec.transfer_status = Some(*val as u8),
                    "PN_XID" => self.profinet_spec.xid = Some(*val),
                    "IPIP_VERSION" => {
                        self.ipip_spec.version = Some(if *val == 6 {
                            IpipVersion::V6
                        } else {
                            IpipVersion::V4
                        });
                    }
                    "INNER_TTL" => self.ipip_spec.ttl = Some(*val as u8),
                    "INNER_DSCP" => self.ipip_spec.dscp = Some(*val as u8),
                    "SRV6_SEG_LEFT" => self.srv6_spec.seg_left = Some(*val as u8),
                    "SRV6_FLAGS" => self.srv6_spec.flags = Some(*val as u8),
                    "SRV6_TAG" => self.srv6_spec.tag = Some(*val as u16),
                    "ERSPAN_VERSION" => self.erspan_spec.version = Some(*val as u8),
                    "ERSPAN_SESSION_ID" => self.erspan_spec.session_id = Some(*val as u16),
                    "ERSPAN_VID" => self.erspan_spec.vid = Some(*val as u16),
                    "ERSPAN_COS" => self.erspan_spec.cos = Some(*val as u8),
                    "ERSPAN_INDEX" => self.erspan_spec.index = Some(*val),
                    "ERSPAN_TIMESTAMP" => self.erspan_spec.timestamp = Some(*val),
                    "ERSPAN_DIRECTION" => self.erspan_spec.direction = Some(*val as u8),
                    "RSVP_TUNNEL_ID" => self.rsvp_spec.tunnel_id = Some(*val as u16),
                    "RSVP_LSP_ID" => self.rsvp_spec.lsp_id = Some(*val as u16),
                    "RSVP_LABEL" => self.rsvp_spec.label = Some(*val),
                    "RSVP_REFRESH" => self.rsvp_spec.refresh = Some(*val),
                    "RSVP_ERRCODE" => self.rsvp_spec.err_code = Some(*val as u8),
                    "LDP_LABEL_SPACE" => self.ldp_spec.label_space = Some(*val as u16),
                    "LDP_MSGID" => self.ldp_spec.msg_id = Some(*val),
                    "LDP_HOLDTIME" => self.ldp_spec.holdtime = Some(*val as u16),
                    "LDP_LABEL" => self.ldp_spec.label = Some(*val),
                    "LDP_STATUS" => self.ldp_spec.status = Some(*val),
                    "BMP_PEER_TYPE" => self.bmp_spec.peer_type = Some(*val as u8),
                    "BMP_REASON" => self.bmp_spec.reason = Some(*val as u16),
                    "RPKIRTR_SESSION_ID" => self.rpkirtr_spec.session_id = Some(*val as u16),
                    "RPKIRTR_SERIAL" => self.rpkirtr_spec.serial = Some(*val),
                    "RPKIRTR_MAX_LEN" => self.rpkirtr_spec.max_len = Some(*val as u8),
                    "RPKIRTR_REFRESH" => self.rpkirtr_spec.refresh = Some(*val),
                    "RPKIRTR_RETRY" => self.rpkirtr_spec.retry = Some(*val),
                    "RPKIRTR_EXPIRE" => self.rpkirtr_spec.expire = Some(*val),
                    "L2TP_TUNNEL_ID" => self.l2tp_spec.tunnel_id = Some(*val),
                    "L2TP_SESSION_ID" => self.l2tp_spec.session_id = Some(*val),
                    "L2TP_NS" => self.l2tp_spec.ns = Some(*val as u16),
                    "L2TP_NR" => self.l2tp_spec.nr = Some(*val as u16),
                    "L2TP_FLAGS" => self.l2tp_spec.flags = Some(*val as u16),
                    "LISP_IID" => self.lisp_spec.iid = Some(*val),
                    "LISP_WEIGHT" => self.lisp_spec.weight = Some(*val as u8),
                    "GLBP_GROUP" => self.glbp_spec.group = Some(*val as u16),
                    "GLBP_STATE" => self.glbp_spec.state = Some(*val as u8),
                    "GLBP_WEIGHT" => self.glbp_spec.weight = Some(*val as u8),
                    "GLBP_FORWARDER" => self.glbp_spec.forwarder = Some(*val as u8),
                    "GLBP_HELLO_TIME" => self.glbp_spec.hellotime = Some(*val),
                    "GLBP_HOLD_TIME" => self.glbp_spec.holdtime = Some(*val),
                    "GLBP_REDIRECT" => self.glbp_spec.redirect = Some(*val as u16),
                    "GLBP_TIMEOUT" => self.glbp_spec.timeout = Some(*val as u16),
                    "GTPU_TEID" => self.gtpu_spec.teid = Some(*val),
                    "GTPU_SEQNUM" => self.gtpu_spec.seqnum = Some(*val as u16),
                    "GTPU_NPDU" => self.gtpu_spec.npdu = Some(*val as u8),
                    "GTPU_QFI" => self.gtpu_spec.qfi = Some(*val as u8),
                    "DCERPC_OPNUM" => self.dcerpc_spec.opnum = Some(*val as u16),
                    "DCERPC_CALL_ID" => self.dcerpc_spec.call_id = Some(*val),
                    "DCERPC_CTX_ID" => self.dcerpc_spec.ctx_id = Some(*val as u16),
                    "DCERPC_FLAGS" => self.dcerpc_spec.flags = Some(*val as u8),
                    "DCERPC_STATUS" => self.dcerpc_spec.status = Some(*val),
                    "NTLM_FLAGS" => self.ntlm_spec.flags = Some(*val),
                    "NTLM_STATUS" => self.ntlm_spec.status = Some(*val as u16),
                    "RDP_PROTO" => self.rdp_spec.proto = Some(*val),
                    "RDP_FLAGS" => self.rdp_spec.flags = Some(*val as u8),
                    "RDP_SESSION_ID" => self.rdp_spec.session_id = Some(*val as u16),
                    "RDP_WIDTH" => self.rdp_spec.width = Some(*val as u16),
                    "RDP_HEIGHT" => self.rdp_spec.height = Some(*val as u16),
                    "LLMNR_TXID" => self.llmnr_spec.txid = Some(*val as u16),
                    "LLMNR_RCODE" => self.llmnr_spec.rcode = Some(*val as u8),
                    "LLMNR_ANS_TTL" => self.llmnr_spec.ans_ttl = Some(*val),
                    "LLMNR_FLAGS" => self.llmnr_spec.flags = Some(*val as u16),
                    "NBNS_TXID" => self.nbns_spec.txid = Some(*val as u16),
                    "NBNS_NB_TYPE" => self.nbns_spec.nb_type = Some(*val as u8),
                    "NBNS_RCODE" => self.nbns_spec.rcode = Some(*val as u8),
                    "NBNS_ANS_TTL" => self.nbns_spec.ans_ttl = Some(*val),
                    "NBNS_FLAGS" => self.nbns_spec.flags = Some(*val as u16),
                    "SOCKS_VERSION" => self.socks_spec.version = Some(*val as u8),
                    "SOCKS_STATUS" => self.socks_spec.status = Some(*val as u8),
                    "TARGET_PORT" => self.socks_spec.target_port = Some(*val as u16),
                    "SECURITY_TYPE" => self.vnc_spec.security_type = Some(*val as u8),
                    "WIDTH" => self.vnc_spec.width = Some(*val as u16),
                    "HEIGHT" => self.vnc_spec.height = Some(*val as u16),
                    "VNC_KEY" => self.vnc_spec.key = Some(*val),
                    "VNC_FLAGS" => self.vnc_spec.flags = Some(*val as u8),
                    "XPOS" => self.vnc_spec.xpos = Some(*val as u16),
                    "YPOS" => self.vnc_spec.ypos = Some(*val as u16),
                    "TX_SEQ" => self.iec104_spec.tx_seq = Some(*val as u16),
                    "RX_SEQ" => self.iec104_spec.rx_seq = Some(*val as u16),
                    "TYPE_ID" => self.iec104_spec.type_id = Some(*val as u8),
                    "COT" => self.iec104_spec.cot = Some(*val as u8),
                    "CA" => self.iec104_spec.ca = Some(*val as u16),
                    "IOA" => self.iec104_spec.ioa = Some(*val),
                    "MMS_INVOKE_ID" => self.mms_spec.invoke_id = Some(*val),
                    "S7PLUS_VERSION" => self.s7commplus_spec.version = Some(*val as u8),
                    "S7PLUS_SEQ_NUM" => self.s7commplus_spec.seq_num = Some(*val as u16),
                    "OBJECT_ID" => self.s7commplus_spec.object_id = Some(*val),
                    "SYN_VERSION" => self.synchrophasor_spec.version = Some(*val as u8),
                    "SYN_ID" => self.synchrophasor_spec.id_code = Some(*val as u16),
                    "FRAC_SEC" => self.synchrophasor_spec.frac_sec = Some(*val),
                    "SYN_CMD" => self.synchrophasor_spec.cmd = Some(*val as u16),
                    "SYN_STATUS" => self.synchrophasor_spec.status = Some(*val as u16),
                    "HART_VERSION" => self.hartip_spec.version = Some(*val as u8),
                    "HART_MSG_ID" => self.hartip_spec.msg_id = Some(*val as u8),
                    "HART_STATUS" => self.hartip_spec.status = Some(*val as u8),
                    "HOLD_TIME" => self.hartip_spec.inactivity_timer = Some(*val),
                    "HART_ADDR" => self.hartip_spec.poll_addr = Some(*val as u8),
                    "HART_CMD" => self.hartip_spec.hart_cmd = Some(*val as u8),
                    "FINS_ICF" => self.fins_spec.icf = Some(*val as u8),
                    "FINS_DNA" => self.fins_spec.dna = Some(*val as u8),
                    "FINS_DA1" => self.fins_spec.da1 = Some(*val as u8),
                    "FINS_DA2" => self.fins_spec.da2 = Some(*val as u8),
                    "FINS_SNA" => self.fins_spec.sna = Some(*val as u8),
                    "FINS_SA1" => self.fins_spec.sa1 = Some(*val as u8),
                    "FINS_SA2" => self.fins_spec.sa2 = Some(*val as u8),
                    "FINS_SID" => self.fins_spec.sid = Some(*val as u8),
                    "FINS_AREA" => self.fins_spec.area = Some(*val as u8),
                    "MELSEC_SUBCMD" => self.melsec_spec.subcmd = Some(*val as u16),
                    "MELSEC_NETWORK" => self.melsec_spec.network = Some(*val as u8),
                    "MELSEC_PC" => self.melsec_spec.pc = Some(*val as u8),
                    "MELSEC_IO" => self.melsec_spec.io = Some(*val as u16),
                    "MELSEC_STATION" => self.melsec_spec.station = Some(*val as u8),
                    "MELSEC_TIMER" => self.melsec_spec.timer = Some(*val as u16),
                    "MELSEC_DEVICE" => self.melsec_spec.device = Some(*val as u8),
                    "MELSEC_ADDR" => self.melsec_spec.addr = Some(*val),
                    "MELSEC_ENDCODE" => self.melsec_spec.endcode = Some(*val as u16),
                    "SOMEIP_SERVICE_ID" => self.someip_spec.service_id = Some(*val as u16),
                    "SOMEIP_METHOD_ID" => self.someip_spec.method_id = Some(*val as u16),
                    "SOMEIP_CLIENT_ID" => self.someip_spec.client_id = Some(*val as u16),
                    "SOMEIP_SESSION_ID" => self.someip_spec.session_id = Some(*val as u16),
                    "SOMEIP_PROTO_VER" => self.someip_spec.proto_ver = Some(*val as u8),
                    "SOMEIP_IFACE_VER" => self.someip_spec.iface_ver = Some(*val as u8),
                    "SOMEIP_RETURN_CODE" => self.someip_spec.return_code = Some(*val as u8),
                    "SOMEIP_SD_FLAGS" => self.someip_spec.sd_flags = Some(*val as u8),
                    "SOMEIP_SD_SERVICE" => self.someip_spec.sd_service = Some(*val as u16),
                    "SOMEIP_INSTANCE_ID" => self.someip_spec.instance_id = Some(*val as u16),
                    "SOMEIP_MAJOR_VER" => self.someip_spec.major_ver = Some(*val as u8),
                    "SOMEIP_SD_TTL" => self.someip_spec.sd_ttl = Some(*val),
                    "SOMEIP_MINOR_VER" => self.someip_spec.minor_ver = Some(*val),
                    "SOMEIP_ENDPOINT_PORT" => self.someip_spec.endpoint_port = Some(*val as u16),
                    "DOIP_VERSION" => self.doip_spec.version = Some(*val as u8),
                    "DOIP_INV_VERSION" => self.doip_spec.inv_version = Some(*val as u8),
                    "DOIP_SRC" => self.doip_spec.src = Some(*val as u16),
                    "DOIP_DST" => self.doip_spec.dst = Some(*val as u16),
                    "DOIP_CODE" => self.doip_spec.code = Some(*val as u8),
                    "C1222_CALLING_ID" => self.c1222_spec.calling_id = Some(*val),
                    "C1222_CALLED_ID" => self.c1222_spec.called_id = Some(*val),
                    "C1222_EPSEM_CTRL" => self.c1222_spec.epsem_ctrl = Some(*val as u8),
                    "C1222_ED_CLASS" => self.c1222_spec.ed_class = Some(*val),
                    "C1222_TABLE_ID" => self.c1222_spec.table_id = Some(*val as u16),
                    "C1222_ERRCODE" => self.c1222_spec.errcode = Some(*val as u8),
                    "ROC_DST" => self.rocplus_spec.dst = Some(*val as u8),
                    "ROC_SRC" => self.rocplus_spec.src = Some(*val as u8),
                    "ROC_TYPE" => self.rocplus_spec.point_type = Some(*val as u8),
                    "ROC_ADDR" => self.rocplus_spec.addr = Some(*val as u8),
                    "ROC_PARAM" => self.rocplus_spec.param = Some(*val as u8),
                    "BSAP_SEQ" => self.bsap_spec.seq_num = Some(*val as u8),
                    "BSAP_COUNT" => self.bsap_spec.count = Some(*val as u8),
                    "KNX_CHANNEL" => self.knxnetip_spec.channel = Some(*val as u8),
                    "KNX_SEQ" => self.knxnetip_spec.seq_num = Some(*val as u8),
                    "KNX_STATUS" => self.knxnetip_spec.status = Some(*val as u8),
                    "PKEY" => self.rocev2_spec.pkey = Some(*val as u16),
                    "DEST_QP" => self.rocev2_spec.dest_qp = Some(*val),
                    "ROCE_PSN" => self.rocev2_spec.psn = Some(*val),
                    "RKEY" => self.rocev2_spec.rkey = Some(*val),
                    "DMA_LEN" => self.rocev2_spec.dma_len = Some(*val),
                    "ROCE_SYNDROME" => self.rocev2_spec.syndrome = Some(*val as u8),
                    "ROCE_MSN" => self.rocev2_spec.msn = Some(*val),
                    "ICRC" => self.rocev2_spec.icrc = Some(*val),
                    "NETFN" => self.ipmi_spec.netfn = Some(*val as u8),
                    "IPMI_CMD" => self.ipmi_spec.cmd = Some(*val as u8),
                    "LUN" => {
                        self.ipmi_spec.lun = Some(*val as u8);
                        self.iscsi_spec.lun = Some(*val as u16);
                    }
                    "RQSEQ" => self.ipmi_spec.rqseq = Some(*val as u8),
                    "ERROR_ESTIMATE" => self.twamp_spec.error_estimate = Some(*val as u16),
                    "SENDER_TTL" => self.twamp_spec.sender_ttl = Some(*val as u8),
                    "TWAMP_MODE" => self.twamp_spec.mode = Some(*val),
                    "TWAMP_COUNT" => self.twamp_spec.count = Some(*val),
                    "PORT" => self.twamp_spec.port = Some(*val as u16),
                    "PADDING" => self.twamp_spec.padding = Some(*val as u16),
                    "TEID" => self.gtpc_spec.teid = Some(*val),
                    "CAUSE" => {
                        self.gtpc_spec.cause = Some(*val as u8);
                        self.pfcp_spec.cause = Some(*val as u8);
                        self.h323_spec.cause = Some(*val as u8);
                    }
                    "RAT" => self.gtpc_spec.rat = Some(*val as u8),
                    "RECOVERY" => {
                        self.gtpc_spec.recovery = Some(*val as u8);
                        self.pfcp_spec.recovery = Some(*val);
                    }
                    "app_id" => self.diameter_spec.app_id = Some(*val),
                    "hop_id" => self.diameter_spec.hop_id = Some(*val),
                    "end_id" => self.diameter_spec.end_id = Some(*val),
                    "result_code" => self.diameter_spec.result_code = Some(*val),
                    "proc_code" => {
                        self.ngap_spec.proc_code = Some(*val as u8);
                        self.s1ap_spec.proc_code = Some(*val as u8);
                    }
                    "ran_ue_id" => self.ngap_spec.ran_ue_id = Some(*val),
                    "gnb_id" => self.ngap_spec.gnb_id = Some(*val),
                    "tac" => {
                        self.ngap_spec.tac = Some(*val);
                        self.s1ap_spec.tac = Some(*val as u16);
                    }
                    "mme_ue_id" => self.s1ap_spec.mme_ue_id = Some(*val),
                    "enb_ue_id" => self.s1ap_spec.enb_ue_id = Some(*val),
                    "enb_id" => self.s1ap_spec.enb_id = Some(*val),
                    "errcode" => self.mssql_spec.errcode = Some(*val),
                    "spid" => self.mssql_spec.spid = Some(*val as u16),
                    "pkt_id" => self.mssql_spec.pkt_id = Some(*val as u8),
                    "api_version" => self.kafka_spec.api_version = Some(*val as u16),
                    "ITT" => self.iscsi_spec.itt = Some(*val),
                    "CMDSN" => self.iscsi_spec.cmdsn = Some(*val),
                    "STATSN" => self.iscsi_spec.statsn = Some(*val),
                    "NSID" => self.nvmetcp_spec.nsid = Some(*val),
                    "QID" => self.nvmetcp_spec.qid = Some(*val as u16),
                    "NVME_COUNT" => self.nvmetcp_spec.count = Some(*val),
                    "FRACTION" => self.rtcp_spec.fraction = Some(*val as u8),
                    "LOST" => self.rtcp_spec.lost = Some(*val),
                    "JITTER" => self.rtcp_spec.jitter = Some(*val),
                    "LIFETIME" => self.turn_spec.lifetime = Some(*val),
                    "REQUESTED_TRANSPORT" => self.turn_spec.requested_transport = Some(*val as u8),
                    "CALL_REF" => self.h323_spec.call_ref = Some(*val as u16),
                    "LINE" => self.sccp_spec.line = Some(*val),
                    "CALL_ID" => self.sccp_spec.call_id = Some(*val),
                    "STATE" => self.sccp_spec.call_state = Some(*val),
                    "BUTTON" => self.sccp_spec.button = Some(*val),
                    "TONE" => self.sccp_spec.tone = Some(*val),
                    "MEDIA_PORT" => self.sccp_spec.media_port = Some(*val as u16),
                    "RESPONSE_TO" => self.mongodb_spec.response_to = Some(*val),
                    _ => {}
                }
            }
            ParsedField::L7I32Field(key, val, span) => {
                let mod_key = if *key == "errcode" { "ERRCODE" } else { *key };
                self.record_mod(mod_key, *span);
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
                match *key {
                    "ETYPE" => self.kerberos_spec.etype = Some(*val),
                    "MSGID" => self.ldap_spec.msgid = Some(*val),
                    "PRECISION" => self.ntp_spec.precision = Some(*val as i8),
                    "correlation_id" => self.kafka_spec.correlation_id = Some(*val),
                    "partition" => self.kafka_spec.partition = Some(*val),
                    "acks" => {
                        if *val > i32::from(i16::MAX) {
                            self.check_bound(key, *val as u64, 0, i16::MAX as u64, *span);
                        } else if *val < i32::from(i16::MIN) {
                            self.check_bound(key, (*val).unsigned_abs() as u64, 0, 32768, *span);
                        } else {
                            self.kafka_spec.acks = Some(*val as i16);
                        }
                    }
                    "errcode" => {
                        if *val > i32::from(i16::MAX) {
                            self.check_bound(key, *val as u64, 0, i16::MAX as u64, *span);
                        } else if *val < i32::from(i16::MIN) {
                            self.check_bound(key, (*val).unsigned_abs() as u64, 0, 32768, *span);
                        } else {
                            self.kafka_spec.errcode = Some(*val as i16);
                        }
                    }
                    _ => {}
                }
            }
            ParsedField::L7BytesField(key, bytes, span) => {
                let mod_key = match *key {
                    "COAP_TOKEN" => "TOKEN",
                    "QUIC_DCID" => "DCID",
                    "QUIC_SCID" => "SCID",
                    "TURN_XOR_RELAYED" => "XOR_RELAYED_ADDR",
                    "TURN_XOR_PEER" => "XOR_PEER_ADDR",
                    "H323_RAS_ADDR" => "RAS_ADDR",
                    "nas_pdu" => "NAS_PDU",
                    _ => *key,
                };
                self.record_mod(mod_key, *span);
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
                match *key {
                    "COAP_TOKEN" => {
                        self.coap_spec.token_bytes = Some(bytes.clone());
                        if !bytes.is_empty() && bytes.len() <= 4 {
                            let mut buf = [0u8; 4];
                            buf[4 - bytes.len()..].copy_from_slice(bytes);
                            self.coap_spec.token = Some(u32::from_be_bytes(buf));
                        }
                    }
                    "QUIC_DCID" => {
                        self.quic_spec.dcid_bytes = Some(bytes.clone());
                        if !bytes.is_empty() && bytes.len() <= 8 {
                            let mut buf = [0u8; 8];
                            buf[8 - bytes.len()..].copy_from_slice(bytes);
                            self.quic_spec.dcid = Some(u64::from_be_bytes(buf));
                        }
                    }
                    "QUIC_SCID" => {
                        self.quic_spec.scid_bytes = Some(bytes.clone());
                        if !bytes.is_empty() && bytes.len() <= 8 {
                            let mut buf = [0u8; 8];
                            buf[8 - bytes.len()..].copy_from_slice(bytes);
                            self.quic_spec.scid = Some(u64::from_be_bytes(buf));
                        }
                    }
                    "PPPOE_HOST_UNIQ" => self.pppoe_spec.host_uniq = Some(bytes.clone()),
                    "PPPOE_AC_COOKIE" => self.pppoe_spec.ac_cookie = Some(bytes.clone()),
                    "NSH_CONTEXT" => self.nsh_spec.context = Some(bytes.clone()),
                    "nas_pdu" => {
                        self.ngap_spec.nas_pdu = Some(bytes.clone());
                        self.s1ap_spec.nas_pdu = Some(bytes.clone());
                    }
                    "TURN_XOR_RELAYED" => {
                        if let Some((ip, port)) = decode_packed_addr_port(bytes) {
                            self.turn_spec.xor_relayed_addr = Some(ip);
                            if let Some(p) = port {
                                self.check_bound("XOR_RELAYED_ADDR", p as u64, 0, 65535, *span);
                                self.turn_spec.xor_relayed_port = Some(p as u16);
                            }
                        }
                    }
                    "TURN_XOR_PEER" => {
                        if let Some((ip, port)) = decode_packed_addr_port(bytes) {
                            self.turn_spec.xor_peer_addr = Some(ip);
                            if let Some(p) = port {
                                self.check_bound("XOR_PEER_ADDR", p as u64, 0, 65535, *span);
                                self.turn_spec.xor_peer_port = Some(p as u16);
                            }
                        }
                    }
                    "H323_RAS_ADDR" => {
                        if let Some((ip, port)) = decode_packed_addr_port(bytes) {
                            self.h323_spec.ras_addr = Some(ip);
                            if let Some(p) = port {
                                self.check_bound("RAS_ADDR", p as u64, 0, 65535, *span);
                                self.h323_spec.ras_port = Some(p as u16);
                            }
                        }
                    }
                    _ => {}
                }
            }
            ParsedField::StunXorMapped(ip, port, span) => {
                self.record_mod("XOR_MAPPED_ADDR", *span);
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
                self.stun_spec.xor_mapped_addr = Some(*ip);
                self.turn_spec.xor_mapped_addr = Some(*ip);
                if let Some(p) = port {
                    self.check_bound("STUN xor-mapped port", *p as u64, 0, 65535, *span);
                    self.stun_spec.xor_mapped_port = Some(*p as u16);
                    self.turn_spec.xor_mapped_port = Some(*p as u16);
                }
            }
            ParsedField::L7U64Field(key, val, span) => {
                let mod_key = match *key {
                    "TWAMP_TIMESTAMP" => "TIMESTAMP",
                    "amf_ue_id" => "AMF_UE_ID",
                    "offset" => "OFFSET",
                    _ => *key,
                };
                self.record_mod(mod_key, *span);
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
                match *key {
                    "TX_TIMESTAMP" => self.ntp_spec.tx_timestamp = Some(*val),
                    "SESSION_ID" => {
                        self.tacacs_spec.session_id = Some(*val as u32);
                        self.smb_spec.session_id = Some(*val);
                        self.ipmi_spec.session_id = Some(*val as u32);
                        self.netconf_spec.session_id = Some(*val as u32);
                        self.s7commplus_spec.session_id = Some(*val as u32);
                        self.deferred_u64_fields.push(("SESSION_ID", *val, *span));
                    }
                    "DCID" => self.quic_spec.dcid = Some(*val),
                    "SCID" => self.quic_spec.scid = Some(*val),
                    "MSGID" => self.smb_spec.msgid = Some(*val),
                    "CAS" => self.memcached_spec.cas = Some(*val),
                    "CONTEXT" => self.ethernetip_spec.context = Some(*val),
                    "MACSEC_SCI" => self.macsec_spec.sci = Some(*val),
                    "LISP_NONCE" => self.lisp_spec.nonce = Some(*val),
                    "ROCE_VA" => self.rocev2_spec.va = Some(*val),
                    "TWAMP_TIMESTAMP" => self.twamp_spec.timestamp = Some(*val),
                    "SEID" => self.pfcp_spec.seid = Some(*val),
                    "amf_ue_id" => self.ngap_spec.amf_ue_id = Some(*val),
                    "offset" => self.kafka_spec.offset = Some(*val),
                    _ => {}
                }
            }
            ParsedField::L7IpField(key, val, span) => {
                if *key != "SRV6_SID" {
                    self.record_mod(key, *span);
                }
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
                match *key {
                    "CIADDR" => self.dhcp_spec.ciaddr = Some(*val),
                    "YIADDR" => self.dhcp_spec.yiaddr = Some(*val),
                    "SIADDR" => self.dhcp_spec.siaddr = Some(*val),
                    "DNS_SERVER" => self.dhcp_spec.dns_server = Some(*val),
                    "ROUTER" => self.dhcp_spec.router = Some(*val),
                    "SUBNET_MASK" => self.dhcp_spec.subnet_mask = Some(*val),
                    "NAS_IP" => self.radius_spec.nas_ip = Some(*val),
                    "FRAMED_IP" => self.radius_spec.framed_ip = Some(*val),
                    "SRCIP" => {
                        self.netflow_spec.srcip = Some(*val);
                        self.ipfix_spec.srcip = Some(*val);
                        self.ipip_spec.src_ip = Some(*val);
                        self.rsvp_spec.src_ip = Some(*val);
                    }
                    "DSTIP" => {
                        self.netflow_spec.dstip = Some(*val);
                        self.ipfix_spec.dstip = Some(*val);
                        self.ipip_spec.dst_ip = Some(*val);
                        self.rsvp_spec.dst_ip = Some(*val);
                    }
                    "AGENT_IP" => self.sflow_spec.agent_ip = Some(*val),
                    "XOR_MAPPED_ADDR" => self.stun_spec.xor_mapped_addr = Some(*val),
                    "CDP_ADDR" => self.cdp_spec.addr = Some(*val),
                    "SRV6_SID" => self.srv6_spec.sids.push(*val),
                    "LDP_LSR_ID" => self.ldp_spec.lsr_id = Some(*val),
                    "BMP_PEER_IP" => self.bmp_spec.peer_ip = Some(*val),
                    "LISP_RLOC" => self.lisp_spec.rloc = Some(*val),
                    "SOMEIP_ENDPOINT_IP" => self.someip_spec.endpoint_ip = Some(*val),
                    "ADDR" => {
                        self.gtpc_spec.addr = Some(*val);
                        self.sccp_spec.addr = Some(*val);
                    }
                    _ => {}
                }
            }
            ParsedField::L7MacField(key, val, span) => {
                self.record_mod(key, *span);
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
                match *key {
                    "CHADDR" => self.dhcp_spec.chaddr = Some(*val),
                    "GLBP_OWNER_ID" => self.glbp_spec.owner_id = Some(*val),
                    "GLBP_VMAC" => self.glbp_spec.vmac = Some(*val),
                    "DOIP_EID" => self.doip_spec.eid = Some(*val),
                    "DOIP_GID" => self.doip_spec.gid = Some(*val),
                    _ => {}
                }
            }
            ParsedField::L7Flag(key, span) => {
                let mod_key = match *key {
                    "PN_REQUEST" | "PN_RESPONSE" => "PN_DIR",
                    "IPMI_REQUEST" => "RESPONSE",
                    _ => *key,
                };
                self.record_mod(mod_key, *span);
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
                match *key {
                    "QUERY" => {
                        self.dns_spec.is_query = true;
                        self.whois_spec.is_query = true;
                        self.mysql_spec.is_query = true;
                        self.postgres_spec.is_query = true;
                        self.doh_spec.is_query = true;
                    }
                    "RESPONSE" => {
                        self.dns_spec.is_response = true;
                        self.whois_spec.is_response = true;
                        self.doh_spec.is_response = true;
                        self.ipmi_spec.is_response = true;
                        self.mongodb_spec.is_response = true;
                    }
                    "DISCOVER" => self.dhcp_spec.is_discover = true,
                    "SOLICIT" => self.dhcp_spec.is_solicit = true,
                    "OFFER" => self.dhcp_spec.is_offer = true,
                    "ADVERTISE" => self.dhcp_spec.is_advertise = true,
                    "REQUEST" => {
                        self.dhcp_spec.is_request = true;
                        self.turn_spec.is_request = true;
                    }
                    "ACK" => {
                        self.dhcp_spec.is_ack = true;
                        self.tftp_spec.is_ack = true;
                        self.coap_spec.msg_type = Some("ACK");
                    }
                    "REPLY" => self.dhcp_spec.is_reply = true,
                    "RELEASE" => self.dhcp_spec.is_release = true,
                    "SYNC" => self.ptp_spec.msg_type = Some("SYNC"),
                    "DELAY_REQ" => self.ptp_spec.msg_type = Some("DELAY_REQ"),
                    "FOLLOW_UP" => self.ptp_spec.msg_type = Some("FOLLOW_UP"),
                    "DELAY_RESP" => self.ptp_spec.msg_type = Some("DELAY_RESP"),
                    "ANNOUNCE" => self.ptp_spec.msg_type = Some("ANNOUNCE"),
                    "RRQ" => self.tftp_spec.is_rrq = true,
                    "WRQ" => self.tftp_spec.is_wrq = true,
                    "DATA" => {
                        self.tftp_spec.is_data = true;
                        self.http2_spec.is_data = true;
                    }
                    "ERROR" => {
                        self.tftp_spec.is_error = true;
                        self.turn_spec.is_error = true;
                    }
                    "KEXINIT" => self.ssh_spec.is_kexinit = true,
                    "NEWKEYS" => self.ssh_spec.is_newkeys = true,
                    "PREFACE" => self.http2_spec.is_preface = true,
                    "SETTINGS" => self.http2_spec.is_settings = true,
                    "HEADERS" => self.http2_spec.is_headers = true,
                    "WINDOW_UPDATE" => self.http2_spec.is_window_update = true,
                    "PING" => self.http2_spec.is_ping = true,
                    "GOAWAY" => self.http2_spec.is_goaway = true,
                    "CLIENT_HELLO" => self.tls_spec.is_client_hello = true,
                    "SERVER_HELLO" => self.tls_spec.is_server_hello = true,
                    "CERTIFICATE" => self.tls_spec.is_certificate = true,
                    "FINISHED" => self.tls_spec.is_finished = true,
                    "APP_DATA" => self.tls_spec.is_app_data = true,
                    "ALERT" => self.tls_spec.is_alert = true,
                    "INITIAL" => self.quic_spec.is_initial = true,
                    "ZERO_RTT" => self.quic_spec.is_zero_rtt = true,
                    "HANDSHAKE" => self.quic_spec.is_handshake = true,
                    "RETRY" => self.quic_spec.is_retry = true,
                    "SHORT" => self.quic_spec.is_short = true,
                    "BINDING_REQUEST" => self.stun_spec.is_binding_request = true,
                    "BINDING_RESPONSE" => self.stun_spec.is_binding_response = true,
                    "BINDING_ERROR" => self.stun_spec.is_binding_error = true,
                    "OK" => {
                        self.pop3_spec.is_ok = true;
                        self.mysql_spec.is_ok = true;
                        self.mongodb_spec.is_response = true;
                    }
                    "ERR" => {
                        self.pop3_spec.is_err = true;
                        self.mysql_spec.is_err = true;
                        self.tftp_spec.is_error = true;
                        self.mongodb_spec.is_err = true;
                    }
                    "AS_REQ" => self.kerberos_spec.is_as_req = true,
                    "AS_REP" => self.kerberos_spec.is_as_rep = true,
                    "TGS_REQ" => self.kerberos_spec.is_tgs_req = true,
                    "TGS_REP" => self.kerberos_spec.is_tgs_rep = true,
                    "KRB_ERROR" => self.kerberos_spec.is_krb_error = true,
                    "BIND_REQ" => self.ldap_spec.is_bind_req = true,
                    "BIND_RES" => self.ldap_spec.is_bind_res = true,
                    "SEARCH_REQ" => self.ldap_spec.is_search_req = true,
                    "SEARCH_ENTRY" => self.ldap_spec.is_search_entry = true,
                    "SEARCH_DONE" => self.ldap_spec.is_search_done = true,
                    "UNBIND_REQ" => self.ldap_spec.is_unbind_req = true,
                    "GREETING" => {
                        self.mysql_spec.is_greeting = true;
                        self.socks_spec.is_greeting = true;
                    }
                    "LOGIN" => self.mysql_spec.is_login = true,
                    "EOF" => self.mysql_spec.is_eof = true,
                    "STARTUP" => self.postgres_spec.is_startup = true,
                    "READY_FOR_QUERY" => self.postgres_spec.is_ready_for_query = true,
                    "COMMAND_COMPLETE" => self.postgres_spec.is_command_complete = true,
                    "ERROR_RESPONSE" => self.postgres_spec.is_error_response = true,
                    "AUTH_OK" => self.postgres_spec.is_auth_ok = true,
                    "RETAIN" => self.mqtt_spec.retain = Some(true),
                    "NO_RETAIN" => self.mqtt_spec.retain = Some(false),
                    "PROTOCOL_HEADER" => self.amqp_spec.is_protocol_header = true,
                    "CONNECTION_START" => self.amqp_spec.is_connection_start = true,
                    "CHANNEL_OPEN" => self.amqp_spec.is_channel_open = true,
                    "BASIC_PUBLISH" => self.amqp_spec.is_basic_publish = true,
                    "BASIC_DELIVER" => self.amqp_spec.is_basic_deliver = true,
                    "HEARTBEAT" => self.amqp_spec.is_heartbeat = true,
                    "MSEARCH" => self.ssdp_spec.is_msearch = true,
                    "NOTIFY" => self.ssdp_spec.is_notify = true,
                    "IS_RESPONSE" => {
                        self.modbus_spec.is_response = true;
                        self.mms_spec.is_response = true;
                        self.s7commplus_spec.is_response = true;
                        self.hartip_spec.is_response = true;
                        self.fins_spec.is_response = true;
                        self.melsec_spec.is_response = true;
                        self.rocplus_spec.is_response = true;
                        self.bsap_spec.is_response = true;
                    }
                    "WHO_IS" => self.bacnet_spec.is_who_is = true,
                    "I_AM" => self.bacnet_spec.is_i_am = true,
                    "READ_PROPERTY" => self.bacnet_spec.is_read_property = true,
                    "WRITE_PROPERTY" => self.bacnet_spec.is_write_property = true,
                    "COMPLEX_ACK" => self.bacnet_spec.is_complex_ack = true,
                    "EDNS0" => {
                        self.dns_spec.edns0 = true;
                        self.doh_spec.edns0 = true;
                    }
                    "DO_BIT" => {
                        self.dns_spec.do_bit = true;
                        self.doh_spec.do_bit = true;
                    }
                    "NSH_OAM" => self.nsh_spec.oam = true,
                    "PN_REQUEST" => self.profinet_spec.is_response = false,
                    "PN_RESPONSE" => self.profinet_spec.is_response = true,
                    "IEC_SIMULATION" => {
                        self.goose_spec.simulation = true;
                        self.sv_spec.simulation = true;
                    }
                    "NDS_COM" => self.goose_spec.nds_com = true,
                    "L2TP_DATA" => self.l2tp_spec.is_data = true,
                    "LLMNR_QUERY" => self.llmnr_spec.is_query = true,
                    "LLMNR_RESPONSE" => self.llmnr_spec.is_response = true,
                    "NBNS_RESPONSE" => self.nbns_spec.is_response = true,
                    "NBNS_GROUP" => self.nbns_spec.is_group = true,
                    "SOCKS_REPLY" => self.socks_spec.is_reply = true,
                    "CONFIRM" => self.iec104_spec.confirm = true,
                    "KNX_READ" => self.knxnetip_spec.is_read = true,
                    "KNX_WRITE" => self.knxnetip_spec.is_read = false,
                    "ACK_REQ" => self.rocev2_spec.ack_req = true,
                    "IPMI_REQUEST" => self.ipmi_spec.is_response = false,
                    "CHUNKED" => self.netconf_spec.chunked = true,
                    "cer" => self.diameter_spec.cmd = Some("cer"),
                    "cea" => {
                        self.diameter_spec.cmd = Some("cea");
                        self.diameter_spec.is_response = true;
                    }
                    "dwr" => self.diameter_spec.cmd = Some("dwr"),
                    "dwa" => {
                        self.diameter_spec.cmd = Some("dwa");
                        self.diameter_spec.is_response = true;
                    }
                    "ccr" => self.diameter_spec.cmd = Some("ccr"),
                    "cca" => {
                        self.diameter_spec.cmd = Some("cca");
                        self.diameter_spec.is_response = true;
                    }
                    "request" => self.diameter_spec.is_response = false,
                    "response" => {
                        self.diameter_spec.is_response = true;
                        self.kafka_spec.is_response = true;
                    }
                    "ngsetuprequest" | "ngsetupresponse" | "ngsetupfailure" => {
                        self.ngap_spec.pdu_type = Some(*key);
                    }
                    "s1setuprequest" | "s1setupresponse" | "s1setupfailure" => {
                        self.s1ap_spec.pdu_type = Some(*key);
                    }
                    "initialuemessage"
                    | "downlinknastransport"
                    | "uplinknastransport"
                    | "uecontextreleasecommand"
                    | "uecontextreleasecomplete"
                    | "errorindication" => {
                        self.ngap_spec.pdu_type = Some(*key);
                        self.s1ap_spec.pdu_type = Some(*key);
                    }
                    "prelogin" => self.mssql_spec.is_prelogin = true,
                    "login" => self.mssql_spec.is_login = true,
                    "query" => self.mssql_spec.is_query = true,
                    "ok" => self.mssql_spec.is_ok = true,
                    "err" => self.mssql_spec.is_err = true,
                    "attention" => self.mssql_spec.pkt_type = Some("attention"),
                    "apiversions" | "metadata" | "produce" | "fetch" | "heartbeat" => {
                        self.kafka_spec.api = Some(*key);
                    }
                    _ => {}
                }
            }
            ParsedField::L7Header(k, v, span) => {
                self.http_spec.headers.push((*k, *v));
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
            }
            _ => {}
        }
    }
}
