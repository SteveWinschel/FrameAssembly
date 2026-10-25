//! Layer 7 field accumulation and application-layer modifier dispatch for [`FrameBuilder`].
//!
//! This module implements [`FrameBuilder::apply_l7_field`], which updates the statement
//! accumulator's protocol-specific Layer 7 [`ProtocolSpec`] state when
//! an [`L7StringField`](super::fields::ParsedField::L7StringField),
//! [`L7U32Field`](super::fields::ParsedField::L7U32Field),
//! [`L7U64Field`](super::fields::ParsedField::L7U64Field),
//! [`L7IpField`](super::fields::ParsedField::L7IpField),
//! [`L7MacField`](super::fields::ParsedField::L7MacField),
//! [`L7Flag`](super::fields::ParsedField::L7Flag), or
//! [`L7Header`](super::fields::ParsedField::L7Header) modifier is parsed from a frame statement.
//! It records modifier spans for duplicate detection, advances the statement end byte offset, and
//! routes each keyed attribute to the corresponding Layer 7 specification struct.

use super::fields::ParsedField;
use super::statement::FrameBuilder;

impl<'a> FrameBuilder<'a> {
    /// Applies a parsed Layer 7 modifier field (`L7StringField`, `L7U32Field`, `L7U64Field`,
    /// `L7IpField`, `L7MacField`, `L7Flag`, or `L7Header`) to the builder state.
    pub(crate) fn apply_l7_field(&mut self, f: &ParsedField<'a>) {
        match f {
            ParsedField::L7StringField(key, val, span) => {
                self.record_mod(key, *span);
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
                match *key {
                    "QNAME" => self.dns_spec.qname = Some(*val),
                    "QTYPE" => self.dns_spec.qtype = Some(*val),
                    "RDATA" => self.dns_spec.rdata = Some(*val),
                    "HOSTNAME" => {
                        self.dhcp_spec.hostname = Some(*val);
                        self.syslog_spec.hostname = Some(*val);
                    }
                    "REFID" => self.ntp_spec.refid = Some(*val),
                    "MSG_TYPE" => {
                        self.ptp_spec.msg_type = Some(*val);
                        self.coap_spec.msg_type = Some(*val);
                        self.opcua_spec.msg_type = Some(*val);
                    }
                    "CLOCK_ID" => self.ptp_spec.clock_id = Some(*val),
                    "DOMAIN" => {
                        self.whois_spec.domain = Some(*val);
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
                    }
                    "DATA" => {
                        self.tacacs_spec.data = Some(*val);
                        self.telnet_spec.data = Some(*val);
                    }
                    "APP" => self.syslog_spec.app = Some(*val),
                    "PROCID" => self.syslog_spec.procid = Some(*val),
                    "MSGID" => self.syslog_spec.msgid = Some(*val),
                    "MSG" => self.syslog_spec.msg = Some(*val),
                    "FILENAME" => {
                        self.tftp_spec.filename = Some(*val);
                        self.smb_spec.filename = Some(*val);
                    }
                    "MODE" => self.tftp_spec.mode = Some(*val),
                    "ERRMSG" => self.tftp_spec.errmsg = Some(*val),
                    "CMD" => {
                        self.ftp_spec.cmd = Some(*val);
                        self.smtp_spec.cmd = Some(*val);
                        self.imap_spec.cmd = Some(*val);
                        self.pop3_spec.cmd = Some(*val);
                        self.redis_spec.cmd = Some(*val);
                        self.memcached_spec.cmd = Some(*val);
                        self.ethernetip_spec.cmd = Some(*val);
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
                    }
                    "URI" => {
                        self.http_spec.uri = Some(*val);
                        self.sip_spec.uri = Some(*val);
                        self.rtsp_spec.uri = Some(*val);
                    }
                    "VERSION" => self.http_spec.version = Some(*val),
                    "HOST_HDR" => {
                        self.http_spec.host_hdr = Some(*val);
                        self.ssdp_spec.host_hdr = Some(*val);
                    }
                    "USER_AGENT" => self.http_spec.user_agent = Some(*val),
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
                    }
                    "BODY" => {
                        self.http_spec.body = Some(*val);
                        self.smtp_spec.body = Some(*val);
                        self.sip_spec.body = Some(*val);
                    }
                    "SERVICE" => self.grpc_spec.service = Some(*val),
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
                    "SOFTWARE" => self.stun_spec.software = Some(*val),
                    "FROM" => self.sip_spec.from = Some(*val),
                    "TO" => self.sip_spec.to = Some(*val),
                    "CALL_ID" => self.sip_spec.call_id = Some(*val),
                    "VIA" => self.sip_spec.via = Some(*val),
                    "CONTACT" => self.sip_spec.contact = Some(*val),
                    "TRANSPORT_HDR" => self.rtsp_spec.transport_hdr = Some(*val),
                    "SESSION" => self.rtsp_spec.session = Some(*val),
                    "PARAM" => self.smtp_spec.param = Some(*val),
                    "RESPONSE" => {
                        self.imap_spec.response = Some(*val);
                        self.pop3_spec.response = Some(*val);
                    }
                    "REALM" => self.kerberos_spec.realm = Some(*val),
                    "CNAME" => self.kerberos_spec.cname = Some(*val),
                    "SNAME" => self.kerberos_spec.sname = Some(*val),
                    "BASE_DN" => self.ldap_spec.base_dn = Some(*val),
                    "FILTER" => self.ldap_spec.filter = Some(*val),
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
                    }
                    "DB" => {
                        self.mysql_spec.db = Some(*val);
                        self.postgres_spec.db = Some(*val);
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
                    }
                    "ROSCTR" => self.s7comm_spec.rosctr = Some(*val),
                    "AREA" => {
                        self.s7comm_spec.area = Some(match val.to_ascii_uppercase().as_str() {
                            "PE" | "I" => 0x81,
                            "PA" | "Q" => 0x82,
                            "MK" | "M" => 0x83,
                            "DB" => 0x84,
                            "CT" | "C" => 0x1C,
                            "TM" | "T" => 0x1D,
                            _ => val.parse::<u8>().unwrap_or(0x84),
                        });
                    }
                    "ENDPOINT_URL" => self.opcua_spec.endpoint_url = Some(*val),
                    "NODE_ID" => self.opcua_spec.node_id = Some(*val),
                    "CHUNK_TYPE" => self.opcua_spec.chunk_type = val.chars().next(),
                    "HSRP_AUTH" => self.hsrp_auth = Some(*val),
                    _ => {}
                }
            }
            ParsedField::L7U32Field(key, val, span) => {
                self.record_mod(key, *span);
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
                match *key {
                    "TXID" => {
                        self.dns_spec.txid = Some(*val as u16);
                        self.modbus_spec.txid = Some(*val as u16);
                        self.stun_spec.txid = Some(*val);
                    }
                    "ICMP_TYPE" => self.icmp_type_val = Some(*val as u8),
                    "CODE" => {
                        self.icmp_code_val = Some(*val as u8);
                        self.ftp_spec.code = Some(*val as u16);
                        self.smtp_spec.code = Some(*val as u16);
                    }
                    "DOMAIN" => self.ptp_spec.domain = Some(*val as u8),
                    "RCODE" => self.dns_spec.rcode = Some(*val as u8),
                    "ANS_TTL" => self.dns_spec.ans_ttl = Some(*val),
                    "LEASE_TIME" => self.dhcp_spec.lease_time = Some(*val),
                    "LI" => self.ntp_spec.li = Some(*val as u8),
                    "VN" => self.ntp_spec.vn = Some(*val as u8),
                    "MODE" => self.ntp_spec.mode = Some(*val as u8),
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
                    }
                    "PACKETS" => {
                        self.netflow_spec.packets = Some(*val);
                        self.ipfix_spec.packets = Some(*val);
                    }
                    "OCTETS" => {
                        self.netflow_spec.octets = Some(*val);
                        self.ipfix_spec.octets = Some(*val);
                    }
                    "DOMAIN_ID" => self.ipfix_spec.domain_id = Some(*val),
                    "SUB_AGENT_ID" => self.sflow_spec.sub_agent_id = Some(*val),
                    "UPTIME" => self.sflow_spec.uptime = Some(*val),
                    "SAMPLES" => self.sflow_spec.samples = Some(*val),
                    "BLOCK" => self.tftp_spec.block = Some(*val as u16),
                    "ERRCODE" => {
                        self.tftp_spec.errcode = Some(*val as u16);
                        self.mysql_spec.errcode = Some(*val as u16);
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
                    }
                    "STREAM_ID" => self.http2_spec.stream_id = Some(*val),
                    "GRPC_STATUS" => self.grpc_spec.grpc_status = Some(*val),
                    "FIN_BIT" => self.websocket_spec.fin_bit = Some(*val as u8),
                    "MASK_KEY" => self.websocket_spec.mask_key = Some(*val),
                    "RECORD_VERSION" => self.tls_spec.record_version = Some(*val as u16),
                    "HANDSHAKE_VERSION" => self.tls_spec.handshake_version = Some(*val as u16),
                    "CIPHERSUITE" => self.tls_spec.ciphersuite = Some(*val as u16),
                    "VERSION" => self.quic_spec.version = Some(*val),
                    "PKT_NUM" => self.quic_spec.pkt_num = Some(*val),
                    "CSEQ" => {
                        self.sip_spec.cseq = Some(*val);
                        self.rtsp_spec.cseq = Some(*val);
                    }
                    "PT" => self.rtp_spec.pt = Some(*val as u8),
                    "TIMESTAMP" => self.rtp_spec.timestamp = Some(*val),
                    "SSRC" => self.rtp_spec.ssrc = Some(*val),
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
                    }
                    "EXPTIME" => self.memcached_spec.exptime = Some(*val),
                    "OPCODE" => self.memcached_spec.opcode = Some(*val as u8),
                    "OPAQUE" => self.memcached_spec.opaque = Some(*val),
                    "QOS" => self.mqtt_spec.qos = Some(*val as u8),
                    "PKT_ID" => self.mqtt_spec.pkt_id = Some(*val as u16),
                    "KEEPALIVE" => self.mqtt_spec.keepalive = Some(*val as u16),
                    "RETURN_CODE" => self.mqtt_spec.return_code = Some(*val as u8),
                    "TOKEN" => self.coap_spec.token = Some(*val),
                    "CONTENT_FORMAT" => self.coap_spec.content_format = Some(*val as u16),
                    "CHANNEL" => self.amqp_spec.channel = Some(*val as u16),
                    "MX" => self.ssdp_spec.mx = Some(*val as u8),
                    "PROTO_ID" => self.modbus_spec.proto_id = Some(*val as u16),
                    "UNITID" => self.modbus_spec.unitid = Some(*val as u8),
                    "ADDR" => self.modbus_spec.addr = Some(*val as u16),
                    "COUNT" => self.modbus_spec.count = Some(*val as u16),
                    "VALUE" => {
                        self.modbus_spec.value = Some(*val as u16);
                        self.bacnet_spec.value = Some(*val);
                    }
                    "INVOKE_ID" => self.bacnet_spec.invoke_id = Some(*val as u8),
                    "OBJECT_TYPE" => self.bacnet_spec.object_type = Some(*val as u16),
                    "OBJECT_INSTANCE" => self.bacnet_spec.object_instance = Some(*val),
                    "PROPERTY_ID" => self.bacnet_spec.property_id = Some(*val),
                    "SRC" => self.dnp3_spec.src = Some(*val as u16),
                    "DST" => self.dnp3_spec.dst = Some(*val as u16),
                    "GROUP" => self.dnp3_spec.group = Some(*val as u8),
                    "VARIATION" => self.dnp3_spec.variation = Some(*val as u8),
                    "CRC" => self.dnp3_spec.crc = Some(*val as u16),
                    "PDU_REF" => self.s7comm_spec.pdu_ref = Some(*val as u16),
                    "AREA" => self.s7comm_spec.area = Some(*val as u8),
                    "DB_NUM" => self.s7comm_spec.db_num = Some(*val as u16),
                    "OFFSET" => self.s7comm_spec.offset = Some(*val),
                    "SESSION_HANDLE" => self.ethernetip_spec.session_handle = Some(*val),
                    "CIP_SERVICE" => self.ethernetip_spec.cip_service = Some(*val as u8),
                    "CIP_CLASS" => self.ethernetip_spec.cip_class = Some(*val as u16),
                    "CIP_INSTANCE" => self.ethernetip_spec.cip_instance = Some(*val as u16),
                    "CIP_ATTR" => self.ethernetip_spec.cip_attr = Some(*val as u16),
                    "SECURE_CHANNEL_ID" => self.opcua_spec.secure_channel_id = Some(*val),
                    "TOKEN_ID" => self.opcua_spec.token_id = Some(*val),
                    "SEQ_NUM" => self.opcua_spec.seq_num = Some(*val),
                    "REQ_ID" => self.opcua_spec.req_id = Some(*val),
                    _ => {}
                }
            }
            ParsedField::L7U64Field(key, val, span) => {
                self.record_mod(key, *span);
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
                match *key {
                    "TX_TIMESTAMP" => self.ntp_spec.tx_timestamp = Some(*val),
                    "SESSION_ID" => {
                        self.tacacs_spec.session_id = Some(*val as u32);
                        self.smb_spec.session_id = Some(*val);
                    }
                    "DCID" => self.quic_spec.dcid = Some(*val),
                    "SCID" => self.quic_spec.scid = Some(*val),
                    "MSGID" => self.smb_spec.msgid = Some(*val),
                    "CAS" => self.memcached_spec.cas = Some(*val),
                    "CONTEXT" => self.ethernetip_spec.context = Some(*val),
                    _ => {}
                }
            }
            ParsedField::L7IpField(key, val, span) => {
                self.record_mod(key, *span);
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
                    }
                    "DSTIP" => {
                        self.netflow_spec.dstip = Some(*val);
                        self.ipfix_spec.dstip = Some(*val);
                    }
                    "AGENT_IP" => self.sflow_spec.agent_ip = Some(*val),
                    "XOR_MAPPED_ADDR" => self.stun_spec.xor_mapped_addr = Some(*val),
                    _ => {}
                }
            }
            ParsedField::L7MacField(key, val, span) => {
                self.record_mod(key, *span);
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
                if *key == "CHADDR" {
                    self.dhcp_spec.chaddr = Some(*val);
                }
            }
            ParsedField::L7Flag(key, span) => {
                self.record_mod(key, *span);
                self.stmt_end_offset = self.stmt_end_offset.max(span.0 + span.1);
                match *key {
                    "QUERY" => {
                        self.dns_spec.is_query = true;
                        self.whois_spec.is_query = true;
                        self.mysql_spec.is_query = true;
                        self.postgres_spec.is_query = true;
                    }
                    "RESPONSE" => {
                        self.dns_spec.is_response = true;
                        self.whois_spec.is_response = true;
                    }
                    "DISCOVER" => self.dhcp_spec.is_discover = true,
                    "SOLICIT" => self.dhcp_spec.is_solicit = true,
                    "OFFER" => self.dhcp_spec.is_offer = true,
                    "ADVERTISE" => self.dhcp_spec.is_advertise = true,
                    "REQUEST" => self.dhcp_spec.is_request = true,
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
                    }
                    "ERR" => {
                        self.pop3_spec.is_err = true;
                        self.mysql_spec.is_err = true;
                        self.tftp_spec.is_error = true;
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
                    "GREETING" => self.mysql_spec.is_greeting = true,
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
                    "IS_RESPONSE" => self.modbus_spec.is_response = true,
                    "WHO_IS" => self.bacnet_spec.is_who_is = true,
                    "I_AM" => self.bacnet_spec.is_i_am = true,
                    "READ_PROPERTY" => self.bacnet_spec.is_read_property = true,
                    "WRITE_PROPERTY" => self.bacnet_spec.is_write_property = true,
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
