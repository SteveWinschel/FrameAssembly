//! End-to-End (E2E) integration test suite for FrameAssembly Layer 7 application protocols.
//!
//! Validates the full Layer 7 application, telemetry, infrastructure, web, cloud, security, VoIP,
//! mail, authentication, storage, database, messaging, and industrial OT/SCADA protocol catalog
//! across IPv4 and IPv6 endpoints:
//! - Tier 1: Feature coverage across all 50 Layer 7 protocols (`SNMP1`, `SNMP2`, `SNMP3`, `DNS`,
//!   `MDNS`, `DHCP`, `NTP`, `PTP`, `RADIUS`, `TACACS`, `SYSLOG`, `NETFLOW`, `IPFIX`, `SFLOW`,
//!   `TFTP`, `FTP`, `SSH`, `TELNET`, `HTTP`, `HTTP2`, `GRPC`, `WEBSOCKET`, `TLS`, `QUIC`, `STUN`,
//!   `SIP`, `RTP`, `RTSP`, `SMTP`, `IMAP`, `POP3`, `KERBEROS`, `LDAP`, `SMB`, `NFS`, `REDIS`,
//!   `MEMCACHED`, `MYSQL`, `POSTGRES`, `MQTT`, `COAP`, `AMQP`, `SSDP`, `WHOIS`, `MODBUS`,
//!   `BACNET`, `DNP3`, `S7COMM`, `ETHERNETIP`, `OPCUA`).
//! - Tier 4: Real-world multi-step application workflows (BGP4+ peering, HTTPS over TLS, recursive
//!   DNS, IoT MQTT over TLS, VoIP SIP+RTP, enterprise NMS SNMPv3+Syslog, and SCADA substation).

use std::fs;
use std::path::Path;

/// Context holding a captured network frame from an emitted PCAPNG file.
#[derive(Debug, Clone)]
pub struct PacketContext {
    /// Raw Ethernet frame byte buffer extracted from an Enhanced Packet Block.
    pub raw: Vec<u8>,
}

#[allow(dead_code)]
impl PacketContext {
    /// Extracts the 16-bit big-endian Ethernet EtherType at byte offset `12..14`.
    pub fn ethertype(&self) -> Option<u16> {
        (self.raw.len() >= 14).then(|| u16::from_be_bytes([self.raw[12], self.raw[13]]))
    }

    /// Extracts the 6-byte Ethernet source MAC address at byte offset `6..12`.
    pub fn src_mac(&self) -> Option<[u8; 6]> {
        self.raw.get(6..12).and_then(|s| s.try_into().ok())
    }

    /// Extracts the 6-byte Ethernet destination MAC address at byte offset `0..6`.
    pub fn dst_mac(&self) -> Option<[u8; 6]> {
        self.raw.get(0..6).and_then(|d| d.try_into().ok())
    }
}

/// Reads all Enhanced Packet Blocks from an emitted PCAPNG file on disk.
fn read_pcapng_packets(path: &Path) -> Result<Vec<PacketContext>, String> {
    let pcap_file =
        fs::File::open(path).map_err(|e| format!("Failed to open {}: {}", path.display(), e))?;
    let mut reader = pcap_file::pcapng::PcapNgReader::new(pcap_file)
        .map_err(|e| format!("Failed to create PCAPNG reader: {}", e))?;
    let mut frames = Vec::new();
    while let Some(block_res) = reader.next_block() {
        let block = block_res.map_err(|e| format!("Failed to read block: {}", e))?;
        if let pcap_file::pcapng::Block::EnhancedPacket(epb) = block {
            frames.push(PacketContext { raw: epb.data.to_vec() });
        }
    }
    Ok(frames)
}

/// Compiles a `.fasm` script to a temporary PCAPNG file and runs the verification closure.
///
/// Panics immediately if parsing, semantic validation, or PCAPNG generation fails, or if zero
/// packets are emitted.
pub fn run_e2e_test<F>(script: &str, verifier: F)
where
    F: FnOnce(&[PacketContext]),
{
    /// Monotonic counter ensuring thread-safe temporary PCAPNG filenames across parallel tests.
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let idx = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let ts_ns = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let temp_pcap = std::env::temp_dir().join(format!(
        "e2e_l7_{}_{}_{}.pcap",
        std::process::id(),
        idx,
        ts_ns
    ));
    let temp_pcap_str = temp_pcap.to_str().unwrap();

    match frameassembly::parser::parse_program(script) {
        Ok(program) => match frameassembly::backend::generate_pcap(&program, temp_pcap_str) {
            Ok(_) => {
                let packets = read_pcapng_packets(&temp_pcap).expect("read emitted l7 pcapng");
                let _ = fs::remove_file(&temp_pcap);
                assert!(!packets.is_empty(), "Generated L7 PCAPNG must contain at least one packet");
                verifier(&packets);
            }
            Err(compile_err) => {
                let _ = fs::remove_file(&temp_pcap);
                panic!("E2E L7 compilation failure: {:?}", compile_err);
            }
        },
        Err(parse_err) => {
            let _ = fs::remove_file(&temp_pcap);
            panic!("E2E L7 parser failure: {:?}", parse_err);
        }
    }
}

/// Tier 1: Feature coverage across all 50 Layer 7 protocols.
pub mod tier1_feature_coverage {
    use super::*;

    /// Tests `SNMP1`, `SNMP2`, and `SNMP3` USM network management PDUs.
    #[test]
    pub fn test_tier1_l7_snmp() {
        let snmp_script = r#"
            HOST snmp_agent { IP 10.100.1.1 }
            HOST snmp_nms { IP 10.100.1.2 }
            FLOW snmp_multi_version(ag, mgr) {
                ag -> mgr SNMP1 TRAP COMMUNITY "public" OID "1.3.6.1.6.3.1.1.5.1"
                ag -> mgr SNMP2 GET COMMUNITY "public" OID "1.3.6.1.2.1.1.1.0"
                ag -> mgr SNMP3 TRAP USER "usr-md5-des" ENGINEID "8000000001" ENGINEBOOTS 1 ENGINETIME 100 AUTH MD5 "pass123456" PRIV DES "priv123456" OID "1.3.6.1.6.3.1.1.5.1"
            } COMPILE { snmp_multi_version(snmp_agent, snmp_nms) }"#;
        run_e2e_test(snmp_script, |snmp_pkts| assert_eq!((snmp_pkts.len(), snmp_pkts[0].ethertype(), snmp_pkts[0].raw[23]), (3, Some(0x0800), 17)));
    }

    /// Tests RFC 1035 DNS queries and responses over UDP port 53.
    #[test]
    pub fn test_tier1_l7_dns() {
        let dns_script = r#"
            HOST dns_stub { IP 10.100.2.1 }
            HOST dns_recursor { IP 8.8.8.8 }
            FLOW dns_query_reply(stub, rec) {
                stub -> rec DNS QUERY TXID 0x1234 QNAME "example.com" QTYPE A
                stub <- rec DNS RESPONSE TXID 0x1234 QNAME "example.com" QTYPE A RDATA "93.184.216.34"
            } COMPILE { dns_query_reply(dns_stub, dns_recursor) }"#;
        run_e2e_test(dns_script, |dns_pkts| assert_eq!((dns_pkts.len(), u16::from_be_bytes([dns_pkts[0].raw[36], dns_pkts[0].raw[37]])), (2, 53)));
    }

    /// Tests RFC 6762 mDNS multicast DNS query over UDP port 5353.
    #[test]
    pub fn test_tier1_l7_mdns() {
        let mdns_script = r#"
            HOST mdns_host { IP 192.168.100.10 }
            HOST mdns_grp { IP 224.0.0.251 }
            FLOW mdns_discover(mh, mg) {
                mh -> mg MDNS QUERY QNAME "printer.local" QTYPE A
            } COMPILE { mdns_discover(mdns_host, mdns_grp) }"#;
        run_e2e_test(mdns_script, |mdns_pkts| assert_eq!((mdns_pkts.len(), u16::from_be_bytes([mdns_pkts[0].raw[36], mdns_pkts[0].raw[37]])), (1, 5353)));
    }

    /// Tests RFC 2131 DHCPv4 `DISCOVER` broadcast transaction on UDP port 67.
    #[test]
    pub fn test_tier1_l7_dhcp() {
        let dhcp_script = r#"
            HOST dhcp_unconf { IP 0.0.0.0 }
            HOST dhcp_bcast { IP 255.255.255.255 }
            FLOW dhcp_dora_init(dh_c, dh_s) {
                dh_c -> dh_s DHCP DISCOVER XID 0x12345678
            } COMPILE { dhcp_dora_init(dhcp_unconf, dhcp_bcast) }"#;
        run_e2e_test(dhcp_script, |dhcp_pkts| assert_eq!((dhcp_pkts.len(), u16::from_be_bytes([dhcp_pkts[0].raw[36], dhcp_pkts[0].raw[37]])), (1, 67)));
    }

    /// Tests RFC 5905 NTPv4 network time synchronization request on UDP port 123.
    #[test]
    pub fn test_tier1_l7_ntp() {
        let ntp_script = r#"
            HOST ntp_client { IP 10.100.5.1 }
            HOST ntp_stratum1 { IP 10.100.5.2 }
            FLOW ntp_poll_flow(nc, ns) {
                nc -> ns NTP MODE 3 STRATUM 0
            } COMPILE { ntp_poll_flow(ntp_client, ntp_stratum1) }"#;
        run_e2e_test(ntp_script, |ntp_pkts| assert_eq!((ntp_pkts.len(), u16::from_be_bytes([ntp_pkts[0].raw[36], ntp_pkts[0].raw[37]])), (1, 123)));
    }

    /// Tests IEEE 1588v2 PTP precision time `SYNC` event message on UDP port 319.
    #[test]
    pub fn test_tier1_l7_ptp() {
        let ptp_script = r#"
            HOST ptp_grandmaster { IP 10.100.6.1 }
            HOST ptp_ordinary_clk { IP 10.100.6.2 }
            FLOW ptp_sync_flow(gm, oc) {
                gm -> oc PTP MSG_TYPE SYNC DOMAIN 0
            } COMPILE { ptp_sync_flow(ptp_grandmaster, ptp_ordinary_clk) }"#;
        run_e2e_test(ptp_script, |ptp_pkts| assert_eq!((ptp_pkts.len(), u16::from_be_bytes([ptp_pkts[0].raw[36], ptp_pkts[0].raw[37]])), (1, 319)));
    }

    /// Tests RFC 2865 RADIUS `ACCESS_REQUEST` authentication packet on UDP port 1812.
    #[test]
    pub fn test_tier1_l7_radius() {
        let radius_script = r#"
            HOST radius_nas { IP 10.100.7.1 }
            HOST radius_aaa { IP 10.100.7.2 }
            FLOW radius_auth_flow(nas_ep, aaa_ep) {
                nas_ep -> aaa_ep RADIUS CODE ACCESS_REQUEST ID 1 USER "alice"
            } COMPILE { radius_auth_flow(radius_nas, radius_aaa) }"#;
        run_e2e_test(radius_script, |rad_pkts| assert_eq!((rad_pkts.len(), u16::from_be_bytes([rad_pkts[0].raw[36], rad_pkts[0].raw[37]])), (1, 1812)));
    }

    /// Tests RFC 8907 TACACS+ device administration authentication on TCP port 49.
    #[test]
    pub fn test_tier1_l7_tacacs() {
        let tacacs_script = r#"
            HOST tac_router { IP 10.100.8.1 }
            HOST tac_daemon { IP 10.100.8.2 }
            FLOW tacacs_authen_flow(tr, td) {
                tr -> td TACACS TYPE AUTHEN USER "admin"
            } COMPILE { tacacs_authen_flow(tac_router, tac_daemon) }"#;
        run_e2e_test(tacacs_script, |tac_pkts| assert_eq!((tac_pkts.len(), u16::from_be_bytes([tac_pkts[0].raw[36], tac_pkts[0].raw[37]])), (1, 49)));
    }

    /// Tests RFC 5424 structured Syslog event emission on UDP port 514.
    #[test]
    pub fn test_tier1_l7_syslog() {
        let syslog_script = r#"
            HOST syslog_origin { IP 10.100.9.1 }
            HOST syslog_siem { IP 10.100.9.2 }
            FLOW syslog_emit_flow(orig, siem_srv) {
                orig -> siem_srv SYSLOG FACILITY 1 SEVERITY 6 APP "authd" MSG "Login successful"
            } COMPILE { syslog_emit_flow(syslog_origin, syslog_siem) }"#;
        run_e2e_test(syslog_script, |sys_pkts| assert_eq!((sys_pkts.len(), u16::from_be_bytes([sys_pkts[0].raw[36], sys_pkts[0].raw[37]])), (1, 514)));
    }

    /// Tests Cisco NetFlow v5 (port 2055) and RFC 7011 IPFIX (port 4739) flow telemetry.
    #[test]
    pub fn test_tier1_l7_netflow_and_ipfix() {
        let flow_tel_script = r#"
            HOST flow_exporter { IP 10.100.10.1 }
            HOST flow_collector { IP 10.100.10.2 }
            FLOW telemetry_export(exp_rtr, col_srv) {
                exp_rtr -> col_srv NETFLOW SRCIP 192.168.1.100 DSTIP 8.8.8.8 PACKETS 50 OCTETS 25000
                exp_rtr -> col_srv IPFIX SRCIP 192.168.1.100 DSTIP 1.1.1.1 PACKETS 10 OCTETS 5000
            } COMPILE { telemetry_export(flow_exporter, flow_collector) }"#;
        run_e2e_test(flow_tel_script, |ft_pkts| assert_eq!((ft_pkts.len(), u16::from_be_bytes([ft_pkts[0].raw[36], ft_pkts[0].raw[37]]), u16::from_be_bytes([ft_pkts[1].raw[36], ft_pkts[1].raw[37]])), (2, 2055, 4739)));
    }

    /// Tests sFlow v5 sampled packet counter datagram on UDP port 6343.
    #[test]
    pub fn test_tier1_l7_sflow() {
        let sflow_script = r#"
            HOST sflow_sw { IP 10.100.11.1 }
            HOST sflow_col { IP 10.100.11.2 }
            FLOW sflow_sample_flow(sf_ag, sf_cl) {
                sf_ag -> sf_cl SFLOW AGENT_IP 10.100.11.1 SEQ 1
            } COMPILE { sflow_sample_flow(sflow_sw, sflow_col) }"#;
        run_e2e_test(sflow_script, |sf_pkts| assert_eq!((sf_pkts.len(), u16::from_be_bytes([sf_pkts[0].raw[36], sf_pkts[0].raw[37]])), (1, 6343)));
    }

    /// Tests RFC 1350 TFTP read request (`RRQ`) on UDP port 69.
    #[test]
    pub fn test_tier1_l7_tftp() {
        let tftp_script = r#"
            HOST pxe_client { IP 10.100.12.1 }
            HOST tftp_boot_srv { IP 10.100.12.2 }
            FLOW tftp_rrq_flow(pxe, boot_s) {
                pxe -> boot_s TFTP RRQ FILENAME "boot.bin" MODE "octet"
            } COMPILE { tftp_rrq_flow(pxe_client, tftp_boot_srv) }"#;
        run_e2e_test(tftp_script, |tftp_pkts| assert_eq!((tftp_pkts.len(), u16::from_be_bytes([tftp_pkts[0].raw[36], tftp_pkts[0].raw[37]])), (1, 69)));
    }

    /// Tests RFC 959 FTP command and status reply exchange on TCP port 21.
    #[test]
    pub fn test_tier1_l7_ftp() {
        let ftp_script = r#"
            HOST ftp_cli { IP 10.100.13.1 }
            HOST ftp_daemon { IP 10.100.13.2 }
            FLOW ftp_login_flow(fc, fd) {
                fc -> fd FTP CMD "USER" ARG "anonymous"
                fc <- fd FTP CODE 331 REPLY "Password required"
            } COMPILE { ftp_login_flow(ftp_cli, ftp_daemon) }"#;
        run_e2e_test(ftp_script, |ftp_pkts| assert_eq!((ftp_pkts.len(), u16::from_be_bytes([ftp_pkts[0].raw[36], ftp_pkts[0].raw[37]])), (2, 21)));
    }

    /// Tests RFC 4253 SSH-2.0 version banner negotiation on TCP port 22.
    #[test]
    pub fn test_tier1_l7_ssh() {
        let ssh_script = r#"
            HOST ssh_user { IP 10.100.14.1 }
            HOST ssh_bastion { IP 10.100.14.2 }
            FLOW ssh_banner_exchange(su, sb) {
                su -> sb SSH BANNER "SSH-2.0-OpenSSH_9.0"
                su <- sb SSH BANNER "SSH-2.0-OpenSSH_8.9"
            } COMPILE { ssh_banner_exchange(ssh_user, ssh_bastion) }"#;
        run_e2e_test(ssh_script, |ssh_pkts| assert_eq!((ssh_pkts.len(), u16::from_be_bytes([ssh_pkts[0].raw[36], ssh_pkts[0].raw[37]])), (2, 22)));
    }

    /// Tests RFC 854 Telnet `IAC DO` option negotiation on TCP port 23.
    #[test]
    pub fn test_tier1_l7_telnet() {
        let telnet_script = r#"
            HOST tn_term { IP 10.100.15.1 }
            HOST tn_host { IP 10.100.15.2 }
            FLOW telnet_iac_flow(tt, th) {
                tt -> th TELNET DO 1
            } COMPILE { telnet_iac_flow(tn_term, tn_host) }"#;
        run_e2e_test(telnet_script, |tn_pkts| assert_eq!((tn_pkts.len(), u16::from_be_bytes([tn_pkts[0].raw[36], tn_pkts[0].raw[37]])), (1, 23)));
    }

    /// Tests RFC 9110 HTTP/1.1 `GET` request and `200 OK` JSON response on TCP port 80.
    #[test]
    pub fn test_tier1_l7_http() {
        let http_script = r#"
            HOST web_browser { IP 10.100.16.1 }
            HOST web_origin { IP 10.100.16.2 }
            FLOW http_rest_call(wb, wo) {
                wb -> wo HTTP GET URI "/api/v1/status" HOST_HDR "example.local"
                wb <- wo HTTP STATUS 200 REASON "OK" BODY "{\"status\":\"healthy\"}"
            } COMPILE { http_rest_call(web_browser, web_origin) }"#;
        run_e2e_test(http_script, |http_pkts| assert_eq!((http_pkts.len(), u16::from_be_bytes([http_pkts[0].raw[36], http_pkts[0].raw[37]])), (2, 80)));
    }

    /// Tests RFC 9113 HTTP/2 `SETTINGS` frame (port 443) and gRPC service invocation (port 50051).
    #[test]
    pub fn test_tier1_l7_http2_and_grpc() {
        let h2_grpc_script = r#"
            HOST mesh_caller { IP 10.100.17.1 }
            HOST mesh_callee { IP 10.100.17.2 }
            FLOW h2_grpc_flow(mc1, mc2) {
                mc1 -> mc2 HTTP2 SETTINGS
                mc1 -> mc2 GRPC SERVICE "OrderService" METHOD "GetOrder"
            } COMPILE { h2_grpc_flow(mesh_caller, mesh_callee) }"#;
        run_e2e_test(h2_grpc_script, |h2_pkts| assert_eq!((h2_pkts.len(), u16::from_be_bytes([h2_pkts[0].raw[36], h2_pkts[0].raw[37]]), u16::from_be_bytes([h2_pkts[1].raw[36], h2_pkts[1].raw[37]])), (2, 443, 50051)));
    }

    /// Tests RFC 6455 WebSocket masked text frame on TCP port 80.
    #[test]
    pub fn test_tier1_l7_websocket() {
        let ws_script = r#"
            HOST ws_browser { IP 10.100.18.1 }
            HOST ws_backend { IP 10.100.18.2 }
            FLOW websocket_text_flow(wb_c, wb_s) {
                wb_c -> wb_s WEBSOCKET OPCODE TEXT PAYLOAD "ping"
            } COMPILE { websocket_text_flow(ws_browser, ws_backend) }"#;
        run_e2e_test(ws_script, |ws_pkts| assert_eq!((ws_pkts.len(), ws_pkts[0].ethertype(), ws_pkts[0].raw[23]), (1, Some(0x0800), 6)));
    }

    /// Tests RFC 8446 TLS 1.3 `CLIENT_HELLO` (with SNI) and `SERVER_HELLO` handshake records.
    #[test]
    pub fn test_tier1_l7_tls() {
        let tls_script = r#"
            HOST tls_cli { IP 10.100.19.1 }
            HOST tls_edge { IP 10.100.19.2 }
            FLOW tls_handshake_pair(tc, te) {
                tc -> te TLS CLIENT_HELLO SNI "secure.example.com"
                tc <- te TLS SERVER_HELLO
            } COMPILE { tls_handshake_pair(tls_cli, tls_edge) }"#;
        run_e2e_test(tls_script, |tls_pkts| assert_eq!((tls_pkts.len(), u16::from_be_bytes([tls_pkts[0].raw[36], tls_pkts[0].raw[37]])), (2, 443)));
    }

    /// Tests RFC 9000 QUIC long-header `INITIAL` packet on UDP port 443.
    #[test]
    pub fn test_tier1_l7_quic() {
        let quic_script = r#"
            HOST quic_peer_c { IP 10.100.20.1 }
            HOST quic_peer_s { IP 10.100.20.2 }
            FLOW quic_init_flow(qc, qs) {
                qc -> qs QUIC INITIAL DCID 0x01020304 SCID 0x05060708
            } COMPILE { quic_init_flow(quic_peer_c, quic_peer_s) }"#;
        run_e2e_test(quic_script, |quic_pkts| assert_eq!((quic_pkts.len(), quic_pkts[0].raw[23], u16::from_be_bytes([quic_pkts[0].raw[36], quic_pkts[0].raw[37]])), (1, 17, 443)));
    }

    /// Tests RFC 8489 STUN `BINDING_REQUEST` with magic cookie `0x2112A442` on UDP port 3478.
    #[test]
    pub fn test_tier1_l7_stun() {
        let stun_script = r#"
            HOST webrtc_peer { IP 192.168.101.10 }
            HOST stun_turn_srv { IP 34.200.1.1 }
            FLOW stun_bind_flow(wp, st_s) {
                wp -> st_s STUN BINDING_REQUEST TXID 0x11223344
            } COMPILE { stun_bind_flow(webrtc_peer, stun_turn_srv) }"#;
        run_e2e_test(stun_script, |stun_pkts| assert_eq!((stun_pkts.len(), u16::from_be_bytes([stun_pkts[0].raw[36], stun_pkts[0].raw[37]])), (1, 3478)));
    }

    /// Tests RFC 3261 SIP `INVITE` VoIP call signaling on UDP port 5060.
    #[test]
    pub fn test_tier1_l7_sip() {
        let sip_script = r#"
            HOST sip_uac { IP 10.100.22.1 }
            HOST sip_uas { IP 10.100.22.2 }
            FLOW sip_invite_flow(uac, uas) {
                uac -> uas SIP INVITE FROM "sip:alice@pbx" TO "sip:bob@pbx" CALL_ID "call123"
            } COMPILE { sip_invite_flow(sip_uac, sip_uas) }"#;
        run_e2e_test(sip_script, |sip_pkts| assert_eq!((sip_pkts.len(), u16::from_be_bytes([sip_pkts[0].raw[36], sip_pkts[0].raw[37]])), (1, 5060)));
    }

    /// Tests RFC 3550 RTP real-time media packet on UDP port 5004.
    #[test]
    pub fn test_tier1_l7_rtp() {
        let rtp_script = r#"
            HOST rtp_ep_1 { IP 10.100.23.1 }
            HOST rtp_ep_2 { IP 10.100.23.2 }
            FLOW rtp_media_flow(re1, re2) {
                re1 -> re2 RTP PT 0 SEQ 100 SSRC 0x12345678
            } COMPILE { rtp_media_flow(rtp_ep_1, rtp_ep_2) }"#;
        run_e2e_test(rtp_script, |rtp_pkts| assert_eq!((rtp_pkts.len(), u16::from_be_bytes([rtp_pkts[0].raw[36], rtp_pkts[0].raw[37]])), (1, 5004)));
    }

    /// Tests RFC 7826 RTSP media streaming `OPTIONS` request on TCP port 554.
    #[test]
    pub fn test_tier1_l7_rtsp() {
        let rtsp_script = r#"
            HOST nvr_viewer { IP 10.100.24.1 }
            HOST ip_camera { IP 10.100.24.2 }
            FLOW rtsp_options_flow(viewer, cam) {
                viewer -> cam RTSP OPTIONS URI "rtsp://cam/live" CSEQ 1
            } COMPILE { rtsp_options_flow(nvr_viewer, ip_camera) }"#;
        run_e2e_test(rtsp_script, |rtsp_pkts| assert_eq!((rtsp_pkts.len(), u16::from_be_bytes([rtsp_pkts[0].raw[36], rtsp_pkts[0].raw[37]])), (1, 554)));
    }

    /// Tests RFC 5321 SMTP `EHLO` greeting and `250` reply on TCP port 25.
    #[test]
    pub fn test_tier1_l7_smtp() {
        let smtp_script = r#"
            HOST smtp_mta_in { IP 10.100.25.1 }
            HOST smtp_mta_out { IP 10.100.25.2 }
            FLOW smtp_ehlo_flow(mta_a, mta_b) {
                mta_a -> mta_b SMTP EHLO "mail.source.org"
                mta_a <- mta_b SMTP CODE 250 REPLY "250-mail.dest.org"
            } COMPILE { smtp_ehlo_flow(smtp_mta_in, smtp_mta_out) }"#;
        run_e2e_test(smtp_script, |smtp_pkts| assert_eq!((smtp_pkts.len(), u16::from_be_bytes([smtp_pkts[0].raw[36], smtp_pkts[0].raw[37]])), (2, 25)));
    }

    /// Tests RFC 9051 `IMAP` (port 143) and RFC 1939 `POP3` (port 110) mailbox access.
    #[test]
    pub fn test_tier1_l7_imap_and_pop3() {
        let mail_script = r#"
            HOST mua_client { IP 10.100.26.1 }
            HOST mbox_srv { IP 10.100.26.2 }
            FLOW mail_retrieve_flow(mua, mbox) {
                mua -> mbox IMAP TAG "A01" CMD "LOGIN" ARG "user pass"
                mua -> mbox POP3 CMD "USER" ARG "bob"
            } COMPILE { mail_retrieve_flow(mua_client, mbox_srv) }"#;
        run_e2e_test(mail_script, |mail_pkts| assert_eq!((mail_pkts.len(), u16::from_be_bytes([mail_pkts[0].raw[36], mail_pkts[0].raw[37]]), u16::from_be_bytes([mail_pkts[1].raw[36], mail_pkts[1].raw[37]])), (2, 143, 110)));
    }

    /// Tests RFC 4120 `KERBEROS` (port 88) and RFC 4511 `LDAP` (port 389) directory services.
    #[test]
    pub fn test_tier1_l7_kerberos_and_ldap() {
        let auth_dir_script = r#"
            HOST ad_workstation { IP 10.100.27.1 }
            HOST ad_domain_ctrl { IP 10.100.27.2 }
            FLOW krb_ldap_flow(wks, dc_srv) {
                wks -> dc_srv KERBEROS AS_REQ REALM "CORP.LOCAL"
                wks -> dc_srv LDAP BIND_REQ MSGID 1 BASE_DN "dc=corp,dc=local"
            } COMPILE { krb_ldap_flow(ad_workstation, ad_domain_ctrl) }"#;
        run_e2e_test(auth_dir_script, |ad_pkts| assert_eq!((ad_pkts.len(), u16::from_be_bytes([ad_pkts[0].raw[36], ad_pkts[0].raw[37]]), u16::from_be_bytes([ad_pkts[1].raw[36], ad_pkts[1].raw[37]])), (2, 88, 389)));
    }

    /// Tests SMB2/3 (`SMB` port 445) and ONC-RPC `NFS` v4 (port 2049) network file storage.
    #[test]
    pub fn test_tier1_l7_smb_and_nfs() {
        let storage_script = r#"
            HOST storage_mnt { IP 10.100.28.1 }
            HOST storage_filer { IP 10.100.28.2 }
            FLOW smb_nfs_flow(mnt_c, filer_s) {
                mnt_c -> filer_s SMB COMMAND NEGOTIATE
                mnt_c -> filer_s NFS PROC LOOKUP PATH "/exports/data"
            } COMPILE { smb_nfs_flow(storage_mnt, storage_filer) }"#;
        run_e2e_test(storage_script, |st_pkts| assert_eq!((st_pkts.len(), u16::from_be_bytes([st_pkts[0].raw[36], st_pkts[0].raw[37]]), u16::from_be_bytes([st_pkts[1].raw[36], st_pkts[1].raw[37]])), (2, 445, 2049)));
    }

    /// Tests `REDIS` RESP (port 6379) and `MEMCACHED` (port 11211) in-memory cache protocols.
    #[test]
    pub fn test_tier1_l7_redis_and_memcached() {
        let cache_script = r#"
            HOST cache_worker { IP 10.100.29.1 }
            HOST cache_cluster { IP 10.100.29.2 }
            FLOW redis_mc_flow(cw, cc) {
                cw -> cc REDIS CMD "PING"
                cw -> cc MEMCACHED GET KEY "session:123"
            } COMPILE { redis_mc_flow(cache_worker, cache_cluster) }"#;
        run_e2e_test(cache_script, |cache_pkts| assert_eq!((cache_pkts.len(), u16::from_be_bytes([cache_pkts[0].raw[36], cache_pkts[0].raw[37]]), u16::from_be_bytes([cache_pkts[1].raw[36], cache_pkts[1].raw[37]])), (2, 6379, 11211)));
    }

    /// Tests `MYSQL` (port 3306) and `POSTGRES` (port 5432) relational database wire queries.
    #[test]
    pub fn test_tier1_l7_mysql_and_postgres() {
        let sql_script = r#"
            HOST orm_backend { IP 10.100.30.1 }
            HOST sql_primary { IP 10.100.30.2 }
            FLOW sql_queries_flow(orm, rdbms) {
                orm -> rdbms MYSQL QUERY SQL "SELECT 1"
                orm -> rdbms POSTGRES QUERY SQL "SELECT version()"
            } COMPILE { sql_queries_flow(orm_backend, sql_primary) }"#;
        run_e2e_test(sql_script, |sql_pkts| assert_eq!((sql_pkts.len(), u16::from_be_bytes([sql_pkts[0].raw[36], sql_pkts[0].raw[37]]), u16::from_be_bytes([sql_pkts[1].raw[36], sql_pkts[1].raw[37]])), (2, 3306, 5432)));
    }

    /// Tests OASIS `MQTT` (TCP port 1883) and RFC 7252 `COAP` (UDP port 5683) IoT messaging.
    #[test]
    pub fn test_tier1_l7_mqtt_and_coap() {
        let iot_script = r#"
            HOST iot_edge_node { IP 10.100.31.1 }
            HOST iot_gateway { IP 10.100.31.2 }
            FLOW mqtt_coap_flow(edge_n, gw_n) {
                edge_n -> gw_n MQTT CONNECT CLIENT_ID "sensor-01"
                edge_n -> gw_n COAP CON GET URI_PATH "/telemetry"
            } COMPILE { mqtt_coap_flow(iot_edge_node, iot_gateway) }"#;
        run_e2e_test(iot_script, |iot_pkts| assert_eq!((iot_pkts.len(), u16::from_be_bytes([iot_pkts[0].raw[36], iot_pkts[0].raw[37]]), u16::from_be_bytes([iot_pkts[1].raw[36], iot_pkts[1].raw[37]])), (2, 1883, 5683)));
    }

    /// Tests `AMQP` 0-9-1 (port 5672), UPnP `SSDP` (port 1900), and RFC 3912 `WHOIS` (port 43).
    #[test]
    pub fn test_tier1_l7_amqp_ssdp_whois() {
        let misc_app_script = r#"
            HOST app_requester { IP 10.100.32.1 }
            HOST app_responder { IP 10.100.32.2 }
            FLOW amqp_ssdp_whois_flow(req_h, rsp_h) {
                req_h -> rsp_h AMQP PROTOCOL_HEADER
                req_h -> rsp_h SSDP MSEARCH ST "upnp:rootdevice"
                req_h -> rsp_h WHOIS QUERY DOMAIN "example.com"
            } COMPILE { amqp_ssdp_whois_flow(app_requester, app_responder) }"#;
        run_e2e_test(misc_app_script, |misc_pkts| assert_eq!((misc_pkts.len(), u16::from_be_bytes([misc_pkts[0].raw[36], misc_pkts[0].raw[37]]), u16::from_be_bytes([misc_pkts[2].raw[36], misc_pkts[2].raw[37]])), (3, 5672, 43)));
    }

    /// Tests industrial OT protocols: `MODBUS` TCP (port 502) and `BACNET`/IP (UDP port 47808).
    #[test]
    pub fn test_tier1_l7_industrial_modbus_and_bacnet() {
        let ot_mb_script = r#"
            HOST bms_scada { IP 192.168.110.10 }
            HOST hvac_plc { IP 192.168.110.20 }
            FLOW modbus_bacnet_flow(scada_m, plc_s) {
                scada_m -> plc_s MODBUS FUNC READ_HOLDING_REGISTERS ADDR 100 COUNT 5
                scada_m -> plc_s BACNET WHO_IS
            } COMPILE { modbus_bacnet_flow(bms_scada, hvac_plc) }"#;
        run_e2e_test(ot_mb_script, |mb_pkts| assert_eq!((mb_pkts.len(), u16::from_be_bytes([mb_pkts[0].raw[36], mb_pkts[0].raw[37]]), u16::from_be_bytes([mb_pkts[1].raw[36], mb_pkts[1].raw[37]])), (2, 502, 47808)));
    }

    /// Tests industrial OT protocols: IEEE 1815 `DNP3`, Siemens `S7COMM`, `ETHERNETIP`, `OPCUA`.
    #[test]
    pub fn test_tier1_l7_industrial_dnp3_s7_enip_opcua() {
        let ot_ics_script = r#"
            HOST ics_hist { IP 192.168.111.10 }
            HOST ics_rtu { IP 192.168.111.20 }
            FLOW ics_quad_flow(hist_c, rtu_s) {
                hist_c -> rtu_s DNP3 FUNC READ
                hist_c -> rtu_s S7COMM FUNC READ_VAR
                hist_c -> rtu_s ETHERNETIP CMD LIST_IDENTITY
                hist_c -> rtu_s OPCUA MSG_TYPE HEL
            } COMPILE { ics_quad_flow(ics_hist, ics_rtu) }"#;
        run_e2e_test(ot_ics_script, |ics_pkts| assert_eq!((ics_pkts.len(), u16::from_be_bytes([ics_pkts[0].raw[36], ics_pkts[0].raw[37]]), u16::from_be_bytes([ics_pkts[3].raw[36], ics_pkts[3].raw[37]])), (4, 20000, 4840)));
    }
}

/// Tier 4: Real-world multi-step network application workflows.
pub mod tier4_real_world_application_flows {
    use super::*;

    /// Tests complete BGP4+ peering flow over IPv6 with TCP 3-way handshake and keepalives.
    #[test]
    pub fn test_tier4_bgp_peering_session() {
        let bgp6_script = r#"
            HOST core_r1 { IP 2001:db8:400::1 }
            HOST core_r2 { IP 2001:db8:400::2 }
            FLOW bgp_session(peer_1, peer_2) {
                peer_1 -> peer_2 TCP SYN SRCPORT 179 DSTPORT 179
                peer_1 <- peer_2 TCP SYN ACK
                peer_1 -> peer_2 TCP ACK
                peer_1 -> peer_2 BGP OPEN ASN 65000 HOLDTIME 90 BGPID 1.1.1.1
                peer_1 <- peer_2 BGP OPEN ASN 65001 HOLDTIME 90 BGPID 2.2.2.2
                peer_1 -> peer_2 BGP KEEPALIVE
                peer_1 <- peer_2 BGP KEEPALIVE
            } COMPILE { bgp_session(core_r1, core_r2) }"#;
        run_e2e_test(bgp6_script, |bgp6_pkts| assert_eq!((bgp6_pkts.len(), bgp6_pkts[0].ethertype()), (7, Some(0x86DD))));
    }

    /// Tests REST API transaction preceded by TLS handshake records.
    #[test]
    pub fn test_tier4_rest_api_over_tls() {
        let https_script = r#"
            HOST mobile_app { IP 10.210.1.1 }
            HOST api_gateway { IP 10.210.1.2 }
            FLOW https_flow(app_c, gw_s) {
                app_c -> gw_s TLS CLIENT_HELLO SNI "api.service.local"
                app_c <- gw_s TLS SERVER_HELLO
                app_c -> gw_s HTTP GET URI "/v2/users" HOST_HDR "api.service.local"
                app_c <- gw_s HTTP STATUS 200 REASON "OK" BODY "[]"
            } COMPILE { https_flow(mobile_app, api_gateway) }"#;
        run_e2e_test(https_script, |https_pkts| assert_eq!((https_pkts.len(), https_pkts[0].ethertype()), (4, Some(0x0800))));
    }

    /// Tests recursive DNS resolution workflow (`CNAME` alias followed by final `A` record).
    #[test]
    pub fn test_tier4_recursive_dns_resolution() {
        let rec_dns_script = r#"
            HOST corp_resolver { IP 192.168.210.1 }
            HOST auth_nameserver { IP 198.51.100.53 }
            FLOW dns_lookup(res_node, ns_node) {
                res_node -> ns_node DNS QUERY TXID 0x1001 QNAME "service.corp.internal" QTYPE A
                res_node <- ns_node DNS RESPONSE TXID 0x1001 QNAME "service.corp.internal" QTYPE CNAME RDATA "edge-lb.corp.internal"
                res_node -> ns_node DNS QUERY TXID 0x1002 QNAME "edge-lb.corp.internal" QTYPE A
                res_node <- ns_node DNS RESPONSE TXID 0x1002 QNAME "edge-lb.corp.internal" QTYPE A RDATA "10.50.0.1"
            } COMPILE { dns_lookup(corp_resolver, auth_nameserver) }"#;
        run_e2e_test(rec_dns_script, |rdns_pkts| assert_eq!((rdns_pkts.len(), rdns_pkts[0].ethertype(), rdns_pkts[0].raw[23]), (4, Some(0x0800), 17)));
    }

    /// Tests IoT MQTT sensor telemetry stream negotiated over TLS.
    #[test]
    pub fn test_tier4_iot_mqtt_over_tls() {
        let mqtts_script = r#"
            HOST temp_sensor { IP 10.210.2.5 }
            HOST mqtt_broker { IP 10.210.2.1 }
            FLOW mqtt_flow(dev_ep, brk_ep) {
                dev_ep -> brk_ep TLS CLIENT_HELLO SNI "iot.hub"
                dev_ep <- brk_ep TLS SERVER_HELLO
                dev_ep -> brk_ep MQTT CONNECT CLIENT_ID "device-temperature-sensor"
                dev_ep <- brk_ep MQTT CONNACK RETURN_CODE 0
                dev_ep -> brk_ep MQTT PUBLISH TOPIC "sensors/temp" PAYLOAD "22.5C"
            } COMPILE { mqtt_flow(temp_sensor, mqtt_broker) }"#;
        run_e2e_test(mqtts_script, |mqtts_pkts| assert_eq!((mqtts_pkts.len(), mqtts_pkts[0].ethertype()), (5, Some(0x0800))));
    }

    /// Tests VoIP session: SIP `INVITE` + `200 OK` + `ACK` followed by bidirectional RTP audio.
    #[test]
    pub fn test_tier4_voip_sip_and_rtp_call_session() {
        let voip_script = r#"
            HOST desk_phone1 { IP 192.168.211.10 }
            HOST desk_phone2 { IP 192.168.211.20 }
            FLOW voip_call(ph_a, ph_b) {
                ph_a -> ph_b SIP INVITE FROM "sip:1001@pbx" TO "sip:1002@pbx" CALL_ID "c1"
                ph_a <- ph_b SIP STATUS 200 REASON "OK" CALL_ID "c1"
                ph_a -> ph_b SIP ACK CALL_ID "c1"
                ph_a -> ph_b RTP PT 0 SEQ 1 SSRC 0x11111111
                ph_a <- ph_b RTP PT 0 SEQ 1 SSRC 0x22222222
            } COMPILE { voip_call(desk_phone1, desk_phone2) }"#;
        run_e2e_test(voip_script, |voip_pkts| assert_eq!((voip_pkts.len(), voip_pkts[0].raw[23], voip_pkts[3].raw[23]), (5, 17, 17)));
    }

    /// Tests enterprise NMS monitoring: encrypted SNMPv3 trap followed by RFC 5424 Syslog alert.
    #[test]
    pub fn test_tier4_enterprise_nms_telemetry() {
        let nms_script = r#"
            HOST dist_switch { IP 10.200.1.1 }
            HOST soc_siem { IP 10.200.1.2 }
            FLOW nms_alert(sw_node, siem_node) {
                sw_node -> siem_node SNMP3 TRAP USER "sec-admin" ENGINEID "8000000001" ENGINEBOOTS 5 ENGINETIME 500 AUTH SHA "authpwd12345" PRIV AES "privpwd12345" OID "1.3.6.1.6.3.1.1.5.3"
                sw_node -> siem_node SYSLOG FACILITY 1 SEVERITY 2 APP "linkmon" MSG "Interface GigabitEthernet0/1 changed state to down"
            } COMPILE { nms_alert(dist_switch, soc_siem) }"#;
        run_e2e_test(nms_script, |nms_pkts| assert_eq!((nms_pkts.len(), u16::from_be_bytes([nms_pkts[0].raw[36], nms_pkts[0].raw[37]]), u16::from_be_bytes([nms_pkts[1].raw[36], nms_pkts[1].raw[37]])), (2, 162, 514)));
    }

    /// Tests industrial SCADA substation flow: Modbus holding register poll + DNP3 direct operate.
    #[test]
    pub fn test_tier4_industrial_scada_substation() {
        let scada_script = r#"
            HOST sub_hmi { IP 192.168.100.10 }
            HOST breaker_rtu { IP 192.168.100.50 }
            FLOW substation_flow(hmi_ctrl, rtu_dev) {
                hmi_ctrl -> rtu_dev MODBUS FUNC READ_HOLDING_REGISTERS ADDR 2000 COUNT 4
                hmi_ctrl -> rtu_dev DNP3 FUNC DIRECT_OPERATE GROUP 12 VARIATION 1
            } COMPILE { substation_flow(sub_hmi, breaker_rtu) }"#;
        run_e2e_test(scada_script, |scada_pkts| assert_eq!((scada_pkts.len(), u16::from_be_bytes([scada_pkts[0].raw[36], scada_pkts[0].raw[37]]), u16::from_be_bytes([scada_pkts[1].raw[36], scada_pkts[1].raw[37]])), (2, 502, 20000)));
    }
}
