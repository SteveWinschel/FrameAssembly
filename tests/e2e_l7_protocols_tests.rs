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

/// Compiles a `.frasm` script to a temporary PCAPNG file and runs the verification closure.
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
            host snmp_agent { ip 10.100.1.1 }
            host snmp_nms { ip 10.100.1.2 }
            flow snmp_multi_version(ag, mgr) {
                ag -> mgr snmp1 trap community "public" oid "1.3.6.1.6.3.1.1.5.1"
                ag -> mgr snmp2 get community "public" oid "1.3.6.1.2.1.1.1.0"
                ag -> mgr snmp3 trap user "usr-md5-des" engineid "8000000001" engineboots 1 enginetime 100 auth md5 "pass123456" priv des "priv123456" oid "1.3.6.1.6.3.1.1.5.1"
            } compile { snmp_multi_version(snmp_agent, snmp_nms) }"#;
        run_e2e_test(snmp_script, |snmp_pkts| assert_eq!((snmp_pkts.len(), snmp_pkts[0].ethertype(), snmp_pkts[0].raw[23]), (3, Some(0x0800), 17)));
    }

    /// Tests RFC 1035 DNS queries and responses over UDP port 53.
    #[test]
    pub fn test_tier1_l7_dns() {
        let dns_script = r#"
            host dns_stub { ip 10.100.2.1 }
            host dns_recursor { ip 8.8.8.8 }
            flow dns_query_reply(stub, rec) {
                stub -> rec dns query txid 0x1234 qname "example.com" qtype a
                stub <- rec dns response txid 0x1234 qname "example.com" qtype a rdata "93.184.216.34"
            } compile { dns_query_reply(dns_stub, dns_recursor) }"#;
        run_e2e_test(dns_script, |dns_pkts| assert_eq!((dns_pkts.len(), u16::from_be_bytes([dns_pkts[0].raw[36], dns_pkts[0].raw[37]])), (2, 53)));
    }

    /// Tests RFC 6762 mDNS multicast DNS query over UDP port 5353.
    #[test]
    pub fn test_tier1_l7_mdns() {
        let mdns_script = r#"
            host mdns_host { ip 192.168.100.10 }
            host mdns_grp { ip 224.0.0.251 }
            flow mdns_discover(mh, mg) {
                mh -> mg mdns query qname "printer.local" qtype a
            } compile { mdns_discover(mdns_host, mdns_grp) }"#;
        run_e2e_test(mdns_script, |mdns_pkts| assert_eq!((mdns_pkts.len(), u16::from_be_bytes([mdns_pkts[0].raw[36], mdns_pkts[0].raw[37]])), (1, 5353)));
    }

    /// Tests RFC 2131 DHCPv4 `DISCOVER` broadcast transaction on UDP port 67.
    #[test]
    pub fn test_tier1_l7_dhcp() {
        let dhcp_script = r#"
            host dhcp_unconf { ip 0.0.0.0 }
            host dhcp_bcast { ip 255.255.255.255 }
            flow dhcp_dora_init(dh_c, dh_s) {
                dh_c -> dh_s dhcp discover xid 0x12345678
            } compile { dhcp_dora_init(dhcp_unconf, dhcp_bcast) }"#;
        run_e2e_test(dhcp_script, |dhcp_pkts| assert_eq!((dhcp_pkts.len(), u16::from_be_bytes([dhcp_pkts[0].raw[36], dhcp_pkts[0].raw[37]])), (1, 67)));
    }

    /// Tests RFC 5905 NTPv4 network time synchronization request on UDP port 123.
    #[test]
    pub fn test_tier1_l7_ntp() {
        let ntp_script = r#"
            host ntp_client { ip 10.100.5.1 }
            host ntp_stratum1 { ip 10.100.5.2 }
            flow ntp_poll_flow(nc, ns) {
                nc -> ns ntp mode 3 stratum 0
            } compile { ntp_poll_flow(ntp_client, ntp_stratum1) }"#;
        run_e2e_test(ntp_script, |ntp_pkts| assert_eq!((ntp_pkts.len(), u16::from_be_bytes([ntp_pkts[0].raw[36], ntp_pkts[0].raw[37]])), (1, 123)));
    }

    /// Tests IEEE 1588v2 PTP precision time `SYNC` event message on UDP port 319.
    #[test]
    pub fn test_tier1_l7_ptp() {
        let ptp_script = r#"
            host ptp_grandmaster { ip 10.100.6.1 }
            host ptp_ordinary_clk { ip 10.100.6.2 }
            flow ptp_sync_flow(gm, oc) {
                gm -> oc ptp msgtype sync domain 0
            } compile { ptp_sync_flow(ptp_grandmaster, ptp_ordinary_clk) }"#;
        run_e2e_test(ptp_script, |ptp_pkts| assert_eq!((ptp_pkts.len(), u16::from_be_bytes([ptp_pkts[0].raw[36], ptp_pkts[0].raw[37]])), (1, 319)));
    }

    /// Tests RFC 2865 RADIUS `ACCESS_REQUEST` authentication packet on UDP port 1812.
    #[test]
    pub fn test_tier1_l7_radius() {
        let radius_script = r#"
            host radius_nas { ip 10.100.7.1 }
            host radius_aaa { ip 10.100.7.2 }
            flow radius_auth_flow(nas_ep, aaa_ep) {
                nas_ep -> aaa_ep radius code accessrequest id 1 user "alice"
            } compile { radius_auth_flow(radius_nas, radius_aaa) }"#;
        run_e2e_test(radius_script, |rad_pkts| assert_eq!((rad_pkts.len(), u16::from_be_bytes([rad_pkts[0].raw[36], rad_pkts[0].raw[37]])), (1, 1812)));
    }

    /// Tests RFC 8907 TACACS+ device administration authentication on TCP port 49.
    #[test]
    pub fn test_tier1_l7_tacacs() {
        let tacacs_script = r#"
            host tac_router { ip 10.100.8.1 }
            host tac_daemon { ip 10.100.8.2 }
            flow tacacs_authen_flow(tr, td) {
                tr -> td tacacs type authen user "admin"
            } compile { tacacs_authen_flow(tac_router, tac_daemon) }"#;
        run_e2e_test(tacacs_script, |tac_pkts| assert_eq!((tac_pkts.len(), u16::from_be_bytes([tac_pkts[0].raw[36], tac_pkts[0].raw[37]])), (1, 49)));
    }

    /// Tests RFC 5424 structured Syslog event emission on UDP port 514.
    #[test]
    pub fn test_tier1_l7_syslog() {
        let syslog_script = r#"
            host syslog_origin { ip 10.100.9.1 }
            host syslog_siem { ip 10.100.9.2 }
            flow syslog_emit_flow(orig, siem_srv) {
                orig -> siem_srv syslog facility 1 severity 6 app "authd" msg "Login successful"
            } compile { syslog_emit_flow(syslog_origin, syslog_siem) }"#;
        run_e2e_test(syslog_script, |sys_pkts| assert_eq!((sys_pkts.len(), u16::from_be_bytes([sys_pkts[0].raw[36], sys_pkts[0].raw[37]])), (1, 514)));
    }

    /// Tests Cisco NetFlow v5 (port 2055) and RFC 7011 IPFIX (port 4739) flow telemetry.
    #[test]
    pub fn test_tier1_l7_netflow_and_ipfix() {
        let flow_tel_script = r#"
            host flow_exporter { ip 10.100.10.1 }
            host flow_collector { ip 10.100.10.2 }
            flow telemetry_export(exp_rtr, col_srv) {
                exp_rtr -> col_srv netflow srcip 192.168.1.100 dstip 8.8.8.8 packets 50 octets 25000
                exp_rtr -> col_srv ipfix srcip 192.168.1.100 dstip 1.1.1.1 packets 10 octets 5000
            } compile { telemetry_export(flow_exporter, flow_collector) }"#;
        run_e2e_test(flow_tel_script, |ft_pkts| assert_eq!((ft_pkts.len(), u16::from_be_bytes([ft_pkts[0].raw[36], ft_pkts[0].raw[37]]), u16::from_be_bytes([ft_pkts[1].raw[36], ft_pkts[1].raw[37]])), (2, 2055, 4739)));
    }

    /// Tests sFlow v5 sampled packet counter datagram on UDP port 6343.
    #[test]
    pub fn test_tier1_l7_sflow() {
        let sflow_script = r#"
            host sflow_sw { ip 10.100.11.1 }
            host sflow_col { ip 10.100.11.2 }
            flow sflow_sample_flow(sf_ag, sf_cl) {
                sf_ag -> sf_cl sflow agentip 10.100.11.1 seq 1
            } compile { sflow_sample_flow(sflow_sw, sflow_col) }"#;
        run_e2e_test(sflow_script, |sf_pkts| assert_eq!((sf_pkts.len(), u16::from_be_bytes([sf_pkts[0].raw[36], sf_pkts[0].raw[37]])), (1, 6343)));
    }

    /// Tests RFC 1350 TFTP read request (`RRQ`) on UDP port 69.
    #[test]
    pub fn test_tier1_l7_tftp() {
        let tftp_script = r#"
            host pxe_client { ip 10.100.12.1 }
            host tftp_boot_srv { ip 10.100.12.2 }
            flow tftp_rrq_flow(pxe, boot_s) {
                pxe -> boot_s tftp rrq filename "boot.bin" mode "octet"
            } compile { tftp_rrq_flow(pxe_client, tftp_boot_srv) }"#;
        run_e2e_test(tftp_script, |tftp_pkts| assert_eq!((tftp_pkts.len(), u16::from_be_bytes([tftp_pkts[0].raw[36], tftp_pkts[0].raw[37]])), (1, 69)));
    }

    /// Tests RFC 959 FTP command and status reply exchange on TCP port 21.
    #[test]
    pub fn test_tier1_l7_ftp() {
        let ftp_script = r#"
            host ftp_cli { ip 10.100.13.1 }
            host ftp_daemon { ip 10.100.13.2 }
            flow ftp_login_flow(fc, fd) {
                fc -> fd ftp cmd "USER" arg "anonymous"
                fc <- fd ftp code 331 reply "Password required"
            } compile { ftp_login_flow(ftp_cli, ftp_daemon) }"#;
        run_e2e_test(ftp_script, |ftp_pkts| assert_eq!((ftp_pkts.len(), u16::from_be_bytes([ftp_pkts[0].raw[36], ftp_pkts[0].raw[37]])), (2, 21)));
    }

    /// Tests RFC 4253 SSH-2.0 version banner negotiation on TCP port 22.
    #[test]
    pub fn test_tier1_l7_ssh() {
        let ssh_script = r#"
            host ssh_user { ip 10.100.14.1 }
            host ssh_bastion { ip 10.100.14.2 }
            flow ssh_banner_exchange(su, sb) {
                su -> sb ssh banner "SSH-2.0-OpenSSH_9.0"
                su <- sb ssh banner "SSH-2.0-OpenSSH_8.9"
            } compile { ssh_banner_exchange(ssh_user, ssh_bastion) }"#;
        run_e2e_test(ssh_script, |ssh_pkts| assert_eq!((ssh_pkts.len(), u16::from_be_bytes([ssh_pkts[0].raw[36], ssh_pkts[0].raw[37]])), (2, 22)));
    }

    /// Tests RFC 854 Telnet `IAC DO` option negotiation on TCP port 23.
    #[test]
    pub fn test_tier1_l7_telnet() {
        let telnet_script = r#"
            host tn_term { ip 10.100.15.1 }
            host tn_host { ip 10.100.15.2 }
            flow telnet_iac_flow(tt, th) {
                tt -> th telnet do 1
            } compile { telnet_iac_flow(tn_term, tn_host) }"#;
        run_e2e_test(telnet_script, |tn_pkts| assert_eq!((tn_pkts.len(), u16::from_be_bytes([tn_pkts[0].raw[36], tn_pkts[0].raw[37]])), (1, 23)));
    }

    /// Tests RFC 9110 HTTP/1.1 `GET` request and `200 OK` JSON response on TCP port 80.
    #[test]
    pub fn test_tier1_l7_http() {
        let http_script = r#"
            host web_browser { ip 10.100.16.1 }
            host web_origin { ip 10.100.16.2 }
            flow http_rest_call(wb, wo) {
                wb -> wo http get uri "/api/v1/status" hosthdr "example.local"
                wb <- wo http status 200 reason "OK" body "{\"status\":\"healthy\"}"
            } compile { http_rest_call(web_browser, web_origin) }"#;
        run_e2e_test(http_script, |http_pkts| assert_eq!((http_pkts.len(), u16::from_be_bytes([http_pkts[0].raw[36], http_pkts[0].raw[37]])), (2, 80)));
    }

    /// Tests RFC 9113 HTTP/2 `SETTINGS` frame (port 443) and gRPC service invocation (port 50051).
    #[test]
    pub fn test_tier1_l7_http2_and_grpc() {
        let h2_grpc_script = r#"
            host mesh_caller { ip 10.100.17.1 }
            host mesh_callee { ip 10.100.17.2 }
            flow h2_grpc_flow(mc1, mc2) {
                mc1 -> mc2 http2 settings
                mc1 -> mc2 grpc service "OrderService" method "GetOrder"
            } compile { h2_grpc_flow(mesh_caller, mesh_callee) }"#;
        run_e2e_test(h2_grpc_script, |h2_pkts| assert_eq!((h2_pkts.len(), u16::from_be_bytes([h2_pkts[0].raw[36], h2_pkts[0].raw[37]]), u16::from_be_bytes([h2_pkts[1].raw[36], h2_pkts[1].raw[37]])), (2, 443, 50051)));
    }

    /// Tests RFC 6455 WebSocket masked text frame on TCP port 80.
    #[test]
    pub fn test_tier1_l7_websocket() {
        let ws_script = r#"
            host ws_browser { ip 10.100.18.1 }
            host ws_backend { ip 10.100.18.2 }
            flow websocket_text_flow(wb_c, wb_s) {
                wb_c -> wb_s websocket opcode text payload "ping"
            } compile { websocket_text_flow(ws_browser, ws_backend) }"#;
        run_e2e_test(ws_script, |ws_pkts| assert_eq!((ws_pkts.len(), ws_pkts[0].ethertype(), ws_pkts[0].raw[23]), (1, Some(0x0800), 6)));
    }

    /// Tests RFC 8446 TLS 1.3 `CLIENT_HELLO` (with SNI) and `SERVER_HELLO` handshake records.
    #[test]
    pub fn test_tier1_l7_tls() {
        let tls_script = r#"
            host tls_cli { ip 10.100.19.1 }
            host tls_edge { ip 10.100.19.2 }
            flow tls_handshake_pair(tc, te) {
                tc -> te tls clienthello sni "secure.example.com"
                tc <- te tls serverhello
            } compile { tls_handshake_pair(tls_cli, tls_edge) }"#;
        run_e2e_test(tls_script, |tls_pkts| assert_eq!((tls_pkts.len(), u16::from_be_bytes([tls_pkts[0].raw[36], tls_pkts[0].raw[37]])), (2, 443)));
    }

    /// Tests RFC 9000 QUIC long-header `INITIAL` packet on UDP port 443.
    #[test]
    pub fn test_tier1_l7_quic() {
        let quic_script = r#"
            host quic_peer_c { ip 10.100.20.1 }
            host quic_peer_s { ip 10.100.20.2 }
            flow quic_init_flow(qc, qs) {
                qc -> qs quic initial dcid 0x01020304 scid 0x05060708
            } compile { quic_init_flow(quic_peer_c, quic_peer_s) }"#;
        run_e2e_test(quic_script, |quic_pkts| assert_eq!((quic_pkts.len(), quic_pkts[0].raw[23], u16::from_be_bytes([quic_pkts[0].raw[36], quic_pkts[0].raw[37]])), (1, 17, 443)));
    }

    /// Tests RFC 8489 STUN `BINDING_REQUEST` with magic cookie `0x2112A442` on UDP port 3478.
    #[test]
    pub fn test_tier1_l7_stun() {
        let stun_script = r#"
            host webrtc_peer { ip 192.168.101.10 }
            host stun_turn_srv { ip 34.200.1.1 }
            flow stun_bind_flow(wp, st_s) {
                wp -> st_s stun bindingrequest txid 0x11223344
            } compile { stun_bind_flow(webrtc_peer, stun_turn_srv) }"#;
        run_e2e_test(stun_script, |stun_pkts| assert_eq!((stun_pkts.len(), u16::from_be_bytes([stun_pkts[0].raw[36], stun_pkts[0].raw[37]])), (1, 3478)));
    }

    /// Tests RFC 3261 SIP `INVITE` VoIP call signaling on UDP port 5060.
    #[test]
    pub fn test_tier1_l7_sip() {
        let sip_script = r#"
            host sip_uac { ip 10.100.22.1 }
            host sip_uas { ip 10.100.22.2 }
            flow sip_invite_flow(uac, uas) {
                uac -> uas sip invite from "sip:alice@pbx" to "sip:bob@pbx" callid "call123"
            } compile { sip_invite_flow(sip_uac, sip_uas) }"#;
        run_e2e_test(sip_script, |sip_pkts| assert_eq!((sip_pkts.len(), u16::from_be_bytes([sip_pkts[0].raw[36], sip_pkts[0].raw[37]])), (1, 5060)));
    }

    /// Tests RFC 3550 RTP real-time media packet on UDP port 5004.
    #[test]
    pub fn test_tier1_l7_rtp() {
        let rtp_script = r#"
            host rtp_ep_1 { ip 10.100.23.1 }
            host rtp_ep_2 { ip 10.100.23.2 }
            flow rtp_media_flow(re1, re2) {
                re1 -> re2 rtp pt 0 seq 100 ssrc 0x12345678
            } compile { rtp_media_flow(rtp_ep_1, rtp_ep_2) }"#;
        run_e2e_test(rtp_script, |rtp_pkts| assert_eq!((rtp_pkts.len(), u16::from_be_bytes([rtp_pkts[0].raw[36], rtp_pkts[0].raw[37]])), (1, 5004)));
    }

    /// Tests RFC 7826 RTSP media streaming `OPTIONS` request on TCP port 554.
    #[test]
    pub fn test_tier1_l7_rtsp() {
        let rtsp_script = r#"
            host nvr_viewer { ip 10.100.24.1 }
            host ip_camera { ip 10.100.24.2 }
            flow rtsp_options_flow(viewer, cam) {
                viewer -> cam rtsp options uri "rtsp://cam/live" cseq 1
            } compile { rtsp_options_flow(nvr_viewer, ip_camera) }"#;
        run_e2e_test(rtsp_script, |rtsp_pkts| assert_eq!((rtsp_pkts.len(), u16::from_be_bytes([rtsp_pkts[0].raw[36], rtsp_pkts[0].raw[37]])), (1, 554)));
    }

    /// Tests RFC 5321 SMTP `EHLO` greeting and `250` reply on TCP port 25.
    #[test]
    pub fn test_tier1_l7_smtp() {
        let smtp_script = r#"
            host smtp_mta_in { ip 10.100.25.1 }
            host smtp_mta_out { ip 10.100.25.2 }
            flow smtp_ehlo_flow(mta_a, mta_b) {
                mta_a -> mta_b smtp ehlo "mail.source.org"
                mta_a <- mta_b smtp code 250 reply "250-mail.dest.org"
            } compile { smtp_ehlo_flow(smtp_mta_in, smtp_mta_out) }"#;
        run_e2e_test(smtp_script, |smtp_pkts| assert_eq!((smtp_pkts.len(), u16::from_be_bytes([smtp_pkts[0].raw[36], smtp_pkts[0].raw[37]])), (2, 25)));
    }

    /// Tests RFC 9051 `IMAP` (port 143) and RFC 1939 `POP3` (port 110) mailbox access.
    #[test]
    pub fn test_tier1_l7_imap_and_pop3() {
        let mail_script = r#"
            host mua_client { ip 10.100.26.1 }
            host mbox_srv { ip 10.100.26.2 }
            flow mail_retrieve_flow(mua, mbox) {
                mua -> mbox imap tag "A01" cmd "LOGIN" arg "user pass"
                mua -> mbox pop3 cmd "USER" arg "bob"
            } compile { mail_retrieve_flow(mua_client, mbox_srv) }"#;
        run_e2e_test(mail_script, |mail_pkts| assert_eq!((mail_pkts.len(), u16::from_be_bytes([mail_pkts[0].raw[36], mail_pkts[0].raw[37]]), u16::from_be_bytes([mail_pkts[1].raw[36], mail_pkts[1].raw[37]])), (2, 143, 110)));
    }

    /// Tests RFC 4120 `KERBEROS` (port 88) and RFC 4511 `LDAP` (port 389) directory services.
    #[test]
    pub fn test_tier1_l7_kerberos_and_ldap() {
        let auth_dir_script = r#"
            host ad_workstation { ip 10.100.27.1 }
            host ad_domain_ctrl { ip 10.100.27.2 }
            flow krb_ldap_flow(wks, dc_srv) {
                wks -> dc_srv kerberos asreq realm "CORP.LOCAL"
                wks -> dc_srv ldap bindreq msgid 1 basedn "dc=corp,dc=local"
            } compile { krb_ldap_flow(ad_workstation, ad_domain_ctrl) }"#;
        run_e2e_test(auth_dir_script, |ad_pkts| assert_eq!((ad_pkts.len(), u16::from_be_bytes([ad_pkts[0].raw[36], ad_pkts[0].raw[37]]), u16::from_be_bytes([ad_pkts[1].raw[36], ad_pkts[1].raw[37]])), (2, 88, 389)));
    }

    /// Tests SMB2/3 (`SMB` port 445) and ONC-RPC `NFS` v4 (port 2049) network file storage.
    #[test]
    pub fn test_tier1_l7_smb_and_nfs() {
        let storage_script = r#"
            host storage_mnt { ip 10.100.28.1 }
            host storage_filer { ip 10.100.28.2 }
            flow smb_nfs_flow(mnt_c, filer_s) {
                mnt_c -> filer_s smb command negotiate
                mnt_c -> filer_s nfs proc lookup path "/exports/data"
            } compile { smb_nfs_flow(storage_mnt, storage_filer) }"#;
        run_e2e_test(storage_script, |st_pkts| assert_eq!((st_pkts.len(), u16::from_be_bytes([st_pkts[0].raw[36], st_pkts[0].raw[37]]), u16::from_be_bytes([st_pkts[1].raw[36], st_pkts[1].raw[37]])), (2, 445, 2049)));
    }

    /// Tests `REDIS` RESP (port 6379) and `MEMCACHED` (port 11211) in-memory cache protocols.
    #[test]
    pub fn test_tier1_l7_redis_and_memcached() {
        let cache_script = r#"
            host cache_worker { ip 10.100.29.1 }
            host cache_cluster { ip 10.100.29.2 }
            flow redis_mc_flow(cw, cc) {
                cw -> cc redis cmd "PING"
                cw -> cc memcached get key "session:123"
            } compile { redis_mc_flow(cache_worker, cache_cluster) }"#;
        run_e2e_test(cache_script, |cache_pkts| assert_eq!((cache_pkts.len(), u16::from_be_bytes([cache_pkts[0].raw[36], cache_pkts[0].raw[37]]), u16::from_be_bytes([cache_pkts[1].raw[36], cache_pkts[1].raw[37]])), (2, 6379, 11211)));
    }

    /// Tests `MYSQL` (port 3306) and `POSTGRES` (port 5432) relational database wire queries.
    #[test]
    pub fn test_tier1_l7_mysql_and_postgres() {
        let sql_script = r#"
            host orm_backend { ip 10.100.30.1 }
            host sql_primary { ip 10.100.30.2 }
            flow sql_queries_flow(orm, rdbms) {
                orm -> rdbms mysql query sql "SELECT 1"
                orm -> rdbms postgres query sql "SELECT version()"
            } compile { sql_queries_flow(orm_backend, sql_primary) }"#;
        run_e2e_test(sql_script, |sql_pkts| assert_eq!((sql_pkts.len(), u16::from_be_bytes([sql_pkts[0].raw[36], sql_pkts[0].raw[37]]), u16::from_be_bytes([sql_pkts[1].raw[36], sql_pkts[1].raw[37]])), (2, 3306, 5432)));
    }

    /// Tests OASIS `MQTT` (TCP port 1883) and RFC 7252 `COAP` (UDP port 5683) IoT messaging.
    #[test]
    pub fn test_tier1_l7_mqtt_and_coap() {
        let iot_script = r#"
            host iot_edge_node { ip 10.100.31.1 }
            host iot_gateway { ip 10.100.31.2 }
            flow mqtt_coap_flow(edge_n, gw_n) {
                edge_n -> gw_n mqtt connect clientid "sensor-01"
                edge_n -> gw_n coap con get uripath "/telemetry"
            } compile { mqtt_coap_flow(iot_edge_node, iot_gateway) }"#;
        run_e2e_test(iot_script, |iot_pkts| assert_eq!((iot_pkts.len(), u16::from_be_bytes([iot_pkts[0].raw[36], iot_pkts[0].raw[37]]), u16::from_be_bytes([iot_pkts[1].raw[36], iot_pkts[1].raw[37]])), (2, 1883, 5683)));
    }

    /// Tests `AMQP` 0-9-1 (port 5672), UPnP `SSDP` (port 1900), and RFC 3912 `WHOIS` (port 43).
    #[test]
    pub fn test_tier1_l7_amqp_ssdp_whois() {
        let misc_app_script = r#"
            host app_requester { ip 10.100.32.1 }
            host app_responder { ip 10.100.32.2 }
            flow amqp_ssdp_whois_flow(req_h, rsp_h) {
                req_h -> rsp_h amqp protocolheader
                req_h -> rsp_h ssdp msearch st "upnp:rootdevice"
                req_h -> rsp_h whois query domain "example.com"
            } compile { amqp_ssdp_whois_flow(app_requester, app_responder) }"#;
        run_e2e_test(misc_app_script, |misc_pkts| assert_eq!((misc_pkts.len(), u16::from_be_bytes([misc_pkts[0].raw[36], misc_pkts[0].raw[37]]), u16::from_be_bytes([misc_pkts[2].raw[36], misc_pkts[2].raw[37]])), (3, 5672, 43)));
    }

    /// Tests industrial OT protocols: `MODBUS` TCP (port 502) and `BACNET`/IP (UDP port 47808).
    #[test]
    pub fn test_tier1_l7_industrial_modbus_and_bacnet() {
        let ot_mb_script = r#"
            host bms_scada { ip 192.168.110.10 }
            host hvac_plc { ip 192.168.110.20 }
            flow modbus_bacnet_flow(scada_m, plc_s) {
                scada_m -> plc_s modbus func readholdingregisters addr 100 count 5
                scada_m -> plc_s bacnet whois
            } compile { modbus_bacnet_flow(bms_scada, hvac_plc) }"#;
        run_e2e_test(ot_mb_script, |mb_pkts| assert_eq!((mb_pkts.len(), u16::from_be_bytes([mb_pkts[0].raw[36], mb_pkts[0].raw[37]]), u16::from_be_bytes([mb_pkts[1].raw[36], mb_pkts[1].raw[37]])), (2, 502, 47808)));
    }

    /// Tests industrial OT protocols: IEEE 1815 `DNP3`, Siemens `S7COMM`, `ETHERNETIP`, `OPCUA`.
    #[test]
    pub fn test_tier1_l7_industrial_dnp3_s7_enip_opcua() {
        let ot_ics_script = r#"
            host ics_hist { ip 192.168.111.10 }
            host ics_rtu { ip 192.168.111.20 }
            flow ics_quad_flow(hist_c, rtu_s) {
                hist_c -> rtu_s dnp3 func read
                hist_c -> rtu_s s7comm func readvar
                hist_c -> rtu_s ethernetip cmd listidentity
                hist_c -> rtu_s opcua msgtype hel
            } compile { ics_quad_flow(ics_hist, ics_rtu) }"#;
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
            host core_r1 { ip 2001:db8:400::1 }
            host core_r2 { ip 2001:db8:400::2 }
            flow bgp_session(peer_1, peer_2) {
                peer_1 -> peer_2 tcp syn srcport 179 dstport 179
                peer_1 <- peer_2 tcp syn ack
                peer_1 -> peer_2 tcp ack
                peer_1 -> peer_2 bgp open asn 65000 holdtime 90 bgpid 1.1.1.1
                peer_1 <- peer_2 bgp open asn 65001 holdtime 90 bgpid 2.2.2.2
                peer_1 -> peer_2 bgp keepalive
                peer_1 <- peer_2 bgp keepalive
            } compile { bgp_session(core_r1, core_r2) }"#;
        run_e2e_test(bgp6_script, |bgp6_pkts| assert_eq!((bgp6_pkts.len(), bgp6_pkts[0].ethertype()), (7, Some(0x86DD))));
    }

    /// Tests REST API transaction preceded by TLS handshake records.
    #[test]
    pub fn test_tier4_rest_api_over_tls() {
        let https_script = r#"
            host mobile_app { ip 10.210.1.1 }
            host api_gateway { ip 10.210.1.2 }
            flow https_flow(app_c, gw_s) {
                app_c -> gw_s tls clienthello sni "api.service.local"
                app_c <- gw_s tls serverhello
                app_c -> gw_s http get uri "/v2/users" hosthdr "api.service.local"
                app_c <- gw_s http status 200 reason "OK" body "[]"
            } compile { https_flow(mobile_app, api_gateway) }"#;
        run_e2e_test(https_script, |https_pkts| assert_eq!((https_pkts.len(), https_pkts[0].ethertype()), (4, Some(0x0800))));
    }

    /// Tests recursive DNS resolution workflow (`CNAME` alias followed by final `A` record).
    #[test]
    pub fn test_tier4_recursive_dns_resolution() {
        let rec_dns_script = r#"
            host corp_resolver { ip 192.168.210.1 }
            host auth_nameserver { ip 198.51.100.53 }
            flow dns_lookup(res_node, ns_node) {
                res_node -> ns_node dns query txid 0x1001 qname "service.corp.internal" qtype a
                res_node <- ns_node dns response txid 0x1001 qname "service.corp.internal" qtype cname rdata "edge-lb.corp.internal"
                res_node -> ns_node dns query txid 0x1002 qname "edge-lb.corp.internal" qtype a
                res_node <- ns_node dns response txid 0x1002 qname "edge-lb.corp.internal" qtype a rdata "10.50.0.1"
            } compile { dns_lookup(corp_resolver, auth_nameserver) }"#;
        run_e2e_test(rec_dns_script, |rdns_pkts| assert_eq!((rdns_pkts.len(), rdns_pkts[0].ethertype(), rdns_pkts[0].raw[23]), (4, Some(0x0800), 17)));
    }

    /// Tests IoT MQTT sensor telemetry stream negotiated over TLS.
    #[test]
    pub fn test_tier4_iot_mqtt_over_tls() {
        let mqtts_script = r#"
            host temp_sensor { ip 10.210.2.5 }
            host mqtt_broker { ip 10.210.2.1 }
            flow mqtt_flow(dev_ep, brk_ep) {
                dev_ep -> brk_ep tls clienthello sni "iot.hub"
                dev_ep <- brk_ep tls serverhello
                dev_ep -> brk_ep mqtt connect clientid "device-temperature-sensor"
                dev_ep <- brk_ep mqtt connack returncode 0
                dev_ep -> brk_ep mqtt publish topic "sensors/temp" payload "22.5C"
            } compile { mqtt_flow(temp_sensor, mqtt_broker) }"#;
        run_e2e_test(mqtts_script, |mqtts_pkts| assert_eq!((mqtts_pkts.len(), mqtts_pkts[0].ethertype()), (5, Some(0x0800))));
    }

    /// Tests VoIP session: SIP `INVITE` + `200 OK` + `ACK` followed by bidirectional RTP audio.
    #[test]
    pub fn test_tier4_voip_sip_and_rtp_call_session() {
        let voip_script = r#"
            host desk_phone1 { ip 192.168.211.10 }
            host desk_phone2 { ip 192.168.211.20 }
            flow voip_call(ph_a, ph_b) {
                ph_a -> ph_b sip invite from "sip:1001@pbx" to "sip:1002@pbx" callid "c1"
                ph_a <- ph_b sip status 200 reason "OK" callid "c1"
                ph_a -> ph_b sip ack callid "c1"
                ph_a -> ph_b rtp pt 0 seq 1 ssrc 0x11111111
                ph_a <- ph_b rtp pt 0 seq 1 ssrc 0x22222222
            } compile { voip_call(desk_phone1, desk_phone2) }"#;
        run_e2e_test(voip_script, |voip_pkts| assert_eq!((voip_pkts.len(), voip_pkts[0].raw[23], voip_pkts[3].raw[23]), (5, 17, 17)));
    }

    /// Tests enterprise NMS monitoring: encrypted SNMPv3 trap followed by RFC 5424 Syslog alert.
    #[test]
    pub fn test_tier4_enterprise_nms_telemetry() {
        let nms_script = r#"
            host dist_switch { ip 10.200.1.1 }
            host soc_siem { ip 10.200.1.2 }
            flow nms_alert(sw_node, siem_node) {
                sw_node -> siem_node snmp3 trap user "sec-admin" engineid "8000000001" engineboots 5 enginetime 500 auth sha "authpwd12345" priv aes "privpwd12345" oid "1.3.6.1.6.3.1.1.5.3"
                sw_node -> siem_node syslog facility 1 severity 2 app "linkmon" msg "Interface GigabitEthernet0/1 changed state to down"
            } compile { nms_alert(dist_switch, soc_siem) }"#;
        run_e2e_test(nms_script, |nms_pkts| assert_eq!((nms_pkts.len(), u16::from_be_bytes([nms_pkts[0].raw[36], nms_pkts[0].raw[37]]), u16::from_be_bytes([nms_pkts[1].raw[36], nms_pkts[1].raw[37]])), (2, 162, 514)));
    }

    /// Tests industrial SCADA substation flow: Modbus holding register poll + DNP3 direct operate.
    #[test]
    pub fn test_tier4_industrial_scada_substation() {
        let scada_script = r#"
            host sub_hmi { ip 192.168.100.10 }
            host breaker_rtu { ip 192.168.100.50 }
            flow substation_flow(hmi_ctrl, rtu_dev) {
                hmi_ctrl -> rtu_dev modbus func readholdingregisters addr 2000 count 4
                hmi_ctrl -> rtu_dev dnp3 func directoperate group 12 variation 1
            } compile { substation_flow(sub_hmi, breaker_rtu) }"#;
        run_e2e_test(scada_script, |scada_pkts| assert_eq!((scada_pkts.len(), u16::from_be_bytes([scada_pkts[0].raw[36], scada_pkts[0].raw[37]]), u16::from_be_bytes([scada_pkts[1].raw[36], scada_pkts[1].raw[37]])), (2, 502, 20000)));
    }
}
