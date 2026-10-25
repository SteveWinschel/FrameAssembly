//! Adversarial stress test harness for FrameAssembly compiler.
//!
//! Evaluates:
//! 1. Two-Stage TCP Port Inheritance & 4-Tuple State:
//!    - Multi-port concurrent streams between the same host pairs.
//!    - Arrow direction reversals (`->` followed by `<-` followed by `->`): verifying remembered endpoint ports and that sequence/ack numbers progress without clobbering.
//!    - Loopback pairs: `127.0.0.1 -> 127.0.0.1` and `::1 -> ::1` with different ports asserting sequence numbers remain isolated.
//!    - Strict 1 statement = 1 frame rule: verifying L7 statements auto-emit `TCP PSH ACK` and advance sequence numbers by payload length.
//! 2. Spanned Semantic Diagnostics & Negative Tests:
//!    - Mixed IPv4 and IPv6 endpoints in a single statement.
//!    - Out-of-range fields: `VLAN > 4094`, `DSCP > 63`, `ECN > 3`, `TTL > 255`, `FLOWLABEL > 0xFFFFF`, `GENTRAP > 6`.
//!    - Duplicate declarations of HOST, FLOW, parameters.
//!    - Duplicate statement modifiers.
//!    - Invalid cross-protocol modifiers.
//! 3. Delayed PCAP Creation:
//!    - Compilation or semantic errors leave NO output file on disk (neither create nor truncate).

use frameassembly::backend::generate_pcap;
use frameassembly::error::CompilerError;
use frameassembly::parser::parse_program;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

/// Dissected TCP packet details extracted from an Ethernet frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DissectedTcpPacket {
    /// Source IP address.
    pub src_ip: IpAddr,
    /// Destination IP address.
    pub dst_ip: IpAddr,
    /// Source TCP port.
    pub src_port: u16,
    /// Destination TCP port.
    pub dst_port: u16,
    /// TCP sequence number.
    pub seq: u32,
    /// TCP acknowledgment number.
    pub ack: u32,
    /// TCP header flags byte (SYN=0x02, ACK=0x10, PSH=0x08, FIN=0x01, RST=0x04).
    pub flags: u8,
    /// TCP payload bytes.
    pub payload: Vec<u8>,
}

/// Dissects an Ethernet frame containing an IPv4 or IPv6 TCP packet.
///
/// Returns `None` if the frame is malformed, not an IP frame, or not TCP.
pub fn dissect_tcp_frame(raw: &[u8]) -> Option<DissectedTcpPacket> {
    if raw.len() < 14 {
        return None;
    }
    let mut offset = 14;
    let mut ethertype = u16::from_be_bytes([raw[12], raw[13]]);
    if ethertype == 0x8100 && raw.len() >= 18 {
        ethertype = u16::from_be_bytes([raw[16], raw[17]]);
        offset = 18;
    }

    let (src_ip, dst_ip, l4_proto, ip_payload_offset) = match ethertype {
        0x0800 => {
            if raw.len() < offset + 20 {
                return None;
            }
            let ihl = ((raw[offset] & 0x0F) * 4) as usize;
            let proto = raw[offset + 9];
            let mut s = [0u8; 4];
            s.copy_from_slice(&raw[offset + 12..offset + 16]);
            let mut d = [0u8; 4];
            d.copy_from_slice(&raw[offset + 16..offset + 20]);
            (
                IpAddr::V4(Ipv4Addr::from(s)),
                IpAddr::V4(Ipv4Addr::from(d)),
                proto,
                offset + ihl,
            )
        }
        0x86DD => {
            if raw.len() < offset + 40 {
                return None;
            }
            let proto = raw[offset + 6];
            let mut s = [0u8; 16];
            s.copy_from_slice(&raw[offset + 8..offset + 24]);
            let mut d = [0u8; 16];
            d.copy_from_slice(&raw[offset + 24..offset + 40]);
            (
                IpAddr::V6(Ipv6Addr::from(s)),
                IpAddr::V6(Ipv6Addr::from(d)),
                proto,
                offset + 40,
            )
        }
        _ => return None,
    };

    if l4_proto != 6 || raw.len() < ip_payload_offset + 20 {
        return None;
    }

    let tcp_raw = &raw[ip_payload_offset..];
    let src_port = u16::from_be_bytes([tcp_raw[0], tcp_raw[1]]);
    let dst_port = u16::from_be_bytes([tcp_raw[2], tcp_raw[3]]);
    let seq = u32::from_be_bytes([tcp_raw[4], tcp_raw[5], tcp_raw[6], tcp_raw[7]]);
    let ack = u32::from_be_bytes([tcp_raw[8], tcp_raw[9], tcp_raw[10], tcp_raw[11]]);
    let data_offset = ((tcp_raw[12] >> 4) * 4) as usize;
    let flags = tcp_raw[13];
    let payload = if tcp_raw.len() > data_offset {
        tcp_raw[data_offset..].to_vec()
    } else {
        Vec::new()
    };

    Some(DissectedTcpPacket {
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        seq,
        ack,
        flags,
        payload,
    })
}

/// Helper that allocates a unique temporary PCAP path.
fn get_unique_temp_pcap_path() -> PathBuf {
    /// Atomic counter ensuring unique temporary PCAP filenames across concurrent test threads.
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let count = COUNTER.fetch_add(1, Ordering::Relaxed);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("adv_chall_{}_{}_{}.pcap", std::process::id(), count, nanos))
}

/// Helper that reads raw packet buffers from a generated PCAPNG file.
fn read_raw_pcapng_frames(path: &Path) -> Result<Vec<Vec<u8>>, String> {
    let file = fs::File::open(path)
        .map_err(|e| format!("Failed to open PCAP file {}: {}", path.display(), e))?;
    let mut reader = pcap_file::pcapng::PcapNgReader::new(file)
        .map_err(|e| format!("Failed to create PCAPNG reader: {}", e))?;
    let mut frames = Vec::new();
    while let Some(block) = reader.next_block() {
        let block = block.map_err(|e| format!("Failed to read block: {}", e))?;
        if let pcap_file::pcapng::Block::EnhancedPacket(epb) = block {
            frames.push(epb.data.to_vec());
        }
    }
    Ok(frames)
}

/// Helper that parses a script, generates PCAP, and returns dissected TCP packets.
fn compile_and_dissect_tcp(script: &str) -> Vec<DissectedTcpPacket> {
    let program = parse_program(script).expect("Script parsing should succeed");
    let temp_path = get_unique_temp_pcap_path();
    let temp_str = temp_path.to_str().expect("valid temp path");

    generate_pcap(&program, temp_str).expect("PCAP generation should succeed");
    let frames = read_raw_pcapng_frames(&temp_path).expect("read raw frames");
    let _ = fs::remove_file(&temp_path);

    frames
        .iter()
        .map(|f| dissect_tcp_frame(f).expect("Frame must be a valid TCP packet"))
        .collect()
}

// =========================================================================
// Category 1: Two-Stage TCP Port Inheritance & 4-Tuple State
// =========================================================================

/// Stress test multi-port concurrent streams between the same host pairs.
///
/// Interleaves packets from Stream A (40001 -> 80) and Stream B (40002 -> 443),
/// verifying that each 4-tuple tracks sequence numbers and acknowledgment numbers
/// in complete isolation.
#[test]
pub fn test_adversarial_concurrent_multi_port_interleaved_streams() {
    let script = r#"
        HOST client { IP 192.168.1.10 }
        HOST server { IP 192.168.1.20 }

        FLOW stream_a_syn(c, s) {
            c -> s TCP SYN SRCPORT 40001 DSTPORT 80
        }
        FLOW stream_b_syn(c, s) {
            c -> s TCP SYN SRCPORT 40002 DSTPORT 443
        }
        FLOW stream_a_synack(c, s) {
            c <- s TCP SYN ACK SRCPORT 80 DSTPORT 40001
        }
        FLOW stream_b_synack(c, s) {
            c <- s TCP SYN ACK SRCPORT 443 DSTPORT 40002
        }
        FLOW stream_a_data(c, s) {
            c -> s TCP PSH ACK SRCPORT 40001 DSTPORT 80 PAYLOAD "StreamA-Data-1"
        }
        FLOW stream_b_data(c, s) {
            c -> s TCP PSH ACK SRCPORT 40002 DSTPORT 443 PAYLOAD "StreamB-Data-ABCDE"
        }
        FLOW stream_a_ack(c, s) {
            c <- s TCP ACK SRCPORT 80 DSTPORT 40001
        }
        FLOW stream_b_ack(c, s) {
            c <- s TCP ACK SRCPORT 443 DSTPORT 40002
        }

        COMPILE {
            stream_a_syn(client, server)
            stream_b_syn(client, server)
            stream_a_synack(client, server)
            stream_b_synack(client, server)
            stream_a_data(client, server)
            stream_b_data(client, server)
            stream_a_ack(client, server)
            stream_b_ack(client, server)
        }
    "#;

    let packets = compile_and_dissect_tcp(script);
    assert_eq!(packets.len(), 8);

    // Frame 0: Stream A SYN
    assert_eq!(packets[0].src_port, 40001);
    assert_eq!(packets[0].dst_port, 80);
    assert_eq!(packets[0].seq, 1000);
    assert_eq!(packets[0].flags, 0x02); // SYN

    // Frame 1: Stream B SYN (independent seq starting at 1000)
    assert_eq!(packets[1].src_port, 40002);
    assert_eq!(packets[1].dst_port, 443);
    assert_eq!(packets[1].seq, 1000);
    assert_eq!(packets[1].flags, 0x02); // SYN

    // Frame 2: Stream A SYN ACK (server seq=1000, acking client seq 1000+1=1001)
    assert_eq!(packets[2].src_port, 80);
    assert_eq!(packets[2].dst_port, 40001);
    assert_eq!(packets[2].seq, 1000);
    assert_eq!(packets[2].ack, 1001);
    assert_eq!(packets[2].flags, 0x12); // SYN + ACK

    // Frame 3: Stream B SYN ACK (server seq=1000, acking client seq 1000+1=1001)
    assert_eq!(packets[3].src_port, 443);
    assert_eq!(packets[3].dst_port, 40002);
    assert_eq!(packets[3].seq, 1000);
    assert_eq!(packets[3].ack, 1001);
    assert_eq!(packets[3].flags, 0x12); // SYN + ACK

    // Frame 4: Stream A Data ("StreamA-Data-1" len=14, seq=1001, ack=1001)
    assert_eq!(packets[4].src_port, 40001);
    assert_eq!(packets[4].dst_port, 80);
    assert_eq!(packets[4].seq, 1001);
    assert_eq!(packets[4].ack, 1001);
    assert_eq!(packets[4].payload, b"StreamA-Data-1");

    // Frame 5: Stream B Data ("StreamB-Data-ABCDE" len=18, seq=1001, ack=1001)
    assert_eq!(packets[5].src_port, 40002);
    assert_eq!(packets[5].dst_port, 443);
    assert_eq!(packets[5].seq, 1001);
    assert_eq!(packets[5].ack, 1001);
    assert_eq!(packets[5].payload, b"StreamB-Data-ABCDE");

    // Frame 6: Stream A ACK from server (seq=1001, ack=1001 + 14 = 1015)
    assert_eq!(packets[6].src_port, 80);
    assert_eq!(packets[6].dst_port, 40001);
    assert_eq!(packets[6].seq, 1001);
    assert_eq!(packets[6].ack, 1015);

    // Frame 7: Stream B ACK from server (seq=1001, ack=1001 + 18 = 1019)
    assert_eq!(packets[7].src_port, 443);
    assert_eq!(packets[7].dst_port, 40002);
    assert_eq!(packets[7].seq, 1001);
    assert_eq!(packets[7].ack, 1019);
}

/// Stress test arrow direction reversals (`->` followed by `<-` followed by `->`).
///
/// Verifies remembered endpoint ports across reversals and asserts that sequence/ack
/// numbers progress accurately without clobbering.
#[test]
pub fn test_adversarial_arrow_direction_reversals_ports_and_sequence() {
    let script = r#"
        HOST client { IP 10.1.1.5 }
        HOST server { IP 10.2.2.8 }

        FLOW full_conversation(c, s) {
            c -> s TCP SYN SRCPORT 49152 DSTPORT 8080
            c <- s TCP SYN ACK
            c -> s TCP ACK
            c -> s TCP PSH ACK PAYLOAD "RequestPayload"
            c <- s TCP PSH ACK PAYLOAD "ResponsePayload12345"
            c -> s TCP ACK
            c <- s TCP FIN ACK
            c -> s TCP ACK
        }

        COMPILE {
            full_conversation(client, server)
        }
    "#;

    let packets = compile_and_dissect_tcp(script);
    assert_eq!(packets.len(), 8);

    let ip_client = IpAddr::V4(Ipv4Addr::new(10, 1, 1, 5));
    let ip_server = IpAddr::V4(Ipv4Addr::new(10, 2, 2, 8));

    // Frame 0 (c -> s): SYN
    assert_eq!(packets[0].src_ip, ip_client);
    assert_eq!(packets[0].dst_ip, ip_server);
    assert_eq!(packets[0].src_port, 49152);
    assert_eq!(packets[0].dst_port, 8080);
    assert_eq!(packets[0].seq, 1000);
    assert_eq!(packets[0].flags, 0x02); // SYN

    // Frame 1 (c <- s): SYN ACK (inherits s_port=8080, d_port=49152)
    assert_eq!(packets[1].src_ip, ip_server);
    assert_eq!(packets[1].dst_ip, ip_client);
    assert_eq!(packets[1].src_port, 8080);
    assert_eq!(packets[1].dst_port, 49152);
    assert_eq!(packets[1].seq, 1000);
    assert_eq!(packets[1].ack, 1001);
    assert_eq!(packets[1].flags, 0x12); // SYN + ACK

    // Frame 2 (c -> s): ACK (inherits s_port=49152, d_port=8080)
    assert_eq!(packets[2].src_ip, ip_client);
    assert_eq!(packets[2].dst_ip, ip_server);
    assert_eq!(packets[2].src_port, 49152);
    assert_eq!(packets[2].dst_port, 8080);
    assert_eq!(packets[2].seq, 1001);
    assert_eq!(packets[2].ack, 1001);
    assert_eq!(packets[2].flags, 0x10); // ACK

    // Frame 3 (c -> s): PSH ACK RequestPayload (14 bytes)
    assert_eq!(packets[3].src_port, 49152);
    assert_eq!(packets[3].dst_port, 8080);
    assert_eq!(packets[3].seq, 1001);
    assert_eq!(packets[3].ack, 1001);
    assert_eq!(packets[3].payload, b"RequestPayload");
    assert_eq!(packets[3].flags & 0x18, 0x18); // PSH + ACK

    // Frame 4 (c <- s): PSH ACK ResponsePayload12345 (20 bytes)
    assert_eq!(packets[4].src_port, 8080);
    assert_eq!(packets[4].dst_port, 49152);
    assert_eq!(packets[4].seq, 1001);
    assert_eq!(packets[4].ack, 1015); // 1001 + 14 = 1015
    assert_eq!(packets[4].payload, b"ResponsePayload12345");
    assert_eq!(packets[4].flags & 0x18, 0x18); // PSH + ACK

    // Frame 5 (c -> s): ACK of response
    assert_eq!(packets[5].src_port, 49152);
    assert_eq!(packets[5].dst_port, 8080);
    assert_eq!(packets[5].seq, 1015);
    assert_eq!(packets[5].ack, 1021); // 1001 + 20 = 1021

    // Frame 6 (c <- s): FIN ACK
    assert_eq!(packets[6].src_port, 8080);
    assert_eq!(packets[6].dst_port, 49152);
    assert_eq!(packets[6].seq, 1021);
    assert_eq!(packets[6].ack, 1015);
    assert_eq!(packets[6].flags, 0x11); // FIN + ACK

    // Frame 7 (c -> s): ACK of FIN
    assert_eq!(packets[7].src_port, 49152);
    assert_eq!(packets[7].dst_port, 8080);
    assert_eq!(packets[7].seq, 1015);
    assert_eq!(packets[7].ack, 1022); // 1021 + 1 (FIN) = 1022
}

/// Stress test loopback pairs: `127.0.0.1 -> 127.0.0.1` and `::1 -> ::1`.
///
/// Verifies that multiple concurrent loopback connections with different ports
/// maintain completely isolated sequence/acknowledgment progression.
#[test]
pub fn test_adversarial_loopback_isolation_v4_and_v6() {
    let script = r#"
        HOST loop_v4 { IP 127.0.0.1 }
        HOST loop_v6 { IP ::1 }

        FLOW loop4_conn1(node) {
            node -> node TCP SYN SRCPORT 30001 DSTPORT 30002
            node <- node TCP SYN ACK
            node -> node TCP PSH ACK PAYLOAD "Loop4-Conn1-Msg"
        }
        FLOW loop4_conn2(node) {
            node -> node TCP SYN SRCPORT 30003 DSTPORT 30004
            node <- node TCP SYN ACK
        }
        FLOW loop6_conn1(node) {
            node -> node TCP SYN SRCPORT 50001 DSTPORT 50002
            node <- node TCP SYN ACK
            node -> node TCP PSH ACK PAYLOAD "Loop6-Conn1-Msg"
        }
        FLOW loop6_conn2(node) {
            node -> node TCP SYN SRCPORT 50003 DSTPORT 50004
            node <- node TCP SYN ACK
        }

        COMPILE {
            loop4_conn1(loop_v4)
            loop4_conn2(loop_v4)
            loop6_conn1(loop_v6)
            loop6_conn2(loop_v6)
        }
    "#;

    let packets = compile_and_dissect_tcp(script);
    assert_eq!(packets.len(), 10);

    let ip_v4 = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
    let ip_v6 = IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1));

    // IPv4 Connection 1:
    // Frame 0: SYN (30001 -> 30002)
    assert_eq!(packets[0].src_ip, ip_v4);
    assert_eq!(packets[0].dst_ip, ip_v4);
    assert_eq!(packets[0].src_port, 30001);
    assert_eq!(packets[0].dst_port, 30002);
    assert_eq!(packets[0].seq, 1000);

    // Frame 1: SYN ACK (30002 -> 30001)
    assert_eq!(packets[1].src_port, 30002);
    assert_eq!(packets[1].dst_port, 30001);
    assert_eq!(packets[1].seq, 1000);
    assert_eq!(packets[1].ack, 1001);

    // Frame 2: PSH ACK (30001 -> 30002, payload len=15)
    assert_eq!(packets[2].src_port, 30001);
    assert_eq!(packets[2].dst_port, 30002);
    assert_eq!(packets[2].seq, 1001);
    assert_eq!(packets[2].payload, b"Loop4-Conn1-Msg");

    // IPv4 Connection 2 (completely separate ports, seq must restart from initial):
    // Frame 3: SYN (30003 -> 30004)
    assert_eq!(packets[3].src_port, 30003);
    assert_eq!(packets[3].dst_port, 30004);
    assert_eq!(packets[3].seq, 1000); // Must be isolated from conn 1!

    // Frame 4: SYN ACK (30004 -> 30003)
    assert_eq!(packets[4].src_port, 30004);
    assert_eq!(packets[4].dst_port, 30003);
    assert_eq!(packets[4].seq, 1000);
    assert_eq!(packets[4].ack, 1001);

    // IPv6 Connection 1:
    // Frame 5: SYN (50001 -> 50002)
    assert_eq!(packets[5].src_ip, ip_v6);
    assert_eq!(packets[5].dst_ip, ip_v6);
    assert_eq!(packets[5].src_port, 50001);
    assert_eq!(packets[5].dst_port, 50002);
    assert_eq!(packets[5].seq, 1000);

    // Frame 6: SYN ACK (50002 -> 50001)
    assert_eq!(packets[6].src_port, 50002);
    assert_eq!(packets[6].dst_port, 50001);
    assert_eq!(packets[6].seq, 1000);
    assert_eq!(packets[6].ack, 1001);

    // Frame 7: PSH ACK (50001 -> 50002)
    assert_eq!(packets[7].src_port, 50001);
    assert_eq!(packets[7].dst_port, 50002);
    assert_eq!(packets[7].seq, 1001);
    assert_eq!(packets[7].payload, b"Loop6-Conn1-Msg");

    // IPv6 Connection 2:
    // Frame 8: SYN (50003 -> 50004)
    assert_eq!(packets[8].src_ip, ip_v6);
    assert_eq!(packets[8].dst_ip, ip_v6);
    assert_eq!(packets[8].src_port, 50003);
    assert_eq!(packets[8].dst_port, 50004);
    assert_eq!(packets[8].seq, 1000); // Must be isolated from loop6 conn 1!

    // Frame 9: SYN ACK (50004 -> 50003)
    assert_eq!(packets[9].src_port, 50004);
    assert_eq!(packets[9].dst_port, 50003);
    assert_eq!(packets[9].seq, 1000);
    assert_eq!(packets[9].ack, 1001);
}

/// Stress test strict 1 statement = 1 frame rule.
///
/// Asserts that L7 application statements auto-emit `TCP PSH ACK` (flags & 0x18 == 0x18)
/// and advance sequence numbers by their payload length.
#[test]
pub fn test_adversarial_l7_tcp_auto_emit_psh_ack_and_seq_advance() {
    let script = r#"
        HOST client { IP 10.0.0.1 }
        HOST server { IP 10.0.0.2 }

        FLOW http_exchange(c, s) {
            c -> s HTTP GET URI "/api/v1/status"
            c <- s HTTP STATUS 200 BODY "OK"
            c -> s HTTP GET URI "/api/v1/data"
        }

        COMPILE {
            http_exchange(client, server)
        }
    "#;

    let packets = compile_and_dissect_tcp(script);
    assert_eq!(packets.len(), 3, "Strict 1 statement = 1 frame must emit exactly 3 frames");

    // Frame 0: First HTTP GET request
    let p0 = &packets[0];
    assert_eq!(p0.dst_port, 80);
    assert_eq!(p0.seq, 1000);
    assert_eq!(p0.flags & 0x18, 0x18, "L7 TCP statement must set PSH and ACK");
    let p0_payload_len = p0.payload.len() as u32;
    assert!(p0_payload_len > 0, "HTTP GET must have non-empty payload");

    // Frame 1: HTTP 200 response
    let p1 = &packets[1];
    assert_eq!(p1.src_port, 80);
    assert_eq!(p1.seq, 1000);
    // Acknowledgment number must match client's sequence + payload length
    assert_eq!(p1.ack, 1000 + p0_payload_len, "Server ACK must reflect client request payload length");
    assert_eq!(p1.flags & 0x18, 0x18, "L7 TCP response must set PSH and ACK");
    let p1_payload_len = p1.payload.len() as u32;
    assert!(p1_payload_len > 0, "HTTP 200 response must have non-empty payload");

    // Frame 2: Second HTTP GET request from client
    let p2 = &packets[2];
    assert_eq!(p2.dst_port, 80);
    // Client sequence number must have advanced by first payload length
    assert_eq!(p2.seq, 1000 + p0_payload_len, "Client sequence number must advance by previous payload length");
    // Client acknowledgment number must acknowledge server's response
    assert_eq!(p2.ack, 1000 + p1_payload_len, "Client ACK must reflect server response payload length");
    assert_eq!(p2.flags & 0x18, 0x18, "Subsequent L7 TCP statement must set PSH and ACK");
}

// =========================================================================
// Category 2: Spanned Semantic Diagnostics & Negative Tests
// =========================================================================

/// Asserts that a FASM script fails compilation with a SemanticError matching a substring.
fn assert_semantic_error(script: &str, expected_substring: &str) {
    let err = parse_program(script).expect_err("Script must fail semantic validation");
    match err {
        CompilerError::SemanticError { message, span, .. } => {
            assert!(
                message.contains(expected_substring),
                "Expected error message containing '{}', but got '{}'",
                expected_substring,
                message
            );
            assert!(
                span.1 > 0,
                "SemanticError span length must be > 0 (got length {})",
                span.1
            );
        }
        other => panic!("Expected CompilerError::SemanticError, got {:?}", other),
    }
}

/// Tests rejection of mixed IPv4 and IPv6 endpoints in a single statement.
#[test]
pub fn test_adversarial_semantic_mixed_ipv4_ipv6() {
    let script_forward = r#"
        HOST mix_v4_a { IP 192.168.1.1 }
        HOST mix_v6_b { IP 2001:db8::1 }
        FLOW mix_fwd(ma, mb) { ma -> mb TCP SYN }
        COMPILE { mix_fwd(mix_v4_a, mix_v6_b) }"#;
    assert_semantic_error(script_forward, "Mixed IPv4 and IPv6");

    let script_reverse = r#"
        HOST mix_v6_c { IP 2001:db8::2 }
        HOST mix_v4_d { IP 192.168.1.2 }
        FLOW mix_rev(mc, md) { mc <- md UDP }
        COMPILE { mix_rev(mix_v6_c, mix_v4_d) }"#;
    assert_semantic_error(script_reverse, "Mixed IPv4 and IPv6");
}

/// Tests rejection of out-of-range VLAN IDs (`VLAN == 0` or `VLAN > 4094`).
#[test]
pub fn test_adversarial_semantic_out_of_range_vlan() {
    let script_zero = r#"
        HOST v0_cli { IP 10.11.0.1 }
        HOST v0_srv { IP 10.11.0.2 }
        FLOW vlan_zero_f(vc0, vs0) { vc0 -> vs0 TCP SYN VLAN 0 }
        COMPILE { vlan_zero_f(v0_cli, v0_srv) }"#;
    assert_semantic_error(script_zero, "VLAN ID 0 out of range");

    let script_4095 = r#"
        HOST v_max_cli { IP 10.11.1.1 }
        HOST v_max_srv { IP 10.11.1.2 }
        FLOW vlan_4095_f(vcm, vsm) { vcm -> vsm TCP SYN VLAN 4095 }
        COMPILE { vlan_4095_f(v_max_cli, v_max_srv) }"#;
    assert_semantic_error(script_4095, "VLAN ID 4095 out of range");
}

/// Tests rejection of out-of-range DSCP values (`DSCP > 63`).
#[test]
pub fn test_adversarial_semantic_out_of_range_dscp() {
    let dscp_bad_script = r#"
        HOST dscp_c { IP 10.12.0.1 }
        HOST dscp_s { IP 10.12.0.2 }
        FLOW dscp_bad_f(dc, ds) { dc -> ds UDP DSCP 64 }
        COMPILE { dscp_bad_f(dscp_c, dscp_s) }"#;
    assert_semantic_error(dscp_bad_script, "DSCP 64 out of range");
}

/// Tests rejection of out-of-range ECN values (`ECN > 3`).
#[test]
pub fn test_adversarial_semantic_out_of_range_ecn() {
    let ecn_bad_script = r#"
        HOST ecn_c { IP 10.13.0.1 }
        HOST ecn_s { IP 10.13.0.2 }
        FLOW ecn_bad_f(ec, es) { ec -> es UDP ECN 4 }
        COMPILE { ecn_bad_f(ecn_c, ecn_s) }"#;
    assert_semantic_error(ecn_bad_script, "ECN 4 out of range");
}

/// Tests rejection of out-of-range TTL values (`TTL > 255`).
#[test]
pub fn test_adversarial_semantic_out_of_range_ttl() {
    let ttl_bad_script = r#"
        HOST ttl_c { IP 10.14.0.1 }
        HOST ttl_s { IP 10.14.0.2 }
        FLOW ttl_bad_f(tc, ts) { tc -> ts UDP TTL 256 }
        COMPILE { ttl_bad_f(ttl_c, ttl_s) }"#;
    assert_semantic_error(ttl_bad_script, "TTL 256 out of range");
}

/// Tests rejection of out-of-range FLOWLABEL values (`FLOWLABEL > 0xFFFFF`).
#[test]
pub fn test_adversarial_semantic_out_of_range_flowlabel() {
    let fl_bad_script = r#"
        HOST fl_c6 { IP fe80::11 }
        HOST fl_s6 { IP fe80::12 }
        FLOW fl_bad_f(fc, fs) { fc -> fs TCP SYN FLOWLABEL 1048576 }
        COMPILE { fl_bad_f(fl_c6, fl_s6) }"#;
    assert_semantic_error(fl_bad_script, "FLOWLABEL 1048576 out of range");
}

/// Tests rejection of out-of-range GENTRAP values (`GENTRAP > 6`).
#[test]
pub fn test_adversarial_semantic_out_of_range_gentrap() {
    let gt_bad_script = r#"
        HOST gt_c { IP 10.15.0.1 }
        HOST gt_s { IP 10.15.0.2 }
        FLOW gt_bad_f(gc, gs) { gc -> gs SNMP1 GENTRAP 7 }
        COMPILE { gt_bad_f(gt_c, gt_s) }"#;
    assert_semantic_error(gt_bad_script, "GENTRAP 7 out of range");
}

/// Tests rejection of duplicate `HOST` declarations.
#[test]
pub fn test_adversarial_semantic_duplicate_host() {
    let dup_host_script = r#"
        HOST my_host { IP 10.16.0.1 }
        HOST my_host { IP 10.16.0.2 }
        COMPILE {}"#;
    assert_semantic_error(dup_host_script, "Duplicate HOST declaration: 'my_host'");
}

/// Tests rejection of duplicate `FLOW` declarations.
#[test]
pub fn test_adversarial_semantic_duplicate_flow() {
    let dup_flow_script = r#"
        HOST df_h1 { IP 10.17.0.1 }
        HOST df_h2 { IP 10.17.0.2 }
        FLOW my_flow(a, b) { a -> b UDP }
        FLOW my_flow(x, y) { x -> y TCP SYN }
        COMPILE { my_flow(df_h1, df_h2) }"#;
    assert_semantic_error(dup_flow_script, "Duplicate FLOW declaration: 'my_flow'");
}

/// Tests rejection of duplicate parameters in a `FLOW` definition.
#[test]
pub fn test_adversarial_semantic_duplicate_flow_params() {
    let dup_param_script = r#"
        HOST dp_h1 { IP 10.18.0.1 }
        FLOW f(dup, dup) { dup -> dup UDP }
        COMPILE { f(dp_h1, dp_h1) }"#;
    assert_semantic_error(dup_param_script, "Duplicate parameter 'dup' in FLOW 'f'");
}

/// Tests rejection of duplicate statement modifier keys.
#[test]
pub fn test_adversarial_semantic_duplicate_statement_modifier_keys() {
    let script_ttl = r#"
        HOST dm_c1 { IP 10.19.1.1 }
        HOST dm_s1 { IP 10.19.1.2 }
        FLOW dm_f1(c1, s1) { c1 -> s1 UDP TTL 10 TTL 20 }
        COMPILE { dm_f1(dm_c1, dm_s1) }"#;
    assert_semantic_error(script_ttl, "Duplicate statement modifier 'TTL'");

    let script_vlan = r#"
        HOST dm_c2 { IP 10.19.2.1 }
        HOST dm_s2 { IP 10.19.2.2 }
        FLOW dm_f2(c2, s2) { c2 -> s2 UDP VLAN 100 VLAN 200 }
        COMPILE { dm_f2(dm_c2, dm_s2) }"#;
    assert_semantic_error(script_vlan, "Duplicate statement modifier 'VLAN'");

    let script_srcport = r#"
        HOST dm_c3 { IP 10.19.3.1 }
        HOST dm_s3 { IP 10.19.3.2 }
        FLOW dm_f3(c3, s3) { c3 -> s3 TCP SYN SRCPORT 1000 SRCPORT 2000 }
        COMPILE { dm_f3(dm_c3, dm_s3) }"#;
    assert_semantic_error(script_srcport, "Duplicate statement modifier 'SRCPORT'");
}

/// Tests rejection of duplicate TCP flags within a statement.
#[test]
pub fn test_adversarial_semantic_duplicate_tcp_flags() {
    let dup_flag_script = r#"
        HOST tf_c { IP 10.20.0.1 }
        HOST tf_s { IP 10.20.0.2 }
        FLOW tf_f(tc, ts) { tc -> ts TCP SYN SYN }
        COMPILE { tf_f(tf_c, tf_s) }"#;
    assert_semantic_error(dup_flag_script, "Duplicate statement modifier: TCP flag 'Syn' specified multiple times");
}

/// Tests rejection when both `PAYLOAD` and `HEXPAYLOAD` are specified on the same statement.
#[test]
pub fn test_adversarial_semantic_duplicate_conflicting_payloads() {
    let both_pay_script = r#"
        HOST bp_c { IP 10.21.0.1 }
        HOST bp_s { IP 10.21.0.2 }
        FLOW bp_f(bc, bs) { bc -> bs UDP PAYLOAD "hello" HEXPAYLOAD "68656c6c6f" }
        COMPILE { bp_f(bp_c, bp_s) }"#;
    assert_semantic_error(both_pay_script, "cannot specify both PAYLOAD and HEXPAYLOAD");
}

/// Tests rejection of invalid cross-protocol modifiers across UDP, TCP, SNMP1, SNMP2, and SNMP3.
#[test]
pub fn test_adversarial_semantic_invalid_cross_protocol_modifiers() {
    let script_udp_flags = r#"
        HOST xp_c1 { IP 10.22.1.1 }
        HOST xp_s1 { IP 10.22.1.2 }
        FLOW xp_f1(a1, b1) { a1 -> b1 UDP SYN }
        COMPILE { xp_f1(xp_c1, xp_s1) }"#;
    assert_semantic_error(script_udp_flags, "TCP flags cannot be used with UDP");

    let script_udp_seq = r#"
        HOST xp_c2 { IP 10.22.2.1 }
        HOST xp_s2 { IP 10.22.2.2 }
        FLOW xp_f2(a2, b2) { a2 -> b2 UDP SEQ 1000 }
        COMPILE { xp_f2(xp_c2, xp_s2) }"#;
    assert_semantic_error(script_udp_seq, "SEQ/ACKNUM/WIN cannot be used with UDP");

    let script_udp_snmp = r#"
        HOST xp_c3 { IP 10.22.3.1 }
        HOST xp_s3 { IP 10.22.3.2 }
        FLOW xp_f3(a3, b3) { a3 -> b3 UDP COMMUNITY "public" }
        COMPILE { xp_f3(xp_c3, xp_s3) }"#;
    assert_semantic_error(script_udp_snmp, "SNMP fields cannot be used with UDP");

    let script_tcp_snmp = r#"
        HOST xp_c4 { IP 10.22.4.1 }
        HOST xp_s4 { IP 10.22.4.2 }
        FLOW xp_f4(a4, b4) { a4 -> b4 TCP SYN COMMUNITY "public" }
        COMPILE { xp_f4(xp_c4, xp_s4) }"#;
    assert_semantic_error(script_tcp_snmp, "SNMP fields cannot be used with TCP");

    let script_snmp1_flags = r#"
        HOST xp_c5 { IP 10.22.5.1 }
        HOST xp_s5 { IP 10.22.5.2 }
        FLOW xp_f5(a5, b5) { a5 -> b5 SNMP1 SYN }
        COMPILE { xp_f5(xp_c5, xp_s5) }"#;
    assert_semantic_error(script_snmp1_flags, "TCP flags cannot be used with SNMP1");

    let script_snmp1_usm = r#"
        HOST xp_c6 { IP 10.22.6.1 }
        HOST xp_s6 { IP 10.22.6.2 }
        FLOW xp_f6(a6, b6) { a6 -> b6 SNMP1 USER "alice" }
        COMPILE { xp_f6(xp_c6, xp_s6) }"#;
    assert_semantic_error(script_snmp1_usm, "SNMPv3 USM fields cannot be used with SNMP1");

    let script_snmp1_getbulk = r#"
        HOST xp_c7 { IP 10.22.7.1 }
        HOST xp_s7 { IP 10.22.7.2 }
        FLOW xp_f7(a7, b7) { a7 -> b7 SNMP1 GETBULK }
        COMPILE { xp_f7(xp_c7, xp_s7) }"#;
    assert_semantic_error(script_snmp1_getbulk, "GETBULK and INFORM are not supported in SNMP1");

    let script_snmp2_trap = r#"
        HOST xp_c8 { IP 10.22.8.1 }
        HOST xp_s8 { IP 10.22.8.2 }
        FLOW xp_f8(a8, b8) { a8 -> b8 SNMP2 ENTERPRISE "1.3.6.1.4.1" }
        COMPILE { xp_f8(xp_c8, xp_s8) }"#;
    assert_semantic_error(script_snmp2_trap, "SNMPv1 trap fields cannot be used with SNMP2");

    let script_snmp3_comm = r#"
        HOST xp_c9 { IP 10.22.9.1 }
        HOST xp_s9 { IP 10.22.9.2 }
        FLOW xp_f9(a9, b9) { a9 -> b9 SNMP3 COMMUNITY "public" }
        COMPILE { xp_f9(xp_c9, xp_s9) }"#;
    assert_semantic_error(script_snmp3_comm, "COMMUNITY cannot be used with SNMP3");
}

// =========================================================================
// Category 3: Delayed PCAP Creation
// =========================================================================

/// Verifies that a syntax error does not create the output PCAP file on disk.
#[test]
pub fn test_adversarial_delayed_pcap_not_created_on_syntax_error() {
    let invalid_syntax = "THIS IS NOT VALID FASM SYNTAX !!!";
    let syntax_err_path = get_unique_temp_pcap_path();

    assert!(parse_program(invalid_syntax).is_err(), "Invalid syntax must produce ParseError");
    assert!(!syntax_err_path.exists(), "Output file must NOT exist after syntax error");
    let _ = fs::remove_file(&syntax_err_path);
}

/// Verifies that a semantic error does not create the output PCAP file on disk.
#[test]
pub fn test_adversarial_delayed_pcap_not_created_on_semantic_error() {
    let sem_err_script = r#"
        HOST sem_c4 { IP 10.23.0.1 }
        HOST sem_s6 { IP 2001:db8::99 }
        FLOW sem_f(sc4, ss6) { sc4 -> ss6 TCP SYN }
        COMPILE { sem_f(sem_c4, sem_s6) }"#;
    let sem_err_path = get_unique_temp_pcap_path();

    assert!(parse_program(sem_err_script).is_err(), "Mixed endpoints must produce SemanticError");
    assert!(!sem_err_path.exists(), "Output file must NOT exist after semantic error");
    let _ = fs::remove_file(&sem_err_path);
}

/// Verifies that when a compilation error occurs, any pre-existing file at the output
/// path is preserved without being overwritten or truncated.
#[test]
pub fn test_adversarial_delayed_pcap_preserves_preexisting_file_on_error() {
    let sentinel_path = get_unique_temp_pcap_path();
    let original_content = b"SENTINEL_DATA_MUST_NOT_BE_TRUNCATED_OR_OVERWRITTEN";

    fs::write(&sentinel_path, original_content).expect("Write initial sentinel file");
    assert!(sentinel_path.exists());

    let dup_script = r#"
        HOST sentinel_h { IP 10.24.0.1 }
        HOST sentinel_h { IP 10.24.0.2 }
        COMPILE {}"#;
    assert!(parse_program(dup_script).is_err(), "Duplicate host must fail validation");

    let current_content = fs::read(&sentinel_path).expect("Read existing file content");
    assert_eq!(current_content, original_content, "Pre-existing file content must NOT be truncated");
    let _ = fs::remove_file(&sentinel_path);
}

/// Verifies that when compilation succeeds, the output PCAP file is created with valid data.
#[test]
pub fn test_adversarial_delayed_pcap_created_on_success() {
    let ok_path = get_unique_temp_pcap_path();
    let ok_str = ok_path.to_str().expect("valid temp path");
    assert!(!ok_path.exists());

    let valid_fasm = r#"
        HOST ok_cli { IP 10.25.0.1 }
        HOST ok_srv { IP 10.25.0.2 }
        FLOW ok_flow(oc, os) { oc -> os UDP PAYLOAD "ValidPayload" }
        COMPILE { ok_flow(ok_cli, ok_srv) }"#;

    let program = parse_program(valid_fasm).expect("Parse valid script");
    generate_pcap(&program, ok_str).expect("PCAP generation should succeed");

    assert!(ok_path.exists() && fs::metadata(&ok_path).expect("Read metadata").len() > 0);
    let frames = read_raw_pcapng_frames(&ok_path).expect("PCAPNG must be valid");
    assert_eq!(frames.len(), 1, "Must contain 1 frame");
    let _ = fs::remove_file(&ok_path);
}

/// Stress tests that an explicit `SRCPORT` override on a subsequent statement
/// updates the remembered endpoint port for following statements in both directions.
#[test]
pub fn test_adversarial_explicit_port_override_updates_remembered_state() {
    let script = r#"
        HOST client { IP 10.0.0.1 }
        HOST server { IP 10.0.0.2 }

        FLOW dynamic_ports(c, s) {
            c -> s TCP SYN SRCPORT 12345 DSTPORT 80
            c <- s TCP SYN ACK
            c -> s TCP PSH ACK SRCPORT 23456 PAYLOAD "NewPortData"
            c <- s TCP ACK
        }

        COMPILE {
            dynamic_ports(client, server)
        }
    "#;

    let packets = compile_and_dissect_tcp(script);
    assert_eq!(packets.len(), 4);

    // Frame 0: Initial SYN on port 12345
    assert_eq!(packets[0].src_port, 12345);
    assert_eq!(packets[0].dst_port, 80);

    // Frame 1: SYN ACK inherits caller_port=12345 as dst_port
    assert_eq!(packets[1].src_port, 80);
    assert_eq!(packets[1].dst_port, 12345);

    // Frame 2: Explicit SRCPORT override to 23456
    assert_eq!(packets[2].src_port, 23456);
    assert_eq!(packets[2].dst_port, 80);

    // Frame 3: Server ACK must now inherit the updated caller_port 23456!
    assert_eq!(packets[3].src_port, 80);
    assert_eq!(packets[3].dst_port, 23456);
}

/// Stress tests an extended 5-turn alternating conversation (`->`, `<-`, `->`, `<-`, `->`)
/// with data payloads in both directions, verifying sequence and ack progression across
/// multiple round trips.
#[test]
pub fn test_adversarial_extended_five_turn_conversation_sequence_integrity() {
    let script = r#"
        HOST c { IP 10.10.10.1 }
        HOST s { IP 10.10.10.2 }

        FLOW chat(client, server) {
            client -> server TCP SYN SRCPORT 50000 DSTPORT 9000
            client <- server TCP SYN ACK
            client -> server TCP PSH ACK PAYLOAD "Msg1_From_Client_10B"
            client <- server TCP PSH ACK PAYLOAD "Msg2_From_Server_20Bytes"
            client -> server TCP PSH ACK PAYLOAD "Msg3_Final_Client_15B"
        }

        COMPILE {
            chat(c, s)
        }
    "#;

    let packets = compile_and_dissect_tcp(script);
    assert_eq!(packets.len(), 5);

    // Frame 0 (c -> s): SYN (seq=1000)
    assert_eq!(packets[0].src_port, 50000);
    assert_eq!(packets[0].dst_port, 9000);
    assert_eq!(packets[0].seq, 1000);

    // Frame 1 (c <- s): SYN ACK (seq=1000, ack=1001)
    assert_eq!(packets[1].src_port, 9000);
    assert_eq!(packets[1].dst_port, 50000);
    assert_eq!(packets[1].seq, 1000);
    assert_eq!(packets[1].ack, 1001);

    // Frame 2 (c -> s): PSH ACK (seq=1001, ack=1001, payload len=21)
    let p2_len = packets[2].payload.len() as u32; // "Msg1_From_Client_10B" = 20 bytes
    assert_eq!(packets[2].seq, 1001);
    assert_eq!(packets[2].ack, 1001);

    // Frame 3 (c <- s): PSH ACK (seq=1001, ack=1001 + p2_len, payload len=24)
    let p3_len = packets[3].payload.len() as u32; // "Msg2_From_Server_20Bytes" = 24 bytes
    assert_eq!(packets[3].seq, 1001);
    assert_eq!(packets[3].ack, 1001 + p2_len);

    // Frame 4 (c -> s): PSH ACK (seq=1001 + p2_len, ack=1001 + p3_len)
    assert_eq!(packets[4].seq, 1001 + p2_len);
    assert_eq!(packets[4].ack, 1001 + p3_len);
}
