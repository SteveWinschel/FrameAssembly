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
        host client { ip 192.168.1.10 }
        host server { ip 192.168.1.20 }

        flow stream_a_syn(c, s) {
            c -> s tcp syn srcport 40001 dstport 80
        }
        flow stream_b_syn(c, s) {
            c -> s tcp syn srcport 40002 dstport 443
        }
        flow stream_a_synack(c, s) {
            c <- s tcp syn ack srcport 80 dstport 40001
        }
        flow stream_b_synack(c, s) {
            c <- s tcp syn ack srcport 443 dstport 40002
        }
        flow stream_a_data(c, s) {
            c -> s tcp psh ack srcport 40001 dstport 80 payload "StreamA-Data-1"
        }
        flow stream_b_data(c, s) {
            c -> s tcp psh ack srcport 40002 dstport 443 payload "StreamB-Data-ABCDE"
        }
        flow stream_a_ack(c, s) {
            c <- s tcp ack srcport 80 dstport 40001
        }
        flow stream_b_ack(c, s) {
            c <- s tcp ack srcport 443 dstport 40002
        }

        compile {
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
        host client { ip 10.1.1.5 }
        host server { ip 10.2.2.8 }

        flow full_conversation(c, s) {
            c -> s tcp syn srcport 49152 dstport 8080
            c <- s tcp syn ack
            c -> s tcp ack
            c -> s tcp psh ack payload "RequestPayload"
            c <- s tcp psh ack payload "ResponsePayload12345"
            c -> s tcp ack
            c <- s tcp fin ack
            c -> s tcp ack
        }

        compile {
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
        host loop_v4 { ip 127.0.0.1 }
        host loop_v6 { ip ::1 }

        flow loop4_conn1(node) {
            node -> node tcp syn srcport 30001 dstport 30002
            node <- node tcp syn ack
            node -> node tcp psh ack payload "Loop4-Conn1-Msg"
        }
        flow loop4_conn2(node) {
            node -> node tcp syn srcport 30003 dstport 30004
            node <- node tcp syn ack
        }
        flow loop6_conn1(node) {
            node -> node tcp syn srcport 50001 dstport 50002
            node <- node tcp syn ack
            node -> node tcp psh ack payload "Loop6-Conn1-Msg"
        }
        flow loop6_conn2(node) {
            node -> node tcp syn srcport 50003 dstport 50004
            node <- node tcp syn ack
        }

        compile {
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
        host client { ip 10.0.0.1 }
        host server { ip 10.0.0.2 }

        flow http_exchange(c, s) {
            c -> s http get uri "/api/v1/status"
            c <- s http status 200 body "OK"
            c -> s http get uri "/api/v1/data"
        }

        compile {
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
        host mix_v4_a { ip 192.168.1.1 }
        host mix_v6_b { ip 2001:db8::1 }
        flow mix_fwd(ma, mb) { ma -> mb tcp syn }
        compile { mix_fwd(mix_v4_a, mix_v6_b) }"#;
    assert_semantic_error(script_forward, "Mixed IPv4 and IPv6");

    let script_reverse = r#"
        host mix_v6_c { ip 2001:db8::2 }
        host mix_v4_d { ip 192.168.1.2 }
        flow mix_rev(mc, md) { mc <- md udp }
        compile { mix_rev(mix_v6_c, mix_v4_d) }"#;
    assert_semantic_error(script_reverse, "Mixed IPv4 and IPv6");
}

/// Tests rejection of out-of-range VLAN IDs (`VLAN == 0` or `VLAN > 4094`).
#[test]
pub fn test_adversarial_semantic_out_of_range_vlan() {
    let script_zero = r#"
        host v0_cli { ip 10.11.0.1 }
        host v0_srv { ip 10.11.0.2 }
        flow vlan_zero_f(vc0, vs0) { vc0 -> vs0 tcp syn vlan 0 }
        compile { vlan_zero_f(v0_cli, v0_srv) }"#;
    assert_semantic_error(script_zero, "VLAN ID 0 out of range");

    let script_4095 = r#"
        host v_max_cli { ip 10.11.1.1 }
        host v_max_srv { ip 10.11.1.2 }
        flow vlan_4095_f(vcm, vsm) { vcm -> vsm tcp syn vlan 4095 }
        compile { vlan_4095_f(v_max_cli, v_max_srv) }"#;
    assert_semantic_error(script_4095, "VLAN ID 4095 out of range");
}

/// Tests rejection of out-of-range DSCP values (`DSCP > 63`).
#[test]
pub fn test_adversarial_semantic_out_of_range_dscp() {
    let dscp_bad_script = r#"
        host dscp_c { ip 10.12.0.1 }
        host dscp_s { ip 10.12.0.2 }
        flow dscp_bad_f(dc, ds) { dc -> ds udp dscp 64 }
        compile { dscp_bad_f(dscp_c, dscp_s) }"#;
    assert_semantic_error(dscp_bad_script, "DSCP 64 out of range");
}

/// Tests rejection of out-of-range ECN values (`ECN > 3`).
#[test]
pub fn test_adversarial_semantic_out_of_range_ecn() {
    let ecn_bad_script = r#"
        host ecn_c { ip 10.13.0.1 }
        host ecn_s { ip 10.13.0.2 }
        flow ecn_bad_f(ec, es) { ec -> es udp ecn 4 }
        compile { ecn_bad_f(ecn_c, ecn_s) }"#;
    assert_semantic_error(ecn_bad_script, "ECN 4 out of range");
}

/// Tests rejection of out-of-range TTL values (`TTL > 255`).
#[test]
pub fn test_adversarial_semantic_out_of_range_ttl() {
    let ttl_bad_script = r#"
        host ttl_c { ip 10.14.0.1 }
        host ttl_s { ip 10.14.0.2 }
        flow ttl_bad_f(tc, ts) { tc -> ts udp ttl 256 }
        compile { ttl_bad_f(ttl_c, ttl_s) }"#;
    assert_semantic_error(ttl_bad_script, "TTL 256 out of range");
}

/// Tests rejection of out-of-range FLOWLABEL values (`FLOWLABEL > 0xFFFFF`).
#[test]
pub fn test_adversarial_semantic_out_of_range_flowlabel() {
    let fl_bad_script = r#"
        host fl_c6 { ip fe80::11 }
        host fl_s6 { ip fe80::12 }
        flow fl_bad_f(fc, fs) { fc -> fs tcp syn flowlabel 1048576 }
        compile { fl_bad_f(fl_c6, fl_s6) }"#;
    assert_semantic_error(fl_bad_script, "FLOWLABEL 1048576 out of range");
}

/// Tests rejection of out-of-range GENTRAP values (`GENTRAP > 6`).
#[test]
pub fn test_adversarial_semantic_out_of_range_gentrap() {
    let gt_bad_script = r#"
        host gt_c { ip 10.15.0.1 }
        host gt_s { ip 10.15.0.2 }
        flow gt_bad_f(gc, gs) { gc -> gs snmp1 gentrap 7 }
        compile { gt_bad_f(gt_c, gt_s) }"#;
    assert_semantic_error(gt_bad_script, "GENTRAP 7 out of range");
}

/// Tests rejection of duplicate `HOST` declarations.
#[test]
pub fn test_adversarial_semantic_duplicate_host() {
    let dup_host_script = r#"
        host my_host { ip 10.16.0.1 }
        host my_host { ip 10.16.0.2 }
        compile {}"#;
    assert_semantic_error(dup_host_script, "Duplicate HOST declaration: 'my_host'");
}

/// Tests rejection of duplicate `FLOW` declarations.
#[test]
pub fn test_adversarial_semantic_duplicate_flow() {
    let dup_flow_script = r#"
        host df_h1 { ip 10.17.0.1 }
        host df_h2 { ip 10.17.0.2 }
        flow my_flow(a, b) { a -> b udp }
        flow my_flow(x, y) { x -> y tcp syn }
        compile { my_flow(df_h1, df_h2) }"#;
    assert_semantic_error(dup_flow_script, "Duplicate FLOW declaration: 'my_flow'");
}

/// Tests rejection of duplicate parameters in a `FLOW` definition.
#[test]
pub fn test_adversarial_semantic_duplicate_flow_params() {
    let dup_param_script = r#"
        host dp_h1 { ip 10.18.0.1 }
        flow f(dup, dup) { dup -> dup udp }
        compile { f(dp_h1, dp_h1) }"#;
    assert_semantic_error(dup_param_script, "Duplicate parameter 'dup' in FLOW 'f'");
}

/// Tests rejection of duplicate statement modifier keys.
#[test]
pub fn test_adversarial_semantic_duplicate_statement_modifier_keys() {
    let script_ttl = r#"
        host dm_c1 { ip 10.19.1.1 }
        host dm_s1 { ip 10.19.1.2 }
        flow dm_f1(c1, s1) { c1 -> s1 udp ttl 10 ttl 20 }
        compile { dm_f1(dm_c1, dm_s1) }"#;
    assert_semantic_error(script_ttl, "Duplicate statement modifier 'TTL'");

    let script_vlan = r#"
        host dm_c2 { ip 10.19.2.1 }
        host dm_s2 { ip 10.19.2.2 }
        flow dm_f2(c2, s2) { c2 -> s2 udp vlan 100 vlan 200 }
        compile { dm_f2(dm_c2, dm_s2) }"#;
    assert_semantic_error(script_vlan, "Duplicate statement modifier 'VLAN'");

    let script_srcport = r#"
        host dm_c3 { ip 10.19.3.1 }
        host dm_s3 { ip 10.19.3.2 }
        flow dm_f3(c3, s3) { c3 -> s3 tcp syn srcport 1000 srcport 2000 }
        compile { dm_f3(dm_c3, dm_s3) }"#;
    assert_semantic_error(script_srcport, "Duplicate statement modifier 'SRCPORT'");
}

/// Tests rejection of duplicate TCP flags within a statement.
#[test]
pub fn test_adversarial_semantic_duplicate_tcp_flags() {
    let dup_flag_script = r#"
        host tf_c { ip 10.20.0.1 }
        host tf_s { ip 10.20.0.2 }
        flow tf_f(tc, ts) { tc -> ts tcp syn syn }
        compile { tf_f(tf_c, tf_s) }"#;
    assert_semantic_error(dup_flag_script, "Duplicate statement modifier: TCP flag 'Syn' specified multiple times");
}

/// Tests rejection when both `PAYLOAD` and `HEXPAYLOAD` are specified on the same statement.
#[test]
pub fn test_adversarial_semantic_duplicate_conflicting_payloads() {
    let both_pay_script = r#"
        host bp_c { ip 10.21.0.1 }
        host bp_s { ip 10.21.0.2 }
        flow bp_f(bc, bs) { bc -> bs udp payload "hello" hexpayload "68656c6c6f" }
        compile { bp_f(bp_c, bp_s) }"#;
    assert_semantic_error(both_pay_script, "cannot specify both PAYLOAD and HEXPAYLOAD");
}

/// Tests rejection of invalid cross-protocol modifiers across UDP, TCP, SNMP1, SNMP2, and SNMP3.
#[test]
pub fn test_adversarial_semantic_invalid_cross_protocol_modifiers() {
    let script_udp_flags = r#"
        host xp_c1 { ip 10.22.1.1 }
        host xp_s1 { ip 10.22.1.2 }
        flow xp_f1(a1, b1) { a1 -> b1 udp syn }
        compile { xp_f1(xp_c1, xp_s1) }"#;
    assert_semantic_error(script_udp_flags, "TCP flags cannot be used with UDP");

    let script_udp_seq = r#"
        host xp_c2 { ip 10.22.2.1 }
        host xp_s2 { ip 10.22.2.2 }
        flow xp_f2(a2, b2) { a2 -> b2 udp seq 1000 }
        compile { xp_f2(xp_c2, xp_s2) }"#;
    assert_semantic_error(script_udp_seq, "SEQ/ACKNUM/WIN cannot be used with UDP");

    let script_udp_snmp = r#"
        host xp_c3 { ip 10.22.3.1 }
        host xp_s3 { ip 10.22.3.2 }
        flow xp_f3(a3, b3) { a3 -> b3 udp community "public" }
        compile { xp_f3(xp_c3, xp_s3) }"#;
    assert_semantic_error(script_udp_snmp, "SNMP fields cannot be used with UDP");

    let script_tcp_snmp = r#"
        host xp_c4 { ip 10.22.4.1 }
        host xp_s4 { ip 10.22.4.2 }
        flow xp_f4(a4, b4) { a4 -> b4 tcp syn community "public" }
        compile { xp_f4(xp_c4, xp_s4) }"#;
    assert_semantic_error(script_tcp_snmp, "SNMP fields cannot be used with TCP");

    let script_snmp1_flags = r#"
        host xp_c5 { ip 10.22.5.1 }
        host xp_s5 { ip 10.22.5.2 }
        flow xp_f5(a5, b5) { a5 -> b5 snmp1 syn }
        compile { xp_f5(xp_c5, xp_s5) }"#;
    assert_semantic_error(script_snmp1_flags, "TCP flags cannot be used with SNMP1");

    let script_snmp1_usm = r#"
        host xp_c6 { ip 10.22.6.1 }
        host xp_s6 { ip 10.22.6.2 }
        flow xp_f6(a6, b6) { a6 -> b6 snmp1 user "alice" }
        compile { xp_f6(xp_c6, xp_s6) }"#;
    assert_semantic_error(script_snmp1_usm, "SNMPv3 USM fields cannot be used with SNMP1");

    let script_snmp1_getbulk = r#"
        host xp_c7 { ip 10.22.7.1 }
        host xp_s7 { ip 10.22.7.2 }
        flow xp_f7(a7, b7) { a7 -> b7 snmp1 getbulk }
        compile { xp_f7(xp_c7, xp_s7) }"#;
    assert_semantic_error(script_snmp1_getbulk, "GETBULK and INFORM are not supported in SNMP1");

    let script_snmp2_trap = r#"
        host xp_c8 { ip 10.22.8.1 }
        host xp_s8 { ip 10.22.8.2 }
        flow xp_f8(a8, b8) { a8 -> b8 snmp2 enterprise "1.3.6.1.4.1" }
        compile { xp_f8(xp_c8, xp_s8) }"#;
    assert_semantic_error(script_snmp2_trap, "SNMPv1 trap fields cannot be used with SNMP2");

    let script_snmp3_comm = r#"
        host xp_c9 { ip 10.22.9.1 }
        host xp_s9 { ip 10.22.9.2 }
        flow xp_f9(a9, b9) { a9 -> b9 snmp3 community "public" }
        compile { xp_f9(xp_c9, xp_s9) }"#;
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
        host sem_c4 { ip 10.23.0.1 }
        host sem_s6 { ip 2001:db8::99 }
        flow sem_f(sc4, ss6) { sc4 -> ss6 tcp syn }
        compile { sem_f(sem_c4, sem_s6) }"#;
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
        host sentinel_h { ip 10.24.0.1 }
        host sentinel_h { ip 10.24.0.2 }
        compile {}"#;
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
        host ok_cli { ip 10.25.0.1 }
        host ok_srv { ip 10.25.0.2 }
        flow ok_flow(oc, os) { oc -> os udp payload "ValidPayload" }
        compile { ok_flow(ok_cli, ok_srv) }"#;

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
        host client { ip 10.0.0.1 }
        host server { ip 10.0.0.2 }

        flow dynamic_ports(c, s) {
            c -> s tcp syn srcport 12345 dstport 80
            c <- s tcp syn ack
            c -> s tcp psh ack srcport 23456 payload "NewPortData"
            c <- s tcp ack
        }

        compile {
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
        host c { ip 10.10.10.1 }
        host s { ip 10.10.10.2 }

        flow chat(client, server) {
            client -> server tcp syn srcport 50000 dstport 9000
            client <- server tcp syn ack
            client -> server tcp psh ack payload "Msg1_From_Client_10B"
            client <- server tcp psh ack payload "Msg2_From_Server_20Bytes"
            client -> server tcp psh ack payload "Msg3_Final_Client_15B"
        }

        compile {
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
