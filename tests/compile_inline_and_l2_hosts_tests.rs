//! Integration test suite for FrameAssembly v1.5.0 grammar, inline compilation, Layer 2 MAC-only
//! hosts, and CLI stem-derived default path contracts.
//!
//! This test module validates four core capabilities across the parser, semantic analyzer,
//! wire builder backend, reverse PCAP/PCAPNG decompiler, and `frameassembly` CLI binary:
//! 1. **Case-Insensitive Grammar Invariants**: Confirms that uppercase, lowercase, and mixed-case
//!    `.fasm` keywords, protocol identifiers, TCP flags, field modifiers, host/flow symbols, and
//!    time units (`ns`, `us`, `ms`, `s`, `m`) compile into 100% byte-identical wire frames and
//!    nanosecond timestamps.
//! 2. **Inline `compile { ... }` Frame Statements & LL(2) Lookahead**: Verifies standalone
//!    directional packet statements (`a -> b` and `a <- b`) directly inside `compile { ... }`,
//!    mixed execution with `flow` invocations and `loop` blocks, 4-tuple TCP sequence/ack and
//!    bidirectional port inheritance, and LL(2) statement-boundary disambiguation when contextual
//!    keywords (`ip`, `mac`, `ttl`, `seq`, `ack`, `win`, `user`, `domain`, `status`, `code`,
//!    `id`, `type`, `version`) are used as host or flow identifiers.
//! 3. **Optional-`IP` Layer 2 Host Declarations**: Verifies that MAC-only `host` blocks compile
//!    across all eight Layer 2 protocols (`stp`, `lldp`, `lacp`, `eapol`, `vlan`, `qinq`, `mpls`,
//!    `arp`) with RFC/IEEE default inner EtherTypes (`0x88B5` for `vlan`/`qinq`, `0x8847` for
//!    `mpls`, `0x0806` for `arp`) while rejecting empty `host` blocks and rejecting MAC-only
//!    endpoints on Layer 3, Layer 4, and Layer 7 IP-requiring protocols.
//! 4. **CLI Stem-Derived Output Paths & Collision Guards**: Exercises the compiled
//!    `frameassembly` binary inside an RAII temporary directory to verify default `<stem>.pcap`
//!    and `<stem>.fasm` output derivation, `-o` overrides, `.pcapng` reversal, input overwrite
//!    collision protection, and read-only `frameassembly show` packet ladder rendering.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use frameassembly::backend::compile_program;
use frameassembly::error::CompilerError;
use frameassembly::parser::parse_program;

/// Monotonic atomic counter ensuring every test thread gets a unique temporary directory.
static TEMP_DIR_COUNTER: AtomicU64 = AtomicU64::new(0);

/// RAII temporary directory guard that creates an isolated folder under `std::env::temp_dir()`
/// combining `std::process::id()` and a monotonic [`AtomicU64`] counter, removing all files on drop.
struct TempTestDir {
    /// Absolute path to the isolated temporary directory.
    path: PathBuf,
}

impl TempTestDir {
    /// Creates a new isolated temporary directory for a test case.
    fn new(prefix: &str) -> Self {
        let id = TEMP_DIR_COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir_name = format!("frameassembly_test_{}_{}_{}", prefix, std::process::id(), id);
        let path = std::env::temp_dir().join(dir_name);
        fs::create_dir_all(&path).expect("failed to create temporary test directory");
        Self { path }
    }

    /// Returns a path inside this temporary directory for the given relative file name.
    fn join(&self, file_name: &str) -> PathBuf {
        self.path.join(file_name)
    }

    /// Returns the directory path as a [`Path`] reference.
    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempTestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

/// Parses and compiles a `.fasm` source string into `(raw_frame_bytes, timestamp_ns)` tuples.
fn must_compile(src: &str) -> Vec<(Vec<u8>, u64)> {
    let program = parse_program(src).unwrap_or_else(|e| panic!("failed to parse program: {e}"));
    compile_program(&program).unwrap_or_else(|e| panic!("failed to compile program: {e}"))
}

// ============================================================================
// 1. Case-Insensitive Grammar Tests
// ============================================================================

/// Verifies that uppercase, lowercase, and mixed-case `.fasm` programs using `host`, `flow`,
/// `compile`, `loop`, `wait`, `ip`, `mac`, protocol keywords, TCP flags, time units, and L2-L7
/// field modifiers compile to 100% byte-identical PCAP frames and nanosecond timestamps.
#[test]
fn test_case_insensitive_grammar_uppercase_lowercase_mixed_byte_identical() {
    let uppercase_fasm = r#"
        HOST CLIENT_1 { IP 10.10.1.10 MAC 00:1A:2B:3C:4D:01 }
        HOST SERVER_1 { IP 10.10.1.20 MAC 00:1A:2B:3C:4D:02 }

        FLOW HANDSHAKE_AND_APP(C, S) {
            C -> S VLAN 100 PCP 5 DEI 1 DSCP 46 ECN 2 TTL 64 TCP SYN SRCPORT 51000 DSTPORT 8080 SEQ 2000 WIN 65535 MSS 1460 WSCALE 7 SACK_PERM TSVAL 100 TSECR 0 WAIT 100NS
            C <- S VLAN 100 PCP 5 DEI 0 DSCP 46 ECN 2 TTL 64 TCP SYN ACK SEQ 4000 ACKNUM 2001 WIN 32768 MSS 1460 WSCALE 6 SACK_PERM TSVAL 200 TSECR 100 WAIT 50US
            C -> S TCP ACK WIN 65535 WAIT 5MS
            C -> S HTTP GET URI "/api/v1/status" HOST_HDR "service.internal" PAYLOAD "ping" WAIT 2S
            C <- S HTTP STATUS 200 REASON "OK" BODY "{\"ok\":true}" WAIT 1M
        }

        COMPILE {
            LOOP 2 {
                HANDSHAKE_AND_APP(CLIENT_1, SERVER_1)
            }
            CLIENT_1 -> SERVER_1 DNS QUERY TXID 0x1234 QNAME "example.com" QTYPE "A" WAIT 10MS
            CLIENT_1 <- SERVER_1 DNS RESPONSE TXID 0x1234 QNAME "example.com" QTYPE "A" RDATA "93.184.216.34" WAIT 15MS
        }
    "#;

    let lowercase_fasm = r#"
        host client_1 { ip 10.10.1.10 mac 00:1a:2b:3c:4d:01 }
        host server_1 { ip 10.10.1.20 mac 00:1a:2b:3c:4d:02 }

        flow handshake_and_app(c, s) {
            c -> s vlan 100 pcp 5 dei 1 dscp 46 ecn 2 ttl 64 tcp syn srcport 51000 dstport 8080 seq 2000 win 65535 mss 1460 wscale 7 sack_perm tsval 100 tsecr 0 wait 100ns
            c <- s vlan 100 pcp 5 dei 0 dscp 46 ecn 2 ttl 64 tcp syn ack seq 4000 acknum 2001 win 32768 mss 1460 wscale 6 sack_perm tsval 200 tsecr 100 wait 50us
            c -> s tcp ack win 65535 wait 5ms
            c -> s http get uri "/api/v1/status" host_hdr "service.internal" payload "ping" wait 2s
            c <- s http status 200 reason "OK" body "{\"ok\":true}" wait 1m
        }

        compile {
            loop 2 {
                handshake_and_app(client_1, server_1)
            }
            client_1 -> server_1 dns query txid 0x1234 qname "example.com" qtype "A" wait 10ms
            client_1 <- server_1 dns response txid 0x1234 qname "example.com" qtype "A" rdata "93.184.216.34" wait 15ms
        }
    "#;

    let mixed_case_fasm = r#"
        HoSt ClIeNt_1 { Ip 10.10.1.10 MaC 00:1a:2B:3c:4D:01 }
        hOsT sErVeR_1 { iP 10.10.1.20 mAc 00:1A:2b:3C:4d:02 }

        FlOw HaNdShAkE_aNd_ApP(c, S) {
            C -> s VlAn 100 PcP 5 DeI 1 DsCp 46 EcN 2 TtL 64 TcP sYn SrCpOrT 51000 DsTpOrT 8080 SeQ 2000 WiN 65535 MsS 1460 WsCaLe 7 SaCk_PeRm TsVaL 100 TsEcR 0 WaIt 100Ns
            c <- S vLaN 100 pCp 5 dEi 0 dScP 46 eCn 2 tTl 64 tCp SyN aCk sEq 4000 AcKnUm 2001 wIn 32768 mSs 1460 wScAlE 6 sAcK_pErM tSvAl 200 tSeCr 100 wAiT 50Us
            C -> S TcP AcK WiN 65535 WaIt 5Ms
            c -> s HtTp GeT uRi "/api/v1/status" HoSt_HdR "service.internal" PaYlOaD "ping" wAiT 2S
            C <- S hTtP sTaTuS 200 rEaSoN "OK" bOdY "{\"ok\":true}" WaIt 1m
        }

        CoMpIlE {
            LoOp 2 {
                hAnDsHaKe_AnD_aPp(cLiEnT_1, SeRvEr_1)
            }
            ClIeNt_1 -> sErVeR_1 DnS qUeRy TxId 0x1234 QnAmE "example.com" QtYpE "A" WaIt 10mS
            cLiEnT_1 <- SeRvEr_1 dNs ReSpOnSe tXiD 0x1234 qNaMe "example.com" qTyPe "A" RdAtA "93.184.216.34" wAiT 15Ms
        }
    "#;

    let upper_frames = must_compile(uppercase_fasm);
    let lower_frames = must_compile(lowercase_fasm);
    let mixed_frames = must_compile(mixed_case_fasm);

    assert_eq!(upper_frames.len(), 12);
    assert_eq!(upper_frames, lower_frames);
    assert_eq!(upper_frames, mixed_frames);
}

/// Verifies that all five time units (`ns`, `us`, `ms`, `s`, `m`) and SNMPv3 USM parameters
/// produce identical nanosecond timestamps and encrypted PDUs regardless of keyword casing.
#[test]
fn test_case_insensitive_time_units_and_snmpv3_usm() {
    let upper = r#"
        HOST AGENT { IP 192.168.10.1 MAC 00:11:22:33:44:01 }
        HOST NMS   { IP 192.168.10.2 MAC 00:11:22:33:44:02 }
        COMPILE {
            AGENT -> NMS SNMP3 TRAP USER "admin" ENGINEID "80001f8880510001" ENGINEBOOTS 3 ENGINETIME 1200 AUTH SHA256 "authpass123" PRIV AES "privpass123" VARBIND 1.3.6.1.2.1.1.3.0 TIMETICKS 5000 WAIT 250NS
            AGENT -> NMS ICMP ECHO_REQUEST ID 1 SEQ 1 WAIT 40US
            AGENT <- NMS ICMP ECHO_REPLY ID 1 SEQ 1 WAIT 12MS
            AGENT -> NMS UDP SRCPORT 40000 DSTPORT 9000 HEXPAYLOAD "deadbeef" WAIT 3S
            AGENT <- NMS UDP HEXPAYLOAD "cafebabe" WAIT 2M
        }
    "#;

    let lower = r#"
        host agent { ip 192.168.10.1 mac 00:11:22:33:44:01 }
        host nms   { ip 192.168.10.2 mac 00:11:22:33:44:02 }
        compile {
            agent -> nms snmp3 trap user "admin" engineid "80001f8880510001" engineboots 3 enginetime 1200 auth sha256 "authpass123" priv aes "privpass123" varbind 1.3.6.1.2.1.1.3.0 timeticks 5000 wait 250ns
            agent -> nms icmp echo_request id 1 seq 1 wait 40us
            agent <- nms icmp echo_reply id 1 seq 1 wait 12ms
            agent -> nms udp srcport 40000 dstport 9000 hexpayload "deadbeef" wait 3s
            agent <- nms udp hexpayload "cafebabe" wait 2m
        }
    "#;

    let upper_frames = must_compile(upper);
    let lower_frames = must_compile(lower);
    assert_eq!(upper_frames, lower_frames);
    assert_eq!(upper_frames.len(), 5);

    let t0 = upper_frames[0].1;
    assert_eq!(upper_frames[1].1 - t0, 40_000);
    assert_eq!(upper_frames[2].1 - upper_frames[1].1, 12_000_000);
    assert_eq!(upper_frames[3].1 - upper_frames[2].1, 3_000_000_000);
    assert_eq!(upper_frames[4].1 - upper_frames[3].1, 120_000_000_000);
}

// ============================================================================
// 2. Inline `compile { ... }` Flow Statement Tests
// ============================================================================

/// Verifies that directional `FrameStatement`s (`a -> b ...` and `a <- b ...`) written directly
/// inside `compile { ... }` without any `flow` declarations compile to the exact same bytes and
/// timestamps as an equivalent program using `flow` declarations.
#[test]
fn test_inline_compile_statements_without_flows_match_flow_invocation() {
    let inline_fasm = r#"
        host client { ip 10.0.0.10 mac 00:1c:73:aa:bb:01 }
        host server { ip 10.0.0.20 mac 00:1c:73:aa:bb:02 }

        compile {
            client -> server tcp syn srcport 49152 dstport 443 seq 1000 win 65535 mss 1460 wait 1ms
            client <- server tcp syn ack seq 5000 acknum 1001 win 65535 mss 1460 wait 1ms
            client -> server tcp ack win 65535 wait 1ms
            client -> server tls client_hello sni "secure.example.com" wait 5ms
            client <- server tls server_hello wait 2ms
        }
    "#;

    let flow_fasm = r#"
        host client { ip 10.0.0.10 mac 00:1c:73:aa:bb:01 }
        host server { ip 10.0.0.20 mac 00:1c:73:aa:bb:02 }

        flow tls_handshake(c, s) {
            c -> s tcp syn srcport 49152 dstport 443 seq 1000 win 65535 mss 1460 wait 1ms
            c <- s tcp syn ack seq 5000 acknum 1001 win 65535 mss 1460 wait 1ms
            c -> s tcp ack win 65535 wait 1ms
            c -> s tls client_hello sni "secure.example.com" wait 5ms
            c <- s tls server_hello wait 2ms
        }

        compile {
            tls_handshake(client, server)
        }
    "#;

    let inline_frames = must_compile(inline_fasm);
    let flow_frames = must_compile(flow_fasm);
    assert_eq!(inline_frames.len(), 5);
    assert_eq!(inline_frames, flow_frames);
}

/// Verifies mixing inline `FrameStatement`s with `flow` invocations and `loop` blocks inside
/// `compile { ... }`, preserving chronological order and shared connection state.
#[test]
fn test_mixing_inline_statements_flow_invocations_and_loops_in_compile() {
    let fasm = r#"
        host h1 { ip 172.16.0.1 mac 00:11:22:33:44:01 }
        host h2 { ip 172.16.0.2 mac 00:11:22:33:44:02 }

        flow ping_exchange(a, b) {
            a -> b icmp echo_request id 0x0042 seq 1 wait 2ms
            a <- b icmp echo_reply id 0x0042 seq 1 wait 2ms
        }

        compile {
            h1 -> h2 arp request wait 1ms
            h1 <- h2 arp reply wait 1ms
            ping_exchange(h1, h2)
            h1 -> h2 dns query txid 0xabcd qname "internal.corp" qtype "A" wait 3ms
            loop 3 {
                ping_exchange(h1, h2)
            }
            h1 <- h2 dns response txid 0xabcd qname "internal.corp" qtype "A" rdata "172.16.0.99" wait 4ms
        }
    "#;

    let frames = must_compile(fasm);
    // 2 inline ARP + 2 flow ICMP + 1 inline DNS query + (3 * 2 loop ICMP) + 1 inline DNS response = 12 frames
    assert_eq!(frames.len(), 12);

    // Frame 0 & 1: ARP (EtherType 0x0806 at bytes 12..14)
    assert_eq!(&frames[0].0[12..14], &[0x08, 0x06]);
    assert_eq!(&frames[1].0[12..14], &[0x08, 0x06]);

    // Frame 2 & 3: ICMP (IPv4 protocol 1 at byte 23)
    assert_eq!(frames[2].0[23], 1);
    assert_eq!(frames[3].0[23], 1);

    // Frame 4: DNS Query over UDP (IPv4 protocol 17 at byte 23, dst port 53 at bytes 36..38)
    assert_eq!(frames[4].0[23], 17);
    assert_eq!(u16::from_be_bytes([frames[4].0[36], frames[4].0[37]]), 53);

    // Frame 11: DNS Response over UDP (`<-` swaps src port to 53 at bytes 34..36)
    assert_eq!(frames[11].0[23], 17);
    assert_eq!(u16::from_be_bytes([frames[11].0[34], frames[11].0[35]]), 53);
}

/// Verifies 4-tuple TCP sequence/acknowledgment progression and bidirectional port inheritance
/// across `->` and `<-` directly inside `compile { ... }` across raw `tcp` and L7 `http` frames.
#[test]
fn test_inline_compile_tcp_4tuple_seq_ack_and_port_inheritance() {
    let fasm = r#"
        host client { ip 10.1.1.10 mac 00:00:00:00:00:01 }
        host server { ip 10.1.1.20 mac 00:00:00:00:00:02 }

        compile {
            client -> server tcp syn srcport 54321 dstport 8080 seq 1000
            client <- server tcp syn ack seq 2000
            client -> server tcp ack
            client -> server http get uri "/test" host_hdr "app.local"
            client <- server tcp ack
            client <- server tcp fin ack
            client -> server tcp fin ack
        }
    "#;

    let frames = must_compile(fasm);
    assert_eq!(frames.len(), 7);

    // Helper to extract (src_port, dst_port, seq, ack, flags, tcp_payload_len) from an IPv4 Ethernet frame
    let tcp_info = |frame: &[u8]| -> (u16, u16, u32, u32, u8, u32) {
        let ihl = ((frame[14] & 0x0F) as usize) * 4;
        let l4 = &frame[14 + ihl..];
        let sport = u16::from_be_bytes([l4[0], l4[1]]);
        let dport = u16::from_be_bytes([l4[2], l4[3]]);
        let seq = u32::from_be_bytes([l4[4], l4[5], l4[6], l4[7]]);
        let ack = u32::from_be_bytes([l4[8], l4[9], l4[10], l4[11]]);
        let data_off = ((l4[12] >> 4) as usize) * 4;
        let flags = l4[13];
        let payload_len = (l4.len() - data_off) as u32;
        (sport, dport, seq, ack, flags, payload_len)
    };

    // 1. SYN: 54321 -> 8080, seq=1000, ack=0
    let (sp0, dp0, seq0, ack0, flags0, len0) = tcp_info(&frames[0].0);
    assert_eq!((sp0, dp0, seq0, ack0, flags0, len0), (54321, 8080, 1000, 0, 0x02, 0));

    // 2. SYN-ACK (`<-`): 8080 -> 54321, seq=2000, ack=1001
    let (sp1, dp1, seq1, ack1, flags1, len1) = tcp_info(&frames[1].0);
    assert_eq!((sp1, dp1, seq1, ack1, flags1, len1), (8080, 54321, 2000, 1001, 0x12, 0));

    // 3. ACK (`->`): 54321 -> 8080, seq=1001, ack=2001
    let (sp2, dp2, seq2, ack2, flags2, len2) = tcp_info(&frames[2].0);
    assert_eq!((sp2, dp2, seq2, ack2, flags2, len2), (54321, 8080, 1001, 2001, 0x10, 0));

    // 4. HTTP GET (`->`): inherits explicit 54321 -> 8080, PSH+ACK (0x18), seq=1001, ack=2001
    let (sp3, dp3, seq3, ack3, flags3, http_len) = tcp_info(&frames[3].0);
    assert_eq!((sp3, dp3, seq3, ack3, flags3), (54321, 8080, 1001, 2001, 0x18));
    assert!(http_len > 0);

    // 5. Server ACK (`<-`): 8080 -> 54321, seq=2001, ack = 1001 + http_len
    let (sp4, dp4, seq4, ack4, flags4, _) = tcp_info(&frames[4].0);
    assert_eq!((sp4, dp4, seq4, ack4, flags4), (8080, 54321, 2001, 1001 + http_len, 0x10));

    // 6. Server FIN-ACK (`<-`): 8080 -> 54321, seq=2001, ack = 1001 + http_len (FIN advances server seq to 2002)
    let (sp5, dp5, seq5, ack5, flags5, _) = tcp_info(&frames[5].0);
    assert_eq!((sp5, dp5, seq5, ack5, flags5), (8080, 54321, 2001, 1001 + http_len, 0x11));

    // 7. Client FIN-ACK (`->`): 54321 -> 8080, seq = 1001 + http_len, ack=2002
    let (sp6, dp6, seq6, ack6, flags6, _) = tcp_info(&frames[6].0);
    assert_eq!((sp6, dp6, seq6, ack6, flags6), (54321, 8080, 1001 + http_len, 2002, 0x11));
}

/// Verifies LL(2) boundary lookahead when contextual keywords (`ip`, `mac`, `ttl`, `seq`, `ack`,
/// `win`, `user`, `domain`, `status`, `code`, `id`, `type`, `version`) are used as host or flow
/// identifiers in consecutive statements inside `flow` and `compile` blocks.
#[test]
fn test_ll2_boundary_lookahead_contextual_keywords_as_host_and_flow_identifiers() {
    let fasm = r#"
        host ip      { ip 10.20.0.1 }
        host mac     { ip 10.20.0.2 }
        host ttl     { ip 10.20.0.3 }
        host seq     { ip 10.20.0.4 }
        host ack     { ip 10.20.0.5 }
        host win     { ip 10.20.0.6 }
        host user    { ip 10.20.0.7 }
        host domain  { ip 10.20.0.8 }
        host status  { ip 10.20.0.9 }
        host code    { ip 10.20.0.10 }
        host id      { ip 10.20.0.11 }
        host type    { ip 10.20.0.12 }
        host version { ip 10.20.0.13 }

        flow ack(ip, mac) {
            ip -> mac tcp syn
            mac -> ip tcp syn ack
        }

        flow status(user, domain) {
            user -> domain dns query qname "test.local"
            domain -> user dns response qname "test.local" rdata "10.20.0.99"
        }

        flow version(id, type) {
            id -> type icmp echo_request
            type -> id icmp echo_reply
        }

        compile {
            ip -> mac tcp syn srcport 40000 dstport 80
            ttl <- seq tcp syn ack
            ack -> win udp srcport 5000 dstport 5001 payload "hello"
            user <- domain http get uri "/health"
            status -> code icmp echo_request
            id <- type arp request
            version -> ip tcp ack
            ack(ttl, seq)
            status(user, domain)
            version(id, type)
            loop 2 {
                ack(status, code)
            }
        }
    "#;

    let frames = must_compile(fasm);
    // 7 inline statements + 2 (ack) + 2 (status) + 2 (version) + 4 (loop 2 * ack) = 17 frames
    assert_eq!(frames.len(), 17);
}

// ============================================================================
// 3. Optional-`IP` Layer 2 Host Tests
// ============================================================================

/// Verifies that MAC-only `host` declarations (`host h { mac ... }`) compile cleanly across all
/// 8 Layer 2 protocols (`stp`, `lldp`, `lacp`, `eapol`, `vlan`, `qinq`, `mpls`, `arp`) and emit
/// the expected IEEE/RFC wire headers and inner EtherTypes.
#[test]
fn test_mac_only_hosts_across_all_8_layer2_protocols() {
    let fasm = r#"
        host host_1 { mac 00:1c:73:00:00:01 }
        host host_2 { mac 00-1C-73-00-00-02 }
        host host_3 { mac 001c.7300.0003 }

        compile {
            // 1. STP (802.1D Configuration BPDU & 802.1w RSTP BPDU)
            host_1 -> host_2 stp root_id "32768/00:1c:73:00:00:01" bridge_id "32768/00:1c:73:00:00:01" port_id 0x8001 cost 4
            host_1 -> host_2 stp rstp cost 2000

            // 2. LLDP (EtherType 0x88CC)
            host_1 -> host_2 lldp chassis_id "sw1.dc" port_id "Ethernet1" ttl 120 sysname "leaf-01"

            // 3. LACP (EtherType 0x8809)
            host_1 -> host_2 lacp actor_sys 00:1c:73:00:00:01 actor_key 10 actor_port 1 partner_sys 00:1c:73:00:00:02 partner_key 10 partner_port 1

            // 4. EAPOL (EtherType 0x888E)
            host_1 -> host_2 eapol version 2 type eap_packet eap_code 1 eap_id 7 eap_method 1 identity "alice@corp"

            // 5a. VLAN with default inner EtherType (0x88B5 for MAC-only hosts)
            host_1 -> host_2 vlan 150 pcp 6 dei 1 payload "l2-vlan-default"

            // 5b. VLAN with explicit ETHERTYPE override (0x88F7 PTP over L2)
            host_1 -> host_2 vlan 200 ethertype 0x88f7 hexpayload "0002002c"

            // 6. QINQ with default inner EtherType (0x88B5 for MAC-only hosts)
            host_1 -> host_3 qinq 1000 inner_vlan 250 payload "l2-qinq-payload"

            // 7. MPLS (EtherType 0x8847)
            host_2 -> host_3 mpls 104857 exp 5 bos 1 mpls_ttl 64 payload "mpls-l2-circuit"

            // 8. ARP over MAC-only hosts using SENDERIP and TARGETIP
            host_1 -> host_2 arp request senderip 192.168.1.1 targetip 192.168.1.2
            host_1 <- host_2 arp reply senderip 192.168.1.2 targetip 192.168.1.1
        }
    "#;

    let frames = must_compile(fasm);
    assert_eq!(frames.len(), 11);

    // 0 & 1: STP frames addressed to 01:80:c2:00:00:00 with LLC 0x42, 0x42, 0x03 at bytes 14..17
    assert_eq!(&frames[0].0[0..6], &[0x01, 0x80, 0xc2, 0x00, 0x00, 0x00]);
    assert_eq!(&frames[0].0[6..12], &[0x00, 0x1c, 0x73, 0x00, 0x00, 0x01]);
    assert_eq!(&frames[0].0[14..17], &[0x42, 0x42, 0x03]);
    assert_eq!(&frames[1].0[14..17], &[0x42, 0x42, 0x03]);

    // 2: LLDP (EtherType 0x88CC at 12..14, dst MAC 01:80:c2:00:00:0e)
    assert_eq!(&frames[2].0[0..6], &[0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e]);
    assert_eq!(&frames[2].0[12..14], &[0x88, 0xcc]);

    // 3: LACP (EtherType 0x8809 at 12..14, dst MAC 01:80:c2:00:00:02)
    assert_eq!(&frames[3].0[0..6], &[0x01, 0x80, 0xc2, 0x00, 0x00, 0x02]);
    assert_eq!(&frames[3].0[12..14], &[0x88, 0x09]);

    // 4: EAPOL (EtherType 0x888E at 12..14, dst MAC 01:80:c2:00:00:03)
    assert_eq!(&frames[4].0[0..6], &[0x01, 0x80, 0xc2, 0x00, 0x00, 0x03]);
    assert_eq!(&frames[4].0[12..14], &[0x88, 0x8e]);

    // 5: VLAN default inner EtherType: outer TPID 0x8100 at 12..14, inner EtherType 0x88B5 at 16..18
    assert_eq!(&frames[5].0[12..14], &[0x81, 0x00]);
    assert_eq!(&frames[5].0[16..18], &[0x88, 0xb5]);

    // 6: VLAN explicit EtherType override: outer TPID 0x8100 at 12..14, inner EtherType 0x88F7 at 16..18
    assert_eq!(&frames[6].0[12..14], &[0x81, 0x00]);
    assert_eq!(&frames[6].0[16..18], &[0x88, 0xf7]);

    // 7: QINQ default inner EtherType: outer S-Tag 0x88A8 at 12..14, inner C-Tag 0x8100 at 16..18, inner EtherType 0x88B5 at 20..22
    assert_eq!(&frames[7].0[12..14], &[0x88, 0xa8]);
    assert_eq!(&frames[7].0[16..18], &[0x81, 0x00]);
    assert_eq!(&frames[7].0[20..22], &[0x88, 0xb5]);
    assert_eq!(&frames[7].0[0..6], &[0x00, 0x1c, 0x73, 0x00, 0x00, 0x03]);

    // 8: MPLS: EtherType 0x8847 at 12..14
    assert_eq!(&frames[8].0[12..14], &[0x88, 0x47]);

    // 9 & 10: ARP Request & Reply: EtherType 0x0806 at 12..14, SPA & TPA encoded in ARP payload
    assert_eq!(&frames[9].0[12..14], &[0x08, 0x06]);
    assert_eq!(&frames[9].0[28..32], &[192, 168, 1, 1]);
    assert_eq!(&frames[9].0[38..42], &[192, 168, 1, 2]);
    assert_eq!(&frames[10].0[12..14], &[0x08, 0x06]);
    assert_eq!(&frames[10].0[28..32], &[192, 168, 1, 2]);
    assert_eq!(&frames[10].0[38..42], &[192, 168, 1, 1]);
}

/// Verifies that `parse_program` rejects an empty `host h1 { }` declaration that omits both
/// `ip` and `mac`.
#[test]
fn test_empty_host_declaration_rejected() {
    let empty_host_fasm = r#"
        host h1 { }
        host h2 { mac 00:1c:73:00:00:02 }
        compile {
            h1 -> h2 lldp
        }
    "#;

    let err = parse_program(empty_host_fasm).expect_err("empty host block must be rejected");
    match err {
        CompilerError::ParseError { message, .. } => {
            assert!(
                message.contains("must specify at least an 'IP <address>' or 'MAC <address>'"),
                "unexpected ParseError message: {message}"
            );
        }
        other => panic!("expected CompilerError::ParseError, got: {other:?}"),
    }
}

/// Verifies that `parse_program` rejects MAC-only hosts with `CompilerError::SemanticError` when
/// used with Layer 3, Layer 4, or Layer 7 IP-requiring protocols (`icmp`, `ospf`, `tcp`, `udp`,
/// `sctp`, `dns`, `http`, `snmp3`, etc.), whether in a `flow` invocation or inline in `compile`.
#[test]
fn test_mac_only_host_rejected_for_l3_l4_l7_ip_requiring_protocols() {
    let protocols = [
        "icmp echo_request",
        "ospf hello",
        "tcp syn",
        "udp dstport 9999",
        "sctp init",
        "dns query qname \"example.com\"",
        "http get uri \"/\"",
        "snmp3 trap user \"admin\"",
    ];

    for proto_stmt in protocols {
        // 1. Caller is MAC-only in inline COMPILE statement
        let inline_caller_src = format!(
            "host l2_only {{ mac 00:1c:73:00:00:01 }}\nhost ip_host {{ ip 10.0.0.2 }}\ncompile {{\n    l2_only -> ip_host {proto_stmt}\n}}"
        );
        let err = parse_program(&inline_caller_src)
            .expect_err("MAC-only caller must fail for IP-requiring protocol");
        match err {
            CompilerError::SemanticError { message, .. } => {
                assert!(
                    message.contains("requires an 'IP <address>' field on HOST 'l2_only'"),
                    "unexpected semantic error for '{proto_stmt}': {message}"
                );
            }
            other => panic!("expected SemanticError for '{proto_stmt}', got: {other:?}"),
        }

        // 2. Callee is MAC-only inside a FLOW invocation
        let flow_callee_src = format!(
            "host ip_host {{ ip 10.0.0.1 }}\nhost l2_only {{ mac 00:1c:73:00:00:02 }}\nflow test_f(a, b) {{\n    a -> b {proto_stmt}\n}}\ncompile {{\n    test_f(ip_host, l2_only)\n}}"
        );
        let err = parse_program(&flow_callee_src)
            .expect_err("MAC-only callee must fail for IP-requiring protocol");
        match err {
            CompilerError::SemanticError { message, .. } => {
                assert!(
                    message.contains("requires an 'IP <address>' field on HOST 'l2_only'"),
                    "unexpected semantic error for '{proto_stmt}': {message}"
                );
            }
            other => panic!("expected SemanticError for '{proto_stmt}', got: {other:?}"),
        }
    }
}

// ============================================================================
// 4. CLI Contract & Stem-Derived Default Output Path Tests
// ============================================================================

/// Returns the path to the compiled `frameassembly` binary under test.
fn cli_binary_path() -> &'static str {
    env!("CARGO_BIN_EXE_frameassembly")
}

/// Verifies that `frameassembly <example.fasm>` (without `-o`) automatically writes `<example>.pcap`
/// and that `frameassembly <example.fasm> -o <custom.pcap>` writes only `<custom.pcap>`.
#[test]
fn test_cli_forward_compile_default_stem_and_explicit_output() {
    let temp = TempTestDir::new("cli_forward");
    let fasm_path = temp.join("example.fasm");
    let default_pcap_path = temp.join("example.pcap");

    let sample_fasm = "\
host client { ip 10.0.0.1 mac 00:11:22:33:44:01 }
host server { ip 10.0.0.2 mac 00:11:22:33:44:02 }
compile {
    client -> server icmp echo_request id 10 seq 1 wait 5ms
    client <- server icmp echo_reply id 10 seq 1 wait 5ms
}
";
    fs::write(&fasm_path, sample_fasm).expect("write example.fasm");

    // 1. Run `frameassembly <example.fasm>` without `-o`
    let output = Command::new(cli_binary_path())
        .arg(&fasm_path)
        .output()
        .expect("run frameassembly default output");
    assert!(
        output.status.success(),
        "CLI failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        default_pcap_path.exists(),
        "expected default output file {} to exist",
        default_pcap_path.display()
    );
    let pcap_bytes = fs::read(&default_pcap_path).expect("read generated example.pcap");
    assert!(pcap_bytes.len() > 28);
    assert_eq!(&pcap_bytes[0..4], &[0x0A, 0x0D, 0x0D, 0x0A]);

    // 2. Run `frameassembly <other.fasm> -o <custom.pcap>`
    let other_fasm_path = temp.join("other.fasm");
    let other_default_pcap = temp.join("other.pcap");
    let custom_pcap_path = temp.join("custom_out.pcap");
    fs::write(&other_fasm_path, sample_fasm).expect("write other.fasm");

    let output_custom = Command::new(cli_binary_path())
        .arg(&other_fasm_path)
        .arg("-o")
        .arg(&custom_pcap_path)
        .output()
        .expect("run frameassembly -o custom_out.pcap");
    assert!(
        output_custom.status.success(),
        "CLI with -o failed: {}",
        String::from_utf8_lossy(&output_custom.stderr)
    );
    assert!(custom_pcap_path.exists(), "expected custom_out.pcap to exist");
    assert!(
        !other_default_pcap.exists(),
        "other.pcap must not be created when -o is provided"
    );
    assert_eq!(
        fs::read(&custom_pcap_path).expect("read custom_out.pcap"),
        pcap_bytes
    );
}

/// Verifies that `frameassembly reverse <example.pcap>` (without `-o`) writes `<example>.fasm`,
/// recompiling `<example>.fasm` via `frameassembly <example.fasm> -o <recompiled.pcap>` succeeds,
/// and `frameassembly reverse <trace.pcapng>` writes `<trace>.fasm`.
#[test]
fn test_cli_reverse_default_stem_pcap_and_pcapng_roundtrip() {
    let temp = TempTestDir::new("cli_reverse");
    let seed_fasm = temp.join("seed.fasm");
    let example_pcap = temp.join("example.pcap");
    let expected_example_fasm = temp.join("example.fasm");
    let recompiled_pcap = temp.join("recompiled.pcap");

    let fasm_code = "\
host h1 { ip 192.168.1.10 mac 00:1c:73:11:22:01 }
host h2 { ip 192.168.1.20 mac 00:1c:73:11:22:02 }
compile {
    h1 -> h2 dns query txid 0x2a3b qname \"example.org\" qtype \"A\" wait 10ms
    h1 <- h2 dns response txid 0x2a3b qname \"example.org\" qtype \"A\" rdata \"93.184.216.34\" wait 5ms
}
";
    fs::write(&seed_fasm, fasm_code).expect("write seed.fasm");

    // Compile seed.fasm -> example.pcap
    let compile_out = Command::new(cli_binary_path())
        .arg(&seed_fasm)
        .arg("-o")
        .arg(&example_pcap)
        .output()
        .expect("compile seed.fasm to example.pcap");
    assert!(compile_out.status.success());
    assert!(example_pcap.exists());

    // Reverse example.pcap without `-o` -> must write example.fasm
    let rev_out = Command::new(cli_binary_path())
        .arg("reverse")
        .arg(&example_pcap)
        .output()
        .expect("reverse example.pcap");
    assert!(
        rev_out.status.success(),
        "reverse failed: {}",
        String::from_utf8_lossy(&rev_out.stderr)
    );
    assert!(
        expected_example_fasm.exists(),
        "expected {} to be generated automatically",
        expected_example_fasm.display()
    );

    // Recompile example.fasm -> recompiled.pcap via CLI
    let recompile_out = Command::new(cli_binary_path())
        .arg(&expected_example_fasm)
        .arg("-o")
        .arg(&recompiled_pcap)
        .output()
        .expect("recompile example.fasm to recompiled.pcap");
    assert!(
        recompile_out.status.success(),
        "recompile failed: {}",
        String::from_utf8_lossy(&recompile_out.stderr)
    );
    assert!(recompiled_pcap.exists());
    assert_eq!(
        fs::read(&example_pcap).expect("read example.pcap"),
        fs::read(&recompiled_pcap).expect("read recompiled.pcap")
    );

    // Test `.pcapng` extension stem replacement: `frameassembly reverse trace.pcapng` -> `trace.fasm`
    let trace_pcapng = temp.join("trace.pcapng");
    let expected_trace_fasm = temp.join("trace.fasm");
    fs::copy(&example_pcap, &trace_pcapng).expect("copy to trace.pcapng");

    let rev_pcapng_out = Command::new(cli_binary_path())
        .arg("reverse")
        .arg(&trace_pcapng)
        .output()
        .expect("reverse trace.pcapng");
    assert!(
        rev_pcapng_out.status.success(),
        "reverse trace.pcapng failed: {}",
        String::from_utf8_lossy(&rev_pcapng_out.stderr)
    );
    assert!(
        expected_trace_fasm.exists(),
        "expected {} to be generated from trace.pcapng",
        expected_trace_fasm.display()
    );
}

/// Verifies the CLI collision guard when the input file already ends with `.pcap` on forward
/// compilation or `.fasm` on `reverse` decompilation so input files are never overwritten.
#[test]
fn test_cli_collision_guard_never_overwrites_input_file() {
    let temp = TempTestDir::new("cli_collision");

    // 1. Forward compile where input `.fasm` source is named `input_named.pcap`
    let fasm_named_pcap = temp.join("input_named.pcap");
    let expected_double_pcap = temp.join("input_named.pcap.pcap");
    let original_fasm_text = "\
host a { ip 10.0.0.1 mac 00:11:22:33:44:01 }
host b { ip 10.0.0.2 mac 00:11:22:33:44:02 }
compile {
    a -> b udp srcport 1234 dstport 5678 payload \"safe\"
}
";
    fs::write(&fasm_named_pcap, original_fasm_text).expect("write input_named.pcap");

    let fwd_out = Command::new(cli_binary_path())
        .arg(&fasm_named_pcap)
        .output()
        .expect("compile input_named.pcap");
    assert!(
        fwd_out.status.success(),
        "forward compile collision test failed: {}",
        String::from_utf8_lossy(&fwd_out.stderr)
    );
    assert!(
        expected_double_pcap.exists(),
        "expected {} to be created",
        expected_double_pcap.display()
    );
    // Verify original input file was not overwritten
    assert_eq!(
        fs::read_to_string(&fasm_named_pcap).expect("read original input_named.pcap"),
        original_fasm_text
    );

    // 2. Reverse decompile where binary capture file is named `capture_named.fasm`
    let pcap_named_fasm = temp.join("capture_named.fasm");
    let expected_double_fasm = temp.join("capture_named.fasm.fasm");
    let original_pcap_bytes = fs::read(&expected_double_pcap).expect("read binary pcap bytes");
    fs::write(&pcap_named_fasm, &original_pcap_bytes).expect("write capture_named.fasm");

    let rev_out = Command::new(cli_binary_path())
        .arg("reverse")
        .arg(&pcap_named_fasm)
        .output()
        .expect("reverse capture_named.fasm");
    assert!(
        rev_out.status.success(),
        "reverse collision test failed: {}",
        String::from_utf8_lossy(&rev_out.stderr)
    );
    assert!(
        expected_double_fasm.exists(),
        "expected {} to be created",
        expected_double_fasm.display()
    );
    // Verify original binary input file was not overwritten
    assert_eq!(
        fs::read(&pcap_named_fasm).expect("read original capture_named.fasm"),
        original_pcap_bytes
    );
    let reversed_text = fs::read_to_string(&expected_double_fasm).expect("read reversed fasm");
    assert!(reversed_text.contains("compile"));
}

/// Verifies that `frameassembly show <example.fasm>` succeeds and prints the formatted packet
/// ladder table without creating any `.pcap` file on disk.
#[test]
fn test_cli_show_prints_packet_ladder_without_writing_pcap() {
    let temp = TempTestDir::new("cli_show");
    let fasm_path = temp.join("ladder_demo.fasm");
    let unexpected_pcap_path = temp.join("ladder_demo.pcap");

    let sample_fasm = "\
host sw1 { mac 00:1c:73:00:00:01 }
host sw2 { mac 00:1c:73:00:00:02 }
compile {
    sw1 -> sw2 lldp chassis_id \"sw1\" port_id \"Eth1\" wait 5ms
    sw1 <- sw2 lldp chassis_id \"sw2\" port_id \"Eth2\" wait 5ms
}
";
    fs::write(&fasm_path, sample_fasm).expect("write ladder_demo.fasm");

    let show_out = Command::new(cli_binary_path())
        .arg("show")
        .arg(&fasm_path)
        .current_dir(temp.path())
        .output()
        .expect("run frameassembly show");
    assert!(
        show_out.status.success(),
        "frameassembly show failed: {}",
        String::from_utf8_lossy(&show_out.stderr)
    );

    let stdout = String::from_utf8_lossy(&show_out.stdout);
    assert!(stdout.contains("Source -> Destination"));
    assert!(stdout.contains("LLDP"));
    assert!(stdout.contains("00:1c:73:00:00:01"));
    assert!(
        !unexpected_pcap_path.exists(),
        "frameassembly show must not create a .pcap file on disk"
    );
}
