//! Integration test suite for FrameAssembly v2.0.0 strict-lowercase grammar, self-healing
//! diagnostics, inline compilation, Layer 2 MAC-only hosts, and default-compile + 4-subcommand CLI.
//!
//! This test module validates four core capabilities across the parser, semantic analyzer,
//! wire builder backend, reverse PCAP/PCAPNG decompiler, and `frameassembly` CLI binary:
//! 1. **Strict-Lowercase v2.0.0 Grammar & Self-Healing Hints**: Confirms strict `[a-z0-9]+`
//!    built-in keywords without `_` or `-`, flexible hyphenated/uppercase user identifiers,
//!    self-healing `miette` diagnostics on uppercase/`_`/`-`/`loop` tokens, `whois` vs
//!    `bacnet whois` disambiguation, and unified `hellotime` validation on `stp` and `hsrp`.
//! 2. **Inline `compile { ... }` Frame Statements & LL(2) Lookahead**: Verifies standalone
//!    directional packet statements (`a -> b` and `a <- b`) directly inside `compile { ... }`,
//!    mixed execution with `flow` invocations, 4-tuple TCP sequence/ack and bidirectional port
//!    inheritance, and LL(2) statement-boundary disambiguation on contextual host/flow names.
//! 3. **Optional-`ip` Layer 2 Host Declarations**: Verifies that MAC-only `host` blocks compile
//!    across all eight Layer 2 protocols (`stp`, `lldp`, `lacp`, `eapol`, `vlan`, `qinq`, `mpls`,
//!    `arp`) while rejecting empty `host` blocks and MAC-only endpoints on IP-requiring protocols.
//! 4. **v2.0.0 Default-Compile & 4-Subcommand CLI Contract**: Exercises default root compilation
//!    (`frameassembly <input.fasm> [output.pcap]`), `show`, `reverse`, `version`, `help`, hidden
//!    `-h`/`--help` and `-V`/`--version`, collision protection, and migration safety guards.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use frameassembly::backend::compile_program;
use frameassembly::error::CompilerError;
use frameassembly::parser::parse_program;
use miette::Diagnostic;

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
// 1. Strict-Lowercase v2.0.0 Grammar, Identifiers & Self-Healing Hints
// ============================================================================

/// Verifies strict-lowercase `[a-z0-9]+` keywords (`sackperm`, `hosthdr`, `echorequest`, `ns`,
/// `us`, `ms`, `s`, `m`) paired with flexible user-defined identifiers containing uppercase, `_`,
/// and internal `-` (`fw-dmz-01`, `CORE_SW_1`, `handshake-v2`), stopping cleanly before `->`.
#[test]
fn test_v2_strict_lowercase_keywords_and_flexible_hyphenated_identifiers() {
    let fasm = r#"
        host fw-dmz-01 { ip 10.10.1.10 mac 00:1A:2B:3C:4D:01 }
        host CORE_SW_1 { ip 10.10.1.20 mac 00:1a:2b:3c:4d:02 }

        flow handshake-v2(Client_A, srv-node-2) {
            Client_A->srv-node-2 vlan 100 pcp 5 dei 1 dscp 46 ecn 2 ttl 64 tcp syn srcport 51000 dstport 8080 seq 2000 win 65535 mss 1460 wscale 7 sackperm tsval 100 tsecr 0 wait 100ns
            Client_A<-srv-node-2 vlan 100 pcp 5 dei 0 dscp 46 ecn 2 ttl 64 tcp syn ack seq 4000 acknum 2001 win 32768 mss 1460 wscale 6 sackperm tsval 200 tsecr 100 wait 50us
            Client_A -> srv-node-2 tcp ack win 65535 wait 5ms
            Client_A -> srv-node-2 http get uri "/api/v1/status" hosthdr "service.internal" payload "ping" wait 2s
            Client_A <- srv-node-2 http status 200 reason "OK" body "{\"ok\":true}" wait 1m
        }

        compile {
            handshake-v2(fw-dmz-01, CORE_SW_1)
            handshake-v2(fw-dmz-01, CORE_SW_1)
            fw-dmz-01 -> CORE_SW_1 dns query txid 0x1234 qname "example.com" qtype "a" wait 10ms
            fw-dmz-01 <- CORE_SW_1 dns response txid 0x1234 qname "example.com" qtype "a" rdata "93.184.216.34" wait 15ms
        }
    "#;

    let frames = must_compile(fasm);
    assert_eq!(frames.len(), 12);

    // Verify all 5 time units (`ns`, `us`, `ms`, `s`, `m`) and SNMPv3 USM parameters
    let snmp_fasm = r#"
        host agent-01 { ip 192.168.10.1 mac 00:11:22:33:44:01 }
        host nms_srv  { ip 192.168.10.2 mac 00:11:22:33:44:02 }
        compile {
            agent-01 -> nms_srv snmp3 trap user "admin" engineid "80001f8880510001" engineboots 3 enginetime 1200 auth sha256 "authpass123" priv aes "privpass123" varbind 1.3.6.1.2.1.1.3.0 timeticks 5000 wait 250ns
            agent-01 -> nms_srv icmp echorequest id 1 seq 1 wait 40us
            agent-01 <- nms_srv icmp echoreply id 1 seq 1 wait 12ms
            agent-01 -> nms_srv udp srcport 40000 dstport 9000 hexpayload "deadbeef" wait 3s
            agent-01 <- nms_srv udp hexpayload "cafebabe" wait 2m
        }
    "#;
    let snmp_frames = must_compile(snmp_fasm);
    assert_eq!(snmp_frames.len(), 5);
    let t0 = snmp_frames[0].1;
    assert_eq!(snmp_frames[1].1 - t0, 40_000);
    assert_eq!(snmp_frames[2].1 - snmp_frames[1].1, 12_000_000);
    assert_eq!(snmp_frames[3].1 - snmp_frames[2].1, 3_000_000_000);
    assert_eq!(snmp_frames[4].1 - snmp_frames[3].1, 120_000_000_000);
}

/// Verifies that uppercase, underscore, hyphenated, and `loop` v1.x keywords are rejected in
/// FrameAssembly v2.0.0 with actionable self-healing `miette::Diagnostic::help` hints.
#[test]
fn test_v2_uppercase_underscore_and_loop_self_healing_diagnostics() {
    let cases: &[(&str, &str)] = &[
        (
            "HOST h1 { ip 10.0.0.1 }\nhost h2 { ip 10.0.0.2 }\ncompile { h1 -> h2 icmp }\n",
            "replace 'HOST' with 'host'",
        ),
        (
            "host h1 { ip 10.0.0.1 }\nhost h2 { ip 10.0.0.2 }\ncompile { h1 -> h2 icmp echo_request }\n",
            "replace 'echo_request' with 'echorequest'",
        ),
        (
            "host h1 { ip 10.0.0.1 }\nhost h2 { ip 10.0.0.2 }\ncompile { h1 -> h2 tcp syn SACK_PERM }\n",
            "replace 'SACK_PERM' with 'sackperm'",
        ),
        (
            "host h1 { ip 10.0.0.1 }\nhost h2 { ip 10.0.0.2 }\ncompile { h1 -> h2 http get host-hdr \"a.com\" }\n",
            "replace 'host-hdr' with 'hosthdr'",
        ),
        (
            "host h1 { ip 10.0.0.1 }\nhost h2 { ip 10.0.0.2 }\nflow f(a, b) { a -> b icmp }\ncompile { loop 2 { f(h1, h2) } }\n",
            "The 'loop' block was removed in FrameAssembly 2.0",
        ),
    ];

    for &(bad_src, expected_hint) in cases {
        let err = parse_program(bad_src).expect_err("must reject non-v2 keyword or loop");
        let help_text = err
            .help()
            .map(|h| h.to_string())
            .unwrap_or_default();
        let combined = format!("{err} | {help_text}");
        assert!(
            combined.contains(expected_hint),
            "expected hint '{expected_hint}' in diagnostic, got: {combined}"
        );
    }
}

/// Verifies `whois` (`TCP/43` RFC 3912) vs `bacnet whois` (`UDP/47808` ASHRAE 135) dispatch and
/// unified `hellotime` handling on `stp` (`u16` ticks) vs `hsrp` (`u8` seconds `0..=255`).
#[test]
fn test_v2_whois_vs_bacnet_whois_and_unified_hellotime() {
    let fasm = r#"
        host h1 { ip 10.0.0.1 mac 00:11:22:33:44:01 }
        host h2 { ip 10.0.0.2 mac 00:11:22:33:44:02 }
        compile {
            h1 -> h2 whois domain "example.com"
            h1 -> h2 bacnet whois objectinstance 100
            h1 -> h2 stp hellotime 512 maxage 5120 forwarddelay 3840
            h1 -> h2 hsrp state 16 group 10 priority 120 hellotime 3 holdtime 10 vip 10.0.0.254
        }
    "#;
    let frames = must_compile(fasm);
    assert_eq!(frames.len(), 4);
    // Frame 0: WHOIS over TCP (proto 6) dstport 43
    assert_eq!(frames[0].0[23], 6);
    assert_eq!(u16::from_be_bytes([frames[0].0[36], frames[0].0[37]]), 43);
    // Frame 1: BACnet Who-Is over UDP (proto 17) dstport 47808 (0xBAC0)
    assert_eq!(frames[1].0[23], 17);
    assert_eq!(u16::from_be_bytes([frames[1].0[36], frames[1].0[37]]), 47808);

    // HSRP hellotime > 255 must be rejected by semantic validation
    let bad_hsrp = r#"
        host h1 { ip 10.0.0.1 }
        host h2 { ip 10.0.0.2 }
        compile {
            h1 -> h2 hsrp group 1 hellotime 300 vip 10.0.0.254
        }
    "#;
    let err = parse_program(bad_hsrp).expect_err("HSRP hellotime > 255 must fail");
    assert!(
        err.to_string().contains("HSRP hellotime 300 out of range (0..=255)"),
        "unexpected error: {err}"
    );
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
            client -> server tls clienthello sni "secure.example.com" wait 5ms
            client <- server tls serverhello wait 2ms
        }
    "#;

    let flow_fasm = r#"
        host client { ip 10.0.0.10 mac 00:1c:73:aa:bb:01 }
        host server { ip 10.0.0.20 mac 00:1c:73:aa:bb:02 }

        flow tls_handshake(c, s) {
            c -> s tcp syn srcport 49152 dstport 443 seq 1000 win 65535 mss 1460 wait 1ms
            c <- s tcp syn ack seq 5000 acknum 1001 win 65535 mss 1460 wait 1ms
            c -> s tcp ack win 65535 wait 1ms
            c -> s tls clienthello sni "secure.example.com" wait 5ms
            c <- s tls serverhello wait 2ms
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

/// Verifies mixing inline `FrameStatement`s with `flow` invocations inside `compile { ... }`,
/// preserving chronological order and shared connection state.
#[test]
fn test_mixing_inline_statements_and_flow_invocations_in_compile() {
    let fasm = r#"
        host h1 { ip 172.16.0.1 mac 00:11:22:33:44:01 }
        host h2 { ip 172.16.0.2 mac 00:11:22:33:44:02 }

        flow ping_exchange(a, b) {
            a -> b icmp echorequest id 0x0042 seq 1 wait 2ms
            a <- b icmp echoreply id 0x0042 seq 1 wait 2ms
        }

        compile {
            h1 -> h2 arp request wait 1ms
            h1 <- h2 arp reply wait 1ms
            ping_exchange(h1, h2)
            h1 -> h2 dns query txid 0xabcd qname "internal.corp" qtype "a" wait 3ms
            ping_exchange(h1, h2)
            ping_exchange(h1, h2)
            ping_exchange(h1, h2)
            h1 <- h2 dns response txid 0xabcd qname "internal.corp" qtype "a" rdata "172.16.0.99" wait 4ms
        }
    "#;

    let frames = must_compile(fasm);
    assert_eq!(frames.len(), 12);
    assert_eq!(&frames[0].0[12..14], &[0x08, 0x06]);
    assert_eq!(&frames[1].0[12..14], &[0x08, 0x06]);
    assert_eq!(frames[2].0[23], 1);
    assert_eq!(frames[3].0[23], 1);
    assert_eq!(frames[4].0[23], 17);
    assert_eq!(u16::from_be_bytes([frames[4].0[36], frames[4].0[37]]), 53);
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
            client -> server http get uri "/test" hosthdr "app.local"
            client <- server tcp ack
            client <- server tcp fin ack
            client -> server tcp fin ack
        }
    "#;

    let frames = must_compile(fasm);
    assert_eq!(frames.len(), 7);

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

    let (sp0, dp0, seq0, ack0, flags0, len0) = tcp_info(&frames[0].0);
    assert_eq!((sp0, dp0, seq0, ack0, flags0, len0), (54321, 8080, 1000, 0, 0x02, 0));

    let (sp1, dp1, seq1, ack1, flags1, len1) = tcp_info(&frames[1].0);
    assert_eq!((sp1, dp1, seq1, ack1, flags1, len1), (8080, 54321, 2000, 1001, 0x12, 0));

    let (sp2, dp2, seq2, ack2, flags2, len2) = tcp_info(&frames[2].0);
    assert_eq!((sp2, dp2, seq2, ack2, flags2, len2), (54321, 8080, 1001, 2001, 0x10, 0));

    let (sp3, dp3, seq3, ack3, flags3, http_len) = tcp_info(&frames[3].0);
    assert_eq!((sp3, dp3, seq3, ack3, flags3), (54321, 8080, 1001, 2001, 0x18));
    assert!(http_len > 0);

    let (sp4, dp4, seq4, ack4, flags4, _) = tcp_info(&frames[4].0);
    assert_eq!((sp4, dp4, seq4, ack4, flags4), (8080, 54321, 2001, 1001 + http_len, 0x10));

    let (sp5, dp5, seq5, ack5, flags5, _) = tcp_info(&frames[5].0);
    assert_eq!((sp5, dp5, seq5, ack5, flags5), (8080, 54321, 2001, 1001 + http_len, 0x11));

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
            id -> type icmp echorequest
            type -> id icmp echoreply
        }

        compile {
            ip -> mac tcp syn srcport 40000 dstport 80
            ttl <- seq tcp syn ack
            ack -> win udp srcport 5000 dstport 5001 payload "hello"
            user <- domain http get uri "/health"
            status -> code icmp echorequest
            id <- type arp request
            version -> ip tcp ack
            ack(ttl, seq)
            status(user, domain)
            version(id, type)
            ack(status, code)
            ack(status, code)
        }
    "#;

    let frames = must_compile(fasm);
    assert_eq!(frames.len(), 17);
}

// ============================================================================
// 3. Optional-`ip` Layer 2 Host Tests
// ============================================================================

/// Verifies that MAC-only `host` declarations (`host h { mac ... }`) compile cleanly across all
/// 8 Layer 2 protocols (`stp`, `lldp`, `lacp`, `eapol`, `vlan`, `qinq`, `mpls`, `arp`) and emit
/// the expected IEEE/RFC wire headers and inner EtherTypes.
#[test]
fn test_mac_only_hosts_across_all_8_layer2_protocols() {
    let fasm = r#"
        host host1 { mac 00:1c:73:00:00:01 }
        host host2 { mac 00-1C-73-00-00-02 }
        host host3 { mac 001c.7300.0003 }

        compile {
            host1 -> host2 stp rootid "32768/00:1c:73:00:00:01" bridgeid "32768/00:1c:73:00:00:01" portid 0x8001 cost 4
            host1 -> host2 stp rstp cost 2000
            host1 -> host2 lldp chassisid "sw1.dc" portid "Ethernet1" ttl 120 sysname "leaf-01"
            host1 -> host2 lacp actorsys 00:1c:73:00:00:01 actorkey 10 actorport 1 partnersys 00:1c:73:00:00:02 partnerkey 10 partnerport 1
            host1 -> host2 eapol version 2 type eappacket eapcode 1 eapid 7 eapmethod 1 identity "alice@corp"
            host1 -> host2 vlan 150 pcp 6 dei 1 payload "l2-vlan-default"
            host1 -> host2 vlan 200 ethertype 0x88f7 hexpayload "0002002c"
            host1 -> host3 qinq 1000 innervlan 250 payload "l2-qinq-payload"
            host2 -> host3 mpls 104857 exp 5 bos 1 mplsttl 64 payload "mpls-l2-circuit"
            host1 -> host2 arp request senderip 192.168.1.1 targetip 192.168.1.2
            host1 <- host2 arp reply senderip 192.168.1.2 targetip 192.168.1.1
        }
    "#;

    let frames = must_compile(fasm);
    assert_eq!(frames.len(), 11);

    assert_eq!(&frames[0].0[0..6], &[0x01, 0x80, 0xc2, 0x00, 0x00, 0x00]);
    assert_eq!(&frames[0].0[6..12], &[0x00, 0x1c, 0x73, 0x00, 0x00, 0x01]);
    assert_eq!(&frames[0].0[14..17], &[0x42, 0x42, 0x03]);
    assert_eq!(&frames[1].0[14..17], &[0x42, 0x42, 0x03]);

    assert_eq!(&frames[2].0[0..6], &[0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e]);
    assert_eq!(&frames[2].0[12..14], &[0x88, 0xcc]);

    assert_eq!(&frames[3].0[0..6], &[0x01, 0x80, 0xc2, 0x00, 0x00, 0x02]);
    assert_eq!(&frames[3].0[12..14], &[0x88, 0x09]);

    assert_eq!(&frames[4].0[0..6], &[0x01, 0x80, 0xc2, 0x00, 0x00, 0x03]);
    assert_eq!(&frames[4].0[12..14], &[0x88, 0x8e]);

    assert_eq!(&frames[5].0[12..14], &[0x81, 0x00]);
    assert_eq!(&frames[5].0[16..18], &[0x88, 0xb5]);

    assert_eq!(&frames[6].0[12..14], &[0x81, 0x00]);
    assert_eq!(&frames[6].0[16..18], &[0x88, 0xf7]);

    assert_eq!(&frames[7].0[12..14], &[0x88, 0xa8]);
    assert_eq!(&frames[7].0[16..18], &[0x81, 0x00]);
    assert_eq!(&frames[7].0[20..22], &[0x88, 0xb5]);
    assert_eq!(&frames[7].0[0..6], &[0x00, 0x1c, 0x73, 0x00, 0x00, 0x03]);

    assert_eq!(&frames[8].0[12..14], &[0x88, 0x47]);

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
/// used with Layer 3, Layer 4, or Layer 7 IP-requiring protocols.
#[test]
fn test_mac_only_host_rejected_for_l3_l4_l7_ip_requiring_protocols() {
    let protocols = [
        "icmp echorequest",
        "ospf hello",
        "tcp syn",
        "udp dstport 9999",
        "sctp init",
        "dns query qname \"example.com\"",
        "http get uri \"/\"",
        "snmp3 trap user \"admin\"",
    ];

    for proto_stmt in protocols {
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
// 4. v2.0.0 Default-Compile + 4-Subcommand CLI Contract & Safety Guard Tests
// ============================================================================

/// Returns the path to the compiled `frameassembly` binary under test.
fn cli_binary_path() -> &'static str {
    env!("CARGO_BIN_EXE_frameassembly")
}

/// Verifies `frameassembly <example.fasm>` (default `<example>.pcap`),
/// `frameassembly <other.fasm> <custom.pcap>` (positional output), the 4 subcommands (`show`,
/// `reverse`, `help`, `version`), hidden `-h`/`--help` and `-V`/`--version`, and helpful error
/// hints on `-o`, bare `.pcap`, an accidental `compile` subcommand token, and `.fasm` output paths.
#[test]
fn test_cli_default_compile_subcommands_hidden_flags_and_safety_guards() {
    let temp = TempTestDir::new("cli_forward");
    let fasm_path = temp.join("example.fasm");
    let default_pcap_path = temp.join("example.pcap");

    let sample_fasm = "\
host client { ip 10.0.0.1 mac 00:11:22:33:44:01 }
host server { ip 10.0.0.2 mac 00:11:22:33:44:02 }
compile {
    client -> server icmp echorequest id 10 seq 1 wait 5ms
    client <- server icmp echoreply id 10 seq 1 wait 5ms
}
";
    fs::write(&fasm_path, sample_fasm).expect("write example.fasm");

    // 1. Default root compile: `frameassembly <example.fasm>` -> `<example>.pcap`
    let output = Command::new(cli_binary_path())
        .arg(&fasm_path)
        .output()
        .expect("run frameassembly default output");
    assert!(
        output.status.success(),
        "Default CLI compilation failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(default_pcap_path.exists());
    let pcap_bytes = fs::read(&default_pcap_path).expect("read generated example.pcap");
    assert!(pcap_bytes.len() > 28);
    assert_eq!(&pcap_bytes[0..4], &[0x0A, 0x0D, 0x0D, 0x0A]);

    // 2. Explicit positional output: `frameassembly <other.fasm> <custom.pcap>`
    let other_fasm_path = temp.join("other.fasm");
    let other_default_pcap = temp.join("other.pcap");
    let custom_pcap_path = temp.join("custom_out.pcap");
    fs::write(&other_fasm_path, sample_fasm).expect("write other.fasm");

    let output_custom = Command::new(cli_binary_path())
        .arg(&other_fasm_path)
        .arg(&custom_pcap_path)
        .output()
        .expect("run frameassembly other.fasm custom_out.pcap");
    assert!(
        output_custom.status.success(),
        "Default CLI custom output failed: {}",
        String::from_utf8_lossy(&output_custom.stderr)
    );
    assert!(custom_pcap_path.exists());
    assert!(!other_default_pcap.exists());
    assert_eq!(fs::read(&custom_pcap_path).expect("read custom_out.pcap"), pcap_bytes);

    // 3. `version` subcommand + hidden `-V` and `--version`
    for ver_arg in ["version", "-V", "--version"] {
        let ver_out = Command::new(cli_binary_path())
            .arg(ver_arg)
            .output()
            .expect("run frameassembly version query");
        assert!(ver_out.status.success(), "version query '{ver_arg}' failed");
        assert!(
            String::from_utf8_lossy(&ver_out.stdout).contains("2.0.0"),
            "version query '{ver_arg}' missing 2.0.0"
        );
    }

    // 4. `help` subcommand + hidden `-h` and `--help` (4 subcommands: show, reverse, help, version)
    for help_arg in ["help", "-h", "--help"] {
        let help_out = Command::new(cli_binary_path())
            .arg(help_arg)
            .output()
            .expect("run frameassembly help query");
        assert!(help_out.status.success(), "help query '{help_arg}' failed");
        let help_stdout = String::from_utf8_lossy(&help_out.stdout);
        for sub in ["show", "reverse", "help", "version"] {
            assert!(
                help_stdout.contains(sub),
                "help output for '{help_arg}' missing subcommand '{sub}'"
            );
        }
        assert!(
            !help_stdout.contains("--output") && !help_stdout.contains(" -o"),
            "v2.0.0 help output must not advertise removed -o/--output flags"
        );
    }

    // 5. Rejections with helpful hints: `-o`, bare `.pcap`, accidental `compile` token, `.fasm` as OUTPUT.pcap
    let legacy_o = Command::new(cli_binary_path())
        .arg(&fasm_path)
        .arg("-o")
        .arg(&custom_pcap_path)
        .output()
        .expect("run legacy -o");
    assert!(!legacy_o.status.success());
    let o_stderr = String::from_utf8_lossy(&legacy_o.stderr);
    assert!(o_stderr.contains("frameassembly") && o_stderr.contains("reverse"));

    let bare_pcap = Command::new(cli_binary_path())
        .arg(&default_pcap_path)
        .output()
        .expect("run bare .pcap at arg 1");
    assert!(!bare_pcap.status.success());
    assert!(
        String::from_utf8_lossy(&bare_pcap.stderr).contains("frameassembly reverse"),
        "bare .pcap must suggest 'frameassembly reverse'"
    );
    assert_eq!(fs::read(&default_pcap_path).expect("pcap intact"), pcap_bytes);

    let accidental_compile_sub = Command::new(cli_binary_path())
        .current_dir(temp.path())
        .arg("compile")
        .arg(&fasm_path)
        .output()
        .expect("run accidental compile subcommand");
    assert!(!accidental_compile_sub.status.success());
    let comp_stderr = String::from_utf8_lossy(&accidental_compile_sub.stderr);
    assert!(
        comp_stderr.contains("compile") && comp_stderr.contains("frameassembly"),
        "accidental compile subcommand must print clear guidance, got: {comp_stderr}"
    );
    assert_eq!(fs::read_to_string(&fasm_path).expect("fasm intact"), sample_fasm);

    let protected_fasm = temp.join("protected.fasm");
    fs::write(&protected_fasm, sample_fasm).expect("write protected.fasm");
    let fasm_as_output = Command::new(cli_binary_path())
        .arg(&fasm_path)
        .arg(&protected_fasm)
        .output()
        .expect("run with .fasm passed as OUTPUT.pcap");
    assert!(!fasm_as_output.status.success());
    assert!(
        String::from_utf8_lossy(&fasm_as_output.stderr).contains(".fasm"),
        "passing .fasm as OUTPUT.pcap must warn about .fasm overwrite"
    );
    assert_eq!(
        fs::read_to_string(&protected_fasm).expect("protected.fasm intact"),
        sample_fasm
    );
}

/// Verifies `frameassembly reverse <example.pcap>` (default `<example>.fasm`), positional
/// `<custom.fasm>`, recompilation via default root `frameassembly`, and `.pcapng` stem replacement.
#[test]
fn test_cli_reverse_default_stem_pcap_and_pcapng_roundtrip() {
    let temp = TempTestDir::new("cli_reverse");
    let seed_fasm = temp.join("seed.fasm");
    let example_pcap = temp.join("example.pcap");
    let expected_example_fasm = temp.join("example.fasm");
    let custom_reversed_fasm = temp.join("custom_rev.fasm");
    let recompiled_pcap = temp.join("recompiled.pcap");

    let fasm_code = "\
host h1 { ip 192.168.1.10 mac 00:1c:73:11:22:01 }
host h2 { ip 192.168.1.20 mac 00:1c:73:11:22:02 }
compile {
    h1 -> h2 dns query txid 0x2a3b qname \"example.org\" qtype \"a\" wait 10ms
    h1 <- h2 dns response txid 0x2a3b qname \"example.org\" qtype \"a\" rdata \"93.184.216.34\" wait 5ms
}
";
    fs::write(&seed_fasm, fasm_code).expect("write seed.fasm");

    let compile_out = Command::new(cli_binary_path())
        .arg(&seed_fasm)
        .arg(&example_pcap)
        .output()
        .expect("compile seed.fasm to example.pcap");
    assert!(compile_out.status.success());
    assert!(example_pcap.exists());

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
    assert!(expected_example_fasm.exists());

    let rev_custom_out = Command::new(cli_binary_path())
        .arg("reverse")
        .arg(&example_pcap)
        .arg(&custom_reversed_fasm)
        .output()
        .expect("reverse example.pcap custom_rev.fasm");
    assert!(rev_custom_out.status.success());
    assert_eq!(
        fs::read_to_string(&custom_reversed_fasm).expect("read custom_rev.fasm"),
        fs::read_to_string(&expected_example_fasm).expect("read example.fasm")
    );

    let recompile_out = Command::new(cli_binary_path())
        .arg(&expected_example_fasm)
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

    let trace_pcapng = temp.join("trace.pcapng");
    let expected_trace_fasm = temp.join("trace.fasm");
    fs::copy(&example_pcap, &trace_pcapng).expect("copy to trace.pcapng");

    let rev_pcapng_out = Command::new(cli_binary_path())
        .arg("reverse")
        .arg(&trace_pcapng)
        .output()
        .expect("reverse trace.pcapng");
    assert!(rev_pcapng_out.status.success());
    assert!(expected_trace_fasm.exists());
}

/// Verifies CLI collision guards so extensionless inputs on root compilation and `.fasm`-named
/// captures on `reverse` never overwrite the input file in place.
#[test]
fn test_cli_collision_guard_never_overwrites_input_file() {
    let temp = TempTestDir::new("cli_collision");

    let spec_no_ext = temp.join("spec_without_ext");
    let expected_spec_pcap = temp.join("spec_without_ext.pcap");
    let original_fasm_text = "\
host a { ip 10.0.0.1 mac 00:11:22:33:44:01 }
host b { ip 10.0.0.2 mac 00:11:22:33:44:02 }
compile {
    a -> b udp srcport 1234 dstport 5678 payload \"safe\"
}
";
    fs::write(&spec_no_ext, original_fasm_text).expect("write spec_without_ext");

    let fwd_out = Command::new(cli_binary_path())
        .arg(&spec_no_ext)
        .output()
        .expect("compile spec_without_ext");
    assert!(
        fwd_out.status.success(),
        "forward collision test failed: {}",
        String::from_utf8_lossy(&fwd_out.stderr)
    );
    assert!(expected_spec_pcap.exists());
    assert_eq!(
        fs::read_to_string(&spec_no_ext).expect("read original spec_without_ext"),
        original_fasm_text
    );

    let pcap_named_fasm = temp.join("capture_named.fasm");
    let expected_double_fasm = temp.join("capture_named.fasm.fasm");
    let original_pcap_bytes = fs::read(&expected_spec_pcap).expect("read binary pcap bytes");
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
    assert!(expected_double_fasm.exists());
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
    sw1 -> sw2 lldp chassisid \"sw1\" portid \"Eth1\" wait 5ms
    sw1 <- sw2 lldp chassisid \"sw2\" portid \"Eth2\" wait 5ms
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
