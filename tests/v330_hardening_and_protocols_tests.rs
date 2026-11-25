//! Integration and wire-verification suite for FrameAssembly v3.3.0 language hardening, CLI
//! streaming, deferred semantic validation bounds, strict lowercase diagnostic keys, and key
//! new Layer 2, Layer 3, and Layer 7 protocol builders and reverse decompilers.
//!
//! Covers Wave 1 through Wave 3 deliverables: stdin/stdout `-` CLI piping for forward compile,
//! `show`, and `reverse`; `repeat <n> { ... }` loops and cumulative `wait` timing; IEEE 802.3
//! `fcs`/`badfcs` trailers, PCAPNG `comment` options, IPv4/IPv6 `routeralert`, `badipchecksum`,
//! TCP `sackperm`/`sackblock`/`tcpmd5`/`tfo` options, SCTP `sack`, UTF-8 BOM, multiline
//! `hexpayload`, EOF `//` comments, strict `[a-z0-9]+` diagnostic labels, deferred width bounds,
//! and wire/dissection checks across the flagship new Layer 2, Layer 3, and Layer 7 protocols.

/// Enclosing test module scoped to Rust `1.100.0` Clippy MSRV for [`core::mem::DropGuard`].
#[clippy::msrv = "1.100.0"]
mod suite {
use std::fs;
use std::io::Write as _;
use std::mem::DropGuard;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

use frameassembly::backend::{compile_program, compile_program_with_metadata};
use frameassembly::error::CompilerError;
use frameassembly::packet::ieee8023_crc32;
use frameassembly::parser::{parse_program, validate_semantics};
use frameassembly::pcap::serialize_pcapng_with_metadata;
use frameassembly::reverse::reverse_pcap_bytes;

/// Removes a temporary file created by a test when the owning [`DropGuard`] drops.
fn remove_temp_path(path: PathBuf) {
    let _ = fs::remove_file(&path);
}

/// Allocates a unique temporary file path in `std::env::temp_dir()` wrapped in [`DropGuard`].
fn guarded_temp_path(ext: &str) -> DropGuard<PathBuf, fn(PathBuf)> {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let id = COUNTER.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!(
        "frameassembly_v330_{}_{}.{}",
        std::process::id(),
        id,
        ext
    ));
    DropGuard::new(path, remove_temp_path)
}

/// Returns the path to the Cargo-built `frameassembly` binary under test.
fn frameassembly_bin() -> &'static str {
    env!("CARGO_BIN_EXE_frameassembly")
}

/// Spawns `frameassembly` with `args`, feeds `stdin_bytes`, and collects captured stdout, stderr, and status.
fn run_cli_with_stdin(args: &[&str], stdin_bytes: &[u8]) -> std::process::Output {
    let mut child = Command::new(frameassembly_bin())
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn frameassembly CLI");
    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(stdin_bytes)
            .expect("write stdin payload to frameassembly");
    }
    child
        .wait_with_output()
        .expect("wait for frameassembly CLI output")
}

/// Parses, validates, and compiles a `.frasm` program into wire frames and timestamps.
fn compile_frames(src: &str) -> Vec<(Vec<u8>, u64)> {
    let prog = parse_program(src).unwrap_or_else(|e| panic!("parse failed: {e}\n{src}"));
    validate_semantics(&prog, src).unwrap_or_else(|e| panic!("semantic check failed: {e}\n{src}"));
    compile_program(&prog).unwrap_or_else(|e| panic!("compile failed: {e}\n{src}"))
}

/// Parses and returns the semantic or parse/lex error string for an invalid `.frasm` program.
fn parse_err_string(src: &str) -> String {
    let err = parse_program(src).expect_err("expected parse_program to reject invalid input");
    err.to_string()
}

// ============================================================================
// 1. CLI Stdin/Stdout (`-`) Streaming Across Compile, Show, and Reverse
// ============================================================================

/// Verifies `frameassembly -`, `- -`, `<in> -`, `- <out.pcap>`, `show -`, and `reverse -`
/// streaming workflows without leaving temporary artifacts on disk.
#[test]
fn test_cli_stdin_stdout_dash_streaming_pipeline() {
    let sample_frasm = "\
host client { ip 10.77.0.1 mac 00:11:22:33:44:01 }
host server { ip 10.77.0.2 mac 00:11:22:33:44:02 }
compile {
    client -> server dns query txid 0x4242 qname \"stream.local\" qtype \"a\" wait 5ms
    client <- server dns response txid 0x4242 qname \"stream.local\" qtype \"a\" rdata \"10.77.0.99\"
}
";

    // 1. `frameassembly -` writes PCAPNG to stdout and metadata summary to stderr
    let out_dash = run_cli_with_stdin(&["-"], sample_frasm.as_bytes());
    assert!(
        out_dash.status.success(),
        "frameassembly - failed: {}",
        String::from_utf8_lossy(&out_dash.stderr)
    );
    assert!(
        out_dash.stdout.len() > 28 && out_dash.stdout[0..4] == [0x0A, 0x0D, 0x0D, 0x0A],
        "frameassembly - stdout must emit PCAPNG magic"
    );
    let err_dash = String::from_utf8_lossy(&out_dash.stderr);
    assert!(
        err_dash.contains("Wrote <stdout>") && err_dash.contains("pcapng"),
        "expected <stdout> summary on stderr, got: {err_dash}"
    );

    // 2. `frameassembly - -` behaves identically
    let out_dash_dash = run_cli_with_stdin(&["-", "-"], sample_frasm.as_bytes());
    assert!(out_dash_dash.status.success());
    assert_eq!(out_dash_dash.stdout, out_dash.stdout);

    // 3. `frameassembly <file.frasm> -` compiles from disk directly to PCAPNG stdout
    let in_frasm = guarded_temp_path("frasm");
    fs::write(&*in_frasm, sample_frasm).expect("write input frasm");
    let in_frasm_str = in_frasm.to_str().expect("utf-8 temp path");
    let out_file_to_stdout = Command::new(frameassembly_bin())
        .args([in_frasm_str, "-"])
        .output()
        .expect("run frameassembly <in.frasm> -");
    assert!(out_file_to_stdout.status.success());
    assert_eq!(out_file_to_stdout.stdout, out_dash.stdout);

    // 4. `frameassembly - <out.pcap>` compiles stdin to classic libpcap file
    let out_pcap = guarded_temp_path("pcap");
    let out_pcap_str = out_pcap.to_str().expect("utf-8 temp path");
    let out_stdin_to_file = run_cli_with_stdin(&["-", out_pcap_str], sample_frasm.as_bytes());
    assert!(out_stdin_to_file.status.success());
    let classic_bytes = fs::read(&*out_pcap).expect("read classic pcap");
    assert!(
        classic_bytes[0..4] == [0xd4, 0xc3, 0xb2, 0xa1]
            || classic_bytes[0..4] == [0xa1, 0xb2, 0xc3, 0xd4],
        "expected classic libpcap magic"
    );

    // 5. Overwrite guard rejects `.frasm` output path even when reading stdin `-`
    let bad_guard = run_cli_with_stdin(&["-", in_frasm_str], sample_frasm.as_bytes());
    assert!(!bad_guard.status.success());
    assert!(String::from_utf8_lossy(&bad_guard.stderr).contains("Refusing to write binary PCAP"));

    // 6. `show -` accepts both `.frasm` source and binary PCAPNG on stdin
    let show_frasm = run_cli_with_stdin(&["show", "-"], sample_frasm.as_bytes());
    assert!(show_frasm.status.success());
    let ladder_from_src = String::from_utf8_lossy(&show_frasm.stdout);
    assert!(
        ladder_from_src.contains("DNS") && ladder_from_src.contains("5.000"),
        "show - from .frasm missing DNS / 5.000ms row:\n{ladder_from_src}"
    );

    let show_pcapng = run_cli_with_stdin(&["show", "-"], &out_dash.stdout);
    assert!(show_pcapng.status.success());
    let ladder_from_cap = String::from_utf8_lossy(&show_pcapng.stdout);
    assert!(
        ladder_from_cap.contains("DNS") && ladder_from_cap.contains("5.000"),
        "show - from PCAPNG missing DNS / 5.000ms row:\n{ladder_from_cap}"
    );

    // 7. `reverse -`, `reverse - <out.frasm>`, and `reverse <in.pcapng> -`
    let rev_stdout = run_cli_with_stdin(&["reverse", "-"], &out_dash.stdout);
    assert!(rev_stdout.status.success());
    let reversed_text = String::from_utf8_lossy(&rev_stdout.stdout);
    assert!(reversed_text.contains("dns query") && reversed_text.contains("stream.local"));
    assert!(String::from_utf8_lossy(&rev_stdout.stderr).contains("Wrote <stdout>"));

    let rev_out_file = guarded_temp_path("frasm");
    let rev_out_str = rev_out_file.to_str().expect("utf-8 temp path");
    let rev_to_file = run_cli_with_stdin(&["reverse", "-", rev_out_str], &out_dash.stdout);
    assert!(rev_to_file.status.success());
    assert_eq!(
        fs::read_to_string(&*rev_out_file).expect("read reversed frasm"),
        reversed_text
    );

    let in_pcapng = guarded_temp_path("pcapng");
    fs::write(&*in_pcapng, &out_dash.stdout).expect("write input pcapng");
    let in_pcapng_str = in_pcapng.to_str().expect("utf-8 temp path");
    let rev_file_to_stdout = Command::new(frameassembly_bin())
        .args(["reverse", in_pcapng_str, "-"])
        .output()
        .expect("run frameassembly reverse <in.pcapng> -");
    assert!(rev_file_to_stdout.status.success());
    assert_eq!(
        String::from_utf8_lossy(&rev_file_to_stdout.stdout),
        reversed_text
    );
}

// ============================================================================
// 2. `repeat <n> { ... }`, `wait`, BOM, Multiline `hexpayload`, EOF Comments
// ============================================================================

/// Verifies nested `repeat <n> { ... }`, zero-iteration `repeat 0 { ... }`, cumulative `wait`
/// timestamps, sequential TCP state, UTF-8 BOM skipping, multiline `hexpayload` statements,
/// unclosed-string rejection, and trailing `//` EOF comments without newlines.
#[test]
fn test_repeat_wait_bom_multiline_hexpayload_and_eof_comments() {
    let repeat_src = "\u{FEFF}\
host c { ip 10.88.0.1 mac 00:11:22:33:44:01 }
host s { ip 10.88.0.2 mac 00:11:22:33:44:02 }
flow burst(x, y) {
    repeat 2 {
        x -> y tcp psh ack payload \"ab\" wait 2ms
    }
}
compile {
    repeat 0 {
        c -> s arp
    }
    repeat 2 {
        burst(c, s)
    }
    c -> s udp srcport 4000 dstport 5000
        hexpayload \"de ad:be ef\" wait 1s
}
// trailing EOF comment without newline";

    let frames = compile_frames(repeat_src);
    assert_eq!(frames.len(), 5, "expected 4 repeated TCP frames + 1 UDP frame");

    // Check sequential TCP sequence progression (1000, 1002, 1004, 1006)
    for (idx, (raw, _)) in frames[..4].iter().enumerate() {
        let seq = u32::from_be_bytes([raw[38], raw[39], raw[40], raw[41]]);
        assert_eq!(seq, 1000 + (idx as u32) * 2, "TCP seq mismatch on iter {idx}");
    }
    // Check cumulative 2ms timestamps across all 4 TCP frames before 1s wait on frame 4
    let t0 = frames[0].1;
    assert_eq!(frames[1].1 - t0, 2_000_000);
    assert_eq!(frames[2].1 - t0, 4_000_000);
    assert_eq!(frames[3].1 - t0, 6_000_000);
    assert_eq!(frames[4].1 - t0, 8_000_000);

    // Check multiline UDP `hexpayload` statement wire bytes
    assert_eq!(&frames[4].0[42..], &[0xDE, 0xAD, 0xBE, 0xEF]);

    // Check inline comment directly at EOF with no trailing newline
    let inline_eof = "host a { ip 10.0.0.1 }\nhost b { ip 10.0.0.2 }\ncompile { a -> b icmp } // eof";
    assert_eq!(compile_frames(inline_eof).len(), 1);

    // Unclosed newline inside quoted hexpayload fails cleanly with lex diagnostic
    let unclosed = "host a { ip 10.0.0.1 }\nhost b { ip 10.0.0.2 }\ncompile { a -> b udp hexpayload \"dead\nbeef\" }";
    let err = parse_program(unclosed).unwrap_err();
    assert!(matches!(err, CompilerError::LexError { .. }));
}

// ============================================================================
// 3. L2/L3/L4 Wire Hardening: `fcs`/`badfcs`, `comment`, `routeralert`, TCP Opts
// ============================================================================

/// Verifies `fcs`/`badfcs` CRC-32 trailers, PCAPNG `comment` option round-tripping, IPv4 and IPv6
/// `routeralert` options, `badipchecksum` behavior and IPv6 guard, and TCP `sackperm` / `sackblock` /
/// `tcpmd5` / `tfo` options plus SCTP `sack` chunk wire encoding.
#[test]
fn test_fcs_comment_routeralert_badipchecksum_and_tcp_sctp_options() {
    let src = r#"
        host c4 { ip 10.90.0.1 mac 00:11:22:33:44:01 }
        host s4 { ip 10.90.0.2 mac 00:11:22:33:44:02 }
        host c6 { ip 2001:db8:90::1 mac 00:11:22:33:44:11 }
        host s6 { ip 2001:db8:90::2 mac 00:11:22:33:44:12 }
        compile {
            c4 -> s4 udp payload "goodfcs" fcs comment "valid crc step"
            c4 -> s4 udp payload "corrupt" badfcs routeralert badipchecksum
            c6 -> s6 udp payload "v6alert" routeralert
            c4 -> s4 tcp syn sackperm mss 1460 wscale 7 sackblock 100 200 tcpmd5 "00112233445566778899aabbccddeeff"
            c4 -> s4 tcp syn tfo "0102030405060708"
            c4 -> s4 sctp sack vtag 0x11223344
        }
    "#;
    let prog = parse_program(src).expect("parse hardening program");
    validate_semantics(&prog, src).expect("validate hardening program");
    let (compiled, hosts) = compile_program_with_metadata(&prog).expect("compile with metadata");
    assert_eq!(compiled.len(), 6);

    // Frame 0: valid trailing IEEE 802.3 CRC-32 + PCAPNG `comment`
    let f0 = &compiled[0].data;
    let crc0 = ieee8023_crc32(&f0[..f0.len() - 4]);
    assert_eq!(f0[f0.len() - 4..], crc0.to_le_bytes());
    assert_eq!(compiled[0].comment.as_deref(), Some("valid crc step"));

    // Roundtrip PCAPNG with comment + fcs preserves `comment` and `fcs`
    let raw_meta = vec![(
        compiled[0].data.clone(),
        compiled[0].timestamp_ns,
        compiled[0].comment.clone(),
    )];
    let pcapng_with_comment =
        serialize_pcapng_with_metadata(&raw_meta, &hosts).expect("serialize pcapng with comment");
    let rev_comment = reverse_pcap_bytes(&pcapng_with_comment).expect("reverse pcapng with comment");
    assert!(
        rev_comment.fasm.contains("fcs") && rev_comment.fasm.contains("comment \"valid crc step\""),
        "expected fcs and comment in reversed .frasm:\n{}",
        rev_comment.fasm
    );

    // Frame 1: `badfcs` (^ 0xFFFF_FFFF) + IPv4 `routeralert` (IHL=6 -> 0x46, opt [0x94,0x04,0x00,0x00]) + `badipchecksum`
    let f1 = &compiled[1].data;
    let crc1 = ieee8023_crc32(&f1[..f1.len() - 4]);
    assert_eq!(f1[f1.len() - 4..], (crc1 ^ 0xFFFF_FFFF).to_le_bytes());
    assert_eq!(f1[14], 0x46, "expected IPv4 version 4 + IHL 6 (24 bytes)");
    assert_eq!(&f1[34..38], &[0x94, 0x04, 0x00, 0x00]);
    let badfcs_pcapng = serialize_pcapng_with_metadata(
        &[(f1.clone(), compiled[1].timestamp_ns, None)],
        &hosts,
    )
    .expect("serialize badfcs/routeralert pcapng");
    let rev_badfcs = reverse_pcap_bytes(&badfcs_pcapng).expect("reverse badfcs/routeralert");
    assert!(
        rev_badfcs.fasm.contains("badfcs") && rev_badfcs.fasm.contains("routeralert"),
        "expected badfcs + routeralert in reversed .frasm:\n{}",
        rev_badfcs.fasm
    );

    // Frame 2: IPv6 Hop-by-Hop Router Alert (NextHeader 0 -> [17, 0x00, 0x05, 0x02, 0, 0, 1, 0])
    let f2 = &compiled[2].data;
    assert_eq!(f2[20], 0, "expected IPv6 Next Header 0 (Hop-by-Hop)");
    assert_eq!(&f2[54..62], &[17, 0x00, 0x05, 0x02, 0x00, 0x00, 0x01, 0x00]);

    // Frame 3: TCP options (MSS Kind 2, SACK-Perm Kind 4, WScale Kind 3, SACK Block Kind 5, MD5 Kind 19)
    let f3 = &compiled[3].data;
    let tcp_doff3 = usize::from(f3[46] >> 4) * 4;
    assert!(tcp_doff3 > 20 && tcp_doff3 <= 60);
    let opts3 = &f3[54..34 + tcp_doff3];
    assert!(opts3.windows(4).any(|w| w == [2, 4, 0x05, 0xB4]));
    assert!(opts3.windows(2).any(|w| w == [4, 2]));
    assert!(opts3.windows(10).any(|w| w == [5, 10, 0, 0, 0, 100, 0, 0, 0, 200]));
    assert!(opts3.windows(4).any(|w| w == [19, 18, 0x00, 0x11]));

    // Frame 4: TCP TFO cookie (Kind 34, Len 10)
    let f4 = &compiled[4].data;
    let tcp_doff4 = usize::from(f4[46] >> 4) * 4;
    let opts4 = &f4[54..34 + tcp_doff4];
    assert!(opts4.windows(10).any(|w| w == [34, 10, 1, 2, 3, 4, 5, 6, 7, 8]));

    // Frame 5: SCTP SACK chunk (IP proto 132, chunk type 3)
    let f5 = &compiled[5].data;
    assert_eq!(f5[23], 132);
    assert_eq!(f5[46], 3);

    // TCP options exceeding 40 bytes fail in backend cleanly
    let too_many_opts = r#"
        host a { ip 10.0.0.1 }
        host b { ip 10.0.0.2 }
        compile {
            a -> b tcp syn sackblock 1 2 sackblock 3 4 tcpmd5 "00112233445566778899aabbccddeeff" tfo "0102030405060708"
        }
    "#;
    let prog_over = parse_program(too_many_opts).expect("parse overlong tcp opts");
    assert!(compile_program(&prog_over).is_err());

    // `badipchecksum` on IPv6 fails semantic validation
    let bad_v6_ip_csum = "host a { ip 2001:db8::1 }\nhost b { ip 2001:db8::2 }\ncompile { a -> b badipchecksum udp }";
    assert!(parse_err_string(bad_v6_ip_csum).contains("badipchecksum"));
}

// ============================================================================
// 4. Strict `[a-z0-9]+` Diagnostic Labels & Deferred Bounds Validation
// ============================================================================

/// Verifies strict lowercase diagnostic labels (zero underscores, zero internal prefixes) on
/// duplicate modifier errors and deferred numeric range checks, alongside per-protocol deferred
/// bit-width bounds, `nsh ttl 0..=63`, `srv6` IPv6-only, and `profinet`/`ethercat` UDP IP rules.
#[test]
fn test_strict_lowercase_error_labels_and_deferred_width_bounds() {
    // 1. Duplicate statement modifiers emit canonical lowercase keyword names without prefixes/underscores
    let dup_cases = [
        (
            "host a { mac 00:11:22:33:44:01 }\nhost b { mac 00:11:22:33:44:02 }\ncompile { a -> b cdp nativevlan 10 nativevlan 20 }",
            "Duplicate statement modifier 'nativevlan'",
        ),
        (
            "host a { ip 10.0.0.1 }\nhost b { ip 10.0.0.2 }\ncompile { a -> b diameter originhost \"h1\" originhost \"h2\" }",
            "Duplicate statement modifier 'originhost'",
        ),
        (
            "host a { ip 10.0.0.1 }\nhost b { ip 10.0.0.2 }\ncompile { a -> b ngap amfueid 1 amfueid 2 }",
            "Duplicate statement modifier 'amfueid'",
        ),
        (
            "host a { ip 10.0.0.1 }\nhost b { ip 10.0.0.2 }\ncompile { a -> b bmp peertype 0 peertype 1 }",
            "Duplicate statement modifier 'peertype'",
        ),
    ];
    for (src, expected_msg) in dup_cases {
        let msg = parse_err_string(src);
        assert!(msg.contains(expected_msg), "for `{src}`, got `{msg}`");
        assert!(!msg.contains('_') && !msg.contains("kw"), "leaked raw key: `{msg}`");
    }

    // 2. Deferred u32 / u64 field width bounds (tight vs wide widths per protocol)
    let ok_wide = "\
host a { ip 10.0.0.1 }
host b { ip 10.0.0.2 }
compile {
    a -> b stun bindingrequest txid 70000
    a -> b turn allocate txid 70000
    a -> b mgcp crcx txid 70000
    a -> b smb negotiate status 70000 sessionid 0x0001000000000001
    a -> b ethernetip listidentity status 70000
    a -> b dcerpc fault status 70000
    a -> b memcached get flags 70000
    a -> b mongodb query flags 70000
    a -> b ntlm negotiate flags 70000
    a -> b quic initial version 70000
    a -> b sccp register version 70000
    a -> b opcua msgtype \"MSG\" seqnum 70000 reqid 70000
    a -> b mongodb query reqid 70000
    a -> b ipmi ping seqnum 70000
    a -> b twamp sender seqnum 70000
    a -> b gtpc echorequest seqnum 70000
    a -> b pfcp heartbeatrequest seqnum 70000 recovery 70000
    a -> b rtcp sr seqnum 70000
    a -> b ngap initialuemessage tac 0xFFFFFF
    a -> b s1ap initialuemessage tac 65535
    a -> b nsh ttl 63
}
";
    assert_eq!(compile_frames(ok_wide).len(), 21);

    let out_of_range_cases = [
        // txid u16 on dns/mdns/modbus/doh/hartip
        ("a -> b dns query txid 65536", "txid 65536 out of range"),
        ("a -> b mdns query txid 65536", "txid 65536 out of range"),
        ("a -> b modbus readcoils txid 65536", "txid 65536 out of range"),
        ("a -> b doh query txid 65536", "txid 65536 out of range"),
        ("a -> b hartip init txid 65536", "txid 65536 out of range"),
        // status u16 vs u8
        ("a -> b http get status 65536", "status 65536 out of range"),
        ("a -> b sip invite status 65536", "status 65536 out of range"),
        ("a -> b rtsp options status 65536", "status 65536 out of range"),
        ("a -> b doh response status 65536", "status 65536 out of range"),
        ("a -> b mgcp crcx status 65536", "status 65536 out of range"),
        ("a -> b nvmetcp response status 65536", "status 65536 out of range"),
        ("a -> b gesrtp response status 65536", "status 65536 out of range"),
        ("a -> b iscsi response status 256", "status 256 out of range"),
        ("a -> b ipmi response status 256", "status 256 out of range"),
        ("a -> b twamp reflector status 256", "status 256 out of range"),
        // flags u8 vs u16
        ("a -> b stp flags 256", "flags 256 out of range"),
        ("a -> b ikev2 flags 256", "flags 256 out of range"),
        ("a -> b tacacs authen flags 256", "flags 256 out of range"),
        ("a -> b s7commplus flags 256", "flags 256 out of range"),
        ("a -> b iscsi nop flags 256", "flags 256 out of range"),
        ("a -> b nvmetcp read flags 256", "flags 256 out of range"),
        ("a -> b tns connect flags 65536", "flags 65536 out of range"),
        // value u16
        ("a -> b modbus writesinglecoil value 65536", "value 65536 out of range"),
        ("a -> b fins write value 65536", "value 65536 out of range"),
        ("a -> b melsec write value 65536", "value 65536 out of range"),
        ("a -> b c1222 write value 65536", "value 65536 out of range"),
        // version u8 vs u16
        ("a -> b ipmi ping version 256", "version 256 out of range"),
        ("a -> b tns connect version 65536", "version 65536 out of range"),
        // seqnum u16
        ("a -> b gesrtp read seqnum 65536", "seqnum 65536 out of range"),
        ("a -> b h323 grq seqnum 65536", "seqnum 65536 out of range"),
        // reqid u16
        ("a -> b nvmetcp read reqid 65536", "reqid 65536 out of range"),
        // recovery u8
        ("a -> b gtpc echorequest recovery 256", "recovery 256 out of range"),
        // lun u8 vs u16
        ("a -> b ipmi request lun 256", "lun 256 out of range"),
        ("a -> b iscsi read lun 65536", "lun 65536 out of range"),
        // tac u16 on s1ap vs u24 on ngap
        ("a -> b s1ap initialuemessage tac 65536", "tac 65536 out of range"),
        ("a -> b ngap initialuemessage tac 16777216", "tac 16777216 out of range"),
        // sessionid u32 on tacacs/ipmi/netconf/s7commplus
        ("a -> b tacacs authen sessionid 4294967296", "sessionid 4294967296 out of range"),
        ("a -> b ipmi ping sessionid 4294967296", "sessionid 4294967296 out of range"),
        ("a -> b netconf hello sessionid 4294967296", "sessionid 4294967296 out of range"),
        ("a -> b s7commplus sessionid 4294967296", "sessionid 4294967296 out of range"),
        // nsh ttl 0..=63
        ("a -> b nsh ttl 64", "NSH ttl 64 out of range (0..=63)"),
    ];
    for (stmt, expected) in out_of_range_cases {
        let full = format!("host a {{ ip 10.0.0.1 }}\nhost b {{ ip 10.0.0.2 }}\ncompile {{ {stmt} }}");
        let msg = parse_err_string(&full);
        assert!(msg.contains(expected), "for `{stmt}`, expected `{expected}`, got `{msg}`");
        assert!(!msg.contains('_'), "unexpected underscore in error `{msg}`");
    }

    // 3. `srv6` rejects IPv4 endpoints
    let bad_srv6 = "host a { ip 10.0.0.1 }\nhost b { ip 10.0.0.2 }\ncompile { a -> b srv6 }";
    assert!(parse_err_string(bad_srv6).contains("requires IPv6 endpoints"));

    // 4. `profinet` / `ethercat` permit MAC-only L2, but reject MAC-only endpoints with `transport udp`
    let l2_mac_ok = "\
host sw1 { mac 00:11:22:33:44:01 }
host sw2 { mac 00:11:22:33:44:02 }
compile {
    sw1 -> sw2 profinet
    sw1 -> sw2 ethercat
}
";
    assert_eq!(compile_frames(l2_mac_ok).len(), 2);

    for bad_ot_udp in [
        "host sw1 { mac 00:11:22:33:44:01 }\nhost sw2 { mac 00:11:22:33:44:02 }\ncompile { sw1 -> sw2 profinet transport udp }",
        "host sw1 { mac 00:11:22:33:44:01 }\nhost sw2 { mac 00:11:22:33:44:02 }\ncompile { sw1 -> sw2 ethercat transport udp }",
    ] {
        assert!(parse_err_string(bad_ot_udp).contains("requires an 'ip <address>'"));
    }
}

// ============================================================================
// 5. Key New L2 / L3 / L7 Wire Encoding & Reverse Dissection Checks
// ============================================================================

/// Verifies wire-level headers, ports, EtherTypes, LLC/SNAP framing, SCTP PPIDs, and multicast
/// destination derivation across flagship new L2, L3, and L7 protocols, plus reverse dissection.
#[test]
fn test_key_new_l2_l3_l7_wire_encoding_and_dissection() {
    // --- Layer 2 wire framing & UDP dual-mode (`profinet`, `ethercat`, `pppoe`, `cdp`, `isis`) ---
    let l2_wire_src = r#"
        host p1 { ip 10.95.0.1 mac 00:11:22:33:44:01 }
        host p2 { ip 10.95.0.2 mac 00:11:22:33:44:02 }
        compile {
            p1 -> p2 profinet
            p1 -> p2 profinet transport udp service "connect"
            p1 -> p2 ethercat
            p1 -> p2 ethercat transport udp read
            p1 -> p2 pppoe padi
            p1 -> p2 pppoe session sessionid 7
            p1 -> p2 cdp deviceid "sw-core"
            p1 -> p2 isis
        }
    "#;
    let l2_frames = compile_frames(l2_wire_src);
    assert_eq!(l2_frames.len(), 8);

    // 0: PROFINET L2 EtherType 0x8892
    assert_eq!(&l2_frames[0].0[12..14], &[0x88, 0x92]);
    // 1: PROFINET UDP port 34964
    assert_eq!(l2_frames[1].0[23], 17);
    assert_eq!(u16::from_be_bytes([l2_frames[1].0[36], l2_frames[1].0[37]]), 34964);
    // 2: EtherCAT L2 EtherType 0x88A4
    assert_eq!(&l2_frames[2].0[12..14], &[0x88, 0xA4]);
    // 3: EtherCAT UDP port 34980
    assert_eq!(l2_frames[3].0[23], 17);
    assert_eq!(u16::from_be_bytes([l2_frames[3].0[36], l2_frames[3].0[37]]), 34980);
    // 4: PPPoE Discovery 0x8863; 5: PPPoE Session 0x8864
    assert_eq!(&l2_frames[4].0[12..14], &[0x88, 0x63]);
    assert_eq!(&l2_frames[5].0[12..14], &[0x88, 0x64]);
    // 6: CDP IEEE 802.3 length + LLC/SNAP AA AA 03 00 00 0C 20 00
    assert!(u16::from_be_bytes([l2_frames[6].0[12], l2_frames[6].0[13]]) <= 1500);
    assert_eq!(&l2_frames[6].0[14..22], &[0xAA, 0xAA, 0x03, 0x00, 0x00, 0x0C, 0x20, 0x00]);
    // 7: IS-IS IEEE 802.3 length + LLC FE FE 03 + NLPID 0x83
    assert!(u16::from_be_bytes([l2_frames[7].0[12], l2_frames[7].0[13]]) <= 1500);
    assert_eq!(&l2_frames[7].0[14..18], &[0xFE, 0xFE, 0x03, 0x83]);

    // --- Layer 3 wire checks (`ipip`, `srv6`, `l2tp`, `glbp`) ---
    let l3_wire_src = r#"
        host r1 { ip 10.96.0.1 mac 00:11:22:33:44:01 }
        host r2 { ip 10.96.0.2 mac 00:11:22:33:44:02 }
        host mcast4 { ip 0.0.0.0 }
        host v6a { ip 2001:db8:96::1 mac 00:11:22:33:44:11 }
        host v6b { ip 2001:db8:96::2 mac 00:11:22:33:44:12 }
        compile {
            r1 -> r2 ipip v4
            r1 -> r2 ipip v6
            r1 -> r2 l2tp v3
            r1 -> r2 l2tp transport udp v2 sccrq
            r1 -> mcast4 glbp
            v6a -> v6b srv6 sid 2001:db8:96::10 sid 2001:db8:96::20
        }
    "#;
    let l3_frames = compile_frames(l3_wire_src);
    assert_eq!(l3_frames.len(), 6);

    // `ipip v4` -> outer proto 4; `ipip v6` -> outer proto 41
    assert_eq!(l3_frames[0].0[23], 4);
    assert_eq!(l3_frames[1].0[23], 41);
    // `l2tp v3` -> IP proto 115; `l2tp transport udp v2` -> UDP dst port 1701
    assert_eq!(l3_frames[2].0[23], 115);
    assert_eq!(l3_frames[3].0[23], 17);
    assert_eq!(u16::from_be_bytes([l3_frames[3].0[36], l3_frames[3].0[37]]), 1701);
    // `glbp` multicast 224.0.0.102 + UDP 3222
    assert_eq!(&l3_frames[4].0[30..34], &[224, 0, 0, 102]);
    assert_eq!(u16::from_be_bytes([l3_frames[4].0[36], l3_frames[4].0[37]]), 3222);
    // `srv6` IPv6 Next Header 43, Routing Type 4
    assert_eq!(&l3_frames[5].0[12..14], &[0x86, 0xDD]);
    assert_eq!(l3_frames[5].0[20], 43);
    assert_eq!(l3_frames[5].0[56], 4);

    // --- Layer 7 wire checks (`ngap`, `s1ap`, `diameter` SCTP PPIDs, `llmnr`, `wsdiscovery`, `rocev2`, `h323`) ---
    let l7_wire_src = r#"
        host a4 { ip 10.97.0.1 mac 00:11:22:33:44:01 }
        host b4 { ip 10.97.0.2 mac 00:11:22:33:44:02 }
        host any4 { ip 0.0.0.0 }
        host a6 { ip 2001:db8:97::1 mac 00:11:22:33:44:11 }
        host any6 { ip :: }
        compile {
            a4 -> b4 ngap ngsetuprequest
            a4 -> b4 s1ap s1setuprequest
            a4 -> b4 diameter transport sctp cer
            a4 -> any4 llmnr query qname "nas01"
            a6 -> any6 llmnr query qname "nas01"
            a4 -> b4 llmnr transport tcp query qname "nas01"
            a4 -> any4 wsdiscovery probe
            a4 -> b4 rocev2 read
            a4 -> b4 h323 setup
            a4 -> b4 h323 grq
        }
    "#;
    let l7_frames = compile_frames(l7_wire_src);
    assert_eq!(l7_frames.len(), 10);

    // 0..=2: SCTP PPIDs 60 (NGAP), 18 (S1AP), 46 (Diameter) at byte offset 34 + 24 = 58..62
    assert_eq!(l7_frames[0].0[23], 132);
    assert_eq!(u32::from_be_bytes([l7_frames[0].0[58], l7_frames[0].0[59], l7_frames[0].0[60], l7_frames[0].0[61]]), 60);
    assert_eq!(u16::from_be_bytes([l7_frames[0].0[36], l7_frames[0].0[37]]), 38412);

    assert_eq!(l7_frames[1].0[23], 132);
    assert_eq!(u32::from_be_bytes([l7_frames[1].0[58], l7_frames[1].0[59], l7_frames[1].0[60], l7_frames[1].0[61]]), 18);
    assert_eq!(u16::from_be_bytes([l7_frames[1].0[36], l7_frames[1].0[37]]), 36412);

    assert_eq!(l7_frames[2].0[23], 132);
    assert_eq!(u32::from_be_bytes([l7_frames[2].0[58], l7_frames[2].0[59], l7_frames[2].0[60], l7_frames[2].0[61]]), 46);
    assert_eq!(u16::from_be_bytes([l7_frames[2].0[36], l7_frames[2].0[37]]), 3868);

    // 3..=5: LLMNR UDP multicast 224.0.0.252, IPv6 ff02::1:3, and TCP port 5355
    assert_eq!(l7_frames[3].0[23], 17);
    assert_eq!(&l7_frames[3].0[30..34], &[224, 0, 0, 252]);
    assert_eq!(u16::from_be_bytes([l7_frames[3].0[36], l7_frames[3].0[37]]), 5355);

    assert_eq!(l7_frames[4].0[20], 17);
    assert_eq!(
        &l7_frames[4].0[38..54],
        &[0xFF, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 3]
    );
    assert_eq!(u16::from_be_bytes([l7_frames[4].0[56], l7_frames[4].0[57]]), 5355);

    assert_eq!(l7_frames[5].0[23], 6);
    assert_eq!(u16::from_be_bytes([l7_frames[5].0[36], l7_frames[5].0[37]]), 5355);

    // 6: WS-Discovery multicast 239.255.255.250 UDP 3702
    assert_eq!(&l7_frames[6].0[30..34], &[239, 255, 255, 250]);
    assert_eq!(u16::from_be_bytes([l7_frames[6].0[36], l7_frames[6].0[37]]), 3702);

    // 7: RoCEv2 UDP port 4791 + non-zero 4-byte ICRC trailer
    assert_eq!(u16::from_be_bytes([l7_frames[7].0[36], l7_frames[7].0[37]]), 4791);
    assert!(l7_frames[7].0.len() >= 42 + 12 + 4);

    // 8..=9: H.323 Setup (TCP 1720, TPKT 0x03 0x00) vs GRQ RAS (UDP 1719)
    assert_eq!(l7_frames[8].0[23], 6);
    assert_eq!(u16::from_be_bytes([l7_frames[8].0[36], l7_frames[8].0[37]]), 1720);
    assert_eq!(&l7_frames[8].0[54..56], &[0x03, 0x00]);
    assert_eq!(l7_frames[9].0[23], 17);
    assert_eq!(u16::from_be_bytes([l7_frames[9].0[36], l7_frames[9].0[37]]), 1719);

    // Reverse dissect combined capture frames and ensure every key protocol recovers without `hexpayload`
    let meta_l7: Vec<(Vec<u8>, u64, Option<String>)> =
        l7_frames.into_iter().map(|(d, ts)| (d, ts, None)).collect();
    let pcapng_l7 = serialize_pcapng_with_metadata(&meta_l7, &[]).expect("serialize l7 pcapng");
    let rev_l7 = reverse_pcap_bytes(&pcapng_l7).expect("reverse key l7 frames");
    for kw in ["ngap", "s1ap", "diameter", "llmnr", "wsdiscovery", "rocev2", "h323"] {
        assert!(
            rev_l7.fasm.contains(kw),
            "missing '{kw}' in reversed L7 output:\n{}",
            rev_l7.fasm
        );
    }
    assert!(!rev_l7.fasm.contains("hexpayload"), "unexpected hexpayload:\n{}", rev_l7.fasm);
}
}
