//! Command-line interface entry point for the FrameAssembly network packet compiler.
//!
//! Compiling `.fasm` network traffic code to `.pcap` / `.pcapng` is the default root command,
//! paired with four subcommands across 81 Layer 2 through Layer 7 protocols:
//! - `frameassembly <input.fasm> [output.pcap]` validates `.fasm` code and writes a
//!   nanosecond-precision `.pcapng` capture file (defaulting to `<input_stem>.pcap`).
//! - `frameassembly show <input.fasm>` validates `.fasm` code and prints a relative-timestamp
//!   packet ladder table to standard output without writing a capture file to disk.
//! - `frameassembly reverse <input.pcap> [output.fasm]` reverses a `.pcap` or `.pcapng` capture
//!   file into `.fasm` code (defaulting to `<input_stem>.fasm`).
//! - `frameassembly version` prints the active `frameassembly` binary version.
//! - `frameassembly help [subcommand]` displays command usage and subcommand reference text.

use clap::builder::PathBufValueParser;
use clap::builder::styling::{AnsiColor, Effects, Styles};
use clap::{Arg, ArgAction, Command, ValueHint};
use frameassembly::backend::{compile_program, generate_pcap};
use frameassembly::parser::parse_program;
use frameassembly::reverse::reverse_pcap_file;
use miette::{IntoDiagnostic, NamedSource, Result};
use std::ffi::{OsStr, OsString};
use std::fmt::Write as _;
use std::fs;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};

/// Nine-role `anstyle` terminal color palette used by `clap` help and usage diagnostics.
const CLI_STYLES: Styles = Styles::styled()
    .header(AnsiColor::Green.on_default().effects(Effects::BOLD))
    .usage(AnsiColor::Green.on_default().effects(Effects::BOLD))
    .literal(AnsiColor::Cyan.on_default().effects(Effects::BOLD))
    .placeholder(AnsiColor::Cyan.on_default())
    .error(AnsiColor::Red.on_default().effects(Effects::BOLD))
    .valid(AnsiColor::Green.on_default().effects(Effects::BOLD))
    .invalid(AnsiColor::Yellow.on_default().effects(Effects::BOLD))
    .context(AnsiColor::BrightBlack.on_default())
    .context_value(AnsiColor::Cyan.on_default());

/// Canonical top-level subcommands exposed by FrameAssembly 2.0.
const SUBCOMMANDS: [&str; 4] = ["show", "reverse", "version", "help"];

/// Derives the default output path from `input` by replacing its extension with `default_ext`,
/// or appending `.default_ext` when `input` already ends with `default_ext` so the input file
/// is never overwritten in place.
fn derive_default_output_path(input: &Path, default_ext: &str) -> PathBuf {
    let has_same_ext = input
        .extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| e.eq_ignore_ascii_case(default_ext));
    if has_same_ext {
        let mut os = input.as_os_str().to_os_string();
        os.push(".");
        os.push(default_ext);
        PathBuf::from(os)
    } else {
        let candidate = input.with_extension(default_ext);
        if candidate == input {
            let mut os = input.as_os_str().to_os_string();
            os.push(".");
            os.push(default_ext);
            PathBuf::from(os)
        } else {
            candidate
        }
    }
}

/// Checks raw CLI arguments for legacy or invalid invocation patterns (`-o` / `--output`,
/// `--show` / `--reverse`, bare `.pcap` / `.pcapng` paths, removed `compile` subcommand, or
/// `.fasm` passed as `OUTPUT.pcap`) and returns a clear migration or safety hint.
fn check_legacy_cli_args<I, T>(args: I) -> std::result::Result<(), String>
where
    I: IntoIterator<Item = T>,
    T: AsRef<OsStr>,
{
    let collected: Vec<OsString> = args
        .into_iter()
        .map(|a| a.as_ref().to_os_string())
        .collect();
    if collected.len() <= 1 {
        return Ok(());
    }

    let mut positional: Vec<String> = Vec::new();
    let mut after_double_dash = false;
    for arg in &collected[1..] {
        let s = arg.to_string_lossy();
        if !after_double_dash {
            if s == "--" {
                after_double_dash = true;
                continue;
            }
            if s == "-o"
                || s == "--output"
                || s.starts_with("--output=")
                || (s.starts_with("-o") && s.len() > 2 && !s.starts_with("--"))
            {
                return Err(
                    "The '-o' / '--output' flag was replaced by an optional second positional path in FrameAssembly 2.0.\n  Compile: frameassembly <in.fasm> [out.pcap]\n  Reverse: frameassembly reverse <in.pcap> [out.fasm]"
                        .to_string(),
                );
            }
            if s == "--show" || s.starts_with("--show=") {
                return Err(
                    "The '--show' flag is not supported; use the 'show' subcommand instead:\n  frameassembly show <in.fasm>"
                        .to_string(),
                );
            }
            if s == "--reverse" || s.starts_with("--reverse=") {
                return Err(
                    "The '--reverse' flag is not supported; use the 'reverse' subcommand instead:\n  frameassembly reverse <in.pcap> [out.fasm]"
                        .to_string(),
                );
            }
            if s.starts_with('-') {
                continue;
            }
        }
        positional.push(s.into_owned());
    }

    let Some(arg1) = positional.first() else {
        return Ok(());
    };

    if !after_double_dash && arg1 == "compile" && !Path::new("compile").is_file() {
        return Err(
            "Compiling is the default command in FrameAssembly 2.0 (there is no 'compile' subcommand); run:\n  frameassembly <in.fasm> [out.pcap]"
                .to_string(),
        );
    }

    if after_double_dash || !SUBCOMMANDS.contains(&arg1.as_str()) {
        let lower = arg1.to_ascii_lowercase();
        if lower.ends_with(".pcap") || lower.ends_with(".pcapng") {
            return Err(format!(
                "Direct capture invocation is not supported; use the 'reverse' subcommand instead:\n  frameassembly reverse {arg1}"
            ));
        }
        if let Some(arg2) = positional.get(1)
            && arg2.to_ascii_lowercase().ends_with(".fasm")
        {
            return Err(format!(
                "Refusing to write binary PCAP output to '.fasm' source file '{arg2}'; specify a '.pcap' or '.pcapng' output path instead:\n  frameassembly {arg1} [out.pcap]"
            ));
        }
    }

    Ok(())
}

/// Constructs the `clap::Command` definition for the `frameassembly` CLI.
fn build_cli() -> Command {
    Command::new("frameassembly")
        .version(env!("CARGO_PKG_VERSION"))
        .about("Compile .fasm network traffic code to .pcap/.pcapng and reverse captures back to .fasm")
        .after_help("Feedback & protocol requests: https://github.com/SteveWinschel/FrameAssembly/issues")
        .styles(CLI_STYLES)
        .subcommand_negates_reqs(true)
        .args_conflicts_with_subcommands(true)
        .arg_required_else_help(true)
        .disable_help_flag(true)
        .disable_version_flag(true)
        .arg(
            Arg::new("help")
                .short('h')
                .long("help")
                .action(ArgAction::Help)
                .global(true)
                .hide(true),
        )
        .arg(
            Arg::new("version")
                .short('V')
                .long("version")
                .action(ArgAction::Version)
                .hide(true),
        )
        .arg(
            Arg::new("input")
                .value_name("INPUT.fasm")
                .help("Path to the input .fasm file")
                .required(true)
                .index(1)
                .value_hint(ValueHint::FilePath)
                .value_parser(PathBufValueParser::new()),
        )
        .arg(
            Arg::new("output")
                .value_name("OUTPUT.pcap")
                .help("Optional output .pcap/.pcapng path (defaults to <input_stem>.pcap)")
                .index(2)
                .value_hint(ValueHint::FilePath)
                .value_parser(PathBufValueParser::new()),
        )
        .subcommand(
            Command::new("show")
                .about("Validate a .fasm file and print a packet ladder table without writing a capture file")
                .disable_help_flag(true)
                .arg(
                    Arg::new("input")
                        .value_name("INPUT.fasm")
                        .help("Path to the input .fasm file")
                        .required(true)
                        .index(1)
                        .value_hint(ValueHint::FilePath)
                        .value_parser(PathBufValueParser::new()),
                ),
        )
        .subcommand(
            Command::new("reverse")
                .about("Reverse a .pcap or .pcapng capture file into .fasm code")
                .disable_help_flag(true)
                .arg(
                    Arg::new("input")
                        .value_name("INPUT.pcap")
                        .help("Path to the input .pcap or .pcapng capture file")
                        .required(true)
                        .index(1)
                        .value_hint(ValueHint::FilePath)
                        .value_parser(PathBufValueParser::new()),
                )
                .arg(
                    Arg::new("output")
                        .value_name("OUTPUT.fasm")
                        .help("Optional output .fasm path (defaults to <input_stem>.fasm)")
                        .index(2)
                        .value_hint(ValueHint::FilePath)
                        .value_parser(PathBufValueParser::new()),
                ),
        )
        .subcommand(
            Command::new("version")
                .about("Print the FrameAssembly version")
                .disable_help_flag(true),
        )
}

/// Maps well-known TCP/UDP port numbers to concise L7 protocol display labels for `frameassembly show`.
fn port_to_l7_name(port: u16, is_tcp: bool) -> Option<&'static str> {
    match (port, is_tcp) {
        (21, true) => Some("FTP"),
        (22, true) => Some("SSH"),
        (23, true) => Some("TELNET"),
        (25 | 587, true) => Some("SMTP"),
        (43, true) => Some("WHOIS"),
        (49, true) => Some("TACACS"),
        (53, _) => Some("DNS"),
        (67 | 68 | 546 | 547, false) => Some("DHCP"),
        (69, false) => Some("TFTP"),
        (80, true) => Some("HTTP"),
        (88, _) => Some("KERBEROS"),
        (102, true) => Some("S7COMM"),
        (110, true) => Some("POP3"),
        (123, false) => Some("NTP"),
        (143, true) => Some("IMAP"),
        (161 | 162, false) => Some("SNMP"),
        (179, true) => Some("BGP"),
        (319 | 320, false) => Some("PTP"),
        (389, _) => Some("LDAP"),
        (443, true) => Some("TLS"),
        (443, false) => Some("QUIC"),
        (445, true) => Some("SMB"),
        (500 | 4500, false) => Some("IKEV2"),
        (502, _) => Some("MODBUS"),
        (514 | 6514, _) => Some("SYSLOG"),
        (520 | 521, false) => Some("RIP"),
        (554, true) => Some("RTSP"),
        (1812 | 1813, false) => Some("RADIUS"),
        (1883, true) => Some("MQTT"),
        (1900, false) => Some("SSDP"),
        (1985, false) => Some("HSRP"),
        (2049, _) => Some("NFS"),
        (2055, false) => Some("NETFLOW"),
        (3306, true) => Some("MYSQL"),
        (3478, false) => Some("STUN"),
        (3784, false) => Some("BFD"),
        (4739, false) => Some("IPFIX"),
        (4789, false) => Some("VXLAN"),
        (4840, true) => Some("OPCUA"),
        (5004, false) => Some("RTP"),
        (5060, _) => Some("SIP"),
        (5353, false) => Some("MDNS"),
        (5432, true) => Some("POSTGRES"),
        (5672, true) => Some("AMQP"),
        (5683, false) => Some("COAP"),
        (6081, false) => Some("GENEVE"),
        (6343, false) => Some("SFLOW"),
        (6379, true) => Some("REDIS"),
        (6653, true) => Some("OPENFLOW"),
        (11211, _) => Some("MEMCACHED"),
        (20000, _) => Some("DNP3"),
        (2222, false) | (44818, _) => Some("ETHERNETIP"),
        (47808, false) => Some("BACNET"),
        (50051, true) => Some("GRPC"),
        (51820, false) => Some("WIREGUARD"),
        _ => None,
    }
}

/// Formats a 6-byte Ethernet MAC address slice as lowercase colon-hex (`xx:xx:xx:xx:xx:xx`).
fn format_mac(bytes: &[u8]) -> String {
    let Some(&[b0, b1, b2, b3, b4, b5]) = bytes.first_chunk::<6>() else {
        return "00:00:00:00:00:00".to_string();
    };
    format!("{b0:02x}:{b1:02x}:{b2:02x}:{b3:02x}:{b4:02x}:{b5:02x}")
}

/// Dissects a single raw Ethernet frame into `(src_to_dst, proto_label, summary_text)`.
fn summarize_frame(data: &[u8]) -> (String, String, String) {
    if data.len() < 14 {
        return (
            "unknown -> unknown".to_string(),
            "RAW".to_string(),
            format!("{} bytes", data.len()),
        );
    }

    let dst_mac = format_mac(&data[0..6]);
    let src_mac = format_mac(&data[6..12]);
    let mut etype = u16::from_be_bytes([data[12], data[13]]);
    let mut offset = 14usize;
    let mut l2_tags = Vec::new();

    while matches!(etype, 0x8100 | 0x88A8 | 0x9100) && offset + 4 <= data.len() {
        let tci = u16::from_be_bytes([data[offset], data[offset + 1]]);
        let vid = tci & 0x0FFF;
        let pcp = (tci >> 13) & 0x07;
        if etype == 0x88A8 || etype == 0x9100 {
            l2_tags.push(format!("SVLAN={vid}"));
        } else if l2_tags.iter().any(|t: &String| t.starts_with("SVLAN=")) {
            l2_tags.push(format!("CVLAN={vid}"));
        } else if pcp > 0 {
            l2_tags.push(format!("VLAN={vid}(PCP={pcp})"));
        } else {
            l2_tags.push(format!("VLAN={vid}"));
        }
        etype = u16::from_be_bytes([data[offset + 2], data[offset + 3]]);
        offset += 4;
    }

    if matches!(etype, 0x8847 | 0x8848) && offset + 4 <= data.len() {
        while let Some(&[b0, b1, b2, b3]) = data[offset..].first_chunk::<4>() {
            let entry = u32::from_be_bytes([b0, b1, b2, b3]);
            let label = entry >> 12;
            let bos = (entry >> 8) & 1;
            l2_tags.push(format!("MPLS={label}"));
            offset += 4;
            if bos == 1 {
                break;
            }
        }
        if let Some(&first_byte) = data.get(offset) {
            match first_byte >> 4 {
                4 => etype = 0x0800,
                6 => etype = 0x86DD,
                _ => {}
            }
        }
    }

    let tag_prefix = if l2_tags.is_empty() {
        String::new()
    } else {
        format!("[{}] ", l2_tags.join(" "))
    };

    match etype {
        0x0806 if offset + 28 <= data.len() => {
            let arp = &data[offset..offset + 28];
            let oper = u16::from_be_bytes([arp[6], arp[7]]);
            let spa = Ipv4Addr::new(arp[14], arp[15], arp[16], arp[17]);
            let tpa = Ipv4Addr::new(arp[24], arp[25], arp[26], arp[27]);
            let detail = if oper == 1 {
                format!("{tag_prefix}Who has {tpa}? Tell {spa}")
            } else {
                format!("{tag_prefix}{spa} is at {src_mac}")
            };
            (format!("{spa} -> {tpa}"), "ARP".to_string(), detail)
        }
        0x0800 if offset + 20 <= data.len() => {
            let ip = &data[offset..];
            let ihl = ((ip[0] & 0x0F) as usize) * 4;
            let proto = ip[9];
            let src_ip = Ipv4Addr::new(ip[12], ip[13], ip[14], ip[15]);
            let dst_ip = Ipv4Addr::new(ip[16], ip[17], ip[18], ip[19]);
            let l4_slice = if ihl >= 20 && ihl <= ip.len() {
                &ip[ihl..]
            } else {
                &[]
            };
            let (p_label, summary) = summarize_l4(proto, l4_slice, &tag_prefix);
            (format!("{src_ip} -> {dst_ip}"), p_label, summary)
        }
        0x86DD if offset + 40 <= data.len() => {
            let ip6 = &data[offset..];
            let mut next_hdr = ip6[6];
            let mut src_bytes = [0u8; 16];
            src_bytes.copy_from_slice(&ip6[8..24]);
            let mut dst_bytes = [0u8; 16];
            dst_bytes.copy_from_slice(&ip6[24..40]);
            let src_ip = Ipv6Addr::from(src_bytes);
            let dst_ip = Ipv6Addr::from(dst_bytes);
            let mut l4_offset = 40usize;
            if next_hdr == 0 && l4_offset + 8 <= ip6.len() {
                next_hdr = ip6[l4_offset];
                let ext_len = (ip6[l4_offset + 1] as usize + 1) * 8;
                if l4_offset + ext_len <= ip6.len() {
                    l4_offset += ext_len;
                }
            }
            let l4_slice = ip6.get(l4_offset..).unwrap_or(&[]);
            let (p_label, summary) = summarize_l4(next_hdr, l4_slice, &tag_prefix);
            (format!("{src_ip} -> {dst_ip}"), p_label, summary)
        }
        0x88CC => (
            format!("{src_mac} -> {dst_mac}"),
            "LLDP".to_string(),
            format!("{tag_prefix}Link Layer Discovery Protocol frame"),
        ),
        0x8809 => (
            format!("{src_mac} -> {dst_mac}"),
            "LACP".to_string(),
            format!("{tag_prefix}Link Aggregation Control Protocol PDU"),
        ),
        0x888E => (
            format!("{src_mac} -> {dst_mac}"),
            "EAPOL".to_string(),
            format!("{tag_prefix}IEEE 802.1X EAP over LAN frame"),
        ),
        _ => {
            let proto = if dst_mac == "01:80:c2:00:00:00" {
                "STP"
            } else if l2_tags.iter().any(|t| t.starts_with("SVLAN=")) {
                "QINQ"
            } else if l2_tags.iter().any(|t| t.starts_with("VLAN=")) {
                "VLAN"
            } else if l2_tags.iter().any(|t| t.starts_with("MPLS=")) {
                "MPLS"
            } else {
                "L2"
            };
            (
                format!("{src_mac} -> {dst_mac}"),
                proto.to_string(),
                format!("{tag_prefix}EtherType 0x{etype:04x}"),
            )
        }
    }
}

/// Dissects the Layer 4 or Layer 3 control header carried inside an IPv4 or IPv6 packet.
fn summarize_l4(proto: u8, l4: &[u8], tag_prefix: &str) -> (String, String) {
    match proto {
        6 if l4.len() >= 20 => {
            let sport = u16::from_be_bytes([l4[0], l4[1]]);
            let dport = u16::from_be_bytes([l4[2], l4[3]]);
            let seq = u32::from_be_bytes([l4[4], l4[5], l4[6], l4[7]]);
            let ack = u32::from_be_bytes([l4[8], l4[9], l4[10], l4[11]]);
            let hdr_len = ((l4[12] >> 4) as usize) * 4;
            let flags = l4[13];
            let payload_len = l4.len().saturating_sub(hdr_len);

            let mut flag_names = Vec::new();
            for (bit, name) in [
                (0x02, "SYN"),
                (0x10, "ACK"),
                (0x08, "PSH"),
                (0x04, "RST"),
                (0x01, "FIN"),
                (0x20, "URG"),
                (0x40, "ECE"),
                (0x80, "CWR"),
            ] {
                if flags & bit != 0 {
                    flag_names.push(name);
                }
            }
            let flags_str = if flag_names.is_empty() {
                "NONE".to_string()
            } else {
                flag_names.join(" ")
            };

            let l7_proto = if payload_len > 0 {
                port_to_l7_name(dport, true).or_else(|| port_to_l7_name(sport, true))
            } else {
                None
            };
            let label = l7_proto.unwrap_or("TCP").to_string();
            let ack_part = if flags & 0x10 != 0 {
                format!(" ack={ack}")
            } else {
                String::new()
            };
            (
                label,
                format!(
                    "{tag_prefix}{sport} -> {dport} [{flags_str}] seq={seq}{ack_part} len={payload_len}"
                ),
            )
        }
        17 if l4.len() >= 8 => {
            let sport = u16::from_be_bytes([l4[0], l4[1]]);
            let dport = u16::from_be_bytes([l4[2], l4[3]]);
            let payload_len = l4.len().saturating_sub(8);
            let l7_proto = port_to_l7_name(dport, false).or_else(|| port_to_l7_name(sport, false));
            let label = l7_proto.unwrap_or("UDP").to_string();
            (
                label,
                format!("{tag_prefix}{sport} -> {dport} len={payload_len}"),
            )
        }
        1 if l4.len() >= 4 => {
            let icmp_type = l4[0];
            let icmp_code = l4[1];
            let desc = match icmp_type {
                8 => "Echo Request",
                0 => "Echo Reply",
                3 => "Destination Unreachable",
                5 => "Redirect",
                11 => "Time Exceeded",
                _ => "Control Message",
            };
            (
                "ICMP".to_string(),
                format!("{tag_prefix}{desc} (type={icmp_type} code={icmp_code})"),
            )
        }
        58 if l4.len() >= 4 => {
            let icmp6_type = l4[0];
            let (label, desc) = match icmp6_type {
                128 => ("ICMPv6", "Echo Request"),
                129 => ("ICMPv6", "Echo Reply"),
                130..=132 | 143 => ("MLD", "Multicast Listener Discovery"),
                133..=137 => ("NDP", "Neighbor Discovery Protocol"),
                _ => ("ICMPv6", "Control Message"),
            };
            (
                label.to_string(),
                format!("{tag_prefix}{desc} (type={icmp6_type})"),
            )
        }
        2 => (
            "IGMP".to_string(),
            format!("{tag_prefix}Multicast Membership Message"),
        ),
        47 => ("GRE".to_string(), format!("{tag_prefix}GRE Tunnel Packet")),
        50 => (
            "ESP".to_string(),
            format!("{tag_prefix}IPsec Encapsulating Security Payload"),
        ),
        51 => (
            "AH".to_string(),
            format!("{tag_prefix}IPsec Authentication Header"),
        ),
        89 => (
            "OSPF".to_string(),
            format!("{tag_prefix}Open Shortest Path First"),
        ),
        103 => (
            "PIM".to_string(),
            format!("{tag_prefix}Protocol Independent Multicast"),
        ),
        112 => (
            "VRRP".to_string(),
            format!("{tag_prefix}Virtual Router Redundancy Protocol"),
        ),
        132 if l4.len() >= 12 => {
            let sport = u16::from_be_bytes([l4[0], l4[1]]);
            let dport = u16::from_be_bytes([l4[2], l4[3]]);
            (
                "SCTP".to_string(),
                format!("{tag_prefix}{sport} -> {dport}"),
            )
        }
        other => (
            format!("IP({other})"),
            format!("{tag_prefix}Protocol {other} ({} bytes)", l4.len()),
        ),
    }
}

/// Formats a terminal packet ladder table for `frameassembly show`.
fn format_packet_ladder(frames: &[(Vec<u8>, u64)]) -> String {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "{:<5}  {:<10}  {:<39}  {:<10}  {:<5}  Summary",
        "#", "Time (ms)", "Source -> Destination", "Proto", "Bytes"
    );
    let _ = writeln!(out, "{}", "-".repeat(110));
    let base_ts = frames.first().map(|(_, ts)| *ts).unwrap_or(0);
    for (idx, (data, timestamp_ns)) in frames.iter().enumerate() {
        let time_ms = timestamp_ns.saturating_sub(base_ts) as f64 / 1_000_000.0;
        let (endpoints, proto, summary) = summarize_frame(data);
        let _ = writeln!(
            out,
            "{:<5}  {:<10.3}  {:<39}  {:<10}  {:<5}  {}",
            idx + 1,
            time_ms,
            endpoints,
            proto,
            data.len(),
            summary
        );
    }
    out
}

/// Entry point for the `frameassembly` CLI binary.
///
/// # Errors
/// Returns a [`miette::Result`] error if legacy 1.x flags are supplied, the input file cannot
/// be read, parsing/validation/decompilation fails, or writing the output file fails.
fn main() -> Result<()> {
    let raw_args: Vec<OsString> = std::env::args_os().collect();
    if let Err(hint) = check_legacy_cli_args(&raw_args) {
        return Err(miette::miette!("{hint}"));
    }

    let mut matches = build_cli().get_matches_from(raw_args);
    match matches.remove_subcommand() {
        Some((sub_name, mut sub_matches)) => match sub_name.as_str() {
            "version" => {
                println!("frameassembly {}", env!("CARGO_PKG_VERSION"));
                Ok(())
            }
            "reverse" => {
                let input_path = sub_matches
                    .remove_one::<PathBuf>("input")
                    .ok_or_else(|| miette::miette!("Missing input .pcap / .pcapng file"))?;
                let output_path = sub_matches
                    .remove_one::<PathBuf>("output")
                    .unwrap_or_else(|| derive_default_output_path(&input_path, "fasm"));
                let res = reverse_pcap_file(&input_path)
                    .map_err(|e| miette::miette!("Reverse decompilation error: {}", e))?;
                fs::write(&output_path, &res.fasm).into_diagnostic()?;
                println!(
                    "Successfully reversed {} into {} ({} hosts, {} packets)",
                    input_path.display(),
                    output_path.display(),
                    res.host_count,
                    res.packet_count
                );
                Ok(())
            }
            "show" => {
                let file_path = sub_matches
                    .remove_one::<PathBuf>("input")
                    .ok_or_else(|| miette::miette!("Missing input .fasm file"))?;
                let file_display = file_path.display().to_string();
                let code = fs::read_to_string(&file_path).into_diagnostic()?;
                let program = parse_program(&code).map_err(|e| {
                    miette::Report::new(e)
                        .with_source_code(NamedSource::new(file_display, code.clone()))
                })?;
                let frames = compile_program(&program)
                    .map_err(|e| miette::miette!("Backend error: {}", e))?;
                print!("{}", format_packet_ladder(&frames));
                Ok(())
            }
            _ => unreachable!("clap enforces known subcommands"),
        },
        None => {
            let file_path = matches
                .remove_one::<PathBuf>("input")
                .ok_or_else(|| miette::miette!("Missing input .fasm file"))?;
            let output_pcap = matches
                .remove_one::<PathBuf>("output")
                .unwrap_or_else(|| derive_default_output_path(&file_path, "pcap"));
            if output_pcap
                .extension()
                .and_then(|e| e.to_str())
                .is_some_and(|e| e.eq_ignore_ascii_case("fasm"))
            {
                return Err(miette::miette!(
                    "Refusing to write binary PCAP output to '.fasm' source file '{}'; specify a '.pcap' or '.pcapng' output path instead",
                    output_pcap.display()
                ));
            }

            let file_display = file_path.display().to_string();
            let code = fs::read_to_string(&file_path).into_diagnostic()?;
            let program = parse_program(&code).map_err(|e| {
                miette::Report::new(e)
                    .with_source_code(NamedSource::new(file_display, code.clone()))
            })?;
            let frames =
                compile_program(&program).map_err(|e| miette::miette!("Backend error: {}", e))?;

            println!(
                "Successfully parsed {} hosts, {} flows",
                program.hosts.len(),
                program.flows.len(),
            );

            let total_bytes: usize = frames.iter().map(|(data, _)| data.len()).sum();
            let first_ts = frames.first().map(|(_, ts)| *ts).unwrap_or(0);
            let duration_ms = frames
                .last()
                .map(|(_, ts_ns)| ts_ns.saturating_sub(first_ts) as f64 / 1_000_000.0)
                .unwrap_or(0.0);

            let output_pcap_str = output_pcap.to_string_lossy();
            println!("Starting PCAP compilation...");
            generate_pcap(&program, &output_pcap_str)
                .map_err(|e| miette::miette!("Backend error: {}", e))?;

            println!(
                "Successfully generated {} ({} frames, {} bytes, duration {:.3} ms)",
                output_pcap_str,
                frames.len(),
                total_bytes,
                duration_ms
            );
            Ok(())
        }
    }
}

/// Unit tests for FrameAssembly 2.0 default root compilation and four subcommands
/// (`show`, `reverse`, `version`, `help`), hidden script compatibility flags, legacy migration
/// hints, safety guards, and packet ladder formatting.
#[cfg(test)]
mod tests {
    use super::*;
    use clap::error::ErrorKind;

    /// Validates that the `clap::Command` configuration has no conflicting flags, duplicate indices, or invalid defaults.
    #[test]
    fn verify_cli_invariants() {
        build_cli().debug_assert();
    }

    /// Verifies `derive_default_output_path` stem matching and collision avoidance for `.pcap` and `.fasm`.
    #[test]
    fn test_derive_default_output_path() {
        assert_eq!(
            derive_default_output_path(Path::new("example.fasm"), "pcap"),
            PathBuf::from("example.pcap")
        );
        assert_eq!(
            derive_default_output_path(Path::new("dir/test.fasm"), "pcap"),
            PathBuf::from("dir/test.pcap")
        );
        assert_eq!(
            derive_default_output_path(Path::new("already.pcap"), "pcap"),
            PathBuf::from("already.pcap.pcap")
        );
        assert_eq!(
            derive_default_output_path(Path::new("example.pcap"), "fasm"),
            PathBuf::from("example.fasm")
        );
        assert_eq!(
            derive_default_output_path(Path::new("traces/cap.pcapng"), "fasm"),
            PathBuf::from("traces/cap.fasm")
        );
        assert_eq!(
            derive_default_output_path(Path::new("already.fasm"), "fasm"),
            PathBuf::from("already.fasm.fasm")
        );
    }

    /// Verifies that default root `.fasm` compilation and the four v2.0 subcommands (`show`,
    /// `reverse`, `version`, `help`) parse positional arguments cleanly and hide `-h`/`--help`
    /// and `-V`/`--version` from rendered help text while keeping `--help` and `--version`
    /// functional for scripts.
    #[test]
    fn test_cli_default_compile_four_subcommands_and_hidden_flags() {
        let mut cmd = build_cli();
        let help_text = cmd.render_help().to_string();
        assert!(
            help_text.contains("<INPUT.fasm>") && help_text.contains("[OUTPUT.pcap]"),
            "root help text should advertise positional <INPUT.fasm> [OUTPUT.pcap]:\n{help_text}"
        );
        for sub in SUBCOMMANDS {
            assert!(
                help_text.contains(sub),
                "root help text should list subcommand '{sub}':\n{help_text}"
            );
        }
        for hidden in ["--help", "--version", "-o", "--output", "DSL"] {
            assert!(
                !help_text.contains(hidden),
                "root help text must not expose '{hidden}':\n{help_text}"
            );
        }
        assert!(help_text.contains("https://github.com/SteveWinschel/FrameAssembly/issues"));

        for sub_name in ["show", "reverse", "version"] {
            let sub_help = cmd
                .find_subcommand_mut(sub_name)
                .expect("subcommand exists")
                .render_help()
                .to_string();
            assert!(
                !sub_help.contains("--help") && !sub_help.contains("--output"),
                "subcommand '{sub_name}' help must hide --help and omit --output:\n{sub_help}"
            );
        }

        // Silent compatibility for shell/CI scripts invoking --help or --version
        let help_err = build_cli()
            .try_get_matches_from(["frameassembly", "--help"])
            .expect_err("--help exits via DisplayHelp");
        assert_eq!(help_err.kind(), ErrorKind::DisplayHelp);

        let ver_err = build_cli()
            .try_get_matches_from(["frameassembly", "--version"])
            .expect_err("--version exits via DisplayVersion");
        assert_eq!(ver_err.kind(), ErrorKind::DisplayVersion);

        let no_args_err = build_cli()
            .try_get_matches_from(["frameassembly"])
            .expect_err("zero args should render help");
        assert_eq!(
            no_args_err.kind(),
            ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand
        );

        let root_default = build_cli()
            .try_get_matches_from(["frameassembly", "demo.fasm"])
            .expect("default root compile with 1 arg should parse");
        assert!(root_default.subcommand_name().is_none());
        assert_eq!(
            root_default.get_one::<PathBuf>("input"),
            Some(&PathBuf::from("demo.fasm"))
        );
        assert_eq!(root_default.get_one::<PathBuf>("output"), None);

        let root_explicit = build_cli()
            .try_get_matches_from(["frameassembly", "demo.fasm", "custom.pcap"])
            .expect("default root compile with 2 positional args should parse");
        assert!(root_explicit.subcommand_name().is_none());
        assert_eq!(
            root_explicit.get_one::<PathBuf>("input"),
            Some(&PathBuf::from("demo.fasm"))
        );
        assert_eq!(
            root_explicit.get_one::<PathBuf>("output"),
            Some(&PathBuf::from("custom.pcap"))
        );

        let show_matches = build_cli()
            .try_get_matches_from(["frameassembly", "show", "demo.fasm"])
            .expect("show subcommand should parse");
        assert_eq!(
            show_matches
                .subcommand_matches("show")
                .and_then(|m| m.get_one::<PathBuf>("input")),
            Some(&PathBuf::from("demo.fasm"))
        );

        let rev_matches = build_cli()
            .try_get_matches_from([
                "frameassembly",
                "reverse",
                "traces/cap.pcapng",
                "traces/cap.fasm",
            ])
            .expect("reverse subcommand should parse");
        let rev_sub = rev_matches
            .subcommand_matches("reverse")
            .expect("reverse matched");
        assert_eq!(
            rev_sub.get_one::<PathBuf>("input"),
            Some(&PathBuf::from("traces/cap.pcapng"))
        );
        assert_eq!(
            rev_sub.get_one::<PathBuf>("output"),
            Some(&PathBuf::from("traces/cap.fasm"))
        );

        let ver_sub = build_cli()
            .try_get_matches_from(["frameassembly", "version"])
            .expect("version subcommand should parse");
        assert!(ver_sub.subcommand_matches("version").is_some());
    }

    /// Verifies that legacy CLI flags (`-o`, `--output`, `--show`, `--reverse`), bare `.pcap`
    /// paths, removed `compile` subcommands, and `.fasm` output typos return clear hints.
    #[test]
    fn test_legacy_cli_migration_hints_and_safety_guards() {
        let dash_o = check_legacy_cli_args(["frameassembly", "demo.fasm", "-o", "a.pcap"])
            .expect_err("-o should trigger hint");
        assert!(dash_o.contains("Compile: frameassembly <in.fasm> [out.pcap]"));
        assert!(dash_o.contains("Reverse: frameassembly reverse <in.pcap> [out.fasm]"));

        let long_out =
            check_legacy_cli_args(["frameassembly", "reverse", "a.pcap", "--output=a.fasm"])
                .expect_err("--output should trigger hint");
        assert!(long_out.contains("frameassembly reverse <in.pcap> [out.fasm]"));

        let flag_show = check_legacy_cli_args(["frameassembly", "--show", "demo.fasm"])
            .expect_err("--show should trigger hint");
        assert!(flag_show.contains("frameassembly show <in.fasm>"));

        let flag_rev = check_legacy_cli_args(["frameassembly", "--reverse", "trace.pcap"])
            .expect_err("--reverse should trigger hint");
        assert!(flag_rev.contains("frameassembly reverse <in.pcap> [out.fasm]"));

        let bare_pcap = check_legacy_cli_args(["frameassembly", "trace.pcapng"])
            .expect_err("bare .pcapng should trigger reverse hint");
        assert!(bare_pcap.contains("frameassembly reverse trace.pcapng"));

        let old_compile_sub = check_legacy_cli_args(["frameassembly", "compile", "demo.fasm"])
            .expect_err("removed compile subcommand should trigger safety guard");
        assert!(old_compile_sub.contains("there is no 'compile' subcommand"));
        assert!(old_compile_sub.contains("frameassembly <in.fasm> [out.pcap]"));

        let fasm_as_output = check_legacy_cli_args(["frameassembly", "a.fasm", "b.fasm"])
            .expect_err(".fasm second positional arg should be rejected to protect source file");
        assert!(fasm_as_output.contains("b.fasm"));

        assert!(check_legacy_cli_args(["frameassembly", "demo.fasm"]).is_ok());
        assert!(check_legacy_cli_args(["frameassembly", "demo.fasm", "out.pcap"]).is_ok());
        assert!(check_legacy_cli_args(["frameassembly", "reverse", "a.pcap", "a.fasm"]).is_ok());
        assert!(check_legacy_cli_args(["frameassembly", "--version"]).is_ok());
    }

    /// Verifies packet ladder rendering on strict-lowercase FrameAssembly 2.0 `.fasm` code.
    #[test]
    fn test_packet_ladder_strict_lowercase_fasm() {
        let sample = "host a { ip 10.0.0.1 }\nhost b { ip 10.0.0.2 }\nflow f(c, s) {\n    c -> s tcp srcport 50000 dstport 443 syn\n    c <- s tcp syn ack wait 5ms\n}\ncompile { f(a, b) }";
        let program = parse_program(sample).expect("sample should parse");
        let frames = compile_program(&program).expect("sample should compile");
        let ladder = format_packet_ladder(&frames);
        assert!(ladder.contains("Source -> Destination"));
        assert!(ladder.contains("0.000"));
        assert!(ladder.contains("5.000"));
    }
}
