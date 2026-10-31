//! Command-line interface (CLI) entry point for the FrameAssembly network packet compiler.
//!
//! This binary reads declarative `.fasm` source files specifying network hosts, protocol flows,
//! and execution blocks, runs the two-phase lexical/syntactic parser and semantic validator,
//! and invokes the deterministic backend engine to emit nanosecond-precision `.pcap` / `.pcapng`
//! packet capture files with rich `miette` terminal diagnostics and a `frameassembly show <file.fasm>`
//! subcommand that validates `.fasm` specifications and prints a terminal packet ladder table
//! without writing a `.pcap` file.
use clap::{Arg, Command};
use frameassembly::backend::{compile_program, generate_pcap};
use frameassembly::parser::parse_program;
use miette::{IntoDiagnostic, NamedSource, Result};
use std::fmt::Write as _;
use std::fs;
use std::net::{Ipv4Addr, Ipv6Addr};

/// Constructs the `clap::Command` definition for the `frameassembly` CLI.
fn build_cli() -> Command {
    Command::new("frameassembly")
        .version(env!("CARGO_PKG_VERSION"))
        .about("Declarative network packet crafting tool generating deterministic .pcap/.pcapng captures across 81 L2-L7 protocols")
        .args_conflicts_with_subcommands(true)
        .subcommand(
            Command::new("show")
                .about("Validate a .fasm file and print a terminal packet ladder table without writing a .pcap file")
                .arg(
                    Arg::new("input")
                        .help("Path to the .fasm source file")
                        .required(true)
                        .index(1),
                ),
        )
        .arg(
            Arg::new("input")
                .help("Path to the .fasm source file")
                .required(true)
                .index(1),
        )
        .arg(
            Arg::new("output")
                .short('o')
                .long("output")
                .help("Path to the output PCAP file")
                .default_value("output.pcap"),
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
        (502, true) => Some("MODBUS"),
        (514, false) => Some("SYSLOG"),
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
        (20000, true) => Some("DNP3"),
        (44818, true) => Some("ETHERNETIP"),
        (47808, false) => Some("BACNET"),
        (50051, true) => Some("GRPC"),
        (51820, false) => Some("WIREGUARD"),
        _ => None,
    }
}

/// Formats a 6-byte Ethernet MAC address slice as `xx:xx:xx:xx:xx:xx`.
fn format_mac(b: &[u8]) -> String {
    if b.len() < 6 {
        return "00:00:00:00:00:00".to_string();
    }
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        b[0], b[1], b[2], b[3], b[4], b[5]
    )
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

    while (etype == 0x8100 || etype == 0x88A8 || etype == 0x9100) && offset + 4 <= data.len() {
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

    if (etype == 0x8847 || etype == 0x8848) && offset + 4 <= data.len() {
        while offset + 4 <= data.len() {
            let entry = u32::from_be_bytes([
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            ]);
            let label = entry >> 12;
            let bos = (entry >> 8) & 1;
            l2_tags.push(format!("MPLS={label}"));
            offset += 4;
            if bos == 1 {
                break;
            }
        }
        if offset < data.len() {
            let first_nibble = data[offset] >> 4;
            if first_nibble == 4 {
                etype = 0x0800;
            } else if first_nibble == 6 {
                etype = 0x86DD;
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
            let oper = u16::from_be_bytes([data[offset + 6], data[offset + 7]]);
            let spa = Ipv4Addr::new(
                data[offset + 14],
                data[offset + 15],
                data[offset + 16],
                data[offset + 17],
            );
            let tpa = Ipv4Addr::new(
                data[offset + 24],
                data[offset + 25],
                data[offset + 26],
                data[offset + 27],
            );
            let detail = if oper == 1 {
                format!("{tag_prefix}Who has {tpa}? Tell {spa}")
            } else {
                format!("{tag_prefix}{spa} is at {src_mac}")
            };
            (format!("{spa} -> {tpa}"), "ARP".to_string(), detail)
        }
        0x0800 if offset + 20 <= data.len() => {
            let ihl = ((data[offset] & 0x0F) as usize) * 4;
            let proto = data[offset + 9];
            let src_ip = Ipv4Addr::new(
                data[offset + 12],
                data[offset + 13],
                data[offset + 14],
                data[offset + 15],
            );
            let dst_ip = Ipv4Addr::new(
                data[offset + 16],
                data[offset + 17],
                data[offset + 18],
                data[offset + 19],
            );
            let l4_slice = if offset + ihl <= data.len() {
                &data[offset + ihl..]
            } else {
                &[]
            };
            let (p_label, summary) = summarize_l4(proto, l4_slice, &tag_prefix);
            (format!("{src_ip} -> {dst_ip}"), p_label, summary)
        }
        0x86DD if offset + 40 <= data.len() => {
            let mut next_hdr = data[offset + 6];
            let mut src_bytes = [0u8; 16];
            src_bytes.copy_from_slice(&data[offset + 8..offset + 24]);
            let mut dst_bytes = [0u8; 16];
            dst_bytes.copy_from_slice(&data[offset + 24..offset + 40]);
            let src_ip = Ipv6Addr::from(src_bytes);
            let dst_ip = Ipv6Addr::from(dst_bytes);
            let mut l4_offset = offset + 40;
            if next_hdr == 0 && l4_offset + 8 <= data.len() {
                next_hdr = data[l4_offset];
                let ext_len = (data[l4_offset + 1] as usize + 1) * 8;
                if l4_offset + ext_len <= data.len() {
                    l4_offset += ext_len;
                }
            }
            let l4_slice = if l4_offset <= data.len() {
                &data[l4_offset..]
            } else {
                &[]
            };
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

/// Dissects the Layer 4 / Layer 3-control header inside an IPv4 or IPv6 packet.
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

/// The main entry point for the `frameassembly` CLI.
///
/// # Errors
/// Returns a `miette::Result` error if CLI arguments are invalid, the input `.fasm` file
/// cannot be read, parsing/validation fails, or writing the `.pcap` capture fails.
fn main() -> Result<()> {
    let matches = build_cli().get_matches();

    let (file, show_only, output_pcap) =
        if let Some(show_matches) = matches.subcommand_matches("show") {
            let input_file = show_matches
                .get_one::<String>("input")
                .ok_or_else(|| miette::miette!("Missing input .fasm file"))?;
            (input_file, true, "output.pcap")
        } else {
            let input_file = matches
                .get_one::<String>("input")
                .ok_or_else(|| miette::miette!("Missing input .fasm file"))?;
            let out_path = matches
                .get_one::<String>("output")
                .map(String::as_str)
                .unwrap_or("output.pcap");
            (input_file, false, out_path)
        };

    let code = fs::read_to_string(file).into_diagnostic()?;

    let program = parse_program(&code).map_err(|e| {
        miette::Report::new(e).with_source_code(NamedSource::new(file.clone(), code.clone()))
    })?;

    let frames = compile_program(&program).map_err(|e| miette::miette!("Backend error: {}", e))?;

    if show_only {
        print!("{}", format_packet_ladder(&frames));
        return Ok(());
    }

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

    println!("Starting PCAP compilation...");
    generate_pcap(&program, output_pcap).map_err(|e| miette::miette!("Backend error: {}", e))?;

    println!(
        "Successfully generated {} ({} frames, {} bytes, duration {:.3} ms)",
        output_pcap,
        frames.len(),
        total_bytes,
        duration_ms
    );
    Ok(())
}

/// Unit tests for CLI commands (`frameassembly <input.fasm>` and `frameassembly show <input.fasm>`) and packet ladder formatting.
#[cfg(test)]
mod tests {
    use super::*;

    /// Validates that the `clap::Command` configuration has no conflicting flags, duplicate indices, or invalid defaults.
    #[test]
    fn verify_cli_invariants() {
        build_cli().debug_assert();
    }

    /// Verifies that both `frameassembly <file.fasm> [-o <output.pcap>]` and `frameassembly show <file.fasm>` parse cleanly and format a relative-timestamp packet ladder.
    #[test]
    fn test_cli_compile_and_show_subcommand() {
        let compile_matches = build_cli()
            .try_get_matches_from(["frameassembly", "demo.fasm", "-o", "custom.pcap"])
            .expect("compile CLI arguments should parse");
        assert!(compile_matches.subcommand_matches("show").is_none());
        assert_eq!(
            compile_matches
                .get_one::<String>("input")
                .map(String::as_str),
            Some("demo.fasm")
        );
        assert_eq!(
            compile_matches
                .get_one::<String>("output")
                .map(String::as_str),
            Some("custom.pcap")
        );

        let show_matches = build_cli()
            .try_get_matches_from(["frameassembly", "show", "demo.fasm"])
            .expect("show subcommand should parse");
        let show_sub = show_matches
            .subcommand_matches("show")
            .expect("show subcommand should be matched");
        assert_eq!(
            show_sub.get_one::<String>("input").map(String::as_str),
            Some("demo.fasm")
        );

        let sample = "HOST a { IP 10.0.0.1 }\nHOST b { IP 10.0.0.2 }\nFLOW f(c, s) {\n    c -> s TCP SRCPORT 50000 DSTPORT 443 SYN\n    c <- s TCP SYN ACK WAIT 5ms\n}\nCOMPILE { f(a, b) }";
        let program = parse_program(sample).expect("sample should parse");
        let frames = compile_program(&program).expect("sample should compile");
        let ladder = format_packet_ladder(&frames);
        assert!(ladder.contains("Source -> Destination"));
        assert!(ladder.contains("0.000"));
        assert!(ladder.contains("5.000"));
    }
}
