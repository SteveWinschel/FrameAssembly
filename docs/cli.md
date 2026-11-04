# Command-Line Interface & Replay Workflows (`docs/cli.md`)

[**Commands & Flags**](#cli-commands-and-flags) • [**`frameassembly show`**](#1-sanity-check-flows-vlan-tags-and-tcp-math-without-opening-wireshark) • [**Replay (`tcpreplay`)**](#2-inject-captures-into-span-ports-and-inline-stateful-firewalls) • [**Headless `tshark` & CI/CD**](#3-replace-mystery-pcap-blobs-in-git-and-ci-pipelines) • [**Error Diagnostics**](#4-fix-muscle-memory-typos-without-reading-parser-stack-traces) • [**Compiler Internals**](for_nerds.md)

## Why the FrameAssembly CLI Has Two Commands Instead of Forty Flags

Most packet-crafting CLIs force a choice between two bad ergonomics: memorize 47 single-letter flags that require `sudo` just to print `--help` (one typo away from blasting a `SYN` flood out of your production management NIC), or click through nested GUI stream dialogs every time you want to change a VLAN ID :)

`frameassembly` intentionally stays out of the packet-injection business and sticks to doing one job cleanly in unprivileged user space -> **compiling human-readable `.fasm` files into deterministic `.pcap` / `.pcapng` captures** (or printing a terminal packet ladder so you can check your math first), ready to hand off to **`tcpreplay`**, **Wireshark** / **`tshark`**, **Suricata**, or **Zeek**:

```frameassembly
host branch_ws { ip 10.20.10.50 mac 00:1a:2b:3c:4d:50 }
host hq_api    { ip 10.90.1.80  mac 00:1c:73:90:01:80 }

flow api_probe(c, s) {
    c -> s vlan 20 pcp 5 tcp syn srcport 52400 dstport 443 win 65535 mss 1460 wait 1ms
    c <- s vlan 20 pcp 5 tcp syn ack win 65535 mss 1460 wait 1ms
    c -> s vlan 20 pcp 5 tcp ack wait 1ms
    c -> s vlan 20 pcp 5 tls client_hello sni "api.corp.internal" ciphersuite 4865 alpn "h2" wait 2ms
    c <- s vlan 20 pcp 5 tls server_hello ciphersuite 4865 alpn "h2" wait 2ms
}

compile { api_probe(branch_ws, hq_api) }
```

```console
$ frameassembly show wan_check.fasm
#      Time (ms)   Source -> Destination                    Proto       Bytes  Summary
--------------------------------------------------------------------------------------------------------------
1      0.000       10.20.10.50 -> 10.90.1.80                TCP         62     [VLAN=20(PCP=5)] 52400 -> 443 [SYN] seq=1000 len=0
2      1.000       10.90.1.80 -> 10.20.10.50                TCP         62     [VLAN=20(PCP=5)] 443 -> 52400 [SYN ACK] seq=1000 ack=1001 len=0
3      2.000       10.20.10.50 -> 10.90.1.80                TCP         58     [VLAN=20(PCP=5)] 52400 -> 443 [ACK] seq=1001 ack=1001 len=0
4      4.000       10.20.10.50 -> 10.90.1.80                TLS         147    [VLAN=20(PCP=5)] 52400 -> 443 [ACK PSH] seq=1001 ack=1001 len=89
5      6.000       10.90.1.80 -> 10.20.10.50                TLS         116    [VLAN=20(PCP=5)] 443 -> 52400 [ACK PSH] seq=1001 ack=1090 len=58

$ frameassembly wan_check.fasm -o wan_check.pcap
Successfully parsed 2 hosts, 1 flows
Starting PCAP compilation...
Successfully generated wan_check.pcap (5 frames, 445 bytes, duration 6.000 ms)
```

## CLI Commands and Flags

| Command / Flag | Example | What It Does |
| :--- | :--- | :--- |
| `frameassembly <input.fasm>` | `frameassembly test.fasm` | Validates and compiles `<input.fasm>` to `./output.pcap` (default output path) |
| `-o`, `--output <path>` | `frameassembly test.fasm -o acl.pcapng` | Writes the compiled capture to `<path>` (`.pcap` or `.pcapng`) |
| `frameassembly show <input.fasm>` | `frameassembly show test.fasm` | Runs full lexical, syntax, semantic, and wire synthesis in memory and prints a 6-column packet ladder without writing a file |
| `-V`, `--version` | `frameassembly --version` | Prints the installed `frameassembly` compiler version |
| `-h`, `--help` | `frameassembly --help` | Prints CLI usage (`frameassembly show --help` for subcommand options) |

### Three Built-In CLI Guarantees

* **Zero Root, Zero `libpcap`, Zero Live Sockets:** `frameassembly` never requests `CAP_NET_RAW`, loads kernel capture drivers, or touches network interfaces. It runs identically on a locked-down corporate laptop, an SSH jump host, or an unprivileged Docker container.
* **Transactional File Writes (No Half-Written Captures):** The compiler lexes, parses, validates semantics, and synthesizes every Ethernet frame in RAM *before* opening the output file path. If line 42 has a typo, `frameassembly` exits with code `1` and leaves any existing `output.pcap` untouched instead of overwriting it with a 0-byte file.
* **Bit-for-Bit Reproducible PCAPNG Output:** Every compiled capture uses PCAP Next Generation (`LINKTYPE_ETHERNET`, `65535`-byte snaplen, `IfTsResol(9)` $10^{-9}\text{ s}$ nanosecond resolution) anchored to a deterministic epoch (`2023-11-14T22:13:20Z`) and deterministic SNMPv3 salts. Compiling the same `.fasm` file on Linux, macOS, and Windows produces the exact same `sha256sum`.

## CLI Workflows and Companion Pipelines

### 1. Sanity-Check Flows, VLAN Tags and TCP Math Without Opening Wireshark
Launching a desktop GUI over VPN/SSH—or piping binary output into `tcpdump -r -`—just to check whether you flipped an arrow (`<-` vs `->`) or tagged the right outer S-VLAN gets old fast. Run `frameassembly show <file.fasm>` to validate the file and dissect every synthesized frame in your terminal:

* **`Time (ms)`:** Relative to Frame 1 (`0.000` ms), advancing by each statement's `wait` duration (`10.000` ms default when `wait` is omitted) with microsecond decimal precision (`wait 250us` -> `+0.250` ms).
* **`Source -> Destination`:** Displays `<src_ip> -> <dst_ip>` for IPv4/IPv6 packets (including auto-derived multicast targets like `224.0.0.5` or `ff02::fb`), and `<src_mac> -> <dst_mac>` for pure Layer 2 frames (`LLDP`, `STP`, `LACP`, `EAPOL`).
* **`Proto` & `Summary`:** Peels outer L2 shims (`[VLAN=100(PCP=5)]`, `[SVLAN=850 CVLAN=12]`, `[MPLS=24010]`), labels well-known L2–L7 protocols (`ARP`, `OSPF`, `BGP`, `SNMP`, `DNS`, `TLS`, `MODBUS`, `DNP3`, `S7COMM`, etc.), and prints TCP flags, `seq`, `ack`, and L4 payload lengths.

```console
# Validate syntax/semantics and grep the packet ladder for VLAN or sequence alignment
$ frameassembly show trunk_audit.fasm
```

### 2. Inject Captures Into SPAN Ports and Inline Stateful Firewalls
Once `frameassembly` emits your `.pcap`, **`tcpreplay`** handles putting frames onto physical NICs, veth pairs, or lab TAPs:

```bash
# 1. Replay into a SPAN / TAP / IDS sensor or NMS collector honoring .fasm `wait` intervals
frameassembly snmp_alert.fasm -o snmp_alert.pcap
sudo tcpreplay -i eth0 snmp_alert.pcap

# 2. Stress-test a collector or DDoS scrubber at fixed PPS, loop count, or NIC line rate
sudo tcpreplay -i eth0 --loop=100 --pps=10000 syn_flood.pcap
sudo tcpreplay -i eth0 --topspeed syn_flood.pcap
```

#### Splitting Client & Server NICs Across an Inline Stateful Firewall (`tcpprep`)
If you blast both directions (`->` and `<-`) of a TCP flow into a **single** interface of an inline firewall (**Palo Alto**, **FortiGate**, **CheckPoint**, `nftables`), the firewall will drop the server's `SYN ACK` because it arrived on the client ingress interface. Split the capture with `tcpprep` so client packets enter `eth0` (trust/untrust) and server replies enter `eth1` (DMZ):

```bash
# Compile the bidirectional flow
frameassembly acl_test.fasm -o acl_test.pcap

# Auto-classify client vs. server endpoints into a tcpprep cache file
tcpprep --auto=client --pcap=acl_test.pcap --cachefile=acl_test.cache

# Replay client -> firewall on eth0 and server <- firewall on eth1 simultaneously
sudo tcpreplay --cachefile=acl_test.cache --intf1=eth0 --intf2=eth1 acl_test.pcap
```

### 3. Replace Mystery `.pcap` Blobs in Git and CI Pipelines
Checking binary `.pcap` files into a Git repository is terrible for code review: `git diff` just shrugs (`Binary files differ`), nobody can tell whether a teammate updated a TCP port or accidentally committed customer PII from a production capture, and editing one IP later means recapturing from scratch.

Instead, commit the `.fasm` source file ("Packets as Code") and compile the `.pcap` on the fly inside CI—with zero `sudo` or special container capabilities:

```bash
#!/usr/bin/env bash
set -euo pipefail

# 1. Fast dry-run lint across every .fasm scenario in the repo (no disk writes)
for f in tests/packets/*.fasm; do
    frameassembly show "$f" > /dev/null
done

# 2. Compile ephemeral PCAPs and run Suricata / Zeek / tshark assertions
frameassembly tests/packets/c2_beacon.fasm -o /tmp/c2_beacon.pcap
suricata -r /tmp/c2_beacon.pcap -l /tmp/suricata-logs -k none
zeek -C -r /tmp/c2_beacon.pcap

# 3. Verify protocol fields or decrypt SNMPv3 authPriv traps headlessly in tshark
tshark -r /tmp/c2_beacon.pcap -T fields -e frame.number -e ip.src -e ip.dst -e tls.handshake.extensions_server_name
```

### 4. Fix Muscle-Memory Typos Without Reading Parser Stack Traces
Because `.fasm` is built for network and security engineers—not compiler theorists—errors point directly to the offending token in your terminal with a plain-English `help:` hint instead of dumping internal parser jargon:

```text
frameassembly::parse_error

  × Failed to parse input: Syntax error: unexpected number '1001' after 'ACK'. In .fasm,
  │ 'ACK' alone is a TCP flag; did you mean 'ACKNUM 1001' to set the acknowledgment number?
   ╭─[handshake.fasm:5:18]
 4 │ flow check(c, s) {
 5 │     c <- s tcp ack 1001
   ·                    ──┬─
   ·                      ╰── Here
 6 │ }
   ╰─
  help: Use 'ACK' alone as a TCP flag, and use 'ACKNUM <number>' to set the TCP acknowledgment number (for example: TCP ACK ACKNUM 100).
```

| Diagnostic Code | Exit | Common Mistakes Caught Before Any `.pcap` Is Written |
| :--- | :---: | :--- |
| `frameassembly::lex_error` | `1` | `#` or `/* */` comments (use `//`), `'single quotes'` (use `"..."`), `10.0.0.1/24` CIDR masks in `host`, `=` / `:` / `;` punctuation, `[SYN]` brackets |
| `frameassembly::parse_error` | `1` | Muscle-memory aliases (`sport`/`dport` -> `srcport`/`dstport`, `ack 100` -> `acknum 100`, `hoplimit` -> `ttl`, `tos` -> `dscp`, `cos` -> `pcp`, HTTP `host` -> `host_hdr`), missing `compile {}` block, typo suggestions (`SRCPROT` -> `SRCPORT`) |
| `frameassembly::semantic_error` | `1` | Mixing IPv4 and IPv6 hosts on the same packet line, out-of-range fields (`vlan 0` / `4095`, `dscp > 63`, `ttl > 255`), TCP flags on `udp`/`snmp`, duplicate `host` or modifier names |
| `frameassembly::backend_error` | `1` | SNMPv3 `priv` without `auth` (`noAuthPriv`), `counter64` / `getbulk` on `snmp1`, or unwriteable output directory path |

> **Accidentally Fed It an x86 Assembly or FPGA `.fasm` File?**
> Two older ecosystems also use `.fasm`: x86 Flat Assembler (`format ELF64`, `mov eax, 1`, `;` comments) and FPGA bitstream assembly (`CLBLL_L_X12Y34...`, `#` comments). If you pass either one to `frameassembly`, the CLI detects the foreign `.fasm` dialect automatically and tells you what kind of file you actually opened instead of spitting out 200 syntax errors.

## Related Documentation

* [**Main README (`../README.md`)**](../README.md) — Overview, installation one-liners, and end-to-end testing scenarios.
* [**Getting Started (`getting_started.md`)**](getting_started.md) — Core `host` / `flow` / `compile` syntax, stateful TCP, and Wireshark cheat sheet.
* [**Layer 2 — Switching & Data Link (`l2_protocols.md`)**](l2_protocols.md) — `arp`, `vlan`, `qinq`, `lldp`, `stp`, `lacp`, `eapol`, and `mpls`.
* [**Layer 3 — Routing, Overlays, Tunnels & VPNs (`l3_protocols.md`)**](l3_protocols.md) — `icmp`, `ndp`, `ospf`, `bgp`, `bfd`, `vxlan`, `geneve`, `ikev2`, `esp`, and `wireguard`.
* [**Layer 4 — Stateful TCP, UDP & Telecom SCTP (`l4_transports.md`)**](l4_transports.md) — Automatic 4-tuple `SEQ`/`ACK` tracking, `ZeroWindow` stalls, `udp`, and 5G `sctp`.
* [**Layer 7 — SNMP (`l7_snmp.md`)**](l7_snmp.md) & [**Infrastructure / Telemetry (`l7_infra_and_telemetry.md`)**](l7_infra_and_telemetry.md) — `snmp1`–`snmp3` USM decryption, `dns`, `dhcp`, `ptp`, `radius`, `tacacs`, `syslog`, and `ipfix`.
* [**Layer 7 — Web & VoIP (`l7_web_and_cloud.md`)**](l7_web_and_cloud.md), [**Enterprise / DB (`l7_mail_auth_storage_db.md`)**](l7_mail_auth_storage_db.md) & [**Industrial OT (`l7_industrial_ot.md`)**](l7_industrial_ot.md) — Application, database, broker, and SCADA protocol guides.
* [**For Nerds (`for_nerds.md`)**](for_nerds.md) — Six-stage Rust compiler internals, public Rust crate API, and formal `EBNF` / `GBNF` / `Lark` grammars.