# FrameAssembly (`frameassembly`) — Create Custom `.pcap` Packet Captures from Plain Text Without Root or Programming Experience

[![Crates.io](https://img.shields.io/crates/v/frameassembly.svg)](https://crates.io/crates/frameassembly)
[![Docs.rs](https://docs.rs/frameassembly/badge.svg)](https://docs.rs/frameassembly)
[![Rust 1.85+](https://img.shields.io/badge/rust-1.85%2B%20(Edition%202024)-orange.svg)](https://www.rust-lang.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

[**Copy-Paste Packet Recipes**](#copy-paste-packet-recipes-for-common-network-tasks) • [**The 3-Step Mental Model**](#the-3-step-mental-model-for-network-engineers) • [**Terminal Ladder (`frameassembly show`)**](#visual-packet-ladders--terminal-inspection-frameassembly-show) • [**Multi-Platform Install**](#multi-platform-installation) • [**Wireshark Cheat Sheet**](#from-wireshark--tcpdump-to-fasm-translation-table) • [**Common Mistakes**](#common-syntax-mistakes--plain-english-error-messages) • [**All 81 Protocols**](#supported-protocols--default-wire-behavior) • [**FAQ & Disambiguation**](#faq-what-is-a-fasm-file-frameassembly-vs-flat-assembler-vs-fpga-fasm) • [**Documentation**](#documentation)

**FrameAssembly** (`frameassembly` v1.4.1) is a **rootless, offline "Packets as Code" ("PCAP as Code") packet generator and compiler** that turns a **plain-text packet recipe (`.fasm`, media type `text/vnd.frameassembly`) into a deterministic `.pcap` / `.pcapng` packet capture file** across **81 network protocols spanning Layers 2 through 7**—with no `libpcap` or raw sockets required.

It is built for **network technicians, firewall engineers, Linux system administrators, NOC/SOC analysts, and OT/SCADA integrators** who want a **Scapy alternative without Python**, without clicking through GUI stream dialogs in `Ostinato`, and without fighting raw hexadecimal byte offsets in `text2pcap`. Positioned as the upstream companion compiler to your analysis and replay tools, you simply list the devices in your scenario, write one line per packet using everyday networking terms (`VLAN 100`, `TCP SYN`, `DSTPORT 443`, `DSCP 46`, `SNMP3 TRAP`), and FrameAssembly automatically builds the Ethernet/IPv4/IPv6/TCP/UDP/SCTP headers, calculates lengths and checksums, swaps ports on reply packets (`<-`), and tracks TCP `SEQ`/`ACK` numbers—producing a clean, zero-noise `.pcap` file ready to open in **Wireshark** / **`tshark`**, feed into **Suricata** / **Zeek**, or transmit onto a live network port with **`tcpreplay`**.

---

## Copy-Paste Packet Recipes for Common Network Tasks

### Create Custom `.pcap` Captures from Plain Text (No Root Permissions or Programming Experience Required)

Generate a test capture without setting up a Python environment for `Scapy`, calculating raw hex offsets in `text2pcap`, or needing `sudo` raw-socket permissions. Write your hosts and packet lines in plain text and compile directly to `.pcap` in user space:

```frameassembly
host client { ip 10.0.0.10 mac 00:11:22:33:44:55 }
host server { ip 10.0.0.80 mac aa:bb:cc:dd:ee:ff }

flow web_session(c, s) {
    c -> s tcp syn srcport 51234 dstport 80 win 65535 mss 1460 wait 1ms
    c <- s tcp syn ack win 65535 mss 1460 wait 1ms
    c -> s tcp ack wait 1ms
    c -> s http get uri "/index.html" host_hdr "example.com" wait 5ms
    c <- s http status 200 reason "OK" body "<h1>Hello</h1>" wait 2ms
}

compile {
    web_session(client, server)
}
```

```console
$ frameassembly web.fasm -o web.pcap && frameassembly show web.fasm
```

---

### Test SNMPv1/v2c & Encrypted SNMPv3 Trap Receivers

Verify Zabbix, SolarWinds, LibreNMS, PRTG, or `snmptrapd` alerting rules without waiting for a switch power supply or BGP peer to fail. FrameAssembly generates SNMPv1/v2c polls and encrypted SNMPv3 `authPriv` (`SHA-256` + `AES-128`) traps with standard RFC 3414/3826/7860 cryptography out of the box:

```frameassembly
host core_switch { ip 10.10.1.2  mac 00:1a:2b:3c:4d:01 }
host nms_server  { ip 10.10.1.50 mac 00:1a:2b:3c:4d:50 }

flow snmp_alert_and_poll(sw, nms) {
    sw -> nms vlan 100 snmp3 trap user "netops" engineid "80001f8801" engineboots 5 enginetime 3600 auth sha256 "AuthPass123!" priv aes "PrivPass123!" oid 1.3.6.1.6.3.1.1.5.3 varbind 1.3.6.1.2.1.2.2.1.8.1 int 2 wait 5ms
    nms -> sw vlan 100 snmp2 get community "noc_ro" reqid 101 varbind 1.3.6.1.2.1.1.5.0 null wait 2ms
    nms <- sw vlan 100 snmp2 response community "noc_ro" reqid 101 varbind 1.3.6.1.2.1.1.5.0 string "core-sw-01.dc1" wait 2ms
}

compile {
    snmp_alert_and_poll(core_switch, nms_server)
}
```

```console
$ frameassembly snmp_test.fasm -o snmp_test.pcap && tshark -r snmp_test.pcap
```

---

### Craft 802.1Q VLAN, 802.1ad QinQ, MPLS & DSCP QoS Packets

Desktop OS network stacks and NIC drivers often strip 802.1Q tags on capture and block raw-socket injection of carrier `QinQ` double tags or custom DiffServ markings. FrameAssembly writes `VLAN <id> PCP <0..7>`, `QINQ <s_vid> INNER_VLAN <c_vid>`, `MPLS <label> EXP <0..7>`, and `DSCP <0..63>` headers directly into the `.pcap` file:

```frameassembly
host branch_cpe { ip 10.220.1.10  mac 00:50:56:c0:01:10 }
host hq_gateway { ip 10.220.1.200 mac 00:50:56:c0:01:c8 }

flow metro_qos_and_tls(cpe, hq) {
    cpe -> hq vlan 110 pcp 5 dei 0 dscp 46 rtp pt 0 seq 1 timestamp 160 ssrc 0x10203040 payload "G711_VOICE" wait 5ms
    cpe -> hq qinq 2000 inner_vlan 150 pcp 6 mpls 40960 exp 6 bos 1 mpls_ttl 64 dscp 46 ttl 64 tls client_hello sni "vault.hq.example.com" ciphersuite 4866 alpn "h2" wait 5ms
    cpe <- hq qinq 2000 inner_vlan 150 pcp 6 mpls 40960 exp 6 bos 1 mpls_ttl 63 dscp 46 ttl 63 tls server_hello ciphersuite 4866 alpn "h2" wait 5ms
}

compile {
    metro_qos_and_tls(branch_cpe, hq_gateway)
}
```

```console
$ frameassembly qos.fasm -o qos.pcap && wireshark qos.pcap &
```

---

### Validate Firewall ACLs & Suricata / Zeek IDS Rules

Stateful firewalls and IDS/IPS engines drop isolated packets that lack a valid 3-way TCP handshake or sequence progression. FrameAssembly tracks TCP sequence numbers and reply ports automatically across permitted handshakes, blocked port `RST ACK` rejections, and ICMP Administratively Prohibited replies:

```frameassembly
host dmz_scanner { ip 172.16.99.9 mac 00:1a:2b:3c:4d:09 }
host target_fw   { ip 10.10.1.1   mac 00:1a:2b:3c:4d:01 }

flow firewall_acl_test(scanner, fw) {
    scanner -> fw vlan 200 tcp syn srcport 54320 dstport 443 win 64240 mss 1460 wait 1ms
    scanner <- fw vlan 200 tcp syn ack win 65535 mss 1460 wait 1ms
    scanner -> fw vlan 200 tcp ack wait 2ms
    scanner -> fw vlan 200 tcp syn srcport 54321 dstport 22 win 64240 wait 1ms
    scanner <- fw vlan 200 tcp rst ack wait 2ms
    scanner -> fw vlan 200 ttl 64 icmp echo_request id 500 seq 1 payload "ACL_PING_TEST" wait 1ms
    scanner <- fw vlan 200 ttl 64 icmp dest_unreach code 13
}

compile {
    firewall_acl_test(dmz_scanner, target_fw)
}
```

```console
$ frameassembly firewall.fasm -o firewall.pcap && suricata -r firewall.pcap -k none
```

---

### Build Sanitized Reproducer Captures for Vendor TAC Tickets & CI

Instead of scrubbing live production captures for vendor support tickets (Cisco TAC, Juniper JTAC, Arista) or CI tests—and risking leaked internal IPs or customer data—build a clean, zero-noise reproducer using RFC 5737 documentation subnets (`192.0.2.0/24`, `198.51.100.0/24`):

```frameassembly
host branch_gw { ip 192.0.2.1     mac 00:11:22:aa:bb:01 }
host auth_srv  { ip 198.51.100.10 mac 00:11:22:cc:dd:10 }

flow tac_sanitized_radius(gw, srv) {
    gw -> srv radius access_request user "redacted_user" nas_ip 192.0.2.1 wait 10ms
    gw <- srv radius access_accept wait 5ms
    gw -> srv syslog facility 1 severity 6 hostname "branch-gw" app "tacacs" msg "User authenticated via 802.1X"
}

compile {
    tac_sanitized_radius(branch_gw, auth_srv)
}
```

```console
$ frameassembly tac_repro.fasm -o tac_repro.pcap && frameassembly show tac_repro.fasm
```

---

### Test Industrial OT / SCADA Firewalls (Modbus, DNP3, S7comm, BACnet, OPC UA)

Test industrial firewall conduits and OT security sensors without physical PLCs or vendor engineering workstations. Generate Modbus TCP, IEEE 1815 DNP3 (with automatic CRC-16), Siemens S7comm, BACnet/IP, EtherNet/IP, and OPC UA traffic directly on your laptop:

```frameassembly
host scada_hmi { ip 192.168.100.10 mac 00:1b:21:a0:00:10 }
host plant_plc { ip 192.168.100.50 mac 00:0e:8c:a0:00:50 }

flow ot_firewall_test(hmi, plc) {
    hmi -> plc vlan 110 modbus read_holding_registers txid 1 unitid 1 addr 40001 count 2 wait 2ms
    hmi <- plc vlan 110 modbus read_holding_registers txid 1 unitid 1 count 2 is_response wait 2ms
    hmi -> plc vlan 110 dnp3 read src 1 dst 10 group 60 variation 1 wait 2ms
    hmi -> plc vlan 110 s7comm setup_comm rosctr "JOB" pdu_ref 101 wait 2ms
    hmi -> plc vlan 110 bacnet read_property invoke_id 1 object_type 0 object_instance 1 property_id 85 wait 2ms
    hmi -> plc vlan 110 opcua msg_type "HEL" chunk_type "F" endpoint_url "opc.tcp://192.168.100.50:4840"
}

compile {
    ot_firewall_test(scada_hmi, plant_plc)
}
```

```console
$ frameassembly ot_test.fasm -o ot_test.pcap && tshark -r ot_test.pcap
```

---

## Comparison Matrix: FrameAssembly vs. Traditional Tools

| Capability | FrameAssembly (`.fasm`) | Python + `Scapy` | `text2pcap` / Hex Editing | `Ostinato` (GUI / Streams) |
| :--- | :--- | :--- | :--- | :--- |
| **Who It Is Built For** | **Network technicians, firewall/NOC engineers & CI** (no coding needed) | Python programmers & developers | Analysts editing raw hex dumps | Desktop lab engineers using a GUI |
| **How You Write Packets** | **Plain-text hosts & 1-line-per-packet flows ("Packets as Code")** | Python scripts, loops & class objects | Raw hexadecimal byte offsets | Interactive GUI stream builder dialogs |
| **Low-Level Header Control** | **Full control** over flags, VLAN/QinQ/MPLS tags, QoS, TTL & options | Full control via nested Python code | Manual bit-by-bit hex math | Per-stream protocol field forms |
| **Unset Optional Fields** | **Works out of the box** with standard RFC wire defaults | Varies by protocol layer | None (every byte typed by hand) | Requires filling stream dialogs |
| **Checksums & TCP `SEQ`/`ACK`** | **Automatic checksums, TCP `SEQ`/`ACK` math** & reply port swapping on `<-` | Manual per-packet sequence & port math | Manual hex recalculation on every edit | Stateless stream templates |
| **SNMPv3 `authPriv` Encryption**| **Built-in SNMPv3 encryption** (`MD5`/`SHA`/`SHA-2` + `DES`/`AES`) | Manual ASN.1 BER & crypto code | Impractical by hand | Not built-in |
| **Offline & Rootless Workflow** | **No root, `libpcap`, or raw sockets needed**; ready for `Wireshark` & `tcpreplay` | Requires Python env; root needed for wire send | Offline user space | Requires `drone` agent / privileges |

---

## The 3-Step Mental Model for Network Engineers

Every `.fasm` file is structured in three logical steps that mirror how network technicians diagram traffic:

```text
┌────────────────────────────────────────────────────────────────────────┐
│                      The 3-Step Mental Model                           │
├───────────────────┬───────────────────────────────┬────────────────────┤
│ 1. HOST           │ 2. FLOW                       │ 3. COMPILE         │
│ Declare endpoints │ Define the packet sequence    │ Emit the .pcap     │
│ IP & optional MAC │ 1 statement = 1 wire frame    │ Wire hosts to flow │
│ (v4, v6, any MAC) │ -> forward, <- reply (swaps)  │ Single or loop N   │
└───────────────────┴───────────────────────────────┴────────────────────┘
```

1. **Step 1: Declare Endpoints with `HOST`**: Give friendly names to your IPv4 or IPv6 endpoints. FrameAssembly natively accepts Linux colon (`00:1a:2b:3c:4d:5e`), Windows hyphen (`00-1A-2B-3C-4D-5E`), and Cisco dotted-quad (`001a.2b3c.4d5e`) MAC addresses. If you omit the MAC, FrameAssembly assigns clean unicast MACs or derives standard RFC 1112 / RFC 2464 multicast MACs automatically.
2. **Step 2: Define Packet Sequences with `FLOW`**: Write traffic patterns between placeholder endpoints (`c`, `s`). Every statement inside a `FLOW` block generates **exactly one Ethernet frame**. Using `c -> s` marks a forward request; using `c <- s` marks a reverse response that automatically swaps source and destination ports.
3. **Step 3: Build the Capture with `COMPILE`**: Connect your declared hosts into your flow templates. A single flow can be executed once or repeated across multiple host pairs and `loop <count>` iterations.

---

## Visual Packet Ladders & Terminal Inspection (`frameassembly show`)

FrameAssembly aligns directly with Wireshark's **Flow Graph** ladder view:

```text
  Wireshark Flow Graph               FrameAssembly .fasm Flow Statement
--------------------------------------------------------------------------------------
  10.0.0.10             10.0.0.80
      |                     |
      |   TCP 51234 -> 80   |
      |-------------------->|        c -> s tcp syn srcport 51234 dstport 80 win 65535
      |        [SYN]        |
      |                     |
      |   TCP 80 -> 51234   |
      |<--------------------|        c <- s tcp syn ack win 65535 wait 1ms
      |      [SYN, ACK]     |
      |                     |
      |   TCP 51234 -> 80   |
      |-------------------->|        c -> s tcp ack wait 1ms
      |        [ACK]        |
      |                     |
      |  HTTP GET /index    |
      |-------------------->|        c -> s http get uri "/index.html" host_hdr "example.com"
      |      [PSH, ACK]     |
      |                     |
      |   HTTP 200 OK       |
      |<--------------------|        c <- s http status 200 reason "OK" body "<h1>Hello</h1>"
      |      [PSH, ACK]     |
```

### Inspecting Frames in Terminal Without Writing Files

Use `frameassembly show <file.fasm>` to inspect your generated ladder directly in your terminal without touching the disk:

```console
$ frameassembly show demo.fasm
#      Time (ms)   Source -> Destination                    Proto       Bytes  Summary
--------------------------------------------------------------------------------------------------------------
1      0.000       10.0.0.10 -> 10.0.0.80                   TCP         58     51234 -> 80 [SYN] seq=1000 len=0
2      1.000       10.0.0.80 -> 10.0.0.10                   TCP         58     80 -> 51234 [SYN ACK] seq=2000 ack=1001 len=0
3      2.000       10.0.0.10 -> 10.0.0.80                   TCP         54     51234 -> 80 [ACK] seq=1001 ack=2001 len=0
4      3.000       10.0.0.10 -> 10.0.0.80                   HTTP        97     51234 -> 80 [ACK PSH] seq=1001 ack=2001 len=43
5      8.000       10.0.0.80 -> 10.0.0.10                   HTTP        126    80 -> 51234 [ACK PSH] seq=2001 ack=1044 len=72
```

To compile to a `.pcap` capture file:

```console
$ frameassembly demo.fasm -o output.pcap
Successfully parsed 2 hosts, 1 flows
Starting PCAP compilation...
Successfully generated output.pcap (5 frames, 393 bytes, duration 8.000 ms)
```

You can then inspect the output in **Wireshark** or replay it on a live network port with **`tcpreplay`**:

```bash
# Inspect in Wireshark or tshark
tshark -r output.pcap
wireshark output.pcap &

# Replay onto a live interface or firewall test port
sudo tcpreplay -i eth0 output.pcap
```

---

## Multi-Platform Installation

Install FrameAssembly using your platform's standard package manager:

| Platform / OS | Package Manager / Method | Installation Command | Package Identifier |
| :--- | :--- | :--- | :--- |
| **Linux (Universal)** | **One-line installer** (prebuilt binary fast-path + fallback) | `curl -fsSL https://raw.githubusercontent.com/SteveWinschel/FrameAssembly/main/install.sh \| sh` | `frameassembly` |
| **Debian / Ubuntu** | **APT** (`.deb` package from GitHub Releases) | `curl -fsSLo /tmp/frameassembly.deb https://github.com/SteveWinschel/FrameAssembly/releases/latest/download/frameassembly_amd64.deb && sudo apt install -y /tmp/frameassembly.deb && rm -f /tmp/frameassembly.deb` | `frameassembly` |
| **macOS & Linux** | **Homebrew** (Tap) | `brew install SteveWinschel/tap-FrameAssembly/frameassembly` | `frameassembly` |
| **Arch Linux** | **AUR** (`yay` / `paru`) | `yay -S frameassembly-bin` | `frameassembly-bin` |
| **Windows 10 / 11** | **WinGet** (Windows Package Manager) | `winget install SteveWinschel.FrameAssembly` | `SteveWinschel.FrameAssembly` |
| **Windows** | **Scoop** | `scoop bucket add frameassembly https://github.com/SteveWinschel/homebrew-tap-FrameAssembly && scoop install frameassembly` | `frameassembly` |
| **Any (Rust 1.85+)** | **Cargo** (crates.io) | `cargo install frameassembly` | `frameassembly` |
| **Browser / Node.js** | **NPM** (WebAssembly compiler) | `npm install frameassembly-wasm` | `frameassembly-wasm` |
| **VS Code / Cursor / VSCodium** | **VS Marketplace & Open VSX** | `code --install-extension SteveWinschel.frameassembly` | `SteveWinschel.frameassembly` |
| **Direct Binaries** | **GitHub Releases** (`.tar.gz`, `.zip`, `.deb`, `.vsix`) | [Download from GitHub Releases (`latest`)](https://github.com/SteveWinschel/FrameAssembly/releases/latest) | `v1.4.1` |

---

## Common Syntax Mistakes & Plain-English Error Messages

FrameAssembly's diagnostic engine provides actionable, plain-English `"Did you mean...?"` hints designed specifically for network technicians:

| Networking Habit / Typo | Incorrect in `.fasm` | Correct `.fasm` Syntax | Helpful Compiler Diagnostic Hint |
| :--- | :--- | :--- | :--- |
| **Assigning with `:` or `=`** | `host rtr { ip: 10.0.0.1 }` | `host rtr { ip 10.0.0.1 }` | *"Separate keywords and values with a space instead of '=' or ':'"* |
| **CIDR subnet masks in HOST** | `ip 10.0.0.1/24` | `ip 10.0.0.1` | *"Remove the CIDR prefix length and write a plain IP address"* |
| **Bash / Python `#` comments** | `# Test DMZ flow` | `// Test DMZ flow` | *"Replace '#' with '//' to write a comment"* |
| **Short port names (`sport`/`dport`)** | `sport 50000 dport 443` | `srcport 50000 dstport 443` | *"Replace 'sport' with 'SRCPORT <port>'"* |
| **TCP ACK with number** | `tcp ack 1000` | `tcp ack acknum 1000` | *"Use 'ACK' alone as a TCP flag, and 'ACKNUM <number>' for the acknowledgment value"* |
| **IPv6 Hop Limit keyword** | `hoplimit 64` / `hlim 64` | `ttl 64` | *"Use 'TTL <value>' for both IPv4 Time-to-Live and IPv6 Hop Limit"* |
| **IPv4 TOS or Traffic Class** | `tos 0xb8` / `trafficclass` | `dscp 46 ecn 0` | *"Use 'DSCP <0..63>' and optional 'ECN <0..3>'"* |
| **TCP flags in brackets** | `flags [SYN, ACK]` | `tcp syn ack` | *"Write TCP flags as space-separated words without brackets"* |
| **Delay prefix (`+5ms`)** | `+5ms c -> s tcp syn` | `c -> s tcp syn wait 5ms` | *"Put 'WAIT <duration>' at the end of the packet statement instead"* |
| **Omitting flow arguments** | `flow test { ... }` | `flow test(c, s) { ... }` | *"Add endpoint parameter names in parentheses after the flow name"* |
| **Omitting COMPILE block** | *(only HOST and FLOW)* | `compile { test(h1, h2) }` | *"Every .fasm file must contain exactly one COMPILE { ... } block at the end"* |
| **Passing x86 Flat Assembler file** | `format PE` / `section` / `;` | *(FrameAssembly DSL)* | *"This file appears to be an x86 Flat Assembler file, not a FrameAssembly network packet specification"* |
| **Passing FPGA FASM file** | `CLBLL_L_X0Y0.ENABLE` / `#` | *(FrameAssembly DSL)* | *"This file appears to be an FPGA FASM file, not a FrameAssembly network packet specification"* |

---

## From Wireshark / `tcpdump` to `.fasm` Translation Table

If you know how to read Wireshark filters or `tcpdump` expressions, you already know FrameAssembly syntax:

| What You See in Wireshark / `tcpdump` / Switch CLI | Wireshark Display Filter / `tcpdump` | How You Write It in `.fasm` | Reference Table Link |
| :--- | :--- | :--- | :--- |
| **Linux / Wireshark colon MAC** | `eth.addr == 00:1a:2b:3c:4d:5e` | `mac 00:1a:2b:3c:4d:5e` (or `srcmac` / `dstmac`) | [L2 MAC Formats](docs/l2_protocols.md#universal-ethernet-ii-header-overrides--automatic-mac-derivation) |
| **Windows `ipconfig /all` hyphen MAC** | `00-1A-2B-3C-4D-5E` | `mac 00-1A-2B-3C-4D-5E` *(supported natively!)* | [L2 MAC Formats](docs/l2_protocols.md#universal-ethernet-ii-header-overrides--automatic-mac-derivation) |
| **Cisco IOS `show mac address-table` dotted MAC** | `001a.2b3c.4d5e` | `mac 001a.2b3c.4d5e` *(supported natively!)* | [L2 MAC Formats](docs/l2_protocols.md#universal-ethernet-ii-header-overrides--automatic-mac-derivation) |
| **Custom Ethernet EtherType** | `eth.type == 0x88cc` | `ethertype 0x88cc` | [L2 EtherType Overrides](docs/l2_protocols.md#universal-ethernet-ii-header-overrides--automatic-mac-derivation) |
| **802.1Q VLAN ID & 802.1p CoS Priority** | `vlan.id == 100 && vlan.priority == 5` | `vlan 100 pcp 5 dei 0` | [802.1p CoS (`PCP`) Table](docs/l2_protocols.md#ieee-8021p-class-of-service-pcp-reference-table) |
| **802.1ad Carrier QinQ Double Tag** | `vlan.id == 2000 && vlan.id == 100` | `qinq 2000 inner_vlan 100` | [VLAN & QinQ Guide](docs/l2_protocols.md#2-virtual-lan-vlan--ieee-8021q--provider-bridging-qinq--ieee-8021ad) |
| **MPLS Label, Traffic Class (`EXP`) & TTL** | `mpls.label == 16000 && mpls.exp == 5` | `mpls 16000 exp 5 bos 1 mpls_ttl 64` | [MPLS Labels Guide](docs/l2_protocols.md#7-multiprotocol-label-switching-mpls--rfc-3032--rfc-5462) |
| **DiffServ QoS (`DSCP`) & `ECN`** | `ip.dsfield.dscp == 46` (`EF` Voice) | `dscp 46 ecn 0` | [DiffServ `DSCP` & `ECN` Table](docs/l3_protocols.md#common-diffserv-dscp--ecn-quick-reference) |
| **IPv4 TTL or IPv6 Hop Limit** | `ip.ttl == 64` / `ipv6.hlim == 64` | `ttl 64` *(works on both IPv4 and IPv6)* | [Universal L3 Modifiers](docs/l3_protocols.md#1-universal-ipv4--ipv6-header-modifiers) |
| **IPv4 Don't Fragment (`DF`) / Fragmentation** | `ip.flags.df == 1` / `ip.frag_offset` | `df` or `ipid 0x1234 mf fragoffset 0` | [IPv4 Fragmentation Guide](docs/l3_protocols.md#example-ipv4-fragmentation-reassembly--dual-stack-qos-markings) |
| **TCP / UDP / SCTP Source & Dest Ports** | `tcp.srcport == 50000 && tcp.dstport == 443` | `srcport 50000 dstport 443` | [L4 Transports Guide](docs/l4_transports.md) |
| **TCP Flags (`SYN`, `ACK`, `RST`, `FIN`, `PSH`)** | `tcp.flags.syn == 1 && tcp.flags.ack == 1` | `tcp syn ack` *(bare flag words, no brackets)* | [TCP Flags & Options](docs/l4_transports.md) |
| **TCP Sequence, Ack Number & Window Size** | `tcp.seq == 1000 && tcp.ack == 2000` | `seq 1000 acknum 2000 win 65535` | [TCP Sequence Tracking](docs/l4_transports.md) |
| **SNMP Trap / Poll OIDs (`sysName`, `linkDown`)** | `snmp.name == 1.3.6.1.2.1.1.5.0` | `varbind 1.3.6.1.2.1.1.5.0 string "sw-01"` | [Standard MIB-II OID Table](docs/l7_snmp.md#22-common-standard-mib-ii--notification-oids-cheat-sheet) |

---

## Use ChatGPT, Claude, or Copilot to Write `.fasm` from Plain English

FrameAssembly publishes a machine-readable reference sheet ([`llms.txt`](llms.txt)) specifically optimized for AI coding assistants. Copy and paste the prompt below into **ChatGPT**, **Claude**, **Microsoft Copilot**, or **Cursor**:

```text
Read the FrameAssembly (.fasm) syntax reference at:
https://raw.githubusercontent.com/SteveWinschel/FrameAssembly/main/llms.txt

Write a complete, compilable FrameAssembly (.fasm) packet recipe with HOST, FLOW, and COMPILE blocks for the following network scenario:
[Describe your scenario here — for example: "A branch router at 10.10.1.1 sending an encrypted SNMPv3 SHA256 + AES trap to NMS server 10.10.1.50 on VLAN 100, followed by a TCP 3-way handshake and HTTPS TLS 1.3 ClientHello to vault.example.com"]

Rules to follow:
- Use only canonical HOST <id> { IP <ip> [MAC <mac>] }, FLOW <id>(<params>) { ... }, and COMPILE { ... } blocks.
- Use SRCPORT, DSTPORT, ACKNUM, bare TCP flag names (SYN ACK), and trailing WAIT <n><ms|s|us|ns>.
- Output only the compilable .fasm file.
```

---

## Universal Layer 2–4 Modifiers

Any packet line can attach Layer 2 trunk tags, Layer 3 QoS/fragmentation headers, Layer 4 port/TCP options, raw payloads, and capture timestamps alongside any protocol:

| Category | Modifiers | Networking Purpose & Wire Effect |
| :--- | :--- | :--- |
| **Layer 2** | `SRCMAC <mac>`, `DSTMAC <mac>` | Override outer Ethernet source or destination MAC (`00:1a:2b:3c:4d:5e`, `00-1A-2B-3C-4D-5E`, or `001a.2b3c.4d5e`) |
| | `ETHERTYPE <u16>` | Override outer Ethernet Type field (e.g. `0x8100`, `0x8847`, `0x88cc`) |
| | `VLAN <1..4094> [PCP <0..7>] [DEI <0..1>]` | Add IEEE 802.1Q VLAN tag, 802.1p priority (`PCP`), and drop eligible bit (`DEI`) |
| | `QINQ <1..4094> [INNER_VLAN <1..4094>]` | Add IEEE 802.1ad outer service tag (`S-VLAN`) + inner customer tag (`C-VLAN`) |
| | `MPLS <label> [EXP <0..7>] [BOS <0..1>] [MPLS_TTL <u8>]` | Add MPLS shim header (`0x8847`) with 20-bit label, Traffic Class (`EXP`), `BOS`, and TTL |
| **Layer 3** | `TTL <0..255>` | Set IPv4 Time-To-Live or IPv6 Hop Limit |
| | `DSCP <0..63>`, `ECN <0..3>` | Set DiffServ QoS Code Point (e.g. `46` for voice `EF`) and ECN congestion bits |
| | `FLOWLABEL <0..1048575>` | Set 20-bit IPv6 Flow Label (automatically ignored when the flow runs over IPv4) |
| | `IPID <u16>`, `DF`, `MF`, `FRAGOFFSET <u16>` | Set IPv4 Identification, Don't Fragment, More Fragments, and 8-byte fragment offset |
| **Layer 4** | `SRCPORT <u16>`, `DSTPORT <u16>` | Override TCP, UDP, or SCTP source and destination port numbers |
| | `TRANSPORT TCP \| UDP` | Select TCP or UDP for dual-transport protocols (`DNS`, `SIP`, `NFS`, `SYSLOG`) |
| | `SEQ <u32>`, `ACKNUM <u32>`, `WIN <u16>` | Override TCP sequence number, acknowledgment number, and window size |
| | `MSS <u16>`, `WSCALE <u8>`, `SACK_PERM` | Add TCP Maximum Segment Size, Window Scale, and SACK Permitted options |
| | `TSVAL <u32>`, `TSECR <u32>`, `URGENT <u16>` | Add RFC 7323 TCP Timestamp (`TSval`/`TSecr`) options and Urgent Pointer |
| **Payload** | `PAYLOAD "<string>"` | Append ASCII/UTF-8 payload text (supports `\r`, `\n`, `\t`, `\xHH` escapes) |
| | `HEXPAYLOAD "<hex>"` | Append raw hexadecimal bytes (e.g. `"deadbeef"`) |
| **Timing** | `WAIT <duration>` | Advance `.pcap` timestamp after emitting the packet (`ns`, `us`, `ms`, `s`, `m`) |

---

## Supported Protocols & Default Wire Behavior

Every protocol works out of the box with standard RFC defaults when optional fields are omitted:

| Protocol | Layer | Transport | Default Port | Default Wire Behavior |
| :--- | :--- | :--- | :--- | :--- |
| `ARP` | L2 | Ethernet (`0x0806`) | N/A | Request, Hardware `1` (Ethernet), Protocol `0x0800` (IPv4); uses ICMPv6 Neighbor Solicitation on IPv6. |
| `VLAN` | L2 | Ethernet (`0x8100`) | N/A | IEEE 802.1Q tag, default VLAN ID `100`, `PCP 0`, `DEI 0`. |
| `QINQ` | L2 | Ethernet (`0x88A8`) | N/A | IEEE 802.1ad outer tag (`VLAN 100`) + 802.1Q inner tag (`VLAN 200`). |
| `LLDP` | L2 | Ethernet (`0x88CC`) | N/A | Multicast `01:80:c2:00:00:0e`, Chassis ID & Port ID TLVs, `TTL 120s`, End TLV. |
| `STP` | L2 | LLC/SNAP (`0x4242`) | N/A | Multicast `01:80:c2:00:00:00`, Configuration BPDU, Root ID, Bridge ID, `Cost 0`. |
| `LACP` | L2 | Ethernet (`0x8809`) | N/A | Multicast `01:80:c2:00:00:02`, Actor Info & Partner Info TLVs, Collector TLV. |
| `EAPOL` | L2 | Ethernet (`0x888E`) | N/A | IEEE 802.1X Version `1`, EAP-Packet Identity request/response. |
| `MPLS` | L2.5 | Ethernet (`0x8847`) | N/A | Label `16`, `EXP 0`, `BOS 1`, `TTL 64` unicast shim header. |
| `ICMP` | L3 | IP proto `1` / `58` | N/A | Echo Request (Type `8` for IPv4, Type `128` for IPv6), `ID 1`, `Seq 1`. |
| `NDP` | L3 | IPv6 ICMPv6 (`58`) | N/A | Neighbor Solicitation (Type `135`), Hop Limit `255`. |
| `IGMP` | L3 | IPv4 proto `2` | N/A | Membership Query to `224.0.0.1` (All Hosts), Max Resp Time `10.0s`. |
| `MLD` | L3 | IPv6 ICMPv6 (`58`) | N/A | Multicast Listener Query (Type `130`) to `ff02::1`. |
| `GRE` | L3 | IP proto `47` | N/A | GRE Version `0`, Protocol Type `0x0800` (IPv4) / `0x86DD` (IPv6). |
| `VXLAN` | L3 | UDP | `4789` | Flags `0x08` (`I` flag), 24-bit `VNI 1000`, 8-byte VXLAN header + inner frame. |
| `GENEVE` | L3 | UDP | `6081` | Version `0`, 24-bit `VNI 1000`, Protocol Type `0x6558` (Ethernet). |
| `IPSEC` | L3 | IP proto `50` | N/A | `SPI 0x1000`, `Sequence 1`, default ESP wire header. |
| `ESP` | L3 | IP proto `50` | N/A | Encapsulating Security Payload, `SPI 0x1000`, `Sequence 1`. |
| `AH` | L3 | IP proto `51` | N/A | Authentication Header, `SPI 0x1000`, `Sequence 1`, 96-bit ICV. |
| `IKEV2` | L3 | UDP | `500` | `SA_INIT` exchange (Type `34`), Initiator SPI set, Responder SPI `0`. |
| `WIREGUARD` | L3 | UDP | `51820` | Handshake Initiation message (Type `1`), Sender index `1`. |
| `OSPF` | L3 | IP proto `89` | N/A | OSPFv2 (IPv4) or OSPFv3 (IPv6) Hello packet, Area `0.0.0.0`, to `224.0.0.5` / `ff02::5`. |
| `BGP` | L3 | TCP | `179` | BGP-4 16-byte marker, `OPEN` message, `ASN 65001`, Hold Time `180s`. |
| `RIP` | L3 | UDP | `520` | RIPv2 Response (Command `2`), Version `2`, Route AFI `2` (IP), Metric `1`. |
| `VRRP` | L3 | IP proto `112` | N/A | VRRPv3 Advertisement, `VRID 1`, `Priority 100`, `TTL 255`. |
| `HSRP` | L3 | UDP | `1985` | Cisco HSRP Hello, State Active, `Group 1` to `224.0.0.2`. |
| `PIM` | L3 | IP proto `103` | N/A | PIM-SM Hello message, `DR Priority 1` to `224.0.0.13` / `ff02::d`. |
| `BFD` | L3 | UDP | `3784` | Single-hop Control packet, State `Up`, Detect Mult `3`, Min TX/RX `1000ms`. |
| `OPENFLOW` | L3 | TCP | `6653` | OpenFlow 1.3 (`0x04`) Hello / Features Request, `XID 1`. |
| `TCP` | L4 | IP proto `6` | `80` | Sequence numbers auto-incremented, `ACK` numbers tracked across reverse arrows. |
| `UDP` | L4 | IP proto `17` | `80` | Stateless UDP datagram with computed RFC 768 checksum. |
| `SCTP` | L4 | IP proto `132` | `80` | Verification Tag `0`, `DATA` chunk, `TSN 1`, `Stream 0`, CRC32c checksum. |
| `SNMP1` | L7 | UDP | `162` / `161` | Community `"public"`, `sysUpTime 0`, Trap/Poll PDU, RFC 1157 BER encoding. |
| `SNMP2` | L7 | UDP | `162` / `161` | Community `"public"`, `sysUpTime 0`, Trap/Poll PDU, RFC 3416 BER encoding. |
| `SNMP3` | L7 | UDP | `161` / `162` | USM security model, RFC 3414 / 3826 / 7860 authentication & privacy engine. |
| `DNS` | L7 | UDP / TCP | `53` | Standard Query, `TXID 0x1234`, `QNAME "example.com"`, `QTYPE A` / `AAAA`. |
| `MDNS` | L7 | UDP | `5353` | Multicast DNS Query (`TXID 0`) to `224.0.0.251` / `ff02::fb`. |
| `DHCP` | L7 | UDP | `67`/`68` (`546`/`547` v6) | `DHCPDISCOVER` (IPv4) or `Solicit` (IPv6) with client MAC. |
| `NTP` | L7 | UDP | `123` | Mode `3` (Client), Version `4`, Stratum `0`, Poll `4`. |
| `PTP` | L7 | UDP | `319` / `320` | IEEE 1588-2008 Version `2` `Sync` message, Domain `0`. |
| `RADIUS` | L7 | UDP | `1812` / `1813` | `Access-Request` (Code `1`, port `1812`; Accounting on `1813`), `Identifier 1`. |
| `TACACS` | L7 | TCP | `49` | TACACS+ Authentication Start, `Session ID 0x12345678`. |
| `SYSLOG` | L7 | UDP / TCP | `514` | RFC 5424 PRI `<14>` (Facility `1` User, Severity `6` Info), `APP "frameassembly"`. |
| `NETFLOW` | L7 | UDP | `2055` | Cisco NetFlow v5 Flow Record export packet. |
| `IPFIX` | L7 | UDP | `4739` | RFC 7011 IPFIX Observation Domain & Data Record packet. |
| `SFLOW` | L7 | UDP | `6343` | sFlow v5 Flow Sample datagram. |
| `TFTP` | L7 | UDP | `69` | Read Request (`RRQ`), `Filename "file.bin"`, `Mode "octet"`. |
| `FTP` | L7 | TCP | `21` | Greeting banner `"220 FTP Server Ready\r\n"` or control command. |
| `SSH` | L7 | TCP | `22` | Identification banner `"SSH-2.0-FrameAssembly_1.0\r\n"`. |
| `TELNET` | L7 | TCP | `23` | IAC `WILL`/`DO` negotiation bytes (`\xff\xfb...`). |
| `HTTP` | L7 | TCP | `80` | `GET / HTTP/1.1\r\nHost: <host>\r\n\r\n`. |
| `HTTP2` | L7 | TCP | `443` | 24-byte client connection preface (`PRI * HTTP/2.0...`) + `SETTINGS` frame. |
| `GRPC` | L7 | TCP | `50051` | Length-prefixed gRPC frame over HTTP/2 (`application/grpc`). |
| `WEBSOCKET`| L7 | TCP | `80` | RFC 6455 WebSocket frame with optional client masking. |
| `TLS` | L7 | TCP | `443` | TLS 1.3 `ClientHello` with `SNI` and `supported_versions` extensions. |
| `QUIC` | L7 | UDP | `443` | QUIC v1 `Initial` packet or 1-RTT `Short` packet. |
| `STUN` | L7 | UDP | `3478` | Binding Request, RFC 8489 Magic Cookie `0x2112A442`. |
| `SIP` | L7 | UDP / TCP | `5060` | `INVITE sip:bob@domain SIP/2.0\r\n...`. |
| `RTP` | L7 | UDP | `5004` | RTP Version `2`, Payload Type `0` (PCMU), `Seq 1`, `Timestamp 0`. |
| `RTSP` | L7 | TCP | `554` | `DESCRIBE rtsp://server/media RTSP/1.0\r\n...`. |
| `SMTP` | L7 | TCP | `25` | `EHLO mail.example.com\r\n`. |
| `IMAP` | L7 | TCP | `143` | `A001 CAPABILITY\r\n`. |
| `POP3` | L7 | TCP | `110` | `+OK POP3 server ready\r\n` or `USER`/`PASS` command. |
| `KERBEROS` | L7 | UDP / TCP | `88` | Kerberos v5 `AS-REQ` for `krbtgt` ticket. |
| `LDAP` | L7 | TCP | `389` | LDAPv3 `BindRequest` (Simple) or `SearchRequest` message. |
| `SMB` | L7 | TCP | `445` | SMB2/3 `Negotiate Protocol Request`. |
| `NFS` | L7 | TCP / UDP | `2049` | ONC-RPC NFSv4 `NULL` / `COMPOUND` call. |
| `REDIS` | L7 | TCP | `6379` | RESP command `*1\r\n$4\r\nPING\r\n`. |
| `MEMCACHED`| L7 | TCP / UDP | `11211` | Text command `version\r\n` or Binary `0x80` packet. |
| `MYSQL` | L7 | TCP | `3306` | Initial Handshake Packet v10 or `COM_QUERY`. |
| `POSTGRES` | L7 | TCP | `5432` | StartupMessage v3.0 or Simple Query (`'Q'`). |
| `MQTT` | L7 | TCP | `1883` | MQTT v3.1.1 `CONNECT` packet, Clean Session. |
| `COAP` | L7 | UDP | `5683` | Confirmable (`CON`) `GET`, Code `0.01`, `Msg ID 1`. |
| `AMQP` | L7 | TCP | `5672` | 8-byte protocol header `'AMQP\x00\x00\x09\x01'`. |
| `SSDP` | L7 | UDP | `1900` | Multicast `M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n...`. |
| `WHOIS` | L7 | TCP | `43` | Query string `"example.com\r\n"`. |
| `MODBUS` | L7 | TCP | `502` | 7-byte MBAP header + Function `3` (`Read Holding Registers`). |
| `BACNET` | L7 | UDP | `47808` | BVLC `0x81` + APDU Unconfirmed `WHO-IS` or `READ-PROPERTY`. |
| `DNP3` | L7 | TCP / UDP | `20000` | IEEE 1815 `0x0564` Data Link Header + Function `1` (`Read`) + CRC-16. |
| `S7COMM` | L7 | TCP | `102` | TPKT + ISO-on-TCP COTP + S7 `0x32` Setup/Read/Write Job. |
| `ETHERNETIP`| L7 | TCP / UDP | `44818` | Encapsulation Command `0x0065` (`Register Session`) or CIP Data. |
| `OPCUA` | L7 | TCP | `4840` | Hello message `HEL` (Chunk `'F'`) with endpoint URL. |

---

## Exhaustive Protocol & Sub-Keyword Reference (All 81 Protocols)

### 1. Layer 2 Switching & Data-Link Protocols (8 Protocols — [`docs/l2_protocols.md`](docs/l2_protocols.md))

- [examples/l2/arp/](examples/l2/arp/) — **`ARP` (RFC 826 / RFC 5227):** `REQUEST`, `REPLY`, `GRATUITOUS` / `GARP`, `SHA <mac>` / `SENDERMAC <mac>`, `SPA <ip>` / `SENDERIP <ip>`, `THA <mac>` / `TARGETMAC <mac>`, `TPA <ip>` / `TARGETIP <ip>`.
- [examples/l2/vlan/](examples/l2/vlan/) — **`VLAN` (IEEE 802.1Q):** `VLAN <1..4094>`, `PCP <0..7>`, `DEI <0..1>`.
- [examples/l2/qinq/](examples/l2/qinq/) — **`QINQ` (IEEE 802.1ad Provider Bridging):** `QINQ <1..4094>`, `INNER_VLAN <1..4094>`, `PCP <0..7>`, `DEI <0..1>`.
- [examples/l2/lldp/](examples/l2/lldp/) — **`LLDP` (IEEE 802.1AB):** `CHASSIS_ID "<str>"`, `PORT_ID "<str>"`, `TTL <u16>`, `SYSNAME "<str>"`, `SYSDESC "<str>"`.
- [examples/l2/stp/](examples/l2/stp/) — **`STP` (IEEE 802.1D / 802.1w RSTP):** `RSTP`, `ROOT_ID "<prio>/<mac>"` / `ROOTID "<str>"`, `BRIDGE_ID "<prio>/<mac>"` / `BRIDGEID "<str>"`, `COST <u32>`, `PORT_ID <u16>`, `MAX_AGE <u16>`, `HELLO_TIME <u16>`, `FORWARD_DELAY <u16>`, `FLAGS <u8>`.
- [examples/l2/lacp/](examples/l2/lacp/) — **`LACP` (IEEE 802.3ad):** `ACTOR_SYS <mac>`, `ACTOR_KEY <u16>`, `ACTOR_PORT <u16>`, `ACTOR_STATE <u8>`, `PARTNER_SYS <mac>`, `PARTNER_KEY <u16>`, `PARTNER_PORT <u16>`, `PARTNER_STATE <u8>`.
- [examples/l2/eapol/](examples/l2/eapol/) — **`EAPOL` (IEEE 802.1X NAC):** `VERSION <u8>`, `TYPE <START|LOGOFF|KEY|EAP_PACKET>`, `EAP_CODE <u8>`, `EAP_ID <u8>`, `EAP_METHOD <u8>`, `IDENTITY "<str>"`.
- [examples/l2/mpls/](examples/l2/mpls/) — **`MPLS` (RFC 3032):** `MPLS <label>` / `LABEL <u32>`, `EXP <0..7>` / `TC <0..7>`, `BOS <0..1>`, `MPLS_TTL <u8>`.

### 2. Layer 3 Control, Tunneling, VPN & Routing Protocols (20 Protocols — [`docs/l3_protocols.md`](docs/l3_protocols.md))

- [examples/l3/icmp/](examples/l3/icmp/) — **`ICMP` (RFC 792 / RFC 4443 Dual-Stack):** `ECHO_REQUEST`, `ECHO_REPLY`, `DEST_UNREACH`, `TIME_EXCEEDED`, `REDIRECT`, `TYPE <u8>`, `CODE <u8>`, `ID <u16>`, `SEQ <u16>`, `GATEWAY <ip>`.
- [examples/l3/ndp/](examples/l3/ndp/) — **`NDP` (RFC 4861 IPv6 Neighbor Discovery):** `ROUTER_SOLICIT`, `ROUTER_ADVERT`, `NEIGHBOR_SOLICIT`, `NEIGHBOR_ADVERT`, `REDIRECT`, `TARGET <ipv6>`, `SLLA <mac>`, `TLLA <mac>`, `ROUTER_LIFETIME <u16>`.
- [examples/l3/igmp/](examples/l3/igmp/) — **`IGMP` (RFC 2236 / RFC 3376):** `QUERY`, `REPORT`, `LEAVE`, `V1`, `V2`, `V3`, `VERSION <1..3>`, `GROUP <ipv4>`, `MAX_RESP <u8>`.
- [examples/l3/mld/](examples/l3/mld/) — **`MLD` (RFC 2710 / RFC 3810 IPv6 Multicast):** `QUERY`, `REPORT`, `DONE`, `MULTICAST_ADDR <ipv6>`, `MAX_RESP_DELAY <u16>`.
- [examples/l3/gre/](examples/l3/gre/) — **`GRE` (RFC 2784 / RFC 2890):** `CHECKSUM`, `GRE_KEY <u32>`, `GRE_SEQ <u32>`, `GRE_PROTO <u16>`.
- [examples/l3/vxlan/](examples/l3/vxlan/) — **`VXLAN` (RFC 7348):** `VNI <0..16777215>` / `VNID <u32>`, `SRCPORT <u16>`, `DSTPORT <u16>`.
- [examples/l3/geneve/](examples/l3/geneve/) — **`GENEVE` (RFC 8926):** `VNI <0..16777215>` / `VNID <u32>`, `PROTOCOL_TYPE <u16>`, `OPT_CLASS <u16>`, `OPT_TYPE <u8>`.
- [examples/l3/ipsec/](examples/l3/ipsec/) — **`IPSEC` (RFC 4301):** `SPI <u32>`, `SEQ <u32>`, `IV "<hex>"`, `ICV "<hex>"`, `NEXT_HEADER <u8>`.
- [examples/l3/esp/](examples/l3/esp/) — **`ESP` (RFC 4303):** `SPI <u32>`, `SEQ <u32>`, `IV "<hex>"`, `ICV "<hex>"`, `NEXT_HEADER <u8>`.
- [examples/l3/ah/](examples/l3/ah/) — **`AH` (RFC 4302):** `SPI <u32>`, `SEQ <u32>`, `ICV "<hex>"`, `NEXT_HEADER <u8>`.
- [examples/l3/ikev2/](examples/l3/ikev2/) — **`IKEV2` (RFC 7296):** `SA_INIT`, `CREATE_CHILD_SA`, `INFORMATIONAL`, `EXCHANGE <mode>`, `INITIATOR_SPI <u64>`, `RESPONDER_SPI <u64>`, `MSGID <u32>`, `FLAGS <u8>`, `NEXT_PAYLOAD <u8>`.
- [examples/l3/wireguard/](examples/l3/wireguard/) — **`WIREGUARD` (WireGuard VPN):** `TYPE <INITIATION|RESPONSE|COOKIE|DATA>` (or bare `INITIATION`, `COOKIE`, `DATA`), `SENDER <u32>`, `RECEIVER <u32>`, `COUNTER <u64>`.
- [examples/l3/ospf/](examples/l3/ospf/) — **`OSPF` (RFC 2328 OSPFv2 / RFC 5340 OSPFv3):** `HELLO`, `DBD`, `LSR`, `LSU`, `LSACK`, `ROUTER_ID <ipv4>`, `AREA_ID <u32>`, `HELLO_INTERVAL <u16>`, `DEAD_INTERVAL <u32>`, `PRIORITY <u8>`.
- [examples/l3/bgp/](examples/l3/bgp/) — **`BGP` (RFC 4271 / RFC 2545 BGP-4):** `OPEN`, `UPDATE`, `NOTIFICATION`, `KEEPALIVE`, `ASN <u32>`, `HOLDTIME <u16>`, `BGPID <ipv4>`, `PREFIX "<cidr>"`, `NEXTHOP <ip>`.
- [examples/l3/rip/](examples/l3/rip/) — **`RIP` (RFC 2453 RIPv2 / RFC 2080 RIPng):** `REQUEST`, `RESPONSE`, `PREFIX <ip>`, `NEXTHOP <ip>`, `METRIC <1..16>`, `TAG <u16>`.
- [examples/l3/vrrp/](examples/l3/vrrp/) — **`VRRP` (RFC 5798 VRRPv3 / RFC 3768 VRRPv2):** `VERSION <2|3>`, `VRID <1..255>`, `PRIORITY <0..255>`, `ADV_INT <u16>`, `VIP <ip>`.
- [examples/l3/hsrp/](examples/l3/hsrp/) — **`HSRP` (RFC 2281):** `GROUP <u8>`, `PRIORITY <u8>`, `STATE <u8>`, `HELLOTIME <u8>`, `HOLDTIME <u16>`, `AUTH "<str>"`, `VIP <ip>`.
- [examples/l3/pim/](examples/l3/pim/) — **`PIM` (RFC 7761 PIM-SM):** `HELLO`, `JOIN_PRUNE`, `REGISTER`, `DR_PRIORITY <u32>`, `HOLDTIME <u16>`, `SOURCE <ip>`, `GROUP <ip>`, `RP <ip>`.
- [examples/l3/bfd/](examples/l3/bfd/) — **`BFD` (RFC 5880 / RFC 5881):** `STATE <0..3>`, `DIAG <0..31>`, `MY_DISC <u32>`, `YOUR_DISC <u32>`, `MIN_TX <u32>`, `MIN_RX <u32>`, `MULT <u8>`.
- [examples/l3/openflow/](examples/l3/openflow/) — **`OPENFLOW` (OpenFlow 1.3):** `HELLO`, `FEATURES_REQ`, `FEATURES_REPLY`, `PACKET_IN`, `PACKET_OUT`, `FLOW_MOD`, `ECHO_REQ`, `ECHO_REPLY`, `VERSION <u8>`, `XID <u32>`, `DPID <u64>`, `TABLE_ID <u8>`, `PRIORITY <u16>`.

### 3. Layer 4 Transport Protocols (3 Protocols — [`docs/l4_transports.md`](docs/l4_transports.md))

- [examples/l4/tcp/](examples/l4/tcp/) — **`TCP` (RFC 9293 / RFC 7323):** `SYN`, `ACK`, `FIN`, `RST`, `PSH`, `URG`, `ECE`, `CWR`, `SRCPORT <u16>`, `DSTPORT <u16>`, `SEQ <u32>`, `ACKNUM <u32>`, `WIN <u16>` / `WINDOW <u16>`, `MSS <u16>`, `WSCALE <u8>`, `SACK_PERM`, `TSVAL <u32>`, `TSECR <u32>`, `URGENT <u16>`.
- [examples/l4/udp/](examples/l4/udp/) — **`UDP` (RFC 768):** `SRCPORT <u16>`, `DSTPORT <u16>`, `PAYLOAD "<str>"`, `HEXPAYLOAD "<hex>"`.
- [examples/l4/sctp/](examples/l4/sctp/) — **`SCTP` (RFC 9260):** `CHUNK <DATA|INIT|INIT_ACK|SACK|HEARTBEAT|HEARTBEAT_ACK|ABORT|SHUTDOWN|COOKIE_ECHO|COOKIE_ACK>`, `VTAG <u32>`, `TSN <u32>` / `SEQ <u32>`, `STREAM <u16>`, `SSN <u16>`, `PPID <u32>`.

### 4. Layer 7 SNMP Protocols (3 Protocols — [`docs/l7_snmp.md`](docs/l7_snmp.md))

- [examples/l7/snmp/snmpv1/](examples/l7/snmp/snmpv1/) — **`SNMP1` (RFC 1157 SMIv1 BER):** `TRAP`, `GET`, `GETNEXT`, `SET`, `RESPONSE`, `COMMUNITY "<str>"`, `REQID <u32>`, `OID <oid>`, `SYSUPTIME <u32>`, `ENTERPRISE <oid>`, `AGENTIP <ipv4>`, `GENTRAP <0..6>`, `SPECTRAP <u32>`, `VARBIND`.
- [examples/l7/snmp/snmpv2c/](examples/l7/snmp/snmpv2c/) — **`SNMP2` (RFC 3416 SMIv2 BER):** `TRAP`, `INFORM`, `GET`, `GETNEXT`, `GETBULK`, `SET`, `RESPONSE`, `COMMUNITY "<str>"`, `REQID <u32>`, `NONREPEATERS <u32>`, `MAXREPETITIONS <u32>`, `SYSUPTIME <u32>`, `OID <oid>`, `VARBIND`.
- [examples/l7/snmp/snmpv3/](examples/l7/snmp/snmpv3/) — **`SNMP3` (RFC 3414 / 3826 / 7860 USM):** `TRAP`, `INFORM`, `GET`, `GETNEXT`, `GETBULK`, `SET`, `RESPONSE`, `USER "<str>"`, `ENGINEID "<hex>"`, `ENGINEBOOTS <u32>`, `ENGINETIME <u32>`, `CONTEXTNAME "<str>"`, `AUTH <MD5|SHA|SHA256|SHA384|SHA512> "<pass>"`, `PRIV <DES|AES> "<pass>"`, `REQID <u32>`, `NONREPEATERS <u32>`, `MAXREPETITIONS <u32>`, `SYSUPTIME <u32>`, `OID <oid>`, `VARBIND`.
  - **All 9 SMI `VARBIND <oid> <TYPE> [value]` Types:** `NULL` / `NULLVAL`, `STRING "<text>"`, `INT <i32>`, `TIMETICKS <u32>`, `IPVAL <ip>`, `OIDVAL <oid>`, `COUNTER32 <u32>`, `GAUGE32 <u32>`, `COUNTER64 <u64>`.

### 5. Layer 7 Infrastructure, Time, AAA & Flow Telemetry Protocols (11 Protocols — [`docs/l7_infra_and_telemetry.md`](docs/l7_infra_and_telemetry.md))

- [examples/l7/dns/](examples/l7/dns/) — **`DNS` (RFC 1035):** `QUERY`, `RESPONSE`, `TXID <u16>`, `QNAME "<domain>"`, `QTYPE "<type>"`, `RDATA "<str>"`, `RCODE <u8>`, `ANS_TTL <u32>`, `TRANSPORT TCP`.
- [examples/l7/mdns/](examples/l7/mdns/) — **`MDNS` (RFC 6762):** `QUERY`, `RESPONSE`, `TXID <u16>`, `QNAME "<name>"`, `QTYPE "<type>"`, `RDATA "<str>"`, `RCODE <u8>`, `ANS_TTL <u32>`.
- [examples/l7/dhcp/](examples/l7/dhcp/) — **`DHCP` (RFC 2131 / RFC 8415 DHCPv6):** `DISCOVER`, `OFFER`, `REQUEST`, `ACK`, `RELEASE`, `SOLICIT`, `ADVERTISE`, `REPLY`, `XID <u32>` / `TXID <u32>`, `CIADDR <ip>`, `YIADDR <ip>`, `SIADDR <ip>`, `CHADDR <mac>`, `HOSTNAME "<str>"`, `DNS_SERVER <ip>`, `ROUTER <ip>`, `SUBNET_MASK <ip>`, `LEASE_TIME <u32>`.
- [examples/l7/ntp/](examples/l7/ntp/) — **`NTP` (RFC 5905):** `LI <0..3>`, `VN <1..4>`, `MODE <1..7>`, `STRATUM <0..16>`, `POLL <u8>`, `PRECISION <i8>`, `REFID "<str>"`, `TX_TIMESTAMP <u64>`.
- [examples/l7/ptp/](examples/l7/ptp/) — **`PTP` (IEEE 1588-2008):** `SYNC`, `DELAY_REQ`, `FOLLOW_UP`, `DELAY_RESP`, `ANNOUNCE`, `MSG_TYPE "<type>"`, `VERSION <u8>`, `DOMAIN <u8>`, `SEQ_ID <u16>`, `CLOCK_ID "<eui64>"`.
- [examples/l7/radius/](examples/l7/radius/) — **`RADIUS` (RFC 2865 / RFC 2866):** `ACCESS_REQUEST`, `ACCESS_ACCEPT`, `ACCESS_REJECT`, `ACCESS_CHALLENGE`, `ACCOUNTING_REQUEST`, `ACCOUNTING_RESPONSE`, `CODE "<type>"`, `ID <u8>`, `USER "<str>"`, `NAS_IP <ip>`, `SERVICE_TYPE <u32>`, `FRAMED_IP <ip>`.
- [examples/l7/tacacs/](examples/l7/tacacs/) — **`TACACS` (RFC 8907 TACACS+):** `AUTHEN`, `AUTHOR`, `ACCT`, `TYPE <AUTHEN|AUTHOR|ACCT>`, `SEQ <u8>`, `FLAGS <u8>`, `SESSION_ID <u32>`, `USER "<str>"`, `PAYLOAD "<str>"`.
- [examples/l7/syslog/](examples/l7/syslog/) — **`SYSLOG` (RFC 5424):** `FACILITY <0..23>`, `SEVERITY <0..7>`, `PRI <0..191>`, `HOSTNAME "<str>"`, `APP "<str>"`, `PROCID "<str>"`, `MSGID "<str>"`, `MSG "<text>"`, `TRANSPORT TCP`.
- [examples/l7/netflow/](examples/l7/netflow/) — **`NETFLOW` (Cisco NetFlow v5):** `SRCIP <ip>`, `DSTIP <ip>`, `SRCPORT <u16>`, `DSTPORT <u16>`, `PROTO <u8>`, `PACKETS <u32>`, `OCTETS <u32>`.
- [examples/l7/ipfix/](examples/l7/ipfix/) — **`IPFIX` (RFC 7011):** `DOMAIN_ID <u32>`, `SRCIP <ip>`, `DSTIP <ip>`, `SRCPORT <u16>`, `DSTPORT <u16>`, `PROTO <u8>`, `PACKETS <u32>`, `OCTETS <u32>`.
- [examples/l7/sflow/](examples/l7/sflow/) — **`SFLOW` (sFlow v5):** `AGENT_IP <ip>`, `SUB_AGENT_ID <u32>`, `SEQ <u32>`, `UPTIME <u32>`, `SAMPLES <u32>`.

### 6. Layer 7 Web, Cloud-Native, Transport Security, VoIP & Remote Access Protocols (16 Protocols — [`docs/l7_web_and_cloud.md`](docs/l7_web_and_cloud.md))

- [examples/l7/http/](examples/l7/http/) — **`HTTP` (RFC 9112 HTTP/1.1):** `GET`, `POST`, `PUT`, `DELETE`, `HEAD`, `OPTIONS`, `PATCH`, `METHOD "<verb>"`, `URI "<path>"`, `VERSION "<ver>"`, `HOST_HDR "<host>"`, `USER_AGENT "<str>"`, `CONTENT_TYPE "<mime>"`, `STATUS <u16>`, `REASON "<str>"`, `HEADER "<k>" "<v>"`, `BODY "<str>"`.
- [examples/l7/http2/](examples/l7/http2/) — **`HTTP2` (RFC 9113):** `PREFACE`, `SETTINGS`, `HEADERS`, `DATA`, `WINDOW_UPDATE`, `PING`, `GOAWAY`, `STREAM_ID <u32>`.
- [examples/l7/grpc/](examples/l7/grpc/) — **`GRPC` (gRPC over HTTP/2):** `SERVICE "<str>"`, `METHOD "<str>"`, `GRPC_STATUS <u32>`, `PAYLOAD "<str>"`.
- [examples/l7/websocket/](examples/l7/websocket/) — **`WEBSOCKET` (RFC 6455):** `OPCODE "<TEXT|BINARY|CLOSE|PING|PONG>"` (or bare `TEXT`, `BINARY`, `PING`, `PONG`, `CLOSE`), `FIN_BIT <0..1>`, `MASK_KEY <u32>`, `PAYLOAD "<str>"`.
- [examples/l7/tls/](examples/l7/tls/) — **`TLS` (RFC 8446 TLS 1.3):** `CLIENT_HELLO`, `SERVER_HELLO`, `CERTIFICATE`, `FINISHED`, `APP_DATA`, `ALERT`, `RECORD_VERSION <u16>`, `HANDSHAKE_VERSION <u16>`, `SNI "<str>"`, `CIPHERSUITE <u16>`, `ALPN "<str>"`.
- [examples/l7/quic/](examples/l7/quic/) — **`QUIC` (RFC 9000):** `INITIAL`, `ZERO_RTT`, `HANDSHAKE`, `RETRY`, `SHORT`, `VERSION <u32>`, `DCID <u64>`, `SCID <u64>`, `TOKEN "<str>"`, `PKT_NUM <u32>`, `PAYLOAD "<str>"`.
- [examples/l7/tftp/](examples/l7/tftp/) — **`TFTP` (RFC 1350):** `RRQ`, `WRQ`, `DATA`, `ACK`, `ERROR`, `FILENAME "<str>"`, `MODE "<str>"`, `BLOCK <u16>`, `ERRCODE <u16>`, `ERRMSG "<str>"`.
- [examples/l7/ftp/](examples/l7/ftp/) — **`FTP` (RFC 959):** `CMD "<str>"`, `ARG "<str>"`, `CODE <u16>`, `REPLY "<str>"`.
- [examples/l7/ssh/](examples/l7/ssh/) — **`SSH` (RFC 4253):** `BANNER "<str>"`, `KEXINIT`, `NEWKEYS`, `MSG_CODE <u8>`, `COOKIE "<str>"`, `PAYLOAD "<str>"`.
- [examples/l7/telnet/](examples/l7/telnet/) — **`TELNET` (RFC 854):** `WILL <u8>`, `WONT <u8>`, `DO <u8>`, `DONT <u8>`, `OPTION <u8>`, `DATA "<str>"`, `PAYLOAD "<str>"`.
- [examples/l7/whois/](examples/l7/whois/) — **`WHOIS` (RFC 3912):** `QUERY`, `RESPONSE`, `DOMAIN "<str>"`, `REGISTRAR "<str>"`.
- [examples/l7/sip/](examples/l7/sip/) — **`SIP` (RFC 3261):** `INVITE`, `BYE`, `CANCEL`, `METHOD "<verb>"`, `URI "<str>"`, `STATUS <u16>`, `REASON "<str>"`, `FROM "<str>"`, `TO "<str>"`, `CALL_ID "<str>"`, `CSEQ <u32>`, `VIA "<str>"`, `CONTACT "<str>"`, `CONTENT_TYPE "<str>"`, `BODY "<sdp>"`, `TRANSPORT TCP`.
- [examples/l7/rtp/](examples/l7/rtp/) — **`RTP` (RFC 3550):** `PT <u8>`, `SEQ <u16>`, `TIMESTAMP <u32>`, `SSRC <u32>`, `MARKER <0..1>`, `PAYLOAD "<str>"`.
- [examples/l7/rtsp/](examples/l7/rtsp/) — **`RTSP` (RFC 2326):** `OPTIONS`, `DESCRIBE`, `SETUP`, `PLAY`, `TEARDOWN`, `METHOD "<verb>"`, `URI "<str>"`, `STATUS <u16>`, `CSEQ <u32>`, `SESSION "<str>"`, `TRANSPORT_HDR "<str>"`.
- [examples/l7/stun/](examples/l7/stun/) — **`STUN` (RFC 8489):** `BINDING_REQUEST`, `BINDING_RESPONSE`, `BINDING_ERROR`, `TXID <u32>`, `XOR_MAPPED_ADDR <ip>`, `SOFTWARE "<str>"`.
- [examples/l7/ssdp/](examples/l7/ssdp/) — **`SSDP` (UPnP Discovery):** `MSEARCH`, `NOTIFY`, `HOST_HDR "<str>"`, `MAN "<str>"`, `MX <u8>`, `ST "<str>"`, `NT "<str>"`, `NTS "<str>"`, `USN "<str>"`, `LOCATION "<str>"`.

### 7. Layer 7 Mail, Directory, Storage, Databases, Caches & Message Brokers (14 Protocols — [`docs/l7_mail_auth_storage_db.md`](docs/l7_mail_auth_storage_db.md))

- [examples/l7/smtp/](examples/l7/smtp/) — **`SMTP` (RFC 5321):** `EHLO "<domain>"`, `HELO "<domain>"`, `MAIL_FROM`, `RCPT_TO`, `DATA`, `QUIT`, `CMD "<str>"`, `PARAM "<addr>"`, `CODE <u16>`, `REPLY "<str>"`, `BODY "<str>"`.
- [examples/l7/imap/](examples/l7/imap/) — **`IMAP` (RFC 3501):** `TAG "<str>"`, `CMD "<str>"`, `ARG "<str>"`, `STATUS "<str>"`, `RESPONSE "<str>"`.
- [examples/l7/pop3/](examples/l7/pop3/) — **`POP3` (RFC 1939):** `CMD "<str>"`, `ARG "<str>"`, `OK`, `ERR`, `RESPONSE "<str>"`.
- [examples/l7/kerberos/](examples/l7/kerberos/) — **`KERBEROS` (RFC 4120):** `AS_REQ`, `AS_REP`, `TGS_REQ`, `TGS_REP`, `KRB_ERROR`, `REALM "<str>"`, `CNAME "<str>"`, `SNAME "<str>"`, `ETYPE <i32>`.
- [examples/l7/ldap/](examples/l7/ldap/) — **`LDAP` (RFC 4511):** `BIND_REQ`, `BIND_RES`, `SEARCH_REQ`, `SEARCH_ENTRY`, `SEARCH_DONE`, `UNBIND_REQ`, `MSGID <i32>`, `BASE_DN "<str>"`, `FILTER "<str>"`, `RESULT_CODE <u32>`.
- [examples/l7/smb/](examples/l7/smb/) — **`SMB` (MS-SMB2/3):** `COMMAND "<NEGOTIATE|SESSION_SETUP|TREE_CONNECT|CREATE|READ|WRITE|CLOSE|TREE_DISCONNECT|LOGOFF>"`, `STATUS <u32>`, `SESSION_ID <u64>`, `TREE_ID <u32>`, `MSGID <u64>`, `SHARE "<str>"`, `FILENAME "<str>"`.
- [examples/l7/nfs/](examples/l7/nfs/) — **`NFS` (RFC 1813 / RFC 7530):** `VERS <u32>`, `PROC "<str>"`, `TAG "<str>"`, `PATH "<str>"`, `XID <u32>`.
- [examples/l7/redis/](examples/l7/redis/) — **`REDIS` (RESP Protocol):** `CMD "<str>"`, `ARGS "<str>"`, `REPLY_TYPE "<str>"`, `VALUE "<str>"`.
- [examples/l7/memcached/](examples/l7/memcached/) — **`MEMCACHED`:** `CMD "<str>"`, `KEY "<str>"`, `VALUE "<str>"`, `FLAGS <u32>`, `EXPTIME <u32>`, `OPCODE <u8>`, `OPAQUE <u32>`, `CAS <u64>`.
- [examples/l7/mysql/](examples/l7/mysql/) — **`MYSQL`:** `GREETING`, `LOGIN`, `QUERY`, `OK`, `ERR`, `EOF`, `SERVER_VERSION "<str>"`, `USER "<str>"`, `DB "<str>"`, `SQL "<query>"`, `ERRCODE <u16>`.
- [examples/l7/postgres/](examples/l7/postgres/) — **`POSTGRES` (v3.0):** `STARTUP`, `QUERY`, `AUTH_OK`, `COMMAND_COMPLETE`, `READY_FOR_QUERY`, `ERROR_RESPONSE`, `USER "<str>"`, `DB "<str>"`, `SQL "<query>"`.
- [examples/l7/mqtt/](examples/l7/mqtt/) — **`MQTT` (v3.1.1 / v5.0):** `CONNECT`, `CONNACK`, `PUBLISH`, `PUBACK`, `SUBSCRIBE`, `SUBACK`, `PINGREQ`, `PINGRESP`, `DISCONNECT`, `CLIENT_ID "<str>"`, `TOPIC "<str>"`, `QOS <0..2>`, `RETAIN`, `PKT_ID <u16>`, `KEEPALIVE <u16>`, `RETURN_CODE <u8>`.
- [examples/l7/coap/](examples/l7/coap/) — **`COAP` (RFC 7252):** `CON`, `NON`, `ACK`, `RST`, `CODE "<str>"`, `MSGID <u16>`, `TOKEN <u32>`, `URI_PATH "<str>"`, `CONTENT_FORMAT <u16>`.
- [examples/l7/amqp/](examples/l7/amqp/) — **`AMQP` (0-9-1 / 1.0):** `PROTOCOL_HEADER`, `CONNECTION_START`, `CHANNEL_OPEN`, `BASIC_PUBLISH`, `BASIC_DELIVER`, `HEARTBEAT`, `CHANNEL <u16>`, `EXCHANGE "<str>"`, `ROUTING_KEY "<str>"`.

### 8. Layer 7 Industrial Control Systems (ICS) & SCADA/OT Protocols (6 Protocols — [`docs/l7_industrial_ot.md`](docs/l7_industrial_ot.md))

- [examples/l7/modbus/](examples/l7/modbus/) — **`MODBUS` (Modbus TCP):** `FUNC "<name>"` (or `READ_COILS`, `READ_DISCRETE_INPUTS`, `READ_HOLDING_REGISTERS`, `READ_INPUT_REGISTERS`, `WRITE_SINGLE_COIL`, `WRITE_SINGLE_REGISTER`, `WRITE_MULTIPLE_REGISTERS`), `TXID <u16>`, `PROTO_ID <u16>`, `UNITID <u8>`, `ADDR <u16>`, `COUNT <u16>`, `VALUE <u16>`, `IS_RESPONSE`.
- [examples/l7/bacnet/](examples/l7/bacnet/) — **`BACNET` (ASHRAE 135 BACnet/IP):** `WHO_IS`, `I_AM`, `READ_PROPERTY`, `WRITE_PROPERTY`, `INVOKE_ID <u8>`, `OBJECT_TYPE <u16>`, `OBJECT_INSTANCE <u32>`, `PROPERTY_ID <u32>`, `VALUE <u32>`.
- [examples/l7/dnp3/](examples/l7/dnp3/) — **`DNP3` (IEEE 1815):** `FUNC "<name>"` (or `CONFIRM`, `READ`, `WRITE`, `SELECT`, `OPERATE`, `DIRECT_OPERATE`, `UNSOLICITED_RESPONSE`), `SRC <u16>`, `DST <u16>`, `SEQ <u8>`, `GROUP <u8>`, `VARIATION <u8>`, `CRC <u16>`.
- [examples/l7/s7comm/](examples/l7/s7comm/) — **`S7COMM` (Siemens S7 PLC):** `ROSCTR "<JOB|ACK|ACK_DATA|USERDATA>"`, `FUNC "<SETUP_COMM|READ_VAR|WRITE_VAR|PLC_CONTROL>"`, `PDU_REF <u16>`, `AREA <u8>`, `DB_NUM <u16>`, `OFFSET <u32>`, `COUNT <u16>`.
- [examples/l7/ethernetip/](examples/l7/ethernetip/) — **`ETHERNETIP` (ODVA EtherNet/IP & CIP):** `CMD "<name>"` (or `LIST_SERVICES`, `LIST_IDENTITY`, `LIST_INTERFACES`, `REGISTER_SESSION`, `UNREGISTER_SESSION`, `SEND_RR_DATA`, `SEND_UNIT_DATA`), `SESSION_HANDLE <u32>`, `STATUS <u32>`, `CONTEXT <u64>`, `CIP_SERVICE <u8>`, `CIP_CLASS <u16>`, `CIP_INSTANCE <u16>`, `CIP_ATTR <u16>`.
- [examples/l7/opcua/](examples/l7/opcua/) — **`OPCUA` (IEC 62541):** `MSG_TYPE "<HEL|ACK|ERR|OPN|CLO|MSG>"`, `CHUNK_TYPE "<F|C|A>"`, `SECURE_CHANNEL_ID <u32>`, `TOKEN_ID <u32>`, `SEQ_NUM <u32>`, `REQID <u32>`, `ENDPOINT_URL "<str>"`, `NODE_ID "<str>"`.

---

## FAQ: What is a .fasm file? (FrameAssembly vs. Flat Assembler vs. FPGA FASM)

### What is a `.fasm` file in FrameAssembly?
A `.fasm` file is a plain-text network packet recipe defined by the **FrameAssembly** compiler (registered IANA vendor media type `text/vnd.frameassembly`, Freedesktop `shared-mime-info` subclass of `text/plain`). It allows network technicians, security engineers, and DevOps pipelines to write declarative "Packets as Code" specifications that compile into deterministic, nanosecond-precision `.pcap` and `.pcapng` packet captures without requiring root permissions, Python scripting, or raw sockets.

### Why do other software tools also use the `.fasm` extension?
Historically, the `.fasm` extension has been used informally by two unrelated tools that lack registered IANA vendor media types:
1. **Flat Assembler (FASM)**: An x86/x86-64 assembly compiler created by Tomasz Grysztar. Flat Assembler `.fasm` files contain CPU assembly instructions (`mov`, `jmp`, `xor`), directives (`format PE`, `format ELF`, `section`, `use32`), and `;` comments, producing `.exe` or `.o` machine code.
2. **FPGA FASM (FPGA Assembly)**: A plain-text hardware configuration format used by SymbiFlow / F4PGA / Project X-Ray. FPGA FASM files contain dot-separated FPGA tile feature paths (`CLBLL_L_X12Y34.SLICEL_X0.ALUT.INIT[31:0] = 32'h00000000`) and `#` comments, producing FPGA `.bit` bitstreams.

### How does FrameAssembly disambiguate `.fasm` files?
FrameAssembly provides unambiguous, multi-layered disambiguation:
* **IANA Media Type**: Formally registered vendor tree media type [`text/vnd.frameassembly`](contrib/iana/text-vnd.frameassembly.md).
* **Freedesktop XML MIME Database**: Provides [`contrib/mime/text-vnd.frameassembly.xml`](contrib/mime/text-vnd.frameassembly.xml) with magic rules matching `HOST`, `FLOW`, and `COMPILE` blocks.
* **Unix `file(1)` Magic**: Magic rules in `contrib/magic/frameassembly.magic` identifying FrameAssembly network packet specifications.
* **GitHub Linguist**: Language definition in `contrib/linguist/languages.yml` and regex disambiguation in `contrib/linguist/heuristics.yml`.
* **Editor Syntax Scope**: Dedicated TextMate scope `source.frameassembly` in `frameassembly-vscode` (avoiding Flat Assembler's `source.fasm`).
* **Compiler Error Diagnostics**: Built-in detection in `src/error.rs` that automatically detects when an x86 Flat Assembler or FPGA FASM file is passed by mistake and guides the user with a plain-English explanation.

| Format | Domain | Comment Syntax | Structural Signature | Output Artifact |
| :--- | :--- | :--- | :--- | :--- |
| **FrameAssembly (`.fasm`, `text/vnd.frameassembly`)** | Declarative network packet capture recipes ("Packets as Code") | `// comment` | `HOST <id> { IP ... }`, `FLOW <id>(...) { ... }`, `COMPILE { ... }`, `->` / `<-` | `.pcap` / `.pcapng` captures for Wireshark, `tshark`, `tcpreplay`, Suricata & Zeek |
| **Flat Assembler (`.asm`, `.fasm`)** | x86 / x86-64 CPU assembly | `; comment` | `format PE`/`ELF`, `section`, `org`, `mov`/`xor`/`int` mnemonics | x86 machine binaries (`.o`, `.exe`, `.elf`) |
| **FPGA Assembly (`FASM`, `.fasm`)** | SymbiFlow / F4PGA hardware bitstreams | `# comment` | Dot-separated tile feature paths (`CLBLL_L_X10Y100.SLICEL_X0...`) | FPGA bitstream frames (`.bit`) |

---

## Documentation

### Step-by-Step Guides & Practical Cookbooks
* **[Getting Started Guide](docs/getting_started.md)** — Step-by-step introduction for network technicians with zero programming background: anatomy of a `.fasm` file, colon/hyphen/Cisco dotted-quad MAC support, `frameassembly show` terminal preview, Wireshark/`tcpdump`-to-`.fasm` translation table, generating `.fasm` with ChatGPT/Claude/Copilot, and pairing `frameassembly` with `Wireshark`, `tshark`, and `tcpreplay`.
* **[Practical Use Cases & Recipes](docs/use_cases.md)** — Symptom-based quick-jump index and ready-to-copy `.fasm` recipes for simulating SNMPv1/v2c/v3 traps & polls, testing firewall rules and ACLs, verifying VLAN/QinQ trunks and DiffServ QoS, testing IDS/IPS & flow collectors, validating industrial OT dissectors, and sharing zero-noise captures.

### Protocol & Topology Reference Guides
* **[Layer 2 Switching & Data-Link Protocols](docs/l2_protocols.md)** — `ARP`, `VLAN` (802.1Q), `QINQ` (802.1ad), `LLDP`, `STP` / `RSTP`, `LACP`, `EAPOL` (802.1X), and `MPLS` (`8` protocols).
* **[Layer 3 Control, Tunneling, VPN & Routing Protocols](docs/l3_protocols.md)** — `ICMP`, `NDP`, `IGMP`, `MLD`, `GRE`, `VXLAN`, `GENEVE`, `IPSEC`, `ESP`, `AH`, `IKEV2`, `WIREGUARD`, `OSPF`, `BGP`, `RIP`, `VRRP`, `HSRP`, `PIM`, `BFD`, and `OPENFLOW` (`20` protocols).
* **[Layer 4 Transport Protocols](docs/l4_transports.md)** — `TCP`, `UDP`, and `SCTP`, including automatic 4-tuple `SEQ`/`ACK` and reply-port tracking, RFC 7323 TCP options, and SCTP multi-chunk signaling (`3` protocols).
* **[Layer 7 SNMPv1, SNMPv2c & Encrypted SNMPv3 Guide](docs/l7_snmp.md)** — Network administrator's guide to `SNMP1`, `SNMP2`, and `SNMP3` USM authentication (`MD5`/`SHA`/`SHA256`/`SHA384`/`SHA512`), encryption (`DES`/`AES`), and all 9 `VARBIND` data types (`3` protocols).
* **[Layer 7 Infrastructure, Time, AAA & Flow Telemetry](docs/l7_infra_and_telemetry.md)** — `DNS`, `MDNS`, `DHCP` / `DHCPv6`, `NTP`, `PTP`, `RADIUS`, `TACACS`, `SYSLOG`, `NETFLOW`, `IPFIX`, and `SFLOW` (`11` protocols).
* **[Layer 7 Web, Cloud-Native, Transport Security, VoIP & Remote Access](docs/l7_web_and_cloud.md)** — `HTTP`, `HTTP2`, `GRPC`, `WEBSOCKET`, `TLS`, `QUIC`, `TFTP`, `FTP`, `SSH`, `TELNET`, `WHOIS`, `SIP`, `RTP`, `RTSP`, `STUN`, and `SSDP` (`16` protocols).
* **[Layer 7 Mail, Directory, Storage, Databases, Caches & Message Brokers](docs/l7_mail_auth_storage_db.md)** — `SMTP`, `IMAP`, `POP3`, `KERBEROS`, `LDAP`, `SMB`, `NFS`, `REDIS`, `MEMCACHED`, `MYSQL`, `POSTGRES`, `MQTT`, `COAP`, and `AMQP` (`14` protocols).
* **[Layer 7 Industrial Control Systems (ICS) & SCADA/OT](docs/l7_industrial_ot.md)** — `MODBUS`, `BACNET`, `DNP3`, `S7COMM`, `ETHERNETIP`, and `OPCUA` (`6` protocols).
* **[Multi-Protocol Network Topologies & Dual-Stack Scenarios](docs/topologies_and_dual_stack.md)** — Multi-host enterprise, data center EVPN-VXLAN, campus 802.1X NAC, and industrial OT topologies (plus [`examples/`](examples/) with `2,611` verified `.fasm` scenarios across all 81 protocols).

### Standards Specifications, Developer & AI Architecture
* **[`.fasm` File Format & Media Type Specification (`text/vnd.frameassembly`)](docs/fasm-specification.md)** — Canonical RFC 6838 specification for the FrameAssembly `.fasm` file format: UTF-8 encoding rules, lexical magic numbers, disambiguation from x86 Flat Assembler and FPGA FASM files, security considerations, and links to IANA ([`contrib/iana/text-vnd.frameassembly.md`](contrib/iana/text-vnd.frameassembly.md)), Freedesktop MIME ([`contrib/mime/text-vnd.frameassembly.xml`](contrib/mime/text-vnd.frameassembly.xml)), and GitHub Linguist ([`contrib/linguist/`](contrib/linguist/)) registration artifacts.
* **[For Nerds: Architecture, Rust Library API & Formal Grammars](docs/for_nerds.md)** — Six-stage Rust pipeline, embedding `frameassembly` as a Rust library (`parse_program`, `compile_program`, `generate_pcap`), formal grammars ([`grammar.ebnf`](grammar.ebnf), [`frameassembly.gbnf`](frameassembly.gbnf), [`frameassembly.lark`](frameassembly.lark)), constrained LLM decoding, and `examples/` SFT/RLVR corpus conventions.

---

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.