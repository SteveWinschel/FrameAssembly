# FrameAssembly (`.fasm`) — Syntax Highlighting for VS Code

[![VS Code Marketplace](https://img.shields.io/visual-studio-marketplace/v/SteveWinschel.frameassembly-vscode.svg)](https://marketplace.visualstudio.com/items?itemName=SteveWinschel.frameassembly-vscode)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://github.com/SteveWinschel/FrameAssembly/blob/main/LICENSE)

[**Editor Problems Solved**](#editor-problems-this-extension-solves) • [**Example `.fasm` Workflows**](#example-fasm-workflows) • [**81 Highlighted Protocols**](#highlighted-protocol-keywords-81-native-protocols) • [**18 Snippets**](#bonus-18-tab-completable-keyword-snippets) • [**Get the Compiler**](#compiler-not-included)

## What Is This Extension?

[**FrameAssembly**](https://github.com/SteveWinschel/FrameAssembly) is a **Packets as Code** tool built ironically for the very people who hate programming -> **Networking & Cybersecurity professionals**.

**What this extension does:** One thing—it highlights `.fasm` keywords so your packet definitions don't look like a monochrome ransom note in `notepad.exe`.

**What this extension does NOT do:** It does **not** download or bundle the `frameassembly` compiler, spin up a bloated background language server eating 2 GB of RAM, or turn `.fasm` files into `.pcap` captures by itself. It is a zero-runtime TextMate grammar (`source.frameassembly`) for **VS Code**, **Cursor**, **Windsurf**, **VSCodium**, and **Antigravity IDE**. If you want to compile `.fasm` code into `.pcap` / `.pcapng` captures or reverse existing `.pcap` captures into `.fasm` code (`frameassembly reverse <input.pcap>`), grab the standalone [**FrameAssembly CLI**](#compiler-not-included).

## Editor Problems This Extension Solves

### 1. `.fasm` File Extension Hijacking (x86 Assembly & FPGA Bitstreams)
* **The Problem:** Open a `.fasm` network capture spec in a stock setup and generic assembly plugins immediately assume you are writing 1999 x86 Flat Assembler (`;` comments, `mov eax, 1`) or SymbiFlow FPGA tile bitstreams (`#` comments)—painting valid `host`, `flow`, and `compile` blocks in bogus syntax errors.
* **The Solution:** Binds `.fasm` (`text/vnd.frameassembly`) and `host` / `flow` / `compile` first-line signatures to the dedicated `source.frameassembly` scope so x86 and FPGA highlighters leave your packet specs alone.

### 2. Going Blind Reading Raw OIDs, Mixed MAC Formats & 640+ Keywords in Unhighlighted Code
* **The Problem:** Hunting down a typo in a 10-arc SNMP OID (`1.3.6.1.6.3.1.1.5.3`), a compressed IPv6 address, or a Cisco IOS dotted-quad MAC (`001a.2b3c.4d5e`) inside unhighlighted white text is pure eye strain—especially when half your team writes polite lowercase (`tcp syn`) and the other half shouts in `UPPERCASE` (`TCP SYN`).
* **The Solution:** Case-insensitive keyword highlighting across all **81 Layer 2–7 protocols** and **640+ frame modifiers**, with distinct colors for structural blocks (`host`, `flow`, `compile`, `loop`), directional arrows (`->`, `<-`), IPv4/IPv6 addresses, IEEE colon/hyphen and Cisco MACs, hex literals (`0x...`), SNMP OIDs, and wait units (`ns`, `us`, `ms`, `s`, `m`).

### 3. Unreadable Packet Examples in Markdown Runbooks & Pentest Reports
* **The Problem:** Pasting firewall test cases, IDS rule reproducers, or sanitized vendor TAC captures into `.md` documentation turns structured L2–L7 flows into flat gray walls of text.
* **The Solution:** Automatically injects `source.frameassembly` syntax highlighting into ```` ```frameassembly ```` and ```` ```fasm ```` fenced code blocks inside any Markdown file (`markdown.frameassembly.codeblock`).

### 4. Overeager Editors Auto-Inserting Invalid Punctuation
* **The Problem:** Generic editor defaults love auto-closing `'single quotes'`, `[square brackets]`, and `/* block comments */`—none of which exist in `.fasm` and all of which trigger immediate compiler errors.
* **The Solution:** Configures clean `//` line-comment toggling (`Ctrl+/`) and `{...}`, `(...)`, `"..."` pairs while intentionally stripping unsupported bracket and single-quote auto-closures.

## Example `.fasm` Workflows

> **Heads up:** The blocks below show how this extension highlights `.fasm` keywords for common network and security testing problems. Compiling them into `.pcap` files requires the separate [`frameassembly` CLI](https://github.com/SteveWinschel/FrameAssembly) -> what you do with `tcpreplay` afterward is between you and HR :)

### Simulating `SNMPv3` Traps & `Syslog` Alerts Without Unplugging Switch Cables
Waiting for a core router interface to die—or yanking patch cables out of a switch after fighting MIB imports and EngineID mismatches—just to verify whether **Zabbix**, **LibreNMS**, **PRTG**, **Checkmk**, **SolarWinds**, or `snmptrapd` fires an alert is nobody's idea of a good afternoon. Keyword highlighting cleanly separates USM crypto parameters (`sha256`, `aes`), EngineIDs, dotted OIDs, and `syslog` severities:

```frameassembly
// Preview: SNMPv3 authPriv linkDown trap + RFC 5424 Syslog alert
host core_sw { ip 10.10.1.2  mac 001a.2b3c.4d01 }
host zabbix  { ip 10.10.1.50 mac 00:1a:2b:3c:4d:50 }

flow link_down_alert(sw, nms) {
    sw -> nms vlan 100 snmp3 trap user "netops" engineid "80001f8880510001" engineboots 5 enginetime 3600 auth sha256 "AuthPass123!" priv aes "PrivPass123!" oid 1.3.6.1.6.3.1.1.5.3 varbind 1.3.6.1.2.1.2.2.1.8.1 int 2 wait 5ms
    sw -> nms vlan 100 syslog facility 16 severity 3 hostname "core-sw-01" app "link" msg "Gi0/1 changed state to down"
}

compile { link_down_alert(core_sw, zabbix) }
```

### Testing Stateful Firewalls, ACLs & IDS Rules (`Suricata`, `Zeek`, `Snort`) Without `Scapy` Venvs
Throwing a single spoofed packet at **Palo Alto**, **FortiGate**, **CheckPoint**, or `nftables` won't test application rules because stateful engines drop mid-stream data without a 3-way handshake—and maintaining Python `Scapy` virtualenvs or downloading noisy mystery `.pcap` files off GitHub gets old fast. Highlighting keeps TCP flags (`syn`, `ack`, `rst`), ports, `dns` queries, and `tls` `sni` fields readable at a glance:

```frameassembly
// Preview: SYN flood loop + stateful C2 DNS/TLS signature check
host bot_node    { ip 198.51.100.66 mac 00:50:56:c0:00:66 }
host workstation { ip 10.40.5.25     mac 00:50:56:40:05:25 }
host sec_gateway { ip 10.40.5.1      mac 00:1c:73:40:05:01 }

flow syn_flood(bot, gw) {
    bot -> gw tcp syn dstport 443 win 1024 wait 100us
}

flow c2_signature_check(ws, gw) {
    ws -> gw dns query txid 0x4401 qname "c2-beacon.bad-domain.test" qtype "A" wait 1ms
    ws <- gw dns response txid 0x4401 qname "c2-beacon.bad-domain.test" qtype "A" rcode 5 wait 2ms
    ws -> gw tcp syn srcport 53443 dstport 443 win 65535 mss 1460 wait 1ms
    ws <- gw tcp syn ack win 65535 mss 1460 wait 1ms
    ws -> gw tcp ack wait 1ms
    ws -> gw tls client_hello sni "shadow-upload.example.net" ciphersuite 4866 alpn "h2" wait 2ms
    ws <- gw tls alert payload "BLOCKED_BY_SNI_POLICY"
}

compile {
    loop 100 { syn_flood(bot_node, sec_gateway) }
    c2_signature_check(workstation, sec_gateway)
}
```

### Verifying `802.1Q` `VLAN`, `802.1ad` `QinQ`, `MPLS` & `DSCP` QoS Without NIC Drivers Eating Tags
OS network card drivers love stripping `802.1Q` and carrier `QinQ` double tags before live capture tools ever see them. Writing offline `.fasm` specs keeps outer service tags, inner customer VLANs, MPLS labels, and `pcp` / `dscp` priority markings visually distinct from the inner payload:

```frameassembly
// Preview: Carrier 802.1ad QinQ trunk + 802.1p/DSCP EF voice frame
host pe_hub    { ip 10.99.1.1 mac 00-1B-21-99-01-01 }
host ce_branch { ip 10.99.1.2 mac 00-1B-21-99-01-02 }

flow carrier_trunk_check(hub, branch) {
    hub -> branch qinq 850 inner_vlan 12 dscp 46 icmp echo_request id 1 seq 1
    hub <- branch qinq 850 inner_vlan 12 dscp 46 icmp echo_reply id 1 seq 1 wait 2ms
    hub -> branch vlan 100 pcp 5 dscp 46 rtp pt 0 seq 1 timestamp 160 ssrc 9001 wait 5ms
}

compile { carrier_trunk_check(pe_hub, ce_branch) }
```

### Auditing Industrial OT / SCADA Firewalls Without Poking a Live PLC
Throwing live test traffic at a production **Siemens S7** PLC or substation RTU is a great way to update your resume, and editing hex offsets by hand in `text2pcap` to sanitize TAC captures is pure masochism. This grammar highlights industrial `modbus`, `dnp3`, `s7comm`, `opcua`, `bacnet`, and `ethernetip` function codes and register modifiers natively:

```frameassembly
// Preview: VLAN-tagged Modbus/TCP register poll + DNP3 read request
host scada_hmi { ip 172.22.10.5  mac 00:1b:21:22:0a:05 }
host field_plc { ip 172.22.10.50 mac 00:0e:8c:22:0a:32 }

flow ot_conduit_audit(hmi, plc) {
    hmi -> plc vlan 110 tcp syn srcport 54000 dstport 502 win 64240 mss 1460
    hmi <- plc vlan 110 tcp syn ack win 64240 mss 1460 wait 1ms
    hmi -> plc vlan 110 tcp ack wait 1ms
    hmi -> plc vlan 110 modbus read_holding_registers txid 1 unitid 1 addr 100 count 2 wait 2ms
    hmi <- plc vlan 110 modbus read_holding_registers txid 1 unitid 1 count 2 value 42 is_response wait 5ms
    hmi -> plc vlan 110 dnp3 func "READ" src 1 dst 10 group 60 variation 1 wait 2ms
}

compile { ot_conduit_audit(scada_hmi, field_plc) }
```

### Reversing `.pcap` Captures (`frameassembly reverse`) & Pure Layer 2 Frames
When you need to sanitize customer IP addresses in a vendor TAC capture or modify an existing `.pcap` / `.pcapng` file without editing raw hex offsets, `frameassembly reverse <input.pcap> [-o <output.fasm>]` converts the capture into `.fasm` code using inline frame statements inside `compile { ... }` and MAC-only `host` definitions for pure Layer 2 protocols (`lldp`, `stp`, `lacp`, `eapol`):

```frameassembly
// Preview: Reversed pure L2 LLDP neighbor discovery with MAC-only hosts and inline compile frames
host core_sw   { mac 00:1a:2b:3c:4d:01 }
host access_sw { mac 00:1a:2b:3c:4d:02 }

compile {
    core_sw -> access_sw lldp chassis_id "core-sw-01" port_id "Gi1/0/1" ttl 120 sysname "core-sw-01.corp"
    core_sw <- access_sw lldp chassis_id "access-sw-02" port_id "Gi0/24" ttl 120 sysname "access-sw-02.corp" wait 5ms
}
```

## Highlighted Protocol Keywords (81 Native Protocols)

Every protocol identifier, flag, and sub-keyword below is highlighted case-insensitively (`lowercase`, `UPPERCASE`, or `MixedCase`):

| OSI Layer | Count | Highlighted Protocol Keywords |
| :--- | :---: | :--- |
| **Layer 2 (Switching & Data Link)** | 8 | `arp`, `vlan` (802.1Q), `qinq` (802.1ad), `mpls`, `lldp`, `stp` / `rstp`, `lacp`, `eapol` (802.1X) |
| **Layer 3 (Control, Tunnel, VPN, Routing)** | 20 | `icmp`, `ndp`, `igmp`, `mld`, `gre`, `vxlan`, `geneve`, `ipsec`, `esp`, `ah`, `ikev2`, `wireguard`, `ospf`, `bgp`, `rip`, `vrrp`, `hsrp`, `pim`, `bfd`, `openflow` |
| **Layer 4 (Transport)** | 3 | `tcp`, `udp`, `sctp` |
| **Layer 7 (SNMP, Infra, AAA, Telemetry)** | 14 | `snmp1`, `snmp2`, `snmp3`, `dns`, `mdns`, `dhcp`, `ntp`, `ptp`, `radius`, `tacacs`, `syslog`, `netflow`, `ipfix`, `sflow` |
| **Layer 7 (Web, Cloud, TLS, VoIP, Access)** | 16 | `http`, `http2`, `grpc`, `websocket`, `tls`, `quic`, `tftp`, `ftp`, `ssh`, `telnet`, `whois`, `sip`, `rtp`, `rtsp`, `stun`, `ssdp` |
| **Layer 7 (Mail, Auth, Storage, DB, Brokers)** | 14 | `smtp`, `imap`, `pop3`, `kerberos`, `ldap`, `smb`, `nfs`, `redis`, `memcached`, `mysql`, `postgres`, `mqtt`, `coap`, `amqp` |
| **Layer 7 (Industrial ICS / SCADA / OT)** | 6 | `modbus`, `bacnet`, `dnp3`, `s7comm`, `ethernetip`, `opcua` |

## Bonus: 18 Tab-Completable Keyword Snippets

If you don't feel like typing protocol boilerplate from scratch inside a `.fasm` file, type any prefix below and press `Tab`:

* **Structure & Reachability:** `fasm` (full `host`/`flow`/`compile` skeleton), `compile-inline` (inline `compile` frames without a `flow` block), `host` (IP + MAC endpoint block), `host-l2` (MAC-only Layer 2 endpoint), `icmp-ping` (echo request/reply)
* **Transport & Firewalling:** `tcp-handshake` (3-way `syn` / `syn ack` / `ack`), `firewall-rst` (blocked `syn` -> `rst ack`)
* **SNMP Alerting:** `snmp2-trap` (`linkDown` v2c trap), `snmp3-trap` (encrypted USM `sha256` + `aes` trap)
* **Infra, Web & Cloud:** `dns-query` (`A` lookup), `dhcp-dora` (4-way lease), `http-get` (handshake + `GET` + `200 OK`)
* **Switching, Routing & OT:** `vlan-qos` (`vlan` + `dscp` `rtp`), `qinq` (802.1ad double tag), `vxlan-overlay` (UDP VNI), `bgp-open` (peering + keepalive), `ospf-hello` (`hello` + `dbd`), `modbus-poll` (SCADA register poll)

## Compiler Not Included

Installing this extension (`frameassembly-vscode-1.5.0.vsix`) only teaches your editor (**VS Code `^1.75.0`**, **Cursor**, **Windsurf**, **VSCodium**, **Antigravity IDE**) how to highlight `.fasm` code and Markdown blocks.

To compile `.fasm` code into `.pcap` / `.pcapng` captures (`frameassembly input.fasm -o output.pcap`), inspect the packet ladder in your terminal (`frameassembly show input.fasm`), or reverse existing `.pcap` / `.pcapng` captures into editable `.fasm` code (`frameassembly reverse <input.pcap> [-o <output.fasm>]`), install the standalone **FrameAssembly** CLI from the main repository:

* **FrameAssembly CLI, Releases & Protocol Docs:** [github.com/SteveWinschel/FrameAssembly](https://github.com/SteveWinschel/FrameAssembly)
* **Language & Keyword Reference (`docs/`):** [Getting Started](https://github.com/SteveWinschel/FrameAssembly/blob/main/docs/getting_started.md) • [Use-Case Cookbook](https://github.com/SteveWinschel/FrameAssembly/blob/main/docs/use_cases.md) • [`.fasm` Media Type Spec (`text/vnd.frameassembly`)](https://github.com/SteveWinschel/FrameAssembly/blob/main/docs/fasm-specification.md)

## License

MIT License. Copyright (c) 2026 [Steve Winschel](https://github.com/SteveWinschel/FrameAssembly).