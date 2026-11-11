# FrameAssembly — PCAP & Network Packet Studio (`.fasm` v2.0.0)

[![Website & Playground](https://img.shields.io/badge/web%20app-frameassembly.ai.studio-0ea5e9.svg)](https://frameassembly.ai.studio/)
[![VS Code Marketplace](https://img.shields.io/visual-studio-marketplace/v/SteveWinschel.frameassembly-vscode.svg)](https://marketplace.visualstudio.com/items?itemName=SteveWinschel.frameassembly-vscode)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://github.com/SteveWinschel/FrameAssembly/blob/main/LICENSE)

[**Try in Browser (`frameassembly.ai.studio`)**](https://frameassembly.ai.studio/) • [**Studio Features**](#interactive-packet-studio-features) • [**Example `.fasm` Workflows**](#example-fasm-workflows) • [**81 Native Protocols**](#protocol-coverage-81-native-protocols) • [**18 Snippets**](#18-tab-completable-snippets) • [**CLI Companion**](#cli--replay-companion-tools)

## What Is FrameAssembly Packet Studio?

[**FrameAssembly**](https://github.com/SteveWinschel/FrameAssembly) is a **Packets as Code** toolkit built for **Network Engineers, Firewall Administrators, SOC/NDR Analysts, Pentesters, and OT/SCADA Integrators** who need `.pcap` and `.pcapng` traffic captures without maintaining Python `Scapy` virtualenvs, pulling switch cables to trigger alerts, or editing raw hex offsets in `text2pcap`.

Starting in **v2.0.0**, this extension bundles the full **FrameAssembly WebAssembly engine** directly inside **VS Code**, **VS Code for the Web (`vscode.dev`)**, **Cursor**, **Windsurf**, **VSCodium**, and **Antigravity IDE**—with zero external dependencies, zero background daemons, and dedicated `source.frameassembly` (`text/vnd.frameassembly`) disambiguation so x86 Flat Assembler (`;` comments) and FPGA bitstream (`#` comments) extensions never hijack your network packet files.

---

## Interactive Packet Studio Features

### 1. Live In-Editor Diagnostics & 1-Click Quick Fixes
As you edit `.fasm` code, the embedded WebAssembly compiler validates endpoint IPv4/IPv6 families, MAC formats, port bounds, and protocol modifiers in under `5ms` (`120ms` typing debounce). Pasted an older snippet with uppercase or underscored keywords like `ECHO_REQUEST` or `inner_vlan`? Press `Ctrl+.` / `Cmd+.` (or click the lightbulb) for a **1-click Quick Fix** that converts it to FrameAssembly 2.0 strict lowercase (`echorequest`, `innervlan`).

### 2. Protocol-Scoped Autocomplete Across All 81 Protocols
Press `Ctrl+Space` anywhere in a `.fasm` file for context-aware completions:
* **Top-level & `host` blocks:** Completes `host`, `flow`, `compile`, `ip`, and `mac`.
* **Endpoints & Flows:** Suggests declared `host` identifiers, `flow` parameters right after `->` or `<-`, and parameterized flow calls inside `compile { ... }`.
* **81 Protocols & Scoped Modifiers:** Suggests all 81 L2–L7 protocols after `<src> -> <dst>`, then narrows modifier completions to the active protocol (`snmp3` USM crypto flags, `modbus` function codes, `dns` record fields, `bgp` peering attributes, `vlan`/`qinq`/`mpls` tags, and `wait` units `ns`, `us`, `ms`, `s`, `m`).

### 3. Live Packet Ladder Preview & 1-Click Compile to `.pcap`
Use the editor title bar buttons whenever a `.fasm` file is open:
* **Show Live Packet Ladder Preview (`frameassembly.showPacketLadder`):** Opens a theme-aware side-by-side panel displaying `# | Time (ms) | Source -> Destination | Proto | Bytes | Summary` that refreshes live as you edit. Click any packet row to inspect its raw Ethernet frame hex dump.
* **Compile `.fasm` to `.pcapng` (`frameassembly.compileToPcap`):** Compiles the active `.fasm` specification directly into `<stem>.pcap` (nanosecond-precision PCAPNG) ready for **Wireshark**, **`tshark`**, **`tcpreplay`**, **Suricata**, or **Zeek**.

### 4. Explorer Right-Click `.pcap` / `.pcapng` -> Reverse to `.fasm`
Need to anonymize customer IPs before sending a capture to vendor TAC, or tweak one packet inside an existing trace? Right-click any `.pcap` or `.pcapng` file in the VS Code Explorer and select **`FrameAssembly: Reverse Capture (.pcap/.pcapng) to .fasm`** (`frameassembly.reversePcap`) to decompile the capture into `.fasm` code (`host1`, `host2`, ... and inline `compile { ... }` statements) and open it immediately in a new tab.

### 5. Markdown Runbook Highlighting & Safe Auto-Closing Pairs
Injects `source.frameassembly` syntax highlighting into ```` ```frameassembly ```` and ```` ```fasm ```` code blocks inside Markdown files (`markdown.frameassembly.codeblock`), and configures `//` comment toggling (`Ctrl+/`) with `{...}`, `(...)`, and `"..."` pairs without inserting invalid `'single quotes'` or `[brackets]`.

---

## Example `.fasm` Workflows

### Simulating Encrypted `SNMPv3` `authPriv` Traps & `Syslog` Alerts (`Checkmk`, `Zabbix`, `PRTG`)
Verifying whether **Checkmk**, **Zabbix**, **PRTG**, **LibreNMS**, **SolarWinds**, or `snmptrapd` fires an incident alert should not require fighting MIB imports, matching EngineIDs on hardware, or pulling fiber out of a core switch. Write the trap and syslog frames in `.fasm` code and click **Compile `.fasm` to `.pcapng`**:

```frameassembly
// SNMPv3 authPriv linkDown trap + RFC 5424 Syslog alert
host core_sw { ip 10.10.1.2  mac 001a.2b3c.4d01 }
host zabbix  { ip 10.10.1.50 mac 00:1a:2b:3c:4d:50 }

flow link_down_alert(sw, nms) {
    sw -> nms vlan 100 snmp3 trap user "netops" engineid "80001f8880510001" engineboots 5 enginetime 3600 auth sha256 "AuthPass123!" priv aes "PrivPass123!" oid 1.3.6.1.6.3.1.1.5.3 varbind 1.3.6.1.2.1.2.2.1.8.1 int 2 wait 5ms
    sw -> nms vlan 100 syslog facility 16 severity 3 hostname "core-sw-01" app "link" msg "Gi0/1 changed state to down"
}

compile { link_down_alert(core_sw, zabbix) }
```

### Testing Shadow IT, NDR Policies & Stateful IDS Rules (`Suricata`, `Zeek`, `Snort`)
Single spoofed packets bounce right off stateful firewalls (**Palo Alto**, **FortiGate**, **Check Point**, `nftables`) without a valid 3-way TCP handshake and advancing sequence numbers. FrameAssembly tracks 4-tuple `seq`/`acknum` counters automatically so you can test unauthorized SaaS/Shadow IT `tls` `sni` policies, rogue `quic`/`mdns` discovery, and C2 signatures in seconds:

```frameassembly
// Stateful C2 DNS lookup + unauthorized Shadow IT TLS SNI policy test
host workstation { ip 10.40.5.25 mac 00:50:56:40:05:25 }
host sec_gateway { ip 10.40.5.1  mac 00:1c:73:40:05:01 }

flow shadow_it_policy_check(ws, gw) {
    ws -> gw dns query txid 0x4401 qname "c2-beacon.bad-domain.test" qtype "a" wait 1ms
    ws <- gw dns response txid 0x4401 qname "c2-beacon.bad-domain.test" qtype "a" rcode 5 wait 2ms
    ws -> gw tcp syn srcport 53443 dstport 443 win 65535 mss 1460 wait 1ms
    ws <- gw tcp syn ack win 65535 mss 1460 wait 1ms
    ws -> gw tcp ack wait 1ms
    ws -> gw tls clienthello sni "shadow-upload.example.net" ciphersuite 4866 alpn "h2" wait 2ms
    ws <- gw tls alert payload "BLOCKED_BY_SNI_POLICY"
}

compile {
    shadow_it_policy_check(workstation, sec_gateway)
}
```

### Verifying `802.1Q` `VLAN`, `802.1ad` `QinQ`, `MPLS` & `DSCP` QoS Without NIC Tag Stripping
Desktop OS network card drivers frequently strip `802.1Q` tags and carrier `QinQ` double tags before live capture tools see them. Compiling `.fasm` code writes outer service tags, inner customer VLANs (`innervlan`), MPLS label stacks, and `pcp` / `dscp` markings straight into the `.pcap` capture:

```frameassembly
// Carrier 802.1ad QinQ trunk + 802.1p/DSCP EF voice frame
host pe_hub    { ip 10.99.1.1 mac 00-1B-21-99-01-01 }
host ce_branch { ip 10.99.1.2 mac 00-1B-21-99-01-02 }

flow carrier_trunk_check(hub, branch) {
    hub -> branch qinq 850 innervlan 12 dscp 46 icmp echorequest id 1 seq 1
    hub <- branch qinq 850 innervlan 12 dscp 46 icmp echoreply id 1 seq 1 wait 2ms
    hub -> branch vlan 100 pcp 5 dscp 46 rtp pt 0 seq 1 timestamp 160 ssrc 9001 wait 5ms
}

compile { carrier_trunk_check(pe_hub, ce_branch) }
```

### Auditing Industrial OT / SCADA Firewalls Without Touching a Live PLC
Sending live test frames toward a production **Siemens S7** PLC or substation RTU is an unnecessary operational risk. Generate `modbus`, `dnp3`, `s7comm`, `opcua`, `bacnet`, and `ethernetip` register polls offline and validate OT firewall rules safely:

```frameassembly
// VLAN-tagged Modbus/TCP register poll + DNP3 read request
host scada_hmi { ip 172.22.10.5  mac 00:1b:21:22:0a:05 }
host field_plc { ip 172.22.10.50 mac 00:0e:8c:22:0a:32 }

flow ot_conduit_audit(hmi, plc) {
    hmi -> plc vlan 110 tcp syn srcport 54000 dstport 502 win 64240 mss 1460
    hmi <- plc vlan 110 tcp syn ack win 64240 mss 1460 wait 1ms
    hmi -> plc vlan 110 tcp ack wait 1ms
    hmi -> plc vlan 110 modbus readholdingregisters txid 1 unitid 1 addr 100 count 2 wait 2ms
    hmi <- plc vlan 110 modbus readholdingregisters txid 1 unitid 1 count 2 value 42 isresponse wait 5ms
    hmi -> plc vlan 110 dnp3 read src 1 dst 10 group 60 variation 1 wait 2ms
}

compile { ot_conduit_audit(scada_hmi, field_plc) }
```

### Reversing `.pcap` Captures & MAC-Only Layer 2 Topologies
Right-clicking a `.pcap` or `.pcapng` capture in Explorer (or running `frameassembly reverse capture.pcap`) produces `.fasm` code with `host1`, `host2`, ... declarations (including MAC-only `host` blocks for pure Layer 2 switching protocols such as `lldp`, `stp`, `lacp`, and `eapol`) and inline `compile { ... }` statements:

```frameassembly
// Reversed pure L2 LLDP neighbor discovery with MAC-only hosts and inline compile frames
host host1 { mac 00:1a:2b:3c:4d:01 }
host host2 { mac 00:1a:2b:3c:4d:02 }

compile {
    host1 -> host2 lldp chassisid "core-sw-01" portid "Gi1/0/1" ttl 120 sysname "core-sw-01.corp"
    host1 <- host2 lldp chassisid "access-sw-02" portid "Gi0/24" ttl 120 sysname "access-sw-02.corp" wait 5ms
}
```

---

## Protocol Coverage (81 Native Protocols)

All keywords, protocols, modifiers, and duration units (`ns`, `us`, `ms`, `s`, `m`) in FrameAssembly 2.0 use strict lowercase without `_` or `-` (`echorequest`, `innervlan`, `clienthello`, `readholdingregisters`):

| OSI Layer | Count | Native Protocol Keywords |
| :--- | :---: | :--- |
| **Layer 2 (Switching & Data Link)** | 8 | `arp`, `vlan` (802.1Q), `qinq` (802.1ad), `mpls`, `lldp`, `stp`, `lacp`, `eapol` (802.1X) |
| **Layer 3 (Control, Tunnel, VPN, Routing)** | 20 | `icmp`, `ndp`, `igmp`, `mld`, `gre`, `vxlan`, `geneve`, `ipsec`, `esp`, `ah`, `ikev2`, `wireguard`, `ospf`, `bgp`, `rip`, `vrrp`, `hsrp`, `pim`, `bfd`, `openflow` |
| **Layer 4 (Transport)** | 3 | `tcp`, `udp`, `sctp` |
| **Layer 7 (SNMP, Infra, AAA, Telemetry)** | 14 | `snmp1`, `snmp2`, `snmp3`, `dns`, `mdns`, `dhcp`, `ntp`, `ptp`, `radius`, `tacacs`, `syslog`, `netflow`, `ipfix`, `sflow` |
| **Layer 7 (Web, Cloud, TLS, VoIP, Access)** | 16 | `http`, `http2`, `grpc`, `websocket`, `tls`, `quic`, `tftp`, `ftp`, `ssh`, `telnet`, `whois`, `sip`, `rtp`, `rtsp`, `stun`, `ssdp` |
| **Layer 7 (Mail, Auth, Storage, DB, Brokers)** | 14 | `smtp`, `imap`, `pop3`, `kerberos`, `ldap`, `smb`, `nfs`, `redis`, `memcached`, `mysql`, `postgres`, `mqtt`, `coap`, `amqp` |
| **Layer 7 (Industrial ICS / SCADA / OT)** | 6 | `modbus`, `bacnet`, `dnp3`, `s7comm`, `ethernetip`, `opcua` |

---

## 18 Tab-Completable Snippets

Type any prefix below in a `.fasm` file and press `Tab`:

* **Structure & Reachability:** `fasm` (full `host`/`flow`/`compile` skeleton), `compile-inline` (inline `compile` frames matching `reverse` output), `host` (IP + MAC endpoint block), `host-l2` (MAC-only Layer 2 endpoint), `icmp-ping` (`echorequest` / `echoreply`)
* **Transport & Firewalling:** `tcp-handshake` (3-way `syn` / `syn ack` / `ack`), `firewall-rst` (blocked `syn` -> `rst ack`)
* **SNMP Alerting:** `snmp2-trap` (`linkDown` v2c trap), `snmp3-trap` (encrypted USM `sha256` + `aes` trap)
* **Infra, Web & Cloud:** `dns-query` (`a` record lookup), `dhcp-dora` (4-way lease), `http-get` (handshake + `get` + `200 OK`)
* **Switching, Routing & OT:** `vlan-qos` (`vlan` + `dscp` `rtp`), `qinq` (802.1ad double tag), `vxlan-overlay` (UDP VNI), `bgp-open` (peering + keepalive), `ospf-hello` (`hello` + `dbd`), `modbus-poll` (SCADA `readholdingregisters` poll)

---

## CLI & Replay Companion Tools

For headless CI/CD pipelines, shell batch jobs, and pairing with `tshark` or `tcpreplay`, install the companion `frameassembly` CLI (`frameassembly demo.fasm output.pcap`, `frameassembly show demo.fasm`, `frameassembly reverse capture.pcap`):

* **Try in Browser (No Install Required):** [frameassembly.ai.studio](https://frameassembly.ai.studio/)
* **FrameAssembly CLI, Releases & Protocol Guides:** [github.com/SteveWinschel/FrameAssembly](https://github.com/SteveWinschel/FrameAssembly)
* **Language & Use-Case Reference (`docs/`):** [Getting Started](https://github.com/SteveWinschel/FrameAssembly/blob/main/docs/getting_started.md) • [Use-Case Cookbook](https://github.com/SteveWinschel/FrameAssembly/blob/main/docs/use_cases.md) • [`.fasm` Media Type Spec (`text/vnd.frameassembly`)](https://github.com/SteveWinschel/FrameAssembly/blob/main/docs/fasm-specification.md)

## License

MIT License. Copyright (c) 2026 [Steve Winschel](https://github.com/SteveWinschel/FrameAssembly).
