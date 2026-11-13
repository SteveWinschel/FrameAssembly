# FrameAssembly — Packets as Code

[![Website & Playground](https://img.shields.io/badge/web%20app-frameassembly.ai.studio-0ea5e9.svg)](https://frameassembly.ai.studio/)
[![VS Code Marketplace](https://img.shields.io/visual-studio-marketplace/v/SteveWinschel.frameassembly-vscode?label=VS%20Code&color=007ACC)](https://marketplace.visualstudio.com/items?itemName=SteveWinschel.frameassembly-vscode)
[![Crates.io](https://img.shields.io/crates/v/frameassembly.svg)](https://crates.io/crates/frameassembly)
[![Docs.rs](https://docs.rs/frameassembly/badge.svg)](https://docs.rs/frameassembly)
[![NPM](https://img.shields.io/npm/v/frameassembly-wasm.svg)](https://www.npmjs.com/package/frameassembly-wasm)
[![Rust 1.85+](https://img.shields.io/badge/rust-1.85%2B%20(Edition%202024)-orange.svg)](https://www.rust-lang.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://github.com/SteveWinschel/FrameAssembly/blob/main/LICENSE)

[**Try in Browser (`frameassembly.ai.studio`)**](https://frameassembly.ai.studio/) • [**Use Cases**](#network-and-security-testing-use-cases) • [**How It Works**](#how-frameassembly-works) • [**Comparison**](#why-frameassembly-instead-of-scapy-or-lab-vms) • [**Installation**](#installation) • [**81 Protocols & Docs**](#supported-protocols-and-documentation)

## What Is FrameAssembly?

At first you may think **FrameAssembly** is a programming language for systems development, but ironically it is a tool built specifically for the very people who hate programming -> **Networking & Cybersecurity professionals**.

Have you ever wished you could just describe traffic in a few lines of simple networking keywords, get your own `.pcap`, and do a little SQL injection onto your favourite coworker's machine with the help of `tcpreplay`?

Well, here you have it and it's fun and free to use (even commercially) -> as long as **I'm not responsible for what you do with it** :)

**Compilation works in both directions** -> Compile FrameAssembly `.fasm` code into custom `.pcap` or `.pcapng` captures across **81 protocols**, or reverse captured `.pcap` / `.pcapng` traces back into `.fasm` code for anonymizing, editing, inspecting, and replaying with **`tcpreplay`**, **Wireshark** / **`tshark`**, or **Suricata** / **Zeek**:

```frameassembly
host client   { ip 10.0.0.10 mac 00:11:22:33:44:55 }
host firewall { ip 10.0.0.1  mac aa:bb:cc:dd:ee:ff }

flow http_check(c, fw) {
    c -> fw tcp syn srcport 51234 dstport 80 win 65535 mss 1460 wait 1ms
    c <- fw tcp syn ack win 65535 mss 1460 wait 1ms
    c -> fw tcp ack wait 1ms
    c -> fw http get uri "/healthz" hosthdr "api.example.com" wait 2ms
    c <- fw http status 200 reason "OK" body "ok"
}

compile { http_check(client, firewall) }
```

```console
$ frameassembly show test.fasm
#      Time (ms)   Source -> Destination                    Proto       Bytes  Summary
--------------------------------------------------------------------------------------------------------------
1      0.000       10.0.0.10 -> 10.0.0.1                    TCP         58     51234 -> 80 [SYN] seq=1000 len=0
2      1.000       10.0.0.1 -> 10.0.0.10                    TCP         58     80 -> 51234 [SYN ACK] seq=1000 ack=1001 len=0
3      2.000       10.0.0.10 -> 10.0.0.1                    TCP         54     51234 -> 80 [ACK] seq=1001 ack=1001 len=0
4      3.000       10.0.0.10 -> 10.0.0.1                    HTTP        102    51234 -> 80 [ACK PSH] seq=1001 ack=1001 len=48
5      5.000       10.0.0.1 -> 10.0.0.10                    HTTP        94     80 -> 51234 [ACK PSH] seq=1001 ack=1049 len=40

$ frameassembly test.fasm && sudo tcpreplay -i eth0 test.pcap
$ frameassembly reverse test.pcap edited.fasm
```

## Network and Security Testing Use Cases

### 1. Simulate Encrypted SNMPv3 Traps & Syslog Alerts (`Checkmk`, `Zabbix`, `PRTG`)
Testing whether **Checkmk** Event Console, **Zabbix**, **PRTG**, **LibreNMS**, **SolarWinds**, or `snmptrapd` actually pages on an encrypted SNMPv3 `authPriv` trap usually means configuring a switch agent, loading vendor MIBs, matching EngineIDs, and pulling a fiber patch cord out of hardware. With FrameAssembly, you generate encrypted SNMPv3 traps (`SHA-256` + `AES-128`), SNMPv1/v2c notifications, `Syslog` events, and `NetFlow` / `IPFIX` / `sFlow` records in seconds:

```frameassembly
host core_sw { ip 10.10.1.2  mac 00:1a:2b:3c:4d:01 }
host checkmk { ip 10.10.1.50 mac 00:1a:2b:3c:4d:50 }

flow link_down_alert(sw, nms) {
    sw -> nms vlan 100 snmp3 trap user "netops" engineid "80001f8801" engineboots 5 enginetime 3600 auth sha256 "AuthPass123!" priv aes "PrivPass123!" oid 1.3.6.1.6.3.1.1.5.3 varbind 1.3.6.1.2.1.2.2.1.8.1 int 2 wait 5ms
    sw -> nms vlan 100 syslog facility 16 severity 3 hostname "core-sw-01" app "link" msg "Gi0/1 changed state to down"
}

compile { link_down_alert(core_sw, checkmk) }
```

```console
$ frameassembly snmp_alert.fasm snmp_alert.pcap && sudo tcpreplay -i eth0 snmp_alert.pcap
```

### 2. Validate Shadow IT, NDR & IDS Detection Rules (`Suricata`, `Zeek`, `Snort`)
Proving that your NDR sensor, DNS sinkhole, or SIEM catches Shadow IT SaaS/AI uploads (unauthorized TLS `sni` or HTTP/3 `quic`), rogue `dhcp` servers, or unauthorized `mdns` / `ssdp` discovery normally means hunting down noisy third-party `.pcap` captures. FrameAssembly builds exact detection-test captures in a few lines of `.fasm` code:

```frameassembly
host workstation { ip 10.40.5.25 mac 00:50:56:40:05:25 }
host rogue_iot   { ip 10.40.5.99 mac 00:50:56:40:05:99 }
host sec_gateway { ip 10.40.5.1  mac 00:1c:73:40:05:01 }
host mdns_group  { ip 224.0.0.251 }

flow shadow_it_and_ndr_audit(ws, iot, gw, mcast) {
    ws  -> gw    dns query txid 0x4401 qname "shadow-ai-upload.example.net" qtype "a" wait 1ms
    ws  <- gw    dns response txid 0x4401 qname "shadow-ai-upload.example.net" qtype "a" rcode 5 wait 2ms
    ws  -> gw    tcp syn srcport 53443 dstport 443 win 65535 mss 1460 wait 1ms
    ws  <- gw    tcp syn ack win 65535 mss 1460 wait 1ms
    ws  -> gw    tcp ack wait 1ms
    ws  -> gw    tls clienthello sni "shadow-ai-upload.example.net" ciphersuite 4866 alpn "h2" wait 2ms
    ws  <- gw    tls alert payload "BLOCKED_BY_SNI_POLICY" wait 2ms
    ws  -> gw    quic initial version 1 dcid "a1b2c3d4" scid "e5f60708" pktnum 1 payload "QUIC_SHADOW_SAAS" wait 2ms
    iot -> mcast mdns query qname "_airplay._tcp.local" qtype "ptr" wait 2ms
    iot -> gw    ssdp msearch st "ssdp:all"
}

compile { shadow_it_and_ndr_audit(workstation, rogue_iot, sec_gateway, mdns_group) }
```

```console
$ frameassembly ids_test.fasm ids_test.pcap && suricata -r ids_test.pcap -k none
```

### 3. Test Stateful Firewalls, VLAN Trunks & OT Rules Without Lab VMs
Sending a single spoofed packet at a stateful firewall (`nftables` / `iptables`, **Palo Alto**, **FortiGate**, **CheckPoint**) won't test your application rules because the firewall drops mid-stream data without a completed 3-way TCP handshake. FrameAssembly tracks TCP `SEQ`/`ACK` numbers and swaps reply ports on `<-` automatically, so you can verify DMZ rules, 802.1Q `vlan` tags, and industrial OT (`modbus`, `dnp3`, `s7comm`, `opcua`) policies before a maintenance window:

```frameassembly
host eng_ws  { ip 192.168.20.25  mac 00:11:22:33:44:55 }
host dmz_srv { ip 203.0.113.10   mac aa:bb:cc:dd:ee:ff }
host ot_plc  { ip 192.168.110.50 mac 00:0e:8c:aa:bb:01 }

flow acl_audit(c, srv, plc) {
    c -> srv vlan 20 tcp syn srcport 52000 dstport 443 win 65535 mss 1460 wait 1ms
    c <- srv vlan 20 tcp syn ack win 65535 mss 1460 wait 1ms
    c -> srv vlan 20 tcp ack wait 1ms
    c -> srv vlan 20 tls clienthello sni "portal.example.com" ciphersuite 4866 alpn "h2" wait 2ms

    c -> srv vlan 20 tcp syn srcport 52001 dstport 22 win 64240 wait 1ms
    c <- srv vlan 20 tcp rst ack wait 1ms

    c -> plc vlan 110 tcp syn srcport 52002 dstport 502 win 64240 mss 1460 wait 1ms
    c <- plc vlan 110 tcp syn ack win 64240 mss 1460 wait 1ms
    c -> plc vlan 110 tcp ack wait 1ms
    c -> plc vlan 110 modbus readholdingregisters txid 1 unitid 1 addr 0 count 2
}

compile { acl_audit(eng_ws, dmz_srv, ot_plc) }
```

```console
# Replay into a SPAN/TAP sensor port (for inline firewalls, split client/server NICs via tcpprep + tcpreplay -i eth0 -I eth1)
$ frameassembly acl_test.fasm acl_test.pcap && sudo tcpreplay -i eth0 acl_test.pcap
```

### 4. Anonymize & Edit Production `.pcap` Captures (`frameassembly reverse`)
When you need to attach a production capture to a vendor TAC ticket without leaking internal subnets or customer hostnames—or turn a live `tcpdump` capture into a Git-tracked regression test—run `frameassembly reverse`. Swap the `host` IPs, MACs, VLAN tags, or TLS `sni` names in `.fasm` code, delete background chatter, and recompile—FrameAssembly recalculates all L3/L4 checksums and TCP `SEQ`/`ACK` numbers automatically:

```console
$ frameassembly reverse customer_incident.pcap sanitized_ticket.fasm
```

```frameassembly
host host1 { ip 192.0.2.10 mac 00:11:22:33:44:01 }
host host2 { ip 198.51.100.20 mac 00:11:22:33:44:02 }

compile {
    host1 -> host2 vlan 100 tcp syn srcport 54321 dstport 443 win 64240 mss 1460 wait 1ms
    host1 <- host2 vlan 100 tcp syn ack win 64240 mss 1460 wait 1ms
    host1 -> host2 vlan 100 tcp ack wait 1ms
    host1 -> host2 vlan 100 tls clienthello sni "sanitized-app.example.com" ciphersuite 4865 alpn "h2" wait 2ms
    host1 <- host2 vlan 100 tcp rst ack
}
```

```console
$ frameassembly sanitized_ticket.fasm sanitized_ticket.pcap
```

## How FrameAssembly Works

Every `.fasm` file uses up to three building blocks, with strictly lowercase keywords (`host`, `flow`, `compile`, `echorequest`, `clienthello`) and zero underscores or hyphens on built-in keywords:

1. **`host` — Declare Endpoints Once:** Bind names to `ip` (IPv4 or IPv6) and `mac` addresses—or declare MAC-only switches (`host sw1 { mac 00:1c:73:00:00:01 }`) for Layer 2 switching protocols (`lldp`, `stp`, `lacp`, `eapol`, `vlan`, `qinq`, `mpls`, `arp`).
2. **`flow` — Describe Exchanges Directionally:** Write packets top-to-bottom using `->` and `<-` arrows, optional `vlan` / `qinq` / `mpls` headers, Layer 2–7 protocol keywords, and `wait` deltas (`ns`, `us`, `ms`, `s`, `m`).
3. **`compile` — Emit Standard Captures:** Call reusable flows across different host pairs, or write packet statements directly inside `compile { ... }` without a `flow` block.

```frameassembly
host sw1 { mac 00:1c:73:00:00:01 }
host sw2 { mac 00:1c:73:00:00:02 }

compile {
    sw1 -> sw2 lldp chassisid "00:1c:73:00:00:01" portid "Ethernet1/1" ttl 120 sysname "leaf-01" wait 2ms
    sw1 <- sw2 stp rstp rootid "4096/00:1c:73:00:00:02" bridgeid "4096/00:1c:73:00:00:02" portid 0x8001 cost 0 flags 0x3c
}
```

Under the hood, the compiler handles the packet plumbing automatically:

* **Stateful TCP Tracking:** Advances `SEQ` and `ACK` numbers from payload byte lengths and `SYN`/`FIN` flags, while flipping ports, IPs, and MAC addresses on `<-` replies.
* **Wire-Valid Framing & Checksums:** Computes Ethernet/802.1Q framing, IPv4/IPv6 lengths, and L3/L4/L7 checksums out of the box.
* **PCAP-to-`.fasm` Decompilation:** Turns existing `.pcap` and `.pcapng` captures into `.fasm` code so you can anonymize IPs or edit headers and recompile. Encrypted payloads (such as SNMPv3 `authPriv`, TLS application data, SSH, or IPsec `ESP`) stay intact as `tcp` or `udp` statements with `payload` / `hexpayload` so recompiled captures preserve exact wire bytes.
* **Git-Friendly:** Turns binary `.pcap` blobs into `.fasm` code files that you can review with `git diff` in CI/CD and regression suites.

## Why FrameAssembly Instead of Scapy or Lab VMs?

| Capability | FrameAssembly (`.fasm`) | Scapy (Python) | Full Lab VMs / GNS3 | Downloaded `.pcap` |
| :--- | :--- | :--- | :--- | :--- |
| **Setup Overhead** | Single CLI binary or VS Code / Web Studio | Python + `venv` + packages | Hypervisor + OS images | None |
| **Admin Rights to Build PCAP** | Never required | Not for offline `wrpcap` | Admin / hypervisor access | Not required |
| **TCP `SEQ`/`ACK` Math** | Automatic on `->` / `<-` | Manual state in Python | Real OS TCP stack | Fixed static stream |
| **Anonymize & Edit `.pcap`s** | `frameassembly reverse` (`.pcap` <-> `.fasm`) | Custom Python parsing & checksum scripts | Cannot import `.pcap` into live state | Hex editor / `tcprewrite` only |
| **Version Control** | L2–L7 `.fasm` code | Imperative scripts | Multi-GB disk images | Binary blobs |
| **Capture Hygiene** | Zero background chatter | Isolated, high boilerplate | ARP / mDNS / OS noise | Foreign IPs & noise |

FrameAssembly is built to work **alongside** **`tcpreplay`**, **Wireshark** / **`tshark`**, **Suricata**, and **Zeek**—not replace them. Instead of maintaining Python environments or booting multi-VM labs just to synthesize 10 packets—or struggling to sanitize a customer capture—you compile or reverse `.fasm` code in milliseconds and feed the resulting `.pcap` straight into your existing replay and analysis tools.

## Installation

### Try in Browser (No Install Required)
Open the official website and browser playground at [**frameassembly.ai.studio**](https://frameassembly.ai.studio/) to compile `.fasm` code <-> `.pcap` / `.pcapng` captures and inspect packet ladders directly in your browser.

### VS Code Packet Studio Extension
Install the interactive VS Code Packet Studio (live diagnostics, 1-click Quick Fixes, protocol autocomplete, live Packet Ladder preview, `.fasm` -> `.pcap` compilation, and right-click `.pcap` -> `.fasm` decompilation):
```bash
code --install-extension SteveWinschel.frameassembly-vscode
```

### Cargo (Recommended CLI Install — Rust 1.85+)
```bash
cargo install frameassembly
```

### Linux & macOS Shell Installer (Includes Shell Tab Completion)
```bash
curl -fsSL https://raw.githubusercontent.com/SteveWinschel/FrameAssembly/main/install.sh | sh
```

### Homebrew (macOS & Linux) & Scoop (Windows)
```bash
# Homebrew
brew install SteveWinschel/tap-FrameAssembly/frameassembly

# Scoop (Windows)
scoop bucket add frameassembly https://github.com/SteveWinschel/homebrew-tap-FrameAssembly && scoop install frameassembly
```

### Debian / Ubuntu (`.deb`) & Prebuilt Release Binaries
Download `.deb` packages, standalone archives for Linux, macOS, and Windows, and `SHA-256` checksums from [**GitHub Releases**](https://github.com/SteveWinschel/FrameAssembly/releases).

### WebAssembly Package (`npm`)
For browser tools, custom IDEs, and Node/bundler integrations:
```bash
npm install frameassembly-wasm
```

### Quick CLI Usage
```bash
# Inspect packet timing, flags, sequence numbers, and byte lengths in the terminal
frameassembly show demo.fasm

# Compile .fasm code to .pcap (writes demo.pcap by default, or pass an output path)
frameassembly demo.fasm
frameassembly demo.fasm custom.pcap

# Decompile an existing .pcap or .pcapng into .fasm code (writes trace.fasm by default, or pass an output path)
frameassembly reverse trace.pcap
frameassembly reverse trace.pcap sanitized.fasm

# Print CLI version and command help
frameassembly version
frameassembly help
```

## Supported Protocols and Documentation

FrameAssembly natively compiles and decompiles **81 protocols across Layers 2–7**. Start with the guides below or jump straight into the protocol reference for your layer:

* [**Getting Started (`docs/getting_started.md`)**](docs/getting_started.md) — Core `.fasm` syntax, `host` / `flow` / `compile` mechanics, AI copy-paste prompt, reverse PCAP conversion, and your first capture.
* [**Real-World Use Cases (`docs/use_cases.md`)**](docs/use_cases.md) — Copy-paste recipes for Checkmk/Zabbix SNMPv3 traps, Shadow IT & NDR detection, firewall/VLAN verification, and PCAP anonymization.
* [**Topologies & Dual-Stack (`docs/topologies_and_dual_stack.md`)**](docs/topologies_and_dual_stack.md) — Multi-hop gateways, VLAN/QinQ trunks, and IPv4/IPv6 dual-stack flows.
* [**`.fasm` Media Type Specification (`docs/fasm-specification.md`)**](docs/fasm-specification.md) — Formal `text/vnd.frameassembly` format rules and `.fasm` extension disambiguation.
* [**Compiler Architecture (`docs/for_nerds.md`)**](docs/for_nerds.md) — Lexing, parsing, semantic validation, and binary emission internals for curious engineers.

### Layer 2–7 Protocol Reference

* [**Layer 2 — Switching & Data Link (`docs/l2_protocols.md`)**](docs/l2_protocols.md) — Ethernet II, IEEE 802.1Q `vlan`, 802.1ad `qinq`, `arp`, `stp` / `rstp`, `lldp`, `lacp`, `mpls`, and `eapol` (802.1X).
* [**Layer 3 — Network, Routing & Tunnels (`docs/l3_protocols.md`)**](docs/l3_protocols.md) — `IPv4`, `IPv6`, `icmp`, `ndp`, `igmp`, `mld`, `gre`, `ipsec` (`esp` / `ah`), `ikev2`, `vxlan`, `geneve`, `ospf`, `bgp`, `rip`, `pim`, `vrrp`, `hsrp`, `bfd`, `openflow`, and `wireguard`.
* [**Layer 4 — Transports (`docs/l4_transports.md`)**](docs/l4_transports.md) — Stateful `tcp` (flags, window, `mss`, options, automatic `SEQ`/`ACK`), `udp`, and `sctp`.
* [**Layer 7 — SNMPv1 / v2c / v3 (`docs/l7_snmp.md`)**](docs/l7_snmp.md) — `get`, `getnext`, `getbulk`, `set`, `response`, `trap`, `inform`, and encrypted `snmp3` USM (`SHA-256` auth + `AES-128` priv).
* [**Layer 7 — Infrastructure & Telemetry (`docs/l7_infra_and_telemetry.md`)**](docs/l7_infra_and_telemetry.md) — `dns`, `mdns`, `dhcp` / `DHCPv6`, `ntp`, `ptp`, `radius`, `tacacs`, `syslog`, `netflow`, `ipfix`, and `sflow`.
* [**Layer 7 — Web, Cloud, Security & VoIP (`docs/l7_web_and_cloud.md`)**](docs/l7_web_and_cloud.md) — `http`, `http2`, `grpc`, `websocket`, `tls` (`clienthello`, `sni`, `alpn`, `alert`), `quic`, `ssh`, `telnet`, `ftp`, `tftp`, `whois`, `sip`, `rtp`, `rtsp`, `stun`, and `ssdp`.
* [**Layer 7 — Mail, Auth, Storage, Databases & Brokers (`docs/l7_mail_auth_storage_db.md`)**](docs/l7_mail_auth_storage_db.md) — `smtp`, `imap`, `pop3`, `kerberos`, `ldap`, `smb`, `nfs`, `postgres`, `mysql`, `redis`, `memcached`, `mqtt`, `coap`, and `amqp`.
* [**Layer 7 — Industrial OT & ICS (`docs/l7_industrial_ot.md`)**](docs/l7_industrial_ot.md) — `modbus`, `dnp3`, `s7comm`, `opcua`, `bacnet`, and `ethernetip`.

## License

Released under the [MIT License](LICENSE). Free for personal, academic, and commercial use.
