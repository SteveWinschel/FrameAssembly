# FrameAssembly — Packets as Code

[![Crates.io](https://img.shields.io/crates/v/frameassembly.svg)](https://crates.io/crates/frameassembly)
[![Docs.rs](https://docs.rs/frameassembly/badge.svg)](https://docs.rs/frameassembly)
[![NPM](https://img.shields.io/npm/v/frameassembly-wasm.svg)](https://www.npmjs.com/package/frameassembly-wasm)
[![Rust 1.85+](https://img.shields.io/badge/rust-1.85%2B%20(Edition%202024)-orange.svg)](https://www.rust-lang.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://github.com/SteveWinschel/FrameAssembly/blob/main/LICENSE)

[**Use Cases**](#network-and-security-testing-use-cases) • [**How It Works**](#how-frameassembly-works) • [**Comparison**](#why-frameassembly-instead-of-scapy-or-lab-vms) • [**Installation**](#installation) • [**81 Protocols & Docs**](#supported-protocols-and-documentation)

## What Is FrameAssembly?

At first you may think **FrameAssembly** is a programming language for systems development, but ironically it is a tool specifically for the very people who hate programming -> **Networking & Cybersecurity professionals**.

Have you ever wished you could just describe traffic in a few lines of simple networking keywords, get your own `.pcap`, and do a little SQL injection onto your favourite coworker's machine with the help of `tcpreplay`?

Well, here you have it and it's fun and free to use (even commercially) -> as long as **I'm not responsible for what you do with it** :)

**Compilation works in both directions** -> You can either compile FrameAssembly `.fasm` files into custom `.pcap` or `.pcapng` files covering **81 protocols** or decompile captured `.pcap` or `.pcapng` into `.fasm` files for editing, inspecting and replaying with **`tcpreplay`**, **Wireshark** / **`tshark`**, or **Suricata** / **Zeek**:

```frameassembly
host client   { ip 10.0.0.10 mac 00:11:22:33:44:55 }
host firewall { ip 10.0.0.1  mac aa:bb:cc:dd:ee:ff }

flow http_check(c, fw) {
    c -> fw tcp syn srcport 51234 dstport 80 win 65535 mss 1460 wait 1ms
    c <- fw tcp syn ack win 65535 mss 1460 wait 1ms
    c -> fw tcp ack wait 1ms
    c -> fw http get uri "/healthz" host_hdr "api.example.com" wait 2ms
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
$ frameassembly reverse test.pcap -o edited.fasm
```

## Network and Security Testing Use Cases

### 1. Simulate `linkDown` SNMP Traps & Syslog Alerts Without Unplugging Cables
Testing whether **Zabbix**, **LibreNMS**, **PRTG**, **Checkmk**, **SolarWinds**, **Datadog**, or `snmptrapd` actually pages on an encrypted SNMPv3 `authPriv` trap usually means configuring an SNMP agent, loading vendor MIBs, matching EngineIDs, and pulling a cable out of a switch. With FrameAssembly, you can generate encrypted SNMPv3 traps (`SHA-256` + `AES-128`), SNMPv1/v2c notifications, `Syslog` events, and `NetFlow` / `IPFIX` / `sFlow` records in seconds:

```frameassembly
host core_sw { ip 10.10.1.2  mac 00:1a:2b:3c:4d:01 }
host zabbix  { ip 10.10.1.50 mac 00:1a:2b:3c:4d:50 }

flow link_down_alert(sw, nms) {
    sw -> nms vlan 100 snmp3 trap user "netops" engineid "80001f8801" engineboots 5 enginetime 3600 auth sha256 "AuthPass123!" priv aes "PrivPass123!" oid 1.3.6.1.6.3.1.1.5.3 varbind 1.3.6.1.2.1.2.2.1.8.1 int 2 wait 5ms
    sw -> nms vlan 100 syslog facility 16 severity 3 hostname "core-sw-01" app "link" msg "Gi0/1 changed state to down"
}

compile { link_down_alert(core_sw, zabbix) }
```

```console
$ frameassembly snmp_alert.fasm -o snmp_alert.pcap && sudo tcpreplay -i eth0 snmp_alert.pcap
```

### 2. Generate `SYN` Floods & Threat Captures for IDS, NDR & SIEM Testing (`Suricata`, `Snort`, `Zeek`)
Validating detection rules for a TCP `SYN` flood, DNS sinkhole hit, or suspicious TLS `SNI` normally means searching GitHub for third-party `.pcap` files full of background noise or sensitive production IPs. FrameAssembly lets you build clean, repeatable `.pcap` files for detection engineering in a few lines of `.fasm` code:

```frameassembly
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

```console
$ frameassembly ids_test.fasm -o ids_test.pcap && suricata -r ids_test.pcap -k none
```

### 3. Test Stateful Firewalls, VLAN Trunks & OT Rules Without Lab VMs
Sending a single spoofed packet at a stateful firewall (`nftables` / `iptables`, **Palo Alto**, **FortiGate**, **CheckPoint**) won't test your application rules because the firewall drops mid-stream data without a completed 3-way TCP handshake. FrameAssembly tracks TCP `SEQ`/`ACK` numbers and swaps reply ports on `<-` automatically, so you can verify DMZ rules, 802.1Q `VLAN` tags, and industrial OT (`Modbus`, `DNP3`, `S7comm`, `OPC UA`) policies before a maintenance window:

```frameassembly
host eng_ws  { ip 192.168.20.25  mac 00:11:22:33:44:55 }
host dmz_srv { ip 203.0.113.10   mac aa:bb:cc:dd:ee:ff }
host ot_plc  { ip 192.168.110.50 mac 00:0e:8c:aa:bb:01 }

flow acl_audit(c, srv, plc) {
    c -> srv vlan 20 tcp syn srcport 52000 dstport 443 win 65535 mss 1460 wait 1ms
    c <- srv vlan 20 tcp syn ack win 65535 mss 1460 wait 1ms
    c -> srv vlan 20 tcp ack wait 1ms
    c -> srv vlan 20 tls client_hello sni "portal.example.com" ciphersuite 4866 alpn "h2" wait 2ms

    c -> srv vlan 20 tcp syn srcport 52001 dstport 22 win 64240 wait 1ms
    c <- srv vlan 20 tcp rst ack wait 1ms

    c -> plc vlan 110 tcp syn srcport 52002 dstport 502 win 64240 mss 1460 wait 1ms
    c <- plc vlan 110 tcp syn ack win 64240 mss 1460 wait 1ms
    c -> plc vlan 110 tcp ack wait 1ms
    c -> plc vlan 110 modbus read_holding_registers txid 1 unitid 1 addr 0 count 2
}

compile { acl_audit(eng_ws, dmz_srv, ot_plc) }
```

```console
# Replay into a SPAN/TAP sensor port (for inline firewalls, split client/server NICs via tcpprep + tcpreplay -i eth0 -I eth1)
$ frameassembly acl_test.fasm -o acl_test.pcap && sudo tcpreplay -i eth0 acl_test.pcap
```

### **4. Reverse & Edit Production `.pcap` Captures (`frameassembly reverse`)**
Instead of only generating captures from scratch, `frameassembly reverse` converts existing `.pcap` and `.pcapng` files back into `.fasm` code. When you need to attach a production capture to a vendor TAC ticket without leaking internal subnets, or turn a live `tcpdump` capture into a regression test, reverse the capture, edit the `host` IPs/MACs/VLANs or delete background chatter, and recompile—FrameAssembly automatically recalculates all L3/L4 checksums and TCP `SEQ`/`ACK` numbers:

```console
$ frameassembly reverse customer_incident.pcap -o sanitized_ticket.fasm
```

```frameassembly
host host_1 { ip 192.0.2.10 mac 00:11:22:33:44:01 }
host host_2 { ip 198.51.100.20 mac 00:11:22:33:44:02 }

compile {
    host_1 -> host_2 vlan 100 tcp syn srcport 54321 dstport 443 win 64240 mss 1460 wait 1ms
    host_1 <- host_2 vlan 100 tcp syn ack win 64240 mss 1460 wait 1ms
    host_1 -> host_2 vlan 100 tcp ack wait 1ms
    host_1 -> host_2 vlan 100 tls client_hello sni "sanitized-app.example.com" ciphersuite 4865 alpn "h2" wait 2ms
    host_1 <- host_2 vlan 100 tcp rst ack
}
```

```console
$ frameassembly sanitized_ticket.fasm -o sanitized_ticket.pcap
```

## How FrameAssembly Works

Every `.fasm` file uses up to three building blocks:

1. **`host` — Declare Endpoints Once:** Bind names to `ip` (IPv4 or IPv6) and `mac` addresses—or declare MAC-only switches (`host sw1 { mac 00:1c:73:00:00:01 }`) for Layer 2 switching protocols (`lldp`, `stp`, `lacp`, `eapol`, `vlan`, `qinq`, `mpls`, `arp`).
2. **`flow` — Describe Exchanges Directionally:** Write packets top-to-bottom using `->` and `<-` arrows, optional `vlan` / `qinq` / `mpls` headers, Layer 2–7 protocol keywords, and `wait` deltas (`ns`, `us`, `ms`, `s`, `m`).
3. **`compile` — Emit Standard Captures:** Call parameterized flows, wrap bursts in `loop <count> { ... }` blocks, or write packet statements directly inside `compile { ... }` without a `flow` block.

```frameassembly
host sw1 { mac 00:1c:73:00:00:01 }
host sw2 { mac 00:1c:73:00:00:02 }

compile {
    sw1 -> sw2 lldp chassis_id "00:1c:73:00:00:01" port_id "Ethernet1/1" ttl 120 sysname "leaf-01" wait 2ms
    sw1 <- sw2 stp rstp root_id "4096/00:1c:73:00:00:02" bridge_id "4096/00:1c:73:00:00:02" port_id 0x8001 cost 0 flags 0x3c
}
```

Under the hood, the compiler handles the packet plumbing automatically:

* **Stateful TCP Tracking:** Advances `SEQ` and `ACK` numbers from payload byte lengths and `SYN`/`FIN` flags, while flipping ports, IPs, and MAC addresses on `<-` replies.
* **Wire-Valid Framing & Checksums:** Computes Ethernet/802.1Q framing, IPv4/IPv6 lengths, and L3/L4/L7 checksums out of the box.
* **Reverse PCAP-to-`.fasm` Decompilation:** Turns existing `.pcap` and `.pcapng` captures into `.fasm` code so you can edit IPs or headers and recompile. Encrypted payloads (such as SNMPv3 `authPriv`, TLS application data, SSH, or IPsec `ESP`) stay intact as `tcp` or `udp` statements with `payload` / `hexpayload` so recompiled captures preserve exact wire bytes.
* **Git-Friendly:** Turns binary `.pcap` blobs into `.fasm` code files that you can review with `git diff` in CI/CD and regression suites.

## Why FrameAssembly Instead of Scapy or Lab VMs?

| Capability | FrameAssembly (`.fasm`) | Scapy (Python) | Full Lab VMs / GNS3 | Downloaded `.pcap` |
| :--- | :--- | :--- | :--- | :--- |
| **Setup Overhead** | Single CLI binary | Python + `venv` + packages | Hypervisor + OS images | None |
| **Root to Build PCAP** | Never required | Not for offline `wrpcap` | Admin / hypervisor access | Not required |
| **TCP `SEQ`/`ACK` Math** | Automatic on `->` / `<-` | Manual state in Python | Real OS TCP stack | Fixed static stream |
| **Edit Existing `.pcap`s** | `frameassembly reverse` (`.pcap` <-> `.fasm`) | Custom Python parsing & checksum scripts | Cannot import `.pcap` into live state | Hex editor / `tcprewrite` only |
| **Version Control** | L2–L7 `.fasm` code | Imperative scripts | Multi-GB disk images | Binary blobs |
| **Capture Hygiene** | Zero background chatter | Clean, high boilerplate | ARP / mDNS / OS noise | Foreign IPs & noise |

FrameAssembly is built to work **alongside** **`tcpreplay`**, **Wireshark** / **`tshark`**, **Suricata**, and **Zeek**—not replace them. Instead of maintaining Python environments or booting multi-VM labs just to synthesize 10 packets—or struggling to sanitize an existing capture—you compile or reverse `.fasm` code in milliseconds and feed the resulting `.pcap` straight into your existing replay and analysis tools.

## Installation

### Cargo (Recommended — Rust 1.85+)
Installing via Cargo is the recommended method because updating to future releases only requires re-running the same command:
```bash
cargo install frameassembly
```

### Linux & macOS Shell Installer
```bash
curl -fsSL https://raw.githubusercontent.com/SteveWinschel/FrameAssembly/main/install.sh | sh
```

### Prebuilt Release Binaries (Linux, Windows, macOS)
Download standalone archives and `SHA-256` checksums from [**GitHub Releases**](https://github.com/SteveWinschel/FrameAssembly/releases).

### WebAssembly Package (`npm`)
For browser-based playgrounds, IDEs, and Node/bundler integrations:
```bash
npm install frameassembly-wasm
```

### Quick CLI Usage
```bash
# Inspect packet timing, flags, sequence numbers, and byte lengths in the terminal
frameassembly show demo.fasm

# Compile .fasm to .pcap (writes demo.pcap by default, or pass -o)
frameassembly demo.fasm
frameassembly demo.fasm -o custom.pcapng

# Decompile an existing .pcap or .pcapng into .fasm (writes trace.fasm by default, or pass -o)
frameassembly reverse trace.pcap
frameassembly reverse trace.pcap -o sanitized.fasm

# View all CLI flags and options
frameassembly --help
```

## Supported Protocols and Documentation

FrameAssembly natively compiles and decompiles **81 protocols across Layers 2–7**. Start with the guides below or jump straight into the protocol reference for your layer:

* [**Getting Started (`docs/getting_started.md`)**](docs/getting_started.md) — Core `.fasm` syntax, `host` / `flow` / `compile` mechanics, reverse PCAP conversion, and your first capture.
* [**Real-World Use Cases (`docs/use_cases.md`)**](docs/use_cases.md) — Copy-paste recipes for NetOps alerting, firewall verification, and SecOps rule validation.
* [**Topologies & Dual-Stack (`docs/topologies_and_dual_stack.md`)**](docs/topologies_and_dual_stack.md) — Multi-hop gateways, VLAN/QinQ trunks, and IPv4/IPv6 dual-stack flows.
* [**`.fasm` Media Type Specification (`docs/fasm-specification.md`)**](docs/fasm-specification.md) — Canonical `text/vnd.frameassembly` format rules and `.fasm` extension disambiguation.
* [**Compiler Architecture (`docs/for_nerds.md`)**](docs/for_nerds.md) — Lexing, parsing, semantic validation, and binary emission internals for curious engineers.

### Layer 2–7 Protocol Reference

* [**Layer 2 — Switching & Data Link (`docs/l2_protocols.md`)**](docs/l2_protocols.md) — Ethernet II, IEEE 802.1Q `VLAN`, 802.1ad `QinQ`, `ARP`, `STP` / `RSTP`, `LLDP`, `LACP`, `MPLS`, and `EAPOL` (802.1X).
* [**Layer 3 — Network, Routing & Tunnels (`docs/l3_protocols.md`)**](docs/l3_protocols.md) — `IPv4`, `IPv6`, `ICMP`, `NDP`, `IGMP`, `MLD`, `GRE`, `IPsec` (`ESP` / `AH`), `IKEv2`, `VXLAN`, `Geneve`, `OSPF`, `BGP`, `RIP`, `PIM`, `VRRP`, `HSRP`, `BFD`, `OpenFlow`, and `WireGuard`.
* [**Layer 4 — Transports (`docs/l4_transports.md`)**](docs/l4_transports.md) — Stateful `TCP` (flags, window, `MSS`, options, automatic `SEQ`/`ACK`), `UDP`, and `SCTP`.
* [**Layer 7 — SNMPv1 / v2c / v3 (`docs/l7_snmp.md`)**](docs/l7_snmp.md) — `GET`, `GETNEXT`, `GETBULK`, `SET`, `RESPONSE`, `TRAP`, `INFORM`, and encrypted `SNMPv3` USM (`SHA-256` auth + `AES-128` priv).
* [**Layer 7 — Infrastructure & Telemetry (`docs/l7_infra_and_telemetry.md`)**](docs/l7_infra_and_telemetry.md) — `DNS`, `mDNS`, `DHCP` / `DHCPv6`, `NTP`, `PTP`, `RADIUS`, `TACACS+`, `Syslog`, `NetFlow`, `IPFIX`, and `sFlow`.
* [**Layer 7 — Web, Cloud, Security & VoIP (`docs/l7_web_and_cloud.md`)**](docs/l7_web_and_cloud.md) — `HTTP`, `HTTP/2`, `gRPC`, `WebSocket`, `TLS` (`ClientHello`, `SNI`, `ALPN`, Alerts), `QUIC`, `SSH`, `Telnet`, `FTP`, `TFTP`, `WHOIS`, `SIP`, `RTP`, `RTSP`, `STUN`, and `SSDP`.
* [**Layer 7 — Mail, Auth, Storage, Databases & Brokers (`docs/l7_mail_auth_storage_db.md`)**](docs/l7_mail_auth_storage_db.md) — `SMTP`, `IMAP`, `POP3`, `Kerberos`, `LDAP`, `SMB`, `NFS`, `PostgreSQL`, `MySQL`, `Redis`, `Memcached`, `MQTT`, `CoAP`, and `AMQP`.
* [**Layer 7 — Industrial OT & ICS (`docs/l7_industrial_ot.md`)**](docs/l7_industrial_ot.md) — `Modbus/TCP`, `DNP3`, `S7comm`, `OPC UA`, `BACnet/IP`, and `EtherNet/IP`.

## License

Released under the [MIT License](LICENSE). Free for personal, academic, and commercial use.