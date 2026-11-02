# FrameAssembly — Packets as Code

[![Crates.io](https://img.shields.io/crates/v/frameassembly.svg)](https://crates.io/crates/frameassembly)
[![Docs.rs](https://docs.rs/frameassembly/badge.svg)](https://docs.rs/frameassembly)
[![NPM](https://img.shields.io/npm/v/frameassembly-wasm.svg)](https://www.npmjs.com/package/frameassembly-wasm)
[![Rust 1.85+](https://img.shields.io/badge/rust-1.85%2B%20(Edition%202024)-orange.svg)](https://www.rust-lang.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

[**Workflows**](#built-for-network--security-testing) • [**How It Works**](#how-it-works) • [**Comparison**](#how-frameassembly-compares) • [**Installation**](#installation) • [**81 Protocols & Docs**](#supported-protocols--documentation)

**FrameAssembly** (`frameassembly` v1.4.3) turns a few lines of `.fasm` code into a custom `.pcap` / `.pcapng` packet capture across **81 Layer 2–7 protocols**—no programming background or root privileges needed to build the capture.

Instead of spending hours configuring test gear, triggering faults on live hardware, spinning up lab VMs, or calculating TCP sequence numbers and checksums by hand, write the packet exchange you need, generate a clean `.pcap`, and replay or inspect it with **`tcpreplay`**, **Wireshark** / **`tshark`**, or **Suricata** / **Zeek**:

```frameassembly
host client   { ip 10.0.0.10 mac 00:11:22:33:44:55 }
host firewall { ip 10.0.0.1  mac aa:bb:cc:dd:ee:ff }

flow http_check(c, fw) {
    c -> fw tcp syn srcport 51234 dstport 80 win 65535 mss 1460 wait 1ms
    c <- fw tcp syn ack win 65535 mss 1460 wait 1ms
    c -> fw tcp ack wait 1ms
    c -> fw http get uri "/healthz" host_hdr "api.example.com" wait 2ms
    c <- fw http status 200 reason "OK" body "{\"ok\":true}"
}

compile { http_check(client, firewall) }
```

```console
$ frameassembly test.fasm -o test.pcap && sudo tcpreplay -i eth0 test.pcap
$ frameassembly show test.fasm
#   Time (ms)    Bytes  Source -> Destination                        Proto        Summary
------------------------------------------------------------------------------------------------------------------------
1   +0.000          58  10.0.0.10:51234 -> 10.0.0.1:80               TCP          [SYN] seq=1000 ack=0 win=65535
2   +1.000          58  10.0.0.1:80 -> 10.0.0.10:51234               TCP          [SYN, ACK] seq=2000 ack=1001 win=65535
3   +2.000          54  10.0.0.10:51234 -> 10.0.0.1:80               TCP          [ACK] seq=1001 ack=2001 win=65535
4   +3.000         111  10.0.0.10:51234 -> 10.0.0.1:80               HTTP         [PSH, ACK] seq=1001 ack=2001 len=57
5   +5.000         133  10.0.0.1:80 -> 10.0.0.10:51234               HTTP         [PSH, ACK] seq=2001 ack=1058 len=79
```

---

## Built for Network & Security Testing

### 1. Simulate SNMP Traps & Test Monitoring Alerts
Testing whether **Zabbix**, **LibreNMS**, **PRTG**, **Checkmk**, **SolarWinds**, or `snmptrapd` actually pages on an encrypted SNMPv3 `authPriv` trap usually means configuring an SNMP agent, loading MIBs, matching EngineIDs, and pulling a cable on a switch. With FrameAssembly, you can generate encrypted SNMPv3 traps (`SHA-256` + `AES-128`), `Syslog` messages, and `NetFlow` / `IPFIX` / `sFlow` records in seconds:

```frameassembly
host core_sw { ip 10.10.1.2  mac 00:1a:2b:3c:4d:01 }
host zabbix  { ip 10.10.1.50 mac 00:1a:2b:3c:4d:50 }

flow snmp_alert(sw, nms) {
    sw -> nms vlan 100 snmp3 trap user "netops" engineid "80001f8801" engineboots 5 enginetime 3600 auth sha256 "AuthPass123!" priv aes "PrivPass123!" oid 1.3.6.1.6.3.1.1.5.3 varbind 1.3.6.1.2.1.2.2.1.8.1 int 2 wait 5ms
    sw -> nms vlan 100 syslog facility 4 severity 3 hostname "core-sw-01" app "link" msg "Gi0/1 down"
}

compile { snmp_alert(core_sw, zabbix) }
```

```console
$ frameassembly snmp_alert.fasm -o snmp_alert.pcap && sudo tcpreplay -i eth0 snmp_alert.pcap
```

### 2. Test Stateful Firewalls, VLAN Trunks & OT Rules
Sending a single spoofed packet at a stateful firewall (`nftables`/`iptables`, **Palo Alto**, **FortiGate**, **CheckPoint**) won't test your application rules because the firewall drops mid-stream data without a completed 3-way TCP handshake. FrameAssembly tracks TCP `SEQ`/`ACK` numbers and flips reply ports on `<-` automatically, so you can verify DMZ rules, 802.1Q `VLAN` tags, and industrial OT (`Modbus`, `DNP3`, `S7comm`) policies before a maintenance window:

```frameassembly
host branch { ip 198.51.100.25 mac 00:11:22:33:44:55 }
host dmz_fw { ip 203.0.113.10  mac aa:bb:cc:dd:ee:ff }

flow acl_audit(c, fw) {
    c -> fw vlan 20 tcp syn srcport 52000 dstport 443 win 65535 mss 1460 wait 1ms
    c <- fw vlan 20 tcp syn ack win 65535 mss 1460 wait 1ms
    c -> fw vlan 20 tcp ack wait 1ms
    c -> fw vlan 20 tls client_hello sni "portal.example.com" ciphersuite 4866 alpn "h2" wait 2ms
    c -> fw vlan 20 tcp syn srcport 52001 dstport 22 win 64240 wait 1ms
    c <- fw vlan 20 tcp rst ack wait 1ms
    c -> fw vlan 110 modbus read_holding_registers txid 1 unitid 1 addr 40001 count 2
}

compile { acl_audit(branch, dmz_fw) }
```

```console
$ frameassembly acl_audit.fasm -o acl_audit.pcap && sudo tcpreplay -i eth1 acl_audit.pcap
```

### 3. Craft Custom Packets for Pentesting
Build Xmas scans (`FIN PSH URG`), unsolicited `ACK` probes, zero-window packets, double-tagged 802.1ad `QinQ` frames, MPLS label stacks, or Active Directory (`Kerberos`, `LDAP`, `SMB`) traffic without wrestling with Python libraries, OS socket restrictions that strip VLAN headers, or manual checksum math:

```frameassembly
host red_box { ip 10.50.1.10  mac 00:50:56:c0:01:10 }
host target  { ip 10.50.1.200 mac 00:50:56:c0:01:c8 }

flow stealth_probe(src, dst) {
    src -> dst tcp fin psh urg srcport 44100 dstport 8443 seq 9000 win 1024 wait 2ms
    src -> dst tcp ack srcport 44101 dstport 445 acknum 50000 win 0 wait 2ms
    src -> dst qinq 2000 inner_vlan 150 mpls 40960 exp 6 bos 1 mpls_ttl 64 icmp echo_request id 99 seq 1
}

compile { stealth_probe(red_box, target) }
```

```console
$ frameassembly stealth_probe.fasm -o stealth_probe.pcap && sudo tcpreplay -i eth0 stealth_probe.pcap
```

### 4. Validate IDS / IPS Signatures & Security Tools (`Suricata`, `Snort`, `Zeek`, SIEM)
Create clean, repeatable `.pcap` files to test detection rules, DNS sinkholes, and TLS `SNI` policies—without background chatter from a live network or sensitive production IPs and credentials:

```frameassembly
host endpoint    { ip 10.40.5.25 mac 00:50:56:40:05:25 }
host sec_gateway { ip 10.40.5.1  mac 00:1c:73:40:05:01 }

flow ids_signature_check(ws, gw) {
    ws -> gw dns query txid 0x4401 qname "c2-beacon.bad-domain.test" qtype "A" wait 1ms
    ws <- gw dns response txid 0x4401 qname "c2-beacon.bad-domain.test" qtype "A" rcode 5 wait 2ms
    ws -> gw tcp syn srcport 53443 dstport 443 win 65535 mss 1460 wait 1ms
    ws <- gw tcp syn ack win 65535 mss 1460 wait 1ms
    ws -> gw tcp ack wait 1ms
    ws -> gw tls client_hello sni "shadow-upload.example.net" ciphersuite 4866 alpn "h2" wait 2ms
    ws <- gw tls alert payload "BLOCKED_BY_SNI_POLICY"
}

compile { ids_signature_check(endpoint, sec_gateway) }
```

```console
$ frameassembly ids.fasm -o ids.pcap && suricata -r ids.pcap -k none
```

---

## How It Works

Every `.fasm` file has three parts, and all keywords are **case-insensitive** (`host` or `HOST`, `tcp` or `TCP`):

1. **`host` — Define your devices:** Give each device an IPv4 or IPv6 address and an optional MAC address (colon `00:1a:2b:3c:4d:5e`, hyphen `00-1A-2B-3C-4D-5E`, or Cisco `001a.2b3c.4d5e` format). If you leave out `mac`, FrameAssembly fills in valid unicast or multicast MACs automatically.
2. **`flow` — One line = one packet:** Write `a -> b <protocol>` or `a <- b <protocol>`.
   - **Smart defaults:** Every protocol works with just its name (`a -> b bgp`, `a -> b ospf`, `a -> b dns`) using standard ports and headers, or you can override any field (`vlan 100`, `ttl 64`, `dscp 46`, `wait 5ms`).
   - **Automatic TCP `SEQ`/`ACK` & reply ports:** When `a <- b` replies to `a -> b`, source and destination ports swap automatically, and TCP sequence/acknowledgment numbers advance by the exact payload size—unless you override `seq` or `acknum` yourself.
3. **`compile` — Build IPv4, IPv6, or repeated traffic:** Run a `flow` with IPv4 hosts, reuse the **exact same `flow`** with IPv6 hosts, or wrap it in `loop 100 { ... }`:

```frameassembly
host v4_client { ip 10.0.0.10 }
host v4_server { ip 10.0.0.80 }
host v6_client { ip 2001:db8::10 }
host v6_server { ip 2001:db8::80 }

flow dns_ping(c, s) {
    c -> s dns query qname "internal.corp" qtype "A" wait 1ms
    c <- s dns response qname "internal.corp" rdata "10.0.0.80" wait 2ms
    c -> s icmp echo_request id 1 seq 1 wait 1ms
    c <- s icmp echo_reply id 1 seq 1
}

compile {
    dns_ping(v4_client, v4_server)
    loop 3 { dns_ping(v6_client, v6_server) }
}
```

---

## How FrameAssembly Compares

| Feature | FrameAssembly (`.fasm`) | Python + `Scapy` | `text2pcap` (Hex Dumps) | `Ostinato` (GUI) | Hardware / VM Labs |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **How you build traffic** | Readable `.fasm` code (`1 line = 1 packet`) | Python scripts | Raw hex dumps | GUI dialog tabs | Live services & switch CLI |
| **Setup & permissions** | Single binary, no root needed to build `.pcap` | Python env + root for wire | Offline command line | Requires `drone` agent | Hours of VM & cable setup |
| **TCP `SEQ`/`ACK` & ports** | Automatic `SEQ`/`ACK` & `<-` port swapping | Manual per-packet math | Manual hex editing | Single-packet stream templates | OS kernel TCP stack |
| **SNMPv3 `authPriv`** | Built-in `MD5`/`SHA`/`SHA-2` + `DES`/`AES` | Custom ASN.1 & crypto code | Impractical by hand | Not built-in | Full agent + MIB setup |
| **Sharing & version control** | Easy-to-diff `.fasm` files, clean `.pcapng` output | Tied to Python packages | Hard-to-read hex blobs | Binary stream files | Noisy background traffic |

---

## Installation

| Platform | Method | Command |
| :--- | :--- | :--- |
| **Linux (Universal)** | One-line installer | `curl -fsSL https://raw.githubusercontent.com/SteveWinschel/FrameAssembly/main/install.sh \| sh` |
| **Debian / Ubuntu** | APT (`.deb`) | `curl -fsSLo /tmp/frameassembly.deb https://github.com/SteveWinschel/FrameAssembly/releases/latest/download/frameassembly_amd64.deb && sudo apt install -y /tmp/frameassembly.deb && rm -f /tmp/frameassembly.deb` |
| **macOS & Linux** | Homebrew | `brew install SteveWinschel/tap-FrameAssembly/frameassembly` |
| **Arch Linux** | AUR | `yay -S frameassembly-bin` |
| **Windows 10 / 11** | WinGet | `winget install SteveWinschel.FrameAssembly` |
| **Windows** | Scoop | `scoop bucket add frameassembly https://github.com/SteveWinschel/homebrew-tap-FrameAssembly && scoop install frameassembly` |
| **Rust (CLI / Crate)** | Cargo (`1.85+`) | `cargo install frameassembly` |
| **Browser / Node.js** | NPM (WebAssembly) | `npm install frameassembly-wasm` |
| **VS Code / Cursor** | Extension | `code --install-extension SteveWinschel.frameassembly-vscode` |
| **Prebuilt Binaries** | GitHub Releases | [Download `.tar.gz`, `.zip`, `.deb`, `.vsix`](https://github.com/SteveWinschel/FrameAssembly/releases/latest) |

---

## Supported Protocols & Documentation

| Layer & Category | Count | Supported `.fasm` Protocol Keywords | Guide & Examples |
| :--- | :---: | :--- | :--- |
| **Layer 2 Switching & Trunks** | 8 | `arp`, `vlan`, `qinq`, `lldp`, `stp`, `lacp`, `eapol`, `mpls` | [`docs/l2_protocols.md`](docs/l2_protocols.md) • [`examples/l2/`](examples/l2/) |
| **Layer 3 Control, VPN & Routing** | 20 | `icmp`, `ndp`, `igmp`, `mld`, `gre`, `vxlan`, `geneve`, `ipsec`, `esp`, `ah`, `ikev2`, `wireguard`, `ospf`, `bgp`, `rip`, `vrrp`, `hsrp`, `pim`, `bfd`, `openflow` | [`docs/l3_protocols.md`](docs/l3_protocols.md) • [`examples/l3/`](examples/l3/) |
| **Layer 4 Transports** | 3 | `tcp`, `udp`, `sctp` | [`docs/l4_transports.md`](docs/l4_transports.md) • [`examples/l4/`](examples/l4/) |
| **Layer 7 SNMP Management** | 3 | `snmp1`, `snmp2`, `snmp3` *(all 9 `varbind` types + `authPriv`)* | [`docs/l7_snmp.md`](docs/l7_snmp.md) • [`examples/l7/snmp/`](examples/l7/snmp/) |
| **Layer 7 Infra, Time, AAA & Flow** | 11 | `dns`, `mdns`, `dhcp`, `ntp`, `ptp`, `radius`, `tacacs`, `syslog`, `netflow`, `ipfix`, `sflow` | [`docs/l7_infra_and_telemetry.md`](docs/l7_infra_and_telemetry.md) • [`examples/l7/`](examples/l7/) |
| **Layer 7 Web, TLS/QUIC & VoIP** | 16 | `http`, `http2`, `grpc`, `websocket`, `tls`, `quic`, `tftp`, `ftp`, `ssh`, `telnet`, `whois`, `sip`, `rtp`, `rtsp`, `stun`, `ssdp` | [`docs/l7_web_and_cloud.md`](docs/l7_web_and_cloud.md) • [`examples/l7/`](examples/l7/) |
| **Layer 7 Mail, AD, Storage & DBs** | 14 | `smtp`, `imap`, `pop3`, `kerberos`, `ldap`, `smb`, `nfs`, `redis`, `memcached`, `mysql`, `postgres`, `mqtt`, `coap`, `amqp` | [`docs/l7_mail_auth_storage_db.md`](docs/l7_mail_auth_storage_db.md) • [`examples/l7/`](examples/l7/) |
| **Layer 7 Industrial ICS / SCADA** | 6 | `modbus`, `bacnet`, `dnp3`, `s7comm`, `ethernetip`, `opcua` | [`docs/l7_industrial_ot.md`](docs/l7_industrial_ot.md) • [`examples/l7/`](examples/l7/) |

* **[Getting Started Guide](docs/getting_started.md)** — Build your first `.pcap` in 60 seconds, learn `host`/`flow`/`compile`, and replay captures with `tcpreplay` and Wireshark.
* **[Practical Use-Case Cookbook](docs/use_cases.md)** — Copy-and-paste recipes for SNMPv3 traps, firewall rule checks, VLAN/QinQ trunks, IDS testing, and OT/SCADA traffic.
* **[Multi-Host Topologies & Dual-Stack Scenarios](docs/topologies_and_dual_stack.md)** — Data center EVPN-VXLAN fabrics, Campus 802.1X NAC onboarding, and 100+ multi-host scenarios in [`examples/topologies/`](examples/topologies/).
* **[`.fasm` Format Specification (`text/vnd.frameassembly`)](docs/fasm-specification.md)** — File format specification and how FrameAssembly `.fasm` files differ from x86 Flat Assembler (`;` comments) and FPGA FASM (`#` comments).
* **[For Nerds: Compiler Internals, Rust Crate API & Formal Grammars](docs/for_nerds.md)** — Compiler architecture, Rust library API, and LLM grammars ([`grammar.ebnf`](grammar.ebnf), [`frameassembly.gbnf`](frameassembly.gbnf), [`frameassembly.lark`](frameassembly.lark), [`llms.txt`](llms.txt), [`llms-full.txt`](llms-full.txt)).

## License

Licensed under the MIT License. See [LICENSE](LICENSE) for details.