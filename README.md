# FrameAssembly — Packets as Code

[![Try in Browser](https://img.shields.io/badge/Try%20in%20Browser-frameassembly--lang.dev-0ea5e9.svg)](https://frameassembly-lang.dev/)
[![VS Code Extension](https://img.shields.io/badge/VS%20Code-Extension%20v3.1.2-007ACC.svg)](https://marketplace.visualstudio.com/items?itemName=SteveWinschel.frameassembly-vscode)
[![Download for Windows, macOS and Linux](https://img.shields.io/badge/Download-Windows%20%C2%B7%20macOS%20%C2%B7%20Linux-16a34a.svg)](https://github.com/SteveWinschel/FrameAssembly/releases/latest)
[![81 Protocols and User Docs](https://img.shields.io/badge/81%20Protocols-User%20Docs-8b5cf6.svg)](https://frameassembly-lang.dev/docs)
[![MIT License](https://img.shields.io/badge/License-MIT-blue.svg)](https://github.com/SteveWinschel/FrameAssembly/blob/main/LICENSE)

[**Try in Browser**][nav-try] • [**Quick Download**][nav-dl] • [**Use Cases**][nav-uc] • [**How It Works**][nav-how] • [**Comparison**][nav-cmp] • [**81 Protocols & Docs**][nav-docs]

## What Is FrameAssembly?

At first you may think **FrameAssembly** is a programming language for systems development, but ironically it is a tool built specifically for the very people who hate programming -> **Networking & Cybersecurity professionals**.

Have you ever wished you could just describe traffic in a few lines of simple networking keywords, get your own `.pcap`, and do a little SQL injection onto your favourite coworker's machine with the help of `tcpreplay`?

Well, here you have it and it's fun and free to use (even commercially) -> as long as **I'm not responsible for what you do with it** :)

**Compilation works in both directions** -> Compile FrameAssembly `.frasm` code into `.pcap` or `.pcapng` captures across **81 protocols**, or reverse captured `.pcap` / `.pcapng` traces back
into `.frasm` code for anonymizing, editing, inspecting, and replaying with **`tcpreplay`**, **Wireshark** / **`tshark`**, or **Suricata** / **Zeek**.

A complete TCP handshake plus an HTTP request, in a few lines:

```frameassembly
host client   { ip 10.0.0.10 mac 00:11:22:33:44:55 }
host firewall { ip 10.0.0.1  mac aa:bb:cc:dd:ee:ff }

compile {
    client -> firewall tcp syn srcport 51234 dstport 80 win 65535 mss 1460 wait 1ms
    client <- firewall tcp syn ack win 65535 mss 1460 wait 1ms
    client -> firewall tcp ack wait 1ms
    client -> firewall http get uri "/healthz" hosthdr "api.example.com" wait 2ms
    client <- firewall http status 200 reason "OK" body "ok"
}
```

```console
$ frameassembly show test.frasm
#      Time (ms)   Source -> Destination                    Proto       Bytes  Summary
--------------------------------------------------------------------------------------------------------------
1      0.000       10.0.0.10 -> 10.0.0.1                    TCP         58     51234 -> 80 [SYN] seq=1000 len=0
2      1.000       10.0.0.1 -> 10.0.0.10                    TCP         58     80 -> 51234 [SYN ACK] seq=1000 ack=1001 len=0
3      2.000       10.0.0.10 -> 10.0.0.1                    TCP         54     51234 -> 80 [ACK] seq=1001 ack=1001 len=0
4      3.000       10.0.0.10 -> 10.0.0.1                    HTTP        102    51234 -> 80 [ACK PSH] seq=1001 ack=1001 len=48
5      5.000       10.0.0.1 -> 10.0.0.10                    HTTP        94     80 -> 51234 [ACK PSH] seq=1001 ack=1049 len=40

$ frameassembly test.frasm && sudo tcpreplay -i eth0 test.pcap
$ frameassembly reverse test.pcap edited.frasm
```

## Quick Download & Try Now

Pick the fastest route. Every option runs offline and writes standard `.pcap` (classic libpcap) or `.pcapng` (`PCAPNG` with nanosecond timestamps) files.

1. **Recommended CLI Install (`Cargo`, Crates.io):**
   ```bash
   cargo install frameassembly
   ```
   [![Crates.io](https://img.shields.io/crates/v/frameassembly.svg)](https://crates.io/crates/frameassembly) [![Docs.rs](https://docs.rs/frameassembly/badge.svg)](https://docs.rs/frameassembly)

2. **Browser Playground** — nothing to install: [**frameassembly-lang.dev**](https://frameassembly-lang.dev/)

3. **Windows** (PowerShell, no Administrator rights):
   ```powershell
   irm https://raw.githubusercontent.com/SteveWinschel/FrameAssembly/main/install.ps1 | iex
   ```

4. **macOS & Linux** (installs binary + shell Tab completion):
   ```bash
   curl -fsSL https://raw.githubusercontent.com/SteveWinschel/FrameAssembly/main/install.sh | sh
   ```

5. **VS Code Extension** — syntax highlighting, live inline error checking, and 1-click typo Quick Fix:
   ```bash
   code --install-extension SteveWinschel.frameassembly-vscode
   ```

6. **Offline Archives & `.deb` Packages** from [**GitHub Releases**](https://github.com/SteveWinschel/FrameAssembly/releases/latest) (each `.zip` / `.tar.gz` includes `frameassembly`,
   a `quickstart.frasm` starter file, and shell completions; on Windows you can also drag a `.frasm` or `.pcap` file directly onto `frameassembly.exe` in Explorer):

   | System | Download |
   | :--- | :--- |
   | Windows (x64) | [`frameassembly-windows-x64.zip`](https://github.com/SteveWinschel/FrameAssembly/releases/latest/download/frameassembly-windows-x64.zip) |
   | macOS (Apple Silicon) | [`frameassembly-macos-arm64.tar.gz`](https://github.com/SteveWinschel/FrameAssembly/releases/latest/download/frameassembly-macos-arm64.tar.gz) |
   | Linux (x64) | [`frameassembly-linux-x64.tar.gz`](https://github.com/SteveWinschel/FrameAssembly/releases/latest/download/frameassembly-linux-x64.tar.gz) |
   | Debian / Ubuntu | [`frameassembly_amd64.deb`](https://github.com/SteveWinschel/FrameAssembly/releases/latest/download/frameassembly_amd64.deb) |

   Other builds (Windows ARM64, macOS Intel, Linux ARM64, `.deb` for ARM64) and `SHA256SUMS.txt` are on the same page.

7. **Homebrew & Scoop:**
   ```bash
   # Homebrew (macOS & Linux)
   brew install SteveWinschel/tap-FrameAssembly/frameassembly

   # Scoop (Windows)
   scoop bucket add frameassembly https://github.com/SteveWinschel/homebrew-tap-FrameAssembly && scoop install frameassembly
   ```

<details>
<summary><strong>Rust Library & WebAssembly (`docs.rs`, `npm`)</strong></summary>

```bash
# Browser and Node.js WebAssembly package
npm install frameassembly-wasm
```

[![NPM](https://img.shields.io/npm/v/frameassembly-wasm.svg)](https://www.npmjs.com/package/frameassembly-wasm)

Rust 1.88+ library API reference: [**docs.rs/frameassembly**](https://docs.rs/frameassembly) • Compiler internals: [**frameassembly-lang.dev/docs**](https://frameassembly-lang.dev/docs)

</details>

First capture in one minute:

```bash
cat <<'EOF' > demo.frasm
host client { ip 10.0.0.10 }
host server { ip 10.0.0.20 }
compile {
    client -> server icmp echorequest id 1 seq 1 payload "hello" wait 2ms
    client <- server icmp echoreply   id 1 seq 1 payload "hello"
}
EOF

frameassembly show demo.frasm            # packet ladder in the terminal
frameassembly demo.frasm                 # writes classic libpcap demo.pcap (double-click in Wireshark)
frameassembly demo.frasm demo.pcapng     # writes nanosecond PCAPNG demo.pcapng
frameassembly reverse demo.pcap          # writes demo.frasm from any .pcap or .pcapng
```

## Network and Security Testing Use Cases

### 1. Simulate Encrypted SNMPv3 Traps & Syslog Alerts (`Checkmk`, `Zabbix`, `PRTG`)
Testing whether **Checkmk** Event Console, **Zabbix**, **PRTG**, **LibreNMS**, **SolarWinds**, or `snmptrapd` actually pages on an encrypted SNMPv3 `authPriv` trap usually means configuring
a switch agent, loading vendor MIBs, matching EngineIDs, and pulling a fiber patch cord out of hardware. With FrameAssembly, you generate encrypted SNMPv3 traps (`SHA-256` + `AES-128`),
SNMPv1/v2c notifications, `Syslog` events, and `NetFlow` / `IPFIX` / `sFlow` records in seconds:

```frameassembly
host core_sw { ip 10.10.1.2  mac 00:1a:2b:3c:4d:01 }
host checkmk { ip 10.10.1.50 mac 00:1a:2b:3c:4d:50 }

compile {
    core_sw -> checkmk vlan 100 snmp3 trap user "netops" engineid "80001f8801" engineboots 5 enginetime 3600
        auth sha256 "AuthPass123!" priv aes "PrivPass123!"
        oid 1.3.6.1.6.3.1.1.5.3 varbind 1.3.6.1.2.1.2.2.1.8.1 int 2 wait 5ms
    core_sw -> checkmk vlan 100 syslog facility 16 severity 3 hostname "core-sw-01" app "link" msg "Gi0/1 changed state to down"
}
```

```console
$ frameassembly snmp_alert.frasm snmp_alert.pcap && sudo tcpreplay -i eth0 snmp_alert.pcap
```

### 2. Validate Shadow IT, NDR & IDS Detection Rules (`Suricata`, `Zeek`, `Snort`)
Proving that your NDR sensor, DNS sinkhole, or SIEM catches Shadow IT SaaS/AI uploads (unauthorized TLS `sni` or HTTP/3 `quic`), rogue `dhcp` servers, or unauthorized `mdns` / `ssdp`
discovery normally means hunting down noisy third-party `.pcap` captures. FrameAssembly builds exact detection-test captures in a few lines of `.frasm` code:

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
$ frameassembly ids_test.frasm ids_test.pcap && suricata -r ids_test.pcap -k none
```

### 3. Test Stateful Firewalls, VLAN Trunks & OT Rules Without Lab VMs
Sending a single spoofed packet at a stateful firewall (`nftables` / `iptables`, **Palo Alto**, **FortiGate**, **CheckPoint**) won't test your application rules because the firewall drops
mid-stream data without a completed 3-way TCP handshake. FrameAssembly tracks TCP `SEQ`/`ACK` numbers and swaps reply ports on `<-` automatically, so you can verify DMZ rules, 802.1Q `vlan`
tags, and industrial OT (`modbus`, `dnp3`, `s7comm`, `opcua`) policies before a maintenance window:

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
$ frameassembly acl_test.frasm acl_test.pcap && sudo tcpreplay -i eth0 acl_test.pcap
```

### 4. Anonymize & Edit Production `.pcap` Captures (`frameassembly reverse`)
When you need to attach a production capture to a vendor TAC ticket without leaking internal subnets or customer hostnames—or turn a live `tcpdump` capture into a Git-tracked regression
test—run `frameassembly reverse`. Swap the `host` IPs, MACs, VLAN tags, or TLS `sni` names in `.frasm` code, delete background chatter, and recompile—FrameAssembly recalculates all L3/L4
checksums and TCP `SEQ`/`ACK` numbers automatically:

```console
$ frameassembly reverse customer_incident.pcap sanitized_ticket.frasm
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
$ frameassembly sanitized_ticket.frasm sanitized_ticket.pcap
```

More recipes are collected at [**frameassembly-lang.dev/use-cases**](https://frameassembly-lang.dev/use-cases).

## How FrameAssembly Works

Most `.frasm` files need only `host` declarations and a `compile { ... }` block (add an optional `flow` block when reusing sequences across host pairs). Built-in keywords are lowercase with
zero underscores or hyphens (`host`, `flow`, `compile`, `echorequest`, `clienthello`):

1. **`host` — Declare Endpoints Once:** Bind names to `ip` (IPv4 or IPv6) and optional `mac` addresses (omitted unicast MACs default to `00:00:00:00:00:01`, `:02`, ... in declaration order),
   or declare MAC-only switches (`host sw1 { mac 00:1c:73:00:00:01 }`) for Layer 2 switching protocols (`lldp`, `stp`, `lacp`, `eapol`, `vlan`, `qinq`, `mpls`, `arp`).
2. **`compile` — Emit Standard Captures:** Write packet statements directly inside `compile { ... }` using `->` and `<-` arrows, optional `vlan` / `qinq` / `mpls` headers, Layer 2–7 protocol
   keywords, and post-packet `wait` gaps (`ns`, `us`, `ms`, `s`, `m`; `10ms` default between packets when omitted).
3. **`flow` *(Optional)* — Reuse Packet Exchanges:** Group a multi-step sequence into `flow name(a, b) { ... }` and call it inside `compile` across IPv4 or IPv6 host pairs.

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
* **Wire-Valid Framing & Checksums:** Computes Ethernet/802.1Q/802.1ad framing, IPv4/IPv6 lengths, and L3/L4/L7 checksums out of the box.
* **PCAP-to-`.frasm` Decompilation:** Turns existing `.pcap` and `.pcapng` captures into `.frasm` code so you can anonymize IPs or edit headers and recompile. Encrypted payloads (such as
  SNMPv3 `authPriv`, TLS application data, SSH, or IPsec `ESP`) stay intact as `tcp` or `udp` statements with `payload` / `hexpayload` so recompiled captures preserve exact wire bytes.
* **Git-Friendly:** Turns binary `.pcap` blobs into `.frasm` code files that you can review with `git diff` in CI/CD and regression suites.

## Why FrameAssembly Instead of Scapy or Lab VMs?

| Capability | FrameAssembly (`.frasm`) | Scapy (Python) | Full Lab VMs / GNS3 | Downloaded `.pcap` |
| :--- | :--- | :--- | :--- | :--- |
| **Setup Overhead** | Single CLI binary, Browser Playground, or VS Code | Python + `venv` + packages | Hypervisor + OS images | None |
| **Admin Rights to Build PCAP** | Never required | Not for offline `wrpcap` | Admin / hypervisor access | Not required |
| **TCP `SEQ`/`ACK` Math** | Automatic on `->` / `<-` | Manual state in Python | Real OS TCP stack | Fixed static stream |
| **Anonymize & Edit `.pcap`s** | `frameassembly reverse` (`.pcap` <-> `.frasm`) | Custom Python parsing & checksum scripts | Cannot import `.pcap` into live state | Hex editor / `tcprewrite` only |
| **Version Control** | L2–L7 `.frasm` code | Imperative scripts | Multi-GB disk images | Binary blobs |
| **Capture Hygiene** | Zero background chatter | Isolated, high boilerplate | ARP / mDNS / OS noise | Foreign IPs & noise |

FrameAssembly is built to work **alongside** **`tcpreplay`**, **Wireshark** / **`tshark`**, **Suricata**, and **Zeek**—not replace them. Instead of maintaining Python environments or booting
multi-VM labs just to synthesize 10 packets—or struggling to sanitize a customer capture—you compile or reverse `.frasm` code in milliseconds and feed the resulting `.pcap` straight into your
existing replay and analysis tools.

## VS Code Extension

Install the VS Code extension (`SteveWinschel.frameassembly-vscode`) for `.frasm` syntax highlighting, live inline error checking powered by the bundled WebAssembly compiler, and 1-click Quick
Fixes when muscle memory types `sport` instead of `srcport` or `ECHO_REQUEST` instead of `echorequest`.

## Quick CLI Usage

```bash
# Inspect packet timing, flags, sequence numbers, and byte lengths in the terminal
frameassembly show demo.frasm

# Compile .frasm code (.pcap writes classic libpcap; .pcapng writes nanosecond PCAPNG)
frameassembly demo.frasm
frameassembly demo.frasm custom.pcapng

# Decompile an existing .pcap or .pcapng into .frasm code (writes trace.frasm by default)
frameassembly reverse trace.pcap
frameassembly reverse trace.pcap sanitized.frasm

# Print CLI version and command help
frameassembly version
frameassembly help
```

## Supported Protocols and Documentation

FrameAssembly compiles and decompiles **81 protocols across Layers 2–7**. The full guides live on the website:

* [**Documentation**](https://frameassembly-lang.dev/docs) — Getting started with `host`, `flow`, and `compile`, field references for every protocol, multi-hop and dual-stack topologies, the `.frasm` media type specification (`text/vnd.frameassembly`), and compiler internals.
* [**Use Cases & Examples**](https://frameassembly-lang.dev/use-cases) — Copy-paste `.frasm` recipes for Checkmk/Zabbix SNMPv3 traps, Shadow IT & NDR detection, firewall and VLAN verification, IDS/IPS testing, OT/SCADA, and PCAP anonymization.

| Layer | Protocols |
| :--- | :--- |
| **Layer 2** | `arp`, `vlan`, `qinq`, `lldp`, `stp` / `rstp`, `lacp`, `eapol` (802.1X), `mpls` |
| **Layer 3** | `icmp`, `ndp`, `igmp`, `mld`, `gre`, `vxlan`, `geneve`, `ipsec`, `esp`, `ah`, `ikev2`, `wireguard`, `ospf`, `bgp`, `rip`, `vrrp`, `hsrp`, `pim`, `bfd`, `openflow` |
| **Layer 4** | `tcp` (automatic `SEQ`/`ACK`), `udp`, `sctp` |
| **SNMP** | `snmp1`, `snmp2`, `snmp3` (USM auth + `DES`/`AES` privacy) |
| **Infrastructure & Telemetry** | `dns`, `mdns`, `dhcp` / `DHCPv6`, `ntp`, `ptp`, `radius`, `tacacs`, `syslog`, `netflow`, `ipfix`, `sflow` |
| **Web, Cloud, Security & VoIP** | `http`, `http2`, `grpc`, `websocket`, `tls`, `quic`, `ssh`, `telnet`, `ftp`, `tftp`, `whois`, `sip`, `rtp`, `rtsp`, `stun`, `ssdp` |
| **Mail, Auth, Storage, Databases & Brokers** | `smtp`, `imap`, `pop3`, `kerberos`, `ldap`, `smb`, `nfs`, `postgres`, `mysql`, `redis`, `memcached`, `mqtt`, `coap`, `amqp` |
| **Industrial OT & ICS** | `modbus`, `dnp3`, `s7comm`, `opcua`, `bacnet`, `ethernetip` |

## License

Released under the [MIT License](LICENSE). Free for personal, academic, and commercial use.

[nav-try]: https://frameassembly-lang.dev/
[nav-dl]: #quick-download--try-now
[nav-uc]: #network-and-security-testing-use-cases
[nav-how]: #how-frameassembly-works
[nav-cmp]: #why-frameassembly-instead-of-scapy-or-lab-vms
[nav-docs]: #supported-protocols-and-documentation
