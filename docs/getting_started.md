# Getting Started with FrameAssembly (`docs/getting_started.md`)

[**Try in Browser (`frameassembly.ai.studio`)**](https://frameassembly.ai.studio/) • [**Installation**](#1-install-frameassembly) • [**60-Second Quickstart**](#2-build-your-first-pcap-in-60-seconds) • [**Reverse PCAP to `.fasm`**](#convert-existing-pcap--pcapng-captures-to-fasm-code-frameassembly-reverse) • [**MACs & Defaults**](#3-skip-mac-formatting-and-boilerplate) • [**Stateful TCP**](#4-stateful-tcp-without-sequence-number-math) • [**VLANs, QinQ, MPLS & QoS**](#5-vlan-trunks-qinq-mpls-qos-and-fragments) • [**Dual-Stack & Loops**](#6-ipv4ipv6-reuse-and-loop-traffic-bursts) • [**Cheat Sheet**](#7-wireshark-and-tcpdump-to-fasm-cheat-sheet)

## Why FrameAssembly Exists

Crafting custom network traffic is usually way harder than whatever you are actually trying to test.

Want to verify a stateful firewall rule, check if Zabbix pages on an encrypted SNMPv3 trap, or test a new Suricata signature? Normally you have three choices: wire up lab gear and pull cables by hand, fight Python virtual environments and manual TCP sequence math in `Scapy` as `root`, or count hex byte offsets in `text2pcap` until you question your career choices :)

**FrameAssembly** (`frameassembly`) lets you write traffic in `.fasm` code, compile it into `.pcap` / `.pcapng` captures—or decompile existing captures back into `.fasm`—and feed the result into **`tcpreplay`**, **Wireshark** / **`tshark`**, **Suricata**, or **Zeek**.

## 1. Install FrameAssembly

Installing via **Cargo** (`cargo install frameassembly`) is the recommended method because updating to future releases only requires re-running `cargo install frameassembly`—or you can [**Try in Browser (No Install Required)**](https://frameassembly.ai.studio/) on the official web app to compile `.fasm` <-> `.pcap` / `.pcapng` and inspect packets with zero install:

| Platform / OS | Method | Command |
| :--- | :--- | :--- |
| **Any (Rust 1.85+)** | **Cargo (Recommended)** | `cargo install frameassembly` |
| **Web Browser** | **Try in Browser (No Install Required)** | [**frameassembly.ai.studio**](https://frameassembly.ai.studio/) (compile `.fasm` <-> `.pcap`/`.pcapng` & inspect packets in the browser) |
| **Linux & macOS** | Shell installer | `curl -fsSL https://raw.githubusercontent.com/SteveWinschel/FrameAssembly/main/install.sh \| sh` |
| **macOS & Linux** | Homebrew | `brew install SteveWinschel/tap-FrameAssembly/frameassembly` |
| **Debian / Ubuntu** | APT (`.deb`) | `curl -fsSLo /tmp/frameassembly.deb https://github.com/SteveWinschel/FrameAssembly/releases/latest/download/frameassembly_amd64.deb && sudo apt install -y /tmp/frameassembly.deb && rm -f /tmp/frameassembly.deb` |
| **Arch Linux** | AUR | `yay -S frameassembly-bin` |
| **Windows 10 / 11** | WinGet | `winget install SteveWinschel.FrameAssembly` |
| **Windows** | Scoop | `scoop bucket add frameassembly https://github.com/SteveWinschel/homebrew-tap-FrameAssembly && scoop install frameassembly` |
| **Browser / Node.js** | NPM (WASM) | `npm install frameassembly-wasm` |
| **VS Code / Cursor** | Syntax highlighting | `code --install-extension SteveWinschel.frameassembly-vscode` |
| **Standalone Archives**| GitHub Releases | [**Download prebuilt binaries (`v1.5.1`)**](https://github.com/SteveWinschel/FrameAssembly/releases/latest) |

Check that the binary is ready:

```bash
frameassembly --version
frameassembly --help
```

## 2. Build Your First `.pcap` in 60 Seconds

Every `.fasm` file has up to three building blocks:

1. **`host` — Name Your Devices:** Bind a name to an `ip` (IPv4 or IPv6) and an optional `mac`—or declare MAC-only `host` blocks (`host sw1 { mac 00:1c:73:00:00:01 }`) for Layer 2 switching protocols (`lldp`, `stp`, `lacp`, `eapol`, `vlan`, `qinq`, `mpls`, `arp`).
2. **`flow` — Group Reusable Packet Exchanges (Optional):** One line = one Ethernet frame. Use `->` for forward packets, `<-` for replies, and `wait` (`ns`, `us`, `ms`, `s`, `m`) for timing.
3. **`compile` — Generate the Capture:** Call your `flow` with your `host` names, wrap bursts in `loop <count> { ... }`, or write packet statements directly inside `compile { ... }` without a `flow` block.

Save this as `ping_test.fasm`:

```frameassembly
// 1. Declare the endpoints
host workstation { ip 192.168.10.50 mac 00:1a:2b:3c:4d:50 }
host gateway     { ip 192.168.10.1  mac 00:1a:2b:3c:4d:01 }

// 2. Describe the packet exchange (1 line = 1 wire frame)
flow ping_check(c, gw) {
    c -> gw icmp echo_request id 100 seq 1 payload "ping-1"
    c <- gw icmp echo_reply   id 100 seq 1 payload "ping-1" wait 2ms
    c -> gw icmp echo_request id 100 seq 2 payload "ping-2" wait 10ms
    c <- gw icmp echo_reply   id 100 seq 2 payload "ping-2" wait 2ms
}

// 3. Build the capture
compile { ping_check(workstation, gateway) }
```

Preview the packet ladder in your terminal, compile `ping_test.fasm` (which writes `ping_test.pcap` by default unless you pass `-o`), and inspect or replay it:

```console
$ frameassembly show ping_test.fasm
#      Time (ms)   Source -> Destination                    Proto       Bytes  Summary
--------------------------------------------------------------------------------------------------------------
1      0.000       192.168.10.50 -> 192.168.10.1            ICMP        48     Echo Request (type=8 code=0)
2      2.000       192.168.10.1 -> 192.168.10.50            ICMP        48     Echo Reply (type=0 code=0)
3      12.000      192.168.10.50 -> 192.168.10.1            ICMP        48     Echo Request (type=8 code=0)
4      14.000      192.168.10.1 -> 192.168.10.50            ICMP        48     Echo Reply (type=0 code=0)

$ frameassembly ping_test.fasm
$ tshark -r ping_test.pcap
$ sudo tcpreplay -i eth0 ping_test.pcap
```

### Inline Statements in `compile` & MAC-Only Layer 2 Switches
For quick one-off captures or Layer 2 switch frames (`lldp`, `stp`, `lacp`, `eapol`, `vlan`, `qinq`, `mpls`, `arp`), you can omit `ip` from your `host` blocks and write packet lines directly inside `compile { ... }` with no `flow` block needed:

```frameassembly
host sw1 { mac 00:1c:73:00:00:01 }
host sw2 { mac 00:1c:73:00:00:02 }

compile {
    sw1 -> sw2 lldp chassis_id "00:1c:73:00:00:01" port_id "Ethernet1/1" ttl 120 sysname "spine-01" wait 2ms
    sw1 <- sw2 lldp chassis_id "00:1c:73:00:00:02" port_id "Ethernet49/1" ttl 120 sysname "leaf-01" wait 2ms
    sw1 -> sw2 stp rstp root_id "4096/00:1c:73:00:00:01" bridge_id "4096/00:1c:73:00:00:01" port_id 0x8001 cost 0 flags 0x3c
}
```

### Convert Existing `.pcap` / `.pcapng` Captures to `.fasm` Code (`frameassembly reverse`)
Already have a `.pcap` or `.pcapng` capture from `tcpdump` or Wireshark that you want to sanitize, edit, or check into Git? Run `frameassembly reverse` (which writes `<input_stem>.fasm` by default unless you pass `-o`):

```console
$ frameassembly reverse ping_test.pcap -o reversed_ping.fasm
```

`frameassembly reverse` inspects every packet in the capture, discovers the `host` endpoints (`host_1`, `host_2`, ...), and emits `.fasm` code with a `compile { ... }` block:

```frameassembly
host host_1 { ip 192.168.10.50 mac 00:1a:2b:3c:4d:50 }
host host_2 { ip 192.168.10.1 mac 00:1a:2b:3c:4d:01 }

compile {
    host_1 -> host_2 icmp echo_request id 100 seq 1 payload "ping-1"
    host_1 <- host_2 icmp echo_reply id 100 seq 1 payload "ping-1" wait 2ms
    host_1 -> host_2 icmp echo_request id 100 seq 2 payload "ping-2" wait 10ms
    host_1 <- host_2 icmp echo_reply id 100 seq 2 payload "ping-2" wait 2ms
}
```

From there, you can change any IP, MAC, VLAN tag, or payload and recompile (`frameassembly reversed_ping.fasm -o edited.pcap`)—FrameAssembly automatically recalculates all L3/L4 checksums and TCP `SEQ`/`ACK` numbers. Encrypted payloads (like SNMPv3 `authPriv`, TLS application data, SSH, or IPsec `ESP`) are not decrypted; `reverse` keeps them as `tcp` or `udp` statements with `payload` / `hexpayload` so recompiling preserves the exact wire bytes.

### Three Quick Ground Rules
* **Case-insensitive keywords:** `host`, `HOST`, and `Host` compile to the exact same bytes (including all keywords, protocols, modifiers, time units `ns`/`us`/`ms`/`s`/`m`, and identifiers). Quoted strings (`"..."`) always keep their exact casing on the wire.
* **Comments use `//`:** Never `#` or `;`.
* **1 statement = 1 frame:** Even if you wrap a long Layer 7 line across multiple indented lines for readability, each `->` or `<-` statement emits one Ethernet frame.

## 3. Skip MAC Formatting and Boilerplate

### Paste Any MAC Format—Or Leave MACs Out Completely
Copying MAC addresses between Linux (`ip link`), Windows (`ipconfig /all`), and Cisco (`show mac address-table`) usually means replacing colons, hyphens, and dots by hand. FrameAssembly accepts all three formats natively—and if you only care about Layer 3–7, you can skip `mac` altogether:

* **Unicast hosts without `mac`:** Automatically get clean direction-aware MACs (`00:00:00:00:00:01` and `00:00:00:00:00:02`) so switch CAM tables don't flap during `tcpreplay`.
* **Multicast hosts without `mac`:** Automatically get RFC multicast MACs (`01:00:5e:xx:xx:xx` for IPv4 `224.0.0.0/4` and `33:33:xx:xx:xx:xx` for IPv6 `ff00::/8`).

```frameassembly
host linux_srv  { ip 10.0.0.10 mac 00:1a:2b:3c:4d:5e }
host windows_pc { ip 10.0.0.20 mac 00-1A-2B-3C-4D-5F }
host cisco_sw   { ip 10.0.0.1  mac 001a.2b3c.4d01 }
host core_rtr   { ip 10.0.0.254 }
host ospf_mcast { ip 224.0.0.5 }

flow mac_and_multicast_demo(srv, pc, sw, rtr, mcast) {
    pc  -> sw arp request sendermac 00-1A-2B-3C-4D-5F senderip 10.0.0.20 targetip 10.0.0.1 wait 1ms
    pc  <- sw arp reply   sendermac 001a.2b3c.4d01    senderip 10.0.0.1  targetmac 00-1A-2B-3C-4D-5F targetip 10.0.0.20 wait 2ms
    srv -> pc icmp echo_request id 1 seq 1 payload "all-mac-formats-work" wait 2ms

    // No MAC on ospf_mcast -> automatically derives 01:00:5e:00:00:05
    rtr -> mcast ttl 1 ospf hello router_id 10.0.0.254 area_id 0 hello_interval 10 dead_interval 40
}

compile { mac_and_multicast_demo(linux_srv, windows_pc, cisco_sw, core_rtr, ospf_mcast) }
```

### Every Protocol Works With Zero Extra Keywords
All **81 supported protocols** compile with sensible RFC defaults and standard ports out of the box (`UDP 53` for `dns`, `UDP 162` for `snmp3`, `TCP 179` for `bgp`). Override only the fields you actually care about:

```frameassembly
host client { ip 10.10.0.10 }
host server { ip 10.10.0.1 }

flow defaults_vs_overrides(c, s) {
    // Valid RFC packets with zero extra sub-keywords
    c -> s icmp  wait 1ms
    c -> s dns   wait 1ms
    s -> c snmp3 wait 2ms

    // The exact same protocols with custom headers and credentials
    c -> s ttl 128 df icmp echo_request id 42 seq 1 payload "MTU_PROBE_1472" wait 2ms
    c -> s dns query txid 0x99a1 qname "db01.corp.internal" qtype "AAAA" wait 2ms
    s -> c snmp3 trap user "netops" engineid "80001f8801" auth sha256 "AuthPass123!" priv aes "PrivPass123!" oid 1.3.6.1.6.3.1.1.5.3
}

compile { defaults_vs_overrides(client, server) }
```

## 4. Stateful TCP Without Sequence Number Math

Firing a single spoofed HTTP or Modbus packet at a stateful firewall (**Palo Alto**, **FortiGate**, **CheckPoint**, `nftables`) won't test your application rules because the firewall drops mid-stream data without a valid 3-way handshake—and calculating `SEQ`/`ACK` byte offsets by hand in Wireshark gets old fast.

Keep `c` on the left and `s` on the right inside `flow(c, s)` and flip the arrow (`->` vs. `<-`). FrameAssembly tracks the TCP connection automatically:
* **Reply port swapping:** Set `srcport` and `dstport` once on `syn`; every `c <- s` line flips them automatically (`80 -> 52100`).
* **Automatic `SEQ`/`ACK` progression:** `syn` and `fin` advance sequence numbers by `+1`, and any TCP-based Layer 7 protocol (`http`, `tls`, `ssh`, `bgp`, `smb`, `modbus`, etc.) emits a `PSH ACK` segment and advances `SEQ`/`ACK` by the exact payload length:

```frameassembly
host app_client { ip 10.20.1.50 }
host web_server { ip 10.20.1.80 }

flow http_health_check(c, s) {
    c -> s tcp syn srcport 52100 dstport 80 win 65535 mss 1460 wscale 7 sack_perm wait 1ms
    c <- s tcp syn ack win 65535 mss 1460 wscale 7 sack_perm wait 1ms
    c -> s tcp ack wait 1ms

    c -> s http get uri "/api/v1/status" host_hdr "api.internal" user_agent "NOC-Probe/1.0" wait 5ms
    c <- s http status 200 reason "OK" content_type "application/json" body "{\"healthy\":true}" wait 2ms

    c -> s tcp fin ack wait 1ms
    c <- s tcp fin ack wait 1ms
    c -> s tcp ack
}

compile { http_health_check(app_client, web_server) }
```

### Need Broken TCP Traffic? Override Anything
When you *want* to test how an IDS or firewall reacts to `TCP ZeroWindow` stalls, out-of-window sequence numbers, or `RST` teardowns, override `win 0`, `seq`, `acknum`, or `rst` on any line:

```frameassembly
host scanner { ip 10.30.0.10 }
host backend { ip 10.30.0.20 }

flow firewall_state_test(c, s) {
    c -> s tcp syn srcport 54000 dstport 8080 win 65535 mss 1460 wait 1ms
    c <- s tcp syn ack win 65535 mss 1460 wait 1ms
    c -> s tcp ack wait 1ms

    c -> s http post uri "/upload" host_hdr "ingest.local" body "BATCH_01" wait 2ms
    c <- s tcp ack win 0 wait 50ms

    // Out-of-window segment to verify stateful firewall drop counters
    c -> s tcp psh ack seq 900000 acknum 1 payload "OUT_OF_WINDOW_PROBE" wait 5ms
    c <- s tcp rst ack
}

compile { firewall_state_test(scanner, backend) }
```

## 5. VLAN Trunks, QinQ, MPLS, QoS and Fragments

Desktop OS network stacks and NIC drivers love stripping 802.1Q VLAN tags and blocking unprivileged `QinQ`, `MPLS`, or fragmented packets. In FrameAssembly, you can slap Layer 2–4 tags onto **any** packet statement:

| Feature | `.fasm` Modifier | Example / Range | What Goes on the Wire |
| :--- | :--- | :--- | :--- |
| **802.1Q VLAN & CoS** | `vlan <1..4094> [pcp <0..7>] [dei <0..1>]` | `vlan 110 pcp 5` | 802.1Q tag (`0x8100`) + 802.1p priority |
| **802.1ad QinQ** | `qinq <s_vid> inner_vlan <c_vid>` | `qinq 2000 inner_vlan 110` | S-VLAN (`0x88a8`) + C-VLAN (`0x8100`) |
| **MPLS Label** | `mpls <lbl> [exp <0..7>] [bos <0\|1>] [mpls_ttl <n>]` | `mpls 16000 exp 5` | MPLS shim header (`0x8847`) |
| **Outer Ethernet** | `srcmac <mac>` / `dstmac <mac>` / `ethertype <u16>` | `ethertype 0x88b5` | Custom Ethernet MACs or EtherType |
| **Hop Limit & QoS** | `ttl <0..255>` / `dscp <0..63>` / `ecn <0..3>` | `ttl 64 dscp 46` | IPv4 TTL or IPv6 Hop Limit + DiffServ (`46` = `EF`) |
| **IPv6 Flow Label** | `flowlabel <0..1048575>` | `flowlabel 0x1a2b3` | 20-bit IPv6 ECMP Flow Label (ignored on IPv4) |
| **IPv4 Fragments** | `df` / `ipid <u16>` / `mf` / `fragoffset <0..8191>` | `ipid 0x7788 mf fragoffset 0` | PMTUD Don't Fragment (`df`) or 8-byte fragment offsets |
| **Ports & Transport**| `srcport <p>` / `dstport <p>` / `transport tcp\|udp` | `transport tcp` | Custom L4 ports or TCP/UDP switch (e.g., TCP Syslog/DNS) |

```frameassembly
host branch_edge { ip 172.16.100.10 mac 00:1c:73:aa:00:10 }
host core_pe     { ip 172.16.100.1  mac 00:1c:73:aa:00:01 }

flow trunk_and_wan_tags(edge, pe) {
    // Voice VLAN 110 with 802.1p CoS 5 + DiffServ EF (DSCP 46)
    edge -> pe vlan 110 pcp 5 dei 0 dscp 46 rtp pt 0 seq 1 timestamp 160 ssrc 0x10203040 payload "VOICE_20MS" wait 5ms

    // Carrier 802.1ad QinQ double tag + MPLS L3VPN shim label
    edge -> pe qinq 2000 inner_vlan 110 dscp 26 udp srcport 50000 dstport 9000 payload "METRO_ETH" wait 5ms
    edge -> pe mpls 16000 exp 5 bos 1 mpls_ttl 63 ttl 63 dscp 46 icmp echo_request id 50 seq 1 payload "L3VPN_PING" wait 5ms

    // Path MTU Don't Fragment (DF) probe + 2-part IPv4 fragmented ping
    edge -> pe df ipid 0x4400 ttl 64 icmp echo_request id 51 seq 1 payload "PMTUD_DF_PROBE" wait 5ms
    edge -> pe ipid 0x7788 mf fragoffset 0 icmp echo_request id 52 seq 1 payload "FIRST_8B_SECOND8" wait 1ms
    edge -> pe ipid 0x7788 fragoffset 2 icmp echo_request id 52 seq 1 payload "FINAL_FRAGMENT_B"
}

compile { trunk_and_wan_tags(branch_edge, core_pe) }
```

## 6. IPv4/IPv6 Reuse and `loop` Traffic Bursts

Because a `flow` uses role names instead of hardcoded IPs, you can write a traffic scenario once and run it across both IPv4 and IPv6 hosts—or repeat it inside `loop <count> { ... }` to generate flood, load, or heartbeat captures without copy-pasting lines:

```frameassembly
host sensor_v4    { ip 10.50.0.10 }
host collector_v4 { ip 10.50.0.100 }
host sensor_v6    { ip 2001:db8:50::10 }
host collector_v6 { ip 2001:db8:50::100 }

flow heartbeat_and_log(node, col) {
    node -> col vlan 50 dscp 16 ttl 64 flowlabel 0x1a2b3 icmp echo_request id 90 seq 1 payload "HB" wait 2ms
    node <- col vlan 50 dscp 16 ttl 64 flowlabel 0x1a2b3 icmp echo_reply   id 90 seq 1 payload "HB" wait 5ms
    node -> col vlan 50 dscp 16 ttl 64 flowlabel 0x1a2b3 syslog facility 16 severity 6 hostname "edge-01" app "healthd" msg "Link OK" wait 10ms
}

compile {
    loop 5 {
        heartbeat_and_log(sensor_v4, collector_v4)
        heartbeat_and_log(sensor_v6, collector_v6)
    }
}
```

## 7. Wireshark and `tcpdump` to `.fasm` Cheat Sheet

If muscle memory makes you type `sport` instead of `srcport` (or `ack 100` instead of `acknum 100`), FrameAssembly refuses to write a broken `.pcap` and points straight to the fix:

```text
frameassembly::parse_error

  × Failed to parse input: Syntax error: unexpected token 'sport', expected a valid statement
  │ or protocol modifier (such as SRCPORT, DSTPORT, SEQ, ACKNUM, WIN, or TCP flags). Did you mean 'SRCPORT'?
   ╭─[test.fasm:5:16]
 4 │ flow check(c, s) {
 5 │     c -> s tcp sport 50000 dstport 80 syn
   ·                ──┬──
   ·                  ╰── Here
   ╰────
  help: Replace 'sport' with 'SRCPORT <port>' (for example: SRCPORT 51234).
```

| What You Want | Wireshark Filter | `tcpdump` Filter | `.fasm` Code |
| :--- | :--- | :--- | :--- |
| **Host IP & MAC** | `ip.addr == 10.0.0.1` | `host 10.0.0.1` | `host rtr { ip 10.0.0.1 mac 00:1a:2b:3c:4d:5e }` |
| **802.1Q VLAN & CoS** | `vlan.id == 100 && vlan.priority == 5` | `vlan 100` | `vlan 100 pcp 5 dei 0` |
| **802.1ad QinQ** | `vlan.id == 2000 && vlan.id == 100` | `vlan 2000 and vlan 100` | `qinq 2000 inner_vlan 100` |
| **MPLS Label** | `mpls.label == 16000` | `mpls 16000` | `mpls 16000 exp 5 bos 1 mpls_ttl 64` |
| **QoS `DSCP` / `ECN`** | `ip.dsfield.dscp == 46` | `ip[1] & 0xfc == 0xb8` | `dscp 46 ecn 2` |
| **TTL / Hop Limit** | `ip.ttl == 64` / `ipv6.hlim == 64` | `ip[8] == 64` | `ttl 64` |
| **Ports & TCP Flags** | `tcp.dstport == 443 && tcp.flags.syn == 1` | `dst port 443` | `tcp syn srcport 52000 dstport 443` |
| **TCP Seq / Ack / Win**| `tcp.seq == 1000 && tcp.ack == 2000` | `tcp[4:4] == 1000` | `seq 1000 acknum 2000 win 65535` |
| **HTTP Host Header** | `http.host == "api.local"` | `port 80` | `http get uri "/" host_hdr "api.local"` |
| **Packet Delay** | `frame.time_delta` | `-tt` | `wait 500us` / `wait 5ms` / `wait 1s` |

> **Generating `.fasm` Code with AI:** Point ChatGPT, Claude, Cursor, or Copilot at [`llms.txt`](https://raw.githubusercontent.com/SteveWinschel/FrameAssembly/main/llms.txt) when you want to scaffold a big multi-host capture from a quick prompt.

## Where to Go Next

* [**Real-World Use Cases (`use_cases.md`)**](use_cases.md) — Copy-paste recipes for SNMP alerting, firewall ACL audits, QoS trunks, SIEM/IDS testing, and OT conduits.
* [**Layer 2 — Switching & Data Link (`l2_protocols.md`)**](l2_protocols.md) — `arp`, `vlan`, `qinq`, `lldp`, `stp`, `lacp`, `eapol`, and `mpls`.
* [**Layer 3 — Network, Routing & Tunnels (`l3_protocols.md`)**](l3_protocols.md) — `icmp`, `ndp`, `igmp`, `mld`, `gre`, `vxlan`, `geneve`, `ipsec`, `esp`, `ah`, `ikev2`, `wireguard`, `ospf`, `bgp`, `rip`, `vrrp`, `hsrp`, `pim`, `bfd`, and `openflow`.
* [**Layer 4 — Transports (`l4_transports.md`)**](l4_transports.md) — Stateful `tcp`, `udp`, and `sctp`.
* [**Layer 7 — SNMPv1 / v2c / v3 (`l7_snmp.md`)**](l7_snmp.md) — `snmp1`, `snmp2`, encrypted `snmp3` USM, and all 9 `varbind` types.
* [**Layer 7 — Infrastructure & Telemetry (`l7_infra_and_telemetry.md`)**](l7_infra_and_telemetry.md) — `dns`, `mdns`, `dhcp`, `ntp`, `ptp`, `radius`, `tacacs`, `syslog`, `netflow`, `ipfix`, and `sflow`.
* [**Layer 7 — Web, Cloud, Security & VoIP (`l7_web_and_cloud.md`)**](l7_web_and_cloud.md) — `http`, `http2`, `grpc`, `websocket`, `tls`, `quic`, `tftp`, `ftp`, `ssh`, `telnet`, `whois`, `sip`, `rtp`, `rtsp`, `stun`, and `ssdp`.
* [**Layer 7 — Mail, Auth, Storage & Databases (`l7_mail_auth_storage_db.md`)**](l7_mail_auth_storage_db.md) — `smtp`, `imap`, `pop3`, `kerberos`, `ldap`, `smb`, `nfs`, `redis`, `memcached`, `mysql`, `postgres`, `mqtt`, `coap`, and `amqp`.
* [**Layer 7 — Industrial OT & ICS (`l7_industrial_ot.md`)**](l7_industrial_ot.md) — `modbus`, `bacnet`, `dnp3`, `s7comm`, `ethernetip`, and `opcua`.
* [**Topologies & Dual-Stack (`topologies_and_dual_stack.md`)**](topologies_and_dual_stack.md) — Multi-device EVPN-VXLAN, 802.1X NAC, and WAN failover captures.
* [**`.fasm` Format Spec (`fasm-specification.md`)**](fasm-specification.md) & [**For Nerds (`for_nerds.md`)**](for_nerds.md) — `text/vnd.frameassembly` media type spec, Rust library API, and compiler internals.