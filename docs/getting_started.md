# Getting Started with FrameAssembly

Crafting custom network traffic is usually way harder than whatever you are actually trying to test. If you want to verify a stateful firewall ACL, check whether Zabbix alerts on an encrypted SNMPv3 trap, or test a new Suricata rule, your options are grim: wire up spare lab hardware and yank cables by hand, wrestle with Python virtual environments and manual TCP sequence numbers in `Scapy` as `root`, or count hexadecimal byte offsets in `text2pcap` until you lose the will to live.

**FrameAssembly** (`frameassembly`) fixes that without needing `sudo` privileges, `libpcap`, or raw sockets. You write the network conversation as readable `.fasm` code ("Packets as Code") using everyday networking terms, compile it into a deterministic `.pcap` / `.pcapng` capture in milliseconds, and feed it straight into **Wireshark**, **`tshark`**, **Suricata**, **Zeek**, or **`tcpreplay`**:

```text
┌────────────────────────────────────────────────────────────────────────┐
│                      The 3-Step Mental Model                           │
├───────────────────┬───────────────────────────────┬────────────────────┤
│ 1. host           │ 2. flow                       │ 3. compile         │
│ Declare endpoints │ Script the packet sequence    │ Emit the .pcap     │
│ IP & optional MAC │ 1 statement = 1 wire frame    │ Wire hosts to flow │
│ (v4, v6, any MAC) │ -> forward, <- reply (swaps)  │ Single or loop N   │
└───────────────────┴───────────────────────────────┴────────────────────┘
```

---

## Step 1 — Installing FrameAssembly

Pick the one-liner for your operating system:

| Platform / OS | Method | Installation Command |
| :--- | :--- | :--- |
| **Linux (Universal)** | One-line installer | `curl -fsSL https://raw.githubusercontent.com/SteveWinschel/FrameAssembly/main/install.sh \| sh` |
| **Debian / Ubuntu** | APT (`.deb`) | `curl -fsSLo /tmp/frameassembly.deb https://github.com/SteveWinschel/FrameAssembly/releases/latest/download/frameassembly_amd64.deb && sudo apt install -y /tmp/frameassembly.deb && rm -f /tmp/frameassembly.deb` |
| **macOS & Linux** | Homebrew | `brew install SteveWinschel/tap-FrameAssembly/frameassembly` |
| **Arch Linux** | AUR | `yay -S frameassembly-bin` |
| **Windows 10 / 11** | WinGet | `winget install SteveWinschel.FrameAssembly` |
| **Windows** | Scoop | `scoop bucket add frameassembly https://github.com/SteveWinschel/homebrew-tap-FrameAssembly && scoop install frameassembly` |
| **Any (Rust 1.85+)** | Cargo | `cargo install frameassembly` |
| **Browser / Node.js** | NPM (WASM) | `npm install frameassembly-wasm` |
| **VS Code / Cursor** | Extension | `code --install-extension SteveWinschel.frameassembly-vscode` |
| **Prebuilt Binaries** | GitHub Releases (`v1.4.3`) | [Download from GitHub Releases (`v1.4.3` / `latest`)](https://github.com/SteveWinschel/FrameAssembly/releases/latest) |

Verify that the compiler is on your `PATH` (if you used the universal Linux installer, run `. "$HOME/.cargo/env"` or open a new shell first):

```bash
frameassembly --version   # frameassembly 1.4.3
frameassembly --help
```

---

## Step 2 — Your First `.fasm` Capture in 60 Seconds

You do not need any programming background to write `.fasm` code. Every `.fasm` file has just three sections from top to bottom:
1. **`host` blocks** — Declare the devices on your network diagram (`ip` and optional `mac`).
2. **`flow` blocks** — Script the packet-by-packet conversation between role labels like `(client, gw)`, using `->` for forward packets and `<-` for replies.
3. **`compile` block** — Plug your declared `host` devices into those flow roles in matching left-to-right order to build the `.pcap`.

Save the following code as `ping_test.fasm`:

```frameassembly
// 1. Declare the network devices
host workstation {
    ip 192.168.10.50
    mac 00:1a:2b:3c:4d:50
}

host default_gw {
    ip 192.168.10.1
    mac 00:1a:2b:3c:4d:01
}

// 2. Script the packet sequence (1 directional statement = 1 Ethernet frame)
flow verify_gateway_ping(client, gw) {
    client -> gw icmp echo_request id 100 seq 1 payload "ping-check-1" wait 2ms
    client <- gw icmp echo_reply   id 100 seq 1 payload "ping-check-1" wait 10ms
    client -> gw icmp echo_request id 100 seq 2 payload "ping-check-2" wait 2ms
    client <- gw icmp echo_reply   id 100 seq 2 payload "ping-check-2"
}

// 3. Compile the capture (maps workstation -> client, default_gw -> gw)
compile {
    verify_gateway_ping(workstation, default_gw)
}
```

Preview the packet ladder in your terminal, compile it to a `.pcap` file, and inspect or replay it:

```bash
# Preview the packet ladder in your terminal without creating a file
frameassembly show ping_test.fasm

# Compile to a deterministic, nanosecond-precision .pcap capture
frameassembly ping_test.fasm -o ping_test.pcap

# Dissect in Wireshark / tshark, or replay onto a live test interface
tshark -r ping_test.pcap
wireshark ping_test.pcap &
sudo tcpreplay -i eth0 ping_test.pcap
```

---

## Step 3 — Three Ground Rules & Zero-Hassle MAC Addresses

* **Keywords are case-insensitive:** Lowercase (`host`, `tcp syn`, `dstport 443`) is standard, though `HOST` or `Tcp` compiles to the exact same bytes. Quoted text (`"..."`) always preserves exact casing on the wire.
* **Comments start with `//`:** Use `//` anywhere on a line. Never use `#` or `;` for comments.
* **One statement = one Ethernet frame:** Every `a -> b ...` or `a <- b ...` statement inside `flow { ... }` emits **one Ethernet frame**—even if you wrap a long Layer 7 statement across multiple indented lines to keep it readable.

### Copy-Paste Any MAC Format (Or Skip MACs Completely)

Whether you copy a MAC address from `ip link` on Linux, `ipconfig /all` on Windows, or `show mac address-table` on a Cisco switch, **do not waste time reformatting colons, hyphens, and dots**—FrameAssembly accepts all three natively:

```frameassembly
host linux_srv  { ip 10.0.0.10 mac 00:1a:2b:3c:4d:5e }
host windows_pc { ip 10.0.0.20 mac 00-1A-2B-3C-4D-5F }
host cisco_sw   { ip 10.0.0.1  mac 001a.2b3c.4d01 }

flow verify_mac_notations(srv, pc, sw) {
    srv -> pc icmp echo_request id 1 seq 1 payload "colon-to-hyphen" wait 1ms
    pc  -> sw arp request sendermac 00-1A-2B-3C-4D-5F senderip 10.0.0.20 targetip 10.0.0.1 wait 1ms
    pc  <- sw arp reply   sendermac 001a.2b3c.4d01    senderip 10.0.0.1  targetmac 00-1A-2B-3C-4D-5F targetip 10.0.0.20
}

compile {
    verify_mac_notations(linux_srv, windows_pc, cisco_sw)
}
```

And if your test only cares about Layer 3–7 behavior, **leave `mac` out of `host` completely**:
1. **Unicast hosts without `mac`:** FrameAssembly assigns clean, direction-aware unicast MACs (`00:00:00:00:00:01` and `00:00:00:00:00:02`) so switch CAM tables never flap during `tcpreplay`.
2. **Multicast hosts without `mac`:** IPv4 multicast (`224.0.0.0/4`) automatically derives RFC 1112 MACs (`01:00:5e:xx:xx:xx`), and IPv6 multicast (`ff00::/8`) automatically derives RFC 2464 MACs (`33:33:xx:xx:xx:xx`).

```frameassembly
host core_rtr     { ip 10.0.0.1 }
host ospf_all_spf { ip 224.0.0.5 }
host core_rtr_v6  { ip fe80::1 }
host ospf6_all    { ip ff02::5 }

flow send_ospf_hello(rtr, mcast) {
    // Auto-derives 01:00:5e:00:00:05 on IPv4 and 33:33:00:00:00:05 on IPv6
    rtr -> mcast ttl 1 ospf hello router_id 10.0.0.1 area_id 0 hello_interval 10 dead_interval 40
}

compile {
    send_ospf_hello(core_rtr, ospf_all_spf)
    send_ospf_hello(core_rtr_v6, ospf6_all)
}
```

---

## Step 4 — Sensible RFC Defaults vs. Custom Overrides

Every one of FrameAssembly's **81 protocols** compiles with **zero required sub-keywords**. Write just the protocol keyword when you want a valid RFC packet on its standard port (`UDP 53` for `dns`, `TCP 179` for `bgp`, `UDP 162` for `snmp3`), and add modifiers in any order only for the fields you want to customize:

```frameassembly
host peer_a { ip 10.10.0.1 }
host peer_b { ip 10.10.0.2 }

// Minimal RFC defaults—zero boilerplate
flow quick_defaults(c, s) {
    c -> s icmp wait 1ms
    c -> s dns  wait 1ms
    c -> s bgp
}

// Explicit header overrides on the same three protocols
flow custom_headers(c, s) {
    c -> s ttl 128 df icmp echo_request id 42 seq 10 payload "MTU_PROBE_1472" wait 2ms
    c -> s dns query txid 0x99a1 qname "db01.corp.internal" qtype "AAAA" wait 2ms
    c -> s ttl 255 dscp 48 bgp update asn 65001 prefix "172.16.0.0/16" nexthop 10.10.0.1
}

compile {
    quick_defaults(peer_a, peer_b)
    custom_headers(peer_a, peer_b)
}
```

---

## Step 5 — Stateful TCP Without Manual Sequence Math

Hand-crafting TCP streams in older packet tools is miserable: if one sequence byte is off, Wireshark flags `[TCP Previous segment not captured]` and stateful firewalls drop the packet cold.

Inside `flow(c, s)`, keep `c` on the left and `s` on the right and flip the arrow (`->` vs. `<-`). That layout matches Wireshark's **Flow Graph** line for line, and FrameAssembly handles the bookkeeping automatically:

```text
  Wireshark Flow Graph               FrameAssembly .fasm Flow Statement
--------------------------------------------------------------------------------------
  10.0.0.10             10.0.0.80
      |                     |
      |   TCP 52100 -> 80   |
      |-------------------->|        c -> s tcp syn srcport 52100 dstport 80 win 65535
      |        [SYN]        |
      |                     |
      |   TCP 80 -> 52100   |
      |<--------------------|        c <- s tcp syn ack win 65535 wait 1ms
      |      [SYN, ACK]     |
      |                     |
      |   TCP 52100 -> 80   |
      |-------------------->|        c -> s tcp ack wait 1ms
      |        [ACK]        |
      |                     |
      |  HTTP GET /status   |
      |-------------------->|        c -> s http get uri "/status" host_hdr "api.local"
      |      [PSH, ACK]     |
      |                     |
      |   HTTP 200 OK       |
      |<--------------------|        c <- s http status 200 reason "OK" body "{\"up\":true}"
      |      [PSH, ACK]     |
```

* **Automatic reply port swapping:** Set `srcport 52100 dstport 80` once on the opening `syn`. Every `c <- s` reply automatically flips the ports to `80 -> 52100`.
* **Shared 4-tuple `seq` & `acknum` state:** `syn` and `fin` advance the sequence counter by `+1`, and any TCP-based Layer 7 statement (`http`, `tls`, `ssh`, `bgp`, `smb`, `modbus`, etc.) emits a `PSH ACK` segment that advances `seq` and `acknum` by the exact byte length of the generated payload:

```frameassembly
host app_client { ip 10.20.1.50 }
host web_server { ip 10.20.1.80 }

flow tracked_http_conversation(c, s) {
    c -> s tcp syn srcport 52100 dstport 80 win 65535 mss 1460 wscale 7 sack_perm wait 1ms
    c <- s tcp syn ack win 65535 mss 1460 wscale 7 sack_perm wait 1ms
    c -> s tcp ack wait 2ms

    c -> s http get uri "/api/v1/status" host_hdr "api.internal" user_agent "NOC-Probe/1.0" wait 5ms
    c <- s http status 200 reason "OK" content_type "application/json" body "{\"healthy\":true}" wait 2ms

    c -> s tcp fin ack wait 1ms
    c <- s tcp fin ack wait 1ms
    c -> s tcp ack
}

compile {
    tracked_http_conversation(app_client, web_server)
}
```

Need to test how a firewall or IDS handles **broken** TCP traffic? Override `win 0`, `seq`, `acknum`, or `rst` on any line:

```frameassembly
host client_node { ip 10.30.0.10 }
host server_node { ip 10.30.0.20 }

flow tcp_anomaly_and_zero_window(c, s) {
    c -> s tcp syn srcport 54000 dstport 8080 win 65535 mss 1460 wait 1ms
    c <- s tcp syn ack win 65535 mss 1460 wait 1ms
    c -> s tcp ack wait 1ms

    c -> s http post uri "/upload" host_hdr "ingest.local" body "CHUNK_DATA_01" wait 2ms
    // Server receive buffer fills up (TCP ZeroWindow)
    c <- s tcp ack win 0 wait 50ms
    // Inject an out-of-window segment to verify stateful firewall drop counters
    c -> s tcp psh ack seq 900000 acknum 1 payload "OUT_OF_WINDOW_PROBE" wait 5ms
    // Server reopens receive window and completes response
    c <- s tcp ack win 32768 wait 2ms
    c <- s http status 200 reason "OK" body "UPLOAD_COMPLETE"
}

compile {
    tcp_anomaly_and_zero_window(client_node, server_node)
}
```

---

## Step 6 — VLANs, Carrier QinQ, MPLS, QoS & Fragmentation

Attach Layer 2 tags, Layer 3 DiffServ/fragmentation bits, transport overrides, and nanosecond-to-minute `wait` timers to **any** statement:

| Layer | Modifier Syntax | Range / Format | Wire Effect |
| :--- | :--- | :--- | :--- |
| **L2 VLAN** | `vlan <id> [pcp <0..7>] [dei <0..1>]` | VID `1..4094` | Inserts IEEE 802.1Q tag (`0x8100`) + CoS priority |
| **L2 QinQ** | `qinq <s_vid> inner_vlan <c_vid>` | VID `1..4094` | Inserts 802.1ad S-VLAN (`0x88a8`) + 802.1Q C-VLAN (`0x8100`) |
| **L2 MPLS** | `mpls <lbl> [exp <0..7>] [bos <0\|1>] [mpls_ttl <n>]` | Label `0..1048575` | Inserts RFC 3032 MPLS shim header (`0x8847`) |
| **L2 Ethernet** | `srcmac <mac>` / `dstmac <mac>` / `ethertype <u16>` | Any MAC / `0x88cc` | Overrides outer Ethernet MACs or EtherType |
| **L3 Hop & QoS** | `ttl <0..255>` / `dscp <0..63>` / `ecn <0..3>` | Unified IPv4 & IPv6 | Sets TTL/Hop Limit and TOS/Traffic Class (`dscp 46` = `EF`) |
| **L3 IPv6** | `flowlabel <0..1048575>` | `0..0xfffff` | Sets 20-bit IPv6 Flow Label (ignored on IPv4) |
| **L3 IPv4 Frag** | `ipid <u16>` / `df` / `mf` / `fragoffset <0..8191>` | 8-byte offset units | PMTUD Don't Fragment (`df`) or multi-fragment IPv4 reassembly |
| **L4 & Timing** | `srcport <p>` / `dstport <p>` / `transport tcp\|udp` / `wait <t>` | `ns`, `us`, `ms`, `s`, `m` | Overrides L4 ports/transport and advances PCAPNG timestamp |

```frameassembly
host branch_edge { ip 172.16.100.10 mac 00:1c:73:aa:00:10 }
host core_pe     { ip 172.16.100.1  mac 00:1c:73:aa:00:01 }

flow wan_encapsulation_showcase(edge, core) {
    edge -> core vlan 110 pcp 5 dei 0 ttl 64 dscp 46 ecn 2
        rtp pt 0 seq 1 timestamp 160 ssrc 0x10203040 payload "VOICE_FRAME" wait 5ms
    edge -> core qinq 2000 inner_vlan 110 dscp 26
        udp srcport 50000 dstport 9000 payload "METRO_ETHERNET_DATA" wait 5ms
    edge -> core mpls 16000 exp 5 bos 1 mpls_ttl 63 ttl 63 dscp 46
        icmp echo_request id 50 seq 1 payload "MPLS_L3VPN_PING" wait 5ms
    edge -> core df ipid 0x4400 ttl 64
        icmp echo_request id 51 seq 1 payload "PMTUD_DO_NOT_FRAGMENT" wait 5ms
    edge -> core ipid 0x7788 mf fragoffset 0
        icmp echo_request id 52 seq 1 payload "FIRST_8B_SECOND8" wait 1ms
    edge -> core ipid 0x7788 fragoffset 2
        icmp echo_request id 52 seq 1 payload "FINAL_FRAGMENT_B"
}

compile {
    wan_encapsulation_showcase(branch_edge, core_pe)
}
```

---

## Step 7 — Reusable Dual-Stack IPv4/IPv6 Flows & `loop` Bursts

Because a `flow(node, srv)` uses role labels instead of hardcoded IPs, you can write a packet sequence once and run it inside `compile` with IPv4 hosts, IPv6 hosts, or inside a `loop <count> { ... }` block to generate a multi-packet traffic burst. FrameAssembly automatically switches between IPv4 (`0x0800`) and IPv6 (`0x86dd`), recalculates pseudo-header checksums, and advances sequence numbers and timestamps on every pass:

```frameassembly
host sensor_v4    { ip 10.50.0.10 }
host collector_v4 { ip 10.50.0.100 }
host sensor_v6    { ip 2001:db8:50::10 }
host collector_v6 { ip 2001:db8:50::100 }

flow heartbeat_burst(node, srv) {
    node -> srv vlan 50 dscp 16 ttl 64 flowlabel 0x1a2b3
        icmp echo_request id 90 seq 1 payload "HEARTBEAT" wait 2ms
    node <- srv vlan 50 dscp 16 ttl 64 flowlabel 0x1a2b3
        icmp echo_reply id 90 seq 1 payload "HEARTBEAT" wait 5ms
    node -> srv vlan 50 dscp 16 ttl 64 flowlabel 0x1a2b3
        syslog facility 16 severity 6 hostname "edge-sensor" app "healthd" msg "Heartbeat OK" wait 10ms
}

compile {
    loop 4 {
        heartbeat_burst(sensor_v4, collector_v4)
        heartbeat_burst(sensor_v6, collector_v6)
    }
}
```

---

## Step 8 — Helpful Error Messages & Typo Hints

When a `.fasm` file has a typo—or if someone accidentally passes an x86 Flat Assembler or FPGA FASM file—FrameAssembly refuses to create a broken `.pcap` and prints a plain-English fix:

```text
frameassembly::parse_error

  × Failed to parse input: Syntax error: unexpected token 'sport', expected a valid statement
  │ or protocol modifier. Did you mean 'SRCPORT'?
   ╭─[my_test.fasm:6:16]
 5 │ flow test(c, s) {
 6 │     c -> s tcp sport 50000 dstport 80 syn
   ·                ──┬──
   ·                  ╰── Here
   ╰────
  help: Replace 'sport' with 'SRCPORT <port>' (for example: srcport 51234).
```

---

## Step 9 — Wireshark / `tcpdump` to `.fasm` Cheat Sheet

| Networking Concept | Wireshark Display Filter | `tcpdump` Expression | `.fasm` Syntax |
| :--- | :--- | :--- | :--- |
| **Host IP & MAC** | `ip.addr == 10.0.0.1 && eth.addr == ...` | `host 10.0.0.1 and ether host ...` | `host rtr { ip 10.0.0.1 mac 00:1a:2b:3c:4d:5e }` |
| **802.1Q VLAN & CoS** | `vlan.id == 100 && vlan.priority == 5` | `vlan 100` | `vlan 100 pcp 5 dei 0` |
| **802.1ad QinQ** | `vlan.id == 2000 && vlan.id == 100` | `vlan 2000 and vlan 100` | `qinq 2000 inner_vlan 100` |
| **MPLS Label & EXP** | `mpls.label == 16000 && mpls.exp == 5` | `mpls 16000` | `mpls 16000 exp 5 bos 1 mpls_ttl 64` |
| **DiffServ `DSCP` / `ECN`** | `ip.dsfield.dscp == 46` | `ip[1] & 0xfc == 0xb8` | `dscp 46 ecn 2` |
| **TTL / IPv6 Hop Limit** | `ip.ttl == 64` / `ipv6.hlim == 64` | `ip[8] == 64` / `ip6[7] == 64` | `ttl 64` |
| **IPv4 DF / Fragments** | `ip.flags.df == 1` / `ip.frag_offset` | `ip[6] & 0x40 != 0` | `df` or `ipid 0x1234 mf fragoffset 0` |
| **L4 Ports & TCP Flags** | `tcp.dstport == 443 && tcp.flags.syn == 1` | `dst port 443 and tcp[tcpflags] & tcp-syn != 0` | `tcp syn srcport 52000 dstport 443` |
| **TCP Seq / Ack / Win** | `tcp.seq == 1000 && tcp.ack == 2000` | `tcp[4:4] == 1000` | `seq 1000 acknum 2000 win 65535` |
| **SNMP VarBinds** | `snmp.name == 1.3.6.1.2.1.1.5.0` | `udp port 161 or udp port 162` | `varbind 1.3.6.1.2.1.1.5.0 string "core-sw"` |

> **Tip — Using AI Coding Assistants with `.fasm`:**
> FrameAssembly ships a compact syntax sheet at [`llms.txt`](https://github.com/SteveWinschel/FrameAssembly/blob/main/llms.txt) (`https://raw.githubusercontent.com/SteveWinschel/FrameAssembly/main/llms.txt`). Point ChatGPT, Claude, Copilot, or Cursor at that URL when you want to scaffold a large multi-host topology from a plain-English description.

---

## Where to Go Next

* **[Practical Use-Case Cookbook (`use_cases.md`)](use_cases.md)** — Ready-to-run `.fasm` recipes for SNMPv3 traps, DMZ firewall audits, VLAN/QinQ/MPLS QoS, SIEM & IDS rules, OT conduits, and HA failovers.
* **[Layer 2 Switching & Data-Link (`l2_protocols.md`)](l2_protocols.md)** — `arp`, `vlan`, `qinq`, `lldp`, `stp`, `lacp`, `eapol`, and `mpls`.
* **[Layer 3 Control, Tunneling, VPN & Routing (`l3_protocols.md`)](l3_protocols.md)** — `icmp`, `ndp`, `igmp`, `mld`, `gre`, `vxlan`, `geneve`, `ipsec`, `esp`, `ah`, `ikev2`, `wireguard`, `ospf`, `bgp`, `rip`, `vrrp`, `hsrp`, `pim`, `bfd`, and `openflow`.
* **[Layer 4 Transports (`l4_transports.md`)](l4_transports.md)** — `tcp`, `udp`, and `sctp`.
* **[Layer 7 SNMPv1, SNMPv2c & SNMPv3 USM (`l7_snmp.md`)](l7_snmp.md)** — `snmp1`, `snmp2`, and encrypted `snmp3` USM traps, polls, and all 9 `varbind` types.
* **[Layer 7 Infrastructure, Time, AAA & Telemetry (`l7_infra_and_telemetry.md`)](l7_infra_and_telemetry.md)** — `dns`, `mdns`, `dhcp`, `ntp`, `ptp`, `radius`, `tacacs`, `syslog`, `netflow`, `ipfix`, and `sflow`.
* **[Layer 7 Web, Cloud, Security & VoIP (`l7_web_and_cloud.md`)](l7_web_and_cloud.md)** — `http`, `http2`, `grpc`, `websocket`, `tls`, `quic`, `tftp`, `ftp`, `ssh`, `telnet`, `whois`, `sip`, `rtp`, `rtsp`, `stun`, and `ssdp`.
* **[Layer 7 Mail, Directory, Storage, Databases & Brokers (`l7_mail_auth_storage_db.md`)](l7_mail_auth_storage_db.md)** — `smtp`, `imap`, `pop3`, `kerberos`, `ldap`, `smb`, `nfs`, `redis`, `memcached`, `mysql`, `postgres`, `mqtt`, `coap`, and `amqp`.
* **[Layer 7 Industrial Control Systems & SCADA/OT (`l7_industrial_ot.md`)](l7_industrial_ot.md)** — `modbus`, `bacnet`, `dnp3`, `s7comm`, `ethernetip`, and `opcua`.
* **[Multi-Host Topologies & Dual-Stack Scenarios (`topologies_and_dual_stack.md`)](topologies_and_dual_stack.md)** — Enterprise EVPN-VXLAN, 802.1X NAC, and dual-stack service-mesh captures.
* **[`.fasm` File Format Specification (`fasm-specification.md`)](fasm-specification.md)** & **[For Nerds (`for_nerds.md`)](for_nerds.md)** — Formal `text/vnd.frameassembly` specification, Rust library API, and compiler internals.