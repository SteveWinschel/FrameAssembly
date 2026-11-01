# Getting Started with FrameAssembly

**FrameAssembly** (`frameassembly`) is an offline, rootless "Packets as Code" ("PCAP as Code") command-line compiler that turns a plain-text packet recipe (`.fasm`, media type `text/vnd.frameassembly`) into a deterministic `.pcap` / `.pcapng` packet capture file ready for **Wireshark**, **`tshark`**, **Suricata**, **Zeek**, or **`tcpreplay`**.

You do not need any programming experience to use FrameAssembly. There are no Python scripts to debug, no libraries or virtual environments to manage, no byte-offset math to calculate by hand, and no root (`sudo`) privileges, `libpcap` libraries, or live raw sockets required to build a capture. You simply list the network devices in your scenario and write one line per packet—FrameAssembly builds the Ethernet frames, IPv4/IPv6 headers, UDP/TCP/SCTP transport headers, Layer 7 protocol payloads, lengths, checksums, and TCP sequence numbers automatically.

---

## Fast Packet Crafting for Network Engineers

Instead of writing Python `Scapy` scripts with nested packet layers (`Ether()/IP()/TCP()`), managing virtual environments, or calculating hexadecimal byte offsets by hand in `text2pcap`, FrameAssembly lets you declare your endpoints with standard IP and MAC addresses (`HOST`), write your packet sequence in everyday networking terms (`FLOW`), and compile directly to a `.pcap` capture file (`COMPILE`):

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

---

## Step 1 — Installing FrameAssembly Across Platforms

Choose the installation method that matches your operating system:

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

### One-Line Linux Installer Details

If you are on a fresh Linux workstation, lab VM, jump host, or container, run the official installer script:

```bash
curl -fsSL https://raw.githubusercontent.com/SteveWinschel/FrameAssembly/main/install.sh | sh
```

#### What this command does behind the scenes:
1. **Checks system prerequisites:** Verifies that `curl`, `ca-certificates`, and a standard C linker (`cc`, `gcc`, or `clang`) are present.
2. **Sets up the Rust build tool (`rustup`):** If Rust (`>= 1.85`) is not already installed, it installs user-space Rust into `~/.cargo`.
3. **Installs the `frameassembly` command:** Places the executable at `~/.cargo/bin/frameassembly`.
4. **Configures editor color highlighting:** If **VS Code** (`code`) or **Antigravity** (`agy`) is detected, it automatically installs the `.fasm` syntax highlighting extension.

Reload your shell environment after installation:

```bash
. "$HOME/.cargo/env"
```

Verify your installation:

```bash
frameassembly --version
frameassembly --help
```

---

## Step 2 — Anatomy of a `.fasm` File

Every `.fasm` file is a plain-text file built from three sections in order:
1. **`host` blocks** — Declare each device in your scenario with its IPv4 or IPv6 address (and an optional MAC address).
2. **`flow` blocks** — List the packets exchanged between devices, top to bottom.
3. **`compile` block** — Choose which flows to run and which hosts to plug into them.

### Three Core Rules to Remember
* **Case-insensitive everywhere:** You can write `host` or `HOST`, `tcp` or `TCP`, `srcport` or `SRCPORT`. Use lowercase, uppercase, or a mix—whichever is easiest for you to read.
* **Comments start with `//`:** Use `//` anywhere on a line to write notes for yourself or your team. **Never use `#` for comments.**
* **One line = one packet:** Every statement inside a `flow { ... }` block generates **exactly one Ethernet frame** in your output `.pcap` file. A 4-line flow produces a 4-packet capture.

### Your First Complete `.fasm` File

Save the following text as `ping_test.fasm`:

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

// 2. List the packet sequence (1 line = 1 Ethernet frame)
flow verify_gateway_ping(client, gw) {
    client -> gw icmp echo_request id 100 seq 1 payload "ping-check-1" wait 2ms
    client <- gw icmp echo_reply id 100 seq 1 payload "ping-check-1" wait 10ms
    client -> gw icmp echo_request id 100 seq 2 payload "ping-check-2" wait 2ms
    client <- gw icmp echo_reply id 100 seq 2 payload "ping-check-2"
}

// 3. Build the capture using our declared hosts
compile {
    verify_gateway_ping(workstation, default_gw)
}
```

### Supported MAC Address Formats (Linux Colon, Windows Hyphen & Cisco Dotted-Quad)

When you copy and paste a MAC address from a Linux terminal, a Windows `ipconfig /all` output, or a Cisco switch `show mac address-table` / `show arp` output, **you do not need to reformat it**. FrameAssembly natively accepts all three standard MAC address notations everywhere a MAC address is allowed (`mac`, `srcmac`, `dstmac`, `sendermac`, `targetmac`, `chaddr`, `slla`, `tlla`, `actor_sys`, `partner_sys`):

| MAC Notation Style | Example Format | Where You Typically Copy It From |
| :--- | :--- | :--- |
| **Colon-Separated** | `00:1a:2b:3c:4d:5e` | Linux `ip link`, `arp -a`, Wireshark, `tcpdump`, macOS |
| **Hyphen-Separated** | `00-1A-2B-3C-4D-5E` | Windows `ipconfig /all`, `getmac`, Microsoft DHCP / NPS logs |
| **Cisco Dotted-Quad** | `001a.2b3c.4d5e` | Cisco IOS / NX-OS `show mac address-table`, `show ip arp`, Arista EOS |

```frameassembly
// All three MAC notations work out of the box without reformatting:
host linux_srv   { ip 10.0.0.10 mac 00:1a:2b:3c:4d:5e }
host windows_pc  { ip 10.0.0.20 mac 00-1A-2B-3C-4D-5F }
host cisco_sw    { ip 10.0.0.1  mac 001a.2b3c.4d01 }

flow verify_mac_notations(srv, pc, sw) {
    srv -> pc icmp echo_request id 1 seq 1 payload "colon-to-hyphen" wait 1ms
    pc -> sw arp request sendermac 00-1A-2B-3C-4D-5F senderip 10.0.0.20 targetip 10.0.0.1 wait 1ms
    pc <- sw arp reply sendermac 001a.2b3c.4d01 senderip 10.0.0.1 targetmac 00-1A-2B-3C-4D-5F targetip 10.0.0.20
}

compile {
    verify_mac_notations(linux_srv, windows_pc, cisco_sw)
}
```

### How Optional MAC Addresses & Automatic Multicast MACs Work

You do **not** have to type a `mac` address in every `host` block unless your test specifically cares about Layer 2 hardware addresses (such as ARP spoofing, DHCP reservations, or 802.1X MAC filtering):

1. **Unicast hosts without `mac`:** If you omit `mac` (for example, `host client { ip 10.0.0.10 }`), FrameAssembly automatically assigns clean, consistent unicast Ethernet MAC addresses (`00:00:00:00:00:01` and `00:00:00:00:00:02`).
2. **Multicast hosts without `mac`:** If a host's IP address is an **IPv4 multicast address** (`224.0.0.0/4`, such as `224.0.0.5` for OSPF or `224.0.0.18` for VRRP) or an **IPv6 multicast address** (`ff00::/8`, such as `ff02::5` for OSPFv3 or `ff02::fb` for mDNS), FrameAssembly automatically computes the standard multicast Ethernet MAC address:
   * **IPv4 Multicast (RFC 1112):** Maps the low 23 bits of the IPv4 address into `01:00:5e:xx:xx:xx` (for example, `224.0.0.5` $\rightarrow$ `01:00:5e:00:00:05`).
   * **IPv6 Multicast (RFC 2464):** Maps the low 32 bits of the IPv6 address into `33:33:xx:xx:xx:xx` (for example, `ff02::1:2` $\rightarrow$ `33:33:00:01:00:02`).

```frameassembly
// Unicast and multicast hosts without manual MAC addresses
host core_rtr     { ip 10.0.0.1 }
host ospf_all_spf { ip 224.0.0.5 }

host core_rtr_v6  { ip fe80::1 }
host ospf6_all    { ip ff02::5 }

flow send_ospf_hello(rtr, mcast) {
    // Automatically uses 01:00:5e:00:00:05 on IPv4 and 33:33:00:00:00:05 on IPv6
    rtr -> mcast ttl 1 ospf hello router_id 10.0.0.1 area_id 0 hello_interval 10 dead_interval 40
}

compile {
    send_ospf_hello(core_rtr, ospf_all_spf)
    send_ospf_hello(core_rtr_v6, ospf6_all)
}
```

---

## Step 3 — Defaults vs. Customizing Header Fields

FrameAssembly supports **81 protocols** across Layer 2 through Layer 7, and **every single protocol works with zero required sub-keywords**.

* When you write **only the protocol name** (such as `c -> s icmp`, `c -> s dns`, or `c -> s bgp`), FrameAssembly fills in standard, RFC-compliant default headers, well-known ports (`UDP 53` for DNS, `TCP 179` for BGP, `TCP 80` for HTTP), lengths, and checksums.
* When you want to **customize specific fields**, you simply add those field keywords onto the same line in any order—leaving everything else at its default.
* Want to preview the frames in your terminal without writing a `.pcap` file? Run `frameassembly show <file.fasm>`!

### Zero-Keyword Defaults vs. Custom Overrides

```frameassembly
host peer_a { ip 10.10.0.1 }
host peer_b { ip 10.10.0.2 }

// Using built-in RFC defaults (minimal typing)
flow quick_defaults(c, s) {
    c -> s icmp wait 1ms
    c -> s dns wait 1ms
    c -> s bgp
}

// Overriding specific header fields on the exact same protocols
flow custom_headers(c, s) {
    // Custom ICMP Echo Request: TTL 128, Don't Fragment (DF), custom ID/SEQ and payload
    c -> s ttl 128 df icmp echo_request id 42 seq 10 payload "MTU_PROBE_1472" wait 2ms

    // Custom DNS AAAA query for an internal hostname with explicit Transaction ID
    c -> s dns query txid 0x99a1 qname "db01.corp.internal" qtype "AAAA" wait 2ms

    // Custom BGP UPDATE advertising 172.16.0.0/16 from ASN 65001
    c -> s ttl 255 dscp 48 bgp update asn 65001 prefix "172.16.0.0/16" nexthop 10.10.0.1
}

compile {
    quick_defaults(peer_a, peer_b)
    custom_headers(peer_a, peer_b)
}
```

---

## Step 4 — Visual Packet Ladders, Arrows (`->` / `<-`) & Automatic TCP Math

Inside a `flow(c, s)` block, keep the initiating client (`c`) on the left and the server (`s`) on the right:
* **`c -> s`** sends a packet **from `c` to `s`** (forward client request).
* **`c <- s`** sends a packet **from `s` back to `c`** (reverse server response).

This structure maps 1:1 to Wireshark's graphical **Flow Graph**:

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
      |  HTTP GET /status   |
      |-------------------->|        c -> s http get uri "/status" host_hdr "api.local"
      |      [PSH, ACK]     |
      |                     |
      |   HTTP 200 OK       |
      |<--------------------|        c <- s http status 200 reason "OK" body "{\"up\":true}"
      |      [PSH, ACK]     |
```

### Automatic Reply Port Swapping
When `c -> s` sets `srcport 52100 dstport 80`, FrameAssembly automatically remembers that session:
* Subsequent forward packets (`c -> s`) automatically use `52100 -> 80`.
* Subsequent reply packets (`c <- s`) automatically swap the ports to `80 -> 52100`.

### Automatic TCP `SEQ` and `ACKNUM` Progression
FrameAssembly tracks TCP connection state automatically:
1. **`SYN` and `FIN` flags** consume 1 sequence number each.
2. **Layer 7 TCP statements** (`http`, `tls`, `ssh`, `bgp`, `smb`, `modbus`, etc.) automatically emit a `PSH ACK` TCP segment on that connection and advance `SEQ` and `ACKNUM` by the exact byte length of the generated payload.
3. **Graceful `FIN ACK` teardowns** resume sequence numbers exactly where Layer 7 finished.

```frameassembly
host app_client { ip 10.20.1.50 }
host web_server { ip 10.20.1.80 }

flow tracked_http_conversation(c, s) {
    // 1. TCP 3-way handshake: set srcport and dstport once on the opening SYN
    c -> s tcp syn srcport 52100 dstport 80 win 65535 mss 1460 wscale 7 sack_perm wait 1ms
    c <- s tcp syn ack win 65535 mss 1460 wscale 7 sack_perm wait 1ms
    c -> s tcp ack wait 2ms

    // 2. Layer 7 HTTP exchange: reuses ports 52100 <-> 80 and advances SEQ/ACKNUM automatically
    c -> s http get uri "/api/v1/status" host_hdr "api.internal" user_agent "NOC-Monitor/1.0" wait 5ms
    c <- s http status 200 reason "OK" content_type "application/json" body "{\"healthy\":true}" wait 2ms

    // 3. Clean TCP FIN teardown: SEQ and ACKNUM match the exact end of the HTTP response
    c -> s tcp fin ack wait 1ms
    c <- s tcp fin ack wait 1ms
    c -> s tcp ack
}

compile {
    tracked_http_conversation(app_client, web_server)
}
```

### Intentionally Overriding `seq`, `acknum`, or `win` (Anomalies & Zero-Window)

To test firewall state tables or TCP stack anomalies, simply specify explicit values on that packet line:

```frameassembly
host client_node { ip 10.30.0.10 }
host server_node { ip 10.30.0.20 }

flow tcp_anomaly_and_zero_window(c, s) {
    c -> s tcp syn srcport 54000 dstport 8080 win 65535 mss 1460 wait 1ms
    c <- s tcp syn ack win 65535 mss 1460 wait 1ms
    c -> s tcp ack wait 1ms

    c -> s http post uri "/upload" host_hdr "ingest.local" body "CHUNK_DATA_01" wait 2ms

    // Override 1: Server advertises a TCP Zero Window (buffer full)
    c <- s tcp ack win 0 wait 50ms

    // Override 2: Inject an out-of-window segment (seq 900000) to test state inspection
    c -> s tcp psh ack seq 900000 acknum 1 payload "OUT_OF_WINDOW_PROBE" wait 5ms

    // Override 3: Server sends a Window Update reopening the window to 32768 bytes
    c <- s tcp ack win 32768 wait 2ms
    c <- s http status 200 reason "OK" body "UPLOAD_COMPLETE"
}

compile {
    tcp_anomaly_and_zero_window(client_node, server_node)
}
```

---

## Step 5 — Attaching VLAN, QinQ, MPLS, QoS (`DSCP`/`ECN`) & Fragmentation

Any packet line in FrameAssembly can attach Layer 2 trunk tags (`VLAN`, `QINQ`, `MPLS`) or Layer 3 QoS/fragmentation modifiers:

| Layer | Modifier Syntax | Valid Range / Format | What It Sets on the Wire |
| :--- | :--- | :--- | :--- |
| **Layer 2 (VLAN)** | `vlan <id> pcp <0..7> dei <0..1>` | `1..4094` | Adds an IEEE 802.1Q VLAN tag (`EtherType 0x8100`) |
| **Layer 2 (CoS)** | `pcp <0..7>` | `0..7` | Sets the 3-bit 802.1p Priority Code Point inside the `vlan` tag |
| **Layer 2 (Drop)** | `dei <0..1>` | `0..1` | Sets the 1-bit Drop Eligible Indicator inside the `vlan` tag |
| **Layer 2 (QinQ)** | `qinq <s_vid> inner_vlan <c_vid>` | `1..4094` | Adds IEEE 802.1ad outer S-VLAN (`0x88a8`) + inner C-VLAN (`0x8100`) tags |
| **Layer 2 (MPLS)** | `mpls <label> exp <0..7> bos <0..1> mpls_ttl <ttl>` | Label `0..1048575`, EXP `0..7`, BOS `0..1`, TTL `0..255` | Adds an RFC 3032 MPLS shim header (`EtherType 0x8847`) |
| **Layer 2 (MAC)** | `srcmac <mac>` / `dstmac <mac>` | `00:1a:2b:3c:4d:5e`, `00-1A-2B-3C-4D-5E`, or `001a.2b3c.4d5e` | Overrides the source or destination Ethernet MAC for that single frame |
| **Layer 2 (Type)** | `ethertype <val>` | `0..65535` (e.g. `0x88cc`) | Overrides the Ethernet frame's outer EtherType field |
| **Layer 3 (Hop)** | `ttl <hops>` | `0..255` (default `64`) | Sets IPv4 Time-to-Live **or** IPv6 Hop Limit |
| **Layer 3 (QoS)** | `dscp <val>` | `0..63` (e.g. `46` for EF) | Sets the 6-bit DiffServ Code Point in IPv4 TOS or IPv6 Traffic Class |
| **Layer 3 (ECN)** | `ecn <val>` | `0..3` (`3` = Congestion Experienced) | Sets the 2-bit Explicit Congestion Notification field |
| **Layer 3 (IPv6)** | `flowlabel <val>` | `0..1048575` (`0xFFFFF`) | Sets the 20-bit IPv6 Flow Label (silently ignored when run on IPv4) |
| **Layer 3 (Frag)** | `ipid <id>` | `0..65535` (e.g. `0x1234`) | Sets the 16-bit IPv4 Identification field used for fragment reassembly |
| **Layer 3 (Frag)** | `df` | *(bare keyword)* | Sets the IPv4 **Don't Fragment (DF)** bit (for Path MTU Discovery tests) |
| **Layer 3 (Frag)** | `mf` | *(bare keyword)* | Sets the IPv4 **More Fragments (MF)** bit on non-final fragments |
| **Layer 3 (Frag)** | `fragoffset <units>` | `0..8191` (8-byte units) | Sets the IPv4 Fragment Offset (`fragoffset 1` = 8 bytes, `fragoffset 185` = 1480 bytes) |
| **Layer 4 / Timing** | `srcport <p>` / `dstport <p>` | `0..65535` | Sets or overrides the TCP, UDP, or SCTP source/destination port |
| **Layer 4 (Proto)**| `transport <tcp>` or `transport <udp>` | `tcp` or `udp` | Forces a dual-transport L7 protocol (like `dns`, `sip`, or `syslog`) onto TCP or UDP |
| **Timing** | `wait <n><unit>` | `ns`, `us`, `ms`, `s`, `m` | Advances the PCAP timestamp after this packet by the exact duration |

```frameassembly
host branch_edge { ip 172.16.100.10 mac 00:1c:73:aa:00:10 }
host core_pe     { ip 172.16.100.1  mac 00:1c:73:aa:00:01 }

flow wan_encapsulation_showcase(edge, core) {
    // 1. 802.1Q VLAN 110 with CoS 5 (PCP 5, DEI 0) and DiffServ EF (DSCP 46, ECN 2)
    edge -> core vlan 110 pcp 5 dei 0 ttl 64 dscp 46 ecn 2 rtp pt 0 seq 1 timestamp 160 ssrc 0x10203040 payload "VOICE_FRAME" wait 5ms

    // 2. Carrier 802.1ad QinQ double-tagged frame (Outer S-VLAN 2000, Inner C-VLAN 110)
    edge -> core qinq 2000 inner_vlan 110 dscp 26 udp srcport 50000 dstport 9000 payload "METRO_ETHERNET_DATA" wait 5ms

    // 3. MPLS labeled packet (Label 16000, EXP/TC 5, Bottom-of-Stack 1, MPLS TTL 63)
    edge -> core mpls 16000 exp 5 bos 1 mpls_ttl 63 ttl 63 dscp 46 icmp echo_request id 50 seq 1 payload "MPLS_L3VPN_PING" wait 5ms

    // 4. IPv4 Path MTU probe with Don't Fragment (DF) set
    edge -> core df ipid 0x4400 ttl 64 icmp echo_request id 51 seq 1 payload "PMTUD_DO_NOT_FRAGMENT" wait 5ms

    // 5. IPv4 fragmented ping sharing IPID 0x7788:
    edge -> core ipid 0x7788 mf fragoffset 0 icmp echo_request id 52 seq 1 payload "FIRST_8B_SECOND8" wait 1ms
    edge -> core ipid 0x7788 fragoffset 2 icmp echo_request id 52 seq 1 payload "FINAL_FRAGMENT_B"
}

compile {
    wan_encapsulation_showcase(branch_edge, core_pe)
}
```

---

## Step 6 — Polymorphic Dual-Stack Flows & Repeating with `loop`

A `flow` uses placeholder endpoint names like `(client, server)`, meaning you can define a traffic scenario **once** and run it over both IPv4 and IPv6 host pairs without duplicate definitions.

* On IPv4 pairs: emits standard IPv4 headers (`EtherType 0x0800`).
* On IPv6 pairs: emits standard IPv6 headers (`EtherType 0x86dd`), translates `icmp` to **ICMPv6** (with RFC 4443 checksums), and applies `flowlabel`.
* **`loop <count>`**: repeats the enclosed flows `<count>` times while advancing sequence numbers and timestamps.

```frameassembly
host sensor_v4    { ip 10.50.0.10 }
host collector_v4 { ip 10.50.0.100 }

host sensor_v6    { ip 2001:db8:50::10 }
host collector_v6 { ip 2001:db8:50::100 }

flow dns_and_syslog_heartbeat(node, srv) {
    node -> srv vlan 50 dscp 16 ttl 64 flowlabel 0x1a2b3 dns query txid 0x1001 qname "time.corp.internal" qtype "A" wait 2ms
    node <- srv vlan 50 dscp 16 ttl 64 flowlabel 0x1a2b3 dns response txid 0x1001 qname "time.corp.internal" qtype "A" rdata "10.50.0.100" wait 5ms
    node -> srv vlan 50 dscp 16 ttl 64 flowlabel 0x1a2b3 syslog facility 16 severity 6 hostname "edge-sensor" app "healthd" msg "Heartbeat OK" wait 10ms
}

compile {
    loop 4 {
        dns_and_syslog_heartbeat(sensor_v4, collector_v4)
        dns_and_syslog_heartbeat(sensor_v6, collector_v6)
    }
}
```

---

## Step 7 — From Wireshark / `tcpdump` to `.fasm` Translation Table

| Networking Field / Concept | Wireshark Display Filter | `tcpdump` Filter Expression | `.fasm` Keyword Syntax | Detailed Reference Table |
| :--- | :--- | :--- | :--- | :--- |
| **Device IP & MAC Address** | `ip.addr == 10.0.0.1 && eth.addr == 00:1a:2b:3c:4d:5e` | `host 10.0.0.1 and ether host 00:1a:2b:3c:4d:5e` | `host rtr { ip 10.0.0.1 mac 00:1a:2b:3c:4d:5e }` *(also accepts `00-1A-2B-3C-4D-5E` & `001a.2b3c.4d5e`)* | [Ethernet & MAC Overrides](l2_protocols.md#universal-ethernet-ii-header-overrides--automatic-mac-derivation) |
| **Per-Packet MAC / EtherType** | `eth.src == ... && eth.type == 0x88cc` | `ether src ... and ether proto 0x88cc` | `srcmac <mac> dstmac <mac> ethertype 0x88cc` | [EtherType & MAC Table](l2_protocols.md#universal-ethernet-ii-header-overrides--automatic-mac-derivation) |
| **802.1Q VLAN & 802.1p CoS** | `vlan.id == 100 && vlan.priority == 5` | `vlan 100` | `vlan 100 pcp 5 dei 0` | [802.1p CoS (`PCP`) Table](l2_protocols.md#ieee-8021p-class-of-service-pcp-reference-table) |
| **802.1ad QinQ Double Tag** | `vlan.id == 2000 && vlan.id == 100` | `vlan 2000 and vlan 100` | `qinq 2000 inner_vlan 100` | [VLAN & QinQ Reference](l2_protocols.md#2-virtual-lan-vlan--ieee-8021q--provider-bridging-qinq--ieee-8021ad) |
| **MPLS Label & EXP / TC** | `mpls.label == 16000 && mpls.exp == 5` | `mpls 16000` | `mpls 16000 exp 5 bos 1 mpls_ttl 64` | [MPLS Reference](l2_protocols.md#7-multiprotocol-label-switching-mpls--rfc-3032--rfc-5462) |
| **DiffServ QoS (`DSCP`) & `ECN`** | `ip.dsfield.dscp == 46 && ip.dsfield.ecn == 2` | `ip[1] & 0xfc == 0xb8` | `dscp 46 ecn 2` | [DiffServ `DSCP` & `ECN` Table](l3_protocols.md#common-diffserv-dscp--ecn-quick-reference) |
| **IPv4 TTL / IPv6 Hop Limit** | `ip.ttl == 64` / `ipv6.hlim == 64` | `ip[8] == 64` / `ip6[7] == 64` | `ttl 64` | [Universal L3 Modifiers](l3_protocols.md#1-universal-ipv4--ipv6-header-modifiers) |
| **IPv4 Don't Fragment (`DF`)** | `ip.flags.df == 1` | `ip[6] & 0x40 != 0` | `df` | [Universal L3 Modifiers](l3_protocols.md#1-universal-ipv4--ipv6-header-modifiers) |
| **IPv4 Fragmentation** | `ip.flags.mf == 1 && ip.frag_offset == 0` | `ip[6:2] & 0x3fff != 0` | `ipid 0x1234 mf fragoffset 0` | [Universal L3 Modifiers](l3_protocols.md#1-universal-ipv4--ipv6-header-modifiers) |
| **Source & Destination Ports** | `tcp.srcport == 52000 && tcp.dstport == 443` | `src port 52000 and dst port 443` | `srcport 52000 dstport 443` | [L4 Transports Guide](l4_transports.md) |
| **TCP Flags** | `tcp.flags.syn == 1 && tcp.flags.ack == 1` | `tcp[tcpflags] & (tcp-syn\|tcp-ack) != 0` | `tcp syn ack` *(or `fin`, `rst`, `psh`, `urg`, `ece`, `cwr`)* | [L4 Transports Guide](l4_transports.md) |
| **TCP Seq / Ack / Window** | `tcp.seq == 1000 && tcp.ack == 2000` | `tcp[4:4] == 1000` | `seq 1000 acknum 2000 win 65535` | [L4 Transports Guide](l4_transports.md) |
| **SNMP Trap & Poll OIDs** | `snmp.name == 1.3.6.1.2.1.1.5.0` | `udp port 161 or udp port 162` | `varbind 1.3.6.1.2.1.1.5.0 string "core-sw"` | [MIB-II & Trap OID Table](l7_snmp.md#22-common-standard-mib-ii--notification-oids-cheat-sheet) |

---

## Step 8 — Use ChatGPT / Claude / Copilot to Write `.fasm` from Plain English

Copy and paste this prompt into **ChatGPT**, **Claude**, **Microsoft Copilot**, or **Cursor**:

```text
Read the FrameAssembly (.fasm) syntax reference at:
https://raw.githubusercontent.com/SteveWinschel/FrameAssembly/main/llms.txt

Write a complete, compilable FrameAssembly (.fasm) packet recipe with HOST, FLOW, and COMPILE blocks for the following network scenario:
[Describe what you want to test in plain English — for example: "Simulate an access switch at 10.20.1.2 sending an SNMPv3 SHA256+AES linkDown trap on VLAN 100 to NMS 10.20.1.50, followed by a blocked SSH connection attempt from 172.16.99.9 that gets rejected with a TCP RST ACK"]

Rules to follow:
- Use only canonical HOST <id> { IP <ip> [MAC <mac>] }, FLOW <id>(<params>) { ... }, and COMPILE { ... } blocks.
- Use SRCPORT, DSTPORT, ACKNUM, bare TCP flag names (SYN ACK), and trailing WAIT <n><ms|s|us|ns>.
- Output only the compilable .fasm file.
```

---

## Step 9 — How to Read Compiler Error Messages & Foreign `.fasm` Diagnostics

When a `.fasm` file contains a typo, FrameAssembly never writes a corrupt `.pcap`. Instead, it renders an exact file pointer and plain-English remediation hint:

### Example 1: Keyword Typo (`frameassembly::parse_error`)

```text
frameassembly::parse_error

  × Failed to parse input: Syntax error: unexpected token Ident("sport") ('sport'), expected a valid statement or protocol modifier. Did you mean 'SRCPORT'?
   ╭─[my_test.fasm:6:16]
 5 │ flow test(c, s) {
 6 │     c -> s tcp sport 50000 dstport 80 syn
   ·                ──┬──
   ·                  ╰── Here
 7 │ }
   ╰────
  help: Replace 'sport' with 'SRCPORT <port>' (for example: SRCPORT 51234).
```

### Example 2: Accidentally Passing an x86 Flat Assembler or FPGA FASM File

If you accidentally pass an x86 Flat Assembler file (with `format PE`, `section`, or `;` comments) or an FPGA FASM bitstream file, FrameAssembly identifies the foreign format and guides you:

```text
frameassembly::parse_error

  × Failed to parse input: unexpected token
   ╭─[firmware.fasm:1:1]
 1 │ format PE GUI 4.0
   · ──┬───
   ·   ╰── Here
   ╰────
  help: This file appears to be an x86 Flat Assembler file, not a FrameAssembly network packet specification. FrameAssembly files declare HOST { IP ... }, FLOW(...), and COMPILE { ... } blocks to compile network traffic into .pcap/.pcapng captures. See https://github.com/SteveWinschel/FrameAssembly for syntax and examples.
```

---

## Step 10 — Verification with Wireshark, `tshark` & `tcpreplay`

```bash
# Preview packet ladder in terminal without creating files
frameassembly show ping_test.fasm

# Build the .pcap file
frameassembly ping_test.fasm -o ping_test.pcap

# Inspect packet headers in terminal with tshark
tshark -r ping_test.pcap

# Open graphically in Wireshark
wireshark ping_test.pcap &

# Replay onto a live interface or firewall test port
sudo tcpreplay -i eth0 ping_test.pcap
```

---

## Where to Go Next: The 12 Other FrameAssembly Guides

* **[Practical Use Cases & Cookbook (`use_cases.md`)](use_cases.md)** — Ready-to-copy `.fasm` recipes for SNMPv1/v2c/v3 traps & polls, firewall ACL & stateful inspection testing, VLAN/QinQ/MPLS/QoS verification, SIEM & IDS/IPS validation (Suricata/Zeek), industrial OT/SCADA dissectors, and zero-noise bug/failover reproducers.
* **[Layer 2 Switching & Data-Link Protocols (`l2_protocols.md`)](l2_protocols.md)** — All **8** Layer 2 protocols: `ARP` (including Gratuitous ARP), `VLAN` (802.1Q), `QINQ` (802.1ad), `LLDP`, `STP` / RSTP, `LACP`, `EAPOL` (802.1X), and `MPLS`.
* **[Layer 3 Control, Tunneling, VPN & Routing (`l3_protocols.md`)](l3_protocols.md)** — All **20** Layer 3 protocols: `ICMP` (v4/v6), `NDP`, `IGMP`, `MLD`, `GRE`, `VXLAN`, `GENEVE`, `IPSEC`, `ESP`, `AH`, `IKEV2`, `WIREGUARD`, `OSPF`, `BGP`, `RIP`, `VRRP`, `HSRP`, `PIM`, `BFD`, and `OPENFLOW`.
* **[Layer 4 Transports (`l4_transports.md`)](l4_transports.md)** — All **3** Layer 4 transports: `TCP` (connection tracking, handshakes, resets, zero-window, RFC 7323 options `MSS`/`WSCALE`/`SACK_PERM`/`TSVAL`/`TSECR`), `UDP`, and `SCTP` (verification tags, streams, chunks, and RFC 9260 CRC32c).
* **[Layer 7 SNMPv1, SNMPv2c & SNMPv3 USM (`l7_snmp.md`)](l7_snmp.md)** — All **3** SNMP versions (`SNMP1`, `SNMP2`, `SNMP3`), `GET`/`SET`/`GETNEXT`/`GETBULK`/`RESPONSE`/`TRAP`/`INFORM` messages, RFC 3414/3826/7860 USM authentication (`MD5`, `SHA`, `SHA256`, `SHA384`, `SHA512`) and privacy (`DES`, `AES`), and all 9 SMI `VARBIND` types.
* **[Layer 7 Infrastructure, Time, AAA & Telemetry (`l7_infra_and_telemetry.md`)](l7_infra_and_telemetry.md)** — All **11** core infrastructure and telemetry protocols: `DNS`, `MDNS`, `DHCP` (v4/v6), `NTP`, `PTP` (IEEE 1588v2), `RADIUS`, `TACACS` (TACACS+), `SYSLOG` (RFC 5424), `NETFLOW` (v5), `IPFIX` (v10), and `SFLOW` (v5).
* **[Layer 7 Web, Cloud, Security, VoIP & Remote Access (`l7_web_and_cloud.md`)](l7_web_and_cloud.md)** — All **16** web, cloud, security, VoIP, and remote access protocols: `HTTP`, `HTTP2`, `GRPC`, `WEBSOCKET`, `TLS`, `QUIC`, `TFTP`, `FTP`, `SSH`, `TELNET`, `WHOIS`, `SIP`, `RTP`, `RTSP`, `STUN`, and `SSDP`.
* **[Layer 7 Mail, Auth, Storage, Databases & Messaging (`l7_mail_auth_storage_db.md`)](l7_mail_auth_storage_db.md)** — All **14** mail, directory, file storage, database, cache, and message broker protocols: `SMTP`, `IMAP`, `POP3`, `KERBEROS`, `LDAP`, `SMB`, `NFS`, `REDIS`, `MEMCACHED`, `MYSQL`, `POSTGRES`, `MQTT`, `COAP`, and `AMQP`.
* **[Layer 7 Industrial Control Systems & SCADA/OT (`l7_industrial_ot.md`)](l7_industrial_ot.md)** — All **6** industrial automation and SCADA protocols: `MODBUS` (Modbus TCP), `BACNET` (BACnet/IP), `DNP3` (IEEE 1815 with automatic CRC-16), `S7COMM` (Siemens S7), `ETHERNETIP` (ODVA CIP), and `OPCUA` (OPC UA Binary).
* **[Multi-Host Topologies & Dual-Stack Scenarios (`topologies_and_dual_stack.md`)](topologies_and_dual_stack.md)** — End-to-end multi-tier enterprise, EVPN-VXLAN data center, and Zero-Trust 802.1X campus NAC architectures across IPv4 and IPv6.
* **[`.fasm` File Format & Media Type Specification (`fasm-specification.md`)](fasm-specification.md)** — Normative `text/vnd.frameassembly` specification, UTF-8 encoding rules, lexical magic signatures, and disambiguation from x86 Flat Assembler and FPGA FASM files.
* **[For Nerds: Architecture, Rust Library API & Formal Grammars (`for_nerds.md`)](for_nerds.md)** — Deep dive into the internal Rust pipeline, embedding `frameassembly` as a Rust crate, formal `EBNF`/`GBNF`/`Lark` grammars, and LLM constrained decoding.