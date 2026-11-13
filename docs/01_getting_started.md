# Getting Started with FrameAssembly

[← Main README](../README.md) • [Docs Index](README.md) • [Use-Case Cookbook](02_use_cases.md)

Your firewall team swears the box never dropped your packet. You swear it did. Only one of you has a capture, and right now neither does. FrameAssembly turns "trust me" into a few lines of `.frasm` code: describe the traffic, compile it into a `.pcap`, replay it, and read the counters. No sticky note covered in TCP sequence numbers, no Python `virtualenv` that worked fine yesterday.

You can [**Try in Browser**](https://frameassembly.ai.studio/) first, or jump straight to [install](#1-install-frameassembly), your [first capture](#2-build-your-first-pcap-in-60-seconds), [scrubbing a customer capture](#scrub-a-capture-before-support-blames-dns-frameassembly-reverse), [stateful TCP](#4-stateful-tcp-without-sequence-number-math), [VLAN and QoS tags](#5-vlan-trunks-qinq-mpls-qos-and-fragments), [IPv4 and IPv6 reuse](#6-reusing-flows-across-ipv4-and-ipv6), the [Wireshark and `tcpdump` cheat sheet](#7-wireshark-and-tcpdump-to-frasm-cheat-sheet), or the [AI prompt](#8-generating-frasm-code-with-ai-assistants-copy-paste-prompt).

## 1. Install FrameAssembly

Pick whichever route is fastest for you. None of these need a Rust toolchain, and the browser route needs nothing installed at all:

| Platform / OS | Method | Command |
| :--- | :--- | :--- |
| **Web Browser** | **Browser Playground** | [**frameassembly.ai.studio**](https://frameassembly.ai.studio/) (turn `.frasm` code into captures and captures back into code, with packet ladders, without installing anything) |
| **VS Code** | **VS Code Packet Studio** | `code --install-extension SteveWinschel.frameassembly-vscode` ([**Marketplace**](https://marketplace.visualstudio.com/items?itemName=SteveWinschel.frameassembly-vscode)) |
| **Windows** | **PowerShell installer** (no Administrator rights) | `irm https://raw.githubusercontent.com/SteveWinschel/FrameAssembly/main/install.ps1 \| iex` |
| **Linux & macOS** | **Shell installer** | `curl -fsSL https://raw.githubusercontent.com/SteveWinschel/FrameAssembly/main/install.sh \| sh` |
| **Windows, macOS & Linux** | **GitHub Releases** | [**Download `frameassembly-windows-x64.zip`, `frameassembly-macos-arm64.tar.gz`, `frameassembly-linux-x64.tar.gz` or `frameassembly_amd64.deb`**](https://github.com/SteveWinschel/FrameAssembly/releases/latest) |
| **macOS & Linux** | **Homebrew** | `brew install SteveWinschel/tap-FrameAssembly/frameassembly` |
| **Windows** | **Scoop** | `scoop bucket add frameassembly https://github.com/SteveWinschel/homebrew-tap-FrameAssembly && scoop install frameassembly` |
| **Debian / Ubuntu** | **APT (`.deb`)** | `curl -fsSLo /tmp/frameassembly.deb https://github.com/SteveWinschel/FrameAssembly/releases/latest/download/frameassembly_amd64.deb && sudo apt install -y /tmp/frameassembly.deb && rm -f /tmp/frameassembly.deb` |

<details>
<summary><strong>Developer Install (Cargo, Docs.rs, NPM / WebAssembly)</strong></summary>

| Platform / OS | Method | Command |
| :--- | :--- | :--- |
| **Any (Rust 1.85+)** | **Cargo** | `cargo install frameassembly` |
| **Rust library users** | **Docs.rs API reference** | [**docs.rs/frameassembly**](https://docs.rs/frameassembly) |
| **Browser / Node.js** | **NPM (WASM)** | `npm install frameassembly-wasm` |

</details>


Check that the CLI binary is ready:

```bash
frameassembly version
frameassembly help
```

> **Shell Tab Completions:** Context-aware Tab completion scripts for **Bash**, **Zsh**, **Fish**, and **PowerShell** (completing `.frasm` inputs, `show`, `reverse`, `help`, `version`, and `.pcap` / `.pcapng` paths) are installed automatically by `install.sh` and the `.deb` package, or can be installed manually from [`contrib/completions/`](../contrib/completions/README.md).

## 2. Build Your First `.pcap` in 60 Seconds

Every `.frasm` file has up to three building blocks:

1. **`host` — Name Your Devices:** Bind a name to an `ip` (IPv4 or IPv6) and an optional `mac`—or declare MAC-only `host` blocks (`host sw1 { mac 00:1c:73:00:00:01 }`) for Layer 2 switching protocols (`lldp`, `stp`, `lacp`, `eapol`, `vlan`, `qinq`, `mpls`, `arp`).
2. **`flow` — Group Reusable Packet Exchanges (Optional):** One line is one Ethernet frame. An arrow pointing right sends the packet forward, an arrow pointing left sends the reply, and `wait` (`ns`, `us`, `ms`, `s`, `m`) sets the gap before the next one (see the first line of `ping_check` below).
3. **`compile` — Generate the Capture:** Call your `flow` with your `host` names, or write packet statements directly inside `compile { ... }` without a `flow` block.

Save this as `ping_test.frasm`:

```frameassembly
// 1. Declare the endpoints
host workstation { ip 192.168.10.50 mac 00:1a:2b:3c:4d:50 }
host gateway     { ip 192.168.10.1  mac 00:1a:2b:3c:4d:01 }

// 2. Describe the packet exchange (1 line = 1 wire frame)
flow ping_check(c, gw) {
    c -> gw icmp echorequest id 100 seq 1 payload "ping-1"
    c <- gw icmp echoreply   id 100 seq 1 payload "ping-1" wait 2ms
    c -> gw icmp echorequest id 100 seq 2 payload "ping-2" wait 10ms
    c <- gw icmp echoreply   id 100 seq 2 payload "ping-2" wait 2ms
}

// 3. Build the capture
compile { ping_check(workstation, gateway) }
```

Preview the packet ladder in your terminal with `frameassembly show`, compile `ping_test.frasm` directly with `frameassembly ping_test.frasm` (which writes `ping_test.pcap` by default, or pass a custom output filename as the second argument), and inspect or replay it:

```console
$ frameassembly show ping_test.frasm
#      Time (ms)   Source -> Destination                    Proto       Bytes  Summary
--------------------------------------------------------------------------------------------------------------
1      0.000       192.168.10.50 -> 192.168.10.1            ICMP        48     Echo Request (type=8 code=0)
2      2.000       192.168.10.1 -> 192.168.10.50            ICMP        48     Echo Reply (type=0 code=0)
3      12.000      192.168.10.50 -> 192.168.10.1            ICMP        48     Echo Request (type=8 code=0)
4      14.000      192.168.10.1 -> 192.168.10.50            ICMP        48     Echo Reply (type=0 code=0)

$ frameassembly ping_test.frasm
$ frameassembly ping_test.frasm custom_ping.pcap
$ tshark -r ping_test.pcap
$ sudo tcpreplay -i eth0 ping_test.pcap
```

### Inline Statements in `compile` & MAC-Only Layer 2 Switches
For quick one-off captures or Layer 2 switch frames (`lldp`, `stp`, `lacp`, `eapol`, `vlan`, `qinq`, `mpls`, `arp`), you can omit `ip` from your `host` blocks and write packet lines directly inside `compile { ... }` with no `flow` block needed:

```frameassembly
host sw1 { mac 00:1c:73:00:00:01 }
host sw2 { mac 00:1c:73:00:00:02 }

compile {
    sw1 -> sw2 lldp chassisid "00:1c:73:00:00:01" portid "Ethernet1/1" ttl 120 sysname "spine-01" wait 2ms
    sw1 <- sw2 lldp chassisid "00:1c:73:00:00:02" portid "Ethernet49/1" ttl 120 sysname "leaf-01" wait 2ms
    sw1 -> sw2 stp rstp rootid "4096/00:1c:73:00:00:01" bridgeid "4096/00:1c:73:00:00:01" portid 0x8001 cost 0 flags 0x3c
}
```

### Scrub a Capture Before Support Blames DNS (`frameassembly reverse`)

The vendor ticket needs a capture. The capture has your customer's internal subnets in it, and DNS will be blamed regardless. Run `frameassembly reverse` on the `.pcap` or `.pcapng` (it writes `<input_stem>.frasm` unless you pass an output name), swap the identifying bits, and recompile:

```console
$ frameassembly reverse ping_test.pcap reversed_ping.frasm
```

`reverse` walks every packet, names the endpoints `host1`, `host2` and so on, and writes the conversation out as `.frasm` code inside a `compile { ... }` block:

```frameassembly
host host1 { ip 192.168.10.50 mac 00:1a:2b:3c:4d:50 }
host host2 { ip 192.168.10.1 mac 00:1a:2b:3c:4d:01 }

compile {
    host1 -> host2 icmp echorequest id 100 seq 1 payload "ping-1"
    host1 <- host2 icmp echoreply id 100 seq 1 payload "ping-1" wait 2ms
    host1 -> host2 icmp echorequest id 100 seq 2 payload "ping-2" wait 10ms
    host1 <- host2 icmp echoreply id 100 seq 2 payload "ping-2" wait 2ms
}
```

Change any IP, MAC, VLAN tag, or payload, then recompile with `frameassembly reversed_ping.frasm edited.pcap`. Checksums and TCP `SEQ`/`ACK` numbers are recalculated for you. Encrypted payloads (such as SNMPv3 `authPriv`, TLS application data, SSH, or IPsec `ESP`) are not decrypted; `reverse` keeps them as `tcp` or `udp` statements with `payload` / `hexpayload` so recompiling preserves the exact wire bytes.

### Three Quick Ground Rules
* **Strictly lowercase built-in keywords (zero `_` or `-`):** Every built-in keyword, protocol, modifier, and time unit (`ns`, `us`, `ms`, `s`, `m`) is lowercase without underscores or hyphens (`host`, `flow`, `compile`, `echorequest`, `innervlan`, `clienthello`, `hosthdr`, `readholdingregisters`). Your own `host`, `flow`, and parameter names can freely use uppercase, `_`, or `-` (`core_sw`, `fw-dmz-01`), and quoted strings (`"..."`) keep their exact casing on the wire.
* **Comments use `//`:** Never `#` or `;`.
* **1 statement = 1 frame:** You can wrap a long Layer 7 line across several indented lines; it still produces exactly one Ethernet frame.

## 3. Skip MAC Formatting and Boilerplate

### Paste Any MAC Format—Or Leave MACs Out Completely
Linux prints MACs with colons, Windows with hyphens, Cisco with dots, and somebody always spends ten minutes with find-and-replace. Paste them as they come. If all you care about is Layer 3–7, leave `mac` out entirely:

* **Unicast hosts without `mac`:** Automatically get direction-aware MACs (`00:00:00:00:00:01` and `00:00:00:00:00:02`) so switch CAM tables don't flap during `tcpreplay`.
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
    srv -> pc icmp echorequest id 1 seq 1 payload "all-mac-formats-work" wait 2ms

    // ospf_mcast has no MAC, so 01:00:5e:00:00:05 is derived automatically
    rtr -> mcast ttl 1 ospf hello routerid 10.0.0.254 areaid 0 hellointerval 10 deadinterval 40
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
    c -> s ttl 128 df icmp echorequest id 42 seq 1 payload "MTU_PROBE_1472" wait 2ms
    c -> s dns query txid 0x99a1 qname "db01.corp.internal" qtype "aaaa" wait 2ms
    s -> c snmp3 trap user "netops" engineid "80001f8801" auth sha256 "AuthPass123!" priv aes "PrivPass123!" oid 1.3.6.1.6.3.1.1.5.3
}

compile { defaults_vs_overrides(client, server) }
```

## 4. Stateful TCP Without Sequence Number Math

One spoofed HTTP packet fired at a stateful firewall (**Palo Alto**, **FortiGate**, **CheckPoint**, `nftables`) proves nothing: no handshake, no session, and the firewall is correct to drop it. Sending the handshake first normally means a sticky note with sequence numbers on it, and an off-by-one that sends you back to the beginning.

Keep `c` on the left and `s` on the right inside `flow(c, s)` and flip the arrow direction for replies. The compiler tracks the connection:
* **Reply port swapping:** Set `srcport` and `dstport` once on `syn`; every reply line flips them automatically (`80` to `52100`).
* **Automatic `SEQ`/`ACK` progression:** `syn` and `fin` advance sequence numbers by one, and any TCP-based Layer 7 protocol (`http`, `tls`, `ssh`, `bgp`, `smb`, `modbus`, and so on) emits a `PSH ACK` segment and advances `SEQ`/`ACK` by the exact payload length:

```frameassembly
host app_client { ip 10.20.1.50 }
host web_server { ip 10.20.1.80 }

flow http_health_check(c, s) {
    c -> s tcp syn srcport 52100 dstport 80 win 65535 mss 1460 wscale 7 sackperm wait 1ms
    c <- s tcp syn ack win 65535 mss 1460 wscale 7 sackperm wait 1ms
    c -> s tcp ack wait 1ms

    c -> s http get uri "/api/v1/status" hosthdr "api.internal" useragent "NOC-Probe/1.0" wait 5ms
    c <- s http status 200 reason "OK" contenttype "application/json" body "{\"healthy\":true}" wait 2ms

    c -> s tcp fin ack wait 1ms
    c <- s tcp fin ack wait 1ms
    c -> s tcp ack
}

compile { http_health_check(app_client, web_server) }
```

### Need Broken TCP Traffic? Override Anything
Sometimes the point is to misbehave: a `ZeroWindow` stall, an out-of-window segment, an abrupt `RST`. Override `win 0`, `seq`, `acknum`, or `rst` on any line and the compiler does exactly what you said, even if the RFC would object:

```frameassembly
host scanner { ip 10.30.0.10 }
host backend { ip 10.30.0.20 }

flow firewall_state_test(c, s) {
    c -> s tcp syn srcport 54000 dstport 8080 win 65535 mss 1460 wait 1ms
    c <- s tcp syn ack win 65535 mss 1460 wait 1ms
    c -> s tcp ack wait 1ms

    c -> s http post uri "/upload" hosthdr "ingest.local" body "BATCH_01" wait 2ms
    c <- s tcp ack win 0 wait 50ms

    // Out-of-window segment to verify stateful firewall drop counters
    c -> s tcp psh ack seq 900000 acknum 1 payload "OUT_OF_WINDOW_PROBE" wait 5ms
    c <- s tcp rst ack
}

compile { firewall_state_test(scanner, backend) }
```

## 5. VLAN Trunks, QinQ, MPLS, QoS and Fragments

Desktop network stacks and NIC drivers quietly strip VLAN tags and refuse to send `QinQ`, `MPLS`, or hand-made fragments, which makes lab testing a guessing game. Here the tags are just modifiers you add to **any** packet statement:

| Feature | `.frasm` Modifier | Example / Range | What Goes on the Wire |
| :--- | :--- | :--- | :--- |
| **802.1Q VLAN & CoS** | `vlan <1..4094> [pcp <0..7>] [dei <0..1>]` | `vlan 110 pcp 5` | 802.1Q tag (`0x8100`) + 802.1p priority |
| **802.1ad QinQ** | `qinq <s_vid> innervlan <c_vid>` | `qinq 2000 innervlan 110` | S-VLAN (`0x88a8`) + C-VLAN (`0x8100`) |
| **MPLS Label** | `mpls <lbl> [exp <0..7>] [bos <0\|1>] [mplsttl <n>]` | `mpls 16000 exp 5` | MPLS shim header (`0x8847`) |
| **Outer Ethernet** | `srcmac <mac>` / `dstmac <mac>` / `ethertype <u16>` | `ethertype 0x88b5` | Custom Ethernet MACs or EtherType |
| **Hop Limit & QoS** | `ttl <0..255>` / `dscp <0..63>` / `ecn <0..3>` | `ttl 64 dscp 46` | IPv4 TTL or IPv6 Hop Limit + DiffServ (`46` = `EF`) |
| **IPv6 Flow Label** | `flowlabel <0..1048575>` | `flowlabel 0x1a2b3` | 20-bit IPv6 ECMP Flow Label (ignored on IPv4) |
| **IPv4 Fragments** | `df` / `ipid <u16>` / `mf` / `fragoffset <0..8191>` | `ipid 0x7788 mf fragoffset 0` | PMTUD Don't Fragment (`df`) or 8-byte fragment offsets |
| **Ports & Transport** | `srcport <p>` / `dstport <p>` / `transport tcp\|udp` | `transport tcp` | Custom L4 ports or TCP/UDP switch (e.g., TCP Syslog/DNS) |

```frameassembly
host branch_edge { ip 172.16.100.10 mac 00:1c:73:aa:00:10 }
host core_pe     { ip 172.16.100.1  mac 00:1c:73:aa:00:01 }

flow trunk_and_wan_tags(edge, pe) {
    // Voice VLAN 110 with 802.1p CoS 5 + DiffServ EF (DSCP 46)
    edge -> pe vlan 110 pcp 5 dei 0 dscp 46 rtp pt 0 seq 1 timestamp 160 ssrc 0x10203040 payload "VOICE_20MS" wait 5ms

    // Carrier 802.1ad QinQ double tag + MPLS L3VPN shim label
    edge -> pe qinq 2000 innervlan 110 dscp 26 udp srcport 50000 dstport 9000 payload "METRO_ETH" wait 5ms
    edge -> pe mpls 16000 exp 5 bos 1 mplsttl 63 ttl 63 dscp 46 icmp echorequest id 50 seq 1 payload "L3VPN_PING" wait 5ms

    // Path MTU Don't Fragment (DF) probe + 2-part IPv4 fragmented ping
    edge -> pe df ipid 0x4400 ttl 64 icmp echorequest id 51 seq 1 payload "PMTUD_DF_PROBE" wait 5ms
    edge -> pe ipid 0x7788 mf fragoffset 0 icmp echorequest id 52 seq 1 payload "FIRST_8B_SECOND8" wait 1ms
    edge -> pe ipid 0x7788 fragoffset 2 icmp echorequest id 52 seq 1 payload "FINAL_FRAGMENT_B"
}

compile { trunk_and_wan_tags(branch_edge, core_pe) }
```

## 6. Reusing Flows Across IPv4 and IPv6

A `flow` refers to roles, not addresses, so the same exchange runs unchanged over IPv4 and IPv6 host pairs. Call it several times inside `compile { ... }` and you have a heartbeat generator:

```frameassembly
host sensor_v4    { ip 10.50.0.10 }
host collector_v4 { ip 10.50.0.100 }
host sensor_v6    { ip 2001:db8:50::10 }
host collector_v6 { ip 2001:db8:50::100 }

flow heartbeat_and_log(node, col) {
    node -> col vlan 50 dscp 16 ttl 64 flowlabel 0x1a2b3 icmp echorequest id 90 seq 1 payload "HB" wait 2ms
    node <- col vlan 50 dscp 16 ttl 64 flowlabel 0x1a2b3 icmp echoreply   id 90 seq 1 payload "HB" wait 5ms
    node -> col vlan 50 dscp 16 ttl 64 flowlabel 0x1a2b3 syslog facility 16 severity 6 hostname "edge-01" app "healthd" msg "Link OK" wait 10ms
}

compile {
    heartbeat_and_log(sensor_v4, collector_v4)
    heartbeat_and_log(sensor_v6, collector_v6)
    heartbeat_and_log(sensor_v4, collector_v4)
}
```

## 7. Wireshark and `tcpdump` to `.frasm` Cheat Sheet

Muscle memory will make you type `sport` instead of `srcport`, `ack 100` instead of `acknum 100`, or `ECHO_REQUEST` instead of `echorequest`. FrameAssembly refuses to write a broken `.pcap` and tells you the fix (VS Code adds a 1-click Quick Fix):

```text
frameassembly::parse_error

  × Failed to parse input: Syntax error: unexpected token 'sport', expected a valid statement
  │ or protocol modifier (such as srcport, dstport, seq, acknum, win, or tcp flags).
   ╭─[test.frasm:5:16]
 4 │ flow check(c, s) {
 5 │     c -> s tcp sport 50000 dstport 80 syn
   ·                ──┬──
   ·                  ╰── Here
   ╰────
  help: Replace 'sport' with 'srcport <port>' (for example: srcport 51234).
```

The filters you already type, next to their `.frasm` equivalents:

| What You Want | Wireshark Filter | `tcpdump` Filter | `.frasm` Code |
| :--- | :--- | :--- | :--- |
| **Host IP & MAC** | `ip.addr == 10.0.0.1` | `host 10.0.0.1` | `host rtr { ip 10.0.0.1 mac 00:1a:2b:3c:4d:5e }` |
| **802.1Q VLAN & CoS** | `vlan.id == 100 && vlan.priority == 5` | `vlan 100` | `vlan 100 pcp 5 dei 0` |
| **802.1ad QinQ** | `vlan.id == 2000 && vlan.id == 100` | `vlan 2000 and vlan 100` | `qinq 2000 innervlan 100` |
| **MPLS Label** | `mpls.label == 16000` | `mpls 16000` | `mpls 16000 exp 5 bos 1 mplsttl 64` |
| **QoS `DSCP` / `ECN`** | `ip.dsfield.dscp == 46` | `ip[1] & 0xfc == 0xb8` | `dscp 46 ecn 2` |
| **TTL / Hop Limit** | `ip.ttl == 64` / `ipv6.hlim == 64` | `ip[8] == 64` | `ttl 64` |
| **Ports & TCP Flags** | `tcp.dstport == 443 && tcp.flags.syn == 1` | `dst port 443` | `tcp syn srcport 52000 dstport 443` |
| **TCP Seq / Ack / Win** | `tcp.seq == 1000 && tcp.ack == 2000` | `tcp[4:4] == 1000` | `seq 1000 acknum 2000 win 65535` |
| **HTTP Host Header** | `http.host == "api.local"` | `port 80` | `http get uri "/" hosthdr "api.local"` |
| **Packet Delay** | `frame.time_delta` | `-tt` | `wait 500us` / `wait 5ms` / `wait 1s` |

## 8. Generating `.frasm` Code with AI Assistants (Copy-Paste Prompt)

If you would rather describe the scenario than type it, ChatGPT, Claude, Copilot, and Gemini can draft `.frasm` code too, provided they know the rules. Paste the block below into your chat and replace the last line with your scenario:

```text
Write valid FrameAssembly v3.0.0 (.frasm) network packet code following these strict rules:
1. Structure: Declare endpoints with `host <name> { [ip <addr>] [mac <mac>] }`, optional flows with `flow <name>(a, b) { ... }`, and exactly one `compile { ... }` block at the end calling flows or inline packet statements.
2. Strict Lowercase Keywords: Every built-in keyword, protocol, modifier, and time unit (`ns`, `us`, `ms`, `s`, `m`) MUST be lowercase alphanumeric (`[a-z0-9]+`) with ZERO underscores and ZERO hyphens (e.g., `echorequest`, `echoreply`, `innervlan`, `mplsttl`, `sackperm`, `clienthello`, `serverhello`, `hosthdr`, `useragent`, `contenttype`, `readholdingregisters`, `isresponse`). User-defined host/flow/parameter names may use `_` or `-`.
3. Never Use Invalid Syntax: Never use `=`, `:`, `,`, or `/24` CIDR inside `host`; never use `sport`/`dport` (use `srcport`/`dstport`); never use `ack <n>` for acknowledgment numbers (use `acknum <n>`); never write standalone `wait` lines or `+5ms` (append `wait 2ms` at the end of a packet line); never use `loop` blocks (invoke flows or packet lines directly inside `compile { ... }`); never mix IPv4 and IPv6 hosts on the same line; use `//` comments and double quotes `"..."`.
4. Reference Example:
host client { ip 10.0.0.10 mac 00:11:22:33:44:55 }
host server { ip 10.0.0.20 mac aa:bb:cc:dd:ee:ff }
flow check(c, s) {
    c -> s vlan 100 tcp syn srcport 51000 dstport 443 win 65535 mss 1460 wait 1ms
    c <- s vlan 100 tcp syn ack win 65535 mss 1460 wait 1ms
    c -> s vlan 100 tcp ack wait 1ms
    c -> s vlan 100 tls clienthello sni "app.example.com" ciphersuite 4866 alpn "h2" wait 2ms
}
compile { check(client, server) }

Task: [DESCRIBE YOUR NETWORK SCENARIO HERE]
```

Need all 81 protocol keywords and syntax rules inside your chat prompt? Attach or paste [`llms-full.txt`](https://raw.githubusercontent.com/SteveWinschel/FrameAssembly/main/llms-full.txt) (or point search-enabled assistants at [`llms.txt`](https://raw.githubusercontent.com/SteveWinschel/FrameAssembly/main/llms.txt)).
