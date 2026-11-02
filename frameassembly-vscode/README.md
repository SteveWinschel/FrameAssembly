# FrameAssembly (.fasm Packet Crafting DSL) Support (v1.4.3)

Case-insensitive syntax highlighting, Markdown code block injection (```` ```frameassembly ```` and ```` ```fasm ````), and 16 tab-completable snippets for FrameAssembly (`.fasm`, `text/vnd.frameassembly`) — the declarative **Packets as Code** DSL that compiles `.fasm` code into deterministic `.pcap` / `.pcapng` captures for pentesting, testing firewalls, simulating SNMP traps, and validating network monitoring and cybersecurity solutions in Visual Studio Code, Cursor, Windsurf, VSCodium, and Antigravity IDE.

---

## Example `.fasm` Workflows

### Pentesting, Testing Firewall ACLs & Validating Cybersecurity / IDS Rules

Write readable `.fasm` code and let the compiler calculate Ethernet headers, IPv4/IPv6 lengths, UDP/TCP pseudo-header checksums, and stateful sequence numbers offline in unprivileged user space—without root sockets (`CAP_NET_RAW`), brittle Python `Scapy` virtualenvs, or counting hex byte offsets by hand in `text2pcap`:

```frameassembly
host client { ip 192.168.1.100 }
host server { ip 8.8.8.8 }

flow dns_resolve(c, s) {
    c -> s dns query txid 0x1a2b qname "example.com" qtype "A"
    c <- s dns response txid 0x1a2b qname "example.com" qtype "A" rdata "93.184.216.34"
}

compile {
    dns_resolve(client, server)
}
```

```console
$ frameassembly dns.fasm -o dns.pcap
```

### Simulate SNMPv1/v2c & Encrypted SNMPv3 `authPriv` Traps on Demand

Waiting for a core router interface to fail just to verify an NMS alert rule is nobody's idea of a good afternoon. FrameAssembly derives RFC 3414/3826/7860 localized keys (`Ku -> Kul`), computes HMAC-SHA-256 digests, and encrypts `AES-128-CFB` / `DES-CBC` varbind payloads directly into a capture file you can replay with `tcpreplay`:

```frameassembly
host router { ip 10.151.0.1 }
host soc    { ip 10.151.0.250 }

flow snmpv3_trap(r, s) {
    r -> s snmp3 trap user "admin" engineid "80001f8880510001" auth sha256 "authpass123" priv aes "privpass123" oid 1.3.6.1.6.3.1.1.5.3
}

compile {
    snmpv3_trap(router, soc)
}
```

```console
$ frameassembly trap.fasm -o trap.pcap && tcpreplay -i eth0 trap.pcap
```

### Verify 802.1Q `vlan`, 802.1ad `qinq`, `mpls` & `dscp` QoS Markings

OS network card drivers love stripping 802.1Q and QinQ tags before live capture tools ever see them. FrameAssembly writes outer service tags, inner customer VLANs, MPLS label stacks, and `dscp` priority markings straight into the `.pcapng` file so every header bit survives intact:

```frameassembly
host hub    { ip 10.99.1.1 }
host branch { ip 10.99.1.2 }

flow qinq_flow(h, b) {
    h -> b qinq 850 inner_vlan 12 icmp echo_request
    h <- b qinq 850 inner_vlan 12 icmp echo_reply
}

compile {
    qinq_flow(hub, branch)
}
```

```console
$ frameassembly trunk.fasm -o trunk.pcap && tshark -r trunk.pcap -V
```

---

## Features

- **Case-Insensitive Highlighting Across 81 Native Protocols:** Write `.fasm` code in lowercase (`host`, `flow`, `tcp`, `syn`), uppercase (`HOST`, `FLOW`, `TCP`, `SYN`), or mixed case across all 81 Layer 2 through Layer 7 protocols (Ethernet, VLAN, QinQ, MPLS, IPv4, IPv6, ICMP, NDP, GRE, VXLAN, IPsec, OSPF, BGP, TCP, UDP, SCTP, SNMPv1/v2c/v3, DNS, HTTP, TLS, QUIC, Modbus, BACnet, S7comm, and more).
- **Markdown Fenced Code Block Highlighting:** Automatically highlights ```` ```frameassembly ```` and ```` ```fasm ```` code blocks inside `.md` documentation files and runbooks (`markdown.frameassembly.codeblock`).
- **16 Built-In Tab-Completable Snippets:** Instant lowercase templates for complete `.fasm` programs and protocol exchanges (`fasm`, `host`, `tcp-handshake`, `snmp2-trap`, `snmp3-trap`, `http-get`, `dns-query`, `dhcp-dora`, `vlan-qos`, `qinq`, `bgp-open`, `ospf-hello`, `modbus-poll`, `firewall-rst`, `icmp-ping`, `vxlan-overlay`).
- **Comprehensive Modifiers & Sub-Keywords:** Full coverage of over 640 protocol keywords, flags, and frame modifiers (VLAN PCP/DEI, MPLS EXP/BOS/TTL, IPv4/IPv6 TTL, DSCP, ECN, Flow Labels, fragmentation, TCP options, SCTP chunks).
- **Dual-Stack & Multi-Format MAC Addressing:** Native highlighting for IPv4 dotted-quads, full/compressed/mapped IPv6 addresses, and colon-separated (`00:1a:2b:3c:4d:5e`), hyphen-separated (`00-1A-2B-3C-4D-5E`), and Cisco IOS dotted-quad (`001a.2b3c.4d5e`) MAC addresses.
- **Timing & Numeric Formats:** Support for duration units (`ns`, `us`, `ms`, `s`, `m`), hexadecimal integer literals (`0x...`), and dotted SNMP OID notation.
- **Language Structure:** Distinct styling for structural declarations (`host`, `flow`, `compile`, `loop`), transmission direction arrows (`->`, `<-`), and quoted string payloads.
- **Standardized MIME & Scope:** Bound to the official `text/vnd.frameassembly` media type and `source.frameassembly` TextMate scope.

---

## Usage

Open any `.fasm` file (or any Markdown file with ```` ```frameassembly ```` / ```` ```fasm ```` blocks) in VS Code, Cursor, Windsurf, VSCodium, or Antigravity IDE. The extension activates automatically and applies the `source.frameassembly` TextMate grammar and snippets.

To install both the `frameassembly` CLI compiler and this editor extension in a single command (without cloning the repository):

```bash
curl -fsSL https://raw.githubusercontent.com/SteveWinschel/FrameAssembly/main/install.sh | sh
```

Or install the CLI compiler directly via Cargo and compile `.fasm` files into `.pcap` captures:

```bash
cargo install frameassembly
frameassembly show capture.fasm
frameassembly capture.fasm -o output.pcap
```

---

## License

MIT License. Copyright (c) 2026 Steve Winschel.
