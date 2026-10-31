# FrameAssembly DSL Support (v1.3.0)

Provides full syntax highlighting, code snippets, and language tooling for FrameAssembly (`.fasm`) files in VS Code, Cursor, Windsurf, VSCodium, and Antigravity IDE.

## Features

- **81 Native Protocols:** Complete syntax highlighting for all 81 Layer 2, Layer 3, Layer 4, and Layer 7 protocols (including Ethernet, VLAN, QinQ, MPLS, IPv4, IPv6, ICMP, NDP, GRE, VXLAN, IPsec, OSPF, BGP, TCP, UDP, SCTP, SNMPv1/v2c/v3, DNS, HTTP, TLS, QUIC, Modbus, BACnet, S7comm, and more).
- **16 Built-In Tab-Completable Snippets:** Instant templates for complete `.fasm` programs (`fasm-skeleton`, `fasm-tcp-http`, `fasm-snmpv3`, `fasm-vlan`, `fasm-qinq`, `fasm-dns`, `fasm-dhcp`, `fasm-icmp`, `fasm-arp`, `fasm-bgp`, `fasm-ospf`, `fasm-vxlan`, `fasm-wireguard`, `fasm-modbus`, `fasm-syslog`) plus individual `host`, `flow`, and `compile` blocks.
- **Comprehensive Modifiers & Sub-Keywords:** Full coverage of over 180 protocol sub-keywords, frame modifiers (VLAN PCP/DEI, MPLS EXP/BOS/TTL, IPv4/IPv6 TTL, DSCP, ECN, Flow Labels, fragmentation, TCP options, SCTP chunks).
- **Dual-Stack & Multi-Format MAC Addressing:** Native highlighting for IPv4 dotted-quads, full/compressed/mapped IPv6 addresses, and colon-separated (`00:1a:2b:3c:4d:5e`), hyphen-separated (`00-1A-2B-3C-4D-5E`), and Cisco IOS dotted-quad (`001a.2b3c.4d5e`) MAC addresses.
- **Timing & Numeric Formats:** Support for duration units (`ns`, `us`, `ms`, `s`, `m`), hexadecimal integer literals (`0x...`), and dotted SNMP OID notation.
- **Language Structure:** Distinct styling for structural declarations (`HOST`, `FLOW`, `COMPILE`, `LOOP`), transmission direction arrows (`->`, `<-`), and quoted string payloads.

## Usage

Open any `.fasm` file in VS Code or Antigravity IDE. The extension activates automatically and applies the `source.fasm` TextMate grammar and snippets.

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

## License

MIT License. Copyright (c) 2026 Steve Winschel.
