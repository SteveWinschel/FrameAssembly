# FrameAssembly DSL Support (v1.1.0)

Provides full syntax highlighting and language tooling for FrameAssembly (`.fasm`) files in VS Code and Antigravity IDE.

## Features

- **81 Native Protocols:** Complete syntax highlighting for all 81 Layer 2, Layer 3, Layer 4, and Layer 7 protocols (including Ethernet, VLAN, QinQ, MPLS, IPv4, IPv6, ICMP, NDP, GRE, VXLAN, IPsec, OSPF, BGP, TCP, UDP, SCTP, SNMPv1/v2c/v3, DNS, HTTP, TLS, QUIC, Modbus, BACnet, S7comm, and more).
- **Comprehensive Modifiers & Sub-Keywords:** Full coverage of over 180 protocol sub-keywords, frame modifiers (VLAN PCP/DEI, MPLS EXP/BOS/TTL, IPv4/IPv6 TTL, DSCP, ECN, Flow Labels, fragmentation, TCP options, SCTP chunks).
- **Dual-Stack Addressing:** Native highlighting for IPv4 dotted-quads, full/compressed/mapped IPv6 addresses, and IEEE 802 MAC addresses.
- **Timing & Numeric Formats:** Support for duration units (`ns`, `us`, `ms`, `s`, `m`), hexadecimal integer literals (`0x...`), and dotted SNMP OID notation.
- **Language Structure:** Distinct styling for structural declarations (`HOST`, `FLOW`, `COMPILE`, `LOOP`), transmission direction arrows (`->`, `<-`), and quoted string payloads.

## Usage

Open any `.fasm` file in VS Code or Antigravity IDE. The extension activates automatically and applies the `source.fasm` TextMate grammar.

To build and compile `.fasm` source files into deterministic `.pcap` captures, install the FrameAssembly CLI compiler:

```bash
cargo install frameassembly
frameassembly capture.fasm -o output.pcap
```

## License

MIT License. Copyright (c) 2026 Steve Winschel.
