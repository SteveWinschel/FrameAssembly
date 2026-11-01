# FrameAssembly (.fasm Packet Crafting DSL) Support (v1.4.2)

Comprehensive syntax highlighting, 16 tab-completable snippets, and language tooling for FrameAssembly (`.fasm`, `text/vnd.frameassembly`) network packet specifications in Visual Studio Code, Cursor, Windsurf, VSCodium, and Antigravity IDE.

---

## Example `.fasm` Workflows

### Create a Custom `.pcap` Capture from Plain Text (No Root or Python)

Write a declarative `.fasm` recipe with automatic RFC checksums and compile it in unprivileged user space—without Python `Scapy` scripts, `CAP_NET_RAW` root permissions, or raw hexadecimal byte offsets in `text2pcap`:

```frameassembly
HOST client { IP 192.168.1.100 }
HOST server { IP 8.8.8.8 }

FLOW dns_resolve(c, s) {
    c -> s DNS QUERY TXID 0x1a2b QNAME "example.com" QTYPE "A"
    c <- s DNS RESPONSE TXID 0x1a2b QNAME "example.com" QTYPE "A" RDATA "93.184.216.34"
}

COMPILE {
    dns_resolve(client, server)
}
```

```console
$ frameassembly dns.fasm -o dns.pcap
```

### Test SNMPv1/v2c & Encrypted SNMPv3 `authPriv` Trap Receivers

FrameAssembly handles RFC 3414/3826/7860 key derivation (`Ku -> Kul`), localized auth HMACs, and `DES-CBC`/`AES-128-CFB` encryption automatically with zero manual ASN.1 math:

```frameassembly
HOST router { IP 10.151.0.1 }
HOST soc    { IP 10.151.0.250 }

FLOW snmpv3_trap(r, s) {
    r -> s SNMP3 TRAP USER "admin" ENGINEID "80001f8880510001" AUTH SHA256 "authpass123" PRIV AES "privpass123" OID 1.3.6.1.6.3.1.1.5.3
}

COMPILE {
    snmpv3_trap(router, soc)
}
```

```console
$ frameassembly trap.fasm -o trap.pcap && tcpreplay -i eth0 trap.pcap
```

### Craft 802.1Q `VLAN`, 802.1ad `QinQ`, `MPLS` & `DSCP` QoS Packets

Write inner and outer VLAN tags, MPLS labels, and `DSCP` priority fields directly into the `.pcap` file without OS NIC drivers stripping VLAN tags:

```frameassembly
HOST hub    { IP 10.99.1.1 }
HOST branch { IP 10.99.1.2 }

FLOW qinq_flow(h, b) {
    h -> b QINQ 850 INNER_VLAN 12 ICMP ECHO_REQUEST
    h <- b QINQ 850 INNER_VLAN 12 ICMP ECHO_REPLY
}

COMPILE {
    qinq_flow(hub, branch)
}
```

```console
$ frameassembly trunk.fasm -o trunk.pcap && tshark -r trunk.pcap -V
```

---

## Features

- **81 Native Protocols:** Complete syntax highlighting for all 81 Layer 2, Layer 3, Layer 4, and Layer 7 protocols (including Ethernet, VLAN, QinQ, MPLS, IPv4, IPv6, ICMP, NDP, GRE, VXLAN, IPsec, OSPF, BGP, TCP, UDP, SCTP, SNMPv1/v2c/v3, DNS, HTTP, TLS, QUIC, Modbus, BACnet, S7comm, and more).
- **16 Built-In Tab-Completable Snippets:** Instant templates for complete `.fasm` programs (`fasm-skeleton`, `fasm-tcp-http`, `fasm-snmpv3`, `fasm-vlan`, `fasm-qinq`, `fasm-dns`, `fasm-dhcp`, `fasm-icmp`, `fasm-arp`, `fasm-bgp`, `fasm-ospf`, `fasm-vxlan`, `fasm-wireguard`, `fasm-modbus`, `fasm-syslog`) plus individual `host`, `flow`, and `compile` blocks.
- **Comprehensive Modifiers & Sub-Keywords:** Full coverage of over 180 protocol sub-keywords, frame modifiers (VLAN PCP/DEI, MPLS EXP/BOS/TTL, IPv4/IPv6 TTL, DSCP, ECN, Flow Labels, fragmentation, TCP options, SCTP chunks).
- **Dual-Stack & Multi-Format MAC Addressing:** Native highlighting for IPv4 dotted-quads, full/compressed/mapped IPv6 addresses, and colon-separated (`00:1a:2b:3c:4d:5e`), hyphen-separated (`00-1A-2B-3C-4D-5E`), and Cisco IOS dotted-quad (`001a.2b3c.4d5e`) MAC addresses.
- **Timing & Numeric Formats:** Support for duration units (`ns`, `us`, `ms`, `s`, `m`), hexadecimal integer literals (`0x...`), and dotted SNMP OID notation.
- **Language Structure:** Distinct styling for structural declarations (`HOST`, `FLOW`, `COMPILE`, `LOOP`), transmission direction arrows (`->`, `<-`), and quoted string payloads.
- **Standardized MIME & Scope:** Bound to the official `text/vnd.frameassembly` media type and `source.frameassembly` TextMate scope.

---

## Usage

Open any `.fasm` file in VS Code, Cursor, Windsurf, VSCodium, or Antigravity IDE. The extension activates automatically and applies the `source.frameassembly` TextMate grammar and snippets.

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
