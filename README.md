# FrameAssembly (`frameassembly`)

[![Crates.io](https://img.shields.io/crates/v/frameassembly.svg)](https://crates.io/crates/frameassembly)
[![Docs.rs](https://docs.rs/frameassembly/badge.svg)](https://docs.rs/frameassembly)
[![Rust 1.85+](https://img.shields.io/badge/rust-1.85%2B%20(Edition%202024)-orange.svg)](https://www.rust-lang.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

[**Quickstart**](#quickstart) • [**Why FrameAssembly?**](#why-frameassembly) • [**Syntax Guide**](#syntax-guide) • [**All 81 Protocols (Defaults)**](#supported-protocols--default-wire-behavior) • [**Sub-Keyword Reference**](#exhaustive-protocol--sub-keyword-reference-all-81-protocols) • [**Documentation**](#documentation)

**FrameAssembly** (`frameassembly` v1.2.2) builds standard `.pcap` and `.pcapng` packet capture files from readable plain-text descriptions (`.fasm`) across **81 network protocols spanning Layers 2 through 7**.

You define the hosts in your scenario and list the frames exchanged between them using familiar networking terms—IPs, MACs, VLAN tags, TCP flags, routing attributes, or application fields. FrameAssembly handles the binary packet framing, byte lengths, checksums, and TCP sequence tracking automatically, producing a clean `.pcap` file ready to inspect in **Wireshark** / `tshark` or send onto a network interface with **`tcpreplay`**.

---

## Why FrameAssembly?

Tools like **Wireshark** and **`tcpdump`** record traffic that already exists on a network, and **`tcpreplay`** transmits existing `.pcap` files over a network interface—but neither helps when the packet capture you need doesn't exist yet.

Building custom `.pcap` files from scratch usually forces an awkward trade-off:
* **Writing Python scripts (`Scapy`)** and manually managing TCP sequence numbers, return ports, and nested protocol objects in code.
* **Editing raw hex dumps (`text2pcap`)** where changing a single field breaks byte offsets, header lengths, and checksums.
* **Building a physical or virtual lab** just to capture a specific protocol handshake, error condition, or alert—while filtering out background LAN chatter.

FrameAssembly gives you direct, bit-level control over packet headers through a readable text format that looks like a network diagram:

* **Test firewalls, ACLs, and IDS/IPS sensors:** Craft exact TCP flag combinations, blocked-port probes, fragmented IPv4 packets, or double-tagged VLAN/QinQ frames and replay them against an appliance with `tcpreplay`.
* **Verify monitoring, SIEM, and flow collectors:** Generate valid SNMPv1/v2c/v3 traps, Syslog alerts, or NetFlow/IPFIX/sFlow exports without waiting for real hardware faults.
* **Simulate routing, overlays, VoIP, and OT/SCADA traffic:** Build BGP, OSPF, VXLAN, IPsec, WireGuard, TLS 1.3, SIP/RTP, or industrial PLC captures (Modbus, S7comm, DNP3, OPC UA) without physical lab equipment.
* **Share reproducible, zero-noise captures:** Check a 15-line `.fasm` text file into Git or attach it to a ticket instead of passing around noisy binary `.pcap` dumps.

| Capability | FrameAssembly (`.fasm`) | Python (`Scapy`) | `text2pcap` / Hex Editors | Live Lab Capture (`tcpdump`) |
| :--- | :--- | :--- | :--- | :--- |
| **How Traffic Is Defined** | Plain-text host & packet lines | Python scripts | Raw hexadecimal byte dumps | Live devices or VMs |
| **Scripting / Coding Needed** | **None** — standard networking terms | Python programming required | Manual hex & byte-offset math | Full lab/device configuration |
| **Low-Level Header Control** | Any L2–L7 field (VLANs, flags, QoS, TTL, payloads) | Nested code constructors | Manual bit-by-bit hex editing | Difficult to force edge cases |
| **Unset Optional Fields** | Filled with valid RFC defaults automatically | Varies by layer | None (every byte written by hand) | OS / device dependent |
| **TCP `SEQ`/`ACK` & Return Ports** | **Tracked & swapped automatically** | Manual math per packet | Manual hex recalculation | Handled by OS kernel |
| **Checksums, Lengths & Crypto** | **Automatic** (IP, L4, CRC32c, ASN.1, SNMPv3) | Manual setup for stateful/crypto | Limited dummy headers | Handled by OS / NIC |
| **Privileges & Capture Noise** | Normal user; **zero background noise** | Root needed for raw socket send | Normal user | Root required; includes LAN chatter |

---

## Quickstart

### 1. Install `frameassembly`

**Cross-Platform Installer (Linux, macOS & BSDs):**
Checks for required build tools, sets up the Rust toolchain if missing, installs `frameassembly` from Crates.io, and installs the VS Code `.fasm` syntax extension if `code` is on `PATH`:

```bash
curl -fsSL [https://raw.githubusercontent.com/SteveWinschel/FrameAssembly/main/install.sh](https://raw.githubusercontent.com/SteveWinschel/FrameAssembly/main/install.sh) | sh
```

**Or install directly via Cargo (Rust `>= 1.85`):**

```bash
cargo install frameassembly
```

### 2. Write a Traffic Specification (`demo.fasm`)

Every protocol works out of the box with standard RFC defaults—you only write the fields you want to customize:

```frameassembly
// Define the endpoints
host client { ip 10.0.0.10 mac 00:11:22:33:44:55 }
host server { ip 10.0.0.80 mac aa:bb:cc:dd:ee:ff }

// List the packets exchanged between them (1 line = 1 frame)
flow web_session(c, s) {
    c -> s tcp syn srcport 51234 dstport 80 win 65535 mss 1460 wait 1ms
    c <- s tcp syn ack win 65535 mss 1460 wait 1ms
    c -> s tcp ack wait 1ms
    c -> s http get uri "/index.html" host_hdr "example.com" wait 5ms
    c <- s http status 200 reason "OK" body "<h1>Hello</h1>" wait 2ms
}

// Build the capture
compile {
    web_session(client, server)
}
```

### 3. Compile to `.pcap`, Inspect & Replay

```console
$ frameassembly demo.fasm -o output.pcap
Successfully parsed 2 hosts, 1 flows
Starting PCAP compilation...
Successfully generated output.pcap

$ tshark -r output.pcap
    1 0.000000000    10.0.0.10 → 10.0.0.80    TCP 58 51234 → 80 [SYN] Seq=0 Win=65535 Len=0 MSS=1460
    2 0.001000000    10.0.0.80 → 10.0.0.10    TCP 58 80 → 51234 [SYN, ACK] Seq=0 Ack=1 Win=65535 Len=0 MSS=1460
    3 0.002000000    10.0.0.10 → 10.0.0.80    TCP 54 51234 → 80 [ACK] Seq=1 Ack=1 Win=65535 Len=0
    4 0.003000000    10.0.0.10 → 10.0.0.80    HTTP 97 GET /index.html HTTP/1.1
    5 0.008000000    10.0.0.80 → 10.0.0.10    HTTP 126 HTTP/1.1 200 OK  (text/html)
```

Once verified in Wireshark or `tshark`, you can transmit the `.pcap` over a live network interface with `tcpreplay`:

```bash
sudo tcpreplay -i eth0 output.pcap
```

What FrameAssembly handled behind the scenes:
* **Return Port Swapping:** `51234 -> 80` on `c -> s` automatically reversed to `80 -> 51234` on `c <- s` without retyping port numbers.
* **Automatic TCP `SEQ` & `ACK` Progression:** The `http` request and response automatically reused the established TCP session, emitted `PSH, ACK` segments, and incremented `Seq` and `Ack` counters by exact payload byte lengths.
* **Checksums & Nanosecond Timing:** Ethernet headers, IPv4/TCP checksums, HTTP `Content-Length`, and `wait` timestamp offsets (`0.001s`, `0.002s`, `0.003s`, `0.008s`) were calculated automatically.

---

## Syntax Guide

### 1. `host`, `flow` & `compile` Blocks

FrameAssembly syntax is completely **case-insensitive** across all keywords, protocol names, modifiers, time units (`ns`, `us`, `ms`, `s`, `m`), and identifiers (`host` or `HOST`, `tcp` or `TCP`). Single-line comments start with `//`.

* **`host <name> { ip <address> [mac <mac>] }`**: Binds a symbolic name to an IPv4 or IPv6 address. If `mac` is omitted, a deterministic unicast MAC—or RFC 1112 (`01:00:5e:...`) / RFC 2464 (`33:33:...`) multicast MAC for multicast IPs—is derived automatically.
* **`flow <name>(<param1>, <param2>, ...) { ... }`**: Defines a reusable sequence of packets:
  * `A -> B`: `A` is the sender (source), `B` is the receiver (destination).
  * `A <- B`: `B` is the sender (source), `A` is the receiver (destination).
* **`compile { ... }`**: Generates packets by passing concrete hosts into your flows. Because flows don't hardcode IPv4 vs. IPv6, the same flow can be run with IPv4 hosts and IPv6 hosts, and repeated inside `loop <count> { ... }`:

```frameassembly
host client_v4  { ip 192.168.1.50 }
host server_v4  { ip 192.168.1.100 mac 00:11:22:33:44:55 }
host client_v6  { ip 2001:db8::10 }
host server_v6  { ip 2001:db8::100 }
host mdns_mcast { ip 224.0.0.251 }

flow tcp_handshake(client, server) {
    client -> server tcp syn srcport 50100 dstport 443 win 65535
    client <- server tcp syn ack win 65535 wait 1ms
    client -> server tcp ack wait 1ms
}

flow mdns_probe(node, mcast) {
    node -> mcast mdns query qname "_http._tcp.local" qtype "PTR" wait 2ms
}

compile {
    loop 2 {
        tcp_handshake(client_v4, server_v4)
        tcp_handshake(client_v6, server_v6)
    }
    mdns_probe(client_v4, mdns_mcast)
}
```

### 2. Universal Layer 2–4 Modifiers

Any packet statement can include Layer 2, Layer 3, Layer 4, payload, and timing modifiers—allowing you to wrap upper-layer protocols inside VLAN trunks, QinQ service tags, MPLS label stacks, QoS markings, or fragmented IPv4 packets:

| Category | Modifiers | Wire Effect |
| :--- | :--- | :--- |
| **Layer 2** | `SRCMAC <mac>`, `DSTMAC <mac>` | Override outer Ethernet source or destination MAC address |
| | `ETHERTYPE <u16>` | Override outer Ethernet Type field (e.g. `0x8100`, `0x8847`) |
| | `VLAN <1..4094> [PCP <0..7>] [DEI <0..1>]` | Add IEEE 802.1Q VLAN tag, priority (`PCP`), and drop indicator (`DEI`) |
| | `QINQ <1..4094> [INNER_VLAN <1..4094>]` | Add IEEE 802.1ad outer S-VLAN tag + inner C-VLAN tag |
| | `MPLS <label> [EXP <0..7>] [BOS <0..1>] [MPLS_TTL <u8>]` | Add MPLS shim header (`0x8847`) with label, Traffic Class, BOS, and TTL |
| **Layer 3** | `TTL <0..255>` | Set IPv4 Time-To-Live or IPv6 Hop Limit |
| | `DSCP <0..63>`, `ECN <0..3>` | Set DiffServ QoS Code Point (e.g. `46` = EF) and ECN congestion bits |
| | `FLOWLABEL <0..1048575>` | Set 20-bit IPv6 Flow Label (ignored on IPv4 statements) |
| | `IPID <u16>`, `DF`, `MF`, `FRAGOFFSET <u16>` | Set IPv4 Identification, Don't Fragment, More Fragments, and 8-byte offset |
| **Layer 4** | `SRCPORT <u16>`, `DSTPORT <u16>` | Override TCP, UDP, or SCTP source and destination port numbers |
| | `TRANSPORT TCP \| UDP` | Force TCP or UDP for dual-mode protocols (`DNS`, `SIP`, `NFS`, `SYSLOG`) |
| | `SEQ <u32>`, `ACKNUM <u32>`, `WIN <u16>` | Override TCP sequence number, ack number, and window size |
| | `MSS <u16>`, `WSCALE <u8>`, `SACK_PERM` | Add TCP Maximum Segment Size, Window Scale, and SACK Permitted options |
| | `TSVAL <u32>`, `TSECR <u32>`, `URGENT <u16>` | Set TCP Timestamps and Urgent Pointer |
| **Payload** | `PAYLOAD "<string>"` | Append text payload (supports `\r`, `\n`, `\t`, `\xHH` escapes) |
| | `HEXPAYLOAD "<hex>"` | Append raw hexadecimal bytes (e.g. `"deadbeef"`) |
| **Timing** | `WAIT <duration>` | Advance `.pcap` capture timestamp after emitting frame (`ns`, `us`, `ms`, `s`, `m`) |

### 3. Combining Cross-Layer Encapsulation & Application Protocols

```frameassembly
host branch_cpe { ip 10.220.1.10  mac 00:50:56:c0:01:10 }
host hq_gateway { ip 10.220.1.200 mac 00:50:56:c0:01:c8 }

// TLS 1.3 handshake carried over QinQ (2000/150) + MPLS (Label 40960) + DSCP EF (46)
flow metro_backhaul_tls(cpe, hq) {
    cpe -> hq qinq 2000 inner_vlan 150 pcp 6 mpls 40960 exp 6 bos 1 mpls_ttl 64 dscp 46 ttl 64 tls client_hello sni "vault.hq.example.com" ciphersuite 4866 alpn "h2" wait 5ms
    cpe <- hq qinq 2000 inner_vlan 150 pcp 6 mpls 40960 exp 6 bos 1 mpls_ttl 63 dscp 46 ttl 63 tls server_hello ciphersuite 4866 alpn "h2" wait 5ms
}

compile {
    metro_backhaul_tls(branch_cpe, hq_gateway)
}
```

### 4. CLI & Editor Options

```bash
# Default output is output.pcap, or specify a path with -o / --output
frameassembly demo.fasm -o output.pcap

# Install only the VS Code .vsix syntax highlighting extension without cloning:
curl -fsSLo /tmp/frameassembly.vsix [https://raw.githubusercontent.com/SteveWinschel/FrameAssembly/main/frameassembly-vscode/frameassembly-vscode-1.2.2.vsix](https://raw.githubusercontent.com/SteveWinschel/FrameAssembly/main/frameassembly-vscode/frameassembly-vscode-1.2.2.vsix) && code --install-extension /tmp/frameassembly.vsix && rm -f /tmp/frameassembly.vsix
```

---

## Supported Protocols & Default Wire Behavior

Every protocol can be used with **zero mandatory sub-keywords**, emitting RFC-compliant default wire headers when optional fields are omitted:

| Protocol | Layer | Transport | Default Port | Default Wire Behavior |
| :--- | :--- | :--- | :--- | :--- |
| `ARP` | L2 | Ethernet (`0x0806`) | N/A | Request, Hardware `1` (Ethernet), Protocol `0x0800` (IPv4); uses ICMPv6 Neighbor Solicitation on IPv6. |
| `VLAN` | L2 | Ethernet (`0x8100`) | N/A | IEEE 802.1Q tag, default VLAN ID `100`, `PCP 0`, `DEI 0`. |
| `QINQ` | L2 | Ethernet (`0x88A8`) | N/A | IEEE 802.1ad outer tag (`VLAN 100`) + 802.1Q inner tag (`VLAN 200`). |
| `LLDP` | L2 | Ethernet (`0x88CC`) | N/A | Multicast `01:80:c2:00:00:0e`, Chassis ID & Port ID TLVs, `TTL 120s`, End TLV. |
| `STP` | L2 | LLC/SNAP (`0x4242`) | N/A | Multicast `01:80:c2:00:00:00`, Configuration BPDU, Root ID, Bridge ID, `Cost 0`. |
| `LACP` | L2 | Ethernet (`0x8809`) | N/A | Multicast `01:80:c2:00:00:02`, Actor Info & Partner Info TLVs, Collector TLV. |
| `EAPOL` | L2 | Ethernet (`0x888E`) | N/A | IEEE 802.1X Version `1`, EAP-Packet Identity request/response. |
| `MPLS` | L2.5 | Ethernet (`0x8847`) | N/A | Label `16`, `EXP 0`, `BOS 1`, `TTL 64` unicast shim header. |
| `ICMP` | L3 | IP proto `1` / `58` | N/A | Echo Request (Type `8` for IPv4, Type `128` for IPv6), `ID 1`, `Seq 1`. |
| `NDP` | L3 | IPv6 ICMPv6 (`58`) | N/A | Neighbor Solicitation (Type `135`), Hop Limit `255`. |
| `IGMP` | L3 | IPv4 proto `2` | N/A | Membership Query to `224.0.0.1` (All Hosts), Max Resp Time `10.0s`. |
| `MLD` | L3 | IPv6 ICMPv6 (`58`) | N/A | Multicast Listener Query (Type `130`) to `ff02::1`. |
| `GRE` | L3 | IP proto `47` | N/A | GRE Version `0`, Protocol Type `0x0800` (IPv4) / `0x86DD` (IPv6). |
| `VXLAN` | L3 | UDP | `4789` | Flags `0x08` (`I` flag), 24-bit `VNI 1000`, 8-byte VXLAN header + inner frame. |
| `GENEVE` | L3 | UDP | `6081` | Version `0`, 24-bit `VNI 1000`, Protocol Type `0x6558` (Ethernet). |
| `IPSEC` | L3 | IP proto `50` | N/A | `SPI 0x1000`, `Sequence 1`, default ESP wire header. |
| `ESP` | L3 | IP proto `50` | N/A | Encapsulating Security Payload, `SPI 0x1000`, `Sequence 1`. |
| `AH` | L3 | IP proto `51` | N/A | Authentication Header, `SPI 0x1000`, `Sequence 1`, 96-bit ICV. |
| `IKEV2` | L3 | UDP | `500` | `SA_INIT` exchange (Type `34`), Initiator SPI set, Responder SPI `0`. |
| `WIREGUARD` | L3 | UDP | `51820` | Handshake Initiation message (Type `1`), Sender index `1`. |
| `OSPF` | L3 | IP proto `89` | N/A | OSPFv2 (IPv4) or OSPFv3 (IPv6) Hello packet, Area `0.0.0.0`, to `224.0.0.5` / `ff02::5`. |
| `BGP` | L3 | TCP | `179` | BGP-4 16-byte marker, `OPEN` message, `ASN 65001`, Hold Time `180s`. |
| `RIP` | L3 | UDP | `520` | RIPv2 Response (Command `2`), Version `2`, Route AFI `2` (IP), Metric `1`. |
| `VRRP` | L3 | IP proto `112` | N/A | VRRPv3 Advertisement, `VRID 1`, `Priority 100`, `TTL 255`. |
| `HSRP` | L3 | UDP | `1985` | Cisco HSRP Hello, State Active, `Group 1` to `224.0.0.2`. |
| `PIM` | L3 | IP proto `103` | N/A | PIM-SM Hello message, `DR Priority 1` to `224.0.0.13` / `ff02::d`. |
| `BFD` | L3 | UDP | `3784` | Single-hop Control packet, State `Up`, Detect Mult `3`, Min TX/RX `1000ms`. |
| `OPENFLOW` | L3 | TCP | `6653` | OpenFlow 1.3 (`0x04`) Hello / Features Request, `XID 1`. |
| `TCP` | L4 | IP proto `6` | `80` | Sequence numbers auto-incremented, `ACK` numbers tracked across reverse arrows. |
| `UDP` | L4 | IP proto `17` | `80` | Stateless UDP datagram with computed RFC 768 checksum. |
| `SCTP` | L4 | IP proto `132` | `80` | Verification Tag `0`, `DATA` chunk, `TSN 1`, `Stream 0`, CRC32c checksum. |
| `SNMP1` | L7 | UDP | `162` / `161` | Community `"public"`, `sysUpTime 0`, Trap/Poll PDU, RFC 1157 BER encoding. |
| `SNMP2` | L7 | UDP | `162` / `161` | Community `"public"`, `sysUpTime 0`, Trap/Poll PDU, RFC 3416 BER encoding. |
| `SNMP3` | L7 | UDP | `161` / `162` | USM security model, RFC 3414 / 3826 / 7860 authentication & privacy engine. |
| `DNS` | L7 | UDP / TCP | `53` | Standard Query, `TXID 0x1234`, `QNAME "example.com"`, `QTYPE A` / `AAAA`. |
| `MDNS` | L7 | UDP | `5353` | Multicast DNS Query (`TXID 0`) to `224.0.0.251` / `ff02::fb`. |
| `DHCP` | L7 | UDP | `67`/`68` (`546`/`547` v6) | `DHCPDISCOVER` (IPv4) or `Solicit` (IPv6) with client MAC. |
| `NTP` | L7 | UDP | `123` | Mode `3` (Client), Version `4`, Stratum `0`, Poll `4`. |
| `PTP` | L7 | UDP | `319` / `320` | IEEE 1588-2008 Version `2` `Sync` message, Domain `0`. |
| `RADIUS` | L7 | UDP | `1812` / `1813` | `Access-Request` (Code `1`, port `1812`; Accounting on `1813`), `Identifier 1`. |
| `TACACS` | L7 | TCP | `49` | TACACS+ Authentication Start, `Session ID 0x12345678`. |
| `SYSLOG` | L7 | UDP / TCP | `514` | RFC 5424 PRI `<14>` (Facility `1` User, Severity `6` Info), `APP "frameassembly"`. |
| `NETFLOW` | L7 | UDP | `2055` | Cisco NetFlow v5 Flow Record export packet. |
| `IPFIX` | L7 | UDP | `4739` | RFC 7011 IPFIX Observation Domain & Data Record packet. |
| `SFLOW` | L7 | UDP | `6343` | sFlow v5 Flow Sample datagram. |
| `TFTP` | L7 | UDP | `69` | Read Request (`RRQ`), `Filename "file.bin"`, `Mode "octet"`. |
| `FTP` | L7 | TCP | `21` | Greeting banner `"220 FTP Server Ready\r\n"` or control command. |
| `SSH` | L7 | TCP | `22` | Identification banner `"SSH-2.0-FrameAssembly_1.0\r\n"`. |
| `TELNET` | L7 | TCP | `23` | IAC `WILL`/`DO` negotiation bytes (`\xff\xfb...`). |
| `HTTP` | L7 | TCP | `80` | `GET / HTTP/1.1\r\nHost: <host>\r\n\r\n`. |
| `HTTP2` | L7 | TCP | `443` | 24-byte client connection preface (`PRI * HTTP/2.0...`) + `SETTINGS` frame. |
| `GRPC` | L7 | TCP | `50051` | Length-prefixed gRPC frame over HTTP/2 (`application/grpc`). |
| `WEBSOCKET`| L7 | TCP | `80` | RFC 6455 WebSocket frame with optional client masking. |
| `TLS` | L7 | TCP | `443` | TLS 1.3 `ClientHello` with `SNI` and `supported_versions` extensions. |
| `QUIC` | L7 | UDP | `443` | QUIC v1 `Initial` packet or 1-RTT `Short` packet. |
| `STUN` | L7 | UDP | `3478` | Binding Request, RFC 8489 Magic Cookie `0x2112A442`. |
| `SIP` | L7 | UDP / TCP | `5060` | `INVITE sip:bob@domain SIP/2.0\r\n...`. |
| `RTP` | L7 | UDP | `5004` | RTP Version `2`, Payload Type `0` (PCMU), `Seq 1`, `Timestamp 0`. |
| `RTSP` | L7 | TCP | `554` | `DESCRIBE rtsp://server/media RTSP/1.0\r\n...`. |
| `SMTP` | L7 | TCP | `25` | `EHLO mail.example.com\r\n`. |
| `IMAP` | L7 | TCP | `143` | `A001 CAPABILITY\r\n`. |
| `POP3` | L7 | TCP | `110` | `+OK POP3 server ready\r\n` or `USER`/`PASS` command. |
| `KERBEROS` | L7 | UDP / TCP | `88` | Kerberos v5 `AS-REQ` for `krbtgt` ticket. |
| `LDAP` | L7 | TCP | `389` | LDAPv3 `BindRequest` (Simple) or `SearchRequest` message. |
| `SMB` | L7 | TCP | `445` | SMB2/3 `Negotiate Protocol Request`. |
| `NFS` | L7 | TCP / UDP | `2049` | ONC-RPC NFSv4 `NULL` / `COMPOUND` call. |
| `REDIS` | L7 | TCP