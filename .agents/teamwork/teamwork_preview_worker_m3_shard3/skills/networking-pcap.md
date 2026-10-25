---
name: networking-pcap
description: Comprehensive guide, API selection matrix, and production code templates for building high-performance, zero-heap native RFC network protocol engines and packet capture serializers in Rust with frameassembly's native wire builders and pcap-file 2.0.0 (including L2 Ethernet/VLAN/QinQ/MPLS framing, dual-stack IPv4/IPv6 headers, TCP/UDP/SCTP transports, RFC 1071/768/793/4443/9260 CRC32c & IEEE 1815 DNP3 CRC-16 checksum engines, PCAPNG block ordering, and nanosecond timestamp fidelity).
---

# Networking, Native RFC Wire Crafting & PCAP Engineering Skill

Use this skill when designing, implementing, debugging, or verifying network protocol packet crafting, multi-layer encapsulation, wire dissection, and packet capture (`.pcap` / `.pcapng`) serialization in Rust using **native zero-dependency RFC wire builders** (`src/packet.rs`, `src/builders/`) and **`pcap-file` (`2.0.0`)** (`src/pcap.rs`).

> **Architectural Note (`frameassembly`)**: `frameassembly` does **not** depend on external packet-crafting crates such as `etherparse`. All L2–L7 headers, pseudo-headers, RFC 1071 one's complement checksums, RFC 9260 Castagnoli CRC32c checksums, and IEEE 1815 DNP3 CRC-16 checksums are synthesized natively using Rust 2024 slice operations (`slice.as_chunks::<2>()`) and serialized into PCAPNG streams via `pcap-file = "2.0.0"`.

---

## 1. Quick API & Wire-Crafting Selection Matrix

| Networking / Capture Goal | Idiomatic Native RFC Wire Builder / `pcap-file 2.0.0` Pattern | Avoid (Stale / Suboptimal / Error-Prone) |
| :--- | :--- | :--- |
| **Full L2–L4 wire packet synthesis** | `frameassembly::packet::build_wire_packet(...)` | External crate builders (`etherparse::PacketBuilder`) or unvalidated byte concatenation |
| **L2 Ethernet + VLAN/QinQ/MPLS framing** | `build_ethernet_and_l2(src_mac, dst_mac, &l2, ip_ethertype, &inner)` | Hardcoding 14-byte Ethernet offsets when 802.1Q/QinQ/MPLS tags are active |
| **802.1ad QinQ double VLAN tagging** | Outer TPID `0x88A8` (S-VLAN) + Inner TPID `0x8100` (C-VLAN) | Emitting `0x8100` for outer S-VLAN tag (violates IEEE 802.1ad) |
| **RFC 3032 MPLS label stack entry** | EtherType `0x8847` + `((label & 0xFFFFF) << 12) \| ((exp & 7) << 9) \| ((bos & 1) << 8) \| ttl` | Appending an extra 2-byte EtherType after the MPLS shim header |
| **Multicast MAC auto-derivation** | RFC 1112 IPv4 (`01:00:5e:(b1 & 0x7f):b2:b3`) & RFC 2464 IPv6 (`33:33:b12:b13:b14:b15`) | Using unicast default MACs (`00:00:00:00:00:02`) for multicast destinations |
| **Dual-stack ARP over IPv6** | Polymorphic adaptation in `build_arp_frame` to ICMPv6 NDP NS (Type 135) / NA (Type 136) | Emitting EtherType `0x0806` ARP frames with 16-byte IPv6 addresses |
| **RFC 1071 Internet Checksum** | `internet_checksum(&[&pseudo, &l4_hdr, payload])` using `slice.as_chunks::<2>()` | Allocating intermediate `Vec<u8>` just to concatenate pseudo-header + payload |
| **RFC 791 IPv4 header checksum** | `internet_checksum(&[&ipv4_header[..]])` with bytes `10..12` zeroed | Computing L3 header checksums for IPv6 (removed in RFC 8200) |
| **RFC 768 / RFC 8200 UDP checksum** | `let c = internet_checksum(...); if c == 0 { 0xFFFF } else { c }` | Emitting `0x0000` on wire when one's complement sum is `0xFFFF` (illegal in IPv6) |
| **RFC 793 / RFC 8200 TCP checksum** | `internet_checksum(&[&pseudo, &tcp_header, payload])` + 32-bit NOP-padded options | Forgetting to pad TCP options to a 4-byte boundary before setting `data_offset` |
| **ICMPv4 vs. ICMPv6 / NDP / MLD** | ICMPv4/IGMP/OSPF: no pseudo-header; ICMPv6/NDP/MLD: 40-byte IPv6 pseudo-header (proto `58`) | Omitting IPv6 pseudo-header on ICMPv6/NDP/MLD or using unicast IP instead of Solicited-Node multicast |
| **RFC 9260 SCTP CRC32c checksum** | `crc32c(&[&sctp_packet])` stored in **little-endian** (`cksum.to_le_bytes()`) at bytes `8..12` | Using RFC 1071 checksum or big-endian byte order for SCTP CRC32c |
| **IEEE 1815 DNP3 link/chunk CRC-16** | `calculate_dnp3_crc(chunk)` (poly `0xA653` reflected) in **little-endian** every 16 bytes | Computing a single trailing CRC over the entire DNP3 payload |
| **Modern packet capture output** | `pcap_file::pcapng::PcapNgWriter::new(file)` (`frameassembly::pcap::PcapWriter`) | Legacy flat `pcap_file::pcap::PcapWriter` lacking interface options |
| **Nanosecond timestamp fidelity** | `InterfaceDescriptionOption::IfTsResol(9)` in `InterfaceDescriptionBlock` | Omitting `IfTsResol` (Wireshark defaults to $10^{-6}\text{s}$ microseconds, 1000x error) |
| **PCAPNG block emission** | `writer.write_block(&idb.into_block())` (`PcapNgBlock` trait) before any `EnhancedPacketBlock` | Writing `EnhancedPacketBlock` before registering `InterfaceDescriptionBlock` (`InvalidInterfaceId`) |
| **Transactional PCAP file creation** | Buffer `(Vec<u8>, u64)` frames in memory; call `PcapWriter::create` only after all frames succeed | Creating/truncating output `.pcap` file before AST evaluation and semantic validation complete |
| **Zero-copy capture stream reading** | `while let Some(block) = ng_reader.next_block() { ... }` + `.into_owned()` only when escaping lifetime | Loading entire multi-gigabyte `.pcapng` files into memory at once |

---

## 2. Architecture Decision Guide

### 1. Native Disjoint-Slice Checksum Engine vs. Heap Concatenation
- **Disjoint Slice Borrowing (`&[&[u8]]`)**: Transport and control protocols (TCP, UDP, ICMPv6, NDP, MLD) compute checksums over an L3 pseudo-header, an L4 header, and an L7 payload. By accepting `&[&[u8]]` and iterating with Rust 2024's `slice.as_chunks::<2>()`, `internet_checksum` accumulates 16-bit big-endian words directly from stack arrays (`pseudo: [u8; 12]` or `[u8; 40]`) and borrowed slices without allocating a contiguous heap buffer.
- **Protocol-Specific Checksum Rules**:
  - **IPv4 Header (RFC 791)**: 16-bit one's complement over the 20-byte IPv4 header only.
  - **TCP (RFC 793 / RFC 8200)**: 16-bit one's complement over IPv4 (12B) or IPv6 (40B) pseudo-header + TCP header (including 32-bit padded options) + payload.
  - **UDP (RFC 768 / RFC 8200 §8.1)**: 16-bit one's complement over pseudo-header + 8-byte UDP header + payload. A computed `0x0000` result **must** be rewritten as `0xFFFF`.
  - **ICMPv4 (RFC 792), IGMPv2 (RFC 2236), OSPFv2 (RFC 2328), VRRPv3 (RFC 5798 in `frameassembly`)**: 16-bit one's complement over the protocol message bytes.
  - **ICMPv6 (RFC 4443), NDP (RFC 4861), MLD (RFC 2710)**: 16-bit one's complement over the **40-byte IPv6 pseudo-header** (Next Header = `58`) + message body. When NDP/MLD rewrites the destination IP to a multicast address (e.g., Solicited-Node `ff02::1:ffXX:XXXX` or `ff02::2`), the pseudo-header **must** use that effective multicast destination IP.
  - **SCTP (RFC 9260 §3.3.10 / RFC 3309)**: 32-bit Castagnoli CRC32c (`0x1EDC6F41` / reflected `0x82F63B78`) over the 12-byte common header (checksum bytes `8..12` zeroed) and 4-byte-padded chunks, written in **little-endian** (`to_le_bytes()`).

### 2. Multi-Layer L2–L4 Encapsulation & Dual-Stack State Machines
- **Outer-Inward vs. Inner-Outward Assembly**:
  - Construct packets **inner-outward**: L7 Payload -> L4 Segment/Datagram (`build_tcp_segment` / `build_udp_datagram` / `build_sctp_payload`) -> L3 Packet (`build_ipv4_header` / `build_ipv6_header`) -> L2 Frame (`build_ethernet_and_l2`).
  - Inner-outward construction ensures exact payload lengths and checksums are known before outer headers are serialized, avoiding retroactive offset patching.
- **L2 Tag Stacking Order (`build_ethernet_and_l2`)**:
  - Standard Ethernet II: `[dst_mac (6B), src_mac (6B), ethertype (2B), inner_packet]`.
  - Single 802.1Q VLAN: `[dst_mac, src_mac, 0x81, 0x00, TCI (2B), next_ethertype (2B), inner_packet]`.
  - 802.1ad QinQ: `[dst_mac, src_mac, 0x88, 0xA8, outer_TCI (2B), 0x81, 0x00, inner_TCI (2B), next_ethertype (2B), inner_packet]`.
  - RFC 3032 MPLS (standalone or inside VLAN/QinQ): Replaces `next_ethertype` with `0x8847` followed by the 4-byte MPLS label stack entry `[label(20b) | exp(3b) | bos(1b) | ttl(8b)]` and `inner_packet`.
- **Two-Stage Port Inheritance & Canonical 4-Tuple TCP State**:
  - Stage 1 (`EndpointPairPorts`): Remembers `(caller_port, callee_port)` across forward (`->`) and reverse (`<-`) arrows so reply packets automatically mirror the request's ephemeral and service ports.
  - Stage 2 (`Canonical4Tuple`): Normalizes `((src_ip, src_port), (dst_ip, dst_port))` via `ep1 <= ep2` to track bidirectional `seq1` and `seq2` counters (starting at `1000`), auto-populating `ACK` numbers and advancing sequence numbers by `payload_len + SYN + FIN`.

### 3. PCAPNG Block Lifecycle & Timestamp Fidelity (`pcap-file 2.0.0`)
- **Strict Block Ordering (`SHB -> IDB -> EPB`)**:
  - `PcapNgWriter::new(writer)` automatically emits the mandatory `SectionHeaderBlock` (SHB).
  - You **must** write an `InterfaceDescriptionBlock` (IDB) before any `EnhancedPacketBlock` (EPB) referencing `interface_id: 0`.
- **Nanosecond Precision (`IfTsResol(9)`)**:
  - Always include `InterfaceDescriptionOption::IfTsResol(9)` in the IDB options vector when passing `Duration::from_nanos(ts_ns)` to `EnhancedPacketBlock`. Without `IfTsResol(9)`, `pcap-file` and Wireshark default to microsecond resolution ($10^{-6}\text{s}$), distorting packet capture timelines by 1,000x.

---

## 3. Production Reference Templates

Read [references/patterns.md](references/patterns.md) for complete, copy-pasteable production implementations verified against `frameassembly` and `pcap-file 2.0.0`:
1. **Native RFC 1071, RFC 768 Zero-Mapping, RFC 9260 CRC32c & DNP3 CRC-16 Checksum Engines**: Disjoint-slice one's complement checksums, adversarial `0x0000 -> 0xFFFF` UDP verification, `const` Castagnoli CRC32c, and IEEE 1815 CRC-16.
2. **Native L3/L4 Dual-Stack Wire Builders (IPv4, IPv6, TCP with Options, UDP, SCTP)**: Complete header synthesis with DSCP/ECN, IPv4 DF/MF/Fragment Offset, IPv6 Flow Labels, and 32-bit aligned TCP options.
3. **Native L2 Encapsulation (Ethernet II, 802.1Q VLAN, 802.1ad QinQ, RFC 3032 MPLS) & Multicast MAC Derivation**: Tag stacking, RFC 1112 / RFC 2464 multicast MAC derivation, and polymorphic IPv6 ARP-to-NDP adaptation.
4. **Canonical 4-Tuple TCP Stream State Machine & Two-Stage Port Inheritance**: Stateful sequence/acknowledgment progression and bidirectional port mirroring.
5. **Transactional PCAPNG Writer with Nanosecond Fidelity (`pcap-file 2.0.0`)**: `PcapNgWriter`, `PcapNgBlock::into_block()`, `IfTsResol(9)`, snaplen invariants, and delayed file creation.
6. **Zero-Copy Streaming PCAPNG & Legacy PCAP Dissector (`PcapNgReader` + Native Wire Slicing)**: Incremental block iteration, `.into_owned()` lifetime promotion, and native L2–L4 wire offset verification without external parser crates.
