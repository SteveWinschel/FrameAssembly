---
trigger: glob
globs: "src/packet.rs, src/pcap.rs, src/backend/**/*.rs, src/builders/**/*.rs, tests/**/*.rs"
description: "Native RFC L2-L7 wire packet crafting, checksums, Wireshark/tshark dissector QA invariants, and pcap-file 2.0.0 PCAPNG serialization rules."
---

# Networking, Native RFC Wire Crafting & PCAP Architecture Best Practices

Always enforce these zero-dependency, wire-valid, and idiomatic native RFC packet construction (`src/packet.rs`, `src/builders/`, `src/backend/`) and `pcap-file` (`2.0.0`) (`src/pcap.rs`) engineering rules when designing, implementing, testing, or auditing network protocol builders, checksum engines, traffic dissectors, and PCAPNG serializers in Rust:

---

## 1. Native Inner-Outward Packet Construction Architecture (`src/packet.rs`, `src/builders/`)

- **Zero External Packet-Crafting Dependencies**:
  - `frameassembly` synthesizes all OSI Layer 2 through Layer 7 frames natively using standard Rust 2024 slice operations without external packet-builder dependencies (`etherparse` is **not** used).
  - Construct frames **inner-outward**:
    1. **Layer 7 / Application Payload**: Synthesize protocol bytes (e.g., DNS, HTTP, TLS, QUIC, SNMP BER, Modbus, DNP3, S7comm).
    2. **Layer 4 / Transport Segment (`build_tcp_segment`, `build_udp_datagram`, `build_sctp_payload`)**: Prepend transport header, pad options/chunks to 32-bit alignment, and compute transport checksum over the L3 pseudo-header + L4 header + L7 payload (or Castagnoli CRC32c for SCTP).
    3. **Layer 3 / Network Packet (`build_ipv4_header`, `build_ipv6_header`, `build_ip_packet`)**: Prepend the 20-byte IPv4 header (computing the RFC 791 header checksum at bytes `10..12`) or 40-byte IPv6 header (packing Version `6`, 8-bit Traffic Class `(dscp << 2) | ecn`, and 20-bit Flow Label).
    4. **Layer 2 / Data Link Frame (`build_ethernet_and_l2`)**: Prepend Destination MAC (6B), Source MAC (6B), optional IEEE 802.1ad QinQ (`0x88A8`), IEEE 802.1Q VLAN (`0x8100`), and/or RFC 3032 MPLS (`0x8847`) shim headers, and the inner EtherType (`0x0800` for IPv4, `0x86DD` for IPv6, `0x0806` for ARP).
- **Strict Address Family Matching**:
  - Source and destination IP addresses in a single frame **must** share the same address family (`(IpAddr::V4, IpAddr::V4)` or `(IpAddr::V6, IpAddr::V6)`). Mixing IPv4 and IPv6 endpoints in `build_tcp_segment`, `build_udp_datagram`, `build_ip_packet`, or `build_wire_packet` must fail immediately with `CompilerError::BackendError`.

---

## 2. Native Checksum & CRC Engines (RFC 1071, RFC 768, RFC 793, RFC 4443, RFC 5798, RFC 9260, IEEE 1815)

- **Disjoint-Slice RFC 1071 Internet Checksum (`internet_checksum(data: &[&[u8]]) -> u16`)**:
  - Never allocate a temporary `Vec<u8>` just to concatenate a pseudo-header, transport header, and payload before checksum calculation.
  - Pass borrowed slice references `&[&pseudo, &header, payload]` into `frameassembly::packet::internet_checksum`.
  - Use Rust 2024's `slice.as_chunks::<2>()` to accumulate 16-bit big-endian words (`u16::from_be_bytes(*chunk) as u32`), handle odd-length slices by shifting the remainder byte (`(remainder[0] as u32) << 8`), fold 32-bit carries (`while (sum >> 16) != 0 { sum = (sum & 0xffff) + (sum >> 16); }`), and return `!sum as u16`.
- **RFC 768 / RFC 8200 §8.1 UDP Zero-Checksum Invariant (`0x0000 -> 0xFFFF`)**:
  - In UDP, a wire checksum value of `0x0000` means "no checksum was computed by the transmitter" (which is strictly illegal over IPv6 per RFC 8200 §8.1).
  - Whenever `internet_checksum(&[&pseudo, &udp_header, payload])` evaluates to `0x0000` (which happens when the raw 16-bit one's complement sum equals `0xFFFF`), the builder **must** emit `0xFFFF` (`if c == 0 { 0xFFFF } else { c }`).
- **ICMPv4 / IGMP / OSPF / GRE vs. ICMPv6 / NDP / MLD / VRRPv3 Pseudo-Header Rules**:
  - **No Pseudo-Header**: IPv4 header checksum (RFC 791), ICMPv4 (RFC 792, IP proto `1`), IGMPv2/v3 (RFC 2236/3376, IP proto `2`), GRE (RFC 2784/2890, IP proto `47`), and OSPFv2 (RFC 2328, IP proto `89`) compute `internet_checksum` solely over their own header/body bytes.
  - **Mandatory 40-Byte IPv6 Pseudo-Header (Next Header = `58`)**: TCP over IPv6 (`6`), UDP over IPv6 (`17`), ICMPv6 (RFC 4443, `58`), Neighbor Discovery Protocol (NDP, RFC 4861, `58`), and Multicast Listener Discovery (MLD, RFC 2710, `58`) **strictly require** a 40-byte IPv6 pseudo-header: `[src_v6 (16B), effective_dst_v6 (16B), upper_layer_len_u32_be (4B), 0, 0, 0, next_header]`.
  - **Mandatory VRRPv3 Pseudo-Header (RFC 5798 §5.2.8, Protocol / Next Header = `112`)**: Unlike VRRPv2, VRRPv3 (`version_type = 0x31`) computes its checksum over the **12-byte IPv4 pseudo-header** or **40-byte IPv6 pseudo-header** (using multicast destination `224.0.0.18` or `ff02::12` and protocol `112`) + VRRPv3 packet bytes.
  - **Effective Multicast Destination Invariant**: When NDP Neighbor Solicitation (`135`) rewrites the destination IP to Solicited-Node multicast (`ff02::1:ffXX:XXXX`), or NDP Router Solicitation (`133`) rewrites to `ff02::2`, or MLD/VRRPv3 targets a multicast group (`ff02::1` / `ff02::16` / `ff02::12`), the L3 pseudo-header **must** use that effective multicast destination address—never the original unicast target host address.
- **RFC 9260 §3.3.10 / RFC 3309 SCTP Castagnoli CRC32c (`crc32c`)**:
  - SCTP (IP proto `132`) does **not** use RFC 1071 one's complement checksums and does **not** use an IP pseudo-header.
  - Compute the 32-bit Castagnoli CRC32c (polynomial `0x1EDC6F41`, reflected `0x82F6_3B78`, initial `0xFFFF_FFFF`, final XOR `0xFFFF_FFFF`) over the entire SCTP packet with header bytes `8..12` zeroed and all variable-length chunks padded with `0x00` to 4-byte boundaries (RFC 9260 §3.3.1).
  - **Little-Endian Wire Invariant**: Store the computed SCTP CRC32c in **little-endian** byte order (`cksum.to_le_bytes()`) at `sctp_packet[8..12]`.
- **IEEE 1815 DNP3 CRC-16 (`calculate_dnp3_crc`)**:
  - Uses reflected polynomial `0xA653` (`0x3D65`), initial `0x0000`, and bitwise inverted remainder `!crc`, written in **little-endian** (`to_le_bytes()`) immediately after the 8-byte Data Link header and after every chunk of up to 16 user-data bytes.

---

## 3. Dual-Stack L2 Framing, Tag Stacking & Multicast MAC Derivation

- **L2 Tag Stacking Order (`build_ethernet_and_l2`)**:
  - **802.1ad QinQ**: Outer TPID `0x88A8` + outer TCI `((pcp & 7) << 13) | ((dei & 1) << 12) | (outer_vid & 0x0FFF)`, followed by optional inner TPID `0x8100` + inner TCI `inner_vid & 0x0FFF`.
  - **802.1Q VLAN**: TPID `0x8100` + TCI `((pcp & 7) << 13) | ((dei & 1) << 12) | (vid & 0x0FFF)`.
  - **RFC 3032 MPLS**: EtherType `0x8847` (which may follow Ethernet II, 802.1Q VLAN, or 802.1ad QinQ) + 32-bit MPLS shim `((label & 0x000F_FFFF) << 12) | ((exp & 7) << 9) | ((bos & 1) << 8) | (ttl as u32)`. No extra EtherType follows the MPLS shim header; the inner L3 packet begins immediately at `offset + 4`.
- **Deterministic MAC Resolution Precedence (`derive_mac`)**:
  1. Explicit statement-level MAC (`SRCMAC` / `DSTMAC`).
  2. Host-level configured MAC (`HOST ... { MAC ... }`).
  3. **RFC 1112 IPv4 Multicast (`224.0.0.0/4`, first octet `224..=239`)**: `[0x01, 0x00, 0x5E, octets[1] & 0x7F, octets[2], octets[3]]`.
  4. **RFC 2464 IPv6 Multicast (`ff00::/8`, first octet `0xFF`)**: `[0x33, 0x33, octets[12], octets[13], octets[14], octets[15]]`.
  5. Deterministic unicast defaults: `[0x00, 0x00, 0x00, 0x00, 0x00, 0x01]` for caller, `[0x00, 0x00, 0x00, 0x00, 0x00, 0x02]` for callee.
  6. **IEEE 802.1D Link-Local Multicast Defaults**: STP (`01:80:c2:00:00:00`), LACP (`01:80:c2:00:00:02`), EAPOL (`01:80:c2:00:00:03`), LLDP (`01:80:c2:00:00:0e`), ARP Request broadcast (`ff:ff:ff:ff:ff:ff`).
- **Polymorphic ARP-over-IPv6 Adaptation (`build_arp_frame`)**:
  - Because RFC 826 ARP is strictly an IPv4/Ethernet protocol (`hrd = 1`, `pro = 0x0800`, `pln = 4`), invoking `ARP` between IPv6 endpoints automatically adapts to RFC 4861 ICMPv6 Neighbor Discovery with **IPv6 Hop Limit = `255`**:
    - ARP Request -> Neighbor Solicitation (Type `135`, Code `0`, Solicited-Node multicast IP `ff02::1:ffXX:XXXX`, multicast MAC `33:33:ff:XX:XX:XX`, Option 1 SLLA).
    - ARP Reply -> Neighbor Advertisement (Type `136`, Code `0`, Flags `0x60` Solicited+Override, Option 2 TLLA).

---

## 4. Two-Stage Port Inheritance & Canonical 4-Tuple TCP State Machine

- **Stage 1: Bidirectional Endpoint-Pair Port Inheritance (`EndpointPairPorts`)**:
  - Track `(caller_port, callee_port)` per `(caller_id, callee_id)` pair.
  - On `LeftToRight (`->`)`, resolve `src_port` from `stmt.src_port.or(pair.caller_port).unwrap_or(default_src_port)` and `dst_port` from `stmt.dst_port.or(pair.callee_port).unwrap_or(default_dst_port)`.
  - On `RightToLeft (`<-`)`, mirror the ports: resolve `src_port` from `stmt.src_port.or(pair.callee_port).unwrap_or(default_dst_port)` and `dst_port` from `stmt.dst_port.or(pair.caller_port).unwrap_or(default_src_port)`.
- **Stage 2: Canonical 4-Tuple TCP Sequence Tracking (`Canonical4Tuple`)**:
  - Normalize `ep1 = (src_ip, src_port)` and `ep2 = (dst_ip, dst_port)` into a canonical key `if ep1 <= ep2 { (ep1, ep2) } else { (ep2, ep1) }`.
  - Initialize `seq1: 1000` and `seq2: 1000`.
  - Populate `ack_num` from the peer's current sequence counter when not explicitly overridden.
  - Advance the sender's sequence counter by `payload_len + (SYN ? 1 : 0) + (FIN ? 1 : 0)` using `wrapping_add`.
- **TCP Option Alignment (`encode_tcp_options`)**:
  - Always pad encoded TCP options (`MSS`, `WSCALE`, `SACK_PERM`, `TSVAL`/`TSECR`) with `NOP` (`0x01`) until `opts_buf.len() % 4 == 0` so `data_offset = ((20 + opts_buf.len()) / 4) as u8` is an exact 32-bit word count.

---

## 5. PCAPNG Serialization, `pcap-file 2.0.0` API & Critical Quirks (`src/pcap.rs`)

- **Exact `PcapError` Enum (6 Variants)**:
  - `pcap_file::PcapError` in `2.0.0` defines **exactly 6 variants**: `IncompleteBuffer`, `IoError(std::io::Error)`, `InvalidField(&'static str)`, `Utf8Error(std::str::Utf8Error)`, `FromUtf8Error(std::string::FromUtf8Error)`, and `InvalidInterfaceId(u32)`. Never match on non-existent variants (`InvalidTsResolution`, `HeaderNotFound`, `QuoteNotClosed`).
- **Exact `Block<'a>` Enum (9 Variants)**:
  - `pcap_file::pcapng::Block<'a>` defines **9 variants**: `SectionHeader`, `InterfaceDescription`, `Packet`, `SimplePacket`, `NameResolution`, `InterfaceStatistics`, `EnhancedPacket`, `SystemdJournalExport`, and `Unknown(UnknownBlock<'a>)`. IETF PCAPNG `DecryptionSecretsBlock` (`0x0000000A`) and `CustomBlock` (`0x00000BAD`) deserialize into `Block::Unknown`.
- **Lifetime Promotion & Buffer Limits**:
  - All block and option structs derive an inherent `.into_owned(self)` method via `derive-into-owned 0.2.0`. `PcapNgReader` uses an internal `ReadBuffer` with an **8,000,000-byte (8 MB)** single-block limit.
- **Strict Block Ordering (`SHB -> IDB -> EPB`) & Transactional File Creation**:
  - `PcapNgWriter::new(writer)` automatically emits the `SectionHeaderBlock` (SHB, `0x0A0D0D0A`).
  - Write an `InterfaceDescriptionBlock` (IDB, `0x00000001`) via `writer.write_block(&idb.into_block())` before any `EnhancedPacketBlock` (EPB, `0x00000006`) or `PcapNgWriter` fails with `PcapError::InvalidInterfaceId(id)`.
  - Buffer all synthesized `(Vec<u8>, u64)` frames in memory **before** calling `PcapWriter::create(output_path)` so failed compilations never leave partial `.pcap` files on disk.
- **Quirk 1 (`EnhancedPacketBlock` Timestamp Resolution Mismatch)**:
  - In `pcap-file 2.0.0`, `EnhancedPacketBlock` unconditionally converts `Duration` via `as_nanos()` / `Duration::from_nanos()` while ignoring the IDB's `IfTsResol` option. However, Wireshark and `tshark` follow the IETF PCAPNG spec and default to `IfTsResol(6)` ($10^{-6}\text{s}$ microseconds) when Option 9 is omitted. Therefore, `InterfaceDescriptionOption::IfTsResol(9)` ($10^{-9}\text{s}$) is **strictly mandatory** in every IDB.
- **Quirk 2 (`InterfaceDescriptionOption::IfTzone` Fatal Read Bug)**:
  - In `pcap-file 2.0.0`, Option 10 (`IfTzone`) checks `if slice.len() != 1` (failing if length $\ne 1$) and immediately calls `slice.read_u32::<B>()` (4 bytes, failing with `UnexpectedEof` if length $== 1$). Any PCAPNG containing `IfTzone` **cannot be read** by `PcapNgReader`. **Never emit `InterfaceDescriptionOption::IfTzone`**.

---

## 6. 81-Protocol Wire & Wireshark (`tshark`) Dissector QA Invariant Checklist

Every protocol builder and dispatcher in `src/backend/` and `src/builders/` must satisfy these wire and dissector invariants:

### 6.1 `src/backend/l7_dispatch.rs` Builder Return-Tuple Preservation
1. **`DHCP` (`l7_dispatch.rs`)**: `build_dhcp_payload` returns `(pkt, sport, dport)` — `(68, 67)` / `(67, 68)` for DHCPv4 and `(546, 547)` / `(547, 546)` for DHCPv6. Never discard `sport`/`dport` in favor of hardcoded UDP port `67` (BOOTPS), which breaks DHCPv6 dissection in Wireshark.
2. **`MDNS` (`l7_dispatch.rs`)**: `build_mdns_payload` returns `(payload, target_ip, 5353)` where `target_ip` is `224.0.0.251` (IPv4) or `ff02::fb` (IPv6). Honor both the multicast `target_ip` and UDP port `5353`.
3. **`PTP` (`l7_dispatch.rs`)**: `build_ptp_payload` returns `(result, dport)` where `dport` is `319` (Event port for `SYNC`/`DELAY_REQ`) or `320` (General port for `FOLLOW_UP`/`DELAY_RESP`/`ANNOUNCE`).
4. **`RADIUS` (`l7_dispatch.rs`)**: `build_radius_payload` returns `(pkt, dport)` where `dport` is `1812` (Auth) or `1813` (Accounting for codes `4, 5`).

### 6.2 L2/L3 Checksum, TTL & Inner Frame Invariants
1. **`GRE` (`src/builders/l3/gre.rs`)**: When `CHECKSUM` (`0x8000` flag) is set, compute `internet_checksum(&[&gre])` over the entire GRE packet (header + encapsulated inner IPv4/IPv6 packet) and write it into `gre[4..6]` (never leave `0x0000`).
2. **`VRRP` (`src/builders/l3/vrrp.rs`)**: VRRPv3 (`0x31`, RFC 5798 §5.2.8) requires the **IPv4 (12B) or IPv6 (40B) pseudo-header** (Protocol / Next Header = `112`) in its checksum calculation and requires IP TTL / Hop Limit = **`255`**.
3. **`NDP` (`src/builders/l3/ndp.rs` & `src/builders/l2/arp.rs`)**: RFC 4861 requires IPv6 Hop Limit = **`255`** for all NDP messages (`133..=137`).
4. **`GENEVE` (`src/builders/l3/geneve.rs`)**: Default `proto = 0x6558` (Transparent Ethernet Bridging) requires a valid 14B inner Ethernet + 20B IPv4 frame (like `vxlan.rs`), never raw ASCII text.
5. **`WIREGUARD` (`src/builders/l3/wireguard.rs`)**: Type `4` (`DATA`) requires a 16B header + encrypted payload + **16B Poly1305 AEAD tag** ($\ge 32$ bytes total).
6. **`STP` & `EAPOL` (`src/builders/l2/stp.rs`, `eapol.rs`)**: RSTP (`Version = 2`, `BPDU Type = 0x02`) requires the 36th byte `Version 1 Length = 0x00` (IEEE 802.1D-2004 §9.3.3). EAP Success/Failure (`Code 3/4`) in `EAPOL` are strictly 4 bytes (`[Code, Id, 0x00, 0x04]`, no `Type` byte).

### 6.3 L7 Length, Varint, ASN.1 & Byte-Order Invariants
1. **`QUIC` (`src/builders/l7/quic.rs`)**: Long Header `Length` is an RFC 9000 §16 2-byte variable-length integer requiring the `0x4000` prefix (`(0x4000 | inner_len).to_be_bytes()`).
2. **`IPFIX` (`src/builders/l7/ipfix.rs`)**: Both `total_len` (`16 + set_len`) and `set_len` (`4 + record.len() + payload_bytes.len()`) must include `payload_bytes.len()`.
3. **`SFLOW` (`src/builders/l7/sflow.rs`)**: sFlow v5 Flow Sample (`sample_type = 1`) header has **8 `u32` fields (32 bytes)** (`seq_num`, `source_id`, `sampling_rate`, `sample_pool`, `drops`, `input_if`, `output_if`, `num_flow_records`), not 4 `u32`s (16 bytes).
4. **`LDAP` (`src/builders/l7/ldap.rs`)**: `SearchRequest` (`0x63`) requires all 8 RFC 4511 §4.5.1 elements (`baseObject`, `scope`, `derefAliases`, `sizeLimit`, `timeLimit`, `typesOnly`, `filter`, `attributes`).
5. **`KERBEROS` (`src/builders/l7/kerberos.rs`)**: RFC 4120 `KDC-REQ-BODY` requires `[7] till (GeneralizedTime)` and `[8] nonce (UInt32)` after `[3] sname`.
6. **L7 Framing & Byte-Order Summary**:
   - `MYSQL`: 3-byte **little-endian** payload length + 1-byte `seq_id`.
   - `POSTGRES`: `'Q'` (`0x51`) + 4-byte **big-endian** length **including the 4 length bytes** (`4 + query.len() + 1`).
   - `SMB`: 4-byte NetBIOS header (`0x00` + 24-bit BE length) + 64-byte **little-endian** `\xFESMB` header.
   - `NFS`: 4-byte **big-endian** RPC record marker (`0x80000000 | frag_len`) + 4-byte XDR string padding.
   - `MODBUS`: 7-byte MBAP header with `len = 1 + pdu.len()`.
   - `DNP3`: `0x0564` start bytes + **little-endian** CRC-16 after the 8B link header and every $\le 16$B data block.
   - `S7COMM`: 4B TPKT + 3B COTP + S7 Header (`0x32`, **10B** for `0x01 Job`, **12B** with 2B error field for `0x03 Ack_Data`).
   - `ETHERNETIP`: 24-byte **little-endian** encapsulation header.
   - `OPCUA`: 8-byte **little-endian** UACP header (`total_size` includes the 8B header).

---

## 7. Anti-Patterns & Wire-Level QA Guardrails

| # | Anti-Pattern | Correct Native / `pcap-file 2.0.0` Practice | Failure Mode Prevented |
| :--- | :--- | :--- | :--- |
| 1 | Importing `etherparse` or assuming external packet builders | Use `frameassembly::packet::*` and `frameassembly::builders::*` | Unnecessary dependency bloat; `Cargo.toml` is strictly zero-`etherparse` |
| 2 | Emitting raw `0x0000` UDP checksum when one's complement sum is `0xFFFF` | Map `if c == 0 { 0xFFFF } else { c }` in `build_udp_datagram` | Violates RFC 768 and RFC 8200 §8.1 (receivers drop IPv6 UDP datagrams with zero checksum) |
| 3 | Writing SCTP CRC32c in big-endian (`to_be_bytes()`) | Write `cksum.to_le_bytes()` at `sctp_packet[8..12]` | Violates RFC 9260 §3.3.10; Wireshark and kernel SCTP stacks flag every packet as corrupt |
| 4 | Omitting pseudo-header on ICMPv6, NDP, MLD, or VRRPv3 | Prepend 40B IPv6 pseudo-header (`58`) or 12B/40B VRRPv3 pseudo-header (`112`) | Violates RFC 4443 §2.3 and RFC 5798 §5.2.8; packets fail checksum verification |
| 5 | Discarding `(sport, dport)` / `target_ip` returned by `DHCP`, `MDNS`, `PTP`, `RADIUS` builders | Preserve builder-returned ports (`546/547`, `5353`, `319/320`, `1812/1813`) in `l7_dispatch.rs` | DHCPv6 sent to port 67 (BOOTPS) or PTP General messages sent to Event port 319 |
| 6 | Emitting `InterfaceDescriptionOption::IfTzone` or omitting `IfTsResol(9)` | Include `IfTsResol(9)` and never emit `IfTzone` in `pcap-file 2.0.0` | `IfTzone` triggers a fatal `PcapNgReader` bug; missing `IfTsResol(9)` causes 1,000x timestamp error |
| 7 | Creating `PcapWriter::create(path)` before evaluating statements | Buffer `(Vec<u8>, u64)` in memory; create file only after synthesis completes | Failed compilations leave truncated or empty `.pcap` files on disk |
