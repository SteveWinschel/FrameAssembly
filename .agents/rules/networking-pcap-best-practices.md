---
trigger: glob
globs: "src/packet.rs, src/pcap.rs, src/backend/**, src/builders/**, src/reverse/**, tests/**/*.rs"
description: "Native RFC L2-L7 wire packet crafting, case-insensitive enum string normalization, checksums, 4-tuple state machine constants, pcap-file 2.0.0 PCAPNG quirks, etherparse 0.21.0 PCAP-to-.frasm decompilation, and 81-protocol tshark QA invariants."
---

# Networking, Native RFC Wire Crafting, PCAPNG & Decompilation Best Practices

Enforce these rootless, offline, wire-exact RFC packet synthesis, `pcap-file 2.0.0`, and `etherparse 0.21.0` PCAP-to-`.frasm` decompilation rules across `src/packet.rs`, `src/pcap.rs`, `src/backend/`, `src/builders/`, and `src/reverse/`:

## 1. Forward Native Wire Synthesis vs. PCAP-to-`.frasm` Decompilation
- **Forward Wire Synthesis (`src/packet.rs`, `src/builders/`)**: Uses 100% zero-heap native Rust 2024 slice operations (`etherparse::PacketBuilder` and `libpcap` are never used), normalizing `_` and `-` case-insensitively on quoted protocol enum strings (e.g., `qtype "a"` or `"A"`).
- **PCAP/PCAPNG-to-`.frasm` Decompilation (`src/reverse/`)**: Uses `etherparse = { version = "0.21.0", default-features = false, features = ["std"] }` for zero-copy L2–L4 header slicing and `pcap-file = "2.0.0"` (`PcapNgReader` and `PcapReader`) for container reading, emitting v3.0.0 strict-lowercase `[a-z0-9]+` keywords without `_` or `-`, `host1`/`host2` host names, and direct flow calls in `compile` (never `loop`).
- **Inner-Outward Encapsulation Order (`src/packet.rs`)**:
  1. **L7 Payload** (`src/builders/l7/`) -> 2. **L4 Segment/Datagram** (`build_tcp_segment`, `build_udp_datagram`, `build_sctp_payload` with 4-byte padded options/chunks) -> 3. **L3 Packet** (`build_ipv4_header`, `build_ipv6_header` with strict `(V4, V4)` or `(V6, V6)` family homogeneity) -> 4. **L2 Frame** (`build_ethernet_and_l2`: `0x88A8` QinQ S-Tag -> `0x8100` C-Tag/VLAN -> `0x8847` MPLS shim with **no** extra EtherType after MPLS -> inner packet).
- **Pure L2 MAC-Only EtherType `0x88B5` Fallback**: When `vlan` (`src/builders/l2/vlan.rs`) or `qinq` (`src/builders/l2/qinq.rs`) executes between MAC-only hosts with no IP (`ctx.src_ip.is_unspecified() || ctx.dst_ip.is_unspecified()`), default the inner EtherType to `l2.ethertype.unwrap_or(0x88B5)` (IEEE 802.1 Local Experimental) and wrap `payload` directly without synthesizing an IP/UDP header.

## 2. Checksum & CRC Engines (Zero Intermediate Heap Concatenation)
- **Disjoint-Slice RFC 1071 Checksum (`internet_checksum(data: &[&[u8]]) -> u16`)**: Accumulate 16-bit big-endian words via `slice.as_chunks::<2>()` directly over `&[&pseudo, &header, payload]` without allocating a contiguous `Vec<u8>`.
- **RFC 768 / RFC 8200 §8.1 UDP Zero-Checksum Folding**: Whenever `internet_checksum` evaluates to `0x0000`, emit `0xFFFF` (`if c == 0 { 0xFFFF } else { c }`).
- **Pseudo-Header & Effective Multicast Destination Rules**:
  - **No Pseudo-Header**: IPv4 header, ICMPv4 (`1`), IGMP (`2`), GRE (`47`), OSPFv2 (`89`), VRRPv2.
  - **Mandatory Pseudo-Header**: TCP (`6`), UDP (`17`), ICMPv6 (`58`), NDP (`58`), MLD (`58`), and **VRRPv3** (`112`, RFC 5798 §5.2.8 over 12B IPv4 or 40B IPv6 pseudo-header). When NDP/MLD/VRRPv3 rewrites the destination IP to a multicast group (`ff02::1:ffXX:XXXX`, `ff02::2`, `224.0.0.18`, `ff02::12`), compute the pseudo-header using that **effective multicast IP**, never the original unicast callee IP!
- **Little-Endian Wire CRCs**:
  - **SCTP (`src/builders/l4/sctp.rs`)**: Castagnoli `CRC32c` (`0x1EDC6F41` / reflected `0x82F6_3B78`, no IP pseudo-header, chunks 4-byte padded) written in **little-endian** (`cksum.to_le_bytes()`) at `sctp[8..12]`.
  - **DNP3 (`src/builders/l7/dnp3.rs`)**: IEEE 1815 `CRC-16` (reflected `0xA653`, inverted `!crc`) written in **little-endian** after the 8B link header and after every `<= 16`B user-data block.

## 3. Deterministic Backend Constants & 4-Tuple State (`src/backend/mod.rs`)
- **Clock & Timing**: Base epoch starts at `1_700_000_000_000_000_000` ns; each statement adds `stmt.wait.unwrap_or(10_000_000)` (`10ms`) *before* emitting its frame. `frameassembly show` subtracts frame 1's timestamp so frame 1 displays at `0.000` ms.
- **MAC & TTL Defaults**: `derive_mac` resolves `stmt_mac` -> protocol group MAC (`lldp`, `stp`, `lacp`, `eapol`, broadcast `arp` request) -> multicast IP (`01:00:5e:xx:xx:xx` / `33:33:xx:xx:xx:xx`) -> `host_mac` -> `00:00:00:00:00:01` (caller) / `02` (callee). Auto-default `ttl = 255` when omitted on `ndp`, `vrrp`, and IPv6 `arp` (which polymorphically emits NDP NS `135` / NA `136`).
- **Two-Stage Ports & 4-Tuple TCP**: `EndpointPairPorts` tracks `(caller_port, callee_port)` across `->` (default `srcport 12345`) and `<-` (automatic port swap). `Canonical4Tuple` initializes `seq1 = 1000`, `seq2 = 1000`, default `win = 64240`, advancing `seq` by `payload_len + syn + fin` (`wrapping_add`).

## 4. `pcap-file 2.0.0` Invariants & Critical Quirks (`src/pcap.rs`)
- **Exact Enums**: `PcapError` has 6 variants (`IncompleteBuffer`, `IoError`, `InvalidField`, `Utf8Error`, `FromUtf8Error`, `InvalidInterfaceId`); `pcapng::Block<'a>` has 9 variants.
- **Transactional Buffering**: Synthesize all `(Vec<u8>, u64)` frames in `compile_program` before calling `PcapWriter::create(path)` (or writing to `PcapNgWriter::new(Vec::new())` in WASM) so errors never leave partial `.pcap` files on disk.
- **Mandatory `IfTsResol(9)` & Forbidden `IfTzone`**:
  1. `EnhancedPacketBlock` in `pcap-file 2.0.0` unconditionally encodes `Duration::as_nanos()` while Wireshark defaults to $10^{-6}\text{s}$ if Option 9 is absent—**always** emit `InterfaceDescriptionOption::IfTsResol(9)` in the IDB before any EPB!
  2. `InterfaceDescriptionOption::IfTzone` has a fatal 1-byte vs 4-byte read bug in `pcap-file 2.0.0`—**never** emit `IfTzone`!

## 5. Key Wire & `tshark` Dissector QA Invariants
- Preserve `L7DispatchResult` in `l7_dispatch.rs` (`dhcp` `68/67` & `546/547`, `mdns` `5353` + multicast IP, `ptp` `319/320`, `radius` `1812/1813` + reverse `<-` `src_port`).
- Maintain full RFC wire structures: `gre` `checksum` at `gre[4..6]`; `geneve` `0x6558` & `vxlan` 42B inner Ethernet+IPv4+UDP frame; `wireguard` `data` `>= 32`B (16B Poly1305 tag); `rstp` 36th byte `0x00`; `eap` Success/Failure 4B; `quic` Long Header 2B varint `0x4000 | len`; `ipfix` lengths including payload; `sflow` v5 Flow Sample 32B (`8 x u32`) header; complete 8-field RFC 4511 BER `SearchRequest` in `ldap.rs`; complete explicit-tag RFC 4120 DER `KDC-REQ`/`KDC-REP`/`KRB-ERROR` in `kerberos.rs`; `mysql` 3B LE length; `postgres` `'Q'` 4B BE length including self; `smb` 4B NetBIOS + 64B LE `\xFESMB`; `nfs` `0x80000000 | len` RPC record mark; `modbus` MBAP `len = 1 + pdu.len()`; `s7comm` 10B Job / 12B Ack_Data; `ethernetip` 24B LE header; `opcua` 8B LE UACP header.

## 6. `etherparse 0.21.0` & PCAP-to-`.frasm` Decompiler Invariants (`src/reverse/`)
- **`etherparse 0.21.0` APIs**:
  - `SlicedPacket::from_ethernet(frame)` (strict length checks) and `LaxSlicedPacket::from_ethernet(frame)` (partial/truncated capture fallback).
  - `link_exts: ArrayVec<LinkExtSlice, 3>` replaces the removed `.vlan` field on `SlicedPacket` / `LaxSlicedPacket` to support up to 3 `LinkExtSlice::Vlan(SingleVlanSlice)` or IEEE 802.1AE `LinkExtSlice::Macsec(MacsecSlice)` headers; call `.vlan()` helper for `Option<VlanSlice>` (`SingleVlan` or `DoubleVlan`).
  - Match L3 via `NetSlice::{Ipv4(v4), Ipv6(v6), Arp(arp)}` and L4 via `TransportSlice::{Tcp(tcp), Udp(udp), Icmpv4(icmp4), Icmpv6(icmp6), Igmp(igmp)}`, iterating TCP options with `tcp.options_iterator()` (`TcpOptionElement::{Noop, MaximumSegmentSize, WindowScale, SelectiveAcknowledgementPermitted, Timestamp, ...}`). Peel RFC 3032 MPLS (`0x8847`/`0x8848`) and RFC 9260 SCTP (`ip_proto == 132`) chunks manually.
- **Decompiler Modularity, Safety & Self-Check Oracle**:
  - Mirror `src/ast/`, `src/parser/`, and `src/builders/` 1-to-1 across `src/reverse/{l2,l3,l4,l7}/<protocol>.rs` (including `src/reverse/l3/{ip,ipv6,icmpv6}.rs` alongside the 20 L3 protocol dissectors and `src/reverse/l7/{snmp1,snmp2,snmp3}.rs` across all 50 L7 protocol dissectors, plus `container.rs`, `topology.rs`, `oracle.rs`, and `shadow_emit.rs`), keeping every `src/reverse/**/*.rs` file `< 50,000` bytes with 100% fuzz-safe bounds checks (zero `.unwrap()`/`.expect()`, `MAX_DNS_JUMPS = 16` pointer-loop guard).
  - Verify every decompiled candidate statement through `verify_with_oracle` (`parse_program` -> `compile_program` byte comparison), auto-attaching trailing `payload`/`hexpayload` or stepping down cleanly to raw L4/L2 statements with zero `//` warning/fallback comments if bytes diverge.
