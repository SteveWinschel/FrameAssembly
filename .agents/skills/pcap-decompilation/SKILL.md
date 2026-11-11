---
name: pcap-decompilation
description: Comprehensive architecture guide, etherparse 0.21.0 and pcap-file 2.0.0 API selection matrix, container linktype normalization rules, fuzz-safe 81-protocol v2.0.0 strict-lowercase decompilation patterns, and self-checking forward-compiler oracle verification for PCAP/PCAPNG-to-.fasm decompilation in FrameAssembly.
---

# PCAP & PCAPNG to `.fasm` Decompilation Engineering Skill (`etherparse 0.21.0`, `pcap-file 2.0.0`)

Use this skill when designing, implementing, debugging, or verifying **PCAP and PCAPNG to `.fasm` decompilation** (`frameassembly reverse <input.pcap> [output.fasm]`, `src/reverse/`, `reverse_pcap_reader(reader)`, `reverse_pcap_bytes(bytes)`, `reverse_pcap_file(path)`—single-argument Rust signatures taking only the input capture) using **`etherparse = { version = "0.21.0", default-features = false, features = ["std"] }`** and **`pcap-file = "2.0.0"`**.

> **Terminology & Architectural Boundary**:
> - Always refer to binary `.pcap` / `.pcapng` to `.fasm` translation as **decompilation** (or **PCAP-to-`.fasm` decompiler**).
> - **Forward Wire Synthesis (`src/packet.rs`, `src/builders/`)** uses 100% zero-heap native byte assembly (see [`networking-pcap`](../networking-pcap/SKILL.md)), whereas **PCAP-to-`.fasm` Decompilation (`src/reverse/`)** uses `etherparse 0.21.0` for zero-copy L2–L4 slicing, `pcap-file 2.0.0` for container streaming, and FrameAssembly v2.0.0's forward compiler as an in-memory self-checking oracle (`verify_with_oracle`).

---

## 1. 5-Stage PCAP-to-`.fasm` Decompiler Pipeline (`src/reverse/mod.rs`)

1. **Stage 1 — Container Normalization (`src/reverse/container.rs`)**:
   - Inspects the leading 4-byte magic number of any `std::io::Read` stream:
     - `0x0A0D0D0A`: Next-Generation Packet Capture (`PCAPNG` via `PcapNgReader`), tracking per-section `InterfaceDescriptionBlock` linktypes across `EnhancedPacketBlock`, `SimplePacketBlock`, and `PacketBlock`.
     - `0xa1b2c3d4` / `0xd4c3b2a1` (microsecond) & `0xa1b23c4d` / `0x4d3cb2a1` (nanosecond): Legacy `PCAP` via `PcapReader`.
   - Normalizes 8 linktypes (`ETHERNET`, `RAW`, `IPV4`, `IPV6`, `LINUX_SLL`, `LINUX_SLL2`, `NULL`, `LOOP`) into canonical 14-byte Ethernet II frames (`NormalizedFrame { timestamp_ns, eth_bytes, is_l3_only }`).
   - Strips 60/64-byte Ethernet zero-padding and 4-byte Frame Check Sequence (FCS) trailers using exact inner L2/L3 header length fields (`IPv4.total_len`, `IPv6.payload_len`, `ARP` 28B body, `EAPOL` `body_len`, or IEEE 802.3 length `<= 1500`).
2. **Stage 2 — Modular `<layer>/<protocol>` Strict-Lowercase Decompilation (`src/reverse/{l2,l3,l4,l7}/<protocol>.rs`)**:
   - Slices L2 (`Ethernet2Slice`, `SingleVlanSlice`, `MacsecSlice`, manual RFC 3032 MPLS `0x8847`/`0x8848`), L3 (`Ipv4Slice`, `Ipv6Slice`, `ArpPacket`), and L4 (`TcpSlice`, `UdpSlice`, `Icmpv4Slice`, `Icmpv6Slice`, `IgmpSlice`, manual RFC 9260 SCTP `proto == 132`) across `src/reverse/{l2,l3,l4}/mod.rs`.
   - Dispatches across 81 per-protocol decompiler modules (`src/reverse/{l2,l3,l4,l7}/<protocol>.rs`, mirroring `src/ast/`, `src/parser/`, and `src/builders/` 1-to-1) to decode all 81 native protocols into `ProtocolDissection { protocol, tokens, residual_payload, explicit_transport }`.
   - **CRITICAL v2.0.0 Invariant**: Every emitted keyword and modifier token across `src/reverse/` **must** use FrameAssembly v2.0.0 strict lowercase `[a-z0-9]+` with zero `_` and zero `-` (`echorequest`, `innervlan`, `mplsttl`, `sackperm`, `clienthello`, `hosthdr`, `transporthdr`, `readholdingregisters`, `isresponse`, `whois`, `pkttype`, `shutdownack`, etc.) so `verify_with_oracle` (`parse_program`) succeeds in memory instead of stepping down to raw `tcp`/`udp` + `hexpayload`.
3. **Stage 3 — Deterministic Topology Discovery (`src/reverse/topology.rs`)**:
   - Assigns sequential **`host1`, `host2`, ...** identifiers (never `host_1`, `host_2`) in order of discovery.
   - Tracks each host's dominant unicast MAC address, pairs broadcast (`ff:ff:ff:ff:ff:ff`) and multicast (`01:00:5e:...`, `33:33:...`, `01:80:c2:...`) frames with deterministic peer hosts, and locks directional arrows (`->` vs `<-`) per endpoint pair.
4. **Stage 4 — Per-Packet Self-Check Compiler Oracle (`src/reverse/oracle.rs`)**:
   - `verify_with_oracle` wraps each candidate statement into a minimal self-contained v2.0.0 `.fasm` program, runs `parse_program` -> `compile_program` in memory (hydrating elided `srcport`, `dstport`, `seq`, and `acknum` fields), and compares the synthesized Ethernet II bytes against `pkt.raw_eth_frame`.
   - If `pkt.raw_eth_frame` has extra trailing bytes, automatically appends `payload "..."` or `hexpayload "..."` before `wait` and re-verifies.
   - If any byte still diverges, steps down cleanly to raw L4 (`tcp`/`udp` + `payload`/`hexpayload`) or raw L2 (`vlan`/`qinq`/`mpls` + `payload`/`hexpayload`) statements—emitting **zero** `//` warning or fallback comments in reversed `.fasm` output.
5. **Stage 5 — Shadow-State Elision & Direct `compile` Emission (`src/reverse/shadow_emit.rs`)**:
   - Mirrors the forward compiler's `EndpointPairPorts` and `Canonical4Tuple` TCP sequence/acknowledgment state machines to elide default modifiers (`srcport 12345`, well-known `dstport`, predictable `seq`/`acknum`, `window 64240`, `ttl 64`, `wait 10ms`) and emits direct flow invocations in `compile { ... }` (**never** folding consecutive frames into `loop`, which was removed in FrameAssembly v2.0.0).

---

## 2. `etherparse 0.21.0` API Selection Matrix

| Decompilation Goal | Idiomatic `etherparse 0.21.0` / Native Pattern | Avoid (Removed / Unsafe / Pre-`0.21` API) |
| :--- | :--- | :--- |
| **Standard Ethernet II frame slicing** | `SlicedPacket::from_ethernet(frame)` | Manual unchecked `[u8]` indexing without header bounds checks |
| **Truncated / snaplen frame fallback** | `LaxSlicedPacket::from_ethernet(frame)` | Rejecting an entire capture when one packet is snaplen-truncated |
| **VLAN & QinQ tag extraction (`0.21.0`)** | `sliced.vlan()` (`Option<VlanSlice::{SingleVlan, DoubleVlan}>`) or iterating `sliced.link_exts` (`ArrayVec<LinkExtSlice, 3>`) | Accessing `sliced.vlan` as a struct field (replaced by `link_exts` + `.vlan()` method in `etherparse 0.21.0`) |
| **IEEE 802.1AE MACsec header (`0x88E5`)** | Match `LinkExtSlice::Macsec(macsec)` inside `sliced.link_exts` | Assuming `link_exts` only ever contains 802.1Q VLAN tags |
| **RFC 3032 MPLS label stack (`0x8847`)** | Peel 4B MPLS shims manually (`label = shim >> 12`, `exp = (shim >> 9) & 7`, `bos = (shim >> 8) & 1`, `mplsttl = shim & 0xFF`) until `bos == 1` | Expecting `etherparse::SlicedPacket` to parse MPLS shims natively |
| **ARP packet decompilation (`0x0806`)** | Match `Some(NetSlice::Arp(arp))` (`arp.operation()`, `arp.sender_hw_addr()`, `arp.sender_protocol_addr()`) | Parsing Ethernet ARP offsets without checking `htype == 1 && ptype == 0x0800 && hlen == 6 && plen == 4` |
| **IPv4 & IPv6 header fields** | Match `Some(NetSlice::Ipv4(v4))` (`v4.header()`, `v4.payload().payload`) and `Some(NetSlice::Ipv6(v6))` (`v6.header()`, `v6.payload().payload`) | Ignoring IPv4 IHL (`> 20`B options) or IPv6 extension headers when locating L4 payload |
| **TCP, UDP, ICMPv4/v6 & IGMP slicing** | Match `sliced.transport` on `TransportSlice::{Tcp(t), Udp(u), Icmpv4(i4), Icmpv6(i6), Igmp(igmp_slice)}` | Treating `Icmpv4` / `Icmpv6` / `Igmp` as raw IP payloads when `TransportSlice` already slices them |
| **TCP options (`mss`, `wscale`, `sackperm`, `tsval`, `tsecr`)** | `for opt_res in tcp.options_iterator() { match opt_res? { TcpOptionElement::... } }` | Manually walking TCP option bytes without bounds/length validation |
| **RFC 9260 SCTP (`ip_proto == 132`)** | Slice 12B SCTP common header (`src_port`, `dst_port`, `vtag`, `cksum_le`) + 4B-aligned chunks (`type`, `flags`, `len`, including `shutdownack` type `8`) from IP payload | Expecting `TransportSlice` to include an `Sctp` variant |

---

## 3. Fuzz-Safety, Bounds-Checking & File Size Guardrails

1. **Zero `.unwrap()` / `.expect()` on Capture Input**: Every decompiler helper in `src/reverse/` must use `.get(..)`, `try_into().ok()`, `checked_add`, and `from_utf8(...).ok()` so corrupt, truncated, or adversarial fuzz inputs never panic.
2. **Bounded DNS Compression Pointers (`MAX_DNS_JUMPS = 16`)**: When decoding RFC 1035 §4.1.4 domain names (`0xC0` pointer bytes) in `dns` and `mdns`, cap pointer jumps at `MAX_DNS_JUMPS = 16` and reject forward/out-of-bounds offsets to prevent infinite loops on self-referencing `0xC000` packets.
3. **ASN.1 BER/DER Remainder Validation**: In `snmp1`/`snmp2`/`snmp3`, `ldap`, and `kerberos` decompilation, decode with `rasn::ber::decode_with_remainder` (or `rasn::der::decode_with_remainder`) and route any trailing bytes into `residual_payload`.
4. **Strict `< 50,000` Byte File Ceiling**: Keep every `src/reverse/**/*.rs` module strictly `< 50,000` bytes (`50 KB`).

---

## 4. Production Reference Templates

Read [references/patterns.md](references/patterns.md) for complete, copy-pasteable v2.0.0 production implementations verified against `src/reverse/`, `etherparse 0.21.0`, and `pcap-file 2.0.0`:
1. **Container Magic Detection, 8-Linktype Normalization & Ethernet Padding/FCS Stripping (`container.rs` pattern)**
2. **`etherparse 0.21.0` Zero-Copy L2–L4 + MPLS + SCTP Decompilation (`src/reverse/{l2,l3,l4}` pattern)**
3. **Fuzz-Safe L7 Protocol Decompilation with Bounded DNS Pointers (`MAX_DNS_JUMPS = 16`) & ASN.1 BER/DER Decoding (`src/reverse/l7/<protocol>.rs` pattern)**
4. **Deterministic Topology Discovery (`host1`, `host2`, Dominant MACs, Arrow Locking) & Direct `compile` Emission (Zero `loop` Blocks)**
5. **Self-Checking Forward-Compiler Oracle (`verify_with_oracle`) & Round-Trip Decompilation Verification Test Template**
