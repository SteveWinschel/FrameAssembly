---
trigger: glob
globs: "src/reverse/**, Cargo.toml, tests/**/*.rs"
description: "PCAP and PCAPNG to .fasm decompilation pipeline, etherparse 0.21.0 zero-copy slicing, pcap-file 2.0.0 container normalization, fuzz-safe protocol decompilation, and self-checking compiler oracle invariants."
---

# PCAP & PCAPNG to `.fasm` Decompilation Best Practices (`etherparse 0.21.0`, `pcap-file 2.0.0`)

Enforce these 5-stage PCAP-to-`.fasm` decompilation (`src/reverse/`), `etherparse 0.21.0`, container normalization, fuzz-safety, and self-checking compiler oracle rules across `src/reverse/` and decompilation test suites:

## 1. 5-Stage PCAP-to-`.fasm` Decompiler Pipeline (`src/reverse/mod.rs`)
Maintain strict separation across the 5 decompilation stages (`reverse_pcap_reader(reader)`, `reverse_pcap_bytes(bytes)`, `reverse_pcap_file(path)`—single-argument signatures taking only the input capture):
1. **Container Normalization (`container.rs`)**: Inspect the leading 4-byte magic (`0x0A0D0D0A` PCAPNG vs `0xa1b2c3d4`/`0xd4c3b2a1` µs PCAP and `0xa1b23c4d`/`0x4d3cb2a1` ns PCAP), normalize `ETHERNET`, `RAW`, `IPV4`, `IPV6`, `LINUX_SLL`, `LINUX_SLL2`, `NULL`, and `LOOP` linktypes into 14-byte Ethernet II frames, and strip 60/64-byte Ethernet zero-padding and 4-byte FCS trailers using inner L2/L3 length fields.
2. **Modular `<layer>/<protocol>` Decompilation (`src/reverse/{l2,l3,l4,l7}/<protocol>.rs`)**: Slice L2–L4 headers via `etherparse 0.21.0` (`src/reverse/{l2,l3,l4}/mod.rs` plus `src/reverse/l3/{ip,ipv6,icmpv6}.rs`) and dispatch across 81 per-protocol modules (`src/reverse/{l2,l3,l4,l7}/<protocol>.rs`, including `src/reverse/l7/{snmp1,snmp2,snmp3}.rs` across all 50 L7 protocol dissectors and 20 L3 protocol dissectors, mirroring `src/ast/`, `src/parser/`, and `src/builders/` 1-to-1) to decode all 81 native protocols into `ProtocolDissection` (`protocol`, canonical lowercase `tokens`, `residual_payload`, `explicit_transport`).
3. **Deterministic Topology Discovery (`topology.rs`)**: Infer sequential `host_1`, `host_2`, ... declarations, track each host's dominant unicast MAC, pair broadcast/multicast traffic deterministically, and lock directional arrows (`->` vs `<-`) per endpoint pair.
4. **Per-Packet Self-Check Compiler Oracle (`oracle.rs`)**: Run `verify_with_oracle` (`parse_program` -> `compile_program`) on every candidate `.fasm` statement, auto-attaching trailing `payload`/`hexpayload` or stepping down cleanly to raw L4 (`tcp`/`udp`) or L2 (`vlan`/`qinq`/`mpls`) statements if any byte diverges—emitting **zero** `//` warning or fallback comments in reversed `.fasm` output.
5. **Shadow-State Elision & Loop Folding (`shadow_emit.rs`)**: Mirror the forward compiler's `EndpointPairPorts` and `Canonical4Tuple` TCP sequence/acknowledgment progression to elide redundant defaults (`srcport 12345`, well-known `dstport`, `seq`, `acknum`, `win 64240`, `wait 10ms`) and fold consecutive identical statements into `loop <N> { ... }` blocks.

## 2. `etherparse 0.21.0` Zero-Copy Slicing Rules
- **Exact Dependency Pin**: `etherparse = { version = "0.21.0", default-features = false, features = ["std"] }` (backed by `arrayvec 0.7.8`).
- **`link_exts` Replaces `.vlan` in `0.21.0`**:
  - `SlicedPacket` and `LaxSlicedPacket` store up to 3 link extensions in `link_exts: ArrayVec<LinkExtSlice, 3>`, where each `LinkExtSlice` is `LinkExtSlice::Vlan(SingleVlanSlice)` (`0x8100`/`0x88A8`/`0x9100`) or IEEE 802.1AE `LinkExtSlice::Macsec(MacsecSlice)` (`0x88E5`).
  - Use `sliced.vlan()` (`Option<VlanSlice<'_>>` returning `SingleVlan` or `DoubleVlan`) or iterate `sliced.link_exts` directly—never access a `.vlan` struct field directly.
- **`SlicedPacket` vs. `LaxSlicedPacket`**: Prefer `SlicedPacket::from_ethernet(frame)` for standard frames and fall back to `LaxSlicedPacket::from_ethernet(frame)` when handling truncated snaplen captures or non-conforming L3/L4 payload lengths.
- **L3, L4 & Manual MPLS / SCTP Handling**:
  - Match `sliced.net` on `NetSlice::{Ipv4(v4), Ipv6(v6), Arp(arp)}` and `sliced.transport` on `TransportSlice::{Tcp(tcp), Udp(udp), Icmpv4(icmp4), Icmpv6(icmp6), Igmp(igmp)}`.
  - Iterate TCP options with `tcp.options_iterator()` (`TcpOptionElement::{Noop, MaximumSegmentSize(mss), WindowScale(ws), SelectiveAcknowledgementPermitted, Timestamp(tsval, tsecr), ...}`).
  - Because `etherparse 0.21.0` does not slice RFC 3032 MPLS (`0x8847`/`0x8848`) or RFC 9260 SCTP (`ip_proto == 132`), peel MPLS shims (`label = shim >> 12`, `exp = (shim >> 9) & 7`, `bos = (shim >> 8) & 1`, `ttl = shim & 0xff`) before L3 slicing and decode the 12-byte SCTP common header + 4-byte padded chunks directly from the IP payload.

## 3. Fuzz-Safety, `< 50 KB` File Ceiling & Terminology Guardrails
- **100% Fuzz-Safe Decompilation**: Every function in `src/reverse/` must use checked slice indexing (`.get(..)`, `split_at_checked`, `try_into().ok()`) with **zero** `.unwrap()` or `.expect()` calls on packet input. Enforce `MAX_DNS_JUMPS = 16` when following RFC 1035 `0xC0` compression pointers and validate ASN.1 BER/DER via `rasn::ber::decode_with_remainder` / `rasn::der::decode_with_remainder`.
- **File Size Cap**: Keep every `src/reverse/**/*.rs` file strictly `< 50,000` bytes (`50 KB`).
- **Terminology**: Always refer to PCAP-to-`.fasm` translation as **decompilation** (or **PCAP-to-`.fasm` decompiler**), never `"reverse dissection"`.
