# For Nerds: Six-Stage Compiler Architecture, Rust Library API & Formal Grammars

[← Main README](../README.md) • [Docs Index](README.md) • [Use-Case Cookbook](02_use_cases.md)

Every other guide in `docs/` took a solemn oath never to say "AST", "zero-copy DFA", or "context-free grammar". You clicked on `13_for_nerds.md`, so the oath does not apply
here. Welcome to the guts.

On the surface, FrameAssembly lets network engineers, firewall administrators, and NOC/SOC operators produce deterministic `.pcap` and `.pcapng` captures from a few lines of
declarative `.frasm` code ("Packets as Code"). Underneath, `frameassembly` (v3.1.0, Rust Edition 2024, `rust-version = "1.88"`) is a six-stage, zero-copy optimizing compiler,
a five-stage PCAP/PCAPNG-to-`.frasm` decompiler, a reusable Rust library crate, and a formally specified language (`text/vnd.frameassembly`) backed by six-way synchronized
context-free grammars, IDE/WASM bindings ([`frameassembly.ai.studio`](https://frameassembly.ai.studio/)), and a `2,690`-scenario compiler-verified corpus. Yes, for a tool
whose job is "make some packets", this is a lot of machinery. No, we are not sorry.

This guide is the dedicated home for **systems engineers**, **Rust developers**, and **AI/ML practitioners**. If you came for the formal RFC 6838 media type specification,
UTF-8 encoding rules, lexical magic numbers, and `.frasm` extension disambiguation (IANA, Freedesktop `shared-mime-info`, Wikidata, and GitHub Linguist), that lives in
**[`docs/12_frasm_specification.md`](12_frasm_specification.md)** and **[`contrib/`](../contrib/)**.

---

## 1. Six-Stage Zero-Copy Rust Compiler Pipeline

FrameAssembly compiles `.frasm` source buffers into `.pcap` (classic libpcap) or nanosecond-precision `.pcapng` (`PCAPNG`) captures through a deterministic six-stage pipeline
in pure userspace—rootless, offline, and requiring **no `libpcap` or raw sockets** (`CAP_NET_RAW` is never required at build time or runtime). The only thing it ever sends
over a wire is nothing, which makes the threat model refreshingly short.

```text
 ┌───────────────────────────────────────────────────────────────────────────────┐
 │                           .frasm Source Text (&'a str)                         │
 └───────────────────────────────────────┬───────────────────────────────────────┘
                                         │
                                         ▼
 ┌───────────────────────────────────────────────────────────────────────────────┐
 │ STAGE 1: Zero-Copy Lexical Analysis (src/lexer/mod.rs — logos 0.14.4)         │
 │  • DFA scanner emitting SpannedToken<'a> = (Token<'a>, Range<usize>) slices   │
 │  • Strict-lowercase [a-z0-9]+ keywords & time units (zero '_'/'-'), 81 protos │
 │  • Flexible user Token::Ident ([a-zA-Z_][a-zA-Z0-9_]*(-[a-zA-Z0-9_]+)*)       │
 └───────────────────────────────────────┬───────────────────────────────────────┘
                                         │
                                         ▼
 ┌───────────────────────────────────────────────────────────────────────────────┐
 │ STAGE 2: Two-Phase Token-Slice Parsing (src/parser/ — winnow 1.0.5)           │
 │  • Operates on Stream<'i, 'a> = &'i [(Token<'a>, Range<usize>, &'a str)]      │
 │  • Protocol-first whois guard + 3-tier scoped dispatch (universal -> protocol │
 │    -> fallback) + plain-English self-healing ("replace '<raw>' with '<kw>'")  │
 │  • Contextual identifier recovery (parse_spanned_ident) for host/flow/params  │
 └───────────────────────────────────────┬───────────────────────────────────────┘
                                         │
                                         ▼
 ┌───────────────────────────────────────────────────────────────────────────────┐
 │ STAGE 3: Semantic Validation (src/parser/validation.rs — miette 7.6)          │
 │  • Symbol uniqueness & duplicate host/flow/param detection                    │
 │  • Flow arity, protocol_requires_ip (L2 MAC-only vs L3+ IP), & dual-stack     │
 │  • IEEE/RFC bounds (vlan/qinq 0..=4095, pcp, dscp, ecn, u8/u16, DNS <=63B)    │
 │  • 9-proto transport tcp|udp gate & cross-protocol modifier exclusivity       │
 └───────────────────────────────────────┬───────────────────────────────────────┘
                                         │
                                         ▼
 ┌───────────────────────────────────────────────────────────────────────────────┐
 │ STAGE 4: Zero-Heap Wire Builders, Checksums & Crypto (src/builders/, packet.rs)│
 │  • Inner-outward encapsulation: L7 -> L4 -> L3 -> MPLS/QinQ/VLAN/Ethernet II  │
 │  • Disjoint-slice RFC 1071 checksums, RFC 8200 UDP 0x0000->0xFFFF rule,       │
 │    RFC 4443/5340/5798/7761 checksums, SCTP CRC32c (LE), DNP3 CRC-16 (LE)      │
 │  • ASN.1 BER/DER (rasn 0.28) + SNMPv3 USM (RFC 3414/3826/7860) Ku -> Kul      │
 │    key localization, DES-CBC / AES-128-CFB, and HMAC-MD5/SHA-1/SHA-2          │
 └───────────────────────────────────────┬───────────────────────────────────────┘
                                         │
                                         ▼
 ┌───────────────────────────────────────────────────────────────────────────────┐
 │ STAGE 5: Stateful 4-Tuple & Bidirectional Port Engine (src/backend/)          │
 │  • Evaluates RunStatement::{Invocation, Frame} inside compile { ... }         │
 │  • Stage 5a (EndpointPairPorts): Two-stage port inheritance across -> and <-  │
 │  • Stage 5b (Canonical4Tuple): Shared TCP seq/acknum state across tcp & L7    │
 │  • Declaration-order unicast MACs (00:00:00:00:00:01..) & post-packet wait    │
 └───────────────────────────────────────┬───────────────────────────────────────┘
                                         │
                                         ▼
 ┌───────────────────────────────────────────────────────────────────────────────┐
 │ STAGE 6: Classic .pcap / Nanosecond .pcapng (src/pcap.rs) & Reverse Decompiler│
 │  • Transactional synthesis -> classic libpcap (.pcap) or PCAPNG (.pcapng)     │
 │  • 5-stage PCAP/PCAPNG-to-.frasm decompiler (host1, host2, oracle verified)   │
 └───────────────────────────────────────────────────────────────────────────────┘
```

### Stage 1: Zero-Copy Strict-Lowercase Lexical Analysis (`src/lexer/mod.rs`)

The front-end tokenizer is built on [`logos 0.14.4`](https://docs.rs/logos) and compiles the `Token<'a>` enum into a jump-table Deterministic Finite Automaton (DFA). It reads
each byte once and never looks back, which is more than most of us can say about our own regexes:

* **Zero-Copy Lifetimes (`Token<'a>`)**: Variable-length tokens—including `Token::Ident(&'a str)`, `Token::StringLit(&'a str)`, `Token::IpAddress(&'a str)`,
  `Token::MacAddress(&'a str)`, `Token::OidStr(&'a str)`, and `Token::Number(&'a str)`—borrow slices directly from the input `&'a str` source buffer without heap allocation.
* **Strict-Lowercase Built-In Keywords (`[a-z0-9]+`, Zero `_`, Zero `-`, No `ignore(ascii_case)`)**: Every built-in keyword and time-unit token (`host`, `ip`, `mac`, `flow`,
  `compile`, `wait`, all 81 protocol names, L2–L7 modifiers such as `echorequest`, `innervlan`, `clienthello`, `hosthdr`, `transporthdr`, `sackperm`, `agentip`, `hellotime`,
  `whois`, `pkttype`, `read`, `write`, `nop`, `error`, `shutdownack`, `readholdingregisters`, `nextheader`, and time suffixes `ns`, `us`, `ms`, `s`, `m`) uses exact lowercase
  `#[token("...")]` attributes without `ignore(ascii_case)`.
* **Token Consolidation & No `loop`**: `Token::Loop` is absent (`loop` blocks were retired in v2.0 in favor of direct flow calls and inline packet statements inside
  `compile { ... }`); `sackperm`, `agentip`, `hellotime` (unified across STP `u16` and HSRP `<= 255` `u8`), `auth` (shared across SNMPv3 USM `auth` and IKEv2 `exchange auth`),
  and `whois` (shared across `Protocol::Whois` and BACnet `whois`) are deduplicated.
* **Flexible User Identifiers**: `Token::Ident` uses `#[regex(r"[a-zA-Z_][a-zA-Z0-9_]*(-[a-zA-Z0-9_]+)*", priority = 1)]` so user-defined `host`, `flow`, and parameter names
  permit uppercase letters, underscores (`core_sw`), and internal hyphens (`fw-dmz-01`) while stopping cleanly before `->`.
* **Six-Tier DFA Priority Disambiguation**: Overlapping lexical classes are resolved deterministically at compile time via `logos` priority weights:
  1. `priority = 6`: IEEE 802.3 MAC addresses across colon-separated (`00:1a:2b:3c:4d:5e`), Windows hyphen-separated (`00-1A-2B-3C-4D-5E`), and Cisco dotted-quad
     (`001a.2b3c.4d5e`) formats—outranks IPv6 hextets and dotted OIDs.
  2. `priority = 5`: Dotted-quad IPv4 literals (`[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+`)—outranks dotted ASN.1 OIDs.
  3. `priority = 4`: Signed decimal and hexadecimal integer literals (`-?[0-9]+|0[xX][0-9a-fA-F]+`).
  4. `priority = 3`: ASN.1 Object Identifiers (`\.?[0-9]+(\.[0-9]+)*`).
  5. `priority = 2`: IPv6 addresses (`::[0-9a-fA-F:.]*|...`) and strict-lowercase time suffixes (`ns`, `us`, `ms`, `s`, `m`).
  6. `priority = 1`: Flexible user-defined identifiers (`[a-zA-Z_][a-zA-Z0-9_]*(-[a-zA-Z0-9_]+)*`).
* **Spanned Token Output (`SpannedToken<'a>`)**: `lexer::lex(input)` returns `Result<Vec<(Token<'a>, Range<usize>)>, CompilerError>`, pairing every token with its exact byte
  offset range in `O(N)` time while skipping whitespace (`[ \t\r\n\f]+`) and single-line comments (`//[^\r\n]*`).

### Stage 2: Two-Phase Token-Slice Combinator Parsing (`src/parser/`)

Rather than parsing raw characters with backtracking regexes (an approach with a long history of producing both parsers and outages), FrameAssembly uses a two-phase
[`winnow 1.0.5`](https://docs.rs/winnow) combinator architecture operating over a contiguous 3-tuple token slice (`Stream<'i, 'a>` in `src/parser/mod.rs`):

```rust
pub type Stream<'i, 'a> = &'i [(Token<'a>, core::ops::Range<usize>, &'a str)];
```

* **Protocol-First `whois` Disambiguation & Three-Tier Scoped Field Dispatch (`src/parser/statement.rs` & `src/parser/fields.rs`)**: Across 81 network protocols, many domain
  keywords naturally overlap (`whois`, `auth`, `hellotime`, `cookie`, `data`, `value`, `version`, `status`, `token`, `msgid`, `group`, `get`, `set`, `response`, `reqid`,
  `echoreply`, `query`, `report`, `request`, `reply`, `read`, `write`, `nop`, `error`, and `keepalive`). Eighty-one protocols sharing one vocabulary is how you get two of them
  fighting over the word `whois`. FrameAssembly prevents cross-protocol keyword shadowing in `parse_frame_statement`:
  1. **Protocol-First Guard**: When `current_protocol.is_none()`, an explicit protocol-keyword matcher runs *before* fallback field parsing so a `whois` statement carrying
     `domain "example.com"` always sets `Protocol::Whois` instead of being intercepted by BACnet's `whois` modifier.
  2. **Three-Tier Modifier Loop**:
     * `parse_universal_field`: Cross-layer L2 (`vlan`, `qinq`, `mpls`, `srcmac`, `dstmac`, `ethertype`), L3 (`ttl`, `dscp`, `ecn`, `flowlabel`, `ipid`, `df`, `mf`,
       `fragoffset`), L4 (`srcport`, `dstport`, `seq`, `acknum`, `win`, `mss`, `wscale`, `sackperm`, `tsval`, `tsecr`, TCP flags—bypassing `ack` and `rst` when the active
       protocol is `coap`, `dhcp`, `tftp`, or `sip`), payload (`payload`, `hexpayload`), and timing (`wait`) modifiers.
     * `dispatch_protocol_field(active_proto, input)`: Routes directly to the active protocol's dedicated combinator module (`src/parser/{l2,l3,l4,l7}/<protocol>.rs`, kept
       `pub(crate) mod` for clean `docs.rs` output).
     * `parse_fallback_field`: Invoked only when diagnosing cross-protocol modifier mistakes so Stage 3 can report a rich semantic error rather than a generic syntax failure.
* **Contextual Keyword Recovery (`parse_spanned_ident` in `src/parser/ident.rs`)**: Every keyword token in `Token<'a>` is mapped in `parse_spanned_ident`, allowing users to
  name hosts, flows, or flow parameters `http`, `dns`, `client`, `server`, `token`, or `status` without reserved-word collisions.
* **Plain-English Self-Healing Diagnostics (`src/parser/mod.rs` & `src/error.rs`)**: Terminal error headings use plain labels (`syntax error`, `validation error`,
  `compile error`) while guiding fixes directly:
  * Common CLI/Scapy habits (`sport`, `dport`, `ack <num>`, `ipv4`/`ipv6`, `=`, `,`, standalone `wait`) get targeted hints (`Use 'srcport <port>'...`, `Use 'acknum <num>'...`).
  * Uppercase, `_`, or `-` typos matching a built-in keyword `<kw>` emit `"replace '<raw>' with '<kw>'"` (powering 1-click Quick Fix actions in `frameassembly-vscode`).
  * Removed `loop` blocks emit `"The 'loop' block was removed in FrameAssembly 2.0; invoke flows or frame statements directly inside 'compile { ... }'."`

### Stage 3: Semantic Validation (`src/parser/validation.rs`)

Once `parse_all` constructs the `Program<'a>` AST, `validate_semantics(&program, &source)` enforces domain invariants before any wire buffers are allocated. Better to be told
"no" by a compiler than by a switch at 2 a.m. Failures come back as structured [`miette 7.6`](https://docs.rs/miette) diagnostics:

1. **Symbol Uniqueness**: Rejects duplicate `host` declarations, duplicate `flow` declarations, and duplicate parameter names within a `flow` signature.
2. **Statement Modifier Uniqueness & Exclusivity**: Rejects duplicate modifiers on the same statement, duplicate TCP flags (`syn syn`), and simultaneous `payload` + `hexpayload`.
3. **IEEE & RFC Field Bounds**:
   * `vlan`, `qinq`, `innervlan`: `0..=4095` (IEEE 802.1Q / 802.1ad 12-bit VID, including `vlan 0` priority-tagged frames), and `pcp`: `0..=7`.
   * `dscp`: `0..=63` (RFC 2474 6-bit DSCP), `ecn`: `0..=3` (RFC 3168 2-bit ECN), `ttl` / `mplsttl`: `0..=255`, `flowlabel`: `0..=0xFFFFF` (`0..=1,048,575`).
   * Protocol `u8` (`0..=255`) and `u16` (`0..=65535`) numeric bounds, `gentrap`: `0..=6` on `snmp1`, and `hellotime`: `0..=255` on `hsrp`.
   * DNS `qname` label lengths (`<= 63` octets per label per RFC 1035) and even-length hexadecimal validation on SNMPv3 `engineid`.
4. **Cross-Protocol & Transport Gates**: Gates `transport tcp|udp` strictly to the 9 dual-transport protocols (`dns`, `sip`, `syslog`, `kerberos`, `nfs`, `memcached`,
   `modbus`, `dnp3`, `ethernetip`), rejects TCP-only modifiers (`syn`/`fin`/`rst`/`psh`/`urg`/`ece`/`cwr`, `seq`, `acknum`, `win`, `mss`, `wscale`, `sackperm`, `tsval`,
   `tsecr`) on non-TCP frames, and enforces SNMPv1/v2c/v3 modifier boundaries.
5. **Flow Arity, Inline `compile` Statements (`RunStatement::{Invocation, Frame}`) & Dual-Stack Endpoint Homogeneity**: Verifies that every flow call and inline packet
   statement resolves to a declared `host` (with at least one of `ip` or `mac`), enforces `protocol_requires_ip` (allowing MAC-only `host` blocks across all 8 pure Layer 2
   protocols: `arp`, `vlan`, `qinq`, `mpls`, `lldp`, `stp`, `lacp`, `eapol`), and rejects mixed IPv4 and IPv6 endpoints on the same statement.

### Stage 4: Zero-Heap Protocol Wire Builders & Checksum/Crypto Engines (`src/builders/` & `src/packet.rs`)

FrameAssembly constructs frames **inner-outward** (`Application Layer 7 → Transport Layer 4 → Network Layer 3 → Data-Link Layer 2`) so every outer header knows the exact byte
length and checksum of its encapsulated payload before serialization:

```text
 ┌─────────────────────────────────────────────────────────────────────────┐
 │ Ethernet II (14B) + Optional QinQ (8B) / VLAN (4B) + Optional MPLS (4B) │
 │  ┌───────────────────────────────────────────────────────────────────┐  │
 │  │ IPv4 Header (20B, RFC 791 cksum) OR IPv6 Header (40B, RFC 8200)   │  │
 │  │  ┌─────────────────────────────────────────────────────────────┐  │  │
 │  │  │ TCP (20B + RFC 7323 opts) / UDP (8B) / SCTP (12B + chunks)  │  │  │
 │  │  │  ┌───────────────────────────────────────────────────────┐  │  │  │
 │  │  │  │ Layer 7 Wire Builder Payload + Optional payload Bytes │  │  │  │
 │  │  │  └───────────────────────────────────────────────────────┘  │  │  │
 │  │  └─────────────────────────────────────────────────────────────┘  │  │
 │  └───────────────────────────────────────────────────────────────────┘  │
 └─────────────────────────────────────────────────────────────────────────┘
```

* **Disjoint-Slice RFC 1071 One's-Complement Checksum (`packet::internet_checksum`)**:
  Implemented over `&[&[u8]]` using Rust's `slice.as_chunks::<2>()` so pseudo-headers, transport headers, and payloads are summed in place without temporary heap vectors:
  * **IPv4 Header Checksum (RFC 791)** and **TCP/UDP Pseudo-Header Checksums (RFC 9293 / RFC 768 / RFC 8200)** across IPv4 (12B) and IPv6 (40B) pseudo-headers.
  * **Mandatory UDP `0x0000` → `0xFFFF` Folding (RFC 768 / RFC 8200 §8.1)**: Whenever the UDP one's-complement sum evaluates to `0x0000`, `build_udp_datagram` writes `0xFFFF`.
  * **L3 Control & Routing Checksums**: Computed automatically for `icmp` (IPv4 & ICMPv6), `ndp`, `igmp`, `mld`, `gre` (when `C=1`), `ospf` (OSPFv2 24B RFC 2328 header on
    IPv4 and OSPFv3 16B RFC 5340 IPv6 pseudo-header checksum on IPv6), `pim` (including RFC 7761 §4.9.3 8-byte header-only checksum on `register`), and `vrrp` (RFC 3768 v2 and
    RFC 5798 v3 pseudo-header checksum).
* **Protocol Fidelity Highlights**:
  * **Standalone 802.1ad `qinq`**: Emits both the outer `0x88A8` S-Tag and inner `0x8100` C-Tag (default `innervlan 1`) even when `qinq` is the statement's primary protocol.
  * **BGP 4-Byte ASNs (RFC 6793)**: Encodes `AS_TRANS` (`23456`) in the 2-byte `My Autonomous System` field plus Optional Parameter Capability `65` carrying the 32-bit `asn`.
  * **IKEv2 & HTTP/2**: Supports `ikev2 exchange auth` (type `35`) and `nextheader` (`nextpayload` alias), and populates RFC 9113 default bodies on `http2 ping` (8B),
    `windowupdate` (4B), and `goaway` (8B) when `payload`/`hexpayload` is omitted.
* **SCTP Castagnoli CRC32c (`builders::l4::sctp::crc32c`, RFC 9260 §3.3.10)** & **DNP3 IEEE 1815 CRC-16 (`builders::l7::dnp3::calculate_dnp3_crc`)**:
  Computed via lookup tables and written in **little-endian** order per RFC 9260 and IEEE 1815-2012.
* **ASN.1 BER/DER & SNMPv3 USM Cryptography (`src/builders/l7/snmp/`)**:
  * Encodes SMIv1/SMIv2 `VarBind` lists across all 9 ASN.1 types and SNMPv1/v2c/v3 PDUs (`get`, `getnext`, `getbulk`, `set`, `response`, `trap`, `inform`, and `report` `0xa8`).
  * Performs RFC 3414 & RFC 7860 1 MB `Ku` → `Kul` key localization (`Md5`, `Sha1`, `Sha256`, `Sha384`, `Sha512`), `DES-CBC` / `AES-128-CFB` `ScopedPDU` encryption, and
    two-pass whole-message truncated HMAC signing.

### Stage 5: Stateful 4-Tuple, Port Inheritance, Auto-MACs & Post-Packet `wait` (`src/backend/`)

`backend::compile_program` evaluates `RunStatement::{Invocation, Frame}` entries in `compile { ... }` and tracks state across frames so you never compute TCP sequence math by
hand:

* **Stage 5a — Bidirectional Port Inheritance (`EndpointPairPorts`)**: Forward `c -> s` defaults `src_port` to `12345` (or custom `srcport`) and `dst_port` to the protocol's
  well-known port; reverse `c <- s` flips `src_port` and `dst_port` automatically.
* **Dynamic `L7DispatchResult` Preservation (`src/backend/l7_dispatch.rs`)**: Preserves dynamic ports and multicast IPs for `dhcp` (`68/67` v4 vs `546/547` v6), `mdns`
  (`224.0.0.251` / `ff02::fb` on UDP `5353`), `ptp` (`319` Event vs `320` General), `radius` (`1812` Auth vs `1813` Accounting), and `snmp2`/`snmp3` (`162` for
  `trap`/`inform`/`report` vs `161` for polling PDUs).
* **Stage 5b — Canonical 4-Tuple TCP State (`Canonical4Tuple` & `TcpStreamState`)**: Initializes `seq1 = 1000` and `seq2 = 1000` per sorted 4-tuple, advances by
  `payload_len + (1 if syn) + (1 if fin)`, and emits `psh ack` (`0x18`) segments for TCP-based L7 statements on the shared connection.
* **Declaration-Order Unicast & RFC Multicast MACs (`HostMacMap` & `derive_mac`)**:
  * **IPv6 Multicast (`ff00::/8`, RFC 2464 §7)**: Maps low 32 bits to `33:33:xx:xx:xx:xx`.
  * **IPv4 Multicast (`224.0.0.0/4`, RFC 1112 §6.4)**: Maps low 23 bits to `01:00:5e:xx:xx:xx`.
  * **Unicast Hosts Omitting `mac`**: Assigns sequential unicast MACs `00:00:00:00:00:01`, `00:00:00:00:00:02`, ... deterministically in `host` declaration order so
    every host keeps a distinct Layer 2 identity across multi-host flows.
* **Post-Packet `wait` Timeline**: Packet 1 starts at `0.000 ms` (epoch `1_700_000_000_000_000_000` ns = `2023-11-14T22:13:20Z`). Each statement's `wait <duration>` advances
  the clock *after* that packet before the next packet is emitted (defaulting to `10ms` = `10_000_000` ns when omitted).

### Stage 6: Classic `.pcap` & Nanosecond `.pcapng` Serialization (`src/pcap.rs`) + 5-Stage Decompiler (`src/reverse/`)

`src/pcap.rs` wraps [`pcap-file 2.0.0`](https://docs.rs/pcap-file) and selects the container format from the output path extension after transactional in-memory synthesis:

1. **Classic `libpcap` (`.pcap` — Default)**: Emits standard classic PCAP (`LINKTYPE_ETHERNET = 1`, `snaplen = 65535`), using classic microsecond headers (`0xA1B2C3D4`) when
   all frame timestamps align to microseconds and RFC/libpcap nanosecond magic (`0xA1B23C4D`) when sub-microsecond `ns` delays are present. Classic `.pcap` opens in Wireshark,
   `tcpdump`, `tcpreplay`, Suricata, Zeek, Snort, Scapy, and legacy network appliances alike.
2. **PCAP Next Generation (`.pcapng`)**: Emits `SHB` (`0x0A0D0D0A`) → `IDB` (`DataLink::ETHERNET`, `snaplen = 65535`, `IfTsResol(9)` nanosecond resolution) → `EPB` blocks.

In the reverse direction (`frameassembly reverse <input.pcap> [output.frasm]`), `src/reverse/` decompiles `.pcap` and `.pcapng` captures into strict-lowercase v3.1.0 `.frasm`:
1. **Container Normalization (`src/reverse/container.rs`)**: Detects PCAPNG vs. microsecond/nanosecond classic PCAP, normalizes 8 linktypes (`ETHERNET`, `RAW`, `IPV4`, `IPV6`,
   `LINUX_SLL`, `LINUX_SLL2`, `NULL`, `LOOP`) into Ethernet II frames, and strips Ethernet padding.
2. **Modular `<layer>/<protocol>` Dissection (`src/reverse/{l2,l3,l4,l7}/<protocol>.rs`)**: Uses `etherparse 0.21.0` for zero-copy L2–L4 slicing and dispatches across 81
   per-protocol decompiler modules matching `src/ast/`, `src/parser/`, and `src/builders/` 1-to-1.
3. **Deterministic Topology Discovery (`src/reverse/topology.rs`)**: Emits sequential `host1`, `host2`, ... blocks (omitting `mac` when it matches the default auto-MAC) and
   locks directional arrows (`->` vs. `<-`) per endpoint pair.
4. **Per-Packet Self-Check Compiler Oracle (`src/reverse/oracle.rs`)**: Verifies every candidate `.frasm` statement through `parse_program` → `compile_program`, stepping down
   cleanly to `tcp`/`udp` with `payload`/`hexpayload` when wire bytes diverge, with zero warning comments.
5. **Shadow-State Elision & Post-Packet `wait` Emission (`src/reverse/shadow_emit.rs`)**: Mirrors 4-tuple port/seq state to elide defaults and emits post-packet `wait` gaps
   derived from `(next_ts - current_ts)` inside a single `compile { ... }` block.

---

## 2. CLI Contract, Supported Packaging & `<layer>/<protocol>` Symmetry

### CLI Command Contract (`src/main.rs` & `contrib/completions/`)

Compiling `.frasm` to `.pcap` is the **default root command**, paired with four subcommands:
* `frameassembly <input.frasm> [output.pcap]` — compiles `.frasm` to classic `.pcap` (default `<input_stem>.pcap`) or `.pcapng` when the output path ends in `.pcapng`.
* `frameassembly show <input.frasm>` — validates and prints a relative-timestamp packet ladder in the terminal without writing disk files.
* `frameassembly reverse <input.pcap> [output.frasm]` — decompiles `.pcap` / `.pcapng` into v3.1.0 `.frasm` code (defaults to `<input_stem>.frasm`).
* `frameassembly help [subcommand]` & `frameassembly version` — display CLI documentation and version (`-h`/`--help` and `-V`/`--version` remain hidden for scripts).
* **Windows Desktop Ergonomics**: Double-clicking `frameassembly.exe` in Windows Explorer prints quickstart instructions and pauses before closing (`GetConsoleProcessList`),
  and dragging a `.frasm`, `.pcap`, or `.pcapng` file onto `frameassembly.exe` compiles or reverses it next to the input file automatically.
* Static Tab-completion scripts live in [`contrib/completions/`](../contrib/completions/README.md), and the 5 supported distribution channels in
  [`contrib/packaging/`](../contrib/packaging/README.md) cover Crates.io (`cargo install frameassembly`), GitHub Releases + `.deb`, NPM (`frameassembly-wasm`), VS Code
  Marketplace (`frameassembly-vscode`), and `SteveWinschel/homebrew-tap-FrameAssembly` (`Homebrew` & `Scoop`).

### Repository `<layer>/<protocol>` Symmetry

FrameAssembly enforces 1-to-1 structural symmetry across `src/`, `examples/`, and `docs/`:

```text
frameassembly/
├── Cargo.toml                         # Crate manifest (v3.1.0, Rust 1.88+, Edition 2024, centralized [lints])
├── grammar.ebnf                       # Formal ISO/IEC 14977 EBNF grammar (strict-lowercase v3.1.0)
├── frameassembly.gbnf                 # GGML BNF grammar for llama.cpp / XGrammar constrained decoding
├── frameassembly.lark                 # Earley/LALR Lark grammar for Outlines / vLLM / Guidance / llguidance
├── llms.txt / llms-full.txt           # AI/search discovery index (llms.txt) & prompt-injection context (llms-full.txt)
├── contrib/
│   ├── completions/                   # Bash, Zsh, Fish, and PowerShell Tab-completion scripts
│   ├── dataset/                       # Offline SFT / FIM / reverse / DPO / self-repair JSONL dataset exporter
│   ├── packaging/                     # .deb, Homebrew & Scoop tap, NPM WASM, and VS Code packaging
│   └── {iana,linguist,magic,mime}/    # text/vnd.frameassembly MIME, libmagic, IANA & Linguist rules
├── frameassembly-wasm/                # WebAssembly (wasm-bindgen) compiler (.pcap/.pcapng), reverse & IDE diagnostics
├── frameassembly-vscode/              # VS Code extension & TextMate grammar (source.frameassembly)
├── src/
│   ├── lib.rs                         # Crate root & public library re-exports
│   ├── main.rs                        # Clap 4.6 CLI + Windows Explorer drag-and-drop / pause handling
│   ├── error.rs                       # CompilerError enum with plain-English miette::Diagnostic spans
│   ├── packet.rs                      # Ethernet/VLAN/QinQ/MPLS/IPv4/IPv6/TCP/UDP framing & RFC 1071 checksums
│   ├── pcap.rs                        # Classic libpcap (.pcap) & PCAPNG (.pcapng, IfTsResol(9)) serializers
│   ├── lexer/mod.rs                   # Logos 0.14.4 strict-lowercase Token<'a> DFA & lex() entrypoint
│   ├── ast/{mod.rs,l2,l3,l4,l7}/      # Program, HostDef, FlowDef, RunStatement & 81 *Spec structs
│   ├── parser/{mod,fields,statement,validation,l2,l3,l4,l7}/ # Winnow combinators & semantic validator
│   ├── builders/{mod,l2,l3,l4,l7}/    # Wire encoders, SCTP CRC32c, DNP3 CRC-16, and SNMPv3 USM crypto
│   ├── backend/{mod,l7_dispatch}.rs   # compile_program(), generate_pcap(), 4-tuple, auto-MACs & post-packet wait
│   └── reverse/{mod,container,topology,oracle,shadow_emit,l2,l3,l4,l7}/ # 5-stage PCAP/PCAPNG decompiler
├── docs/                              # 13 Markdown guides
├── examples/                          # 2,690 human-first .frasm scenarios across 82 directories + layer READMEs
└── tests/                             # Integration, RFC wire, decompiler, packaging & corpus verification suites
```

---

## 3. Using `frameassembly` as a Rust Library

In addition to the `frameassembly` CLI binary, the crate exposes its full compiler and decompiler pipelines as a library, so Rust projects can synthesize deterministic network
frames in memory for protocol parser unit tests, IDS/IPS engine benchmarks, or automated `.pcap` fixture generation.

### Public API Reference

| Function / Type | Signature & Purpose |
| :--- | :--- |
| [`lexer::lex`](../src/lexer/mod.rs) | `lex(input) -> Result<Vec<(Token<'a>, Range<usize>)>, CompilerError>` — Zero-copy `Token<'a>` slices + byte spans. |
| [`parser::parse_program`](../src/parser/mod.rs) | `parse_program(input_str) -> Result<Program<'a>, CompilerError>` — Lexes, parses into `Program<'a>`, and validates. |
| [`parser::validate_semantics`](../src/parser/validation.rs) | `validate_semantics(program, src) -> Result<(), CompilerError>` — Checks symbols, arity, IP/MAC rules, and ranges. |
| [`backend::compile_program`](../src/backend/mod.rs) | `compile_program(program) -> Result<Vec<(Vec<u8>, u64)>, String>` — Synthesizes `(frame_bytes, ts_nanos)` in memory. |
| [`backend::generate_pcap`](../src/backend/mod.rs) | `generate_pcap(program, path) -> Result<(), String>` — Writes classic `.pcap` (default) or `.pcapng` (`.pcapng` path). |
| [`packet::build_wire_packet`](../src/packet.rs) | `pub fn build_wire_packet(...) -> Result<Vec<u8>, CompilerError>` — Low-level Ethernet/VLAN/QinQ/MPLS + IPv4/IPv6 + TCP/UDP frame builder. |
| [`pcap::PcapWriter`](../src/pcap.rs) | Streaming capture writer + in-memory `serialize_classic_pcap` / `serialize_pcapng` (`LINKTYPE_ETHERNET`, `IfTsResol(9)`). |
| [`reverse::reverse_pcap_reader`](../src/reverse/mod.rs) | `reverse_pcap_reader(reader) -> Result<ReverseOutput, CompilerError>` — Decompiles a `.pcap`/`.pcapng` stream. |
| [`reverse::reverse_pcap_bytes`](../src/reverse/mod.rs) | `reverse_pcap_bytes(bytes) -> Result<ReverseOutput, CompilerError>` — Decompiles an in-memory `.pcap`/`.pcapng` slice. |
| [`reverse::reverse_pcap_file`](../src/reverse/mod.rs) | `pub fn reverse_pcap_file(path: impl AsRef<Path>) -> Result<ReverseOutput, CompilerError>` — Decompiles a `.pcap`/`.pcapng` file on disk. |
| [`error::CompilerError`](../src/error.rs) | `miette::Diagnostic` enum (`LexError`, `ParseError`, `SemanticError`, `BackendError`) with `(start_byte, byte_len)` spans and plain-English CLI codes. |

### Example 1: In-Memory Frame Synthesis & Byte-Offset Assertions

```rust
use frameassembly::backend::compile_program;
use frameassembly::parser::parse_program;

fn main() {
    let frasm = r#"
        host hmi { ip 192.168.10.5  mac 00:1a:2b:3c:4d:5e }
        host plc { ip 192.168.10.20 mac 00:1a:2b:3c:4d:5f }

        flow modbus_poll(c, s) {
            c -> s tcp syn srcport 50100 dstport 502 seq 1000 win 64240 mss 1460 wait 1ms
            c <- s tcp syn ack seq 2000 acknum 1001 win 64240 mss 1460 wait 1ms
            c -> s tcp ack wait 1ms
            c -> s modbus txid 1 unitid 1 readholdingregisters addr 100 count 4 wait 5ms
            c <- s modbus txid 1 unitid 1 readholdingregisters isresponse value 42
        }

        compile {
            modbus_poll(hmi, plc)
        }
    "#;

    let program = parse_program(frasm).expect("valid v3.1.0 .frasm specification");
    let frames = compile_program(&program).expect("in-memory wire synthesis succeeds");
    assert_eq!(frames.len(), 5);

    // Frame 3 (0-indexed) is the Modbus request; post-packet `wait 5ms` places Frame 4 at +5,000,000 ns
    let (req_frame, req_ts_ns) = &frames[3];
    let (resp_frame, resp_ts_ns) = &frames[4];
    assert_eq!(&req_frame[12..14], &[0x08, 0x00]);
    assert_eq!(u16::from_be_bytes([req_frame[36], req_frame[37]]), 502);
    assert_eq!(*resp_ts_ns - *req_ts_ns, 5_000_000);
    assert_eq!(u16::from_be_bytes([resp_frame[34], resp_frame[35]]), 502);
    assert_eq!(u16::from_be_bytes([resp_frame[36], resp_frame[37]]), 50100);
}
```

### Example 2: Writing Deterministic `.pcap` or `.pcapng` Fixtures to Disk

```rust
use frameassembly::backend::generate_pcap;
use frameassembly::parser::parse_program;

fn write_dns_fixture(output_path: &str) {
    let frasm = r#"
        host stub_v6     { ip 2001:db8:10::5 }
        host resolver_v6 { ip 2001:4860:4860::8888 }

        compile {
            stub_v6 -> resolver_v6 dns query txid 0x1a2b qname "api.example.com" qtype "aaaa" wait 2ms
            stub_v6 <- resolver_v6 dns response txid 0x1a2b qname "api.example.com" qtype "aaaa" rdata "2001:db8:99::80" ansttl 300
        }
    "#;

    let program = parse_program(frasm).expect("valid IPv6 DNS specification");
    // Writes classic .pcap by default, or PCAPNG with IfTsResol(9) if output_path ends in ".pcapng"
    generate_pcap(&program, output_path).expect("capture written cleanly");
}
```

### Example 3: Inspecting Structured `miette` Diagnostics Programmatically

```rust
use frameassembly::error::CompilerError;
use frameassembly::parser::parse_program;

fn verify_mixed_ip_family_rejection() {
    let invalid_frasm = r#"
        host v4_node { ip 10.0.0.1 }
        host v6_node { ip 2001:db8::1 }
        compile {
            v4_node -> v6_node icmp echorequest
        }
    "#;

    let err = parse_program(invalid_frasm).expect_err("mixed IPv4/IPv6 endpoints must fail");
    match err {
        CompilerError::SemanticError { message, span, .. } => {
            assert!(message.contains("Mixed IPv4 and IPv6 endpoints"));
            assert!(span.1 > 0);
        }
        other => panic!("Expected SemanticError, got: {:?}", other),
    }
}
```

---

## 4. Formal Grammars, Constrained LLM Decoding & RLVR Architecture

Because `.frasm` v3.1.0 is a compact, non-Turing-complete specification language with strict-lowercase `[a-z0-9]+` built-in keywords and zero mandatory protocol sub-keywords,
it is directly suited for **constrained LLM decoding** (100% syntactically valid generation) and **Reinforcement Learning with Verifiable Rewards (RLVR)**.

### Six-Way Grammar, Lexer, IDE & WASM Lockstep

FrameAssembly keeps six grammar, IDE, and WASM artifacts in automated lockstep via `tests/corpus_verification_tests.rs`, verifying that every strict-lowercase `#[token("...")]`
literal in `src/lexer/mod.rs` exists in every grammar with zero `_`, zero `-`, and zero `loop`:

| Artifact | Format | Target Inference Engines & Tooling |
| :--- | :--- | :--- |
| [`src/lexer/mod.rs`](../src/lexer/mod.rs) | Rust `logos 0.14.4` DFA | Authoritative strict-lowercase compiler token vocabulary (`Token<'a>`) |
| [`grammar.ebnf`](../grammar.ebnf) | ISO/IEC 14977 EBNF | Canonical human and compiler context-free grammar specification |
| [`frameassembly.gbnf`](../frameassembly.gbnf) | GGML BNF (`GBNF`) | `llama.cpp` (`--grammar-file`), `MLC-LLM`, `XGrammar`, `KoboldCpp`, `TabbyAPI` |
| [`frameassembly.lark`](../frameassembly.lark) | Lark Earley / LALR | `Outlines`, `vLLM` (`guided_grammar`), `SGLang`, `Guidance`, `llguidance` |
| [`frameassembly.tmLanguage.json`][tmlang] | TextMate JSON (`source.frameassembly`) | VS Code (`frameassembly-vscode`), VSCodium, Cursor, Windsurf, and GitHub/Shiki |
| [`frameassembly-wasm/src/lib.rs`](../frameassembly-wasm/src/lib.rs) | WebAssembly (`wasm-bindgen`) | Browser `.pcap`/`.pcapng` compiler, `reverse_pcap`, `inspect_frasm`, `validate_frasm` |

[tmlang]: ../frameassembly-vscode/syntaxes/frameassembly.tmLanguage.json

### Core v3.1.0 Grammar Productions (`EBNF` / `GBNF` / `Lark`)

All three context-free grammars enforce strict-lowercase `host`, optional `flow`, and `compile` blocks, flexible user identifiers, and `run_statement = flow_invocation | frame_statement`:

```ebnf
(* ISO/IEC 14977 EBNF excerpt — grammar.ebnf *)
program          = { top_level_decl } , compile_block , { top_level_decl } ;
top_level_decl   = host_declaration | flow_declaration ;
host_declaration = "host" , identifier , "{" , host_property , { host_property } , "}" ;
host_property    = ( "ip" , ip_address ) | ( "mac" , mac_address ) ;
flow_declaration = "flow" , identifier , "(" , [ param_list ] , ")" , "{" , { frame_statement } , "}" ;
frame_statement  = endpoint , ( "->" | "<-" ) , endpoint , { frame_field } ;
compile_block    = "compile" , "{" , { run_statement } , "}" ;
run_statement    = flow_invocation | frame_statement ;
```

```bnf
# GGML BNF excerpt — frameassembly.gbnf
root ::= ws (host-decl | flow-decl)* compile-block (host-decl | flow-decl)* ws
host-decl ::= "host" ws1 ident ws "{" ws host-prop+ "}" ws
host-prop ::= ("ip" ws1 ip-addr | "mac" ws1 mac-addr) ws
flow-decl ::= "flow" ws1 ident ws "(" ws param-list? ")" ws "{" ws frame-stmt* "}" ws
compile-block ::= "compile" ws "{" ws run-stmt* "}" ws
run-stmt ::= flow-call | frame-stmt
```

```lark
// Earley / LALR Lark excerpt — frameassembly.lark
start: top_level_decl* compile_block top_level_decl*
top_level_decl: host_decl | flow_decl
host_decl: "host" ident "{" host_prop+ "}"
host_prop: "ip" ip_addr | "mac" MAC_ADDR
flow_decl: "flow" ident "(" param_list? ")" "{" frame_stmt* "}"
compile_block: "compile" "{" run_stmt* "}"
run_stmt: flow_call | frame_stmt
```

### Constrained Decoding with `llama.cpp` (`frameassembly.gbnf`) & `Outlines` / `vLLM` (`frameassembly.lark`)

```bash
llama-cli \
  -m qwen2.5-coder-7b-instruct-q8_0.gguf \
  --grammar-file frameassembly.gbnf \
  -p "Write a FrameAssembly v3.1.0 (.frasm) program that performs a TCP handshake between 10.0.0.1 and 10.0.0.2 on port 443 and sends a TLS clienthello with sni 'secure.example.com'." \
  > generated.frasm && frameassembly generated.frasm synthesized.pcap
```

```python
from pathlib import Path
import outlines

lark_grammar = Path("frameassembly.lark").read_text(encoding="utf-8")
model = outlines.models.transformers("Qwen/Qwen2.5-Coder-7B-Instruct")
generator = outlines.generate.cfg(model, lark_grammar)

frasm_code = generator(
    "Generate a FrameAssembly v3.1.0 (.frasm) specification for a bgp open and keepalive "
    "session between peer_a (10.0.0.1, asn 65001) and peer_b (10.0.0.2, asn 65002)."
)
```

### Four-Stage Hierarchical Verifiable Compiler Reward (RLVR / GRPO)

Because `frameassembly` compiles in microseconds in pure memory without `libpcap` or network interfaces, the Rust library serves directly as a dense, deterministic reward
oracle `R(x, y)` in `[0.0, 1.0]` for GRPO / PPO post-training:

1. **Stage 1 — Lexical Validity (`R = 0.15`, `+0.15`)**: `frameassembly::lexer::lex(candidate)` succeeds with zero `LexError` tokens.
2. **Stage 2 — Syntactic AST Validity (`R = 0.40`, `+0.25`)**: `frameassembly::parser::parse_program(candidate)` builds a syntactically valid `Program<'a>` AST.
3. **Stage 3 — Semantic Validity (`R = 0.70`, `+0.30`)**: `frameassembly::parser::validate_semantics(&program, candidate)` passes symbol, arity, range, and IP-family gates.
4. **Stage 4 — Wire & Reverse Decompiler Oracle (`R = 1.00`, `+0.30`)**: `frameassembly::backend::compile_program(&program)` synthesizes valid Ethernet frames and round-trips
   cleanly through `frameassembly::reverse::reverse_pcap_bytes`.

```rust
use frameassembly::backend::compile_program;
use frameassembly::error::CompilerError;
use frameassembly::lexer::lex;
use frameassembly::parser::parse_program;

/// Computes a dense 4-stage verifiable reward in [0.0, 1.0] for an LLM-generated `.frasm` candidate.
pub fn compute_rlvr_reward(candidate_frasm: &str) -> f64 {
    if lex(candidate_frasm).is_err() {
        return 0.0;
    }
    let mut reward = 0.15; // Stage 1 passed (R = 0.15): valid strict-lowercase lexical tokens

    match parse_program(candidate_frasm) {
        Ok(program) => {
            reward += 0.55; // Stage 2 (+0.25 -> R = 0.40) + Stage 3 (+0.30 -> R = 0.70) passed
            if let Ok(frames) = compile_program(&program)
                && !frames.is_empty()
                && frames.iter().all(|(bytes, _)| bytes.len() >= 14)
            {
                reward += 0.30; // Stage 4 passed (R = 1.00): valid wire frames synthesized
            }
        }
        Err(CompilerError::SemanticError { .. }) => {
            reward += 0.25; // Stage 2 passed (R = 0.40), failed Stage 3 semantics
        }
        Err(_) => {}
    }
    reward
}
```

---

## 5. Human-First Verified Corpus (`examples/`) & Offline ML Dataset Exporter (`contrib/dataset/`)

Every `.frasm` file across the **`2,690` verified scenarios** (`>= 30` per protocol across all 81 protocols plus `106` multi-host topologies in [`examples/`](../examples/)) is
continuously validated by `cargo test --test corpus_verification_tests`.

In FrameAssembly v3.1.0, `examples/` is strictly **human-first**:
* **Readable Networking Comments**: Every scenario opens with concise `//` comments explaining what network behavior or failure mode the capture tests, key protocol/port/OID
  details, and the matching **`// Wireshark:`** display filter (`snmp`, `icmp || icmpv6`, `bgp`, `isakmp`, `modbus`, `tls.handshake`, etc.)—with zero synthetic ML prompt tags
  cluttering human-facing `.frasm` files.
* **Minimal Two-Block Starters in Every Protocol Directory**: Every one of the 81 protocol directories includes a `<protocol>_default_frame.frasm` starter using minimal
  `host` + `compile` syntax (zero `flow` boilerplate) alongside stateful multi-packet and dual-stack `flow` scenarios.
* **Open-Code Quality Gates**: Every file satisfies word count `>= 50` words, file size `< 50,000` bytes, average line length `<= 85` characters, maximum line length `<= 200`
  characters, post-packet `wait` ordering, and 100% forward compilation + wire synthesis.
* **Offline JSONL Dataset Export (`contrib/dataset/`)**: Researchers training or fine-tuning code models can generate multi-task JSONL datasets (forward natural-language-to-
  `.frasm` SFT pairs, fill-in-the-middle spans, `.pcap`-to-`.frasm` reverse decompilation pairs, contrastive negative pairs, and compiler-guided self-repair trajectories) from
  the clean `examples/` corpus via [`contrib/dataset/`](../contrib/dataset/) without embedding training metadata inside the example files themselves.

### Corpus Example 1: Minimal Two-Block Protocol Starter (`host` + `compile`)

```frameassembly
// Minimal BGP-4 default frame between two eBGP routers on TCP port 179.
// Wireshark: bgp
host peer_a { ip 10.0.0.1 mac 00:1c:73:00:00:01 }
host peer_b { ip 10.0.0.2 mac 00:1c:73:00:00:02 }

compile {
    peer_a -> peer_b bgp
}
```

### Corpus Example 2: Dual-Stack ICMPv4 / ICMPv6 Echo Flow

```frameassembly
// Dual-stack ICMPv4 and ICMPv6 Echo Request and Echo Reply using one reusable flow.
// Wireshark: icmp || icmpv6
host client_v4 { ip 10.0.0.10 }
host dns_v4    { ip 8.8.8.8 }
host client_v6 { ip 2001:db8::10 }
host dns_v6    { ip 2001:4860:4860::8888 }

flow dual_stack_ping(ep_a, ep_b) {
    ep_a -> ep_b icmp echorequest id 100 seq 1 ttl 64 payload "dual-stack-ping" wait 5ms
    ep_a <- ep_b icmp echoreply   id 100 seq 1 ttl 57 payload "dual-stack-ping"
}

compile {
    dual_stack_ping(client_v4, dns_v4)
    dual_stack_ping(client_v6, dns_v6)
}
```

### Corpus Example 3: Cross-Layer IEEE 802.1Q VLAN + TCP Handshake + Modbus/TCP Poll

```frameassembly
// Industrial OT Modbus/TCP holding register poll over VLAN 200 with DSCP EF (46).
// Wireshark: vlan.id == 200 && modbus
host scada_hmi { ip 172.16.200.10 mac 00:1b:21:aa:bb:01 }
host rtu_plc   { ip 172.16.200.50 mac 00:1b:21:aa:bb:50 }

flow ot_register_poll(hmi, plc) {
    hmi -> plc tcp syn srcport 52100 dstport 502 seq 5000 win 64240 mss 1460 vlan 200 pcp 5 dscp 46 wait 1ms
    hmi <- plc tcp syn ack seq 9000 acknum 5001 win 64240 mss 1460 vlan 200 pcp 5 dscp 46 wait 1ms
    hmi -> plc tcp ack vlan 200 pcp 5 dscp 46 wait 1ms
    hmi -> plc modbus txid 77 unitid 1 readholdingregisters addr 40001 count 2 vlan 200 pcp 5 dscp 46 wait 4ms
    hmi <- plc modbus txid 77 unitid 1 readholdingregisters isresponse value 1250 vlan 200 pcp 5 dscp 46
}

compile {
    ot_register_poll(scada_hmi, rtu_plc)
}
```

---

That is the whole machine. If you found a bug in it, the corpus gates would very much like to hear about it before the rest of us do. Back to the people-friendly docs:
[← Main README](../README.md) • [Docs Index](README.md) • [Use-Case Cookbook](02_use_cases.md)
