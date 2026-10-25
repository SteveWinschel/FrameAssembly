# Survey Handoff Report: Crate Dependencies, Rust 1.99.1 (Edition 2024), Skills & Modern QA Architecture

## 1. Observation

### 1.1 Toolchain & Compiler Invariants
- **Command**: `rustc --version && cargo --version`
  - **Output**:
    ```text
    rustc 1.99.1 (58cf8f9c3 2026-10-13)
    cargo 1.99.1 (5f94df478 2026-08-27)
    ```
- **Cargo.toml Manifest (`/home/steve/frameassembly/Cargo.toml`)**:
  - Line 3: `version = "1.0.1"`
  - Line 4: `edition = "2024"`
  - Lines 12–20:
    ```toml
    exclude = [
        "frameassembly-vscode/",
        "llms.txt",
        "llms-full.txt",
        "demo.fasm",
        "tests/",
        ".github/",
        ".agents/",
    ]
    ```
  - Lines 22–39: Exactly 17 crates are declared under `[dependencies]`:
    1. `aes = "0.9.3"`
    2. `block-padding = "0.4.2"`
    3. `cbc = "0.2.1"`
    4. `cfb-mode = "0.9.1"`
    5. `clap = "4.6.7"`
    6. `des = "0.9.0"`
    7. `hmac = "0.13.0"`
    8. `logos = "0.14.3"`
    9. `md-5 = "0.11.0"`
    10. `miette = { version = "7.6.0", features = ["fancy"] }`
    11. `pcap-file = "2.0.0"`
    12. `rasn = "0.28.15"`
    13. `rasn-smi = "0.28.15"`
    14. `rasn-snmp = "0.28.15"`
    15. `sha1 = "0.11.0"`
    16. `sha2 = "0.11.0"`
    17. `winnow = "1.0.4"`

### 1.2 Verification of Crates in `src/`
Direct inspection of `src/` confirms the role and integration of every crate:
1. `aes = "0.9.3"`: Imported in `src/builders/l7/snmp/crypto.rs:7` (`use aes::Aes128;`) and used at line 166 for SNMPv3 USM AES-128-CFB encryption per RFC 3826.
2. `block-padding = "0.4.2"`: Imported in `src/builders/l7/snmp/crypto.rs:9` (`use cbc::cipher::{..., block_padding};`) and used at line 159 (`block_padding::ZeroPadding`) for RFC 3414 §8.1.1.2 DES-CBC zero padding.
3. `cbc = "0.2.1"`: Imported in `src/builders/l7/snmp/crypto.rs:9, 19` (`type DesCbcEnc = cbc::Encryptor<Des>;`) for DES-CBC block mode encryption.
4. `cfb-mode = "0.9.1"`: Imported in `src/builders/l7/snmp/crypto.rs:21` (`type Aes128CfbEnc = cfb_mode::Encryptor<Aes128>;`) for AES-128 CFB stream encryption without block padding expansion.
5. `clap = "4.6.7"`: Imported in `src/main.rs:5` (`use clap::{Arg, Command};`) for the CLI interface parsing `input` and optional `-o`/`--output`.
6. `des = "0.9.0"`: Imported in `src/builders/l7/snmp/crypto.rs:11` (`use des::Des;`) for SNMPv3 legacy USM privacy encryption.
7. `hmac = "0.13.0"`: Imported in `src/builders/l7/snmp/crypto.rs:12` (`use hmac::{Hmac, KeyInit, Mac};`) for HMAC-MD5, HMAC-SHA1, and HMAC-SHA2 (SHA-256/384/512) message authentication.
8. `logos = "0.14.3"`: Imported in `src/lexer/mod.rs:6` (`use logos::Logos;`) deriving `Token` with `#[derive(Logos)]` and skip directives (`#[logos(skip r"[ \t\n\f]+")]`, `#[logos(skip r"//.*")]`) for 81 protocol tokens and delimiters.
9. `md-5 = "0.11.0"`: Imported in `src/builders/l7/snmp/crypto.rs:13` (`use md5::Md5;`) for RFC 3414 key localization (`password_to_key_md5`) and HMAC-MD5-96 authentication (`sign_md5`).
10. `miette = { version = "7.6.0", features = ["fancy"] }`: Imported in `src/error.rs:2` (`use miette::Diagnostic;`) deriving `CompilerError` (`LexError`, `ParseError`, `SemanticError`, `BackendError`) with `#[source_code]` and `#[label]`, and in `src/main.rs:8` (`use miette::{IntoDiagnostic, Result};`).
11. `pcap-file = "2.0.0"`: Imported in `src/pcap.rs:1–6` (`use pcap_file::pcapng::{PcapNgBlock, PcapNgWriter};`, `EnhancedPacketBlock`, `InterfaceDescriptionBlock`, `InterfaceDescriptionOption::IfTsResol(9)`) for writing nanosecond-resolution PCAPNG captures.
12. `rasn = "0.28.15"`: Imported in `src/builders/l7/snmp/builder.rs:156, 270, 328, 345` (`rasn::ber::encode`) and `src/builders/l7/snmp/builder.rs:360` (`rasn::types::ObjectIdentifier`) for ASN.1 BER encoding of SNMP messages.
13. `rasn-smi = "0.28.15"`: Imported in `src/builders/l7/snmp/builder.rs:407–464` (`rasn_smi::v1::{Counter, Gauge, IpAddress, NetworkAddress, ObjectSyntax, SimpleSyntax}`, `rasn_smi::v2::Counter64`) for SMIv1 and SMIv2 variable binding structures.
14. `rasn-snmp = "0.28.15"`: Imported in `src/builders/l7/snmp/builder.rs:143, 163, 423, 530–543` (`rasn_snmp::v1::VarBind`, `rasn_snmp::v2::{GetRequest, SetRequest, Trap, Response, InformRequest, GetNextRequest, GetBulkRequest}`, `rasn_snmp::v3::{HeaderData, Message, ScopedPdu, USMSecurityParameters}`) for RFC-compliant SNMP PDUs.
15. `sha1 = "0.11.0"`: Imported in `src/builders/l7/snmp/crypto.rs:14` (`use sha1::Sha1;`) for RFC 3414 key localization (`password_to_key_sha1`) and HMAC-SHA-96 signing (`sign_sha1`).
16. `sha2 = "0.11.0"`: Imported in `src/builders/l7/snmp/crypto.rs:15–16` (`use sha2::{Digest, Sha256, Sha384, Sha512};`) for RFC 7860 modern SNMPv3 SHA-2 authentication and key derivation.
17. `winnow = "1.0.4"`: Imported in `src/parser/mod.rs:13–18` (`use winnow::ModalResult as PResult;`, `winnow::combinator::{alt, cut_err, opt, repeat, separated};`, `winnow::error::{ContextError, ErrMode};`, `winnow::token::any;`) for two-phase parsing of lexical token streams `&'i [(Token<'a>, core::ops::Range<usize>)]`.

### 1.3 Absence of `etherparse` & Discovery of Native Wire Builders
- Search across all repository files (`grep -rn "etherparse" .`) returned **zero occurrences** in `Cargo.toml`, `Cargo.lock`, `src/`, or `tests/`.
- `etherparse` is **NOT** a dependency of `frameassembly`.
- In `src/packet.rs:1–600`, packet assembly is implemented with **native RFC wire encoders**:
  - `internet_checksum(&[&[u8]]) -> u16` (`src/packet.rs:23–38`): Uses Rust 2024 `slice.as_chunks::<2>()` for 16-bit word accumulation and one's complement addition per RFC 1071.
  - `build_ipv4_header(...)` (`src/packet.rs:41–90`): Manual 20-byte RFC 791 header construction with DSCP, ECN, Identification, Flags (DF/MF), TTL, Protocol, and Header Checksum.
  - `build_ipv6_header(...)` (`src/packet.rs:92–130`): RFC 8200 40-byte header with Traffic Class (DSCP/ECN), 20-bit Flow Label, Payload Length, Next Header, and Hop Limit.
  - `build_tcp_packet(...)` (`src/packet.rs:495–550`): RFC 793 / RFC 7323 TCP segment construction with Sequence/Ack numbers, Data Offset, Flags (`SYN`, `ACK`, `FIN`, `RST`, `PSH`, `URG`), Window Size, TCP options (MSS, Window Scale, Timestamps, SACK-Permitted), and IPv4/IPv6 pseudo-header checksum.
  - `build_udp_packet(...)` (`src/packet.rs:553–590`): RFC 768 datagram with IPv4/IPv6 pseudo-header checksum and RFC 768 `0x0000 -> 0xFFFF` zero-checksum mapping.
  - `build_wire_packet(...)` (`src/packet.rs:402–490`): Wire multiplexer chaining IEEE 802.3 Ethernet, IEEE 802.1Q VLAN, IEEE 802.1ad QinQ, RFC 3032 MPLS label stack serialization, L3, and L4.
  - `crc32c(...)` (`src/builders/l4/sctp.rs:32–54`): RFC 4960 SCTP CRC32c polynomial checksum calculation.
- Stale Skill/Rule Defect:
  - `.agents/skills/networking-pcap/SKILL.md` (lines 1–58), `references/patterns.md` (lines 1–890), and `.agents/rules/networking-pcap-best-practices.md` (lines 1–105) currently instruct agents to use `etherparse 0.21.0` (`PacketBuilder`, `SlicedPacket`, `Sum16BitWords`). This is completely stale and does not reflect this codebase.

### 1.4 Status of Existing Skills & Rules
1. Existing 6 skills in `.agents/skills/`:
   - `clap-cli/` (`SKILL.md` 82 lines, `references/patterns.md` 919 lines)
   - `logos-miette-diagnostics/` (`SKILL.md` 73 lines, `references/patterns.md` 894 lines)
   - `networking-pcap/` (`SKILL.md` 57 lines, `references/patterns.md` 890 lines) — **Stale etherparse code**
   - `rasn-snmp-codec/` (`SKILL.md` 80 lines, `references/patterns.md` 488 lines)
   - `rustcrypto-engineering/` (`SKILL.md` 75 lines, `references/patterns.md` 572 lines)
   - `winnow-parser/` (`SKILL.md` 53 lines, `references/patterns.md` 317 lines) — **Needs depth expansion**
2. Corresponding rules in `.agents/rules/`:
   - `clap-best-practices.md` (161 lines)
   - `logos-miette-best-practices.md` (73 lines)
   - `networking-pcap-best-practices.md` (105 lines) — **Stale etherparse code**
   - `rasn-snmp-best-practices.md` (232 lines)
   - `rustcrypto-best-practices.md` (141 lines)
   - `winnow-best-practices.md` (75 lines)
3. Status of `.agents/skills/frameassembly/`: **Does NOT exist yet**.
4. Status of `.agents/skills/rust-modern-qa/`: **Does NOT exist yet**.
5. Status of `.agents/rules/rust-2024-best-practices.md`: Exists, but is only 30 lines. Needs extensive expansion to serve as the definitive QA and language standard.

### 1.5 Repository Test Suite & Verification Results
- **Command**: `cargo test`
  - Output:
    - `tests/corpus_verification_tests.rs`: 4 passed (0 failed).
    - Unit tests (`tests/tier1` to `tier4`): 93 passed (0 failed).
    - Spec tests (`tests/snmp_spec_tests.rs`): 15 passed (0 failed).
    - Doc tests (`src/`): 17 passed (0 failed).
    - Total: **129 passed, 0 failed, 0 warnings**.
- **Command**: `cargo clippy --all-targets -- -D warnings`
  - Output: Exited with code 0 in 8.21s, **zero warnings emitted**.

---

## 2. Logic Chain

1. **Premise 1 (Dependency Scope & Architecture)**:
   - `Cargo.toml` specifies exactly 17 dependencies and Edition 2024.
   - `etherparse` is absent; all packet and frame framing logic in `frameassembly` is built from scratch using native byte-level RFC builders (`src/packet.rs`, `src/builders/`) and written to PCAPNG using `pcap-file 2.0.0` (`src/pcap.rs`).
   - *Inference*: Any skill or rule instructing agents to use `etherparse` is counterproductive, misleads code analysis, and violates repo integrity. `networking-pcap` must be completely renovated to document native RFC wire builders and `pcap-file 2.0.0`.

2. **Premise 2 (Skill Ecosystem Completeness)**:
   - Acceptance criteria require 9 total skills in `.agents/skills/`:
     - 6 existing: `clap-cli`, `logos-miette-diagnostics`, `networking-pcap`, `rasn-snmp-codec`, `rustcrypto-engineering`, `winnow-parser`.
     - 3 new/pending: `ai-seo-training-data`, `frameassembly`, `rust-modern-qa`.
   - Currently, `.agents/skills/frameassembly/` and `.agents/skills/rust-modern-qa/` do not exist.
   - *Inference*: Dedicated `SKILL.md` and `references/patterns.md` must be designed and authored for both `frameassembly` and `rust-modern-qa`.

3. **Premise 3 (Rust 1.99.1 Edition 2024 Language & QA Rigor)**:
   - The toolchain is verified as `rustc 1.99.1` and `cargo 1.99.1` with `edition = "2024"`.
   - Edition 2024 introduces strict language rules:
     - Match ergonomics: Reference patterns must match `&expr` directly without explicit `ref`/`ref mut`.
     - RPIT lifetime captures: Captured by default; explicit restriction with `+ use<...>`.
     - Static mut deprecation: Deny-by-default `static_mut_refs`; replaced with `LazyLock`, `OnceLock`, and `Atomic*`.
     - Slice idioms: `as_chunks::<N>()` (const in 1.99+), `as_array::<N>()`, `array_windows::<N>()`, `get_disjoint_mut`.
     - Single-binary merged doctests (`cargo test --doc`) with zero failure tolerance.
     - Unsafe hygiene: `unsafe_op_in_unsafe_fn` mandatory `// SAFETY:` rationale, `unsafe extern "C"` with `safe fn`, `#[unsafe(...)]` attributes.
   - The existing `.agents/rules/rust-2024-best-practices.md` is only 30 lines and lacks detailed implementation patterns, clippy configurations, multi-tier QA blueprints, and corpus verification standards.
   - *Inference*: `rust-2024-best-practices.md` must be deeply expanded, and `rust-modern-qa` skill must provide full reference implementations for multi-tier test architectures and corpus validation.

---

## 3. Caveats

1. **No Source Code Modifications**:
   - `src/` must remain completely unmodified per hard repository guardrails (`git diff src/` must remain empty). All upgrades apply strictly to `.agents/skills/` and `.agents/rules/`.
2. **Version Invariance**:
   - `Cargo.toml` `version = "1.0.1"` must never be bumped.
3. **Crate Exclusions**:
   - Heavy AI documentation files and `.agents/` are already excluded in `Cargo.toml:12–20`; newly generated `docs/*.md` chunks will also need to be kept excluded when packaged.
4. **Scope Boundaries**:
   - This survey focuses on crate dependencies, Rust 1.99.1 Edition 2024, existing skills/rules, and blueprints for upgrades. The execution of example expansion (R2) and AI SEO documentation (R1) are handled by peer/orchestrator pipelines.

---

## 4. Conclusion & Detailed Upgrade Blueprints

### 4.1 Dependency Catalog (All 17 Crates)

| # | Crate | Version | Category | Primary Usage in `frameassembly` |
|---|---|---|---|---|
| 1 | `aes` | `0.9.3` | Cryptography | `Aes128` block cipher for SNMPv3 USM AES-128-CFB stream encryption (RFC 3826). |
| 2 | `block-padding` | `0.4.2` | Cryptography | `ZeroPadding` algorithm for SNMPv3 USM DES-CBC padding (RFC 3414 §8.1.1.2). |
| 3 | `cbc` | `0.2.1` | Cryptography | `cbc::Encryptor<Des>` cipher block mode for SNMPv3 USM DES-CBC encryption. |
| 4 | `cfb-mode` | `0.9.1` | Cryptography | `cfb_mode::Encryptor<Aes128>` for 128-bit CFB stream cipher (byte-for-byte exact length). |
| 5 | `clap` | `4.6.7` | CLI | `Command`, `Arg` builder in `src/main.rs` for `frameassembly <input> [-o <out>]`. |
| 6 | `des` | `0.9.0` | Cryptography | `Des` 64-bit block cipher for legacy SNMPv3 USM DES-CBC encryption. |
| 7 | `hmac` | `0.13.0` | Cryptography | `Hmac` with MD5, SHA-1, SHA-256/384/512 for SNMPv3 USM message authentication tags. |
| 8 | `logos` | `0.14.3` | Lexer | `#[derive(Logos)]` for zero-allocation tokenization of 81 protocol keywords and syntax. |
| 9 | `md-5` | `0.11.0` | Cryptography | `Md5` digest for RFC 3414 SNMPv3 key localization and HMAC-MD5-96 signing. |
| 10 | `miette` | `7.6.0` (`fancy`) | Diagnostics | `Diagnostic` derive on `CompilerError` with span labels and terminal color rendering. |
| 11 | `pcap-file` | `2.0.0` | PCAP Engine | `PcapNgWriter` with nanosecond resolution (`IfTsResol(9)`) in `src/pcap.rs`. |
| 12 | `rasn` | `0.28.15` | ASN.1 Codec | `rasn::ber::encode` for BER serialization of SNMP messages and security parameters. |
| 13 | `rasn-smi` | `0.28.15` | ASN.1 SMI | SMIv1 & SMIv2 types (`Counter`, `Gauge`, `IpAddress`, `Counter64`, `ObjectSyntax`). |
| 14 | `rasn-snmp` | `0.28.15` | Protocol Model | SNMPv1, SNMPv2c, and SNMPv3 protocol PDUs (`GetRequest`, `SetRequest`, `Trap`, `Message`). |
| 15 | `sha1` | `0.11.0` | Cryptography | `Sha1` digest for RFC 3414 key localization and HMAC-SHA-96 signing. |
| 16 | `sha2` | `0.11.0` | Cryptography | `Sha256`, `Sha384`, `Sha512` for RFC 7860 modern SNMPv3 authentication and keys. |
| 17 | `winnow` | `1.0.4` | Parser | Combinators (`seq!`, `alt`, `cut_err`, `repeat`, `separated`) for two-phase token stream parsing. |

---

### 4.2 Blueprint: Deep Upgrade of the 6 Existing Skills & Rules

#### 1. `networking-pcap` (`SKILL.md`, `references/patterns.md`, `networking-pcap-best-practices.md`)
- **Root Problem**: Currently documents `etherparse 0.21.0`, which is not in `Cargo.toml`.
- **Exact Upgrade Scope**:
  1. Purge all `etherparse` imports and types (`PacketBuilder`, `SlicedPacket`, `Sum16BitWords`).
  2. Implement **Native RFC Wire Builders**:
     - RFC 1071 Internet Checksum Engine using Rust 2024 `slice.as_chunks::<2>()` and 16-bit one's complement folding.
     - RFC 791 IPv4 Header Builder: IHL, TOS/DSCP/ECN, Total Length, Identification, Flags (DF/MF), TTL, Protocol, and Header Checksum.
     - RFC 8200 IPv6 Header Builder: Version 6, Traffic Class, 20-bit Flow Label, Payload Length, Next Header, Hop Limit, 128-bit addresses.
     - RFC 793 / RFC 7323 TCP Segment Builder: Ports, Sequence/Ack numbers, Data Offset, Flags, Window Size, TCP Options (MSS, Window Scale, Timestamps, SACK-Permitted), and IPv4/IPv6 pseudo-header checksums.
     - RFC 768 UDP Datagram Builder: Ports, Length, and Pseudo-Header Checksum with RFC 768 `0x0000 -> 0xFFFF` zero-checksum mapping.
     - IEEE 802.3 Ethernet II, IEEE 802.1Q Single VLAN (`0x8100`), IEEE 802.1ad QinQ Double VLAN (`0x88A8`/`0x8100`), and RFC 3032 MPLS Label Stack wire serialization.
     - RFC 4960 SCTP CRC32c checksum calculation.
  3. Expand `pcap-file 2.0.0` Production Patterns:
     - PCAPNG generation with mandatory Section Header Block (SHB), Interface Description Block (IDB) with `InterfaceDescriptionOption::IfTsResol(9)` nanosecond resolution, and Enhanced Packet Blocks (EPB) borrowing packet slices via `Cow::Borrowed`.
     - Streaming capture analysis with `PcapNgReader` and interface index resolution.
     - Microsecond vs. nanosecond duration conversion algorithms.
  4. Synchronize `.agents/rules/networking-pcap-best-practices.md` to mandate native RFC wire encoding, zero heap allocations in hot paths, and nanosecond timestamp fidelity.

#### 2. `clap-cli` (`SKILL.md`, `references/patterns.md`, `clap-best-practices.md`)
- **Exact Upgrade Scope**:
  1. Align directly with `clap 4.6.7` builder and derive patterns in Rust 1.99.1 Edition 2024.
  2. Document FrameAssembly's production CLI pattern: `Command::new("frameassembly").version(env!("CARGO_PKG_VERSION")).about(...).arg(Arg::new("input")...).arg(Arg::new("output")...)`.
  3. Integrate `anstyle` terminal styling with Edition 2024 constant colors.
  4. Showcase `TypedValueParser` with `.try_map()`, bounded ranges, and custom path validation.
  5. Add multi-subcommand architectures, global argument propagation, and automated `--help`/`--version` generation without heap allocations.

#### 3. `logos-miette-diagnostics` (`SKILL.md`, `references/patterns.md`, `logos-miette-best-practices.md`)
- **Exact Upgrade Scope**:
  1. Align with `logos 0.14.3` and `miette 7.6.0` (`features = ["fancy"]`).
  2. Implement the **Two-Phase Bridge Pattern**:
     - `#[derive(Logos)]` lexer scanning source code into a token vector `Vec<(Token<'a>, Range<usize>)>`.
     - `winnow` combinator ingestion of token slices with exact source byte span tracking.
     - Fast keyword vs identifier disambiguation with 81 protocol tokens and contextual identifiers.
  3. Model FrameAssembly's `CompilerError` (`LexError`, `ParseError`, `SemanticError`, `BackendError`) with `#[derive(Diagnostic)]`, `#[source_code]`, and `#[label]` annotations.
  4. Document `GraphicalReportHandler` programmatic rendering and terminal header configuration with `NamedSource::new(file, src).with_language("fasm")`.

#### 4. `rasn-snmp-codec` (`SKILL.md`, `references/patterns.md`, `rasn-snmp-best-practices.md`)
- **Exact Upgrade Scope**:
  1. Align with `rasn 0.28.15`, `rasn-smi 0.28.15`, and `rasn-snmp 0.28.15`.
  2. Add complete, copy-pasteable production implementations in `references/patterns.md`:
     - **SNMPv1 Traps (RFC 1157 & RFC 3584)**: Defaulting `agent_addr` to `0.0.0.0` on IPv6 endpoints unless overridden by `AGENTIP <ipv4>`.
     - **SNMPv2c Bulk Walks (RFC 3416)**: `GetBulkRequest` with `non_repeaters` and `max_repetitions`, and standard trap varbind ordering (`sysUpTime.0`, `snmpTrapOID.0`).
     - **SNMPv3 Two-Stage BER USM Serialization (RFC 3412 §6.6)**: Stage 1 encodes `USMSecurityParameters` to BER bytes; Stage 2 assigns to `Message.security_parameters: OctetString` and encodes the outer message.
     - **SNMPv3 ScopedPDU Privacy & Encryption**: DES-CBC zero padding (RFC 3414 §8.1.1.2) vs AES-128-CFB stream mode (RFC 3826).
     - **SNMPv3 Authentication Digest Calculation**: Zeroing `authentication_parameters` before calculating HMAC MAC over the entire BER message.
     - **Dual-Stack VarBinds (RFC 4001)**: `InetAddressType` + 16-byte `OctetString` for IPv6 addresses.

#### 5. `rustcrypto-engineering` (`SKILL.md`, `references/patterns.md`, `rustcrypto-best-practices.md`)
- **Exact Upgrade Scope**:
  1. Align with all 9 cryptographic crates in `Cargo.toml`: `aes 0.9.3`, `block-padding 0.4.2`, `cbc 0.2.1`, `cfb-mode 0.9.1`, `des 0.9.0`, `hmac 0.13.0`, `md-5 0.11.0`, `sha1 0.11.0`, `sha2 0.11.0`.
  2. Implement RFC 3414 and RFC 7860 Password-to-Key Localization:
     - 1,048,576 byte circular password buffer hashing followed by EngineID concatenation.
     - Support for MD5, SHA-1, SHA-224, SHA-256, SHA-384, and SHA-512.
  3. Implement RFC 3414 DES-CBC ZeroPadding (pad only if not multiple of 8, returning unchanged slice if 8-byte aligned).
  4. Implement RFC 3826 AES-128-CFB stream encryption using `cfb_mode::Encryptor<Aes128>` without padding overhead.
  5. Implement Truncated HMAC Message Authentication Codes (96-bit MD5/SHA-1, 192-bit SHA-256, 256-bit SHA-384, 384-bit SHA-512).
  6. Document constant-time tag verification (`Mac::verify_slice`) to prevent timing side channels.

#### 6. `winnow-parser` (`SKILL.md`, `references/patterns.md`, `winnow-best-practices.md`)
- **Exact Upgrade Scope**:
  1. Expand `references/patterns.md` from 317 lines to ~800–900 lines covering `winnow 1.0.4`.
  2. Deeply document **Two-Phase Lexing & Parsing**:
     - Operating directly over `&'i [(Token<'a>, Range<usize>)]` and `TokenSlice<'t, Token<'a>>`.
     - Matching tokens via `any.verify()` and `literal(TokenKind)`.
  3. Combinator Mastery:
     - `seq!`, `separated`, `alt`, `opt`, `repeat`, `cut_err`.
     - Parsing DSL structural blocks (`HOST`, `FLOW`, `COMPILE`).
     - Parsing protocol fields with contextual keyword disambiguation.
  4. Zero-copy string unescaping and hex payload parsing (`take_escaped`, `\xHH`).
  5. Built-in Pratt expression parser (`combinator::expression`).
  6. Rich Diagnostic Integration: Converting `ModalResult`, `ErrMode::Cut`, and `ContextError` with `StrContext` into `CompilerError::ParseError`.

---

### 4.3 Blueprint: New Skill `frameassembly` (`SKILL.md` + `references/patterns.md`)

- **Location**: `.agents/skills/frameassembly/SKILL.md` and `.agents/skills/frameassembly/references/patterns.md`
- **Frontmatter**:
  ```yaml
  ---
  name: frameassembly
  description: Comprehensive architecture guide, DSL syntax specification, AST design, protocol engine, wire builders, and PCAP serialization patterns for FrameAssembly in Rust.
  ---
  ```
- **Content Outline**:
  1. **FrameAssembly Architecture & Dataflow**:
     - Source `.fasm` -> Lexer (`logos`) -> Parser (`winnow`) -> AST -> Protocol Payload Builders (`src/builders/`) -> Wire Packet Assembly (`src/packet.rs`) -> PCAPNG Serializer (`src/pcap.rs`).
  2. **DSL Grammar Specification**:
     - `HOST <name> = { IP: <ip>, MAC: <mac>, MASK: <mask> }`
     - `FLOW <name> = { HOST1 -> HOST2: <PROTOCOL> [FIELDS...], ... }`
     - `COMPILE <name> { <flow_invocations> }`
     - Timing: `WAIT <duration>` (`us`, `ms`, `s`).
     - Iteration: `LOOP <count> { ... }`.
  3. **Full 81-Protocol Native Matrix**:
     - L2: `ARP`, `VLAN`, `QINQ`, `LLDP`, `STP`, `LACP`, `EAPOL`, `MPLS`.
     - L3: `ICMP`, `NDP`, `IGMP`, `MLD`, `GRE`, `VXLAN`, `GENEVE`, `IPSEC`, `ESP`, `AH`, `IKEV2`, `WIREGUARD`, `OSPF`, `BGP`, `RIP`, `VRRP`, `HSRP`, `PIM`, `BFD`, `OPENFLOW`.
     - L4: `TCP`, `UDP`, `SCTP`.
     - L7: `SNMP1`, `SNMP2`, `SNMP3`, `DNS`, `MDNS`, `DHCP`, `NTP`, `PTP`, `RADIUS`, `TACACS`, `SYSLOG`, `NETFLOW`, `IPFIX`, `SFLOW`, `TFTP`, `FTP`, `SSH`, `TELNET`, `HTTP`, `HTTP2`, `GRPC`, `WEBSOCKET`, `TLS`, `QUIC`, `STUN`, `SIP`, `RTP`, `RTSP`, `SMTP`, `IMAP`, `POP3`, `KERBEROS`, `LDAP`, `SMB`, `NFS`, `REDIS`, `MEMCACHED`, `MYSQL`, `POSTGRES`, `MQTT`, `COAP`, `AMQP`, `SSDP`, `WHOIS`, `MODBUS`, `BACNET`, `DNP3`, `S7COMM`, `ETHERNETIP`, `OPCUA`.
  4. **Smart RFC Wire Defaults & Invariants**:
     - Multicast MAC auto-derivation: RFC 2464 (`33:33:xx:xx:xx:xx`) for IPv6 and RFC 1112 (`01:00:5e:xx:xx:xx`) for IPv4.
     - SNMPv1 over IPv6: `agent_addr` default to `0.0.0.0` (RFC 3584 §3.2) unless overridden by `AGENTIP`.
     - Dual-stack flows: Polymorphic flow execution over IPv4 or IPv6 endpoints without code duplication.
     - 1 Statement = 1 Frame & Shared 4-tuple TCP Sequence/Ack tracking for all TCP L7 protocols.
     - Two-stage TCP port inheritance.
  5. **Production DSL Pattern Reference**:
     - Ready-to-use scenario patterns for enterprise NMS, industrial SCADA, VoIP/SIP/RTP, BGP peering, IoT telemetry, and security attack simulations.
     - Enforcing strict headers (`// PROMPT:`, `// TOKENS:`, `// INSTRUCTION:`) and line length guardrails (`avg <= 85`, `max <= 200`).

---

### 4.4 Blueprint: New Skill `rust-modern-qa` & Expansion of `rust-2024-best-practices.md`

#### 1. New Skill `rust-modern-qa` (`SKILL.md` + `references/patterns.md`)
- **Location**: `.agents/skills/rust-modern-qa/SKILL.md` and `.agents/skills/rust-modern-qa/references/patterns.md`
- **Frontmatter**:
  ```yaml
  ---
  name: rust-modern-qa
  description: Comprehensive guide, multi-tier testing architecture, corpus verification, doctest optimization, fuzzing, and quality assurance patterns for modern Rust 1.99.1 Edition 2024.
  ---
  ```
- **Content Outline**:
  1. **Multi-Tier Testing Hierarchy**:
     - Tier 1: Feature & Protocol Coverage (`tests/tier1_feature_coverage.rs`).
     - Tier 2: Boundary, Overflow & Corner Cases (`tests/tier2_boundary_and_corner_cases.rs`).
     - Tier 3: Cross-Feature Combinations & State Tracking (`tests/tier3_cross_feature_combinations.rs`).
     - Tier 4: Real-World Application & Network Telemetry Flows (`tests/tier4_real_world_application_flows.rs`).
     - Spec Regression: SNMP RFC test suite (`tests/snmp_spec_tests.rs`) and backwards compatibility (`tests/cli_and_backwards_compatibility.rs`).
  2. **Corpus Verification Test Architecture (`tests/corpus_verification_tests.rs`)**:
     - Systematic verification of 1,200+ `.fasm` files across 82 directories.
     - Automated checks: header validation (`// PROMPT:`, `// TOKENS:`, `// INSTRUCTION:`), non-numeric naming, protocol folder coverage, non-empty PCAP compilation, and average/maximum line length limits.
     - Thread-safe unique temporary PCAP handling with `std::sync::atomic::AtomicU64` and zero leak guarantee.
  3. **Edition 2024 Single-Binary Doctests (`cargo test --doc`)**:
     - Leveraging merged doctest compilation to execute hundreds of doc tests in under half a second.
     - Writing runnable doc tests for all public structs, methods, and functions.
     - Formatted code blocks (`text`, `console`) for non-Rust DSL snippets.
  4. **Property Testing, Wire Fuzzing & Error Soundness**:
     - Fuzzing parsers and wire decoders with arbitrary byte sequences.
     - Invariant testing: roundtrip serialization, checksum fidelity, no unexpected panics.
  5. **CI/CD Quality Gates & Toolchain Hygiene**:
     - `cargo check --tests`, `cargo test`, `cargo clippy --all-targets -- -D warnings`, `cargo fmt --check`.
     - Zero-warning, zero-clippy-allow policy.

#### 2. Expansion of `.agents/rules/rust-2024-best-practices.md`
- **Current State**: 30 lines.
- **Target State**: 180–220 lines comprehensive engineering standard covering:
  1. **Edition 2024 Match Ergonomics**: Matching on `&expr` directly; strict ban on `ref`/`ref mut` inside patterns.
  2. **Lifetimes & RPIT (`+ use<...>`)**: Default capture rules in 2024; precision capture syntax; mandatory explicit elided lifetimes `'_` on returned references.
  3. **Modern Control Flow**: Chained `if let` / `while let` with `&&` (1.88+); `if let` match guards (1.95+); `let ... else` early returns.
  4. **Concurrency & Thread Safety**: Ban on `static mut` (`static_mut_refs` deny-by-default); `LazyLock`, `OnceLock`, `Atomic<T>` (1.98+), and `Atomic*::update` (1.95+).
  5. **Slice & Array Acceleration**: `as_chunks::<N>()` (const in 1.99+), `as_array::<N>()` (1.93+), `array_windows::<N>()` (1.94+), and `get_disjoint_mut` (1.86+).
  6. **Unsafe Soundness & FFI**: `unsafe_op_in_unsafe_fn` with `// SAFETY:` rationale; `unsafe extern "C"` with `safe fn`; `#[unsafe(...)]` attribute syntax; `&raw const`/`&raw mut` pointers; `std::env::set_var` as `unsafe fn`.
  7. **Cargo & Doctests**: `resolver = "3"`, centralized `Cargo.toml` lints under `[lints.rust]` and `[lints.clippy]`, single-binary combined doctests.
  8. **Multi-Tier Testing & Corpus Quality**: Multi-tier test taxonomy, corpus validation, zero-warning clippy enforcement, and documentation completeness.

---

## 5. Verification Method

To independently verify all findings and validate the state of the workspace:

1. **Verify Rust Compiler & Edition**:
   ```bash
   rustc --version
   cargo --version
   grep -E 'edition = "2024"' Cargo.toml
   ```
2. **Verify Exact 17 Dependencies in Cargo.toml**:
   ```bash
   cargo read-manifest | jq '.dependencies[] | {name: .name, req: .req}'
   ```
3. **Verify Absence of `etherparse` in Project Code**:
   ```bash
   grep -rn "etherparse" Cargo.toml Cargo.lock src/ tests/
   # Returns 0 results (empty)
   ```
4. **Verify Native RFC Wire Builders**:
   ```bash
   grep -n "fn internet_checksum" src/packet.rs
   grep -n "fn build_ipv4_header" src/packet.rs
   grep -n "fn build_tcp_packet" src/packet.rs
   grep -n "PcapNgWriter" src/pcap.rs
   ```
5. **Verify Full Test Suite & Corpus Verification (Zero Warnings / Zero Failures)**:
   ```bash
   cargo test --test corpus_verification_tests
   cargo test
   cargo clippy --all-targets -- -D warnings
   ```
6. **Verify Non-Existence of New Skills (Prior to Creation)**:
   ```bash
   ls -d .agents/skills/frameassembly .agents/skills/rust-modern-qa 2>/dev/null || echo "Skills do not exist yet"
   ```
7. **Invalidation Conditions**:
   - Any modification of files in `src/` (violates guardrails).
   - Any bumping of `version = "1.0.1"` in `Cargo.toml` (violates guardrails).
   - Presence of any compiler or clippy warnings during `cargo test` or `cargo clippy`.
