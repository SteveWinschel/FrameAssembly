# AGENTS.md — FrameAssembly AI Agent & LLM Onboarding Guide

**FrameAssembly** (`frameassembly` v1.2.1) is a Rust 2024 Domain-Specific Language (DSL) and optimizing compiler that compiles declarative `.fasm` network traffic specifications into deterministic, nanosecond-precision `.pcap` / `.pcapng` packet captures across **81 native Layer 2 through Layer 7 protocols** (`2,611` verified `.fasm` corpus scenarios).

---

## 1. Quick Build, Test & Verification Commands

```bash
# Cross-platform bootstrap install (curl + C linker + rustup >= 1.85 + cargo install)
curl -fsSL https://raw.githubusercontent.com/SteveWinschel/FrameAssembly/main/install.sh | sh

# Build compiler and CLI binary
cargo build --release

# Run all unit, integration, and corpus verification tests
cargo test

# Run the corpus verification suite (validates all 2,611 examples/**/*.fasm headers, AST parsing & PCAP output)
cargo test --test corpus_verification_tests

# Compile a single .fasm specification to a .pcap file
cargo run -- demo.fasm -o output.pcap
```

---

## 2. Unified `<layer>/<protocol>` Repository Architecture

FrameAssembly enforces strict structural symmetry across `src/`, `examples/`, and `docs/`:

- **`src/lexer/mod.rs`**: Zero-copy `logos 0.14` tokenizer defining `Token<'a>` for all 81 protocols, L2–L4 modifiers, SNMP USM parameters, time units (`ns`, `us`, `ms`, `s`, `m`), IPv4/IPv6, MAC, and OID literals.
- **`src/ast/{l2,l3,l4,l7}/<protocol>.rs`**: Strongly-typed AST node and `*Spec` definitions. Every AST type includes a `/// Syntax mapping: \`...\`` docstring binding the Rust type to its `.fasm` grammar.
- **`src/parser/{l2,l3,l4,l7}/<protocol>.rs`**: Two-phase `winnow 1.0` token-slice (`Stream<'i, 'a>`) combinator parsers and semantic validator (`validate_semantics` in `src/parser/mod.rs`).
- **`src/builders/{l2,l3,l4,l7}/<protocol>.rs`**: Zero-heap wire payload encoders and `src/builders/l7/snmp/` (`builder.rs`, `crypto.rs`) for RFC 1157 / 3416 / 3414 / 3826 / 7860 BER and USM encryption.
- **`src/backend/mod.rs` & `src/packet.rs` & `src/pcap.rs`**: 4-tuple TCP sequence/acknowledgment progression, bidirectional port inheritance across `->` and `<-`, multicast MAC derivation (RFC 2464 `33:33:xx:xx:xx:xx` and RFC 1112 `01:00:5e:xx:xx:xx`), and `pcap-file 2.0` PCAPNG serialization.
- **`examples/{l2,l3,l4,l7,topologies}/`**: Verified `.fasm` corpus (`2,611` files) organized by `<layer>/<protocol>/<protocol>_<scenario>.fasm`.
- **`docs/*.md`**: Chunked (`< 50 KB` each) Markdown protocol reference and instruction-tuning guides:
  - [`docs/architecture_and_grammar.md`](docs/architecture_and_grammar.md) — Five-stage compiler pipeline, `HOST`/`FLOW`/`COMPILE` syntax, L2–L4 modifiers, dual-stack polymorphism, and formal grammar overview.
  - [`docs/l2_protocols.md`](docs/l2_protocols.md) — Layer 2 switching & data-link protocols (`ARP`, `VLAN`, `QINQ`, `LLDP`, `STP`, `LACP`, `EAPOL`, `MPLS`).
  - [`docs/l3_protocols.md`](docs/l3_protocols.md) — Layer 3 control, tunneling, VPN, and routing protocols (`ICMP`, `NDP`, `IGMP`, `MLD`, `GRE`, `VXLAN`, `GENEVE`, `IPSEC`, `ESP`, `AH`, `IKEV2`, `WIREGUARD`, `OSPF`, `BGP`, `RIP`, `VRRP`, `HSRP`, `PIM`, `BFD`, `OPENFLOW`).
  - [`docs/l4_transports.md`](docs/l4_transports.md) — Layer 4 transports (`TCP`, `UDP`, `SCTP`), 4-tuple state tracking, RFC 7323 TCP options, and SCTP multi-chunk signaling.
  - [`docs/l7_snmp.md`](docs/l7_snmp.md) — Layer 7 `SNMP1`, `SNMP2`, and `SNMP3` USM authentication (`MD5`/`SHA`/`SHA256`/`SHA384`/`SHA512`), encryption (`DES`/`AES`), and all 9 ASN.1 SMI `VARBIND` types.
  - [`docs/l7_infra_and_telemetry.md`](docs/l7_infra_and_telemetry.md) — Layer 7 infrastructure, time, AAA, and flow telemetry (`DNS`, `MDNS`, `DHCP`, `NTP`, `PTP`, `RADIUS`, `TACACS`, `SYSLOG`, `NETFLOW`, `IPFIX`, `SFLOW`).
  - [`docs/l7_web_and_cloud.md`](docs/l7_web_and_cloud.md) — Layer 7 web, cloud-native, transport security, VoIP, and remote access (`HTTP`, `HTTP2`, `GRPC`, `WEBSOCKET`, `TLS`, `QUIC`, `TFTP`, `FTP`, `SSH`, `TELNET`, `WHOIS`, `SIP`, `RTP`, `RTSP`, `STUN`, `SSDP`).
  - [`docs/l7_mail_auth_storage_db.md`](docs/l7_mail_auth_storage_db.md) — Layer 7 mail, directory, storage, databases, caches, and message brokers (`SMTP`, `IMAP`, `POP3`, `KERBEROS`, `LDAP`, `SMB`, `NFS`, `REDIS`, `MEMCACHED`, `MYSQL`, `POSTGRES`, `MQTT`, `COAP`, `AMQP`).
  - [`docs/l7_industrial_ot.md`](docs/l7_industrial_ot.md) — Layer 7 Industrial Control Systems (ICS) & SCADA/OT (`MODBUS`, `BACNET`, `DNP3`, `S7COMM`, `ETHERNETIP`, `OPCUA`).
  - [`docs/topologies_and_dual_stack.md`](docs/topologies_and_dual_stack.md) — Multi-host enterprise, data center EVPN-VXLAN, and campus Zero-Trust 802.1X NAC topologies.
  - [`docs/qa_synthesis_guide.md`](docs/qa_synthesis_guide.md) — Natural-Language Prompt to `.fasm` instruction-tuning Q&A pairs and GBNF constrained decoding guide.
- **Formal Grammars**:
  - [`grammar.ebnf`](grammar.ebnf): Formal ISO/IEC 14977 EBNF grammar.
  - [`frameassembly.gbnf`](frameassembly.gbnf): `llama.cpp` & MLC `XGrammar` GBNF grammar for constrained decoding (`--grammar-file frameassembly.gbnf`).
  - [`frameassembly.lark`](frameassembly.lark): Earley/LALR Lark grammar for `vLLM`, `Outlines`, `Guidance`, `XGrammar`, and `llguidance`.
- **AI Routing Maps & Metadata**:
  - [`CLAUDE.md`](CLAUDE.md) & [`.github/copilot-instructions.md`](.github/copilot-instructions.md): Agent & IDE instructions.
  - [`llms.txt`](llms.txt) & [`llms-full.txt`](llms-full.txt): Concise index map and single-fetch full context bundle.
  - [`context7.json`](context7.json), [`codemeta.json`](codemeta.json) & [`CITATION.cff`](CITATION.cff): Structured AI/SEO and academic citation metadata.

---

## 3. Core FrameAssembly DSL Rules & Invariants

1. **Program Structure & Case-Insensitivity**: Every `.fasm` file declares `HOST <id> { IP <ip> [MAC <mac>] }`, `FLOW <id>(<params>) { <statements> }`, and exactly one `COMPILE { <invocations_or_loops> }` block. All keywords, protocols, modifiers, time units (`ns`, `us`, `ms`, `s`, `m`), and identifiers (`HOST`, `FLOW`, parameters) are case-insensitive (`host` / `HOST`).
2. **Polymorphic Dual-Stack Flows**: A `FLOW` works identically over IPv4 and IPv6 host pairs. Mixing IPv4 and IPv6 endpoints in the same statement is a semantic error.
3. **Zero-Keyword RFC Defaults**: Every one of the 81 protocols compiles with zero mandatory sub-keywords (emitting RFC-compliant default headers and ports) and supports explicit field overrides.
4. **1 Statement = 1 Frame & Shared 4-Tuple State**: Each statement emits 1 frame. TCP-based L7 statements emit a `PSH ACK` frame on that protocol's well-known port and share 4-tuple sequence/ack counters with raw `TCP` statements on the same connection.
5. **Corpus, AI Discovery & Documentation Hygiene**:
   - Every `.fasm` file in `examples/` must start with `// PROMPT: ...` on line 1, `// TOKENS: ...` on line 2 (matching real `src/lexer/mod.rs` tokens), and include `// INSTRUCTION: ...` before every `HOST`, `FLOW`, and `COMPILE` block (`avg_line_length <= 85`, `max_line_length <= 200`, `words >= 50`).
   - **Canonical Syntax Only (Anti-Hallucination Guardrail)**:
     - Never use `=`, colons, commas, `IPV4`, `IPV6`, or `MASK` in `HOST` blocks (only `HOST <id> { IP <ip> [MAC <mac>] }`).
     - Never declare parameterless `FLOW <id> { ... }` or use `FROM`, `TO`, `REVERSE`, `SEND`, standalone `WAIT` lines, or `+5ms` / `[+delay]` prefixes (always `FLOW <id>(<params>) { <a> -> <b> <PROTO> ... [WAIT <int><ns|us|ms|s|m>] }`).
     - Never use `SPORT`, `DPORT`, `ACK <n>`, or `FLAGS [...]` (always `SRCPORT`, `DSTPORT`, `ACKNUM <n>`, and bare flag tokens `SYN ACK`).
     - Never write bare `COMPILE` or argumentless flow calls inside `COMPILE { <flow>(<hosts>) }`.
   - **Five-Way Grammar & Parser Lockstep**: Every keyword in `src/lexer/mod.rs`, `grammar.ebnf`, `frameassembly.gbnf`, `frameassembly.lark`, and `frameassembly.tmLanguage.json` must be wired into `src/parser/` (with protocol-scoped field dispatch so `cut_err` or 0-arg flags never shadow other protocols) and included in `parse_spanned_ident`.
   - **100% Compilable Documentation & Examples**: Every `.fasm` file in `examples/` (`2,611` files) and every ````frameassembly` / ````fasm` code block in `README.md`, `AGENTS.md`, `CLAUDE.md`, `.github/copilot-instructions.md`, `docs/*.md`, `src/**/*.rs`, and `.agents/skills/**/*.md` must compile with zero errors.
   - **Rustdoc & `docs.rs` SEO Hygiene**: Every `src/**/*.rs` file must start with `//!` (`< 50 KB` per file, `>= 50` words). Never place outer `///` comments on `pub mod` declarations that have inner `//!` docs. Keep internal parser submodules `pub(crate) mod` so `docs.rs` never generates empty module pages, use `#[doc(inline)]` on layer re-exports, and annotate all 81 AST `*Spec` structs with `/// Syntax mapping:` and `#[doc(alias = "...")]`.
   - Never write literal NUL bytes (`0x00`) into any `.md` or `.txt` file.
   - Keep `docs/*.md` and `src/**/*.rs` files strictly `< 50 KB` (`50,000` bytes) with zero broken links or orphan `.md` files.
   - Never bump `version` in `Cargo.toml` or run `git commit`, `git push`, or `git tag` unless explicitly instructed by the user.

---

## 4. Antigravity & AI Agent Customization Routing Tables

### 4.1 Workspace Rules (`.agents/rules/*.md` — 13 Rules)

| Rule File | Trigger Mode | Scope / Globs & Purpose |
| :--- | :--- | :--- |
| [`.agents/rules/frameassembly-dsl.md`](.agents/rules/frameassembly-dsl.md) | `always_on` | Canonical `.fasm` grammar, 81-protocol invariants, and anti-hallucination guardrails |
| [`.agents/rules/rust-2024-best-practices.md`](.agents/rules/rust-2024-best-practices.md) | `always_on` | Rust 1.85+ Edition 2024 idioms, `< 50 KB` file ceiling, and strict clippy/doc lints |
| [`.agents/rules/publishing_and_docs.md`](.agents/rules/publishing_and_docs.md) | `always_on` | Zero `0x00` NUL bytes, Rustdoc/`docs.rs` lint gates, `//!` hygiene, and `Cargo.toml` packaging |
| [`.agents/rules/versioning_and_git.md`](.agents/rules/versioning_and_git.md) | `always_on` | Prohibits automatic version bumping and unrequested `git commit`/`push`/`tag` |
| [`.agents/rules/temporary_files.md`](.agents/rules/temporary_files.md) | `always_on` | Workspace `temp/` directory and `.gitignore` hygiene for scratch captures |
| [`.agents/rules/token-and-context-efficiency.md`](.agents/rules/token-and-context-efficiency.md) | `always_on` | Token-budget conservation, subagent context isolation, disjoint parallel file ownership, and `/compact` checkpoint persistence |
| [`.agents/rules/ai-seo-best-practices.md`](.agents/rules/ai-seo-best-practices.md) | `glob` (`README.md`, `docs/**`, `examples/**`, `*.ebnf`, `*.gbnf`, `*.lark`) | Pre-training dataset filters, RLVR compiler rewards, 5-way constrained decoding grammars, and SEO |
| [`.agents/rules/clap-best-practices.md`](.agents/rules/clap-best-practices.md) | `glob` (`src/main.rs`, `Cargo.toml`) | `clap 4.6+` Derive CLI flags, `TypedValueParser`, and terminal styling |
| [`.agents/rules/logos-miette-best-practices.md`](.agents/rules/logos-miette-best-practices.md) | `glob` (`src/lexer/**`, `src/error.rs`, `src/parser/**`) | `logos 0.14` zero-copy lexing and `miette 7.6` graphical diagnostic spans |
| [`.agents/rules/networking-pcap-best-practices.md`](.agents/rules/networking-pcap-best-practices.md) | `glob` (`src/packet.rs`, `src/pcap.rs`, `src/backend/**`, `src/builders/**`) | L2–L7 RFC wire encoding, IPv4/TCP/UDP/ICMPv6/CRC32c/CRC16 checksums, and `pcap-file 2.0` PCAPNG |
| [`.agents/rules/rasn-snmp-best-practices.md`](.agents/rules/rasn-snmp-best-practices.md) | `glob` (`src/builders/l7/snmp/**`, `src/ast/l7/snmp.rs`, `src/parser/l7/snmp.rs`) | `rasn 0.28` ASN.1 BER/DER codec, SMIv1/SMIv2 `ObjectSyntax`, and SNMPv1/v2c/v3 PDUs |
| [`.agents/rules/rustcrypto-best-practices.md`](.agents/rules/rustcrypto-best-practices.md) | `glob` (`src/builders/l7/snmp/crypto.rs`) | RustCrypto RFC 3414/3826/7860 SNMPv3 USM key localization, HMAC, DES-CBC, and AES-128-CFB |
| [`.agents/rules/winnow-best-practices.md`](.agents/rules/winnow-best-practices.md) | `glob` (`src/parser/**`) | `winnow 1.0` token-slice (`Stream<'i, 'a>`) combinators, protocol-scoped dispatch, and `cut_err` |

### 4.2 Specialized Domain Skills (`.agents/skills/*/SKILL.md` — 9 Skills)

| Skill Name | Entrypoint & Reference Patterns | When to Activate |
| :--- | :--- | :--- |
| **`frameassembly`** | [`.agents/skills/frameassembly/SKILL.md`](.agents/skills/frameassembly/SKILL.md) ([`patterns.md`](.agents/skills/frameassembly/references/patterns.md)) | Adding or modifying `.fasm` syntax, AST `*Spec` types, parser dispatch, or backend 4-tuple state |
| **`networking-pcap`** | [`.agents/skills/networking-pcap/SKILL.md`](.agents/skills/networking-pcap/SKILL.md) ([`patterns.md`](.agents/skills/networking-pcap/references/patterns.md)) | Implementing L2–L7 wire builders, RFC checksums, multicast MACs, or PCAPNG serialization |
| **`winnow-parser`** | [`.agents/skills/winnow-parser/SKILL.md`](.agents/skills/winnow-parser/SKILL.md) ([`patterns.md`](.agents/skills/winnow-parser/references/patterns.md)) | Writing or debugging `winnow 1.0` `Stream<'i, 'a>` combinators and `StrContext` error recovery |
| **`logos-miette-diagnostics`** | [`.agents/skills/logos-miette-diagnostics/SKILL.md`](.agents/skills/logos-miette-diagnostics/SKILL.md) ([`patterns.md`](.agents/skills/logos-miette-diagnostics/references/patterns.md)) | Updating `logos 0.14` `Token<'a>` definitions or `miette 7.6` source span diagnostics |
| **`rasn-snmp-codec`** | [`.agents/skills/rasn-snmp-codec/SKILL.md`](.agents/skills/rasn-snmp-codec/SKILL.md) ([`patterns.md`](.agents/skills/rasn-snmp-codec/references/patterns.md)) | Working on ASN.1 BER encoding, SMIv1/SMIv2 varbinds, or SNMPv1/v2c/v3 wire builders |
| **`rustcrypto-engineering`** | [`.agents/skills/rustcrypto-engineering/SKILL.md`](.agents/skills/rustcrypto-engineering/SKILL.md) ([`patterns.md`](.agents/skills/rustcrypto-engineering/references/patterns.md)) | Working on SNMPv3 USM RFC 3414/3826/7860 authentication (`MD5`/`SHA`/`SHA-2`) and privacy (`DES`/`AES`) |
| **`clap-cli`** | [`.agents/skills/clap-cli/SKILL.md`](.agents/skills/clap-cli/SKILL.md) ([`patterns.md`](.agents/skills/clap-cli/references/patterns.md)) | Extending the `frameassembly` CLI (`src/main.rs`) with `clap 4.6+` Derive arguments or validations |
| **`rust-modern-qa`** | [`.agents/skills/rust-modern-qa/SKILL.md`](.agents/skills/rust-modern-qa/SKILL.md) ([`patterns.md`](.agents/skills/rust-modern-qa/references/patterns.md)) | Running or extending 4-tier tests, 5-gate corpus checks (`2,611` files), `proptest`, `cargo-mutants`, or `tshark` gates |
| **`ai-seo-training-data`** | [`.agents/skills/ai-seo-training-data/SKILL.md`](.agents/skills/ai-seo-training-data/SKILL.md) ([`patterns.md`](.agents/skills/ai-seo-training-data/references/patterns.md)) | Auditing pre-training dataset filters, RLVR rewards, 5-way constrained decoding grammars, `llms.txt`, or `docs.rs` SEO |
