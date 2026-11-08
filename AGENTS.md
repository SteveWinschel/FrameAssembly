# AGENTS.md — FrameAssembly AI Agent & LLM Onboarding Guide

**FrameAssembly** (`frameassembly` v1.5.1, official website & interactive browser playground: [`https://frameassembly.ai.studio/`](https://frameassembly.ai.studio/), repository: [`https://github.com/SteveWinschel/FrameAssembly`](https://github.com/SteveWinschel/FrameAssembly)) is a Rust 2024 Domain-Specific Language (DSL) and optimizing compiler that compiles declarative `.fasm` network traffic specifications into deterministic, nanosecond-precision `.pcap` / `.pcapng` packet captures—and decompiles `.pcap` / `.pcapng` captures back into canonical `.fasm` code—across **81 native Layer 2 through Layer 7 protocols** (`2,611` verified `.fasm` corpus scenarios).

---

## 1. Quick Build, Test & Verification Commands

```bash
# Cross-platform bootstrap install (prebuilt release binary fast-path or curl + C linker + rustup >= 1.85 + cargo install)
curl -fsSL https://raw.githubusercontent.com/SteveWinschel/FrameAssembly/main/install.sh | sh

# Build compiler and CLI binary
cargo build --release

# Run all unit, integration, and corpus verification tests
cargo test

# Run the corpus verification suite (validates all 2,611 examples/**/*.fasm headers, AST parsing & PCAP output)
cargo test --test corpus_verification_tests

# Compile a single .fasm specification to a .pcap file (defaults to <input_stem>.pcap)
cargo run -- demo.fasm -o output.pcap

# Show the terminal packet ladder for a .fasm file without writing a .pcap file
cargo run -- show demo.fasm

# Decompile a .pcap / .pcapng capture into canonical .fasm code (defaults to <input_stem>.fasm)
cargo run -- reverse output.pcap -o reversed.fasm
```

---

## 2. Unified `<layer>/<protocol>` Repository Architecture

FrameAssembly enforces strict structural symmetry across `src/`, `examples/`, and `docs/`:

- **`src/lexer/mod.rs`**: Zero-copy `logos 0.14` tokenizer defining `Token<'a>` for all 81 protocols, L2–L4 modifiers, SNMP USM parameters, time units (`ns`, `us`, `ms`, `s`, `m`), IPv4/IPv6, MAC, and OID literals.
- **`src/ast/{l2,l3,l4,l7}/<protocol>.rs`**: Strongly-typed AST node and `*Spec` definitions. Every AST type includes a `/// Syntax mapping: \`...\`` docstring binding the Rust type to its `.fasm` grammar.
- **`src/parser/{l2,l3,l4,l7}/<protocol>.rs`**: Two-phase `winnow 1.0` token-slice (`Stream<'i, 'a>`) combinator parsers and semantic validator (`validate_semantics` in `src/parser/mod.rs`).
- **`src/builders/{l2,l3,l4,l7}/<protocol>.rs`**: Zero-heap wire payload encoders and `src/builders/l7/snmp/` (`builder.rs`, `crypto.rs`) for RFC 1157 / 3416 / 3414 / 3826 / 7860 BER and USM encryption.
- **`src/backend/mod.rs` & `src/packet.rs` & `src/pcap.rs`**: 4-tuple TCP sequence/acknowledgment progression, bidirectional port inheritance across `->` and `<-`, multicast MAC derivation (RFC 2464 `33:33:xx:xx:xx:xx` and RFC 1112 `01:00:5e:xx:xx:xx`), and `pcap-file 2.0` PCAPNG serialization.
- **`src/reverse/{l2,l3,l4,l7}/<protocol>.rs`**: Five-stage PCAP/PCAPNG-to-`.fasm` decompiler (`reverse_pcap_reader`, `reverse_pcap_bytes`, `reverse_pcap_file`) with `container.rs`, `topology.rs`, `oracle.rs`, `shadow_emit.rs`, `src/reverse/l3/{ip,ipv6,icmpv6}.rs` alongside the 20 L3 protocol dissectors, and `src/reverse/l7/{snmp1,snmp2,snmp3}.rs` across all 50 L7 protocol dissectors (81 per-protocol dissectors total mirroring `src/ast/`, `src/parser/`, and `src/builders/` 1-to-1).
- **`examples/{l2,l3,l4,l7,topologies}/`**: Verified `.fasm` corpus (`2,611` files) organized by `<layer>/<protocol>/<protocol>_<scenario>.fasm`.
- **`docs/*.md`**: 13 canonical Markdown guides (human-first getting started, use-case cookbook, 9 layer/topology references, `.fasm` media type specification, and `for_nerds.md` for compiler/LLM internals):
  - [`docs/getting_started.md`](docs/getting_started.md) — Step-by-step beginner guide: `.fasm` anatomy, defaults vs. overrides, automatic TCP `SEQ`/`ACK` and reply ports, cross-layer tags, compiler error messages, and pairing with Wireshark/`tshark` and `tcpreplay`.
  - [`docs/use_cases.md`](docs/use_cases.md) — Practical cookbook: SNMPv1/v2c/v3 traps & polls, firewall ACL testing, VLAN/QinQ/MPLS/QoS verification, IDS/IPS & telemetry validation, OT/SCADA dissectors, and zero-noise captures.
  - [`docs/l2_protocols.md`](docs/l2_protocols.md) — Layer 2 switching & data-link protocols (`ARP`, `VLAN`, `QINQ`, `LLDP`, `STP`, `LACP`, `EAPOL`, `MPLS`).
  - [`docs/l3_protocols.md`](docs/l3_protocols.md) — Layer 3 control, tunneling, VPN, and routing protocols (`ICMP`, `NDP`, `IGMP`, `MLD`, `GRE`, `VXLAN`, `GENEVE`, `IPSEC`, `ESP`, `AH`, `IKEV2`, `WIREGUARD`, `OSPF`, `BGP`, `RIP`, `VRRP`, `HSRP`, `PIM`, `BFD`, `OPENFLOW`).
  - [`docs/l4_transports.md`](docs/l4_transports.md) — Layer 4 transports (`TCP`, `UDP`, `SCTP`), 4-tuple state tracking, RFC 7323 TCP options, and SCTP multi-chunk signaling.
  - [`docs/l7_snmp.md`](docs/l7_snmp.md) — Layer 7 `SNMP1`, `SNMP2`, and `SNMP3` USM authentication (`MD5`/`SHA`/`SHA256`/`SHA384`/`SHA512`), encryption (`DES`/`AES`), and all 9 ASN.1 SMI `VARBIND` types.
  - [`docs/l7_infra_and_telemetry.md`](docs/l7_infra_and_telemetry.md) — Layer 7 infrastructure, time, AAA, and flow telemetry (`DNS`, `MDNS`, `DHCP`, `NTP`, `PTP`, `RADIUS`, `TACACS`, `SYSLOG`, `NETFLOW`, `IPFIX`, `SFLOW`).
  - [`docs/l7_web_and_cloud.md`](docs/l7_web_and_cloud.md) — Layer 7 web, cloud-native, transport security, VoIP, and remote access (`HTTP`, `HTTP2`, `GRPC`, `WEBSOCKET`, `TLS`, `QUIC`, `TFTP`, `FTP`, `SSH`, `TELNET`, `WHOIS`, `SIP`, `RTP`, `RTSP`, `STUN`, `SSDP`).
  - [`docs/l7_mail_auth_storage_db.md`](docs/l7_mail_auth_storage_db.md) — Layer 7 mail, directory, storage, databases, caches, and message brokers (`SMTP`, `IMAP`, `POP3`, `KERBEROS`, `LDAP`, `SMB`, `NFS`, `REDIS`, `MEMCACHED`, `MYSQL`, `POSTGRES`, `MQTT`, `COAP`, `AMQP`).
  - [`docs/l7_industrial_ot.md`](docs/l7_industrial_ot.md) — Layer 7 Industrial Control Systems (ICS) & SCADA/OT (`MODBUS`, `BACNET`, `DNP3`, `S7COMM`, `ETHERNETIP`, `OPCUA`).
  - [`docs/topologies_and_dual_stack.md`](docs/topologies_and_dual_stack.md) — Multi-host enterprise, data center EVPN-VXLAN, and campus Zero-Trust 802.1X NAC topologies.
  - [`docs/fasm-specification.md`](docs/fasm-specification.md) — Canonical RFC 6838 specification for the FrameAssembly `.fasm` file format (`text/vnd.frameassembly`), UTF-8 encoding, lexical magic rules, and `.fasm` extension disambiguation.
  - [`docs/for_nerds.md`](docs/for_nerds.md) — Six-stage zero-copy Rust compiler architecture, public Rust library API (`parse_program`, `compile_program`, `generate_pcap`), formal grammars (`EBNF`/`GBNF`/`Lark`), constrained decoding, and `examples/` SFT/RLVR corpus conventions.
- **Formal Grammars & `.fasm` Standards Registration (`contrib/`)**:
  - [`grammar.ebnf`](grammar.ebnf): Formal ISO/IEC 14977 EBNF grammar.
  - [`frameassembly.gbnf`](frameassembly.gbnf): `llama.cpp` & MLC `XGrammar` GBNF grammar for constrained decoding (`--grammar-file frameassembly.gbnf`).
  - [`frameassembly.lark`](frameassembly.lark): Earley/LALR Lark grammar for `vLLM`, `Outlines`, `Guidance`, `XGrammar`, and `llguidance`.
  - [`contrib/iana/text-vnd.frameassembly.md`](contrib/iana/text-vnd.frameassembly.md): IANA RFC 6838 Vendor Tree registration (`text/vnd.frameassembly`) & Wikidata property mappings (`P31`, `P1195`, `P1163`, `P973`).
  - [`contrib/mime/text-vnd.frameassembly.xml`](contrib/mime/text-vnd.frameassembly.xml): Freedesktop.org `shared-mime-info` XML database definition (`*.fasm` glob + lexer-derived `<magic>` rules).
  - [`contrib/linguist/`](contrib/linguist/README.md): GitHub Linguist `languages.yml`, `heuristics.yml` regex disambiguation, and verified `.fasm` samples.
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
5. **Branding, `.fasm` (`text/vnd.frameassembly`) Disambiguation & Companion Positioning**:
   - Always write the project name as one CamelCase word: `FrameAssembly` (or lowercase `frameassembly` strictly for the crate name, CLI binary, URLs, and code identifiers); never split the name into two words, which collides with CAD queries.
   - Maintain clear, factual disambiguation separating FrameAssembly `.fasm` (`text/vnd.frameassembly`) network packet specifications from unregistered x86 Flat Assembler and SymbiFlow/F4PGA FPGA FASM files.
   - Position FrameAssembly as the upstream "Packets as Code" companion compiler to `Wireshark`, `tshark`, `tcpreplay`, `Suricata`, and `Zeek` (comparing only against packet-crafting generators: `Scapy`, `text2pcap`, `Ostinato`), and describe its architecture accurately ("rootless", "offline", "deterministic", "no `libpcap` or raw sockets required") without claiming zero external crate dependencies.
6. **Corpus, AI Discovery & Documentation Hygiene**:
   - **Audience Architecture, Natural Voice & Calling `.fasm` Code (Zero Developer Jargon, Zero AI Parroting & Zero Prompt Leaking)**: (1) `llms.txt` is optimized for search engines of AIs and `llms-full.txt` is optimized for pre-training and prompting of AIs; (2) `docs/*.md` are written for networking and cybersecurity professionals in a natural, direct human voice with practical tool examples (`Checkmk`, `Zabbix`, `Wireshark`, `Suricata`, `tcpreplay`); (3) READMEs (`README.md`, `frameassembly-vscode/README.md`, `frameassembly-wasm/README.md`) are tailored to their target audiences, with root `README.md` kept minimalistic—interesting and informative without being overwhelming—focused on the problems solved (preventing manual device/daemon configuration work, avoiding manual fault triggering on hardware, skipping lab VM setup, avoiding manual checksum/TCP sequence math), use cases (pentesting, testing firewalls, simulating SNMP traps, testing monitoring or cybersecurity solutions), and advantages over other solutions. Never spam filler AI adjectives (`"readable"`, `"clean"`, `"editable"`, `"canonical"`, `"repeatable"`), never parrot repetitive slogans across paragraphs (`"no root"`, `"without sudo, libpcap, or raw sockets"`, `"unprivileged user space"`, `"no programming experience required"`), never use compiler/PL jargon (`"DSL"`, `"Domain-Specific Language"`, `"declarative"`, `"polymorphic"`, `"deterministic"`) in `README.md` or `docs/*.md` (except `docs/for_nerds.md`), and never leak or quote informal prompt phrasing into documentation. Always call `.fasm` **code** (`Packets as Code`), never `"plain text"`.
   - Every `.fasm` file in `examples/` must start with `// PROMPT: ...` on line 1, `// TOKENS: ...` on line 2 (matching real `src/lexer/mod.rs` tokens), and include `// INSTRUCTION: ...` before every `HOST`, `FLOW`, and `COMPILE` block (`avg_line_length <= 85`, `max_line_length <= 200`, `words >= 50`). Human-facing docs (`README.md` and `docs/*.md` except `docs/for_nerds.md`) must never include `// PROMPT:`, `// TOKENS:`, or `// INSTRUCTION:` metadata comments.
   - **Canonical Syntax Only (Anti-Hallucination Guardrail)**:
     - Never use `=`, colons, commas, `IPV4`, `IPV6`, or `MASK` in `HOST` blocks (only `HOST <id> { IP <ip> [MAC <mac>] }`).
     - Never declare parameterless `FLOW <id> { ... }` or use `FROM`, `TO`, `REVERSE`, `SEND`, standalone `WAIT` lines, or `+5ms` / `[+delay]` prefixes (always `FLOW <id>(<params>) { <a> -> <b> <PROTO> ... [WAIT <int><ns|us|ms|s|m>] }`).
     - Never use `SPORT`, `DPORT`, `ACK <n>`, or `FLAGS [...]` (always `SRCPORT`, `DSTPORT`, `ACKNUM <n>`, and bare flag tokens `SYN ACK`).
     - Never write bare `COMPILE` or argumentless flow calls inside `COMPILE { <flow>(<hosts>) }`.
   - **Five-Way Grammar, Parser, Specification & MIME Lockstep**: Every keyword in `src/lexer/mod.rs`, `grammar.ebnf`, `frameassembly.gbnf`, `frameassembly.lark`, and `frameassembly.tmLanguage.json` must be wired into `src/parser/` (with protocol-scoped field dispatch so `cut_err` or 0-arg flags never shadow other protocols) and included in `parse_spanned_ident`. Whenever lexer tokens or supported protocols change, automatically synchronize `README.md`, `src/lib.rs`, `docs/fasm-specification.md`, `llms.txt`, `llms-full.txt`, and `contrib/mime/text-vnd.frameassembly.xml`.
   - **100% Compilable Documentation & Examples**: Every `.fasm` file in `examples/` (`2,611` files) and `contrib/linguist/samples/` and every ````frameassembly` / ````fasm` code block in `README.md`, `AGENTS.md`, `CLAUDE.md`, `.github/copilot-instructions.md`, `docs/*.md`, `contrib/**/*.md`, `src/**/*.rs`, and `.agents/skills/**/*.md` must compile with zero errors.
   - **Rustdoc & `docs.rs` SEO Hygiene**: Every `src/**/*.rs` file must start with `//!` (`< 50 KB` per file, `>= 50` words). Never place outer `///` comments on `pub mod` declarations that have inner `//!` docs. Keep internal parser submodules `pub(crate) mod` so `docs.rs` never generates empty module pages, use `#[doc(inline)]` on layer re-exports, and annotate all 81 AST `*Spec` structs with `/// Syntax mapping:` and `#[doc(alias = "...")]`.
   - Never write literal NUL bytes (`0x00`) into any `.md` or `.txt` file.
   - Keep AI-critical Rust and corpus files (`src/**/*.rs`, `tests/*.rs`, `examples/**/*.fasm`) strictly `< 50 KB` (`50,000` bytes) (human-facing `README.md` and `docs/*.md` have no `< 50 KB` cap), and maintain zero broken links or orphan `.md` files in `docs/`.
   - Never bump `version` in `Cargo.toml` or run `git commit`, `git push`, or `git tag` unless explicitly instructed by the user.

---

## 4. Antigravity & AI Agent Customization Routing Tables

### 4.1 Workspace Rules (`.agents/rules/*.md` — 15 Rules: `4` `always_on` + `11` `glob`-Scoped)

| Rule File | Trigger Mode | Scope / Globs & Purpose |
| :--- | :--- | :--- |
| [`.agents/rules/frameassembly-dsl.md`](.agents/rules/frameassembly-dsl.md) | `always_on` | Canonical `.fasm` grammar, 6-stage forward compiler + reverse PCAP decompiler invariants, 81-protocol rules, and anti-hallucination guardrails |
| [`.agents/rules/versioning_and_git.md`](.agents/rules/versioning_and_git.md) | `always_on` | Enforces 4-way ecosystem version synchronization on explicit request and prohibits unrequested version bumps or `git commit`/`push`/`tag` |
| [`.agents/rules/temporary_files.md`](.agents/rules/temporary_files.md) | `always_on` | Workspace `temp/` directory and thread-safe RAII cleanup guards for scratch packet captures |
| [`.agents/rules/token-and-context-efficiency.md`](.agents/rules/token-and-context-efficiency.md) | `always_on` | 20k-token rules budget discipline, 3-layer parallel multi-agent file locking (`.agents/scripts/file_lock.sh` + `.agents/hooks.json`), subagent context isolation, and `/compact` persistence |
| [`.agents/rules/rust-2024-best-practices.md`](.agents/rules/rust-2024-best-practices.md) | `glob` (`Cargo.toml`, `src/**/*.rs`, `tests/**/*.rs`, `frameassembly-wasm/**/*.rs`) | Rust 2024 Edition and `rustc 1.85–1.99.1` idioms (`let_chains`, `as_chunks`, `array_windows`, `cfg_select!`, `assert_matches!`, `File::lock`), `< 50 KB` ceiling, and strict clippy/doc lints |
| [`.agents/rules/publishing_and_docs.md`](.agents/rules/publishing_and_docs.md) | `glob` (`Cargo.toml`, `README.md`, `**/README.md`, `docs/**/*.md`, `llms*.txt`, `src/**/*.rs`, `contrib/**`) | Zero `0x00` NUL bytes, Rustdoc/`docs.rs` lint gates, Cargo `build.warnings` (Rust 1.97+), `//!` hygiene, and `Cargo.toml` packaging |
| [`.agents/rules/ai-seo-best-practices.md`](.agents/rules/ai-seo-best-practices.md) | `glob` (`README.md`, `docs/**`, `examples/**`, `*.ebnf`, `*.gbnf`, `*.lark`, `llms*.txt`, `context7.json`, `codemeta.json`, `CITATION.cff`) | Pre-training dataset filters, 4-stage RLVR compiler & PCAP-to-`.fasm` decompilation rewards, 6-way grammar/IDE/WASM lockstep, and SEO |
| [`.agents/rules/clap-best-practices.md`](.agents/rules/clap-best-practices.md) | `glob` (`src/main.rs`, `Cargo.toml`, `tests/**/*.rs`) | `clap 4.6.7+`, `anstyle 1.0.14`, and `anstream 1.0.0` Derive CLI flags, hybrid positional + `show`/`reverse` subcommand routing, and `TypedValueParser` |
| [`.agents/rules/logos-miette-best-practices.md`](.agents/rules/logos-miette-best-practices.md) | `glob` (`src/lexer/**/*.rs`, `src/error.rs`, `src/parser/**/*.rs`, `Cargo.toml`, `tests/**/*.rs`) | `logos 0.14.4` / `0.16.1` zero-copy lexing, 6-tier priority ladder, `miette 7.6.0` `(start, len)` span invariants, and foreign `.fasm` detection |
| [`.agents/rules/networking-pcap-best-practices.md`](.agents/rules/networking-pcap-best-practices.md) | `glob` (`src/packet.rs`, `src/pcap.rs`, `src/backend/**`, `src/builders/**`, `src/reverse/**`, `tests/**/*.rs`) | L2–L7 RFC wire encoding, IPv4/TCP/UDP/ICMPv6/CRC32c/CRC16 checksums, 4-tuple state constants, and `pcap-file 2.0.0` PCAPNG |
| [`.agents/rules/pcap-decompilation-best-practices.md`](.agents/rules/pcap-decompilation-best-practices.md) | `glob` (`src/reverse/**`, `Cargo.toml`, `tests/**/*.rs`) | 5-stage PCAP/PCAPNG-to-`.fasm` decompilation pipeline, `etherparse 0.21.0` `link_exts` zero-copy slicing, container normalization, fuzz safety, and self-checking compiler oracle |
| [`.agents/rules/rasn-snmp-best-practices.md`](.agents/rules/rasn-snmp-best-practices.md) | `glob` (`src/builders/l7/snmp/**`, `src/builders/l7/ldap.rs`, `src/builders/l7/kerberos.rs`, `src/reverse/**`, `src/ast/l7/snmp*.rs`, `src/parser/l7/snmp*.rs`) | `rasn`, `rasn-smi`, and `rasn-snmp 0.28.15` ASN.1 BER/DER encoding & decompilation, SMIv1/SMIv2 `ObjectSyntax`, and SNMPv1/v2c/v3 / LDAP / Kerberos PDUs |
| [`.agents/rules/rustcrypto-best-practices.md`](.agents/rules/rustcrypto-best-practices.md) | `glob` (`src/builders/l7/snmp/crypto.rs`, `src/builders/l7/snmp/builder.rs`, `src/builders/l7/radius.rs`, `src/builders/l7/tacacs.rs`) | RustCrypto (`aes 0.9.4`, `des 0.9.0`, `cbc 0.2.1`, `cfb-mode 0.9.1`, `hmac 0.13.0`, `md-5`/`sha1`/`sha2 0.11.0`, `cipher 0.5.2`, `digest 0.11.3`) SNMPv3 USM RFC 3414/3826/7860 |
| [`.agents/rules/wasm-vscode-best-practices.md`](.agents/rules/wasm-vscode-best-practices.md) | `glob` (`frameassembly-wasm/**`, `frameassembly-vscode/**`, `Cargo.toml`, `.github/workflows/**`) | WebAssembly (`wasm-bindgen 0.2.130`, `serde-wasm-bindgen 0.6.5`, `wasm-pack 0.15.1`), UTF-16 IDE span mapping, VS Code extension (`@vscode/vsce 4.1.0`), and OIDC Trusted Publishing |
| [`.agents/rules/winnow-best-practices.md`](.agents/rules/winnow-best-practices.md) | `glob` (`src/parser/**/*.rs`, `Cargo.toml`, `tests/**/*.rs`) | `winnow 1.0.5+` and `memchr 2.8.3` zero-copy 3-tuple `Stream<'i, 'a>` combinators, 3-tier protocol-scoped dispatch, and `cut_err` rules |

### 4.2 Specialized Domain Skills (`.agents/skills/*/SKILL.md` — 11 Skills)

| Skill Name | Entrypoint & Reference Patterns | When to Activate |
| :--- | :--- | :--- |
| **`frameassembly`** | [`.agents/skills/frameassembly/SKILL.md`](.agents/skills/frameassembly/SKILL.md) ([`patterns.md`](.agents/skills/frameassembly/references/patterns.md)) | Adding or modifying `.fasm` syntax, AST `*Spec` types, parser dispatch, backend 4-tuple state, or forward/reverse pipeline stages |
| **`networking-pcap`** | [`.agents/skills/networking-pcap/SKILL.md`](.agents/skills/networking-pcap/SKILL.md) ([`patterns.md`](.agents/skills/networking-pcap/references/patterns.md)) | Implementing L2–L7 wire builders, RFC checksums, multicast MACs, or `pcap-file 2.0.0` PCAPNG serialization |
| **`pcap-decompilation`** | [`.agents/skills/pcap-decompilation/SKILL.md`](.agents/skills/pcap-decompilation/SKILL.md) ([`patterns.md`](.agents/skills/pcap-decompilation/references/patterns.md)) | Working on `src/reverse/` PCAP/PCAPNG-to-`.fasm` decompilation, `etherparse 0.21.0` slicing, linktype normalization, or oracle verification |
| **`winnow-parser`** | [`.agents/skills/winnow-parser/SKILL.md`](.agents/skills/winnow-parser/SKILL.md) ([`patterns.md`](.agents/skills/winnow-parser/references/patterns.md)) | Writing or debugging `winnow 1.0.5+` and `memchr 2.8.3` `Stream<'i, 'a>` combinators and `StrContext` error recovery |
| **`logos-miette-diagnostics`** | [`.agents/skills/logos-miette-diagnostics/SKILL.md`](.agents/skills/logos-miette-diagnostics/SKILL.md) ([`patterns.md`](.agents/skills/logos-miette-diagnostics/references/patterns.md)) | Updating `logos 0.14.4` / `0.16.1` `Token<'a>` definitions or `miette 7.6.0` source span diagnostics |
| **`rasn-snmp-codec`** | [`.agents/skills/rasn-snmp-codec/SKILL.md`](.agents/skills/rasn-snmp-codec/SKILL.md) ([`patterns.md`](.agents/skills/rasn-snmp-codec/references/patterns.md)) | Working on `rasn 0.28.15` ASN.1 BER/DER encoding, decoding, SMIv1/SMIv2 varbinds, or SNMPv1/v2c/v3 wire builders |
| **`rustcrypto-engineering`** | [`.agents/skills/rustcrypto-engineering/SKILL.md`](.agents/skills/rustcrypto-engineering/SKILL.md) ([`patterns.md`](.agents/skills/rustcrypto-engineering/references/patterns.md)) | Working on SNMPv3 USM RFC 3414/3826/7860 authentication (`MD5`/`SHA`/`SHA-2`) and privacy (`DES`/`AES`) with RustCrypto |
| **`clap-cli`** | [`.agents/skills/clap-cli/SKILL.md`](.agents/skills/clap-cli/SKILL.md) ([`patterns.md`](.agents/skills/clap-cli/references/patterns.md)) | Extending the `frameassembly` CLI (`src/main.rs`) with `clap 4.6.7+`, `anstyle 1.0.14`, and `anstream 1.0.0` |
| **`rust-modern-qa`** | [`.agents/skills/rust-modern-qa/SKILL.md`](.agents/skills/rust-modern-qa/SKILL.md) ([`patterns.md`](.agents/skills/rust-modern-qa/references/patterns.md)) | Running or extending multi-tier tests, 6-gate corpus & AST-to-builder checks, `proptest`, `cargo-mutants`, `tshark` gates, or `.agents/scripts/file_lock.sh` |
| **`ai-seo-training-data`** | [`.agents/skills/ai-seo-training-data/SKILL.md`](.agents/skills/ai-seo-training-data/SKILL.md) ([`patterns.md`](.agents/skills/ai-seo-training-data/references/patterns.md)) | Auditing pre-training dataset filters, 4-stage RLVR compiler/decompiler rewards, 6-way grammar/IDE/WASM lockstep, `llms.txt`, or `docs.rs` SEO |
| **`wasm-vscode`** | [`.agents/skills/wasm-vscode/SKILL.md`](.agents/skills/wasm-vscode/SKILL.md) ([`patterns.md`](.agents/skills/wasm-vscode/references/patterns.md)) | Working on `frameassembly-wasm` (`wasm-bindgen 0.2.130`), UTF-16 IDE diagnostics, `frameassembly-vscode` (`@vscode/vsce 4.1.0`), or OIDC publishing |
