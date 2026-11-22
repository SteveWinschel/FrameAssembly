# AGENTS.md — FrameAssembly AI Agent & LLM Onboarding Guide

**FrameAssembly** (`frameassembly` v3.2.1, official website & interactive browser playground: [`https://frameassembly-lang.dev/`](https://frameassembly-lang.dev/), repository: [`https://github.com/SteveWinschel/FrameAssembly`](https://github.com/SteveWinschel/FrameAssembly)) is a Rust 2024 Domain-Specific Language (DSL) and optimizing compiler that compiles declarative `.frasm` network traffic specifications into deterministic, nanosecond-precision `.pcap` / `.pcapng` packet captures—and decompiles `.pcap` / `.pcapng` captures back into canonical `.frasm` code—across **81 native Layer 2 through Layer 7 protocols** (scenarios: [`https://frameassembly-lang.dev/use-cases`](https://frameassembly-lang.dev/use-cases)).

---

## 1. Quick Build, Test & Verification Commands

```bash
# Cross-platform bootstrap install (prebuilt release binary fast-path or curl + C linker + rustup >= 1.89 + cargo install)
curl -fsSL https://raw.githubusercontent.com/SteveWinschel/FrameAssembly/main/install.sh | sh

# Windows PowerShell bootstrap (no Administrator rights; installs frameassembly.exe, PATH entry, completions, and the VS Code extension when `code` is present)
# irm https://raw.githubusercontent.com/SteveWinschel/FrameAssembly/main/install.ps1 | iex

# Build compiler and CLI binary
cargo build --release

# Run all unit, integration, and verification tests
cargo test

# Run the verification gate suite (grammar lockstep, AST-to-builder wiring, reverse symmetry, packaging sync)
cargo test --test corpus_verification_tests

# Compile a single .frasm specification to a .pcap file (default root command; optional 2nd positional path defaults to <input_stem>.pcap)
cargo run -- demo.frasm output.pcap

# Show the terminal packet ladder for a .frasm file without writing a .pcap file
cargo run -- show demo.frasm

# Decompile a .pcap / .pcapng capture into canonical .frasm code (optional 2nd positional path defaults to <input_stem>.frasm)
cargo run -- reverse output.pcap reversed.frasm

# Self-update the CLI via Cargo/rustup or verified GitHub Release assets
cargo run -- update

# Display CLI usage or active compiler version (default root compile + 5 subcommands: show, reverse, update, help, version — no -o/--output flags)
cargo run -- help
cargo run -- version
```

---

## 2. Unified `<layer>/<protocol>` Repository Architecture

FrameAssembly enforces strict `<layer>/<protocol>` structural symmetry across `src/ast/`, `src/parser/`, `src/builders/`, and `src/reverse/`:

- **`src/lexer/mod.rs`**: Zero-copy `logos 0.14.4` strict-lowercase tokenizer defining `Token<'a>` for all 81 protocols, L2–L7 modifiers, SNMPv3 USM parameters, time units (`ns`, `us`, `ms`, `s`, `m`), flexible user `Token::Ident` (`[a-zA-Z_][a-zA-Z0-9_]*(-[a-zA-Z0-9_]+)*`), IPv4/IPv6, MAC, and OID literals (zero `_` or `-` in built-in keywords, no `ignore(ascii_case)`, no `Token::Loop`).
- **`src/ast/{l2,l3,l4,l7}/<protocol>.rs`**: Strongly-typed AST node and `*Spec` definitions (`RunStatement::{Invocation, Frame}`). Every AST type includes a strict-lowercase v3.0.0 `/// Syntax mapping: \`...\`` docstring binding the Rust type to its `.frasm` grammar.
- **`src/parser/{l2,l3,l4,l7}/<protocol>.rs`**: Two-phase `winnow 1.0.5` token-slice (`Stream<'i, 'a>`) combinator parsers (protocol-first `whois` disambiguation + 3-tier field dispatch), self-healing diagnostics (`replace '<raw>' with '<kw>'` and `loop` removal guidance), and semantic validator (`validate_semantics(&program, &source)` in `src/parser/validation.rs`).
- **`src/builders/{l2,l3,l4,l7}/<protocol>.rs`**: Zero-heap wire payload encoders and `src/builders/l7/snmp/` (`builder.rs`, `crypto.rs`) for RFC 1157 / 3416 / 3414 / 3826 / 7860 BER and USM encryption.
- **`src/backend/mod.rs` & `src/packet.rs` & `src/pcap.rs`**: 4-tuple TCP sequence/acknowledgment progression, bidirectional port inheritance across `->` and `<-`, multicast MAC derivation (RFC 2464 `33:33:xx:xx:xx:xx` and RFC 1112 `01:00:5e:xx:xx:xx`), and `pcap-file 2.0.0` PCAPNG serialization.
- **`src/reverse/{l2,l3,l4,l7}/<protocol>.rs`**: Five-stage PCAP/PCAPNG-to-`.frasm` decompiler (`reverse_pcap_reader`, `reverse_pcap_bytes`, `reverse_pcap_file`) with `container.rs`, `topology.rs`, `oracle.rs`, `shadow_emit.rs`, `src/reverse/l3/{ip,ipv6,icmpv6}.rs` alongside the 20 L3 protocol dissectors, and `src/reverse/l7/{snmp1,snmp2,snmp3}.rs` across all 50 L7 protocol dissectors (81 per-protocol dissectors total mirroring `src/ast/`, `src/parser/`, and `src/builders/` 1-to-1, emitting `host1`, `host2` without `_`, strict-lowercase `[a-z0-9]+` keywords, and direct `compile` invocations with zero `loop` blocks).
- **`src/main.rs` & `src/update.rs`**: CLI entry point (default root compilation + 5 subcommands `show`, `reverse`, `update`, `help`, `version`; `src/update.rs` is a binary-private zero-new-crate Cargo-first + GitHub Release self-updater).
- **Documentation & Examples**: hosted at https://frameassembly-lang.dev/docs and https://frameassembly-lang.dev/use-cases (no in-repo `docs/` or `examples/`); `.agents/` is local-only (gitignored in `.gitignore`, never linked in tracked docs or CI tests); `contrib/branding/social-preview-1280x640.png` is the GitHub social preview card.
- **Formal Grammars, Shell Completions, Packaging & `.frasm` Standards Registration (`contrib/`)**:
  - [`grammar.ebnf`](grammar.ebnf): Formal ISO/IEC 14977 EBNF grammar (strict-lowercase v3.0.0).
  - [`frameassembly.gbnf`](frameassembly.gbnf): `llama.cpp` & MLC `XGrammar` GBNF grammar for constrained decoding (`--grammar-file frameassembly.gbnf`).
  - [`frameassembly.lark`](frameassembly.lark): Earley/LALR Lark grammar for `vLLM`, `Outlines`, `Guidance`, `XGrammar`, and `llguidance`.
  - [`contrib/completions/`](contrib/completions/README.md): Shell Tab-completion scripts for Bash, Zsh, Fish, and PowerShell.
  - [`contrib/packaging/`](contrib/packaging/README.md): Maintainer recipes and CI templates (Debian/Ubuntu `.deb`, internal tap/bucket manifests, and VS Code Marketplace `frameassembly-vscode` bundling internal `frameassembly-wasm`).
  - [`contrib/iana/text-vnd.frameassembly.md`](contrib/iana/text-vnd.frameassembly.md): IANA RFC 6838 Vendor Tree registration (`text/vnd.frameassembly`) & Wikidata property mappings (`P31`, `P1195`, `P1163`, `P973`).
  - [`contrib/mime/text-vnd.frameassembly.xml`](contrib/mime/text-vnd.frameassembly.xml): Freedesktop.org `shared-mime-info` XML database definition (`*.frasm` glob + lexer-derived `<magic>` rules).
  - [`contrib/linguist/`](contrib/linguist/README.md): GitHub Linguist `languages.yml`, `heuristics.yml` regex disambiguation, and verified `.frasm` samples.
- **AI Routing Maps & Metadata**:
  - [`CLAUDE.md`](CLAUDE.md) & [`.github/copilot-instructions.md`](.github/copilot-instructions.md): Agent & IDE instructions.
  - [`llms.txt`](llms.txt) & [`llms-full.txt`](llms-full.txt): Search-engine/AI-search discovery index (`llms.txt`) and dedicated prompt-injection context file (`llms-full.txt`).
  - [`context7.json`](context7.json), [`codemeta.json`](codemeta.json) & [`CITATION.cff`](CITATION.cff): Structured AI/SEO and academic citation metadata.

---

## 3. Core FrameAssembly v3.0.0 DSL Rules & Invariants

1. **Program Structure, Strict-Lowercase Keywords & Flexible User Identifiers**:
   - Every `.frasm` file declares `host <id> { [ip <ip>] [mac <mac>] }` (at least one of `ip` or `mac` required; MAC-only endpoints valid for the 8 pure L2 protocols `arp`, `vlan`, `qinq`, `lldp`, `stp`, `lacp`, `eapol`, `mpls`), `flow <id>(<params>) { <statements> }`, and exactly one `compile { <invocations_or_frames> }` block (`loop` was removed in v2.0.0; `compile` supports flow invocations and inline frame statements).
   - **Strict-Lowercase Built-In Keywords (`[a-z0-9]+`)**: Every built-in keyword, protocol, modifier, and time unit (`ns`, `us`, `ms`, `s`, `m`) is **strictly lowercase alphanumeric with zero `_` and zero `-`** (no `ignore(ascii_case)`: `echorequest`, `innervlan`, `clienthello`, `hosthdr`, `transporthdr`, `sackperm`, `agentip`, `hellotime`, `whois`, `pkttype`, `read`, `write`, `nop`, `error`, `shutdownack`, `readholdingregisters`, etc.), backed by self-healing compiler diagnostics (`replace '<raw>' with '<kw>'`).
   - **Flexible User Identifiers**: User-defined `host`, `flow`, and parameter names match `[a-zA-Z_][a-zA-Z0-9_]*(-[a-zA-Z0-9_]+)*` (allowing uppercase, `_`, and internal `-` such as `fw-dmz-01` or `core_sw`, stopping cleanly before `->`). Reverse PCAP decompilation (`frameassembly reverse`) emits `host1`, `host2` without `_`, strict-lowercase `[a-z0-9]+` tokens, and direct flow invocations in `compile` with zero `loop` blocks.
2. **Polymorphic Dual-Stack Flows**: A `flow` works identically over IPv4 and IPv6 host pairs. Mixing IPv4 and IPv6 endpoints in the same statement is a semantic error.
3. **Zero-Keyword RFC Defaults**: Every one of the 81 protocols compiles with zero mandatory sub-keywords (emitting RFC-compliant default headers and ports) and supports explicit field overrides.
4. **1 Statement = 1 Frame & Shared 4-Tuple State**: Each statement emits 1 frame. TCP-based L7 statements emit a `psh ack` frame on that protocol's well-known port and share 4-tuple sequence/ack counters with raw `tcp` statements on the same connection.
5. **Branding, `.frasm` (`text/vnd.frameassembly`) Disambiguation, Supported Release Channels & Confidentiality**:
   - Always write the project name as one CamelCase word: `FrameAssembly` (or lowercase `frameassembly` strictly for the crate name, CLI binary, URLs, and code identifiers); never split the name into two words, which collides with CAD queries.
   - Maintain clear, factual disambiguation separating FrameAssembly `.frasm` (`text/vnd.frameassembly`) network packet specifications from unregistered x86 Flat Assembler and SymbiFlow/F4PGA FPGA FASM files.
   - Position FrameAssembly as the upstream "Packets as Code" companion compiler to `Wireshark`, `tshark`, `tcpreplay`, `Suricata`, and `Zeek` (comparing only against packet-crafting generators: `Scapy`, `text2pcap`, `Ostinato`), and describe its architecture accurately ("rootless", "offline", "deterministic", "no `libpcap` or raw sockets required") without claiming zero external crate dependencies.
   - **User-Facing CLI Channels & Internal WASM Engine**: User-facing CLI distribution channels are **Crates.io (`cargo install frameassembly`, primary recommended)** and **GitHub Releases** (OS archives + `.deb` packages), alongside VS Code Marketplace (`frameassembly-vscode`). `frameassembly-wasm` is an internal WebAssembly engine powering `frameassembly-lang.dev` and `frameassembly-vscode`—never advertise `npm install frameassembly-wasm`, `Homebrew`, or `Scoop` in root `README.md`, and never add third-party package/extension workflows beyond `.github/workflows/release.yml`. Keep `.agents/` local-only (gitignored) with zero `.agents/` links in tracked Markdown or CI tests.
   - **Private User Context Confidentiality**: Never include private background context shared by the user in prompts (such as employer names or employment/apprenticeship status) anywhere in code, comments, examples, documentation, or metadata.
6. **AI Discovery & Documentation Hygiene**:
   - **Audience Architecture, Natural Voice & Calling `.frasm` Code (Zero Developer Jargon, Zero AI Parroting & Zero Prompt Leaking)**: (1) `llms.txt` (`< 512` lines, `< 25 KB`) is for search engines and AIs with web search, and `llms-full.txt` (`60–250 KB`) is a dedicated context file for purposeful injection inside prompts (never dumping `AGENTS.md` contributor rules, human docs banter, or raw Rust `src/ast/` code); (2) READMEs (`README.md`, `frameassembly-vscode/README.md`, `frameassembly-wasm/README.md`) are tailored to their target audiences, with root `README.md` kept minimalistic—interesting and informative without being overwhelming—focused on the problems solved (preventing manual device/daemon configuration work, avoiding manual fault triggering on hardware, skipping lab VM setup, avoiding manual checksum/TCP sequence math), use cases (pentesting, testing firewalls, simulating SNMP traps, testing monitoring or cybersecurity solutions), and advantages over other solutions. Never spam filler AI adjectives (`"readable"`, `"clean"`, `"editable"`, `"canonical"`, `"repeatable"`), never parrot repetitive slogans across paragraphs (`"no root"`, `"without sudo, libpcap, or raw sockets"`, `"unprivileged user space"`, `"no programming experience required"`), never use compiler/PL jargon (`"DSL"`, `"Domain-Specific Language"`, `"declarative"`, `"polymorphic"`, `"deterministic"`) in `README.md`, and never leak or quote informal prompt phrasing into documentation. Always call `.frasm` **code** (`Packets as Code`), never `"plain text"`.
   - **Canonical v3.0.0 Syntax Only (Anti-Hallucination Guardrail)**:
     - Never use uppercase built-in keywords (`HOST`, `TCP`, `WAIT`), underscores/hyphens in keywords (`echo_request`, `inner_vlan`, `host_hdr`, `sack_perm`), or `=`, colons, commas, `ipv4`, `ipv6`, or `mask` in `host` blocks (only `host <id> { [ip <ip>] [mac <mac>] }`).
     - Never declare parameterless `flow <id> { ... }` or use `from`, `to`, `reverse`, `send`, standalone `wait` lines, or `+5ms` / `[+delay]` prefixes (always `flow <id>(<params>) { <a> -> <b> <proto> ... [wait <int><ns|us|ms|s|m>] }`).
     - Never use `sport`, `dport`, `ack <n>`, `flags [...]`, `hop_limit`, `http ... host`, or `rtsp ... transport` (always `srcport`, `dstport`, `acknum <n>`, bare flag tokens `syn ack`, `ttl`, `hosthdr`, and `transporthdr`).
     - Never write `loop`, bare `compile`, argumentless flow calls inside `compile { <flow>(<hosts>) }`, a `compile` CLI subcommand, or legacy `-o` / `--output` CLI flags (compiling is the default root command `frameassembly <input.frasm> [output.pcap]`, alongside the 5 subcommands `show`, `reverse`, `update`, `help`, and `version`).
   - **Six-Way Grammar, Lexer, IDE, WASM & Docs Lockstep**: Every strict-lowercase `[a-z0-9]+` keyword in `src/lexer/mod.rs`, `grammar.ebnf`, `frameassembly.gbnf`, `frameassembly.lark`, and `frameassembly-vscode/syntaxes/frameassembly.tmLanguage.json` must be wired into `src/parser/` (with protocol-first `whois` disambiguation and 3-tier protocol-scoped field dispatch so `cut_err` or 0-arg flags never shadow other protocols) and included in `parse_spanned_ident`. Whenever lexer tokens or supported protocols change, synchronize `frameassembly-wasm`, `README.md`, `src/lib.rs`, `llms.txt`, `llms-full.txt`, `contrib/mime/text-vnd.frameassembly.xml`, and `contrib/linguist/heuristics.yml`.
   - **100% Compilable Code Blocks**: Every `.frasm` file in `contrib/linguist/samples/` and every ````frameassembly` / ````frasm` code block in `README.md`, `AGENTS.md`, `CLAUDE.md`, `.github/copilot-instructions.md`, `contrib/**/*.md`, and `src/**/*.rs` must compile with zero errors under v3.0.0 strict-lowercase syntax.
   - **Rustdoc & `docs.rs` SEO Hygiene**: Every `src/**/*.rs` file must start with `//!` (`< 50 KB` per file, `>= 50` words). Never place outer `///` comments on `pub mod` declarations that have inner `//!` docs. Keep internal parser submodules `pub(crate) mod` so `docs.rs` never generates empty module pages, use `#[doc(inline)]` on layer re-exports, and annotate all 81 AST `*Spec` structs with strict-lowercase `/// Syntax mapping:` and `#[doc(alias = "...")]`.
   - Never write literal NUL bytes (`0x00`) into any `.md` or `.txt` file.
   - Keep AI-critical Rust files (`src/**/*.rs`, `tests/*.rs`) strictly `< 50 KB` (`50,000` bytes) and `AGENTS.md` strictly `<= 24,000` bytes (human-facing `README.md` has no `< 50 KB` cap).
   - Never bump `version` in `Cargo.toml` or run `git commit`, `git push`, or `git tag` unless explicitly instructed by the user.
