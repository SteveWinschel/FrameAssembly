# AGENTS.md — FrameAssembly AI Agent & LLM Onboarding Guide

**FrameAssembly** (`frameassembly` v3.2.2, website & playground: [`https://frameassembly-lang.dev/`](https://frameassembly-lang.dev/), repository: [`https://github.com/SteveWinschel/FrameAssembly`](https://github.com/SteveWinschel/FrameAssembly)) is a Rust 2024 Domain-Specific Language (DSL) and optimizing compiler that compiles `.frasm` network traffic specifications into deterministic, nanosecond-precision `.pcap` / `.pcapng` captures—and decompiles `.pcap` / `.pcapng` captures back into `.frasm` code—across **81 native Layer 2 through Layer 7 protocols** (docs: [`https://frameassembly-lang.dev/docs`](https://frameassembly-lang.dev/docs), scenarios: [`https://frameassembly-lang.dev/use-cases`](https://frameassembly-lang.dev/use-cases)).

---

## 1. Quick Build, Test & Verification Commands

```bash
# Bootstrap install (prebuilt binary or cargo install; Windows: irm https://raw.githubusercontent.com/SteveWinschel/FrameAssembly/main/install.ps1 | iex)
curl -fsSL https://raw.githubusercontent.com/SteveWinschel/FrameAssembly/main/install.sh | sh

# Build and verify (MSRV 1.89 in src/; tests/ may use Rust 1.100+ with cfg_attr(test, clippy::msrv = "1.100.0"))
cargo build --release
cargo test
cargo test --test corpus_verification_tests

# CLI (default root compile + 5 subcommands: show, reverse, update, help, version; zero -o/--output flags, zero `compile` subcommand)
cargo run -- demo.frasm output.pcap          # defaults to <input_stem>.pcap (.pcap=libpcap, .pcapng=PCAPNG)
cargo run -- show demo.frasm                 # print packet ladder without disk I/O
cargo run -- reverse output.pcap out.frasm   # decompile .pcap/.pcapng (defaults to <input_stem>.frasm)
cargo run -- update                          # zero-flag self-updater (Cargo/rustup-first, SHA-256 GitHub Release fallback)
cargo run -- help
cargo run -- version
```

---

## 2. Unified `<layer>/<protocol>` Architecture & Discovery Map

FrameAssembly enforces strict `<layer>/<protocol>` symmetry across `src/ast/`, `src/parser/`, `src/builders/`, and `src/reverse/`:

- **`src/lexer/mod.rs`**: Zero-copy `logos 0.14.4` strict-lowercase tokenizer (`Token<'a>`, 81 protocols, L2–L7 modifiers, SNMPv3 USM, time units `ns`/`us`/`ms`/`s`/`m`, IP/MAC/OID literals, flexible user `Token::Ident`; zero `ignore(ascii_case)`, zero `Token::Loop`).
- **`src/ast/{l2,l3,l4,l7}/<protocol>.rs`**: Typed AST nodes (`RunStatement::{Invocation, Frame}`) and `*Spec` structs with lowercase `/// Syntax mapping: \`...\`` and `#[doc(alias = "...")]`.
- **`src/parser/{l2,l3,l4,l7}/<protocol>.rs`**: Two-phase `winnow 1.0.5` `Stream<'i, 'a>` combinators (`pub(crate) mod` internals, `whois` protocol-first guard + 3-tier dispatch), self-healing `replace '<raw>' with '<kw>'` / `loop` diagnostics, and `validate_semantics(&program, &source)` (`src/parser/validation.rs`, invoked by `parse_program`).
- **`src/builders/{l2,l3,l4,l7}/<protocol>.rs` & `src/packet.rs`**: Native zero-heap wire encoders (including `l7/snmp/{builder,crypto}.rs` RFC 1157/3416/3414/3826/7860 BER & USM crypto) and `L7 -> L4 -> L3 -> L2` checksum/framing.
- **`src/backend/{mod.rs,l7_dispatch.rs}` & `src/pcap.rs`**: 4-tuple TCP `seq`/`acknum` progression (`seq = 1000`, `psh ack`), `<-` port swapping, multicast MAC derivation (RFC 1112 / 2464), dynamic `L7DispatchResult` ports/multicast, and `pcap-file 2.0.0` PCAP/PCAPNG writer (`IfTsResol(9)`).
- **`src/reverse/{l2,l3,l4,l7}/<protocol>.rs`**: Five-stage PCAP/PCAPNG-to-`.frasm` decompiler (`reverse_pcap_reader`, `reverse_pcap_bytes`, `reverse_pcap_file`) with `container.rs`, `topology.rs`, `oracle.rs`, `shadow_emit.rs`, `l3/{ip,ipv6,icmpv6}.rs` + 20 L3 + 50 L7 (`l7/{snmp1,snmp2,snmp3}.rs`), emitting `host1`, `host2`, strict-lowercase tokens, and chronological **inline directional frame statements inside `compile { ... }`** (no `flow` blocks/calls, no `loop`).
- **`src/main.rs` & `src/updater.rs`**: CLI entrypoint and binary-private Cargo-first + fail-closed SHA-256 GitHub Release self-updater (`mod updater;`).
- **Website Docs & Local `.agents/` Isolation**: User docs and examples live at `https://frameassembly-lang.dev/docs` and `https://frameassembly-lang.dev/use-cases` (no in-repo `docs/` or `examples/`). `.agents/` is local-only (gitignored in `.gitignore`, never linked from tracked Markdown docs or scanned in CI).
- **Grammars, Standards & AI Metadata**: [`grammar.ebnf`](grammar.ebnf) (ISO 14977 EBNF), [`frameassembly.gbnf`](frameassembly.gbnf) (`llama.cpp` / `XGrammar` GBNF), [`frameassembly.lark`](frameassembly.lark) (`llguidance` / `Outlines` / `vLLM` / `XGrammar` Lark), [`contrib/completions/`](contrib/completions/README.md), [`contrib/packaging/`](contrib/packaging/README.md), [`contrib/iana/text-vnd.frameassembly.md`](contrib/iana/text-vnd.frameassembly.md), [`contrib/mime/text-vnd.frameassembly.xml`](contrib/mime/text-vnd.frameassembly.xml), [`contrib/linguist/`](contrib/linguist/README.md), [`contrib/dataset/croissant.json`](contrib/dataset/croissant.json) (Croissant `1.1`), [`CLAUDE.md`](CLAUDE.md), [`.github/copilot-instructions.md`](.github/copilot-instructions.md), [`llms.txt`](llms.txt), [`llms-full.txt`](llms-full.txt), [`context7.json`](context7.json), [`codemeta.json`](codemeta.json) (CodeMeta `4.0`), [`CITATION.cff`](CITATION.cff).

---

## 3. Canonical `.frasm` v3.2.2 Rules, Branding & Documentation Invariants

1. **Program Structure & Strict-Lowercase Keywords (`[a-z0-9]+`)**:
   - Minimal programs require `host <id> { [ip <ip>] [mac <mac>] }` and one `compile { ... }` block (`flow <id>(<params>) { ... }` is **optional** for reusable sequences; `loop` was removed in v2.0.0; `compile` accepts flow invocations and inline frame statements). MAC-only hosts are valid for the 8 L2 protocols (`arp`, `vlan`, `qinq`, `lldp`, `stp`, `lacp`, `eapol`, `mpls`); L3–L7 require `ip`.
   - Every built-in keyword, protocol, modifier, and time unit (`ns`, `us`, `ms`, `s`, `m`) is **strictly lowercase alphanumeric with zero `_` and zero `-`** (`echorequest`, `innervlan`, `clienthello`, `hosthdr`, `transporthdr`, `sackperm`, `agentip`, `hellotime`, `whois`, `pkttype`, `read`, `write`, `nop`, `error`, `shutdownack`, `readholdingregisters`). User `host`, `flow`, and parameter names accept `[a-zA-Z_][a-zA-Z0-9_]*(-[a-zA-Z0-9_]+)*` (`fw-dmz-01`, `core_sw`).
   - Flows are dual-stack across IPv4/IPv6 (never mix IPv4 and IPv6 in one statement). Every one of the 81 protocols compiles with zero mandatory modifiers, and each statement emits 1 frame sharing 4-tuple TCP state (`seq = 1000`, `psh ack` on TCP L7).
2. **Anti-Hallucination Ban List**:
   - Never write uppercase built-in keywords (`HOST`, `TCP`, `WAIT`), underscores/hyphens in keywords (`echo_request`, `inner_vlan`, `host_hdr`, `sack_perm`), or `=`, colons, commas, CIDR `/24`, `ipv4`, `ipv6`, or `mask` in `host` blocks.
   - Never declare parameterless `flow <id> { ... }` or use `from`, `to`, `reverse`, `send`, `loop`, standalone `wait` lines, `+5ms`/`[+delay]`, `;`, `#` comments, or `'single quotes'`.
   - Never use `sport`, `dport`, `ack <n>`, `flags [...]`, `hop_limit`/`hoplimit`, `http ... host`, `rtsp ... transport`, or `qinq 100 200` (use `srcport`, `dstport`, `acknum <n>`, bare flags `syn ack`, `ttl`, `hosthdr`, `transporthdr`, `qinq 100 innervlan 200`).
   - Never invent a `compile` CLI subcommand or `-o`/`--output` flags, or call `compile` with argumentless flows.
3. **Branding, Channel Boundaries & Confidentiality**:
   - Write `FrameAssembly` as one CamelCase word (`frameassembly` for crate/CLI/URLs/code); never split with a space. Disambiguate `.frasm` (`text/vnd.frameassembly`, scope `source.frameassembly`) from x86 Flat Assembler and FPGA FASM. Position FrameAssembly as the upstream companion to `Wireshark`, `tshark`, `tcpreplay`, `Suricata`, and `Zeek` (compare only against `Scapy`, `text2pcap`, `Ostinato`; describe as `"rootless"`, `"offline"`, `"deterministic"`, `"no libpcap or raw sockets required"`—never claim zero external crate dependencies).
   - **Public vs. Maintainer Channels**: User-facing CLI docs (`README.md`, `llms.txt`) promote ONLY **Crates.io (`cargo install frameassembly`, primary)** and **GitHub Releases** (archives, `.deb`, `.vsix`, `SHA256SUMS.txt`), alongside `frameassembly-lang.dev` and VS Code Marketplace (`frameassembly-vscode`). `frameassembly-wasm` is internal to `frameassembly-lang.dev` and `frameassembly-vscode` (never advertise `npm install frameassembly-wasm`, `brew install`, or `scoop install` in root `README.md`, while `contrib/packaging/` and `.github/workflows/release.yml` retain maintainer packaging recipes and CI jobs).
   - **Private Context Confidentiality**: Never include private background context from user prompts (e.g., employer names or employment status) anywhere in code, comments, docs, or metadata.
4. **Audience Voice, Anti-Slop Craft, 6-Way Lockstep & Rust/Doc Hygiene**:
   - Keep `llms.txt` (`< 512` lines, `< 25 KB`) as an AI discovery index and `llms-full.txt` (`60–250 KB`) for prompt injection (no `AGENTS.md` contributor rules or raw `src/ast/` code). Write `README.md` in a natural human voice for network/security practitioners—minimalistic, problem-focused (`Checkmk`, `Zabbix`, `Wireshark`, `Suricata`, `tcpreplay`), calling `.frasm` **code** (never `"plain text"`), preserving playful practitioner humor while banning corporate AI-slop tells (negative parallelism, rule-of-three padding, stacked em dashes, prose `->` arrows, filler adjectives `"readable"`, `"clean"`, `"editable"`, `"canonical"`, `"repeatable"`, PL jargon `"DSL"`, `"declarative"`, `"polymorphic"`, `"deterministic"`, unverified speed/count claims, and prompt leaks).
   - Maintain 6-way lockstep (`src/lexer/mod.rs` <-> `src/parser/` <-> `grammar.ebnf` <-> `frameassembly.gbnf` <-> `frameassembly.lark` <-> `frameassembly.tmLanguage.json`), sync `frameassembly-wasm` (`*_frasm` canonical exports + `2.x` aliases), `README.md`, `src/lib.rs`, `llms*.txt`, `contrib/mime/text-vnd.frameassembly.xml`, and `contrib/linguist/heuristics.yml`, and ensure every ````frameassembly`/````frasm` block and `contrib/linguist/samples/*.frasm` file compiles cleanly.
   - Keep `src/**/*.rs` and `tests/*.rs` strictly `< 50,000` B with `//!` headers (`>= 50` words) and RAII temp cleanups in tests, `AGENTS.md <= 12 KB` (`<= 24,000` B cap), zero `0x00` NUL bytes, no outer `///` on `pub mod` with inner `//!`, `pub(crate) mod` parser internals, `#[doc(inline)]` layer re-exports, and AST `*Spec` `/// Syntax mapping:` + `#[doc(alias = "...")]`.
   - Never bump `version` in manifests or run `git commit`, `git push`, or `git tag` unless explicitly instructed by the user.
