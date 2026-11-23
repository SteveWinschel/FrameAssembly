# CLAUDE.md — FrameAssembly Project Instructions for Claude Code & AI Agents

**FrameAssembly** (`frameassembly` v3.2.2, playground: [`https://frameassembly-lang.dev/`](https://frameassembly-lang.dev/), docs: [`https://frameassembly-lang.dev/docs`](https://frameassembly-lang.dev/docs), scenarios: [`https://frameassembly-lang.dev/use-cases`](https://frameassembly-lang.dev/use-cases), repo: [`https://github.com/SteveWinschel/FrameAssembly`](https://github.com/SteveWinschel/FrameAssembly)) compiles `.frasm` network traffic code into deterministic `.pcap` / `.pcapng` packet captures—and decompiles `.pcap` / `.pcapng` captures back into `.frasm` code—across **81 native Layer 2 through Layer 7 protocols**.

Please read [`AGENTS.md`](AGENTS.md) at the repository root for complete branding, audience voice, release channel boundaries, confidentiality, Rustdoc `< 50 KB` caps, and 6-way grammar lockstep rules.

---

## 1. Essential Build, Test & CLI Commands

```bash
# Bootstrap install (Windows PowerShell: irm https://raw.githubusercontent.com/SteveWinschel/FrameAssembly/main/install.ps1 | iex)
curl -fsSL https://raw.githubusercontent.com/SteveWinschel/FrameAssembly/main/install.sh | sh

cargo build --release
cargo test

# CLI: default root compile + 5 subcommands (show, reverse, update, help, version; no -o/--output flags, no `compile` subcommand)
cargo run -- demo.frasm output.pcap          # defaults to <input_stem>.pcap
cargo run -- show demo.frasm                 # print packet ladder without writing disk files
cargo run -- reverse output.pcap out.frasm   # defaults to <input_stem>.frasm
cargo run -- update
cargo run -- help
cargo run -- version
```

---

## 2. Canonical `.frasm` v3.2.2 Syntax Rules (Zero Hallucinations)

1. **Program Structure, Strict-Lowercase Keywords (`[a-z0-9]+`) & Flexible Identifiers**:
   - **Built-In Keywords**: Strictly lowercase alphanumeric with zero `_` and zero `-`, and no `ignore(ascii_case)` (`host`, `ip`, `mac`, `flow`, `compile`, `tcp`, `echorequest`, `innervlan`, `clienthello`, `hosthdr`, `transporthdr`, `sackperm`, `agentip`, `hellotime`, `whois`, `pkttype`, `read`, `write`, `nop`, `error`, `shutdownack`, `readholdingregisters`).
   - **User Identifiers**: `host`, `flow`, and parameter names match `[a-zA-Z_][a-zA-Z0-9_]*(-[a-zA-Z0-9_]+)*` (`fw-dmz-01`, `core_sw`). Reverse decompilation (`frameassembly reverse`) emits `host1`, `host2` without `_`, strict-lowercase tokens, and chronological **inline directional frame statements inside `compile { ... }`** (zero `flow` blocks/calls, zero `loop`).
   - `host <id> { [ip <ipv4_or_ipv6>] [mac <mac>] }` (at least one of `ip` or `mac` required; MAC-only valid for the 8 L2 protocols `arp`, `vlan`, `qinq`, `lldp`, `stp`, `lacp`, `eapol`, `mpls`; `mac` accepts `:`, `-`, or Cisco dot-quad `001a.2b3c.4d5e`; never `ipv4`, `ipv6`, `=`, `:`, `,`, CIDR, or `mask`).
   - Optional reusable `flow <id>(<param1>, <param2>, ...) { <src> -> <dst> <protocol> [modifiers...] [wait <int><ns|us|ms|s|m>] }` (never parameterless `flow <id> { ... }`, `from`/`to`/`reverse`/`send`, standalone `wait` lines, or `+5ms`/`[+delay]`).
   - `compile { <flow_id>(<host1>, <host2>, ...) | <src> -> <dst> <protocol> ... }` (`loop` removed in v2.0.0; minimal compilable `.frasm` programs and ````frameassembly` blocks only require `host` and `compile`—`flow` is optional).
2. **Exact Modifier Keywords & Dual-Stack Endpoints**:
   - Use `srcport`, `dstport`, `seq`, `acknum`, `win`/`window`, `sackperm`, bare TCP flags `syn ack fin rst psh urg ece cwr` (never `sport`, `dport`, `ack_num`, `ack <n>`, `sack_perm`, `flags [...]`).
   - Use `ttl` for IPv4/IPv6 (never `hop_limit`/`hoplimit`), `qinq <outer> innervlan <inner>`, `hosthdr`, `transporthdr`, `reqid`. Never mix IPv4 and IPv6 in one statement.
3. **Training-Data Headers (External SFT Datasets Only — Never in Repo Docs or User `.frasm` Examples)**:
   - Restrict `// PROMPT:`, `// TOKENS:`, and `// INSTRUCTION:` strictly to external SFT/DPO dataset exports (never emit them in `README.md`, `llms*.txt`, Copilot examples, or user `.frasm` files). Keep `src/**/*.rs` and `tests/*.rs` `< 50,000` B with `words >= 50`, `avg_line_length <= 85`, and `max_line_length <= 200`.

---

## 3. Repository Architecture & Discovery Map

- **Compiler & Reverse Pipeline (`src/`)**: [`src/lexer/mod.rs`](src/lexer/mod.rs) (`logos 0.14.4`), [`src/ast/`](src/ast/mod.rs), [`src/parser/`](src/parser/mod.rs) (`winnow 1.0.5`, `parse_program`, `validate_semantics`), [`src/builders/`](src/builders/mod.rs), [`src/main.rs`](src/main.rs), [`src/updater.rs`](src/updater.rs) (`mod updater;` CLI self-updater), [`src/backend/mod.rs`](src/backend/mod.rs), [`src/packet.rs`](src/packet.rs), [`src/pcap.rs`](src/pcap.rs), and [`src/reverse/`](src/reverse/mod.rs) (5-stage PCAP/PCAPNG-to-`.frasm` decompiler emitting `host1`/`host2` + inline `compile { ... }` statements).
- **Grammars, Registration & Metadata**: [`grammar.ebnf`](grammar.ebnf), [`frameassembly.gbnf`](frameassembly.gbnf), [`frameassembly.lark`](frameassembly.lark), [`contrib/completions/`](contrib/completions/README.md), [`contrib/packaging/`](contrib/packaging/README.md), [`contrib/iana/text-vnd.frameassembly.md`](contrib/iana/text-vnd.frameassembly.md), [`contrib/mime/text-vnd.frameassembly.xml`](contrib/mime/text-vnd.frameassembly.xml), [`contrib/linguist/`](contrib/linguist/README.md), [`contrib/dataset/croissant.json`](contrib/dataset/croissant.json), [`AGENTS.md`](AGENTS.md), [`llms.txt`](llms.txt), [`llms-full.txt`](llms-full.txt), [`context7.json`](context7.json), [`CITATION.cff`](CITATION.cff), [`codemeta.json`](codemeta.json).
- **Boundaries**: User CLI channels are Crates.io (`cargo install frameassembly`, primary) and GitHub Releases (`frameassembly-wasm` is internal to `frameassembly-lang.dev` and `frameassembly-vscode`; never advertise `npm install frameassembly-wasm`, `brew install`, or `scoop install` in root `README.md`). `.agents/` is local-only (gitignored, never linked from tracked docs). Write `FrameAssembly` as one CamelCase word, keep private user context confidential, and never bump versions or run `git commit`/`push`/`tag` unless explicitly instructed.
