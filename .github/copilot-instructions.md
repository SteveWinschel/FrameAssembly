# GitHub Copilot Instructions for FrameAssembly (`frameassembly`)

You are working on **FrameAssembly** (`frameassembly` v3.3.1, official website & browser playground: [`https://frameassembly-lang.dev/`](https://frameassembly-lang.dev/), documentation: [`https://frameassembly-lang.dev/docs`](https://frameassembly-lang.dev/docs), use cases: [`https://frameassembly-lang.dev/use-cases`](https://frameassembly-lang.dev/use-cases), repository: [`https://github.com/SteveWinschel/FrameAssembly`](https://github.com/SteveWinschel/FrameAssembly)), a Rust 2024 Domain-Specific Language (DSL) and optimizing compiler that compiles `.frasm` network packet specifications into deterministic `.pcap` / `.pcapng` packet captures—and decompiles `.pcap` / `.pcapng` captures back into canonical `.frasm` code—across **146 native Layer 2 through Layer 7 protocols** (`18` L2 / `31` L3 / `3` L4 / `94` L7).

## 1. Canonical `.frasm` v3.3.1 Syntax Guardrails (Never Hallucinate Keywords)

When generating or editing FrameAssembly (`.frasm`) code or Markdown ````frameassembly` blocks:
1. **Strict-Lowercase Built-In Keywords (`[a-z0-9]+`, Zero `_`, Zero `-`) & Host + Compile Structure (Optional Flow)**:
   - Every built-in keyword, protocol, modifier, and time unit (`ns`, `us`, `ms`, `s`, `m`) is **strictly lowercase alphanumeric with zero `_` and zero `-`** (no `ignore(ascii_case)` across `1,130+` lexer keywords), while user-defined `host`, `flow`, and parameter names remain flexible (`[a-zA-Z_][a-zA-Z0-9_]*(-[a-zA-Z0-9_]+)*`).
   - Always include `host` and `compile` blocks (plus optional reusable `flow` blocks supporting nested `flow` invocations and global `host` refs, and `repeat <u64> { ... }` loops inside `flow`/`compile`; `loop` was removed in v2.0.0) so every snippet compiles standalone:
   ```frameassembly
   // Client and server endpoints for an HTTP healthcheck capture
   host client { ip 10.0.0.10 mac 00:11:22:33:44:10 }
   host server { ip 10.0.0.20 mac 00:11:22:33:44:20 }

   // Reusable TCP 3-way handshake and HTTP/1.1 GET healthcheck sequence
   flow http_healthcheck(c, s) {
       c -> s tcp syn srcport 51000 dstport 80 mss 1460
       c <- s tcp syn ack mss 1460 wait 1ms
       c -> s tcp ack wait 1ms
       c -> s http get uri "/healthz" hosthdr "api.internal" wait 2ms
       c <- s http status 200 reason "OK" body "{\"status\":\"healthy\"}" wait 2ms
   }

   // Emit the capture frames in chronological order
   compile {
       http_healthcheck(client, server)
   }
   ```
2. **CLI Contract (Default Root Compile + 5 Subcommands `show`, `reverse`, `update`, `help`, `version` — Zero `-o`/`--output` Flags)**:
   - Compile (default root command): `cargo run -- demo.frasm output.pcap` (or `frameassembly demo.frasm [output.pcap]`, defaulting to `<input_stem>.pcap`, or `-` for `stdin` `.frasm` -> `stdout` PCAPNG)
   - Preview ladder: `cargo run -- show demo.frasm` (accepts `.frasm`, `.pcap`/`.pcapng`, or `-` `stdin`)
   - Reverse PCAP/PCAPNG: `cargo run -- reverse output.pcap reversed.frasm` (`-` streams `stdin`/`stdout`; emits `host1`, `host2` without `_`, strict lowercase, and chronological inline frame statements inside `compile { ... }` with zero `loop` blocks)
   - Self-update, help & version: `frameassembly update`, `frameassembly help [subcommand]`, and `frameassembly version` (hidden `-h`/`--help` and `-V`/`--version`; Tab completions in `contrib/completions/`)
3. **Forbidden Hallucinations**:
   - Never use uppercase built-in keywords (`HOST`, `TCP`, `SYN`, `WAIT 1MS`) or `_`/`-` inside built-in keywords (`echo_request`, `inner_vlan`, `client_hello`, `host_hdr`, `transport_hdr`, `sack_perm`, `who_is`, `pkt_type`, `read_holding_registers`).
   - Never use `ipv4`, `ipv6`, `=`, colons, commas, or `mask` inside `host { ... }` (only `[ip <ip>]` and `[mac <mac>]`).
   - Never declare parameterless `flow <id> { ... }` or use `from`, `to`, `reverse`, `send`, `loop`, standalone `wait` lines, or `+5ms` / `[+delay]` prefixes (always `flow <id>(<params>) { <a> -> <b> <proto> ... [wait <int><ns|us|ms|s|m>] }`).
   - Never use `sport`, `dport`, `ack_num`, `ack <n>`, `flags [...]`, `hop_limit`, `http ... host`, `rtsp ... transport`, or `req_id` (always use `srcport`, `dstport`, `acknum`, bare flags `syn ack`, `ttl`, `hosthdr`, `transporthdr`, and `reqid`).
   - Never write `qinq 100 200` (always write `qinq 100 innervlan 200`).
   - Never mix IPv4 and IPv6 endpoints in the same statement (`a -> b` or `a <- b`).

## 2. Rust 2024 Compiler, Release Channels & Confidentiality Standards

- Rust source and test files (`src/**/*.rs` and `tests/*.rs`) have no `< 50,000`-byte cap; enforce zero `0x00` NUL bytes, `//! >= 50` words, `max_line_length <= 1,000`, `avg_line_length <= 100`, alphabetic `>= 25%`, and the `1–8` MB raw pretraining ceiling. Human-facing `README.md` must never include `// PROMPT:`, `// TOKENS:`, or `// INSTRUCTION:` metadata comments. User documentation lives at https://frameassembly-lang.dev/docs and use cases/examples at https://frameassembly-lang.dev/use-cases.
- Every `src/**/*.rs` file must begin with `//!` module-level documentation (`>= 50` words) and document all structs, enums, fields, and functions without combining outer `///` on `pub mod` with inner `//!`.
- Keep `src/lexer/mod.rs`, `src/parser/`, `grammar.ebnf`, `frameassembly.gbnf`, `frameassembly.lark`, `frameassembly-vscode/syntaxes/frameassembly.tmLanguage.json`, `frameassembly-wasm`, `README.md`, `src/lib.rs`, `llms.txt`, `llms-full.txt`, and `contrib/mime/text-vnd.frameassembly.xml` synchronized whenever lexer tokens or supported protocols change.
- **AI Context Files**: `llms.txt` (`< 512` lines, `< 25 KB`) serves search engines and web-fetching assistants; `llms-full.txt` (`60–250 KB`) is dedicated prompt-injection context (no `AGENTS.md` contributor rules or raw `src/ast/` code).
- **Practitioner Docs & `README.md` Voice**: Website docs (`https://frameassembly-lang.dev/docs`) and `README.md` target networking and cybersecurity practitioners (`Checkmk`, `Zabbix`, `Wireshark`, `Suricata`, `tcpreplay`) in a direct human voice, calling `.frasm` **code** (`Packets as Code`, never `"plain text"`). Keep `README.md` problem-focused and preserve playful practitioner humor (such as the coworker SQL-injection hook and `:)`) while banning corporate AI-slop patterns (negative parallelism, rule-of-three padding, stacked em dashes, prose `->` arrows, filler adjectives `"readable"`, `"clean"`, `"editable"`, `"canonical"`, `"repeatable"`, PL jargon `"DSL"`, `"Domain-Specific Language"`, `"declarative"`, `"polymorphic"`, `"deterministic"`, unverified latency/scenario claims, and prompt leaks).
- **Subcrate READMEs**: Tailor `frameassembly-vscode/README.md` and `frameassembly-wasm/README.md` to their readers (`*_frasm` canonical WASM names with a `2.x` alias note).
- **Branding & Disambiguation**: Write `FrameAssembly` as one unspaced CamelCase word (`frameassembly` for crate/CLI/URLs/identifiers), never claim zero external crate dependencies (use `"rootless"`, `"offline"`, `"deterministic"`, `"no libpcap or raw sockets required"`), disambiguate `.frasm` (`text/vnd.frameassembly`) from x86 Flat Assembler and FPGA FASM `.fasm` files, and position FrameAssembly as the upstream companion to `tcpreplay`, `Wireshark`, `tshark`, `Suricata`, and `Zeek` (comparing only against `Scapy`, `text2pcap`, and `Ostinato`).
- **User-Facing CLI Channels & Internal WASM Engine**: User-facing CLI channels are Crates.io (`cargo install frameassembly`, primary recommended, Rust `1.89+`) and GitHub Releases (pre-built archives + Debian/Ubuntu `.deb`), alongside VS Code Marketplace (`frameassembly-vscode`). `frameassembly-wasm` is internal for `frameassembly-lang.dev` and `frameassembly-vscode`—never advertise `npm install frameassembly-wasm`, `Homebrew`, or `Scoop` in root `README.md`, and never add third-party registry workflows beyond `.github/workflows/release.yml`. `.agents/` is local-only (gitignored) and must never be linked in tracked docs or CI tests.
- **Private User Context Confidentiality**: Never include private background context shared by the user in prompts (such as employer names or employment/apprenticeship status) anywhere in code, comments, examples, documentation, or metadata.
- Never bump `version` in manifests or run `git commit`, `git push`, or `git tag` unless explicitly instructed by the user.
- Run `cargo test` to verify all unit, integration, and documentation tests pass.
