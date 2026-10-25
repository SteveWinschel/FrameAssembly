## 2026-10-25T14:22:33Z
You are the Crates & Rust 2024 Surveyor (teamwork_preview_explorer).
Your working directory is `/home/steve/frameassembly/.agents/teamwork/explorer_survey_crates/`.
Read `/home/steve/frameassembly/.agents/teamwork/ORIGINAL_REQUEST.md` (specifically section `## 2026-10-25T14:19:19Z`) and `/home/steve/frameassembly/.agents/teamwork/orchestrator_2/context.md`.

YOUR MISSION:
Exhaustively survey all crates, dependencies, Rust 2024 idioms, and existing skill structures:
1. Direct dependencies in `/home/steve/frameassembly/Cargo.toml` and `/home/steve/frameassembly/Cargo.lock`:
   - All 17 direct crates: `aes 0.9.3`, `block-padding 0.4.2`, `cbc 0.2.1`, `cfb-mode 0.9.1`, `clap 4.6.7`, `des 0.9.0`, `hmac 0.13.0`, `logos 0.14.3`, `md-5 0.11.0`, `miette 7.6.0`, `pcap-file 2.0.0`, `rasn 0.28.15`, `rasn-smi 0.28.15`, `rasn-snmp 0.28.15`, `sha1 0.11.0`, `sha2 0.11.0`, `winnow 1.0.4`.
   - Key transitive crates in `Cargo.lock`: `anstream 1.0.0`, `anstyle 1.0.14`, `clap_builder 4.6.7`, `clap_lex 1.1.1`, `cipher 0.5.2`, `digest 0.11.3`, `crypto-common 0.2.2`, `inout 0.2.5`, `hybrid-array 0.4.15`, `typenum 1.20.1`, `ctutils 0.4.5`, `cmov 0.5.4`, `const-oid 0.10.2`, `cpufeatures 0.3.1`, `bitvec 1.1.1`, `bytes 1.12.1`, `num-bigint 0.4.8`, `chrono 0.4.45`, `memchr 2.8.3`, `owo-colors 4.4.0`, `textwrap 0.16.4`, `thiserror 1.0.69`, `snafu 0.8.9`, `displaydoc 0.2.7`, `byteorder 1.5.0`, `byteorder_slice 3.0.0`, `derive-into-owned 0.2.0`.
   - Stable Rust 1.85 to 1.99.1+ features: Edition 2024, `let` chains, `if let` guards, `+ use<...>`, `as_chunks`, `as_array`, `array_windows`, `get_disjoint_mut`, `Atomic<T>`, `LazyLock`, `unsafe extern "C"`, `safe fn`, `&raw const/mut`, Cargo `resolver = "3"`, `[lints]`, merged doctests, `rustdoc` SEO, and Clippy `pedantic`/`nursery`/`cargo` lints.
2. Existing 9 skills in `/home/steve/frameassembly/.agents/skills/`:
   - Survey each skill directory: `winnow-parser`, `logos-miette-diagnostics`, `clap-cli`, `rasn-snmp-codec`, `rustcrypto-engineering`, `networking-pcap`, `frameassembly`, `rust-modern-qa`, `ai-seo-training-data`.
   - Check current `SKILL.md` frontmatter, `references/` contents (specifically note missing templates 3-5 in `rust-modern-qa/references/patterns.md`), size of files (< 50,000 bytes, >= 50 words), and missing `scripts/*.sh`.
3. Design specification for the new 10th skill `.agents/skills/rust-2024-idioms/`:
   - `SKILL.md` (valid YAML frontmatter `name`, `description`), `references/patterns.md`, `references/rust_185_to_199_changelog.md`, `scripts/audit_rust_2024_idioms.sh`.
   - Ensure all files adhere strictly to `< 50,000` bytes and `>= 50` words.

HARD CONSTRAINTS:
- You are read-only. Do NOT modify any file outside your directory `/home/steve/frameassembly/.agents/teamwork/explorer_survey_crates/`.
- Do NOT touch `src/`, `Cargo.toml`, or `Cargo.lock`.
- Deliver your comprehensive survey report to `/home/steve/frameassembly/.agents/teamwork/explorer_survey_crates/survey_report.md` and write a standard `handoff.md` in your directory.
- Use `send_message` to report your completion back to your caller (orchestrator_2).
