---
trigger: glob
globs: "src/main.rs, Cargo.toml, tests/**/*.rs"
description: "Clap 4.6.7+, clap_builder 4.6.7, clap_lex 1.1.1, anstyle 1.0.14, and anstream 1.0.0 CLI architecture, hybrid positional + show/reverse subcommand routing, ValueSource precedence, and debug_assert QA rules."
---

# Clap 4.6.7+ CLI Engineering Architecture & Best Practices

Enforce these type-safe, zero-proc-macro-ready `clap` (`4.6.7+`, `clap_builder 4.6.7`, `clap_lex 1.1.1`, `anstyle 1.0.14`, `anstream 1.0.0`, MSRV `1.85.0`) rules when maintaining or extending `src/main.rs` and CLI integration tests:

## 1. Workspace Feature Boundary Matrix & New `4.6.x` APIs (`clap = "4.6.7"`)
- **Default Feature Set (`Cargo.toml` uses `clap = "4.6.7"` without `derive`)**:
  - Enabled by default: `std`, `color`, `help`, `usage`, `error-context`, `suggestions`.
  - Available without proc-macros: full `Command` / `Arg` / `ArgGroup` Builder API, `ArgAction`, `ArgMatches`, `ValueSource`, `ValueHint`, `TypedValueParser` (`PathBufValueParser`, `NonEmptyStringValueParser`, `RangedI64ValueParser`, `RangedU64ValueParser`, `PossibleValuesParser`, `BoolishValueParser`), `anstyle::Styles`, and traits (`Parser`, `Subcommand`, `Args`, `ValueEnum`, `CommandFactory`, `FromArgMatches`—including `Args`/`FromArgMatches` impls for `()` and `core::convert::Infallible`).
  - **Clap `4.6.x` Additions**: `Command::defer` / `#[command(defer = true)]` for lazy subcommand tree initialization (startup optimization for large subcommand hierarchies) and `Command::get_overridden_usage` for inspecting custom usage strings.
- **Opt-In Features (Do Not Assume Unless Enabled in `Cargo.toml`)**:
  - `derive` (`#[derive(Parser)]`), `cargo` (`command!()`), `env` (`Arg::env`), `string` (dynamic `String` names/help), `wrap_help`, `unicode`. Without `cargo`, always pass `env!("CARGO_PKG_VERSION")` to `.version(...)`.

## 2. FrameAssembly Hybrid Positional + Subcommand Architecture
- **Tri-Modal Entry Pattern (`frameassembly <input.fasm>` + `frameassembly show <input.fasm>` + `frameassembly reverse <input.pcap>`)**:
  - `src/main.rs` supports direct compilation (`frameassembly capture.fasm [-o capture.pcap]`, defaulting to `<input_stem>.pcap`), terminal packet ladder inspection (`frameassembly show capture.fasm`), and reverse PCAP decompilation (`frameassembly reverse capture.pcap [-o capture.fasm]`, defaulting to `<input_stem>.fasm`).
  - Always set `.args_conflicts_with_subcommands(true)` (and `.arg_required_else_help(true)` if making root positional `input` optional) on the root `Command` so `frameassembly show <file>` and `frameassembly reverse <file>` dispatch cleanly to their subcommands without colliding with the root positional `input` argument!
  - Never set `.subcommand_required(true)` on the root `Command` while direct positional compilation `frameassembly <input.fasm>` remains part of the CLI contract.

## 3. Builder Extraction, `ValueHint` & Mandatory `debug_assert()` Gate
- **Extract `build_cli() -> Command`**: Never inline `Command::new(...)` directly inside `fn main()`. Keep CLI construction in `fn build_cli() -> Command` so unit tests validate invariants without spawning subprocesses.
- **Mandatory `debug_assert()` Test**: Every CLI binary must keep this unit test:
  ```rust
  #[test]
  fn verify_cli_invariants() {
      build_cli().debug_assert();
  }
  ```
- **Strongly-Typed Path & Bounded Parsers**:
  - Annotate file/directory arguments with `ValueHint::FilePath` / `ValueHint::DirPath` and prefer `PathBufValueParser::new()` (`get_one::<PathBuf>`) or `NonEmptyStringValueParser::new()` over raw unchecked strings.
  - Extract owned values with `matches.remove_one::<T>("id")` when mutating `ArgMatches` to avoid heap `.clone()` calls.

## 4. `ArgAction`, Constraints & 9-Role `anstyle` Palette
- **Explicit `ArgAction`**: Use `ArgAction::Set`, `ArgAction::Append`, `ArgAction::SetTrue`, `ArgAction::SetFalse`, and `ArgAction::Count`. Pair `--flag` / `--no-flag` toggles via `.overrides_with(...)`.
- **Declarative Constraints**: Express mutual exclusivity and conditional dependencies with `ArgGroup`, `.conflicts_with(...)`, and `.requires(...)` rather than post-parse `if` checks.
- **Terminal Styling & Global Color Sync**: Configure `clap::builder::styling::Styles` across all 9 roles (`header`, `usage`, `literal`, `placeholder`, `error`, `valid`, `invalid`, `context`, `context_value`). If a `--color <auto|always|never>` flag is added, call `anstream::ColorChoice::write_global(...)` so `miette` inherits the exact color mode.

## 5. Layered Configuration & The `ValueSource::CommandLine` Invariant
- **CRITICAL INVARIANT**: Whenever an `Arg` defines `.default_value("output.pcap")`, `matches.get_one::<T>("output")` **always returns `Some(...)`** even when omitted on the CLI (`ValueSource::DefaultValue`).
- If environment variables or config files are layered underneath CLI flags, **always** check `matches.value_source("output") == Some(clap::parser::ValueSource::CommandLine)` before treating the value as an explicit user CLI override; fall back to `DefaultValue` last.