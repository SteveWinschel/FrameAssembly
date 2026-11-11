---
trigger: glob
globs: "src/main.rs, Cargo.toml, contrib/completions/**, tests/**/*.rs"
description: "Clap 4.6.7+, clap_builder 4.6.7, clap_lex 1.1.1, anstyle 1.0.14, and anstream 1.0.0 CLI architecture, v2.0.0 default-compile + 4-subcommand routing (show/reverse/help/version), static shell completions, ValueSource precedence, and debug_assert QA rules."
---

# Clap 4.6.7+ CLI Engineering Architecture & Best Practices

Enforce these type-safe, zero-proc-macro-ready `clap` (`4.6.7+`, `clap_builder 4.6.7`, `clap_lex 1.1.1`, `anstyle 1.0.14`, `anstream 1.0.0`, MSRV `1.85.0`) rules when maintaining or extending `src/main.rs`, `contrib/completions/`, and CLI integration tests:

## 1. Workspace Feature Boundary Matrix & New `4.6.x` APIs (`clap = "4.6.7"`)
- **Default Feature Set (`Cargo.toml` uses `clap = "4.6.7"` without `derive`)**:
  - Enabled by default: `std`, `color`, `help`, `usage`, `error-context`, `suggestions`.
  - Available without proc-macros: full `Command` / `Arg` / `ArgGroup` Builder API, `ArgAction`, `ArgMatches`, `ValueSource`, `ValueHint`, `TypedValueParser` (`PathBufValueParser`, `NonEmptyStringValueParser`, `RangedI64ValueParser`, `RangedU64ValueParser`, `PossibleValuesParser`, `BoolishValueParser`), `anstyle::Styles`, and traits (`Parser`, `Subcommand`, `Args`, `ValueEnum`, `CommandFactory`, `FromArgMatches`—including `Args`/`FromArgMatches` impls for `()` and `core::convert::Infallible`).
  - **Clap `4.6.x` Additions**: `Command::defer` / `#[command(defer = true)]` for lazy subcommand tree initialization (startup optimization for large subcommand hierarchies) and `Command::get_overridden_usage` for inspecting custom usage strings.
- **Opt-In Features (Do Not Assume Unless Enabled in `Cargo.toml`)**:
  - `derive` (`#[derive(Parser)]`), `cargo` (`command!()`), `env` (`Arg::env`), `string` (dynamic `String` names/help), `wrap_help`, `unicode`. Without `cargo`, always pass `env!("CARGO_PKG_VERSION")` to `.version(...)`.

## 2. FrameAssembly v2.0.0 Default-Compile + 4-Subcommand CLI & Tab-Prediction Architecture
- **Root Default Compile + Four Canonical Subcommands (`show`, `reverse`, `help`, `version`)**:
  - `frameassembly <input.fasm> [output.pcap]` (default root command; optional 2nd positional `[output.pcap]` replaces `-o`/`--output`, defaulting via `derive_default_output_path(input, "pcap")` to `<input_stem>.pcap`; configured with `.subcommand_negates_reqs(true)`, `.args_conflicts_with_subcommands(true)`, and `.arg_required_else_help(true)`—there is **no** `compile` CLI subcommand).
  - `frameassembly show <input.fasm>` (validates `.fasm` code and prints a relative-timestamp packet ladder table without writing disk files).
  - `frameassembly reverse <input.pcap> [output.fasm]` (optional 2nd positional `[output.fasm]` replaces `-o`/`--output`, defaulting to `<input_stem>.fasm`).
  - `frameassembly help [subcommand]` and `frameassembly version` (pair `.disable_help_flag(true)` / `.disable_version_flag(true)` with hidden `-h`/`--help` `ArgAction::Help` and `-V`/`--version` `ArgAction::Version` via `.hide(true)` so scripts still exit `0`, and guard in `check_legacy_cli_args` against `-o`/`--output`, `--show`/`--reverse`, bare `.pcap`/`.pcapng` at arg 1, accidental `"compile"` as arg 1, and `.fasm` passed as `OUTPUT.pcap`).
- **Extension-Aware Shell Tab Predictions (`contrib/completions/`)**:
  - Maintain static `bash`, `zsh`, `fish`, and `powershell` completion scripts in `contrib/completions/` completing both the 4 subcommands (`show`, `reverse`, `version`, `help`) and `.fasm` paths at position 1, `.pcap`/`.pcapng` paths at position 2 when arg 1 is a `.fasm` path, `.fasm` paths after `show`, `.pcap`/`.pcapng` (arg 2) and `.fasm` (arg 3) after `reverse`, and subcommand names after `help`, installed automatically by `install.sh` and `.deb` packaging.

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
- If environment variables or config files are layered underneath CLI subcommand arguments, **always** check `matches.value_source("output") == Some(clap::parser::ValueSource::CommandLine)` before treating the value as an explicit user CLI override; fall back to `DefaultValue` last.
