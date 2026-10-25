---
trigger: glob
globs: "src/main.rs, Cargo.toml, tests/**/*.rs"
description: "Clap 4.6.7+, clap_builder, clap_lex 1.1.1, anstyle 1.0.14, and anstream 1.0.0 CLI architecture, ValueSource precedence, and debug_assert QA rules."
---

# Clap 4.6.7+ CLI Engineering Architecture & Best Practices

Always enforce these modern, type-safe, high-performance, and idiomatic `clap` (`4.6.7+`, `clap_builder 4.6.7`, `clap_lex 1.1.1`, `anstyle 1.0.14`, `anstream 1.0.0`) command-line interface design rules, feature boundary constraints, attribute grammars, and builder patterns when creating, expanding, or refactoring Rust CLIs:

## 1. Workspace Feature Boundary Matrix (`clap 4.6.7`)
- **Default Feature Set (`clap = "4.6"` without `features = [...]`)**:
  - Enabled by default: `std`, `color`, `help`, `usage`, `error-context`, `suggestions`.
  - Available out-of-the-box without proc-macros: full `Command` / `Arg` / `ArgGroup` Builder API, `ArgAction`, `ArgMatches`, `ValueSource`, `ValueHint`, `TypedValueParser` implementations (`PathBufValueParser`, `NonEmptyStringValueParser`, `RangedI64ValueParser`, `RangedU64ValueParser`, `PossibleValuesParser`, `BoolishValueParser`, `FalseyValueParser`, `EnumValueParser`, `ValueParser`), `anstyle::Styles`, and the trait definitions (`Parser`, `Subcommand`, `Args`, `ValueEnum`, `CommandFactory`, `FromArgMatches`).
- **Opt-In Cargo Feature Flags (Must Be Enabled Before Using)**:
  - `derive`: Enables `#[derive(Parser, Subcommand, Args, ValueEnum)]` via `clap_derive`. Never write `#[derive(Parser)]` unless `features = ["derive"]` is present in `Cargo.toml` (or implement `CommandFactory` + `FromArgMatches` + `Parser` manually).
  - `cargo`: Enables `crate_version!()`, `crate_authors!()`, `crate_description!()`, and `command!()`. Without `cargo`, pass `env!("CARGO_PKG_VERSION")` to `.version(...)`.
  - `env`: Enables `Arg::env(...)` and `#[arg(env = "...")]`. Without `env`, resolve `std::env::var(...)` in layered configuration using `matches.value_source("id")`.
  - `string`: Enables dynamic `String` (non-`&'static str`) identifiers and help text via `Str::from(String)`.
  - `wrap_help`: Enables dynamic terminal-width line wrapping via `terminal_size`.
  - `unicode`: Enables Unicode display width calculation and case-insensitive comparisons.

## 2. Declarative Derive Architecture & Attribute Grammar
- **Primary Derive Macros (`Parser`, `Subcommand`, `Args`, `ValueEnum`)**:
  - `#[derive(Parser)]`: Annotate only the top-level application CLI struct. Automatically implements `Parser`, `CommandFactory`, and `FromArgMatches`, exposing `.parse()`, `.try_parse()`, `.parse_from()`, and `.try_parse_from()`.
  - `#[derive(Subcommand)]`: Annotate enum types representing mutually exclusive subcommands. Each variant represents a discrete action (e.g., `Compile`, `Check`, `Run`).
  - `#[derive(Args)]`: Annotate reusable, composable struct groups of CLI options flattened across commands via `#[command(flatten)]`.
  - `#[derive(ValueEnum)]`: Annotate simple field-less enums representing constrained argument choices (e.g., `enum Format { Pcap, PcapNg }`).
- **Strict Attribute Namespaces**:
  - `#[command(...)]`: Applies strictly to container structs/enums or subcommand variants (`name`, `version`, `about`, `subcommand_required`, `arg_required_else_help`, `styles`).
  - `#[arg(...)]`: Applies strictly to field arguments on `Parser` or `Args` structs (`short`, `long`, `help`, `action`, `value_parser`, `value_hint`, `global`, `env`).
  - `#[group(...)]`: Applies strictly to container structs to configure an `ArgGroup` across nested fields.
  - `#[value(...)]`: Applies strictly to enum variants implementing `ValueEnum` (`#[value(name = "pcapng", alias = "pcap-ng")]`).
- **Magic Attributes vs. Raw Attributes**:
  - Magic attributes (`flatten`, `subcommand`, `default_value_t`, `default_values_t`, `default_value_os_t`, `value_parser`, `value_enum`, `action`, `verbatim_doc_comment`, `help_template`) trigger proc-macro code generation transformations.
  - Raw attributes map directly to builder methods on `Command` or `Arg` (`#[arg(global = true)]`, `#[arg(short = 'v')]`, `#[command(subcommand_required = true)]`).
- **Doc Comment Semantics**:
  - The first doc paragraph becomes `about` (with a single trailing period stripped automatically); subsequent paragraphs become `long_about` for `--help`. Use `verbatim_doc_comment` only when ASCII diagrams or exact trailing punctuation must be preserved.

## 3. Builder API, `ValueHint` & Mandatory `debug_assert()` QA
- **Extract `build_cli() -> Command` & Run `debug_assert()`**:
  - Always extract the root `Command` construction into a dedicated function `pub fn build_cli() -> Command` (or `Cli::command()` with Derive) rather than inlining `Command::new(...)` inside `fn main()`.
  - **MANDATORY QA GATE**: Every CLI crate MUST include a unit test calling `.debug_assert()`:
    ```rust
    #[test]
    fn verify_cli_invariants() {
        build_cli().debug_assert();
    }
    ```
    `debug_assert()` validates unique argument IDs, short/long flag collisions, valid `ArgGroup` / `requires` / `conflicts_with` targets, positional ordering, and `ValueParser` compatibility with `get_one::<T>()` at test time.
- **Zero-Allocation Identifiers & Shell Hints (`ValueHint`)**:
  - Pass static identifiers (`Command::new("frameassembly")`, `Arg::new("input")`) and annotate filesystem/network arguments with `clap::ValueHint` (`ValueHint::FilePath`, `ValueHint::DirPath`, `ValueHint::ExecutablePath`, `ValueHint::Hostname`, `ValueHint::Url`) for accurate shell completions and semantic metadata.
- **Top-Level Command Guardrails & `ArgMatches` Extraction**:
  - Enable `arg_required_else_help(true)` on commands requiring arguments, `subcommand_required(true)` on pure subcommand dispatchers, and `args_override_self(true)` when repeated flags should overwrite earlier values.
  - Query values type-safely via `matches.get_one::<T>("id")`, `matches.get_many::<T>("id")`, `matches.get_flag("id")`, `matches.get_count("id")`, or destructively move owned values via `matches.remove_one::<T>("id")` / `remove_many::<T>("id")` (zero `.clone()`).

## 4. Argument Actions, Groups & Constraint Modeling
- **Explicit `ArgAction` Taxonomy**:
  - `ArgAction::Set` (single value), `ArgAction::Append` (`Vec<T>`), `ArgAction::SetTrue` (boolean flag, defaults to `false`), `ArgAction::SetFalse` (defaults to `true`), `ArgAction::Count` (`u8` verbosity counter), `ArgAction::Help` / `HelpShort` / `HelpLong` / `Version`.
- **Negatable Flag Pairs (`--flag` / `--no-flag`)**:
  - Pair `Arg::new("cache").long("cache").action(ArgAction::SetTrue).overrides_with("no-cache")` with `Arg::new("no-cache").long("no-cache").action(ArgAction::SetTrue).overrides_with("cache")` and evaluate `!matches.get_flag("no-cache")`.
- **Declarative Constraints (`ArgGroup`, `conflicts_with`, `requires`)**:
  - Express mutual exclusivity (`ArgGroup::new("src").args([...]).multiple(false)`), one-of requirements (`.required(true)`), and conditional requirements (`requires`, `requires_if`, `requires_ifs`, `conflicts_with_all`) in the CLI definition so `clap` renders rich usage errors automatically.

## 5. Strongly-Typed Value Parsers (`TypedValueParser`) & `clap_lex`
- **Built-In `clap::builder` Value Parsers**:
  - `PathBufValueParser::new()` -> `PathBuf` (never parse file paths as `String` when `PathBuf` is needed).
  - `NonEmptyStringValueParser::new()` -> rejects `""` at parse time.
  - `RangedI64ValueParser::<T>::new().range(min..=max)` & `RangedU64ValueParser::<T>::new().range(min..=max)` -> bounded integer validation with range context.
  - `PossibleValuesParser::new(["pcap", "pcapng"])` (or static array `["pcap", "pcapng"]`) -> constrained string choices.
  - `BoolishValueParser::new()` (`true`/`false`/`yes`/`no`/`1`/`0`) & `FalseyValueParser::new()`.
- **Functional & Custom `TypedValueParser`**:
  - Adapt `FromStr` or custom validation closures via `StringValueParser::new().try_map(|s| s.parse::<IpAddr>())`.
  - Implement `TypedValueParser` (`fn parse_ref(&self, cmd: &Command, arg: Option<&Arg>, value: &OsStr) -> Result<Self::Value, clap::Error>`) when custom `ContextKind` hints or `possible_values()` introspection are required.
- **Low-Level Token Cursor (`clap_lex 1.1.1`)**:
  - When writing custom pre-parsers or external plugin wrappers, use `clap_lex::RawArgs::new(args)` with `ArgCursor` and `ParsedArg` (`to_long()`, `to_short()`, `is_escape()`, `is_stdio()`) instead of manual string splitting on `std::env::args_os()`.

## 6. Terminal Styling (`anstyle 1.0.14` & `anstream 1.0.0`)
- **Complete 9-Role `Styles` Palette**:
  - Configure all 9 `clap::builder::styling::Styles` roles—including `.context()` and `.context_value()` for `[default: ...]` and `[possible values: ...]` hints:
    ```rust
    use clap::builder::styling::{AnsiColor, Effects, Styles};

    pub const fn cli_styles() -> Styles {
        Styles::styled()
            .header(AnsiColor::Yellow.on_default().effects(Effects::BOLD))
            .usage(AnsiColor::Green.on_default().effects(Effects::BOLD))
            .literal(AnsiColor::Cyan.on_default().effects(Effects::BOLD))
            .placeholder(AnsiColor::Cyan.on_default())
            .error(AnsiColor::Red.on_default().effects(Effects::BOLD))
            .valid(AnsiColor::Green.on_default().effects(Effects::BOLD))
            .invalid(AnsiColor::Yellow.on_default().effects(Effects::BOLD))
            .context(AnsiColor::White.on_default().effects(Effects::DIMMED))
            .context_value(AnsiColor::Cyan.on_default().effects(Effects::ITALIC))
    }
    ```
- **Global Color Choice & Error Rendering**:
  - `clap` delegates TTY and `NO_COLOR`/`CLICOLOR`/`CLICOLOR_FORCE` detection to `anstream`. When exposing a `--color <auto|always|never>` flag, call `anstream::ColorChoice::Always.write_global()` (or `Never`) so downstream `miette` or logging formatters inherit the user's color preference.
  - In tests, inspect `err.render().to_string()` (plain text) or `err.render().ansi().to_string()` (ANSI styled).

## 7. Layered Configuration & The `ValueSource` Precedence Invariant
- **CRITICAL INVARIANT (`ValueSource::CommandLine` vs `DefaultValue`)**:
  - When an `Arg` defines `.default_value(...)`, calling `matches.get_one::<T>("id")` **always returns `Some(...)`** even when the user omitted the flag on the command line (`ValueSource::DefaultValue`).
  - If you check `if let Some(val) = matches.get_one::<T>("id")` before checking environment variables or config files, the default value silently shadows all lower configuration layers!
  - **Mandatory Rule**: Always check `matches.value_source("id") == Some(clap::parser::ValueSource::CommandLine)` before treating a matched value as an explicit CLI override:
    ```rust
    use clap::parser::ValueSource;

    let out_dir = if matches.value_source("out-dir") == Some(ValueSource::CommandLine) {
        matches.get_one::<PathBuf>("out-dir").cloned().unwrap()
    } else if let Ok(env_dir) = std::env::var("DAEMON_OUT_DIR") {
        PathBuf::from(env_dir)
    } else if let Some(cfg_dir) = file_cfg.out_dir {
        cfg_dir
    } else {
        matches.get_one::<PathBuf>("out-dir").cloned().unwrap() // DefaultValue fallback
    };
    ```

## 8. Anti-Patterns & Complete v2/v3 -> v4.6.7+ Migration Matrix

| Outdated / Anti-Pattern | Modern Idiom (`clap 4.6.7+`) | Technical Rationale & Invariant |
| :--- | :--- | :--- |
| Inlining `Command::new` in `main` without tests | Extract `pub fn build_cli() -> Command` + `build_cli().debug_assert()` | Catches duplicate IDs, invalid groups, and type mismatches in `cargo test` |
| Checking `get_one` on `.default_value` arg in layered config | Check `matches.value_source("id") == Some(ValueSource::CommandLine)` | Prevents `ValueSource::DefaultValue` from shadowing env vars and config files |
| Using `String` for file paths (`get_one::<String>`) | Use `PathBufValueParser::new()` + `ValueHint::FilePath` | Preserves non-UTF-8 OS paths (`PathBuf`) and enables shell file completion |
| Using `#[derive(Parser)]` without `derive` feature | Enable `features = ["derive"]` or implement `CommandFactory` + `FromArgMatches` | Default `clap` omits `clap_derive` to minimize compile times |
| `#[clap(...)]` / `App::new` / `SubCommand::with_name` | `#[command(...)]`, `#[arg(...)]`, `#[value(...)]` / `Command::new` | Strict attribute scope segregation and unified `Command` builder |
| `matches.value_of` / `values_of` / `is_present` | `get_one::<T>` / `get_many::<T>` / `get_flag` / `get_count` | Compile-time type safety without stringly-typed downcasting |
| Cloning large values out of `ArgMatches` | Use `matches.remove_one::<T>("id")` / `remove_many::<T>("id")` | Moves owned values out of `mut ArgMatches` with zero heap cloning |
| Manual string parsing and `process::exit(1)` in `main` | `TypedValueParser::try_map` + `cmd.error(...).exit()` | Formats rich `anstyle` errors with usage hints and standard exit code `2` |
