---
name: clap-cli
description: Comprehensive guide, API selection matrix, and production code templates for building modern, type-safe, and scalable command-line interfaces in Rust with clap 4.6+ (covering Derive and Builder APIs, deeply nested subcommands, anstyle terminal styling, TypedValueParser validation, and companion crates).
---

# Clap 4.6.7+ CLI Engineering Skill

Use this skill when designing, implementing, refactoring, or testing command-line interfaces using `clap` (`4.6.7+`), `clap_builder` (`4.6.7`), `clap_lex` (`1.1.1`), `anstyle` (`1.0.14`), and `anstream` (`1.0.0`) in Rust.

## 1. Quick API Selection Matrix

| CLI Goal | Idiomatic `clap 4.6.7+` API | Avoid (Legacy / Suboptimal) |
| :--- | :--- | :--- |
| Top-level CLI entry point (Derive) | `#[derive(Parser)]` (requires `features = ["derive"]`) | `structopt` / `#[clap(...)]` |
| Top-level CLI entry point (Builder) | `pub fn build_cli() -> Command` + `build_cli().debug_assert()` | Inlining `App::new` in `main()` without `debug_assert()` |
| Mutually exclusive subcommands | `#[derive(Subcommand)]` / `cmd.subcommand(...)` | `SubCommand::with_name(...)` |
| Reusable argument group composition | `#[command(flatten)]` / `Args::augment_args(cmd)` | Duplicating `Arg` definitions across commands |
| Propagate argument down all subcommands | `#[arg(global = true)]` / `arg.global(true)` | Manually re-declaring flags on every subcommand |
| Boolean flag (presence sets true) | `action = ArgAction::SetTrue` / `.action(ArgAction::SetTrue)` | `takes_value(false)` |
| Flag occurrence counter (`-v`, `-vv`) | `action = ArgAction::Count` / `matches.get_count("id")` | `matches.occurrences_of("id")` |
| Negatable flag pair (`--cache` / `--no-cache`) | Two `SetTrue` flags paired with `.overrides_with(...)` | Manual string parsing or boolean negation |
| Multi-value argument collection | `action = ArgAction::Append` / `matches.get_many::<T>()` | `arg.multiple(true)` / `matches.values_of()` |
| Constrain argument to fixed string set | `#[derive(ValueEnum)]` or `PossibleValuesParser::new(["a", "b"])` | `arg.possible_values(&["a", "b"])` |
| Non-empty string validation | `NonEmptyStringValueParser::new()` | Post-parse `if s.is_empty()` checks |
| Bounded integer validation | `RangedI64ValueParser::<T>::new().range(min..=max)` / `RangedU64ValueParser` | Post-parse manual bounds checking |
| Path argument & shell completion hint | `PathBufValueParser::new()` + `ValueHint::FilePath` / `DirPath` | Raw `String` parsing with manual `PathBuf::from` |
| Fallible string conversion | `StringValueParser::new().try_map(\|s\| ...)` | `arg.validator(...)` returning raw strings |
| Mutually exclusive argument group | `ArgGroup::new("grp").args([...]).multiple(false)` | Hand-rolled conflict validation in application logic |
| Conditional argument requirement | `arg.requires("other")` / `arg.requires_if("val", "other")` | Manual assertion checks after argument matching |
| Modern 9-role terminal styling | `Styles::styled().header(...).context(...).context_value(...)` | Hardcoded ANSI escape sequences |
| Global color override propagation | `anstream::ColorChoice::Always.write_global()` | Custom global booleans ignored by `miette` / `anstream` |
| Layered config with `.default_value(...)` | Check `matches.value_source("id") == Some(ValueSource::CommandLine)` | `if let Some(v) = matches.get_one(...)` (shadows env/file!) |
| Destructive argument extraction | `matches.remove_one::<T>("id")` / `remove_many::<T>("id")` | Cloning values out of `matches.get_one::<T>()` |
| Low-level OS argument token cursor | `clap_lex::RawArgs::new(args)` + `ArgCursor` | Manual splitting on `std::env::args_os()` |
| Standardized usage error exit & testing | `cmd.error(ErrorKind::InvalidValue, ...).exit()` / `err.render().ansi()` | Calling `eprintln!` followed by `std::process::exit(1)` |

---

## 2. Workspace Feature Boundary Matrix (`clap 4.6.7`)

Before choosing between Builder and Derive patterns in a crate, check `Cargo.toml`:

| Feature / Capability | Default `clap = "4.6.7"` | Optional Feature Flag Required |
| :--- | :--- | :--- |
| `Command`, `Arg`, `ArgGroup`, `ArgAction`, `ArgMatches` | Included (`std`, `color`, `help`, `usage`, `error-context`, `suggestions`) | None |
| `ValueSource`, `ValueHint`, `TypedValueParser`, `Styles` | Included | None |
| Trait definitions (`Parser`, `Subcommand`, `Args`, `ValueEnum`, `CommandFactory`, `FromArgMatches`) | Included | None (manual impls work without `derive`) |
| `#[derive(Parser, Subcommand, Args, ValueEnum)]` | **Not enabled** | `features = ["derive"]` |
| `crate_version!()`, `command!()` macros | **Not enabled** (use `env!("CARGO_PKG_VERSION")`) | `features = ["cargo"]` |
| `Arg::env("VAR")` / `#[arg(env = "VAR")]` | **Not enabled** (use `ValueSource` + `std::env::var`) | `features = ["env"]` |
| Dynamic `String` arg names/help (`Str::from(String)`) | **Not enabled** (use `&'static str`) | `features = ["string"]` |
| Dynamic terminal-width help wrapping | **Not enabled** | `features = ["wrap_help"]` |

---

## 3. Architecture Decision Guide

1. **Derive vs. Builder vs. Trait-Based Hybrid**:
   - **Declarative Derive (`#[derive(Parser, Subcommand, Args, ValueEnum)]`)**: Best when `features = ["derive"]` is enabled. Structs reflect CLI grammar directly, type conversions are inferred from field types, and doc comments map to `--help` text automatically.
   - **Imperative Builder (`Command`, `Arg`, `ArgGroup`)**: Best for zero-proc-macro builds (like `frameassembly`'s default dependency graph), dynamic runtime plugin CLIs, or minimal compile-time profiles. Always pair `PathBufValueParser::new()` with `ValueHint::FilePath` so paths are parsed directly as `PathBuf` rather than `String`.
   - **Trait-Based Hybrid (`CommandFactory` + `FromArgMatches` + `Parser` + `Args`)**: Implement `CommandFactory` and `FromArgMatches` manually (with `impl Parser for Cli {}`) to enjoy strongly-typed struct parsing (`Cli::parse()`, `Cli::try_parse_from(...)`) without pulling in `clap_derive`.

2. **Mandatory CLI Verification Gate (`Command::debug_assert()`)**:
   - Always factor `Command` construction out of `fn main()` into `pub fn build_cli() -> Command` (or `Cli::command()`).
   - Add a unit test `#[test] fn verify_cli() { build_cli().debug_assert(); }` to catch duplicate argument IDs, conflicting short/long flags, dangling `ArgGroup` / `requires` / `conflicts_with` references, and `ValueParser` type mismatches during `cargo test`.

3. **Layered Configuration Resolution & The `ValueSource` Invariant**:
   - Production CLIs resolve options through an explicit four-tier precedence hierarchy:
     $$\text{CLI Argument Flag (`ValueSource::CommandLine`)} > \text{Environment Variable (`ValueSource::EnvVariable`)} > \text{Configuration File} > \text{Static Default (`ValueSource::DefaultValue`)}$$
   - **Critical Pitfall**: If an `Arg` has `.default_value("...")`, `matches.get_one::<T>("id")` *always* returns `Some(...)`. Checking `if let Some(v) = matches.get_one("id")` without checking `matches.value_source("id") == Some(ValueSource::CommandLine)` causes the default value to override environment variables and config files! Always inspect `matches.value_source("id")` first.

4. **Terminal UX & Styling (`anstyle 1.0.14` & `anstream 1.0.0`)**:
   - Configure all 9 `clap::builder::styling::Styles` roles using `const fn`:
     - `.header(...)`, `.usage(...)`, `.literal(...)`, `.placeholder(...)`, `.error(...)`, `.valid(...)`, `.invalid(...)`, `.context(...)`, and `.context_value(...)`.
   - `clap` delegates TTY and `NO_COLOR` / `CLICOLOR` / `CLICOLOR_FORCE` detection to `anstream`. When providing a `--color <auto|always|never>` flag, call `anstream::ColorChoice::write_global(...)` so downstream `miette` diagnostics and terminal loggers share the exact same color state.

---

## 4. Production Reference Templates

Read [references/patterns.md](references/patterns.md) for complete, copy-pasteable production implementations with complete rustdoc comments:
1. **Multi-Subcommand Enterprise CLI Architecture (`anstyle` 9-Role Styling + `ValueHint` + Global Flags + `debug_assert()` QA)**
2. **Custom Strongly-Typed Value Validation (`TypedValueParser` + `.try_map()` + `NonEmptyStringValueParser` + Rich `clap::Error` Diagnostics)**
3. **Advanced Argument Relationships & Flag Constraints (`ArgGroup` + Negatable Flags + `requires_if` + `conflicts_with`)**
4. **Trait-Based Derive/Builder Interoperability (`CommandFactory` + `FromArgMatches` + `Args` + `Parser` Implementation)**
5. **Layered Configuration Resolution (`ValueSource::CommandLine` Precedence + `anstream::ColorChoice` + `clap_lex` Pre-Inspection + Exit Codes)**
