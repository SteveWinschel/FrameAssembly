# Clap 4.6.7+ Production Reference Patterns

## 1. FrameAssembly v2.0.0 Default-Compile + 4-Subcommand CLI (`<input.fasm> [output.pcap]` + `show`, `reverse`, `version`, `help` + Optional 2nd Positional Output + Hidden `--help`/`--version` + Legacy/Safety Guards + `debug_assert()`)

In FrameAssembly v2.0.0 (`src/main.rs`), compiling `.fasm` to `.pcap` is the default root command (`frameassembly <input.fasm> [output.pcap]`) configured with `.subcommand_negates_reqs(true)`, `.args_conflicts_with_subcommands(true)`, and `.arg_required_else_help(true)` alongside 4 subcommands (`show <input.fasm>`, `reverse <input.pcap> [output.fasm]`, `version`, and `help [subcommand]`). It replaces legacy `-o`/`--output` flags with an optional 2nd positional output path (`derive_default_output_path`), hides `-h`/`--help` and `-V`/`--version` via `.disable_help_flag(true)` / `.disable_version_flag(true)` paired with hidden `ArgAction::Help` / `ArgAction::Version` so scripts still exit `0`, intercepts legacy flags and accidental typos (`check_legacy_cli_args`), pairs with static extension-aware shell completions in `contrib/completions/` (`bash`, `zsh`, `fish`, `powershell`), and verifies invariants via `build_cli().debug_assert()`:

```rust
//! FrameAssembly v2.0.0 default-compile + 4-subcommand CLI architecture (`show`, `reverse`, `version`, `help`)
//! with optional 2nd positional output derivation, hidden script-compatible `--help`/`--version`,
//! pre-match legacy and typo safety guards, 9-role `anstyle` styling, and `debug_assert()` QA in `clap` 4.6.7+.

use clap::builder::PathBufValueParser;
use clap::builder::styling::{AnsiColor, Effects, Styles};
use clap::{Arg, ArgAction, ArgMatches, Command, ValueHint};
use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};

/// Nine-role `anstyle 1.0.14` terminal color palette used by `clap` help and usage diagnostics.
pub const CLI_STYLES: Styles = Styles::styled()
    .header(AnsiColor::Green.on_default().effects(Effects::BOLD))
    .usage(AnsiColor::Green.on_default().effects(Effects::BOLD))
    .literal(AnsiColor::Cyan.on_default().effects(Effects::BOLD))
    .placeholder(AnsiColor::Cyan.on_default())
    .error(AnsiColor::Red.on_default().effects(Effects::BOLD))
    .valid(AnsiColor::Green.on_default().effects(Effects::BOLD))
    .invalid(AnsiColor::Yellow.on_default().effects(Effects::BOLD))
    .context(AnsiColor::BrightBlack.on_default())
    .context_value(AnsiColor::Cyan.on_default());

/// Canonical top-level subcommands exposed by FrameAssembly 2.0 (compilation is the root default).
pub const SUBCOMMANDS: [&str; 4] = ["show", "reverse", "version", "help"];

/// Strongly-typed parameters for default root invocation `frameassembly <input.fasm> [output.pcap]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompileArgs {
    /// Input `.fasm` file path (`index(1)`).
    pub input_file: PathBuf,
    /// Resolved output `.pcap`/`.pcapng` path (`index(2)` or derived `<input_stem>.pcap`).
    pub output_file: PathBuf,
}

/// Strongly-typed parameters for `frameassembly show <input.fasm>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShowArgs {
    /// Input `.fasm` file path (`index(1)`) to validate and render as a packet ladder.
    pub input_file: PathBuf,
}

/// Strongly-typed parameters for `frameassembly reverse <input.pcap> [output.fasm]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReverseArgs {
    /// Input `.pcap` or `.pcapng` capture path (`index(1)`).
    pub input_pcap: PathBuf,
    /// Resolved output `.fasm` file path (`index(2)` or derived `<input_stem>.fasm`).
    pub output_fasm: PathBuf,
}

/// Discriminated CLI operations across FrameAssembly 2.0 root compile and subcommands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CliCommand {
    /// Compile `.fasm` code into a `.pcap`/`.pcapng` capture (default root command).
    Compile(CompileArgs),
    /// Validate `.fasm` code and print a packet ladder table without writing disk files.
    Show(ShowArgs),
    /// Reverse a `.pcap` / `.pcapng` capture into `.fasm` code.
    Reverse(ReverseArgs),
    /// Print `frameassembly <CARGO_PKG_VERSION>`.
    Version,
}

/// Derives the default output path from `input` by replacing its extension with `default_ext`,
/// or appending `.default_ext` when `input` already ends with `default_ext` so input is never overwritten.
pub fn derive_default_output_path(input: &Path, default_ext: &str) -> PathBuf {
    let has_same_ext = input
        .extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| e.eq_ignore_ascii_case(default_ext));
    if has_same_ext {
        let mut os = input.as_os_str().to_os_string();
        os.push(".");
        os.push(default_ext);
        PathBuf::from(os)
    } else {
        let candidate = input.with_extension(default_ext);
        if candidate == input {
            let mut os = input.as_os_str().to_os_string();
            os.push(".");
            os.push(default_ext);
            PathBuf::from(os)
        } else {
            candidate
        }
    }
}

/// Checks raw CLI arguments for legacy invocation flags (`-o`/`--output`, `--show`, `--reverse`),
/// bare `.pcap`/`.pcapng` captures at arg 1, accidental `"compile"` at arg 1, or `.fasm` passed as
/// `OUTPUT.pcap`, returning an actionable error hint.
pub fn check_legacy_cli_args<I, T>(args: I) -> Result<(), String>
where
    I: IntoIterator<Item = T>,
    T: AsRef<OsStr>,
{
    let collected: Vec<OsString> = args
        .into_iter()
        .map(|a| a.as_ref().to_os_string())
        .collect();
    if collected.len() <= 1 {
        return Ok(());
    }

    for arg in &collected[1..] {
        let s = arg.to_string_lossy();
        if s == "--" {
            break;
        }
        if s == "-o"
            || s == "--output"
            || s.starts_with("--output=")
            || (s.starts_with("-o") && s.len() > 2 && !s.starts_with("--"))
        {
            return Err(
                "The '-o' / '--output' flag was replaced by an optional second positional path in FrameAssembly 2.0.\n  Compile: frameassembly <in.fasm> [out.pcap]\n  Reverse: frameassembly reverse <in.pcap> [out.fasm]"
                    .to_string(),
            );
        }
        if s == "--show" {
            return Err(
                "The '--show' flag was replaced by the 'show' subcommand in FrameAssembly 2.0:\n  frameassembly show <in.fasm>"
                    .to_string(),
            );
        }
        if s == "--reverse" {
            return Err(
                "The '--reverse' flag was replaced by the 'reverse' subcommand in FrameAssembly 2.0:\n  frameassembly reverse <in.pcap> [out.fasm]"
                    .to_string(),
            );
        }
    }

    let arg1 = collected[1].to_string_lossy();
    if arg1 == "compile" && !Path::new("compile").is_file() {
        return Err(
            "Compiling is the default command in FrameAssembly 2.0 (there is no 'compile' subcommand); run:\n  frameassembly <in.fasm> [out.pcap]"
                .to_string(),
        );
    }

    if !arg1.starts_with('-') && !SUBCOMMANDS.contains(&arg1.as_ref()) {
        let lower = arg1.to_ascii_lowercase();
        if lower.ends_with(".pcap") || lower.ends_with(".pcapng") {
            return Err(format!(
                "Direct capture invocation is not supported; use the 'reverse' subcommand instead:\n  frameassembly reverse {arg1}"
            ));
        }
        if let Some(arg2) = collected.get(2) {
            let s2 = arg2.to_string_lossy();
            if !s2.starts_with('-') && s2.to_ascii_lowercase().ends_with(".fasm") {
                return Err(format!(
                    "Refusing to write PCAP capture bytes to a '.fasm' source path ('{s2}'); specify a '.pcap' or '.pcapng' output path:\n  frameassembly {arg1} <out.pcap>"
                ));
            }
        }
    }

    Ok(())
}

/// Constructs the `clap::Command` definition for FrameAssembly 2.0 (default root compile + `show`, `reverse`, `version`, `help`).
pub fn build_cli() -> Command {
    Command::new("frameassembly")
        .version(env!("CARGO_PKG_VERSION"))
        .about("Compile .fasm network traffic code to .pcap/.pcapng and reverse captures back to .fasm")
        .after_help("Feedback & protocol requests: https://github.com/SteveWinschel/FrameAssembly/issues")
        .styles(CLI_STYLES)
        .subcommand_negates_reqs(true)
        .args_conflicts_with_subcommands(true)
        .arg_required_else_help(true)
        .disable_help_flag(true)
        .disable_version_flag(true)
        .arg(
            Arg::new("help")
                .short('h')
                .long("help")
                .action(ArgAction::Help)
                .global(true)
                .hide(true),
        )
        .arg(
            Arg::new("version")
                .short('V')
                .long("version")
                .action(ArgAction::Version)
                .hide(true),
        )
        .arg(
            Arg::new("input")
                .value_name("INPUT.fasm")
                .help("Path to the input .fasm file")
                .required(true)
                .index(1)
                .value_hint(ValueHint::FilePath)
                .value_parser(PathBufValueParser::new()),
        )
        .arg(
            Arg::new("output")
                .value_name("OUTPUT.pcap")
                .help("Optional output .pcap/.pcapng path (defaults to <input_stem>.pcap)")
                .index(2)
                .value_hint(ValueHint::FilePath)
                .value_parser(PathBufValueParser::new()),
        )
        .subcommand(
            Command::new("show")
                .about("Validate a .fasm file and print a packet ladder table without writing a capture file")
                .disable_help_flag(true)
                .arg(
                    Arg::new("input")
                        .value_name("INPUT.fasm")
                        .help("Path to the input .fasm file")
                        .required(true)
                        .index(1)
                        .value_hint(ValueHint::FilePath)
                        .value_parser(PathBufValueParser::new()),
                ),
        )
        .subcommand(
            Command::new("reverse")
                .about("Reverse a .pcap or .pcapng capture file into .fasm code")
                .disable_help_flag(true)
                .arg(
                    Arg::new("input")
                        .value_name("INPUT.pcap")
                        .help("Path to the input .pcap or .pcapng capture file")
                        .required(true)
                        .index(1)
                        .value_hint(ValueHint::FilePath)
                        .value_parser(PathBufValueParser::new()),
                )
                .arg(
                    Arg::new("output")
                        .value_name("OUTPUT.fasm")
                        .help("Optional output .fasm path (defaults to <input_stem>.fasm)")
                        .index(2)
                        .value_hint(ValueHint::FilePath)
                        .value_parser(PathBufValueParser::new()),
                ),
        )
        .subcommand(
            Command::new("version")
                .about("Print the FrameAssembly version")
                .disable_help_flag(true),
        )
}

/// Extracts a strongly-typed `CliCommand` from validated `ArgMatches`.
pub fn parse_command(matches: &ArgMatches) -> CliCommand {
    match matches.subcommand() {
        Some(("show", sub_m)) => {
            let input_file = sub_m
                .get_one::<PathBuf>("input")
                .cloned()
                .expect("input is required for show");
            CliCommand::Show(ShowArgs { input_file })
        }
        Some(("reverse", sub_m)) => {
            let input_pcap = sub_m
                .get_one::<PathBuf>("input")
                .cloned()
                .expect("input is required for reverse");
            let output_fasm = sub_m
                .get_one::<PathBuf>("output")
                .cloned()
                .unwrap_or_else(|| derive_default_output_path(&input_pcap, "fasm"));
            CliCommand::Reverse(ReverseArgs {
                input_pcap,
                output_fasm,
            })
        }
        Some(("version", _)) => CliCommand::Version,
        None => {
            let input_file = matches
                .get_one::<PathBuf>("input")
                .cloned()
                .expect("root input is required when no subcommand is matched");
            let output_file = matches
                .get_one::<PathBuf>("output")
                .cloned()
                .unwrap_or_else(|| derive_default_output_path(&input_file, "pcap"));
            CliCommand::Compile(CompileArgs {
                input_file,
                output_file,
            })
        }
        Some((other, _)) => unreachable!("unexpected subcommand: {other}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Mandatory clap QA gate verifying all Command/Arg invariants and hidden script flags.
    #[test]
    fn verify_cli_invariants() {
        let cmd = build_cli();
        assert!(cmd.get_overridden_usage().is_none());
        cmd.debug_assert();
    }

    /// Verifies root default compilation and rejection of legacy flags and accidental typos.
    #[test]
    fn verify_default_compile_and_legacy_guards() {
        let matches = build_cli()
            .try_get_matches_from(["frameassembly", "demo.fasm"])
            .expect("default root compile should parse");
        assert_eq!(
            parse_command(&matches),
            CliCommand::Compile(CompileArgs {
                input_file: PathBuf::from("demo.fasm"),
                output_file: PathBuf::from("demo.pcap"),
            })
        );
        assert!(check_legacy_cli_args(["frameassembly", "compile", "demo.fasm"]).is_err());
        assert!(check_legacy_cli_args(["frameassembly", "a.fasm", "b.fasm"]).is_err());
        assert!(check_legacy_cli_args(["frameassembly", "capture.pcap"]).is_err());
    }
}
```

---

## 2. Custom Strongly-Typed Value Validation (`TypedValueParser` + `.try_map()` + Rich Diagnostics)

Avoid post-match validation by implementing `TypedValueParser` or applying `.try_map()` directly on `StringValueParser`. Errors emit structured `clap::Error` instances with usage and command context:

```rust
//! Custom strongly-typed value validation using `TypedValueParser`, `.try_map()`,
//! and rich `clap::Error` diagnostics in `clap` 4.6+.

use clap::builder::{StringValueParser, TypedValueParser};
use clap::error::{Error, ErrorKind};
use clap::{Arg, Command};
use std::ffi::OsStr;
use std::net::IpAddr;
use std::ops::RangeInclusive;
use std::str::FromStr;

/// Parsed IP network prefix combining an IP address and a CIDR subnet mask.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CidrPrefix {
    /// Base IP address (IPv4 or IPv6).
    pub ip: IpAddr,
    /// Prefix length in bits (0..=32 for IPv4, 0..=128 for IPv6).
    pub prefix_len: u8,
}

impl FromStr for CidrPrefix {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (ip_str, len_str) = s
            .split_once('/')
            .ok_or_else(|| format!("missing CIDR slash delimiter in `{s}`; expected format IP/LEN"))?;

        let ip = ip_str
            .parse::<IpAddr>()
            .map_err(|e| format!("invalid IP address `{ip_str}`: {e}"))?;

        let prefix_len = len_str
            .parse::<u8>()
            .map_err(|e| format!("invalid prefix length `{len_str}`: {e}"))?;

        let max_len = if ip.is_ipv4() { 32 } else { 128 };
        if prefix_len > max_len {
            return Err(format!(
                "prefix length {prefix_len} exceeds maximum {max_len} for {}",
                if ip.is_ipv4() { "IPv4" } else { "IPv6" }
            ));
        }

        Ok(Self { ip, prefix_len })
    }
}

/// Creates a `TypedValueParser` that validates CIDR network prefix notation via `.try_map()`.
pub fn cidr_value_parser() -> impl TypedValueParser<Value = CidrPrefix> {
    StringValueParser::new().try_map(|val: String| val.parse::<CidrPrefix>())
}

/// Parsed port specification supporting either a single port or a port range.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PortTarget {
    /// Single TCP/UDP port number.
    Single(u16),
    /// Inclusive range of TCP/UDP ports.
    Range(RangeInclusive<u16>),
}

/// Custom `TypedValueParser` that parses and bounds-checks network port specifications.
#[derive(Debug, Clone, Copy, Default)]
pub struct PortRangeParser;

impl PortRangeParser {
    /// Creates a new `PortRangeParser` instance.
    pub const fn new() -> Self {
        Self
    }
}

impl TypedValueParser for PortRangeParser {
    type Value = PortTarget;

    fn parse_ref(
        &self,
        cmd: &Command,
        arg: Option<&Arg>,
        value: &OsStr,
    ) -> Result<Self::Value, Error> {
        let val_str = value.to_str().ok_or_else(|| {
            cmd.clone().error(
                ErrorKind::InvalidUtf8,
                format!(
                    "argument `{}` contains non-UTF-8 characters",
                    arg.map(|a| a.get_id().as_str()).unwrap_or("port")
                ),
            )
        })?;

        if let Some((start_str, end_str)) = val_str.split_once('-') {
            let start = start_str.parse::<u16>().map_err(|_| {
                cmd.clone().error(
                    ErrorKind::InvalidValue,
                    format!("invalid start port `{start_str}` in range `{val_str}`: must be 1..=65535"),
                )
            })?;
            let end = end_str.parse::<u16>().map_err(|_| {
                cmd.clone().error(
                    ErrorKind::InvalidValue,
                    format!("invalid end port `{end_str}` in range `{val_str}`: must be 1..=65535"),
                )
            })?;

            if start == 0 || end == 0 {
                return Err(cmd.clone().error(
                    ErrorKind::InvalidValue,
                    format!("port numbers must be non-zero in `{val_str}`"),
                ));
            }

            if start > end {
                return Err(cmd.clone().error(
                    ErrorKind::InvalidValue,
                    format!("start port {start} cannot exceed end port {end} in range `{val_str}`"),
                ));
            }

            Ok(PortTarget::Range(start..=end))
        } else {
            let port = val_str.parse::<u16>().map_err(|_| {
                cmd.clone().error(
                    ErrorKind::InvalidValue,
                    format!("invalid port number `{val_str}`: must be 1..=65535"),
                )
            })?;

            if port == 0 {
                return Err(cmd.clone().error(
                    ErrorKind::InvalidValue,
                    format!("port number must be non-zero; got `{val_str}`"),
                ));
            }

            Ok(PortTarget::Single(port))
        }
    }
}

/// Constructs a network filter CLI command demonstrating custom value parsers.
pub fn build_filter_cli() -> Command {
    Command::new("netfilter")
        .version("1.0.0")
        .about("Packet capture filter generator with typed value validation")
        .arg(
            Arg::new("cidr")
                .short('c')
                .long("cidr")
                .help("Subnet prefix in CIDR notation (e.g. 10.0.0.0/8 or 2001:db8::/32)")
                .value_name("CIDR")
                .value_parser(cidr_value_parser())
                .required(true),
        )
        .arg(
            Arg::new("ports")
                .short('p')
                .long("ports")
                .help("Target port or range (e.g. 80 or 8000-8080)")
                .value_name("PORT[-PORT]")
                .value_parser(PortRangeParser::new())
                .required(true),
        )
}
```

---

## 3. Advanced Argument Relationships & Flag Constraints (`ArgGroup` + Negatable Flags + `requires`)

Model complex business rules, mutually exclusive arguments, and negatable flag overrides cleanly with `ArgGroup`, `conflicts_with`, and `requires`:

```rust
//! Advanced argument relationships, mutually exclusive groups, negatable flags,
//! and conditional requirements using `clap` 4.6+.

use clap::{Arg, ArgAction, ArgGroup, ArgMatches, Command};

/// Authentication configuration parsed from mutually exclusive or conditionally required flags.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthConfig {
    /// Username when username/password authentication is active.
    pub username: Option<String>,
    /// Password when username/password authentication is active.
    pub password: Option<String>,
    /// Token string when token authentication is active.
    pub token: Option<String>,
}

/// Capture target selection mode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TargetSelection {
    /// Capture all available network interfaces.
    All,
    /// Capture interfaces matching a specific filter expression.
    Filter(String),
    /// Explicit list of interface identifiers.
    Explicit(Vec<String>),
}

/// Resolved runtime configuration reflecting flag overrides and groups.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EngineConfig {
    /// Caching enabled state (true unless `--no-cache` was specified last).
    pub cache_enabled: bool,
    /// Interface selection strategy.
    pub selection: TargetSelection,
    /// Authentication credentials if specified.
    pub auth: Option<AuthConfig>,
}

/// Builds a CLI command with mutually exclusive groups and negatable flags.
pub fn build_engine_cli() -> Command {
    Command::new("packet-engine")
        .version("1.0.0")
        .about("High-throughput packet generator with complex argument constraints")
        // Pair negatable flags: --cache (SetTrue) and --no-cache (SetFalse)
        .arg(
            Arg::new("cache")
                .long("cache")
                .help("Enable packet descriptor caching (default)")
                .action(ArgAction::SetTrue)
                .overrides_with("no-cache"),
        )
        .arg(
            Arg::new("no-cache")
                .long("no-cache")
                .help("Disable packet descriptor caching")
                .action(ArgAction::SetTrue)
                .overrides_with("cache"),
        )
        // Interface selection group: exactly one of --all, --filter, or --interface
        .arg(
            Arg::new("all")
                .long("all")
                .help("Capture across all active network interfaces")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("filter")
                .long("filter")
                .help("Capture interfaces matching a regex or glob filter")
                .value_name("PATTERN"),
        )
        .arg(
            Arg::new("interface")
                .short('i')
                .long("interface")
                .help("Explicit interface to capture (may be specified multiple times)")
                .value_name("IFACE")
                .action(ArgAction::Append),
        )
        .group(
            ArgGroup::new("target_selection")
                .args(["all", "filter", "interface"])
                .required(true)
                .multiple(false),
        )
        // Authentication requirements: token vs (username + password)
        .arg(
            Arg::new("token")
                .long("token")
                .help("Bearer authentication token")
                .value_name("TOKEN")
                .conflicts_with_all(["username", "password"]),
        )
        .arg(
            Arg::new("username")
                .long("username")
                .help("Authentication username")
                .value_name("USER")
                .requires("password"),
        )
        .arg(
            Arg::new("password")
                .long("password")
                .help("Authentication password")
                .value_name("PASS")
                .requires("username"),
        )
}

/// Extracts strongly-typed `EngineConfig` from validated argument matches.
pub fn parse_engine_config(matches: &ArgMatches) -> EngineConfig {
    // Negatable flag evaluation: default is cache enabled (true) unless --no-cache was given
    let cache_enabled = !matches.get_flag("no-cache");

    let selection = if matches.get_flag("all") {
        TargetSelection::All
    } else if let Some(pattern) = matches.get_one::<String>("filter") {
        TargetSelection::Filter(pattern.clone())
    } else if let Some(ifaces) = matches.get_many::<String>("interface") {
        TargetSelection::Explicit(ifaces.cloned().collect())
    } else {
        unreachable!("ArgGroup target_selection guarantees one branch matches");
    };

    let auth = if let Some(token) = matches.get_one::<String>("token") {
        Some(AuthConfig {
            username: None,
            password: None,
            token: Some(token.clone()),
        })
    } else if let Some(username) = matches.get_one::<String>("username") {
        let password = matches.get_one::<String>("password").cloned();
        Some(AuthConfig {
            username: Some(username.clone()),
            password,
            token: None,
        })
    } else {
        None
    };

    EngineConfig {
        cache_enabled,
        selection,
        auth,
    }
}
```

---

## 4. Trait-Based Derive & Builder Interoperability (`CommandFactory` + `FromArgMatches` + `Parser`)

Understand what `clap_derive` generates under the hood and bridge dynamic `Command` definitions with type-safe struct extraction by implementing `CommandFactory`, `FromArgMatches`, and `Parser` traits:

```rust
//! Trait-based interoperability implementing `CommandFactory`, `FromArgMatches`,
//! `Args`, and `Parser` in `clap` 4.6+.

use clap::builder::{PathBufValueParser, RangedI64ValueParser};
use clap::{Arg, ArgAction, ArgMatches, Args, Command, CommandFactory, Error, FromArgMatches, Parser};
use std::path::PathBuf;

/// Reusable logging options bundle modeled after the `Args` trait.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogOptions {
    /// Incremental verbosity level.
    pub verbose: u8,
    /// Quiet flag to silence console logs.
    pub quiet: bool,
}

impl Args for LogOptions {
    fn augment_args(cmd: Command) -> Command {
        cmd.arg(
            Arg::new("verbose")
                .short('v')
                .long("verbose")
                .help("Increase diagnostic verbosity")
                .action(ArgAction::Count),
        )
        .arg(
            Arg::new("quiet")
                .short('q')
                .long("quiet")
                .help("Suppress console output")
                .action(ArgAction::SetTrue)
                .conflicts_with("verbose"),
        )
    }

    fn augment_args_for_update(cmd: Command) -> Command {
        Self::augment_args(cmd)
    }
}

impl FromArgMatches for LogOptions {
    fn from_arg_matches(matches: &ArgMatches) -> Result<Self, Error> {
        let verbose = matches.get_count("verbose");
        let quiet = matches.get_flag("quiet");
        Ok(Self { verbose, quiet })
    }

    fn update_from_arg_matches(&mut self, matches: &ArgMatches) -> Result<(), Error> {
        self.verbose = matches.get_count("verbose");
        self.quiet = matches.get_flag("quiet");
        Ok(())
    }
}

/// Primary application options combining sub-structures and command traits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppConfig {
    /// Reusable logging options flattened into the application command.
    pub logging: LogOptions,
    /// Target trace capture path.
    pub output_path: PathBuf,
    /// Maximum allowable frame count.
    pub frame_limit: i64,
}

impl CommandFactory for AppConfig {
    fn command() -> Command {
        let cmd = Command::new("packet-crafter")
            .version("2.0.0")
            .about("Type-safe network traffic synthesizer")
            .arg(
                Arg::new("output")
                    .short('o')
                    .long("output")
                    .help("Destination PCAP file path")
                    .value_name("PATH")
                    .default_value("capture.pcap")
                    .value_parser(PathBufValueParser::new()),
            )
            .arg(
                Arg::new("limit")
                    .short('l')
                    .long("limit")
                    .help("Maximum frame count limit (1..=1000000)")
                    .value_name("COUNT")
                    .default_value("1000")
                    .value_parser(RangedI64ValueParser::<i64>::new().range(1..=1_000_000)),
            );

        // Flatten reusable arguments into the command builder
        LogOptions::augment_args(cmd)
    }

    fn command_for_update() -> Command {
        Self::command()
    }
}

impl FromArgMatches for AppConfig {
    fn from_arg_matches(matches: &ArgMatches) -> Result<Self, Error> {
        let logging = LogOptions::from_arg_matches(matches)?;
        let output_path = matches
            .get_one::<PathBuf>("output")
            .cloned()
            .expect("output has default value");
        let frame_limit = *matches
            .get_one::<i64>("limit")
            .expect("limit has default value");

        Ok(Self {
            logging,
            output_path,
            frame_limit,
        })
    }

    fn update_from_arg_matches(&mut self, matches: &ArgMatches) -> Result<(), Error> {
        self.logging.update_from_arg_matches(matches)?;
        if let Some(out) = matches.get_one::<PathBuf>("output") {
            self.output_path = out.clone();
        }
        if let Some(&lim) = matches.get_one::<i64>("limit") {
            self.frame_limit = lim;
        }
        Ok(())
    }
}

// Blanket implementation of `Parser` enables parse(), try_parse(), and parse_from()
impl Parser for AppConfig {}

/// Demonstrates parsing from an argument iterator using the `Parser` trait.
///
/// # Errors
/// Returns `clap::Error` if arguments fail parsing or bounds validation.
pub fn parse_app_args<I, T>(args: I) -> Result<AppConfig, Error>
where
    I: IntoIterator<Item = T>,
    T: Into<std::ffi::OsString> + Clone,
{
    AppConfig::try_parse_from(args)
}
```

---

## 5. Layered Configuration Resolution (`ValueSource::CommandLine` Precedence + `anstream::ColorChoice` + `clap_lex`)

Implement an enterprise-grade four-tier configuration resolution hierarchy (`ValueSource::CommandLine` > Environment Variable > Config File > `ValueSource::DefaultValue`) paired with `anstream::ColorChoice` global synchronization, `clap_lex` pre-inspection, and standardized exit code mapping:

```rust
//! Layered configuration resolution and production CLI lifecycle in `clap` 4.6.7+.
//!
//! Demonstrates hierarchical precedence: CLI Flag (`ValueSource::CommandLine`) >
//! Environment Variable > Configuration File Fallback > Default Value (`ValueSource::DefaultValue`),
//! avoiding the classic bug where `.default_value(...)` shadows lower configuration layers.

use clap::builder::{NonEmptyStringValueParser, PathBufValueParser, PossibleValuesParser};
use clap::error::{ContextKind, ContextValue, Error, ErrorKind};
use clap::parser::ValueSource;
use clap::{Arg, ArgAction, ArgMatches, Command, ValueHint};
use std::collections::HashMap;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};

/// Application configuration resolved across multiple configuration layers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedConfig {
    /// Server listen address.
    pub host: String,
    /// Server port number.
    pub port: u16,
    /// Destination output directory.
    pub output_dir: PathBuf,
    /// Whether dry-run mode is enabled.
    pub dry_run: bool,
}

/// Simulated file-based configuration settings.
#[derive(Debug, Clone, Default)]
pub struct FileConfig {
    /// In-memory key-value dictionary representing parsed configuration entries.
    pub settings: HashMap<String, String>,
}

impl FileConfig {
    /// Simulates loading configuration from a file path.
    ///
    /// # Errors
    /// Returns an error message if the file path is nonexistent or invalid.
    pub fn load_from_path(path: &Path) -> Result<Self, String> {
        if !path.exists() {
            return Err(format!("configuration file `{}` does not exist", path.display()));
        }
        let mut settings = HashMap::new();
        settings.insert("host".to_string(), "127.0.0.1".to_string());
        settings.insert("port".to_string(), "8080".to_string());
        settings.insert("out_dir".to_string(), "/var/lib/daemon/output".to_string());
        Ok(Self { settings })
    }
}

/// Builds the CLI command definition.
pub fn build_layered_cli() -> Command {
    Command::new("daemon-runner")
        .version("1.0.0")
        .about("Layered configuration service with CLI, Env, and File resolution")
        .arg(
            Arg::new("color")
                .long("color")
                .help("Control terminal ANSI color output")
                .value_name("WHEN")
                .default_value("auto")
                .value_parser(PossibleValuesParser::new(["auto", "always", "never"]))
                .global(true),
        )
        .arg(
            Arg::new("config")
                .short('c')
                .long("config")
                .help("Path to configuration file")
                .value_name("FILE")
                .value_hint(ValueHint::FilePath)
                .value_parser(PathBufValueParser::new()),
        )
        .arg(
            Arg::new("host")
                .short('H')
                .long("host")
                .help("Bind host address (overrides DAEMON_HOST env var and config file)")
                .value_name("HOST")
                .value_hint(ValueHint::Hostname)
                .value_parser(NonEmptyStringValueParser::new()),
        )
        .arg(
            Arg::new("port")
                .short('p')
                .long("port")
                .help("Bind port number (overrides DAEMON_PORT env var and config file)")
                .value_name("PORT")
                .value_parser(clap::builder::RangedU64ValueParser::<u16>::new().range(1..=65535)),
        )
        .arg(
            Arg::new("out-dir")
                .short('o')
                .long("out-dir")
                .help("Working directory for outputs (overrides DAEMON_OUT_DIR and config file)")
                .value_name("DIR")
                .default_value("./output")
                .value_hint(ValueHint::DirPath)
                .value_parser(PathBufValueParser::new()),
        )
        .arg(
            Arg::new("dry-run")
                .long("dry-run")
                .help("Validate configuration without starting daemon")
                .action(ArgAction::SetTrue),
        )
}

/// Synchronizes global `anstream::ColorChoice` from the parsed `--color` flag so
/// downstream `miette` and logging formatters respect the user's CLI choice.
pub fn apply_color_choice(matches: &ArgMatches) {
    match matches.get_one::<String>("color").map(String::as_str) {
        Some("always") => anstream::ColorChoice::Always.write_global(),
        Some("never") => anstream::ColorChoice::Never.write_global(),
        _ => anstream::ColorChoice::Auto.write_global(),
    }
}

/// Resolves effective configuration by merging CLI arguments, environment variables,
/// configuration file entries, and hardcoded defaults.
///
/// Precedence order:
/// 1. Explicit CLI argument flag (`matches.value_source(id) == Some(ValueSource::CommandLine)`)
/// 2. Process environment variable (`DAEMON_HOST` / `DAEMON_PORT` / `DAEMON_OUT_DIR`)
/// 3. File-based configuration file (`--config`)
/// 4. Hardcoded static default (`ValueSource::DefaultValue`)
///
/// # Errors
/// Returns a formatted `clap::Error` if required fields cannot be resolved.
pub fn resolve_configuration(
    matches: &ArgMatches,
    cmd: &Command,
) -> Result<ResolvedConfig, Error> {
    apply_color_choice(matches);

    // 1. Check for optional configuration file
    let file_cfg = if let Some(cfg_path) = matches.get_one::<PathBuf>("config") {
        FileConfig::load_from_path(cfg_path).map_err(|err_msg| {
            let mut err = cmd.clone().error(ErrorKind::InvalidValue, err_msg);
            err.insert(
                ContextKind::InvalidArg,
                ContextValue::String("--config".to_string()),
            );
            err
        })?
    } else {
        FileConfig::default()
    };

    // 2. Resolve `host`: CLI arg > Env var > File Config > Default
    let host = if matches.value_source("host") == Some(ValueSource::CommandLine) {
        matches.get_one::<String>("host").cloned().unwrap()
    } else if let Ok(env_host) = std::env::var("DAEMON_HOST") {
        env_host
    } else if let Some(h) = file_cfg.settings.get("host") {
        h.clone()
    } else {
        "0.0.0.0".to_string()
    };

    // 3. Resolve `port`: CLI arg > Env var > File Config > Default
    let port = if matches.value_source("port") == Some(ValueSource::CommandLine) {
        *matches.get_one::<u16>("port").unwrap()
    } else if let Ok(env_port_str) = std::env::var("DAEMON_PORT") {
        env_port_str.parse::<u16>().map_err(|_| {
            cmd.clone().error(
                ErrorKind::InvalidValue,
                format!("invalid port `{env_port_str}` in DAEMON_PORT environment variable"),
            )
        })?
    } else if let Some(p_str) = file_cfg.settings.get("port") {
        p_str.parse::<u16>().map_err(|_| {
            cmd.clone().error(
                ErrorKind::InvalidValue,
                format!("invalid port `{p_str}` in configuration file"),
            )
        })?
    } else {
        8080
    };

    // 4. Resolve `output_dir`: MUST check `ValueSource::CommandLine` because `out-dir`
    // has `.default_value("./output")`, so `get_one` is ALWAYS `Some(...)`!
    let output_dir = if matches.value_source("out-dir") == Some(ValueSource::CommandLine) {
        matches.get_one::<PathBuf>("out-dir").cloned().unwrap()
    } else if let Ok(env_dir) = std::env::var("DAEMON_OUT_DIR") {
        PathBuf::from(env_dir)
    } else if let Some(cfg_dir) = file_cfg.settings.get("out_dir") {
        PathBuf::from(cfg_dir)
    } else {
        matches
            .get_one::<PathBuf>("out-dir")
            .cloned()
            .expect("default_value guarantees ValueSource::DefaultValue is present")
    };

    let dry_run = matches.get_flag("dry-run");

    Ok(ResolvedConfig {
        host,
        port,
        output_dir,
        dry_run,
    })
}

/// Low-level `clap_lex 1.1.1` pre-scanner extracting trailing passthrough arguments after `--`.
pub fn split_escaped_passthrough<'a>(raw: &'a clap_lex::RawArgs) -> Vec<&'a OsStr> {
    let mut cursor = raw.cursor();
    let _bin = raw.next_os(&mut cursor);
    let mut passthrough = Vec::new();
    let mut after_escape = false;

    while let Some(arg) = raw.next(&mut cursor) {
        if after_escape {
            passthrough.push(arg.to_value_os());
        } else if arg.is_escape() {
            after_escape = true;
        }
    }
    passthrough
}

/// Entry point executing the production CLI lifecycle with standardized exit codes.
pub fn run_cli_lifecycle(args: &[&str]) -> i32 {
    let mut cmd = build_layered_cli();
    match cmd.try_get_matches_from_mut(args) {
        Ok(matches) => match resolve_configuration(&matches, &cmd) {
            Ok(_config) => 0,
            Err(err) => {
                let _ = err.print();
                2
            }
        },
        Err(err) => {
            // Inspect plain or ANSI-styled rendering via `err.render()` / `err.render().ansi()`
            let _ = err.print();
            err.exit_code()
        }
    }
}
```

