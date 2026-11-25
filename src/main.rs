//! Command-line interface entry point for the FrameAssembly `v3.3.0` network packet compiler.
//!
//! Compiling `.frasm` network traffic code to `.pcap` / `.pcapng` is the default root command,
//! paired with five subcommands across **146 native Layer 2 through Layer 7 protocols**:
//! - `frameassembly <input.frasm|-> [output.pcap|-]` validates `.frasm` code (or `stdin`) and
//!   writes a nanosecond-precision `.pcap` / `PCAPNG` capture file (or streams `PCAPNG` to `stdout`).
//! - `frameassembly show <input.frasm|capture.pcap|capture.pcapng|->` displays a relative-timestamp
//!   packet ladder table to standard output without writing a capture file to disk.
//! - `frameassembly reverse <input.pcap|-> [output.frasm|-]` reverses a `.pcap` or `.pcapng`
//!   capture stream into `.frasm` code (defaulting to `<input_stem>.frasm`, or `stdout` for `-`).
//! - `frameassembly update` checks for a newer release and updates the installed binary.
//! - `frameassembly version` prints the active `frameassembly` binary version.
//! - `frameassembly help [subcommand]` displays command usage and subcommand reference text.

mod updater;

use clap::builder::PathBufValueParser;
use clap::builder::styling::{AnsiColor, Effects, Styles};
use clap::{Arg, ArgAction, Command, ValueHint};
use frameassembly::backend::{CompiledFrame, compile_program_with_metadata};
use frameassembly::inspect::format_packet_ladder;
use frameassembly::parser::parse_program;
use frameassembly::pcap::{serialize_pcapng_with_metadata, write_capture_file_with_metadata};
use frameassembly::reverse::{
    read_capture_bytes_for_show, reverse_pcap_file, reverse_pcap_reader,
};
use miette::{IntoDiagnostic, NamedSource, Result};
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};

/// Returns `true` when `bytes` begins with a recognized `PCAP` or `PCAPNG` 4-byte file magic.
fn is_capture_magic(bytes: &[u8]) -> bool {
    matches!(
        bytes.get(0..4),
        Some(
            [0x0A, 0x0D, 0x0D, 0x0A]
                | [0xA1, 0xB2, 0xC3, 0xD4]
                | [0xD4, 0xC3, 0xB2, 0xA1]
                | [0xA1, 0xB2, 0x3C, 0x4D]
                | [0x4D, 0x3C, 0xB2, 0xA1]
        )
    )
}

/// Reads the entire standard input stream into memory for `-` CLI streaming paths.
fn read_stdin_bytes() -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    std::io::stdin()
        .lock()
        .read_to_end(&mut buf)
        .into_diagnostic()?;
    Ok(buf)
}

/// Nine-role `anstyle` terminal color palette used by `clap` help and usage diagnostics.
const CLI_STYLES: Styles = Styles::styled()
    .header(AnsiColor::Green.on_default().effects(Effects::BOLD))
    .usage(AnsiColor::Green.on_default().effects(Effects::BOLD))
    .literal(AnsiColor::Cyan.on_default().effects(Effects::BOLD))
    .placeholder(AnsiColor::Cyan.on_default())
    .error(AnsiColor::Red.on_default().effects(Effects::BOLD))
    .valid(AnsiColor::Green.on_default().effects(Effects::BOLD))
    .invalid(AnsiColor::Yellow.on_default().effects(Effects::BOLD))
    .context(AnsiColor::BrightBlack.on_default())
    .context_value(AnsiColor::Cyan.on_default());

/// Detects whether the current process owns a standalone console created by Windows Explorer
/// (double-click or drag-and-drop onto `frameassembly.exe`) rather than an interactive shell.
#[cfg(windows)]
fn is_standalone_windows_console() -> bool {
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetConsoleProcessList(lpdw_list: *mut u32, dw_process_count: u32) -> u32;
    }
    let mut pids = [0u32; 2];
    // SAFETY: `pids` points to a valid stack-allocated array of 2 `u32` values matching `dw_process_count = 2`.
    let count = unsafe { GetConsoleProcessList(pids.as_mut_ptr(), 2) };
    count == 1
}

/// Non-Windows targets never run inside a transient Windows Explorer console window.
#[cfg(not(windows))]
const fn is_standalone_windows_console() -> bool {
    false
}

/// Prompts the user to press Enter before closing a standalone Windows Explorer console window.
#[cfg(windows)]
fn pause_windows_console() {
    use std::io::{BufRead, Write};
    let _ = write!(std::io::stdout(), "\nPress Enter to close this window...");
    let _ = std::io::stdout().flush();
    let mut line = String::new();
    let _ = std::io::stdin().lock().read_line(&mut line);
}
/// Canonical list of top-level CLI subcommands.
const SUBCOMMANDS: [&str; 5] = ["show", "reverse", "update", "version", "help"];

/// Derives the default output path from `input` by replacing its extension with `default_ext`,
/// or appending `.default_ext` when `input` already ends with `default_ext` so the input file
/// is never overwritten in place.
fn derive_default_output_path(input: &Path, default_ext: &str) -> PathBuf {
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

/// Checks raw CLI arguments for legacy or invalid invocation patterns (`-o` / `--output`,
/// `--show` / `--reverse`, legacy `.fasm` file paths, bare `.pcap` / `.pcapng` paths, removed
/// `compile` subcommand, or `.frasm` passed as `OUTPUT.pcap`) and returns a clear migration or
/// safety hint.
fn check_legacy_cli_args<I, T>(args: I) -> std::result::Result<(), String>
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

    let mut positional: Vec<String> = Vec::new();
    let mut after_double_dash = false;
    for arg in &collected[1..] {
        let s = arg.to_string_lossy();
        if !after_double_dash {
            if s == "--" {
                after_double_dash = true;
                continue;
            }
            if s == "-o"
                || s == "--output"
                || s.starts_with("--output=")
                || (s.starts_with("-o") && s.len() > 2 && !s.starts_with("--"))
            {
                return Err(
                    "The '-o' / '--output' flag was replaced by an optional second positional path in FrameAssembly 2.0.\n  Compile: frameassembly <in.frasm> [out.pcap]\n  Reverse: frameassembly reverse <in.pcap> [out.frasm]"
                        .to_string(),
                );
            }
            if s == "--show" || s.starts_with("--show=") {
                return Err(
                    "The '--show' flag is not supported; use the 'show' subcommand instead:\n  frameassembly show <in.frasm>"
                        .to_string(),
                );
            }
            if s == "--reverse" || s.starts_with("--reverse=") {
                return Err(
                    "The '--reverse' flag is not supported; use the 'reverse' subcommand instead:\n  frameassembly reverse <in.pcap> [out.frasm]"
                        .to_string(),
                );
            }
            if s != "-" && s.starts_with('-') {
                continue;
            }
        }
        positional.push(s.into_owned());
    }

    let Some(arg1) = positional.first() else {
        return Ok(());
    };

    if !after_double_dash && arg1.eq_ignore_ascii_case("compile") && !Path::new(arg1).is_file() {
        return Err(
            "Compiling is the default command in FrameAssembly (there is no 'compile' subcommand); run:\n  frameassembly <in.frasm> [out.pcap]"
                .to_string(),
        );
    }

    if !after_double_dash && arg1 == "show" {
        if let Some(arg2) = positional.get(1)
            && arg2.to_ascii_lowercase().ends_with(".fasm")
        {
            let suggested = format!("{}.frasm", &arg2[..arg2.len() - 5]);
            return Err(format!(
                "FrameAssembly 3.0 uses '.frasm'; rename '{arg2}' to '{suggested}':\n  frameassembly show {suggested}"
            ));
        }
        return Ok(());
    }

    if !after_double_dash && arg1 == "reverse" {
        if let (Some(arg2), Some(arg3)) = (positional.get(1), positional.get(2))
            && arg3.to_ascii_lowercase().ends_with(".fasm")
        {
            let suggested = format!("{}.frasm", &arg3[..arg3.len() - 5]);
            return Err(format!(
                "FrameAssembly 3.0 uses '.frasm'; rename '{arg3}' to '{suggested}':\n  frameassembly reverse {arg2} {suggested}"
            ));
        }
        return Ok(());
    }

    if after_double_dash || !SUBCOMMANDS.contains(&arg1.as_str()) {
        let lower = arg1.to_ascii_lowercase();
        if lower.ends_with(".pcap") || lower.ends_with(".pcapng") {
            return Err(format!(
                "Direct capture invocation is not supported; use the 'reverse' subcommand instead:\n  frameassembly reverse {arg1}"
            ));
        }
        if lower.ends_with(".fasm") {
            let suggested = format!("{}.frasm", &arg1[..arg1.len() - 5]);
            return Err(format!(
                "FrameAssembly 3.0 uses '.frasm'; rename '{arg1}' to '{suggested}':\n  frameassembly {suggested}"
            ));
        }
        if let Some(arg2) = positional.get(1) {
            let out_lower = arg2.to_ascii_lowercase();
            if out_lower.ends_with(".frasm") || out_lower.ends_with(".fasm") {
                return Err(format!(
                    "Refusing to write binary PCAP output to source file '{arg2}'; specify a '.pcap' or '.pcapng' output path instead:\n  frameassembly {arg1} [out.pcap]"
                ));
            }
        }
    }

    Ok(())
}

/// Constructs the `clap::Command` definition for the `frameassembly` CLI.
fn build_cli() -> Command {
    Command::new("frameassembly")
        .version(env!("CARGO_PKG_VERSION"))
        .about("Compile .frasm network traffic code to .pcap/.pcapng and reverse captures back to .frasm")
        .after_help(
            "Examples:\n  frameassembly demo.frasm\n  frameassembly show demo.frasm\n  frameassembly reverse capture.pcap\n\nFeedback & protocol requests: https://github.com/SteveWinschel/FrameAssembly/issues",
        )
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
                .value_name("INPUT.frasm")
                .help("Path to the input .frasm file (or '-' for stdin)")
                .required(true)
                .index(1)
                .value_hint(ValueHint::FilePath)
                .value_parser(PathBufValueParser::new()),
        )
        .arg(
            Arg::new("output")
                .value_name("OUTPUT.pcap")
                .help("Optional output .pcap/.pcapng path (defaults to <input_stem>.pcap, or '-' for stdout PCAPNG)")
                .index(2)
                .value_hint(ValueHint::FilePath)
                .value_parser(PathBufValueParser::new()),
        )
        .subcommand(
            Command::new("show")
                .about("Validate a .frasm file or inspect a .pcap/.pcapng capture (or '-' for stdin) without writing a file")
                .disable_help_flag(true)
                .arg(
                    Arg::new("input")
                        .value_name("INPUT.frasm")
                        .help("Path to the input .frasm or .pcap/.pcapng file (or '-' for stdin)")
                        .required(true)
                        .index(1)
                        .value_hint(ValueHint::FilePath)
                        .value_parser(PathBufValueParser::new()),
                ),
        )
        .subcommand(
            Command::new("reverse")
                .about("Reverse a .pcap or .pcapng capture file into .frasm code")
                .disable_help_flag(true)
                .arg(
                    Arg::new("input")
                        .value_name("INPUT.pcap")
                        .help("Path to the input .pcap or .pcapng capture file (or '-' for stdin)")
                        .required(true)
                        .index(1)
                        .value_hint(ValueHint::FilePath)
                        .value_parser(PathBufValueParser::new()),
                )
                .arg(
                    Arg::new("output")
                        .value_name("OUTPUT.frasm")
                        .help("Optional output .frasm path (defaults to <input_stem>.frasm, or '-' for stdout)")
                        .index(2)
                        .value_hint(ValueHint::FilePath)
                        .value_parser(PathBufValueParser::new()),
                ),
        )
        .subcommand(
            Command::new("update")
                .about("Update frameassembly to the newest release")
                .disable_help_flag(true),
        )
        .subcommand(
            Command::new("version")
                .about("Print the FrameAssembly version")
                .disable_help_flag(true),
        )
}

/// Executes the parsed CLI invocation for `raw_args`.
fn run_cli(raw_args: Vec<OsString>) -> Result<()> {
    if let Err(hint) = check_legacy_cli_args(&raw_args) {
        return Err(miette::miette!("{hint}"));
    }

    let mut matches = match build_cli().try_get_matches_from(raw_args) {
        Ok(m) => m,
        Err(err) => {
            #[cfg(windows)]
            if is_standalone_windows_console() {
                let _ = err.print();
                pause_windows_console();
                std::process::exit(err.exit_code());
            }
            err.exit();
        }
    };
    match matches.remove_subcommand() {
        Some((sub_name, mut sub_matches)) => match sub_name.as_str() {
            "update" => updater::run_update(),
            "version" => {
                println!("frameassembly {}", env!("CARGO_PKG_VERSION"));
                Ok(())
            }
            "reverse" => {
                let input_path = sub_matches
                    .remove_one::<PathBuf>("input")
                    .ok_or_else(|| miette::miette!("Missing input .pcap / .pcapng file"))?;
                let input_is_stdin = input_path == Path::new("-");
                let output_path = sub_matches.remove_one::<PathBuf>("output");
                let output_is_stdout = match &output_path {
                    Some(p) => p == Path::new("-"),
                    None => input_is_stdin,
                };
                let res = if input_is_stdin {
                    let stdin = std::io::stdin();
                    reverse_pcap_reader(stdin.lock())
                        .map_err(|e| miette::miette!("reverse error: {}", e))?
                } else {
                    reverse_pcap_file(&input_path)
                        .map_err(|e| miette::miette!("reverse error: {}", e))?
                };
                for warning in &res.warnings {
                    eprintln!("Warning: {warning}");
                }
                if output_is_stdout {
                    {
                        let mut stdout = std::io::stdout().lock();
                        stdout.write_all(res.fasm.as_bytes()).into_diagnostic()?;
                        stdout.flush().into_diagnostic()?;
                    }
                    eprintln!(
                        "Wrote <stdout> ({} host(s), {} packet(s) reversed from {})",
                        res.host_count,
                        res.packet_count,
                        if input_is_stdin {
                            String::from("<stdin>")
                        } else {
                            input_path.display().to_string()
                        }
                    );
                } else {
                    let out_file = output_path
                        .unwrap_or_else(|| derive_default_output_path(&input_path, "frasm"));
                    fs::write(&out_file, &res.fasm).into_diagnostic()?;
                    println!(
                        "Wrote {} ({} host(s), {} packet(s) reversed from {})",
                        out_file.display(),
                        res.host_count,
                        res.packet_count,
                        input_path.display(),
                    );
                }
                Ok(())
            }
            "show" => {
                let file_path = sub_matches
                    .remove_one::<PathBuf>("input")
                    .ok_or_else(|| miette::miette!("Missing input .frasm or capture file"))?;
                let is_stdin = file_path == Path::new("-");
                let raw_bytes = if is_stdin {
                    read_stdin_bytes()?
                } else {
                    fs::read(&file_path).into_diagnostic()?
                };
                let ext_is_capture = !is_stdin
                    && file_path
                        .extension()
                        .and_then(|e| e.to_str())
                        .is_some_and(|e| {
                            e.eq_ignore_ascii_case("pcap") || e.eq_ignore_ascii_case("pcapng")
                        });
                if ext_is_capture || is_capture_magic(&raw_bytes) {
                    let (pkts, warnings) = read_capture_bytes_for_show(&raw_bytes)
                        .map_err(|e| miette::miette!("show error: {}", e))?;
                    for warning in &warnings {
                        eprintln!("Warning: {warning}");
                    }
                    if pkts.is_empty() {
                        eprintln!("Warning: capture contains 0 frames.");
                    }
                    let frames: Vec<(Vec<u8>, u64)> = pkts
                        .into_iter()
                        .map(|p| (p.raw_eth_frame, p.timestamp_ns))
                        .collect();
                    print!("{}", format_packet_ladder(&frames, &[]));
                    return Ok(());
                }

                let file_display = if is_stdin {
                    String::from("<stdin>")
                } else {
                    file_path.display().to_string()
                };
                let code = String::from_utf8(raw_bytes).into_diagnostic()?;
                let program = parse_program(&code).map_err(|e| {
                    miette::Report::new(e)
                        .with_source_code(NamedSource::new(file_display, code.clone()))
                })?;
                let ast_protocols = program.emitted_protocols();
                let (compiled, _) = compile_program_with_metadata(&program)
                    .map_err(|e| miette::miette!("compile error: {}", e))?;
                let frames: Vec<(Vec<u8>, u64)> = compiled
                    .into_iter()
                    .map(|f| (f.data, f.timestamp_ns))
                    .collect();
                if frames.is_empty() {
                    eprintln!(
                        "Warning: 0 packets emitted — check that 'compile {{ ... }}' invokes a flow or packet statement."
                    );
                }
                print!("{}", format_packet_ladder(&frames, &ast_protocols));
                Ok(())
            }
            _ => unreachable!("clap enforces known subcommands"),
        },
        None => {
            let file_path = matches
                .remove_one::<PathBuf>("input")
                .ok_or_else(|| miette::miette!("Missing input .frasm file"))?;
            let input_is_stdin = file_path == Path::new("-");
            let output_pcap = matches.remove_one::<PathBuf>("output").unwrap_or_else(|| {
                if input_is_stdin {
                    PathBuf::from("-")
                } else {
                    derive_default_output_path(&file_path, "pcap")
                }
            });
            let output_is_stdout = output_pcap == Path::new("-");
            if !output_is_stdout
                && output_pcap
                    .extension()
                    .and_then(|e| e.to_str())
                    .is_some_and(|e| {
                        e.eq_ignore_ascii_case("frasm") || e.eq_ignore_ascii_case("fasm")
                    })
            {
                return Err(miette::miette!(
                    "Refusing to write binary PCAP output to source file '{}'; specify a '.pcap' or '.pcapng' output path instead",
                    output_pcap.display()
                ));
            }

            let (file_display, code) = if input_is_stdin {
                let bytes = read_stdin_bytes()?;
                (
                    String::from("<stdin>"),
                    String::from_utf8(bytes).into_diagnostic()?,
                )
            } else {
                (
                    file_path.display().to_string(),
                    fs::read_to_string(&file_path).into_diagnostic()?,
                )
            };
            let program = parse_program(&code).map_err(|e| {
                miette::Report::new(e)
                    .with_source_code(NamedSource::new(file_display, code.clone()))
            })?;
            let (compiled, hosts) = compile_program_with_metadata(&program)
                .map_err(|e| miette::miette!("compile error: {}", e))?;
            let packet_count = compiled.len();
            let raw_meta: Vec<(Vec<u8>, u64, Option<String>)> = compiled
                .into_iter()
                .map(|f: CompiledFrame| (f.data, f.timestamp_ns, f.comment))
                .collect();

            if output_is_stdout {
                if program.flows.is_empty() {
                    eprintln!("Successfully parsed {} hosts", program.hosts.len());
                } else {
                    eprintln!(
                        "Successfully parsed {} hosts, {} flows",
                        program.hosts.len(),
                        program.flows.len(),
                    );
                }
                if packet_count == 0 {
                    eprintln!("Warning: 0 packets emitted — capture contains header only.");
                }
                let bytes = serialize_pcapng_with_metadata(&raw_meta, &hosts)
                    .map_err(|e| miette::miette!("compile error: {}", e))?;
                {
                    let mut stdout = std::io::stdout().lock();
                    stdout.write_all(&bytes).into_diagnostic()?;
                    stdout.flush().into_diagnostic()?;
                }
                eprintln!("Wrote <stdout> ({packet_count} packet(s), pcapng)");
            } else {
                if program.flows.is_empty() {
                    println!("Successfully parsed {} hosts", program.hosts.len());
                } else {
                    println!(
                        "Successfully parsed {} hosts, {} flows",
                        program.hosts.len(),
                        program.flows.len(),
                    );
                }
                if packet_count == 0 {
                    eprintln!("Warning: 0 packets emitted — capture contains header only.");
                }
                let output_pcap_str = output_pcap.to_string_lossy();
                let fmt_label = if output_pcap_str.len() >= 5
                    && output_pcap_str.as_bytes()[output_pcap_str.len() - 5..]
                        .eq_ignore_ascii_case(b".pcap")
                {
                    "classic pcap"
                } else {
                    "pcapng"
                };
                write_capture_file_with_metadata(&raw_meta, &hosts, &output_pcap_str)
                    .map_err(|e| miette::miette!("compile error: {}", e))?;
                println!("Wrote {output_pcap_str} ({packet_count} packet(s), {fmt_label})");
            }
            Ok(())
        }
    }
}

/// Entry point for the `frameassembly` CLI binary.
///
/// # Errors
/// Returns a [`miette::Result`] error if legacy 1.x flags are supplied, the input file cannot
/// be read, parsing/validation/decompilation fails, or writing the output file fails.
fn main() -> Result<()> {
    updater::cleanup_stale_windows_old_exe();
    let raw_args: Vec<OsString> = std::env::args_os().collect();
    #[cfg(windows)]
    if is_standalone_windows_console() {
        if raw_args.len() <= 1 {
            println!(
                "FrameAssembly {} — Packets as Code (.frasm <-> .pcap / .pcapng)\n\n\
                 Quickstart (PowerShell / Command Prompt):\n  \
                   frameassembly demo.frasm              Compile .frasm code to demo.pcap\n  \
                   frameassembly show demo.frasm         Inspect the packet ladder table\n  \
                   frameassembly reverse capture.pcap    Reverse a .pcap/.pcapng to capture.frasm\n\n\
                 Drag-and-drop tip:\n  \
                   Drag any .frasm file onto frameassembly.exe to compile <name>.pcap,\n  \
                   or drag any .pcap / .pcapng file onto frameassembly.exe to reverse <name>.frasm.",
                env!("CARGO_PKG_VERSION")
            );
            pause_windows_console();
            return Ok(());
        }
        let result = if raw_args.len() == 2 {
            let arg1 = raw_args[1].to_string_lossy().to_ascii_lowercase();
            if arg1.ends_with(".pcap") || arg1.ends_with(".pcapng") {
                run_cli(vec![
                    raw_args[0].clone(),
                    OsString::from("reverse"),
                    raw_args[1].clone(),
                ])
            } else {
                run_cli(raw_args)
            }
        } else {
            run_cli(raw_args)
        };
        match result {
            Ok(()) => {
                pause_windows_console();
                return Ok(());
            }
            Err(err) => {
                eprintln!("{err:?}");
                pause_windows_console();
                std::process::exit(1);
            }
        }
    }
    let _ = is_standalone_windows_console();
    run_cli(raw_args)
}

/// Unit tests for FrameAssembly 3.3 default root compilation and five subcommands
/// (`show`, `reverse`, `update`, `version`, `help`), hidden script compatibility flags, legacy
/// migration hints, safety guards, and packet ladder formatting.
#[cfg(test)]
mod tests {
    use super::*;
    use clap::error::ErrorKind;

    /// Validates that the `clap::Command` configuration has no conflicting flags, duplicate indices, or invalid defaults.
    #[test]
    fn verify_cli_invariants() {
        build_cli().debug_assert();
    }

    /// Verifies `derive_default_output_path` stem matching and collision avoidance for `.pcap` and `.frasm`.
    #[test]
    fn test_derive_default_output_path() {
        assert_eq!(
            derive_default_output_path(Path::new("example.frasm"), "pcap"),
            PathBuf::from("example.pcap")
        );
        assert_eq!(
            derive_default_output_path(Path::new("dir/test.frasm"), "pcap"),
            PathBuf::from("dir/test.pcap")
        );
        assert_eq!(
            derive_default_output_path(Path::new("already.pcap"), "pcap"),
            PathBuf::from("already.pcap.pcap")
        );
        assert_eq!(
            derive_default_output_path(Path::new("example.pcap"), "frasm"),
            PathBuf::from("example.frasm")
        );
        assert_eq!(
            derive_default_output_path(Path::new("traces/cap.pcapng"), "frasm"),
            PathBuf::from("traces/cap.frasm")
        );
        assert_eq!(
            derive_default_output_path(Path::new("already.frasm"), "frasm"),
            PathBuf::from("already.frasm.frasm")
        );
    }

    /// Verifies that default root `.frasm` compilation and the five subcommands (`show`,
    /// `reverse`, `update`, `version`, `help`) parse positional arguments cleanly and hide
    /// `-h`/`--help` and `-V`/`--version` from rendered help text while keeping `--help` and
    /// `--version` functional for scripts.
    #[test]
    fn test_cli_default_compile_four_subcommands_and_hidden_flags() {
        let mut cmd = build_cli();
        assert_eq!(cmd.get_version(), Some(env!("CARGO_PKG_VERSION")));
        let help_text = cmd.render_help().to_string();
        assert!(
            help_text.contains("<INPUT.frasm>") && help_text.contains("[OUTPUT.pcap]"),
            "root help text should advertise positional <INPUT.frasm> [OUTPUT.pcap]:\n{help_text}"
        );
        assert!(
            help_text.contains("Examples:")
                && help_text.contains("frameassembly demo.frasm")
                && help_text.contains("frameassembly show demo.frasm")
                && help_text.contains("frameassembly reverse capture.pcap"),
            "root help text should include copy-paste examples:\n{help_text}"
        );
        for sub in SUBCOMMANDS {
            assert!(
                help_text.contains(sub),
                "root help text should list subcommand '{sub}':\n{help_text}"
            );
        }
        for hidden in ["--help", "--version", "-o", "--output", "DSL", ".fasm"] {
            assert!(
                !help_text.contains(hidden),
                "root help text must not expose '{hidden}':\n{help_text}"
            );
        }
        assert!(help_text.contains("https://github.com/SteveWinschel/FrameAssembly/issues"));

        for sub_name in ["show", "reverse", "update", "version"] {
            let sub_help = cmd
                .find_subcommand_mut(sub_name)
                .expect("subcommand exists")
                .render_help()
                .to_string();
            assert!(
                !sub_help.contains("--help") && !sub_help.contains("--output"),
                "subcommand '{sub_name}' help must hide --help and omit --output:\n{sub_help}"
            );
        }

        // Silent compatibility for shell/CI scripts invoking --help or --version
        let help_err = build_cli()
            .try_get_matches_from(["frameassembly", "--help"])
            .expect_err("--help exits via DisplayHelp");
        assert_eq!(help_err.kind(), ErrorKind::DisplayHelp);

        let ver_err = build_cli()
            .try_get_matches_from(["frameassembly", "--version"])
            .expect_err("--version exits via DisplayVersion");
        assert_eq!(ver_err.kind(), ErrorKind::DisplayVersion);

        let no_args_err = build_cli()
            .try_get_matches_from(["frameassembly"])
            .expect_err("zero args should render help");
        assert_eq!(
            no_args_err.kind(),
            ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand
        );

        let root_default = build_cli()
            .try_get_matches_from(["frameassembly", "demo.frasm"])
            .expect("default root compile with 1 arg should parse");
        assert!(root_default.subcommand_name().is_none());
        assert_eq!(
            root_default.get_one::<PathBuf>("input"),
            Some(&PathBuf::from("demo.frasm"))
        );
        assert_eq!(root_default.get_one::<PathBuf>("output"), None);

        let root_explicit = build_cli()
            .try_get_matches_from(["frameassembly", "demo.frasm", "custom.pcap"])
            .expect("default root compile with 2 positional args should parse");
        assert!(root_explicit.subcommand_name().is_none());
        assert_eq!(
            root_explicit.get_one::<PathBuf>("input"),
            Some(&PathBuf::from("demo.frasm"))
        );
        assert_eq!(
            root_explicit.get_one::<PathBuf>("output"),
            Some(&PathBuf::from("custom.pcap"))
        );

        let show_matches = build_cli()
            .try_get_matches_from(["frameassembly", "show", "demo.frasm"])
            .expect("show subcommand should parse");
        assert_eq!(
            show_matches
                .subcommand_matches("show")
                .and_then(|m| m.get_one::<PathBuf>("input")),
            Some(&PathBuf::from("demo.frasm"))
        );

        let rev_matches = build_cli()
            .try_get_matches_from([
                "frameassembly",
                "reverse",
                "traces/cap.pcapng",
                "traces/cap.frasm",
            ])
            .expect("reverse subcommand should parse");
        let rev_sub = rev_matches
            .subcommand_matches("reverse")
            .expect("reverse matched");
        assert_eq!(
            rev_sub.get_one::<PathBuf>("input"),
            Some(&PathBuf::from("traces/cap.pcapng"))
        );
        assert_eq!(
            rev_sub.get_one::<PathBuf>("output"),
            Some(&PathBuf::from("traces/cap.frasm"))
        );

        let upd_sub = build_cli()
            .try_get_matches_from(["frameassembly", "update"])
            .expect("update subcommand should parse");
        assert!(upd_sub.subcommand_matches("update").is_some());

        let ver_sub = build_cli()
            .try_get_matches_from(["frameassembly", "version"])
            .expect("version subcommand should parse");
        assert!(ver_sub.subcommand_matches("version").is_some());
    }

    /// Verifies that legacy CLI flags (`-o`, `--output`, `--show`, `--reverse`), legacy `.fasm`
    /// paths, bare `.pcap` paths, removed `compile` subcommands, and `.frasm` output typos
    /// return clear hints.
    #[test]
    fn test_legacy_cli_migration_hints_and_safety_guards() {
        let dash_o = check_legacy_cli_args(["frameassembly", "demo.frasm", "-o", "a.pcap"])
            .expect_err("-o should trigger hint");
        assert!(dash_o.contains("Compile: frameassembly <in.frasm> [out.pcap]"));
        assert!(dash_o.contains("Reverse: frameassembly reverse <in.pcap> [out.frasm]"));

        let long_out =
            check_legacy_cli_args(["frameassembly", "reverse", "a.pcap", "--output=a.frasm"])
                .expect_err("--output should trigger hint");
        assert!(long_out.contains("frameassembly reverse <in.pcap> [out.frasm]"));

        let flag_show = check_legacy_cli_args(["frameassembly", "--show", "demo.frasm"])
            .expect_err("--show should trigger hint");
        assert!(flag_show.contains("frameassembly show <in.frasm>"));

        let flag_rev = check_legacy_cli_args(["frameassembly", "--reverse", "trace.pcap"])
            .expect_err("--reverse should trigger hint");
        assert!(flag_rev.contains("frameassembly reverse <in.pcap> [out.frasm]"));

        let bare_pcap = check_legacy_cli_args(["frameassembly", "trace.pcapng"])
            .expect_err("bare .pcapng should trigger reverse hint");
        assert!(bare_pcap.contains("frameassembly reverse trace.pcapng"));

        let old_compile_sub = check_legacy_cli_args(["frameassembly", "compile", "demo.frasm"])
            .expect_err("removed compile subcommand should trigger safety guard");
        assert!(old_compile_sub.contains("there is no 'compile' subcommand"));
        assert!(old_compile_sub.contains("frameassembly <in.frasm> [out.pcap]"));

        let legacy_fasm_compile = check_legacy_cli_args(["frameassembly", "demo.fasm"])
            .expect_err("legacy .fasm input should return v3.0 .frasm rename hint");
        assert!(
            legacy_fasm_compile
                .contains("FrameAssembly 3.0 uses '.frasm'; rename 'demo.fasm' to 'demo.frasm'")
        );
        assert!(legacy_fasm_compile.contains("frameassembly demo.frasm"));

        let legacy_fasm_show = check_legacy_cli_args(["frameassembly", "show", "dir/demo.fasm"])
            .expect_err("legacy .fasm show input should return v3.0 .frasm rename hint");
        assert!(legacy_fasm_show.contains(
            "FrameAssembly 3.0 uses '.frasm'; rename 'dir/demo.fasm' to 'dir/demo.frasm'"
        ));
        assert!(legacy_fasm_show.contains("frameassembly show dir/demo.frasm"));

        let legacy_fasm_rev =
            check_legacy_cli_args(["frameassembly", "reverse", "cap.pcap", "cap.fasm"])
                .expect_err("legacy .fasm reverse output should return v3.0 .frasm rename hint");
        assert!(
            legacy_fasm_rev
                .contains("FrameAssembly 3.0 uses '.frasm'; rename 'cap.fasm' to 'cap.frasm'")
        );
        assert!(legacy_fasm_rev.contains("frameassembly reverse cap.pcap cap.frasm"));

        let frasm_as_output = check_legacy_cli_args(["frameassembly", "a.frasm", "b.frasm"])
            .expect_err(".frasm second positional arg should be rejected to protect source file");
        assert!(frasm_as_output.contains("b.frasm"));

        let old_compile_upper = check_legacy_cli_args(["frameassembly", "COMPILE", "demo.frasm"])
            .expect_err("uppercase COMPILE subcommand should trigger safety guard");
        assert!(old_compile_upper.contains("there is no 'compile' subcommand"));

        let stdin_bad_out = check_legacy_cli_args(["frameassembly", "-", "b.frasm"])
            .expect_err("- input with .frasm output should be rejected");
        assert!(stdin_bad_out.contains("b.frasm"));

        assert!(check_legacy_cli_args(["frameassembly", "demo.frasm"]).is_ok());
        assert!(check_legacy_cli_args(["frameassembly", "demo.frasm", "out.pcap"]).is_ok());
        assert!(check_legacy_cli_args(["frameassembly", "reverse", "a.pcap", "a.frasm"]).is_ok());
        assert!(check_legacy_cli_args(["frameassembly", "--version"]).is_ok());
        assert!(check_legacy_cli_args(["frameassembly", "-"]).is_ok());
        assert!(check_legacy_cli_args(["frameassembly", "-", "-"]).is_ok());
        assert!(check_legacy_cli_args(["frameassembly", "show", "-"]).is_ok());
        assert!(check_legacy_cli_args(["frameassembly", "reverse", "-", "-"]).is_ok());
    }

    /// Verifies packet ladder rendering and binary capture `show` ladder inspection.
    #[test]
    fn test_packet_ladder_strict_lowercase_frasm() {
        let sample = "host a { ip 10.0.0.1 }\nhost b { ip 10.0.0.2 }\nflow f(c, s) {\n    c -> s tcp srcport 50000 dstport 443 syn wait 5ms\n    c <- s tcp syn ack wait 5ms\n}\ncompile { f(a, b) }";
        let program = parse_program(sample).expect("sample should parse");
        let (compiled, _) = compile_program_with_metadata(&program).expect("sample should compile");
        let frames: Vec<(Vec<u8>, u64)> = compiled
            .into_iter()
            .map(|f| (f.data, f.timestamp_ns))
            .collect();
        let ladder = format_packet_ladder(&frames, &program.emitted_protocols());
        assert!(ladder.contains("Source -> Destination"));
        assert!(ladder.contains("Protocol"));
        assert!(ladder.contains("TCP"));
        assert!(ladder.contains("0.000"));
        assert!(ladder.contains("5.000"));

        let pcapng = frameassembly::pcap::serialize_pcapng(&frames).expect("serialize pcapng");
        let (show_pkts, warnings) =
            read_capture_bytes_for_show(&pcapng).expect("show capture decode");
        assert!(warnings.is_empty());
        assert_eq!(show_pkts.len(), 2);
        let raw_frames: Vec<(Vec<u8>, u64)> = show_pkts
            .into_iter()
            .map(|p| (p.raw_eth_frame, p.timestamp_ns))
            .collect();
        let cap_ladder = format_packet_ladder(&raw_frames, &[]);
        assert!(cap_ladder.contains("10.0.0.1 -> 10.0.0.2"));
    }
}
