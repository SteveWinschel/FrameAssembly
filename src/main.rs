//! The FrameAssembly compiler CLI.
#![warn(missing_docs)]
#![warn(clippy::missing_docs_in_private_items)]

use clap::{Arg, Command};
use frameassembly::backend::generate_pcap;
use frameassembly::parser::parse_program;
use miette::{IntoDiagnostic, Result};
use std::fs;

/// The main entry point for the `frameassembly` CLI.
///
/// This reads a `.fasm` file provided via command-line arguments, parses the syntax,
/// and generates the corresponding `.pcap` file.
///
/// # Examples
/// ```no_run
/// // Run from the command line:
/// // $ frameassembly demo.fasm -o output.pcap
/// ```
///
/// # Errors
/// Returns a `miette::Result` error if:
/// * Incorrect CLI arguments are provided.
/// * The input file cannot be read.
/// * Parsing the source file fails.
/// * PCAP generation fails.
fn main() -> Result<()> {
    let matches = Command::new("frameassembly")
        .version(env!("CARGO_PKG_VERSION"))
        .about("A Domain-Specific Language (DSL) compiler for writing deterministic network traffic to .pcap files")
        .arg(
            Arg::new("input")
                .help("Path to the .fasm source file")
                .required(true)
                .index(1),
        )
        .arg(
            Arg::new("output")
                .short('o')
                .long("output")
                .help("Path to the output PCAP file")
                .default_value("output.pcap"),
        )
        .get_matches();

    let file = matches
        .get_one::<String>("input")
        .ok_or_else(|| miette::miette!("Missing input file"))?;
    let output_pcap = matches
        .get_one::<String>("output")
        .map(|s| s.as_str())
        .unwrap_or("output.pcap");

    let code = fs::read_to_string(file).into_diagnostic()?;

    let program =
        parse_program(&code).map_err(|e| miette::Report::new(e).with_source_code(code.clone()))?;

    println!(
        "Successfully parsed {} hosts, {} flows",
        program.hosts.len(),
        program.flows.len(),
    );

    println!("Starting PCAP compilation...");
    generate_pcap(&program, output_pcap).map_err(|e| miette::miette!("Backend error: {}", e))?;

    println!("Successfully generated {}", output_pcap);
    Ok(())
}
