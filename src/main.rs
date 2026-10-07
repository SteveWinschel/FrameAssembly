//! The FrameAssembly compiler CLI.
#![warn(missing_docs)]
#![warn(clippy::missing_docs_in_private_items)]
use frameassembly::backend::generate_pcap;
use frameassembly::parser::parse_program;
use miette::{IntoDiagnostic, Result};
use std::env;
use std::fs;

/// The main entry point for the `frameassembly` CLI.
///
/// This reads a `.fasm` file provided via command-line arguments, parses the syntax,
/// and generates the corresponding `output.pcap` file.
///
/// # Examples
/// ```no_run
/// // Run from the command line:
/// // $ frameassembly demo.fasm
/// ```
///
/// # Errors
/// Returns a `miette::Result` error if:
/// * Incorrect CLI arguments are provided.
/// * The input file cannot be read.
/// * Parsing the source file fails.
/// * PCAP generation fails.
fn main() -> Result<()> {
    let mut args = env::args();
    if args.len() != 2 {
        eprintln!("Usage: frameassembly <file.fasm>");
        std::process::exit(1);
    }
    let file = args
        .nth(1)
        .ok_or_else(|| miette::miette!("Usage: frameassembly <file.fasm>"))?;

    let code = fs::read_to_string(&file).into_diagnostic()?;

    let program =
        parse_program(&code).map_err(|e| miette::Report::new(e).with_source_code(code.clone()))?;

    println!(
        "Successfully parsed {} hosts, {} flows",
        program.hosts.len(),
        program.flows.len(),
    );

    let output_pcap = "output.pcap";
    println!("Starting PCAP compilation...");
    generate_pcap(&program, output_pcap).map_err(|e| miette::miette!("Backend error: {}", e))?;

    println!("Successfully generated {}", output_pcap);
    Ok(())
}
