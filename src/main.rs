use frameassembly::backend::generate_pcap;
use frameassembly::parser::parse_program;
use miette::{IntoDiagnostic, Result};
use std::env;
use std::fs;

fn main() -> Result<()> {
    let mut args = env::args();
    if args.len() != 2 {
        eprintln!("Usage: frameassembly <file>");
        std::process::exit(1);
    }
    let file = args
        .nth(1)
        .ok_or_else(|| miette::miette!("Usage: frameassembly <file>"))?;

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
