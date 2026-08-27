use clap::Parser;
use frameassembly::cli::Cli;
use frameassembly::parser::parse_program;
use frameassembly::runner::run_program;
use std::fs;

fn main() {
    let cli = Cli::parse();

    let code = match fs::read_to_string(&cli.file) {
        Ok(content) => content,
        Err(error) => {
            eprintln!("Error reading file '{}': {}", cli.file, error);
            std::process::exit(1);
        }
    };

    let program = match parse_program(&code) {
        Ok(parsed_prog) => parsed_prog,
        Err(error) => {
            eprintln!("Parser error: {}", error);
            std::process::exit(1);
        }
    };

    println!(
        "Successfully parsed {} assignments, {} templates",
        program.assignments.len(),
        program.templates.len(),
    );

    if let Err(e) = run_program(&program, cli.interface) {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}
