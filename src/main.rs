use std::fs;
use frameassembly::backend::generate_pcap;
use frameassembly::parser::parse_program;

fn main() {
    let filename = std::env::args().nth(1).unwrap_or_else(|| "CODE.txt".to_string());

    let code = match fs::read_to_string(&filename) {
        Ok(content) => content,
        Err(error) => {
            eprintln!("Error reading file '{}': {}", filename, error);
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
        "Successfully parsed {} assignments, {} macros, and {} compile invocations",
        program.assignments.len(),
        program.macros.len(),
        program.compile_block.len()
    );

    let output_pcap = "output.pcap";
    match generate_pcap(&program, output_pcap) {
        Ok(_) => println!("Successfully generated {}", output_pcap),
        Err(e) => {
            eprintln!("Backend error: {}", e);
            std::process::exit(1);
        }
    }
}
