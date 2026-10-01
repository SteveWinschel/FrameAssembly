use frameassembly::backend::generate_pcap;
use frameassembly::parser::parse_program;
use std::env;
use std::fs;

fn main() {
    let mut args = env::args();
    if args.len() != 2 {
        eprintln!("Usage: frameassembly <file>");
        std::process::exit(1);
    }
    let file = args.nth(1).unwrap();

    let code = match fs::read_to_string(&file) {
        Ok(content) => content,
        Err(error) => {
            eprintln!("Error reading file '{}': {}", file, error);
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
        "Successfully parsed {} hosts, {} flows",
        program.hosts.len(),
        program.flows.len(),
    );

    let output_pcap = "output.pcap";
    println!("Starting PCAP compilation...");
    if let Err(e) = generate_pcap(&program, output_pcap) {
        eprintln!("Backend error: {}", e);
        std::process::exit(1);
    } else {
        println!("Successfully generated {}", output_pcap);
    }
}
