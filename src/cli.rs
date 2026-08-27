use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "frameassembly")]
#[command(about = "A minimal DSL for PCAP and live packet generation", long_about = None)]
pub struct Cli {
    /// The input script file (e.g., CODE.txt)
    #[arg(required = true)]
    pub file: String,

    /// Network interface to use for live generation
    pub interface: Option<String>,
}
