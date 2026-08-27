use crate::ast::{ExecutionBlock, Program};
use crate::backend::{execute_traffic, generate_pcap};
use std::error::Error;

pub fn run_program(program: &Program, interface_name_opt: Option<String>) -> Result<(), Box<dyn Error>> {
    match &program.execution {
        ExecutionBlock::Compile(_) => {
            let output_pcap = "output.pcap";
            println!("Starting PCAP compilation...");
            match generate_pcap(program, output_pcap) {
                Ok(_) => {
                    println!("Successfully generated {}", output_pcap);
                    Ok(())
                },
                Err(e) => Err(format!("Backend error: {}", e).into()),
            }
        }
        ExecutionBlock::Run(_) => {
            let interface_name = interface_name_opt.ok_or_else(|| {
                "Error: Interface name is required for live generation\nUsage: frameassembly <file> <interface>"
            })?;

            #[cfg(unix)]
            auto_elevate()?;

            println!("Starting live generation on interface: {}", interface_name);
            match execute_traffic(program, &interface_name) {
                Ok(_) => {
                    println!("Successfully completed live traffic generation");
                    Ok(())
                },
                Err(e) => Err(format!("Backend error: {}", e).into()),
            }
        }
    }
}

#[cfg(unix)]
fn auto_elevate() -> Result<(), Box<dyn Error>> {
    if let Ok(output) = std::process::Command::new("id").arg("-u").output() {
        if String::from_utf8_lossy(&output.stdout).trim() != "0" {
            println!("Live generation requires raw sockets. Elevating privileges via sudo...");
            use std::os::unix::process::CommandExt;
            let err = std::process::Command::new("sudo")
                .arg(std::env::current_exe().expect("Failed to get current executable path"))
                .args(std::env::args().skip(1))
                .exec();
            return Err(format!("Failed to elevate privileges: {}", err).into());
        }
    }
    Ok(())
}
