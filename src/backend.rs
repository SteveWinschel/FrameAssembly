use crate::ast::*;
use crate::packet::{build_tcp_packet, build_udp_packet};
use crate::pcap::PcapWriter;
use alloc::string::String;
use std::collections::HashMap;

/// Resolves a host definition for a given argument in a flow invocation.
fn resolve_endpoint(arg: &Argument, env: &HashMap<String, HostDef>) -> Result<HostDef, String> {
    match arg {
        Argument::Variable(var_name) => {
            if let Some(val) = env.get(var_name) {
                Ok(val.clone())
            } else {
                Err(alloc::format!("Undefined variable: '{}'", var_name))
            }
        }
    }
}

/// Evaluates the AST and generates the PCAP file.
pub fn generate_pcap(program: &Program, output_path: &str) -> Result<(), String> {
    let statements = &program.compile_block;

    let mut env = HashMap::new();
    for host in &program.hosts {
        env.insert(host.name.clone(), host.clone());
    }

    let mut flows = HashMap::new();
    for f in &program.flows {
        flows.insert(f.name.clone(), f);
    }

    let mut pcap = PcapWriter::create(output_path)
        .map_err(|e| alloc::format!("Failed to create PCAP file: {}", e))?;

    let mut current_time_us: u64 = 1_700_000_000_000_000;

    let mut execute_invocation = |invocation: &TemplateInvocation| -> Result<(), String> {
        let flow = flows
            .get(&invocation.name)
            .ok_or_else(|| alloc::format!("Undefined flow: '{}'", invocation.name))?;

        if flow.params.len() != invocation.args.len() {
            return Err(alloc::format!(
                "Flow '{}' expects {} arguments, got {}",
                flow.name,
                flow.params.len(),
                invocation.args.len()
            ));
        }

        let mut param_map = HashMap::new();
        for (i, param_name) in flow.params.iter().enumerate() {
            let endpoint = resolve_endpoint(&invocation.args[i], &env)?;
            param_map.insert(param_name.clone(), endpoint);
        }

        for stmt in &flow.statements {
            let caller_ep = param_map
                .get(&stmt.caller)
                .ok_or_else(|| alloc::format!("Unknown caller '{}' in flow", stmt.caller))?;
            let callee_ep = param_map
                .get(&stmt.callee)
                .ok_or_else(|| alloc::format!("Unknown callee '{}' in flow", stmt.callee))?;

            // Resolve Source and Destination based on Direction!
            let (src_host, dst_host) = match stmt.dir {
                Direction::LeftToRight => (caller_ep, callee_ep),
                Direction::RightToLeft => (callee_ep, caller_ep),
            };

            let src_ip = src_host.ip;
            let dst_ip = dst_host.ip;
            let src_mac = src_host.mac.unwrap_or([0, 0, 0, 0, 0, 0]);
            let dst_mac = dst_host.mac.unwrap_or([0, 0, 0, 0, 0, 0]);

            let src_port = stmt.src_port.unwrap_or(12345);
            let dst_port = stmt.dst_port.unwrap_or(80);

            let wait_time = stmt.wait.unwrap_or(10);
            current_time_us += wait_time;

            let syn = stmt.flags.contains(&TcpFlag::Syn);
            let ack = stmt.flags.contains(&TcpFlag::Ack);

            let payload_bytes = stmt.payload.as_deref().map(|s| s.as_bytes());

            let packet_data = match stmt.protocol {
                Protocol::Tcp => build_tcp_packet(
                    src_ip,
                    src_port,
                    dst_ip,
                    dst_port,
                    syn,
                    ack,
                    stmt.seq,
                    stmt.win,
                    payload_bytes,
                    src_mac,
                    dst_mac,
                ),
                Protocol::Udp => build_udp_packet(
                    src_ip,
                    src_port,
                    dst_ip,
                    dst_port,
                    payload_bytes,
                    src_mac,
                    dst_mac,
                ),
            };

            pcap.write_packet(&packet_data, current_time_us)
                .map_err(|e| alloc::format!("Failed to write packet: {}", e))?;
        }
        Ok(())
    };

    for stmt in statements {
        match stmt {
            RunStatement::Invocation(inv) => execute_invocation(inv)?,
            RunStatement::Loop(count, invocations) => {
                // Infinite loop in compile block is rejected by parser, safe to unwrap_or(1)
                let iter_count = count.unwrap_or(1);
                for _ in 0..iter_count {
                    for inv in invocations {
                        execute_invocation(inv)?;
                    }
                }
            }
        }
    }

    Ok(())
}
