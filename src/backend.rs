use crate::ast::*;
use crate::packet::build_tcp_packet;
use crate::pcap::PcapWriter;
use alloc::string::String;
use core::net::IpAddr;
use std::collections::HashMap;

/// Resolves an IP and port for a given argument in a template invocation.
fn resolve_endpoint(
    arg: &Argument,
    env: &HashMap<String, AssignValue>,
) -> Result<(IpAddr, u16), String> {
    match arg {
        Argument::Variable(var_name) => {
            if let Some(val) = env.get(var_name) {
                match val {
                    AssignValue::Endpoint(ip, port) => Ok((*ip, *port)),
                    AssignValue::Ip(_) => Err(alloc::format!(
                        "Variable '{}' has no port assigned, but one is required",
                        var_name
                    )),
                }
            } else {
                Err(alloc::format!("Undefined variable: '{}'", var_name))
            }
        }
        Argument::VarWithPort(var_name, override_port) => {
            if let Some(val) = env.get(var_name) {
                match val {
                    AssignValue::Endpoint(ip, _) | AssignValue::Ip(ip) => Ok((*ip, *override_port)),
                }
            } else {
                Err(alloc::format!("Undefined variable: '{}'", var_name))
            }
        }
    }
}

/// Evaluates the AST and generates the PCAP file.
pub fn generate_pcap(program: &Program, output_path: &str) -> Result<(), String> {
    // 1. Build the environment from global assignments
    let mut env = HashMap::new();
    for assign in &program.assignments {
        env.insert(assign.name.clone(), assign.value.clone());
    }

    // 2. Build a template lookup table
    let mut templates = HashMap::new();
    for mac in &program.templates {
        templates.insert(mac.name.clone(), mac);
    }

    // 3. Prepare the PCAP writer
    let mut pcap = PcapWriter::create(output_path)
        .map_err(|e| alloc::format!("Failed to create PCAP file: {}", e))?;

    // Start mock epoch at a fixed point
    let mut current_time_us: u64 = 1_700_000_000_000_000;

    // 4. Evaluate the compile block
    for invocation in &program.compile_block {
        let mac = templates
            .get(&invocation.name)
            .ok_or_else(|| alloc::format!("Undefined template: '{}'", invocation.name))?;

        if mac.params.len() != invocation.args.len() {
            return Err(alloc::format!(
                "Template '{}' expects {} arguments, got {}",
                mac.name,
                mac.params.len(),
                invocation.args.len()
            ));
        }

        // Map parameter names to their resolved endpoints for this invocation
        let mut param_map = HashMap::new();
        for (i, param_name) in mac.params.iter().enumerate() {
            let endpoint = resolve_endpoint(&invocation.args[i], &env)?;
            param_map.insert(param_name.clone(), endpoint);
        }

        // 5. Expand statements and craft packets
        for stmt in &mac.statements {
            let caller_ep = param_map
                .get(&stmt.caller)
                .ok_or_else(|| alloc::format!("Unknown caller '{}' in template", stmt.caller))?;
            let callee_ep = param_map
                .get(&stmt.callee)
                .ok_or_else(|| alloc::format!("Unknown callee '{}' in template", stmt.callee))?;

            // Determine actual source and destination based on the direction arrow
            let (src_ip, src_port, dst_ip, dst_port) = match stmt.dir {
                Direction::Src => (caller_ep.0, caller_ep.1, callee_ep.0, callee_ep.1),
                Direction::Dst => (callee_ep.0, callee_ep.1, caller_ep.0, caller_ep.1),
            };

            // Calculate wait time
            let wait_time = stmt.wait.unwrap_or(10);
            current_time_us += wait_time;

            let syn = stmt.flags.contains(&TcpFlag::Syn);
            let ack = stmt.flags.contains(&TcpFlag::Ack);
            
            let payload_bytes = stmt.payload.as_deref().map(|s| s.as_bytes());

            let reverse_macs = stmt.dir == Direction::Dst;

            let packet_data = build_tcp_packet(
                src_ip, src_port, 
                dst_ip, dst_port, 
                syn, ack,
                stmt.seq,
                stmt.win,
                payload_bytes,
                reverse_macs,
            );
            
            pcap.write_packet(&packet_data, current_time_us)
                .map_err(|e| alloc::format!("Failed to write packet: {}", e))?;
        }
    }

    Ok(())
}
