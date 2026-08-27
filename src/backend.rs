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
    let statements = match &program.execution {
        ExecutionBlock::Compile(stmts) => stmts,
        _ => return Err("Expected a compile block for PCAP generation".into()),
    };

    let mut env = HashMap::new();
    for assign in &program.assignments {
        env.insert(assign.name.clone(), assign.value.clone());
    }

    let mut templates = HashMap::new();
    for mac in &program.templates {
        templates.insert(mac.name.clone(), mac);
    }

    let mut pcap = PcapWriter::create(output_path)
        .map_err(|e| alloc::format!("Failed to create PCAP file: {}", e))?;

    let mut current_time_us: u64 = 1_700_000_000_000_000;

    let mut execute_invocation = |invocation: &TemplateInvocation| -> Result<(), String> {
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

        let mut param_map = HashMap::new();
        for (i, param_name) in mac.params.iter().enumerate() {
            let endpoint = resolve_endpoint(&invocation.args[i], &env)?;
            param_map.insert(param_name.clone(), endpoint);
        }

        for stmt in &mac.statements {
            let caller_ep = param_map
                .get(&stmt.caller)
                .ok_or_else(|| alloc::format!("Unknown caller '{}' in template", stmt.caller))?;
            let callee_ep = param_map
                .get(&stmt.callee)
                .ok_or_else(|| alloc::format!("Unknown callee '{}' in template", stmt.callee))?;

            let (src_ip, src_port, dst_ip, dst_port) = match stmt.dir {
                Direction::Src => (caller_ep.0, caller_ep.1, callee_ep.0, callee_ep.1),
                Direction::Dst => (callee_ep.0, callee_ep.1, caller_ep.0, caller_ep.1),
            };

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

/// Evaluates the AST and injects raw datalink layer packets using pnet.
pub fn execute_traffic(program: &Program, interface_name: &str) -> Result<(), String> {
    let statements = match &program.execution {
        ExecutionBlock::Run(stmts) => stmts,
        _ => return Err("Expected a run block for live traffic execution".into()),
    };

    let mut env = HashMap::new();
    for assign in &program.assignments {
        env.insert(assign.name.clone(), assign.value.clone());
    }

    let mut templates = HashMap::new();
    for mac in &program.templates {
        templates.insert(mac.name.clone(), mac);
    }

    let interfaces = pnet::datalink::interfaces();
    let interface = interfaces
        .into_iter()
        .find(|iface| iface.name == interface_name)
        .ok_or_else(|| {
            let available: Vec<_> = pnet::datalink::interfaces().into_iter().map(|i| i.name.clone()).collect();
            alloc::format!("Interface '{}' not found. Available interfaces: {:?}", interface_name, available)
        })?;

    let (mut tx, _rx) = match pnet::datalink::channel(&interface, Default::default()) {
        Ok(pnet::datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => return Err("Unhandled channel type".into()),
        Err(e) => return Err(alloc::format!("Failed to create datalink channel: {}", e)),
    };

    let mut execute_invocation = |invocation: &TemplateInvocation| -> Result<(), String> {
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

        let mut param_map = HashMap::new();
        for (i, param_name) in mac.params.iter().enumerate() {
            let endpoint = resolve_endpoint(&invocation.args[i], &env)?;
            param_map.insert(param_name.clone(), endpoint);
        }

        for stmt in &mac.statements {
            let caller_ep = param_map
                .get(&stmt.caller)
                .ok_or_else(|| alloc::format!("Unknown caller '{}' in template", stmt.caller))?;
            let callee_ep = param_map
                .get(&stmt.callee)
                .ok_or_else(|| alloc::format!("Unknown callee '{}' in template", stmt.callee))?;

            let (src_ip, src_port, dst_ip, dst_port) = match stmt.dir {
                Direction::Src => (caller_ep.0, caller_ep.1, callee_ep.0, callee_ep.1),
                Direction::Dst => (callee_ep.0, callee_ep.1, caller_ep.0, caller_ep.1),
            };

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
            
            tx.send_to(&packet_data, None)
                .ok_or_else(|| "Failed to send packet to channel".to_string())?
                .map_err(|e| alloc::format!("Error sending packet: {}", e))?;

            let wait_time = stmt.wait.unwrap_or(10);
            if wait_time > 0 {
                std::thread::sleep(std::time::Duration::from_micros(wait_time));
            }
        }
        Ok(())
    };

    for stmt in statements {
        match stmt {
            RunStatement::Invocation(inv) => {
                execute_invocation(inv)?;
            }
            RunStatement::Loop(count, invocations) => {
                if let Some(c) = count {
                    for _ in 0..*c {
                        for inv in invocations {
                            execute_invocation(inv)?;
                        }
                    }
                } else {
                    // Infinite loop for live generation
                    loop {
                        for inv in invocations {
                            execute_invocation(inv)?;
                        }
                    }
                }
            }
        }
    }

    Ok(())
}
