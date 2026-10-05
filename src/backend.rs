use crate::ast::*;
use crate::packet::{build_tcp_packet, build_udp_packet};
use crate::pcap::PcapWriter;
use alloc::string::String;
use rasn::prelude::*;
use rasn_snmp::v2::VarBind;
use std::collections::HashMap;



/// Resolves a host definition for a given argument in a flow invocation.
fn resolve_endpoint<'a>(
    arg: &Argument<'a>,
    env: &HashMap<&'a str, HostDef<'a>>,
) -> Result<HostDef<'a>, String> {
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
        env.insert(host.name, host.clone());
    }

    let mut flows = HashMap::new();
    for f in &program.flows {
        flows.insert(f.name, f);
    }

    let mut pcap = PcapWriter::create(output_path)
        .map_err(|e| alloc::format!("Failed to create PCAP file: {}", e))?;

    let mut current_time_ns: u64 = 1_700_000_000_000_000_000;

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
            param_map.insert(*param_name, endpoint);
        }

        for stmt in &flow.statements {
            let caller_ep = param_map
                .get(&stmt.caller)
                .ok_or_else(|| alloc::format!("Unknown caller '{}' in flow", stmt.caller))?;
            let callee_ep = param_map
                .get(&stmt.callee)
                .ok_or_else(|| alloc::format!("Unknown callee '{}' in flow", stmt.callee))?;

            // Resolve Source and Destination based on Direction
            let (src_host, dst_host) = match stmt.dir {
                Direction::LeftToRight => (caller_ep, callee_ep),
                Direction::RightToLeft => (callee_ep, caller_ep),
            };

            let src_ip = src_host.ip;
            let dst_ip = dst_host.ip;
            let src_mac = src_host.mac.unwrap_or([0, 0, 0, 0, 0, 0]);
            let dst_mac = dst_host.mac.unwrap_or([0, 0, 0, 0, 0, 0]);

            let src_port = stmt.src_port.unwrap_or(12345);
            let dst_port = stmt.dst_port.unwrap_or(match stmt.protocol {
                Protocol::Snmp1 | Protocol::Snmp2 | Protocol::Snmp3 => 162,
                _ => 80,
            });

            let wait_time = stmt.wait.unwrap_or(10_000_000); // 10ms default
            current_time_ns += wait_time;

            let syn = stmt.flags.contains(&TcpFlag::Syn);
            let ack = stmt.flags.contains(&TcpFlag::Ack);

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
                    stmt.payload.map(|s| s.as_bytes()),
                    src_mac,
                    dst_mac,
                )
                .map_err(|e| alloc::format!("{:?}", e))?,
                Protocol::Udp => build_udp_packet(
                    src_ip,
                    src_port,
                    dst_ip,
                    dst_port,
                    stmt.payload.map(|s| s.as_bytes()),
                    src_mac,
                    dst_mac,
                )
                .map_err(|e| alloc::format!("{:?}", e))?,
                Protocol::Snmp1 => {
                    use rasn_snmp::v1::{Message, Trap, Pdus};
                    use rasn::types::{Integer, ObjectIdentifier, OctetString};
                    let community_str = stmt.community.unwrap_or("public");
                    let community = OctetString::from(community_str.as_bytes().to_vec());
                    let oid_str = stmt.oid.unwrap_or("1.3.6.1.4.1");
                    let mut oid_vec = alloc::vec::Vec::new();
                    for s in oid_str.trim_start_matches('.').split('.') {
                        match s.parse::<u32>() {
                            Ok(val) => oid_vec.push(val),
                            Err(_) => {
                                return Err(alloc::format!(
                                    "Invalid OID segment: '{}' in '{}'",
                                    s,
                                    oid_str
                                ));
                            }
                        }
                    }
                    let trap_oid = ObjectIdentifier::new(oid_vec)
                        .unwrap_or_else(|| ObjectIdentifier::new(vec![1, 3, 6, 1, 4, 1]).unwrap());

                    let agent_ip = match src_ip {
                        core::net::IpAddr::V4(addr) => addr.octets(),
                        _ => {
                            return Err(alloc::format!(
                                "SNMPv1 Trap requires IPv4 address, got IPv6"
                            ));
                        }
                    };

                    let trap = Trap {
                        enterprise: trap_oid,
                        agent_addr: rasn_smi::v1::NetworkAddress::Internet(rasn_smi::v1::IpAddress(agent_ip.into())),
                        generic_trap: Integer::from(6), // EnterpriseSpecific
                        specific_trap: Integer::from(1),
                        time_stamp: rasn_smi::v1::TimeTicks(stmt.sys_up_time.unwrap_or(0)),
                        variable_bindings: vec![],
                    };

                    let message = Message {
                        version: Integer::from(0),
                        community,
                        data: Pdus::Trap(trap),
                    };

                    let snmp_payload = rasn::ber::encode(&message)
                        .map_err(|e| alloc::format!("SNMP1 encode error: {:?}", e))?;
                    build_udp_packet(
                        src_ip,
                        src_port,
                        dst_ip,
                        dst_port,
                        Some(snmp_payload.as_slice()),
                        src_mac,
                        dst_mac,
                    )
                    .map_err(|e| alloc::format!("{:?}", e))?
                }
                Protocol::Snmp2 => {
                    use rasn::types::{Integer, ObjectIdentifier, OctetString};
                    use rasn_snmp::v2::Pdus;
                    use rasn_snmp::v2::{Pdu, VarBind, VarBindValue};
                    use rasn_snmp::v2c::Message;

                    let community_str = stmt.community.unwrap_or("public");
                    let community = OctetString::from(community_str.as_bytes().to_vec());

                    let sys_up_time_oid =
                        ObjectIdentifier::new(vec![1, 3, 6, 1, 2, 1, 1, 3, 0]).unwrap();
                    let snmp_trap_oid_name =
                        ObjectIdentifier::new(vec![1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0]).unwrap();

                    let oid_str = stmt.oid.unwrap_or("1.3.6.1.6.3.1.1.5.3");
                    let mut oid_vec = alloc::vec::Vec::new();
                    for s in oid_str.trim_start_matches('.').split('.') {
                        match s.parse::<u32>() {
                            Ok(val) => oid_vec.push(val),
                            Err(_) => {
                                return Err(alloc::format!(
                                    "Invalid OID segment: '{}' in '{}'",
                                    s,
                                    oid_str
                                ));
                            }
                        }
                    }
                    let requested_trap_oid = ObjectIdentifier::new(oid_vec).unwrap_or_else(|| {
                        ObjectIdentifier::new(vec![1, 3, 6, 1, 6, 3, 1, 1, 5, 3]).unwrap()
                    });

                    // Use rasn_smi types that rasn_snmp depends on. If rasn_smi is not explicitly in dependencies,
                    // we'll need to add it or use re-exports. We will try rasn_smi first.
                    let varbinds = vec![
                        VarBind {
                            name: sys_up_time_oid,
                            value: VarBindValue::Value(
                                rasn_smi::v2::ObjectSyntax::ApplicationWide(
                                    rasn_smi::v2::ApplicationSyntax::Ticks(
                                        rasn_smi::v1::TimeTicks(stmt.sys_up_time.unwrap_or(0)),
                                    ),
                                ),
                            ),
                        },
                        VarBind {
                            name: snmp_trap_oid_name,
                            value: VarBindValue::Value(rasn_smi::v2::ObjectSyntax::Simple(
                                rasn_smi::v2::SimpleSyntax::ObjectId(requested_trap_oid),
                            )),
                        },
                    ];

                    let pdu = Pdu {
                        request_id: 1,
                        error_status: 0,
                        error_index: 0,
                        variable_bindings: varbinds,
                    };

                    let message = Message {
                        version: Integer::from(1),
                        community,
                        data: Pdus::Trap(rasn_snmp::v2::Trap(pdu)),
                    };

                    let snmp_payload = rasn::ber::encode(&message)
                        .map_err(|e| alloc::format!("SNMP2 encode error: {:?}", e))?;
                    build_udp_packet(
                        src_ip,
                        src_port,
                        dst_ip,
                        dst_port,
                        Some(snmp_payload.as_slice()),
                        src_mac,
                        dst_mac,
                    )
                    .map_err(|e| alloc::format!("{:?}", e))?
                }
                Protocol::Snmp3 => {
                    use rasn::types::{Integer, ObjectIdentifier, OctetString};
                    use rasn_snmp::v2::{Pdu, Pdus, VarBind, VarBindValue};
                    use rasn_snmp::v3::{
                        HeaderData, Message, ScopedPdu, ScopedPduData, USMSecurityParameters,
                    };

                    let user_str = stmt.user.unwrap_or("admin");
                    let user = OctetString::from(user_str.as_bytes().to_vec());

                    let sys_up_time_oid =
                        ObjectIdentifier::new(vec![1, 3, 6, 1, 2, 1, 1, 3, 0]).unwrap();
                    let snmp_trap_oid_name =
                        ObjectIdentifier::new(vec![1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0]).unwrap();

                    let oid_str = stmt.oid.unwrap_or("1.3.6.1.6.3.1.1.5.3");
                    let mut oid_vec = alloc::vec::Vec::new();
                    for s in oid_str.trim_start_matches('.').split('.') {
                        match s.parse::<u32>() {
                            Ok(val) => oid_vec.push(val),
                            Err(_) => {
                                return Err(alloc::format!(
                                    "Invalid OID segment: '{}' in '{}'",
                                    s,
                                    oid_str
                                ));
                            }
                        }
                    }
                    let requested_trap_oid = ObjectIdentifier::new(oid_vec).unwrap_or_else(|| {
                        ObjectIdentifier::new(vec![1, 3, 6, 1, 6, 3, 1, 1, 5, 3]).unwrap()
                    });

                    let varbinds = vec![
                        VarBind {
                            name: sys_up_time_oid,
                            value: VarBindValue::Value(
                                rasn_smi::v2::ObjectSyntax::ApplicationWide(
                                    rasn_smi::v2::ApplicationSyntax::Ticks(
                                        rasn_smi::v1::TimeTicks(stmt.sys_up_time.unwrap_or(0)),
                                    ),
                                ),
                            ),
                        },
                        VarBind {
                            name: snmp_trap_oid_name,
                            value: VarBindValue::Value(rasn_smi::v2::ObjectSyntax::Simple(
                                rasn_smi::v2::SimpleSyntax::ObjectId(requested_trap_oid),
                            )),
                        },
                    ];

                    let pdu = Pdu {
                        request_id: 1,
                        error_status: 0,
                        error_index: 0,
                        variable_bindings: varbinds,
                    };

                    let scoped_pdu = ScopedPdu {
                        engine_id: OctetString::from(vec![0x80, 0x00, 0x00, 0x00, 0x01]),
                        name: OctetString::from(vec![]),
                        data: Pdus::Trap(rasn_snmp::v2::Trap(pdu)),
                    };

                    let usm_params = USMSecurityParameters {
                        authoritative_engine_id: OctetString::from(vec![
                            0x80, 0x00, 0x00, 0x00, 0x01,
                        ]),
                        authoritative_engine_boots: Integer::from(0),
                        authoritative_engine_time: Integer::from(0),
                        user_name: user,
                        authentication_parameters: OctetString::from(vec![]),
                        privacy_parameters: OctetString::from(vec![]),
                    };

                    let usm_bytes = rasn::ber::encode(&usm_params)
                        .map_err(|e| alloc::format!("USM encode error: {:?}", e))?;

                    let message = Message {
                        version: Integer::from(3), // SNMPv3
                        global_data: HeaderData {
                            message_id: Integer::from(1),
                            max_size: Integer::from(65507),
                            flags: OctetString::from(vec![0]), // NoAuthNoPriv
                            security_model: Integer::from(3),  // USM is 3
                        },
                        security_parameters: OctetString::from(usm_bytes),
                        scoped_data: ScopedPduData::CleartextPdu(scoped_pdu),
                    };

                    let snmp_payload = rasn::ber::encode(&message)
                        .map_err(|e| alloc::format!("SNMP3 encode error: {:?}", e))?;
                    build_udp_packet(
                        src_ip,
                        src_port,
                        dst_ip,
                        dst_port,
                        Some(snmp_payload.as_slice()),
                        src_mac,
                        dst_mac,
                    )
                    .map_err(|e| alloc::format!("{:?}", e))?
                }
            };

            pcap.write_packet(&packet_data, current_time_ns)
                .map_err(|e| alloc::format!("Failed to write packet: {}", e))?;
        }
        Ok(())
    };

    for stmt in statements {
        match stmt {
            RunStatement::Invocation(inv) => execute_invocation(inv)?,
            RunStatement::Loop(count, invocations) => {
                for _ in 0..*count {
                    for inv in invocations {
                        execute_invocation(inv)?;
                    }
                }
            }
        }
    }

    Ok(())
}
