use crate::ast::*;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::net::IpAddr;
use core::str::FromStr;

pub type ParseResult<'a, T> = Result<(&'a str, T), String>;

/// Helper to skip whitespace and comments
pub fn skip_whitespace(mut input: &str) -> &str {
    loop {
        input = input.trim_start();
        if input.starts_with("//") {
            if let Some(pos) = input.find('\n') {
                input = &input[pos + 1..];
            } else {
                return "";
            }
        } else {
            break;
        }
    }
    input
}

/// Helper to parse a specific string literal (tag)
pub fn tag<'a>(input: &'a str, target: &str) -> ParseResult<'a, ()> {
    let input = skip_whitespace(input);
    if let Some(stripped) = input.strip_prefix(target) {
        Ok((stripped, ()))
    } else {
        Err(alloc::format!("Expected '{}'", target))
    }
}

/// Helper to parse an identifier (alphanumeric and underscores)
pub fn parse_ident(input: &str) -> ParseResult<'_, String> {
    let input = skip_whitespace(input);
    let mut len = 0;
    for c in input.chars() {
        if c.is_alphanumeric() || c == '_' {
            len += c.len_utf8();
        } else {
            break;
        }
    }
    if len > 0 {
        let ident = &input[..len];
        match ident {
            "HOST" | "FLOW" | "IP" | "MAC" | "COMPILE" | "LOOP" | "TCP" | "UDP" | "SYN" | "ACK"
            | "SRCPORT" | "DSTPORT" | "PORT" => {
                Err(alloc::format!("'{}' is a reserved keyword", ident))
            }
            _ => Ok((&input[len..], ident.to_string())),
        }
    } else {
        Err("Expected identifier".to_string())
    }
}

/// Parse an IP address (IPv4 or IPv6)
fn parse_ip(input: &str) -> ParseResult<'_, IpAddr> {
    let input = skip_whitespace(input);
    let mut len = 0;
    for c in input.chars() {
        if c.is_ascii_digit() || c == '.' {
            len += c.len_utf8();
        } else {
            break;
        }
    }
    if len > 0 {
        let ip_str = &input[..len];
        match IpAddr::from_str(ip_str) {
            Ok(ip) => Ok((&input[len..], ip)),
            Err(_) => Err("Invalid IP address".to_string()),
        }
    } else {
        Err("Expected IP address".to_string())
    }
}

/// Parse an unsigned 16-bit integer (e.g., a port or length)
pub fn parse_u16(input: &str) -> ParseResult<'_, u16> {
    let input = skip_whitespace(input);
    let mut len = 0;
    for c in input.chars() {
        if c.is_ascii_digit() {
            len += c.len_utf8();
        } else {
            break;
        }
    }
    if len > 0 {
        let port_str = &input[..len];
        match u16::from_str(port_str) {
            Ok(port) => Ok((&input[len..], port)),
            Err(_) => Err("Invalid port number".to_string()),
        }
    } else {
        Err("Expected port number".to_string())
    }
}

/// Parse an unsigned 32-bit integer (e.g., sequence number)
pub fn parse_u32(input: &str) -> ParseResult<'_, u32> {
    let input = skip_whitespace(input);
    let mut len = 0;
    for c in input.chars() {
        if c.is_ascii_digit() {
            len += c.len_utf8();
        } else {
            break;
        }
    }
    if len > 0 {
        let num_str = &input[..len];
        match u32::from_str(num_str) {
            Ok(num) => Ok((&input[len..], num)),
            Err(_) => Err("Invalid u32".to_string()),
        }
    } else {
        Err("Expected number".to_string())
    }
}

/// Parse a string literal enclosed in double quotes
pub fn parse_string_lit(input: &str) -> ParseResult<'_, String> {
    let (mut rest, _) = tag(input, "\"")?;
    let mut len = 0;
    for c in rest.chars() {
        if c != '"' {
            len += c.len_utf8();
        } else {
            break;
        }
    }
    let content = &rest[..len];
    rest = &rest[len..];
    let (rest, _) = tag(rest, "\"")?;
    Ok((rest, content.to_string()))
}

/// Parse a MAC address (e.g. 02:00:00:00:00:01)
fn parse_mac(input: &str) -> ParseResult<'_, [u8; 6]> {
    let input = skip_whitespace(input);
    let mut len = 0;
    for c in input.chars() {
        if c.is_ascii_hexdigit() || c == ':' {
            len += c.len_utf8();
        } else {
            break;
        }
    }
    if len > 0 {
        let mac_str = &input[..len];
        let parts: Vec<&str> = mac_str.split(':').collect();
        if parts.len() == 6 {
            let mut mac = [0u8; 6];
            for i in 0..6 {
                if let Ok(byte) = u8::from_str_radix(parts[i], 16) {
                    mac[i] = byte;
                } else {
                    return Err("Invalid MAC address byte".to_string());
                }
            }
            return Ok((&input[len..], mac));
        } else {
            return Err("Invalid MAC address format".to_string());
        }
    }
    Err("Expected MAC address".to_string())
}

/// Parse a HOST block: `HOST name { IP x.x.x.x MAC xx:xx... }`
fn parse_host_def(input: &str) -> ParseResult<'_, HostDef> {
    let (rest, _) = tag(input, "HOST")?;
    let (rest, name) = parse_ident(rest)?;
    let (mut rest, _) = tag(rest, "{")?;

    let mut ip = None;
    let mut mac = None;

    loop {
        if let Ok((new_rest, _)) = tag(rest, "IP") {
            let (new_rest, val) = parse_ip(new_rest)?;
            ip = Some(val);
            rest = new_rest;
        } else if let Ok((new_rest, _)) = tag(rest, "MAC") {
            let (new_rest, val) = parse_mac(new_rest)?;
            mac = Some(val);
            rest = new_rest;
        } else {
            break;
        }
    }

    let (rest, _) = tag(rest, "}")?;

    let ip = ip.ok_or_else(|| "HOST block must contain an IP".to_string())?;

    Ok((rest, HostDef { name, ip, mac }))
}

/// Parse a direction indicator
fn parse_direction(input: &str) -> ParseResult<'_, Direction> {
    if let Ok((rest, _)) = tag(input, "->") {
        Ok((rest, Direction::LeftToRight))
    } else if let Ok((rest, _)) = tag(input, "<-") {
        Ok((rest, Direction::RightToLeft))
    } else {
        Err("Expected '->' or '<-'".to_string())
    }
}

/// Parse a single TCP flag
fn parse_tcp_flag(input: &str) -> ParseResult<'_, TcpFlag> {
    if let Ok((rest, _)) = tag(input, "SYN") {
        Ok((rest, TcpFlag::Syn))
    } else if let Ok((rest, _)) = tag(input, "ACK") {
        Ok((rest, TcpFlag::Ack))
    } else {
        Err("Expected 'SYN' or 'ACK'".to_string())
    }
}

/// Parse a frame statement inside a template: `src -> dst tcp syn ack seq=1 len=64240 payload="test"`
fn parse_frame_statement(input: &str) -> ParseResult<'_, FrameStatement> {
    let (rest, caller) = parse_ident(input)?;
    let (rest, dir) = parse_direction(rest)?;
    let (rest, callee) = parse_ident(rest)?;

    let (mut rest, protocol) = if let Ok((new_rest, _)) = tag(rest, "UDP") {
        (new_rest, Protocol::Udp)
    } else if let Ok((new_rest, _)) = tag(rest, "TCP") {
        (new_rest, Protocol::Tcp)
    } else {
        return Err("Expected 'TCP' or 'UDP'".to_string());
    };

    let mut flags = Vec::new();

    let mut seq = None;
    let mut win = None;
    let mut payload = None;
    let mut wait = None;
    let mut src_port = None;
    let mut dst_port = None;

    loop {
        if let Ok((new_rest, _)) = tag(rest, "SRCPORT") {
            let new_rest = tag(new_rest, "=").map(|(r, _)| r).unwrap_or(new_rest);
            let (new_rest, val) = parse_u16(new_rest)?;
            src_port = Some(val);
            rest = new_rest;
        } else if let Ok((new_rest, _)) = tag(rest, "DSTPORT") {
            let new_rest = tag(new_rest, "=").map(|(r, _)| r).unwrap_or(new_rest);
            let (new_rest, val) = parse_u16(new_rest)?;
            dst_port = Some(val);
            rest = new_rest;

        } else if let Ok((new_rest, _)) = tag(rest, "SEQ") {
            let new_rest = tag(new_rest, "=").map(|(r, _)| r).unwrap_or(new_rest);
            let (new_rest, val) = parse_u32(new_rest)?;
            seq = Some(val);
            rest = new_rest;
        } else if let Ok((new_rest, _)) = tag(rest, "WIN") {
            let new_rest = tag(new_rest, "=").map(|(r, _)| r).unwrap_or(new_rest);
            let (new_rest, val) = parse_u16(new_rest)?;
            win = Some(val);
            rest = new_rest;
        } else if let Ok((new_rest, _)) = tag(rest, "PAYLOAD") {
            let new_rest = tag(new_rest, "=").map(|(r, _)| r).unwrap_or(new_rest);
            let (new_rest, val) = parse_string_lit(new_rest)?;
            payload = Some(val);
            rest = new_rest;
        } else if let Ok((new_rest, _)) = tag(rest, "WAIT") {
            let new_rest = tag(new_rest, "=").map(|(r, _)| r).unwrap_or(new_rest);
            let (new_rest, val) = parse_u32(new_rest)?;

            // Parse suffix
            let (new_rest, final_val) = if let Ok((after_suffix, _)) = tag(new_rest, "ms") {
                (after_suffix, val as u64 * 1_000)
            } else if let Ok((after_suffix, _)) = tag(new_rest, "m") {
                (after_suffix, val as u64 * 60_000_000)
            } else if let Ok((after_suffix, _)) = tag(new_rest, "s") {
                (after_suffix, val as u64 * 1_000_000)
            } else {
                return Err("Expected time suffix (ms, s, m)".to_string());
            };

            wait = Some(final_val);
            rest = new_rest;
        } else if let Ok((new_rest, flag)) = parse_tcp_flag(rest) {
            flags.push(flag);
            rest = new_rest;
        } else {
            break;
        }
    }

    if protocol == Protocol::Tcp && flags.is_empty() {
        return Err("Expected at least one TCP flag (SYN, ACK)".to_string());
    }

    Ok((
        rest,
        FrameStatement {
            caller,
            dir,
            callee,
            protocol,
            src_port,
            dst_port,
            flags,
            seq,
            win,
            payload,
            wait,
        },
    ))
}

/// Parse a flow definition: `FLOW name(arg1, arg2) { ... }`
fn parse_flow_def(input: &str) -> ParseResult<'_, FlowDef> {
    let (rest, _) = tag(input, "FLOW")?;
    let (rest, name) = parse_ident(rest)?;
    let (mut rest, _) = tag(rest, "(")?;

    let mut params = Vec::new();
    if let Ok((new_rest, param)) = parse_ident(rest) {
        params.push(param);
        rest = new_rest;
        while let Ok((new_rest, _)) = tag(rest, ",") {
            let (new_rest2, param) = parse_ident(new_rest)?;
            params.push(param);
            rest = new_rest2;
        }
    }
    let (rest, _) = tag(rest, ")")?;
    let (mut rest, _) = tag(rest, "{")?;

    let mut statements = Vec::new();
    while let Ok((new_rest, stmt)) = parse_frame_statement(rest) {
        statements.push(stmt);
        rest = new_rest;
    }

    let (rest, _) = tag(rest, "}")?;
    Ok((
        rest,
        FlowDef {
            name,
            params,
            statements,
        },
    ))
}

/// Parse a flow argument (just a variable)
fn parse_argument(input: &str) -> ParseResult<'_, Argument> {
    let (rest, var) = parse_ident(input)?;
    Ok((rest, Argument::Variable(var)))
}

/// Parse a template invocation inside the run/compile block
fn parse_template_invocation(input: &str) -> ParseResult<'_, TemplateInvocation> {
    let (rest, name) = parse_ident(input)?;
    let (mut rest, _) = tag(rest, "(")?;

    let mut args = Vec::new();
    if let Ok((new_rest, arg)) = parse_argument(rest) {
        args.push(arg);
        rest = new_rest;
        while let Ok((new_rest, _)) = tag(rest, ",") {
            let (new_rest2, arg) = parse_argument(new_rest)?;
            args.push(arg);
            rest = new_rest2;
        }
    }
    let (rest, _) = tag(rest, ")")?;
    Ok((rest, TemplateInvocation { name, args }))
}

/// Parse a statement in the block, which can be an invocation or a loop
fn parse_run_statement(input: &str) -> ParseResult<'_, RunStatement> {
    if let Ok((rest, _)) = tag(input, "LOOP") {
        let (rest_after_loop, count) = match parse_u32(rest) {
            Ok((r, c)) => (r, Some(c)),
            Err(_) => (rest, None),
        };
        let (mut rest_block, _) = tag(rest_after_loop, "{")?;

        let mut invocations = Vec::new();
        while let Ok((new_rest, inv)) = parse_template_invocation(rest_block) {
            invocations.push(inv);
            rest_block = new_rest;
        }

        let (final_rest, _) = tag(rest_block, "}")?;
        Ok((final_rest, RunStatement::Loop(count, invocations)))
    } else {
        let (rest, inv) = parse_template_invocation(input)?;
        Ok((rest, RunStatement::Invocation(inv)))
    }
}

/// Parse the compile block: `compile { ... }`
fn parse_compile_block(input: &str) -> ParseResult<'_, Vec<RunStatement>> {
    if let Ok((rest, _)) = tag(input, "COMPILE") {
        let (mut rest, _) = tag(rest, "{")?;
        let mut statements = Vec::new();
        while let Ok((new_rest, stmt)) = parse_run_statement(rest) {
            if let RunStatement::Loop(None, _) = &stmt {
                return Err("Infinite loops are not allowed in compile blocks (compiling infinite iterations inside a PCAP is not supported)".to_string());
            }
            statements.push(stmt);
            rest = new_rest;
        }
        let (rest, _) = tag(rest, "}")?;
        Ok((rest, statements))
    } else {
        Err("Expected 'COMPILE'".to_string())
    }
}

/// Top-level parser for the entire DSL file
pub fn parse_program(mut input: &str) -> Result<Program, String> {
    let mut hosts = Vec::new();
    let mut flows = Vec::new();
    let mut compile_block = None;

    loop {
        input = skip_whitespace(input);
        if input.is_empty() {
            break;
        }

        if let Ok((rest, f)) = parse_flow_def(input) {
            flows.push(f);
            input = rest;
        } else if let Ok((rest, h)) = parse_host_def(input) {
            hosts.push(h);
            input = rest;
        } else if let Ok((rest, exec)) = parse_compile_block(input) {
            if compile_block.is_some() {
                return Err("A file cannot contain multiple compile blocks".to_string());
            }
            compile_block = Some(exec);
            input = rest;
        } else {
            return Err(alloc::format!(
                "Syntax error near: '{}'",
                &input[..core::cmp::min(input.len(), 20)]
            ));
        }
    }

    let compile_block =
        compile_block.ok_or_else(|| "No 'COMPILE' block found in program".to_string())?;

    Ok(Program {
        hosts,
        flows,
        compile_block,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_parse_target_syntax() {
        let code = r#"
            HOST my_client { IP 10.0.0.1 MAC 00:11:22:33:44:55 }
            HOST google_dns { IP 8.8.8.8 }

            FLOW tcp_handshake(src, dst) {
                src -> dst TCP SRCPORT 12345 DSTPORT 80 SYN
                src <- dst TCP SRCPORT 80 DSTPORT 12345 SYN ACK
                src -> dst TCP SRCPORT 12345 DSTPORT 80 ACK
            }

            COMPILE {
                LOOP 100 {
                    tcp_handshake(my_client, google_dns)
                }
                tcp_handshake(my_client, google_dns)
            }
        "#;
        let prog = parse_program(code).unwrap();
        assert_eq!(prog.hosts.len(), 2);
        assert_eq!(prog.flows.len(), 1);
        assert_eq!(prog.compile_block.len(), 2);
    }
}
