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
    if input.starts_with(target) {
        Ok((&input[target.len()..], ()))
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
            "let" | "template" | "run" | "compile" | "loop" | "tcp" | "syn" | "ack" => {
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

/// Parse an assigned value: either just an IP, or IP:Port
fn parse_assign_value(input: &str) -> ParseResult<'_, AssignValue> {
    let (rest, ip) = parse_ip(input)?;
    if let Ok((rest_after_colon, _)) = tag(rest, ":") {
        let (final_rest, port) = parse_u16(rest_after_colon)?;
        Ok((final_rest, AssignValue::Endpoint(ip, port)))
    } else {
        Ok((rest, AssignValue::Ip(ip)))
    }
}

/// Parse a let assignment: `let name = value`
fn parse_global_assignment(input: &str) -> ParseResult<'_, GlobalAssignment> {
    let (rest, _) = tag(input, "let")?;
    let (rest, name) = parse_ident(rest)?;
    let (rest, _) = tag(rest, "=")?;
    let (rest, value) = parse_assign_value(rest)?;
    Ok((rest, GlobalAssignment { name, value }))
}

/// Parse a direction indicator
fn parse_direction(input: &str) -> ParseResult<'_, Direction> {
    if let Ok((rest, _)) = tag(input, "->") {
        Ok((rest, Direction::Src))
    } else if let Ok((rest, _)) = tag(input, "<-") {
        Ok((rest, Direction::Dst))
    } else {
        Err("Expected '->' or '<-'".to_string())
    }
}

/// Parse a single TCP flag
fn parse_tcp_flag(input: &str) -> ParseResult<'_, TcpFlag> {
    if let Ok((rest, _)) = tag(input, "syn") {
        Ok((rest, TcpFlag::Syn))
    } else if let Ok((rest, _)) = tag(input, "ack") {
        Ok((rest, TcpFlag::Ack))
    } else {
        Err("Expected 'syn' or 'ack'".to_string())
    }
}

/// Parse a frame statement inside a template: `src -> dst tcp syn ack seq=1 len=64240 payload="test"`
fn parse_frame_statement(input: &str) -> ParseResult<'_, FrameStatement> {
    let (rest, caller) = parse_ident(input)?;
    let (rest, dir) = parse_direction(rest)?;
    let (rest, callee) = parse_ident(rest)?;
    let (mut rest, _) = tag(rest, "tcp")?;
    
    let mut flags = Vec::new();
    while let Ok((new_rest, flag)) = parse_tcp_flag(rest) {
        flags.push(flag);
        rest = new_rest;
    }
    
    if flags.is_empty() {
        return Err("Expected at least one TCP flag (syn, ack)".to_string());
    }

    let mut seq = None;
    let mut win = None;
    let mut payload = None;
    let mut wait = None;

    loop {
        if let Ok((new_rest, _)) = tag(rest, "seq") {
            let (new_rest, _) = tag(new_rest, "=")?;
            let (new_rest, val) = parse_u32(new_rest)?;
            seq = Some(val);
            rest = new_rest;
        } else if let Ok((new_rest, _)) = tag(rest, "win") {
            let (new_rest, _) = tag(new_rest, "=")?;
            let (new_rest, val) = parse_u16(new_rest)?;
            win = Some(val);
            rest = new_rest;
        } else if let Ok((new_rest, _)) = tag(rest, "payload") {
            let (new_rest, _) = tag(new_rest, "=")?;
            let (new_rest, val) = parse_string_lit(new_rest)?;
            payload = Some(val);
            rest = new_rest;
        } else if let Ok((new_rest, _)) = tag(rest, "wait") {
            let (new_rest, _) = tag(new_rest, "=")?;
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
        } else {
            break;
        }
    }
    
    Ok((rest, FrameStatement { caller, dir, callee, flags, seq, win, payload, wait }))
}

/// Parse a template definition: `let template name(arg1, arg2) { ... }`
fn parse_template_def(input: &str) -> ParseResult<'_, TemplateDef> {
    let (rest, _) = tag(input, "let")?;
    let (rest, _) = tag(rest, "template")?;
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
    Ok((rest, TemplateDef { name, params, statements }))
}

/// Parse a template argument (variable, or variable with port override)
fn parse_argument(input: &str) -> ParseResult<'_, Argument> {
    let (rest, var) = parse_ident(input)?;
    if let Ok((rest_after_colon, _)) = tag(rest, ":") {
        let (final_rest, port) = parse_u16(rest_after_colon)?;
        Ok((final_rest, Argument::VarWithPort(var, port)))
    } else {
        Ok((rest, Argument::Variable(var)))
    }
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
    if let Ok((rest, _)) = tag(input, "loop") {
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

/// Parse the execution block: `run { ... }` or `compile { ... }`
fn parse_execution_block(input: &str) -> ParseResult<'_, ExecutionBlock> {
    if let Ok((rest, _)) = tag(input, "run") {
        let (mut rest, _) = tag(rest, "{")?;
        let mut statements = Vec::new();
        while let Ok((new_rest, stmt)) = parse_run_statement(rest) {
            statements.push(stmt);
            rest = new_rest;
        }
        let (rest, _) = tag(rest, "}")?;
        Ok((rest, ExecutionBlock::Run(statements)))
    } else if let Ok((rest, _)) = tag(input, "compile") {
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
        Ok((rest, ExecutionBlock::Compile(statements)))
    } else {
        Err("Expected 'run' or 'compile'".to_string())
    }
}

/// Top-level parser for the entire DSL file
pub fn parse_program(mut input: &str) -> Result<Program, String> {
    let mut assignments = Vec::new();
    let mut templates = Vec::new();
    let mut execution = None;

    loop {
        input = skip_whitespace(input);
        if input.is_empty() {
            break;
        }
        
        // Try parsing template def first, as it starts with "let template"
        if let Ok((rest, m)) = parse_template_def(input) {
            templates.push(m);
            input = rest;
        } 
        // Then try a regular assignment "let x = ..."
        else if let Ok((rest, a)) = parse_global_assignment(input) {
            assignments.push(a);
            input = rest;
        } 
        // Finally, try the execution block
        else if let Ok((rest, exec)) = parse_execution_block(input) {
            if execution.is_some() {
                return Err("A file cannot contain multiple execution blocks (run/compile)".to_string());
            }
            execution = Some(exec);
            input = rest;
        } 
        else {
            return Err(alloc::format!("Syntax error near: '{}'", &input[..core::cmp::min(input.len(), 20)]));
        }
    }

    let execution = execution.ok_or_else(|| "No 'run' or 'compile' block found in program".to_string())?;

    Ok(Program { assignments, templates, execution })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_parse_target_syntax() {
        let code = r#"
            let my_client = 10.0.0.1:1234
            let google_dns = 8.8.8.8

            let template tcp_handshake(src, dst) {
                src -> dst tcp syn
                src <- dst tcp ack
                src -> dst tcp syn ack
            }

            run {
                loop 100 {
                    tcp_handshake(my_client, google_dns:80)
                }
                tcp_handshake(my_client, google_dns:80)
            }
        "#;
        let prog = parse_program(code).unwrap();
        assert_eq!(prog.assignments.len(), 2);
        assert_eq!(prog.templates.len(), 1);
        if let ExecutionBlock::Run(stmts) = &prog.execution {
            assert_eq!(stmts.len(), 2);
        } else {
            panic!("Expected run block");
        }
    }
}
