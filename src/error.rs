//! Structured compiler error definitions and rich diagnostic reporting for FrameAssembly.
//!
//! This module defines the [`CompilerError`] enumeration covering all failure modes across the
//! compilation pipeline: unrecognized character and symbol errors (`LexError`), grammar and
//! keyword errors (`ParseError`), networking rule validation errors (`SemanticError`), and
//! wire-level PCAP emission failures (`BackendError`). Each source-level error integrates with
//! [`miette`] to render file-named source spans and plain-English remediation hints tailored for
//! network technicians and engineers.

use alloc::boxed::Box;
use alloc::string::{String, ToString};
use miette::{Diagnostic, LabeledSpan, SourceSpan};

/// Extracts the offending text slice from `src` for a `(start, len)` byte span.
fn slice_at_span(src: &str, span: (usize, usize)) -> &str {
    let start = span.0.min(src.len());
    let end = span.0.saturating_add(span.1).min(src.len());
    src.get(start..end).unwrap_or("")
}

/// Produces a plain-English explanation of an unrecognized character or symbol for [`CompilerError::LexError`].
fn lex_error_summary(src: &str, span: (usize, usize)) -> String {
    let snippet = slice_at_span(src, span);
    let rest = src.get(span.0.min(src.len())..).unwrap_or("");
    if rest.starts_with('#') {
        "Failed to parse token '#': comments in .frasm start with '//', not '#'".to_string()
    } else if rest.starts_with("/*") || rest.starts_with("*/") {
        "Failed to parse token '/*': block comments are not supported in .frasm (use '//' instead)"
            .to_string()
    } else if rest.starts_with('\'') {
        alloc::format!(
            "Failed to parse token '{}': single quotes are not used for text strings in .frasm (use double quotes \"...\" instead)",
            snippet
        )
    } else if rest.starts_with('/')
        && rest.as_bytes().get(1).is_some_and(|b| b.is_ascii_digit())
    {
        alloc::format!(
            "Failed to parse token '{}': subnet masks (CIDR notation) are not used in host or ip declarations",
            snippet
        )
    } else if rest.starts_with('=') || rest.starts_with(':') {
        let ch = rest.chars().next().unwrap_or('=');
        alloc::format!(
            "Failed to parse token '{}': assignment symbol '{}' is not used between keywords and values in .frasm",
            ch,
            ch
        )
    } else if rest.starts_with('[') || rest.starts_with(']') {
        let ch = rest.chars().next().unwrap_or('[');
        alloc::format!(
            "Failed to parse token '{}': square brackets '[' and ']' are not used in .frasm",
            ch
        )
    } else if rest.starts_with(';') {
        "Failed to parse token ';': semicolons are not needed at the end of lines in .frasm"
            .to_string()
    } else if rest.starts_with('+') {
        "Failed to parse token '+': relative delay prefixes like '+5ms' are not used in .frasm"
            .to_string()
    } else if snippet.is_empty() {
        "Failed to parse token".to_string()
    } else {
        alloc::format!("Failed to parse token '{}'", snippet)
    }
}

/// Detects whether `src` appears to be a foreign `.fasm` assembly file (such as x86 Flat Assembler
/// or FPGA FASM bitstream configuration) rather than a FrameAssembly `.frasm` network packet specification.
///
/// Returns `Some("an x86 Flat Assembler")` or `Some("an FPGA FASM")` if foreign signatures
/// are identified and the input lacks canonical FrameAssembly `flow` and `compile` structure.
pub fn detect_foreign_fasm(src: &str) -> Option<&'static str> {
    // If the file already contains clear FrameAssembly host/flow and compile constructs, it is not foreign.
    let has_compile = src.lines().any(|l| {
        let trimmed = l.trim();
        trimmed.to_ascii_lowercase().starts_with("compile")
    });
    let has_flow = src.lines().any(|l| {
        let trimmed = l.trim();
        trimmed.to_ascii_lowercase().starts_with("flow")
    });
    let has_host = src.lines().any(|l| {
        let trimmed = l.trim();
        trimmed.to_ascii_lowercase().starts_with("host")
    });
    if has_compile && (has_flow || has_host) {
        return None;
    }

    let mut has_semicolon_comment = false;
    let mut has_x86_directive = false;
    let mut has_hash_comment = false;
    let mut has_fpga_tile = false;
    let mut has_dot_tile_feature = false;

    let fpga_tiles = ["CLB", "LUT", "IOB", "INT_L", "INT_R", "BRAM", "DSP", "SLICE"];

    for line in src.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if trimmed.starts_with(';') {
            has_semicolon_comment = true;
        }
        if trimmed.starts_with('#') {
            has_hash_comment = true;
        }

        let upper = trimmed.to_ascii_uppercase();
        if upper.starts_with("FORMAT ")
            || upper.starts_with("SECTION ")
            || upper.starts_with("SEGMENT ")
            || upper.starts_with("USE16")
            || upper.starts_with("USE32")
            || upper.starts_with("USE64")
            || upper.starts_with("ORG ")
            || upper.starts_with("ENTRY ")
            || (upper.starts_with("INCLUDE ") && (trimmed.contains('\'') || trimmed.contains('"')))
        {
            has_x86_directive = true;
        }

        for tile in &fpga_tiles {
            if upper.contains(tile) {
                has_fpga_tile = true;
                if trimmed.contains('.') && (trimmed.contains('[') || trimmed.contains('=')) {
                    has_dot_tile_feature = true;
                }
                break;
            }
        }
    }

    if has_x86_directive || (has_semicolon_comment && !has_flow && !has_compile && !has_host) {
        return Some("an x86 Flat Assembler");
    }

    if has_fpga_tile
        && (has_hash_comment || has_dot_tile_feature)
        && !has_flow
        && !has_compile
        && !has_host
    {
        return Some("an FPGA FASM");
    }

    None
}

/// Produces a plain-English remediation hint for [`CompilerError::LexError`].
fn lex_error_help(src: &str, span: (usize, usize)) -> String {
    if let Some(kind) = detect_foreign_fasm(src) {
        return alloc::format!(
            "This file appears to be {} file, not a FrameAssembly network packet specification. FrameAssembly files declare host {{ ip ... }}, flow(...), and compile {{ ... }} blocks to compile network traffic into .pcap/.pcapng captures. See https://github.com/SteveWinschel/FrameAssembly for syntax and examples.",
            kind
        );
    }

    let rest = src.get(span.0.min(src.len())..).unwrap_or("");
    if rest.starts_with('#') {
        "Replace '#' with '//' to write a comment (for example: // Define client and server hosts)."
            .to_string()
    } else if rest.starts_with("/*") || rest.starts_with("*/") {
        "Start each comment line with '//' instead of wrapping comments in '/* ... */'.".to_string()
    } else if rest.starts_with('\'') {
        "Wrap text strings in double quotes instead of single quotes (for example: uri \"/index.html\" or user \"admin\").".to_string()
    } else if rest.starts_with('/')
        && rest.as_bytes().get(1).is_some_and(|b| b.is_ascii_digit())
    {
        "Remove the CIDR prefix length and write a plain IP address (for example: ip 10.0.0.1 instead of ip 10.0.0.1/24).".to_string()
    } else if rest.starts_with('=') || rest.starts_with(':') {
        "Separate keywords and values with a space instead of '=' or ':' (for example: ip 10.0.0.1 or dstport 443).".to_string()
    } else if rest.starts_with('[') || rest.starts_with(']') {
        "Write TCP flags as space-separated words without brackets (for example: tcp syn ack) and place delays at the end of the line (wait 5ms).".to_string()
    } else if rest.starts_with(';') {
        "Remove the ';' at the end of the line — statements end automatically at the newline."
            .to_string()
    } else if rest.starts_with('+') {
        "Put 'wait <duration>' at the end of the packet statement instead (for example: c -> s tcp syn ack wait 5ms).".to_string()
    } else {
        "Check for unsupported punctuation or typos. See docs/01_getting_started.md for valid .frasm syntax and examples.".to_string()
    }
}

/// Produces a plain-English remediation hint for [`CompilerError::ParseError`].
fn parse_error_help(message: &str, src: &str, span: (usize, usize)) -> String {
    if let Some(kind) = detect_foreign_fasm(src) {
        return alloc::format!(
            "This file appears to be {} file, not a FrameAssembly network packet specification. FrameAssembly files declare host {{ ip ... }}, flow(...), and compile {{ ... }} blocks to compile network traffic into .pcap/.pcapng captures. See https://github.com/SteveWinschel/FrameAssembly for syntax and examples.",
            kind
        );
    }

    let raw = slice_at_span(src, span);
    if raw.eq_ignore_ascii_case("loop") {
        return "The 'loop' block was removed in FrameAssembly 2.0; invoke flows or frame statements directly inside 'compile { ... }'.".to_string();
    }
    if let Some(kw) = crate::lexer::suggest_v2_lowercase_keyword(raw) {
        return alloc::format!(
            "Keywords in FrameAssembly 2.0 are strictly lowercase without '_' or '-': replace '{}' with '{}'.",
            raw,
            kw
        );
    }

    let snippet = raw.to_ascii_lowercase();
    if matches!(snippet.as_str(), "sport" | "source_port" | "sourceport") {
        "Replace 'sport' with 'srcport <port>' (for example: srcport 51234).".to_string()
    } else if matches!(
        snippet.as_str(),
        "dport" | "dest_port" | "destport" | "destination_port"
    ) {
        "Replace 'dport' with 'dstport <port>' (for example: dstport 443).".to_string()
    } else if message.contains("acknum") {
        "Use 'ack' alone as a TCP flag, and use 'acknum <number>' to set the TCP acknowledgment number (for example: tcp ack acknum 100).".to_string()
    } else if matches!(snippet.as_str(), "hoplimit" | "hop_limit" | "hlim")
        || message.contains("Hop Limit")
    {
        "Use 'ttl <value>' for both IPv4 Time-to-Live and IPv6 Hop Limit (for example: ttl 64 or ttl 255).".to_string()
    } else if matches!(
        snippet.as_str(),
        "tos" | "traffic_class" | "trafficclass" | "tclass"
    ) {
        "Use 'dscp <0..63>' and optional 'ecn <0..3>' to set IPv4 TOS / IPv6 Traffic Class bits (for example: dscp 46).".to_string()
    } else if matches!(snippet.as_str(), "cos" | "dot1p") {
        "Use 'vlan <id> pcp <0..7>' to set the Layer 2 802.1p Class of Service priority.".to_string()
    } else if matches!(
        snippet.as_str(),
        "vlan_id" | "vlanid" | "vid" | "svlan" | "cvlan" | "outer_vlan" | "outervlan"
    ) || message.contains("innervlan")
    {
        "Use 'vlan 100' for single 802.1Q tagging, or 'qinq 100 innervlan 200' for 802.1ad double tagging.".to_string()
    } else if message.contains("hosthdr") {
        "Inside an http statement, use 'hosthdr \"example.com\"' to set the HTTP Host header ('host' is reserved for declaring network endpoints).".to_string()
    } else if message.contains("missing a required 'ip")
        || message.contains("must specify at least an 'IP <address>' or 'MAC <address>'")
    {
        "Add 'ip <address>' and/or 'mac <address>' inside the host block — for example: host client { ip 10.0.0.1 mac 00:11:22:33:44:55 }.".to_string()
    } else if message.contains("missing its endpoint parameter list") {
        "Add endpoint parameter names in parentheses after the flow name — for example: flow my_flow(c, s) { c -> s tcp syn }.".to_string()
    } else if message.contains("missing 'compile") || message.contains("duplicate 'compile'") {
        "Every .frasm file must contain exactly one compile { ... } block at the end that calls your flows — for example: compile { my_flow(client, server) }.".to_string()
    } else if message.contains("outside a flow block") {
        "Move packet statements ('a -> b ...') inside a flow name(a, b) { ... } block (then call name(host1, host2) inside compile { ... }) or place inline packet statements directly inside compile { ... }.".to_string()
    } else {
        "Ensure the syntax matches the expected grammar. See docs/01_getting_started.md for ready-to-use .frasm examples.".to_string()
    }
}

/// Produces a plain-English remediation hint for [`CompilerError::SemanticError`].
fn semantic_error_help(message: &str) -> String {
    if message.contains("Mixed IPv4 and IPv6") {
        "Use either two IPv4 hosts or two IPv6 hosts in the same flow call — a single packet cannot have an IPv4 source and an IPv6 destination.".to_string()
    } else if message.contains("requires an 'IP <address>'") {
        "Add 'ip <address>' to the host declaration (for example: host r1 { ip 10.0.0.1 mac 00:11:22:33:44:55 }), or use a pure Layer 2 protocol (arp, vlan, qinq, mpls, lldp, stp, lacp, eapol).".to_string()
    } else if message.contains("Undefined host") {
        "Declare the host at the top of the file with 'host <name> { ip <address> }' before passing it into a flow call in compile.".to_string()
    } else if message.contains("Undefined flow") {
        "Declare the flow with 'flow <name>(a, b) { ... }' before calling it inside compile.".to_string()
    } else if message.contains("Undefined endpoint") || message.contains("Unknown caller") || message.contains("Unknown callee") {
        "Make sure the endpoint name on the packet line matches one of the parameter names listed in 'flow name(param1, param2)'.".to_string()
    } else if message.contains("expects") && message.contains("arguments") {
        "Pass the exact number of host names in 'compile { flow_name(host1, host2) }' to match the parameters in 'flow flow_name(a, b)'.".to_string()
    } else {
        "Check the highlighted field value or endpoint name against protocol limits.".to_string()
    }
}

/// Represents all possible errors that can occur during the compilation process.
///
/// This enum implements [`miette::Diagnostic`] for rich terminal diagnostics with filename spans
/// and plain-English troubleshooting hints for network technicians.
#[derive(Debug)]
pub enum CompilerError {
    /// Occurs when the lexer encounters an invalid sequence of characters that cannot be tokenized.
    LexError {
        /// The source code snippet.
        src: String,
        /// The byte offset and byte length `(start, len)` of the error.
        span: (usize, usize),
    },

    /// Occurs when the parser encounters a syntax error or unexpected token.
    ParseError {
        /// The parser error message.
        message: String,
        /// The source code snippet.
        src: String,
        /// The byte offset and byte length `(start, len)` of the error.
        span: (usize, usize),
    },

    /// Occurs when the specification is syntactically valid but violates networking or semantic rules.
    SemanticError {
        /// The semantic error message.
        message: String,
        /// The source code snippet.
        src: String,
        /// The byte offset and byte length `(start, len)` of the error.
        span: (usize, usize),
    },

    /// Occurs during the backend PCAP generation (e.g. invalid IP address formatting, missing file access).
    BackendError(String),
}

impl Diagnostic for CompilerError {
    fn code<'a>(&'a self) -> Option<Box<dyn core::fmt::Display + 'a>> {
        let code_str = match self {
            Self::LexError { .. } => "frameassembly::lex_error",
            Self::ParseError { .. } => "frameassembly::parse_error",
            Self::SemanticError { .. } => "frameassembly::semantic_error",
            Self::BackendError(_) => "frameassembly::backend_error",
        };
        Some(Box::new(code_str))
    }

    fn help<'a>(&'a self) -> Option<Box<dyn core::fmt::Display + 'a>> {
        match self {
            Self::LexError { src, span } => Some(Box::new(lex_error_help(src, *span))),
            Self::ParseError { message, src, span } => {
                Some(Box::new(parse_error_help(message, src, *span)))
            }
            Self::SemanticError { message, .. } => Some(Box::new(semantic_error_help(message))),
            Self::BackendError(_) => None,
        }
    }

    fn labels(&self) -> Option<Box<dyn Iterator<Item = LabeledSpan> + '_>> {
        match self {
            Self::LexError { span, .. } => Some(Box::new(core::iter::once(
                LabeledSpan::new_with_span(
                    Some("Invalid token".to_string()),
                    SourceSpan::from(*span),
                ),
            ))),
            Self::ParseError { span, .. } => Some(Box::new(core::iter::once(
                LabeledSpan::new_with_span(Some("Here".to_string()), SourceSpan::from(*span)),
            ))),
            Self::SemanticError { span, .. } => Some(Box::new(core::iter::once(
                LabeledSpan::new_with_span(
                    Some("Error occurred here".to_string()),
                    SourceSpan::from(*span),
                ),
            ))),
            Self::BackendError(_) => None,
        }
    }
}

impl core::fmt::Display for CompilerError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::LexError { src, span } => write!(f, "{}", lex_error_summary(src, *span)),
            Self::ParseError { message, .. } => write!(f, "Failed to parse input: {}", message),
            Self::SemanticError { message, .. } => write!(f, "Semantic error: {}", message),
            Self::BackendError(msg) => write!(f, "Backend generation error: {}", msg),
        }
    }
}

impl std::error::Error for CompilerError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_x86_flat_assembler() {
        let sample1 = "format PE GUI 4.0\nentry start\nsection '.text' code readable executable\nstart:\n  ret\n";
        assert_eq!(detect_foreign_fasm(sample1), Some("an x86 Flat Assembler"));

        let sample2 = "; Flat Assembler source\nuse32\norg 0x100\nmov ax, 0x4c00\nint 0x21\n";
        assert_eq!(detect_foreign_fasm(sample2), Some("an x86 Flat Assembler"));

        let sample3 = "format ELF64 executable\nsegment readable executable\nentry $\n";
        assert_eq!(detect_foreign_fasm(sample3), Some("an x86 Flat Assembler"));
    }

    #[test]
    fn test_detect_fpga_fasm() {
        let sample1 = "# Generated by Project X-Ray\nCLBLL_L_X12Y34.SLICEL_X0.ALUT.INIT[31:0] = 32'h00000000\nIOB_X0Y1.ENABLE 1\n";
        assert_eq!(detect_foreign_fasm(sample1), Some("an FPGA FASM"));

        let sample2 = "CLBLL_L_X12Y34.SLICEL_X0.ALUT.INIT[31:0] = 32'h00000000\n";
        assert_eq!(detect_foreign_fasm(sample2), Some("an FPGA FASM"));
    }

    #[test]
    fn test_valid_frameassembly_is_not_foreign() {
        let sample = "host client { ip 10.0.0.1 }\nflow ping(c, s) { c -> s icmp }\ncompile { ping(client, client) }\n";
        assert_eq!(detect_foreign_fasm(sample), None);
    }

    #[test]
    fn test_foreign_fasm_lex_error_help_hint() {
        let sample = "; x86 assembly file\nformat PE\n";
        let help = lex_error_help(sample, (0, 1));
        assert!(help.contains("x86 Flat Assembler"));
        assert!(help.contains("FrameAssembly files declare host { ip ... }, flow(...), and compile { ... } blocks"));
        assert!(help.contains("https://github.com/SteveWinschel/FrameAssembly"));

        let fpga_sample = "# FPGA bitstream\nCLBLL_L_X0Y0.ENABLE 1\n";
        let fpga_help = lex_error_help(fpga_sample, (0, 1));
        assert!(fpga_help.contains("FPGA FASM"));
    }

    #[test]
    fn test_foreign_fasm_parse_error_help_hint() {
        let sample = "format PE GUI 4.0\nentry start\n";
        let help = parse_error_help("unexpected token", sample, (0, 6));
        assert!(help.contains("x86 Flat Assembler"));
    }

    #[test]
    fn test_v2_self_healing_parse_error_help() {
        let loop_src = "host a { ip 10.0.0.1 }\ncompile { loop 2 {} }\n";
        let loop_help = parse_error_help("unexpected 'loop'", loop_src, (33, 4));
        assert_eq!(
            loop_help,
            "The 'loop' block was removed in FrameAssembly 2.0; invoke flows or frame statements directly inside 'compile { ... }'."
        );

        let upper_src = "HOST a { ip 10.0.0.1 }\ncompile {}\n";
        let upper_help = parse_error_help("unexpected 'HOST'", upper_src, (0, 4));
        assert_eq!(
            upper_help,
            "Keywords in FrameAssembly 2.0 are strictly lowercase without '_' or '-': replace 'HOST' with 'host'."
        );

        let snake_src = "host a { ip 10.0.0.1 }\ncompile { a -> a icmp echo_request }\n";
        let snake_help = parse_error_help("unexpected 'echo_request'", snake_src, (45, 12));
        assert_eq!(
            snake_help,
            "Keywords in FrameAssembly 2.0 are strictly lowercase without '_' or '-': replace 'echo_request' with 'echorequest'."
        );
    }
}

