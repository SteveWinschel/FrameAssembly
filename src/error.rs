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
        "Failed to parse token '#': comments in .fasm start with '//', not '#'".to_string()
    } else if rest.starts_with("/*") || rest.starts_with("*/") {
        "Failed to parse token '/*': block comments are not supported in .fasm (use '//' instead)"
            .to_string()
    } else if rest.starts_with('\'') {
        alloc::format!(
            "Failed to parse token '{}': single quotes are not used for text strings in .fasm (use double quotes \"...\" instead)",
            snippet
        )
    } else if rest.starts_with('/')
        && rest.as_bytes().get(1).is_some_and(|b| b.is_ascii_digit())
    {
        alloc::format!(
            "Failed to parse token '{}': subnet masks (CIDR notation) are not used in HOST or IP declarations",
            snippet
        )
    } else if rest.starts_with('=') || rest.starts_with(':') {
        let ch = rest.chars().next().unwrap_or('=');
        alloc::format!(
            "Failed to parse token '{}': assignment symbol '{}' is not used between keywords and values in .fasm",
            ch,
            ch
        )
    } else if rest.starts_with('[') || rest.starts_with(']') {
        let ch = rest.chars().next().unwrap_or('[');
        alloc::format!(
            "Failed to parse token '{}': square brackets '[' and ']' are not used in .fasm",
            ch
        )
    } else if rest.starts_with(';') {
        "Failed to parse token ';': semicolons are not needed at the end of lines in .fasm"
            .to_string()
    } else if rest.starts_with('+') {
        "Failed to parse token '+': relative delay prefixes like '+5ms' are not used in .fasm"
            .to_string()
    } else if snippet.is_empty() {
        "Failed to parse token".to_string()
    } else {
        alloc::format!("Failed to parse token '{}'", snippet)
    }
}

/// Produces a plain-English remediation hint for [`CompilerError::LexError`].
fn lex_error_help(src: &str, span: (usize, usize)) -> String {
    let rest = src.get(span.0.min(src.len())..).unwrap_or("");
    if rest.starts_with('#') {
        "Replace '#' with '//' to write a comment (for example: // Define client and server hosts)."
            .to_string()
    } else if rest.starts_with("/*") || rest.starts_with("*/") {
        "Start each comment line with '//' instead of wrapping comments in '/* ... */'.".to_string()
    } else if rest.starts_with('\'') {
        "Wrap text strings in double quotes instead of single quotes (for example: URI \"/index.html\" or USER \"admin\").".to_string()
    } else if rest.starts_with('/')
        && rest.as_bytes().get(1).is_some_and(|b| b.is_ascii_digit())
    {
        "Remove the CIDR prefix length and write a plain IP address (for example: IP 10.0.0.1 instead of IP 10.0.0.1/24).".to_string()
    } else if rest.starts_with('=') || rest.starts_with(':') {
        "Separate keywords and values with a space instead of '=' or ':' (for example: IP 10.0.0.1 or DSTPORT 443).".to_string()
    } else if rest.starts_with('[') || rest.starts_with(']') {
        "Write TCP flags as space-separated words without brackets (for example: TCP SYN ACK) and place delays at the end of the line (WAIT 5ms).".to_string()
    } else if rest.starts_with(';') {
        "Remove the ';' at the end of the line — statements end automatically at the newline."
            .to_string()
    } else if rest.starts_with('+') {
        "Put 'WAIT <duration>' at the end of the packet statement instead (for example: c -> s TCP SYN ACK WAIT 5ms).".to_string()
    } else {
        "Check for unsupported punctuation or typos. See docs/getting_started.md for valid .fasm syntax and examples.".to_string()
    }
}

/// Produces a plain-English remediation hint for [`CompilerError::ParseError`].
fn parse_error_help(message: &str, src: &str, span: (usize, usize)) -> String {
    let snippet = slice_at_span(src, span).to_ascii_lowercase();
    if matches!(snippet.as_str(), "sport" | "src_port" | "source_port") {
        "Replace 'sport' with 'SRCPORT <port>' (for example: SRCPORT 51234).".to_string()
    } else if matches!(
        snippet.as_str(),
        "dport" | "dst_port" | "dest_port" | "destination_port"
    ) {
        "Replace 'dport' with 'DSTPORT <port>' (for example: DSTPORT 443).".to_string()
    } else if message.contains("ACKNUM") {
        "Use 'ACK' alone as a TCP flag, and use 'ACKNUM <number>' to set the TCP acknowledgment number (for example: TCP ACK ACKNUM 100).".to_string()
    } else if matches!(snippet.as_str(), "hoplimit" | "hop_limit" | "hlim")
        || message.contains("Hop Limit")
    {
        "Use 'TTL <value>' for both IPv4 Time-to-Live and IPv6 Hop Limit (for example: TTL 64 or TTL 255).".to_string()
    } else if matches!(
        snippet.as_str(),
        "tos" | "traffic_class" | "trafficclass" | "tclass"
    ) {
        "Use 'DSCP <0..63>' and optional 'ECN <0..3>' to set IPv4 TOS / IPv6 Traffic Class bits (for example: DSCP 46).".to_string()
    } else if matches!(snippet.as_str(), "cos" | "dot1p") {
        "Use 'VLAN <id> PCP <0..7>' to set the Layer 2 802.1p Class of Service priority.".to_string()
    } else if matches!(
        snippet.as_str(),
        "vlan_id" | "vlanid" | "vid" | "svlan" | "cvlan" | "outer_vlan"
    ) || message.contains("INNER_VLAN")
    {
        "Use 'VLAN 100' for single 802.1Q tagging, or 'QINQ 100 INNER_VLAN 200' for 802.1ad double tagging.".to_string()
    } else if message.contains("HOST_HDR") {
        "Inside an HTTP statement, use 'HOST_HDR \"example.com\"' to set the HTTP Host header ('HOST' is reserved for declaring network endpoints).".to_string()
    } else if message.contains("missing a required 'IP") {
        "Add 'IP <address>' inside the HOST block — for example: HOST client { IP 10.0.0.1 MAC 00:11:22:33:44:55 }.".to_string()
    } else if message.contains("missing its endpoint parameter list") {
        "Add endpoint parameter names in parentheses after the flow name — for example: FLOW my_flow(c, s) { c -> s TCP SYN }.".to_string()
    } else if message.contains("missing 'COMPILE") || message.contains("duplicate 'COMPILE'") {
        "Every .fasm file must contain exactly one COMPILE { ... } block at the end that calls your flows — for example: COMPILE { my_flow(client, server) }.".to_string()
    } else if message.contains("outside a FLOW block") {
        "Move packet statements ('a -> b ...') inside a FLOW name(a, b) { ... } block, then call name(host1, host2) inside COMPILE { ... }.".to_string()
    } else {
        "Ensure the syntax matches the expected grammar. See docs/getting_started.md for ready-to-use .fasm examples.".to_string()
    }
}

/// Produces a plain-English remediation hint for [`CompilerError::SemanticError`].
fn semantic_error_help(message: &str) -> String {
    if message.contains("Mixed IPv4 and IPv6") {
        "Use either two IPv4 hosts or two IPv6 hosts in the same flow call — a single packet cannot have an IPv4 source and an IPv6 destination.".to_string()
    } else if message.contains("Undefined host") {
        "Declare the host at the top of the file with 'HOST <name> { IP <address> }' before passing it into a flow call in COMPILE.".to_string()
    } else if message.contains("Undefined flow") {
        "Declare the flow with 'FLOW <name>(a, b) { ... }' before calling it inside COMPILE.".to_string()
    } else if message.contains("Undefined endpoint") {
        "Make sure the endpoint name on the packet line matches one of the parameter names listed in 'FLOW name(param1, param2)'.".to_string()
    } else if message.contains("expects") && message.contains("arguments") {
        "Pass the exact number of host names in 'COMPILE { flow_name(host1, host2) }' to match the parameters in 'FLOW flow_name(a, b)'.".to_string()
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
