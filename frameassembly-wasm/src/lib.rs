//! WebAssembly bindings, PCAP/PCAPNG-to-`.frasm` decompiler, frame inspector, and UTF-16 IDE
//! diagnostics for the FrameAssembly (`.frasm` v3.3.1) network packet synthesis compiler.
//!
//! This crate exposes `validate_frasm` (`validateFrasm`), `inspect_frasm` (`inspectFrasm`),
//! `compile_frasm_to_pcap` (`compileFrasmToPcap`), `compile_frasm_to_pcapng` (`compileFrasm`), and
//! `reverse_pcap` (`reversePcap`) to browser environments, VS Code Desktop and Web extensions,
//! Node.js test harnesses, and web-based code editors (Monaco, CodeMirror, VS Code Web) via
//! `wasm-bindgen`. The 2.x export names `validate_fasm` (`validateFasm`), `inspect_fasm`, and
//! `compile_fasm_to_pcapng` (`compileFasm`) remain available as compatibility aliases. It compiles
//! strict-lowercase `.frasm` specifications across all 146 native Layer 2 through Layer 7 protocols
//! (`18` L2, `31` L3, `3` L4, `94` L7) into deterministic classic `.pcap` and nanosecond-resolution
//! `PCAPNG` byte arrays (`Uint8Array`), decompiles binary `.pcap` and `.pcapng` packet captures
//! back into canonical lowercase `.frasm` code in memory via
//! [`frameassembly::reverse::reverse_pcap_bytes`], delegates Ethernet/VLAN/QinQ/MPLS/LLC and
//! Layer 3/4/7 frame dissection to [`frameassembly::inspect::summarize_frame`], serializes
//! structured JS outputs as plain objects (`serialize_maps_as_objects(true)`), enforces bounded
//! browser input sizes ([`MAX_WASM_SOURCE_BYTES`] and [`MAX_WASM_PCAP_BYTES`]), and maps compiler
//! diagnostic byte spans (including LF, CRLF, and bare CR line breaks) into zero-based UTF-16
//! line and column coordinates.

use std::fmt::Write;

use frameassembly::backend::{compile_program, compile_program_with_metadata};
use frameassembly::inspect::summarize_frame;
use frameassembly::parser::parse_program;
use frameassembly::pcap::{
    serialize_classic_pcap, serialize_pcapng, serialize_pcapng_with_metadata,
};
use frameassembly::reverse::{ReverseOutput, reverse_pcap_bytes};
use miette::Diagnostic;
use serde::Serialize;
use wasm_bindgen::prelude::*;

/// Maximum `.frasm` source length accepted by WebAssembly entry points (`4 MiB`).
pub const MAX_WASM_SOURCE_BYTES: usize = 4 * 1024 * 1024;

/// Maximum `.pcap` / `.pcapng` capture length accepted by WebAssembly reverse entry points (`64 MiB`).
pub const MAX_WASM_PCAP_BYTES: usize = 64 * 1024 * 1024;

/// Custom TypeScript interface definitions appended to the generated `.d.ts` bindings.
#[wasm_bindgen(typescript_custom_section)]
const TS_APPEND_CONTENT: &'static str = r#"
export interface IdeDiagnostic {
    start_line: number;
    start_col: number;
    end_line: number;
    end_col: number;
    message: string;
    help?: string;
}

export interface PacketPreview {
    index: number;
    timestamp_ms: number;
    length: number;
    hex: string;
    source_dest: string;
    protocol: string;
    summary: string;
}

export interface ReversePcapResult {
    success: boolean;
    frasm: string;
    fasm: string;
    packetCount: number;
    hostCount: number;
}

export type ReverseJsResult = ReversePcapResult;

export interface ReversePcapError {
    success: boolean;
    error: string;
    message: string;
}
"#;

/// Zero-based UTF-16 source range diagnostic and remediation hint for browser and IDE code editors.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct IdeDiagnostic {
    /// Zero-based starting line index.
    pub start_line: u32,
    /// Zero-based starting UTF-16 column offset.
    pub start_col: u32,
    /// Zero-based ending line index.
    pub end_line: u32,
    /// Zero-based ending UTF-16 column offset.
    pub end_col: u32,
    /// Primary diagnostic error message.
    pub message: String,
    /// Optional plain-English remediation hint (including strict-lowercase keyword quick-fix hints).
    pub help: Option<String>,
}

/// Summary metadata, protocol dissection, and hexadecimal wire dump for a synthesized Ethernet frame.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PacketPreview {
    /// One-based frame sequence index in the capture.
    pub index: usize,
    /// Relative frame timestamp in milliseconds from the first frame.
    pub timestamp_ms: f64,
    /// Total Ethernet frame length in bytes.
    pub length: usize,
    /// Space-delimited lowercase hexadecimal representation of the frame bytes.
    pub hex: String,
    /// Formatted `source -> destination` IPv4, IPv6, or MAC endpoint pair.
    pub source_dest: String,
    /// Dissected highest-layer protocol label (e.g. `DNS`, `SNMP`, `MODBUS`, `TCP`, `ARP`, `NGAP`).
    pub protocol: String,
    /// Human-readable Ethernet/VLAN/QinQ/MPLS/LLC/L3/L4/L7 frame summary string.
    pub summary: String,
}

/// Decompilation summary and canonical `.frasm` code returned by [`reverse_pcap`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReversePcapResult {
    /// Indicates that the binary capture was decompiled into `.frasm` code (`true`).
    pub success: bool,
    /// Generated canonical lowercase `.frasm` source code.
    pub frasm: String,
    /// Backward-compatible 2.x alias of [`ReversePcapResult::frasm`] (identical content).
    pub fasm: String,
    /// Total number of packets reversed from the capture.
    pub packet_count: usize,
    /// Total number of `host1`, `host2`, ... definitions emitted in the `.frasm` program.
    pub host_count: usize,
}

impl From<ReverseOutput> for ReversePcapResult {
    /// Converts a core [`ReverseOutput`] into a [`ReversePcapResult`] preserving `frasm` and `fasm`.
    fn from(out: ReverseOutput) -> Self {
        Self {
            success: true,
            frasm: out.fasm.clone(),
            fasm: out.fasm,
            packet_count: out.packet_count,
            host_count: out.host_count,
        }
    }
}

/// Borrowed wire-serialization view over [`ReverseOutput`] avoiding a duplicate `.frasm` heap clone
/// when crossing the JavaScript boundary.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ReversePcapJsPayload<'a> {
    /// Indicates that decompilation succeeded (`true`).
    success: bool,
    /// Generated canonical lowercase `.frasm` source code.
    frasm: &'a str,
    /// Backward-compatible 2.x alias of `frasm`.
    fasm: &'a str,
    /// Total number of packets reversed from the capture.
    packet_count: usize,
    /// Total number of `host1`, `host2`, ... definitions emitted in the `.frasm` program.
    host_count: usize,
}

/// Type alias for [`ReversePcapResult`] returned to JavaScript callers by [`reverse_pcap`].
pub type ReverseJsResult = ReversePcapResult;

/// Structured error payload returned when binary `.pcap` or `.pcapng` decompilation fails.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReversePcapError {
    /// Indicates that decompilation failed (`false`).
    pub success: bool,
    /// Human-readable decompilation error description.
    pub error: String,
    /// Standard JavaScript `Error`-compatible message string.
    pub message: String,
}

impl ReversePcapError {
    /// Constructs a [`ReversePcapError`] with matching `error` and `message` strings.
    fn new(message: impl Into<String>) -> Self {
        let message = message.into();
        Self {
            success: false,
            error: message.clone(),
            message,
        }
    }
}

/// Serializes `value` into a plain JavaScript object/array using `serialize_maps_as_objects(true)`
/// so JS callers always receive plain objects rather than ES6 `Map` instances.
fn serialize_to_js_object<T: Serialize>(value: &T) -> Result<JsValue, serde_wasm_bindgen::Error> {
    let serializer = serde_wasm_bindgen::Serializer::new().serialize_maps_as_objects(true);
    value.serialize(&serializer)
}

/// Enforces [`MAX_WASM_SOURCE_BYTES`] on incoming `.frasm` source strings.
fn check_source_size(source: &str) -> Result<(), String> {
    if source.len() > MAX_WASM_SOURCE_BYTES {
        return Err(format!(
            "Source input ({} bytes) exceeds maximum supported WebAssembly size ({MAX_WASM_SOURCE_BYTES} bytes)",
            source.len()
        ));
    }
    Ok(())
}

/// Enforces [`MAX_WASM_PCAP_BYTES`] on incoming `.pcap`/`.pcapng` capture buffers.
fn check_pcap_size(pcap_bytes: &[u8]) -> Result<(), ReversePcapError> {
    if pcap_bytes.len() > MAX_WASM_PCAP_BYTES {
        return Err(ReversePcapError::new(format!(
            "Capture input ({} bytes) exceeds maximum supported WebAssembly size ({MAX_WASM_PCAP_BYTES} bytes)",
            pcap_bytes.len()
        )));
    }
    Ok(())
}

/// Converts a UTF-8 byte offset within `source` into a zero-based `(line, utf16_col)` pair
/// suitable for Monaco Editor, CodeMirror 6, and VS Code diagnostics.
///
/// Clamps out-of-bounds offsets to `source.len()`, backs up mid-character offsets to the
/// preceding UTF-8 scalar boundary, treats `\r\n`, bare `\r`, and `\n` each as a single line
/// break without off-by-one column drift, and counts UTF-16 code units along the active line.
pub fn byte_offset_to_utf16_line_col(source: &str, byte_offset: usize) -> (u32, u32) {
    let mut safe_end = byte_offset.min(source.len());
    while safe_end > 0 && !source.is_char_boundary(safe_end) {
        safe_end -= 1;
    }

    let mut line: u32 = 0;
    let mut col_utf16: u32 = 0;
    let mut chars = source[..safe_end].chars().peekable();
    while let Some(ch) = chars.next() {
        match ch {
            '\r' => {
                if chars.peek() == Some(&'\n') {
                    chars.next();
                }
                line += 1;
                col_utf16 = 0;
            }
            '\n' => {
                line += 1;
                col_utf16 = 0;
            }
            _ => col_utf16 += ch.len_utf16() as u32,
        }
    }
    (line, col_utf16)
}

/// Scans `source` outside `//` line comments and `"..."` string literals, yielding
/// `(token_str, start_byte, end_byte)` for each identifier or keyword run.
fn scan_code_words(source: &str) -> Vec<(&str, usize, usize)> {
    let bytes = source.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;

    while i < bytes.len() {
        let b = bytes[i];
        if b == b'/' && i + 1 < bytes.len() && bytes[i + 1] == b'/' {
            i += 2;
            while i < bytes.len() && !matches!(bytes[i], b'\n' | b'\r') {
                i += 1;
            }
        } else if b == b'"' {
            i += 1;
            while i < bytes.len() {
                if bytes[i] == b'\\' {
                    i = (i + 2).min(bytes.len());
                } else if bytes[i] == b'"' {
                    i += 1;
                    break;
                } else {
                    i += 1;
                }
            }
        } else if b.is_ascii_alphanumeric() || b == b'_' {
            let start = i;
            i += 1;
            while i < bytes.len()
                && (bytes[i].is_ascii_alphanumeric()
                    || bytes[i] == b'_'
                    || (bytes[i] == b'-'
                        && i + 1 < bytes.len()
                        && (bytes[i + 1].is_ascii_alphanumeric() || bytes[i + 1] == b'_')))
            {
                i += 1;
            }
            if let Some(slice) = source.get(start..i) {
                out.push((slice, start, i));
            }
        } else {
            i += 1;
        }
    }

    out
}

/// Extracts the first single-quoted token `'...'` from a backend error message, if present.
fn extract_single_quoted_subject(err_msg: &str) -> Option<&str> {
    let start = err_msg.find('\'')? + 1;
    let rest = err_msg.get(start..)?;
    let end = rest.find('\'')?;
    let token = &rest[..end];
    if token.is_empty() { None } else { Some(token) }
}

/// Locates the most accurate UTF-8 `(start_byte, end_byte)` span in `source` for a backend
/// compilation error, preferring the offending statement/identifier token inside code or falling
/// back to the `compile` block keyword span instead of `(0, 0)`.
fn find_backend_error_span(source: &str, err_msg: &str) -> (usize, usize) {
    let words = scan_code_words(source);
    let compile_span = words
        .iter()
        .rev()
        .find(|(w, _, _)| w.eq_ignore_ascii_case("compile"))
        .map(|&(_, s, e)| (s, e));

    if let Some(subject) = extract_single_quoted_subject(err_msg)
        && let Some(&(_, s, e)) = words
            .iter()
            .rev()
            .find(|(w, s, _)| *w == subject && compile_span.is_none_or(|(cs, _)| *s >= cs))
            .or_else(|| words.iter().rev().find(|(w, _, _)| *w == subject))
    {
        return (s, e);
    }

    if err_msg.contains("SNMPv1")
        && let Some(&(_, s, e)) = words.iter().find(|(w, _, _)| *w == "snmp1")
    {
        return (s, e);
    }

    if err_msg.contains("SNMPv3")
        && let Some(&(_, s, e)) = words.iter().find(|(w, _, _)| *w == "snmp3")
    {
        return (s, e);
    }

    if let Some(span) = compile_span {
        return span;
    }

    if let Some(&(_, s, e)) = words.first() {
        return (s, e);
    }

    (0, source.len().min(1))
}

/// Builds an [`IdeDiagnostic`] from clamped UTF-8 byte offsets `[start_byte, end_byte)`.
fn make_diagnostic(
    source: &str,
    start_byte: usize,
    end_byte: usize,
    message: String,
    help: Option<String>,
) -> IdeDiagnostic {
    let safe_start = start_byte.min(source.len());
    let safe_end = end_byte.max(safe_start).min(source.len());
    let (start_line, start_col) = byte_offset_to_utf16_line_col(source, safe_start);
    let (end_line, end_col) = byte_offset_to_utf16_line_col(source, safe_end);
    IdeDiagnostic {
        start_line,
        start_col,
        end_line,
        end_col,
        message,
        help,
    }
}

/// Extracts span coordinates and remediation hints from a `miette::Diagnostic` and appends an [`IdeDiagnostic`].
fn push_diagnostic(source: &str, err: &dyn Diagnostic, out: &mut Vec<IdeDiagnostic>) {
    let message = err.to_string();
    let help = err.help().map(|h| h.to_string());

    if let Some(mut labels) = err.labels()
        && let Some(span) = labels.next()
    {
        let start_byte = span.offset().min(source.len());
        let end_byte = start_byte
            .saturating_add(span.len().max(1))
            .min(source.len());
        out.push(make_diagnostic(source, start_byte, end_byte, message, help));
    } else {
        let (start_byte, end_byte) = find_backend_error_span(source, &message);
        out.push(make_diagnostic(
            source,
            start_byte,
            end_byte.max(start_byte.saturating_add(1)),
            message,
            help,
        ));
    }
}

/// Validates `.frasm` source and returns typed [`IdeDiagnostic`] entries without invoking JS bindings.
pub fn validate_frasm_to_diagnostics(source: &str) -> Vec<IdeDiagnostic> {
    if let Err(err_msg) = check_source_size(source) {
        let mut preview_end = source.len().min(64);
        while preview_end > 0 && !source.is_char_boundary(preview_end) {
            preview_end -= 1;
        }
        if let Some(nl) = source[..preview_end].find(['\r', '\n']) {
            preview_end = nl;
        }
        let end_col = source[..preview_end].encode_utf16().count() as u32;
        return vec![IdeDiagnostic {
            start_line: 0,
            start_col: 0,
            end_line: 0,
            end_col,
            message: err_msg,
            help: Some(
                "Split large specifications into smaller .frasm files or use the native frameassembly CLI."
                    .to_string(),
            ),
        }];
    }

    let mut diagnostics = Vec::new();

    match parse_program(source) {
        Ok(program) => {
            if let Err(err) = compile_program(&program) {
                let (start_byte, end_byte) = find_backend_error_span(source, &err);
                diagnostics.push(make_diagnostic(
                    source,
                    start_byte,
                    end_byte.max(start_byte.saturating_add(1)),
                    err,
                    None,
                ));
            }
        }
        Err(err) => push_diagnostic(source, &err, &mut diagnostics),
    }

    diagnostics
}

/// Compatibility alias for [`validate_frasm_to_diagnostics`].
pub fn validate_fasm_to_diagnostics(source: &str) -> Vec<IdeDiagnostic> {
    validate_frasm_to_diagnostics(source)
}

/// Validates `.frasm` source and returns UTF-16 line/column diagnostics for Monaco, CodeMirror, and VS Code.
///
/// # Errors
/// Returns a JavaScript `Error` if diagnostic serialization fails.
#[wasm_bindgen(unchecked_return_type = "IdeDiagnostic[]")]
pub fn validate_frasm(source: &str) -> Result<JsValue, JsError> {
    let diagnostics = validate_frasm_to_diagnostics(source);
    Ok(serialize_to_js_object(&diagnostics)?)
}

/// Validates `.frasm` source and returns UTF-16 line/column diagnostics (`validateFrasm` camelCase alias).
///
/// # Errors
/// Returns a JavaScript `Error` if diagnostic serialization fails.
#[wasm_bindgen(js_name = validateFrasm, unchecked_return_type = "IdeDiagnostic[]")]
pub fn validate_frasm_js(source: &str) -> Result<JsValue, JsError> {
    validate_frasm(source)
}

/// Validates `.frasm` source and returns UTF-16 line/column diagnostics (`validate_fasm` 2.x alias).
///
/// # Errors
/// Returns a JavaScript `Error` if diagnostic serialization fails.
#[wasm_bindgen(unchecked_return_type = "IdeDiagnostic[]")]
pub fn validate_fasm(source: &str) -> Result<JsValue, JsError> {
    validate_frasm(source)
}

/// Validates `.frasm` source and returns UTF-16 line/column diagnostics (`validateFasm` 2.x alias).
///
/// # Errors
/// Returns a JavaScript `Error` if diagnostic serialization fails.
#[wasm_bindgen(js_name = validateFasm, unchecked_return_type = "IdeDiagnostic[]")]
pub fn validate_fasm_js(source: &str) -> Result<JsValue, JsError> {
    validate_frasm(source)
}

/// Compiles `.frasm` source into typed [`PacketPreview`] entries without invoking JS bindings,
/// delegating frame dissection to [`frameassembly::inspect::summarize_frame`].
///
/// # Errors
/// Returns a human-readable error string if `source` exceeds [`MAX_WASM_SOURCE_BYTES`] or if
/// parsing, semantic validation, or wire synthesis fails.
pub fn inspect_frasm_to_previews(source: &str) -> Result<Vec<PacketPreview>, String> {
    check_source_size(source)?;
    let program = parse_program(source).map_err(|e| e.to_string())?;
    let ast_protocols = program.emitted_protocols();
    let packets = compile_program(&program)?;
    let base_ns = packets.first().map_or(0, |(_, ts)| *ts);

    let previews = packets
        .iter()
        .enumerate()
        .map(|(idx, (bytes, ts_ns))| {
            let mut hex = String::with_capacity(bytes.len().saturating_mul(3));
            for (i, b) in bytes.iter().enumerate() {
                if i > 0 {
                    hex.push(' ');
                }
                let _ = write!(hex, "{b:02x}");
            }
            let (source_dest, detected_proto, summary) = summarize_frame(bytes);
            let protocol = ast_protocols
                .get(idx)
                .map_or(detected_proto, |p| p.display_label().to_string());
            PacketPreview {
                index: idx + 1,
                timestamp_ms: ts_ns.saturating_sub(base_ns) as f64 / 1_000_000.0,
                length: bytes.len(),
                hex,
                source_dest,
                protocol,
                summary,
            }
        })
        .collect();

    Ok(previews)
}

/// Compatibility alias for [`inspect_frasm_to_previews`].
///
/// # Errors
/// Returns a human-readable compilation error string if parsing or wire synthesis fails.
pub fn inspect_fasm_to_previews(source: &str) -> Result<Vec<PacketPreview>, String> {
    inspect_frasm_to_previews(source)
}

/// Returns decoded frame metadata, endpoint/protocol summaries, and hex strings for `.frasm` source.
///
/// # Errors
/// Returns a JavaScript `Error` if `source` exceeds [`MAX_WASM_SOURCE_BYTES`], compilation fails,
/// or JS serialization fails.
#[wasm_bindgen(unchecked_return_type = "PacketPreview[]")]
pub fn inspect_frasm(source: &str) -> Result<JsValue, JsError> {
    let previews = inspect_frasm_to_previews(source).map_err(|e| JsError::new(&e))?;
    Ok(serialize_to_js_object(&previews)?)
}

/// Returns decoded frame metadata for `.frasm` source (`inspectFrasm` camelCase alias).
///
/// # Errors
/// Returns a JavaScript `Error` if `source` exceeds [`MAX_WASM_SOURCE_BYTES`], compilation fails,
/// or JS serialization fails.
#[wasm_bindgen(js_name = inspectFrasm, unchecked_return_type = "PacketPreview[]")]
pub fn inspect_frasm_js(source: &str) -> Result<JsValue, JsError> {
    inspect_frasm(source)
}

/// Returns decoded frame metadata, endpoint/protocol summaries, and hex strings (`inspect_fasm` 2.x alias).
///
/// # Errors
/// Returns a JavaScript `Error` if `source` exceeds [`MAX_WASM_SOURCE_BYTES`], compilation fails,
/// or JS serialization fails.
#[wasm_bindgen(unchecked_return_type = "PacketPreview[]")]
pub fn inspect_fasm(source: &str) -> Result<JsValue, JsError> {
    inspect_frasm(source)
}

/// Compiles `.frasm` source into an in-memory classic libpcap (`.pcap`) byte vector without invoking JS bindings.
///
/// # Errors
/// Returns a human-readable error string if `source` exceeds [`MAX_WASM_SOURCE_BYTES`] or if
/// parsing, wire synthesis, or serialization fails.
pub fn compile_frasm_to_pcap(source: &str) -> Result<Vec<u8>, String> {
    check_source_size(source)?;
    let program = parse_program(source).map_err(|e| e.to_string())?;
    let packets = compile_program(&program)?;
    serialize_classic_pcap(&packets)
}

/// Compiles `.frasm` source into a classic libpcap (`.pcap`) byte array (`compileFrasmToPcap` JS `Uint8Array`).
///
/// # Errors
/// Returns a JavaScript `JsValue` error if `source` exceeds [`MAX_WASM_SOURCE_BYTES`] or if
/// parsing, validation, or serialization fails.
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = compileFrasmToPcap)]
pub fn compile_frasm_to_pcap_js(source: &str) -> Result<Vec<u8>, JsValue> {
    compile_frasm_to_pcap(source).map_err(|e| JsError::new(&e).into())
}

/// Compiles `.frasm` source into a classic libpcap (`.pcap`) byte array (`compile_frasm_to_pcap` JS alias).
///
/// # Errors
/// Returns a JavaScript `JsValue` error if `source` exceeds [`MAX_WASM_SOURCE_BYTES`] or if
/// parsing, validation, or serialization fails.
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = compile_frasm_to_pcap)]
pub fn compile_frasm_to_pcap_wasm(source: &str) -> Result<Vec<u8>, JsValue> {
    compile_frasm_to_pcap(source).map_err(|e| JsError::new(&e).into())
}

/// Compiles `.frasm` source into an in-memory PCAPNG byte vector with `NameResolutionBlock` host
/// metadata and per-frame `comment` options without invoking JS bindings.
///
/// # Errors
/// Returns a human-readable error string if `source` exceeds [`MAX_WASM_SOURCE_BYTES`] or if
/// parsing, wire synthesis, or PCAPNG serialization fails.
pub fn compile_frasm_to_pcapng_bytes(source: &str) -> Result<Vec<u8>, String> {
    check_source_size(source)?;
    let program = parse_program(source).map_err(|e| e.to_string())?;
    let (compiled, hosts) = compile_program_with_metadata(&program)?;
    let raw_meta: Vec<(Vec<u8>, u64, Option<String>)> = compiled
        .into_iter()
        .map(|frame| (frame.data, frame.timestamp_ns, frame.comment))
        .collect();
    serialize_pcapng_with_metadata(&raw_meta, &hosts)
}

/// Compiles `.frasm` source into a standards-compliant PCAPNG byte array (JS `Uint8Array`).
///
/// # Errors
/// Returns a JavaScript `Error` if `source` exceeds [`MAX_WASM_SOURCE_BYTES`] or compilation fails.
#[wasm_bindgen]
pub fn compile_frasm_to_pcapng(source: &str) -> Result<Vec<u8>, JsError> {
    compile_frasm_to_pcapng_bytes(source).map_err(|e| JsError::new(&e))
}

/// Compiles `.frasm` source into a standards-compliant PCAPNG byte array (`compileFrasm` alias).
///
/// # Errors
/// Returns a JavaScript `Error` if `source` exceeds [`MAX_WASM_SOURCE_BYTES`] or compilation fails.
#[wasm_bindgen(js_name = compileFrasm)]
pub fn compile_frasm(source: &str) -> Result<Vec<u8>, JsError> {
    compile_frasm_to_pcapng(source)
}

/// Compiles `.frasm` source into a standards-compliant PCAPNG byte array (`compile_fasm_to_pcapng` 2.x alias).
///
/// # Errors
/// Returns a JavaScript `Error` if `source` exceeds [`MAX_WASM_SOURCE_BYTES`] or compilation fails.
#[wasm_bindgen]
pub fn compile_fasm_to_pcapng(source: &str) -> Result<Vec<u8>, JsError> {
    compile_frasm_to_pcapng(source)
}

/// Compiles `.frasm` source into a standards-compliant PCAPNG byte array (`compileFasm` 2.x alias).
///
/// # Errors
/// Returns a JavaScript `Error` if `source` exceeds [`MAX_WASM_SOURCE_BYTES`] or compilation fails.
#[wasm_bindgen(js_name = compileFasm)]
pub fn compile_fasm(source: &str) -> Result<Vec<u8>, JsError> {
    compile_frasm_to_pcapng(source)
}

/// Shared size-guarded core decompilation helper returning [`ReverseOutput`] or [`ReversePcapError`].
fn reverse_pcap_core(pcap_bytes: &[u8]) -> Result<ReverseOutput, ReversePcapError> {
    check_pcap_size(pcap_bytes)?;
    reverse_pcap_bytes(pcap_bytes).map_err(|err| ReversePcapError::new(err.to_string()))
}

/// Decompiles an in-memory `.pcap` or `.pcapng` byte slice into a typed [`ReversePcapResult`]
/// or [`ReversePcapError`] without invoking JavaScript heap bindings.
///
/// # Errors
/// Returns [`ReversePcapError`] if `pcap_bytes` exceeds [`MAX_WASM_PCAP_BYTES`] or is not a
/// valid `.pcap` or `.pcapng` capture.
pub fn reverse_pcap_to_result(pcap_bytes: &[u8]) -> Result<ReversePcapResult, ReversePcapError> {
    reverse_pcap_core(pcap_bytes).map(ReversePcapResult::from)
}

/// Decompiles an in-memory `.pcap` or `.pcapng` capture (`Uint8Array`) into canonical `.frasm`
/// source code and summary counts (`{ success: true, frasm, fasm, packetCount, hostCount }`).
///
/// # Errors
/// Returns a structured plain `JsValue` error object (`{ success: false, error, message }`) if
/// `pcap_bytes` exceeds [`MAX_WASM_PCAP_BYTES`] or is not a valid `.pcap` or `.pcapng` capture.
#[wasm_bindgen(unchecked_return_type = "ReversePcapResult")]
pub fn reverse_pcap(pcap_bytes: &[u8]) -> Result<JsValue, JsValue> {
    match reverse_pcap_core(pcap_bytes) {
        Ok(out) => {
            let payload = ReversePcapJsPayload {
                success: true,
                frasm: &out.fasm,
                fasm: &out.fasm,
                packet_count: out.packet_count,
                host_count: out.host_count,
            };
            serialize_to_js_object(&payload).map_err(|e| JsValue::from_str(&e.to_string()))
        }
        Err(err) => {
            let fallback = err.message.clone();
            Err(serialize_to_js_object(&err).unwrap_or_else(|_| JsValue::from_str(&fallback)))
        }
    }
}

/// Decompiles an in-memory `.pcap` or `.pcapng` capture (`reversePcap` camelCase alias).
///
/// # Errors
/// Returns a structured plain `JsValue` error object (`{ success: false, error, message }`) if
/// `pcap_bytes` exceeds [`MAX_WASM_PCAP_BYTES`] or is not a valid `.pcap` or `.pcapng` capture.
#[wasm_bindgen(js_name = reversePcap, unchecked_return_type = "ReversePcapResult")]
pub fn reverse_pcap_js(pcap_bytes: &[u8]) -> Result<JsValue, JsValue> {
    reverse_pcap(pcap_bytes)
}

/// Serializes `(frame_bytes, timestamp_ns)` tuples into an in-memory PCAPNG byte vector
/// with nanosecond timestamp resolution (`IfTsResol = 9`).
pub fn packets_to_pcapng(packets: &[(Vec<u8>, u64)]) -> Vec<u8> {
    serialize_pcapng(packets).unwrap_or_default()
}

/// Unit tests for UTF-16 span mapping, diagnostics, packet previews, PCAP/PCAPNG serialization,
/// input size caps, and capture decompilation.
#[cfg(test)]
mod tests {
    use super::*;

    /// Verifies that `byte_offset_to_utf16_line_col` maps multi-byte UTF-8 and astral-plane
    /// surrogate pairs to zero-based UTF-16 line and column indices and clamps mid-character offsets.
    #[test]
    fn test_utf16_line_col_handles_multibyte_utf8_and_surrogate_pairs() {
        let src = "host host1 { ip 10.0.0.1 }\n// 🔥\ncompile { host1 -> host1 icmp }";
        assert_eq!(byte_offset_to_utf16_line_col(src, 0), (0, 0));
        let line2_start = src.find("//").unwrap_or(0);
        assert_eq!(byte_offset_to_utf16_line_col(src, line2_start + 7), (1, 5));
        assert_eq!(byte_offset_to_utf16_line_col(src, line2_start + 5), (1, 3));
        assert_eq!(
            byte_offset_to_utf16_line_col(src, src.len() + 100),
            byte_offset_to_utf16_line_col(src, src.len())
        );
    }

    /// Verifies that `byte_offset_to_utf16_line_col`, `make_diagnostic`, and
    /// `validate_frasm_to_diagnostics` handle `\r\n` (CRLF), bare `\r`, astral emoji before `\r\n`,
    /// and zero-width EOF clamping without off-by-one UTF-16 column drift.
    #[test]
    fn test_utf16_line_col_handles_crlf_bare_cr_and_eof_clamp() {
        let crlf = "host a { ip 10.0.0.1 }\r\n// 🔥\r\ncompile { a -> a icmp }";
        let cmt = crlf.find("//").unwrap_or(0);
        assert_eq!(byte_offset_to_utf16_line_col(crlf, cmt - 2), (0, 22));
        assert_eq!(byte_offset_to_utf16_line_col(crlf, cmt), (1, 0));
        assert_eq!(byte_offset_to_utf16_line_col(crlf, cmt + 7), (1, 5));
        assert_eq!(byte_offset_to_utf16_line_col(crlf, cmt + 8), (2, 0));
        assert_eq!(byte_offset_to_utf16_line_col(crlf, cmt + 9), (2, 0));
        assert_eq!(byte_offset_to_utf16_line_col(crlf, cmt + 16), (2, 7));

        let bare_cr = "host a { ip 10.0.0.1 }\r// 🔥\rcompile { a -> a icmp }";
        let bare_cmt = bare_cr.find("//").unwrap_or(0);
        assert_eq!(byte_offset_to_utf16_line_col(bare_cr, bare_cmt), (1, 0));
        assert_eq!(byte_offset_to_utf16_line_col(bare_cr, bare_cmt + 7), (1, 5));
        assert_eq!(byte_offset_to_utf16_line_col(bare_cr, bare_cmt + 8), (2, 0));

        let crlf_err = "host a { ip 10.0.0.1 }\r\ncompile {\r\n    a -> a icmp ECHO_REQUEST\r\n}";
        let diags = validate_frasm_to_diagnostics(crlf_err);
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0].start_line, 2);
        assert_eq!(diags[0].start_col, 16);
        assert_eq!(diags[0].end_line, 2);
        assert_eq!(diags[0].end_col, 28);

        let eof_diag = make_diagnostic("host a {\r\n", usize::MAX, usize::MAX, "eof".to_string(), None);
        assert_eq!((eof_diag.start_line, eof_diag.start_col), (1, 0));
        assert_eq!((eof_diag.end_line, eof_diag.end_col), (1, 0));
    }

    /// Verifies in-memory `.frasm` -> PCAPNG compilation, enriched `PacketPreview` summaries, and `reverse_pcap_to_result`.
    #[test]
    fn test_packets_to_pcapng_preview_and_reverse_pcap_roundtrip_in_memory() {
        let src = "host host1 { ip 192.0.2.10 mac 00:11:22:33:44:55 }\n\
                   host host2 { ip 192.0.2.20 mac 00:aa:bb:cc:dd:ee }\n\
                   compile {\n\
                       host1 -> host2 vlan 100 dns query txid 0x1a2b qname \"example.com\" qtype \"a\"\n\
                   }";
        assert!(validate_fasm_to_diagnostics(src).is_empty());

        let previews = inspect_fasm_to_previews(src).expect("inspect valid .frasm");
        assert_eq!(previews.len(), 1);
        assert_eq!(previews[0].index, 1);
        assert_eq!(previews[0].source_dest, "192.0.2.10 -> 192.0.2.20");
        assert_eq!(previews[0].protocol, "DNS");
        assert!(previews[0].summary.contains("[VLAN=100]"));
        assert!(!previews[0].hex.is_empty());

        let program = parse_program(src).expect("parse valid .frasm");
        let packets = compile_program(&program).expect("compile packets");
        let pcapng_bytes = packets_to_pcapng(&packets);

        let rev = reverse_pcap_to_result(&pcapng_bytes).expect("reverse pcapng bytes");
        assert!(rev.success);
        assert_eq!(rev.packet_count, 1);
        assert_eq!(rev.host_count, 2);
        assert_eq!(rev.frasm, rev.fasm);
        assert!(rev.frasm.contains("host1"));
        assert!(rev.frasm.contains("host2"));
        assert!(rev.frasm.contains("dns"));
    }

    /// Verifies that backend errors highlight the offending statement or `compile` block instead of `(0, 0)`,
    /// and that strict-lowercase keyword hints are preserved in `IdeDiagnostic.help`.
    #[test]
    fn test_validate_fasm_backend_span_and_lowercase_help_hints() {
        let comment_and_compile = "// compile comment on line 0\n\
                                   host host1 { ip 10.0.0.1 }\n\
                                   compile {\n\
                                       host1 -> host1 icmp\n\
                                   }";
        let (s_byte, e_byte) = find_backend_error_span(comment_and_compile, "generic backend failure");
        assert_eq!(&comment_and_compile[s_byte..e_byte], "compile");
        assert_eq!(byte_offset_to_utf16_line_col(comment_and_compile, s_byte), (2, 0));

        let bad_backend = "host host1 { ip 10.0.0.1 }\n\
                           host host2 { ip 10.0.0.2 }\n\
                           compile {\n\
                               host1 -> host2 snmp3 trap user \"ops\" priv aes \"PrivPass123!\"\n\
                           }";
        let diags = validate_fasm_to_diagnostics(bad_backend);
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0].start_line, 3);
        assert!(diags[0].start_col > 0);

        let bad_kw = "host host1 { ip 10.0.0.1 }\n\
                      compile {\n\
                          host1 -> host1 icmp echo_request\n\
                      }";
        let kw_diags = validate_fasm_to_diagnostics(bad_kw);
        assert_eq!(kw_diags.len(), 1);
        let help = kw_diags[0].help.as_deref().unwrap_or("");
        assert!(
            help.contains("replace 'echo_request' with 'echorequest'"),
            "expected strict-lowercase help hint, got: {help}"
        );
    }

    /// Verifies that corrupt or empty capture inputs return a structured [`ReversePcapError`] without panicking.
    #[test]
    fn test_reverse_pcap_rejects_corrupt_bytes_without_panicking() {
        for bad in [&b""[..], &b"xyz"[..], &b"not a pcap capture"[..]] {
            let err = reverse_pcap_to_result(bad).expect_err("must reject invalid capture bytes");
            assert!(!err.success);
            assert!(!err.error.is_empty());
            assert_eq!(err.error, err.message);
        }
    }

    /// Verifies `compile_frasm_to_pcap` classic libpcap magic bytes (usec & nsec) and AST `PacketPreview.protocol`.
    #[test]
    fn test_compile_frasm_to_pcap_classic_magic_and_ast_protocol_labels() {
        let usec_src = "host a { ip 10.0.0.1 }\nhost b { ip 10.0.0.2 }\ncompile {\n    a -> b http2 ping streamid 0 wait 5ms\n    a <- b websocket text payload \"ok\" wait 5ms\n}";
        let pcap_bytes = compile_frasm_to_pcap(usec_src).expect("compile classic .pcap");
        assert!(pcap_bytes.len() > 40);
        assert!(
            matches!(
                &pcap_bytes[0..4],
                [0xd4, 0xc3, 0xb2, 0xa1] | [0xa1, 0xb2, 0xc3, 0xd4]
            ),
            "expected classic microsecond libpcap magic bytes, got {:02x?}",
            &pcap_bytes[0..4]
        );

        let previews = inspect_fasm_to_previews(usec_src).expect("inspect previews");
        assert_eq!(previews.len(), 2);
        assert_eq!(previews[0].protocol, "HTTP2");
        assert_eq!(previews[1].protocol, "WEBSOCKET");

        let rev = reverse_pcap_to_result(&pcap_bytes).expect("reverse classic .pcap");
        assert_eq!(rev.packet_count, 2);

        let nsec_src = "host a { ip 10.0.0.1 }\nhost b { ip 10.0.0.2 }\ncompile {\n    a -> b icmp wait 500ns\n    a <- b icmp\n}";
        let nsec_bytes = compile_frasm_to_pcap(nsec_src).expect("compile nanosecond .pcap");
        assert!(
            matches!(
                &nsec_bytes[0..4],
                [0x4d, 0x3c, 0xb2, 0xa1] | [0xa1, 0xb2, 0x3c, 0x4d]
            ),
            "expected classic nanosecond libpcap magic bytes, got {:02x?}",
            &nsec_bytes[0..4]
        );
    }

    /// Verifies v3.3.0 frame dissection delegation (`frameassembly::inspect::summarize_frame`),
    /// `compile_frasm_to_pcapng_bytes` NRB/comment metadata, and reverse roundtrips on new L2/L3/L7 protocols.
    #[test]
    fn test_v330_inspect_delegation_pcapng_metadata_and_reverse() {
        let src = "host h1 { ip 10.10.0.1 mac 00:11:22:33:44:01 }\n\
                   host h2 { ip 10.10.0.2 mac 00:11:22:33:44:02 }\n\
                   compile {\n\
                       h1 -> h2 pppoe comment \"pppoe pdi\" wait 5ms\n\
                       h1 -> h2 profinet wait 5ms\n\
                       h1 -> h2 ngap comment \"5g ngap\" wait 5ms\n\
                       repeat 2 {\n\
                           h1 -> h2 llmnr wait 2ms\n\
                       }\n\
                   }";
        assert!(validate_frasm_to_diagnostics(src).is_empty());

        let previews = inspect_frasm_to_previews(src).expect("inspect v3.3.0 protocols");
        assert_eq!(previews.len(), 5);
        assert_eq!(previews[0].protocol, "PPPOE");
        assert!(previews[0].summary.contains("PPPoE"));
        assert_eq!(previews[1].protocol, "PROFINET");
        assert!(previews[1].summary.contains("PROFINET"));
        assert_eq!(previews[2].protocol, "NGAP");
        assert_eq!(previews[3].protocol, "LLMNR");
        assert_eq!(previews[4].protocol, "LLMNR");

        let pcapng = compile_frasm_to_pcapng_bytes(src).expect("compile v3.3.0 pcapng");
        assert_eq!(&pcapng[0..4], &[0x0A, 0x0D, 0x0D, 0x0A]);
        assert!(pcapng.windows(9).any(|w| w == b"pppoe pdi"));
        assert!(pcapng.windows(7).any(|w| w == b"5g ngap"));

        let rev = reverse_pcap_to_result(&pcapng).expect("reverse v3.3.0 pcapng");
        assert_eq!(rev.packet_count, 5);
        assert!(rev.frasm.contains("pppoe"));
        assert!(rev.frasm.contains("ngap"));
        assert!(rev.frasm.contains("llmnr"));

        let srv6_src = "host v6a { ip 2001:db8::1 mac 00:11:22:33:44:11 }\n\
                        host v6b { ip 2001:db8::2 mac 00:11:22:33:44:22 }\n\
                        compile { v6a -> v6b srv6 }";
        let srv6_previews = inspect_frasm_to_previews(srv6_src).expect("inspect srv6");
        assert_eq!(srv6_previews.len(), 1);
        assert_eq!(srv6_previews[0].protocol, "SRV6");
        assert_eq!(srv6_previews[0].source_dest, "2001:db8::1 -> 2001:db8::2");
        assert!(srv6_previews[0].summary.contains("SRv6"));
    }

    /// Verifies that oversized browser inputs exceeding [`MAX_WASM_SOURCE_BYTES`] and
    /// [`MAX_WASM_PCAP_BYTES`] return structured diagnostics or errors without panicking.
    #[test]
    fn test_wasm_input_size_caps_return_structured_errors() {
        let oversized_source = "a".repeat(MAX_WASM_SOURCE_BYTES + 1);
        let diags = validate_frasm_to_diagnostics(&oversized_source);
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0].start_line, 0);
        assert_eq!(diags[0].start_col, 0);
        assert!(diags[0].message.contains("exceeds maximum supported WebAssembly size"));
        assert!(diags[0].help.is_some());

        assert!(inspect_frasm_to_previews(&oversized_source).is_err());
        assert!(compile_frasm_to_pcap(&oversized_source).is_err());
        assert!(compile_frasm_to_pcapng_bytes(&oversized_source).is_err());

        let oversized_pcap = vec![0u8; MAX_WASM_PCAP_BYTES + 1];
        let rev_err = reverse_pcap_to_result(&oversized_pcap).expect_err("reject oversized capture");
        assert!(!rev_err.success);
        assert!(rev_err.error.contains("exceeds maximum supported WebAssembly size"));
        assert_eq!(rev_err.error, rev_err.message);
    }
}
