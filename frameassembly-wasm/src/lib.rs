//! WebAssembly bindings, PCAP/PCAPNG-to-`.fasm` decompiler, frame inspector, and UTF-16 IDE
//! diagnostics for the FrameAssembly (`.fasm`) network packet synthesis compiler.
//!
//! This crate exposes `validate_fasm` (`validateFasm`), `inspect_fasm`,
//! `compile_fasm_to_pcapng` (`compileFasm`), and `reversePcap` (`reverse_pcap`) to browser
//! environments, Node.js test harnesses, and web-based code editors (Monaco, CodeMirror,
//! VS Code Web) via `wasm-bindgen`. It compiles declarative `.fasm` specifications across all
//! 81 native Layer 2 through Layer 7 protocols into deterministic nanosecond-resolution PCAPNG
//! byte arrays (`Uint8Array`), decompiles binary `.pcap` and `.pcapng` packet captures back into
//! canonical lowercase `.fasm` code in memory via `frameassembly::reverse::reverse_pcap_bytes`,
//! and maps compiler diagnostic byte spans into zero-based UTF-16 line and column coordinates.

use std::fmt::Write;

use frameassembly::backend::compile_program;
use frameassembly::parser::parse_program;
use frameassembly::reverse::reverse_pcap_bytes;
use miette::Diagnostic;
use serde::Serialize;
use wasm_bindgen::prelude::*;

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
}

export interface ReversePcapResult {
    success: boolean;
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

/// Zero-based UTF-16 source range diagnostic and remediation hint for browser code editors.
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
    /// Optional plain-English remediation hint.
    pub help: Option<String>,
}

/// Summary metadata and hexadecimal wire dump for a single synthesized Ethernet frame.
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
}

/// Decompilation summary and canonical `.fasm` code returned by [`reverse_pcap`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReversePcapResult {
    /// Indicates that the binary capture was decompiled into `.fasm` code (`true`).
    pub success: bool,
    /// Generated canonical lowercase `.fasm` source code.
    pub fasm: String,
    /// Total number of packets reversed from the capture.
    pub packet_count: usize,
    /// Total number of `host_N` definitions emitted in the `.fasm` program.
    pub host_count: usize,
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

/// Converts a UTF-8 byte offset within `source` into a zero-based `(line, utf16_col)` pair
/// suitable for Monaco Editor, CodeMirror 6, and VS Code Web diagnostics.
pub fn byte_offset_to_utf16_line_col(source: &str, byte_offset: usize) -> (u32, u32) {
    let clamped = byte_offset.min(source.len());
    let safe_end = (0..=clamped)
        .rev()
        .find(|&i| source.is_char_boundary(i))
        .unwrap_or(0);

    let prefix = &source[..safe_end];
    let line = prefix.bytes().filter(|&b| b == b'\n').count() as u32;
    let col = match prefix.rfind('\n') {
        Some(nl) => prefix[nl + 1..].encode_utf16().count() as u32,
        None => prefix.encode_utf16().count() as u32,
    };
    (line, col)
}

/// Converts a UTF-8 byte offset within `source` into a zero-based `(line, utf16_col)` pair.
fn byte_to_utf16_pos(source: &str, byte_offset: usize) -> (u32, u32) {
    byte_offset_to_utf16_line_col(source, byte_offset)
}

/// Validates `.fasm` source and returns UTF-16 line/column diagnostics for Monaco/CodeMirror.
#[wasm_bindgen(unchecked_return_type = "IdeDiagnostic[]")]
pub fn validate_fasm(source: &str) -> Result<JsValue, JsError> {
    let mut diagnostics = Vec::new();

    match parse_program(source) {
        Ok(program) => {
            if let Err(err) = compile_program(&program) {
                diagnostics.push(IdeDiagnostic {
                    start_line: 0,
                    start_col: 0,
                    end_line: 0,
                    end_col: 1,
                    message: err,
                    help: None,
                });
            }
        }
        Err(err) => push_diagnostic(source, &err, &mut diagnostics),
    }

    Ok(serde_wasm_bindgen::to_value(&diagnostics)?)
}

/// Validates `.fasm` source and returns UTF-16 line/column diagnostics (`validateFasm` alias).
#[wasm_bindgen(js_name = validateFasm, unchecked_return_type = "IdeDiagnostic[]")]
pub fn validate_fasm_js(source: &str) -> Result<JsValue, JsError> {
    validate_fasm(source)
}

/// Returns decoded frame metadata and hex strings for a browser packet inspector.
#[wasm_bindgen(unchecked_return_type = "PacketPreview[]")]
pub fn inspect_fasm(source: &str) -> Result<JsValue, JsError> {
    let program = parse_program(source).map_err(|e| JsError::new(&e.to_string()))?;
    let packets = compile_program(&program).map_err(|e| JsError::new(&e.to_string()))?;
    let base_ns = packets.first().map_or(0, |(_, ts)| *ts);

    let previews: Vec<PacketPreview> = packets
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
            PacketPreview {
                index: idx + 1,
                timestamp_ms: ts_ns.saturating_sub(base_ns) as f64 / 1_000_000.0,
                length: bytes.len(),
                hex,
            }
        })
        .collect();

    Ok(serde_wasm_bindgen::to_value(&previews)?)
}

/// Compiles `.fasm` source into a standards-compliant PCAPNG byte array (JS `Uint8Array`).
#[wasm_bindgen]
pub fn compile_fasm_to_pcapng(source: &str) -> Result<Vec<u8>, JsError> {
    let program = parse_program(source).map_err(|e| JsError::new(&e.to_string()))?;
    let packets = compile_program(&program).map_err(|e| JsError::new(&e.to_string()))?;
    Ok(packets_to_pcapng(&packets))
}

/// Compiles `.fasm` source into a standards-compliant PCAPNG byte array (`compileFasm` alias).
#[wasm_bindgen(js_name = compileFasm)]
pub fn compile_fasm(source: &str) -> Result<Vec<u8>, JsError> {
    compile_fasm_to_pcapng(source)
}

/// Decompiles an in-memory `.pcap` or `.pcapng` byte slice into a typed [`ReversePcapResult`]
/// or [`ReversePcapError`] without invoking JavaScript heap bindings.
///
/// # Errors
/// Returns [`ReversePcapError`] if `pcap_bytes` is not a valid `.pcap` or `.pcapng` capture.
pub fn reverse_pcap_to_result(pcap_bytes: &[u8]) -> Result<ReversePcapResult, ReversePcapError> {
    match frameassembly::reverse::reverse_pcap_bytes(pcap_bytes) {
        Ok(out) => Ok(ReversePcapResult {
            success: true,
            fasm: out.fasm,
            packet_count: out.packet_count,
            host_count: out.host_count,
        }),
        Err(err) => {
            let message = err.to_string();
            Err(ReversePcapError {
                success: false,
                error: message.clone(),
                message,
            })
        }
    }
}

/// Decompiles an in-memory `.pcap` or `.pcapng` capture (`Uint8Array`) into canonical `.fasm`
/// source code and summary counts (`{ success: true, fasm, packetCount, hostCount }`).
///
/// # Errors
/// Returns a structured `JsValue` error object (`{ success: false, error, message }`) if
/// `pcap_bytes` is not a valid `.pcap` or `.pcapng` capture.
#[wasm_bindgen(js_name = reversePcap, unchecked_return_type = "ReversePcapResult")]
pub fn reverse_pcap(pcap_bytes: &[u8]) -> Result<JsValue, JsValue> {
    let _ = reverse_pcap_bytes;
    match reverse_pcap_to_result(pcap_bytes) {
        Ok(result) => serde_wasm_bindgen::to_value(&result)
            .map_err(|e| JsValue::from_str(&e.to_string())),
        Err(err) => {
            let fallback = err.message.clone();
            Err(serde_wasm_bindgen::to_value(&err)
                .unwrap_or_else(|_| JsValue::from_str(&fallback)))
        }
    }
}

/// Serializes `(frame_bytes, timestamp_ns)` tuples into an in-memory PCAPNG byte vector
/// with nanosecond timestamp resolution (`IfTsResol = 9`).
pub fn packets_to_pcapng(packets: &[(Vec<u8>, u64)]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(60 + packets.len() * 96);

    // Section Header Block (28 bytes)
    buf.extend_from_slice(&0x0A0D_0D0Au32.to_le_bytes());
    buf.extend_from_slice(&28u32.to_le_bytes());
    buf.extend_from_slice(&0x1A2B_3C4Du32.to_le_bytes());
    buf.extend_from_slice(&1u16.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&(-1i64).to_le_bytes());
    buf.extend_from_slice(&28u32.to_le_bytes());

    // Interface Description Block (32 bytes, Ethernet + snaplen 65535 + nanosecond resolution)
    buf.extend_from_slice(&1u32.to_le_bytes());
    buf.extend_from_slice(&32u32.to_le_bytes());
    buf.extend_from_slice(&1u16.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&65_535u32.to_le_bytes());
    buf.extend_from_slice(&9u16.to_le_bytes());
    buf.extend_from_slice(&1u16.to_le_bytes());
    buf.extend_from_slice(&[9, 0, 0, 0]);
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&32u32.to_le_bytes());

    // Enhanced Packet Blocks
    for (frame, ts_ns) in packets {
        let orig_len = frame.len() as u32;
        let padded_len = (frame.len() + 3) & !3;
        let block_len = (32 + padded_len) as u32;

        buf.extend_from_slice(&6u32.to_le_bytes());
        buf.extend_from_slice(&block_len.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.extend_from_slice(&((ts_ns >> 32) as u32).to_le_bytes());
        buf.extend_from_slice(&(*ts_ns as u32).to_le_bytes());
        buf.extend_from_slice(&orig_len.to_le_bytes());
        buf.extend_from_slice(&orig_len.to_le_bytes());
        buf.extend_from_slice(frame);
        buf.resize(buf.len() + (padded_len - frame.len()), 0);
        buf.extend_from_slice(&block_len.to_le_bytes());
    }

    buf
}

/// Extracts span coordinates and remediation hints from a `miette::Diagnostic` and appends an `IdeDiagnostic`.
fn push_diagnostic(source: &str, err: &dyn Diagnostic, out: &mut Vec<IdeDiagnostic>) {
    let message = err.to_string();
    let help = err.help().map(|h| h.to_string());

    if let Some(mut labels) = err.labels()
        && let Some(span) = labels.next()
    {
        let (start_line, start_col) = byte_to_utf16_pos(source, span.offset());
        let (end_line, end_col) = byte_to_utf16_pos(source, span.offset() + span.len().max(1));
        out.push(IdeDiagnostic {
            start_line,
            start_col,
            end_line,
            end_col,
            message,
            help,
        });
    } else {
        out.push(IdeDiagnostic {
            start_line: 0,
            start_col: 0,
            end_line: 0,
            end_col: 1,
            message,
            help,
        });
    }
}

/// Unit tests for UTF-16 span mapping, in-memory PCAPNG serialization, and PCAP/PCAPNG decompilation.
#[cfg(test)]
mod tests {
    use super::*;

    /// Verifies that `byte_offset_to_utf16_line_col` maps multi-byte UTF-8 and astral-plane
    /// surrogate pairs to zero-based UTF-16 line and column indices and clamps mid-character offsets.
    #[test]
    fn test_utf16_line_col_handles_multibyte_utf8_and_surrogate_pairs() {
        let src = "HOST a { IP 10.0.0.1 }\n// 🔥\nCOMPILE { a -> a ICMP }";
        assert_eq!(byte_offset_to_utf16_line_col(src, 0), (0, 0));
        let line2_start = src.find("//").unwrap_or(0);
        assert_eq!(byte_offset_to_utf16_line_col(src, line2_start + 7), (1, 5));
        assert_eq!(byte_offset_to_utf16_line_col(src, line2_start + 5), (1, 3));
        assert_eq!(
            byte_offset_to_utf16_line_col(src, src.len() + 100),
            byte_offset_to_utf16_line_col(src, src.len())
        );
    }

    /// Verifies in-memory `.fasm` -> PCAPNG compilation and `reverse_pcap_to_result` decompilation.
    #[test]
    fn test_packets_to_pcapng_and_reverse_pcap_roundtrip_in_memory() {
        let src = "HOST client { IP 192.0.2.10 MAC 00:11:22:33:44:55 }\n\
                   HOST server { IP 192.0.2.20 MAC 00:aa:bb:cc:dd:ee }\n\
                   COMPILE {\n\
                       client -> server DNS QUERY TXID 0x1a2b QNAME \"example.com\" QTYPE \"A\"\n\
                   }";
        let program = parse_program(src).expect("parse valid .fasm");
        let packets = compile_program(&program).expect("compile packets");
        let pcapng_bytes = packets_to_pcapng(&packets);

        let rev = reverse_pcap_to_result(&pcapng_bytes).expect("reverse pcapng bytes");
        assert!(rev.success);
        assert_eq!(rev.packet_count, 1);
        assert_eq!(rev.host_count, 2);
        assert!(rev.fasm.contains("dns"));
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
}
