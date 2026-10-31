// Used for an experimental NPM package
use std::fmt::Write;

use frameassembly::backend::compile_program;
use frameassembly::parser::parse_program;
use miette::Diagnostic;
use serde::Serialize;
use wasm_bindgen::prelude::*;

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
"#;

#[derive(Serialize)]
pub struct IdeDiagnostic {
    pub start_line: u32,
    pub start_col: u32,
    pub end_line: u32,
    pub end_col: u32,
    pub message: String,
    pub help: Option<String>,
}

#[derive(Serialize)]
pub struct PacketPreview {
    pub index: usize,
    pub timestamp_ms: f64,
    pub length: usize,
    pub hex: String,
}

fn byte_to_utf16_pos(source: &str, byte_offset: usize) -> (u32, u32) {
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

/// Validates .fasm source and returns UTF-16 line/column diagnostics for Monaco/CodeMirror.
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

/// Compiles .fasm source into a standards-compliant PCAPNG byte array (JS Uint8Array).
#[wasm_bindgen]
pub fn compile_fasm_to_pcapng(source: &str) -> Result<Vec<u8>, JsError> {
    let program = parse_program(source).map_err(|e| JsError::new(&e.to_string()))?;
    let packets = compile_program(&program).map_err(|e| JsError::new(&e.to_string()))?;
    Ok(packets_to_pcapng(&packets))
}

fn packets_to_pcapng(packets: &[(Vec<u8>, u64)]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(60 + packets.len() * 96);

    // Section Header Block (28 bytes)
    buf.extend_from_slice(&0x0A0D_0D0Au32.to_le_bytes());
    buf.extend_from_slice(&28u32.to_le_bytes());
    buf.extend_from_slice(&0x1A2B_3C4Du32.to_le_bytes());
    buf.extend_from_slice(&1u16.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&(-1i64).to_le_bytes());
    buf.extend_from_slice(&28u32.to_le_bytes());

    // Interface Description Block (32 bytes, Ethernet + nanosecond resolution)
    buf.extend_from_slice(&1u32.to_le_bytes());
    buf.extend_from_slice(&32u32.to_le_bytes());
    buf.extend_from_slice(&1u16.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&262_144u32.to_le_bytes());
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
