/* tslint:disable */
/* eslint-disable */

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



/**
 * Compiles `.fasm` source into a standards-compliant PCAPNG byte array (`compileFasm` alias).
 */
export function compileFasm(source: string): Uint8Array;

/**
 * Compiles `.fasm` source into a standards-compliant PCAPNG byte array (JS `Uint8Array`).
 */
export function compile_fasm_to_pcapng(source: string): Uint8Array;

/**
 * Returns decoded frame metadata, endpoint/protocol summaries, and hex strings for packet ladder inspectors.
 */
export function inspect_fasm(source: string): PacketPreview[];

/**
 * Decompiles an in-memory `.pcap` or `.pcapng` capture (`reversePcap` camelCase alias).
 *
 * # Errors
 * Returns a structured `JsValue` error object (`{ success: false, error, message }`) if
 * `pcap_bytes` is not a valid `.pcap` or `.pcapng` capture.
 */
export function reversePcap(pcap_bytes: Uint8Array | number[]): ReversePcapResult;

/**
 * Decompiles an in-memory `.pcap` or `.pcapng` capture (`Uint8Array`) into canonical `.fasm`
 * source code and summary counts (`{ success: true, fasm, packetCount, hostCount }`).
 *
 * # Errors
 * Returns a structured `JsValue` error object (`{ success: false, error, message }`) if
 * `pcap_bytes` is not a valid `.pcap` or `.pcapng` capture.
 */
export function reverse_pcap(pcap_bytes: Uint8Array | number[]): ReversePcapResult;

/**
 * Validates `.fasm` source and returns UTF-16 line/column diagnostics (`validateFasm` alias).
 */
export function validateFasm(source: string): IdeDiagnostic[];

/**
 * Validates `.fasm` source and returns UTF-16 line/column diagnostics for Monaco, CodeMirror, and VS Code.
 */
export function validate_fasm(source: string): IdeDiagnostic[];

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly compileFasm: (a: number, b: number) => [number, number, number, number];
    readonly compile_fasm_to_pcapng: (a: number, b: number) => [number, number, number, number];
    readonly inspect_fasm: (a: number, b: number) => [number, number, number];
    readonly reversePcap: (a: number, b: number) => [number, number, number];
    readonly reverse_pcap: (a: number, b: number) => [number, number, number];
    readonly validateFasm: (a: number, b: number) => [number, number, number];
    readonly validate_fasm: (a: number, b: number) => [number, number, number];
    readonly __wbindgen_malloc: (a: number, b: number) => number;
    readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
    readonly __wbindgen_free: (a: number, b: number, c: number) => void;
    readonly __wbindgen_externrefs: WebAssembly.Table;
    readonly __externref_table_dealloc: (a: number) => void;
    readonly __wbindgen_start: () => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;

/**
 * Instantiates the given `module`, which can either be bytes or
 * a precompiled `WebAssembly.Module`.
 *
 * @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
 *
 * @returns {InitOutput}
 */
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
 * If `module_or_path` is {RequestInfo} or {URL}, makes a request and
 * for everything else, calls `WebAssembly.instantiate` directly.
 *
 * @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
 *
 * @returns {Promise<InitOutput>}
 */
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;
