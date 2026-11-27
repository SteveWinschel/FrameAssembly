# FrameAssembly WebAssembly Compiler (`frameassembly-wasm` v3.3.1)

[![Website & Playground](https://img.shields.io/badge/web%20app-frameassembly--lang.dev-0ea5e9.svg)](https://frameassembly-lang.dev/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://github.com/SteveWinschel/FrameAssembly/blob/main/LICENSE)

[**Try in Browser (`frameassembly-lang.dev`)**](https://frameassembly-lang.dev/) • [**Building Locally**](#building-locally) • [**Vite, React & Next.js**](#initialization-vite-react-nextjs--browser-apps) • [**API Reference**](#api-reference)

`frameassembly-wasm` (`v3.3.1`) is the **internal WebAssembly compiler, `.pcap`/`.pcapng`-to-`.frasm` decompiler, packet ladder inspector, and UTF-16 diagnostic engine** powering [**`frameassembly-lang.dev`**](https://frameassembly-lang.dev/) and the official VS Code extension (`SteveWinschel.frameassembly-vscode`). It compiles `.frasm` code into classic `.pcap` and `.pcapng` packet captures and decompiles existing captures back into `.frasm` code across 146 L2–L7 protocols (`18` L2, `31` L3, `3` L4, and `94` L7) inside browser applications and VS Code Desktop/Web Extension Hosts. *(CLI users should install the native binary via `cargo install frameassembly` and update with `frameassembly update`. FrameAssembly is a network packet specification compiler, not x86 Flat Assembler.)*

---

## Client-Side `.frasm` to `.pcapng` Compilation & PCAP Decompilation in the Browser & Node.js

`frameassembly-wasm` compiles the FrameAssembly Rust engine to WebAssembly, turning `.frasm` code into classic `.pcap` (`compileFrasmToPcap` / `compile_frasm_to_pcap`) or `.pcapng` (`compileFrasm` / `compile_frasm_to_pcapng`) byte streams, decompiling binary `.pcap` and `.pcapng` captures into strict-lowercase `.frasm` code via `reverse_pcap(pcapBytes)` / `reversePcap(pcapBytes)`, and emitting real-time Monaco, CodeMirror, and VS Code diagnostics in the browser or Node.js without a backend server:

```frameassembly
host client { ip 192.168.1.10 mac 00:11:22:33:44:55 }
host server { ip 8.8.8.8 mac aa:bb:cc:dd:ee:ff }

flow dns_query(c, s) {
    c -> s dns query txid 0x1234 qname "example.com" qtype "a" wait 1ms
    c <- s dns response txid 0x1234 qname "example.com" qtype "a" rdata 93.184.216.34 wait 1ms
}

compile {
    dns_query(client, server)
}
```

```ts
import init, {
  compile_frasm_to_pcapng,
  validate_frasm,
  inspect_frasm,
  reversePcap,
} from "./pkg/frameassembly_wasm.js";

// Initialize WASM module once at startup
await init();

const source = `host client { ip 192.168.1.10 mac 00:11:22:33:44:55 }
host server { ip 8.8.8.8 mac aa:bb:cc:dd:ee:ff }

flow dns_query(c, s) {
    c -> s dns query txid 0x1234 qname "example.com" qtype "a" wait 1ms
    c <- s dns response txid 0x1234 qname "example.com" qtype "a" rdata 93.184.216.34 wait 1ms
}

compile {
    dns_query(client, server)
}`;

// 1. Validate syntax and semantics for Monaco / CodeMirror / VS Code editor markers
const diagnostics = validate_frasm(source);
if (diagnostics.length === 0) {
  // 2. Inspect individual packet ladder rows, protocol labels, summaries, and hex payloads
  const previews = inspect_frasm(source);
  console.log(`Synthesized ${previews.length} frames (${previews[0].protocol}: ${previews[0].summary}).`);

  // 3. Compile to binary PCAPNG Uint8Array
  const pcapngBytes = compile_frasm_to_pcapng(source);
  const blob = new Blob([pcapngBytes], { type: "application/vnd.tcpdump.pcap" });
  console.log(`Generated PCAPNG: ${blob.size} bytes`);

  // 4. Decompile binary PCAP/PCAPNG bytes back into strict-lowercase .frasm code
  const reversed = reversePcap(pcapngBytes);
  console.log(`Reversed ${reversed.packetCount} frames across ${reversed.hostCount} hosts:\n${reversed.frasm}`);
}
```

---

## Building Locally

`frameassembly-wasm` is an internal workspace crate powering [`frameassembly-lang.dev`](https://frameassembly-lang.dev/) and `frameassembly-vscode` rather than a standalone user CLI package. Build the WebAssembly bundle from the repository root using `wasm-pack`:

```bash
wasm-pack build frameassembly-wasm --release --target web
```

This generates `frameassembly-wasm/pkg/{frameassembly_wasm.js,frameassembly_wasm_bg.wasm,frameassembly_wasm.d.ts,package.json}` for bundling into [`frameassembly-lang.dev`](https://frameassembly-lang.dev/) or `frameassembly-vscode/wasm/`. For command-line `.frasm` compilation and `.pcap` decompilation, install `cargo install frameassembly` and update with `frameassembly update`.

---

## Initialization (Vite, React, Next.js & Browser Apps)

Import the generated WebAssembly binary URL explicitly with `?url` so Vite, Webpack 5, and Next.js serve the `.wasm` asset in both development and production builds, and pass the options object to `init` (`wasm-bindgen 0.2.130`):

```ts
import init, {
  validate_frasm,
  inspect_frasm,
  compile_frasm_to_pcapng,
  reversePcap,
  type IdeDiagnostic,
  type PacketPreview,
  type ReversePcapResult,
} from "./pkg/frameassembly_wasm.js";
import wasmUrl from "./pkg/frameassembly_wasm_bg.wasm?url";

// Call once at application startup (idempotent)
await init({ module_or_path: wasmUrl });
```

---

## API Reference

> **Compatibility aliases:** FrameAssembly 3.x renamed its source files from `.fasm` to `.frasm`. Every export uses a `*_frasm` / `*Frasm` name (`validate_frasm`, `inspect_frasm`, `compile_frasm_to_pcapng`, `validateFrasm`, `inspectFrasm`, `compileFrasm`). Legacy 2.x names (`validate_fasm`, `validateFasm`, `inspect_fasm`, `compile_fasm_to_pcapng`, `compileFasm`) remain exported as identical aliases for existing integrations, and `ReversePcapResult.fasm` aliases `frasm`. All structured JS returns serialize as plain JavaScript objects via `serialize_maps_as_objects(true)`.

### `validate_frasm(source: string): IdeDiagnostic[]` / `validateFrasm(source: string): IdeDiagnostic[]` (aliases: `validate_fasm`, `validateFasm`)
Parses, validates, and test-compiles `.frasm` source code, returning zero-based UTF-16 line and column spans (handling `\n`, `\r\n`, and bare `\r` line breaks) ready for Monaco Editor, CodeMirror 6, or VS Code diagnostic markers (including strict-lowercase quick-fix remediation hints in `help`). Returns an empty array `[]` when compilation succeeds, or a single diagnostic when `source` exceeds the `4 MiB` WebAssembly input limit (`MAX_WASM_SOURCE_BYTES`).

```ts
interface IdeDiagnostic {
  start_line: number; // 0-based UTF-16 line index
  start_col: number;  // 0-based UTF-16 character column
  end_line: number;   // 0-based UTF-16 line index
  end_col: number;    // 0-based UTF-16 character column
  message: string;    // Diagnostic error message
  help?: string;      // Actionable remediation or 1-click quick-fix hint
}
```

### `inspect_frasm(source: string): PacketPreview[]` / `inspectFrasm(source: string): PacketPreview[]` (alias: `inspect_fasm`)
Compiles `.frasm` source code into an array of packet ladder inspection entries using `frameassembly::inspect::summarize_frame`, including relative millisecond timestamps, endpoint pairs (`source_dest`), protocol labels (`protocol`), decoded Ethernet/VLAN/QinQ/MPLS/LLC/L3/L4/L7 summaries (`summary`), frame lengths, and lowercase space-delimited hex byte dumps. Throws a JavaScript `Error` if `source` exceeds `MAX_WASM_SOURCE_BYTES` or compilation fails.

```ts
interface PacketPreview {
  index: number;         // 1-based frame index
  timestamp_ms: number;  // Relative timestamp in milliseconds
  length: number;        // Total packet length in bytes
  hex: string;           // Space-separated lowercase hex byte dump
  source_dest: string;   // Formatted "src -> dst" IPv4, IPv6, or MAC pair
  protocol: string;      // Highest-layer protocol label (e.g. "DNS", "SNMP", "MODBUS", "NGAP")
  summary: string;       // Decoded L2/L3/L4/L7 frame summary string
}
```

### `compileFrasmToPcap(source: string): Uint8Array` / `compile_frasm_to_pcap(source: string): Uint8Array`
Compiles `.frasm` source code into a binary `Uint8Array` containing a valid classic libpcap (`.pcap`) byte stream (`LINKTYPE_ETHERNET`, `snaplen = 262144`, microsecond or nanosecond timestamp header selection). Throws a JavaScript `Error` with diagnostic context if `source` exceeds `MAX_WASM_SOURCE_BYTES` or compilation fails.

### `compile_frasm_to_pcapng(source: string): Uint8Array` / `compileFrasm(source: string): Uint8Array` (aliases: `compile_fasm_to_pcapng`, `compileFasm`)
Compiles `.frasm` source code into a binary `Uint8Array` containing a valid, standards-compliant PCAPNG byte stream with nanosecond timestamp precision (`IfTsResol = 9`), host `NameResolutionBlock` records, and per-frame `comment` options. Throws a JavaScript `Error` with diagnostic context if `source` exceeds `MAX_WASM_SOURCE_BYTES` or compilation fails.

### `reverse_pcap(pcap_bytes: Uint8Array): ReverseJsResult` / `reversePcap(pcap_bytes: Uint8Array): ReverseJsResult`
Decompiles an in-memory `.pcap` or `.pcapng` byte array (`Uint8Array`) across all 146 native Layer 2 through Layer 7 protocols into strict-lowercase `.frasm` code (`host1`, `host2`, ... declarations and an inline `compile` block), returning summary statistics (`packetCount`, `hostCount`). Throws a structured plain JS error object (`{ success: false, error, message }`) if `pcap_bytes` exceeds the `64 MiB` WebAssembly capture limit (`MAX_WASM_PCAP_BYTES`) or is not a valid packet capture.

```ts
interface ReversePcapResult {
  success: boolean;     // true when decompilation succeeds
  frasm: string;        // Strict-lowercase .frasm source code
  fasm: string;         // Backward-compatible 2.x alias of frasm
  packetCount: number;  // Total number of reversed packets
  hostCount: number;    // Total number of host1, host2, ... declarations emitted
}

type ReverseJsResult = ReversePcapResult;
```

---

## Complete Browser Playground & Download Example

```ts
import init, { compile_frasm_to_pcapng, reversePcap, validate_frasm } from "./pkg/frameassembly_wasm.js";
import wasmUrl from "./pkg/frameassembly_wasm_bg.wasm?url";

export async function downloadCapture(frasmCode: string, filename = "capture.pcapng") {
  await init({ module_or_path: wasmUrl });

  const errors = validate_frasm(frasmCode);
  if (errors.length > 0) {
    throw new Error(`Compilation error: ${errors[0].message}`);
  }

  const pcapng = compile_frasm_to_pcapng(frasmCode);
  const blob = new Blob([pcapng], { type: "application/vnd.tcpdump.pcap" });
  const url = URL.createObjectURL(blob);

  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

export async function importCaptureFile(file: File): Promise<string> {
  await init({ module_or_path: wasmUrl });
  const bytes = new Uint8Array(await file.arrayBuffer());
  const result = reversePcap(bytes);
  return result.frasm;
}
```

---

## Features & Engine Capabilities

- **Browser & IDE Execution**: Runs locally in WebAssembly inside Chrome, Firefox, Safari, Edge, Web Workers, VS Code Desktop/Web, and Node.js without a backend server.
- **146 Native Protocols (`18` L2, `31` L3, `3` L4, `94` L7)**: Forward compilation and `.pcap`/`.pcapng` decompilation across Ethernet, 802.1Q VLAN, QinQ, MPLS, CDP, IS-IS, MACsec, PPPoE, PROFINET, EtherCAT, ARP, IPv4/IPv6, ICMP, SRv6, IP-in-IP, TCP, UDP, SCTP (NGAP/S1AP/Diameter), SNMPv1/v2c/v3 USM, DNS, DHCP, HTTP/2, TLS, QUIC, Modbus, DNP3, and MAC-only switch topologies.
- **Nanosecond Fidelity**: Compiles and reverses PCAP and PCAPNG captures with nanosecond-resolution Section and Interface Description Blocks (`IfTsResol(9)`), host name resolution records, and packet comments.
- **Bounded In-Memory Processing**: Executes live syntax validation with CRLF-accurate UTF-16 spans, packet ladder inspection, compilation, and drag-and-drop capture reversal in browser memory with bounded input caps (`4 MiB` source, `64 MiB` capture).

---

## Disambiguation: FrameAssembly vs. Flat Assembler

**FrameAssembly** (`.frasm`, media type `text/vnd.frameassembly`) is a network packet specification compiler for generating and decompiling `.pcap` and `.pcapng` packet captures. It is unrelated to x86 Flat Assembler (`fasm.net`, which uses `.asm`/`.fasm` files) and SymbiFlow / F4PGA FPGA bitstream FASM tools.

Interactive browser playground: [https://frameassembly-lang.dev/](https://frameassembly-lang.dev/) • Documentation: [https://frameassembly-lang.dev/docs](https://frameassembly-lang.dev/docs) • Use cases and examples: [https://frameassembly-lang.dev/use-cases](https://frameassembly-lang.dev/use-cases) • Source code and formal grammars: [GitHub (`SteveWinschel/FrameAssembly`)](https://github.com/SteveWinschel/FrameAssembly)
