# FrameAssembly WebAssembly Compiler (`frameassembly-wasm` v1.5.1)

[![Website & Playground](https://img.shields.io/badge/web%20app-frameassembly.ai.studio-0ea5e9.svg)](https://frameassembly.ai.studio/)
[![NPM](https://img.shields.io/npm/v/frameassembly-wasm.svg)](https://www.npmjs.com/package/frameassembly-wasm)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://github.com/SteveWinschel/FrameAssembly/blob/main/LICENSE)

[**Try in Browser (`frameassembly.ai.studio`)**](https://frameassembly.ai.studio/) • [**Installation**](#installation) • [**Vite, React & Next.js**](#initialization-vite-react-nextjs--google-ai-studio) • [**TypeScript API**](#typescript-api-reference)

WebAssembly compiler, `.pcap`/`.pcapng`-to-`.fasm` decompiler, frame inspector, and UTF-16 IDE diagnostics for **FrameAssembly (`.fasm`)** — compiling `.fasm` code into `.pcapng` packet captures and decompiling existing captures back into `.fasm` code across 81 L2–L7 protocols in browser applications, web cyber ranges, and Node.js test suites. Powers the official FrameAssembly interactive browser playground at [**frameassembly.ai.studio**](https://frameassembly.ai.studio/). *(Note: FrameAssembly is a network protocol DSL, not x86 Flat Assembler).*

---

## Client-Side `.fasm` to `.pcapng` Compilation & PCAP Decompilation in the Browser & Node.js

`frameassembly-wasm` compiles the FrameAssembly Rust engine to WebAssembly, turning `.fasm` code into `.pcapng` byte streams, decompiling binary `.pcap` and `.pcapng` captures into `.fasm` code via `reversePcap(pcapBytes)`, and emitting real-time Monaco/CodeMirror syntax diagnostics directly in the browser or Node.js without a backend server:

```frameassembly
host client { ip 192.168.1.10 mac 00:11:22:33:44:55 }
host server { ip 8.8.8.8 mac aa:bb:cc:dd:ee:ff }

flow dns_query(c, s) {
    c -> s dns query txid 0x1234 qname "example.com" qtype "A" wait 1ms
    c <- s dns response txid 0x1234 qname "example.com" qtype "A" rdata 93.184.216.34 wait 1ms
}

compile {
    dns_query(client, server)
}
```

```ts
import init, {
  compile_fasm_to_pcapng,
  validate_fasm,
  inspect_fasm,
  reversePcap,
} from "frameassembly-wasm";

// Initialize WASM module once at startup
await init();

const source = `host client { ip 192.168.1.10 mac 00:11:22:33:44:55 }
host server { ip 8.8.8.8 mac aa:bb:cc:dd:ee:ff }

flow dns_query(c, s) {
    c -> s dns query txid 0x1234 qname "example.com" qtype "A" wait 1ms
    c <- s dns response txid 0x1234 qname "example.com" qtype "A" rdata 93.184.216.34 wait 1ms
}

compile {
    dns_query(client, server)
}`;

// 1. Validate syntax & semantics for Monaco / CodeMirror editor markers
const diagnostics = validate_fasm(source);
if (diagnostics.length === 0) {
  // 2. Inspect individual packet headers and hex payloads
  const previews = inspect_fasm(source);
  console.log(`Synthesized ${previews.length} frames.`);

  // 3. Compile to binary PCAPNG Uint8Array
  const pcapngBytes = compile_fasm_to_pcapng(source);
  const blob = new Blob([pcapngBytes], { type: "application/vnd.tcpdump.pcap" });
  console.log(`Generated PCAPNG: ${blob.size} bytes`);

  // 4. Decompile binary PCAP/PCAPNG bytes back into canonical .fasm code
  const reversed = reversePcap(pcapngBytes);
  console.log(`Reversed ${reversed.packetCount} frames across ${reversed.hostCount} hosts:\n${reversed.fasm}`);
}
```

```bash
npm install frameassembly-wasm
```

---

## Installation

```bash
npm install frameassembly-wasm
```

### Browser CDN Usage (No Bundler)

```html
<script type="module">
  import init, {
    validate_fasm,
    inspect_fasm,
    compile_fasm_to_pcapng,
    reversePcap,
  } from "https://cdn.jsdelivr.net/npm/frameassembly-wasm@1.5.1/frameassembly_wasm.js";

  await init();
  console.log("FrameAssembly WebAssembly engine v1.5.1 loaded successfully.");
</script>
```

---

## Initialization (Vite, React, Next.js & Google AI Studio)

Import the WebAssembly binary URL explicitly with `?url` so Vite, Webpack 5, and Next.js serve the `.wasm` asset cleanly in both development and production builds:

```ts
import init, {
  validate_fasm,
  inspect_fasm,
  compile_fasm_to_pcapng,
  reversePcap,
  type IdeDiagnostic,
  type PacketPreview,
  type ReversePcapResult,
} from "frameassembly-wasm";
import wasmUrl from "frameassembly-wasm/frameassembly_wasm_bg.wasm?url";

// Call once at application startup (idempotent)
await init({ module_or_path: wasmUrl });
```

---

## API Reference

### `validate_fasm(source: string): IdeDiagnostic[]` / `validateFasm(source: string): IdeDiagnostic[]`
Parses and validates `.fasm` source code, returning zero-based UTF-16 line and column spans ready for Monaco Editor or CodeMirror 6 diagnostic markers. Returns an empty array `[]` when the source compiles cleanly.

```ts
interface IdeDiagnostic {
  start_line: number; // 0-based UTF-16 line index
  start_col: number;  // 0-based UTF-16 character column
  end_line: number;   // 0-based UTF-16 line index
  end_col: number;    // 0-based UTF-16 character column
  message: string;    // Human-readable diagnostic message
  help?: string;      // Actionable "Did you mean...?" remediation hint
}
```

### `inspect_fasm(source: string): PacketPreview[]`
Compiles `.fasm` source code into an array of packet inspection summaries, including relative nanosecond timestamps, frame lengths, and lowercase space-delimited hex byte dumps. Throws a JavaScript `Error` if compilation fails.

```ts
interface PacketPreview {
  index: number;         // 1-based frame index
  timestamp_ms: number;  // Relative timestamp in milliseconds
  length: number;        // Total packet length in bytes
  hex: string;           // Space-separated lowercase hex byte dump
}
```

### `compile_fasm_to_pcapng(source: string): Uint8Array` / `compileFasm(source: string): Uint8Array`
Compiles `.fasm` source code into a binary `Uint8Array` containing a valid, standards-compliant PCAPNG byte stream with nanosecond timestamp precision (`IfTsResol = 9`). Throws a JavaScript `Error` with rich diagnostic context if compilation fails.

### `reversePcap(pcap_bytes: Uint8Array): ReverseJsResult`
Decompiles an in-memory `.pcap` or `.pcapng` byte array (`Uint8Array`) across all 81 native Layer 2 through Layer 7 protocols into canonical lowercase `.fasm` code (`host` declarations and an inline `compile` block), returning summary statistics (`packetCount`, `hostCount`). Throws a structured error object (`{ success: false, error, message }`) if `pcap_bytes` is not a valid packet capture.

```ts
interface ReversePcapResult {
  success: boolean;     // true when decompilation succeeds
  fasm: string;         // Canonical lowercase .fasm source code
  packetCount: number;  // Total number of reversed packets
  hostCount: number;    // Total number of host_N declarations emitted
}

type ReverseJsResult = ReversePcapResult;
```

---

## Complete Browser Playground & Download Example

```ts
import init, { compile_fasm_to_pcapng, reversePcap, validate_fasm } from "frameassembly-wasm";

export async function downloadCapture(fasmCode: string, filename = "capture.pcapng") {
  await init();

  const errors = validate_fasm(fasmCode);
  if (errors.length > 0) {
    throw new Error(`Compilation error: ${errors[0].message}`);
  }

  const pcapng = compile_fasm_to_pcapng(fasmCode);
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
  await init();
  const bytes = new Uint8Array(await file.arrayBuffer());
  const result = reversePcap(bytes);
  return result.fasm;
}
```

---

## Features & Engine Capabilities

- **Zero Server Dependencies**: Executes 100% locally in WebAssembly inside Chrome, Firefox, Safari, Edge, Web Workers, and Node.js.
- **81 Native Protocols (Forward & Reverse)**: Complete compilation and `.pcap`/`.pcapng` decompilation coverage across L2–L7 (Ethernet, 802.1Q VLAN, QinQ, MPLS, ARP, IPv4/IPv6, ICMP, TCP, UDP, SCTP, SNMPv1/v2c/v3 USM, DNS, DHCP, HTTP, TLS, Modbus, DNP3, and more), including pure Layer-2 MAC-only switch topologies and inline `compile` statements.
- **Nanosecond Fidelity**: Compiles and reverses deterministic PCAP/PCAPNG captures with nanosecond-resolution Section and Interface Description Blocks (`IfTsResol(9)`).
- **Sub-Millisecond Compilation**: Small to medium captures compile and decompile in `< 5ms`, making real-time live typing diagnostics and drag-and-drop PCAP import instantaneous in web editors.

---

## Disambiguation: FrameAssembly vs. Flat Assembler

**FrameAssembly** (`.fasm`, media type `text/vnd.frameassembly`) is a domain-specific network protocol specification language for synthesizing and decompiling deterministic `.pcap` and `.pcapng` packet captures. It is completely unrelated to x86 Flat Assembler (`fasm.net`) and SymbiFlow / F4PGA FPGA bitstream FASM tools.

Full documentation, interactive browser playground ([https://frameassembly.ai.studio/](https://frameassembly.ai.studio/)), grammar specifications, and 2,611 verified examples: https://github.com/SteveWinschel/FrameAssembly
