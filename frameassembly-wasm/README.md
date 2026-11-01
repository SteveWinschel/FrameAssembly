# FrameAssembly WebAssembly Compiler (`frameassembly-wasm` v1.4.1)

High-performance WebAssembly compiler, frame inspector, and UTF-16 IDE diagnostics for **FrameAssembly (`.fasm`)** — the deterministic domain-specific language for synthesizing standards-compliant network packets (L2–L7) and PCAPNG captures in browser applications, web playgrounds, and Node.js runtimes. *(Note: FrameAssembly is a network protocol DSL, not x86 Flat Assembler).*

---

## Client-Side `.fasm` to `.pcapng` Compilation in the Browser & Node.js

`frameassembly-wasm` compiles the complete FrameAssembly Rust compiler directly to WebAssembly, generating deterministic, nanosecond-precision `.pcapng` byte streams and real-time Monaco/CodeMirror syntax diagnostics entirely in the browser or Node.js—with no backend server, Python runtime, or native `libpcap` dependencies required:

```ts
import init, {
  compile_fasm_to_pcapng,
  validate_fasm,
  inspect_fasm,
} from "frameassembly-wasm";

// Initialize WASM module once at startup
await init();

const source = `HOST client { IP 192.168.1.10 MAC 00:11:22:33:44:55 }
HOST server { IP 8.8.8.8 MAC aa:bb:cc:dd:ee:ff }

FLOW dns_query(c, s) {
    c -> s DNS QUERY TXID 0x1234 QNAME "example.com" QTYPE "A" WAIT 1ms
    c <- s DNS RESPONSE TXID 0x1234 QNAME "example.com" QTYPE "A" RDATA "93.184.216.34" WAIT 1ms
}

COMPILE {
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
  } from "https://cdn.jsdelivr.net/npm/frameassembly-wasm@1.4.1/frameassembly_wasm.js";

  await init();
  console.log("FrameAssembly WebAssembly engine loaded successfully.");
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
  type IdeDiagnostic,
  type PacketPreview,
} from "frameassembly-wasm";
import wasmUrl from "frameassembly-wasm/frameassembly_wasm_bg.wasm?url";

// Call once at application startup (idempotent)
await init({ module_or_path: wasmUrl });
```

---

## API Reference

### `validate_fasm(source: string): IdeDiagnostic[]`
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
  index: number;         // 0-based frame index
  timestamp_ms: number;  // Relative timestamp in milliseconds
  length: number;        // Total packet length in bytes
  hex: string;           // Space-separated lowercase hex byte dump
}
```

### `compile_fasm_to_pcapng(source: string): Uint8Array`
Compiles `.fasm` source code into a binary `Uint8Array` containing a valid, standards-compliant PCAPNG byte stream with nanosecond timestamp precision (`IfTsResol = 9`). Throws a JavaScript `Error` with rich diagnostic context if compilation fails.

---

## Complete Browser Playground & Download Example

```ts
import init, { compile_fasm_to_pcapng, validate_fasm } from "frameassembly-wasm";

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
```

---

## Features & Engine Capabilities

- **Zero Server Dependencies**: Executes 100% locally in WebAssembly inside Chrome, Firefox, Safari, Edge, Web Workers, and Node.js.
- **81 Native Protocols**: Complete coverage across L2–L7 (Ethernet, 802.1Q VLAN, QinQ, MPLS, ARP, IPv4/IPv6, ICMP, TCP, UDP, SCTP, SNMPv1/v2c/v3 USM, DNS, DHCP, HTTP, TLS, Modbus, DNP3, and more).
- **Nanosecond Fidelity**: Compiles deterministic PCAPNG captures with nanosecond-resolution Section and Interface Description Blocks (`IfTsResol(9)`).
- **Sub-Millisecond Compilation**: Small to medium captures compile in `< 5ms`, making real-time live typing diagnostics instantaneous in web editors.

---

## Disambiguation: FrameAssembly vs. Flat Assembler

**FrameAssembly** (`.fasm`, media type `text/vnd.frameassembly`) is a domain-specific network protocol specification language for synthesizing deterministic `.pcap` and `.pcapng` packet captures. It is completely unrelated to x86 Flat Assembler (`fasm.net`) and SymbiFlow / F4PGA FPGA bitstream FASM tools.

Full documentation, grammar specifications, and 2,611 verified examples: https://github.com/SteveWinschel/FrameAssembly