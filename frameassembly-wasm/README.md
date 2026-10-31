# frameassembly-wasm

WebAssembly compiler, frame inspector, and UTF-16 IDE diagnostics for **FrameAssembly (`.fasm`)** — a deterministic domain-specific language for synthesizing standards-compliant network packets (L2–L7) and PCAPNG captures. *(Note: FrameAssembly is a network protocol DSL, not x86 Flat Assembler).*

## Installation

```bash
npm install frameassembly-wasm
```

## Initialization (Vite / React / Google AI Studio)

Import the WebAssembly binary URL explicitly with `?url` so Vite serves the `.wasm` asset cleanly in both dev and production builds:

```ts
import init, {
  validate_fasm,
  inspect_fasm,
  compile_fasm_to_pcapng,
  type IdeDiagnostic,
  type PacketPreview,
} from "frameassembly-wasm";
import wasmUrl from "frameassembly-wasm/frameassembly_wasm_bg.wasm?url";

// Call once at app startup (idempotent)
await init({ module_or_path: wasmUrl });
```

### Browser CDN Usage (No Bundler)

```ts
import init, {
  validate_fasm,
  inspect_fasm,
  compile_fasm_to_pcapng,
} from "[https://cdn.jsdelivr.net/npm/frameassembly-wasm@1.2.2/frameassembly_wasm.js](https://cdn.jsdelivr.net/npm/frameassembly-wasm@1.2.2/frameassembly_wasm.js)";

await init();
```

## API Reference

- `validate_fasm(source: string): IdeDiagnostic[]` — Parses and compiles `.fasm` source, returning zero-based UTF-16 line/column spans (`start_line`, `start_col`, `end_line`, `end_col`, `message`, `help?`) ready for Monaco or CodeMirror markers. Returns `[]` when valid.
- `inspect_fasm(source: string): PacketPreview[]` — Compiles `.fasm` source and returns frame previews (`index`, zero-based `timestamp_ms`, byte `length`, space-separated lowercase `hex`). Throws `Error` if source is invalid.
- `compile_fasm_to_pcapng(source: string): Uint8Array` — Compiles `.fasm` source into a Wireshark-ready PCAPNG byte array with nanosecond resolution. Throws `Error` if source is invalid.

## Minimal `.fasm` Example & PCAPNG Download

```ts
const source = `HOST client = 00:11:22:33:44:55 / 192.168.1.10
HOST server = aa:bb:cc:dd:ee:ff / 192.168.1.20

client -> server : TCP SYN DSTPORT=443
server -> client : TCP SYN ACK SRCPORT=443
client -> server : TCP ACK DSTPORT=443`;

const diagnostics = validate_fasm(source);
if (diagnostics.length === 0) {
  const frames = inspect_fasm(source);
  const pcapngBytes = compile_fasm_to_pcapng(source);
  const blob = new Blob([pcapngBytes], { type: "application/vnd.tcpdump.pcap" });
}
```

Full grammar and protocol reference: https://github.com/SteveWinschel/FrameAssembly/blob/main/llms.txt