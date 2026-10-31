# For Nerds: Compiler Pipeline, Rust Library API & Formal Grammars

This reference covers FrameAssembly's internal Rust compiler architecture, how to embed `frameassembly` inside Rust unit/integration test suites, and how to use the repository's formal context-free grammars for zero-hallucination LLM constrained decoding.

---

## 1. Six-Stage Zero-Copy Compiler Architecture

FrameAssembly (`frameassembly` v1.2.2, Rust Edition 2024) compiles `.fasm` source buffers into `.pcap` / `.pcapng` captures through a deterministic six-stage pipeline in pure userspace—requiring zero root privileges (`CAP_NET_RAW`), kernel sockets, or external C libraries (`libpcap` is not required at build or runtime):

```text
 ┌────────────────┐     ┌────────────────┐     ┌─────────────────────┐
 │  .fasm Source  │ ──> │  Logos Lexer   │ ──> │  Winnow TokenSlice  │
 │  Text Buffer   │     │  (Zero-Copy)   │     │  Parser Combinators │
 └────────────────┘     └────────────────┘     └─────────────────────┘
                                                          │
                                                          ▼
 ┌────────────────┐     ┌────────────────┐     ┌─────────────────────┐
 │ .pcap / PCAPNG │ <── │  4-Tuple State │ <── │  Semantic Validator │
 │ Serialization  │ <── │ & Wire Builders│ <── │ & AST Representation│
 └────────────────┘     └────────────────┘     └─────────────────────┘
```

### Stage 1: Zero-Copy Lexical Analysis (`src/lexer/mod.rs`)
* Powered by `logos 0.14`, scanning UTF-8 input buffers without allocating heap strings.
* Emits `SpannedToken<'a>` items borrowing `&'a str` slices directly from the source buffer alongside byte-offset spans (`Range<usize>`) across all 81 protocol keywords, 640+ lexer tokens, integer literals, IPv4/IPv6 addresses, IEEE 802 MACs, ASN.1 OIDs, and duration suffixes (`ns`, `us`, `ms`, `s`, `m`).

### Stage 2: Two-Phase Token-Slice Parsing (`src/parser/`)
* Implemented with `winnow 1.0` operating over a custom `TokenSlice<'i, 'a>` stream (`Stream<'i, 'a>`).
* Decoupling lexical tokenization from syntactic combinators eliminates character-level backtracking, strips comments in $O(N)$ time, and dispatches protocol-scoped modifiers cleanly across `src/parser/{l2,l3,l4,l7}/`.

### Stage 3: Semantic Validation (`src/parser/validation.rs`)
Enforces structural invariants across `Program<'a>` before wire serialization, rendering graphical source-mapped diagnostics via `miette 7.6` on errors:
1. **Host uniqueness & scope:** Every `HOST` identifier must be unique, define a valid IPv4 or IPv6 address, and exist when referenced in `COMPILE`.
2. **Flow signature arity:** Every `FLOW` call in `COMPILE` or `LOOP` must pass the exact number of endpoint arguments declared in its parameter list.
3. **Dual-stack endpoint homogeneity:** Concrete hosts bound to `lhs -> rhs` or `lhs <- rhs` must share the same IP family (both IPv4 or both IPv6).
4. **Modifier exclusivity & positive loops:** Rejects duplicate modifiers or multiple protocols on a single frame statement and enforces `LOOP <count>` with `count >= 1`.

### Stage 4: Zero-Heap Protocol Wire Builders (`src/builders/`)
* Dedicated wire builders under `src/builders/{l2,l3,l4,l7}/` serialize RFC-compliant headers directly into pre-allocated frame buffers and populate RFC defaults for omitted optional fields.
* **Built-in Checksum & Crypto Engines:**
  * RFC 1071 16-bit one's complement checksums (IPv4, ICMPv4, TCP/UDP with IPv4/IPv6 pseudo-headers, GRE RFC 2784, IGMP, VRRPv2 RFC 3768).
  * RFC 4443 & RFC 5798 IPv6 pseudo-header checksums (ICMPv6, NDP, MLD, VRRPv3).
  * RFC 9260 32-bit Castagnoli CRC32c (`SCTP`) and IEEE 1815 reflected 16-bit CRC-16 (`DNP3`).
  * ASN.1 BER/DER (`rasn`) & SNMPv3 USM (`src/builders/l7/snmp/`): RFC 3414 1-MB password-to-key (`Ku`) expansion, `ENGINEID` key localization (`Kul`), `DES-CBC` / `AES-128-CFB` encryption, and truncated `HMAC-MD5-96`, `HMAC-SHA-96`, `HMAC-SHA-256-192`, `HMAC-SHA-384-256`, and `HMAC-SHA-512-384` authentication.

### Stage 5: Stateful 4-Tuple Engine (`src/backend/`)
* Tracks bidirectional connection state keyed by canonical 4-tuple (`Endpoint A`, `Endpoint B`, `Port A`, `Port B`, `Protocol`), reversing ports on `<-`, advancing TCP `SEQ`/`ACK` across `SYN`/`FIN` ghost bytes and L4/L7 payloads, and deriving RFC 1112 (`01:00:5e:xx:xx:xx`) and RFC 2464 (`33:33:xx:xx:xx:xx`) multicast MAC addresses.

### Stage 6: Nanosecond PCAPNG Writer (`src/pcap.rs`)
* Serializes finalized Ethernet frames with `IfTsResol(9)` nanosecond timestamps via `pcap-file 2.0`.

---

## 2. Repository `<layer>/<protocol>` Symmetry

```text
frameassembly/
├── src/
│   ├── lexer/          # Zero-copy Logos tokenizer
│   ├── ast/            # Strongly-typed AST & *Spec structs (l2/, l3/, l4/, l7/)
│   ├── parser/         # Winnow token-slice combinators & semantic validator
│   ├── builders/       # RFC wire encoders & SNMPv3 USM crypto (l2/, l3/, l4/, l7/)
│   ├── backend/        # 4-tuple state engine, loop unrolling, L7 dispatch
│   ├── packet.rs       # Ethernet/VLAN/QinQ/MPLS/IPv4/IPv6/L4 framing & checksums
│   ├── pcap.rs         # Nanosecond-precision PCAPNG serializer
│   ├── error.rs        # Miette diagnostic error types (CompilerError)
│   └── main.rs         # Clap CLI binary interface
├── docs/               # User guides, layer protocol references & internals
└── examples/           # 2,611 verified .fasm scenarios (l2/, l3/, l4/, l7/, topologies/)
```

---

## 3. Public Rust Library API

Embed `frameassembly` directly inside Rust test suites to synthesize Ethernet frames (`Vec<(Vec<u8>, u64)>`) in memory or write `.pcap` fixtures to disk:

```rust
use frameassembly::parser::parse_program;
use frameassembly::backend::{compile_program, generate_pcap};

let fasm = r#"
    HOST sensor { IP 192.168.10.5 MAC 00:1a:2b:3c:4d:5e }
    HOST plc    { IP 192.168.10.20 MAC 00:1a:2b:3c:4d:5f }

    FLOW modbus_poll(c, s) {
        c -> s MODBUS TXID 1 UNITID 1 READ_HOLDING_REGISTERS ADDR 100 COUNT 4 WAIT 5ms
        c <- s MODBUS TXID 1 UNITID 1 READ_HOLDING_REGISTERS IS_RESPONSE VALUE 42 WAIT 5ms
    }

    COMPILE { modbus_poll(sensor, plc) }
"#;

let program = parse_program(fasm).expect("valid .fasm specification");
let frames = compile_program(&program).expect("wire synthesis succeeds");
assert_eq!(frames.len(), 2);
assert_eq!(frames[1].1, 5_000_000); // 5ms in nanoseconds

generate_pcap(&program, "modbus_fixture.pcap").expect("pcap written");
```

### Entry Signatures & Error Variants
* `frameassembly::lexer::lex(source: &str) -> Result<Vec<SpannedToken<'_>>, CompilerError>`
* `frameassembly::parser::parse_program(source: &str) -> Result<Program<'_>, CompilerError>` (runs `validate_semantics` automatically)
* `frameassembly::parser::validate_semantics<'a>(program: &Program<'a>, source: &'a str) -> Result<(), CompilerError>`
* `frameassembly::backend::compile_program(program: &Program<'_>) -> Result<Vec<(Vec<u8>, u64)>, String>`
* `frameassembly::backend::generate_pcap(program: &Program<'_>, output_path: &str) -> Result<(), String>`
* `frameassembly::error::CompilerError::{LexError, ParseError, SemanticError, BackendError}`

---

## 4. Formal Grammars, Constrained Decoding & SFT Corpus

FrameAssembly ships synchronized formal grammars in the repository root so structured LLM inference engines can generate syntactically valid `.fasm` specifications with **0% syntax hallucination**:

| Artifact | Format | Target Frameworks & Purpose |
| :--- | :--- | :--- |
| [`grammar.ebnf`](../grammar.ebnf) | ISO/IEC 14977 EBNF | Canonical context-free grammar reference across all 81 protocols |
| [`frameassembly.gbnf`](../frameassembly.gbnf) | GGML BNF (`GBNF`) | `llama.cpp` (`--grammar-file frameassembly.gbnf`), `KoboldCpp`, `TabbyAPI` |
| [`frameassembly.lark`](../frameassembly.lark) | Lark Earley / LALR | `vLLM`, `Outlines`, `Guidance`, `XGrammar`, `SGLang`, `llguidance` |
| [`llms.txt`](../llms.txt) / [`llms-full.txt`](../llms-full.txt) | Markdown Context | Concise LLM index and single-fetch RAG context bundle |

### `llama.cpp` Constrained Decoding Example
```bash
llama-cli \
  -m qwen2.5-coder-7b-instruct-q8_0.gguf \
  --grammar-file frameassembly.gbnf \
  -p "Write a FrameAssembly (.fasm) program that performs a TCP 3-way handshake between 10.0.0.1 and 10.0.0.2 on port 443 and sends a TLS ClientHello with SNI 'secure.example.com'." \
  > generated.fasm && frameassembly generated.fasm -o synthesized.pcap
```

### Training Corpus Conventions (`examples/`)
Every `.fasm` file across the `2,611` scenarios in [`examples/`](../examples/) is verified by `cargo test --test corpus_verification_tests` and includes structured header comments for Supervised Fine-Tuning (SFT) and compiler-verified RLVR evaluation:
* **Line 1 (`// PROMPT:`)**: Natural-language description of the network scenario.
* **Line 2 (`// TOKENS:`)**: Exact uppercase lexer tokens exercised in the file.
* **Block Headers (`// INSTRUCTION:`)**: Precedes each `HOST`, `FLOW`, and `COMPILE` declaration.

```frameassembly
// PROMPT: Polymorphic dual-stack ICMPv4 and ICMPv6 Echo Request and Echo Reply using a single reusable FLOW.
// TOKENS: HOST, IP, FLOW, ->, <-, ICMP, ECHO_REQUEST, ECHO_REPLY, ID, SEQ, TTL, PAYLOAD, WAIT, COMPILE

// INSTRUCTION: Declare IPv4 endpoints and IPv6 endpoints.
HOST client_v4 { IP 10.0.0.10 }
HOST dns_v4    { IP 8.8.8.8 }
HOST client_v6 { IP 2001:db8::10 }
HOST dns_v6    { IP 2001:4860:4860::8888 }

// INSTRUCTION: Define a polymorphic ping flow that works over both IPv4 and IPv6.
FLOW dual_stack_ping(src, dst) {
    src -> dst ICMP ECHO_REQUEST ID 100 SEQ 1 TTL 64 PAYLOAD "polymorphic-ping"
    src <- dst ICMP ECHO_REPLY ID 100 SEQ 1 TTL 57 PAYLOAD "polymorphic-ping" WAIT 5ms
}

// INSTRUCTION: Compile the flow for IPv4 and IPv6 endpoint pairs.
COMPILE {
    dual_stack_ping(client_v4, dns_v4)
    dual_stack_ping(client_v6, dns_v6)
}
```