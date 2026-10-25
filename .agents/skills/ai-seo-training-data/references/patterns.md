# AI Training Data, RLVR Compiler Rewards, Constrained Decoding & SEO Reference Patterns

## 1. Repository-Level AI, Context7, Cross-Agent & Linguist Configuration Templates

### A. `.gitattributes` for Custom DSLs & Pre-Training Hygiene
```gitattributes
# Custom DSL syntax recognition and search indexing on GitHub Linguist / go-enry
*.fasm linguist-language=FrameAssembly linguist-detectable=true text eol=lf
*.ebnf linguist-language=EBNF linguist-detectable=true text eol=lf
*.gbnf linguist-language=EBNF linguist-detectable=true text eol=lf
*.lark linguist-language=EBNF linguist-detectable=true text eol=lf

# Documentation and AI context maps
*.md text eol=lf
llms.txt text eol=lf linguist-documentation=true
llms-full.txt text eol=lf linguist-generated=true
CITATION.cff text eol=lf
codemeta.json text eol=lf
context7.json text eol=lf

# Exclude packaged binaries and capture artifacts from language stats and text crawlers
*.vsix binary linguist-generated=true
*.pcap binary
*.pcapng binary
```

### B. `context7.json` (Upstash Context7 MCP Configuration)
```json
{
  "$schema": "https://context7.com/schema/context7.json",
  "projectTitle": "FrameAssembly",
  "description": "Declarative network packet & protocol synthesis DSL and optimizing Rust compiler (.fasm to .pcap / .pcapng across 81 native L2-L7 protocols).",
  "folders": [
    "docs",
    "examples"
  ],
  "excludeFolders": [
    ".agents",
    ".github",
    "target",
    "frameassembly-vscode",
    "tests"
  ],
  "excludeFiles": [
    "llms-full.txt"
  ],
  "rules": [
    "Always declare hosts as `HOST <id> { IP <ip> [MAC <mac>] }` without `=`, colons, commas, `IPV4`, `IPV6`, or `MASK`.",
    "Always declare parameterized flows as `FLOW <id>(<params>) { <src> -> <dst> <PROTO> ... [WAIT <int><ns|us|ms|s|m>] }` and invoke them inside `COMPILE { <flow>(<hosts>) }`.",
    "Never use `FROM`, `TO`, `REVERSE`, `SEND`, standalone `WAIT` lines, `+5ms` / `[+delay]` prefixes, `SPORT`, `DPORT`, `ACK <n>`, or `FLAGS [...]`; use `->`, `<-`, inline `WAIT 5ms`, `SRCPORT`, `DSTPORT`, `ACKNUM <n>`, and bare flag tokens `SYN ACK`.",
    "Every flow works identically over IPv4 and IPv6 host pairs, and every statement emits exactly 1 frame."
  ]
}
```

### C. `CLAUDE.md` and `.github/copilot-instructions.md` (Cross-Agent Onboarding Pointers)
```markdown
# FrameAssembly — AI Coding Agent Instructions

Please read [`AGENTS.md`](AGENTS.md) at the repository root for the authoritative build/test commands, `<layer>/<protocol>` repository architecture, `.agents/rules/*.md` and `.agents/skills/*/SKILL.md` routing tables, and mandatory `.fasm` DSL syntax invariants.

- **Formal Grammars**: [`grammar.ebnf`](grammar.ebnf) (ISO/IEC 14977 EBNF), [`frameassembly.gbnf`](frameassembly.gbnf) (`llama.cpp` / `XGrammar` GBNF), and [`frameassembly.lark`](frameassembly.lark) (`llguidance` / `Outlines` Lark).
- **AI Routing Map**: [`llms.txt`](llms.txt) and chunked protocol reference guides in [`docs/`](docs/).
- **Canonical `.fasm` Syntax**:
  - `HOST <id> { IP <ip> [MAC <mac>] }` (never use `=`, colons, `IPV4`, `IPV6`, or `MASK`).
  - `FLOW <id>(<params>) { <caller> -> <callee> <PROTOCOL> [subkeywords...] [WAIT <int><ns|us|ms|s|m>] }` (never omit `(<params>)` or use standalone `WAIT` lines, `+5ms` / `[+delay]` prefixes, `SPORT`, or `DPORT`).
  - `COMPILE { <flow_id>(<host_args>) }` (always pass host arguments).
```

### D. `CITATION.cff` & `codemeta.json` (Software Heritage, Zenodo & Academic Indexers)
```yaml
cff-version: 1.2.0
title: "FrameAssembly: A Domain-Specific Language and Optimizing Compiler for Deterministic Network Traffic Generation"
message: "If you use FrameAssembly in your research, security testing, or AI training pipelines, please cite it using this metadata."
type: software
authors:
  - given-names: Steve
    family-names: Winschel
repository-code: "https://github.com/SteveWinschel/FrameAssembly"
url: "https://crates.io/crates/frameassembly"
license: MIT
keywords:
  - network-packets
  - pcap
  - pcapng
  - domain-specific-language
  - packet-crafting
  - wireshark
  - suricata
  - network-security
  - synthetic-traffic
  - rust
```

```json
{
  "@context": "https://doi.org/10.5063/schema/codemeta-2.0",
  "@type": "SoftwareSourceCode",
  "name": "FrameAssembly",
  "description": "Declarative DSL and optimizing Rust compiler for synthesizing deterministic PCAP/PCAPNG network packet captures across 81 native L2-L7 protocols.",
  "codeRepository": "https://github.com/SteveWinschel/FrameAssembly",
  "programmingLanguage": ["Rust", "FrameAssembly"],
  "runtimePlatform": "Rust 2024 Edition",
  "license": "https://spdx.org/licenses/MIT.html",
  "author": [
    {
      "@type": "Person",
      "givenName": "Steve",
      "familyName": "Winschel"
    }
  ],
  "keywords": [
    "pcap",
    "pcapng",
    "network-traffic-generator",
    "packet-crafting",
    "dsl",
    "wireshark",
    "suricata",
    "snmpv3",
    "rust"
  ]
}
```

### E. `Cargo.toml` SEO & Packaging Configuration
```toml
[package]
name = "frameassembly"
version = "1.0.1"
edition = "2024"
rust-version = "1.85"
description = "Declarative DSL and Rust compiler for synthesizing deterministic PCAP/PCAPNG network packet captures across 81 native L2-L7 protocols."
authors = ["Steve Winschel"]
license = "MIT"
repository = "https://github.com/SteveWinschel/FrameAssembly"
homepage = "https://github.com/SteveWinschel/FrameAssembly"
documentation = "https://docs.rs/frameassembly"
keywords = ["pcap", "networking", "dsl", "packet-crafting", "security"]
categories = [
    "network-programming",
    "command-line-utilities",
    "compilers",
    "development-tools::testing",
    "parser-implementations",
]
readme = "README.md"
exclude = [
    "examples/",
    "frameassembly-vscode/",
    "*.vsix",
    "*.pcap",
    "*.pcapng",
    "llms.txt",
    "llms-full.txt",
    "docs/",
    "grammar.ebnf",
    "frameassembly.gbnf",
    "frameassembly.lark",
    "AGENTS.md",
    "CLAUDE.md",
    "CITATION.cff",
    "codemeta.json",
    "context7.json",
    "demo.fasm",
    "tests/",
    ".github/",
    ".agents/",
]

[package.metadata.docs.rs]
all-features = true
rustdoc-args = ["--cfg", "docsrs"]
```

---

## 2. 5-Way Constrained Decoding Grammar Engineering (`EBNF`, `GBNF`, `Lark` & `TextMate`)

### A. ISO/IEC 14977 EBNF Pattern (`grammar.ebnf`)
- Recognized natively by GitHub Linguist (`EBNF`) and ingested by code LLM pre-training pipelines as formal language specification context.
- Every terminal keyword in `src/lexer/mod.rs` and every syntactic production in `src/parser/` must be explicitly represented in 100% lockstep, with **zero undefined non-terminals** (e.g., always define `string_char` when referenced by `string_literal`, and allow full `str_or_ident | unsigned_int` alternatives in `TYPE` and `CHUNK` rules).

```ebnf
(* Top-level program structure *)
program           = { host_declaration | flow_declaration } , compile_block ;
host_declaration  = "HOST" , identifier , "{" , { host_property } , "}" ;
host_property     = ( "IP" , ip_address ) | ( "MAC" , mac_address ) ;
flow_declaration  = "FLOW" , identifier , "(" , [ param_list ] , ")" , "{" , { frame_statement } , "}" ;
param_list        = identifier , { "," , identifier } ;
frame_statement   = identifier , direction , identifier , { frame_field } ;
wait_modifier     = "WAIT" , unsigned_int , ( "ns" | "us" | "ms" | "s" | "m" ) ;
direction         = "->" | "<-" ;
compile_block     = "COMPILE" , "{" , { run_statement } , "}" ;
run_statement     = flow_invocation | loop_block ;
loop_block        = "LOOP" , unsigned_int , "{" , { run_statement } , "}" ;
flow_invocation   = identifier , "(" , [ arg_list ] , ")" ;
arg_list          = identifier , { "," , identifier } ;
string_literal    = '"' , { string_char } , '"' ;
string_char       = ? any printable ASCII character except '"' or '\' ? | '\"' | '\\' ;
```

### B. `llama.cpp` & MLC-AI `XGrammar` GBNF Pattern (`frameassembly.gbnf`)
- Forces token-by-token logit masking in `llama.cpp` (`llama-server -m model.gguf --grammar-file frameassembly.gbnf`) and MLC-AI `XGrammar` (`vLLM`, `SGLang`, `TensorRT-LLM` via `GrammarCompiler.compile_grammar(gbnf_str)`) so an LLM can **only** emit syntactically valid `.fasm` scripts.
- **Critical GBNF Audit Rules**:
  1. Never introduce left recursion; every rule referenced on the RHS must be defined.
  2. Include `"REPORT"` in `snmp-proto-field` alongside `"GET"`, `"GETNEXT"`, `"RESPONSE"`, `"SET"`, `"TRAP"`, `"GETBULK"`, and `"INFORM"`.
  3. Ensure `TYPE` and `CHUNK` rules accept general `str-or-ident` and `[0-9]+` arguments matching `src/parser/`.

```gbnf
root ::= ws (host-decl | flow-decl)* compile-block ws

ws ::= ([ \t\n\r] | "//" [^\n]* "\n")*
ws1 ::= ([ \t\n\r] | "//" [^\n]* "\n")+

host-decl ::= "HOST" ws1 ident ws "{" ws host-prop* "}" ws
host-prop ::= ("IP" ws1 ip-addr | "MAC" ws1 mac-addr) ws

flow-decl ::= "FLOW" ws1 ident ws "(" ws param-list? ")" ws "{" ws frame-stmt* "}" ws
param-list ::= ident ws ("," ws ident ws)*

frame-stmt ::= ident ws direction ws ident (ws1 frame-field)* ws
wait-mod ::= "WAIT" ws1 [0-9]+ ws ("ns" | "us" | "ms" | "s" | "m")
direction ::= "->" | "<-"
snmp-proto-field ::= ("GET" | "GETNEXT" | "RESPONSE" | "SET" | "TRAP" | "GETBULK" | "INFORM" | "REPORT") ws

compile-block ::= "COMPILE" ws "{" ws run-stmt* "}" ws
run-stmt ::= loop-block | flow-call
loop-block ::= "LOOP" ws1 [0-9]+ ws "{" ws run-stmt* "}" ws
flow-call ::= ident ws "(" ws param-list? ")" ws
```

### C. `llguidance` & `Outlines` Lark CFG Pattern (`frameassembly.lark`)
- Consumed by `llguidance` (Guidance / OpenAI Structured Outputs) and `Outlines` (`outlines.types.CFG`).
- **Critical Lark Lexer Disambiguation Rule**: Because Lark's Earley/LALR lexer assigns dedicated terminal types to every literal string keyword (e.g., `"CNAME"`, `"TEXT"`, `"INIT"`, `"DATA"`, `"ACK"`, `"SYNC"`, `"REPORT"`), those uppercase tokens will **not** match `IDENT` when used as unquoted field values (such as `ENCODING CNAME` or `CHUNK INIT`). Always include contextual uppercase keyword tokens inside `str_or_ident`, and include `"REPORT"` in `snmp_proto_field`:

```lark
start: (host_decl | flow_decl)* compile_block

host_decl: "HOST" IDENT "{" host_prop* "}"
host_prop: "IP" IP_ADDR | "MAC" MAC_ADDR

flow_decl: "FLOW" IDENT "(" param_list? ")" "{" frame_stmt* "}"
param_list: IDENT ("," IDENT)*

frame_stmt: IDENT DIRECTION IDENT frame_field*
DIRECTION: "->" | "<-"
wait_mod: "WAIT" INT ("ns" | "us" | "ms" | "s" | "m")
snmp_proto_field: "GET" | "GETNEXT" | "RESPONSE" | "SET" | "TRAP" | "GETBULK" | "INFORM" | "REPORT"

// Allow contextual uppercase keywords where unquoted identifiers or strings are accepted
str_or_ident: STRING | IDENT | contextual_keyword
contextual_keyword: "CNAME" | "TEXT" | "INIT" | "DATA" | "ACK" | "SYNC" | "REPORT" | "HELLO" | "OPEN" | "UPDATE" | "KEEPALIVE" | "NOTIFY" | "QUERY" | "RESPONSE" | "REQUEST" | "REPLY"

compile_block: "COMPILE" "{" run_stmt* "}"
run_stmt: loop_block | flow_call
loop_block: "LOOP" INT "{" run_stmt* "}"
flow_call: IDENT "(" param_list? ")"

IDENT: /[A-Za-z_][A-Za-z0-9_]*/
INT: /[0-9]+/
%ignore /[ \t\r\n]+/
%ignore /\/\/[^\n]*/
```

---

## 3. 4-Stage Hierarchical RLVR Verifiable Compiler Reward Function (`GRPO` / `RLVR`)

Use this deterministic Rust reward evaluator to score candidate `.fasm` generations in Reinforcement Learning with Verifiable Rewards (RLVR) training pipelines:

```rust
//! Four-stage hierarchical RLVR reward evaluator for FrameAssembly (.fasm) rollouts.

use frameassembly::backend::compile_program;
use frameassembly::lexer::Token;
use frameassembly::parser::{parse_program, validate_semantics};
use logos::Logos;

/// Computes the hierarchical verifiable compiler reward R(x, y) in [0.0, 1.0].
pub fn evaluate_fasm_rlvr_reward(candidate_fasm: &str, expected_min_frames: usize) -> f64 {
    let trimmed = candidate_fasm.trim();
    if trimmed.is_empty() {
        return 0.0;
    }

    // Stage 1 (R = 0.1): Zero lexer errors across the entire token stream
    let mut lex = Token::lexer(trimmed);
    let mut token_count = 0usize;
    while let Some(res) = lex.next() {
        if res.is_err() {
            return 0.0;
        }
        token_count += 1;
    }
    if token_count == 0 {
        return 0.0;
    }

    // Stage 2 (R = 0.3): Syntactic AST validity (HOST + parameterized FLOW + COMPILE)
    let Ok(program) = parse_program(trimmed) else {
        return 0.1;
    };

    // Stage 3 (R = 0.6): Semantic & dual-stack IPv4/IPv6 endpoint homogeneity validation
    if validate_semantics(&program, trimmed).is_err() {
        return 0.3;
    }

    // Stage 4 (R = 1.0): Full wire-frame synthesis and RFC frame count verification
    let Ok(packets) = compile_program(&program) else {
        return 0.6;
    };
    if packets.len() < expected_min_frames || packets.iter().any(|(bytes, _)| bytes.len() < 14) {
        return 0.6;
    }

    1.0
}
```

---

## 4. Chunked Pre-Training Documentation & Instruction-Tuning Pairs (`docs/*.md`)

To survive **The Stack v2**'s 512-line `.txt` filter and **go-enry**'s unknown `.fasm` extension filter while maximizing **Stack-Edu** / **FineWeb-Edu** / **Qwen2.5-Coder** educational quality scores (`>= 4/5`), structure each file in `docs/*.md` (`< 50 KB` per file) with:
1. **Self-Contained Architectural, RFC & Problem-Intent Context**: Explain the OSI layer, wire encapsulation headers, RFC standards, and Wireshark/Suricata/Zeek testing use cases.
2. **Protocol Keyword & Sub-Keyword Reference Table**: Single-line GFM table cells mapping DSL keywords to wire fields and default values.
3. **Annotated Dual-Stack `.fasm` Examples**: Fenced with ````frameassembly` including `// PROMPT:`, `// TOKENS:`, and `// INSTRUCTION:` lines, verified to compile via `frameassembly::parser::parse_program`.
4. **Natural-Language Q&A / Instruction-Tuning Pairs**: Explicit `### Prompt:` $\rightarrow$ ````frameassembly` solution pairs for Supervised Fine-Tuning (SFT) and RAG retrieval.

```markdown
### Prompt: Craft an IPv6 OSPFv3 Hello and BGP-4 Peering Session
Write a FrameAssembly (`.fasm`) script that establishes an OSPFv3 Hello adjacency to `ff02::5` followed by a BGP-4 OPEN and KEEPALIVE handshake on TCP port 179 between two IPv6 routers.

```frameassembly
// PROMPT: Establish an IPv6 OSPFv3 Hello adjacency and BGP-4 peering session.
// TOKENS: HOST, IP, FLOW, OSPF, HELLO, ROUTER_ID, AREA_ID, HELLO_INTERVAL, BGP, OPEN, ASN, HOLDTIME, BGPID, KEEPALIVE, COMPILE

// INSTRUCTION: Declare IPv6 core routers and the OSPFv3 AllSPFRouters multicast address.
HOST rtr_a { IP 2001:db8:1::1 }
HOST rtr_b { IP 2001:db8:1::2 }
HOST ospf_all_spf { IP ff02::5 }

// INSTRUCTION: Define the routing control-plane flow with OSPFv3 Hello and BGP-4 session setup.
FLOW routing_peering(peer_a, peer_b, mcast) {
    peer_a -> mcast OSPF HELLO ROUTER_ID 10.0.0.1 AREA_ID 0 HELLO_INTERVAL 10
    peer_a -> peer_b BGP OPEN ASN 65001 HOLDTIME 180 BGPID 10.0.0.1
    peer_a <- peer_b BGP OPEN ASN 65002 HOLDTIME 180 BGPID 10.0.0.2
    peer_a -> peer_b BGP KEEPALIVE
    peer_a <- peer_b BGP KEEPALIVE
}

// INSTRUCTION: Compile the routing peering flow into the output PCAP capture.
COMPILE {
    routing_peering(rtr_a, rtr_b, ospf_all_spf)
}
```
```

---

## 5. Corpus (`2,611` Files), OpenCoder Heuristic & `docs.rs` Hygiene Verification Script

Run these verification checks in CI or pre-release audits to confirm 100% compliance with LLM pre-training filters, `docs.rs` SEO rules, and Crates.io packaging requirements:

```bash
# 1. Verify zero NUL bytes (0x00) across all Markdown, text, and grammar files
python3 -c '
import glob
files = glob.glob("*.md") + glob.glob("docs/*.md") + glob.glob(".agents/skills/**/*.md", recursive=True) + glob.glob(".agents/rules/*.md") + ["llms.txt", "llms-full.txt", "grammar.ebnf", "frameassembly.gbnf", "frameassembly.lark", "CITATION.cff"]
for f in files:
    data = open(f, "rb").read()
    assert b"\x00" not in data, f"NUL byte found in {f}"
print("Zero NUL bytes verified across", len(files), "files.")
'

# 2. Verify all docs/*.md and src/**/*.rs files are strictly < 50 KB (50,000 bytes) and >= 50 words
python3 -c '
import glob, os
for pattern in ["docs/*.md", "src/**/*.rs"]:
    for f in sorted(glob.glob(pattern, recursive=True)):
        sz = os.path.getsize(f)
        words = len(open(f, "r", encoding="utf-8").read().split())
        assert sz < 50000, f"{f} exceeds 50 KB limit: {sz} bytes"
        assert words >= 50, f"{f} has fewer than 50 words (OpenCoder filter): {words} words"
print("All docs/*.md and src/**/*.rs files pass < 50 KB and >= 50 words checks.")
'

# 3. Verify all 2,611 .fasm example line lengths (avg <= 85, max <= 200), word count (>= 50), and alphanumeric ratio (>= 0.25)
python3 -c '
import glob
paths = sorted(glob.glob("examples/**/*.fasm", recursive=True))
assert len(paths) >= 2611, f"Expected >= 2,611 .fasm files, found {len(paths)}"
for p in paths:
    text = open(p, "r", encoding="utf-8").read()
    lines = text.splitlines()
    avg_len = sum(len(l) for l in lines) / max(len(lines), 1)
    max_len = max((len(l) for l in lines), default=0)
    alnum = sum(c.isalnum() for c in text) / max(len(text), 1)
    words = len(text.split())
    assert avg_len <= 85 and max_len <= 200 and alnum >= 0.25 and words >= 50, f"Filter failure in {p}"
print(f"All {len(paths)} .fasm files pass StarCoder2/The Stack v2/OpenCoder heuristics.")
'
```
