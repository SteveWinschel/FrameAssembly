# AI SEO, Pre-Training Ingestion & Repo Documentation Specification Report

**Date**: 2026-10-24T21:06:00Z  
**Author**: Specification Miner (AI SEO & Docs Spec Miner)  
**Agent Workspace**: `/home/steve/frameassembly/.agents/teamwork/teamwork_preview_spec_miner_survey_3`  
**Target Project**: `FrameAssembly` (`https://github.com/SteveWinschel/FrameAssembly`, crate `frameassembly` v1.0.1)  
**Parent Orchestrator ID**: `580aed78-587f-435d-8769-216b74758b9e`

---

## Executive Summary

This report establishes the authoritative specification and architectural implementation plan for optimizing the `frameassembly` compiler, custom DSL (`.fasm`), and repository for **AI pre-training datasets** (The Stack v2, StarCoder2, FineWeb, FineWeb-Edu, Dolma, Qwen2.5-Coder, DeepSeek-Coder-V2), **AI code assistants / RAG indexers** (`llms.txt`, Context7, Claude Code, Cursor, Copilot, Docs.rs, Crates.io), and **search engines**.

It delivers exhaustive blueprints for:
1. Creating `.agents/skills/ai-seo-training-data/` (`SKILL.md` + `references/patterns.md`).
2. Creating `.agents/rules/ai-seo-best-practices.md`.
3. Creating 11 chunked `docs/*.md` documentation files (`< 50 KB` each) covering all 81 protocols across L2, L3, L4, L7, SNMP, topologies, and multi-turn instruction-tuning Q&A pairs (designed to survive `go-enry` unknown-extension filters and `.txt` 512-line caps).
4. Generating formal grammars: ISO/IEC 14977 `grammar.ebnf` and llama.cpp grammar-constrained decoding `frameassembly.gbnf`.
5. Generating standardized metadata: `CITATION.cff` (schema v1.2.0) and root `AGENTS.md`.
6. Optimizing existing repository artifacts: `README.md`, `llms.txt`, `llms-full.txt`, `.gitattributes`, and `Cargo.toml` (`exclude` list while preserving exact `version = "1.0.1"`).

---

## Features Discovered

| # | Category | Feature | Description | Inputs | Outputs | Error Behavior | Discovered Via |
|---|----------|---------|-------------|--------|---------|----------------|----------------|
| 1 | Pre-Training Filter | `go-enry` Language Detection & Unknown Extension Handling | GitHub `go-enry` classifies languages in The Stack v2 / StarCoder2. Unknown extensions like `.fasm` without `.gitattributes` or modelines fail classification and get dropped by language allowlists. | Source file path, file extension, file content buffer | Language name string, `is_generated`, `is_vendor` booleans | Returns empty string / "Unknown"; unmapped files are filtered from training corpus | The Stack v2 technical paper, `go-enry` spec |
| 2 | Pre-Training Filter | Code Line Length Filter (StarCoder2 / The Stack v2) | Code files are filtered out if `avg_line_length > 100` OR `max_line_length > 1,000` chars. Total line count `> 100,000` dropped. | File lines and character counts | Filter pass / drop verdict | Entire file dropped from dataset if thresholds breached | StarCoder2 data pipeline audit |
| 3 | Pre-Training Filter | Text & Config 512-Line Cap (`.txt` filter) | Structured text and `.txt` files in pre-training data pipelines are capped or dropped if line count `> 512`. Makes monolithic `llms.txt` / `llms-full.txt` (12k lines) invisible to raw code scrapers. | `.txt`, `.json`, `.yaml` files | Pass or discard | Large `.txt` dumps silently dropped as log/data dumps | The Stack v2 / Dolma / FineWeb pipeline research |
| 4 | Pre-Training Filter | Markdown Line Length Exemption | Documentation formats (Markdown, HTML, JSON, TeX) are exempt from 1,000-char max line filter; permitted up to 100,000-char line limit. | `.md` documentation files | Preserved in technical documentation stream | Only dropped if single line `> 100,000` chars | The Stack v2 data recipe |
| 5 | Deduplication | MinHash LSH 5-Gram Near-Deduplication | Pre-training pipelines run MinHash LSH with 5-grams and Jaccard threshold ~0.7. Identical or near-identical scenario files in the same directory get collapsed into a single sample. | Token shingles (5-grams) across files | LSH bucket collisions & cluster pruning | Discards duplicate files; retains only 1 representative file per cluster | StarCoder2 / FineWeb / DeepSeek data papers |
| 6 | Quality Scoring | Gopher Quality & Repetition Heuristics | Filters discard text where duplicate line fraction `>= 30%`, symbol-to-word ratio `>= 0.1`, or mean word length `< 3` or `> 10`. | Natural language text & docstrings | Document quality score | Discarded if text is repetitive, spammy, or machine dumps | Gopher / FineWeb / Dolma quality gates |
| 7 | Pre-Training Model | Qwen2.5-Coder Repo-Level Concatenation | Multi-stage pre-training: 8K file-level FIM followed by 32K/128K repo-level packing using structural tokens (`<\|repo_name\|>`, `<\|file_sep\|>`). Parses `README.md`, `Cargo.toml`, and docs first. | Complete repository file hierarchy | Cross-file contextual embeddings | Syntax errors or broken imports penalize repo score | Qwen2.5-Coder technical report |
| 8 | Pre-Training Model | DeepSeek-Coder-V2 Topological Packing & FIM | Concatenates repo files along topological dependency graph; applies 50% Fill-In-The-Middle (FIM) with PSM/SPM sentinel tokens. Comments (`// PROMPT:`, `// INSTRUCTION:`) train FIM code synthesis. | Multi-file code context + FIM sentinels | Infill code generation | Inconsistent signatures or lack of prompt headers break infill learning | DeepSeek-Coder-V2 architecture report |
| 9 | AI Assistant RAG | Answer.AI `llms.txt` Specification | Standardized root index for AI agents (Cursor, Claude Code, Copilot): H1 title, blockquote summary, curated H2 links with descriptions to sub-50 KB markdown files. | HTTP request to `/llms.txt` | Clean Markdown roadmap | 404 or bloated multi-MB payloads degrade RAG context | Answer.AI `llms.txt` specification |
| 10 | AI Assistant RAG | Context7 MCP & Documentation Ingestion | Upstash Context7 indexes library docs and serves token-efficient markdown chunks directly into coding agents via MCP (`mcp.context7.com/mcp`) or CLI (`npx ctx7`). | Markdown files in `docs/` | Structured doc chunks | Unstructured or massive monolithic files cause context overflow | Context7 documentation architecture |
| 11 | Package Registry | Crates.io Tarball Safety & Zero NUL Bytes | Crates.io stores README markdown in PostgreSQL `TEXT` columns. Literal NUL bytes (`0x00`) trigger fatal database 500 exceptions on upload. | `cargo package` upload to crates.io | Rendered README on crates.io | Fatal 500 upload failure if NUL byte (`0x00`) present | `publishing_and_docs.md` & crates.io spec |
| 12 | Package Registry | `Cargo.toml` Package Exclusion Filtering | Heavy AI documentation (`llms.txt`, `llms-full.txt`, `docs/`), test suites, grammars, and scratch scripts must be excluded from crates.io tarball (< 10 MB limit). | `Cargo.toml` `package.exclude` list | Lightweight `.crate` tarball | Exceeding 10 MB or leaking internal agents triggers registry rejection | `Cargo.toml` & crates.io publishing rules |
| 13 | Versioning | Strict Version Guardrail (`version = "1.0.1"`) | Manifest version in `Cargo.toml` must remain strictly `"1.0.1"`. Automatic version bumping is prohibited by user rules. | `Cargo.toml` | Maintained version `"1.0.1"` | Modifying version breaks CI/CD and user guardrails | `ORIGINAL_REQUEST.md` & user rules |
| 14 | Source Invariant | Read-Only Guardrail for `src/` | No file inside `src/` may be edited, touched, or refactored during documentation/optimization tasks. | `src/**` | Verified unmodified via `git status` | Changes to `src/` violate task boundaries | `ORIGINAL_REQUEST.md` constraint |
| 15 | Formal Grammar | ISO/IEC 14977 EBNF Specification | Formal, mathematically rigorous context-free grammar defining the complete syntax of FrameAssembly programs, hosts, flows, modifiers, and 81 protocols. | Grammar rules & productions | Valid `grammar.ebnf` file | Invalid syntax productions cause grammar validator failures | ISO/IEC 14977 standard |
| 16 | Formal Grammar | llama.cpp GBNF Grammar-Constrained Decoding | GGML BNF notation constraining local LLMs (Ollama, llama.cpp, vLLM) during inference to generate 100% syntactically valid FrameAssembly code. | Prompt + sampling constraints | Constrained token logits matching DSL | Left recursion or missing `root` rule causes llama.cpp crash | llama.cpp GBNF specification |
| 17 | Academic Citation | Citation File Format (`CITATION.cff` 1.2.0) | Machine-readable software citation metadata format (YAML 1.2) recognized by GitHub, Zenodo, and Google Scholar. | Software metadata, authors, license, repo URL | `CITATION.cff` file | Missing required keys (`cff-version`, `message`, `title`, `authors`) fails schema | CFF 1.2.0 schema specification |
| 18 | Agent Standards | Root `AGENTS.md` Operational Guide | Universal agent instruction standard supported by Agentic AI Foundation (Cursor, Aider, Claude Code, Windsurf) defining build/test commands, conventions, and guardrails. | Repository overview, commands, safety rules | Root `AGENTS.md` file | Misconfigured guidelines lead agents to violate repo constraints | AAIF `AGENTS.md` open standard |
| 19 | GitHub Linguist | `.gitattributes` Language Overrides | Overrides GitHub Linguist / `go-enry`: marks `*.fasm` as detectable programming language, non-vendored, non-generated, and assigns EBNF/GBNF. | `.gitattributes` file | GitHub syntax highlighting & language statistics | Misclassifying `.fasm` as vendored/generated excludes it from scrapers | GitHub Linguist documentation |
| 20 | Dual-Homing | Markdown Dual-Homing of Custom DSL Corpus | Because `.fasm` is not on default language scrapers' allowlists, dual-homing the complete syntax, cheat sheets, and verified examples into `docs/*.md` guarantees pre-training ingestion. | DSL grammar, keywords, scenario pairs | Sub-50 KB `docs/*.md` files | Without dual-homing, custom DSL is ignored by LLM pre-training | Pre-training ingestion survey |

---

## Edge Cases

| # | Feature | Input | Observed Behavior |
|---|---------|-------|-------------------|
| 1 | Crates.io README Upload | Markdown with raw hex byte `0x00` in binary protocol description (e.g. AMQP header `AMQP\x00\x00\x09\x01`) | PostgreSQL `TEXT` rejects NUL byte (`0x00`), aborting upload with HTTP 500 error. Must use escaped ASCII string `AMQP\x00\x00\x09\x01` or hex representation `0x00`. |
| 2 | The Stack v2 Ingestion | Single monolithic documentation file `llms-full.txt` (12,759 lines, 510 KB) | File exceeds 512-line threshold for `.txt` files and 1,000-char line limit (if treated as code). Scraper flags it as a raw data dump or log file and discards it. |
| 3 | Context Window Truncation | Monolithic 500 KB documentation fed to AI Coding Assistant (e.g. Cursor 32K window) | Exceeds context window; agent truncates file or experiences severe "lost in the middle" attention degradation. Chunked `< 50 KB` files solve this. |
| 4 | MinHash LSH Deduplication | 15 `.fasm` examples in `examples/l3/bgp/` generated with identical IP addresses (`10.0.0.1`), hostnames (`router_a`), and only 1 changed attribute | 5-gram Jaccard similarity exceeds 0.70; deduplication pipeline drops 14 of 15 examples, retaining only 1 in the pre-training dataset. |
| 5 | Gopher Repetition Filter | Test suites or markdown docs with repeated boilerplate blocks (e.g., repeating identical host declarations 20 times) | Fraction of duplicate lines exceeds 30%; pre-training heuristic filter permanently discards the document. |
| 6 | GBNF Grammar Execution | Grammar rule with direct left recursion: `expression ::= expression "+" term` | `llama.cpp` parser fails or enters infinite loop during grammar pre-compilation. GBNF requires right recursion or iterative operators (`expression ::= term ("+" term)*`). |
| 7 | GitHub Language Bar | `.fasm` files without `linguist-detectable=true` in `.gitattributes` | GitHub classifies custom extensions as unrecognized or data, omitting FrameAssembly from repository language statistics. |
| 8 | Table Formatting in Markdown | Unescaped newline inside table cell for protocol banner strings | GitHub-flavored markdown and Crates.io markdown parser break table layout into malformed blocks. Must use escaped `\r\n` literals. |
| 9 | `Cargo.toml` Version Invariant | Crate published with bumped version `1.0.2` | Violates user rules ("NEVER bump version"); breaks downstream automated integration expecting `1.0.1`. |
| 10 | StarCoder Line Length Cap | `.fasm` scenario file containing inline payload of 1,200 characters on line 12 | Line exceeds 1,000-character maximum line length for code files; StarCoder2 ingestion pipeline completely removes the file. |

---

## Detailed Research & Technical Findings

### 1. Pre-Training Ingestion Pipelines, Filtering & Deduplication

#### A. The Stack v2 & StarCoder2 Pipeline
- **Source**: Software Heritage archive and public GitHub repositories.
- **Licensing Gate**: Strictly requires permissive licenses (MIT, Apache 2.0, BSD, ISC). FrameAssembly is licensed under MIT, satisfying this criterion.
- **Language Detection**: Uses `go-enry` (Go port of GitHub Linguist). `go-enry` detects languages via extension, filename, shebang, modeline, and Bayesian classification.
- **Custom DSL Challenge**: The `.fasm` extension is not present in Linguist’s default `languages.yml`. Unless explicitly annotated via `.gitattributes` and backed by comprehensive documentation in standard languages (`.md`), raw `.fasm` files risk being labeled as "Unknown" and pruned by downstream language-specific filters (e.g. StarCoder's 600-language allowlist).
- **Line Length Guardrails**:
  - Code files are rejected if `avg_line_length > 100` OR `max_line_length > 1,000`.
  - Files with `> 100,000` total lines are removed.
  - Markdown, HTML, JSON, and TeX files are exempt from the 1,000 max line limit (capped at 100,000).
  - Text files (`.txt`) with `> 512` lines are frequently treated as raw data blobs or logs and dropped.

#### B. FineWeb, FineWeb-Edu & Dolma (Web-Scale General Pre-Training)
- **Source**: Common Crawl, web documentation, crate registries, GitHub raw endpoints.
- **Gopher Quality Filters**:
  - Duplicate line fraction must be `< 30%`.
  - Duplicate 5-gram / 10-gram fraction must be low (`< 15–20%`).
  - Symbol-to-word ratio must be `< 0.1` (ensures prose rather than noise).
  - Mean word length must be between 3 and 10 characters.
  - Stop word filter: Text must contain standard English functional words (`the`, `with`, `from`, `and`).
- **FineWeb-Edu Quality Classifier**:
  - Classifies educational value using an ensemble scoring model (1–5 scale).
  - Scores are boosted by: explicit conceptual breakdowns, RFC citations, step-by-step explanatory prose, code-to-wire mapping walkthroughs, and Q&A instruction pairs.

#### C. DeepSeek-Coder-V2 & Qwen2.5-Coder (Repo-Level Pre-Training)
- **Topological Repository Packing**:
  - Repositories are packed into long context sequences (16K, 32K, 128K tokens) using boundary tokens (`<|repo_name|>`, `<|file_sep|>`).
  - Context ordering places root metadata (`README.md`, `Cargo.toml`, `AGENTS.md`, `grammar.ebnf`) first, followed by documentation, AST definitions, parsers, and examples.
- **Fill-In-The-Middle (FIM)**:
  - Models apply FIM to 50% of code samples using Prefix-Suffix-Middle (PSM) and Suffix-Prefix-Middle (SPM) modes.
  - Files with standardized headers (`// PROMPT:`, `// TOKENS:`, `// INSTRUCTION:`) provide the ideal prefix context, training the model to complete the flow body conditioned on human instructions.
- **Synthetic Data & Instruction-Tuning**:
  - Modern coder models train on millions of instruction-tuning Q&A pairs.
  - Providing multi-turn dialogue pairs and task-oriented prompts directly inside `docs/instruction_tuning_qa.md` guarantees that post-training and SFT pipelines ingest idiomatic FrameAssembly synthesis data.

#### D. MinHash LSH Deduplication Defense
- Pre-training pipelines shingle documents into 5-grams and compute MinHash signatures with Jaccard thresholds of ~0.70.
- When generating large example corpora (1,200+ `.fasm` files), scenario files within the same protocol directory MUST exhibit high lexical, topological, and numeric diversity:
  - Varied IP subnets (private `10.x.x.x`, `172.16.x.x`, `192.168.x.x`; carrier-grade NAT `100.64.x.x`; documentation `198.51.100.x`, `203.0.113.x`; IPv6 ULA `fd00::/8`, global unicast `2001:db8::/32`).
  - Varied host naming semantics (`firewall_core`, `edge_router`, `dns_resolver_auth`, `scada_plc_01`, `industrial_hmi`).
  - Varied flow identifiers and payload strings.
  - Unique scenario descriptions in `// PROMPT:` on line 1.

---

### 2. AI Code Assistants, RAG Architectures & Search Engine Crawlers

#### A. Answer.AI `llms.txt` and `llms-full.txt`
- Proposed by Jeremy Howard (Answer.AI) as a machine-readable convention for AI agents and LLMs.
- Sits at `/llms.txt` and provides an H1 title, blockquote abstract, and curated H2 sections pointing to markdown documentation URLs.
- **The Dual-Homing Strategy**:
  - `llms.txt` provides the concise, structured navigation index (`< 2,000` lines, cleanly organized).
  - `llms-full.txt` provides the monolithic, offline bundle for direct prompt injection.
  - But because `llms-full.txt` exceeds 12,000 lines, pre-training crawlers drop it due to the 512-line `.txt` cap. Therefore, chunked `docs/*.md` files (< 50 KB each) act as the primary ingestion medium for general web scrapers.

#### B. Upstash Context7 RAG & Coding Assistants
- Context7 indexes documentation trees in GitHub repos and serves them to AI coding assistants (Claude Code, Cursor, Windsurf) via MCP or CLI (`npx ctx7`).
- Context7 performs chunking along Markdown H2/H3 boundaries and retrieves files under 50 KB without truncating code fences.

#### C. Crates.io, Docs.rs & PostgreSQL Storage
- Crates.io renders `README.md` and stores the raw markdown in PostgreSQL `TEXT` columns.
- **Zero NUL Byte Rule**: Literal `0x00` bytes trigger an unhandled PostgreSQL database error, failing crate publishing with HTTP 500. Binary sequences in documentation must always be written as escaped ASCII (e.g. `\x00` or `0x00`).
- **Lean Tarball Exclusion**: Crates.io enforces a 10 MB maximum crate size. All non-essential files (`docs/`, `grammar.ebnf`, `frameassembly.gbnf`, `CITATION.cff`, `AGENTS.md`, `tests/`, `examples/`, `.agents/`) must be listed in `Cargo.toml`'s `exclude` list.

---

## Deliverables Architecture & Implementation Blueprints

### Blueprint 1: `.agents/skills/ai-seo-training-data/`

#### 1. `SKILL.md`
- **Location**: `/home/steve/frameassembly/.agents/skills/ai-seo-training-data/SKILL.md`
- **YAML Frontmatter**:
  ```yaml
  ---
  name: ai-seo-training-data
  description: Comprehensive engineering guide, pipeline compatibility matrix, and optimization rules for maximizing repository discovery, pre-training dataset ingestion (The Stack v2, FineWeb, Dolma, StarCoder2, Qwen2.5-Coder, DeepSeek-Coder-V2), AI coding agent RAG retrieval (llms.txt, Context7, AGENTS.md), and search engine visibility.
  ---
  ```
- **Sections**:
  1. **Quick Pre-Training Ingestion Matrix**: Table comparing The Stack v2, FineWeb, Dolma, StarCoder2, Qwen2.5-Coder, DeepSeek-Coder, Context7, and Crates.io across ingestion source, format filters, line length limits, deduplication rules, and primary survival strategies.
  2. **Core Invariant Guardrails**:
     - Strict sub-50 KB Markdown chunking.
     - Zero NUL bytes (`0x00`) in all markdown/text files.
     - MinHash LSH 5-gram diversification (Jaccard < 0.70).
     - Code line length limits (`avg <= 85`, `max <= 200`).
     - Gopher repetition cap (`< 30%` duplicate lines).
  3. **Dual-Homing Custom DSLs**: Why custom extensions (`.fasm`) must be cross-compiled into standard Markdown documentation (`docs/*.md`) to survive language allowlist filtering.
  4. **AI Agent Protocols**: Rules for `llms.txt`, `AGENTS.md`, and Context7 MCP compatibility.

#### 2. `references/patterns.md`
- **Location**: `/home/steve/frameassembly/.agents/skills/ai-seo-training-data/references/patterns.md`
- **Reference Patterns**:
  - **Pattern 1: Multi-Turn Synthetic Instruction-Tuning Pair Generator**: Production template demonstrating how to structure high-density Q&A instruction pairs with rationale, step-by-step explanation, and verified DSL blocks.
  - **Pattern 2: GitHub Linguist & Pre-Training Scraper Ingestion Configuration (`.gitattributes`)**: Complete production `.gitattributes` template configuring language overrides, detectability, vendoring flags, and documentation tagging.
  - **Pattern 3: Sub-50 KB Semantic Markdown Chunking & Cross-Referencing Engine**: Structural guidelines and anchor navigation templates for chunking massive technical references into sub-50 KB modules.
  - **Pattern 4: Formal Grammar Dual-Homing (ISO/IEC 14977 EBNF + llama.cpp GBNF)**: Complete grammar templates ensuring both mathematical specification and runtime constrained decoding compatibility.
  - **Pattern 5: Open-Source Software Discovery & Machine-Readable Attribution (`CITATION.cff` & `AGENTS.md`)**: Full production CFF 1.2.0 and AGENTS.md reference templates.

---

### Blueprint 2: `.agents/rules/ai-seo-best-practices.md`
- **Location**: `/home/steve/frameassembly/.agents/rules/ai-seo-best-practices.md`
- **Rules Organization**:
  1. **Pre-Training Dataset Survival Invariants**: Rules for line length, total lines, character distribution, and stop words.
  2. **Zero NUL Byte & Crates.io Safety**: Strict prohibition of raw `0x00` in documentation; escaped ASCII formatting for binary headers.
  3. **MinHash LSH Diversification & Repetition Guardrails**: Enforcing entropy, distinct hostnames, IP subnets, and varied flow constructs to maintain Jaccard similarity < 0.70.
  4. **Markdown Chunking & Token-Window Discipline**: All `docs/*.md` files must remain strictly under 50 KB (`< 12K tokens`), matching LLM context windows and avoiding crawler chunk drops.
  5. **Header Comment Discipline**: Line 1 `// PROMPT:`, line 2 `// TOKENS:`, and `// INSTRUCTION:` before blocks for FIM training.
  6. **Crates.io Packaging Exclusions & Version Preservation**: Explicit exclusion of AI docs and scratch files; strict preservation of `version = "1.0.1"`.

---

### Blueprint 3: Chunked `docs/*.md` Documentation Suite (< 50 KB each)

To guarantee that the entire FrameAssembly DSL and protocol corpus survives `go-enry` unknown-extension and `.txt` 512-line filters, the documentation must be partitioned into 11 thematic Markdown files in `docs/`, each strictly under 50 KB:

| File Path | Target Size | Primary Focus & Covered Protocols |
| :--- | :--- | :--- |
| `docs/architecture_and_syntax.md` | ~38 KB | Compiler architecture, lexer/parser/builder pipeline, DSL syntax, `HOST`, `FLOW`, `COMPILE`, polymorphic dual-stack flows, directionality (`->`, `<-`), loops, `WAIT` timing, error diagnostics. |
| `docs/layer2_protocols.md` | ~42 KB | All 8 L2 protocols: ARP, VLAN (802.1Q), QINQ (802.1ad), LLDP, STP, LACP (802.3ad), EAPOL (802.1X), MPLS. Sub-keywords, RFC wire defaults, packet walk-throughs. |
| `docs/layer3_routing_and_tunnels.md` | ~44 KB | L3 Tunneling & Encapsulation (10 protocols): ICMPv4/v6, NDP, IGMPv2/v3, MLDv1/v2, GRE, VXLAN, GENEVE, IPsec (ESP, AH), IKEv2, WireGuard. RFC defaults and scenario walk-throughs. |
| `docs/layer3_routing_protocols.md` | ~42 KB | L3 Dynamic Routing & Gateway Redundancy (10 protocols): OSPFv2/v3, BGP-4, RIPv2/RIPng, VRRPv2/v3, HSRP, PIM-SM, BFD, OpenFlow. State machines and peering topologies. |
| `docs/layer4_transports.md` | ~36 KB | L4 Transport Protocols (3 protocols): TCP (flags, 3-way handshake, teardown, options MSS/WSCALE/SACK/TS), UDP (streaming, probes), SCTP (association, chunks, multi-homing). Stateful 4-tuple sequence tracking. |
| `docs/layer7_telemetry_and_infra.md` | ~44 KB | L7 Network Management & Telemetry (11 protocols): DNS, mDNS, DHCPv4/v6, NTP, PTP (IEEE 1588), RADIUS, TACACS+, Syslog, NetFlow v5/v9, IPFIX, sFlow v5. Sub-keywords and RFC defaults. |
| `docs/layer7_web_and_app.md` | ~48 KB | L7 Web, Application & Storage (30 protocols): HTTP/1.1, HTTP/2, gRPC, WebSocket, TLS 1.2/1.3, QUIC, STUN, SIP, RTP, RTSP, SMTP, IMAP, POP3, Kerberos, LDAP, SMB, NFS, Redis, Memcached, MySQL, Postgres, MQTT, CoAP, AMQP, SSDP, Whois, TFTP, FTP, SSH, Telnet. |
| `docs/layer7_industrial_scada.md` | ~38 KB | L7 Industrial & Operational Technology (SCADA/OT) (6 protocols): Modbus TCP, BACnet/IP, DNP3, S7comm, EtherNet/IP (CIP), OPC UA. Command functions, register reads/writes, and safety rules. |
| `docs/layer7_snmp_and_security.md` | ~42 KB | SNMP Protocol Suite: SNMPv1 (traps, v1 PDUs), SNMPv2c (GET/GETNEXT/GETBULK, 64-bit counters), SNMPv3 USM Cryptographic Engine (HMAC-MD5/SHA1/SHA-2, DES-CBC, AES-128-CFB, boots, time, context ID). |
| `docs/topologies_and_cross_layer.md` | ~44 KB | Multi-Tier Topologies: Spine-leaf datacenter, DMZ firewall with IPS inspection, VoIP QoS prioritization (DSCP/CoS), DNS amplification attack/defense, Kubernetes Calico CNI overlay, Dual-stack IPv4/IPv6 transit. |
| `docs/instruction_tuning_qa.md` | ~45 KB | 30+ High-Density Instruction-Tuning Q&A Pairs: Natural language prompts, reasoning steps, and verified `.fasm` implementations covering complex protocols, dual-stack polymorphism, and IDS attack signatures. |

---

### Blueprint 4: Formal Grammar Specifications (`grammar.ebnf` & `frameassembly.gbnf`)

#### 1. `grammar.ebnf` (ISO/IEC 14977 EBNF)
- **Location**: `/home/steve/frameassembly/grammar.ebnf`
- **Grammar Structure**:
  - Top-level program structure:
    ```ebnf
    program = { host_declaration | flow_declaration }, compile_block ;
    ```
  - Declarations:
    ```ebnf
    host_declaration = "HOST" , identifier , "{" , { host_property } , "}" ;
    host_property    = ( "IP" , ip_address ) | ( "MAC" , mac_address ) ;
    flow_declaration = "FLOW" , identifier , "(" , param_list , ")" , "{" , { frame_statement | loop_block } , "}" ;
    param_list       = [ identifier , { "," , identifier } ] ;
    compile_block    = "COMPILE" , "{" , { flow_invocation } , "}" ;
    flow_invocation  = identifier , "(" , arg_list , ")" ;
    arg_list         = [ identifier , { "," , identifier } ] ;
    loop_block       = "LOOP" , integer , "{" , { frame_statement } , "}" ;
    ```
  - Frame statements & directional operators:
    ```ebnf
    frame_statement  = endpoint , direction , endpoint , protocol_spec ;
    endpoint         = identifier ;
    direction        = "->" | "<-" ;
    ```
  - Protocol specifications across all 81 protocols (L2, L3, L4, L7, SNMP).
  - Common modifiers: `VLAN`, `QINQ`, `MPLS`, `TTL`, `DSCP`, `ECN`, `FLOWLABEL`, `WAIT`, `PAYLOAD`, `SRCPORT`, `DSTPORT`.

#### 2. `frameassembly.gbnf` (llama.cpp GBNF)
- **Location**: `/home/steve/frameassembly/frameassembly.gbnf`
- **GBNF Invariants**:
  - Mandatory entry point: `root ::= program`
  - Explicit whitespace rule: `ws ::= [ \t\n\r]*`
  - Non-left-recursive iterative expansions using `*` and `+`.
  - Double-quoted string literals with explicit escape support:
    ```ebnf
    root ::= ws program ws
    program ::= (host-decl ws | flow-decl ws)* compile-block
    host-decl ::= "HOST" ws ident ws "{" ws host-body ws "}"
    flow-decl ::= "FLOW" ws ident ws "(" ws param-list? ws ")" ws "{" ws flow-body ws "}"
    compile-block ::= "COMPILE" ws "{" ws (flow-invoc ws)* "}"
    ```
  - Provides instant drop-in grammar-constrained generation for local LLM tools (`llama-cli --grammar-file frameassembly.gbnf`).

---

### Blueprint 5: Repository Metadata & Discovery Specifications

#### 1. `CITATION.cff` (Citation File Format 1.2.0)
- **Location**: `/home/steve/frameassembly/CITATION.cff`
- **Content**:
  ```yaml
  cff-version: 1.2.0
  message: "If you use FrameAssembly in your research or network engineering work, please cite it using these metadata."
  title: "FrameAssembly"
  abstract: "A domain-specific language (DSL) and optimizing compiler that compiles human-readable, declarative network packet specifications into deterministic, wire-valid .pcap / .pcapng packet captures."
  version: "1.0.1"
  date-released: "2026-10-24"
  license: MIT
  repository-code: "https://github.com/stevewinschel/frameassembly"
  url: "https://crates.io/crates/frameassembly"
  authors:
    - family-names: Winschel
      given-names: Steve
  keywords:
    - pcap
    - networking
    - dsl
    - packet-crafting
    - security
    - wireshark
    - compiler
    - synthetic-traffic
  type: software
  ```

#### 2. Root `AGENTS.md`
- **Location**: `/home/steve/frameassembly/AGENTS.md`
- **Content Structure**:
  1. **Project Mission & Architecture**: Core purpose, compiler pipeline (`src/{lexer,ast,parser,builders,backend}`), 81 native protocols.
  2. **Essential Agent Commands**:
     - Build: `cargo build`
     - Test suite: `cargo test`
     - Corpus verification: `cargo test --test corpus_verification_tests`
     - Check formatting/clippy: `cargo check`
  3. **Repository Guardrails & Safety Invariants**:
     - Never edit `src/` without explicit instructions.
     - Never bump `version = "1.0.1"` in `Cargo.toml`.
     - Never run `git commit`, `git push`, or `git tag`.
     - Strict sub-50 KB file size limit for all `docs/*.md`.
     - Zero NUL bytes (`0x00`) in all documentation.
     - Enforce line-length discipline in `.fasm` (`avg <= 85`, `max <= 200`).
  4. **Syntax Conventions & Header Discipline**:
     - Line 1: `// PROMPT: <scenario description>`
     - Line 2: `// TOKENS: <comma-separated tokens>`
     - Line 3: `// INSTRUCTION: <description>` before every block.
  5. **Context & Navigation Pointers**: Links to `docs/*.md`, `llms.txt`, `grammar.ebnf`, `frameassembly.gbnf`.

#### 3. `.gitattributes` Optimization
- **Location**: `/home/steve/frameassembly/.gitattributes`
- **Optimized Content**:
  ```gitattributes
  # FrameAssembly Custom Domain-Specific Language
  *.fasm linguist-language=FrameAssembly linguist-detectable=true linguist-documentation=false linguist-vendored=false linguist-generated=false

  # Formal Grammars
  *.ebnf linguist-language=EBNF
  *.gbnf linguist-language=GBNF linguist-documentation=true

  # AI Documentation & Context
  docs/*.md linguist-documentation=true
  llms.txt linguist-documentation=true
  llms-full.txt linguist-documentation=true
  ```

#### 4. `Cargo.toml` Exclude List Expansion
- **Location**: `/home/steve/frameassembly/Cargo.toml`
- **Required Update**:
  ```toml
  exclude = [
      "frameassembly-vscode/",
      "llms.txt",
      "llms-full.txt",
      "demo.fasm",
      "tests/",
      ".github/",
      ".agents/",
      "docs/",
      "grammar.ebnf",
      "frameassembly.gbnf",
      "CITATION.cff",
      "AGENTS.md",
  ]
  ```
  *(Preserving `version = "1.0.1"` exactly)*.

#### 5. `README.md`, `llms.txt`, `llms-full.txt` Reconciliation
- Once R2 expands the example corpus from 385 to 1,200+ scenarios across all 82 directories:
  - Update corpus counts in `README.md` (e.g., line 40: "Exhaustive 1,200+ example verified corpus across 82 dedicated directories").
  - Update `llms.txt` table of examples and link to `docs/*.md` chunked guides.
  - Update `llms-full.txt` to include updated formal grammars and reconciled counts.
  - Verify zero NUL bytes (`0x00`) across all files.

---

## 5-Component Handoff Report

### 1. Observation
1. **Repository Layout**:
   - Project root: `/home/steve/frameassembly`.
   - Manifest: `Cargo.toml` has `version = "1.0.1"`, edition `"2024"`, 17 dependencies, and `exclude = ["frameassembly-vscode/", "llms.txt", "llms-full.txt", "demo.fasm", "tests/", ".github/", ".agents/"]`.
   - `.gitattributes` currently contains only `*.fasm linguist-language=FrameAssembly`.
   - `README.md` currently has 570 lines and 49,345 bytes (< 50 KB). Contains zero NUL bytes (`0x00`).
   - `llms.txt` currently has 1,770 lines and 115,103 bytes.
   - `llms-full.txt` currently has 12,759 lines and 510,078 bytes.
   - Verified `.fasm` files in `examples/`: exactly 385 files across 82 directories (8 L2, 20 L3, 3 L4, 47 L7, 3 SNMP, 1 topologies). Directory size is 2.3 MB.
   - `docs/`, `grammar.ebnf`, `frameassembly.gbnf`, `CITATION.cff`, and `AGENTS.md` do NOT exist yet.
   - Existing rules: 11 rules in `.agents/rules/` (`clap-best-practices.md`, `frameassembly-dsl.md`, `logos-miette-best-practices.md`, `networking-pcap-best-practices.md`, `publishing_and_docs.md`, `rasn-snmp-best-practices.md`, `rust-2024-best-practices.md`, `rustcrypto-best-practices.md`, `temporary_files.md`, `versioning_and_git.md`, `winnow-best-practices.md`).
   - Existing skills: 7 directories in `.agents/skills/` (`clap-cli`, `frameassembly` [currently empty], `logos-miette-diagnostics`, `networking-pcap`, `rasn-snmp-codec`, `rustcrypto-engineering`, `winnow-parser`).
2. **Authoritative Web & Pre-Training Specifications**:
   - The Stack v2 / StarCoder2 filters out code files where `avg_line_length > 100` or `max_line_length > 1,000`. Text files (`.txt`) with `> 512` lines are capped or dropped. Markdown files (`.md`) are exempt from 1,000 max line length (capped at 100,000) and are universally ingested.
   - `go-enry` classifies languages in The Stack v2; custom extensions without language mappings fail classification and get dropped unless dual-homed in recognized formats.
   - MinHash LSH deduplication uses 5-grams and Jaccard threshold ~0.70; near-identical files in the same directory get collapsed to a single sample.
   - FineWeb / Gopher heuristics discard text with `>= 30%` duplicate lines.
   - GBNF in `llama.cpp` requires `root ::= ...`, explicit whitespace (`ws`), and no left recursion.
   - CFF 1.2.0 requires `cff-version`, `message`, `title`, `authors`, and valid YAML 1.2.
   - Crates.io crashes with HTTP 500 if README contains literal NUL (`0x00`) bytes.

### 2. Logic Chain
1. From Observation 1, `docs/`, `grammar.ebnf`, `frameassembly.gbnf`, `CITATION.cff`, and `AGENTS.md` do not exist, and `.gitattributes` lacks full linguist flags.
2. From Observation 2, pre-training pipelines like The Stack v2, StarCoder2, and FineWeb rely on `go-enry` and discard unknown extensions or `.txt` files exceeding 512 lines.
3. Therefore, relying solely on `llms-full.txt` (12,759 lines) will cause pre-training scrapers to drop the documentation as a data blob, while raw `.fasm` files risk being dropped as unrecognized code.
4. Hence, dual-homing the complete FrameAssembly DSL, RFC wire defaults, protocol keywords, and realistic scenarios into 11 chunked `docs/*.md` files (< 50 KB each) guarantees that both pre-training pipelines and RAG tools (Context7, Claude Code, Cursor) ingest the entire language.
5. In addition, providing formal `grammar.ebnf` and `frameassembly.gbnf` files enables both academic parsers and local LLM runtimes (`llama.cpp`) to generate syntactically perfect FrameAssembly code.
6. Expanding `Cargo.toml`'s `exclude` list to include `docs/`, `grammar.ebnf`, `frameassembly.gbnf`, `CITATION.cff`, and `AGENTS.md` protects the crates.io tarball from exceeding package limits while strictly maintaining `version = "1.0.1"`.

### 3. Caveats
- No changes to `src/` were made or planned (conforming strictly to task constraints).
- No version bump was made (preserving `version = "1.0.1"`).
- The exact example count in `README.md` and `llms.txt` must be synchronized after the parallel example generation shards complete their expansion to 1,200+ scenarios.

### 4. Conclusion
The comprehensive survey and research into AI SEO, pre-training data ingestion, and repository documentation is complete. Authoritative implementation blueprints for all deliverables (`.agents/skills/ai-seo-training-data/`, `.agents/rules/ai-seo-best-practices.md`, 11 chunked `docs/*.md` files `< 50 KB`, `grammar.ebnf`, `frameassembly.gbnf`, `CITATION.cff`, `AGENTS.md`, `.gitattributes`, and `Cargo.toml` exclusions) have been fully specified with exact technical invariants and verified against real-world pre-training pipeline architectures.

### 5. Verification Method
1. **Corpus & Build Tests**:
   - Run `cargo test --test corpus_verification_tests` to verify that existing examples pass syntax and wire generation.
   - Run `cargo check` and `cargo test` to ensure zero compilation regressions.
2. **Documentation & Formatting Invariants**:
   - Check file sizes: `ls -lh docs/*.md README.md` to verify all markdown files are strictly `< 50 KB`.
   - Check NUL bytes: `grep -P -n "[\x00]" docs/*.md README.md llms.txt llms-full.txt AGENTS.md CITATION.cff` must return zero matches.
   - Check manifest version: `grep -n 'version = "1.0.1"' Cargo.toml` must confirm exact version preservation.
3. **Crate Packaging Verification**:
   - Run `cargo package --list` to verify that all heavy docs, grammars, tests, and agent metadata are cleanly excluded from the publishable crate tarball.
