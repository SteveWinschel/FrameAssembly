# Project: FrameAssembly Optimization, Example Expansion & QA Ecosystem

## Architecture
- **Compiler Core (`src/`)**: Read-only invariant. Lexer (`logos`), AST, Parser (`winnow`), Protocol builders (`src/builders/`), Native wire builders (`src/packet.rs`), PCAPNG backend (`src/pcap.rs`).
- **Corpus (`examples/`)**: 82 protocol & topology directories (`l2/*`, `l3/*`, `l4/*`, `l7/*`, `l7/snmp/*`, `topologies/`).
- **AI SEO & Documentation (`docs/`, root)**: 11 chunked `< 50 KB` markdown files, `grammar.ebnf`, `frameassembly.gbnf`, `CITATION.cff`, `AGENTS.md`, `.gitattributes`, `Cargo.toml` exclude list.
- **Skills & Rules (`.agents/`)**: 9 complete skills in `.agents/skills/` with `SKILL.md` (valid YAML frontmatter) and `references/patterns.md`; 11 rules in `.agents/rules/`.

## Feature Inventory
| # | Feature | Description | Milestone | Source |
|---|---------|-------------|-----------|--------|
| 1 | AI SEO Skill & Rules | Create `.agents/skills/ai-seo-training-data/` (`SKILL.md` + `references/patterns.md`) and `.agents/rules/ai-seo-best-practices.md` | M1 | Survey 3 |
| 2 | Chunked Documentation Suite | 11 sub-50 KB `docs/*.md` files covering L2, L3, L4, L7, SNMP, topologies, and instruction-tuning Q&A | M1 | Survey 3 |
| 3 | Formal Grammars | ISO/IEC 14977 `grammar.ebnf` and llama.cpp `frameassembly.gbnf` | M1 | Survey 3 |
| 4 | Metadata & Citation | `CITATION.cff` (v1.2.0) and root `AGENTS.md` | M1 | Survey 3 |
| 5 | Linguist & Package Excludes | `.gitattributes` Linguist configuration and `Cargo.toml` `exclude` expansion (preserving `version = "1.0.1"`) | M1 | Survey 3 |
| 6 | Native Wire `networking-pcap` Skill | Replace stale `etherparse` with native RFC wire builders (`src/packet.rs`) and `pcap-file 2.0.0` in skill and rule | M2 | Survey 2 |
| 7 | Upgrade 5 Existing Skills & Rules | Upgrade `clap-cli`, `logos-miette-diagnostics`, `rasn-snmp-codec`, `rustcrypto-engineering`, and `winnow-parser` skills & rules | M2 | Survey 2 |
| 8 | New Skill: `frameassembly` | Populate `.agents/skills/frameassembly/` (`SKILL.md` + `references/patterns.md`) with compiler architecture & DSL spec | M2 | Survey 2 |
| 9 | New Skill: `rust-modern-qa` & Rules | Create `.agents/skills/rust-modern-qa/` (`SKILL.md` + `references/patterns.md`) and expand `.agents/rules/rust-2024-best-practices.md` | M2 | Survey 2 |
| 10 | Corpus Shard 1: L2 & L4 SCTP | Expand 8 dirs (`eapol`, `lacp`, `lldp`, `mpls`, `qinq`, `stp`, `vlan`, `sctp`) by 95 files -> 15 each | M3 | Survey 1 |
| 11 | Corpus Shard 2: L3 Routing A | Expand 10 dirs (`ah`, `bfd`, `bgp`, `esp`, `geneve`, `gre`, `hsrp`, `icmp`, `igmp`, `ikev2`) by 120 files -> 15 each | M3 | Survey 1 |
| 12 | Corpus Shard 3: L3 Routing B | Expand 10 dirs (`ipsec`, `mld`, `ndp`, `openflow`, `ospf`, `pim`, `rip`, `vrrp`, `vxlan`, `wireguard`) by 120 files -> 15 each | M3 | Survey 1 |
| 13 | Corpus Shard 4: L7 Core & App | Expand 12 dirs (`amqp`, `bacnet`, `coap`, `dhcp`, `dnp3`, `dns`, `ethernetip`, `ftp`, `grpc`, `http`, `http2`, `imap`) by 144 files -> 15 each | M3 | Survey 1 |
| 14 | Corpus Shard 5: L7 Telemetry/DB | Expand 12 dirs (`ipfix`, `kerberos`, `ldap`, `mdns`, `memcached`, `modbus`, `mqtt`, `mysql`, `netflow`, `nfs`, `ntp`, `opcua`) by 144 files -> 15 each | M3 | Survey 1 |
| 15 | Corpus Shard 6: L7 Media/Storage | Expand 12 dirs (`pop3`, `postgres`, `ptp`, `quic`, `radius`, `redis`, `rtp`, `rtsp`, `s7comm`, `sflow`, `sip`, `smb`) by 144 files -> 15 each | M3 | Survey 1 |
| 16 | Corpus Shard 7: L7 Sec/Utils & Wrapping | Expand 11 dirs (`smtp`, `ssdp`, `ssh`, `stun`, `syslog`, `tacacs`, `telnet`, `tftp`, `tls`, `websocket`, `whois`) by 132 files -> 15 each, and wrap 51 long lines in SNMP/topologies | M3 | Survey 1 |
| 17 | Final Reconciliation & Full Verification | Reconcile example counts in `README.md`, `llms.txt`, `llms-full.txt`; run `cargo test --test corpus_verification_tests`, `cargo test`, `cargo clippy`; Challenger & Auditor verification | M4 | Survey 1/2/3 |

## Milestones
| # | Name | Scope | Dependencies | Status |
|---|------|-------|-------------|--------|
| M1 | AI SEO & Documentation | Features 1–5 (`docs/`, `grammar.*`, `CITATION.cff`, `AGENTS.md`, `.gitattributes`, `Cargo.toml`, skill/rule) | Survey | IN_PROGRESS (conv: 83857d83-abc7-4381-b93e-95b54282a48d) |
| M2 | Crate & Rust QA Skills/Rules | Features 6–9 (All 9 skills, matching rules, native RFC wire builders, Rust 2024 QA) | Survey | DONE (conv: 6d58be14-fb6f-4fb8-a844-bca3425927fe; all 9 skills valid, 0 clippy warnings) |
| M3 | Parallel Corpus Expansion | Features 10–16 (Shards 1–7 expanding 75 dirs by 899 files -> 1,296 total, line wrapping) | Survey | IN_PROGRESS (Shards 2, 4 complete) |
| M4 | Final Reconciliation & Verification | Feature 17 (README/llms reconciliation, full test suites, Challenger, Forensic Auditor) | M1, M2, M3 | PLANNED |

## Code Layout & Write Boundaries
- `src/**`: READ-ONLY. Zero edits allowed.
- `Cargo.toml`: Only `exclude` list may be updated. `version = "1.0.1"` must remain strictly preserved.
- `docs/*.md`: Owned by M1.
- `grammar.ebnf`, `frameassembly.gbnf`, `CITATION.cff`, `AGENTS.md`, `.gitattributes`: Owned by M1.
- `.agents/skills/ai-seo-training-data/**`, `.agents/rules/ai-seo-best-practices.md`: Owned by M1.
- `.agents/skills/{clap-cli,logos-miette-diagnostics,networking-pcap,rasn-snmp-codec,rustcrypto-engineering,winnow-parser,frameassembly,rust-modern-qa}/**`: Owned by M2.
- `.agents/rules/{clap,logos-miette,networking-pcap,rasn-snmp,rust-2024,rustcrypto,winnow}-best-practices.md`: Owned by M2.
- `examples/**`: Owned exclusively by M3 Shards 1–7 (strictly disjoint directory subsets).
- `README.md`, `llms.txt`, `llms-full.txt`: Updated during M1, final count reconciled in M4.
