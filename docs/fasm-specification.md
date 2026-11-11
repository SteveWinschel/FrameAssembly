# FrameAssembly (`.fasm`) File Format & Media Type Specification (`text/vnd.frameassembly`)

* **Canonical Media Type:** `text/vnd.frameassembly`
* **File Extension:** `.fasm`
* **Uniform Type Identifier (UTI):** `io.github.stevewinschel.frameassembly` (conforms to `public.source-code`, `public.text`)
* **Freedesktop Shared MIME Info:** [`contrib/mime/text-vnd.frameassembly.xml`](../contrib/mime/text-vnd.frameassembly.xml) (`sub-class-of` `text/plain`, glob `*.fasm`) • [`contrib/mime/README.md`](../contrib/mime/README.md)
* **Unix `file(1)` / `libmagic` Rule:** [`contrib/magic/frameassembly.magic`](../contrib/magic/frameassembly.magic)
* **IANA Vendor Tree Registration Template:** [`contrib/iana/text-vnd.frameassembly.md`](../contrib/iana/text-vnd.frameassembly.md)
* **GitHub Linguist Grammar & Heuristics:** [`contrib/linguist/languages.yml`](../contrib/linguist/languages.yml), [`contrib/linguist/heuristics.yml`](../contrib/linguist/heuristics.yml) • [`contrib/linguist/README.md`](../contrib/linguist/README.md)
* **Formal Context-Free Grammars:** [`grammar.ebnf`](../grammar.ebnf) (ISO/IEC 14977 EBNF), [`frameassembly.gbnf`](../frameassembly.gbnf) (`llama.cpp` / `XGrammar` GBNF), [`frameassembly.lark`](../frameassembly.lark) (Earley/LALR Lark)
* **Shell Tab Completions & Supported Distribution:** [`contrib/completions/`](../contrib/completions/README.md) (`bash`, `zsh`, `fish`, `PowerShell`) • [`contrib/packaging/`](../contrib/packaging/README.md) (GitHub Releases + `.deb`, Crates.io `frameassembly`, NPM `frameassembly-wasm`, VS Code Marketplace `frameassembly-vscode`, and `SteveWinschel/homebrew-tap-FrameAssembly` for Homebrew & Scoop)
* **Reference Compiler, Website & Repository:** `frameassembly` v2.0.0 • [frameassembly.ai.studio](https://frameassembly.ai.studio/) • [https://github.com/SteveWinschel/FrameAssembly](https://github.com/SteveWinschel/FrameAssembly) • [crates.io/crates/frameassembly](https://crates.io/crates/frameassembly) • [docs.rs/frameassembly](https://docs.rs/frameassembly)

---

## 1. Abstract & Scope

The **FrameAssembly** file format (`.fasm`, media type `text/vnd.frameassembly`) is a network packet specification code format ("Packets as Code" / "PCAP as Code") for building network packet captures.

A `.fasm` document defines network endpoints (`host`), optional parameterized multi-packet traffic sequences (`flow`), and compilation targets (`compile`). Compiling `.fasm` code to `.pcap` is the default root command of the `frameassembly` reference CLI (`frameassembly <input.fasm> [output.pcap]`, defaulting to `<input_stem>.pcap`), paired with four subcommands:
* `frameassembly show <input.fasm>` — validates a `.fasm` file and prints a relative-timestamp packet ladder in the terminal without writing disk files.
* `frameassembly reverse <input.pcap> [output.fasm]` — decompiles `.pcap` or `.pcapng` captures into `.fasm` code (defaulting to `<input_stem>.fasm`), emitting `host1`, `host2`, ... declarations, strict-lowercase `[a-z0-9]+` keywords, and chronological packet statements inside `compile { ... }`. Encrypted payloads (such as SNMPv3 `authPriv`, TLS application data, SSH, or IPsec `esp`) are not decrypted during decompilation and are preserved as `tcp` or `udp` statements with `payload` / `hexpayload`.
* `frameassembly help [subcommand]` and `frameassembly version` — display CLI command reference and active compiler version (with hidden `-h`/`--help` and `-V`/`--version` flags for script compatibility, and positional output paths rather than output flags).

Generated captures across all **81 native Layer 2 through Layer 7 network protocols** feed directly into **Wireshark** and **`tshark`**, wire-speed packet injection via **`tcpreplay`**, and rule validation in intrusion detection systems (**Suricata**, **Zeek**, **Snort**), firewalls, network monitoring platforms (**Checkmk**, **Zabbix**), and CI/CD pipelines.

---

## 2. Media Type & File Identification (RFC 6838 & RFC 6657)

This section defines the formal media type registration parameters for `text/vnd.frameassembly` in accordance with [RFC 6838](https://www.rfc-editor.org/rfc/rfc6838) (Media Type Specifications and Registration Procedures) and [RFC 6657](https://www.rfc-editor.org/rfc/rfc6657) (Update to MIME regarding "charset" Parameter Handling in Textual Media Types).

| RFC 6838 §5.6 Field | Normative Specification |
| :--- | :--- |
| **Type name** | `text` |
| **Subtype name** | `vnd.frameassembly` |
| **Required parameters** | None. |
| **Optional parameters** | `charset`: Per RFC 6657 §3, the default charset is `UTF-8`. Implementations MUST support `UTF-8` without a Byte Order Mark (BOM). |
| **Encoding considerations** | `8bit` (UTF-8 source code). Documents containing only ASCII characters in comments and string literals are valid `7bit` US-ASCII. |
| **File extension(s)** | `.fasm` |
| **Macintosh file type code(s)** | `TEXT` |
| **Uniform Type Identifier (UTI)** | `io.github.stevewinschel.frameassembly` (`public.source-code`, `public.text`) |
| **Object Identifiers (OIDs)** | None. |
| **Fragment identifier considerations** | Supports [RFC 5147](https://www.rfc-editor.org/rfc/rfc5147) `text/plain` character and line fragment identifiers (for example, `#line=10,25`). |
| **Published specification** | `https://github.com/SteveWinschel/FrameAssembly/blob/main/docs/fasm-specification.md` |

---

## 3. Character Encoding, Line Endings & Binary Safety

1. **Character Encoding (`UTF-8`)**:
   - All `.fasm` files MUST be encoded in valid UTF-8 (RFC 3629).
   - All language keywords, protocol names, header modifiers, identifiers, numeric literals, IPv4/IPv6 addresses, MAC addresses, and ASN.1 Object Identifiers (OIDs) belong to the 7-bit US-ASCII character set (`0x20..0x7E`).
   - Non-ASCII UTF-8 code points MAY appear inside single-line comments (`// ...`) and double-quoted payload strings (`"..."`).
2. **Line Endings & Whitespace**:
   - The preferred line ending for `.fasm` files in version control is LF (`0x0A`, `\n`).
   - Compliant parsers MUST accept both LF (`\n`) and CRLF (`\r\n`) line endings, as well as horizontal tabs (`\t`), form feeds (`\f`), and spaces (`0x20`) as token delimiters (`[ \t\r\n\f]+`).
3. **Prohibition of Literal NUL Bytes (`0x00`)**:
   - A valid `.fasm` file MUST NOT contain literal NUL bytes (`0x00`).
   - Arbitrary binary wire payloads (including NUL bytes) are represented safely in `.fasm` code using hexadecimal escape sequences inside `payload "<string>"` (such as `\x00\x09\x01`) or hexadecimal byte strings inside `hexpayload "<hex>"` (such as `hexpayload "000102ff"`).

---

## 4. Document Structure & Lexical Grammar (v2.0.0)

### 4.1 Comments, Strict-Lowercase Keywords & Flexible User Identifiers

- **Single-Line Comments**: Comments begin with `//` and extend to the end of the line. Neither `#`, `;`, nor `/* ... */` are valid comment delimiters in `.fasm`.
- **Strict-Lowercase Built-In Keywords (`[a-z0-9]+`)**: In FrameAssembly v2.0.0, every structural keyword (`host`, `ip`, `mac`, `flow`, `compile`, `wait`), every one of the 81 protocol keywords, every Layer 2–Layer 7 modifier (`echorequest`, `innervlan`, `clienthello`, `hosthdr`, `transporthdr`, `sackperm`, `agentip`, `hellotime`, `whois`, `pkttype`, `read`, `write`, `nop`, `error`, `shutdownack`, `readholdingregisters`, etc.), and every time unit suffix (`ns`, `us`, `ms`, `s`, `m`) MUST be strictly lowercase alphanumeric (`[a-z0-9]+`) with **zero underscores (`_`)** and **zero hyphens (`-`)**. Case-insensitive keyword matching is not permitted; when an uppercase, underscored, or hyphenated typo is encountered, the reference compiler reports a self-healing diagnostic (`replace '<raw>' with '<kw>'`).
- **Flexible User-Defined Identifiers**: User-defined `host`, `flow`, and flow parameter identifiers match `[a-zA-Z_][a-zA-Z0-9_]*(-[a-zA-Z0-9_]+)*`, allowing uppercase characters, underscores (`core_sw`), and internal hyphens (`fw-dmz-01`) while stopping before `->`. Double-quoted string literals (`"..."`) preserve exact casing on the wire.

### 4.2 Three-Block Program Model

Every compilable `.fasm` file consists of up to three top-level block types:

1. **Endpoint Declarations (`host`)**:
   ```text
   host <identifier> {
       [ip <ipv4-or-ipv6-address>]
       [mac <mac-address>]
   }
   ```
   - At least one of `ip` or `mac` MUST be present (for example, `host sw1 { mac 00:1c:73:00:00:01 }` for a MAC-only Layer 2 switch).
   - `ip` *(required for Layer 3–7 protocols; optional for pure Layer 2 switching protocols `lldp`, `stp`, `lacp`, `eapol`, `vlan`, `qinq`, `mpls`, `arp`)*: Standard IPv4 dotted-quad (`10.0.0.1`) or IPv6 address (`2001:db8::1`, `fe80::1`, `ff02::fb`).
   - `mac` *(optional when `ip` is present)*: 48-bit Ethernet MAC address in IEEE colon notation (`00:1a:2b:3c:4d:5e`), hyphen notation (`00-1A-2B-3C-4D-5E`), or Cisco dotted-quad notation (`001a.2b3c.4d5e`). When omitted on an IP host, FrameAssembly derives a direction-aware unicast MAC or the standard multicast MAC per RFC 1112 (`01:00:5e:xx:xx:xx` for IPv4 `224.0.0.0/4`) and RFC 2464 (`33:33:xx:xx:xx:xx` for IPv6 `ff00::/8`).

2. **Parameterized Traffic Flows (`flow` — Optional When Using Inline `compile` Statements)**:
   ```text
   flow <identifier>(<param1>, <param2>, ...) {
       <endpoint_a> -> <endpoint_b> [modifiers...] <protocol> [protocol_fields...] [wait <duration>]
       <endpoint_a> <- <endpoint_b> [modifiers...] <protocol> [protocol_fields...] [wait <duration>]
   }
   ```
   - **1 Statement = 1 Frame**: Each statement inside a `flow` (or inline inside `compile`) emits one Ethernet frame.
   - **Directional Arrows**: `a -> b` transmits from `a` (source) to `b` (destination); `a <- b` transmits from `b` (source) back to `a` (destination), automatically reversing source and destination ports on reply packets.
   - **Shared 4-Tuple TCP State**: TCP-based Layer 7 statements automatically emit a `PSH ACK` segment on that protocol's standard port and share sequence (`seq`) and acknowledgment (`acknum`) counters with raw `tcp` statements on the same 4-tuple connection.
   - **Dual-Stack IPv4 and IPv6 Reuse**: A `flow` works across both IPv4 host pairs and IPv6 host pairs. Mixing an IPv4 endpoint and an IPv6 endpoint in the same statement is rejected during validation.

3. **Compilation & Inline Statements (`compile`)**:
   ```text
   compile {
       <flow_identifier>(<host1>, <host2>, ...)
       <host1> -> <host2> [modifiers...] <protocol> [protocol_fields...] [wait <duration>]
   }
   ```
   - Exactly one `compile` block defines the ordered sequence of flow invocations and inline packet statements written to the output capture (`loop` blocks were removed in FrameAssembly v2.0.0; repeat flow invocations or inline statements directly inside `compile { ... }`).

### 4.3 Lexical Token Classes

The reference lexer (`src/lexer/mod.rs`) partitions input code into the following token classes:

| Token Class | Lexical Pattern / Rule | Examples |
| :--- | :--- | :--- |
| **Structural Keywords** | `host`, `ip`, `mac`, `flow`, `compile`, `wait` (strict lowercase `[a-z0-9]+`, zero `_` or `-`) | `host`, `flow`, `compile`, `wait` |
| **Directional Operators** | `->` (forward frame), `<-` (reverse frame) | `client -> server`, `client <- server` |
| **Delimiters** | `{`, `}`, `(`, `)`, `,` | `flow web(c, s) { ... }` |
| **Time Unit Suffixes** | `ns`, `us`, `ms`, `s`, `m` (strict lowercase, attached to or following `wait <int>`) | `wait 500ns`, `wait 10ms`, `wait 2s` |
| **MAC Address Literal** | `([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}` \| `([0-9a-fA-F]{2}-){5}[0-9a-fA-F]{2}` \| `[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}` | `00:1a:2b:3c:4d:5e`, `00-1A-2B-3C-4D-5E`, `001a.2b3c.4d5e` |
| **IPv4 / IPv6 Literal** | `[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+` \| `::[0-9a-fA-F:.]*\|[0-9a-fA-F]{1,4}(:[0-9a-fA-F:.]*)+` | `192.168.1.10`, `2001:db8::1`, `ff02::1:ff00:1` |
| **Numeric Literal** | `-?[0-9]+\|0[xX][0-9a-fA-F]+` | `443`, `0x88cc`, `65535` |
| **ASN.1 OID Literal** | `\.?[0-9]+(\.[0-9]+)*` (3 or more arcs for OID context) | `1.3.6.1.2.1.1.5.0`, `1.3.6.1.6.3.1.1.5.3` |
| **String Literal** | `"([^"\\]\|\\.)*"` (supports `\"`, `\\`, `\n`, `\r`, `\t`, `\xHH`) | `"example.com"`, `"AMQP\x00\x00\x09\x01"` |
| **User Identifier** | `[a-zA-Z_][a-zA-Z0-9_]*(-[a-zA-Z0-9_]+)*` | `core_switch`, `fw-dmz-01`, `host1` |

### 4.4 Complete 81 Native Protocol Keywords

Every strict-lowercase protocol keyword below compiles with zero mandatory sub-keywords (emitting RFC-compliant default headers and ports) and accepts protocol-specific field overrides:

| OSI Layer | Count | Strict-Lowercase `.fasm` Protocol Keywords |
| :--- | :---: | :--- |
| **Layer 2 (Switching & Data-Link)** | 8 | `arp`, `vlan`, `qinq`, `lldp`, `stp`, `lacp`, `eapol`, `mpls` |
| **Layer 3 (Control, Tunnel, VPN, Routing)** | 20 | `icmp`, `ndp`, `igmp`, `mld`, `gre`, `vxlan`, `geneve`, `ipsec`, `esp`, `ah`, `ikev2`, `wireguard`, `ospf`, `bgp`, `rip`, `vrrp`, `hsrp`, `pim`, `bfd`, `openflow` |
| **Layer 4 (Transport)** | 3 | `tcp`, `udp`, `sctp` |
| **Layer 7 (SNMP, Infra, Time, AAA, Telemetry)** | 14 | `snmp1`, `snmp2`, `snmp3`, `dns`, `mdns`, `dhcp`, `ntp`, `ptp`, `radius`, `tacacs`, `syslog`, `netflow`, `ipfix`, `sflow` |
| **Layer 7 (Web, Security, VoIP, Access)** | 16 | `http`, `http2`, `grpc`, `websocket`, `tls`, `quic`, `tftp`, `ftp`, `ssh`, `telnet`, `whois`, `sip`, `rtp`, `rtsp`, `stun`, `ssdp` |
| **Layer 7 (Mail, Auth, Storage, DB, Brokers)** | 14 | `smtp`, `imap`, `pop3`, `kerberos`, `ldap`, `smb`, `nfs`, `redis`, `memcached`, `mysql`, `postgres`, `mqtt`, `coap`, `amqp` |
| **Layer 7 (Industrial ICS / SCADA / OT)** | 6 | `modbus`, `bacnet`, `dnp3`, `s7comm`, `ethernetip`, `opcua` |

---

## 5. Lexical Magic, Content Sniffing & `.fasm` Extension Disambiguation

### 5.1 Authoritative Three-Way Format Disambiguation

The `.fasm` file extension is historically associated with three distinct formats across network engineering, systems assembly, and hardware synthesis. Because neither Flat Assembler nor FPGA FASM has registered a formal media type with IANA or Freedesktop.org, naive extension-only associations can cause misclassification.

The table below provides the technical disambiguation across eleven dimensions:

| Dimension | **FrameAssembly (`.fasm`)** | **Flat Assembler x86 (`.asm`, `.fasm`)** | **FPGA Bitstream Assembly (`FASM`, `.fasm`)** |
| :--- | :--- | :--- | :--- |
| **Primary Domain** | Network packet capture specification code ("Packets as Code" / "PCAP as Code") | Low-level x86 / x86-64 machine assembly language | FPGA hardware tile and interconnect feature configuration (SymbiFlow / F4PGA) |
| **Media Type** | `text/vnd.frameassembly` (RFC 6838 Vendor Tree candidate) | Unregistered (`text/x-asm`) | Unregistered (`text/plain`) |
| **Comment Delimiters** | `// single-line comment` (C/C++/Rust style) | `; single-line comment` (standard assembly style) | `# single-line comment` (Python/Tcl/sh style) |
| **Top-Level Block Syntax** | `host <id> { [ip ...] [mac ...] }`, `flow <id>(...) { ... }`, `compile { ... }` | Directives: `format PE/ELF`, `section '.text'`, `segment`, `org`, `use32`/`use64` | Hierarchical dot-separated hardware tile paths: `CLBLL_L_X10Y100.SLICEL_X0...` |
| **Statement Syntax & Operators** | Directional arrows `->` and `<-` paired with Layer 2–7 protocol keywords (`tcp`, `http`, `snmp3`) | x86 CPU mnemonics: `mov`, `eax`, `xor`, `call`, `int 80h`, `push`, `pop`, `db`, `dd` | Bit-slice assignments (`ALUT.INIT[63:0] = 64'h...`) or bare feature strings |
| **Target Output Artifact** | Standard `.pcap` / `.pcapng` packet capture file | Native machine code binary (`.bin`, `.obj`, `.o`, `.exe`, `.elf`) | FPGA configuration bitstream (`.bit`, `.frames`) |
| **Reference Tool / Compiler** | `frameassembly` compiler & CLI (rootless, offline, no `libpcap` or raw sockets required) | Flat Assembler (`fasm`) assembler & linker | `fasm2frames` / `xc7frames2bit` (SymbiFlow / F4PGA architecture tooling) |
| **Downstream Consumers** | **Wireshark**, **`tshark`**, **`tcpreplay`**, **Suricata**, **Zeek**, Snort, test harnesses | Operating system loader, CPU execution, static linkers (`ld`, `link.exe`) | Xilinx 7-Series / Lattice iCE40 FPGA programming hardware |
| **Registry Authority** | Candidate IANA Vendor Tree (`text/vnd.frameassembly`), Freedesktop XML, Wikidata | Unregistered informal convention (`.asm` primary, `.fasm` secondary) | Unregistered informal convention (`.fasm` tile configuration) |
| **Text Encoding & Line Endings** | UTF-8 without BOM (RFC 6657), LF / CRLF accepted, literal NUL (`0x00`) prohibited | ASCII or regional 8-bit code pages, CR+LF or LF | US-ASCII, LF or CRLF |
| **Syntax Highlighting Scopes** | `source.frameassembly` (TextMate), `FrameAssembly` (Linguist) | `source.assembly` or `source.x86` | Generic text or hardware configuration |

### 5.2 Explicit Syntactic Distinguishing Marks & Zero False-Positive Proof

Because each format operates in a separate domain, their lexical token sets and grammars do not overlap:

1. **Comment Syntax Discrimination**:
   - FrameAssembly exclusively accepts single-line comments introduced by `//`. Semicolons (`;`) and hash marks (`#`) are lexical errors outside quoted strings.
   - Flat Assembler exclusively uses semicolons (`;`) for comments.
   - FPGA FASM exclusively uses hash characters (`#`) for comments.
2. **Top-Level Structural Blocks**:
   - Every compilable FrameAssembly file contains strict-lowercase structural blocks: `host`, optional `flow`, and `compile`.
   - Flat Assembler source files never declare `host`, `flow`, or `compile` blocks; they declare `format`, `section`, `segment`, `org`, or raw assembly labels.
   - FPGA FASM files never declare blocks or braces; they consist of newline-separated feature lines with dot-separated tile identifiers.
3. **Directional Flow Statements vs Machine Mnemonics vs Tile Paths**:
   - FrameAssembly packet statements always use directional operators (`client -> server` or `client <- server`) followed by OSI layer protocol tokens (`tcp`, `udp`, `vlan`, `http`, `snmp3`).
   - Flat Assembler statements consist of x86 opcodes and registers (`mov eax, 1`).
   - FPGA FASM statements consist of tile coordinates and bit-slices (`HCLK_L_X0Y130.ENABLE_BUFFER`).

### 5.3 Content-Sniffing & Linguist Heuristics

GitHub Linguist, `bat`, `Chroma`, and Pygments identify FrameAssembly `.fasm` documents with zero false positives using the strict-lowercase v2.0.0 regular expression heuristics published in [`contrib/linguist/heuristics.yml`](../contrib/linguist/heuristics.yml):

- **Positive FrameAssembly Anchors**:
  - `^\s*host\s+[A-Za-z_][A-Za-z0-9_-]*\s*\{\s*(?:ip|mac)\b`
  - `^\s*flow\s+[A-Za-z_][A-Za-z0-9_-]*\s*\([A-Za-z0-9_,\s-]*\)\s*\{`
  - `^\s*compile\s*\{\s*(?:[A-Za-z_][A-Za-z0-9_-]*\s*\(|[A-Za-z_][A-Za-z0-9_-]*\s*(?:->|<-))`
  - Directional packet statement: `\b[A-Za-z_][A-Za-z0-9_-]*\s*(?:->|<-)\s*[A-Za-z_][A-Za-z0-9_-]*\s+(?:...strict-lowercase protocol & modifier tokens...)\b`
- **Negative / Competing Format Anchors**:
  - Flat Assembler: `(?i)^\s*format\s+(?:PE|PE64|ELF|ELF64|MZ|COFF|binary)\b`, `(?i)^\s*(?:section|segment|use16|use32|use64|org)\b`, or lines beginning with `^\s*;`.
  - FPGA FASM: Lines beginning with `#` or matching tile patterns `^[A-Z0-9_]+(?:\.[A-Z0-9_]+){2,}`.

### 5.4 Freedesktop `shared-mime-info` Magic Signatures & Desktop Integration

The Freedesktop MIME package in [`contrib/mime/text-vnd.frameassembly.xml`](../contrib/mime/text-vnd.frameassembly.xml) (documented in [`contrib/mime/README.md`](../contrib/mime/README.md)) registers `text/vnd.frameassembly` as a subclass of `text/plain` with glob `*.fasm` (`weight="60"`) and `<magic priority="60">` rules matching strict-lowercase v2.0.0 keywords:
- `host ` or `host\t` within bytes `0..1024` AND (`ip ` or `mac `) within bytes `0..1536` AND `compile` within bytes `0..8192`, or
- `flow ` or `flow\t` within bytes `0..2048` AND `compile` within bytes `0..8192`.

Priority `60` ensures that FrameAssembly specifications take precedence over generic text handlers on Linux and BSD desktops while avoiding collisions with Flat Assembler and FPGA FASM.

### 5.5 Unix `file(1)` / `libmagic` Content Sniffing

Unix systems and command-line utilities using `libmagic` identify FrameAssembly `.fasm` files via [`contrib/magic/frameassembly.magic`](../contrib/magic/frameassembly.magic):

```magic
0	search/2048	host\ 
>0	search/1536	ip\ 
>>0	search/8192	compile	FrameAssembly network packet specification
!:mime	text/vnd.frameassembly
!:ext	fasm

0	search/2048	host\ 
>0	search/1536	mac\ 
>>0	search/8192	compile	FrameAssembly network packet specification
!:mime	text/vnd.frameassembly
!:ext	fasm

0	search/2048	flow\ 
>0	search/8192	compile	FrameAssembly network packet specification
!:mime	text/vnd.frameassembly
!:ext	fasm
```

Running `file -i <file.fasm>` returns `text/vnd.frameassembly; charset=us-ascii` or `utf-8`.

### 5.6 FAQ: What is a `.fasm` File? (FrameAssembly vs. Flat Assembler vs. FPGA FASM)

#### Q1: What is a `.fasm` file in FrameAssembly?
A `.fasm` file is a network traffic specification written in FrameAssembly `.fasm` code ("Packets as Code"). It defines network endpoints (`host`), optional directional packet exchanges across OSI Layers 2 through 7 (`flow`), and capture targets (`compile`). Running `frameassembly <input.fasm> [output.pcap]` compiles `.fasm` code offline into `.pcap` or `.pcapng` captures for Wireshark, `tshark`, `tcpreplay`, Suricata, and Zeek; `frameassembly show <input.fasm>` previews the packet ladder in the terminal; and `frameassembly reverse <input.pcap> [output.fasm]` decompiles captures back into `.fasm` code.

#### Q2: How does a FrameAssembly `.fasm` file differ from an x86 Flat Assembler file?
Flat Assembler (traditionally abbreviated FASM) is a machine-code assembler that translates low-level x86/x86-64 assembly instructions into binary executables (`.exe`, `.elf`, `.bin`). Flat Assembler files use semicolon (`;`) comments, format directives (`format PE`, `section '.text'`), and CPU mnemonics (`mov`, `jmp`, `xor`). In contrast, FrameAssembly files use slash (`//`) comments, strict-lowercase blocks (`host`, `flow`, `compile`), and networking statements (`client -> server tcp syn`).

#### Q3: How does a FrameAssembly `.fasm` file differ from an FPGA FASM file?
In open-source FPGA toolchains (SymbiFlow / F4PGA), FASM stands for FPGA Assembly. It describes low-level FPGA configuration bitstreams using hash (`#`) comments and dot-separated hardware tile feature paths (such as `CLBLL_L_X10Y100.SLICEL_X0.ALUT.INIT[63:0]`). It has no network endpoints, protocols, or flow logic.

#### Q4: How do tools, operating systems, and code editors disambiguate `.fasm` files?
Multi-tier content sniffing eliminates false-positive collisions:
1. **GitHub**: `.gitattributes` (`linguist-language=FrameAssembly`) and Linguist `heuristics.yml` detect strict-lowercase `host`, `flow`, `compile`, and directional arrows (`->` and `<-`).
2. **Linux & BSD Desktops**: Freedesktop `shared-mime-info` (`contrib/mime/text-vnd.frameassembly.xml`) and `libmagic` (`contrib/magic/frameassembly.magic`) inspect file bytes for `host ... ip|mac ... compile` or `flow ... compile` magic tokens, reporting `text/vnd.frameassembly`.
3. **VS Code & Web Packet Studio**: The VS Code Marketplace extension (`SteveWinschel.frameassembly-vscode`) and browser studio ([`frameassembly.ai.studio`](https://frameassembly.ai.studio/)) register the `source.frameassembly` TextMate scope and `text/vnd.frameassembly` MIME type.

#### Q5: Can I compile an x86 Flat Assembler or FPGA FASM file with the `frameassembly` compiler?
No. FrameAssembly is a network packet capture compiler. If you pass an x86 Flat Assembler or FPGA FASM file to `frameassembly`, the parser detects foreign syntax (such as `;` or `#` comments, `format PE`, or tile paths) and displays a plain-English error explaining that FrameAssembly `.fasm` files use `host`, `flow`, and `compile` blocks.

### 5.7 Registry Status Across Standards Bodies & Public Databases

The `.fasm` file extension and `text/vnd.frameassembly` media type maintain registration entries and packaging assets across major registries and supported channels:

1. **IANA Media Type Registry**: RFC 6838 Vendor Tree registration application in [`contrib/iana/text-vnd.frameassembly.md`](../contrib/iana/text-vnd.frameassembly.md).
2. **Freedesktop `shared-mime-info`**: XML package definition in [`contrib/mime/text-vnd.frameassembly.xml`](../contrib/mime/text-vnd.frameassembly.xml) and upstream merge request guide in [`contrib/mime/README.md`](../contrib/mime/README.md).
3. **Unix `file(1)` / `libmagic`**: Magic rule definition in [`contrib/magic/frameassembly.magic`](../contrib/magic/frameassembly.magic).
4. **GitHub Linguist**: Language definition in [`contrib/linguist/languages.yml`](../contrib/linguist/languages.yml), disambiguation heuristics in [`contrib/linguist/heuristics.yml`](../contrib/linguist/heuristics.yml), TextMate grammar in [`frameassembly-vscode/syntaxes/frameassembly.tmLanguage.json`](../frameassembly-vscode/syntaxes/frameassembly.tmLanguage.json), and upstream PR guide in [`contrib/linguist/README.md`](../contrib/linguist/README.md).
5. **Wikidata Knowledge Graph**: Entity specification and QuickStatements batch script mapping properties `P31`, `P1195`, `P1163`, `P973`, `P856`, `P1324`, `P275`, `P306`, and `P277`.
6. **Supported Software Channels**: GitHub Releases + Debian/Ubuntu `.deb`, Crates.io (`frameassembly`), NPM (`frameassembly-wasm`), VS Code Marketplace (`frameassembly-vscode`), and `SteveWinschel/homebrew-tap-FrameAssembly` (`Homebrew` & `Scoop`), documented in [`contrib/packaging/README.md`](../contrib/packaging/README.md).

---

## 6. Security Considerations (RFC 6838 §4.6 & RFC 3552)

1. **Passive, Non-Executable Format**:
   - A `.fasm` file is a passive network packet specification describing network endpoints and packet header fields. It contains no general-purpose executable code, macros, shell invocations, or system calls.
2. **Bounded, Side-Effect-Free Compilation**:
   - The `frameassembly` language is intentionally non-Turing-complete: there are no loops (`loop` was removed in FrameAssembly v2.0.0), no unbounded recursion, no dynamic memory allocation expressions, and no conditional branching.
   - The language includes no file-inclusion directives (`include` or `import`) and performs no network I/O or DNS resolution during compilation, eliminating Server-Side Request Forgery (SSRF) and local file inclusion vectors when compiling untrusted `.fasm` inputs.
   - The compiler runs offline without `CAP_NET_RAW`, raw sockets, or `libpcap`.
3. **Downstream Packet Capture Considerations**:
   - Compiling `.fasm` code (`frameassembly <input.fasm> [output.pcap]`) produces a passive `.pcap` / `.pcapng` packet capture file.
   - Because FrameAssembly is built for firewall, IDS/IPS (**Suricata**, **Zeek**, **Snort**), and protocol dissector (**Wireshark** / `tshark`) testing, generated `.pcap` files may intentionally contain custom header combinations, fragmentation overlaps (`mf` + `fragoffset`), out-of-window TCP sequence numbers, or intrusion-detection test signatures.
   - Replaying a generated `.pcap` file onto a live network interface requires explicit invocation of an external replay tool (such as `tcpreplay`) by an authorized administrator.

---

## 7. Knowledge Graph & Registry Mapping (Wikidata, IANA, GitHub)

For knowledge graphs, digital preservation registries (Wikidata, PRONOM, Software Heritage), and package indexes, the FrameAssembly `.fasm` format maps to the following properties:

| Property / Registry | Identifier / Property Code | Value |
| :--- | :--- | :--- |
| **IANA Media Type** | RFC 6838 Vendor Tree | `text/vnd.frameassembly` ([`contrib/iana/text-vnd.frameassembly.md`](../contrib/iana/text-vnd.frameassembly.md)) |
| **Freedesktop MIME** | Shared MIME-Info XML | `text/vnd.frameassembly` ([`contrib/mime/text-vnd.frameassembly.xml`](../contrib/mime/text-vnd.frameassembly.xml)) |
| **Unix `file(1)` / `libmagic`** | Magdir Rule | `text/vnd.frameassembly` ([`contrib/magic/frameassembly.magic`](../contrib/magic/frameassembly.magic)) |
| **UK National Archives PRONOM** | Technical Registry | `FrameAssembly Network Packet Specification` (`text/vnd.frameassembly`) ([`contrib/iana/text-vnd.frameassembly.md`](../contrib/iana/text-vnd.frameassembly.md)) |
| **Wikidata: instance of** | `P31` | `Q235557` (file format), `Q1262091` (packet specification format), `Q9143` (computer language) |
| **Wikidata: file extension** | `P1195` | `fasm` |
| **Wikidata: media type** | `P1163` | `text/vnd.frameassembly` |
| **Wikidata: described at URL** | `P973` | `https://github.com/SteveWinschel/FrameAssembly/blob/main/docs/fasm-specification.md` |
| **Wikidata: official website** | `P856` | `https://frameassembly.ai.studio/` |
| **Wikidata: source repository** | `P1324` | `https://github.com/SteveWinschel/FrameAssembly` |
| **Wikidata: copyright license** | `P275` | `Q334661` (MIT License) |
| **Wikidata: operating system** | `P306` | `Q388` (Linux), `Q14116` (macOS), `Q1406` (Microsoft Windows) |
| **Wikidata: programmed in** | `P277` | `Q575650` (Rust) |
| **Public Extension Databases** | FileInfo / File-Extensions / FILExt | `.fasm` (`text/vnd.frameassembly`) ([`contrib/iana/text-vnd.frameassembly.md`](../contrib/iana/text-vnd.frameassembly.md)) |
| **GitHub `.gitattributes`** | `linguist-language` | `*.fasm linguist-language=FrameAssembly linguist-detectable=true` ([`.gitattributes`](../.gitattributes)) |

---

## 8. Validated `.fasm` v2.0.0 Specification Examples

Every example below is a complete `text/vnd.frameassembly` document verified by the `frameassembly` v2.0.0 compiler (`frameassembly <input.fasm> [output.pcap]`).

### Example 1: Stateful TCP Handshake, HTTP/1.1 Transaction & Encrypted SNMPv3 USM Trap

```frameassembly
// Define IPv4 network endpoints (user identifiers allow _ and -)
host web_client    { ip 10.10.1.10  mac 00:1a:2b:3c:4d:10 }
host app-srv-01    { ip 10.10.1.80  mac 00:1a:2b:3c:4d:80 }
host nms_collector { ip 10.10.1.250 mac 00:1a:2b:3c:4d:fa }

// Stateful HTTP health check followed by an RFC 7860 SNMPv3 SHA-256 + AES-128 trap
flow service_check_and_alert(client, srv, nms) {
    client -> srv tcp syn srcport 51400 dstport 80 win 65535 mss 1460 wait 1ms
    client <- srv tcp syn ack win 65535 mss 1460 wait 1ms
    client -> srv tcp ack wait 1ms
    client -> srv http get uri "/healthz" hosthdr "app.internal" wait 4ms
    client <- srv http status 200 reason "OK" body "{\"status\":\"healthy\"}" wait 2ms
    srv -> nms vlan 100 snmp3 trap user "secops" engineid "80001f888001020304" engineboots 3 enginetime 1200 auth sha256 "AuthSecret2026!" priv aes "PrivSecret2026!" oid 1.3.6.1.6.3.1.1.5.4 varbind 1.3.6.1.2.1.1.5.0 string "app-srv-01" wait 5ms
}

compile {
    service_check_and_alert(web_client, app-srv-01, nms_collector)
}
```

### Example 2: Dual-Stack IPv4/IPv6 Flow Reuse with Carrier 802.1ad QinQ & MPLS Tagging

```frameassembly
// IPv4 and IPv6 endpoint pairs
host edge_v4 { ip 172.16.10.1   mac 00-50-56-C0-00-01 }
host core_v4 { ip 172.16.10.2   mac 00-50-56-C0-00-02 }
host edge_v6 { ip 2001:db8:10::1 mac 0050.56c0.0011 }
host core_v6 { ip 2001:db8:10::2 mac 0050.56c0.0012 }

// Reusable TLS 1.3 handshake over 802.1ad QinQ (S-VLAN 2000 / C-VLAN 100) and MPLS label 32000
flow carrier_tls_probe(pe_a, pe_b) {
    pe_a -> pe_b qinq 2000 innervlan 100 pcp 5 mpls 32000 exp 5 bos 1 mplsttl 64 dscp 46 ttl 64 tls clienthello sni "api.carrier.example" ciphersuite 4865 alpn "h2" wait 2ms
    pe_a <- pe_b qinq 2000 innervlan 100 pcp 5 mpls 32000 exp 5 bos 1 mplsttl 63 dscp 46 ttl 63 tls serverhello ciphersuite 4865 alpn "h2" wait 2ms
}

compile {
    carrier_tls_probe(edge_v4, core_v4)
    carrier_tls_probe(edge_v6, core_v6)
}
```

### Example 3: Industrial OT / SCADA Modbus TCP & IEEE 1815 DNP3 Conduit Verification

```frameassembly
host scada_master   { ip 192.168.50.10 mac 00:1b:21:50:00:10 }
host substation_rtu { ip 192.168.50.20 mac 00:0e:8c:50:00:20 }

flow substation_poll(master, rtu) {
    master -> rtu vlan 50 modbus readholdingregisters txid 10 unitid 1 addr 40001 count 4 wait 2ms
    master <- rtu vlan 50 modbus readholdingregisters txid 10 unitid 1 count 4 value 1200 isresponse wait 2ms
    master -> rtu vlan 50 dnp3 read src 1 dst 10 seq 1 group 60 variation 1 wait 5ms
}

compile {
    substation_poll(scada_master, substation_rtu)
}
```

### Example 4: Pure Layer 2 MAC-Only Switches & Inline `compile` Packet Statements

```frameassembly
host sw1 { mac 00:1c:73:00:00:01 }
host sw2 { mac 00:1c:73:00:00:02 }

compile {
    sw1 -> sw2 lldp chassisid "00:1c:73:00:00:01" portid "Ethernet1/1" ttl 120 sysname "spine-01" wait 2ms
    sw1 <- sw2 stp rstp rootid "4096/00:1c:73:00:00:02" bridgeid "4096/00:1c:73:00:00:02" portid 0x8001 cost 0 flags 0x3c
}
```

---

## 9. Related Guides & Companion References

* **[Getting Started Guide (`getting_started.md`)](getting_started.md)** — Beginner tutorial, `frameassembly show` preview, `frameassembly reverse` decompilation, and pairing FrameAssembly with `Wireshark`, `tshark`, and `tcpreplay`.
* **[Practical Use Cases & Cookbook (`use_cases.md`)](use_cases.md)** — Copy-paste `.fasm` recipes for Checkmk/Zabbix SNMPv3 traps, firewall ACLs, VLAN/QinQ/MPLS QoS, IDS/IPS rules, and OT/SCADA testing.
* **[For Nerds: Six-Stage Compiler Architecture, Rust API & Formal Grammars (`for_nerds.md`)](for_nerds.md)** — Deep dive into the zero-copy Rust compiler, public crate API, and `EBNF`/`GBNF`/`Lark` grammars.
