# FrameAssembly (`.fasm`) File Format & Media Type Specification (`text/vnd.frameassembly`)

* **Canonical Media Type:** `text/vnd.frameassembly`
* **File Extension:** `.fasm`
* **Uniform Type Identifier (UTI):** `io.github.stevewinschel.frameassembly` (conforms to `public.source-code`, `public.text`)
* **Freedesktop Shared MIME Info:** [`contrib/mime/text-vnd.frameassembly.xml`](../contrib/mime/text-vnd.frameassembly.xml) (`sub-class-of` `text/plain`, glob `*.fasm`) • [`contrib/mime/README.md`](../contrib/mime/README.md)
* **Unix `file(1)` / `libmagic` Rule:** [`contrib/magic/frameassembly.magic`](../contrib/magic/frameassembly.magic)
* **IANA Vendor Tree Registration Template:** [`contrib/iana/text-vnd.frameassembly.md`](../contrib/iana/text-vnd.frameassembly.md)
* **GitHub Linguist Grammar & Heuristics:** [`contrib/linguist/languages.yml`](../contrib/linguist/languages.yml), [`contrib/linguist/heuristics.yml`](../contrib/linguist/heuristics.yml) • [`contrib/linguist/README.md`](../contrib/linguist/README.md)
* **Formal Context-Free Grammars:** [`grammar.ebnf`](../grammar.ebnf) (ISO/IEC 14977 EBNF), [`frameassembly.gbnf`](../frameassembly.gbnf) (`llama.cpp` / `XGrammar` GBNF), [`frameassembly.lark`](../frameassembly.lark) (Earley/LALR Lark)
* **Reference Compiler & Repository:** `frameassembly` v1.5.0 • [https://github.com/SteveWinschel/FrameAssembly](https://github.com/SteveWinschel/FrameAssembly) • [crates.io/crates/frameassembly](https://crates.io/crates/frameassembly) • [docs.rs/frameassembly](https://docs.rs/frameassembly)

---

## 1. Abstract & Scope

The **FrameAssembly** file format (`.fasm`, media type `text/vnd.frameassembly`) is a network packet specification code format ("Packets as Code" / "PCAP as Code") for building network packet captures.

A `.fasm` document declares network endpoints (`HOST` / `host`), optional parameterized multi-packet traffic sequences (`FLOW` / `flow`), and compilation targets (`COMPILE` / `compile`). The `frameassembly` reference compiler translates `.fasm` files into nanosecond-resolution `.pcap` / `.pcapng` packet capture files across **81 native Layer 2 through Layer 7 network protocols**, and decompiles existing `.pcap` / `.pcapng` captures back into `.fasm` code via `frameassembly reverse`. Encrypted payloads (such as SNMPv3 `authPriv`, TLS application data, SSH, or IPsec `ESP`) are not decrypted during decompilation and are emitted as `tcp` or `udp` statements with `payload` / `hexpayload`.

Generated captures are designed for downstream inspection in **Wireshark** and **`tshark`**, wire-speed packet injection via **`tcpreplay`**, and automated rule validation in intrusion detection systems (**Suricata**, **Zeek**, **Snort**), firewalls, network management systems, and CI/CD pipelines.

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
   - The canonical line ending for `.fasm` files in version control is LF (`0x0A`, `\n`).
   - Compliant parsers MUST accept both LF (`\n`) and CRLF (`\r\n`) line endings, as well as horizontal tabs (`\t`), form feeds (`\f`), and spaces (`0x20`) as token delimiters (`[ \t\r\n\f]+`).
3. **Prohibition of Literal NUL Bytes (`0x00`)**:
   - A valid `.fasm` file MUST NOT contain literal NUL bytes (`0x00`).
   - Arbitrary binary wire payloads (including NUL bytes) are represented safely in `.fasm` source code using hexadecimal escape sequences inside `PAYLOAD "<string>"` (such as `\x00\x09\x01`) or hexadecimal byte strings inside `HEXPAYLOAD "<hex>"` (such as `HEXPAYLOAD "000102ff"`).

---

## 4. Document Structure & Lexical Grammar

### 4.1 Comments & Case-Insensitivity

- **Single-Line Comments**: Comments begin with `//` and extend to the end of the line. Neither `#` nor `/* ... */` are valid comment delimiters in `.fasm`.
- **ASCII Case-Insensitivity**: All structural keywords (`HOST`, `FLOW`, `COMPILE`, `LOOP`), all 81 protocol keywords, all Layer 2–Layer 7 modifiers, all time unit suffixes (`ns`, `us`, `ms`, `s`, `m`), and all user-defined host, flow, and parameter identifiers are ASCII case-insensitive (`host` and `HOST` are identical). String literals (`"..."`) preserve exact case on the wire.

### 4.2 Three-Block Program Model

Every compilable `.fasm` specification consists of up to three top-level block types:

1. **Endpoint Declarations (`HOST`)**:
   ```text
   HOST <identifier> {
       [IP <ipv4-or-ipv6-address>]
       [MAC <mac-address>]
   }
   ```
   - At least one of `IP` or `MAC` MUST be present (for example, `host sw1 { mac 00:1c:73:00:00:01 }` or `HOST sw1 { MAC 00:1c:73:00:00:01 }` for a MAC-only Layer 2 switch).
   - `IP` *(required for Layer 3–7 protocols; optional for pure Layer 2 switching protocols `LLDP`, `STP`, `LACP`, `EAPOL`, `VLAN`, `QINQ`, `MPLS`, `ARP`)*: Standard IPv4 dotted-quad (`10.0.0.1`) or IPv6 address (`2001:db8::1`, `fe80::1`, `ff02::fb`).
   - `MAC` *(optional when `IP` is present)*: 48-bit Ethernet MAC address in IEEE colon notation (`00:1a:2b:3c:4d:5e`), hyphen notation (`00-1A-2B-3C-4D-5E`), or Cisco dotted-quad notation (`001a.2b3c.4d5e`). When omitted on an IP host, FrameAssembly derives a direction-aware unicast MAC or the standard multicast MAC per RFC 1112 (`01:00:5e:xx:xx:xx` for IPv4 `224.0.0.0/4`) and RFC 2464 (`33:33:xx:xx:xx:xx` for IPv6 `ff00::/8`).

2. **Parameterized Traffic Flows (`FLOW` — Optional When Using Inline `COMPILE` Statements)**:
   ```text
   FLOW <identifier>(<param1>, <param2>, ...) {
       <endpoint_a> -> <endpoint_b> [modifiers...] <PROTOCOL> [protocol_fields...] [WAIT <duration>]
       <endpoint_a> <- <endpoint_b> [modifiers...] <PROTOCOL> [protocol_fields...] [WAIT <duration>]
   }
   ```
   - **1 Statement = 1 Frame**: Each statement inside a `FLOW` (or inline inside `COMPILE`) emits exactly one Ethernet frame.
   - **Directional Arrows**: `a -> b` transmits from `a` (source) to `b` (destination); `a <- b` transmits from `b` (source) back to `a` (destination), automatically reversing source and destination ports on reply packets.
   - **Shared 4-Tuple TCP State**: TCP-based Layer 7 statements automatically emit a `PSH ACK` segment on that protocol's default port and share sequence (`SEQ`) and acknowledgment (`ACKNUM`) counters with raw `TCP` statements on the same 4-tuple connection.
   - **Dual-Stack IPv4 and IPv6 Reuse**: A `FLOW` definition is protocol-version agnostic and executes over both IPv4 host pairs and IPv6 host pairs. Mixing an IPv4 endpoint and an IPv6 endpoint in the same statement is rejected at semantic validation time.

3. **Compilation, Inline Statements & Loop Execution (`COMPILE`)**:
   ```text
   COMPILE {
       <flow_identifier>(<host1>, <host2>, ...)
       <host1> -> <host2> [modifiers...] <PROTOCOL> [protocol_fields...] [WAIT <duration>]
       LOOP <positive_integer> {
           <flow_identifier>(<host1>, <host2>, ...)
       }
   }
   ```
   - Exactly one `COMPILE` / `compile` block defines the ordered sequence of flow invocations, inline packet statements (without requiring a `FLOW` block), and bounded `LOOP` repetitions written to the output capture.

### 4.3 Lexical Token Classes

The reference lexer (`src/lexer/mod.rs`) partitions input text into the following token classes:

| Token Class | Lexical Pattern / Rule | Examples |
| :--- | :--- | :--- |
| **Structural Keywords** | `HOST`, `IP`, `MAC`, `FLOW`, `COMPILE`, `LOOP`, `WAIT` (ASCII case-insensitive) | `HOST`, `flow`, `Compile`, `WAIT` |
| **Directional Operators** | `->` (forward frame), `<-` (reverse frame) | `client -> server`, `client <- server` |
| **Delimiters** | `{`, `}`, `(`, `)`, `,` | `FLOW web(c, s) { ... }` |
| **Time Unit Suffixes** | `ns`, `us`, `ms`, `s`, `m` (attached to or following `WAIT <int>`) | `WAIT 500ns`, `WAIT 10ms`, `WAIT 2s` |
| **MAC Address Literal** | `([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}` \| `([0-9a-fA-F]{2}-){5}[0-9a-fA-F]{2}` \| `[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}` | `00:1a:2b:3c:4d:5e`, `00-1A-2B-3C-4D-5E`, `001a.2b3c.4d5e` |
| **IPv4 / IPv6 Literal** | `[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+` \| `::[0-9a-fA-F:.]*\|[0-9a-fA-F]{1,4}(:[0-9a-fA-F:.]*)+` | `192.168.1.10`, `2001:db8::1`, `ff02::1:ff00:1` |
| **Numeric Literal** | `-?[0-9]+\|0[xX][0-9a-fA-F]+` | `443`, `0x88cc`, `65535` |
| **ASN.1 OID Literal** | `\.?[0-9]+(\.[0-9]+)*` (3 or more arcs for OID context) | `1.3.6.1.2.1.1.5.0`, `1.3.6.1.6.3.1.1.5.3` |
| **String Literal** | `"([^"\\]\|\\.)*"` (supports `\"`, `\\`, `\n`, `\r`, `\t`, `\xHH`) | `"example.com"`, `"AMQP\x00\x00\x09\x01"` |
| **Identifier** | `[a-zA-Z_][a-zA-Z0-9_]*` | `core_switch`, `web_session`, `client_v6` |

### 4.4 Complete 81 Native Protocol Keywords

Every protocol keyword below compiles with zero mandatory sub-keywords (emitting RFC-compliant default headers and ports) and accepts protocol-specific field overrides:

| OSI Layer | Count | Canonical `.fasm` Protocol Keywords |
| :--- | :---: | :--- |
| **Layer 2 (Switching & Data-Link)** | 8 | `ARP`, `VLAN`, `QINQ`, `LLDP`, `STP`, `LACP`, `EAPOL`, `MPLS` |
| **Layer 3 (Control, Tunnel, VPN, Routing)** | 20 | `ICMP`, `NDP`, `IGMP`, `MLD`, `GRE`, `VXLAN`, `GENEVE`, `IPSEC`, `ESP`, `AH`, `IKEV2`, `WIREGUARD`, `OSPF`, `BGP`, `RIP`, `VRRP`, `HSRP`, `PIM`, `BFD`, `OPENFLOW` |
| **Layer 4 (Transport)** | 3 | `TCP`, `UDP`, `SCTP` |
| **Layer 7 (SNMP, Infra, Time, AAA, Telemetry)** | 14 | `SNMP1`, `SNMP2`, `SNMP3`, `DNS`, `MDNS`, `DHCP`, `NTP`, `PTP`, `RADIUS`, `TACACS`, `SYSLOG`, `NETFLOW`, `IPFIX`, `SFLOW` |
| **Layer 7 (Web, Security, VoIP, Access)** | 16 | `HTTP`, `HTTP2`, `GRPC`, `WEBSOCKET`, `TLS`, `QUIC`, `TFTP`, `FTP`, `SSH`, `TELNET`, `WHOIS`, `SIP`, `RTP`, `RTSP`, `STUN`, `SSDP` |
| **Layer 7 (Mail, Auth, Storage, DB, Brokers)** | 14 | `SMTP`, `IMAP`, `POP3`, `KERBEROS`, `LDAP`, `SMB`, `NFS`, `REDIS`, `MEMCACHED`, `MYSQL`, `POSTGRES`, `MQTT`, `COAP`, `AMQP` |
| **Layer 7 (Industrial ICS / SCADA / OT)** | 6 | `MODBUS`, `BACNET`, `DNP3`, `S7COMM`, `ETHERNETIP`, `OPCUA` |

---

## 5. Lexical Magic, Content Sniffing & `.fasm` Extension Disambiguation

### 5.1 Authoritative Three-Way Format Disambiguation

The `.fasm` file extension is historically associated with three completely distinct formats across software engineering, compiler design, and hardware synthesis. Because neither Flat Assembler nor FPGA FASM has registered a formal media type with IANA or Freedesktop.org, naive extension-only associations can cause misclassification.

The table below provides the authoritative technical disambiguation across all eleven architectural dimensions:

| Architectural Dimension | **FrameAssembly (`.fasm`)** | **Flat Assembler x86 (`.asm`, `.fasm`)** | **FPGA Bitstream Assembly (`FASM`, `.fasm`)** |
| :--- | :--- | :--- | :--- |
| **Primary Domain** | Network packet capture specification code ("Packets as Code" / "PCAP as Code") | Low-level x86 / x86-64 machine assembly language | FPGA hardware tile and interconnect feature configuration (SymbiFlow / F4PGA) |
| **Canonical Media Type** | `text/vnd.frameassembly` (RFC 6838 Vendor Tree candidate) | Unregistered (`text/x-asm`) | Unregistered (`text/plain`) |
| **Comment Delimiters** | `// single-line comment` (C/C++/Rust style) | `; single-line comment` (standard assembly style) | `# single-line comment` (Python/Tcl/sh style) |
| **Top-Level Block Syntax** | `HOST <id> { [IP ...] [MAC ...] }`, `FLOW <id>(...) { ... }`, `COMPILE { ... }` | Directives: `format PE/ELF`, `section '.text'`, `segment`, `org`, `use32`/`use64` | Hierarchical dot-separated hardware tile paths: `CLBLL_L_X10Y100.SLICEL_X0...` |
| **Statement Syntax & Operators** | Directional arrows `->` and `<-` paired with Layer 2–7 protocol keywords (`TCP`, `HTTP`, `SNMP3`) | x86 CPU mnemonics: `mov`, `eax`, `xor`, `call`, `int 80h`, `push`, `pop`, `db`, `dd` | Bit-slice assignments (`ALUT.INIT[63:0] = 64'h...`) or bare feature strings |
| **Target Output Artifact** | Standard `.pcap` / `.pcapng` packet capture file | Native machine code binary (`.bin`, `.obj`, `.o`, `.exe`, `.elf`) | FPGA configuration bitstream (`.bit`, `.frames`) |
| **Reference Tool / Compiler** | `frameassembly` compiler & CLI (offline userspace, rootless, zero raw sockets) | Flat Assembler (`fasm`) assembler & linker | `fasm2frames` / `xc7frames2bit` (SymbiFlow / F4PGA architecture tooling) |
| **Downstream Consumers** | **Wireshark**, **`tshark`**, **`tcpreplay`**, **Suricata**, **Zeek**, Snort, test harnesses | Operating system loader, CPU execution, static linkers (`ld`, `link.exe`) | Xilinx 7-Series / Lattice iCE40 FPGA programming hardware |
| **Registry Authority** | Candidate IANA Vendor Tree (`text/vnd.frameassembly`), Freedesktop XML, Wikidata | Unregistered informal convention (`.asm` primary, `.fasm` secondary) | Unregistered informal convention (`.fasm` tile configuration) |
| **Text Encoding & Line Endings** | UTF-8 without BOM (RFC 6657), LF / CRLF accepted, literal NUL (`0x00`) prohibited | ASCII or regional 8-bit code pages, CR+LF or LF | US-ASCII, LF or CRLF |
| **Syntax Highlighting Scopes** | `source.frameassembly` (TextMate), `FrameAssembly` (Linguist) | `source.assembly` or `source.x86` | Generic text or hardware configuration |

### 5.2 Explicit Syntactic Distinguishing Marks & Zero False-Positive Proof

Because each format operates in a distinct technological problem domain, their lexical token sets and grammars are strictly disjoint:

1. **Comment Syntax Discrimination**:
   - FrameAssembly exclusively accepts single-line comments introduced by `//`. Semicolons (`;`) and hash marks (`#`) are lexical errors outside quoted strings.
   - Flat Assembler exclusively uses semicolons (`;`) for comments.
   - FPGA FASM exclusively uses hash characters (`#`) for comments.
2. **Top-Level Structural Blocks**:
   - Every compilable FrameAssembly file contains mandatory structural keywords: `HOST`, `FLOW`, and `COMPILE`.
   - Flat Assembler source files never declare `HOST`, `FLOW`, or `COMPILE`; they declare `format`, `section`, `segment`, `org`, or raw assembly labels.
   - FPGA FASM files never declare blocks or braces; they consist of newline-separated feature lines with dot-separated tile identifiers.
3. **Directional Flow Statements vs Machine Mnemonics vs Tile Paths**:
   - FrameAssembly packet statements always utilize directional operators (`client -> server` or `client <- server`) followed by OSI layer protocol tokens (`TCP`, `UDP`, `VLAN`, `HTTP`, `SNMP3`).
   - Flat Assembler statements consist of x86 opcodes and registers (`mov eax, 1`).
   - FPGA FASM statements consist of tile coordinates and bit-slices (`HCLK_L_X0Y130.ENABLE_BUFFER`).

### 5.3 Content-Sniffing & Linguist Heuristics

GitHub Linguist, `bat`, `Chroma`, and Pygments identify FrameAssembly `.fasm` documents with zero false positives using the regular expression heuristics published in [`contrib/linguist/heuristics.yml`](../contrib/linguist/heuristics.yml):

- **Positive FrameAssembly Anchors**:
  - `(?i)^\s*HOST\s+[A-Za-z_][A-Za-z0-9_]*\s*\{\s*(?:IP|MAC)\b`
  - `(?i)^\s*FLOW\s+[A-Za-z_][A-Za-z0-9_]*\s*\([A-Za-z0-9_,\s]*\)\s*\{`
  - `(?i)^\s*COMPILE\s*\{\s*(?:LOOP\s+[0-9]+\s*\{|[A-Za-z_][A-Za-z0-9_]*\s*\()`
  - Directional packet statement: `(?i)\b[A-Za-z_][A-Za-z0-9_]*\s*(?:->|<-)\s*[A-Za-z_][A-Za-z0-9_]*\s+(?:...protocol tokens...)\b`
- **Negative / Competing Format Anchors**:
  - Flat Assembler: `(?i)^\s*(?:format\s+(?:PE|PE64|ELF|ELF64|MZ|COFF|binary)|section\b|segment\b|use16\b|use32\b|use64\b|org\b)` or lines beginning with `;`.
  - FPGA FASM: Lines beginning with `#` or matching tile patterns `^[A-Z0-9_]+(?:\.[A-Z0-9_]+){2,}`.

### 5.4 Freedesktop `shared-mime-info` Magic Signatures & Desktop Integration

The Freedesktop MIME package in [`contrib/mime/text-vnd.frameassembly.xml`](../contrib/mime/text-vnd.frameassembly.xml) (documentation in [`contrib/mime/README.md`](../contrib/mime/README.md)) registers `text/vnd.frameassembly` as a subclass of `text/plain` with glob `*.fasm` (`weight="60"`) and `<magic priority="60">` rules matching:
- `HOST ` / `HOST\t` / `host ` / `host\t` within bytes `0..1024` AND `IP ` / `ip ` within bytes `0..1536` AND `COMPILE` / `compile` within bytes `0..8192`, or
- `FLOW ` / `flow ` within bytes `0..2048` AND `COMPILE` / `compile` within bytes `0..8192`.

Priority `60` ensures that FrameAssembly specifications take precedence over generic text handlers on Linux and BSD desktops while preventing collisions with Flat Assembler and FPGA FASM.

### 5.5 Unix `file(1)` / `libmagic` Content Sniffing

Unix systems and command-line utilities using `libmagic` identify FrameAssembly `.fasm` files via [`contrib/magic/frameassembly.magic`](../contrib/magic/frameassembly.magic):

```magic
0	search/2048/cC	HOST
>0	search/1024/cC	IP
>>0	search/4096/cC	FLOW
>>>0	search/8192/cC	COMPILE	FrameAssembly network packet specification
!:mime	text/vnd.frameassembly
!:ext	fasm

0	search/2048/cC	FLOW
>0	search/4096/cC	HOST
>>0	search/1024/cC	IP
>>>0	search/8192/cC	COMPILE	FrameAssembly network packet specification
!:mime	text/vnd.frameassembly
!:ext	fasm
```

Running `file -i <file.fasm>` returns `text/vnd.frameassembly; charset=us-ascii` or `utf-8`.

### 5.6 FAQ: What is a `.fasm` File? (FrameAssembly vs. Flat Assembler vs. FPGA FASM)

#### Q1: What is a `.fasm` file in FrameAssembly?
A `.fasm` file is a network traffic specification written in FrameAssembly `.fasm` code ("Packets as Code"). It defines network endpoints (`HOST`), optional directional packet exchanges across OSI Layers 2 through 7 (`FLOW`), and compilation schedules (`COMPILE`). The `frameassembly` compiler compiles `.fasm` specifications offline into repeatable `.pcap` or `.pcapng` capture files for Wireshark, `tshark`, `tcpreplay`, Suricata, and Zeek, and decompiles `.pcap` / `.pcapng` captures back into `.fasm` code via `frameassembly reverse`.

#### Q2: How does a FrameAssembly `.fasm` file differ from an x86 Flat Assembler file?
Flat Assembler (traditionally abbreviated FASM) is a machine-code assembler that translates low-level x86/x86-64 assembly instructions into binary executables (`.exe`, `.elf`, `.bin`). Flat Assembler files use semicolon (`;`) comments, format directives (`format PE`, `section '.text'`), and CPU mnemonics (`mov`, `jmp`, `xor`). In contrast, FrameAssembly files use slash (`//`) comments, structural blocks (`HOST`, `FLOW`, `COMPILE`), and networking directives (`client -> server TCP SYN`).

#### Q3: How does a FrameAssembly `.fasm` file differ from an FPGA FASM file?
In open-source FPGA toolchains (SymbiFlow / F4PGA), FASM stands for FPGA Assembly. It describes low-level FPGA configuration bitstreams using hash (`#`) comments and dot-separated hardware tile feature paths (such as `CLBLL_L_X10Y100.SLICEL_X0.ALUT.INIT[63:0]`). It has no network endpoints, protocols, or flow logic.

#### Q4: How do tools, operating systems, and code editors disambiguate `.fasm` files?
Multi-tier content sniffing eliminates false positive collisions:
1. **GitHub**: `.gitattributes` (`linguist-language=FrameAssembly`) and Linguist `heuristics.yml` detect `HOST`, `FLOW`, `COMPILE`, and directional arrows (`->` and `<-`).
2. **Linux & BSD Desktops**: Freedesktop `shared-mime-info` (`contrib/mime/text-vnd.frameassembly.xml`) and `libmagic` (`contrib/magic/frameassembly.magic`) inspect file bytes for `HOST ... IP ... FLOW ... COMPILE` magic tokens, reporting `text/vnd.frameassembly`.
3. **VS Code & IDEs**: The FrameAssembly extension registers the `source.frameassembly` TextMate scope and `text/vnd.frameassembly` MIME type.

#### Q5: Can I compile an x86 Flat Assembler or FPGA FASM file with the `frameassembly` compiler?
No. FrameAssembly is specifically a network packet capture compiler. If you accidentally pass an x86 Flat Assembler or FPGA FASM file to `frameassembly`, the parser immediately recognizes foreign syntax (such as `;` or `#` comments, `format PE`, or tile paths) and displays a plain-English remediation error explaining that FrameAssembly `.fasm` specifications require `HOST`, `FLOW`, and `COMPILE` blocks.

### 5.7 Registry Status Across Standards Bodies & Public Databases

The `.fasm` file extension and `text/vnd.frameassembly` media type maintain active registration entries and assets across all major registries:

1. **IANA Media Type Registry**: RFC 6838 Vendor Tree candidate registration application in [`contrib/iana/text-vnd.frameassembly.md`](../contrib/iana/text-vnd.frameassembly.md).
2. **Freedesktop `shared-mime-info`**: XML package definition in [`contrib/mime/text-vnd.frameassembly.xml`](../contrib/mime/text-vnd.frameassembly.xml) and upstream merge request guide in [`contrib/mime/README.md`](../contrib/mime/README.md).
3. **Unix `file(1)` / `libmagic`**: Magic rule definition in [`contrib/magic/frameassembly.magic`](../contrib/magic/frameassembly.magic).
4. **GitHub Linguist**: Language definition in [`contrib/linguist/languages.yml`](../contrib/linguist/languages.yml), disambiguation heuristics in [`contrib/linguist/heuristics.yml`](../contrib/linguist/heuristics.yml), TextMate grammar in [`frameassembly-vscode/syntaxes/frameassembly.tmLanguage.json`](../frameassembly-vscode/syntaxes/frameassembly.tmLanguage.json), and upstream PR guide in [`contrib/linguist/README.md`](../contrib/linguist/README.md).
5. **Wikidata Knowledge Graph**: Entity specification and QuickStatements batch script mapping properties `P31`, `P1195`, `P1163`, `P973`, `P856`, `P1324`, `P275`, `P306`, and `P277`.
6. **Public File Extension Databases, Preservation & Web Ecosystem**: Submission templates for `file-extensions.org`, `FileInfo.com`, `FILExt.com`, UK National Archives PRONOM (`digital-preservation/PRONOM_Research`), and Node.js `jshttp/mime-db` in [`contrib/iana/text-vnd.frameassembly.md`](../contrib/iana/text-vnd.frameassembly.md).

---

## 6. Security Considerations (RFC 6838 §4.6 & RFC 3552)

1. **Passive, Non-Executable Format**:
   - A `.fasm` file is a passive network packet specification describing network endpoints and packet header fields. It contains no general-purpose executable code, macros, shell invocations, or system calls.
2. **Bounded, Side-Effect-Free Compilation**:
   - The `frameassembly` language is intentionally non-Turing-complete: there is no unbounded recursion, dynamic memory allocation expression, or conditional branching. `LOOP <count> { ... }` blocks require a compile-time positive integer literal.
   - The language includes no file-inclusion directives (`include` or `import`) and performs no network I/O or DNS resolution during compilation, eliminating Server-Side Request Forgery (SSRF) and local file inclusion vectors when compiling untrusted `.fasm` inputs.
   - The compiler executes entirely in unprivileged user space without `CAP_NET_RAW`, raw sockets, or external C packet libraries (`libpcap`).
3. **Downstream Packet Capture Considerations**:
   - Compiling a `.fasm` specification produces a passive `.pcap` / `.pcapng` packet capture file.
   - Because FrameAssembly is designed for firewall, IDS/IPS (**Suricata**, **Zeek**, **Snort**), and protocol dissector (**Wireshark** / `tshark`) testing, generated `.pcap` files may intentionally contain malformed header combinations, fragmentation overlaps (`MF` + `FRAGOFFSET`), out-of-window TCP sequence numbers, or intrusion-detection test signatures.
   - Replaying a generated `.pcap` file onto a live network interface requires explicit administrator invocation of an external replay tool (such as `tcpreplay`) with host network privileges.

---

## 7. Knowledge Graph & Registry Mapping (Wikidata, IANA, GitHub)

For knowledge graphs, digital preservation registries (Wikidata, PRONOM, Software Heritage), and package indexes, the FrameAssembly `.fasm` format maps to the following canonical properties:

| Property / Registry | Identifier / Property Code | Canonical Value |
| :--- | :--- | :--- |
| **IANA Media Type** | RFC 6838 Vendor Tree | `text/vnd.frameassembly` ([`contrib/iana/text-vnd.frameassembly.md`](../contrib/iana/text-vnd.frameassembly.md)) |
| **Freedesktop MIME** | Shared MIME-Info XML | `text/vnd.frameassembly` ([`contrib/mime/text-vnd.frameassembly.xml`](../contrib/mime/text-vnd.frameassembly.xml)) |
| **Unix `file(1)` / `libmagic`** | Magdir Rule | `text/vnd.frameassembly` ([`contrib/magic/frameassembly.magic`](../contrib/magic/frameassembly.magic)) |
| **UK National Archives PRONOM** | Technical Registry | `FrameAssembly Network Packet Specification` (`text/vnd.frameassembly`) ([`contrib/iana/text-vnd.frameassembly.md`](../contrib/iana/text-vnd.frameassembly.md)) |
| **Wikidata: instance of** | `P31` | `Q235557` (file format), `Q1262091` (packet specification format), `Q9143` (computer language) |
| **Wikidata: file extension** | `P1195` | `fasm` |
| **Wikidata: media type** | `P1163` | `text/vnd.frameassembly` |
| **Wikidata: described at URL** | `P973` | `https://github.com/SteveWinschel/FrameAssembly/blob/main/docs/fasm-specification.md` |
| **Wikidata: official website** | `P856` | `https://github.com/SteveWinschel/FrameAssembly` |
| **Wikidata: source repository** | `P1324` | `https://github.com/SteveWinschel/FrameAssembly` |
| **Wikidata: copyright license** | `P275` | `Q334661` (MIT License) |
| **Wikidata: operating system** | `P306` | `Q388` (Linux), `Q14116` (macOS), `Q1406` (Microsoft Windows) |
| **Wikidata: programmed in** | `P277` | `Q575650` (Rust) |
| **Public Extension Databases** | FileInfo / File-Extensions / FILExt | `.fasm` (`text/vnd.frameassembly`) ([`contrib/iana/text-vnd.frameassembly.md`](../contrib/iana/text-vnd.frameassembly.md)) |
| **GitHub `.gitattributes`** | `linguist-language` | `*.fasm linguist-language=FrameAssembly linguist-detectable=true` ([`.gitattributes`](../.gitattributes)) |

---

## 8. Validated `.fasm` Specification Examples

Every example below is a complete, standards-compliant `text/vnd.frameassembly` document verified by the `frameassembly` compiler.

### Example 1: Stateful TCP Handshake, HTTP/1.1 Transaction & Encrypted SNMPv3 USM Trap

```frameassembly
// Define IPv4 network endpoints
HOST web_client { IP 10.10.1.10 MAC 00:1a:2b:3c:4d:10 }
HOST app_server { IP 10.10.1.80 MAC 00:1a:2b:3c:4d:80 }
HOST nms_collector { IP 10.10.1.250 MAC 00:1a:2b:3c:4d:fa }

// Stateful HTTP health check followed by an RFC 7860 SNMPv3 SHA-256 + AES-128 trap
FLOW service_check_and_alert(client, srv, nms) {
    client -> srv TCP SYN SRCPORT 51400 DSTPORT 80 WIN 65535 MSS 1460 WAIT 1ms
    client <- srv TCP SYN ACK WIN 65535 MSS 1460 WAIT 1ms
    client -> srv TCP ACK WAIT 1ms
    client -> srv HTTP GET URI "/healthz" HOST_HDR "app.internal" WAIT 4ms
    client <- srv HTTP STATUS 200 REASON "OK" BODY "{\"status\":\"healthy\"}" WAIT 2ms
    srv -> nms VLAN 100 SNMP3 TRAP USER "secops" ENGINEID "80001f888001020304" ENGINEBOOTS 3 ENGINETIME 1200 AUTH SHA256 "AuthSecret2026!" PRIV AES "PrivSecret2026!" OID 1.3.6.1.6.3.1.1.5.4 VARBIND 1.3.6.1.2.1.1.5.0 STRING "app-srv-01" WAIT 5ms
}

COMPILE {
    service_check_and_alert(web_client, app_server, nms_collector)
}
```

### Example 2: Dual-Stack IPv4/IPv6 Flow Reuse with Carrier 802.1ad QinQ & MPLS Tagging

```frameassembly
// IPv4 and IPv6 endpoint pairs
HOST edge_v4 { IP 172.16.10.1 MAC 00-50-56-C0-00-01 }
HOST core_v4 { IP 172.16.10.2 MAC 00-50-56-C0-00-02 }
HOST edge_v6 { IP 2001:db8:10::1 MAC 0050.56c0.0011 }
HOST core_v6 { IP 2001:db8:10::2 MAC 0050.56c0.0012 }

// Reusable TLS 1.3 handshake over 802.1ad QinQ (S-VLAN 2000 / C-VLAN 100) and MPLS label 32000
FLOW carrier_tls_probe(pe_a, pe_b) {
    pe_a -> pe_b QINQ 2000 INNER_VLAN 100 PCP 5 MPLS 32000 EXP 5 BOS 1 MPLS_TTL 64 DSCP 46 TTL 64 TLS CLIENT_HELLO SNI "api.carrier.example" CIPHERSUITE 4865 ALPN "h2" WAIT 2ms
    pe_a <- pe_b QINQ 2000 INNER_VLAN 100 PCP 5 MPLS 32000 EXP 5 BOS 1 MPLS_TTL 63 DSCP 46 TTL 63 TLS SERVER_HELLO CIPHERSUITE 4865 ALPN "h2" WAIT 2ms
}

COMPILE {
    carrier_tls_probe(edge_v4, core_v4)
    carrier_tls_probe(edge_v6, core_v6)
}
```

### Example 3: Industrial OT / SCADA Modbus TCP & IEEE 1815 DNP3 Conduit Verification

```frameassembly
HOST scada_master { IP 192.168.50.10 MAC 00:1b:21:50:00:10 }
HOST substation_rtu { IP 192.168.50.20 MAC 00:0e:8c:50:00:20 }

FLOW substation_poll(master, rtu) {
    master -> rtu VLAN 50 MODBUS READ_HOLDING_REGISTERS TXID 10 UNITID 1 ADDR 40001 COUNT 4 WAIT 2ms
    master <- rtu VLAN 50 MODBUS READ_HOLDING_REGISTERS TXID 10 UNITID 1 COUNT 4 VALUE 1200 IS_RESPONSE WAIT 2ms
    master -> rtu VLAN 50 DNP3 READ SRC 1 DST 10 SEQ 1 GROUP 60 VARIATION 1 WAIT 5ms
}

COMPILE {
    substation_poll(scada_master, substation_rtu)
}
```

### Example 4: Pure Layer 2 MAC-Only Switches & Inline `COMPILE` Packet Statements

```frameassembly
HOST sw1 { MAC 00:1c:73:00:00:01 }
HOST sw2 { MAC 00:1c:73:00:00:02 }

COMPILE {
    sw1 -> sw2 LLDP CHASSIS_ID "00:1c:73:00:00:01" PORT_ID "Ethernet1/1" TTL 120 SYSNAME "spine-01" WAIT 2ms
    sw1 <- sw2 STP RSTP ROOT_ID "4096/00:1c:73:00:00:02" BRIDGE_ID "4096/00:1c:73:00:00:02" PORT_ID 0x8001 COST 0 FLAGS 0x3c
}
```

---

## 9. Related Guides & Companion References

* **[Getting Started Guide (`getting_started.md`)](getting_started.md)** — Beginner tutorial, `frameassembly show` preview, and pairing FrameAssembly with `Wireshark`, `tshark`, and `tcpreplay`.
* **[Practical Use Cases & Cookbook (`use_cases.md`)](use_cases.md)** — Copy-paste `.fasm` recipes for SNMPv3 traps, firewall ACLs, VLAN/QinQ/MPLS QoS, IDS/IPS rules, and OT/SCADA testing.
* **[For Nerds: Six-Stage Compiler Architecture, Rust API & Formal Grammars (`for_nerds.md`)](for_nerds.md)** — Deep dive into the zero-copy Rust compiler, public crate API, and `EBNF`/`GBNF`/`Lark` grammars.
