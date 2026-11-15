# FrameAssembly (`.frasm`) File Format & Media Type Specification (`text/vnd.frameassembly`)

[← Main README](../README.md) • [Docs Index](README.md) • [Use-Case Cookbook](02_use_cases.md)

* **Canonical Media Type:** `text/vnd.frameassembly`
* **File Extension:** `.frasm`
* **Uniform Type Identifier (UTI):** `io.github.stevewinschel.frameassembly` (conforms to `public.source-code`, `public.text`)
* **Freedesktop Shared MIME Info:** [`contrib/mime/text-vnd.frameassembly.xml`](../contrib/mime/text-vnd.frameassembly.xml) (`sub-class-of` `text/plain`, glob `*.frasm`)
  • [`contrib/mime/README.md`](../contrib/mime/README.md)
* **Unix `file(1)` / `libmagic` Rule:** [`contrib/magic/frameassembly.magic`](../contrib/magic/frameassembly.magic)
* **IANA Vendor Tree Registration Template:** [`contrib/iana/text-vnd.frameassembly.md`](../contrib/iana/text-vnd.frameassembly.md)
* **GitHub Linguist Grammar & Heuristics:** [`contrib/linguist/languages.yml`](../contrib/linguist/languages.yml),
  [`contrib/linguist/heuristics.yml`](../contrib/linguist/heuristics.yml) • [`contrib/linguist/README.md`](../contrib/linguist/README.md)
* **Formal Grammars:** [`grammar.ebnf`](../grammar.ebnf) (ISO/IEC 14977 EBNF), [`frameassembly.gbnf`](../frameassembly.gbnf) (`llama.cpp` / `XGrammar` GBNF),
  [`frameassembly.lark`](../frameassembly.lark) (Lark)
* **Shell Tab Completions & Supported Distribution:** [`contrib/completions/`](../contrib/completions/README.md) (`bash`, `zsh`, `fish`, `PowerShell`)
  • [`contrib/packaging/`](../contrib/packaging/README.md) (`cargo install frameassembly`, GitHub Releases + `.deb`, NPM `frameassembly-wasm`,
  VS Code Marketplace `frameassembly-vscode`, and `SteveWinschel/homebrew-tap-FrameAssembly` for Homebrew & Scoop)
* **Reference Compiler, Website & Repository:** `frameassembly` v3.1.0 • [frameassembly.ai.studio](https://frameassembly.ai.studio/)
  • [github.com/SteveWinschel/FrameAssembly](https://github.com/SteveWinschel/FrameAssembly)
  • [crates.io/crates/frameassembly](https://crates.io/crates/frameassembly) • [docs.rs/frameassembly](https://docs.rs/frameassembly)

---

## 1. Abstract & Scope

The **FrameAssembly** file format (`.frasm`, media type `text/vnd.frameassembly`) is a network packet specification code format ("Packets as Code" / "PCAP as Code") for
building `.pcap` and `.pcapng` packet captures offline.

A `.frasm` file defines network endpoints (`host`) and an ordered capture sequence (`compile`), with optional reusable multi-packet sequences (`flow`). Compiling `.frasm`
code to a packet capture is the default root command of the `frameassembly` CLI (`frameassembly <input.frasm> [output.pcap]`, defaulting to `<input_stem>.pcap`). Passing
an output filename ending in `.pcap` writes classic libpcap format for broad tool compatibility; passing `.pcapng` writes PCAP Next Generation (`PCAPNG`) with nanosecond
timestamp resolution (`IfTsResol(9)`). Four subcommands accompany the default command:
* `frameassembly show <input.frasm>` — validates a `.frasm` file and prints a relative-timestamp packet ladder in the terminal without writing disk files.
* `frameassembly reverse <input.pcap> [output.frasm]` — converts `.pcap` or `.pcapng` captures into `.frasm` code (defaulting to `<input_stem>.frasm`), emitting `host1`,
  `host2`, ... blocks, strict-lowercase `[a-z0-9]+` keywords, and chronological packet statements inside `compile { ... }` with post-packet `wait` gaps. Encrypted payloads
  (such as SNMPv3 `authPriv`, TLS application data, SSH, or IPsec `esp`) are not decrypted and stay intact as `tcp` or `udp` statements with `payload` / `hexpayload`.
* `frameassembly help [subcommand]` and `frameassembly version` — display CLI usage and compiler version (with hidden `-h`/`--help` and `-V`/`--version` flags for scripts).

Generated captures across all **81 native Layer 2 through Layer 7 network protocols** open directly in **Wireshark** and **`tshark`**, replay onto lab interfaces via
**`tcpreplay`**, and test rules in intrusion detection systems (**Suricata**, **Zeek**, **Snort**), firewalls, monitoring platforms (**Checkmk**, **Zabbix**), and CI pipelines.

---

## 2. Media Type & File Identification (RFC 6838 & RFC 6657)

This section defines the media type registration parameters for `text/vnd.frameassembly` under [RFC 6838](https://www.rfc-editor.org/rfc/rfc6838) (Media Type Specifications
and Registration Procedures) and [RFC 6657](https://www.rfc-editor.org/rfc/rfc6657) (Charset Parameter Handling in Textual Media Types).

| RFC 6838 §5.6 Field | Normative Specification |
| :--- | :--- |
| **Type name** | `text` |
| **Subtype name** | `vnd.frameassembly` |
| **Required parameters** | None. |
| **Optional parameters** | `charset`: Per RFC 6657 §3, the default charset is `UTF-8`. Implementations MUST support `UTF-8` without a Byte Order Mark (BOM). |
| **Encoding considerations** | `8bit` (UTF-8 source code). Files using only ASCII in comments and string literals are valid `7bit` US-ASCII. |
| **File extension(s)** | `.frasm` |
| **Macintosh file type code(s)** | `TEXT` |
| **Uniform Type Identifier (UTI)** | `io.github.stevewinschel.frameassembly` (`public.source-code`, `public.text`) |
| **Object Identifiers (OIDs)** | None. |
| **Fragment identifiers** | Supports [RFC 5147](https://www.rfc-editor.org/rfc/rfc5147) `text/plain` character and line fragments (e.g., `#line=10,25`). |
| **Published specification** | `https://github.com/SteveWinschel/FrameAssembly/blob/main/docs/12_frasm_specification.md` |

---

## 3. Character Encoding, Line Endings & Binary Safety

1. **Character Encoding (`UTF-8`)**:
   - All `.frasm` files MUST be encoded in valid UTF-8 (RFC 3629).
   - All built-in keywords, protocol names, header modifiers, endpoint names, numeric values, IPv4/IPv6 addresses, MAC addresses, and ASN.1 Object Identifiers (OIDs) use
     7-bit US-ASCII characters (`0x20..0x7E`).
   - Non-ASCII UTF-8 characters MAY appear inside single-line comments (`// ...`) and double-quoted payload strings (`"..."`).
2. **Line Endings & Whitespace**:
   - The preferred line ending for `.frasm` files in version control is LF (`0x0A`, `\n`).
   - Compliant tools MUST accept both LF (`\n`) and CRLF (`\r\n`) line endings, plus tabs (`\t`), form feeds (`\f`), and spaces (`0x20`) between tokens (`[ \t\r\n\f]+`).
   - Long packet statements MAY wrap across multiple lines without continuation backslashes; line breaks are ordinary whitespace.
3. **Prohibition of Literal NUL Bytes (`0x00`)**:
   - A valid `.frasm` file MUST NOT contain literal NUL bytes (`0x00`).
   - Binary wire payloads (including `0x00` bytes) are written in `.frasm` code with hex escapes inside `payload "<string>"` (such as `\x00\x09\x01`) or hex byte strings
     inside `hexpayload "<hex>"` (such as `hexpayload "000102ff"`).

---

## 4. Document Structure & Token Rules (v3.1.0)

### 4.1 Comments, Strict-Lowercase Keywords & Flexible User Identifiers

- **Single-Line Comments**: Comments begin with `//` and run to the end of the line. Neither `#`, `;`, nor `/* ... */` are valid comment markers in `.frasm`.
- **Strict-Lowercase Built-In Keywords (`[a-z0-9]+`)**: Every structural keyword (`host`, `ip`, `mac`, `flow`, `compile`, `wait`), every one of the 81 protocol keywords,
  every Layer 2–Layer 7 modifier (`echorequest`, `innervlan`, `clienthello`, `hosthdr`, `transporthdr`, `sackperm`, `agentip`, `hellotime`, `whois`, `pkttype`, `read`,
  `write`, `nop`, `error`, `shutdownack`, `readholdingregisters`, `nextheader`, etc.), and every time unit (`ns`, `us`, `ms`, `s`, `m`) MUST be lowercase alphanumeric
  (`[a-z0-9]+`) with **zero underscores (`_`)** and **zero hyphens (`-`)**. When an uppercase, underscored, or hyphenated typo appears, `frameassembly` suggests the exact
  replacement (`replace '<raw>' with '<kw>'`).
- **Flexible User-Defined Names**: User-chosen `host`, `flow`, and parameter names match `[a-zA-Z_][a-zA-Z0-9_]*(-[a-zA-Z0-9_]+)*`, allowing uppercase letters, underscores
  (`core_sw`), and internal hyphens (`fw-dmz-01`) while stopping cleanly before `->`. Double-quoted strings (`"..."`) keep exact casing on the wire.

### 4.2 Two-Block Core Structure (`host` + `compile`) & Optional `flow` Blocks

Every compilable `.frasm` file declares endpoints (`host`) and one capture block (`compile`), with optional `flow` blocks for reusable sequences:

1. **Endpoint Declarations (`host`)**:
   ```text
   host <name> {
       [ip <ipv4-or-ipv6-address>]
       [mac <mac-address>]
   }
   ```
   - At least one of `ip` or `mac` MUST be present (for example, `host sw1 { mac 00:1c:73:00:00:01 }` for a MAC-only Layer 2 switch).
   - `ip` *(required for Layer 3–7 protocols; optional for the 8 Layer 2 switching protocols `lldp`, `stp`, `lacp`, `eapol`, `vlan`, `qinq`, `mpls`, `arp`)*: Standard IPv4
     dotted-quad (`10.0.0.1`) or IPv6 address (`2001:db8::1`, `fe80::1`, `ff02::fb`).
   - `mac` *(optional when `ip` is present)*: 48-bit Ethernet MAC address in IEEE colon (`00:1a:2b:3c:4d:5e`), Windows hyphen (`00-1A-2B-3C-4D-5E`), or Cisco dotted-quad
     (`001a.2b3c.4d5e`) notation. When `mac` is omitted on a unicast `host`, FrameAssembly assigns sequential unicast MACs in `host` declaration order
     (`00:00:00:00:00:01` for the first declared host, `00:00:00:00:00:02` for the second, and so on). Multicast destinations use RFC 1112 (`01:00:5e:xx:xx:xx` for IPv4
     `224.0.0.0/4`) and RFC 2464 (`33:33:xx:xx:xx:xx` for IPv6 `ff00::/8`).

2. **Capture Block (`compile`)**:
   ```text
   compile {
       <host1> -> <host2> [modifiers...] <protocol> [protocol_fields...] [wait <duration>]
       <flow_name>(<host1>, <host2>, ...)
   }
   ```
   - Exactly one `compile` block defines the ordered sequence of inline packet statements and flow calls written to the output capture (`loop` blocks were removed in
     FrameAssembly 2.0; repeat inline statements or flow calls directly inside `compile { ... }`).

3. **Reusable Traffic Flows (`flow` — Optional)**:
   ```text
   flow <name>(<param1>, <param2>, ...) {
       <endpoint_a> -> <endpoint_b> [modifiers...] <protocol> [protocol_fields...] [wait <duration>]
       <endpoint_a> <- <endpoint_b> [modifiers...] <protocol> [protocol_fields...] [wait <duration>]
   }
   ```
   - **1 Statement = 1 Frame**: Each statement in `compile` or inside a `flow` emits one Ethernet frame.
   - **Directional Arrows**: `a -> b` sends from `a` to `b`; `a <- b` sends from `b` back to `a`, flipping source and destination ports on reply packets automatically.
   - **Post-Packet `wait`**: Packet 1 starts at `0.000 ms`. Adding `wait <duration>` (`ns`, `us`, `ms`, `s`, `m`) pauses `<duration>` *after* that packet before the next
     packet is sent. Omitting `wait` inserts a `10ms` gap before the next packet.
   - **Shared 4-Tuple TCP State**: TCP-based Layer 7 statements emit a `psh ack` segment on that protocol's standard port and share sequence (`seq`) and acknowledgment
     (`acknum`) counters with raw `tcp` statements on the same 4-tuple connection.
   - **Dual-Stack IPv4 and IPv6 Reuse**: A `flow` works unchanged over IPv4 host pairs and IPv6 host pairs. Mixing IPv4 and IPv6 hosts on one line is a validation error.

### 4.3 Token Classes

The reference tokenizer splits input `.frasm` code into the following token classes:

| Token Class | Pattern / Rule | Examples |
| :--- | :--- | :--- |
| **Structural Keywords** | `host`, `ip`, `mac`, `flow`, `compile`, `wait` (`[a-z0-9]+`, zero `_` or `-`) | `host`, `flow`, `compile`, `wait` |
| **Directional Operators** | `->` (forward frame), `<-` (reply frame) | `client -> server`, `client <- server` |
| **Delimiters** | `{`, `}`, `(`, `)`, `,` | `flow web(c, s) { ... }` |
| **Time Unit Suffixes** | `ns`, `us`, `ms`, `s`, `m` (strict lowercase after `wait <int>`) | `wait 500ns`, `wait 10ms`, `wait 2s` |
| **MAC Address** | `([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}` \| hyphen \| `[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}` | `00:1a:2b:3c:4d:5e`, `001a.2b3c.4d5e` |
| **IPv4 / IPv6 Address** | Dotted-quad IPv4 or colon-hex IPv6 address | `192.168.1.10`, `2001:db8::1`, `ff02::fb` |
| **Numeric Value** | `-?[0-9]+\|0[xX][0-9a-fA-F]+` | `443`, `0x88cc`, `65535` |
| **ASN.1 OID** | `\.?[0-9]+(\.[0-9]+)*` (3 or more arcs for OID fields) | `1.3.6.1.2.1.1.5.0`, `1.3.6.1.6.3.1.1.5.3` |
| **Quoted String** | `"([^"\\]\|\\.)*"` (supports `\"`, `\\`, `\n`, `\r`, `\t`, `\xHH`) | `"example.com"`, `"AMQP\x00\x00\x09\x01"` |
| **User Name** | `[a-zA-Z_][a-zA-Z0-9_]*(-[a-zA-Z0-9_]+)*` | `core_switch`, `fw-dmz-01`, `host1` |

### 4.4 Complete 81 Native Protocol Keywords

Every strict-lowercase protocol keyword below compiles with zero mandatory sub-keywords (emitting RFC default headers and ports) and accepts protocol-specific overrides:

| OSI Layer | Count | Strict-Lowercase `.frasm` Protocol Keywords |
| :--- | :---: | :--- |
| **Layer 2 (Switching & Data-Link)** | 8 | `arp`, `vlan`, `qinq`, `lldp`, `stp`, `lacp`, `eapol`, `mpls` |
| **Layer 3 (Control & Tunnel)** | 12 | `icmp`, `ndp`, `igmp`, `mld`, `gre`, `vxlan`, `geneve`, `ipsec`, `esp`, `ah`, `ikev2`, `wireguard` |
| **Layer 3 (Routing, FHRP, SDN)** | 8 | `ospf`, `bgp`, `rip`, `vrrp`, `hsrp`, `pim`, `bfd`, `openflow` |
| **Layer 4 (Transport)** | 3 | `tcp`, `udp`, `sctp` |
| **Layer 7 (SNMP, Infra, Time, AAA, Telemetry)** | 14 | `snmp1`, `snmp2`, `snmp3`, `dns`, `mdns`, `dhcp`, `ntp`, `ptp`, `radius`, `tacacs`, `syslog`, `netflow`, `ipfix`, `sflow` |
| **Layer 7 (Web, Security, VoIP, Access)** | 16 | `http`, `http2`, `grpc`, `websocket`, `tls`, `quic`, `tftp`, `ftp`, `ssh`, `telnet`, `whois`, `sip`, `rtp`, `rtsp`, `stun`, `ssdp` |
| **Layer 7 (Mail, Auth, Storage, DB, Brokers)** | 14 | `smtp`, `imap`, `pop3`, `kerberos`, `ldap`, `smb`, `nfs`, `redis`, `memcached`, `mysql`, `postgres`, `mqtt`, `coap`, `amqp` |
| **Layer 7 (Industrial ICS / SCADA / OT)** | 6 | `modbus`, `bacnet`, `dnp3`, `s7comm`, `ethernetip`, `opcua` |

---

## 5. Content Sniffing & `.frasm` Extension Disambiguation

### 5.1 Authoritative Three-Way Format Disambiguation

FrameAssembly 3.x uses the dedicated `.frasm` extension so its network packet files never collide with older `.fasm` tools. The `.fasm` suffix is shared informally by two
unrelated hardware/assembly formats—x86 Flat Assembler and FPGA FASM—neither of which has a registered media type with IANA or Freedesktop.org. FrameAssembly 2.x used
`.fasm`; `frameassembly` 3.1 rejects `.fasm` inputs with a hint to rename the file to `.frasm`.

The table below compares the three formats across eleven technical dimensions:

| Dimension | **FrameAssembly (`.frasm`)** | **Flat Assembler x86 (`.asm`, `.fasm`)** | **FPGA Bitstream Assembly (`FASM`, `.fasm`)** |
| :--- | :--- | :--- | :--- |
| **Primary Domain** | Network packet code ("Packets as Code" / "PCAP as Code") | Low-level x86 / x86-64 machine assembly | FPGA tile configuration (SymbiFlow / F4PGA) |
| **Media Type** | `text/vnd.frameassembly` (RFC 6838 Vendor Tree candidate) | Unregistered (`text/x-asm`) | Unregistered (`text/plain`) |
| **Comment Delimiters** | `// single-line comment` | `; single-line comment` (assembly style) | `# single-line comment` (shell/Python style) |
| **Top-Level Block Syntax** | `host { ... }`, optional `flow(...) { ... }`, `compile { ... }` | `format PE/ELF`, `section '.text'`, `org`, `use64` | Hardware tile paths: `CLBLL_L_X10Y100...` |
| **Statement Syntax** | Arrows `->` / `<-` + L2–L7 protocols (`tcp`, `http`, `snmp3`) | x86 mnemonics: `mov`, `eax`, `xor`, `call`, `db` | Bit-slices (`ALUT.INIT[63:0] = ...`) |
| **Target Output** | Standard `.pcap` or `.pcapng` packet capture file | Machine code binary (`.bin`, `.obj`, `.o`, `.exe`, `.elf`) | FPGA configuration bitstream (`.bit`, `.frames`) |
| **Reference Tool** | `frameassembly` CLI (offline, no `libpcap` or raw sockets required) | Flat Assembler (`fasm`) assembler & linker | `fasm2frames` / `xc7frames2bit` (SymbiFlow / F4PGA tooling) |
| **Downstream Consumers** | **Wireshark**, **`tshark`**, **`tcpreplay`**, **Suricata**, **Zeek** | OS loader, CPU execution, linkers (`ld`, `link.exe`) | Xilinx 7-Series / Lattice iCE40 tools |
| **Registry Authority** | IANA Vendor Tree (`text/vnd.frameassembly`), Freedesktop XML | Unregistered (`.asm` primary, `.fasm` secondary) | Unregistered (`.fasm` tile config) |
| **Text Encoding** | UTF-8 without BOM (RFC 6657), LF / CRLF, literal NUL (`0x00`) prohibited | ASCII or regional 8-bit code pages, CR+LF or LF | US-ASCII, LF or CRLF |
| **Highlighting Scopes** | `source.frameassembly` (TextMate), `FrameAssembly` (Linguist) | `source.assembly` or `source.x86` | Generic text or hardware configuration |

### 5.2 Syntactic Distinguishing Marks

Because each format serves a distinct domain, their comment markers and block structures never overlap:

1. **Comment Syntax**:
   - FrameAssembly accepts single-line comments starting with `//`. Semicolons (`;`) and hash marks (`#`) outside quoted strings are rejected.
   - Flat Assembler uses semicolons (`;`) for comments.
   - FPGA FASM uses hash characters (`#`) for comments.
2. **Top-Level Blocks**:
   - Every compilable FrameAssembly file contains strict-lowercase `host` and `compile` blocks (plus optional `flow` blocks).
   - Flat Assembler files never declare `host`, `flow`, or `compile` blocks; they declare `format`, `section`, `segment`, `org`, or assembly labels.
   - FPGA FASM files never declare blocks or braces; they list newline-separated feature paths with dot-separated tile coordinates.
3. **Packet Statements vs CPU Instructions vs Tile Paths**:
   - FrameAssembly statements pair endpoint names with `->` or `<-` and network protocol keywords (`tcp`, `udp`, `vlan`, `http`, `snmp3`).
   - Flat Assembler statements use x86 opcodes and registers (`mov eax, 1`).
   - FPGA FASM statements use tile coordinates and bit-slices (`HCLK_L_X0Y130.ENABLE_BUFFER`).

### 5.3 Content-Sniffing & Linguist Heuristics

GitHub Linguist, `bat`, `Chroma`, and Pygments identify FrameAssembly `.frasm` files with the regular expression rules in
[`contrib/linguist/heuristics.yml`](../contrib/linguist/heuristics.yml):

- **Positive FrameAssembly Anchors**:
  - `^\s*host\s+[A-Za-z_][A-Za-z0-9_-]*\s*\{\s*(?:ip|mac)\b`
  - `^\s*flow\s+[A-Za-z_][A-Za-z0-9_-]*\s*\([A-Za-z0-9_,\s-]*\)\s*\{`
  - `^\s*compile\s*\{\s*(?:[A-Za-z_][A-Za-z0-9_-]*\s*\(|[A-Za-z_][A-Za-z0-9_-]*\s*(?:->|<-))`
  - Packet statement: `\b[A-Za-z_][A-Za-z0-9_-]*\s*(?:->|<-)\s*[A-Za-z_][A-Za-z0-9_-]*\s+(?:...strict-lowercase protocol & modifier tokens...)\b`
- **Negative / Competing Format Anchors**:
  - Flat Assembler: `(?i)^\s*format\s+(?:PE|PE64|ELF|ELF64|MZ|COFF|binary)\b`, `(?i)^\s*(?:section|segment|use16|use32|use64|org)\b`, or lines starting with `^\s*;`.
  - FPGA FASM: Lines beginning with `#` or matching tile patterns `^[A-Z0-9_]+(?:\.[A-Z0-9_]+){2,}`.

### 5.4 Freedesktop `shared-mime-info` Magic Signatures & Desktop Integration

The Freedesktop MIME package in [`contrib/mime/text-vnd.frameassembly.xml`](../contrib/mime/text-vnd.frameassembly.xml) (see [`contrib/mime/README.md`](../contrib/mime/README.md))
registers `text/vnd.frameassembly` as a subclass of `text/plain` with glob `*.frasm` (`weight="60"`) and `<magic priority="60">` rules matching:
- `host ` or `host\t` within bytes `0..1024` AND (`ip ` or `mac `) within bytes `0..1536` AND `compile` within bytes `0..8192`, or
- `flow ` or `flow\t` within bytes `0..2048` AND `compile` within bytes `0..8192`.

Priority `60` gives FrameAssembly `.frasm` files precedence over generic text handlers on Linux and BSD desktops without matching Flat Assembler or FPGA FASM files.

### 5.5 Unix `file(1)` / `libmagic` Content Sniffing

Unix systems and CLI tools using `libmagic` identify FrameAssembly `.frasm` files via [`contrib/magic/frameassembly.magic`](../contrib/magic/frameassembly.magic):

```magic
0	search/2048	host\ 
>0	search/1536	ip\ 
>>0	search/8192	compile	FrameAssembly network packet specification
!:mime	text/vnd.frameassembly
!:ext	frasm

0	search/2048	host\ 
>0	search/1536	mac\ 
>>0	search/8192	compile	FrameAssembly network packet specification
!:mime	text/vnd.frameassembly
!:ext	frasm

0	search/2048	flow\ 
>0	search/8192	compile	FrameAssembly network packet specification
!:mime	text/vnd.frameassembly
!:ext	frasm
```

Running `file -i <file.frasm>` returns `text/vnd.frameassembly; charset=us-ascii` or `utf-8`.

### 5.6 FAQ: What Is a `.frasm` File? (FrameAssembly vs. Flat Assembler vs. FPGA FASM)

#### Q1: What is a `.frasm` file in FrameAssembly?
A `.frasm` file is a network traffic specification written in FrameAssembly `.frasm` code ("Packets as Code"). It declares network endpoints (`host`), optional reusable packet
flows (`flow`), and a capture sequence (`compile`). Running `frameassembly <input.frasm> [output.pcap]` builds `.pcap` or `.pcapng` captures offline for Wireshark, `tshark`,
`tcpreplay`, Suricata, and Zeek; `frameassembly show <input.frasm>` prints the packet ladder in the terminal; and `frameassembly reverse <input.pcap> [output.frasm]` converts
captures back into `.frasm` code.

#### Q2: How does a FrameAssembly `.frasm` file differ from an x86 Flat Assembler file?
Flat Assembler (abbreviated FASM) translates x86/x86-64 CPU assembly instructions into binary executables (`.exe`, `.elf`, `.bin`). Flat Assembler files use semicolon (`;`)
comments, directives (`format PE`, `section '.text'`), and CPU instructions (`mov`, `jmp`, `xor`). FrameAssembly `.frasm` files use slash (`//`) comments, strict-lowercase
blocks (`host`, `flow`, `compile`), and networking statements (`client -> server tcp syn`).

#### Q3: How does a FrameAssembly `.frasm` file differ from an FPGA FASM file?
In open-source FPGA toolchains (SymbiFlow / F4PGA), FASM stands for FPGA Assembly. It configures FPGA hardware bitstreams using hash (`#`) comments and dot-separated hardware
tile paths (such as `CLBLL_L_X10Y100.SLICEL_X0.ALUT.INIT[63:0]`). It contains no network endpoints, IP addresses, or protocol headers.

#### Q4: How do tools, operating systems, and code editors recognize `.frasm` files?
Multi-layer file identification prevents collisions:
1. **GitHub**: `.gitattributes` (`linguist-language=FrameAssembly`) and Linguist `heuristics.yml` match `host`, `flow`, `compile`, and `->` / `<-`.
2. **Linux & BSD Desktops**: Freedesktop `shared-mime-info` (`contrib/mime/text-vnd.frameassembly.xml`) and `libmagic` (`contrib/magic/frameassembly.magic`) match
   `host ... ip|mac ... compile` or `flow ... compile` tokens and report `text/vnd.frameassembly`.
3. **VS Code Extension & Browser Playground**: The VS Code Marketplace extension (`SteveWinschel.frameassembly-vscode`) and browser playground
   ([`frameassembly.ai.studio`](https://frameassembly.ai.studio/)) register the `source.frameassembly` TextMate scope and `text/vnd.frameassembly` media type.

#### Q5: Can I compile an x86 Flat Assembler or FPGA FASM file with `frameassembly`?
No. FrameAssembly builds network packet captures. Passing an x86 Flat Assembler or FPGA FASM file to `frameassembly` triggers a plain-English diagnostic explaining that
FrameAssembly `.frasm` files use `host` and `compile` blocks rather than `;`/`#` assembly directives or FPGA tile paths.

### 5.7 Registry Status Across Standards Bodies & Supported Channels

The `.frasm` extension and `text/vnd.frameassembly` media type ship registration templates and packaging manifests across standards bodies and supported channels:

1. **IANA Media Type Registry**: RFC 6838 Vendor Tree registration template in [`contrib/iana/text-vnd.frameassembly.md`](../contrib/iana/text-vnd.frameassembly.md).
2. **Freedesktop `shared-mime-info`**: XML definition in [`contrib/mime/text-vnd.frameassembly.xml`](../contrib/mime/text-vnd.frameassembly.xml) and installation guide in
   [`contrib/mime/README.md`](../contrib/mime/README.md).
3. **Unix `file(1)` / `libmagic`**: Magic rule file in [`contrib/magic/frameassembly.magic`](../contrib/magic/frameassembly.magic).
4. **GitHub Linguist**: Language entry in [`contrib/linguist/languages.yml`](../contrib/linguist/languages.yml), regex rules in
   [`contrib/linguist/heuristics.yml`](../contrib/linguist/heuristics.yml), TextMate grammar in
   [`frameassembly-vscode/syntaxes/frameassembly.tmLanguage.json`](../frameassembly-vscode/syntaxes/frameassembly.tmLanguage.json), and guide in
   [`contrib/linguist/README.md`](../contrib/linguist/README.md).
5. **Wikidata Knowledge Graph**: QuickStatements mapping for properties `P31`, `P1195`, `P1163`, `P973`, `P856`, `P1324`, `P275`, `P306`, and `P277`.
6. **Supported Software Channels**: Crates.io (`cargo install frameassembly`), GitHub Releases + Debian/Ubuntu `.deb`, NPM (`frameassembly-wasm`), VS Code Marketplace
   (`frameassembly-vscode`), and `SteveWinschel/homebrew-tap-FrameAssembly` (`Homebrew` & `Scoop`), documented in [`contrib/packaging/README.md`](../contrib/packaging/README.md).

---

## 6. Security Considerations (RFC 6838 §4.6 & RFC 3552)

1. **Passive, Non-Executable Format**:
   - A `.frasm` file specifies network endpoints and packet header fields. It contains no executable code, macros, shell commands, or system calls.
2. **Bounded, Loop-Free and Side-Effect-Free Compilation**:
   - The `.frasm` format is loop-free and side-effect-free: there are no loops (`loop` was removed in FrameAssembly 2.0), no recursion, and no conditional branches.
   - There are no file-inclusion directives (`include` or `import`), and the compiler performs zero network I/O or DNS lookups during compilation, preventing Server-Side
     Request Forgery (SSRF) and local file inclusion risks when processing untrusted `.frasm` inputs.
   - Compilation runs offline without `CAP_NET_RAW`, raw sockets, or `libpcap`.
3. **Downstream Packet Capture Considerations**:
   - Running `frameassembly <input.frasm> [output.pcap]` writes a passive `.pcap` or `.pcapng` packet capture file.
   - Because FrameAssembly tests firewalls, IDS/IPS sensors (**Suricata**, **Zeek**, **Snort**), and protocol dissectors (**Wireshark** / `tshark`), generated captures may
     contain custom header combinations, IP fragmentation (`mf` + `fragoffset`), custom TCP sequence numbers, or intrusion-detection test payloads.
   - Sending a capture onto a live network interface requires an external replay tool (such as `tcpreplay`) run explicitly by an authorized administrator.

---

## 7. Knowledge Graph & Registry Mapping (Wikidata, IANA, GitHub)

For knowledge graphs, digital preservation registries (Wikidata, PRONOM, Software Heritage), and package indexes, `.frasm` maps to the following identifiers:

| Property / Registry | Identifier / Property Code | Value |
| :--- | :--- | :--- |
| **IANA Media Type** | RFC 6838 Vendor Tree | `text/vnd.frameassembly` ([`contrib/iana/text-vnd.frameassembly.md`](../contrib/iana/text-vnd.frameassembly.md)) |
| **Freedesktop MIME** | Shared MIME-Info XML | `text/vnd.frameassembly` ([`contrib/mime/text-vnd.frameassembly.xml`](../contrib/mime/text-vnd.frameassembly.xml)) |
| **Unix `file(1)` / `libmagic`** | Magdir Rule | `text/vnd.frameassembly` ([`contrib/magic/frameassembly.magic`](../contrib/magic/frameassembly.magic)) |
| **UK National Archives PRONOM** | Technical Registry | `FrameAssembly Network Packet Specification` (`text/vnd.frameassembly`) |
| **Wikidata: instance of** | `P31` | `Q235557` (file format), `Q1262091` (packet specification format), `Q9143` (computer language) |
| **Wikidata: file extension** | `P1195` | `frasm` |
| **Wikidata: media type** | `P1163` | `text/vnd.frameassembly` |
| **Wikidata: described at URL** | `P973` | `https://github.com/SteveWinschel/FrameAssembly/blob/main/docs/12_frasm_specification.md` |
| **Wikidata: official website** | `P856` | `https://frameassembly.ai.studio/` |
| **Wikidata: source repository** | `P1324` | `https://github.com/SteveWinschel/FrameAssembly` |
| **Wikidata: copyright license** | `P275` | `Q334661` (MIT License) |
| **Wikidata: operating system** | `P306` | `Q388` (Linux), `Q14116` (macOS), `Q1406` (Microsoft Windows) |
| **Wikidata: programmed in** | `P277` | `Q575650` (Rust) |
| **Public Extension Databases** | FileInfo / File-Extensions / FILExt | `.frasm` (`text/vnd.frameassembly`) |
| **GitHub `.gitattributes`** | `linguist-language` | `*.frasm linguist-language=FrameAssembly linguist-detectable=false` ([`.gitattributes`](../.gitattributes)) |

---

## 8. Validated `.frasm` v3.1.0 Specification Examples

Every example below is a complete `text/vnd.frameassembly` file verified with `frameassembly <input.frasm> [output.pcap]`.

### Example 1: Minimal Two-Block Capture (`host` + `compile`)

```frameassembly
// Unicast hosts without explicit mac get 00:00:00:00:00:01 and 00:00:00:00:00:02
host laptop { ip 192.168.1.10 }
host router { ip 192.168.1.1 }

compile {
    laptop -> router icmp echorequest id 1 seq 1 wait 2ms
    laptop <- router icmp echoreply   id 1 seq 1
}
```

### Example 2: TCP Handshake, HTTP/1.1 Health Check & Encrypted SNMPv3 USM Trap

```frameassembly
// User endpoint names allow underscores and internal hyphens
host web_client    { ip 10.10.1.10  mac 00:1a:2b:3c:4d:10 }
host app-srv-01    { ip 10.10.1.80  mac 00:1a:2b:3c:4d:80 }
host nms_collector { ip 10.10.1.250 mac 00:1a:2b:3c:4d:fa }

flow service_check_and_alert(client, srv, nms) {
    client -> srv tcp syn srcport 51400 dstport 80 win 65535 mss 1460 wait 1ms
    client <- srv tcp syn ack win 65535 mss 1460 wait 1ms
    client -> srv tcp ack wait 1ms
    client -> srv http get uri "/healthz" hosthdr "app.internal" wait 4ms
    client <- srv http status 200 reason "OK" body "{\"status\":\"healthy\"}" wait 2ms
    srv -> nms vlan 100 snmp3 trap user "secops" engineid "80001f888001020304"
        engineboots 3 enginetime 1200
        auth sha256 "AuthSecret2026!" priv aes "PrivSecret2026!"
        oid 1.3.6.1.6.3.1.1.5.4
        varbind 1.3.6.1.2.1.1.5.0 string "app-srv-01"
}

compile {
    service_check_and_alert(web_client, app-srv-01, nms_collector)
}
```

### Example 3: Dual-Stack IPv4/IPv6 Flow Reuse with Carrier 802.1ad QinQ & MPLS Tagging

```frameassembly
host edge_v4 { ip 172.16.10.1   mac 00-50-56-C0-00-01 }
host core_v4 { ip 172.16.10.2   mac 00-50-56-C0-00-02 }
host edge_v6 { ip 2001:db8:10::1 mac 0050.56c0.0011 }
host core_v6 { ip 2001:db8:10::2 mac 0050.56c0.0012 }

flow carrier_tls_probe(pe_a, pe_b) {
    pe_a -> pe_b qinq 2000 innervlan 100 pcp 5 mpls 32000 exp 5 bos 1 mplsttl 64
        dscp 46 ttl 64 tls clienthello sni "api.carrier.example" ciphersuite 4865 alpn "h2" wait 2ms
    pe_a <- pe_b qinq 2000 innervlan 100 pcp 5 mpls 32000 exp 5 bos 1 mplsttl 63
        dscp 46 ttl 63 tls serverhello ciphersuite 4865 alpn "h2" wait 2ms
}

compile {
    carrier_tls_probe(edge_v4, core_v4)
    carrier_tls_probe(edge_v6, core_v6)
}
```

### Example 4: Pure Layer 2 MAC-Only Switches & Inline `compile` Statements

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

* **[Getting Started Guide (`01_getting_started.md`)](01_getting_started.md)** — Beginner tutorial, `frameassembly show` preview, `frameassembly reverse` capture conversion,
  and pairing FrameAssembly with `Wireshark`, `tshark`, and `tcpreplay`.
* **[Practical Use Cases & Cookbook (`02_use_cases.md`)](02_use_cases.md)** — Copy-paste `.frasm` recipes for Checkmk/Zabbix SNMPv3 traps, firewall ACLs, VLAN/QinQ/MPLS QoS,
  IDS/IPS rules, and OT/SCADA testing.
* **[For Nerds: Six-Stage Compiler Architecture, Rust API & Formal Grammars (`13_for_nerds.md`)](13_for_nerds.md)** — Deep dive into the zero-copy Rust compiler, public crate
  API, and `EBNF`/`GBNF`/`Lark` grammars.
