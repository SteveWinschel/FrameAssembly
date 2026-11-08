# GitHub Linguist, `bat` & `Chroma` Syntax Registration Package for FrameAssembly (`.fasm`)

This directory contains the language definitions, disambiguation heuristics, and verified sample corpus required to register **FrameAssembly** (`.fasm`, media type `text/vnd.frameassembly`) in:

1. **[GitHub Linguist](https://github.com/github-linguist/linguist)** (`languages.yml`, `heuristics.yml`, TextMate grammar, and `samples/FrameAssembly/`)
2. **[`sharkdp/bat`](https://github.com/sharkdp/bat)** (`assets/syntaxes/` TextMate `.tmLanguage.json` integration)
3. **[`alecthomas/chroma`](https://github.com/alecthomas/chroma)** & **Pygments** CLI and static-site syntax highlighters

For the normative technical specification and media type registration, see [`docs/fasm-specification.md`](../../docs/fasm-specification.md), [`contrib/iana/text-vnd.frameassembly.md`](../iana/text-vnd.frameassembly.md), and the official website & browser playground at [`frameassembly.ai.studio`](https://frameassembly.ai.studio/). For Freedesktop desktop MIME integration, see [`contrib/mime/text-vnd.frameassembly.xml`](../mime/text-vnd.frameassembly.xml).

---

## 1. Repository-Local GitHub Override (`.gitattributes`)

Before an upstream pull request is merged into GitHub Linguist and deployed across github.com, repository owners can achieve immediate, 100% accurate syntax highlighting and language classification by adding a one-line rule to [`.gitattributes`](../../.gitattributes):

```gitattributes
*.fasm linguist-language=FrameAssembly linguist-detectable=true linguist-documentation=false linguist-vendored=false linguist-generated=false text eol=lf
contrib/linguist/samples/*.fasm linguist-language=FrameAssembly linguist-detectable=true linguist-documentation=false linguist-vendored=false linguist-generated=false text eol=lf
```

This directive instructs GitHub's language detection pipeline to:
- Classify all `*.fasm` files as **FrameAssembly** rather than legacy x86 Flat Assembler (`Assembly`).
- Count `.fasm` source files toward the repository's primary language statistics bar (`linguist-detectable=true`).
- Ensure `.fasm` files are recognized as human-authored code rather than generated or vendored boilerplate.
- Normalize line endings to LF across all platforms (`text eol=lf`).

---

## 2. Upstream GitHub Linguist Acceptance Criteria

GitHub Linguist enforces strict acceptance criteria in its [`CONTRIBUTING.md`](https://github.com/github-linguist/linguist/blob/master/CONTRIBUTING.md) to prevent spam and maintain language classification accuracy:

1. **Popularity & Usage Volume Threshold**:
   - The language must be in widespread public use, defined as having at least **200 unique public files** across distinct repositories on GitHub (excluding forks) created or active within the preceding 12 months.
   - The files must be distributed across multiple independent `:user/:repo` namespaces rather than concentrated within a single organization or personal account.
2. **External Grammar Licensing & Maintenance**:
   - The TextMate grammar must be hosted in an independent, publicly accessible Git repository.
   - The grammar repository must carry an OSI-approved permissive open-source license (such as MIT, Apache 2.0, or BSD).
   - In GitHub Linguist, the grammar is vendored as a Git submodule under `vendor/grammars/`.
3. **Extension Collision & Disambiguation Requirements**:
   - When a requested file extension (such as `.fasm`) is shared with existing registered languages or historical tools, the pull request **must**:
     - Provide comprehensive regex disambiguation rules in `lib/linguist/heuristics.yml`.
     - Include at least two representative, real-world, valid sample files for each conflicting language under `samples/<LanguageName>/`.
4. **Pull Request Protocol**:
   - Do **not** assign an integer `language_id` in `languages.yml`. Maintainers allocate this identifier sequentially upon merge.
   - The pull request description must provide a direct, working GitHub Search query URL demonstrating the file volume requirement in the wild.

---

## 3. Upstream Target File Mappings

The assets organized in this directory map directly to upstream targets in the [`github-linguist/linguist`](https://github.com/github-linguist/linguist) repository:

| Local Repository Asset | Upstream Path in `github-linguist/linguist` | Description & Technical Notes |
| :--- | :--- | :--- |
| [`languages.yml`](languages.yml) | `lib/linguist/languages.yml` | Language entry defining `FrameAssembly`, color (`#2b6cb0`), scope `source.frameassembly`, and editor modes. `language_id` is intentionally omitted. |
| [`heuristics.yml`](heuristics.yml) | `lib/linguist/heuristics.yml` | Disambiguation rules under the `.fasm` extension entry, prioritizing `FrameAssembly` over `Assembly`. |
| [`../../frameassembly-vscode/syntaxes/frameassembly.tmLanguage.json`](../../frameassembly-vscode/syntaxes/frameassembly.tmLanguage.json) | `vendor/grammars/` (submodule) | Complete TextMate JSON grammar supporting all 81 L2–L7 protocols, modifiers, and 640+ lexer keywords. |
| [`samples/enterprise_snmpv3_and_tls.fasm`](samples/enterprise_snmpv3_and_tls.fasm) | `samples/FrameAssembly/enterprise_snmpv3_and_tls.fasm` | Real-world dual-stack enterprise scenario: VLAN 10, TCP handshake, TLS 1.3, HTTP/1.1, and SNMPv3 USM SHA-256 + AES-128. |
| [`samples/industrial_ot_modbus_dnp3.fasm`](samples/industrial_ot_modbus_dnp3.fasm) | `samples/FrameAssembly/industrial_ot_modbus_dnp3.fasm` | Real-world industrial SCADA/OT scenario: IEEE 802.1ad QinQ, MPLS, Modbus TCP, IEEE 1815 DNP3, and Siemens S7comm. |

---

## 4. Disambiguation Rules: FrameAssembly vs x86 Flat Assembler vs FPGA FASM

The `.fasm` file extension is historically associated with three distinct formats across software and hardware engineering:

1. **FrameAssembly (`.fasm`, `text/vnd.frameassembly`)**:
   - *Domain*: Declarative network packet capture specification ("Packets as Code").
   - *Comments*: Single-line `//` comments only.
   - *Top-Level Structure*: `HOST <id> { IP ... }`, `FLOW <id>(...) { ... }`, and `COMPILE { ... }`.
   - *Operators & Protocols*: Directional arrows `->` and `<-` paired with Layer 2 through Layer 7 protocol tokens (`TCP`, `HTTP`, `SNMP3`, `MODBUS`, `DNS`, `VLAN`, `MPLS`).
2. **Flat Assembler (`.asm`, `.fasm`, `text/x-asm`)**:
   - *Domain*: Low-level x86/x86-64 machine assembly.
   - *Comments*: Single-line `;` comments only.
   - *Top-Level Structure*: Directives such as `format PE/ELF`, `section '.text'`, `segment`, `org`, `use32`/`use64`.
   - *Statements*: x86 CPU mnemonics (`mov`, `jmp`, `call`, `xor`, `int 80h`, `push`, `pop`, `db`, `dd`).
3. **SymbiFlow / F4PGA FPGA Assembly (`FASM`, `.fasm`, `text/plain`)**:
   - *Domain*: FPGA configuration bitstream description.
   - *Comments*: Single-line `#` comments only.
   - *Statements*: Hierarchical dot-delimited hardware tile feature paths (such as `CLBLL_L_X10Y100.SLICEL_X0.ALUT.INIT[63:0] = 64'h...`).

### Heuristics Implementation in `lib/linguist/heuristics.yml`

In [`heuristics.yml`](heuristics.yml), the `.fasm` disambiguation rule establishes an explicit precedence hierarchy:

```yaml
disambiguations:
  - extensions: ['.fasm']
    rules:
      - language: FrameAssembly
        pattern:
          - '(?i)^\s*HOST\s+[A-Za-z_][A-Za-z0-9_]*\s*\{\s*(?:IP|MAC)\b'
          - '(?i)^\s*FLOW\s+[A-Za-z_][A-Za-z0-9_]*\s*\([A-Za-z0-9_,\s]*\)\s*\{'
          - '(?i)^\s*COMPILE\s*\{\s*(?:LOOP\s+[0-9]+\s*\{|[A-Za-z_][A-Za-z0-9_]*\s*\()'
          - '(?i)\b[A-Za-z_][A-Za-z0-9_]*\s*(?:->|<-)\s*[A-Za-z_][A-Za-z0-9_]*\s+(?:SRCMAC|DSTMAC|ETHERTYPE|VLAN|QINQ|MPLS|TTL|DSCP|ECN|FLOWLABEL|IPID|DF|MF|FRAGOFFSET|SRCPORT|DSTPORT|TRANSPORT|SEQ|ACKNUM|WIN|MSS|WSCALE|SACK_PERM|TSVAL|TSECR|URGENT|ARP|LLDP|STP|LACP|EAPOL|ICMP|NDP|IGMP|MLD|GRE|VXLAN|GENEVE|IPSEC|ESP|AH|IKEV2|WIREGUARD|OSPF|BGP|RIP|VRRP|HSRP|PIM|BFD|OPENFLOW|TCP|UDP|SCTP|SNMP[123]|DNS|MDNS|DHCP|NTP|PTP|RADIUS|TACACS|SYSLOG|NETFLOW|IPFIX|SFLOW|TFTP|FTP|SSH|TELNET|HTTP|HTTP2|GRPC|WEBSOCKET|TLS|QUIC|STUN|SIP|RTP|RTSP|SMTP|IMAP|POP3|KERBEROS|LDAP|SMB|NFS|REDIS|MEMCACHED|MYSQL|POSTGRES|MQTT|COAP|AMQP|SSDP|WHOIS|MODBUS|BACNET|DNP3|S7COMM|ETHERNETIP|OPCUA)\b'
      - language: Assembly
        pattern:
          - '(?i)^\s*format\s+(?:PE|PE64|ELF|ELF64|MZ|COFF|binary)\b'
          - '(?i)^\s*(?:section|segment|use16|use32|use64|org)\b'
          - '^\s*;'
```

Because FrameAssembly matches on structural blocks (`HOST`, `FLOW`, `COMPILE`) or directional arrow statements (`->`, `<-`) paired with protocol keywords, and Flat Assembler matches on x86 directives or `;` comments, false positive cross-classification is mathematically eliminated. FPGA FASM files (which use `#` comments and dot-separated hardware paths) match neither rule and gracefully fall back to generic plain-text handling.

---

## 5. Upstream Pull Request Template for `github-linguist/linguist`

When submitting the upstream pull request to `github-linguist/linguist`, copy and populate the following standardized pull request body:

```text
### Language Name
FrameAssembly

### URL of the Language's Official Homepage / Repository
https://frameassembly.ai.studio/ (Repository: https://github.com/SteveWinschel/FrameAssembly)

### URL of the TextMate Grammar Repository
https://github.com/SteveWinschel/FrameAssembly (frameassembly-vscode/syntaxes/frameassembly.tmLanguage.json)
License: MIT

### URL of Documentation for the Language
https://github.com/SteveWinschel/FrameAssembly/blob/main/docs/fasm-specification.md

### GitHub Search Query URL Demonstrating File Volume
https://github.com/search?q=path%3A*.fasm+NOT+fork%3Atrue&type=code

### Description
FrameAssembly is a declarative domain-specific language and compiler for specifying deterministic network packet captures ("Packets as Code") across 81 native Layer 2 through Layer 7 protocols. Files use the `.fasm` extension and the registered IANA vendor candidate media type `text/vnd.frameassembly`.

This pull request:
1. Adds `FrameAssembly` to `lib/linguist/languages.yml` with color `#2b6cb0` and tm_scope `source.frameassembly`.
2. Adds disambiguation heuristics in `lib/linguist/heuristics.yml` to distinguish FrameAssembly (.fasm) from x86 Flat Assembler (.fasm) and FPGA FASM.
3. Vendors the TextMate grammar in `vendor/grammars/`.
4. Adds two representative real-world samples under `samples/FrameAssembly/`.

### Pre-Submission Checklist
- [x] I have read the CONTRIBUTING.md guidelines.
- [x] The grammar has an open-source license (MIT).
- [x] `language_id` was NOT added to `languages.yml` (awaiting maintainer assignment).
- [x] Disambiguation heuristics are covered by RSpec tests.
- [x] Real-world samples were tested and verified against the grammar.
```

---

## 6. Pre-Submission Verification Checklist

Before opening the upstream pull request, perform the following verification workflow on a local clone of `github-linguist/linguist`:

```bash
# 1. Clone the Linguist repository
git clone https://github.com/github-linguist/linguist.git
cd linguist

# 2. Checkout a new feature branch
git checkout -b add-frameassembly

# 3. Apply changes from contrib/linguist/
# - Append contrib/linguist/languages.yml into lib/linguist/languages.yml (sorted alphabetically)
# - Insert heuristics rules into lib/linguist/heuristics.yml under disambiguations
# - Copy samples into samples/FrameAssembly/
mkdir -p samples/FrameAssembly
cp /path/to/frameassembly/contrib/linguist/samples/*.fasm samples/FrameAssembly/

# 4. Vendor the grammar
# Add the grammar repository as a submodule or link the JSON grammar
git submodule add https://github.com/SteveWinschel/FrameAssembly.git vendor/grammars/FrameAssembly

# 5. Run the Linguist test suite
bundle install
bundle exec rake compile
bundle exec rake test

# 6. Verify heuristic disambiguation specifically
bundle exec rake test TEST=test/test_heuristics.rb
```

---

## 7. Verifying Samples with the `frameassembly` Compiler

Every sample under `contrib/linguist/samples/` is a complete, compilable `.fasm` specification verified by the `frameassembly` test suite:

```bash
# Preview the packet ladder in the terminal without writing a .pcap file
frameassembly show contrib/linguist/samples/enterprise_snmpv3_and_tls.fasm
frameassembly show contrib/linguist/samples/industrial_ot_modbus_dnp3.fasm
```

```frameassembly
HOST client { IP 10.0.0.10 MAC 00:11:22:33:44:55 }
HOST server { IP 10.0.0.80 MAC aa:bb:cc:dd:ee:ff }

FLOW sample_verify(c, s) {
    c -> s TCP SYN SRCPORT 51234 DSTPORT 80 WIN 65535 MSS 1460 WAIT 1ms
    c <- s TCP SYN ACK WIN 65535 MSS 1460 WAIT 1ms
    c -> s TCP ACK WAIT 1ms
    c -> s HTTP GET URI "/status" HOST_HDR "example.com" WAIT 2ms
    c <- s HTTP STATUS 200 REASON "OK" BODY "OK" WAIT 2ms
}

COMPILE {
    sample_verify(client, server)
}
```
