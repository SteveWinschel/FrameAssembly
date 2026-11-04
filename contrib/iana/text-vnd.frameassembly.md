# IANA Media Type Registration, Wikidata & Public File Extension Registries (`text/vnd.frameassembly`)

This document contains:
1. The complete, copy-paste-ready **IANA RFC 6838 Vendor Tree Media Type Registration Application** (`text/vnd.frameassembly`) for submission at [`https://www.iana.org/form/media-types`](https://www.iana.org/form/media-types).
2. The **IETF Designated Expert Review Process Guide** for tracking the registration on `media-types@ietf.org`.
3. The **Wikidata Entity & Property Mapping Specification** (`P31`, `P1195`, `P1163`, `P973`, `P856`, `P1324`, `P275`, `P306`, `P277`) and ready-to-run QuickStatements batch script.
4. The **`file-extensions.org` Submission Web Form Template** and instructions.

For the normative technical specification referenced by all submissions, see [`docs/fasm-specification.md`](../../docs/fasm-specification.md). For Freedesktop desktop MIME integration, see [`contrib/mime/text-vnd.frameassembly.xml`](../mime/text-vnd.frameassembly.xml). For GitHub Linguist integration, see [`contrib/linguist/README.md`](../linguist/README.md).

---

## 1. IANA Media Type Registration Template (RFC 6838 §5.6 & RFC 6657)

- **Registration Tree:** Vendor Tree (`vnd.`) per [RFC 6838 §3.2](https://www.rfc-editor.org/rfc/rfc6838#section-3.2)
- **Submission Portal:** [`https://www.iana.org/form/media-types`](https://www.iana.org/form/media-types)

### Field-by-Field Application Values

* **Your Full Name:**
  ```text
  Steve Winschel
  ```

* **Your E-mail:**
  ```text
  steve.winschel@gmail.com
  ```

* **Type name:**
  ```text
  text
  ```

* **Subtype name:**
  - **Tree Dropdown Selection:** `Vendor Tree (vnd. prefix)`
  - **Subtype Input Box (omit `vnd.` prefix in the web form input field):** `frameassembly`
  - **Resulting Canonical Subtype Name:**
  ```text
  vnd.frameassembly
  ```

* **Provisional Registrations:**
  ```text
  No. This is a request for vendor-tree, personal-tree, or permanent standards-tree registration.
  ```

* **Required parameters:**
  ```text
  N/A
  ```

* **Optional parameters:**
  ```text
  charset: As specified in RFC 6657, the "charset" parameter may be used to specify the character encoding of the document. The default and strongly recommended charset is "UTF-8" (RFC 3629) without a Byte Order Mark (BOM). All FrameAssembly keywords, protocol identifiers, header modifiers, numeric literals, IPv4/IPv6 addresses, MAC addresses, and ASN.1 Object Identifiers (OIDs) use 7-bit US-ASCII characters; non-ASCII UTF-8 characters may appear inside single-line "//" comments and double-quoted payload string literals.
  ```

* **Encoding considerations:**
  ```text
  8bit (UTF-8 text; 7bit when comments and string literals contain only US-ASCII characters). Both LF (0x0A, canonical) and CRLF (0x0D 0x0A) line endings are permitted per RFC 6838 Section 4.8. Literal NUL bytes (0x00) are strictly prohibited; arbitrary binary packet payloads are represented in ASCII text using "\xHH" escape sequences in PAYLOAD strings or hexadecimal byte strings in HEXPAYLOAD fields.
  ```

* **Security considerations:**
  ```text
  FrameAssembly (.fasm) files are purely declarative, non-executable UTF-8 source specifications that describe network endpoints (HOST), protocol packet sequences (FLOW), and capture compilation targets (COMPILE).

  1. No Active or Turing-Complete Execution: The language contains no executable macros, shell invocations, conditional branches, unbounded loops (LOOP requires a fixed positive integer count), file-inclusion directives, or network I/O primitives. Compiling an untrusted .fasm file does not open network sockets, perform DNS lookups, or read arbitrary local files.
  2. Unprivileged Offline Compilation: The reference compiler (frameassembly) runs entirely offline in unprivileged user space without root privileges (CAP_NET_RAW), kernel packet sockets, or libpcap dependencies, and performs strict lexical, syntactic, and semantic bounds checks before writing passive .pcap / .pcapng capture files.
  3. Downstream Capture Consumers: Because FrameAssembly is used to synthesize deterministic packet captures for testing firewalls, intrusion detection systems (Suricata, Zeek, Snort), and protocol dissectors (Wireshark, tshark), the resulting .pcap / .pcapng files may intentionally contain crafted protocol header values, IPv4 fragments, or IDS signature test payloads. Replaying generated .pcap files onto a live network requires explicit invocation of an external tool such as tcpreplay by an authorized administrator.
  4. Confidentiality & Integrity: .fasm files are unencrypted source code and provide no built-in transport encryption or digital signature container; when SNMPv3 USM (RFC 3414 / 3826 / 7860) test passphrases or network topologies are sensitive, standard transport security (TLS/SSH) and repository access controls should be applied.
  ```

* **Interoperability considerations:**
  ```text
  The ".fasm" file extension is also used informally by two unregistered formats in other domains:
  1. Flat Assembler (x86/x86-64 machine assembly), which uses ";" comments, "format PE/ELF", "section", "org", and x86 CPU mnemonics.
  2. SymbiFlow / F4PGA FPGA Assembly (FASM), which uses "#" comments and dot-separated hardware tile feature paths (e.g., "CLBLL_L_X10Y100.SLICEL_X0...").

  FrameAssembly (text/vnd.frameassembly) documents are unambiguously distinguished by "//" single-line comments, top-level "HOST <id> { IP ... }", "FLOW <id>(...) { ... }", and "COMPILE { ... }" blocks, and directional packet operators ("->" and "<-") paired with OSI Layer 2 through Layer 7 protocol identifiers. Complete content-sniffing magic rules and regular expression heuristics are published in the specification and in the repository's Freedesktop shared-mime-info and GitHub Linguist definitions.
  ```

* **Published specification:**
  ```text
  https://github.com/SteveWinschel/FrameAssembly/blob/main/docs/fasm-specification.md
  https://github.com/SteveWinschel/FrameAssembly/blob/main/grammar.ebnf
  ```

* **Applications that use this media type:**
  ```text
  - FrameAssembly compiler and CLI (frameassembly, https://crates.io/crates/frameassembly and https://docs.rs/frameassembly)
  - FrameAssembly VS Code / Antigravity syntax and language extension (frameassembly-vscode)
  - Upstream "Packets as Code" test fixture pipelines feeding Wireshark, tshark, tcpreplay, Suricata, Zeek, and CI/CD network validation suites
  - Constrained LLM decoding engines (llama.cpp, XGrammar, Outlines, llguidance) via frameassembly.gbnf and frameassembly.lark
  ```

* **Fragment identifier considerations:**
  ```text
  Fragment identifiers for text/vnd.frameassembly follow RFC 5147 (URI Fragment Identifiers for the text/plain Media Type), supporting character and line range addressing (e.g., #line=1,20).
  ```

* **Restrictions on usage:**
  ```text
  None.
  ```

* **Additional information:**
  - **Deprecated alias names for this type:** `N/A`
  - **Magic number(s):** Top-level ASCII case-insensitive keywords `HOST`, `FLOW`, and `COMPILE` within the initial UTF-8 text stream; see [`contrib/mime/text-vnd.frameassembly.xml`](../mime/text-vnd.frameassembly.xml).
  - **File extension(s):** `.fasm`
  - **Macintosh file type code(s):** `TEXT`
  - **Uniform Type Identifier (UTI):** `io.github.stevewinschel.frameassembly` conforms to `public.plain-text` and `public.source-code`
  - **Object Identifiers (OIDs):** `N/A`

* **Intended usage:**
  ```text
  Common
  ```

* **Contact person / Change controller:**
  ```text
  Name: Steve Winschel
  Email: steve.winschel@gmail.com
  Author/Change Controller: Steve Winschel (https://github.com/SteveWinschel/FrameAssembly)
  ```

---

## 2. IANA Designated Expert Review Process & Tracking

Registration in the RFC 6838 Vendor Tree proceeds according to the **Designated Expert Review** policy outlined in [RFC 6838 §5.2](https://www.rfc-editor.org/rfc/rfc6838#section-5.2) and [RFC 8126](https://www.rfc-editor.org/rfc/rfc8126):

1. **Submission Phase**:
   - The applicant submits the form at [`https://www.iana.org/form/media-types`](https://www.iana.org/form/media-types).
   - IANA assigns an internal ticket tracking number (e.g., `[IANA #13xxxxx]`) and confirms receipt via automated email.
2. **Public Review Phase (`media-types@ietf.org`)**:
   - The IANA ticket dispatcher forwards the complete application to the public IETF Media Types mailing list ([`media-types@ietf.org`](https://mailman.ietf.org/mailman/listinfo/media-types)) with subject header:
     `[IANA #xxxxxxx] Registration of media type text/vnd.frameassembly`.
   - The public review period typically lasts **2 to 4 weeks**.
   - Community members and Designated Experts evaluate the application for:
     - Clear naming syntax conformant to RFC 6838 §3.2 (proper vendor subtype prefix `vnd.`).
     - Sound security considerations addressing potential replay, injection, or code execution hazards (RFC 6838 §4.6).
     - Character set specifications adhering to RFC 6657 (explicit default of UTF-8, no BOM).
     - Accurate fragment identifier addressing (RFC 5147).
3. **Expert Feedback & Dialogue**:
   - The project owner responds directly to any questions on the `media-types@ietf.org` thread, referencing the normative technical specification at [`docs/fasm-specification.md`](../../docs/fasm-specification.md).
4. **Approval & Registry Publication**:
   - Upon Designated Expert consensus, IANA notifies the applicant and updates the official IANA Media Types Registry at [`https://www.iana.org/assignments/media-types/media-types.xhtml`](https://www.iana.org/assignments/media-types/media-types.xhtml) under the `text` category.

---

## 3. Wikidata Knowledge Graph Mapping & QuickStatements

Registering the FrameAssembly file format in **Wikidata** populates structured file-extension and media-type knowledge graphs consumed by Google Knowledge Graph, Wikipedia infoboxes, digital preservation registries (PRONOM, Wikidata for Digital Preservation), and AI semantic retrieval engines.

### 3.1 Comprehensive Wikidata Property Table

| Wikidata Property | Property Name | Value | Qualifier / Reference URL (`S854`) |
| :--- | :--- | :--- | :--- |
| **`P31`** | instance of | `Q235557` (file format)<br>`Q1262091` (domain-specific language)<br>`Q9143` (programming language) | `https://github.com/SteveWinschel/FrameAssembly/blob/main/docs/fasm-specification.md` |
| **`P1195`** | file extension | `"fasm"` | `https://github.com/SteveWinschel/FrameAssembly/blob/main/docs/fasm-specification.md` |
| **`P1163`** | media type | `"text/vnd.frameassembly"` | `https://github.com/SteveWinschel/FrameAssembly/blob/main/docs/fasm-specification.md` |
| **`P973`** | described at URL | `https://github.com/SteveWinschel/FrameAssembly/blob/main/docs/fasm-specification.md` | Language of work (`P407`): `Q1860` (English) |
| **`P856`** | official website | `https://github.com/SteveWinschel/FrameAssembly` | — |
| **`P1324`** | source code repository | `https://github.com/SteveWinschel/FrameAssembly` | Version control system (`P8423`): `Q186055` (Git) |
| **`P275`** | copyright license | `Q334661` (MIT License) | [`https://github.com/SteveWinschel/FrameAssembly/blob/main/LICENSE`](../../LICENSE) |
| **`P306`** | operating system | `Q388` (Linux)<br>`Q14116` (macOS)<br>`Q1406` (Microsoft Windows) | — |
| **`P277`** | programmed in | `Q575650` (Rust) | `https://crates.io/crates/frameassembly` |

### 3.2 Option A: Direct Web UI Creation (`Special:NewItem` — Works Immediately for Any Account)

Because QuickStatements requires an autoconfirmed Wikidata account ($\ge 4$ days old and $\ge 50$ edits), new users or maintainers without an autoconfirmed account should create the entity directly through the Wikidata web interface:

1. Open [`https://www.wikidata.org/wiki/Special:NewItem`](https://www.wikidata.org/wiki/Special:NewItem) (optionally create a free account first at [`Special:CreateAccount`](https://www.wikidata.org/w/index.php?title=Special:CreateAccount)).
2. Fill in the initial item creation form and click **Create**:
   - **Language:** `en` (English)
   - **Label:** `FrameAssembly (.fasm)`
   - **Description:** `declarative domain-specific language and file format for generating deterministic .pcap and .pcapng network packet captures`
   - **Aliases (pipe-separated):** `fasm|.fasm|text/vnd.frameassembly|FrameAssembly packet specification`
3. On the newly created item page (`Q...`), click **+ add statement** for each of the 9 properties in [Section 3.1](#31-comprehensive-wikidata-property-table):
   - **`instance of` (`P31`)**: add `file format` (`Q235557`), `domain-specific language` (`Q1262091`), and `programming language` (`Q9143`), each with reference `reference URL` (`P854`) = `https://github.com/SteveWinschel/FrameAssembly/blob/main/docs/fasm-specification.md`.
   - **`file extension` (`P1195`)**: `fasm` (with reference URL `P854` above).
   - **`media type` (`P1163`)**: `text/vnd.frameassembly` (with reference URL `P854` above).
   - **`described at URL` (`P973`)**: `https://github.com/SteveWinschel/FrameAssembly/blob/main/docs/fasm-specification.md` (qualifier `language of work or name` `P407` = `English` `Q1860`).
   - **`official website` (`P856`)**: `https://github.com/SteveWinschel/FrameAssembly`.
   - **`source code repository` (`P1324`)**: `https://github.com/SteveWinschel/FrameAssembly` (qualifier `version control system` `P8423` = `Git` `Q186055`).
   - **`copyright license` (`P275`)**: `MIT License` (`Q334661`).
   - **`operating system` (`P306`)**: `Linux` (`Q388`), `macOS` (`Q14116`), `Microsoft Windows` (`Q1406`).
   - **`programmed in` (`P277`)**: `Rust` (`Q575650`).

### 3.3 Option B: QuickStatements Batch Execution Guide (For Autoconfirmed Accounts)

1. Log into your autoconfirmed Wikimedia account ($\ge 4$ days old, $\ge 50$ edits) at [`https://quickstatements.toolforge.org/`](https://quickstatements.toolforge.org/).
2. Click **New batch** $\rightarrow$ **Import V1 commands**.
3. Copy and paste the batch script below into the command box.
4. Click **Import V1 commands** to validate the syntax.
5. Click **Run** to execute the batch.
6. Record the newly minted Wikidata QID (e.g., `Q...`) in project records.

```text
CREATE
LAST|Len|"FrameAssembly (.fasm)"
LAST|Den|"declarative domain-specific language and file format for generating deterministic .pcap and .pcapng network packet captures"
LAST|Aen|"fasm"
LAST|Aen|".fasm"
LAST|Aen|"text/vnd.frameassembly"
LAST|Aen|"FrameAssembly packet specification"
LAST|P31|Q235557|S854|"https://github.com/SteveWinschel/FrameAssembly/blob/main/docs/fasm-specification.md"
LAST|P31|Q1262091|S854|"https://github.com/SteveWinschel/FrameAssembly/blob/main/docs/fasm-specification.md"
LAST|P31|Q9143|S854|"https://github.com/SteveWinschel/FrameAssembly/blob/main/docs/fasm-specification.md"
LAST|P1195|"fasm"|S854|"https://github.com/SteveWinschel/FrameAssembly/blob/main/docs/fasm-specification.md"
LAST|P1163|"text/vnd.frameassembly"|S854|"https://github.com/SteveWinschel/FrameAssembly/blob/main/docs/fasm-specification.md"
LAST|P973|"https://github.com/SteveWinschel/FrameAssembly/blob/main/docs/fasm-specification.md"|P407|Q1860
LAST|P856|"https://github.com/SteveWinschel/FrameAssembly"
LAST|P1324|"https://github.com/SteveWinschel/FrameAssembly"|P8423|Q186055
LAST|P275|Q334661|S854|"https://github.com/SteveWinschel/FrameAssembly/blob/main/LICENSE"
LAST|P306|Q388
LAST|P306|Q14116
LAST|P306|Q1406
LAST|P277|Q575650|S854|"https://crates.io/crates/frameassembly"
```

---

## 4. Public File Extension & Preservation Registries

To claim the `.fasm` file extension and ensure authoritative consumer and technician search results, maintainers should submit the following ready-to-paste entries across major file format databases:

### 4.1 `file-extensions.org` Submission Web Form Template

* **Submission Portals:** [`https://www.file-extensions.org/contact-us`](https://www.file-extensions.org/contact-us) / [`https://www.file-extensions.org/contact`](https://www.file-extensions.org/contact)
* **Submitter Name & Email:** `Steve Winschel` (`steve.winschel@gmail.com`)

```text
Subject: New File Extension Submission: .fasm (FrameAssembly Network Packet Specification)

File Extension:
fasm

Full File Type Name:
FrameAssembly Network Packet Specification

Media (MIME) Type:
text/vnd.frameassembly

Category:
Network / Data Capture / Developer Tools

Developer / Company:
Steve Winschel / FrameAssembly Project (https://github.com/SteveWinschel/FrameAssembly)

Operating Systems Supported:
Linux, macOS, Microsoft Windows

Associated Programs:
- FrameAssembly CLI (frameassembly)
- FrameAssembly VS Code Extension (frameassembly-vscode)
- Downstream tools: Wireshark, tshark, tcpreplay, Suricata, Zeek

Short Description (1-2 sentences):
A .fasm file is a declarative network traffic specification written in the FrameAssembly Domain-Specific Language. It defines network hosts, directional packet flows, and compilation targets compiled into deterministic .pcap and .pcapng packet captures.

Long Description:
FrameAssembly (.fasm) is a declarative, human-readable language designed for network engineers, security researchers, and test engineers. Instead of writing complex Python scripts or using raw sockets, users declare network endpoints (HOST), protocol sequences (FLOW), and output schedules (COMPILE). The frameassembly compiler parses .fasm files offline in userspace and emits bit-exact .pcap or .pcapng captures across 81 native Layer 2 through Layer 7 protocols (including Ethernet, VLAN, QinQ, MPLS, IPv4, IPv6, TCP, UDP, SCTP, SNMPv1/v2c/v3, DNS, DHCP, TLS, HTTP/2, Modbus, DNP3, and BGP).

Format Disambiguation:
The .fasm extension is also used historically by two unrelated formats:
1. Flat Assembler (x86 assembly language source code, using ';' comments and x86 CPU mnemonics).
2. SymbiFlow / F4PGA FPGA FASM (hardware tile bitstream configuration, using '#' comments and dot-separated hardware paths).
FrameAssembly files are distinguished by '//' comments, 'HOST { IP ... }', 'FLOW(...) { ... }', 'COMPILE { ... }' blocks, and directional packet operators ('->' and '<-').

How to Open / Compile:
Install via cargo (cargo install frameassembly) or download the prebuilt binary.
To preview packet sequences in the terminal:
frameassembly show input.fasm
To compile to a PCAP packet capture:
frameassembly input.fasm -o output.pcap
```

### 4.2 `FileInfo.com` Submission Template

* **Submission Portals:** [`https://fileinfo.com/software/developer`](https://fileinfo.com/software/developer) / [`https://fileinfo.com/help/submit_file_type`](https://fileinfo.com/help/submit_file_type)
* **Developer Contact:** `Steve Winschel` (`steve.winschel@gmail.com`)

```text
File Extension: .fasm
File Type: FrameAssembly Network Packet Specification
Developer: Steve Winschel
Primary Program: FrameAssembly
Format: Text
Category: Developer Files

Description:
A .fasm file is a declarative source specification created in FrameAssembly, a domain-specific language used by network engineers to synthesize deterministic network traffic packet captures (.pcap and .pcapng files). It contains declarations for network endpoints (HOST blocks specifying IP and MAC addresses), traffic sequences (FLOW blocks specifying directional packet transmissions across Layer 2 through Layer 7 protocols), and capture schedules (COMPILE blocks).

Unlike binary packet captures, .fasm files are human-readable and can be version-controlled in Git. The frameassembly compiler processes .fasm files offline without root privileges, generating packet captures for analysis in Wireshark, tcpreplay, Suricata, and Zeek.

Disambiguation:
The .fasm file extension is also used by Flat Assembler (an x86 assembly tool) and SymbiFlow FPGA FASM (FPGA bitstream tooling). FrameAssembly files are distinct in that they exclusively use '//' comments, 'HOST', 'FLOW', and 'COMPILE' blocks, and directional arrows ('->' and '<-').

Programs that open .fasm files:
- Windows: FrameAssembly (CLI), Microsoft Visual Studio Code with FrameAssembly extension
- Mac: FrameAssembly (CLI), Microsoft Visual Studio Code with FrameAssembly extension
- Linux: FrameAssembly (CLI), Microsoft Visual Studio Code with FrameAssembly extension
```

### 4.3 `FILExt.com` Submission Template

* **Submission Portals:** [`https://filext.com/submit_extension.php`](https://filext.com/submit_extension.php) / [`https://filext.com/contact.html`](https://filext.com/contact.html)
* **Submitter Contact:** `Steve Winschel` (`steve.winschel@gmail.com`)

```text
File Extension: fasm
File Type: FrameAssembly Network Packet Specification
MIME-Type: text/vnd.frameassembly
Developer: Steve Winschel / FrameAssembly
File Category: Source Code / Network Data

Overview:
FrameAssembly specification (.fasm) is a declarative source code file used to generate deterministic .pcap and .pcapng network packet captures across 81 protocols (Ethernet, IPv4/IPv6, TCP, UDP, SCTP, SNMPv1/v2c/v3, TLS, HTTP/2, Modbus, DNP3, etc.).

Distinction from other .fasm files:
- FrameAssembly: Uses '//' comments, 'HOST { IP ... }', 'FLOW(...) { ... }', 'COMPILE { ... }' keywords.
- Flat Assembler: Uses ';' comments, 'format PE/ELF', and x86 CPU opcodes.
- FPGA FASM: Uses '#' comments and dot-separated hardware tile strings.

Associated Software:
FrameAssembly CLI (https://github.com/SteveWinschel/FrameAssembly)
```

### 4.4 UK National Archives PRONOM Technical Registry Submission

* **GitHub Submission Portal (Recommended):** [`https://github.com/digital-preservation/PRONOM_Research/issues`](https://github.com/digital-preservation/PRONOM_Research/issues)
* **Direct Registry Email:** `PRONOM@nationalarchives.gov.uk`
* **Registry Overview:** [`https://www.nationalarchives.gov.uk/PRONOM/Default.aspx`](https://www.nationalarchives.gov.uk/PRONOM/Default.aspx)
* **Digital Preservation Format Classification:** Text (Source Code / Data Format)

```text
Format Name: FrameAssembly Network Packet Specification
Acronym: FASM
Version: 1.4.5
Format Type: Text (Source Code) / Network Data Specification
Disclosure: Full (Open Source, MIT License, RFC 6838 Vendor Tree Candidate)
Developer / Organisation: Steve Winschel (steve.winschel@gmail.com) / FrameAssembly Project
Official URL: https://github.com/SteveWinschel/FrameAssembly
Specification Document: https://github.com/SteveWinschel/FrameAssembly/blob/main/docs/fasm-specification.md

File Extension: fasm
Internet Media Type: text/vnd.frameassembly
Character Encoding: UTF-8 (RFC 3629) without BOM, US-ASCII compatible
Line Termination: LF (canonical) or CRLF

Internal Byte Signatures:
Signature 1 (Beginning of file, offset 0:1024):
  Hex: 484F535420 (ASCII "HOST ")
  Subsequence 1 (offset 0:1536): 495020 (ASCII "IP ")
  Subsequence 2 (offset 0:8192): 434F4D50494C45 (ASCII "COMPILE")
Signature 2 (Beginning of file, offset 0:2048):
  Hex: 464C4F5720 (ASCII "FLOW ")
  Subsequence 1 (offset 0:8192): 434F4D50494C45 (ASCII "COMPILE")

Format Purpose:
Declarative DSL allowing network engineers and archivists to define reproducible, deterministic network packet captures. Files are compiled offline into standard PCAP / PCAPNG files without requiring live network interfaces.
```

### 4.5 Node.js / Web Ecosystem (`jshttp/mime-db`) Registration

`jshttp/mime-db` automatically ingests IANA-registered media types, and also accepts direct pull requests to [`src/custom-types.json`](https://github.com/jshttp/mime-db/blob/master/src/custom-types.json) backed by a primary specification URL:

```json
  "text/vnd.frameassembly": {
    "compressible": true,
    "extensions": ["fasm"],
    "sources": [
      "https://github.com/SteveWinschel/FrameAssembly/blob/main/docs/fasm-specification.md"
    ]
  }
```

---

## 5. Step-by-Step Post-Run Upstream Registration Checklist

This checklist outlines the exact sequence of manual submission steps required by the project maintainer:

- [ ] **Step 1: IANA Media Type Registration**
  - Navigate to [`https://www.iana.org/form/media-types`](https://www.iana.org/form/media-types).
  - Copy and paste the field values from [Section 1](#1-iana-media-type-registration-template-rfc-6838-56--rfc-6657) (selecting `Vendor Tree (vnd. prefix)` and entering `frameassembly` without `vnd.` in the Subtype box).
  - Submit the form and record the assigned `[IANA #xxxxxx]` ticket number.
  - Monitor [`media-types@ietf.org`](https://mailman.ietf.org/mailman/listinfo/media-types) for Designated Expert questions.

- [ ] **Step 2: Wikidata Knowledge Graph Entity Creation**
  - **Option A (Immediate — Any Account)**: Open [`https://www.wikidata.org/wiki/Special:NewItem`](https://www.wikidata.org/wiki/Special:NewItem) and follow [Section 3.2](#32-option-a-direct-web-ui-creation-specialnewitem--works-immediately-for-any-account).
  - **Option B (Autoconfirmed Accounts: 4+ days & 50+ edits)**: Open [`https://quickstatements.toolforge.org/`](https://quickstatements.toolforge.org/) and run the batch script in [Section 3.3](#33-option-b-quickstatements-batch-execution-guide-for-autoconfirmed-accounts).
  - Record the newly created Wikidata QID (e.g., `Q...`).

- [ ] **Step 3: Freedesktop `shared-mime-info` Upstream Merge Request**
  - Fork [`https://gitlab.freedesktop.org/xdg/shared-mime-info`](https://gitlab.freedesktop.org/xdg/shared-mime-info).
  - Apply the patch from [`contrib/mime/README.md`](../mime/README.md) to `data/freedesktop.org.xml.in`.
  - Add a test file in `tests/` and verify with `ninja -C build test`.
  - Submit the GitLab Merge Request using the description template in `contrib/mime/README.md`.

- [ ] **Step 4: `file(1)` / `libmagic` Upstream Submission**
  - Clone [`https://github.com/file/file`](https://github.com/file/file) (note: the GitHub repository is a read-only mirror and does not accept GitHub PRs).
  - Copy [`contrib/magic/frameassembly.magic`](../magic/frameassembly.magic) to `magic/Magdir/frameassembly` and verify with `file -C -m magic/Magdir/frameassembly`.
  - Submit the patch via the official upstream bug tracker ([`https://bugs.astron.com/`](https://bugs.astron.com/)) or mailing list (`file@astron.com` / `christos@zoulas.com`).

- [ ] **Step 5: Public File Extension Databases, PRONOM & `mime-db`**
  - Submit the template in [Section 4.1](#41-file-extensionsorg-submission-web-form-template) to [file-extensions.org](https://www.file-extensions.org/contact-us).
  - Submit the template in [Section 4.2](#42-fileinfocom-submission-template) to [FileInfo.com](https://fileinfo.com/software/developer).
  - Submit the template in [Section 4.3](#43-filextcom-submission-template) to [FILExt.com](https://filext.com/submit_extension.php).
  - Submit the template in [Section 4.4](#44-uk-national-archives-pronom-technical-registry-submission) (with a sample `.fasm` file) to [`digital-preservation/PRONOM_Research`](https://github.com/digital-preservation/PRONOM_Research/issues) or `PRONOM@nationalarchives.gov.uk`.
  - Submit the JSON snippet in [Section 4.5](#45-nodejs--web-ecosystem-jshttpmime-db-registration) to [`jshttp/mime-db`](https://github.com/jshttp/mime-db).

- [ ] **Step 6: GitHub Linguist Upstream Pull Request**
  - Monitor public GitHub repositories using the query `path:*.fasm NOT fork:true`.
  - Once the volume reaches **200+ unique public files**, open a pull request against [`github-linguist/linguist`](https://github.com/github-linguist/linguist) using the instructions and template in [`contrib/linguist/README.md`](../linguist/README.md).

---

## 6. Canonical `.fasm` Media Type Verification Sample

```frameassembly
HOST branch_gw { IP 10.20.0.1 MAC 00:1a:2b:3c:4d:01 }
HOST core_peer { IP 10.20.0.2 MAC 00:1a:2b:3c:4d:02 }

FLOW bgp_and_bfd_check(a, b) {
    a -> b BFD STATE 3 DIAG 0 MY_DISC 101 YOUR_DISC 202 MIN_TX 50000 MIN_RX 50000 MULT 3 WAIT 1ms
    a -> b TCP SYN SRCPORT 52179 DSTPORT 179 WIN 65535 MSS 1460 WAIT 1ms
    a <- b TCP SYN ACK WIN 65535 MSS 1460 WAIT 1ms
    a -> b TCP ACK WAIT 1ms
    a -> b BGP OPEN ASN 65001 HOLDTIME 90 BGPID 10.20.0.1 WAIT 2ms
    a <- b BGP KEEPALIVE WAIT 2ms
}

COMPILE {
    bgp_and_bfd_check(branch_gw, core_peer)
}
```
