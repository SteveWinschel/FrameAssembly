# Security Policy

## Execution & Threat Model

**FrameAssembly** (`frameassembly` v3.3.1) compiles and decompiles **100% offline** in unprivileged user space across the CLI, WebAssembly module (`frameassembly-wasm`), browser playground ([`https://frameassembly-lang.dev/`](https://frameassembly-lang.dev/)), and VS Code extension (`frameassembly-vscode`):

- **Zero raw sockets or packet injection**: FrameAssembly never opens raw sockets, never binds network interfaces, and never transmits packets onto the wire. Generated `.pcap` and `.pcapng` files are written only to local disk paths you specify.
- **Zero kernel drivers or `libpcap` runtime bindings**: Compilation and reverse decompilation require no root/Administrator privileges, Npcap, WinPcap, or `libpcap` installation.
- **Zero background telemetry or unrequested network connections**: Compilation, `show`, `reverse`, the WebAssembly build, and the VS Code extension make zero outbound network connections or crash/usage telemetry calls. The `frameassembly update` command initiates outbound HTTPS requests (GitHub Releases, Crates.io, or `rustup`) only when explicitly invoked by the user, and verifies downloaded release archives fail-closed against `SHA256SUMS.txt`.
- **Encrypted payload handling**: When reversing `.pcap` or `.pcapng` captures, encrypted application traffic (such as TLS application data, SSH, IPsec ESP, or SNMPv3 `authPriv` PDUs) is preserved without attempting decryption.
- **Artifact verification**: Every official release publishes [`SHA256SUMS.txt`](https://github.com/SteveWinschel/FrameAssembly/releases/latest) alongside GitHub SLSA build provenance attestations (`gh attestation verify`).

## Supported Versions

Security fixes are released for the current major release line:

| Version | Supported |
| :--- | :--- |
| `3.3.x` | Yes |
| `< 3.3.0` | No (upgrade to `3.3.1`) |

## Reporting a Vulnerability

Please **do not** open a public GitHub issue for security vulnerabilities (such as parser/decompiler panics on malformed `.pcap`/`.frasm` inputs, denial-of-service / unbounded allocations, cryptographic defects in SNMPv3 USM handling, or path handling flaws).

Report vulnerabilities privately through GitHub Security Advisories:

- **Private Vulnerability Reporting:** [https://github.com/SteveWinschel/FrameAssembly/security/advisories/new](https://github.com/SteveWinschel/FrameAssembly/security/advisories/new)

When submitting a report, please include:

1. Your `frameassembly version` output (or VS Code / npm package version) and operating system.
2. A minimal sanitized `.frasm` file, `.pcap` / `.pcapng` capture, or hex reproducer (`tshark -r sample.pcap -x`) with private IP addresses, hostnames, and credentials removed.
3. Observed vs. expected behavior and any relevant backtrace or diagnostic output.

We aim to acknowledge reports promptly, keep you informed during investigation, and credit reporters in release advisories (unless anonymity is requested).
