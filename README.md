# FrameAssembly

> [!WARNING]
> **Experimental Prototype**
> This project is currently in the prototype stage. Many features are missing, APIs are unstable, and there will likely be breaking changes. Please do not use this in front of customers or middle management

**FrameAssembly** is a basic, zero-dependency Domain-Specific Language (DSL) for generating PCAP files. 

It handles the tedious byte-level math required for packet crafting so you can define network traffic conversations in a relatively straightforward format.

---

## Features

*   **Zero Dependencies:** It relies only on the Rust standard library (`std`). No external crates are used.
*   **Simple AST:** Uses a flat Abstract Syntax Tree (AST).
*   **Packet Field Abstraction:** You can set TCP/IP packet fields like `seq`, `win`, `payload`, and `wait` directly using keyword assignments. 
    *   *Note on Checksums:* To avoid dependencies, TCP/IPv4 checksums are intentionally hardcoded to `0x0000`. You *will* see "Bad Checksum" warnings if you open the output in Wireshark.
*   **Basic Parsing:** The compiler front-end is a handcrafted recursive descent parser using `&str` slicing.
*   **Deterministic Output:** Generates reproducible `.pcap` files based on the defined flow and mock epoch timestamps.

## Getting Started

### Prerequisites

You need [Rust and Cargo](https://rustup.rs/) installed.

### Installation

Clone the repository and enter the directory:

```bash
git clone https://github.com/stevewinschel/frameassembly.git
cd frameassembly
```

### Usage

Define your networking scenario in a text file (e.g., `CODE.txt`):

```text
let example_client = 10.0.0.1
let google_dns = 8.8.8.8

let template tcp_handshake(src, dst) {
    src -> dst tcp syn seq=1 win=100 payload="hello" wait=10ms
    src <- dst tcp ack seq=2 win=200 payload="world" wait=1s
    src -> dst tcp syn ack seq=3 wait=1m
}

compile {
    tcp_handshake(example_client, google_dns:80)
}
```

To compile your script into a PCAP file, run:

```bash
cargo run CODE.txt
```

This generates an `output.pcap` file in the root directory.

## License

MIT License. See the `LICENSE` file.