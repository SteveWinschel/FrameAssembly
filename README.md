# FrameAssembly

> [!WARNING]
> **Experimental Prototype**
> This project is currently in the prototype stage. Many features are missing, APIs are unstable, and there will likely be breaking changes. Please do not use this in front of customers or middle management

**FrameAssembly** is a Domain-Specific Language (DSL) for writing Frames. 

It handles the low-level math required for packet crafting so you can define network traffic conversations in a straightforward format. It is meant to be used for network security research, education, and testing.

---

## Features
*   **Prototype AST:** Uses a flat Abstract Syntax Tree (AST).
*   **Packet Field Abstraction:** You can set TCP/IP packet fields like `seq`, `win`, `payload`, and `wait` directly using keyword assignments. 
*   **Prototype Parsing:** The compiler front-end is a handcrafted recursive descent parser using `&str` slicing.
*   **Deterministic Output:** Generates reproducible `.pcap` files based on the defined flow and mock epoch timestamps.
*   **Live Traffic Generation:** Bypasses the OS IP stack to inject crafted L2 frames directly onto the wire using raw sockets (`pnet`).
*   **Comments:** Supports inline comments using `//`.

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

#### PCAP Compilation

Define your networking scenario in a text file (`CODE.txt`) using the `compile` keyword:

```text
let example_client = 10.0.0.1
let google_dns = 8.8.8.8

let template tcp_handshake(src, dst) {
    src -> dst tcp syn seq=1 win=100 payload="hello" wait=10ms
    src <- dst tcp ack seq=2 win=200 payload="world" wait=1s
    src -> dst tcp syn ack seq=3 wait=1m
}

compile {
    tcp_handshake(example_client:1234, google_dns:80)
}
```

To compile your script into a PCAP file, run:

```bash
cargo run CODE.txt
```

This generates an `output.pcap` file in the root directory.

#### Live Traffic Generation

> [!WARNING]
> **Sudo Privileges Required**
> Live packet generation uses raw L2 sockets, which require root/sudo rights. You must also explicitly pass the script file and the network interface name as arguments.

Define your scenario using a `run` block instead of `compile`:

```text
let example_client = 10.0.0.1
let google_dns = 8.8.8.8

let template tcp_handshake(src, dst) {
    src -> dst tcp syn seq=1 win=100 payload="hello" wait=10ms
    src <- dst tcp ack seq=2 win=200 payload="world" wait=10ms
    src -> dst tcp syn ack seq=3 wait=10ms
}

run {
    loop {
        tcp_handshake(example_client:1234, google_dns:53)
    }
}
}
```

Run the injection with your target interface (e.g., `wlp6s0`):

```bash
cargo run -- CODE.txt wlp6s0
```
## License

MIT License. See the `LICENSE` file.