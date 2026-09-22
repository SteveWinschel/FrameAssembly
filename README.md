# FrameAssembly

> [!WARNING]
> **Experimental Prototype**
> This project is currently in the prototype stage. Many features are missing, APIs are unstable, and there will likely be breaking changes. Please do not use this in front of customers or middle management

**FrameAssembly** is a Domain-Specific Language (DSL) for writing network traffic. 
It is meant to be used for network security research, education, and testing.

## Features
*   **Prototype AST:** Uses a flat Abstract Syntax Tree (AST).
*   **Packet Field Abstraction:** You can currently only set TCP/IP and UDP packet fields like `SEQ`, `WIN`, `PAYLOAD`, and `WAIT` directly using keyword assignments. 
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

Define your networking scenario in a text file (`CODE.txt`) using the `COMPILE` keyword (the runner is an experimental feature and subordinated to the compiler). You can generate TCP flows as well as UDP packets (e.g. for SNMP Traps):

```text
LET example_client = 10.0.0.1 
LET google_dns = 8.8.8.8 
LET switch_agent = 10.0.10.5
LET example_nms = 10.0.10.100

LET tcp_handshake(src, dst) { 
    src -> dst TCP SYN SEQ=1 WIN=100 PAYLOAD="hello" WAIT=10ms 
    src <- dst TCP ACK SEQ=2 WIN=200 PAYLOAD="world" WAIT=1s 
    src -> dst TCP SYN ACK SEQ=3 WAIT=1m 
}

LET snmp_trap(agent, nms) {
    agent -> nms UDP PAYLOAD="RAW_SNMP_PAYLOAD_STRING" WAIT=10ms
}

COMPILE { 
    snmp_trap(switch_agent:161, example_nms:162)
    tcp_handshake(example_client:1234, google_dns:53) 
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

Define your scenario using a `RUN` block instead of `COMPILE`:

```text
LET switch_agent = 10.0.10.5
LET example_nms = 10.0.10.100

LET snmp_trap(agent, nms) {
    agent -> nms UDP PAYLOAD="RAW_SNMP_PAYLOAD_STRING" WAIT=10ms
}

RUN { 
    LOOP { 
        snmp_trap(switch_agent:161, example_nms:162)
    }
}
```

Run the injection with your target interface (e.g., `wlp6s0`):

```bash
cargo run CODE.txt wlp6s0
```

## License

MIT License. See the `LICENSE` file.
