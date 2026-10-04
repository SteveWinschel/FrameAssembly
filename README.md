# FrameAssembly

> [!WARNING]
> **Experimental Prototype**
> This project is currently in the prototype stage. Many features are missing, APIs are unstable, and there will likely be breaking changes. Please do not use or show this in front of customers, coworkers or middle management (I already failed at that).

**FrameAssembly** is a Domain-Specific Language (DSL) for writing network traffic that gets compiled into a .pcap file. 
It is meant to be used for network security research, education, and testing.

## Features
*   **Production-Grade Pipeline:** Uses `logos` for zero-copy lexing and `winnow` for robust combinator parsing into a flat Abstract Syntax Tree (AST).
*   **Rich Diagnostics:** Employs `miette` to provide beautiful, `rustc`-style terminal error reporting pointing exactly to syntax errors.
*   **Packet Field Abstraction:** You can set TCP/IP, UDP, and SNMP packet fields like `SEQ`, `WIN`, `PAYLOAD`, `OID`, and `WAIT` using space-separated keyword values.
*   **Reliable Packet Crafting:** Uses `etherparse` for correct zero-allocation L2-L4 encapsulation and checksumming.
*   **Deterministic Output:** Generates reproducible `.pcap` files with nanosecond precision using `pcap-file` (`PcapNgWriter`) based on the defined flow and mock epoch timestamps.
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

## Syntax Guide

FrameAssembly uses a strict, keyword-oriented syntax. Property assignments do not require an `=` sign (though optionally supported for backward compatibility).

### 1. Hosts
Hosts are defined using the `HOST` keyword. They act as network endpoints.
```text
HOST name { IP 1.2.3.4 MAC 00:11:22:33:44:55 }
```
*   `IP` is **mandatory**.
*   `MAC` is **optional** (defaults to `00:00:00:00:00:00` if not provided).

### 2. Flows
Flows (similar to functions) encapsulate sequences of packet transmissions between endpoints. They are defined using the `FLOW` keyword and take arguments for the source and destination endpoints.

```text
FLOW tcp_handshake(client, server) {
    client -> server TCP SRCPORT 1234 DSTPORT 53 SYN SEQ 1 WIN 100 PAYLOAD "hello" WAIT 10ms
    client <- server TCP SRCPORT 53 DSTPORT 1234 ACK SEQ 2 WIN 200 PAYLOAD "world" WAIT 3m 
    client -> server TCP SRCPORT 1234 DSTPORT 53 SYN ACK SEQ 3 WAIT 100s 
}
```

#### Directionality
The arrow dictates the packet's source and destination:
*   `A -> B`: `A` is the source, `B` is the destination.
*   `A <- B`: `B` is the source, `A` is the destination.

#### Supported Protocols
*   `TCP`
*   `UDP`
*   `SNMP1`, `SNMP2`, `SNMP3` (First-class support for SNMP Traps)

#### Port Definitions
*   `SRCPORT <port>`: Defines the source port.
*   `DSTPORT <port>`: Defines the destination port.

#### TCP Flags
Only available when the protocol is `TCP`. You can chain flags separated by spaces.
*   `SYN`
*   `ACK`

#### Packet Properties
These properties follow the protocol and flag definitions. They are defined using space-separated key-value pairs.
*   `SEQ <number>`: Sets the TCP sequence number.
*   `WIN <number>`: Sets the TCP window size.
*   `PAYLOAD "<string>"`: Appends a string payload to the packet.
*   `COMMUNITY "<string>"`: Sets the community string for `SNMP1` and `SNMP2` traps.
*   `USER "<string>"`: Sets the USM authentication user name for `SNMP3` traps.
*   `OID "<string>"`: Sets the primary Object Identifier for the SNMP trap.
*   `WAIT <number><suffix>`: Introduces an artificial delay before sending the next packet. 
    *   Supported suffixes: `ms` (milliseconds), `s` (seconds), `m` (minutes).

### 3. Compile Block
The `COMPILE` block serves as the main entry point to execute flows. You can invoke previously defined `FLOW`s, passing `HOST`s as arguments. You can also use `LOOP` to repeat a sequence of flows.

```text
COMPILE { 
    LOOP 100 {
        snmp_trap(switch_agent, example_nms)
        tcp_handshake(example_client, google_dns) 
    }
}
```
*Note: Infinite loops (a `LOOP` without a specified count) are illegal.*

## Usage

Define your networking scenario in a text file (e.g., `CODE.txt`):

```text
// IPs can be defined like/as variables
HOST example_client { IP 10.0.0.1 }
HOST google_dns { IP 8.8.8.8 }

HOST switch_agent { IP 10.0.10.5 }
HOST example_nms { IP 10.0.10.100 }

// Templates are like functions, they can be called with arguments and are/should be reusable.
FLOW tcp_handshake (client, server) { 
    // The frame definitions are meant to look like they do in Wireshark
    client -> server TCP SRCPORT 1234 DSTPORT 53 SYN SEQ 1 WIN 100 PAYLOAD "hello" WAIT 10ms 
    client <- server TCP SRCPORT 53 DSTPORT 1234 ACK SEQ 2 WIN 200 PAYLOAD "world" WAIT 3m 
    client -> server TCP SRCPORT 1234 DSTPORT 53 SYN ACK SEQ 3 WAIT 100s 
}

// Simple SNMP Traps with fully encoded ASN.1 payloads
FLOW snmp_linkdown_trap(agent, nms) {
    agent -> nms SNMP2 TRAP COMMUNITY "public" OID "1.3.6.1.6.3.1.1.5.3" WAIT 10ms
}

FLOW snmp_v3_trap(agent, nms) {
    agent -> nms SNMP3 TRAP USER "admin" OID "1.3.6.1.6.3.1.1.5.3" WAIT 10ms
}

// You can compile a "Main" entry point like this
COMPILE { 
    LOOP 100 {
        snmp_linkdown_trap(switch_agent, example_nms)
        snmp_v3_trap(switch_agent, example_nms)
        tcp_handshake(example_client, google_dns) 
    }
}
```

To compile your script into a PCAP file, run:

```bash
cargo run --release CODE.txt
```

This generates an `output.pcap` file in the root directory via the help of tcpreplay or similar you can simulate written traffic.

## License

MIT License. See the `LICENSE` file.
