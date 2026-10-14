# FrameAssembly
[![Crates.io](https://img.shields.io/crates/v/frameassembly.svg)](https://crates.io/crates/frameassembly)

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

**Primary Method (via Cargo):**
```bash
cargo install frameassembly
```

**Alternative Method (from source):**
Clone the repository and enter the directory:
```bash
git clone https://github.com/stevewinschel/frameassembly.git
cd frameassembly
```

### Editor Support (VS Code)

A VS Code extension providing syntax highlighting for `.fasm` files is included in the repository. 

To install it manually, you can use the command line:
```bash
code --install-extension frameassembly-vscode/frameassembly-vscode-0.12.1.vsix
```
Alternatively, in VS Code, open the Extensions view, click the `...` menu, and select **Install from VSIX...** to install the file from the `frameassembly-vscode` directory.

## Syntax Guide

### 1. Hosts
Hosts are defined using the `HOST` keyword. They act as network endpoints.
```frameassembly
HOST name { IP 1.2.3.4 MAC 00:11:22:33:44:55 }
```
*   `IP` is **mandatory**.
*   `MAC` is **optional** (defaults to `00:00:00:00:00:00` if not provided).

### 2. Flows
Flows (similar to functions) encapsulate sequences of packet transmissions between endpoints. They are defined using the `FLOW` keyword and take arguments for the source and destination endpoints.

```frameassembly
FLOW tcp_handshake(client, server) {
    client -> server TCP SYN PAYLOAD "Hello" 
    client <- server TCP SYN ACK PAYLOAD "World"
    client -> server TCP ACK PAYLOAD "!" 
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
*   `SRCPORT <port>`: Defines the source port. (Optional: defaults to `12345`)
*   `DSTPORT <port>`: Defines the destination port. (Optional: defaults to `162` for SNMP `TRAP`/`INFORM`, `161` for SNMP `GET`/`SET`/`GETNEXT`/`GETBULK`/`RESPONSE`, and `80` for other protocols)

#### TCP Flags
Only available when the protocol is `TCP`. You can chain flags separated by spaces.
*   `SYN`
*   `ACK`
*   `FIN`
*   `RST`
*   `PSH`
*   `URG`
*   `ECE`
*   `CWR`

#### SNMP PDU Types
Available when the protocol is `SNMP1`, `SNMP2`, or `SNMP3`:
*   `TRAP` (default): Identifies the packet as an SNMP Trap.
*   `INFORM`: Identifies the packet as an SNMP InformRequest (SNMPv2c/v3).
*   `GET`: SNMP GetRequest.
*   `GETNEXT`: SNMP GetNextRequest.
*   `GETBULK`: SNMP GetBulkRequest (SNMPv2c/v3).
*   `SET`: SNMP SetRequest.
*   `RESPONSE`: SNMP Response PDU.

#### Packet Properties
These properties follow the protocol and flag definitions. They are defined using space-separated key-value pairs.
*   `SEQ <number>`: Sets the TCP sequence number. (Optional: auto-calculated)
*   `ACKNUM <number>`: Sets the TCP acknowledgment number. (Optional: auto-calculated)
*   `WIN <number>`: Sets the TCP window size. (Optional)
*   `PAYLOAD "<string>"`: Appends a string payload to the packet.
*   `COMMUNITY "<string>"`: Sets the community string for `SNMP1` and `SNMP2` traps.
*   `SYSUPTIME <number>`: Sets the time stamp (SysUpTime) for SNMP traps.
*   `OID <string> | "<string>"`: Sets the primary Object Identifier for the SNMP trap. Quotes are optional; raw OIDs (e.g., `1.3.6.1.4.1`) and IPv4-formatted strings are natively supported.
*   `NONREPEATERS <number>`: Sets non-repeaters for `GETBULK` requests (default: 0).
*   `MAXREPETITIONS <number>`: Sets max-repetitions for `GETBULK` requests (default: 10).
*   `REQID <number>`: Sets the request ID for SNMP messages (default: 1).
*   `WAIT <number><suffix>`: Introduces an artificial delay before sending the next packet. (Optional: defaults to 10ms)
    *   Supported suffixes: `ms` (milliseconds), `s` (seconds), `m` (minutes).

#### SNMPv1 Trap Specifics
*   `ENTERPRISE <oid>`: Sets the enterprise OID (falls back to `OID` if omitted, default: `1.3.6.1.4.1`).
*   `AGENTIP <ip>`: Sets the IPv4 address of the agent sending the trap.
*   `GENTRAP <0..6>`: Sets the Generic Trap code (0: coldStart, 1: warmStart, 2: linkDown, 3: linkUp, 4: authenticationFailure, 5: egpNeighborLoss, 6: enterpriseSpecific). Standard RFC 1157 generic trap OIDs (`1.3.6.1.6.3.1.1.5.1`..=`6`) automatically map to 0..=5 when omitted.
*   `SPECTRAP <number>`: Sets the Specific Trap code (default: 0 for generic traps, 1 for enterpriseSpecific traps).

#### SNMPv3 USM Cryptography
*   `USER "<string>"`: Sets the USM authentication user name for `SNMP3` traps.
*   `ENGINEID "<hex>"`: Authoritative engine ID in hex string format (e.g. `"8000000001"`).
*   `ENGINEBOOTS <number>`: Authoritative engine boot count (default: 0).
*   `ENGINETIME <number>`: Authoritative engine time in seconds (default: 0).
*   `CONTEXTNAME "<string>"`: SNMPv3 context name.
*   `AUTH <MD5|SHA|SHA256|SHA384|SHA512> "<password>"`: Configures USM authentication.
*   `PRIV <DES|AES> "<password>"`: Configures USM privacy encryption (RFC 3414 DES-CBC with pre-IV XOR salt and RFC 3826 AES-128-CFB).

#### Variable Bindings (VARBIND)
You can append multiple `VARBIND` statements to any SNMP packet:
*   `VARBIND <oid> NULLVAL`: Encodes an ASN.1 NULL value.
*   `VARBIND <oid> STRING "<text>"`: Encodes an OctetString.
*   `VARBIND <oid> INT <signed_i32>`: Encodes a 32-bit signed integer (supports negative values like `-12` for optical dBm levels).
*   `VARBIND <oid> TIMETICKS <u32>`: Encodes TimeTicks (in hundredths of a second).
*   `VARBIND <oid> IPVAL <ipv4>`: Encodes an IPv4 NetworkAddress / IpAddress.
*   `VARBIND <oid> OIDVAL <oid>`: Encodes an Object Identifier value.
*   `VARBIND <oid> COUNTER32 <u32>`: Encodes an SMIv1/SMIv2 32-bit Counter.
*   `VARBIND <oid> GAUGE32 <u32>`: Encodes an SMIv1/SMIv2 32-bit Gauge.
*   `VARBIND <oid> COUNTER64 <u64>`: Encodes an SMIv2 64-bit Counter (SNMPv2c/SNMPv3 only).

> [!NOTE]
> Per RFC 3416, SNMPv2c/v3 `TRAP` and `INFORM` PDUs automatically prepend `sysUpTime.0` (`1.3.6.1.2.1.1.3.0`) and `snmpTrapOID.0` (`1.3.6.1.6.3.1.1.4.1.0`) as the first two variable bindings before appending user-defined `VARBIND` items.

### 3. Compile Block
The `COMPILE` block serves as the main entry point to execute flows. You can invoke previously defined `FLOW`s, passing `HOST`s as arguments. You can also use `LOOP` to repeat a sequence of flows.

```frameassembly
COMPILE { 
    LOOP 100 {
        snmp_trap(switch_agent, example_nms)
        tcp_handshake(example_client, google_dns) 
    }
}
```
*Note: Infinite loops (a `LOOP` without a specified count) are illegal.*

## Usage

Define your networking scenario in a text file (e.g., `demo.fasm`):

```frameassembly
// Written vertically -> Intuitive for programmers
HOST example_server { 
    IP 10.0.10.5
    MAC aa:bb:cc:dd:ee:ff 
}

// Written horizontally -> Intuitive for network engineers
HOST example_nms { IP 10.0.10.100  }

FLOW tcp_handshake(client, server) {
    client -> server TCP SYN PAYLOAD "Hello" 
    client <- server TCP SYN ACK PAYLOAD "World"
    client -> server TCP ACK PAYLOAD "!" 
}

FLOW snmp_v1_trap(agent, nms) {
    agent -> nms SNMP1 TRAP COMMUNITY "public" OID "1.3.6.1.6.3.1.1.5.3" 
}

FLOW snmp_v2_trap(agent, nms) {
    agent -> nms SNMP2 TRAP COMMUNITY "public" OID "1.3.6.1.6.3.1.1.5.3" 
}

FLOW snmp_v3_trap(agent, nms) {
    agent -> nms SNMP3 TRAP USER "admin" OID "1.3.6.1.6.3.1.1.5.3" 
}

COMPILE {
        tcp_handshake(example_server, example_nms)
        snmp_v1_trap(example_server, example_nms)
        snmp_v2_trap(example_server, example_nms)
        snmp_v3_trap(example_server, example_nms)
}
```

To compile your script into a PCAP file, run the globally installed binary:

```bash
frameassembly demo.fasm
```

Or, if you are running from the source repository:

```bash
cargo run --release demo.fasm
```

This generates an `output.pcap` file in the root directory via the help of tcpreplay or similar you can simulate written traffic.

## License

MIT License. See the `LICENSE` file.
