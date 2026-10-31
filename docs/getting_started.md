# Getting Started with FrameAssembly

FrameAssembly builds standard `.pcap` / `.pcapng` packet capture files from plain-text `.fasm` files. You define the hosts in your scenario and list the frames exchanged between them—FrameAssembly handles Ethernet framing, protocol headers, byte lengths, checksums, and TCP sequence numbers automatically.

---

## 1. Installation

### One-Line Installer (Linux, macOS & BSDs)
Checks for basic build prerequisites, installs the Rust toolchain if missing, installs the `frameassembly` binary, and adds `.fasm` syntax highlighting if VS Code (`code`) is on your `PATH`:

```bash
curl -fsSL [https://raw.githubusercontent.com/SteveWinschel/FrameAssembly/main/install.sh](https://raw.githubusercontent.com/SteveWinschel/FrameAssembly/main/install.sh) | sh
```

### Install via Cargo
If you already have Rust `>= 1.85` installed:

```bash
cargo install frameassembly
```

Verify the installation:

```bash
frameassembly --help
```

---

## 2. Structure of a `.fasm` File

Every `.fasm` file has three sections: **`host`**, **`flow`**, and **`compile`**.
* **Case-insensitive:** `host`, `Host`, and `HOST` (or `tcp` and `TCP`) work identically.
* **Comments:** Start single-line comments with `//`.
* **One line = one packet:** Each statement inside a `flow` block produces one frame in your `.pcap` file.

```frameassembly
// 1. Declare the endpoints
host workstation {
    ip 192.168.10.50
    mac 00:1a:2b:3c:4d:50
}

host gateway {
    ip 192.168.10.1
    mac 00:1a:2b:3c:4d:01
}

// 2. Define the packet sequence
flow ping_gateway(client, gw) {
    client -> gw icmp echo_request id 100 seq 1 payload "ping-check" wait 2ms
    client <- gw icmp echo_reply id 100 seq 1 payload "ping-check" wait 2ms
}

// 3. Build the capture
compile {
    ping_gateway(workstation, gateway)
}
```

### Defaults vs. Custom Overrides
Every protocol works with **zero mandatory sub-keywords**. Writing just `client -> gw icmp` emits a valid ICMP Echo Request with standard defaults (`TTL 64`, `ID 1`, `SEQ 1`). Whenever you want control over specific header fields—custom ports, flags, VLAN IDs, TTLs, payloads, or inter-packet delays—append those modifiers to the same line in any order.

---

## 3. Directional Arrows & Automatic TCP Tracking

Inside a `flow` block, keep the initiating host on the left and use arrows to show packet direction—matching how sequence diagrams are drawn:
* `c -> s` sends a frame from `c` (source) to `s` (destination).
* `c <- s` sends a frame from `s` (source) back to `c` (destination).

### Automatic Port Swapping & TCP `SEQ` / `ACK` Math
When you open a connection, FrameAssembly tracks its state automatically across both raw `TCP` packets and TCP-based Layer 7 protocols (`HTTP`, `TLS`, `SSH`, `BGP`, `SMB`, `POSTGRES`, etc.):
1. **Port inheritance:** Set `srcport` and `dstport` on the first packet, and subsequent forward (`->`) and return (`<-`) lines automatically reuse and swap those ports.
2. **Sequence progression:** `SYN` and `FIN` flags advance the sequence number by `1`, and payload segments advance `SEQ` and `ACKNUM` by the exact byte length of the payload.

```frameassembly
host client { ip 10.10.1.50 }
host server { ip 10.10.1.80 }

flow http_health_check(c, s) {
    // Specify ports once on the opening SYN
    c -> s tcp syn srcport 52100 dstport 80 win 65535 mss 1460 wait 1ms
    c <- s tcp syn ack win 65535 mss 1460 wait 1ms
    c -> s tcp ack wait 1ms

    // HTTP automatically reuses 52100 <-> 80 and updates TCP SEQ/ACK counters
    c -> s http get uri "/healthz" host_hdr "service.internal" wait 5ms
    c <- s http status 200 reason "OK" content_type "application/json" body "{\"ok\":true}" wait 2ms

    // Graceful TCP FIN close
    c -> s tcp fin ack wait 1ms
    c <- s tcp fin ack wait 1ms
    c -> s tcp ack
}

compile {
    http_health_check(client, server)
}
```

*(Need to test how a firewall or stack handles out-of-window packets or a zero receive window? Explicitly adding `seq`, `acknum`, or `win 0` on any line overrides the automatic counter for that packet.)*

---

## 4. VLANs, QoS Tags, IPv4/IPv6 Reuse & Loops

### Cross-Layer Modifiers
You can attach Layer 2 (`vlan`, `qinq`, `mpls`, `srcmac`, `dstmac`), Layer 3 (`ttl`, `dscp`, `ecn`, `flowlabel`, `df`, `mf`, `fragoffset`), and timing (`wait`) modifiers to **any** protocol line.

### Dual-Stack Reuse & `loop` Blocks
Because `flow` blocks accept host parameters rather than hardcoded IP addresses, the same flow can be compiled with IPv4 hosts and IPv6 hosts, and repeated inside `loop <count> { ... }`:

```frameassembly
host probe_v4  { ip 172.16.20.10 }
host target_v4 { ip 172.16.20.1 }

host probe_v6  { ip 2001:db8:20::10 }
host target_v6 { ip 2001:db8:20::1 }

flow tagged_sla_probe(src, dst) {
    src -> dst vlan 200 pcp 5 dscp 46 udp srcport 60000 dstport 9000 payload "SLA_PING" wait 5ms
    src <- dst vlan 200 pcp 5 dscp 46 udp payload "SLA_PONG" wait 5ms
}

compile {
    loop 3 {
        tagged_sla_probe(probe_v4, target_v4)
        tagged_sla_probe(probe_v6, target_v6)
    }
}
```

> **Endpoint Rule:** Both hosts in a single packet statement must use the same IP version (both IPv4 or both IPv6). Mixing an IPv4 host and an IPv6 host in one `->` statement raises a compile-time error pointing to the conflicting hosts.

---

## 5. Compiling, Inspecting & Replaying

### 1. Compile `.fasm` to `.pcap`
```bash
frameassembly my_scenario.fasm -o my_scenario.pcap
```
If your file contains a typo or invalid value, `frameassembly` prints the exact line and column of the mistake so you can fix it immediately.

### 2. Inspect in Wireshark or `tshark`
```bash
# Packet summary list
tshark -r my_scenario.pcap

# Full protocol tree decode
tshark -r my_scenario.pcap -V
```

### 3. Replay Over a Network Interface with `tcpreplay`
To send your generated capture onto a physical NIC, VLAN interface, or virtual bridge:

```bash
# Replay honoring the exact WAIT intervals defined in your .fasm file
sudo tcpreplay -i eth0 my_scenario.pcap

# Replay at maximum rate or loop multiple times
sudo tcpreplay -i eth0 --topspeed --loop=50 my_scenario.pcap
```

---

## 6. Quick Syntax Cheat Sheet

| Element | Correct `.fasm` Syntax | Common Mistake to Avoid |
| :--- | :--- | :--- |
| **Host block** | `host web { ip 10.0.0.1 mac 00:11:22:33:44:55 }` | Using `=`, `:`, commas, `ipv4`, or subnet masks |
| **Flow header** | `flow check(c, s) { ... }` | Omitting host parameters `(...)` |
| **Return packet** | `c <- s tcp syn ack` | Writing `reply` or `reverse` keywords |
| **Packet delay** | `c -> s tcp ack wait 5ms` | Putting `wait 5ms` on its own line |
| **Ports & TCP Ack** | `srcport 1234 dstport 80 acknum 100` | Writing `sport`, `dport`, or `ack 100` |
| **TCP flags** | `tcp syn ack` | Writing `flags [syn, ack]` or `flags="SA"` |
| **Hop limit** | `ttl 64` (works for both IPv4 and IPv6) | Writing `hop_limit 64` |
| **Double VLAN** | `qinq 100 inner_vlan 200` | Combining `qinq` and `vlan` on one line |
| **HTTP Host header**| `http get uri "/" host_hdr "example.com"` | Using `host "example.com"` inside an `http` line |
| **Loops** | `compile { loop 5 { check(a, b) } }` | Placing `loop` inside a `flow` block |