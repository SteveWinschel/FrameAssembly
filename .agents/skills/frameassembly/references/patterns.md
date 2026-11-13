# FrameAssembly v3.0.0 Production Reference Patterns

This reference document provides production-ready, fully-documented, and compiler-verified Rust code templates and canonical v3.0.0 `.frasm` scenarios for FrameAssembly, covering forward and reverse compiler pipeline invocation, AST representation with strict-lowercase `/// Syntax mapping:`, protocol-first + 3-tier protocol-scoped sub-keyword parser dispatch, wire invariants, 4-tuple TCP state tracking, and enterprise `.frasm` archetypes.

---

## 1. Programmatic Forward & Reverse Compiler Pipeline Invocation

Demonstrates how to invoke FrameAssembly v3.0.0's two-phase forward compiler pipeline (`parse_program` $\rightarrow$ `validate_semantics(&program, source)` $\rightarrow$ `compile_program` / `generate_pcap`) and the 5-stage reverse PCAP/PCAPNG decompiler (`reverse_pcap_bytes` / `reverse_pcap_file`) without temporary file leaks or unchecked errors.

```rust
//! Programmatic entry points for forward compilation and reverse PCAP decompilation in FrameAssembly v3.0.0.

use std::fs;
use std::path::Path;
use frameassembly::ast::Program;
use frameassembly::backend::{compile_program, generate_pcap};
use frameassembly::parser::{parse_program, validate_semantics};
use frameassembly::reverse::{ReversedCapture, reverse_pcap_bytes};

/// Parses, semantically validates, and compiles v3.0.0 `.frasm` code in-memory into `(wire_bytes, timestamp_ns)` frames.
///
/// # Arguments
/// * `source` - Raw UTF-8 string containing canonical FrameAssembly v3.0.0 `.frasm` code.
///
/// # Errors
/// Returns a descriptive error string if lexing, syntax parsing, semantic validation,
/// or wire packet assembly fails.
pub fn compile_fasm_str(source: &str) -> Result<Vec<(Vec<u8>, u64)>, String> {
    // 1. Two-phase strict-lowercase lexing (logos 0.14.4) + combinator parsing (winnow 1.0.5)
    let program: Program<'_> = parse_program(source)
        .map_err(|e| format!("Syntax/Semantic error: {e:?}"))?;

    // 2. Explicit two-argument semantic validation pass: validate_semantics(&program, source)
    validate_semantics(&program, source)
        .map_err(|e| format!("Semantic validation error: {e:?}"))?;

    // 3. Stateful flow expansion, 4-tuple TCP progression, and RFC wire synthesis
    compile_program(&program)
}

/// Compiles a `.frasm` file on disk directly into a deterministic `.pcapng` capture file
/// (mirroring `frameassembly <input.frasm> [output.pcap]`).
///
/// # Arguments
/// * `input_path` - Path to the input `.frasm` specification.
/// * `output_path` - Destination path for the generated `.pcap` / `.pcapng` capture.
pub fn compile_fasm_file<P: AsRef<Path>>(input_path: P, output_path: &str) -> Result<(), String> {
    let source = fs::read_to_string(input_path.as_ref())
        .map_err(|e| format!("Failed to read {}: {e}", input_path.as_ref().display()))?;

    let program = parse_program(&source)
        .map_err(|e| format!("Parse error: {e:?}"))?;

    validate_semantics(&program, &source)
        .map_err(|e| format!("Semantic validation error: {e:?}"))?;

    generate_pcap(&program, output_path)
}

/// Decompiles raw `.pcap` or `.pcapng` capture bytes into canonical v3.0.0 `.frasm` code
/// (`host1`, `host2`, strict-lowercase keywords without `_`, direct `compile { ... }` statements).
pub fn decompile_capture_bytes(pcap_bytes: &[u8]) -> Result<ReversedCapture, String> {
    reverse_pcap_bytes(pcap_bytes)
}
```

---

## 2. Canonical v3.0.0 AST Structures & `/// Syntax mapping:` Docstring Pattern

Every AST struct in `src/ast/mod.rs` (`HostDef<'a>`, `FlowDef<'a>`, `RunStatement<'a>`, `FrameStatement<'a>`) and every protocol `*Spec` struct in `src/ast/{l2,l3,l4,l7}/<protocol>.rs` must include a `/// Syntax mapping: \`...\`` docstring in v3.0.0 strict-lowercase syntax and `#[doc(alias = "...")]` attributes binding the Rust type to its `.frasm` surface syntax and RFC standard. Note that `RunStatement::Loop` was removed in FrameAssembly v2.0.0 (`RunStatement::{Invocation, Frame}`).

```rust
//! Canonical v3.0.0 AST definitions with Syntax Mapping and docs.rs search aliases.

use core::marker::PhantomData;
use core::net::IpAddr;
use frameassembly::ast::{
    ArrowDirection, L2Modifiers, L3Modifiers, L4Modifiers, Protocol, ProtocolSpec, Spanned,
    TemplateInvocation,
};

/// Host definition declaring network endpoint addressing parameters.
///
/// Syntax mapping: `host <name> { [ip <ip_addr>] [mac <mac_addr>] }`
///
/// At least one of `ip` or `mac` is required. Pure Layer 2 protocols (`lldp`, `stp`, `lacp`,
/// `eapol`, `vlan`, `qinq`, `mpls`, `arp`) allow MAC-only endpoints via `protocol_requires_ip`.
///
/// # Examples
/// ```frameassembly
/// // PROMPT: Declare IPv4 endpoints with explicit MAC addresses and execute an ICMP Echo Request.
/// // TOKENS: host, ip, mac, flow, icmp, echorequest, compile
/// // INSTRUCTION: Declare two IPv4 hosts.
/// host client { ip 10.0.0.1 mac 00:11:22:33:44:55 }
/// host server { ip 10.0.0.2 mac 00:aa:bb:cc:dd:ee }
/// // INSTRUCTION: Define a minimal ICMP flow.
/// flow ping(a, b) {
///     a -> b icmp echorequest
/// }
/// // INSTRUCTION: Compile the flow.
/// compile {
///     ping(client, server)
/// }
/// ```
#[doc(alias = "host")]
#[doc(alias = "ip")]
#[doc(alias = "mac")]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostDef<'a> {
    /// Zero-copy borrowed host identifier name (e.g., `client`, `fw-dmz-01`, `core_sw`).
    pub name: &'a str,
    /// Optional IPv4 or IPv6 address (omitted for pure Layer 2 MAC-only endpoints).
    pub ip: Option<IpAddr>,
    /// Optional IEEE 802.3 6-byte MAC address.
    pub mac: Option<[u8; 6]>,
    /// Source span `(start_byte_offset, byte_length)` of the `host` block.
    pub span: (usize, usize),
}

/// Parameterized flow definition containing ordered frame statements.
///
/// Syntax mapping: `flow <name>(<param1>, <param2>) { <statements> }`
#[doc(alias = "flow")]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FlowDef<'a> {
    /// Zero-copy borrowed flow identifier name.
    pub name: &'a str,
    /// Formal endpoint parameter names.
    pub params: Vec<&'a str>,
    /// Ordered directional frame statements inside the flow body.
    pub statements: Vec<FrameStatement<'a>>,
    /// Source span `(start_byte_offset, byte_length)` of the `flow` block.
    pub span: (usize, usize),
}

/// Statement inside the `compile { ... }` block (`RunStatement` in FrameAssembly v3.0.0).
///
/// Syntax mapping: `compile { <flow>(<args>) | <caller> -> <callee> <proto> ... }`
#[doc(alias = "compile")]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RunStatement<'a> {
    /// A single flow invocation (`my_flow(client, server)`).
    Invocation(TemplateInvocation<'a>),
    /// An inline directional frame statement directly inside `compile`.
    Frame(Box<FrameStatement<'a>>),
}

/// Directional packet transmission statement inside a [`FlowDef`] or inline in `compile`.
///
/// Syntax mapping: `<caller> ->|<- <callee> [L2/L3/L4 modifiers] <protocol> [ProtocolSpec] [wait <duration>]`
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FrameStatement<'a> {
    /// Source endpoint parameter reference.
    pub caller: Spanned<&'a str>,
    /// Packet direction (`->` LeftToRight or `<-` RightToLeft).
    pub arrow: ArrowDirection,
    /// Destination endpoint parameter reference.
    pub callee: Spanned<&'a str>,
    /// Active protocol discriminator (`Protocol::Tcp`, `Protocol::Arp`, `Protocol::Quic`, etc.).
    pub protocol: Protocol,
    /// Strongly-typed protocol-specific AST specification (`ProtocolSpec<'a>`).
    pub protocol_spec: Option<ProtocolSpec<'a>>,
    /// Layer 2 framing modifiers (`vlan`, `qinq`, `innervlan`, `mpls`, `srcmac`, `dstmac`, `ethertype`).
    pub l2: L2Modifiers,
    /// Layer 3 header modifiers (`ttl`, `dscp`, `ecn`, `ipid`, `df`, `mf`, `fragoffset`, `flowlabel`).
    pub l3: L3Modifiers,
    /// Layer 4 transport modifiers (`srcport`, `dstport`, `seq`, `acknum`, `window`, `sackperm`, TCP/SCTP fields).
    pub l4: L4Modifiers,
    /// Optional inter-frame delay in nanoseconds (`wait <int><ns|us|ms|s|m>`).
    pub wait: Option<u64>,
}

/// Layer 2 Address Resolution Protocol (ARP, RFC 826 / RFC 5227) AST specification.
///
/// Syntax mapping: `arp [request | reply] [gratuitous] [sendermac <mac>] [senderip <ip>] [targetmac <mac>] [targetip <ip>]`
#[doc(alias = "arp")]
#[doc(alias = "RFC 826")]
#[doc(alias = "RFC 5227")]
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ArpSpec<'a> {
    /// ARP operation code (`1` = Request, `2` = Reply).
    pub op: Option<u16>,
    /// Sender 48-bit hardware address override (`sendermac`).
    pub sha: Option<[u8; 6]>,
    /// Sender protocol address override (`senderip`).
    pub spa: Option<IpAddr>,
    /// Target 48-bit hardware address override (`targetmac`).
    pub tha: Option<[u8; 6]>,
    /// Target protocol address override (`targetip`).
    pub tpa: Option<IpAddr>,
    /// Zero-copy lifetime marker.
    pub _marker: PhantomData<&'a ()>,
}
```

---

## 3. Protocol-First Guard & 3-Tier Protocol-Scoped Field Parser Dispatch (`src/parser/`)

In FrameAssembly v3.0.0:
1. Because `#[token("whois")] Token::Whois` serves both the L7 `whois` protocol and BACnet's `whois` Unconfirmed-Request service, `parse_frame_statement` checks an explicit protocol-keyword matcher **before** `parse_fallback_field` whenever `current_protocol.is_none()`. That ensures `a -> b whois domain "example.com"` sets `Protocol::Whois` instead of being intercepted alphabetically by `parse_bacnet_field`.
2. When multiple protocols share a modifier token (`value`, `version`, `status`, `token`, `msgid`, `group`, `data`, `cookie`, `response`, `reply`, `keepalive`, `hellotime`, `ack`, `rst`), statement parsing runs a 3-tier loop (`parse_universal_field` $\rightarrow$ `dispatch_protocol_field` $\rightarrow$ `parse_fallback_field`).

```rust
//! Protocol-first guard and 3-tier protocol-scoped field dispatch (`src/parser/fields.rs`).

use winnow::ModalResult as PResult;
use winnow::combinator::alt;
use winnow::prelude::*;
use crate::ast::Protocol;
use crate::lexer::Token;
use crate::parser::{ParsedField, Stream, l2, l3, l4, l7, snmp, tag};

/// Matches an explicit protocol keyword when `current_protocol.is_none()` before `parse_fallback_field`
/// so shared tokens like `Token::Whois` (`whois`) resolve to `Protocol::Whois` rather than BACnet `whois`.
pub(crate) fn parse_explicit_protocol_kw<'i, 'a>(
    input: &mut Stream<'i, 'a>,
) -> PResult<ParsedField<'a>> {
    alt((
        tag(Token::Whois).map(|(_, s)| ParsedField::Protocol(Protocol::Whois, (s.start, s.len()))),
        tag(Token::Bacnet).map(|(_, s)| ParsedField::Protocol(Protocol::Bacnet, (s.start, s.len()))),
        tag(Token::Stp).map(|(_, s)| ParsedField::Protocol(Protocol::Stp, (s.start, s.len()))),
        tag(Token::Hsrp).map(|(_, s)| ParsedField::Protocol(Protocol::Hsrp, (s.start, s.len()))),
    ))
    .parse_next(input)
}

/// Dispatches directly to the active protocol's combinator parser to prevent cross-protocol `cut_err` shadowing.
pub(crate) fn dispatch_protocol_field<'i, 'a>(
    proto: &Protocol,
    input: &mut Stream<'i, 'a>,
) -> PResult<ParsedField<'a>> {
    match proto {
        Protocol::Arp => l2::parse_arp_field(input),
        Protocol::Stp => l2::parse_stp_field(input),
        Protocol::Eapol => l2::parse_eapol_field(input),
        Protocol::Gre => l3::parse_gre_field(input),
        Protocol::Geneve => l3::parse_geneve_field(input),
        Protocol::Vrrp => l3::parse_vrrp_field(input),
        Protocol::Hsrp => l3::parse_hsrp_field(input),
        Protocol::Wireguard => l3::parse_wireguard_field(input),
        Protocol::Tcp => l4::parse_tcp_field(input),
        Protocol::Udp => l4::parse_udp_field(input),
        Protocol::Sctp => l4::parse_sctp_field(input),
        Protocol::Snmp1 | Protocol::Snmp2 | Protocol::Snmp3 => snmp::parse_snmp_field(input),
        Protocol::Dhcp => l7::parse_dhcp_field(input),
        Protocol::Redis => l7::parse_redis_field(input),
        Protocol::Memcached => l7::parse_memcached_field(input),
        Protocol::Bacnet => l7::parse_bacnet_field(input),
        Protocol::Whois => l7::parse_whois_field(input),
        Protocol::Http => l7::parse_http_field(input),
        Protocol::Quic => l7::parse_quic_field(input),
        Protocol::Modbus => l7::parse_modbus_field(input),
        Protocol::Dnp3 => l7::parse_dnp3_field(input),
        Protocol::S7comm => l7::parse_s7comm_field(input),
        Protocol::Ethernetip => l7::parse_ethernetip_field(input),
        Protocol::Opcua => l7::parse_opcua_field(input),
        _ => alt((
            l2::parse_l2_field,
            l3::parse_l3_field,
            l4::parse_l4_field,
            snmp::parse_snmp_field,
            l7::parse_l7_field,
        ))
        .parse_next(input),
    }
}
```

---

## 4. Production v3.0.0 `.frasm` Scenario Archetypes (100% Compiler-Verified)

Complete, copy-pasteable scenarios using strictly canonical FrameAssembly v3.0.0 lowercase syntax (zero `_` or `-` in keywords, flexible user-defined host/flow identifiers, and direct flow invocations in `compile`).

### Scenario 1: Enterprise SNMPv3 USM Encrypted Telemetry over IPv6 (`examples/l7/snmp/snmpv3/`)

```frameassembly
// PROMPT: Synthesize an SNMPv3 USM GetRequest and Response exchange with SHA-256 authentication and AES-128 privacy encryption over IPv6.
// TOKENS: host, ip, mac, flow, snmp3, get, reqid, user, auth, sha256, priv, aes, engineid, engineboots, enginetime, varbind, nullval, response, timeticks, wait, compile

// INSTRUCTION: Declare the IPv6 Network Management Station (NMS) endpoint.
host nms_core {
    ip 2001:db8:100::10
    mac 00:11:22:33:44:55
}

// INSTRUCTION: Declare the managed core switch endpoint.
host core-switch-01 {
    ip 2001:db8:100::20
    mac 00:66:77:88:99:aa
}

// INSTRUCTION: Define the SNMPv3 USM authPriv polling flow for sysUpTime.0.
flow snmpv3_usm_poll(mgr, agent) {
    mgr -> agent snmp3 get reqid 5001 user "secadmin" auth sha256 "AuthSecretKey2026!" priv aes "PrivAesSecretKey!" engineid "80001f888001020304" engineboots 12 enginetime 86400 varbind 1.3.6.1.2.1.1.3.0 nullval
    mgr <- agent snmp3 response reqid 5001 user "secadmin" auth sha256 "AuthSecretKey2026!" priv aes "PrivAesSecretKey!" engineid "80001f888001020304" engineboots 12 enginetime 86400 varbind 1.3.6.1.2.1.1.3.0 timeticks 8640000 wait 5ms
}

// INSTRUCTION: Compile the SNMPv3 USM telemetry flow into the output capture.
compile {
    snmpv3_usm_poll(nms_core, core-switch-01)
}
```

### Scenario 2: Industrial SCADA / OT Modbus TCP Telemetry with IEEE 802.1ad QinQ Tagging

```frameassembly
// PROMPT: Synthesize a Modbus TCP holding register read poll and response over double-tagged IEEE 802.1ad QinQ Ethernet frames.
// TOKENS: host, ip, mac, flow, qinq, innervlan, modbus, txid, unitid, func, addr, count, value, isresponse, wait, compile

// INSTRUCTION: Declare the SCADA HMI master station endpoint.
host scada_hmi {
    ip 192.168.100.10
    mac 00:a0:c9:11:22:33
}

// INSTRUCTION: Declare the industrial PLC endpoint.
host plc-rtu-01 {
    ip 192.168.100.50
    mac 00:1d:9c:44:55:66
}

// INSTRUCTION: Define the QinQ-encapsulated Modbus TCP Function Code 3 (Read Holding Registers) exchange.
flow modbus_qinq_poll(master, plc) {
    master -> plc qinq 100 innervlan 20 modbus txid 1 unitid 1 func "readholdingregisters" addr 40001 count 4
    master <- plc qinq 100 innervlan 20 modbus txid 1 unitid 1 func "readholdingregisters" addr 40001 count 4 value 1500 isresponse wait 10ms
}

// INSTRUCTION: Execute three consecutive polling cycles in the compile block.
compile {
    modbus_qinq_poll(scada_hmi, plc-rtu-01)
    modbus_qinq_poll(scada_hmi, plc-rtu-01)
    modbus_qinq_poll(scada_hmi, plc-rtu-01)
}
```

### Scenario 3: Pure Layer 2 MAC-Only Endpoints (`lldp`) & Inline `compile` Frame Statements

```frameassembly
// PROMPT: Synthesize an IEEE 802.1AB LLDP neighbor advertisement between MAC-only switch endpoints.
// TOKENS: host, mac, flow, lldp, chassisid, portid, sysname, wait, compile

// INSTRUCTION: Declare the pure Layer 2 spine switch endpoint with MAC address only (no IP required for LLDP).
host spine_sw {
    mac 00:1c:73:aa:bb:01
}

// INSTRUCTION: Declare the leaf switch MAC-only endpoint.
host leaf_sw {
    mac 00:1c:73:aa:bb:02
}

// INSTRUCTION: Define a reusable LLDP discovery flow.
flow lldp_announce(a, b) {
    a -> b lldp chassisid "spine-01" portid "Ethernet1/1" sysname "spine-01.dc.local" wait 5ms
}

// INSTRUCTION: Invoke the flow and emit an inline reply frame statement inside compile.
compile {
    lldp_announce(spine_sw, leaf_sw)
    leaf_sw -> spine_sw lldp chassisid "leaf-01" portid "Ethernet49/1" sysname "leaf-01.dc.local" wait 5ms
}
```
