# FrameAssembly Production Reference Patterns

This reference document provides production-ready, fully-documented, and compiler-verified Rust code templates and canonical `.fasm` scenarios for FrameAssembly, covering compiler pipeline invocation, AST representation with `/// Syntax mapping:`, protocol-scoped sub-keyword parser dispatch, wire invariants, 4-tuple TCP state tracking, and enterprise DSL archetypes.

---

## 1. Programmatic Compiler Pipeline Invocation

Demonstrates how to invoke FrameAssembly's two-phase compiler pipeline (`parse_program` $\rightarrow$ `validate_semantics(&program, source)` $\rightarrow$ `compile_program` / `generate_pcap`) without temporary file leaks or unchecked errors.

```rust
//! Programmatic entry point and pipeline invocation for FrameAssembly.

use std::fs;
use std::path::Path;
use frameassembly::ast::Program;
use frameassembly::backend::{compile_program, generate_pcap};
use frameassembly::parser::{parse_program, validate_semantics};

/// Parses, semantically validates, and compiles `.fasm` source code in-memory into `(wire_bytes, timestamp_ns)` frames.
///
/// # Arguments
/// * `source` - Raw UTF-8 string containing canonical FrameAssembly `.fasm` code.
///
/// # Errors
/// Returns a descriptive error string if lexing, syntax parsing, semantic validation,
/// or wire packet assembly fails.
pub fn compile_fasm_str(source: &str) -> Result<Vec<(Vec<u8>, u64)>, String> {
    // 1. Two-phase lexing (logos) + combinator parsing (winnow)
    let program: Program<'_> = parse_program(source)
        .map_err(|e| format!("Syntax/Semantic error: {e:?}"))?;

    // 2. Explicit two-argument semantic validation pass: validate_semantics(&program, source)
    validate_semantics(&program, source)
        .map_err(|e| format!("Semantic validation error: {e:?}"))?;

    // 3. Stateful flow expansion, 4-tuple TCP progression, and RFC wire synthesis
    compile_program(&program)
}

/// Compiles a `.fasm` file on disk directly into a deterministic `.pcapng` capture file.
///
/// # Arguments
/// * `input_path` - Path to the input `.fasm` DSL specification.
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
```

---

## 2. Canonical AST Structures & `/// Syntax mapping:` Docstring Pattern

Every AST struct in `src/ast/mod.rs` (`HostDef<'a>`, `FlowDef<'a>`, `FrameStatement<'a>`) and every protocol `*Spec` struct in `src/ast/{l2,l3,l4,l7}/<protocol>.rs` must include a `/// Syntax mapping: \`...\`` docstring and `#[doc(alias = "...")]` attributes binding the Rust type to its canonical `.fasm` surface syntax and RFC standard.

```rust
//! Canonical AST definitions with Syntax Mapping and docs.rs search aliases.

use core::marker::PhantomData;
use core::net::IpAddr;
use core::ops::Range;
use frameassembly::ast::{
    ArrowDirection, L2Modifiers, L3Modifiers, L4Modifiers, Protocol, ProtocolSpec, Spanned,
};

/// Host definition declaring network endpoint addressing parameters.
///
/// Syntax mapping: `HOST <name> { IP <ip_addr> [MAC <mac_addr>] }`
///
/// # Examples
/// ```frameassembly
/// // PROMPT: Declare IPv4 endpoints with explicit MAC addresses and execute an ICMP Echo Request.
/// // TOKENS: HOST, IP, MAC, FLOW, ICMP, ECHO_REQUEST, COMPILE
/// // INSTRUCTION: Declare two IPv4 hosts.
/// HOST client { IP 10.0.0.1 MAC 00:11:22:33:44:55 }
/// HOST server { IP 10.0.0.2 MAC 00:aa:bb:cc:dd:ee }
/// // INSTRUCTION: Define a minimal ICMP flow.
/// FLOW ping(a, b) {
///     a -> b ICMP ECHO_REQUEST
/// }
/// // INSTRUCTION: Compile the flow.
/// COMPILE {
///     ping(client, server)
/// }
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostDef<'a> {
    /// Zero-copy borrowed host identifier name (e.g., `client`, `server`).
    pub name: &'a str,
    /// Mandatory IPv4 or IPv6 address.
    pub ip: IpAddr,
    /// Optional IEEE 802.3 6-byte MAC address.
    pub mac: Option<[u8; 6]>,
    /// Source span of the `HOST` block.
    pub span: Range<usize>,
}

/// Parameterized flow definition containing ordered frame statements.
///
/// Syntax mapping: `FLOW <name>(<param1>, <param2>) { <statements> }`
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FlowDef<'a> {
    /// Zero-copy borrowed flow identifier name.
    pub name: &'a str,
    /// Formal endpoint parameter names.
    pub params: Vec<&'a str>,
    /// Ordered directional frame statements inside the flow body.
    pub statements: Vec<FrameStatement<'a>>,
    /// Source span of the `FLOW` block.
    pub span: Range<usize>,
}

/// Directional packet transmission statement inside a [`FlowDef`].
///
/// Syntax mapping: `<caller> ->|<-> <callee> [L2/L3/L4 modifiers] <Protocol> [ProtocolSpec] [WAIT <duration>]`
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
    /// Layer 2 framing modifiers (`VLAN`, `QINQ`, `MPLS`, `SRCMAC`, `DSTMAC`, `ETHERTYPE`).
    pub l2: L2Modifiers,
    /// Layer 3 header modifiers (`TTL`, `DSCP`, `ECN`, `IPID`, `DF`, `MF`, `FRAGOFFSET`, `FLOWLABEL`).
    pub l3: L3Modifiers,
    /// Layer 4 transport modifiers (`SRCPORT`, `DSTPORT`, `SEQ`, `ACKNUM`, `WINDOW`, TCP options, SCTP fields).
    pub l4: L4Modifiers,
    /// Optional inter-frame delay in nanoseconds (`WAIT <int><ns|us|ms|s|m>`).
    pub wait: Option<u64>,
}

/// Layer 2 Address Resolution Protocol (ARP, RFC 826 / RFC 5227) AST specification.
///
/// Syntax mapping: `ARP [REQUEST | REPLY | OP <u16>] [SHA <mac>] [SPA <ip>] [THA <mac>] [TPA <ip>]`
/// (Canonical tokens in `src/ast/l2/arp.rs`: `ARP [REQUEST | REPLY] [GRATUITOUS] [SENDERMAC <mac>] [SENDERIP <ip>] [TARGETMAC <mac>] [TARGETIP <ip>]` — never `HWTYPE` or `PROTOTYPE`.)
#[doc(alias = "ARP")]
#[doc(alias = "RFC 826")]
#[doc(alias = "RFC 5227")]
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ArpSpec<'a> {
    /// ARP operation code (`1` = Request, `2` = Reply).
    pub op: Option<u16>,
    /// Sender 48-bit hardware address override (`SHA` / `SENDERMAC`).
    pub sha: Option<[u8; 6]>,
    /// Sender protocol address override (`SPA` / `SENDERIP`).
    pub spa: Option<IpAddr>,
    /// Target 48-bit hardware address override (`THA` / `TARGETMAC`).
    pub tha: Option<[u8; 6]>,
    /// Target protocol address override (`TPA` / `TARGETIP`).
    pub tpa: Option<IpAddr>,
    /// Zero-copy lifetime marker.
    pub _marker: PhantomData<&'a ()>,
}
```

---

## 3. Protocol-Scoped Field Parser Dispatch Pattern (`src/parser/fields.rs`)

When multiple protocols share a keyword token (`Token::Value`, `Token::Version`, `Token::Status`, `Token::Token`, `Token::MsgId`, `Token::Group`, `Token::Data`, `Token::Cookie`, `Token::Response`, `Token::Reply`, `Token::Keepalive`) with different value types (`u8` vs `u32` vs `&str` vs 0-arg flag), dispatch field parsing based on the active `Protocol` on the statement via `dispatch_protocol_field` rather than running a flat protocol-agnostic `alt((...))` loop with `cut_err`.

```rust
//! Protocol-scoped field dispatch preventing cross-protocol keyword shadowing (`src/parser/fields.rs`).

use winnow::ModalResult as PResult;
use winnow::combinator::alt;
use winnow::prelude::*;
use crate::ast::Protocol;
use crate::parser::{ParsedField, Stream, l2, l3, l4, l7, snmp};

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
        Protocol::Wireguard => l3::parse_wireguard_field(input),
        Protocol::Tcp => l4::parse_tcp_field(input),
        Protocol::Udp => l4::parse_udp_field(input),
        Protocol::Sctp => l4::parse_sctp_field(input),
        Protocol::Snmp1 | Protocol::Snmp2 | Protocol::Snmp3 => snmp::parse_snmp_field(input),
        Protocol::Dhcp => l7::parse_dhcp_field(input),
        Protocol::Redis => l7::parse_redis_field(input),
        Protocol::Memcached => l7::parse_memcached_field(input),
        Protocol::Bacnet => l7::parse_bacnet_field(input),
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

## 4. Production `.fasm` Scenario Archetypes (100% Compiler-Verified)

Complete, copy-pasteable DSL scenarios using strictly canonical FrameAssembly syntax.

### Scenario 1: Enterprise SNMPv3 USM Encrypted Telemetry over IPv6 (`examples/l7/snmp/snmpv3/`)

```frameassembly
// PROMPT: Synthesize an SNMPv3 USM GetRequest and Response exchange with SHA-256 authentication and AES-128 privacy encryption over IPv6.
// TOKENS: HOST, IP, MAC, FLOW, SNMP3, GET, REQID, USER, AUTH, SHA256, PRIV, AES, ENGINEID, ENGINEBOOTS, ENGINETIME, VARBIND, NULLVAL, RESPONSE, TIMETICKS, WAIT, COMPILE

// INSTRUCTION: Declare the IPv6 Network Management Station (NMS) and managed core switch endpoints.
HOST nms_core {
    IP 2001:db8:100::10
    MAC 00:11:22:33:44:55
}

// INSTRUCTION: Declare the managed switch endpoint.
HOST core_switch {
    IP 2001:db8:100::20
    MAC 00:66:77:88:99:aa
}

// INSTRUCTION: Define the SNMPv3 USM authPriv polling flow for sysUpTime.0 and sysDescr.0.
FLOW snmpv3_usm_poll(mgr, agent) {
    mgr -> agent SNMP3 GET REQID 5001 USER "secadmin" AUTH SHA256 "AuthSecretKey2026!" PRIV AES "PrivAesSecretKey!" ENGINEID "80001f888001020304" ENGINEBOOTS 12 ENGINETIME 86400 VARBIND 1.3.6.1.2.1.1.3.0 NULLVAL
    mgr <- agent SNMP3 RESPONSE REQID 5001 USER "secadmin" AUTH SHA256 "AuthSecretKey2026!" PRIV AES "PrivAesSecretKey!" ENGINEID "80001f888001020304" ENGINEBOOTS 12 ENGINETIME 86400 VARBIND 1.3.6.1.2.1.1.3.0 TIMETICKS 8640000 WAIT 5ms
}

// INSTRUCTION: Compile the SNMPv3 USM telemetry flow into the output capture.
COMPILE {
    snmpv3_usm_poll(nms_core, core_switch)
}
```

### Scenario 2: Industrial SCADA / OT Modbus TCP Telemetry with IEEE 802.1ad QinQ Tagging

```frameassembly
// PROMPT: Synthesize a Modbus TCP holding register read poll and response over double-tagged IEEE 802.1ad QinQ Ethernet frames.
// TOKENS: HOST, IP, MAC, FLOW, QINQ, INNER_VLAN, MODBUS, TXID, UNITID, FUNC, ADDR, COUNT, VALUE, IS_RESPONSE, WAIT, COMPILE, LOOP

// INSTRUCTION: Declare the SCADA HMI master station and industrial PLC endpoints.
HOST scada_hmi {
    IP 192.168.100.10
    MAC 00:a0:c9:11:22:33
}

// INSTRUCTION: Declare the industrial PLC endpoint.
HOST plc_rtu {
    IP 192.168.100.50
    MAC 00:1d:9c:44:55:66
}

// INSTRUCTION: Define the QinQ-encapsulated Modbus TCP Function Code 3 (Read Holding Registers) exchange.
FLOW modbus_qinq_poll(master, plc) {
    master -> plc QINQ 100 INNER_VLAN 20 MODBUS TXID 1 UNITID 1 FUNC "READ_HOLDING_REGISTERS" ADDR 40001 COUNT 4
    master <- plc QINQ 100 INNER_VLAN 20 MODBUS TXID 1 UNITID 1 FUNC "READ_HOLDING_REGISTERS" ADDR 40001 COUNT 4 VALUE 1500 IS_RESPONSE WAIT 10ms
}

// INSTRUCTION: Execute 5 polling cycles in the COMPILE block.
COMPILE {
    LOOP 5 {
        modbus_qinq_poll(scada_hmi, plc_rtu)
    }
}
```
