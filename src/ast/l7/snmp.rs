//! Simple Network Management Protocol v1, v2c, and v3 (SNMP, RFC 1157 / RFC 3416 / RFC 3414) AST definitions.
//!
//! This module defines the Abstract Syntax Tree (AST) types for SNMPv1 ([`Snmp1Spec`], RFC 1157),
//! community-based SNMPv2c ([`Snmp2Spec`], RFC 1901 / RFC 3416), and User-Based Security Model
//! SNMPv3 ([`Snmp3Spec`], RFC 3412 / RFC 3414 / RFC 3826 / RFC 7860) over UDP ports 161 (queries)
//! and 162 (traps/informs). On the wire, SNMP messages are ASN.1 BER `SEQUENCE` envelopes carrying
//! version integers (`0`, `1`, `3`), community or USM security parameters (HMAC-MD5/SHA/SHA-2 and
//! DES/AES-128 privacy), a context-tagged PDU (`GetRequest`, `GetNextRequest`, `Response`,
//! `SetRequest`, `Trap`, `GetBulkRequest`, `InformRequest`), and a sequence of [`VarBindAst`] pairs.

use alloc::vec::Vec;
use core::net::IpAddr;

/// Represents the ASN.1 BER PDU type of an SNMPv1, SNMPv2c, or SNMPv3 message.
#[doc(alias = "trap")]
#[doc(alias = "get")]
#[doc(alias = "set")]
#[doc(alias = "response")]
#[doc(alias = "inform")]
#[doc(alias = "getnext")]
#[doc(alias = "getbulk")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SnmpPduType {
    /// SNMPv1 Trap (`0xA4`) or SNMPv2c/v3 Trapv2 (`0xA7`) PDU (`trap`).
    Trap,
    /// SNMP GetRequest (`0xA0`) PDU (`get`).
    Get,
    /// SNMP SetRequest (`0xA3`) PDU (`set`).
    Set,
    /// SNMP GetResponse (`0xA2`) PDU (`response`).
    Response,
    /// SNMPv2c/v3 InformRequest (`0xA6`) PDU (`inform`).
    Inform,
    /// SNMP GetNextRequest (`0xA1`) PDU (`getnext`).
    GetNext,
    /// SNMPv2c/v3 GetBulkRequest (`0xA5`) PDU (`getbulk`).
    GetBulk,
}

/// Represents the SNMPv3 User-Based Security Model (USM) authentication algorithm (RFC 3414 / RFC 7860).
#[doc(alias = "auth")]
#[doc(alias = "md5")]
#[doc(alias = "sha")]
#[doc(alias = "sha256")]
#[doc(alias = "sha384")]
#[doc(alias = "sha512")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SnmpAuthType {
    /// HMAC-MD5-96 authentication (`auth md5 <pass>`, RFC 3414).
    Md5,
    /// HMAC-SHA-96 authentication (`auth sha <pass>`, RFC 3414).
    Sha,
    /// HMAC-SHA-256-128 authentication (`auth sha256 <pass>`, RFC 7860).
    Sha256,
    /// HMAC-SHA-384-192 authentication (`auth sha384 <pass>`, RFC 7860).
    Sha384,
    /// HMAC-SHA-512-256 authentication (`auth sha512 <pass>`, RFC 7860).
    Sha512,
}

/// Represents the SNMPv3 User-Based Security Model (USM) privacy encryption algorithm (RFC 3414 / RFC 3826).
#[doc(alias = "priv")]
#[doc(alias = "des")]
#[doc(alias = "aes")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SnmpPrivType {
    /// CBC-DES 56-bit privacy (`priv des <pass>`, RFC 3414).
    Des,
    /// CFB128-AES-128 privacy (`priv aes <pass>`, RFC 3826).
    Aes,
}

/// Represents the typed SMIv1/SMIv2 value of an SNMP variable binding (`varbind <oid> <type> [val]`).
#[doc(alias = "varbind")]
#[doc(alias = "nullval")]
#[doc(alias = "string")]
#[doc(alias = "int")]
#[doc(alias = "timeticks")]
#[doc(alias = "ipval")]
#[doc(alias = "oidval")]
#[doc(alias = "counter32")]
#[doc(alias = "gauge32")]
#[doc(alias = "counter64")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VarBindType<'a> {
    /// ASN.1 `null` (`0x05`) value (`nullval`).
    Null,
    /// ASN.1 `OCTET STRING` (`0x04`) value (`string <str>`).
    String(&'a str),
    /// ASN.1 32-bit signed `INTEGER` (`0x02`) value (`int <i32>`).
    Int(i32),
    /// SMI `TimeTicks` (`0x43`) hundredths of a second value (`timeticks <u32>`).
    TimeTicks(u32),
    /// SMI `IpAddress` (`0x40`) or RFC 4001 `InetAddress` value (`ipval <ip>`).
    Ip(IpAddr),
    /// ASN.1 `OBJECT IDENTIFIER` (`0x06`) value (`oidval <oid>`).
    OidVal(&'a str),
    /// SMI `Counter32` (`0x41`) 32-bit wrapping counter (`counter32 <u32>`).
    Counter32(u32),
    /// SMI `Gauge32` (`0x42`) 32-bit non-wrapping gauge (`gauge32 <u32>`).
    Gauge32(u32),
    /// SMIv2 `Counter64` (`0x46`) 64-bit high-capacity counter (`counter64 <u64>`).
    Counter64(u64),
}

/// Represents a single SNMP variable binding (`varbind <oid> <type> [val]`).
///
/// Syntax mapping: `varbind <oid> <nullval | string <str> | int <i32> | timeticks <u32> | ipval <ip> | oidval <oid> | counter32 <u32> | gauge32 <u32> | counter64 <u64>>`
#[doc(alias = "varbind")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VarBindAst<'a> {
    /// Dotted-decimal Object Identifier string (`<oid>`).
    pub oid: &'a str,
    /// Typed SMI value associated with the OID.
    pub val: VarBindType<'a>,
}

/// RFC 1157 Simple Network Management Protocol Version 1 (SNMPv1) specification.
///
/// Syntax mapping: `snmp1 [trap | get | getnext | set | response] [community <str>] [enterprise <oid>] [agentip <ip>] [gentrap <u32>] [spectrap <u32>] [sysuptime <u32>] [reqid <u32>] [varbind <oid> <val>...]`
#[doc(alias = "snmp1")]
#[doc(alias = "RFC 1157")]
#[doc(alias = "RFC1157")]
#[doc(alias = "trap")]
#[doc(alias = "get")]
#[doc(alias = "getnext")]
#[doc(alias = "set")]
#[doc(alias = "response")]
#[doc(alias = "community")]
#[doc(alias = "enterprise")]
#[doc(alias = "agentip")]
#[doc(alias = "gentrap")]
#[doc(alias = "spectrap")]
#[doc(alias = "sysuptime")]
#[doc(alias = "reqid")]
#[doc(alias = "varbind")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Snmp1Spec<'a> {
    /// Cleartext SNMPv1 community string (`community <str>`, default `"public"`).
    pub community: Option<&'a str>,
    /// Enterprise OID for Trap-PDU (`enterprise <oid>`).
    pub enterprise: Option<&'a str>,
    /// Agent network address override for Trap-PDU (`agentip <ip>`).
    pub agent_ip: Option<IpAddr>,
    /// Generic trap code `0..=6` (`gentrap <u32>`, default `6` for `enterpriseSpecific`).
    pub gen_trap: Option<u32>,
    /// Enterprise-specific trap sub-code (`spectrap <u32>`, default `1`).
    pub spec_trap: Option<u32>,
    /// Agent `sysUpTime` in hundredths of a second (`sysuptime <u32>`).
    pub sys_up_time: Option<u32>,
    /// Ordered list of SMIv1 variable bindings (`varbind <oid> <val>`).
    pub varbinds: Vec<VarBindAst<'a>>,
    /// SNMPv1 PDU operation type (`trap`, `get`, `getnext`, `set`, `response`).
    pub pdu_type: Option<SnmpPduType>,
}

/// RFC 1901 / RFC 3416 Community-Based Simple Network Management Protocol Version 2 (SNMPv2c) specification.
///
/// Syntax mapping: `snmp2 [trap | inform | get | getnext | getbulk | set | response] [community <str>] [reqid <u32>] [nonrepeaters <u32>] [maxrepetitions <u32>] [sysuptime <u32>] [oid <oid>] [varbind <oid> <val>...]`
#[doc(alias = "snmp2")]
#[doc(alias = "SNMPv2c")]
#[doc(alias = "RFC 3416")]
#[doc(alias = "RFC3416")]
#[doc(alias = "RFC 1901")]
#[doc(alias = "RFC1901")]
#[doc(alias = "trap")]
#[doc(alias = "inform")]
#[doc(alias = "get")]
#[doc(alias = "getnext")]
#[doc(alias = "getbulk")]
#[doc(alias = "set")]
#[doc(alias = "response")]
#[doc(alias = "community")]
#[doc(alias = "reqid")]
#[doc(alias = "nonrepeaters")]
#[doc(alias = "maxrepetitions")]
#[doc(alias = "sysuptime")]
#[doc(alias = "oid")]
#[doc(alias = "varbind")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Snmp2Spec<'a> {
    /// Cleartext SNMPv2c community string (`community <str>`, default `"public"`).
    pub community: Option<&'a str>,
    /// Ordered list of SMIv2 variable bindings (`varbind <oid> <val>`).
    pub varbinds: Vec<VarBindAst<'a>>,
    /// SNMPv2c PDU operation type (`trap`, `inform`, `get`, `getnext`, `getbulk`, `set`, `response`).
    pub pdu_type: Option<SnmpPduType>,
    /// `non-repeaters` count for `GetBulkRequest` (`nonrepeaters <u32>`).
    pub non_repeaters: Option<u32>,
    /// `max-repetitions` count for `GetBulkRequest` (`maxrepetitions <u32>`).
    pub max_repetitions: Option<u32>,
    /// 32-bit PDU `request-id` (`reqid <u32>`).
    pub req_id: Option<u32>,
}

/// RFC 3412 / RFC 3414 Simple Network Management Protocol Version 3 (SNMPv3 USM) specification.
///
/// Syntax mapping: `snmp3 [trap | inform | get | getnext | getbulk | set | response] [user <str>] [engineid <hex>] [engineboots <u32>] [enginetime <u32>] [contextname <str>] [auth <alg> <pass>] [priv <alg> <pass>] [reqid <u32>] [nonrepeaters <u32>] [maxrepetitions <u32>] [sysuptime <u32>] [oid <oid>] [varbind <oid> <val>...]`
#[doc(alias = "snmp3")]
#[doc(alias = "SNMPv3")]
#[doc(alias = "RFC 3414")]
#[doc(alias = "RFC3414")]
#[doc(alias = "RFC 3412")]
#[doc(alias = "RFC 3826")]
#[doc(alias = "RFC 7860")]
#[doc(alias = "trap")]
#[doc(alias = "inform")]
#[doc(alias = "get")]
#[doc(alias = "getnext")]
#[doc(alias = "getbulk")]
#[doc(alias = "set")]
#[doc(alias = "response")]
#[doc(alias = "user")]
#[doc(alias = "engineid")]
#[doc(alias = "engineboots")]
#[doc(alias = "enginetime")]
#[doc(alias = "contextname")]
#[doc(alias = "auth")]
#[doc(alias = "priv")]
#[doc(alias = "reqid")]
#[doc(alias = "nonrepeaters")]
#[doc(alias = "maxrepetitions")]
#[doc(alias = "sysuptime")]
#[doc(alias = "oid")]
#[doc(alias = "varbind")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Snmp3Spec<'a> {
    /// USM securityName (`user <str>`, default `"admin"`).
    pub user: Option<&'a str>,
    /// Hex-encoded `msgAuthoritativeEngineID` (`engineid <hex>`).
    pub engine_id: Option<&'a str>,
    /// `msgAuthoritativeEngineBoots` counter (`engineboots <u32>`, default `1`).
    pub engine_boots: Option<u32>,
    /// `msgAuthoritativeEngineTime` in seconds (`enginetime <u32>`, default `100`).
    pub engine_time: Option<u32>,
    /// ScopedPDU `contextName` (`contextname <str>`, default `""`).
    pub context_name: Option<&'a str>,
    /// USM authentication algorithm and passphrase (`auth <md5|sha|sha256|sha384|sha512> <pass>`).
    pub auth: Option<(SnmpAuthType, &'a str)>,
    /// USM privacy algorithm and passphrase (`priv <des|aes> <pass>`).
    pub priv_param: Option<(SnmpPrivType, &'a str)>,
    /// Ordered list of SMIv2 variable bindings (`varbind <oid> <val>`).
    pub varbinds: Vec<VarBindAst<'a>>,
    /// SNMPv3 ScopedPDU operation type (`trap`, `inform`, `get`, `getnext`, `getbulk`, `set`, `response`).
    pub pdu_type: Option<SnmpPduType>,
    /// `non-repeaters` count for `GetBulkRequest` (`nonrepeaters <u32>`).
    pub non_repeaters: Option<u32>,
    /// `max-repetitions` count for `GetBulkRequest` (`maxrepetitions <u32>`).
    pub max_repetitions: Option<u32>,
    /// 32-bit PDU `request-id` (`reqid <u32>`).
    pub req_id: Option<u32>,
}

/// Type alias for SNMP variable binding ([`VarBindAst`]).
pub type SnmpVarBind<'a> = VarBindAst<'a>;

/// Type alias for SNMP variable binding value ([`VarBindType`]).
pub type SnmpValue<'a> = VarBindType<'a>;

/// Type alias for SNMP authentication protocol ([`SnmpAuthType`]).
pub type SnmpAuthProtocol = SnmpAuthType;

/// Type alias for SNMP privacy protocol ([`SnmpPrivType`]).
pub type SnmpPrivProtocol = SnmpPrivType;

/// SNMP security model identifier (RFC 3411 / RFC 3414).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnmpSecurityModel {
    /// User-Based Security Model (USM, securityModel 3, RFC 3414).
    Usm,
}
