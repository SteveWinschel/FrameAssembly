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
#[doc(alias = "TRAP")]
#[doc(alias = "GET")]
#[doc(alias = "SET")]
#[doc(alias = "RESPONSE")]
#[doc(alias = "INFORM")]
#[doc(alias = "GETNEXT")]
#[doc(alias = "GETBULK")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SnmpPduType {
    /// SNMPv1 Trap (`0xA4`) or SNMPv2c/v3 Trapv2 (`0xA7`) PDU (`TRAP`).
    Trap,
    /// SNMP GetRequest (`0xA0`) PDU (`GET`).
    Get,
    /// SNMP SetRequest (`0xA3`) PDU (`SET`).
    Set,
    /// SNMP GetResponse (`0xA2`) PDU (`RESPONSE`).
    Response,
    /// SNMPv2c/v3 InformRequest (`0xA6`) PDU (`INFORM`).
    Inform,
    /// SNMP GetNextRequest (`0xA1`) PDU (`GETNEXT`).
    GetNext,
    /// SNMPv2c/v3 GetBulkRequest (`0xA5`) PDU (`GETBULK`).
    GetBulk,
}

/// Represents the SNMPv3 User-Based Security Model (USM) authentication algorithm (RFC 3414 / RFC 7860).
#[doc(alias = "AUTH")]
#[doc(alias = "MD5")]
#[doc(alias = "SHA")]
#[doc(alias = "SHA256")]
#[doc(alias = "SHA384")]
#[doc(alias = "SHA512")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SnmpAuthType {
    /// HMAC-MD5-96 authentication (`AUTH MD5 <pass>`, RFC 3414).
    Md5,
    /// HMAC-SHA-96 authentication (`AUTH SHA <pass>`, RFC 3414).
    Sha,
    /// HMAC-SHA-256-128 authentication (`AUTH SHA256 <pass>`, RFC 7860).
    Sha256,
    /// HMAC-SHA-384-192 authentication (`AUTH SHA384 <pass>`, RFC 7860).
    Sha384,
    /// HMAC-SHA-512-256 authentication (`AUTH SHA512 <pass>`, RFC 7860).
    Sha512,
}

/// Represents the SNMPv3 User-Based Security Model (USM) privacy encryption algorithm (RFC 3414 / RFC 3826).
#[doc(alias = "PRIV")]
#[doc(alias = "DES")]
#[doc(alias = "AES")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SnmpPrivType {
    /// CBC-DES 56-bit privacy (`PRIV DES <pass>`, RFC 3414).
    Des,
    /// CFB128-AES-128 privacy (`PRIV AES <pass>`, RFC 3826).
    Aes,
}

/// Represents the typed SMIv1/SMIv2 value of an SNMP variable binding (`VARBIND <oid> <type> [val]`).
#[doc(alias = "VARBIND")]
#[doc(alias = "NULLVAL")]
#[doc(alias = "STRING")]
#[doc(alias = "INT")]
#[doc(alias = "TIMETICKS")]
#[doc(alias = "IPVAL")]
#[doc(alias = "OIDVAL")]
#[doc(alias = "COUNTER32")]
#[doc(alias = "GAUGE32")]
#[doc(alias = "COUNTER64")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VarBindType<'a> {
    /// ASN.1 `NULL` (`0x05`) value (`NULLVAL`).
    Null,
    /// ASN.1 `OCTET STRING` (`0x04`) value (`STRING <str>`).
    String(&'a str),
    /// ASN.1 32-bit signed `INTEGER` (`0x02`) value (`INT <i32>`).
    Int(i32),
    /// SMI `TimeTicks` (`0x43`) hundredths of a second value (`TIMETICKS <u32>`).
    TimeTicks(u32),
    /// SMI `IpAddress` (`0x40`) or RFC 4001 `InetAddress` value (`IPVAL <ip>`).
    Ip(IpAddr),
    /// ASN.1 `OBJECT IDENTIFIER` (`0x06`) value (`OIDVAL <oid>`).
    OidVal(&'a str),
    /// SMI `Counter32` (`0x41`) 32-bit wrapping counter (`COUNTER32 <u32>`).
    Counter32(u32),
    /// SMI `Gauge32` (`0x42`) 32-bit non-wrapping gauge (`GAUGE32 <u32>`).
    Gauge32(u32),
    /// SMIv2 `Counter64` (`0x46`) 64-bit high-capacity counter (`COUNTER64 <u64>`).
    Counter64(u64),
}

/// Represents a single SNMP variable binding (`VARBIND <oid> <type> [val]`).
///
/// Syntax mapping: `VARBIND <oid> <NULLVAL | STRING <str> | INT <i32> | TIMETICKS <u32> | IPVAL <ip> | OIDVAL <oid> | COUNTER32 <u32> | GAUGE32 <u32> | COUNTER64 <u64>>`
#[doc(alias = "VARBIND")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VarBindAst<'a> {
    /// Dotted-decimal Object Identifier string (`<oid>`).
    pub oid: &'a str,
    /// Typed SMI value associated with the OID.
    pub val: VarBindType<'a>,
}

/// RFC 1157 Simple Network Management Protocol Version 1 (SNMPv1) specification.
///
/// Syntax mapping: `SNMP1 [TRAP | GET | GETNEXT | SET | RESPONSE] [COMMUNITY <str>] [ENTERPRISE <oid>] [AGENTIP <ip>] [GENTRAP <u32>] [SPECTRAP <u32>] [SYSUPTIME <u32>] [REQID <u32>] [VARBIND <oid> <val>...]`
#[doc(alias = "SNMP1")]
#[doc(alias = "RFC 1157")]
#[doc(alias = "RFC1157")]
#[doc(alias = "TRAP")]
#[doc(alias = "GET")]
#[doc(alias = "GETNEXT")]
#[doc(alias = "SET")]
#[doc(alias = "RESPONSE")]
#[doc(alias = "COMMUNITY")]
#[doc(alias = "ENTERPRISE")]
#[doc(alias = "AGENTIP")]
#[doc(alias = "GENTRAP")]
#[doc(alias = "SPECTRAP")]
#[doc(alias = "SYSUPTIME")]
#[doc(alias = "REQID")]
#[doc(alias = "VARBIND")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Snmp1Spec<'a> {
    /// Cleartext SNMPv1 community string (`COMMUNITY <str>`, default `"public"`).
    pub community: Option<&'a str>,
    /// Enterprise OID for Trap-PDU (`ENTERPRISE <oid>`).
    pub enterprise: Option<&'a str>,
    /// Agent network address override for Trap-PDU (`AGENTIP <ip>`).
    pub agent_ip: Option<IpAddr>,
    /// Generic trap code `0..=6` (`GENTRAP <u32>`, default `6` for `enterpriseSpecific`).
    pub gen_trap: Option<u32>,
    /// Enterprise-specific trap sub-code (`SPECTRAP <u32>`, default `1`).
    pub spec_trap: Option<u32>,
    /// Agent `sysUpTime` in hundredths of a second (`SYSUPTIME <u32>`).
    pub sys_up_time: Option<u32>,
    /// Ordered list of SMIv1 variable bindings (`VARBIND <oid> <val>`).
    pub varbinds: Vec<VarBindAst<'a>>,
    /// SNMPv1 PDU operation type (`TRAP`, `GET`, `GETNEXT`, `SET`, `RESPONSE`).
    pub pdu_type: Option<SnmpPduType>,
}

/// RFC 1901 / RFC 3416 Community-Based Simple Network Management Protocol Version 2 (SNMPv2c) specification.
///
/// Syntax mapping: `SNMP2 [TRAP | INFORM | GET | GETNEXT | GETBULK | SET | RESPONSE] [COMMUNITY <str>] [REQID <u32>] [NONREPEATERS <u32>] [MAXREPETITIONS <u32>] [SYSUPTIME <u32>] [OID <oid>] [VARBIND <oid> <val>...]`
#[doc(alias = "SNMP2")]
#[doc(alias = "SNMPv2c")]
#[doc(alias = "RFC 3416")]
#[doc(alias = "RFC3416")]
#[doc(alias = "RFC 1901")]
#[doc(alias = "RFC1901")]
#[doc(alias = "TRAP")]
#[doc(alias = "INFORM")]
#[doc(alias = "GET")]
#[doc(alias = "GETNEXT")]
#[doc(alias = "GETBULK")]
#[doc(alias = "SET")]
#[doc(alias = "RESPONSE")]
#[doc(alias = "COMMUNITY")]
#[doc(alias = "REQID")]
#[doc(alias = "NONREPEATERS")]
#[doc(alias = "MAXREPETITIONS")]
#[doc(alias = "SYSUPTIME")]
#[doc(alias = "OID")]
#[doc(alias = "VARBIND")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Snmp2Spec<'a> {
    /// Cleartext SNMPv2c community string (`COMMUNITY <str>`, default `"public"`).
    pub community: Option<&'a str>,
    /// Ordered list of SMIv2 variable bindings (`VARBIND <oid> <val>`).
    pub varbinds: Vec<VarBindAst<'a>>,
    /// SNMPv2c PDU operation type (`TRAP`, `INFORM`, `GET`, `GETNEXT`, `GETBULK`, `SET`, `RESPONSE`).
    pub pdu_type: Option<SnmpPduType>,
    /// `non-repeaters` count for `GetBulkRequest` (`NONREPEATERS <u32>`).
    pub non_repeaters: Option<u32>,
    /// `max-repetitions` count for `GetBulkRequest` (`MAXREPETITIONS <u32>`).
    pub max_repetitions: Option<u32>,
    /// 32-bit PDU `request-id` (`REQID <u32>`).
    pub req_id: Option<u32>,
}

/// RFC 3412 / RFC 3414 Simple Network Management Protocol Version 3 (SNMPv3 USM) specification.
///
/// Syntax mapping: `SNMP3 [TRAP | INFORM | GET | GETNEXT | GETBULK | SET | RESPONSE] [USER <str>] [ENGINEID <hex>] [ENGINEBOOTS <u32>] [ENGINETIME <u32>] [CONTEXTNAME <str>] [AUTH <alg> <pass>] [PRIV <alg> <pass>] [REQID <u32>] [NONREPEATERS <u32>] [MAXREPETITIONS <u32>] [SYSUPTIME <u32>] [OID <oid>] [VARBIND <oid> <val>...]`
#[doc(alias = "SNMP3")]
#[doc(alias = "SNMPv3")]
#[doc(alias = "RFC 3414")]
#[doc(alias = "RFC3414")]
#[doc(alias = "RFC 3412")]
#[doc(alias = "RFC 3826")]
#[doc(alias = "RFC 7860")]
#[doc(alias = "TRAP")]
#[doc(alias = "INFORM")]
#[doc(alias = "GET")]
#[doc(alias = "GETNEXT")]
#[doc(alias = "GETBULK")]
#[doc(alias = "SET")]
#[doc(alias = "RESPONSE")]
#[doc(alias = "USER")]
#[doc(alias = "ENGINEID")]
#[doc(alias = "ENGINEBOOTS")]
#[doc(alias = "ENGINETIME")]
#[doc(alias = "CONTEXTNAME")]
#[doc(alias = "AUTH")]
#[doc(alias = "PRIV")]
#[doc(alias = "REQID")]
#[doc(alias = "NONREPEATERS")]
#[doc(alias = "MAXREPETITIONS")]
#[doc(alias = "SYSUPTIME")]
#[doc(alias = "OID")]
#[doc(alias = "VARBIND")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Snmp3Spec<'a> {
    /// USM securityName (`USER <str>`, default `"admin"`).
    pub user: Option<&'a str>,
    /// Hex-encoded `msgAuthoritativeEngineID` (`ENGINEID <hex>`).
    pub engine_id: Option<&'a str>,
    /// `msgAuthoritativeEngineBoots` counter (`ENGINEBOOTS <u32>`, default `1`).
    pub engine_boots: Option<u32>,
    /// `msgAuthoritativeEngineTime` in seconds (`ENGINETIME <u32>`, default `100`).
    pub engine_time: Option<u32>,
    /// ScopedPDU `contextName` (`CONTEXTNAME <str>`, default `""`).
    pub context_name: Option<&'a str>,
    /// USM authentication algorithm and passphrase (`AUTH <MD5|SHA|SHA256|SHA384|SHA512> <pass>`).
    pub auth: Option<(SnmpAuthType, &'a str)>,
    /// USM privacy algorithm and passphrase (`PRIV <DES|AES> <pass>`).
    pub priv_param: Option<(SnmpPrivType, &'a str)>,
    /// Ordered list of SMIv2 variable bindings (`VARBIND <oid> <val>`).
    pub varbinds: Vec<VarBindAst<'a>>,
    /// SNMPv3 ScopedPDU operation type (`TRAP`, `INFORM`, `GET`, `GETNEXT`, `GETBULK`, `SET`, `RESPONSE`).
    pub pdu_type: Option<SnmpPduType>,
    /// `non-repeaters` count for `GetBulkRequest` (`NONREPEATERS <u32>`).
    pub non_repeaters: Option<u32>,
    /// `max-repetitions` count for `GetBulkRequest` (`MAXREPETITIONS <u32>`).
    pub max_repetitions: Option<u32>,
    /// 32-bit PDU `request-id` (`REQID <u32>`).
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
