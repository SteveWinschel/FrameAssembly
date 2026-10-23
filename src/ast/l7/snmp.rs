//! SNMP protocol specifications (v1, v2c, v3), PDU types, security parameters, and variable bindings.

use alloc::vec::Vec;
use core::net::IpAddr;

/// Represents the type of SNMP PDU.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SnmpPduType {
    /// Trap PDU
    Trap,
    /// GetRequest PDU
    Get,
    /// SetRequest PDU
    Set,
    /// Response PDU
    Response,
    /// InformRequest PDU
    Inform,
    /// GetNextRequest PDU
    GetNext,
    /// GetBulkRequest PDU
    GetBulk,
}

/// Represents the SNMP Auth type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SnmpAuthType {
    /// HMAC-MD5-96
    Md5,
    /// HMAC-SHA-96
    Sha,
    /// HMAC-SHA-256
    Sha256,
    /// HMAC-SHA-384
    Sha384,
    /// HMAC-SHA-512
    Sha512,
}

/// Represents the SNMP Priv type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SnmpPrivType {
    /// DES privacy
    Des,
    /// AES privacy
    Aes,
}

/// Represents the value of a VarBind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VarBindType<'a> {
    /// Null value
    Null,
    /// OctetString value
    String(&'a str),
    /// Signed 32-bit integer value
    Int(i32),
    /// TimeTicks value
    TimeTicks(u32),
    /// IpAddress value
    Ip(IpAddr),
    /// Object Identifier value
    OidVal(&'a str),
    /// 32-bit Counter value
    Counter32(u32),
    /// 32-bit Gauge value
    Gauge32(u32),
    /// 64-bit Counter value
    Counter64(u64),
}

/// Represents a single VarBind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VarBindAst<'a> {
    /// The Object Identifier
    pub oid: &'a str,
    /// The value associated with the OID
    pub val: VarBindType<'a>,
}

/// SNMPv1-specific parameters.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Snmp1Spec<'a> {
    /// Community string.
    pub community: Option<&'a str>,
    /// Enterprise OID.
    pub enterprise: Option<&'a str>,
    /// Agent IP address.
    pub agent_ip: Option<IpAddr>,
    /// Generic trap code.
    pub gen_trap: Option<u32>,
    /// Specific trap code.
    pub spec_trap: Option<u32>,
    /// System uptime.
    pub sys_up_time: Option<u32>,
    /// List of variable bindings.
    pub varbinds: Vec<VarBindAst<'a>>,
    /// PDU Type.
    pub pdu_type: Option<SnmpPduType>,
}

/// SNMPv2c-specific parameters.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Snmp2Spec<'a> {
    /// Community string.
    pub community: Option<&'a str>,
    /// List of variable bindings.
    pub varbinds: Vec<VarBindAst<'a>>,
    /// PDU Type.
    pub pdu_type: Option<SnmpPduType>,
    /// Non-Repeaters for GETBULK.
    pub non_repeaters: Option<u32>,
    /// Max-Repetitions for GETBULK.
    pub max_repetitions: Option<u32>,
    /// Request ID.
    pub req_id: Option<u32>,
}

/// SNMPv3-specific parameters.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Snmp3Spec<'a> {
    /// User name.
    pub user: Option<&'a str>,
    /// Authoritative engine ID.
    pub engine_id: Option<&'a str>,
    /// Authoritative engine boot count.
    pub engine_boots: Option<u32>,
    /// Authoritative engine time.
    pub engine_time: Option<u32>,
    /// Context name.
    pub context_name: Option<&'a str>,
    /// Authentication protocol and password.
    pub auth: Option<(SnmpAuthType, &'a str)>,
    /// Privacy protocol and password.
    pub priv_param: Option<(SnmpPrivType, &'a str)>,
    /// List of variable bindings.
    pub varbinds: Vec<VarBindAst<'a>>,
    /// PDU Type.
    pub pdu_type: Option<SnmpPduType>,
    /// Non-Repeaters for GETBULK.
    pub non_repeaters: Option<u32>,
    /// Max-Repetitions for GETBULK.
    pub max_repetitions: Option<u32>,
    /// Request ID.
    pub req_id: Option<u32>,
}

/// Type alias for SNMP variable binding.
pub type SnmpVarBind<'a> = VarBindAst<'a>;

/// Type alias for SNMP variable binding value.
pub type SnmpValue<'a> = VarBindType<'a>;

/// Type alias for SNMP authentication protocol.
pub type SnmpAuthProtocol = SnmpAuthType;

/// Type alias for SNMP privacy protocol.
pub type SnmpPrivProtocol = SnmpPrivType;

/// SNMP security model (RFC 3411 / RFC 3414).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnmpSecurityModel {
    /// User-Based Security Model (USM, RFC 3414).
    Usm,
}
